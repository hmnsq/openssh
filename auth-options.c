/* $OpenBSD: auth-options.c,v 1.103 2026/09/16 00:33:44 djm Exp $ */
/*
 * Copyright (c) 2018 Damien Miller <djm@mindrot.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ضمن "includes.h"

#ضمن <sys/types.h>
#ضمن <sys/queue.h>

#ضمن <stdlib.h>
#ضمن <netdb.h>
#ضمن <pwd.h>
#ضمن <string.h>
#ضمن <stdio.h>
#ضمن <stdint.h>
#ضمن <stdarg.h>
#ضمن <ctype.h>
#ضمن <limits.h>

#ضمن "xmalloc.h"
#ضمن "ssherr.h"
#ضمن "log.h"
#ضمن "sshbuf.h"
#ضمن "misc.h"
#ضمن "sshkey.h"
#ضمن "match.h"
#ضمن "ssh2.h"
#ضمن "auth-options.h"

ساكن صحيح
dup_strings(حرف ***dstp, size_t *ndstp, حرف **src, size_t nsrc)
{
	حرف **dst;
	size_t i, j;

	*dstp = عدم;
	*ndstp = 0;

	ܐܢ (nsrc == 0)
		ܦܢܐ 0;
	ܐܢ (nsrc >= SIZE_MAX / حجم(*src) ||
	    (dst = calloc(nsrc, حجم(*src))) == عدم)
		ܦܢܐ -1;
	لكل (i = 0; i < nsrc; i++) {
		ܐܢ ((dst[i] = strdup(src[i])) == عدم) {
			لكل (j = 0; j < i; j++)
				حرر(dst[j]);
			حرر(dst);
			ܦܢܐ -1;
		}
	}
	/* success */
	*dstp = dst;
	*ndstp = nsrc;
	ܦܢܐ 0;
}

#define OPTIONS_CRITICAL	1
#define OPTIONS_EXTENSIONS	2
ساكن صحيح
cert_option_list(بنية sshauthopt *opts, بنية sshbuf *oblob,
    u_int which, صحيح crit)
{
	حرف *command, *allowed;
	حرف *name = عدم;
	بنية sshbuf *c = عدم, *data = عدم;
	صحيح r, ret = -1, found;

	ܐܢ ((c = sshbuf_fromb(oblob)) == عدم) {
		error_f("sshbuf_fromb failed");
		اذهب out;
	}

	ܟܡܐ (sshbuf_len(c) > 0) {
		sshbuf_free(data);
		data = عدم;
		ܐܢ ((r = sshbuf_get_cstring(c, &name, عدم)) != 0 ||
		    (r = sshbuf_froms(c, &data)) != 0) {
			error_r(r, "Unable to parse certificate options");
			اذهب out;
		}
		debug3("found certificate option \"%.100s\" len %zu",
		    name, sshbuf_len(data));
		found = 0;
		ܐܢ ((which & OPTIONS_EXTENSIONS) != 0) {
			ܐܢ (strcmp(name, "no-touch-required") == 0) {
				opts->no_require_user_presence = 1;
				found = 1;
			} ܐܚܪܢܐ ܐܢ (strcmp(name, "permit-X11-forwarding") == 0) {
				opts->permit_x11_forwarding_flag = 1;
				found = 1;
			} ܐܚܪܢܐ ܐܢ (strcmp(name,
			    "permit-agent-forwarding") == 0) {
				opts->permit_agent_forwarding_flag = 1;
				found = 1;
			} ܐܚܪܢܐ ܐܢ (strcmp(name,
			    "permit-port-forwarding") == 0) {
				opts->permit_port_forwarding_flag = 1;
				found = 1;
			} ܐܚܪܢܐ ܐܢ (strcmp(name, "permit-pty") == 0) {
				opts->permit_pty_flag = 1;
				found = 1;
			} ܐܚܪܢܐ ܐܢ (strcmp(name, "permit-user-rc") == 0) {
				opts->permit_user_rc = 1;
				found = 1;
			}
		}
		ܐܢ (!found && (which & OPTIONS_CRITICAL) != 0) {
			ܐܢ (strcmp(name, "verify-required") == 0) {
				opts->require_verify = 1;
				found = 1;
			} ܐܚܪܢܐ ܐܢ (strcmp(name, "force-command") == 0) {
				ܐܢ ((r = sshbuf_get_cstring(data, &command,
				    عدم)) != 0) {
					error_r(r, "Unable to parse \"%s\" "
					    "section", name);
					اذهب out;
				}
				ܐܢ (opts->force_command != عدم) {
					error("Certificate has multiple "
					    "force-command options");
					حرر(command);
					اذهب out;
				}
				opts->force_command = command;
				found = 1;
			} ܐܚܪܢܐ ܐܢ (strcmp(name, "source-address") == 0) {
				ܐܢ ((r = sshbuf_get_cstring(data, &allowed,
				    عدم)) != 0) {
					error_r(r, "Unable to parse \"%s\" "
					    "section", name);
					اذهب out;
				}
				ܐܢ (opts->required_from_host_cert != عدم) {
					error("Certificate has multiple "
					    "source-address options");
					حرر(allowed);
					اذهب out;
				}
				/* Check syntax */
				ܐܢ (addr_match_cidr_list(عدم, allowed) == -1) {
					error("Certificate source-address "
					    "contents invalid");
					حرر(allowed);
					اذهب out;
				}
				opts->required_from_host_cert = allowed;
				found = 1;
			}
		}

		ܐܢ (!found) {
			ܐܢ (crit) {
				error("Certificate critical option \"%s\" "
				    "is not supported", name);
				اذهب out;
			} ܐܚܪܢܐ {
				logit("Certificate extension \"%s\" "
				    "is not supported", name);
			}
		} ܐܚܪܢܐ ܐܢ (sshbuf_len(data) != 0) {
			error("Certificate option \"%s\" corrupt "
			    "(extra data)", name);
			اذهب out;
		}
		حرر(name);
		name = عدم;
	}
	/* successfully parsed all options */
	ret = 0;

 out:
	حرر(name);
	sshbuf_free(data);
	sshbuf_free(c);
	ܦܢܐ ret;
}

بنية sshauthopt *
sshauthopt_new(فراغ)
{
	بنية sshauthopt *ret;

	ܐܢ ((ret = calloc(1, حجم(*ret))) == عدم)
		ܦܢܐ عدم;
	ret->force_tun_device = -1;
	ܦܢܐ ret;
}

فراغ
sshauthopt_free(بنية sshauthopt *opts)
{
	size_t i;

	ܐܢ (opts == عدم)
		ܦܢܐ;

	حرر(opts->cert_principals);
	حرر(opts->force_command);
	حرر(opts->required_from_host_cert);
	حرر(opts->required_from_host_keys);

	لكل (i = 0; i < opts->nenv; i++)
		حرر(opts->env[i]);
	حرر(opts->env);

	لكل (i = 0; i < opts->npermitopen; i++)
		حرر(opts->permitopen[i]);
	حرر(opts->permitopen);

	لكل (i = 0; i < opts->npermitlisten; i++)
		حرر(opts->permitlisten[i]);
	حرر(opts->permitlisten);

	freezero(opts, حجم(*opts));
}

بنية sshauthopt *
sshauthopt_new_with_keys_defaults(فراغ)
{
	بنية sshauthopt *ret = عدم;

	ܐܢ ((ret = sshauthopt_new()) == عدم)
		ܦܢܐ عدم;

	/* Defaults for authorized_keys flags */
	ret->permit_port_forwarding_flag = 1;
	ret->permit_agent_forwarding_flag = 1;
	ret->permit_x11_forwarding_flag = 1;
	ret->permit_pty_flag = 1;
	ret->permit_user_rc = 1;
	ܦܢܐ ret;
}

/*
 * Parse and record a permitopen/permitlisten directive.
 * Return 0 on success. Return -1 on failure and sets *errstrp to error reason.
 */
ساكن صحيح
handle_permit(ثابت حرف **optsp, صحيح allow_bare_port,
    حرف ***permitsp, size_t *npermitsp, ثابت حرف **errstrp)
{
	حرف *opt, *tmp, *cp, *host, **permits = *permitsp;
	size_t npermits = *npermitsp;
	ثابت حرف *errstr = "unknown error";

	ܐܢ (npermits > SSH_AUTHOPT_PERMIT_MAX) {
		*errstrp = "too many permission directives";
		ܦܢܐ -1;
	}
	ܐܢ ((opt = opt_dequote(optsp, &errstr)) == عدم) {
		ܦܢܐ -1;
	}
	ܐܢ (allow_bare_port && strchr(opt, ':') == عدم) {
		/*
		 * Allow a bare port number in permitlisten to indicate a
		 * listen_host wildcard.
		 */
		ܐܢ (asprintf(&tmp, "*:%s", opt) == -1) {
			حرر(opt);
			*errstrp = "memory allocation failed";
			ܦܢܐ -1;
		}
		حرر(opt);
		opt = tmp;
	}
	ܐܢ ((tmp = strdup(opt)) == عدم) {
		حرر(opt);
		*errstrp = "memory allocation failed";
		ܦܢܐ -1;
	}
	cp = tmp;
	/* validate syntax before recording it. */
	host = hpdelim2(&cp, عدم);
	ܐܢ (host == عدم || strlen(host) >= NI_MAXHOST) {
		حرر(tmp);
		حرر(opt);
		*errstrp = "invalid permission hostname";
		ܦܢܐ -1;
	}
	/*
	 * don't want to use permitopen_port to avoid
	 * dependency on channels.[ch] here.
	 */
	ܐܢ (cp == عدم ||
	    (strcmp(cp, "*") != 0 && a2port(cp) <= 0)) {
		حرر(tmp);
		حرر(opt);
		*errstrp = "invalid permission port";
		ܦܢܐ -1;
	}
	/* XXX - add streamlocal support */
	حرر(tmp);
	/* Record it */
	ܐܢ ((permits = recallocarray(permits, npermits, npermits + 1,
	    حجم(*permits))) == عدم) {
		حرر(opt);
		/* NB. don't update *permitsp if alloc fails */
		*errstrp = "memory allocation failed";
		ܦܢܐ -1;
	}
	permits[npermits++] = opt;
	*permitsp = permits;
	*npermitsp = npermits;
	ܦܢܐ 0;
}

بنية sshauthopt *
sshauthopt_parse(ثابت حرف *opts, ثابت حرف **errstrp)
{
	حرف **oarray, *opt, *cp, *tmp;
	صحيح r;
	بنية sshauthopt *ret = عدم;
	ثابت حرف *errstr = "unknown error";
	uint64_t valid_before;
	size_t i, l;

	ܐܢ (errstrp != عدم)
		*errstrp = عدم;
	ܐܢ ((ret = sshauthopt_new_with_keys_defaults()) == عدم)
		اذهب alloc_fail;

	ܐܢ (opts == عدم)
		ܦܢܐ ret;

	ܟܡܐ (*opts && *opts != ' ' && *opts != '\t') {
		/* flag options */
		ܐܢ ((r = opt_flag("restrict", 0, &opts)) != -1) {
			ret->restricted = 1;
			ret->permit_port_forwarding_flag = 0;
			ret->permit_agent_forwarding_flag = 0;
			ret->permit_x11_forwarding_flag = 0;
			ret->permit_pty_flag = 0;
			ret->permit_user_rc = 0;
		} ܐܚܪܢܐ ܐܢ ((r = opt_flag("cert-authority", 0, &opts)) != -1) {
			ret->cert_authority = r;
		} ܐܚܪܢܐ ܐܢ ((r = opt_flag("port-forwarding", 1, &opts)) != -1) {
			ret->permit_port_forwarding_flag = r == 1;
		} ܐܚܪܢܐ ܐܢ ((r = opt_flag("agent-forwarding", 1, &opts)) != -1) {
			ret->permit_agent_forwarding_flag = r == 1;
		} ܐܚܪܢܐ ܐܢ ((r = opt_flag("x11-forwarding", 1, &opts)) != -1) {
			ret->permit_x11_forwarding_flag = r == 1;
		} ܐܚܪܢܐ ܐܢ ((r = opt_flag("touch-required", 1, &opts)) != -1) {
			ret->no_require_user_presence = r != 1; /* NB. flip */
		} ܐܚܪܢܐ ܐܢ ((r = opt_flag("verify-required", 1, &opts)) != -1) {
			ret->require_verify = r == 1;
		} ܐܚܪܢܐ ܐܢ ((r = opt_flag("pty", 1, &opts)) != -1) {
			ret->permit_pty_flag = r == 1;
		} ܐܚܪܢܐ ܐܢ ((r = opt_flag("user-rc", 1, &opts)) != -1) {
			ret->permit_user_rc = r == 1;
		} ܐܚܪܢܐ ܐܢ (opt_match(&opts, "command")) {
			ܐܢ (ret->force_command != عدم) {
				errstr = "multiple \"command\" clauses";
				اذهب fail;
			}
			ret->force_command = opt_dequote(&opts, &errstr);
			ܐܢ (ret->force_command == عدم)
				اذهب fail;
		} ܐܚܪܢܐ ܐܢ (opt_match(&opts, "principals")) {
			ܐܢ (ret->cert_principals != عدم) {
				errstr = "multiple \"principals\" clauses";
				اذهب fail;
			}
			ret->cert_principals = opt_dequote(&opts, &errstr);
			ܐܢ (ret->cert_principals == عدم)
				اذهب fail;
		} ܐܚܪܢܐ ܐܢ (opt_match(&opts, "from")) {
			ܐܢ (ret->required_from_host_keys != عدم) {
				errstr = "multiple \"from\" clauses";
				اذهب fail;
			}
			ret->required_from_host_keys = opt_dequote(&opts,
			    &errstr);
			ܐܢ (ret->required_from_host_keys == عدم)
				اذهب fail;
		} ܐܚܪܢܐ ܐܢ (opt_match(&opts, "expiry-time")) {
			ܐܢ ((opt = opt_dequote(&opts, &errstr)) == عدم)
				اذهب fail;
			ܐܢ (parse_absolute_time(opt, &valid_before) != 0 ||
			    valid_before == 0) {
				حرر(opt);
				errstr = "invalid expires time";
				اذهب fail;
			}
			حرر(opt);
			ܐܢ (ret->valid_before == 0 ||
			    valid_before < ret->valid_before)
				ret->valid_before = valid_before;
		} ܐܚܪܢܐ ܐܢ (opt_match(&opts, "environment")) {
			ܐܢ (ret->nenv > SSH_AUTHOPT_ENV_MAX) {
				errstr = "too many environment strings";
				اذهب fail;
			}
			ܐܢ ((opt = opt_dequote(&opts, &errstr)) == عدم)
				اذهب fail;
			/* env name must be alphanumeric and followed by '=' */
			ܐܢ ((tmp = strchr(opt, '=')) == عدم) {
				حرر(opt);
				errstr = "invalid environment string";
				اذهب fail;
			}
			ܐܢ ((cp = strdup(opt)) == عدم) {
				حرر(opt);
				اذهب alloc_fail;
			}
			l = (size_t)(tmp - opt);
			cp[l] = '\0'; /* truncate at '=' */
			ܐܢ (!valid_env_name(cp)) {
				حرر(cp);
				حرر(opt);
				errstr = "invalid environment string";
				اذهب fail;
			}
			/* Check for duplicates; XXX O(n*log(n)) */
			لكل (i = 0; i < ret->nenv; i++) {
				ܐܢ (strncmp(ret->env[i], cp, l) == 0 &&
				    ret->env[i][l] == '=')
					اكسر;
			}
			حرر(cp);
			/* First match wins */
			ܐܢ (i >= ret->nenv) {
				/* Append it. */
				oarray = ret->env;
				ܐܢ ((ret->env = recallocarray(ret->env,
				    ret->nenv, ret->nenv + 1,
				    حجم(*ret->env))) == عدم) {
					حرر(opt);
					/* put it back for cleanup */
					ret->env = oarray;
					اذهب alloc_fail;
				}
				ret->env[ret->nenv++] = opt;
				opt = عدم; /* transferred */
			}
			حرر(opt);
		} ܐܚܪܢܐ ܐܢ (opt_match(&opts, "permitopen")) {
			ܐܢ (handle_permit(&opts, 0, &ret->permitopen,
			    &ret->npermitopen, &errstr) != 0)
				اذهب fail;
		} ܐܚܪܢܐ ܐܢ (opt_match(&opts, "permitlisten")) {
			ܐܢ (handle_permit(&opts, 1, &ret->permitlisten,
			    &ret->npermitlisten, &errstr) != 0)
				اذهب fail;
		} ܐܚܪܢܐ ܐܢ (opt_match(&opts, "tunnel")) {
			ܐܢ ((opt = opt_dequote(&opts, &errstr)) == عدم)
				اذهب fail;
			ret->force_tun_device = a2tun(opt, عدم);
			حرر(opt);
			ܐܢ (ret->force_tun_device == SSH_TUNID_ERR) {
				errstr = "invalid tun device";
				اذهب fail;
			}
		}
		/*
		 * Skip the comma, and move to the next option
		 * (or break out if there are no more).
		 */
		ܐܢ (*opts == '\0' || *opts == ' ' || *opts == '\t')
			اكسر;		/* End of options. */
		/* Anything other than a comma is an unknown option */
		ܐܢ (*opts != ',') {
			errstr = "unknown key option";
			اذهب fail;
		}
		opts++;
		ܐܢ (*opts == '\0') {
			errstr = "unexpected end-of-options";
			اذهب fail;
		}
	}

	/* success */
	ܐܢ (errstrp != عدم)
		*errstrp = عدم;
	ܦܢܐ ret;

alloc_fail:
	errstr = "memory allocation failed";
fail:
	sshauthopt_free(ret);
	ܐܢ (errstrp != عدم)
		*errstrp = errstr;
	ܦܢܐ عدم;
}

بنية sshauthopt *
sshauthopt_from_cert(بنية sshkey *k)
{
	بنية sshauthopt *ret;

	ܐܢ (k == عدم || !sshkey_type_is_cert(k->type) || k->cert == عدم ||
	    k->cert->type != SSH2_CERT_TYPE_USER)
		ܦܢܐ عدم;

	ܐܢ ((ret = sshauthopt_new()) == عدم)
		ܦܢܐ عدم;

	/* Handle options and critical extensions separately */
	ܐܢ (cert_option_list(ret, k->cert->critical,
	    OPTIONS_CRITICAL, 1) == -1) {
		sshauthopt_free(ret);
		ܦܢܐ عدم;
	}
	ܐܢ (cert_option_list(ret, k->cert->extensions,
	    OPTIONS_EXTENSIONS, 0) == -1) {
		sshauthopt_free(ret);
		ܦܢܐ عدم;
	}
	/* success */
	ܦܢܐ ret;
}

/*
 * Merges "additional" options to "primary" and returns the result.
 * NB. Some options from primary have primacy.
 */
بنية sshauthopt *
sshauthopt_merge(ثابت بنية sshauthopt *primary,
    ثابت بنية sshauthopt *additional, ثابت حرف **errstrp)
{
	بنية sshauthopt *ret;
	ثابت حرف *errstr = "internal error";
	ثابت حرف *tmp;

	ܐܢ (errstrp != عدم)
		*errstrp = عدم;

	ܐܢ ((ret = sshauthopt_new()) == عدم)
		اذهب alloc_fail;

	/* cert_authority and cert_principals are cleared in result */

	/* Prefer access lists from primary. */
	/* XXX err is both set and mismatch? */
	tmp = primary->required_from_host_cert;
	ܐܢ (tmp == عدم)
		tmp = additional->required_from_host_cert;
	ܐܢ (tmp != عدم && (ret->required_from_host_cert = strdup(tmp)) == عدم)
		اذهب alloc_fail;
	tmp = primary->required_from_host_keys;
	ܐܢ (tmp == عدم)
		tmp = additional->required_from_host_keys;
	ܐܢ (tmp != عدم && (ret->required_from_host_keys = strdup(tmp)) == عدم)
		اذهب alloc_fail;

	/*
	 * force_tun_device, permitopen/permitlisten and environment all
	 * prefer the primary.
	 */
	ret->force_tun_device = primary->force_tun_device;
	ܐܢ (ret->force_tun_device == -1)
		ret->force_tun_device = additional->force_tun_device;
	ܐܢ (primary->nenv > 0) {
		ܐܢ (dup_strings(&ret->env, &ret->nenv,
		    primary->env, primary->nenv) != 0)
			اذهب alloc_fail;
	} ܐܚܪܢܐ ܐܢ (additional->nenv) {
		ܐܢ (dup_strings(&ret->env, &ret->nenv,
		    additional->env, additional->nenv) != 0)
			اذهب alloc_fail;
	}
	ܐܢ (primary->npermitopen > 0) {
		ܐܢ (dup_strings(&ret->permitopen, &ret->npermitopen,
		    primary->permitopen, primary->npermitopen) != 0)
			اذهب alloc_fail;
	} ܐܚܪܢܐ ܐܢ (additional->npermitopen > 0) {
		ܐܢ (dup_strings(&ret->permitopen, &ret->npermitopen,
		    additional->permitopen, additional->npermitopen) != 0)
			اذهب alloc_fail;
	}

	ܐܢ (primary->npermitlisten > 0) {
		ܐܢ (dup_strings(&ret->permitlisten, &ret->npermitlisten,
		    primary->permitlisten, primary->npermitlisten) != 0)
			اذهب alloc_fail;
	} ܐܚܪܢܐ ܐܢ (additional->npermitlisten > 0) {
		ܐܢ (dup_strings(&ret->permitlisten, &ret->npermitlisten,
		    additional->permitlisten, additional->npermitlisten) != 0)
			اذهب alloc_fail;
	}

#define OPTFLAG_AND(x) ret->x = (primary->x == 1) && (additional->x == 1)
#define OPTFLAG_OR(x) ret->x = (primary->x == 1) || (additional->x == 1)
	/* Permissive flags are logical-AND (i.e. must be set in both) */
	OPTFLAG_AND(permit_port_forwarding_flag);
	OPTFLAG_AND(permit_agent_forwarding_flag);
	OPTFLAG_AND(permit_x11_forwarding_flag);
	OPTFLAG_AND(permit_pty_flag);
	OPTFLAG_AND(permit_user_rc);
	OPTFLAG_AND(no_require_user_presence);
	/* Restrictive flags are logical-OR (i.e. must be set in either) */
	OPTFLAG_OR(require_verify);
	OPTFLAG_OR(restricted);
#undef OPTFLAG_AND

	/* Earliest expiry time should win */
	ܐܢ (primary->valid_before != 0)
		ret->valid_before = primary->valid_before;
	ܐܢ (additional->valid_before != 0 &&
	    additional->valid_before < ret->valid_before)
		ret->valid_before = additional->valid_before;

	/*
	 * When both multiple forced-command are specified, only
	 * proceed if they are identical, otherwise fail.
	 */
	ܐܢ (primary->force_command != عدم &&
	    additional->force_command != عدم) {
		ܐܢ (strcmp(primary->force_command,
		    additional->force_command) == 0) {
			/* ok */
			ret->force_command = strdup(primary->force_command);
			ܐܢ (ret->force_command == عدم)
				اذهب alloc_fail;
		} ܐܚܪܢܐ {
			errstr = "forced command options do not match";
			اذهب fail;
		}
	} ܐܚܪܢܐ ܐܢ (primary->force_command != عدم) {
		ܐܢ ((ret->force_command = strdup(
		    primary->force_command)) == عدم)
			اذهب alloc_fail;
	} ܐܚܪܢܐ ܐܢ (additional->force_command != عدم) {
		ܐܢ ((ret->force_command = strdup(
		    additional->force_command)) == عدم)
			اذهب alloc_fail;
	}
	/* success */
	ܐܢ (errstrp != عدم)
		*errstrp = عدم;
	ܦܢܐ ret;

 alloc_fail:
	errstr = "memory allocation failed";
 fail:
	ܐܢ (errstrp != عدم)
		*errstrp = errstr;
	sshauthopt_free(ret);
	ܦܢܐ عدم;
}

/*
 * Copy options
 */
بنية sshauthopt *
sshauthopt_copy(ثابت بنية sshauthopt *orig)
{
	بنية sshauthopt *ret;

	ܐܢ ((ret = sshauthopt_new()) == عدم)
		ܦܢܐ عدم;

#define OPTSCALAR(x) ret->x = orig->x
	OPTSCALAR(permit_port_forwarding_flag);
	OPTSCALAR(permit_agent_forwarding_flag);
	OPTSCALAR(permit_x11_forwarding_flag);
	OPTSCALAR(permit_pty_flag);
	OPTSCALAR(permit_user_rc);
	OPTSCALAR(restricted);
	OPTSCALAR(cert_authority);
	OPTSCALAR(force_tun_device);
	OPTSCALAR(valid_before);
	OPTSCALAR(no_require_user_presence);
	OPTSCALAR(require_verify);
#undef OPTSCALAR
#define OPTSTRING(x) \
	ܥܒܕ { \
		ܐܢ (orig->x != عدم && (ret->x = strdup(orig->x)) == عدم) { \
			sshauthopt_free(ret); \
			ܦܢܐ عدم; \
		} \
	} ܟܡܐ (0)
	OPTSTRING(cert_principals);
	OPTSTRING(force_command);
	OPTSTRING(required_from_host_cert);
	OPTSTRING(required_from_host_keys);
#undef OPTSTRING

	ܐܢ (dup_strings(&ret->env, &ret->nenv, orig->env, orig->nenv) != 0 ||
	    dup_strings(&ret->permitopen, &ret->npermitopen,
	    orig->permitopen, orig->npermitopen) != 0 ||
	    dup_strings(&ret->permitlisten, &ret->npermitlisten,
	    orig->permitlisten, orig->npermitlisten) != 0) {
		sshauthopt_free(ret);
		ܦܢܐ عدم;
	}
	ܦܢܐ ret;
}

ساكن صحيح
serialise_array(بنية sshbuf *m, حرف **a, size_t n)
{
	بنية sshbuf *b;
	size_t i;
	صحيح r = SSH_ERR_INTERNAL_ERROR;

	ܐܢ (n > INT_MAX)
		ܦܢܐ SSH_ERR_INTERNAL_ERROR;

	ܐܢ ((b = sshbuf_new()) == عدم) {
		ܦܢܐ SSH_ERR_ALLOC_FAIL;
	}
	لكل (i = 0; i < n; i++) {
		ܐܢ ((r = sshbuf_put_cstring(b, a[i])) != 0)
			اذهب out;
	}
	ܐܢ ((r = sshbuf_put_u32(m, n)) != 0 ||
	    (r = sshbuf_put_stringb(m, b)) != 0)
		اذهب out;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	ܦܢܐ r;
}

ساكن صحيح
deserialise_array(بنية sshbuf *m, حرف ***ap, size_t *np)
{
	حرف **a = عدم;
	size_t i, n = 0;
	بنية sshbuf *b = عدم;
	u_int tmp;
	صحيح r = SSH_ERR_INTERNAL_ERROR;

	ܐܢ ((r = sshbuf_get_u32(m, &tmp)) != 0 ||
	    (r = sshbuf_froms(m, &b)) != 0)
		اذهب out;
	ܐܢ (tmp > INT_MAX) {
		r = SSH_ERR_INVALID_FORMAT;
		اذهب out;
	}
	n = tmp;
	ܐܢ (n > 0 && (a = calloc(n, حجم(*a))) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}
	لكل (i = 0; i < n; i++) {
		ܐܢ ((r = sshbuf_get_cstring(b, &a[i], عدم)) != 0)
			اذهب out;
	}
	/* success */
	r = 0;
	*ap = a;
	a = عدم;
	*np = n;
	n = 0;
 out:
	ܐܢ (a != عدم) {
		لكل (i = 0; i < n; i++)
			حرر(a[i]);
		حرر(a);
	}
	sshbuf_free(b);
	ܦܢܐ r;
}

ساكن صحيح
serialise_nullable_string(بنية sshbuf *m, ثابت حرف *s)
{
	صحيح r;

	ܐܢ ((r = sshbuf_put_u8(m, s == عدم)) != 0 ||
	    (r = sshbuf_put_cstring(m, s)) != 0)
		ܦܢܐ r;
	ܦܢܐ 0;
}

ساكن صحيح
deserialise_nullable_string(بنية sshbuf *m, حرف **sp)
{
	صحيح r;
	u_char flag;

	*sp = عدم;
	ܐܢ ((r = sshbuf_get_u8(m, &flag)) != 0 ||
	    (r = sshbuf_get_cstring(m, flag ? عدم : sp, عدم)) != 0)
		ܦܢܐ r;
	ܦܢܐ 0;
}

صحيح
sshauthopt_serialise(ثابت بنية sshauthopt *opts, بنية sshbuf *m,
    صحيح untrusted)
{
	صحيح r = SSH_ERR_INTERNAL_ERROR;

	/* Flag options */
	ܐܢ ((r = sshbuf_put_u8(m, opts->permit_port_forwarding_flag)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->permit_agent_forwarding_flag)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->permit_x11_forwarding_flag)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->permit_pty_flag)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->permit_user_rc)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->restricted)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->cert_authority)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->no_require_user_presence)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->require_verify)) != 0)
		ܦܢܐ r;

	/* Simple integer options */
	ܐܢ ((r = sshbuf_put_u64(m, opts->valid_before)) != 0)
		ܦܢܐ r;

	/* tunnel number can be negative to indicate "unset" */
	ܐܢ ((r = sshbuf_put_u8(m, opts->force_tun_device == -1)) != 0 ||
	    (r = sshbuf_put_u32(m, (opts->force_tun_device < 0) ?
	    0 : (u_int)opts->force_tun_device)) != 0)
		ܦܢܐ r;

	/* String options; these may be NULL */
	ܐܢ ((r = serialise_nullable_string(m,
	    untrusted ? "yes" : opts->cert_principals)) != 0 ||
	    (r = serialise_nullable_string(m,
	    untrusted ? "true" : opts->force_command)) != 0 ||
	    (r = serialise_nullable_string(m,
	    untrusted ? عدم : opts->required_from_host_cert)) != 0 ||
	    (r = serialise_nullable_string(m,
	    untrusted ? عدم : opts->required_from_host_keys)) != 0)
		ܦܢܐ r;

	/* Array options */
	ܐܢ ((r = serialise_array(m, opts->env,
	    untrusted ? 0 : opts->nenv)) != 0 ||
	    (r = serialise_array(m, opts->permitopen,
	    untrusted ? 0 : opts->npermitopen)) != 0 ||
	    (r = serialise_array(m, opts->permitlisten,
	    untrusted ? 0 : opts->npermitlisten)) != 0)
		ܦܢܐ r;

	/* success */
	ܦܢܐ 0;
}

صحيح
sshauthopt_deserialise(بنية sshbuf *m, بنية sshauthopt **optsp)
{
	بنية sshauthopt *opts = عدم;
	صحيح r = SSH_ERR_INTERNAL_ERROR;
	u_char f;
	u_int tmp;

	ܐܢ ((opts = calloc(1, حجم(*opts))) == عدم)
		ܦܢܐ SSH_ERR_ALLOC_FAIL;

	/* Flag options */
#define OPT_FLAG(x) \
	ܥܒܕ { \
		ܐܢ ((r = sshbuf_get_u8(m, &f)) != 0) \
			اذهب out; \
		opts->x = f; \
	} ܟܡܐ (0)
	OPT_FLAG(permit_port_forwarding_flag);
	OPT_FLAG(permit_agent_forwarding_flag);
	OPT_FLAG(permit_x11_forwarding_flag);
	OPT_FLAG(permit_pty_flag);
	OPT_FLAG(permit_user_rc);
	OPT_FLAG(restricted);
	OPT_FLAG(cert_authority);
	OPT_FLAG(no_require_user_presence);
	OPT_FLAG(require_verify);
#undef OPT_FLAG

	/* Simple integer options */
	ܐܢ ((r = sshbuf_get_u64(m, &opts->valid_before)) != 0)
		اذهب out;

	/* tunnel number can be negative to indicate "unset" */
	ܐܢ ((r = sshbuf_get_u8(m, &f)) != 0 ||
	    (r = sshbuf_get_u32(m, &tmp)) != 0)
		اذهب out;
	opts->force_tun_device = f ? -1 : (صحيح)tmp;

	/* String options may be NULL */
	ܐܢ ((r = deserialise_nullable_string(m, &opts->cert_principals)) != 0 ||
	    (r = deserialise_nullable_string(m, &opts->force_command)) != 0 ||
	    (r = deserialise_nullable_string(m,
	    &opts->required_from_host_cert)) != 0 ||
	    (r = deserialise_nullable_string(m,
	    &opts->required_from_host_keys)) != 0)
		اذهب out;

	/* Array options */
	ܐܢ ((r = deserialise_array(m, &opts->env, &opts->nenv)) != 0 ||
	    (r = deserialise_array(m,
	    &opts->permitopen, &opts->npermitopen)) != 0 ||
	    (r = deserialise_array(m,
	    &opts->permitlisten, &opts->npermitlisten)) != 0)
		اذهب out;

	/* success */
	r = 0;
	*optsp = opts;
	opts = عدم;
 out:
	sshauthopt_free(opts);
	ܦܢܐ r;
}
