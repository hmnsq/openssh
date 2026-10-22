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

#شامل "includes.h"

#شامل <sys/types.h>
#شامل <sys/queue.h>

#شامل <stdlib.h>
#شامل <netdb.h>
#شامل <pwd.h>
#شامل <string.h>
#شامل <stdio.h>
#شامل <stdint.h>
#شامل <stdarg.h>
#شامل <ctype.h>
#شامل <limits.h>

#شامل "xmalloc.h"
#شامل "ssherr.h"
#شامل "log.h"
#شامل "sshbuf.h"
#شامل "misc.h"
#شامل "sshkey.h"
#شامل "match.h"
#شامل "ssh2.h"
#شامل "auth-options.h"

ایستا صحیح
dup_strings(نویسه ***dstp, size_t *ndstp, نویسه **src, size_t nsrc)
{
	نویسه **dst;
	size_t i, j;

	*dstp = پوچ;
	*ndstp = 0;

	اگر (nsrc == 0)
		بازگشت 0;
	اگر (nsrc >= SIZE_MAX / اندازه(*src) ||
	    (dst = calloc(nsrc, اندازه(*src))) == پوچ)
		بازگشت -1;
	برای (i = 0; i < nsrc; i++) {
		اگر ((dst[i] = strdup(src[i])) == پوچ) {
			برای (j = 0; j < i; j++)
				آزاد(dst[j]);
			آزاد(dst);
			بازگشت -1;
		}
	}
	/* success */
	*dstp = dst;
	*ndstp = nsrc;
	بازگشت 0;
}

#define OPTIONS_CRITICAL	1
#define OPTIONS_EXTENSIONS	2
ایستا صحیح
cert_option_list(ساختار sshauthopt *opts, ساختار sshbuf *oblob,
    u_int which, صحیح crit)
{
	نویسه *command, *allowed;
	نویسه *name = پوچ;
	ساختار sshbuf *c = پوچ, *data = پوچ;
	صحیح r, ret = -1, found;

	اگر ((c = sshbuf_fromb(oblob)) == پوچ) {
		error_f("sshbuf_fromb failed");
		برو out;
	}

	وقتی (sshbuf_len(c) > 0) {
		sshbuf_free(data);
		data = پوچ;
		اگر ((r = sshbuf_get_cstring(c, &name, پوچ)) != 0 ||
		    (r = sshbuf_froms(c, &data)) != 0) {
			error_r(r, "Unable to parse certificate options");
			برو out;
		}
		debug3("found certificate option \"%.100s\" len %zu",
		    name, sshbuf_len(data));
		found = 0;
		اگر ((which & OPTIONS_EXTENSIONS) != 0) {
			اگر (strcmp(name, "no-touch-required") == 0) {
				opts->no_require_user_presence = 1;
				found = 1;
			} وگرنه اگر (strcmp(name, "permit-X11-forwarding") == 0) {
				opts->permit_x11_forwarding_flag = 1;
				found = 1;
			} وگرنه اگر (strcmp(name,
			    "permit-agent-forwarding") == 0) {
				opts->permit_agent_forwarding_flag = 1;
				found = 1;
			} وگرنه اگر (strcmp(name,
			    "permit-port-forwarding") == 0) {
				opts->permit_port_forwarding_flag = 1;
				found = 1;
			} وگرنه اگر (strcmp(name, "permit-pty") == 0) {
				opts->permit_pty_flag = 1;
				found = 1;
			} وگرنه اگر (strcmp(name, "permit-user-rc") == 0) {
				opts->permit_user_rc = 1;
				found = 1;
			}
		}
		اگر (!found && (which & OPTIONS_CRITICAL) != 0) {
			اگر (strcmp(name, "verify-required") == 0) {
				opts->require_verify = 1;
				found = 1;
			} وگرنه اگر (strcmp(name, "force-command") == 0) {
				اگر ((r = sshbuf_get_cstring(data, &command,
				    پوچ)) != 0) {
					error_r(r, "Unable to parse \"%s\" "
					    "section", name);
					برو out;
				}
				اگر (opts->force_command != پوچ) {
					error("Certificate has multiple "
					    "force-command options");
					آزاد(command);
					برو out;
				}
				opts->force_command = command;
				found = 1;
			} وگرنه اگر (strcmp(name, "source-address") == 0) {
				اگر ((r = sshbuf_get_cstring(data, &allowed,
				    پوچ)) != 0) {
					error_r(r, "Unable to parse \"%s\" "
					    "section", name);
					برو out;
				}
				اگر (opts->required_from_host_cert != پوچ) {
					error("Certificate has multiple "
					    "source-address options");
					آزاد(allowed);
					برو out;
				}
				/* Check syntax */
				اگر (addr_match_cidr_list(پوچ, allowed) == -1) {
					error("Certificate source-address "
					    "contents invalid");
					آزاد(allowed);
					برو out;
				}
				opts->required_from_host_cert = allowed;
				found = 1;
			}
		}

		اگر (!found) {
			اگر (crit) {
				error("Certificate critical option \"%s\" "
				    "is not supported", name);
				برو out;
			} وگرنه {
				logit("Certificate extension \"%s\" "
				    "is not supported", name);
			}
		} وگرنه اگر (sshbuf_len(data) != 0) {
			error("Certificate option \"%s\" corrupt "
			    "(extra data)", name);
			برو out;
		}
		آزاد(name);
		name = پوچ;
	}
	/* successfully parsed all options */
	ret = 0;

 out:
	آزاد(name);
	sshbuf_free(data);
	sshbuf_free(c);
	بازگشت ret;
}

ساختار sshauthopt *
sshauthopt_new(تهی)
{
	ساختار sshauthopt *ret;

	اگر ((ret = calloc(1, اندازه(*ret))) == پوچ)
		بازگشت پوچ;
	ret->force_tun_device = -1;
	بازگشت ret;
}

تهی
sshauthopt_free(ساختار sshauthopt *opts)
{
	size_t i;

	اگر (opts == پوچ)
		بازگشت;

	آزاد(opts->cert_principals);
	آزاد(opts->force_command);
	آزاد(opts->required_from_host_cert);
	آزاد(opts->required_from_host_کلیدها);

	برای (i = 0; i < opts->nenv; i++)
		آزاد(opts->env[i]);
	آزاد(opts->env);

	برای (i = 0; i < opts->npermitopen; i++)
		آزاد(opts->permitopen[i]);
	آزاد(opts->permitopen);

	برای (i = 0; i < opts->npermitlisten; i++)
		آزاد(opts->permitlisten[i]);
	آزاد(opts->permitlisten);

	freezero(opts, اندازه(*opts));
}

ساختار sshauthopt *
sshauthopt_new_with_کلیدها_defaults(تهی)
{
	ساختار sshauthopt *ret = پوچ;

	اگر ((ret = sshauthopt_new()) == پوچ)
		بازگشت پوچ;

	/* Defaults for authorized_keys flags */
	ret->permit_port_forwarding_flag = 1;
	ret->permit_agent_forwarding_flag = 1;
	ret->permit_x11_forwarding_flag = 1;
	ret->permit_pty_flag = 1;
	ret->permit_user_rc = 1;
	بازگشت ret;
}

/*
 * Parse and record a permitopen/permitlisten directive.
 * Return 0 on success. Return -1 on failure and sets *errstrp to error reason.
 */
ایستا صحیح
handle_permit(ثابت نویسه **optsp, صحیح allow_bare_port,
    نویسه ***permitsp, size_t *npermitsp, ثابت نویسه **errstrp)
{
	نویسه *opt, *tmp, *cp, *host, **permits = *permitsp;
	size_t npermits = *npermitsp;
	ثابت نویسه *errstr = "unknown error";

	اگر (npermits > SSH_AUTHOPT_PERMIT_MAX) {
		*errstrp = "too many permission directives";
		بازگشت -1;
	}
	اگر ((opt = opt_dequote(optsp, &errstr)) == پوچ) {
		بازگشت -1;
	}
	اگر (allow_bare_port && strchr(opt, ':') == پوچ) {
		/*
		 * Allow a bare port number in permitlisten to indicate a
		 * listen_host wildcard.
		 */
		اگر (asprintf(&tmp, "*:%s", opt) == -1) {
			آزاد(opt);
			*errstrp = "memory allocation failed";
			بازگشت -1;
		}
		آزاد(opt);
		opt = tmp;
	}
	اگر ((tmp = strdup(opt)) == پوچ) {
		آزاد(opt);
		*errstrp = "memory allocation failed";
		بازگشت -1;
	}
	cp = tmp;
	/* validate syntax before recording it. */
	host = hpdelim2(&cp, پوچ);
	اگر (host == پوچ || strlen(host) >= NI_MAXHOST) {
		آزاد(tmp);
		آزاد(opt);
		*errstrp = "invalid permission hostname";
		بازگشت -1;
	}
	/*
	 * don't want to use permitopen_port to avoid
	 * dependency on channels.[ch] here.
	 */
	اگر (cp == پوچ ||
	    (strcmp(cp, "*") != 0 && a2port(cp) <= 0)) {
		آزاد(tmp);
		آزاد(opt);
		*errstrp = "invalid permission port";
		بازگشت -1;
	}
	/* XXX - add streamlocal support */
	آزاد(tmp);
	/* Record it */
	اگر ((permits = recallocarray(permits, npermits, npermits + 1,
	    اندازه(*permits))) == پوچ) {
		آزاد(opt);
		/* NB. don't update *permitsp if alloc fails */
		*errstrp = "memory allocation failed";
		بازگشت -1;
	}
	permits[npermits++] = opt;
	*permitsp = permits;
	*npermitsp = npermits;
	بازگشت 0;
}

ساختار sshauthopt *
sshauthopt_parse(ثابت نویسه *opts, ثابت نویسه **errstrp)
{
	نویسه **oarray, *opt, *cp, *tmp;
	صحیح r;
	ساختار sshauthopt *ret = پوچ;
	ثابت نویسه *errstr = "unknown error";
	uint64_t valid_before;
	size_t i, l;

	اگر (errstrp != پوچ)
		*errstrp = پوچ;
	اگر ((ret = sshauthopt_new_with_کلیدها_defaults()) == پوچ)
		برو alloc_fail;

	اگر (opts == پوچ)
		بازگشت ret;

	وقتی (*opts && *opts != ' ' && *opts != '\t') {
		/* flag options */
		اگر ((r = opt_flag("restrict", 0, &opts)) != -1) {
			ret->restricted = 1;
			ret->permit_port_forwarding_flag = 0;
			ret->permit_agent_forwarding_flag = 0;
			ret->permit_x11_forwarding_flag = 0;
			ret->permit_pty_flag = 0;
			ret->permit_user_rc = 0;
		} وگرنه اگر ((r = opt_flag("cert-authority", 0, &opts)) != -1) {
			ret->cert_authority = r;
		} وگرنه اگر ((r = opt_flag("port-forwarding", 1, &opts)) != -1) {
			ret->permit_port_forwarding_flag = r == 1;
		} وگرنه اگر ((r = opt_flag("agent-forwarding", 1, &opts)) != -1) {
			ret->permit_agent_forwarding_flag = r == 1;
		} وگرنه اگر ((r = opt_flag("x11-forwarding", 1, &opts)) != -1) {
			ret->permit_x11_forwarding_flag = r == 1;
		} وگرنه اگر ((r = opt_flag("touch-required", 1, &opts)) != -1) {
			ret->no_require_user_presence = r != 1; /* NB. flip */
		} وگرنه اگر ((r = opt_flag("verify-required", 1, &opts)) != -1) {
			ret->require_verify = r == 1;
		} وگرنه اگر ((r = opt_flag("pty", 1, &opts)) != -1) {
			ret->permit_pty_flag = r == 1;
		} وگرنه اگر ((r = opt_flag("user-rc", 1, &opts)) != -1) {
			ret->permit_user_rc = r == 1;
		} وگرنه اگر (opt_match(&opts, "command")) {
			اگر (ret->force_command != پوچ) {
				errstr = "multiple \"command\" clauses";
				برو fail;
			}
			ret->force_command = opt_dequote(&opts, &errstr);
			اگر (ret->force_command == پوچ)
				برو fail;
		} وگرنه اگر (opt_match(&opts, "principals")) {
			اگر (ret->cert_principals != پوچ) {
				errstr = "multiple \"principals\" clauses";
				برو fail;
			}
			ret->cert_principals = opt_dequote(&opts, &errstr);
			اگر (ret->cert_principals == پوچ)
				برو fail;
		} وگرنه اگر (opt_match(&opts, "from")) {
			اگر (ret->required_from_host_کلیدها != پوچ) {
				errstr = "multiple \"from\" clauses";
				برو fail;
			}
			ret->required_from_host_کلیدها = opt_dequote(&opts,
			    &errstr);
			اگر (ret->required_from_host_کلیدها == پوچ)
				برو fail;
		} وگرنه اگر (opt_match(&opts, "expiry-time")) {
			اگر ((opt = opt_dequote(&opts, &errstr)) == پوچ)
				برو fail;
			اگر (parse_absolute_time(opt, &valid_before) != 0 ||
			    valid_before == 0) {
				آزاد(opt);
				errstr = "invalid expires time";
				برو fail;
			}
			آزاد(opt);
			اگر (ret->valid_before == 0 ||
			    valid_before < ret->valid_before)
				ret->valid_before = valid_before;
		} وگرنه اگر (opt_match(&opts, "environment")) {
			اگر (ret->nenv > SSH_AUTHOPT_ENV_MAX) {
				errstr = "too many environment strings";
				برو fail;
			}
			اگر ((opt = opt_dequote(&opts, &errstr)) == پوچ)
				برو fail;
			/* env name must be alphanumeric and followed by '=' */
			اگر ((tmp = strchr(opt, '=')) == پوچ) {
				آزاد(opt);
				errstr = "invalid environment string";
				برو fail;
			}
			اگر ((cp = strdup(opt)) == پوچ) {
				آزاد(opt);
				برو alloc_fail;
			}
			l = (size_t)(tmp - opt);
			cp[l] = '\0'; /* truncate at '=' */
			اگر (!valid_env_name(cp)) {
				آزاد(cp);
				آزاد(opt);
				errstr = "invalid environment string";
				برو fail;
			}
			/* Check for duplicates; XXX O(n*log(n)) */
			برای (i = 0; i < ret->nenv; i++) {
				اگر (strncmp(ret->env[i], cp, l) == 0 &&
				    ret->env[i][l] == '=')
					بشکن;
			}
			آزاد(cp);
			/* First match wins */
			اگر (i >= ret->nenv) {
				/* Append it. */
				oarray = ret->env;
				اگر ((ret->env = recallocarray(ret->env,
				    ret->nenv, ret->nenv + 1,
				    اندازه(*ret->env))) == پوچ) {
					آزاد(opt);
					/* put it back for cleanup */
					ret->env = oarray;
					برو alloc_fail;
				}
				ret->env[ret->nenv++] = opt;
				opt = پوچ; /* transferred */
			}
			آزاد(opt);
		} وگرنه اگر (opt_match(&opts, "permitopen")) {
			اگر (handle_permit(&opts, 0, &ret->permitopen,
			    &ret->npermitopen, &errstr) != 0)
				برو fail;
		} وگرنه اگر (opt_match(&opts, "permitlisten")) {
			اگر (handle_permit(&opts, 1, &ret->permitlisten,
			    &ret->npermitlisten, &errstr) != 0)
				برو fail;
		} وگرنه اگر (opt_match(&opts, "tunnel")) {
			اگر ((opt = opt_dequote(&opts, &errstr)) == پوچ)
				برو fail;
			ret->force_tun_device = a2tun(opt, پوچ);
			آزاد(opt);
			اگر (ret->force_tun_device == SSH_TUNID_ERR) {
				errstr = "invalid tun device";
				برو fail;
			}
		}
		/*
		 * Skip the comma, and move to the next option
		 * (or break out if there are no more).
		 */
		اگر (*opts == '\0' || *opts == ' ' || *opts == '\t')
			بشکن;		/* End of options. */
		/* Anything other than a comma is an unknown option */
		اگر (*opts != ',') {
			errstr = "unknown key option";
			برو fail;
		}
		opts++;
		اگر (*opts == '\0') {
			errstr = "unexpected end-of-options";
			برو fail;
		}
	}

	/* success */
	اگر (errstrp != پوچ)
		*errstrp = پوچ;
	بازگشت ret;

alloc_fail:
	errstr = "memory allocation failed";
fail:
	sshauthopt_free(ret);
	اگر (errstrp != پوچ)
		*errstrp = errstr;
	بازگشت پوچ;
}

ساختار sshauthopt *
sshauthopt_from_cert(ساختار sshkey *k)
{
	ساختار sshauthopt *ret;

	اگر (k == پوچ || !sshkey_type_is_cert(k->type) || k->cert == پوچ ||
	    k->cert->type != SSH2_CERT_TYPE_USER)
		بازگشت پوچ;

	اگر ((ret = sshauthopt_new()) == پوچ)
		بازگشت پوچ;

	/* Handle options and critical extensions separately */
	اگر (cert_option_list(ret, k->cert->critical,
	    OPTIONS_CRITICAL, 1) == -1) {
		sshauthopt_free(ret);
		بازگشت پوچ;
	}
	اگر (cert_option_list(ret, k->cert->extensions,
	    OPTIONS_EXTENSIONS, 0) == -1) {
		sshauthopt_free(ret);
		بازگشت پوچ;
	}
	/* success */
	بازگشت ret;
}

/*
 * Merges "additional" options to "primary" and returns the result.
 * NB. Some options from primary have primacy.
 */
ساختار sshauthopt *
sshauthopt_merge(ثابت ساختار sshauthopt *primary,
    ثابت ساختار sshauthopt *additional, ثابت نویسه **errstrp)
{
	ساختار sshauthopt *ret;
	ثابت نویسه *errstr = "internal error";
	ثابت نویسه *tmp;

	اگر (errstrp != پوچ)
		*errstrp = پوچ;

	اگر ((ret = sshauthopt_new()) == پوچ)
		برو alloc_fail;

	/* cert_authority and cert_principals are cleared in result */

	/* Prefer access lists from primary. */
	/* XXX err is both set and mismatch? */
	tmp = primary->required_from_host_cert;
	اگر (tmp == پوچ)
		tmp = additional->required_from_host_cert;
	اگر (tmp != پوچ && (ret->required_from_host_cert = strdup(tmp)) == پوچ)
		برو alloc_fail;
	tmp = primary->required_from_host_کلیدها;
	اگر (tmp == پوچ)
		tmp = additional->required_from_host_کلیدها;
	اگر (tmp != پوچ && (ret->required_from_host_کلیدها = strdup(tmp)) == پوچ)
		برو alloc_fail;

	/*
	 * force_tun_device, permitopen/permitlisten and environment all
	 * prefer the primary.
	 */
	ret->force_tun_device = primary->force_tun_device;
	اگر (ret->force_tun_device == -1)
		ret->force_tun_device = additional->force_tun_device;
	اگر (primary->nenv > 0) {
		اگر (dup_strings(&ret->env, &ret->nenv,
		    primary->env, primary->nenv) != 0)
			برو alloc_fail;
	} وگرنه اگر (additional->nenv) {
		اگر (dup_strings(&ret->env, &ret->nenv,
		    additional->env, additional->nenv) != 0)
			برو alloc_fail;
	}
	اگر (primary->npermitopen > 0) {
		اگر (dup_strings(&ret->permitopen, &ret->npermitopen,
		    primary->permitopen, primary->npermitopen) != 0)
			برو alloc_fail;
	} وگرنه اگر (additional->npermitopen > 0) {
		اگر (dup_strings(&ret->permitopen, &ret->npermitopen,
		    additional->permitopen, additional->npermitopen) != 0)
			برو alloc_fail;
	}

	اگر (primary->npermitlisten > 0) {
		اگر (dup_strings(&ret->permitlisten, &ret->npermitlisten,
		    primary->permitlisten, primary->npermitlisten) != 0)
			برو alloc_fail;
	} وگرنه اگر (additional->npermitlisten > 0) {
		اگر (dup_strings(&ret->permitlisten, &ret->npermitlisten,
		    additional->permitlisten, additional->npermitlisten) != 0)
			برو alloc_fail;
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
	اگر (primary->valid_before != 0)
		ret->valid_before = primary->valid_before;
	اگر (additional->valid_before != 0 &&
	    additional->valid_before < ret->valid_before)
		ret->valid_before = additional->valid_before;

	/*
	 * When both multiple forced-command are specified, only
	 * proceed if they are identical, otherwise fail.
	 */
	اگر (primary->force_command != پوچ &&
	    additional->force_command != پوچ) {
		اگر (strcmp(primary->force_command,
		    additional->force_command) == 0) {
			/* ok */
			ret->force_command = strdup(primary->force_command);
			اگر (ret->force_command == پوچ)
				برو alloc_fail;
		} وگرنه {
			errstr = "forced command options do not match";
			برو fail;
		}
	} وگرنه اگر (primary->force_command != پوچ) {
		اگر ((ret->force_command = strdup(
		    primary->force_command)) == پوچ)
			برو alloc_fail;
	} وگرنه اگر (additional->force_command != پوچ) {
		اگر ((ret->force_command = strdup(
		    additional->force_command)) == پوچ)
			برو alloc_fail;
	}
	/* success */
	اگر (errstrp != پوچ)
		*errstrp = پوچ;
	بازگشت ret;

 alloc_fail:
	errstr = "memory allocation failed";
 fail:
	اگر (errstrp != پوچ)
		*errstrp = errstr;
	sshauthopt_free(ret);
	بازگشت پوچ;
}

/*
 * Copy options
 */
ساختار sshauthopt *
sshauthopt_copy(ثابت ساختار sshauthopt *orig)
{
	ساختار sshauthopt *ret;

	اگر ((ret = sshauthopt_new()) == پوچ)
		بازگشت پوچ;

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
	انجامبده { \
		اگر (orig->x != پوچ && (ret->x = strdup(orig->x)) == پوچ) { \
			sshauthopt_free(ret); \
			بازگشت پوچ; \
		} \
	} وقتی (0)
	OPTSTRING(cert_principals);
	OPTSTRING(force_command);
	OPTSTRING(required_from_host_cert);
	OPTSTRING(required_from_host_کلیدها);
#undef OPTSTRING

	اگر (dup_strings(&ret->env, &ret->nenv, orig->env, orig->nenv) != 0 ||
	    dup_strings(&ret->permitopen, &ret->npermitopen,
	    orig->permitopen, orig->npermitopen) != 0 ||
	    dup_strings(&ret->permitlisten, &ret->npermitlisten,
	    orig->permitlisten, orig->npermitlisten) != 0) {
		sshauthopt_free(ret);
		بازگشت پوچ;
	}
	بازگشت ret;
}

ایستا صحیح
serialise_array(ساختار sshbuf *m, نویسه **a, size_t n)
{
	ساختار sshbuf *b;
	size_t i;
	صحیح r = SSH_ERR_INTERNAL_ERROR;

	اگر (n > INT_MAX)
		بازگشت SSH_ERR_INTERNAL_ERROR;

	اگر ((b = sshbuf_new()) == پوچ) {
		بازگشت SSH_ERR_ALLOC_FAIL;
	}
	برای (i = 0; i < n; i++) {
		اگر ((r = sshbuf_put_cstring(b, a[i])) != 0)
			برو out;
	}
	اگر ((r = sshbuf_put_u32(m, n)) != 0 ||
	    (r = sshbuf_put_stringb(m, b)) != 0)
		برو out;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	بازگشت r;
}

ایستا صحیح
deserialise_array(ساختار sshbuf *m, نویسه ***ap, size_t *np)
{
	نویسه **a = پوچ;
	size_t i, n = 0;
	ساختار sshbuf *b = پوچ;
	u_int tmp;
	صحیح r = SSH_ERR_INTERNAL_ERROR;

	اگر ((r = sshbuf_get_u32(m, &tmp)) != 0 ||
	    (r = sshbuf_froms(m, &b)) != 0)
		برو out;
	اگر (tmp > INT_MAX) {
		r = SSH_ERR_INVALID_FORMAT;
		برو out;
	}
	n = tmp;
	اگر (n > 0 && (a = calloc(n, اندازه(*a))) == پوچ) {
		r = SSH_ERR_ALLOC_FAIL;
		برو out;
	}
	برای (i = 0; i < n; i++) {
		اگر ((r = sshbuf_get_cstring(b, &a[i], پوچ)) != 0)
			برو out;
	}
	/* success */
	r = 0;
	*ap = a;
	a = پوچ;
	*np = n;
	n = 0;
 out:
	اگر (a != پوچ) {
		برای (i = 0; i < n; i++)
			آزاد(a[i]);
		آزاد(a);
	}
	sshbuf_free(b);
	بازگشت r;
}

ایستا صحیح
serialise_nullable_string(ساختار sshbuf *m, ثابت نویسه *s)
{
	صحیح r;

	اگر ((r = sshbuf_put_u8(m, s == پوچ)) != 0 ||
	    (r = sshbuf_put_cstring(m, s)) != 0)
		بازگشت r;
	بازگشت 0;
}

ایستا صحیح
deserialise_nullable_string(ساختار sshbuf *m, نویسه **sp)
{
	صحیح r;
	u_char flag;

	*sp = پوچ;
	اگر ((r = sshbuf_get_u8(m, &flag)) != 0 ||
	    (r = sshbuf_get_cstring(m, flag ? پوچ : sp, پوچ)) != 0)
		بازگشت r;
	بازگشت 0;
}

صحیح
sshauthopt_serialise(ثابت ساختار sshauthopt *opts, ساختار sshbuf *m,
    صحیح untrusted)
{
	صحیح r = SSH_ERR_INTERNAL_ERROR;

	/* Flag options */
	اگر ((r = sshbuf_put_u8(m, opts->permit_port_forwarding_flag)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->permit_agent_forwarding_flag)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->permit_x11_forwarding_flag)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->permit_pty_flag)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->permit_user_rc)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->restricted)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->cert_authority)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->no_require_user_presence)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->require_verify)) != 0)
		بازگشت r;

	/* Simple integer options */
	اگر ((r = sshbuf_put_u64(m, opts->valid_before)) != 0)
		بازگشت r;

	/* tunnel number can be negative to indicate "unset" */
	اگر ((r = sshbuf_put_u8(m, opts->force_tun_device == -1)) != 0 ||
	    (r = sshbuf_put_u32(m, (opts->force_tun_device < 0) ?
	    0 : (u_int)opts->force_tun_device)) != 0)
		بازگشت r;

	/* String options; these may be NULL */
	اگر ((r = serialise_nullable_string(m,
	    untrusted ? "yes" : opts->cert_principals)) != 0 ||
	    (r = serialise_nullable_string(m,
	    untrusted ? "true" : opts->force_command)) != 0 ||
	    (r = serialise_nullable_string(m,
	    untrusted ? پوچ : opts->required_from_host_cert)) != 0 ||
	    (r = serialise_nullable_string(m,
	    untrusted ? پوچ : opts->required_from_host_کلیدها)) != 0)
		بازگشت r;

	/* Array options */
	اگر ((r = serialise_array(m, opts->env,
	    untrusted ? 0 : opts->nenv)) != 0 ||
	    (r = serialise_array(m, opts->permitopen,
	    untrusted ? 0 : opts->npermitopen)) != 0 ||
	    (r = serialise_array(m, opts->permitlisten,
	    untrusted ? 0 : opts->npermitlisten)) != 0)
		بازگشت r;

	/* success */
	بازگشت 0;
}

صحیح
sshauthopt_deserialise(ساختار sshbuf *m, ساختار sshauthopt **optsp)
{
	ساختار sshauthopt *opts = پوچ;
	صحیح r = SSH_ERR_INTERNAL_ERROR;
	u_char f;
	u_int tmp;

	اگر ((opts = calloc(1, اندازه(*opts))) == پوچ)
		بازگشت SSH_ERR_ALLOC_FAIL;

	/* Flag options */
#define OPT_FLAG(x) \
	انجامبده { \
		اگر ((r = sshbuf_get_u8(m, &f)) != 0) \
			برو out; \
		opts->x = f; \
	} وقتی (0)
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
	اگر ((r = sshbuf_get_u64(m, &opts->valid_before)) != 0)
		برو out;

	/* tunnel number can be negative to indicate "unset" */
	اگر ((r = sshbuf_get_u8(m, &f)) != 0 ||
	    (r = sshbuf_get_u32(m, &tmp)) != 0)
		برو out;
	opts->force_tun_device = f ? -1 : (صحیح)tmp;

	/* String options may be NULL */
	اگر ((r = deserialise_nullable_string(m, &opts->cert_principals)) != 0 ||
	    (r = deserialise_nullable_string(m, &opts->force_command)) != 0 ||
	    (r = deserialise_nullable_string(m,
	    &opts->required_from_host_cert)) != 0 ||
	    (r = deserialise_nullable_string(m,
	    &opts->required_from_host_کلیدها)) != 0)
		برو out;

	/* Array options */
	اگر ((r = deserialise_array(m, &opts->env, &opts->nenv)) != 0 ||
	    (r = deserialise_array(m,
	    &opts->permitopen, &opts->npermitopen)) != 0 ||
	    (r = deserialise_array(m,
	    &opts->permitlisten, &opts->npermitlisten)) != 0)
		برو out;

	/* success */
	r = 0;
	*optsp = opts;
	opts = پوچ;
 out:
	sshauthopt_free(opts);
	بازگشت r;
}
