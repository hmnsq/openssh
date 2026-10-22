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

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <sys/queue.h>

#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <netdb.h>
#અન્તર્ભાવ <pwd.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <stdint.h>
#અન્તર્ભાવ <stdarg.h>
#અન્તર્ભાવ <ctype.h>
#અન્તર્ભાવ <limits.h>

#અન્તર્ભાવ "xmalloc.h"
#અન્તર્ભાવ "ssherr.h"
#અન્તર્ભાવ "log.h"
#અન્તર્ભાવ "sshbuf.h"
#અન્તર્ભાવ "misc.h"
#અન્તર્ભાવ "sshkey.h"
#અન્તર્ભાવ "match.h"
#અન્તર્ભાવ "ssh2.h"
#અન્તર્ભાવ "auth-options.h"

સ્થિર પૂર્ણાંક
dup_strings(અક્ષર ***dstp, size_t *ndstp, અક્ષર **src, size_t nsrc)
{
	અક્ષર **dst;
	size_t i, j;

	*dstp = ખાલી;
	*ndstp = 0;

	જો (nsrc == 0)
		પાછા 0;
	જો (nsrc >= SIZE_MAX / કદ(*src) ||
	    (dst = calloc(nsrc, કદ(*src))) == ખાલી)
		પાછા -1;
	માટે (i = 0; i < nsrc; i++) {
		જો ((dst[i] = strdup(src[i])) == ખાલી) {
			માટે (j = 0; j < i; j++)
				મુક્ત(dst[j]);
			મુક્ત(dst);
			પાછા -1;
		}
	}
	/* success */
	*dstp = dst;
	*ndstp = nsrc;
	પાછા 0;
}

#define OPTIONS_CRITICAL	1
#define OPTIONS_EXTENSIONS	2
સ્થિર પૂર્ણાંક
cert_option_list(સંરચના sshauthopt *opts, સંરચના sshbuf *oblob,
    u_int which, પૂર્ણાંક crit)
{
	અક્ષર *command, *allowed;
	અક્ષર *name = ખાલી;
	સંરચના sshbuf *c = ખાલી, *data = ખાલી;
	પૂર્ણાંક r, ret = -1, found;

	જો ((c = sshbuf_fromb(oblob)) == ખાલી) {
		error_f("sshbuf_fromb failed");
		જાઓ out;
	}

	જ્યારે (sshbuf_len(c) > 0) {
		sshbuf_free(data);
		data = ખાલી;
		જો ((r = sshbuf_get_cstring(c, &name, ખાલી)) != 0 ||
		    (r = sshbuf_froms(c, &data)) != 0) {
			error_r(r, "Unable to parse certificate options");
			જાઓ out;
		}
		debug3("found certificate option \"%.100s\" len %zu",
		    name, sshbuf_len(data));
		found = 0;
		જો ((which & OPTIONS_EXTENSIONS) != 0) {
			જો (strcmp(name, "no-touch-required") == 0) {
				opts->no_require_user_presence = 1;
				found = 1;
			} નહીંતર જો (strcmp(name, "permit-X11-forwarding") == 0) {
				opts->permit_x11_forwarding_flag = 1;
				found = 1;
			} નહીંતર જો (strcmp(name,
			    "permit-agent-forwarding") == 0) {
				opts->permit_agent_forwarding_flag = 1;
				found = 1;
			} નહીંતર જો (strcmp(name,
			    "permit-port-forwarding") == 0) {
				opts->permit_port_forwarding_flag = 1;
				found = 1;
			} નહીંતર જો (strcmp(name, "permit-pty") == 0) {
				opts->permit_pty_flag = 1;
				found = 1;
			} નહીંતર જો (strcmp(name, "permit-user-rc") == 0) {
				opts->permit_user_rc = 1;
				found = 1;
			}
		}
		જો (!found && (which & OPTIONS_CRITICAL) != 0) {
			જો (strcmp(name, "verify-required") == 0) {
				opts->require_verify = 1;
				found = 1;
			} નહીંતર જો (strcmp(name, "force-command") == 0) {
				જો ((r = sshbuf_get_cstring(data, &command,
				    ખાલી)) != 0) {
					error_r(r, "Unable to parse \"%s\" "
					    "section", name);
					જાઓ out;
				}
				જો (opts->force_command != ખાલી) {
					error("Certificate has multiple "
					    "force-command options");
					મુક્ત(command);
					જાઓ out;
				}
				opts->force_command = command;
				found = 1;
			} નહીંતર જો (strcmp(name, "source-address") == 0) {
				જો ((r = sshbuf_get_cstring(data, &allowed,
				    ખાલી)) != 0) {
					error_r(r, "Unable to parse \"%s\" "
					    "section", name);
					જાઓ out;
				}
				જો (opts->required_from_host_cert != ખાલી) {
					error("Certificate has multiple "
					    "source-address options");
					મુક્ત(allowed);
					જાઓ out;
				}
				/* Check syntax */
				જો (addr_match_cidr_list(ખાલી, allowed) == -1) {
					error("Certificate source-address "
					    "contents invalid");
					મુક્ત(allowed);
					જાઓ out;
				}
				opts->required_from_host_cert = allowed;
				found = 1;
			}
		}

		જો (!found) {
			જો (crit) {
				error("Certificate critical option \"%s\" "
				    "is not supported", name);
				જાઓ out;
			} નહીંતર {
				logit("Certificate extension \"%s\" "
				    "is not supported", name);
			}
		} નહીંતર જો (sshbuf_len(data) != 0) {
			error("Certificate option \"%s\" corrupt "
			    "(extra data)", name);
			જાઓ out;
		}
		મુક્ત(name);
		name = ખાલી;
	}
	/* successfully parsed all options */
	ret = 0;

 out:
	મુક્ત(name);
	sshbuf_free(data);
	sshbuf_free(c);
	પાછા ret;
}

સંરચના sshauthopt *
sshauthopt_new(શૂન્ય)
{
	સંરચના sshauthopt *ret;

	જો ((ret = calloc(1, કદ(*ret))) == ખાલી)
		પાછા ખાલી;
	ret->force_tun_device = -1;
	પાછા ret;
}

શૂન્ય
sshauthopt_free(સંરચના sshauthopt *opts)
{
	size_t i;

	જો (opts == ખાલી)
		પાછા;

	મુક્ત(opts->cert_principals);
	મુક્ત(opts->force_command);
	મુક્ત(opts->required_from_host_cert);
	મુક્ત(opts->required_from_host_ચાવીઓ);

	માટે (i = 0; i < opts->nenv; i++)
		મુક્ત(opts->env[i]);
	મુક્ત(opts->env);

	માટે (i = 0; i < opts->npermitopen; i++)
		મુક્ત(opts->permitopen[i]);
	મુક્ત(opts->permitopen);

	માટે (i = 0; i < opts->npermitlisten; i++)
		મુક્ત(opts->permitlisten[i]);
	મુક્ત(opts->permitlisten);

	freezero(opts, કદ(*opts));
}

સંરચના sshauthopt *
sshauthopt_new_with_ચાવીઓ_defaults(શૂન્ય)
{
	સંરચના sshauthopt *ret = ખાલી;

	જો ((ret = sshauthopt_new()) == ખાલી)
		પાછા ખાલી;

	/* Defaults for authorized_keys flags */
	ret->permit_port_forwarding_flag = 1;
	ret->permit_agent_forwarding_flag = 1;
	ret->permit_x11_forwarding_flag = 1;
	ret->permit_pty_flag = 1;
	ret->permit_user_rc = 1;
	પાછા ret;
}

/*
 * Parse and record a permitopen/permitlisten directive.
 * Return 0 on success. Return -1 on failure and sets *errstrp to error reason.
 */
સ્થિર પૂર્ણાંક
handle_permit(અચલ અક્ષર **optsp, પૂર્ણાંક allow_bare_port,
    અક્ષર ***permitsp, size_t *npermitsp, અચલ અક્ષર **errstrp)
{
	અક્ષર *opt, *tmp, *cp, *host, **permits = *permitsp;
	size_t npermits = *npermitsp;
	અચલ અક્ષર *errstr = "unknown error";

	જો (npermits > SSH_AUTHOPT_PERMIT_MAX) {
		*errstrp = "too many permission directives";
		પાછા -1;
	}
	જો ((opt = opt_dequote(optsp, &errstr)) == ખાલી) {
		પાછા -1;
	}
	જો (allow_bare_port && strchr(opt, ':') == ખાલી) {
		/*
		 * Allow a bare port number in permitlisten to indicate a
		 * listen_host wildcard.
		 */
		જો (asprintf(&tmp, "*:%s", opt) == -1) {
			મુક્ત(opt);
			*errstrp = "memory allocation failed";
			પાછા -1;
		}
		મુક્ત(opt);
		opt = tmp;
	}
	જો ((tmp = strdup(opt)) == ખાલી) {
		મુક્ત(opt);
		*errstrp = "memory allocation failed";
		પાછા -1;
	}
	cp = tmp;
	/* validate syntax before recording it. */
	host = hpdelim2(&cp, ખાલી);
	જો (host == ખાલી || strlen(host) >= NI_MAXHOST) {
		મુક્ત(tmp);
		મુક્ત(opt);
		*errstrp = "invalid permission hostname";
		પાછા -1;
	}
	/*
	 * don't want to use permitopen_port to avoid
	 * dependency on channels.[ch] here.
	 */
	જો (cp == ખાલી ||
	    (strcmp(cp, "*") != 0 && a2port(cp) <= 0)) {
		મુક્ત(tmp);
		મુક્ત(opt);
		*errstrp = "invalid permission port";
		પાછા -1;
	}
	/* XXX - add streamlocal support */
	મુક્ત(tmp);
	/* Record it */
	જો ((permits = recallocarray(permits, npermits, npermits + 1,
	    કદ(*permits))) == ખાલી) {
		મુક્ત(opt);
		/* NB. don't update *permitsp if alloc fails */
		*errstrp = "memory allocation failed";
		પાછા -1;
	}
	permits[npermits++] = opt;
	*permitsp = permits;
	*npermitsp = npermits;
	પાછા 0;
}

સંરચના sshauthopt *
sshauthopt_parse(અચલ અક્ષર *opts, અચલ અક્ષર **errstrp)
{
	અક્ષર **oarray, *opt, *cp, *tmp;
	પૂર્ણાંક r;
	સંરચના sshauthopt *ret = ખાલી;
	અચલ અક્ષર *errstr = "unknown error";
	uint64_t valid_before;
	size_t i, l;

	જો (errstrp != ખાલી)
		*errstrp = ખાલી;
	જો ((ret = sshauthopt_new_with_ચાવીઓ_defaults()) == ખાલી)
		જાઓ alloc_fail;

	જો (opts == ખાલી)
		પાછા ret;

	જ્યારે (*opts && *opts != ' ' && *opts != '\t') {
		/* flag options */
		જો ((r = opt_flag("restrict", 0, &opts)) != -1) {
			ret->restricted = 1;
			ret->permit_port_forwarding_flag = 0;
			ret->permit_agent_forwarding_flag = 0;
			ret->permit_x11_forwarding_flag = 0;
			ret->permit_pty_flag = 0;
			ret->permit_user_rc = 0;
		} નહીંતર જો ((r = opt_flag("cert-authority", 0, &opts)) != -1) {
			ret->cert_authority = r;
		} નહીંતર જો ((r = opt_flag("port-forwarding", 1, &opts)) != -1) {
			ret->permit_port_forwarding_flag = r == 1;
		} નહીંતર જો ((r = opt_flag("agent-forwarding", 1, &opts)) != -1) {
			ret->permit_agent_forwarding_flag = r == 1;
		} નહીંતર જો ((r = opt_flag("x11-forwarding", 1, &opts)) != -1) {
			ret->permit_x11_forwarding_flag = r == 1;
		} નહીંતર જો ((r = opt_flag("touch-required", 1, &opts)) != -1) {
			ret->no_require_user_presence = r != 1; /* NB. flip */
		} નહીંતર જો ((r = opt_flag("verify-required", 1, &opts)) != -1) {
			ret->require_verify = r == 1;
		} નહીંતર જો ((r = opt_flag("pty", 1, &opts)) != -1) {
			ret->permit_pty_flag = r == 1;
		} નહીંતર જો ((r = opt_flag("user-rc", 1, &opts)) != -1) {
			ret->permit_user_rc = r == 1;
		} નહીંતર જો (opt_match(&opts, "command")) {
			જો (ret->force_command != ખાલી) {
				errstr = "multiple \"command\" clauses";
				જાઓ fail;
			}
			ret->force_command = opt_dequote(&opts, &errstr);
			જો (ret->force_command == ખાલી)
				જાઓ fail;
		} નહીંતર જો (opt_match(&opts, "principals")) {
			જો (ret->cert_principals != ખાલી) {
				errstr = "multiple \"principals\" clauses";
				જાઓ fail;
			}
			ret->cert_principals = opt_dequote(&opts, &errstr);
			જો (ret->cert_principals == ખાલી)
				જાઓ fail;
		} નહીંતર જો (opt_match(&opts, "from")) {
			જો (ret->required_from_host_ચાવીઓ != ખાલી) {
				errstr = "multiple \"from\" clauses";
				જાઓ fail;
			}
			ret->required_from_host_ચાવીઓ = opt_dequote(&opts,
			    &errstr);
			જો (ret->required_from_host_ચાવીઓ == ખાલી)
				જાઓ fail;
		} નહીંતર જો (opt_match(&opts, "expiry-time")) {
			જો ((opt = opt_dequote(&opts, &errstr)) == ખાલી)
				જાઓ fail;
			જો (parse_absolute_time(opt, &valid_before) != 0 ||
			    valid_before == 0) {
				મુક્ત(opt);
				errstr = "invalid expires time";
				જાઓ fail;
			}
			મુક્ત(opt);
			જો (ret->valid_before == 0 ||
			    valid_before < ret->valid_before)
				ret->valid_before = valid_before;
		} નહીંતર જો (opt_match(&opts, "environment")) {
			જો (ret->nenv > SSH_AUTHOPT_ENV_MAX) {
				errstr = "too many environment strings";
				જાઓ fail;
			}
			જો ((opt = opt_dequote(&opts, &errstr)) == ખાલી)
				જાઓ fail;
			/* env name must be alphanumeric and followed by '=' */
			જો ((tmp = strchr(opt, '=')) == ખાલી) {
				મુક્ત(opt);
				errstr = "invalid environment string";
				જાઓ fail;
			}
			જો ((cp = strdup(opt)) == ખાલી) {
				મુક્ત(opt);
				જાઓ alloc_fail;
			}
			l = (size_t)(tmp - opt);
			cp[l] = '\0'; /* truncate at '=' */
			જો (!valid_env_name(cp)) {
				મુક્ત(cp);
				મુક્ત(opt);
				errstr = "invalid environment string";
				જાઓ fail;
			}
			/* Check for duplicates; XXX O(n*log(n)) */
			માટે (i = 0; i < ret->nenv; i++) {
				જો (strncmp(ret->env[i], cp, l) == 0 &&
				    ret->env[i][l] == '=')
					તોડો;
			}
			મુક્ત(cp);
			/* First match wins */
			જો (i >= ret->nenv) {
				/* Append it. */
				oarray = ret->env;
				જો ((ret->env = recallocarray(ret->env,
				    ret->nenv, ret->nenv + 1,
				    કદ(*ret->env))) == ખાલી) {
					મુક્ત(opt);
					/* put it back for cleanup */
					ret->env = oarray;
					જાઓ alloc_fail;
				}
				ret->env[ret->nenv++] = opt;
				opt = ખાલી; /* transferred */
			}
			મુક્ત(opt);
		} નહીંતર જો (opt_match(&opts, "permitopen")) {
			જો (handle_permit(&opts, 0, &ret->permitopen,
			    &ret->npermitopen, &errstr) != 0)
				જાઓ fail;
		} નહીંતર જો (opt_match(&opts, "permitlisten")) {
			જો (handle_permit(&opts, 1, &ret->permitlisten,
			    &ret->npermitlisten, &errstr) != 0)
				જાઓ fail;
		} નહીંતર જો (opt_match(&opts, "tunnel")) {
			જો ((opt = opt_dequote(&opts, &errstr)) == ખાલી)
				જાઓ fail;
			ret->force_tun_device = a2tun(opt, ખાલી);
			મુક્ત(opt);
			જો (ret->force_tun_device == SSH_TUNID_ERR) {
				errstr = "invalid tun device";
				જાઓ fail;
			}
		}
		/*
		 * Skip the comma, and move to the next option
		 * (or break out if there are no more).
		 */
		જો (*opts == '\0' || *opts == ' ' || *opts == '\t')
			તોડો;		/* End of options. */
		/* Anything other than a comma is an unknown option */
		જો (*opts != ',') {
			errstr = "unknown key option";
			જાઓ fail;
		}
		opts++;
		જો (*opts == '\0') {
			errstr = "unexpected end-of-options";
			જાઓ fail;
		}
	}

	/* success */
	જો (errstrp != ખાલી)
		*errstrp = ખાલી;
	પાછા ret;

alloc_fail:
	errstr = "memory allocation failed";
fail:
	sshauthopt_free(ret);
	જો (errstrp != ખાલી)
		*errstrp = errstr;
	પાછા ખાલી;
}

સંરચના sshauthopt *
sshauthopt_from_cert(સંરચના sshkey *k)
{
	સંરચના sshauthopt *ret;

	જો (k == ખાલી || !sshkey_type_is_cert(k->type) || k->cert == ખાલી ||
	    k->cert->type != SSH2_CERT_TYPE_USER)
		પાછા ખાલી;

	જો ((ret = sshauthopt_new()) == ખાલી)
		પાછા ખાલી;

	/* Handle options and critical extensions separately */
	જો (cert_option_list(ret, k->cert->critical,
	    OPTIONS_CRITICAL, 1) == -1) {
		sshauthopt_free(ret);
		પાછા ખાલી;
	}
	જો (cert_option_list(ret, k->cert->extensions,
	    OPTIONS_EXTENSIONS, 0) == -1) {
		sshauthopt_free(ret);
		પાછા ખાલી;
	}
	/* success */
	પાછા ret;
}

/*
 * Merges "additional" options to "primary" and returns the result.
 * NB. Some options from primary have primacy.
 */
સંરચના sshauthopt *
sshauthopt_merge(અચલ સંરચના sshauthopt *primary,
    અચલ સંરચના sshauthopt *additional, અચલ અક્ષર **errstrp)
{
	સંરચના sshauthopt *ret;
	અચલ અક્ષર *errstr = "internal error";
	અચલ અક્ષર *tmp;

	જો (errstrp != ખાલી)
		*errstrp = ખાલી;

	જો ((ret = sshauthopt_new()) == ખાલી)
		જાઓ alloc_fail;

	/* cert_authority and cert_principals are cleared in result */

	/* Prefer access lists from primary. */
	/* XXX err is both set and mismatch? */
	tmp = primary->required_from_host_cert;
	જો (tmp == ખાલી)
		tmp = additional->required_from_host_cert;
	જો (tmp != ખાલી && (ret->required_from_host_cert = strdup(tmp)) == ખાલી)
		જાઓ alloc_fail;
	tmp = primary->required_from_host_ચાવીઓ;
	જો (tmp == ખાલી)
		tmp = additional->required_from_host_ચાવીઓ;
	જો (tmp != ખાલી && (ret->required_from_host_ચાવીઓ = strdup(tmp)) == ખાલી)
		જાઓ alloc_fail;

	/*
	 * force_tun_device, permitopen/permitlisten and environment all
	 * prefer the primary.
	 */
	ret->force_tun_device = primary->force_tun_device;
	જો (ret->force_tun_device == -1)
		ret->force_tun_device = additional->force_tun_device;
	જો (primary->nenv > 0) {
		જો (dup_strings(&ret->env, &ret->nenv,
		    primary->env, primary->nenv) != 0)
			જાઓ alloc_fail;
	} નહીંતર જો (additional->nenv) {
		જો (dup_strings(&ret->env, &ret->nenv,
		    additional->env, additional->nenv) != 0)
			જાઓ alloc_fail;
	}
	જો (primary->npermitopen > 0) {
		જો (dup_strings(&ret->permitopen, &ret->npermitopen,
		    primary->permitopen, primary->npermitopen) != 0)
			જાઓ alloc_fail;
	} નહીંતર જો (additional->npermitopen > 0) {
		જો (dup_strings(&ret->permitopen, &ret->npermitopen,
		    additional->permitopen, additional->npermitopen) != 0)
			જાઓ alloc_fail;
	}

	જો (primary->npermitlisten > 0) {
		જો (dup_strings(&ret->permitlisten, &ret->npermitlisten,
		    primary->permitlisten, primary->npermitlisten) != 0)
			જાઓ alloc_fail;
	} નહીંતર જો (additional->npermitlisten > 0) {
		જો (dup_strings(&ret->permitlisten, &ret->npermitlisten,
		    additional->permitlisten, additional->npermitlisten) != 0)
			જાઓ alloc_fail;
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
	જો (primary->valid_before != 0)
		ret->valid_before = primary->valid_before;
	જો (additional->valid_before != 0 &&
	    additional->valid_before < ret->valid_before)
		ret->valid_before = additional->valid_before;

	/*
	 * When both multiple forced-command are specified, only
	 * proceed if they are identical, otherwise fail.
	 */
	જો (primary->force_command != ખાલી &&
	    additional->force_command != ખાલી) {
		જો (strcmp(primary->force_command,
		    additional->force_command) == 0) {
			/* ok */
			ret->force_command = strdup(primary->force_command);
			જો (ret->force_command == ખાલી)
				જાઓ alloc_fail;
		} નહીંતર {
			errstr = "forced command options do not match";
			જાઓ fail;
		}
	} નહીંતર જો (primary->force_command != ખાલી) {
		જો ((ret->force_command = strdup(
		    primary->force_command)) == ખાલી)
			જાઓ alloc_fail;
	} નહીંતર જો (additional->force_command != ખાલી) {
		જો ((ret->force_command = strdup(
		    additional->force_command)) == ખાલી)
			જાઓ alloc_fail;
	}
	/* success */
	જો (errstrp != ખાલી)
		*errstrp = ખાલી;
	પાછા ret;

 alloc_fail:
	errstr = "memory allocation failed";
 fail:
	જો (errstrp != ખાલી)
		*errstrp = errstr;
	sshauthopt_free(ret);
	પાછા ખાલી;
}

/*
 * Copy options
 */
સંરચના sshauthopt *
sshauthopt_copy(અચલ સંરચના sshauthopt *orig)
{
	સંરચના sshauthopt *ret;

	જો ((ret = sshauthopt_new()) == ખાલી)
		પાછા ખાલી;

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
	કરો { \
		જો (orig->x != ખાલી && (ret->x = strdup(orig->x)) == ખાલી) { \
			sshauthopt_free(ret); \
			પાછા ખાલી; \
		} \
	} જ્યારે (0)
	OPTSTRING(cert_principals);
	OPTSTRING(force_command);
	OPTSTRING(required_from_host_cert);
	OPTSTRING(required_from_host_ચાવીઓ);
#undef OPTSTRING

	જો (dup_strings(&ret->env, &ret->nenv, orig->env, orig->nenv) != 0 ||
	    dup_strings(&ret->permitopen, &ret->npermitopen,
	    orig->permitopen, orig->npermitopen) != 0 ||
	    dup_strings(&ret->permitlisten, &ret->npermitlisten,
	    orig->permitlisten, orig->npermitlisten) != 0) {
		sshauthopt_free(ret);
		પાછા ખાલી;
	}
	પાછા ret;
}

સ્થિર પૂર્ણાંક
serialise_array(સંરચના sshbuf *m, અક્ષર **a, size_t n)
{
	સંરચના sshbuf *b;
	size_t i;
	પૂર્ણાંક r = SSH_ERR_INTERNAL_ERROR;

	જો (n > INT_MAX)
		પાછા SSH_ERR_INTERNAL_ERROR;

	જો ((b = sshbuf_new()) == ખાલી) {
		પાછા SSH_ERR_ALLOC_FAIL;
	}
	માટે (i = 0; i < n; i++) {
		જો ((r = sshbuf_put_cstring(b, a[i])) != 0)
			જાઓ out;
	}
	જો ((r = sshbuf_put_u32(m, n)) != 0 ||
	    (r = sshbuf_put_stringb(m, b)) != 0)
		જાઓ out;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	પાછા r;
}

સ્થિર પૂર્ણાંક
deserialise_array(સંરચના sshbuf *m, અક્ષર ***ap, size_t *np)
{
	અક્ષર **a = ખાલી;
	size_t i, n = 0;
	સંરચના sshbuf *b = ખાલી;
	u_int tmp;
	પૂર્ણાંક r = SSH_ERR_INTERNAL_ERROR;

	જો ((r = sshbuf_get_u32(m, &tmp)) != 0 ||
	    (r = sshbuf_froms(m, &b)) != 0)
		જાઓ out;
	જો (tmp > INT_MAX) {
		r = SSH_ERR_INVALID_FORMAT;
		જાઓ out;
	}
	n = tmp;
	જો (n > 0 && (a = calloc(n, કદ(*a))) == ખાલી) {
		r = SSH_ERR_ALLOC_FAIL;
		જાઓ out;
	}
	માટે (i = 0; i < n; i++) {
		જો ((r = sshbuf_get_cstring(b, &a[i], ખાલી)) != 0)
			જાઓ out;
	}
	/* success */
	r = 0;
	*ap = a;
	a = ખાલી;
	*np = n;
	n = 0;
 out:
	જો (a != ખાલી) {
		માટે (i = 0; i < n; i++)
			મુક્ત(a[i]);
		મુક્ત(a);
	}
	sshbuf_free(b);
	પાછા r;
}

સ્થિર પૂર્ણાંક
serialise_nullable_string(સંરચના sshbuf *m, અચલ અક્ષર *s)
{
	પૂર્ણાંક r;

	જો ((r = sshbuf_put_u8(m, s == ખાલી)) != 0 ||
	    (r = sshbuf_put_cstring(m, s)) != 0)
		પાછા r;
	પાછા 0;
}

સ્થિર પૂર્ણાંક
deserialise_nullable_string(સંરચના sshbuf *m, અક્ષર **sp)
{
	પૂર્ણાંક r;
	u_char flag;

	*sp = ખાલી;
	જો ((r = sshbuf_get_u8(m, &flag)) != 0 ||
	    (r = sshbuf_get_cstring(m, flag ? ખાલી : sp, ખાલી)) != 0)
		પાછા r;
	પાછા 0;
}

પૂર્ણાંક
sshauthopt_serialise(અચલ સંરચના sshauthopt *opts, સંરચના sshbuf *m,
    પૂર્ણાંક untrusted)
{
	પૂર્ણાંક r = SSH_ERR_INTERNAL_ERROR;

	/* Flag options */
	જો ((r = sshbuf_put_u8(m, opts->permit_port_forwarding_flag)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->permit_agent_forwarding_flag)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->permit_x11_forwarding_flag)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->permit_pty_flag)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->permit_user_rc)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->restricted)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->cert_authority)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->no_require_user_presence)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->require_verify)) != 0)
		પાછા r;

	/* Simple integer options */
	જો ((r = sshbuf_put_u64(m, opts->valid_before)) != 0)
		પાછા r;

	/* tunnel number can be negative to indicate "unset" */
	જો ((r = sshbuf_put_u8(m, opts->force_tun_device == -1)) != 0 ||
	    (r = sshbuf_put_u32(m, (opts->force_tun_device < 0) ?
	    0 : (u_int)opts->force_tun_device)) != 0)
		પાછા r;

	/* String options; these may be NULL */
	જો ((r = serialise_nullable_string(m,
	    untrusted ? "yes" : opts->cert_principals)) != 0 ||
	    (r = serialise_nullable_string(m,
	    untrusted ? "true" : opts->force_command)) != 0 ||
	    (r = serialise_nullable_string(m,
	    untrusted ? ખાલી : opts->required_from_host_cert)) != 0 ||
	    (r = serialise_nullable_string(m,
	    untrusted ? ખાલી : opts->required_from_host_ચાવીઓ)) != 0)
		પાછા r;

	/* Array options */
	જો ((r = serialise_array(m, opts->env,
	    untrusted ? 0 : opts->nenv)) != 0 ||
	    (r = serialise_array(m, opts->permitopen,
	    untrusted ? 0 : opts->npermitopen)) != 0 ||
	    (r = serialise_array(m, opts->permitlisten,
	    untrusted ? 0 : opts->npermitlisten)) != 0)
		પાછા r;

	/* success */
	પાછા 0;
}

પૂર્ણાંક
sshauthopt_deserialise(સંરચના sshbuf *m, સંરચના sshauthopt **optsp)
{
	સંરચના sshauthopt *opts = ખાલી;
	પૂર્ણાંક r = SSH_ERR_INTERNAL_ERROR;
	u_char f;
	u_int tmp;

	જો ((opts = calloc(1, કદ(*opts))) == ખાલી)
		પાછા SSH_ERR_ALLOC_FAIL;

	/* Flag options */
#define OPT_FLAG(x) \
	કરો { \
		જો ((r = sshbuf_get_u8(m, &f)) != 0) \
			જાઓ out; \
		opts->x = f; \
	} જ્યારે (0)
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
	જો ((r = sshbuf_get_u64(m, &opts->valid_before)) != 0)
		જાઓ out;

	/* tunnel number can be negative to indicate "unset" */
	જો ((r = sshbuf_get_u8(m, &f)) != 0 ||
	    (r = sshbuf_get_u32(m, &tmp)) != 0)
		જાઓ out;
	opts->force_tun_device = f ? -1 : (પૂર્ણાંક)tmp;

	/* String options may be NULL */
	જો ((r = deserialise_nullable_string(m, &opts->cert_principals)) != 0 ||
	    (r = deserialise_nullable_string(m, &opts->force_command)) != 0 ||
	    (r = deserialise_nullable_string(m,
	    &opts->required_from_host_cert)) != 0 ||
	    (r = deserialise_nullable_string(m,
	    &opts->required_from_host_ચાવીઓ)) != 0)
		જાઓ out;

	/* Array options */
	જો ((r = deserialise_array(m, &opts->env, &opts->nenv)) != 0 ||
	    (r = deserialise_array(m,
	    &opts->permitopen, &opts->npermitopen)) != 0 ||
	    (r = deserialise_array(m,
	    &opts->permitlisten, &opts->npermitlisten)) != 0)
		જાઓ out;

	/* success */
	r = 0;
	*optsp = opts;
	opts = ખાલી;
 out:
	sshauthopt_free(opts);
	પાછા r;
}
