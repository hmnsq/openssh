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

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <sys/queue.h>

#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <netdb.h>
#அந்தர்பாவ <pwd.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <stdint.h>
#அந்தர்பாவ <stdarg.h>
#அந்தர்பாவ <ctype.h>
#அந்தர்பாவ <limits.h>

#அந்தர்பாவ "xmalloc.h"
#அந்தர்பாவ "ssherr.h"
#அந்தர்பாவ "log.h"
#அந்தர்பாவ "sshbuf.h"
#அந்தர்பாவ "misc.h"
#அந்தர்பாவ "sshkey.h"
#அந்தர்பாவ "match.h"
#அந்தர்பாவ "ssh2.h"
#அந்தர்பாவ "auth-options.h"

நிலையான முழு
dup_strings(எழுத்து ***dstp, size_t *ndstp, எழுத்து **src, size_t nsrc)
{
	எழுத்து **dst;
	size_t i, j;

	*dstp = வெற்று;
	*ndstp = 0;

	எனில் (nsrc == 0)
		திரும்பு 0;
	எனில் (nsrc >= SIZE_MAX / அளவு(*src) ||
	    (dst = calloc(nsrc, அளவு(*src))) == வெற்று)
		திரும்பு -1;
	க்கு (i = 0; i < nsrc; i++) {
		எனில் ((dst[i] = strdup(src[i])) == வெற்று) {
			க்கு (j = 0; j < i; j++)
				விடுவி(dst[j]);
			விடுவி(dst);
			திரும்பு -1;
		}
	}
	/* success */
	*dstp = dst;
	*ndstp = nsrc;
	திரும்பு 0;
}

#define OPTIONS_CRITICAL	1
#define OPTIONS_EXTENSIONS	2
நிலையான முழு
cert_option_list(கட்டமைப்பு sshauthopt *opts, கட்டமைப்பு sshbuf *oblob,
    u_int which, முழு crit)
{
	எழுத்து *command, *allowed;
	எழுத்து *name = வெற்று;
	கட்டமைப்பு sshbuf *c = வெற்று, *data = வெற்று;
	முழு r, ret = -1, found;

	எனில் ((c = sshbuf_fromb(oblob)) == வெற்று) {
		error_f("sshbuf_fromb failed");
		செல் out;
	}

	போது (sshbuf_len(c) > 0) {
		sshbuf_free(data);
		data = வெற்று;
		எனில் ((r = sshbuf_get_cstring(c, &name, வெற்று)) != 0 ||
		    (r = sshbuf_froms(c, &data)) != 0) {
			error_r(r, "Unable to parse certificate options");
			செல் out;
		}
		debug3("found certificate option \"%.100s\" len %zu",
		    name, sshbuf_len(data));
		found = 0;
		எனில் ((which & OPTIONS_EXTENSIONS) != 0) {
			எனில் (strcmp(name, "no-touch-required") == 0) {
				opts->no_require_user_presence = 1;
				found = 1;
			} இல்லையெனில் எனில் (strcmp(name, "permit-X11-forwarding") == 0) {
				opts->permit_x11_forwarding_flag = 1;
				found = 1;
			} இல்லையெனில் எனில் (strcmp(name,
			    "permit-agent-forwarding") == 0) {
				opts->permit_agent_forwarding_flag = 1;
				found = 1;
			} இல்லையெனில் எனில் (strcmp(name,
			    "permit-port-forwarding") == 0) {
				opts->permit_port_forwarding_flag = 1;
				found = 1;
			} இல்லையெனில் எனில் (strcmp(name, "permit-pty") == 0) {
				opts->permit_pty_flag = 1;
				found = 1;
			} இல்லையெனில் எனில் (strcmp(name, "permit-user-rc") == 0) {
				opts->permit_user_rc = 1;
				found = 1;
			}
		}
		எனில் (!found && (which & OPTIONS_CRITICAL) != 0) {
			எனில் (strcmp(name, "verify-required") == 0) {
				opts->require_verify = 1;
				found = 1;
			} இல்லையெனில் எனில் (strcmp(name, "force-command") == 0) {
				எனில் ((r = sshbuf_get_cstring(data, &command,
				    வெற்று)) != 0) {
					error_r(r, "Unable to parse \"%s\" "
					    "section", name);
					செல் out;
				}
				எனில் (opts->force_command != வெற்று) {
					error("Certificate has multiple "
					    "force-command options");
					விடுவி(command);
					செல் out;
				}
				opts->force_command = command;
				found = 1;
			} இல்லையெனில் எனில் (strcmp(name, "source-address") == 0) {
				எனில் ((r = sshbuf_get_cstring(data, &allowed,
				    வெற்று)) != 0) {
					error_r(r, "Unable to parse \"%s\" "
					    "section", name);
					செல் out;
				}
				எனில் (opts->required_from_host_cert != வெற்று) {
					error("Certificate has multiple "
					    "source-address options");
					விடுவி(allowed);
					செல் out;
				}
				/* Check syntax */
				எனில் (addr_match_cidr_list(வெற்று, allowed) == -1) {
					error("Certificate source-address "
					    "contents invalid");
					விடுவி(allowed);
					செல் out;
				}
				opts->required_from_host_cert = allowed;
				found = 1;
			}
		}

		எனில் (!found) {
			எனில் (crit) {
				error("Certificate critical option \"%s\" "
				    "is not supported", name);
				செல் out;
			} இல்லையெனில் {
				logit("Certificate extension \"%s\" "
				    "is not supported", name);
			}
		} இல்லையெனில் எனில் (sshbuf_len(data) != 0) {
			error("Certificate option \"%s\" corrupt "
			    "(extra data)", name);
			செல் out;
		}
		விடுவி(name);
		name = வெற்று;
	}
	/* successfully parsed all options */
	ret = 0;

 out:
	விடுவி(name);
	sshbuf_free(data);
	sshbuf_free(c);
	திரும்பு ret;
}

கட்டமைப்பு sshauthopt *
sshauthopt_new(வெறுமை)
{
	கட்டமைப்பு sshauthopt *ret;

	எனில் ((ret = calloc(1, அளவு(*ret))) == வெற்று)
		திரும்பு வெற்று;
	ret->force_tun_device = -1;
	திரும்பு ret;
}

வெறுமை
sshauthopt_free(கட்டமைப்பு sshauthopt *opts)
{
	size_t i;

	எனில் (opts == வெற்று)
		திரும்பு;

	விடுவி(opts->cert_principals);
	விடுவி(opts->force_command);
	விடுவி(opts->required_from_host_cert);
	விடுவி(opts->required_from_host_சாவிகள்);

	க்கு (i = 0; i < opts->nenv; i++)
		விடுவி(opts->env[i]);
	விடுவி(opts->env);

	க்கு (i = 0; i < opts->npermitopen; i++)
		விடுவி(opts->permitopen[i]);
	விடுவி(opts->permitopen);

	க்கு (i = 0; i < opts->npermitlisten; i++)
		விடுவி(opts->permitlisten[i]);
	விடுவி(opts->permitlisten);

	freezero(opts, அளவு(*opts));
}

கட்டமைப்பு sshauthopt *
sshauthopt_new_with_சாவிகள்_defaults(வெறுமை)
{
	கட்டமைப்பு sshauthopt *ret = வெற்று;

	எனில் ((ret = sshauthopt_new()) == வெற்று)
		திரும்பு வெற்று;

	/* Defaults for authorized_keys flags */
	ret->permit_port_forwarding_flag = 1;
	ret->permit_agent_forwarding_flag = 1;
	ret->permit_x11_forwarding_flag = 1;
	ret->permit_pty_flag = 1;
	ret->permit_user_rc = 1;
	திரும்பு ret;
}

/*
 * Parse and record a permitopen/permitlisten directive.
 * Return 0 on success. Return -1 on failure and sets *errstrp to error reason.
 */
நிலையான முழு
handle_permit(மாறிலி எழுத்து **optsp, முழு allow_bare_port,
    எழுத்து ***permitsp, size_t *npermitsp, மாறிலி எழுத்து **errstrp)
{
	எழுத்து *opt, *tmp, *cp, *host, **permits = *permitsp;
	size_t npermits = *npermitsp;
	மாறிலி எழுத்து *errstr = "unknown error";

	எனில் (npermits > SSH_AUTHOPT_PERMIT_MAX) {
		*errstrp = "too many permission directives";
		திரும்பு -1;
	}
	எனில் ((opt = opt_dequote(optsp, &errstr)) == வெற்று) {
		திரும்பு -1;
	}
	எனில் (allow_bare_port && strchr(opt, ':') == வெற்று) {
		/*
		 * Allow a bare port number in permitlisten to indicate a
		 * listen_host wildcard.
		 */
		எனில் (asprintf(&tmp, "*:%s", opt) == -1) {
			விடுவி(opt);
			*errstrp = "memory allocation failed";
			திரும்பு -1;
		}
		விடுவி(opt);
		opt = tmp;
	}
	எனில் ((tmp = strdup(opt)) == வெற்று) {
		விடுவி(opt);
		*errstrp = "memory allocation failed";
		திரும்பு -1;
	}
	cp = tmp;
	/* validate syntax before recording it. */
	host = hpdelim2(&cp, வெற்று);
	எனில் (host == வெற்று || strlen(host) >= NI_MAXHOST) {
		விடுவி(tmp);
		விடுவி(opt);
		*errstrp = "invalid permission hostname";
		திரும்பு -1;
	}
	/*
	 * don't want to use permitopen_port to avoid
	 * dependency on channels.[ch] here.
	 */
	எனில் (cp == வெற்று ||
	    (strcmp(cp, "*") != 0 && a2port(cp) <= 0)) {
		விடுவி(tmp);
		விடுவி(opt);
		*errstrp = "invalid permission port";
		திரும்பு -1;
	}
	/* XXX - add streamlocal support */
	விடுவி(tmp);
	/* Record it */
	எனில் ((permits = recallocarray(permits, npermits, npermits + 1,
	    அளவு(*permits))) == வெற்று) {
		விடுவி(opt);
		/* NB. don't update *permitsp if alloc fails */
		*errstrp = "memory allocation failed";
		திரும்பு -1;
	}
	permits[npermits++] = opt;
	*permitsp = permits;
	*npermitsp = npermits;
	திரும்பு 0;
}

கட்டமைப்பு sshauthopt *
sshauthopt_parse(மாறிலி எழுத்து *opts, மாறிலி எழுத்து **errstrp)
{
	எழுத்து **oarray, *opt, *cp, *tmp;
	முழு r;
	கட்டமைப்பு sshauthopt *ret = வெற்று;
	மாறிலி எழுத்து *errstr = "unknown error";
	uint64_t valid_before;
	size_t i, l;

	எனில் (errstrp != வெற்று)
		*errstrp = வெற்று;
	எனில் ((ret = sshauthopt_new_with_சாவிகள்_defaults()) == வெற்று)
		செல் alloc_fail;

	எனில் (opts == வெற்று)
		திரும்பு ret;

	போது (*opts && *opts != ' ' && *opts != '\t') {
		/* flag options */
		எனில் ((r = opt_flag("restrict", 0, &opts)) != -1) {
			ret->restricted = 1;
			ret->permit_port_forwarding_flag = 0;
			ret->permit_agent_forwarding_flag = 0;
			ret->permit_x11_forwarding_flag = 0;
			ret->permit_pty_flag = 0;
			ret->permit_user_rc = 0;
		} இல்லையெனில் எனில் ((r = opt_flag("cert-authority", 0, &opts)) != -1) {
			ret->cert_authority = r;
		} இல்லையெனில் எனில் ((r = opt_flag("port-forwarding", 1, &opts)) != -1) {
			ret->permit_port_forwarding_flag = r == 1;
		} இல்லையெனில் எனில் ((r = opt_flag("agent-forwarding", 1, &opts)) != -1) {
			ret->permit_agent_forwarding_flag = r == 1;
		} இல்லையெனில் எனில் ((r = opt_flag("x11-forwarding", 1, &opts)) != -1) {
			ret->permit_x11_forwarding_flag = r == 1;
		} இல்லையெனில் எனில் ((r = opt_flag("touch-required", 1, &opts)) != -1) {
			ret->no_require_user_presence = r != 1; /* NB. flip */
		} இல்லையெனில் எனில் ((r = opt_flag("verify-required", 1, &opts)) != -1) {
			ret->require_verify = r == 1;
		} இல்லையெனில் எனில் ((r = opt_flag("pty", 1, &opts)) != -1) {
			ret->permit_pty_flag = r == 1;
		} இல்லையெனில் எனில் ((r = opt_flag("user-rc", 1, &opts)) != -1) {
			ret->permit_user_rc = r == 1;
		} இல்லையெனில் எனில் (opt_match(&opts, "command")) {
			எனில் (ret->force_command != வெற்று) {
				errstr = "multiple \"command\" clauses";
				செல் fail;
			}
			ret->force_command = opt_dequote(&opts, &errstr);
			எனில் (ret->force_command == வெற்று)
				செல் fail;
		} இல்லையெனில் எனில் (opt_match(&opts, "principals")) {
			எனில் (ret->cert_principals != வெற்று) {
				errstr = "multiple \"principals\" clauses";
				செல் fail;
			}
			ret->cert_principals = opt_dequote(&opts, &errstr);
			எனில் (ret->cert_principals == வெற்று)
				செல் fail;
		} இல்லையெனில் எனில் (opt_match(&opts, "from")) {
			எனில் (ret->required_from_host_சாவிகள் != வெற்று) {
				errstr = "multiple \"from\" clauses";
				செல் fail;
			}
			ret->required_from_host_சாவிகள் = opt_dequote(&opts,
			    &errstr);
			எனில் (ret->required_from_host_சாவிகள் == வெற்று)
				செல் fail;
		} இல்லையெனில் எனில் (opt_match(&opts, "expiry-time")) {
			எனில் ((opt = opt_dequote(&opts, &errstr)) == வெற்று)
				செல் fail;
			எனில் (parse_absolute_time(opt, &valid_before) != 0 ||
			    valid_before == 0) {
				விடுவி(opt);
				errstr = "invalid expires time";
				செல் fail;
			}
			விடுவி(opt);
			எனில் (ret->valid_before == 0 ||
			    valid_before < ret->valid_before)
				ret->valid_before = valid_before;
		} இல்லையெனில் எனில் (opt_match(&opts, "environment")) {
			எனில் (ret->nenv > SSH_AUTHOPT_ENV_MAX) {
				errstr = "too many environment strings";
				செல் fail;
			}
			எனில் ((opt = opt_dequote(&opts, &errstr)) == வெற்று)
				செல் fail;
			/* env name must be alphanumeric and followed by '=' */
			எனில் ((tmp = strchr(opt, '=')) == வெற்று) {
				விடுவி(opt);
				errstr = "invalid environment string";
				செல் fail;
			}
			எனில் ((cp = strdup(opt)) == வெற்று) {
				விடுவி(opt);
				செல் alloc_fail;
			}
			l = (size_t)(tmp - opt);
			cp[l] = '\0'; /* truncate at '=' */
			எனில் (!valid_env_name(cp)) {
				விடுவி(cp);
				விடுவி(opt);
				errstr = "invalid environment string";
				செல் fail;
			}
			/* Check for duplicates; XXX O(n*log(n)) */
			க்கு (i = 0; i < ret->nenv; i++) {
				எனில் (strncmp(ret->env[i], cp, l) == 0 &&
				    ret->env[i][l] == '=')
					நிறுத்து;
			}
			விடுவி(cp);
			/* First match wins */
			எனில் (i >= ret->nenv) {
				/* Append it. */
				oarray = ret->env;
				எனில் ((ret->env = recallocarray(ret->env,
				    ret->nenv, ret->nenv + 1,
				    அளவு(*ret->env))) == வெற்று) {
					விடுவி(opt);
					/* put it back for cleanup */
					ret->env = oarray;
					செல் alloc_fail;
				}
				ret->env[ret->nenv++] = opt;
				opt = வெற்று; /* transferred */
			}
			விடுவி(opt);
		} இல்லையெனில் எனில் (opt_match(&opts, "permitopen")) {
			எனில் (handle_permit(&opts, 0, &ret->permitopen,
			    &ret->npermitopen, &errstr) != 0)
				செல் fail;
		} இல்லையெனில் எனில் (opt_match(&opts, "permitlisten")) {
			எனில் (handle_permit(&opts, 1, &ret->permitlisten,
			    &ret->npermitlisten, &errstr) != 0)
				செல் fail;
		} இல்லையெனில் எனில் (opt_match(&opts, "tunnel")) {
			எனில் ((opt = opt_dequote(&opts, &errstr)) == வெற்று)
				செல் fail;
			ret->force_tun_device = a2tun(opt, வெற்று);
			விடுவி(opt);
			எனில் (ret->force_tun_device == SSH_TUNID_ERR) {
				errstr = "invalid tun device";
				செல் fail;
			}
		}
		/*
		 * Skip the comma, and move to the next option
		 * (or break out if there are no more).
		 */
		எனில் (*opts == '\0' || *opts == ' ' || *opts == '\t')
			நிறுத்து;		/* End of options. */
		/* Anything other than a comma is an unknown option */
		எனில் (*opts != ',') {
			errstr = "unknown key option";
			செல் fail;
		}
		opts++;
		எனில் (*opts == '\0') {
			errstr = "unexpected end-of-options";
			செல் fail;
		}
	}

	/* success */
	எனில் (errstrp != வெற்று)
		*errstrp = வெற்று;
	திரும்பு ret;

alloc_fail:
	errstr = "memory allocation failed";
fail:
	sshauthopt_free(ret);
	எனில் (errstrp != வெற்று)
		*errstrp = errstr;
	திரும்பு வெற்று;
}

கட்டமைப்பு sshauthopt *
sshauthopt_from_cert(கட்டமைப்பு sshkey *k)
{
	கட்டமைப்பு sshauthopt *ret;

	எனில் (k == வெற்று || !sshkey_type_is_cert(k->type) || k->cert == வெற்று ||
	    k->cert->type != SSH2_CERT_TYPE_USER)
		திரும்பு வெற்று;

	எனில் ((ret = sshauthopt_new()) == வெற்று)
		திரும்பு வெற்று;

	/* Handle options and critical extensions separately */
	எனில் (cert_option_list(ret, k->cert->critical,
	    OPTIONS_CRITICAL, 1) == -1) {
		sshauthopt_free(ret);
		திரும்பு வெற்று;
	}
	எனில் (cert_option_list(ret, k->cert->extensions,
	    OPTIONS_EXTENSIONS, 0) == -1) {
		sshauthopt_free(ret);
		திரும்பு வெற்று;
	}
	/* success */
	திரும்பு ret;
}

/*
 * Merges "additional" options to "primary" and returns the result.
 * NB. Some options from primary have primacy.
 */
கட்டமைப்பு sshauthopt *
sshauthopt_merge(மாறிலி கட்டமைப்பு sshauthopt *primary,
    மாறிலி கட்டமைப்பு sshauthopt *additional, மாறிலி எழுத்து **errstrp)
{
	கட்டமைப்பு sshauthopt *ret;
	மாறிலி எழுத்து *errstr = "internal error";
	மாறிலி எழுத்து *tmp;

	எனில் (errstrp != வெற்று)
		*errstrp = வெற்று;

	எனில் ((ret = sshauthopt_new()) == வெற்று)
		செல் alloc_fail;

	/* cert_authority and cert_principals are cleared in result */

	/* Prefer access lists from primary. */
	/* XXX err is both set and mismatch? */
	tmp = primary->required_from_host_cert;
	எனில் (tmp == வெற்று)
		tmp = additional->required_from_host_cert;
	எனில் (tmp != வெற்று && (ret->required_from_host_cert = strdup(tmp)) == வெற்று)
		செல் alloc_fail;
	tmp = primary->required_from_host_சாவிகள்;
	எனில் (tmp == வெற்று)
		tmp = additional->required_from_host_சாவிகள்;
	எனில் (tmp != வெற்று && (ret->required_from_host_சாவிகள் = strdup(tmp)) == வெற்று)
		செல் alloc_fail;

	/*
	 * force_tun_device, permitopen/permitlisten and environment all
	 * prefer the primary.
	 */
	ret->force_tun_device = primary->force_tun_device;
	எனில் (ret->force_tun_device == -1)
		ret->force_tun_device = additional->force_tun_device;
	எனில் (primary->nenv > 0) {
		எனில் (dup_strings(&ret->env, &ret->nenv,
		    primary->env, primary->nenv) != 0)
			செல் alloc_fail;
	} இல்லையெனில் எனில் (additional->nenv) {
		எனில் (dup_strings(&ret->env, &ret->nenv,
		    additional->env, additional->nenv) != 0)
			செல் alloc_fail;
	}
	எனில் (primary->npermitopen > 0) {
		எனில் (dup_strings(&ret->permitopen, &ret->npermitopen,
		    primary->permitopen, primary->npermitopen) != 0)
			செல் alloc_fail;
	} இல்லையெனில் எனில் (additional->npermitopen > 0) {
		எனில் (dup_strings(&ret->permitopen, &ret->npermitopen,
		    additional->permitopen, additional->npermitopen) != 0)
			செல் alloc_fail;
	}

	எனில் (primary->npermitlisten > 0) {
		எனில் (dup_strings(&ret->permitlisten, &ret->npermitlisten,
		    primary->permitlisten, primary->npermitlisten) != 0)
			செல் alloc_fail;
	} இல்லையெனில் எனில் (additional->npermitlisten > 0) {
		எனில் (dup_strings(&ret->permitlisten, &ret->npermitlisten,
		    additional->permitlisten, additional->npermitlisten) != 0)
			செல் alloc_fail;
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
	எனில் (primary->valid_before != 0)
		ret->valid_before = primary->valid_before;
	எனில் (additional->valid_before != 0 &&
	    additional->valid_before < ret->valid_before)
		ret->valid_before = additional->valid_before;

	/*
	 * When both multiple forced-command are specified, only
	 * proceed if they are identical, otherwise fail.
	 */
	எனில் (primary->force_command != வெற்று &&
	    additional->force_command != வெற்று) {
		எனில் (strcmp(primary->force_command,
		    additional->force_command) == 0) {
			/* ok */
			ret->force_command = strdup(primary->force_command);
			எனில் (ret->force_command == வெற்று)
				செல் alloc_fail;
		} இல்லையெனில் {
			errstr = "forced command options do not match";
			செல் fail;
		}
	} இல்லையெனில் எனில் (primary->force_command != வெற்று) {
		எனில் ((ret->force_command = strdup(
		    primary->force_command)) == வெற்று)
			செல் alloc_fail;
	} இல்லையெனில் எனில் (additional->force_command != வெற்று) {
		எனில் ((ret->force_command = strdup(
		    additional->force_command)) == வெற்று)
			செல் alloc_fail;
	}
	/* success */
	எனில் (errstrp != வெற்று)
		*errstrp = வெற்று;
	திரும்பு ret;

 alloc_fail:
	errstr = "memory allocation failed";
 fail:
	எனில் (errstrp != வெற்று)
		*errstrp = errstr;
	sshauthopt_free(ret);
	திரும்பு வெற்று;
}

/*
 * Copy options
 */
கட்டமைப்பு sshauthopt *
sshauthopt_copy(மாறிலி கட்டமைப்பு sshauthopt *orig)
{
	கட்டமைப்பு sshauthopt *ret;

	எனில் ((ret = sshauthopt_new()) == வெற்று)
		திரும்பு வெற்று;

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
	செய் { \
		எனில் (orig->x != வெற்று && (ret->x = strdup(orig->x)) == வெற்று) { \
			sshauthopt_free(ret); \
			திரும்பு வெற்று; \
		} \
	} போது (0)
	OPTSTRING(cert_principals);
	OPTSTRING(force_command);
	OPTSTRING(required_from_host_cert);
	OPTSTRING(required_from_host_சாவிகள்);
#undef OPTSTRING

	எனில் (dup_strings(&ret->env, &ret->nenv, orig->env, orig->nenv) != 0 ||
	    dup_strings(&ret->permitopen, &ret->npermitopen,
	    orig->permitopen, orig->npermitopen) != 0 ||
	    dup_strings(&ret->permitlisten, &ret->npermitlisten,
	    orig->permitlisten, orig->npermitlisten) != 0) {
		sshauthopt_free(ret);
		திரும்பு வெற்று;
	}
	திரும்பு ret;
}

நிலையான முழு
serialise_array(கட்டமைப்பு sshbuf *m, எழுத்து **a, size_t n)
{
	கட்டமைப்பு sshbuf *b;
	size_t i;
	முழு r = SSH_ERR_INTERNAL_ERROR;

	எனில் (n > INT_MAX)
		திரும்பு SSH_ERR_INTERNAL_ERROR;

	எனில் ((b = sshbuf_new()) == வெற்று) {
		திரும்பு SSH_ERR_ALLOC_FAIL;
	}
	க்கு (i = 0; i < n; i++) {
		எனில் ((r = sshbuf_put_cstring(b, a[i])) != 0)
			செல் out;
	}
	எனில் ((r = sshbuf_put_u32(m, n)) != 0 ||
	    (r = sshbuf_put_stringb(m, b)) != 0)
		செல் out;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	திரும்பு r;
}

நிலையான முழு
deserialise_array(கட்டமைப்பு sshbuf *m, எழுத்து ***ap, size_t *np)
{
	எழுத்து **a = வெற்று;
	size_t i, n = 0;
	கட்டமைப்பு sshbuf *b = வெற்று;
	u_int tmp;
	முழு r = SSH_ERR_INTERNAL_ERROR;

	எனில் ((r = sshbuf_get_u32(m, &tmp)) != 0 ||
	    (r = sshbuf_froms(m, &b)) != 0)
		செல் out;
	எனில் (tmp > INT_MAX) {
		r = SSH_ERR_INVALID_FORMAT;
		செல் out;
	}
	n = tmp;
	எனில் (n > 0 && (a = calloc(n, அளவு(*a))) == வெற்று) {
		r = SSH_ERR_ALLOC_FAIL;
		செல் out;
	}
	க்கு (i = 0; i < n; i++) {
		எனில் ((r = sshbuf_get_cstring(b, &a[i], வெற்று)) != 0)
			செல் out;
	}
	/* success */
	r = 0;
	*ap = a;
	a = வெற்று;
	*np = n;
	n = 0;
 out:
	எனில் (a != வெற்று) {
		க்கு (i = 0; i < n; i++)
			விடுவி(a[i]);
		விடுவி(a);
	}
	sshbuf_free(b);
	திரும்பு r;
}

நிலையான முழு
serialise_nullable_string(கட்டமைப்பு sshbuf *m, மாறிலி எழுத்து *s)
{
	முழு r;

	எனில் ((r = sshbuf_put_u8(m, s == வெற்று)) != 0 ||
	    (r = sshbuf_put_cstring(m, s)) != 0)
		திரும்பு r;
	திரும்பு 0;
}

நிலையான முழு
deserialise_nullable_string(கட்டமைப்பு sshbuf *m, எழுத்து **sp)
{
	முழு r;
	u_char flag;

	*sp = வெற்று;
	எனில் ((r = sshbuf_get_u8(m, &flag)) != 0 ||
	    (r = sshbuf_get_cstring(m, flag ? வெற்று : sp, வெற்று)) != 0)
		திரும்பு r;
	திரும்பு 0;
}

முழு
sshauthopt_serialise(மாறிலி கட்டமைப்பு sshauthopt *opts, கட்டமைப்பு sshbuf *m,
    முழு untrusted)
{
	முழு r = SSH_ERR_INTERNAL_ERROR;

	/* Flag options */
	எனில் ((r = sshbuf_put_u8(m, opts->permit_port_forwarding_flag)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->permit_agent_forwarding_flag)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->permit_x11_forwarding_flag)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->permit_pty_flag)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->permit_user_rc)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->restricted)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->cert_authority)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->no_require_user_presence)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->require_verify)) != 0)
		திரும்பு r;

	/* Simple integer options */
	எனில் ((r = sshbuf_put_u64(m, opts->valid_before)) != 0)
		திரும்பு r;

	/* tunnel number can be negative to indicate "unset" */
	எனில் ((r = sshbuf_put_u8(m, opts->force_tun_device == -1)) != 0 ||
	    (r = sshbuf_put_u32(m, (opts->force_tun_device < 0) ?
	    0 : (u_int)opts->force_tun_device)) != 0)
		திரும்பு r;

	/* String options; these may be NULL */
	எனில் ((r = serialise_nullable_string(m,
	    untrusted ? "yes" : opts->cert_principals)) != 0 ||
	    (r = serialise_nullable_string(m,
	    untrusted ? "true" : opts->force_command)) != 0 ||
	    (r = serialise_nullable_string(m,
	    untrusted ? வெற்று : opts->required_from_host_cert)) != 0 ||
	    (r = serialise_nullable_string(m,
	    untrusted ? வெற்று : opts->required_from_host_சாவிகள்)) != 0)
		திரும்பு r;

	/* Array options */
	எனில் ((r = serialise_array(m, opts->env,
	    untrusted ? 0 : opts->nenv)) != 0 ||
	    (r = serialise_array(m, opts->permitopen,
	    untrusted ? 0 : opts->npermitopen)) != 0 ||
	    (r = serialise_array(m, opts->permitlisten,
	    untrusted ? 0 : opts->npermitlisten)) != 0)
		திரும்பு r;

	/* success */
	திரும்பு 0;
}

முழு
sshauthopt_deserialise(கட்டமைப்பு sshbuf *m, கட்டமைப்பு sshauthopt **optsp)
{
	கட்டமைப்பு sshauthopt *opts = வெற்று;
	முழு r = SSH_ERR_INTERNAL_ERROR;
	u_char f;
	u_int tmp;

	எனில் ((opts = calloc(1, அளவு(*opts))) == வெற்று)
		திரும்பு SSH_ERR_ALLOC_FAIL;

	/* Flag options */
#define OPT_FLAG(x) \
	செய் { \
		எனில் ((r = sshbuf_get_u8(m, &f)) != 0) \
			செல் out; \
		opts->x = f; \
	} போது (0)
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
	எனில் ((r = sshbuf_get_u64(m, &opts->valid_before)) != 0)
		செல் out;

	/* tunnel number can be negative to indicate "unset" */
	எனில் ((r = sshbuf_get_u8(m, &f)) != 0 ||
	    (r = sshbuf_get_u32(m, &tmp)) != 0)
		செல் out;
	opts->force_tun_device = f ? -1 : (முழு)tmp;

	/* String options may be NULL */
	எனில் ((r = deserialise_nullable_string(m, &opts->cert_principals)) != 0 ||
	    (r = deserialise_nullable_string(m, &opts->force_command)) != 0 ||
	    (r = deserialise_nullable_string(m,
	    &opts->required_from_host_cert)) != 0 ||
	    (r = deserialise_nullable_string(m,
	    &opts->required_from_host_சாவிகள்)) != 0)
		செல் out;

	/* Array options */
	எனில் ((r = deserialise_array(m, &opts->env, &opts->nenv)) != 0 ||
	    (r = deserialise_array(m,
	    &opts->permitopen, &opts->npermitopen)) != 0 ||
	    (r = deserialise_array(m,
	    &opts->permitlisten, &opts->npermitlisten)) != 0)
		செல் out;

	/* success */
	r = 0;
	*optsp = opts;
	opts = வெற்று;
 out:
	sshauthopt_free(opts);
	திரும்பு r;
}
