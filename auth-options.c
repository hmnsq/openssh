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

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <sys/queue.h>

#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <netdb.h>
#അന്തര്ഭാവ <pwd.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <stdint.h>
#അന്തര്ഭാവ <stdarg.h>
#അന്തര്ഭാവ <ctype.h>
#അന്തര്ഭാവ <limits.h>

#അന്തര്ഭാവ "xmalloc.h"
#അന്തര്ഭാവ "ssherr.h"
#അന്തര്ഭാവ "log.h"
#അന്തര്ഭാവ "sshbuf.h"
#അന്തര്ഭാവ "misc.h"
#അന്തര്ഭാവ "sshkey.h"
#അന്തര്ഭാവ "match.h"
#അന്തര്ഭാവ "ssh2.h"
#അന്തര്ഭാവ "auth-options.h"

സ്ഥിതം പൂർണ്ണസംഖ്യ
dup_strings(അക്ഷരം ***dstp, size_t *ndstp, അക്ഷരം **src, size_t nsrc)
{
	അക്ഷരം **dst;
	size_t i, j;

	*dstp = ശൂന്യ;
	*ndstp = 0;

	എങ്കിൽ (nsrc == 0)
		തിരികെ 0;
	എങ്കിൽ (nsrc >= SIZE_MAX / വലുപ്പം(*src) ||
	    (dst = calloc(nsrc, വലുപ്പം(*src))) == ശൂന്യ)
		തിരികെ -1;
	വേണ്ടി (i = 0; i < nsrc; i++) {
		എങ്കിൽ ((dst[i] = strdup(src[i])) == ശൂന്യ) {
			വേണ്ടി (j = 0; j < i; j++)
				സ്വതന്ത്രം(dst[j]);
			സ്വതന്ത്രം(dst);
			തിരികെ -1;
		}
	}
	/* success */
	*dstp = dst;
	*ndstp = nsrc;
	തിരികെ 0;
}

#define OPTIONS_CRITICAL	1
#define OPTIONS_EXTENSIONS	2
സ്ഥിതം പൂർണ്ണസംഖ്യ
cert_option_list(ഘടന sshauthopt *opts, ഘടന sshbuf *oblob,
    u_int which, പൂർണ്ണസംഖ്യ crit)
{
	അക്ഷരം *command, *allowed;
	അക്ഷരം *name = ശൂന്യ;
	ഘടന sshbuf *c = ശൂന്യ, *data = ശൂന്യ;
	പൂർണ്ണസംഖ്യ r, ret = -1, found;

	എങ്കിൽ ((c = sshbuf_fromb(oblob)) == ശൂന്യ) {
		error_f("sshbuf_fromb failed");
		പോകുക out;
	}

	ആകുമ്പോൾ (sshbuf_len(c) > 0) {
		sshbuf_free(data);
		data = ശൂന്യ;
		എങ്കിൽ ((r = sshbuf_get_cstring(c, &name, ശൂന്യ)) != 0 ||
		    (r = sshbuf_froms(c, &data)) != 0) {
			error_r(r, "Unable to parse certificate options");
			പോകുക out;
		}
		debug3("found certificate option \"%.100s\" len %zu",
		    name, sshbuf_len(data));
		found = 0;
		എങ്കിൽ ((which & OPTIONS_EXTENSIONS) != 0) {
			എങ്കിൽ (strcmp(name, "no-touch-required") == 0) {
				opts->no_require_user_presence = 1;
				found = 1;
			} അല്ലെങ്കിൽ എങ്കിൽ (strcmp(name, "permit-X11-forwarding") == 0) {
				opts->permit_x11_forwarding_flag = 1;
				found = 1;
			} അല്ലെങ്കിൽ എങ്കിൽ (strcmp(name,
			    "permit-agent-forwarding") == 0) {
				opts->permit_agent_forwarding_flag = 1;
				found = 1;
			} അല്ലെങ്കിൽ എങ്കിൽ (strcmp(name,
			    "permit-port-forwarding") == 0) {
				opts->permit_port_forwarding_flag = 1;
				found = 1;
			} അല്ലെങ്കിൽ എങ്കിൽ (strcmp(name, "permit-pty") == 0) {
				opts->permit_pty_flag = 1;
				found = 1;
			} അല്ലെങ്കിൽ എങ്കിൽ (strcmp(name, "permit-user-rc") == 0) {
				opts->permit_user_rc = 1;
				found = 1;
			}
		}
		എങ്കിൽ (!found && (which & OPTIONS_CRITICAL) != 0) {
			എങ്കിൽ (strcmp(name, "verify-required") == 0) {
				opts->require_verify = 1;
				found = 1;
			} അല്ലെങ്കിൽ എങ്കിൽ (strcmp(name, "force-command") == 0) {
				എങ്കിൽ ((r = sshbuf_get_cstring(data, &command,
				    ശൂന്യ)) != 0) {
					error_r(r, "Unable to parse \"%s\" "
					    "section", name);
					പോകുക out;
				}
				എങ്കിൽ (opts->force_command != ശൂന്യ) {
					error("Certificate has multiple "
					    "force-command options");
					സ്വതന്ത്രം(command);
					പോകുക out;
				}
				opts->force_command = command;
				found = 1;
			} അല്ലെങ്കിൽ എങ്കിൽ (strcmp(name, "source-address") == 0) {
				എങ്കിൽ ((r = sshbuf_get_cstring(data, &allowed,
				    ശൂന്യ)) != 0) {
					error_r(r, "Unable to parse \"%s\" "
					    "section", name);
					പോകുക out;
				}
				എങ്കിൽ (opts->required_from_host_cert != ശൂന്യ) {
					error("Certificate has multiple "
					    "source-address options");
					സ്വതന്ത്രം(allowed);
					പോകുക out;
				}
				/* Check syntax */
				എങ്കിൽ (addr_match_cidr_list(ശൂന്യ, allowed) == -1) {
					error("Certificate source-address "
					    "contents invalid");
					സ്വതന്ത്രം(allowed);
					പോകുക out;
				}
				opts->required_from_host_cert = allowed;
				found = 1;
			}
		}

		എങ്കിൽ (!found) {
			എങ്കിൽ (crit) {
				error("Certificate critical option \"%s\" "
				    "is not supported", name);
				പോകുക out;
			} അല്ലെങ്കിൽ {
				logit("Certificate extension \"%s\" "
				    "is not supported", name);
			}
		} അല്ലെങ്കിൽ എങ്കിൽ (sshbuf_len(data) != 0) {
			error("Certificate option \"%s\" corrupt "
			    "(extra data)", name);
			പോകുക out;
		}
		സ്വതന്ത്രം(name);
		name = ശൂന്യ;
	}
	/* successfully parsed all options */
	ret = 0;

 out:
	സ്വതന്ത്രം(name);
	sshbuf_free(data);
	sshbuf_free(c);
	തിരികെ ret;
}

ഘടന sshauthopt *
sshauthopt_new(ശൂന്യം)
{
	ഘടന sshauthopt *ret;

	എങ്കിൽ ((ret = calloc(1, വലുപ്പം(*ret))) == ശൂന്യ)
		തിരികെ ശൂന്യ;
	ret->force_tun_device = -1;
	തിരികെ ret;
}

ശൂന്യം
sshauthopt_free(ഘടന sshauthopt *opts)
{
	size_t i;

	എങ്കിൽ (opts == ശൂന്യ)
		തിരികെ;

	സ്വതന്ത്രം(opts->cert_principals);
	സ്വതന്ത്രം(opts->force_command);
	സ്വതന്ത്രം(opts->required_from_host_cert);
	സ്വതന്ത്രം(opts->required_from_host_താക്കോലുകൾ);

	വേണ്ടി (i = 0; i < opts->nenv; i++)
		സ്വതന്ത്രം(opts->env[i]);
	സ്വതന്ത്രം(opts->env);

	വേണ്ടി (i = 0; i < opts->npermitopen; i++)
		സ്വതന്ത്രം(opts->permitopen[i]);
	സ്വതന്ത്രം(opts->permitopen);

	വേണ്ടി (i = 0; i < opts->npermitlisten; i++)
		സ്വതന്ത്രം(opts->permitlisten[i]);
	സ്വതന്ത്രം(opts->permitlisten);

	freezero(opts, വലുപ്പം(*opts));
}

ഘടന sshauthopt *
sshauthopt_new_with_താക്കോലുകൾ_defaults(ശൂന്യം)
{
	ഘടന sshauthopt *ret = ശൂന്യ;

	എങ്കിൽ ((ret = sshauthopt_new()) == ശൂന്യ)
		തിരികെ ശൂന്യ;

	/* Defaults for authorized_keys flags */
	ret->permit_port_forwarding_flag = 1;
	ret->permit_agent_forwarding_flag = 1;
	ret->permit_x11_forwarding_flag = 1;
	ret->permit_pty_flag = 1;
	ret->permit_user_rc = 1;
	തിരികെ ret;
}

/*
 * Parse and record a permitopen/permitlisten directive.
 * Return 0 on success. Return -1 on failure and sets *errstrp to error reason.
 */
സ്ഥിതം പൂർണ്ണസംഖ്യ
handle_permit(സ്ഥിരം അക്ഷരം **optsp, പൂർണ്ണസംഖ്യ allow_bare_port,
    അക്ഷരം ***permitsp, size_t *npermitsp, സ്ഥിരം അക്ഷരം **errstrp)
{
	അക്ഷരം *opt, *tmp, *cp, *host, **permits = *permitsp;
	size_t npermits = *npermitsp;
	സ്ഥിരം അക്ഷരം *errstr = "unknown error";

	എങ്കിൽ (npermits > SSH_AUTHOPT_PERMIT_MAX) {
		*errstrp = "too many permission directives";
		തിരികെ -1;
	}
	എങ്കിൽ ((opt = opt_dequote(optsp, &errstr)) == ശൂന്യ) {
		തിരികെ -1;
	}
	എങ്കിൽ (allow_bare_port && strchr(opt, ':') == ശൂന്യ) {
		/*
		 * Allow a bare port number in permitlisten to indicate a
		 * listen_host wildcard.
		 */
		എങ്കിൽ (asprintf(&tmp, "*:%s", opt) == -1) {
			സ്വതന്ത്രം(opt);
			*errstrp = "memory allocation failed";
			തിരികെ -1;
		}
		സ്വതന്ത്രം(opt);
		opt = tmp;
	}
	എങ്കിൽ ((tmp = strdup(opt)) == ശൂന്യ) {
		സ്വതന്ത്രം(opt);
		*errstrp = "memory allocation failed";
		തിരികെ -1;
	}
	cp = tmp;
	/* validate syntax before recording it. */
	host = hpdelim2(&cp, ശൂന്യ);
	എങ്കിൽ (host == ശൂന്യ || strlen(host) >= NI_MAXHOST) {
		സ്വതന്ത്രം(tmp);
		സ്വതന്ത്രം(opt);
		*errstrp = "invalid permission hostname";
		തിരികെ -1;
	}
	/*
	 * don't want to use permitopen_port to avoid
	 * dependency on channels.[ch] here.
	 */
	എങ്കിൽ (cp == ശൂന്യ ||
	    (strcmp(cp, "*") != 0 && a2port(cp) <= 0)) {
		സ്വതന്ത്രം(tmp);
		സ്വതന്ത്രം(opt);
		*errstrp = "invalid permission port";
		തിരികെ -1;
	}
	/* XXX - add streamlocal support */
	സ്വതന്ത്രം(tmp);
	/* Record it */
	എങ്കിൽ ((permits = recallocarray(permits, npermits, npermits + 1,
	    വലുപ്പം(*permits))) == ശൂന്യ) {
		സ്വതന്ത്രം(opt);
		/* NB. don't update *permitsp if alloc fails */
		*errstrp = "memory allocation failed";
		തിരികെ -1;
	}
	permits[npermits++] = opt;
	*permitsp = permits;
	*npermitsp = npermits;
	തിരികെ 0;
}

ഘടന sshauthopt *
sshauthopt_parse(സ്ഥിരം അക്ഷരം *opts, സ്ഥിരം അക്ഷരം **errstrp)
{
	അക്ഷരം **oarray, *opt, *cp, *tmp;
	പൂർണ്ണസംഖ്യ r;
	ഘടന sshauthopt *ret = ശൂന്യ;
	സ്ഥിരം അക്ഷരം *errstr = "unknown error";
	uint64_t valid_before;
	size_t i, l;

	എങ്കിൽ (errstrp != ശൂന്യ)
		*errstrp = ശൂന്യ;
	എങ്കിൽ ((ret = sshauthopt_new_with_താക്കോലുകൾ_defaults()) == ശൂന്യ)
		പോകുക alloc_fail;

	എങ്കിൽ (opts == ശൂന്യ)
		തിരികെ ret;

	ആകുമ്പോൾ (*opts && *opts != ' ' && *opts != '\t') {
		/* flag options */
		എങ്കിൽ ((r = opt_flag("restrict", 0, &opts)) != -1) {
			ret->restricted = 1;
			ret->permit_port_forwarding_flag = 0;
			ret->permit_agent_forwarding_flag = 0;
			ret->permit_x11_forwarding_flag = 0;
			ret->permit_pty_flag = 0;
			ret->permit_user_rc = 0;
		} അല്ലെങ്കിൽ എങ്കിൽ ((r = opt_flag("cert-authority", 0, &opts)) != -1) {
			ret->cert_authority = r;
		} അല്ലെങ്കിൽ എങ്കിൽ ((r = opt_flag("port-forwarding", 1, &opts)) != -1) {
			ret->permit_port_forwarding_flag = r == 1;
		} അല്ലെങ്കിൽ എങ്കിൽ ((r = opt_flag("agent-forwarding", 1, &opts)) != -1) {
			ret->permit_agent_forwarding_flag = r == 1;
		} അല്ലെങ്കിൽ എങ്കിൽ ((r = opt_flag("x11-forwarding", 1, &opts)) != -1) {
			ret->permit_x11_forwarding_flag = r == 1;
		} അല്ലെങ്കിൽ എങ്കിൽ ((r = opt_flag("touch-required", 1, &opts)) != -1) {
			ret->no_require_user_presence = r != 1; /* NB. flip */
		} അല്ലെങ്കിൽ എങ്കിൽ ((r = opt_flag("verify-required", 1, &opts)) != -1) {
			ret->require_verify = r == 1;
		} അല്ലെങ്കിൽ എങ്കിൽ ((r = opt_flag("pty", 1, &opts)) != -1) {
			ret->permit_pty_flag = r == 1;
		} അല്ലെങ്കിൽ എങ്കിൽ ((r = opt_flag("user-rc", 1, &opts)) != -1) {
			ret->permit_user_rc = r == 1;
		} അല്ലെങ്കിൽ എങ്കിൽ (opt_match(&opts, "command")) {
			എങ്കിൽ (ret->force_command != ശൂന്യ) {
				errstr = "multiple \"command\" clauses";
				പോകുക fail;
			}
			ret->force_command = opt_dequote(&opts, &errstr);
			എങ്കിൽ (ret->force_command == ശൂന്യ)
				പോകുക fail;
		} അല്ലെങ്കിൽ എങ്കിൽ (opt_match(&opts, "principals")) {
			എങ്കിൽ (ret->cert_principals != ശൂന്യ) {
				errstr = "multiple \"principals\" clauses";
				പോകുക fail;
			}
			ret->cert_principals = opt_dequote(&opts, &errstr);
			എങ്കിൽ (ret->cert_principals == ശൂന്യ)
				പോകുക fail;
		} അല്ലെങ്കിൽ എങ്കിൽ (opt_match(&opts, "from")) {
			എങ്കിൽ (ret->required_from_host_താക്കോലുകൾ != ശൂന്യ) {
				errstr = "multiple \"from\" clauses";
				പോകുക fail;
			}
			ret->required_from_host_താക്കോലുകൾ = opt_dequote(&opts,
			    &errstr);
			എങ്കിൽ (ret->required_from_host_താക്കോലുകൾ == ശൂന്യ)
				പോകുക fail;
		} അല്ലെങ്കിൽ എങ്കിൽ (opt_match(&opts, "expiry-time")) {
			എങ്കിൽ ((opt = opt_dequote(&opts, &errstr)) == ശൂന്യ)
				പോകുക fail;
			എങ്കിൽ (parse_absolute_time(opt, &valid_before) != 0 ||
			    valid_before == 0) {
				സ്വതന്ത്രം(opt);
				errstr = "invalid expires time";
				പോകുക fail;
			}
			സ്വതന്ത്രം(opt);
			എങ്കിൽ (ret->valid_before == 0 ||
			    valid_before < ret->valid_before)
				ret->valid_before = valid_before;
		} അല്ലെങ്കിൽ എങ്കിൽ (opt_match(&opts, "environment")) {
			എങ്കിൽ (ret->nenv > SSH_AUTHOPT_ENV_MAX) {
				errstr = "too many environment strings";
				പോകുക fail;
			}
			എങ്കിൽ ((opt = opt_dequote(&opts, &errstr)) == ശൂന്യ)
				പോകുക fail;
			/* env name must be alphanumeric and followed by '=' */
			എങ്കിൽ ((tmp = strchr(opt, '=')) == ശൂന്യ) {
				സ്വതന്ത്രം(opt);
				errstr = "invalid environment string";
				പോകുക fail;
			}
			എങ്കിൽ ((cp = strdup(opt)) == ശൂന്യ) {
				സ്വതന്ത്രം(opt);
				പോകുക alloc_fail;
			}
			l = (size_t)(tmp - opt);
			cp[l] = '\0'; /* truncate at '=' */
			എങ്കിൽ (!valid_env_name(cp)) {
				സ്വതന്ത്രം(cp);
				സ്വതന്ത്രം(opt);
				errstr = "invalid environment string";
				പോകുക fail;
			}
			/* Check for duplicates; XXX O(n*log(n)) */
			വേണ്ടി (i = 0; i < ret->nenv; i++) {
				എങ്കിൽ (strncmp(ret->env[i], cp, l) == 0 &&
				    ret->env[i][l] == '=')
					നിർത്തുക;
			}
			സ്വതന്ത്രം(cp);
			/* First match wins */
			എങ്കിൽ (i >= ret->nenv) {
				/* Append it. */
				oarray = ret->env;
				എങ്കിൽ ((ret->env = recallocarray(ret->env,
				    ret->nenv, ret->nenv + 1,
				    വലുപ്പം(*ret->env))) == ശൂന്യ) {
					സ്വതന്ത്രം(opt);
					/* put it back for cleanup */
					ret->env = oarray;
					പോകുക alloc_fail;
				}
				ret->env[ret->nenv++] = opt;
				opt = ശൂന്യ; /* transferred */
			}
			സ്വതന്ത്രം(opt);
		} അല്ലെങ്കിൽ എങ്കിൽ (opt_match(&opts, "permitopen")) {
			എങ്കിൽ (handle_permit(&opts, 0, &ret->permitopen,
			    &ret->npermitopen, &errstr) != 0)
				പോകുക fail;
		} അല്ലെങ്കിൽ എങ്കിൽ (opt_match(&opts, "permitlisten")) {
			എങ്കിൽ (handle_permit(&opts, 1, &ret->permitlisten,
			    &ret->npermitlisten, &errstr) != 0)
				പോകുക fail;
		} അല്ലെങ്കിൽ എങ്കിൽ (opt_match(&opts, "tunnel")) {
			എങ്കിൽ ((opt = opt_dequote(&opts, &errstr)) == ശൂന്യ)
				പോകുക fail;
			ret->force_tun_device = a2tun(opt, ശൂന്യ);
			സ്വതന്ത്രം(opt);
			എങ്കിൽ (ret->force_tun_device == SSH_TUNID_ERR) {
				errstr = "invalid tun device";
				പോകുക fail;
			}
		}
		/*
		 * Skip the comma, and move to the next option
		 * (or break out if there are no more).
		 */
		എങ്കിൽ (*opts == '\0' || *opts == ' ' || *opts == '\t')
			നിർത്തുക;		/* End of options. */
		/* Anything other than a comma is an unknown option */
		എങ്കിൽ (*opts != ',') {
			errstr = "unknown key option";
			പോകുക fail;
		}
		opts++;
		എങ്കിൽ (*opts == '\0') {
			errstr = "unexpected end-of-options";
			പോകുക fail;
		}
	}

	/* success */
	എങ്കിൽ (errstrp != ശൂന്യ)
		*errstrp = ശൂന്യ;
	തിരികെ ret;

alloc_fail:
	errstr = "memory allocation failed";
fail:
	sshauthopt_free(ret);
	എങ്കിൽ (errstrp != ശൂന്യ)
		*errstrp = errstr;
	തിരികെ ശൂന്യ;
}

ഘടന sshauthopt *
sshauthopt_from_cert(ഘടന sshkey *k)
{
	ഘടന sshauthopt *ret;

	എങ്കിൽ (k == ശൂന്യ || !sshkey_type_is_cert(k->type) || k->cert == ശൂന്യ ||
	    k->cert->type != SSH2_CERT_TYPE_USER)
		തിരികെ ശൂന്യ;

	എങ്കിൽ ((ret = sshauthopt_new()) == ശൂന്യ)
		തിരികെ ശൂന്യ;

	/* Handle options and critical extensions separately */
	എങ്കിൽ (cert_option_list(ret, k->cert->critical,
	    OPTIONS_CRITICAL, 1) == -1) {
		sshauthopt_free(ret);
		തിരികെ ശൂന്യ;
	}
	എങ്കിൽ (cert_option_list(ret, k->cert->extensions,
	    OPTIONS_EXTENSIONS, 0) == -1) {
		sshauthopt_free(ret);
		തിരികെ ശൂന്യ;
	}
	/* success */
	തിരികെ ret;
}

/*
 * Merges "additional" options to "primary" and returns the result.
 * NB. Some options from primary have primacy.
 */
ഘടന sshauthopt *
sshauthopt_merge(സ്ഥിരം ഘടന sshauthopt *primary,
    സ്ഥിരം ഘടന sshauthopt *additional, സ്ഥിരം അക്ഷരം **errstrp)
{
	ഘടന sshauthopt *ret;
	സ്ഥിരം അക്ഷരം *errstr = "internal error";
	സ്ഥിരം അക്ഷരം *tmp;

	എങ്കിൽ (errstrp != ശൂന്യ)
		*errstrp = ശൂന്യ;

	എങ്കിൽ ((ret = sshauthopt_new()) == ശൂന്യ)
		പോകുക alloc_fail;

	/* cert_authority and cert_principals are cleared in result */

	/* Prefer access lists from primary. */
	/* XXX err is both set and mismatch? */
	tmp = primary->required_from_host_cert;
	എങ്കിൽ (tmp == ശൂന്യ)
		tmp = additional->required_from_host_cert;
	എങ്കിൽ (tmp != ശൂന്യ && (ret->required_from_host_cert = strdup(tmp)) == ശൂന്യ)
		പോകുക alloc_fail;
	tmp = primary->required_from_host_താക്കോലുകൾ;
	എങ്കിൽ (tmp == ശൂന്യ)
		tmp = additional->required_from_host_താക്കോലുകൾ;
	എങ്കിൽ (tmp != ശൂന്യ && (ret->required_from_host_താക്കോലുകൾ = strdup(tmp)) == ശൂന്യ)
		പോകുക alloc_fail;

	/*
	 * force_tun_device, permitopen/permitlisten and environment all
	 * prefer the primary.
	 */
	ret->force_tun_device = primary->force_tun_device;
	എങ്കിൽ (ret->force_tun_device == -1)
		ret->force_tun_device = additional->force_tun_device;
	എങ്കിൽ (primary->nenv > 0) {
		എങ്കിൽ (dup_strings(&ret->env, &ret->nenv,
		    primary->env, primary->nenv) != 0)
			പോകുക alloc_fail;
	} അല്ലെങ്കിൽ എങ്കിൽ (additional->nenv) {
		എങ്കിൽ (dup_strings(&ret->env, &ret->nenv,
		    additional->env, additional->nenv) != 0)
			പോകുക alloc_fail;
	}
	എങ്കിൽ (primary->npermitopen > 0) {
		എങ്കിൽ (dup_strings(&ret->permitopen, &ret->npermitopen,
		    primary->permitopen, primary->npermitopen) != 0)
			പോകുക alloc_fail;
	} അല്ലെങ്കിൽ എങ്കിൽ (additional->npermitopen > 0) {
		എങ്കിൽ (dup_strings(&ret->permitopen, &ret->npermitopen,
		    additional->permitopen, additional->npermitopen) != 0)
			പോകുക alloc_fail;
	}

	എങ്കിൽ (primary->npermitlisten > 0) {
		എങ്കിൽ (dup_strings(&ret->permitlisten, &ret->npermitlisten,
		    primary->permitlisten, primary->npermitlisten) != 0)
			പോകുക alloc_fail;
	} അല്ലെങ്കിൽ എങ്കിൽ (additional->npermitlisten > 0) {
		എങ്കിൽ (dup_strings(&ret->permitlisten, &ret->npermitlisten,
		    additional->permitlisten, additional->npermitlisten) != 0)
			പോകുക alloc_fail;
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
	എങ്കിൽ (primary->valid_before != 0)
		ret->valid_before = primary->valid_before;
	എങ്കിൽ (additional->valid_before != 0 &&
	    additional->valid_before < ret->valid_before)
		ret->valid_before = additional->valid_before;

	/*
	 * When both multiple forced-command are specified, only
	 * proceed if they are identical, otherwise fail.
	 */
	എങ്കിൽ (primary->force_command != ശൂന്യ &&
	    additional->force_command != ശൂന്യ) {
		എങ്കിൽ (strcmp(primary->force_command,
		    additional->force_command) == 0) {
			/* ok */
			ret->force_command = strdup(primary->force_command);
			എങ്കിൽ (ret->force_command == ശൂന്യ)
				പോകുക alloc_fail;
		} അല്ലെങ്കിൽ {
			errstr = "forced command options do not match";
			പോകുക fail;
		}
	} അല്ലെങ്കിൽ എങ്കിൽ (primary->force_command != ശൂന്യ) {
		എങ്കിൽ ((ret->force_command = strdup(
		    primary->force_command)) == ശൂന്യ)
			പോകുക alloc_fail;
	} അല്ലെങ്കിൽ എങ്കിൽ (additional->force_command != ശൂന്യ) {
		എങ്കിൽ ((ret->force_command = strdup(
		    additional->force_command)) == ശൂന്യ)
			പോകുക alloc_fail;
	}
	/* success */
	എങ്കിൽ (errstrp != ശൂന്യ)
		*errstrp = ശൂന്യ;
	തിരികെ ret;

 alloc_fail:
	errstr = "memory allocation failed";
 fail:
	എങ്കിൽ (errstrp != ശൂന്യ)
		*errstrp = errstr;
	sshauthopt_free(ret);
	തിരികെ ശൂന്യ;
}

/*
 * Copy options
 */
ഘടന sshauthopt *
sshauthopt_copy(സ്ഥിരം ഘടന sshauthopt *orig)
{
	ഘടന sshauthopt *ret;

	എങ്കിൽ ((ret = sshauthopt_new()) == ശൂന്യ)
		തിരികെ ശൂന്യ;

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
	ചെയ്യുക { \
		എങ്കിൽ (orig->x != ശൂന്യ && (ret->x = strdup(orig->x)) == ശൂന്യ) { \
			sshauthopt_free(ret); \
			തിരികെ ശൂന്യ; \
		} \
	} ആകുമ്പോൾ (0)
	OPTSTRING(cert_principals);
	OPTSTRING(force_command);
	OPTSTRING(required_from_host_cert);
	OPTSTRING(required_from_host_താക്കോലുകൾ);
#undef OPTSTRING

	എങ്കിൽ (dup_strings(&ret->env, &ret->nenv, orig->env, orig->nenv) != 0 ||
	    dup_strings(&ret->permitopen, &ret->npermitopen,
	    orig->permitopen, orig->npermitopen) != 0 ||
	    dup_strings(&ret->permitlisten, &ret->npermitlisten,
	    orig->permitlisten, orig->npermitlisten) != 0) {
		sshauthopt_free(ret);
		തിരികെ ശൂന്യ;
	}
	തിരികെ ret;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
serialise_array(ഘടന sshbuf *m, അക്ഷരം **a, size_t n)
{
	ഘടന sshbuf *b;
	size_t i;
	പൂർണ്ണസംഖ്യ r = SSH_ERR_INTERNAL_ERROR;

	എങ്കിൽ (n > INT_MAX)
		തിരികെ SSH_ERR_INTERNAL_ERROR;

	എങ്കിൽ ((b = sshbuf_new()) == ശൂന്യ) {
		തിരികെ SSH_ERR_ALLOC_FAIL;
	}
	വേണ്ടി (i = 0; i < n; i++) {
		എങ്കിൽ ((r = sshbuf_put_cstring(b, a[i])) != 0)
			പോകുക out;
	}
	എങ്കിൽ ((r = sshbuf_put_u32(m, n)) != 0 ||
	    (r = sshbuf_put_stringb(m, b)) != 0)
		പോകുക out;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	തിരികെ r;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
deserialise_array(ഘടന sshbuf *m, അക്ഷരം ***ap, size_t *np)
{
	അക്ഷരം **a = ശൂന്യ;
	size_t i, n = 0;
	ഘടന sshbuf *b = ശൂന്യ;
	u_int tmp;
	പൂർണ്ണസംഖ്യ r = SSH_ERR_INTERNAL_ERROR;

	എങ്കിൽ ((r = sshbuf_get_u32(m, &tmp)) != 0 ||
	    (r = sshbuf_froms(m, &b)) != 0)
		പോകുക out;
	എങ്കിൽ (tmp > INT_MAX) {
		r = SSH_ERR_INVALID_FORMAT;
		പോകുക out;
	}
	n = tmp;
	എങ്കിൽ (n > 0 && (a = calloc(n, വലുപ്പം(*a))) == ശൂന്യ) {
		r = SSH_ERR_ALLOC_FAIL;
		പോകുക out;
	}
	വേണ്ടി (i = 0; i < n; i++) {
		എങ്കിൽ ((r = sshbuf_get_cstring(b, &a[i], ശൂന്യ)) != 0)
			പോകുക out;
	}
	/* success */
	r = 0;
	*ap = a;
	a = ശൂന്യ;
	*np = n;
	n = 0;
 out:
	എങ്കിൽ (a != ശൂന്യ) {
		വേണ്ടി (i = 0; i < n; i++)
			സ്വതന്ത്രം(a[i]);
		സ്വതന്ത്രം(a);
	}
	sshbuf_free(b);
	തിരികെ r;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
serialise_nullable_string(ഘടന sshbuf *m, സ്ഥിരം അക്ഷരം *s)
{
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((r = sshbuf_put_u8(m, s == ശൂന്യ)) != 0 ||
	    (r = sshbuf_put_cstring(m, s)) != 0)
		തിരികെ r;
	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
deserialise_nullable_string(ഘടന sshbuf *m, അക്ഷരം **sp)
{
	പൂർണ്ണസംഖ്യ r;
	u_char flag;

	*sp = ശൂന്യ;
	എങ്കിൽ ((r = sshbuf_get_u8(m, &flag)) != 0 ||
	    (r = sshbuf_get_cstring(m, flag ? ശൂന്യ : sp, ശൂന്യ)) != 0)
		തിരികെ r;
	തിരികെ 0;
}

പൂർണ്ണസംഖ്യ
sshauthopt_serialise(സ്ഥിരം ഘടന sshauthopt *opts, ഘടന sshbuf *m,
    പൂർണ്ണസംഖ്യ untrusted)
{
	പൂർണ്ണസംഖ്യ r = SSH_ERR_INTERNAL_ERROR;

	/* Flag options */
	എങ്കിൽ ((r = sshbuf_put_u8(m, opts->permit_port_forwarding_flag)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->permit_agent_forwarding_flag)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->permit_x11_forwarding_flag)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->permit_pty_flag)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->permit_user_rc)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->restricted)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->cert_authority)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->no_require_user_presence)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->require_verify)) != 0)
		തിരികെ r;

	/* Simple integer options */
	എങ്കിൽ ((r = sshbuf_put_u64(m, opts->valid_before)) != 0)
		തിരികെ r;

	/* tunnel number can be negative to indicate "unset" */
	എങ്കിൽ ((r = sshbuf_put_u8(m, opts->force_tun_device == -1)) != 0 ||
	    (r = sshbuf_put_u32(m, (opts->force_tun_device < 0) ?
	    0 : (u_int)opts->force_tun_device)) != 0)
		തിരികെ r;

	/* String options; these may be NULL */
	എങ്കിൽ ((r = serialise_nullable_string(m,
	    untrusted ? "yes" : opts->cert_principals)) != 0 ||
	    (r = serialise_nullable_string(m,
	    untrusted ? "true" : opts->force_command)) != 0 ||
	    (r = serialise_nullable_string(m,
	    untrusted ? ശൂന്യ : opts->required_from_host_cert)) != 0 ||
	    (r = serialise_nullable_string(m,
	    untrusted ? ശൂന്യ : opts->required_from_host_താക്കോലുകൾ)) != 0)
		തിരികെ r;

	/* Array options */
	എങ്കിൽ ((r = serialise_array(m, opts->env,
	    untrusted ? 0 : opts->nenv)) != 0 ||
	    (r = serialise_array(m, opts->permitopen,
	    untrusted ? 0 : opts->npermitopen)) != 0 ||
	    (r = serialise_array(m, opts->permitlisten,
	    untrusted ? 0 : opts->npermitlisten)) != 0)
		തിരികെ r;

	/* success */
	തിരികെ 0;
}

പൂർണ്ണസംഖ്യ
sshauthopt_deserialise(ഘടന sshbuf *m, ഘടന sshauthopt **optsp)
{
	ഘടന sshauthopt *opts = ശൂന്യ;
	പൂർണ്ണസംഖ്യ r = SSH_ERR_INTERNAL_ERROR;
	u_char f;
	u_int tmp;

	എങ്കിൽ ((opts = calloc(1, വലുപ്പം(*opts))) == ശൂന്യ)
		തിരികെ SSH_ERR_ALLOC_FAIL;

	/* Flag options */
#define OPT_FLAG(x) \
	ചെയ്യുക { \
		എങ്കിൽ ((r = sshbuf_get_u8(m, &f)) != 0) \
			പോകുക out; \
		opts->x = f; \
	} ആകുമ്പോൾ (0)
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
	എങ്കിൽ ((r = sshbuf_get_u64(m, &opts->valid_before)) != 0)
		പോകുക out;

	/* tunnel number can be negative to indicate "unset" */
	എങ്കിൽ ((r = sshbuf_get_u8(m, &f)) != 0 ||
	    (r = sshbuf_get_u32(m, &tmp)) != 0)
		പോകുക out;
	opts->force_tun_device = f ? -1 : (പൂർണ്ണസംഖ്യ)tmp;

	/* String options may be NULL */
	എങ്കിൽ ((r = deserialise_nullable_string(m, &opts->cert_principals)) != 0 ||
	    (r = deserialise_nullable_string(m, &opts->force_command)) != 0 ||
	    (r = deserialise_nullable_string(m,
	    &opts->required_from_host_cert)) != 0 ||
	    (r = deserialise_nullable_string(m,
	    &opts->required_from_host_താക്കോലുകൾ)) != 0)
		പോകുക out;

	/* Array options */
	എങ്കിൽ ((r = deserialise_array(m, &opts->env, &opts->nenv)) != 0 ||
	    (r = deserialise_array(m,
	    &opts->permitopen, &opts->npermitopen)) != 0 ||
	    (r = deserialise_array(m,
	    &opts->permitlisten, &opts->npermitlisten)) != 0)
		പോകുക out;

	/* success */
	r = 0;
	*optsp = opts;
	opts = ശൂന്യ;
 out:
	sshauthopt_free(opts);
	തിരികെ r;
}
