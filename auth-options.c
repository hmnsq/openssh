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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <sys/queue.h>

#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <netdb.h>
#ಅನ್ತರ್ಭಾವ <pwd.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stdint.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <ctype.h>
#ಅನ್ತರ್ಭಾವ <limits.h>

#ಅನ್ತರ್ಭಾವ "xmalloc.h"
#ಅನ್ತರ್ಭಾವ "ssherr.h"
#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "misc.h"
#ಅನ್ತರ್ಭಾವ "sshkey.h"
#ಅನ್ತರ್ಭಾವ "match.h"
#ಅನ್ತರ್ಭಾವ "ssh2.h"
#ಅನ್ತರ್ಭಾವ "auth-options.h"

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
dup_strings(ವರ್ಣ ***dstp, size_t *ndstp, ವರ್ಣ **src, size_t nsrc)
{
	ವರ್ಣ **dst;
	size_t i, j;

	*dstp = ರಿಕ್ತ;
	*ndstp = 0;

	ಯದಿ (nsrc == 0)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಯದಿ (nsrc >= SIZE_MAX / ಪರಿಮಾಣ(*src) ||
	    (dst = calloc(nsrc, ಪರಿಮಾಣ(*src))) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ -1;
	ಪ್ರತಿ (i = 0; i < nsrc; i++) {
		ಯದಿ ((dst[i] = strdup(src[i])) == ರಿಕ್ತ) {
			ಪ್ರತಿ (j = 0; j < i; j++)
				ಮುಕ್ತ(dst[j]);
			ಮುಕ್ತ(dst);
			ಪ್ರತ್ಯಾಗಮ -1;
		}
	}
	/* success */
	*dstp = dst;
	*ndstp = nsrc;
	ಪ್ರತ್ಯಾಗಮ 0;
}

#define OPTIONS_CRITICAL	1
#define OPTIONS_EXTENSIONS	2
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
cert_option_list(ಸಂರಚನಾ sshauthopt *opts, ಸಂರಚನಾ sshbuf *oblob,
    u_int which, ಪೂರ್ಣಾಙ್ಕ crit)
{
	ವರ್ಣ *command, *allowed;
	ವರ್ಣ *name = ರಿಕ್ತ;
	ಸಂರಚನಾ sshbuf *c = ರಿಕ್ತ, *data = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ r, ret = -1, found;

	ಯದಿ ((c = sshbuf_fromb(oblob)) == ರಿಕ್ತ) {
		error_f("sshbuf_fromb failed");
		ಗಚ್ಛ out;
	}

	ಯಾವತ್ (sshbuf_len(c) > 0) {
		sshbuf_free(data);
		data = ರಿಕ್ತ;
		ಯದಿ ((r = sshbuf_get_cstring(c, &name, ರಿಕ್ತ)) != 0 ||
		    (r = sshbuf_froms(c, &data)) != 0) {
			error_r(r, "Unable to parse certificate options");
			ಗಚ್ಛ out;
		}
		debug3("found certificate option \"%.100s\" len %zu",
		    name, sshbuf_len(data));
		found = 0;
		ಯದಿ ((which & OPTIONS_EXTENSIONS) != 0) {
			ಯದಿ (strcmp(name, "no-touch-required") == 0) {
				opts->no_require_user_presence = 1;
				found = 1;
			} ಅನ್ಯಥಾ ಯದಿ (strcmp(name, "permit-X11-forwarding") == 0) {
				opts->permit_x11_forwarding_flag = 1;
				found = 1;
			} ಅನ್ಯಥಾ ಯದಿ (strcmp(name,
			    "permit-agent-forwarding") == 0) {
				opts->permit_agent_forwarding_flag = 1;
				found = 1;
			} ಅನ್ಯಥಾ ಯದಿ (strcmp(name,
			    "permit-port-forwarding") == 0) {
				opts->permit_port_forwarding_flag = 1;
				found = 1;
			} ಅನ್ಯಥಾ ಯದಿ (strcmp(name, "permit-pty") == 0) {
				opts->permit_pty_flag = 1;
				found = 1;
			} ಅನ್ಯಥಾ ಯದಿ (strcmp(name, "permit-user-rc") == 0) {
				opts->permit_user_rc = 1;
				found = 1;
			}
		}
		ಯದಿ (!found && (which & OPTIONS_CRITICAL) != 0) {
			ಯದಿ (strcmp(name, "verify-required") == 0) {
				opts->require_verify = 1;
				found = 1;
			} ಅನ್ಯಥಾ ಯದಿ (strcmp(name, "force-command") == 0) {
				ಯದಿ ((r = sshbuf_get_cstring(data, &command,
				    ರಿಕ್ತ)) != 0) {
					error_r(r, "Unable to parse \"%s\" "
					    "section", name);
					ಗಚ್ಛ out;
				}
				ಯದಿ (opts->force_command != ರಿಕ್ತ) {
					error("Certificate has multiple "
					    "force-command options");
					ಮುಕ್ತ(command);
					ಗಚ್ಛ out;
				}
				opts->force_command = command;
				found = 1;
			} ಅನ್ಯಥಾ ಯದಿ (strcmp(name, "source-address") == 0) {
				ಯದಿ ((r = sshbuf_get_cstring(data, &allowed,
				    ರಿಕ್ತ)) != 0) {
					error_r(r, "Unable to parse \"%s\" "
					    "section", name);
					ಗಚ್ಛ out;
				}
				ಯದಿ (opts->required_from_host_cert != ರಿಕ್ತ) {
					error("Certificate has multiple "
					    "source-address options");
					ಮುಕ್ತ(allowed);
					ಗಚ್ಛ out;
				}
				/* Check syntax */
				ಯದಿ (addr_match_cidr_list(ರಿಕ್ತ, allowed) == -1) {
					error("Certificate source-address "
					    "contents invalid");
					ಮುಕ್ತ(allowed);
					ಗಚ್ಛ out;
				}
				opts->required_from_host_cert = allowed;
				found = 1;
			}
		}

		ಯದಿ (!found) {
			ಯದಿ (crit) {
				error("Certificate critical option \"%s\" "
				    "is not supported", name);
				ಗಚ್ಛ out;
			} ಅನ್ಯಥಾ {
				logit("Certificate extension \"%s\" "
				    "is not supported", name);
			}
		} ಅನ್ಯಥಾ ಯದಿ (sshbuf_len(data) != 0) {
			error("Certificate option \"%s\" corrupt "
			    "(extra data)", name);
			ಗಚ್ಛ out;
		}
		ಮುಕ್ತ(name);
		name = ರಿಕ್ತ;
	}
	/* successfully parsed all options */
	ret = 0;

 out:
	ಮುಕ್ತ(name);
	sshbuf_free(data);
	sshbuf_free(c);
	ಪ್ರತ್ಯಾಗಮ ret;
}

ಸಂರಚನಾ sshauthopt *
sshauthopt_new(ಶೂನ್ಯ)
{
	ಸಂರಚನಾ sshauthopt *ret;

	ಯದಿ ((ret = calloc(1, ಪರಿಮಾಣ(*ret))) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	ret->force_tun_device = -1;
	ಪ್ರತ್ಯಾಗಮ ret;
}

ಶೂನ್ಯ
sshauthopt_free(ಸಂರಚನಾ sshauthopt *opts)
{
	size_t i;

	ಯದಿ (opts == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ;

	ಮುಕ್ತ(opts->cert_principals);
	ಮುಕ್ತ(opts->force_command);
	ಮುಕ್ತ(opts->required_from_host_cert);
	ಮುಕ್ತ(opts->required_from_host_ಕೀಲಿಗಳು);

	ಪ್ರತಿ (i = 0; i < opts->nenv; i++)
		ಮುಕ್ತ(opts->env[i]);
	ಮುಕ್ತ(opts->env);

	ಪ್ರತಿ (i = 0; i < opts->npermitopen; i++)
		ಮುಕ್ತ(opts->permitopen[i]);
	ಮುಕ್ತ(opts->permitopen);

	ಪ್ರತಿ (i = 0; i < opts->npermitlisten; i++)
		ಮುಕ್ತ(opts->permitlisten[i]);
	ಮುಕ್ತ(opts->permitlisten);

	freezero(opts, ಪರಿಮಾಣ(*opts));
}

ಸಂರಚನಾ sshauthopt *
sshauthopt_new_with_ಕೀಲಿಗಳು_defaults(ಶೂನ್ಯ)
{
	ಸಂರಚನಾ sshauthopt *ret = ರಿಕ್ತ;

	ಯದಿ ((ret = sshauthopt_new()) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;

	/* Defaults for authorized_keys flags */
	ret->permit_port_forwarding_flag = 1;
	ret->permit_agent_forwarding_flag = 1;
	ret->permit_x11_forwarding_flag = 1;
	ret->permit_pty_flag = 1;
	ret->permit_user_rc = 1;
	ಪ್ರತ್ಯಾಗಮ ret;
}

/*
 * Parse and record a permitopen/permitlisten directive.
 * Return 0 on success. Return -1 on failure and sets *errstrp to error reason.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
handle_permit(ಧ್ರುವ ವರ್ಣ **optsp, ಪೂರ್ಣಾಙ್ಕ allow_bare_port,
    ವರ್ಣ ***permitsp, size_t *npermitsp, ಧ್ರುವ ವರ್ಣ **errstrp)
{
	ವರ್ಣ *opt, *tmp, *cp, *host, **permits = *permitsp;
	size_t npermits = *npermitsp;
	ಧ್ರುವ ವರ್ಣ *errstr = "unknown error";

	ಯದಿ (npermits > SSH_AUTHOPT_PERMIT_MAX) {
		*errstrp = "too many permission directives";
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	ಯದಿ ((opt = opt_dequote(optsp, &errstr)) == ರಿಕ್ತ) {
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	ಯದಿ (allow_bare_port && strchr(opt, ':') == ರಿಕ್ತ) {
		/*
		 * Allow a bare port number in permitlisten to indicate a
		 * listen_host wildcard.
		 */
		ಯದಿ (asprintf(&tmp, "*:%s", opt) == -1) {
			ಮುಕ್ತ(opt);
			*errstrp = "memory allocation failed";
			ಪ್ರತ್ಯಾಗಮ -1;
		}
		ಮುಕ್ತ(opt);
		opt = tmp;
	}
	ಯದಿ ((tmp = strdup(opt)) == ರಿಕ್ತ) {
		ಮುಕ್ತ(opt);
		*errstrp = "memory allocation failed";
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	cp = tmp;
	/* validate syntax before recording it. */
	host = hpdelim2(&cp, ರಿಕ್ತ);
	ಯದಿ (host == ರಿಕ್ತ || strlen(host) >= NI_MAXHOST) {
		ಮುಕ್ತ(tmp);
		ಮುಕ್ತ(opt);
		*errstrp = "invalid permission hostname";
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	/*
	 * don't want to use permitopen_port to avoid
	 * dependency on channels.[ch] here.
	 */
	ಯದಿ (cp == ರಿಕ್ತ ||
	    (strcmp(cp, "*") != 0 && a2port(cp) <= 0)) {
		ಮುಕ್ತ(tmp);
		ಮುಕ್ತ(opt);
		*errstrp = "invalid permission port";
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	/* XXX - add streamlocal support */
	ಮುಕ್ತ(tmp);
	/* Record it */
	ಯದಿ ((permits = recallocarray(permits, npermits, npermits + 1,
	    ಪರಿಮಾಣ(*permits))) == ರಿಕ್ತ) {
		ಮುಕ್ತ(opt);
		/* NB. don't update *permitsp if alloc fails */
		*errstrp = "memory allocation failed";
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	permits[npermits++] = opt;
	*permitsp = permits;
	*npermitsp = npermits;
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸಂರಚನಾ sshauthopt *
sshauthopt_parse(ಧ್ರುವ ವರ್ಣ *opts, ಧ್ರುವ ವರ್ಣ **errstrp)
{
	ವರ್ಣ **oarray, *opt, *cp, *tmp;
	ಪೂರ್ಣಾಙ್ಕ r;
	ಸಂರಚನಾ sshauthopt *ret = ರಿಕ್ತ;
	ಧ್ರುವ ವರ್ಣ *errstr = "unknown error";
	uint64_t valid_before;
	size_t i, l;

	ಯದಿ (errstrp != ರಿಕ್ತ)
		*errstrp = ರಿಕ್ತ;
	ಯದಿ ((ret = sshauthopt_new_with_ಕೀಲಿಗಳು_defaults()) == ರಿಕ್ತ)
		ಗಚ್ಛ alloc_fail;

	ಯದಿ (opts == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ ret;

	ಯಾವತ್ (*opts && *opts != ' ' && *opts != '\t') {
		/* flag options */
		ಯದಿ ((r = opt_flag("restrict", 0, &opts)) != -1) {
			ret->restricted = 1;
			ret->permit_port_forwarding_flag = 0;
			ret->permit_agent_forwarding_flag = 0;
			ret->permit_x11_forwarding_flag = 0;
			ret->permit_pty_flag = 0;
			ret->permit_user_rc = 0;
		} ಅನ್ಯಥಾ ಯದಿ ((r = opt_flag("cert-authority", 0, &opts)) != -1) {
			ret->cert_authority = r;
		} ಅನ್ಯಥಾ ಯದಿ ((r = opt_flag("port-forwarding", 1, &opts)) != -1) {
			ret->permit_port_forwarding_flag = r == 1;
		} ಅನ್ಯಥಾ ಯದಿ ((r = opt_flag("agent-forwarding", 1, &opts)) != -1) {
			ret->permit_agent_forwarding_flag = r == 1;
		} ಅನ್ಯಥಾ ಯದಿ ((r = opt_flag("x11-forwarding", 1, &opts)) != -1) {
			ret->permit_x11_forwarding_flag = r == 1;
		} ಅನ್ಯಥಾ ಯದಿ ((r = opt_flag("touch-required", 1, &opts)) != -1) {
			ret->no_require_user_presence = r != 1; /* NB. flip */
		} ಅನ್ಯಥಾ ಯದಿ ((r = opt_flag("verify-required", 1, &opts)) != -1) {
			ret->require_verify = r == 1;
		} ಅನ್ಯಥಾ ಯದಿ ((r = opt_flag("pty", 1, &opts)) != -1) {
			ret->permit_pty_flag = r == 1;
		} ಅನ್ಯಥಾ ಯದಿ ((r = opt_flag("user-rc", 1, &opts)) != -1) {
			ret->permit_user_rc = r == 1;
		} ಅನ್ಯಥಾ ಯದಿ (opt_match(&opts, "command")) {
			ಯದಿ (ret->force_command != ರಿಕ್ತ) {
				errstr = "multiple \"command\" clauses";
				ಗಚ್ಛ fail;
			}
			ret->force_command = opt_dequote(&opts, &errstr);
			ಯದಿ (ret->force_command == ರಿಕ್ತ)
				ಗಚ್ಛ fail;
		} ಅನ್ಯಥಾ ಯದಿ (opt_match(&opts, "principals")) {
			ಯದಿ (ret->cert_principals != ರಿಕ್ತ) {
				errstr = "multiple \"principals\" clauses";
				ಗಚ್ಛ fail;
			}
			ret->cert_principals = opt_dequote(&opts, &errstr);
			ಯದಿ (ret->cert_principals == ರಿಕ್ತ)
				ಗಚ್ಛ fail;
		} ಅನ್ಯಥಾ ಯದಿ (opt_match(&opts, "from")) {
			ಯದಿ (ret->required_from_host_ಕೀಲಿಗಳು != ರಿಕ್ತ) {
				errstr = "multiple \"from\" clauses";
				ಗಚ್ಛ fail;
			}
			ret->required_from_host_ಕೀಲಿಗಳು = opt_dequote(&opts,
			    &errstr);
			ಯದಿ (ret->required_from_host_ಕೀಲಿಗಳು == ರಿಕ್ತ)
				ಗಚ್ಛ fail;
		} ಅನ್ಯಥಾ ಯದಿ (opt_match(&opts, "expiry-time")) {
			ಯದಿ ((opt = opt_dequote(&opts, &errstr)) == ರಿಕ್ತ)
				ಗಚ್ಛ fail;
			ಯದಿ (parse_absolute_time(opt, &valid_before) != 0 ||
			    valid_before == 0) {
				ಮುಕ್ತ(opt);
				errstr = "invalid expires time";
				ಗಚ್ಛ fail;
			}
			ಮುಕ್ತ(opt);
			ಯದಿ (ret->valid_before == 0 ||
			    valid_before < ret->valid_before)
				ret->valid_before = valid_before;
		} ಅನ್ಯಥಾ ಯದಿ (opt_match(&opts, "environment")) {
			ಯದಿ (ret->nenv > SSH_AUTHOPT_ENV_MAX) {
				errstr = "too many environment strings";
				ಗಚ್ಛ fail;
			}
			ಯದಿ ((opt = opt_dequote(&opts, &errstr)) == ರಿಕ್ತ)
				ಗಚ್ಛ fail;
			/* env name must be alphanumeric and followed by '=' */
			ಯದಿ ((tmp = strchr(opt, '=')) == ರಿಕ್ತ) {
				ಮುಕ್ತ(opt);
				errstr = "invalid environment string";
				ಗಚ್ಛ fail;
			}
			ಯದಿ ((cp = strdup(opt)) == ರಿಕ್ತ) {
				ಮುಕ್ತ(opt);
				ಗಚ್ಛ alloc_fail;
			}
			l = (size_t)(tmp - opt);
			cp[l] = '\0'; /* truncate at '=' */
			ಯದಿ (!valid_env_name(cp)) {
				ಮುಕ್ತ(cp);
				ಮುಕ್ತ(opt);
				errstr = "invalid environment string";
				ಗಚ್ಛ fail;
			}
			/* Check for duplicates; XXX O(n*log(n)) */
			ಪ್ರತಿ (i = 0; i < ret->nenv; i++) {
				ಯದಿ (strncmp(ret->env[i], cp, l) == 0 &&
				    ret->env[i][l] == '=')
					ಭಙ್ಗ;
			}
			ಮುಕ್ತ(cp);
			/* First match wins */
			ಯದಿ (i >= ret->nenv) {
				/* Append it. */
				oarray = ret->env;
				ಯದಿ ((ret->env = recallocarray(ret->env,
				    ret->nenv, ret->nenv + 1,
				    ಪರಿಮಾಣ(*ret->env))) == ರಿಕ್ತ) {
					ಮುಕ್ತ(opt);
					/* put it back for cleanup */
					ret->env = oarray;
					ಗಚ್ಛ alloc_fail;
				}
				ret->env[ret->nenv++] = opt;
				opt = ರಿಕ್ತ; /* transferred */
			}
			ಮುಕ್ತ(opt);
		} ಅನ್ಯಥಾ ಯದಿ (opt_match(&opts, "permitopen")) {
			ಯದಿ (handle_permit(&opts, 0, &ret->permitopen,
			    &ret->npermitopen, &errstr) != 0)
				ಗಚ್ಛ fail;
		} ಅನ್ಯಥಾ ಯದಿ (opt_match(&opts, "permitlisten")) {
			ಯದಿ (handle_permit(&opts, 1, &ret->permitlisten,
			    &ret->npermitlisten, &errstr) != 0)
				ಗಚ್ಛ fail;
		} ಅನ್ಯಥಾ ಯದಿ (opt_match(&opts, "tunnel")) {
			ಯದಿ ((opt = opt_dequote(&opts, &errstr)) == ರಿಕ್ತ)
				ಗಚ್ಛ fail;
			ret->force_tun_device = a2tun(opt, ರಿಕ್ತ);
			ಮುಕ್ತ(opt);
			ಯದಿ (ret->force_tun_device == SSH_TUNID_ERR) {
				errstr = "invalid tun device";
				ಗಚ್ಛ fail;
			}
		}
		/*
		 * Skip the comma, and move to the next option
		 * (or break out if there are no more).
		 */
		ಯದಿ (*opts == '\0' || *opts == ' ' || *opts == '\t')
			ಭಙ್ಗ;		/* End of options. */
		/* Anything other than a comma is an unknown option */
		ಯದಿ (*opts != ',') {
			errstr = "unknown key option";
			ಗಚ್ಛ fail;
		}
		opts++;
		ಯದಿ (*opts == '\0') {
			errstr = "unexpected end-of-options";
			ಗಚ್ಛ fail;
		}
	}

	/* success */
	ಯದಿ (errstrp != ರಿಕ್ತ)
		*errstrp = ರಿಕ್ತ;
	ಪ್ರತ್ಯಾಗಮ ret;

alloc_fail:
	errstr = "memory allocation failed";
fail:
	sshauthopt_free(ret);
	ಯದಿ (errstrp != ರಿಕ್ತ)
		*errstrp = errstr;
	ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
}

ಸಂರಚನಾ sshauthopt *
sshauthopt_from_cert(ಸಂರಚನಾ sshkey *k)
{
	ಸಂರಚನಾ sshauthopt *ret;

	ಯದಿ (k == ರಿಕ್ತ || !sshkey_type_is_cert(k->type) || k->cert == ರಿಕ್ತ ||
	    k->cert->type != SSH2_CERT_TYPE_USER)
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;

	ಯದಿ ((ret = sshauthopt_new()) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;

	/* Handle options and critical extensions separately */
	ಯದಿ (cert_option_list(ret, k->cert->critical,
	    OPTIONS_CRITICAL, 1) == -1) {
		sshauthopt_free(ret);
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	}
	ಯದಿ (cert_option_list(ret, k->cert->extensions,
	    OPTIONS_EXTENSIONS, 0) == -1) {
		sshauthopt_free(ret);
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	}
	/* success */
	ಪ್ರತ್ಯಾಗಮ ret;
}

/*
 * Merges "additional" options to "primary" and returns the result.
 * NB. Some options from primary have primacy.
 */
ಸಂರಚನಾ sshauthopt *
sshauthopt_merge(ಧ್ರುವ ಸಂರಚನಾ sshauthopt *primary,
    ಧ್ರುವ ಸಂರಚನಾ sshauthopt *additional, ಧ್ರುವ ವರ್ಣ **errstrp)
{
	ಸಂರಚನಾ sshauthopt *ret;
	ಧ್ರುವ ವರ್ಣ *errstr = "internal error";
	ಧ್ರುವ ವರ್ಣ *tmp;

	ಯದಿ (errstrp != ರಿಕ್ತ)
		*errstrp = ರಿಕ್ತ;

	ಯದಿ ((ret = sshauthopt_new()) == ರಿಕ್ತ)
		ಗಚ್ಛ alloc_fail;

	/* cert_authority and cert_principals are cleared in result */

	/* Prefer access lists from primary. */
	/* XXX err is both set and mismatch? */
	tmp = primary->required_from_host_cert;
	ಯದಿ (tmp == ರಿಕ್ತ)
		tmp = additional->required_from_host_cert;
	ಯದಿ (tmp != ರಿಕ್ತ && (ret->required_from_host_cert = strdup(tmp)) == ರಿಕ್ತ)
		ಗಚ್ಛ alloc_fail;
	tmp = primary->required_from_host_ಕೀಲಿಗಳು;
	ಯದಿ (tmp == ರಿಕ್ತ)
		tmp = additional->required_from_host_ಕೀಲಿಗಳು;
	ಯದಿ (tmp != ರಿಕ್ತ && (ret->required_from_host_ಕೀಲಿಗಳು = strdup(tmp)) == ರಿಕ್ತ)
		ಗಚ್ಛ alloc_fail;

	/*
	 * force_tun_device, permitopen/permitlisten and environment all
	 * prefer the primary.
	 */
	ret->force_tun_device = primary->force_tun_device;
	ಯದಿ (ret->force_tun_device == -1)
		ret->force_tun_device = additional->force_tun_device;
	ಯದಿ (primary->nenv > 0) {
		ಯದಿ (dup_strings(&ret->env, &ret->nenv,
		    primary->env, primary->nenv) != 0)
			ಗಚ್ಛ alloc_fail;
	} ಅನ್ಯಥಾ ಯದಿ (additional->nenv) {
		ಯದಿ (dup_strings(&ret->env, &ret->nenv,
		    additional->env, additional->nenv) != 0)
			ಗಚ್ಛ alloc_fail;
	}
	ಯದಿ (primary->npermitopen > 0) {
		ಯದಿ (dup_strings(&ret->permitopen, &ret->npermitopen,
		    primary->permitopen, primary->npermitopen) != 0)
			ಗಚ್ಛ alloc_fail;
	} ಅನ್ಯಥಾ ಯದಿ (additional->npermitopen > 0) {
		ಯದಿ (dup_strings(&ret->permitopen, &ret->npermitopen,
		    additional->permitopen, additional->npermitopen) != 0)
			ಗಚ್ಛ alloc_fail;
	}

	ಯದಿ (primary->npermitlisten > 0) {
		ಯದಿ (dup_strings(&ret->permitlisten, &ret->npermitlisten,
		    primary->permitlisten, primary->npermitlisten) != 0)
			ಗಚ್ಛ alloc_fail;
	} ಅನ್ಯಥಾ ಯದಿ (additional->npermitlisten > 0) {
		ಯದಿ (dup_strings(&ret->permitlisten, &ret->npermitlisten,
		    additional->permitlisten, additional->npermitlisten) != 0)
			ಗಚ್ಛ alloc_fail;
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
	ಯದಿ (primary->valid_before != 0)
		ret->valid_before = primary->valid_before;
	ಯದಿ (additional->valid_before != 0 &&
	    additional->valid_before < ret->valid_before)
		ret->valid_before = additional->valid_before;

	/*
	 * When both multiple forced-command are specified, only
	 * proceed if they are identical, otherwise fail.
	 */
	ಯದಿ (primary->force_command != ರಿಕ್ತ &&
	    additional->force_command != ರಿಕ್ತ) {
		ಯದಿ (strcmp(primary->force_command,
		    additional->force_command) == 0) {
			/* ok */
			ret->force_command = strdup(primary->force_command);
			ಯದಿ (ret->force_command == ರಿಕ್ತ)
				ಗಚ್ಛ alloc_fail;
		} ಅನ್ಯಥಾ {
			errstr = "forced command options do not match";
			ಗಚ್ಛ fail;
		}
	} ಅನ್ಯಥಾ ಯದಿ (primary->force_command != ರಿಕ್ತ) {
		ಯದಿ ((ret->force_command = strdup(
		    primary->force_command)) == ರಿಕ್ತ)
			ಗಚ್ಛ alloc_fail;
	} ಅನ್ಯಥಾ ಯದಿ (additional->force_command != ರಿಕ್ತ) {
		ಯದಿ ((ret->force_command = strdup(
		    additional->force_command)) == ರಿಕ್ತ)
			ಗಚ್ಛ alloc_fail;
	}
	/* success */
	ಯದಿ (errstrp != ರಿಕ್ತ)
		*errstrp = ರಿಕ್ತ;
	ಪ್ರತ್ಯಾಗಮ ret;

 alloc_fail:
	errstr = "memory allocation failed";
 fail:
	ಯದಿ (errstrp != ರಿಕ್ತ)
		*errstrp = errstr;
	sshauthopt_free(ret);
	ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
}

/*
 * Copy options
 */
ಸಂರಚನಾ sshauthopt *
sshauthopt_copy(ಧ್ರುವ ಸಂರಚನಾ sshauthopt *orig)
{
	ಸಂರಚನಾ sshauthopt *ret;

	ಯದಿ ((ret = sshauthopt_new()) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;

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
	ಕುರು { \
		ಯದಿ (orig->x != ರಿಕ್ತ && (ret->x = strdup(orig->x)) == ರಿಕ್ತ) { \
			sshauthopt_free(ret); \
			ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ; \
		} \
	} ಯಾವತ್ (0)
	OPTSTRING(cert_principals);
	OPTSTRING(force_command);
	OPTSTRING(required_from_host_cert);
	OPTSTRING(required_from_host_ಕೀಲಿಗಳು);
#undef OPTSTRING

	ಯದಿ (dup_strings(&ret->env, &ret->nenv, orig->env, orig->nenv) != 0 ||
	    dup_strings(&ret->permitopen, &ret->npermitopen,
	    orig->permitopen, orig->npermitopen) != 0 ||
	    dup_strings(&ret->permitlisten, &ret->npermitlisten,
	    orig->permitlisten, orig->npermitlisten) != 0) {
		sshauthopt_free(ret);
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	}
	ಪ್ರತ್ಯಾಗಮ ret;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
serialise_array(ಸಂರಚನಾ sshbuf *m, ವರ್ಣ **a, size_t n)
{
	ಸಂರಚನಾ sshbuf *b;
	size_t i;
	ಪೂರ್ಣಾಙ್ಕ r = SSH_ERR_INTERNAL_ERROR;

	ಯದಿ (n > INT_MAX)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INTERNAL_ERROR;

	ಯದಿ ((b = sshbuf_new()) == ರಿಕ್ತ) {
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ALLOC_FAIL;
	}
	ಪ್ರತಿ (i = 0; i < n; i++) {
		ಯದಿ ((r = sshbuf_put_cstring(b, a[i])) != 0)
			ಗಚ್ಛ out;
	}
	ಯದಿ ((r = sshbuf_put_u32(m, n)) != 0 ||
	    (r = sshbuf_put_stringb(m, b)) != 0)
		ಗಚ್ಛ out;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	ಪ್ರತ್ಯಾಗಮ r;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
deserialise_array(ಸಂರಚನಾ sshbuf *m, ವರ್ಣ ***ap, size_t *np)
{
	ವರ್ಣ **a = ರಿಕ್ತ;
	size_t i, n = 0;
	ಸಂರಚನಾ sshbuf *b = ರಿಕ್ತ;
	u_int tmp;
	ಪೂರ್ಣಾಙ್ಕ r = SSH_ERR_INTERNAL_ERROR;

	ಯದಿ ((r = sshbuf_get_u32(m, &tmp)) != 0 ||
	    (r = sshbuf_froms(m, &b)) != 0)
		ಗಚ್ಛ out;
	ಯದಿ (tmp > INT_MAX) {
		r = SSH_ERR_INVALID_FORMAT;
		ಗಚ್ಛ out;
	}
	n = tmp;
	ಯದಿ (n > 0 && (a = calloc(n, ಪರಿಮಾಣ(*a))) == ರಿಕ್ತ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಗಚ್ಛ out;
	}
	ಪ್ರತಿ (i = 0; i < n; i++) {
		ಯದಿ ((r = sshbuf_get_cstring(b, &a[i], ರಿಕ್ತ)) != 0)
			ಗಚ್ಛ out;
	}
	/* success */
	r = 0;
	*ap = a;
	a = ರಿಕ್ತ;
	*np = n;
	n = 0;
 out:
	ಯದಿ (a != ರಿಕ್ತ) {
		ಪ್ರತಿ (i = 0; i < n; i++)
			ಮುಕ್ತ(a[i]);
		ಮುಕ್ತ(a);
	}
	sshbuf_free(b);
	ಪ್ರತ್ಯಾಗಮ r;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
serialise_nullable_string(ಸಂರಚನಾ sshbuf *m, ಧ್ರುವ ವರ್ಣ *s)
{
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((r = sshbuf_put_u8(m, s == ರಿಕ್ತ)) != 0 ||
	    (r = sshbuf_put_cstring(m, s)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
deserialise_nullable_string(ಸಂರಚನಾ sshbuf *m, ವರ್ಣ **sp)
{
	ಪೂರ್ಣಾಙ್ಕ r;
	u_char flag;

	*sp = ರಿಕ್ತ;
	ಯದಿ ((r = sshbuf_get_u8(m, &flag)) != 0 ||
	    (r = sshbuf_get_cstring(m, flag ? ರಿಕ್ತ : sp, ರಿಕ್ತ)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಪೂರ್ಣಾಙ್ಕ
sshauthopt_serialise(ಧ್ರುವ ಸಂರಚನಾ sshauthopt *opts, ಸಂರಚನಾ sshbuf *m,
    ಪೂರ್ಣಾಙ್ಕ untrusted)
{
	ಪೂರ್ಣಾಙ್ಕ r = SSH_ERR_INTERNAL_ERROR;

	/* Flag options */
	ಯದಿ ((r = sshbuf_put_u8(m, opts->permit_port_forwarding_flag)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->permit_agent_forwarding_flag)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->permit_x11_forwarding_flag)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->permit_pty_flag)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->permit_user_rc)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->restricted)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->cert_authority)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->no_require_user_presence)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->require_verify)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;

	/* Simple integer options */
	ಯದಿ ((r = sshbuf_put_u64(m, opts->valid_before)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;

	/* tunnel number can be negative to indicate "unset" */
	ಯದಿ ((r = sshbuf_put_u8(m, opts->force_tun_device == -1)) != 0 ||
	    (r = sshbuf_put_u32(m, (opts->force_tun_device < 0) ?
	    0 : (u_int)opts->force_tun_device)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;

	/* String options; these may be NULL */
	ಯದಿ ((r = serialise_nullable_string(m,
	    untrusted ? "yes" : opts->cert_principals)) != 0 ||
	    (r = serialise_nullable_string(m,
	    untrusted ? "true" : opts->force_command)) != 0 ||
	    (r = serialise_nullable_string(m,
	    untrusted ? ರಿಕ್ತ : opts->required_from_host_cert)) != 0 ||
	    (r = serialise_nullable_string(m,
	    untrusted ? ರಿಕ್ತ : opts->required_from_host_ಕೀಲಿಗಳು)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;

	/* Array options */
	ಯದಿ ((r = serialise_array(m, opts->env,
	    untrusted ? 0 : opts->nenv)) != 0 ||
	    (r = serialise_array(m, opts->permitopen,
	    untrusted ? 0 : opts->npermitopen)) != 0 ||
	    (r = serialise_array(m, opts->permitlisten,
	    untrusted ? 0 : opts->npermitlisten)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;

	/* success */
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಪೂರ್ಣಾಙ್ಕ
sshauthopt_deserialise(ಸಂರಚನಾ sshbuf *m, ಸಂರಚನಾ sshauthopt **optsp)
{
	ಸಂರಚನಾ sshauthopt *opts = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ r = SSH_ERR_INTERNAL_ERROR;
	u_char f;
	u_int tmp;

	ಯದಿ ((opts = calloc(1, ಪರಿಮಾಣ(*opts))) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ALLOC_FAIL;

	/* Flag options */
#define OPT_FLAG(x) \
	ಕುರು { \
		ಯದಿ ((r = sshbuf_get_u8(m, &f)) != 0) \
			ಗಚ್ಛ out; \
		opts->x = f; \
	} ಯಾವತ್ (0)
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
	ಯದಿ ((r = sshbuf_get_u64(m, &opts->valid_before)) != 0)
		ಗಚ್ಛ out;

	/* tunnel number can be negative to indicate "unset" */
	ಯದಿ ((r = sshbuf_get_u8(m, &f)) != 0 ||
	    (r = sshbuf_get_u32(m, &tmp)) != 0)
		ಗಚ್ಛ out;
	opts->force_tun_device = f ? -1 : (ಪೂರ್ಣಾಙ್ಕ)tmp;

	/* String options may be NULL */
	ಯದಿ ((r = deserialise_nullable_string(m, &opts->cert_principals)) != 0 ||
	    (r = deserialise_nullable_string(m, &opts->force_command)) != 0 ||
	    (r = deserialise_nullable_string(m,
	    &opts->required_from_host_cert)) != 0 ||
	    (r = deserialise_nullable_string(m,
	    &opts->required_from_host_ಕೀಲಿಗಳು)) != 0)
		ಗಚ್ಛ out;

	/* Array options */
	ಯದಿ ((r = deserialise_array(m, &opts->env, &opts->nenv)) != 0 ||
	    (r = deserialise_array(m,
	    &opts->permitopen, &opts->npermitopen)) != 0 ||
	    (r = deserialise_array(m,
	    &opts->permitlisten, &opts->npermitlisten)) != 0)
		ಗಚ್ಛ out;

	/* success */
	r = 0;
	*optsp = opts;
	opts = ರಿಕ್ತ;
 out:
	sshauthopt_free(opts);
	ಪ್ರತ್ಯಾಗಮ r;
}
