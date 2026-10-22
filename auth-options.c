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

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
dup_ಅಕ್ಷರಸರಣಿಗಳು(ಅಕ್ಷರ ***dstp, ಗಾತ್ರ_t *ndstp, ಅಕ್ಷರ **src, ಗಾತ್ರ_t nsrc)
{
	ಅಕ್ಷರ **dst;
	ಗಾತ್ರ_t i, j;

	*dstp = ಖಾಲಿ;
	*ndstp = 0;

	ಆದರೆ (nsrc == 0)
		ಹಿಂತಿರುಗಿ 0;
	ಆದರೆ (nsrc >= SIZE_MAX / ಗಾತ್ರ(*src) ||
	    (dst = ಸೊನ್ನೆ_ಸ್ಮರಣೆ_ಕೊಡು(nsrc, ಗಾತ್ರ(*src))) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ -1;
	ಗಾಗಿ (i = 0; i < nsrc; i++) {
		ಆದರೆ ((dst[i] = strdup(src[i])) == ಖಾಲಿ) {
			ಗಾಗಿ (j = 0; j < i; j++)
				ಬಿಡುಗಡೆ(dst[j]);
			ಬಿಡುಗಡೆ(dst);
			ಹಿಂತಿರುಗಿ -1;
		}
	}
	/* success */
	*dstp = dst;
	*ndstp = nsrc;
	ಹಿಂತಿರುಗಿ 0;
}

#ವ್ಯಾಖ್ಯಾನಿಸು OPTIONS_CRITICAL	1
#ವ್ಯಾಖ್ಯಾನಿಸು OPTIONS_EXTENSIONS	2
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
cert_option_list(ರಚನೆ sshauthopt *opts, ರಚನೆ sshbuf *oblob,
    u_int which, ಪೂರ್ಣಾಂಕ crit)
{
	ಅಕ್ಷರ *command, *allowed;
	ಅಕ್ಷರ *name = ಖಾಲಿ;
	ರಚನೆ sshbuf *c = ಖಾಲಿ, *ದತ್ತಾಂಶ = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ r, ret = -1, ಸಿಕ್ಕಿತು;

	ಆದರೆ ((c = sshbuf_fromb(oblob)) == ಖಾಲಿ) {
		error_f("sshbuf_fromb failed");
		ಹೋಗು ಹೊರಹೋಗು;
	}

	ಆಗ (sshbuf_len(c) > 0) {
		sshbuf_free(ದತ್ತಾಂಶ);
		ದತ್ತಾಂಶ = ಖಾಲಿ;
		ಆದರೆ ((r = sshbuf_get_cstring(c, &name, ಖಾಲಿ)) != 0 ||
		    (r = sshbuf_froms(c, &ದತ್ತಾಂಶ)) != 0) {
			error_r(r, "Unable to parse certificate options");
			ಹೋಗು ಹೊರಹೋಗು;
		}
		debug3("found certificate option \"%.100s\" len %zu",
		    name, sshbuf_len(ದತ್ತಾಂಶ));
		ಸಿಕ್ಕಿತು = 0;
		ಆದರೆ ((which & OPTIONS_EXTENSIONS) != 0) {
			ಆದರೆ (strcmp(name, "no-touch-required") == 0) {
				opts->no_require_user_presence = 1;
				ಸಿಕ್ಕಿತು = 1;
			} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcmp(name, "permit-X11-forwarding") == 0) {
				opts->permit_x11_forwarding_flag = 1;
				ಸಿಕ್ಕಿತು = 1;
			} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcmp(name,
			    "permit-agent-forwarding") == 0) {
				opts->permit_agent_forwarding_flag = 1;
				ಸಿಕ್ಕಿತು = 1;
			} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcmp(name,
			    "permit-port-forwarding") == 0) {
				opts->permit_ಪೋರ್ಟ್_forwarding_flag = 1;
				ಸಿಕ್ಕಿತು = 1;
			} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcmp(name, "permit-pty") == 0) {
				opts->permit_pty_flag = 1;
				ಸಿಕ್ಕಿತು = 1;
			} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcmp(name, "permit-user-rc") == 0) {
				opts->permit_user_rc = 1;
				ಸಿಕ್ಕಿತು = 1;
			}
		}
		ಆದರೆ (!ಸಿಕ್ಕಿತು && (which & OPTIONS_CRITICAL) != 0) {
			ಆದರೆ (strcmp(name, "verify-required") == 0) {
				opts->require_verify = 1;
				ಸಿಕ್ಕಿತು = 1;
			} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcmp(name, "force-command") == 0) {
				ಆದರೆ ((r = sshbuf_get_cstring(ದತ್ತಾಂಶ, &command,
				    ಖಾಲಿ)) != 0) {
					error_r(r, "Unable to parse \"%s\" "
					    "section", name);
					ಹೋಗು ಹೊರಹೋಗು;
				}
				ಆದರೆ (opts->force_command != ಖಾಲಿ) {
					error("Certificate has multiple "
					    "force-command options");
					ಬಿಡುಗಡೆ(command);
					ಹೋಗು ಹೊರಹೋಗು;
				}
				opts->force_command = command;
				ಸಿಕ್ಕಿತು = 1;
			} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcmp(name, "source-address") == 0) {
				ಆದರೆ ((r = sshbuf_get_cstring(ದತ್ತಾಂಶ, &allowed,
				    ಖಾಲಿ)) != 0) {
					error_r(r, "Unable to parse \"%s\" "
					    "section", name);
					ಹೋಗು ಹೊರಹೋಗು;
				}
				ಆದರೆ (opts->required_from_host_cert != ಖಾಲಿ) {
					error("Certificate has multiple "
					    "source-address options");
					ಬಿಡುಗಡೆ(allowed);
					ಹೋಗು ಹೊರಹೋಗು;
				}
				/* Check syntax */
				ಆದರೆ (addr_ಹೊಂದಿಕೆ_cidr_list(ಖಾಲಿ, allowed) == -1) {
					error("Certificate source-address "
					    "contents invalid");
					ಬಿಡುಗಡೆ(allowed);
					ಹೋಗು ಹೊರಹೋಗು;
				}
				opts->required_from_host_cert = allowed;
				ಸಿಕ್ಕಿತು = 1;
			}
		}

		ಆದರೆ (!ಸಿಕ್ಕಿತು) {
			ಆದರೆ (crit) {
				error("Certificate critical option \"%s\" "
				    "is not supported", name);
				ಹೋಗು ಹೊರಹೋಗು;
			} ಇಲ್ಲದಿದ್ದರೆ {
				logit("Certificate extension \"%s\" "
				    "is not supported", name);
			}
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (sshbuf_len(ದತ್ತಾಂಶ) != 0) {
			error("Certificate option \"%s\" corrupt "
			    "(extra data)", name);
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಬಿಡುಗಡೆ(name);
		name = ಖಾಲಿ;
	}
	/* successfully parsed all options */
	ret = 0;

 ಹೊರಹೋಗು:
	ಬಿಡುಗಡೆ(name);
	sshbuf_free(ದತ್ತಾಂಶ);
	sshbuf_free(c);
	ಹಿಂತಿರುಗಿ ret;
}

ರಚನೆ sshauthopt *
sshauthopt_new(ಶೂನ್ಯ)
{
	ರಚನೆ sshauthopt *ret;

	ಆದರೆ ((ret = ಸೊನ್ನೆ_ಸ್ಮರಣೆ_ಕೊಡು(1, ಗಾತ್ರ(*ret))) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	ret->force_tun_device = -1;
	ಹಿಂತಿರುಗಿ ret;
}

ಶೂನ್ಯ
sshauthopt_free(ರಚನೆ sshauthopt *opts)
{
	ಗಾತ್ರ_t i;

	ಆದರೆ (opts == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ;

	ಬಿಡುಗಡೆ(opts->cert_principals);
	ಬಿಡುಗಡೆ(opts->force_command);
	ಬಿಡುಗಡೆ(opts->required_from_host_cert);
	ಬಿಡುಗಡೆ(opts->required_from_host_ಕೀಲಿಗಳು);

	ಗಾಗಿ (i = 0; i < opts->nenv; i++)
		ಬಿಡುಗಡೆ(opts->env[i]);
	ಬಿಡುಗಡೆ(opts->env);

	ಗಾಗಿ (i = 0; i < opts->npermitopen; i++)
		ಬಿಡುಗಡೆ(opts->permitopen[i]);
	ಬಿಡುಗಡೆ(opts->permitopen);

	ಗಾಗಿ (i = 0; i < opts->npermitlisten; i++)
		ಬಿಡುಗಡೆ(opts->permitlisten[i]);
	ಬಿಡುಗಡೆ(opts->permitlisten);

	freezero(opts, ಗಾತ್ರ(*opts));
}

ರಚನೆ sshauthopt *
sshauthopt_new_with_ಕೀಲಿಗಳು_defaults(ಶೂನ್ಯ)
{
	ರಚನೆ sshauthopt *ret = ಖಾಲಿ;

	ಆದರೆ ((ret = sshauthopt_new()) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;

	/* Defaults for authorized_keys flags */
	ret->permit_ಪೋರ್ಟ್_forwarding_flag = 1;
	ret->permit_agent_forwarding_flag = 1;
	ret->permit_x11_forwarding_flag = 1;
	ret->permit_pty_flag = 1;
	ret->permit_user_rc = 1;
	ಹಿಂತಿರುಗಿ ret;
}

/*
 * Parse and record a permitopen/permitlisten directive.
 * Return 0 on success. Return -1 on failure and sets *errstrp to error reason.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
handle_permit(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ **optsp, ಪೂರ್ಣಾಂಕ allow_bare_ಪೋರ್ಟ್,
    ಅಕ್ಷರ ***permitsp, ಗಾತ್ರ_t *npermitsp, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ **errstrp)
{
	ಅಕ್ಷರ *opt, *tmp, *cp, *host, **permits = *permitsp;
	ಗಾತ್ರ_t npermits = *npermitsp;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *errstr = "unknown error";

	ಆದರೆ (npermits > SSH_AUTHOPT_PERMIT_MAX) {
		*errstrp = "too many permission directives";
		ಹಿಂತಿರುಗಿ -1;
	}
	ಆದರೆ ((opt = opt_dequote(optsp, &errstr)) == ಖಾಲಿ) {
		ಹಿಂತಿರುಗಿ -1;
	}
	ಆದರೆ (allow_bare_ಪೋರ್ಟ್ && strchr(opt, ':') == ಖಾಲಿ) {
		/*
		 * Allow a bare port number in permitlisten to indicate a
		 * listen_host wildcard.
		 */
		ಆದರೆ (asprintf(&tmp, "*:%s", opt) == -1) {
			ಬಿಡುಗಡೆ(opt);
			*errstrp = "memory allocation failed";
			ಹಿಂತಿರುಗಿ -1;
		}
		ಬಿಡುಗಡೆ(opt);
		opt = tmp;
	}
	ಆದರೆ ((tmp = strdup(opt)) == ಖಾಲಿ) {
		ಬಿಡುಗಡೆ(opt);
		*errstrp = "memory allocation failed";
		ಹಿಂತಿರುಗಿ -1;
	}
	cp = tmp;
	/* validate syntax before recording it. */
	host = hpdelim2(&cp, ಖಾಲಿ);
	ಆದರೆ (host == ಖಾಲಿ || ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(host) >= NI_MAXHOST) {
		ಬಿಡುಗಡೆ(tmp);
		ಬಿಡುಗಡೆ(opt);
		*errstrp = "invalid permission hostname";
		ಹಿಂತಿರುಗಿ -1;
	}
	/*
	 * don't want to use permitopen_port to avoid
	 * dependency on channels.[ch] here.
	 */
	ಆದರೆ (cp == ಖಾಲಿ ||
	    (strcmp(cp, "*") != 0 && a2port(cp) <= 0)) {
		ಬಿಡುಗಡೆ(tmp);
		ಬಿಡುಗಡೆ(opt);
		*errstrp = "invalid permission port";
		ಹಿಂತಿರುಗಿ -1;
	}
	/* XXX - add streamlocal support */
	ಬಿಡುಗಡೆ(tmp);
	/* Record it */
	ಆದರೆ ((permits = recallocarray(permits, npermits, npermits + 1,
	    ಗಾತ್ರ(*permits))) == ಖಾಲಿ) {
		ಬಿಡುಗಡೆ(opt);
		/* NB. don't update *permitsp if alloc fails */
		*errstrp = "memory allocation failed";
		ಹಿಂತಿರುಗಿ -1;
	}
	permits[npermits++] = opt;
	*permitsp = permits;
	*npermitsp = npermits;
	ಹಿಂತಿರುಗಿ 0;
}

ರಚನೆ sshauthopt *
sshauthopt_parse(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *opts, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ **errstrp)
{
	ಅಕ್ಷರ **oarray, *opt, *cp, *tmp;
	ಪೂರ್ಣಾಂಕ r;
	ರಚನೆ sshauthopt *ret = ಖಾಲಿ;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *errstr = "unknown error";
	uint64_t valid_before;
	ಗಾತ್ರ_t i, l;

	ಆದರೆ (errstrp != ಖಾಲಿ)
		*errstrp = ಖಾಲಿ;
	ಆದರೆ ((ret = sshauthopt_new_with_ಕೀಲಿಗಳು_defaults()) == ಖಾಲಿ)
		ಹೋಗು alloc_fail;

	ಆದರೆ (opts == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ ret;

	ಆಗ (*opts && *opts != ' ' && *opts != '\t') {
		/* flag options */
		ಆದರೆ ((r = opt_flag("restrict", 0, &opts)) != -1) {
			ret->restricted = 1;
			ret->permit_ಪೋರ್ಟ್_forwarding_flag = 0;
			ret->permit_agent_forwarding_flag = 0;
			ret->permit_x11_forwarding_flag = 0;
			ret->permit_pty_flag = 0;
			ret->permit_user_rc = 0;
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ ((r = opt_flag("cert-authority", 0, &opts)) != -1) {
			ret->cert_authority = r;
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ ((r = opt_flag("port-forwarding", 1, &opts)) != -1) {
			ret->permit_ಪೋರ್ಟ್_forwarding_flag = r == 1;
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ ((r = opt_flag("agent-forwarding", 1, &opts)) != -1) {
			ret->permit_agent_forwarding_flag = r == 1;
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ ((r = opt_flag("x11-forwarding", 1, &opts)) != -1) {
			ret->permit_x11_forwarding_flag = r == 1;
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ ((r = opt_flag("touch-required", 1, &opts)) != -1) {
			ret->no_require_user_presence = r != 1; /* NB. flip */
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ ((r = opt_flag("verify-required", 1, &opts)) != -1) {
			ret->require_verify = r == 1;
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ ((r = opt_flag("pty", 1, &opts)) != -1) {
			ret->permit_pty_flag = r == 1;
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ ((r = opt_flag("user-rc", 1, &opts)) != -1) {
			ret->permit_user_rc = r == 1;
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (opt_ಹೊಂದಿಕೆ(&opts, "command")) {
			ಆದರೆ (ret->force_command != ಖಾಲಿ) {
				errstr = "multiple \"command\" clauses";
				ಹೋಗು fail;
			}
			ret->force_command = opt_dequote(&opts, &errstr);
			ಆದರೆ (ret->force_command == ಖಾಲಿ)
				ಹೋಗು fail;
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (opt_ಹೊಂದಿಕೆ(&opts, "principals")) {
			ಆದರೆ (ret->cert_principals != ಖಾಲಿ) {
				errstr = "multiple \"principals\" clauses";
				ಹೋಗು fail;
			}
			ret->cert_principals = opt_dequote(&opts, &errstr);
			ಆದರೆ (ret->cert_principals == ಖಾಲಿ)
				ಹೋಗು fail;
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (opt_ಹೊಂದಿಕೆ(&opts, "from")) {
			ಆದರೆ (ret->required_from_host_ಕೀಲಿಗಳು != ಖಾಲಿ) {
				errstr = "multiple \"from\" clauses";
				ಹೋಗು fail;
			}
			ret->required_from_host_ಕೀಲಿಗಳು = opt_dequote(&opts,
			    &errstr);
			ಆದರೆ (ret->required_from_host_ಕೀಲಿಗಳು == ಖಾಲಿ)
				ಹೋಗು fail;
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (opt_ಹೊಂದಿಕೆ(&opts, "expiry-time")) {
			ಆದರೆ ((opt = opt_dequote(&opts, &errstr)) == ಖಾಲಿ)
				ಹೋಗು fail;
			ಆದರೆ (parse_absolute_ಸಮಯ(opt, &valid_before) != 0 ||
			    valid_before == 0) {
				ಬಿಡುಗಡೆ(opt);
				errstr = "invalid expires time";
				ಹೋಗು fail;
			}
			ಬಿಡುಗಡೆ(opt);
			ಆದರೆ (ret->valid_before == 0 ||
			    valid_before < ret->valid_before)
				ret->valid_before = valid_before;
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (opt_ಹೊಂದಿಕೆ(&opts, "environment")) {
			ಆದರೆ (ret->nenv > SSH_AUTHOPT_ENV_MAX) {
				errstr = "too many environment strings";
				ಹೋಗು fail;
			}
			ಆದರೆ ((opt = opt_dequote(&opts, &errstr)) == ಖಾಲಿ)
				ಹೋಗು fail;
			/* env name must be alphanumeric and followed by '=' */
			ಆದರೆ ((tmp = strchr(opt, '=')) == ಖಾಲಿ) {
				ಬಿಡುಗಡೆ(opt);
				errstr = "invalid environment string";
				ಹೋಗು fail;
			}
			ಆದರೆ ((cp = strdup(opt)) == ಖಾಲಿ) {
				ಬಿಡುಗಡೆ(opt);
				ಹೋಗು alloc_fail;
			}
			l = (ಗಾತ್ರ_t)(tmp - opt);
			cp[l] = '\0'; /* truncate at '=' */
			ಆದರೆ (!valid_env_name(cp)) {
				ಬಿಡುಗಡೆ(cp);
				ಬಿಡುಗಡೆ(opt);
				errstr = "invalid environment string";
				ಹೋಗು fail;
			}
			/* Check for duplicates; XXX O(n*log(n)) */
			ಗಾಗಿ (i = 0; i < ret->nenv; i++) {
				ಆದರೆ (ಅಕ್ಷರಸರಣಿ_ಹೋಲಿಕೆ(ret->env[i], cp, l) == 0 &&
				    ret->env[i][l] == '=')
					ನಿಲ್ಲಿಸು;
			}
			ಬಿಡುಗಡೆ(cp);
			/* First match wins */
			ಆದರೆ (i >= ret->nenv) {
				/* Append it. */
				oarray = ret->env;
				ಆದರೆ ((ret->env = recallocarray(ret->env,
				    ret->nenv, ret->nenv + 1,
				    ಗಾತ್ರ(*ret->env))) == ಖಾಲಿ) {
					ಬಿಡುಗಡೆ(opt);
					/* put it back for cleanup */
					ret->env = oarray;
					ಹೋಗು alloc_fail;
				}
				ret->env[ret->nenv++] = opt;
				opt = ಖಾಲಿ; /* transferred */
			}
			ಬಿಡುಗಡೆ(opt);
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (opt_ಹೊಂದಿಕೆ(&opts, "permitopen")) {
			ಆದರೆ (handle_permit(&opts, 0, &ret->permitopen,
			    &ret->npermitopen, &errstr) != 0)
				ಹೋಗು fail;
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (opt_ಹೊಂದಿಕೆ(&opts, "permitlisten")) {
			ಆದರೆ (handle_permit(&opts, 1, &ret->permitlisten,
			    &ret->npermitlisten, &errstr) != 0)
				ಹೋಗು fail;
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (opt_ಹೊಂದಿಕೆ(&opts, "tunnel")) {
			ಆದರೆ ((opt = opt_dequote(&opts, &errstr)) == ಖಾಲಿ)
				ಹೋಗು fail;
			ret->force_tun_device = a2tun(opt, ಖಾಲಿ);
			ಬಿಡುಗಡೆ(opt);
			ಆದರೆ (ret->force_tun_device == SSH_TUNID_ERR) {
				errstr = "invalid tun device";
				ಹೋಗು fail;
			}
		}
		/*
		 * Skip the comma, and move to the next option
		 * (or break out if there are no more).
		 */
		ಆದರೆ (*opts == '\0' || *opts == ' ' || *opts == '\t')
			ನಿಲ್ಲಿಸು;		/* End of options. */
		/* Anything other than a comma is an unknown option */
		ಆದರೆ (*opts != ',') {
			errstr = "unknown key option";
			ಹೋಗು fail;
		}
		opts++;
		ಆದರೆ (*opts == '\0') {
			errstr = "unexpected end-of-options";
			ಹೋಗು fail;
		}
	}

	/* success */
	ಆದರೆ (errstrp != ಖಾಲಿ)
		*errstrp = ಖಾಲಿ;
	ಹಿಂತಿರುಗಿ ret;

alloc_fail:
	errstr = "memory allocation failed";
fail:
	sshauthopt_free(ret);
	ಆದರೆ (errstrp != ಖಾಲಿ)
		*errstrp = errstr;
	ಹಿಂತಿರುಗಿ ಖಾಲಿ;
}

ರಚನೆ sshauthopt *
sshauthopt_from_cert(ರಚನೆ sshkey *k)
{
	ರಚನೆ sshauthopt *ret;

	ಆದರೆ (k == ಖಾಲಿ || !sshkey_type_is_cert(k->type) || k->cert == ಖಾಲಿ ||
	    k->cert->type != SSH2_CERT_TYPE_USER)
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;

	ಆದರೆ ((ret = sshauthopt_new()) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;

	/* Handle options and critical extensions separately */
	ಆದರೆ (cert_option_list(ret, k->cert->critical,
	    OPTIONS_CRITICAL, 1) == -1) {
		sshauthopt_free(ret);
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	}
	ಆದರೆ (cert_option_list(ret, k->cert->extensions,
	    OPTIONS_EXTENSIONS, 0) == -1) {
		sshauthopt_free(ret);
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	}
	/* success */
	ಹಿಂತಿರುಗಿ ret;
}

/*
 * Merges "additional" options to "primary" and returns the result.
 * NB. Some options from primary have primacy.
 */
ರಚನೆ sshauthopt *
sshauthopt_ವಿಲೀನ(ಸ್ಥಿರಾಂಕ ರಚನೆ sshauthopt *primary,
    ಸ್ಥಿರಾಂಕ ರಚನೆ sshauthopt *additional, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ **errstrp)
{
	ರಚನೆ sshauthopt *ret;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *errstr = "internal error";
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *tmp;

	ಆದರೆ (errstrp != ಖಾಲಿ)
		*errstrp = ಖಾಲಿ;

	ಆದರೆ ((ret = sshauthopt_new()) == ಖಾಲಿ)
		ಹೋಗು alloc_fail;

	/* cert_authority and cert_principals are cleared in result */

	/* Prefer access lists from primary. */
	/* XXX err is both set and mismatch? */
	tmp = primary->required_from_host_cert;
	ಆದರೆ (tmp == ಖಾಲಿ)
		tmp = additional->required_from_host_cert;
	ಆದರೆ (tmp != ಖಾಲಿ && (ret->required_from_host_cert = strdup(tmp)) == ಖಾಲಿ)
		ಹೋಗು alloc_fail;
	tmp = primary->required_from_host_ಕೀಲಿಗಳು;
	ಆದರೆ (tmp == ಖಾಲಿ)
		tmp = additional->required_from_host_ಕೀಲಿಗಳು;
	ಆದರೆ (tmp != ಖಾಲಿ && (ret->required_from_host_ಕೀಲಿಗಳು = strdup(tmp)) == ಖಾಲಿ)
		ಹೋಗು alloc_fail;

	/*
	 * force_tun_device, permitopen/permitlisten and environment all
	 * prefer the primary.
	 */
	ret->force_tun_device = primary->force_tun_device;
	ಆದರೆ (ret->force_tun_device == -1)
		ret->force_tun_device = additional->force_tun_device;
	ಆದರೆ (primary->nenv > 0) {
		ಆದರೆ (dup_ಅಕ್ಷರಸರಣಿಗಳು(&ret->env, &ret->nenv,
		    primary->env, primary->nenv) != 0)
			ಹೋಗು alloc_fail;
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (additional->nenv) {
		ಆದರೆ (dup_ಅಕ್ಷರಸರಣಿಗಳು(&ret->env, &ret->nenv,
		    additional->env, additional->nenv) != 0)
			ಹೋಗು alloc_fail;
	}
	ಆದರೆ (primary->npermitopen > 0) {
		ಆದರೆ (dup_ಅಕ್ಷರಸರಣಿಗಳು(&ret->permitopen, &ret->npermitopen,
		    primary->permitopen, primary->npermitopen) != 0)
			ಹೋಗು alloc_fail;
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (additional->npermitopen > 0) {
		ಆದರೆ (dup_ಅಕ್ಷರಸರಣಿಗಳು(&ret->permitopen, &ret->npermitopen,
		    additional->permitopen, additional->npermitopen) != 0)
			ಹೋಗು alloc_fail;
	}

	ಆದರೆ (primary->npermitlisten > 0) {
		ಆದರೆ (dup_ಅಕ್ಷರಸರಣಿಗಳು(&ret->permitlisten, &ret->npermitlisten,
		    primary->permitlisten, primary->npermitlisten) != 0)
			ಹೋಗು alloc_fail;
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (additional->npermitlisten > 0) {
		ಆದರೆ (dup_ಅಕ್ಷರಸರಣಿಗಳು(&ret->permitlisten, &ret->npermitlisten,
		    additional->permitlisten, additional->npermitlisten) != 0)
			ಹೋಗು alloc_fail;
	}

#ವ್ಯಾಖ್ಯಾನಿಸು OPTFLAG_AND(x) ret->x = (primary->x == 1) && (additional->x == 1)
#ವ್ಯಾಖ್ಯಾನಿಸು OPTFLAG_OR(x) ret->x = (primary->x == 1) || (additional->x == 1)
	/* Permissive flags are logical-AND (i.e. must be set in both) */
	OPTFLAG_AND(permit_ಪೋರ್ಟ್_forwarding_flag);
	OPTFLAG_AND(permit_agent_forwarding_flag);
	OPTFLAG_AND(permit_x11_forwarding_flag);
	OPTFLAG_AND(permit_pty_flag);
	OPTFLAG_AND(permit_user_rc);
	OPTFLAG_AND(no_require_user_presence);
	/* Restrictive flags are logical-OR (i.e. must be set in either) */
	OPTFLAG_OR(require_verify);
	OPTFLAG_OR(restricted);
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು OPTFLAG_AND

	/* Earliest expiry time should win */
	ಆದರೆ (primary->valid_before != 0)
		ret->valid_before = primary->valid_before;
	ಆದರೆ (additional->valid_before != 0 &&
	    additional->valid_before < ret->valid_before)
		ret->valid_before = additional->valid_before;

	/*
	 * When both multiple forced-command are specified, only
	 * proceed if they are identical, otherwise fail.
	 */
	ಆದರೆ (primary->force_command != ಖಾಲಿ &&
	    additional->force_command != ಖಾಲಿ) {
		ಆದರೆ (strcmp(primary->force_command,
		    additional->force_command) == 0) {
			/* ok */
			ret->force_command = strdup(primary->force_command);
			ಆದರೆ (ret->force_command == ಖಾಲಿ)
				ಹೋಗು alloc_fail;
		} ಇಲ್ಲದಿದ್ದರೆ {
			errstr = "forced command options do not match";
			ಹೋಗು fail;
		}
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (primary->force_command != ಖಾಲಿ) {
		ಆದರೆ ((ret->force_command = strdup(
		    primary->force_command)) == ಖಾಲಿ)
			ಹೋಗು alloc_fail;
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (additional->force_command != ಖಾಲಿ) {
		ಆದರೆ ((ret->force_command = strdup(
		    additional->force_command)) == ಖಾಲಿ)
			ಹೋಗು alloc_fail;
	}
	/* success */
	ಆದರೆ (errstrp != ಖಾಲಿ)
		*errstrp = ಖಾಲಿ;
	ಹಿಂತಿರುಗಿ ret;

 alloc_fail:
	errstr = "memory allocation failed";
 fail:
	ಆದರೆ (errstrp != ಖಾಲಿ)
		*errstrp = errstr;
	sshauthopt_free(ret);
	ಹಿಂತಿರುಗಿ ಖಾಲಿ;
}

/*
 * Copy options
 */
ರಚನೆ sshauthopt *
sshauthopt_copy(ಸ್ಥಿರಾಂಕ ರಚನೆ sshauthopt *orig)
{
	ರಚನೆ sshauthopt *ret;

	ಆದರೆ ((ret = sshauthopt_new()) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;

#ವ್ಯಾಖ್ಯಾನಿಸು OPTSCALAR(x) ret->x = orig->x
	OPTSCALAR(permit_ಪೋರ್ಟ್_forwarding_flag);
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
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು OPTSCALAR
#ವ್ಯಾಖ್ಯಾನಿಸು OPTSTRING(x) \
	ಮಾಡು { \
		ಆದರೆ (orig->x != ಖಾಲಿ && (ret->x = strdup(orig->x)) == ಖಾಲಿ) { \
			sshauthopt_free(ret); \
			ಹಿಂತಿರುಗಿ ಖಾಲಿ; \
		} \
	} ಆಗ (0)
	OPTSTRING(cert_principals);
	OPTSTRING(force_command);
	OPTSTRING(required_from_host_cert);
	OPTSTRING(required_from_host_ಕೀಲಿಗಳು);
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು OPTSTRING

	ಆದರೆ (dup_ಅಕ್ಷರಸರಣಿಗಳು(&ret->env, &ret->nenv, orig->env, orig->nenv) != 0 ||
	    dup_ಅಕ್ಷರಸರಣಿಗಳು(&ret->permitopen, &ret->npermitopen,
	    orig->permitopen, orig->npermitopen) != 0 ||
	    dup_ಅಕ್ಷರಸರಣಿಗಳು(&ret->permitlisten, &ret->npermitlisten,
	    orig->permitlisten, orig->npermitlisten) != 0) {
		sshauthopt_free(ret);
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	}
	ಹಿಂತಿರುಗಿ ret;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
serialise_array(ರಚನೆ sshbuf *m, ಅಕ್ಷರ **a, ಗಾತ್ರ_t n)
{
	ರಚನೆ sshbuf *b;
	ಗಾತ್ರ_t i;
	ಪೂರ್ಣಾಂಕ r = SSH_ERR_ಆಂತರಿಕ_ERROR;

	ಆದರೆ (n > ಗರಿಷ್ಠ_ಪೂರ್ಣಾಂಕ)
		ಹಿಂತಿರುಗಿ SSH_ERR_ಆಂತರಿಕ_ERROR;

	ಆದರೆ ((b = sshbuf_new()) == ಖಾಲಿ) {
		ಹಿಂತಿರುಗಿ SSH_ERR_ALLOC_FAIL;
	}
	ಗಾಗಿ (i = 0; i < n; i++) {
		ಆದರೆ ((r = sshbuf_put_cstring(b, a[i])) != 0)
			ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((r = sshbuf_put_u32(m, n)) != 0 ||
	    (r = sshbuf_put_stringb(m, b)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	/* success */
	r = 0;
 ಹೊರಹೋಗು:
	sshbuf_free(b);
	ಹಿಂತಿರುಗಿ r;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
deserialise_array(ರಚನೆ sshbuf *m, ಅಕ್ಷರ ***ap, ಗಾತ್ರ_t *np)
{
	ಅಕ್ಷರ **a = ಖಾಲಿ;
	ಗಾತ್ರ_t i, n = 0;
	ರಚನೆ sshbuf *b = ಖಾಲಿ;
	u_int tmp;
	ಪೂರ್ಣಾಂಕ r = SSH_ERR_ಆಂತರಿಕ_ERROR;

	ಆದರೆ ((r = sshbuf_get_u32(m, &tmp)) != 0 ||
	    (r = sshbuf_froms(m, &b)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	ಆದರೆ (tmp > ಗರಿಷ್ಠ_ಪೂರ್ಣಾಂಕ) {
		r = SSH_ERR_INVALID_FORMAT;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	n = tmp;
	ಆದರೆ (n > 0 && (a = ಸೊನ್ನೆ_ಸ್ಮರಣೆ_ಕೊಡು(n, ಗಾತ್ರ(*a))) == ಖಾಲಿ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಗಾಗಿ (i = 0; i < n; i++) {
		ಆದರೆ ((r = sshbuf_get_cstring(b, &a[i], ಖಾಲಿ)) != 0)
			ಹೋಗು ಹೊರಹೋಗು;
	}
	/* success */
	r = 0;
	*ap = a;
	a = ಖಾಲಿ;
	*np = n;
	n = 0;
 ಹೊರಹೋಗು:
	ಆದರೆ (a != ಖಾಲಿ) {
		ಗಾಗಿ (i = 0; i < n; i++)
			ಬಿಡುಗಡೆ(a[i]);
		ಬಿಡುಗಡೆ(a);
	}
	sshbuf_free(b);
	ಹಿಂತಿರುಗಿ r;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
serialise_nullable_string(ರಚನೆ sshbuf *m, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *s)
{
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((r = sshbuf_put_u8(m, s == ಖಾಲಿ)) != 0 ||
	    (r = sshbuf_put_cstring(m, s)) != 0)
		ಹಿಂತಿರುಗಿ r;
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
deserialise_nullable_string(ರಚನೆ sshbuf *m, ಅಕ್ಷರ **sp)
{
	ಪೂರ್ಣಾಂಕ r;
	u_char flag;

	*sp = ಖಾಲಿ;
	ಆದರೆ ((r = sshbuf_get_u8(m, &flag)) != 0 ||
	    (r = sshbuf_get_cstring(m, flag ? ಖಾಲಿ : sp, ಖಾಲಿ)) != 0)
		ಹಿಂತಿರುಗಿ r;
	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
sshauthopt_serialise(ಸ್ಥಿರಾಂಕ ರಚನೆ sshauthopt *opts, ರಚನೆ sshbuf *m,
    ಪೂರ್ಣಾಂಕ untrusted)
{
	ಪೂರ್ಣಾಂಕ r = SSH_ERR_ಆಂತರಿಕ_ERROR;

	/* Flag options */
	ಆದರೆ ((r = sshbuf_put_u8(m, opts->permit_ಪೋರ್ಟ್_forwarding_flag)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->permit_agent_forwarding_flag)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->permit_x11_forwarding_flag)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->permit_pty_flag)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->permit_user_rc)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->restricted)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->cert_authority)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->no_require_user_presence)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->require_verify)) != 0)
		ಹಿಂತಿರುಗಿ r;

	/* Simple integer options */
	ಆದರೆ ((r = sshbuf_put_u64(m, opts->valid_before)) != 0)
		ಹಿಂತಿರುಗಿ r;

	/* tunnel number can be negative to indicate "unset" */
	ಆದರೆ ((r = sshbuf_put_u8(m, opts->force_tun_device == -1)) != 0 ||
	    (r = sshbuf_put_u32(m, (opts->force_tun_device < 0) ?
	    0 : (u_int)opts->force_tun_device)) != 0)
		ಹಿಂತಿರುಗಿ r;

	/* String options; these may be NULL */
	ಆದರೆ ((r = serialise_nullable_string(m,
	    untrusted ? "yes" : opts->cert_principals)) != 0 ||
	    (r = serialise_nullable_string(m,
	    untrusted ? "true" : opts->force_command)) != 0 ||
	    (r = serialise_nullable_string(m,
	    untrusted ? ಖಾಲಿ : opts->required_from_host_cert)) != 0 ||
	    (r = serialise_nullable_string(m,
	    untrusted ? ಖಾಲಿ : opts->required_from_host_ಕೀಲಿಗಳು)) != 0)
		ಹಿಂತಿರುಗಿ r;

	/* Array options */
	ಆದರೆ ((r = serialise_array(m, opts->env,
	    untrusted ? 0 : opts->nenv)) != 0 ||
	    (r = serialise_array(m, opts->permitopen,
	    untrusted ? 0 : opts->npermitopen)) != 0 ||
	    (r = serialise_array(m, opts->permitlisten,
	    untrusted ? 0 : opts->npermitlisten)) != 0)
		ಹಿಂತಿರುಗಿ r;

	/* success */
	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
sshauthopt_deserialise(ರಚನೆ sshbuf *m, ರಚನೆ sshauthopt **optsp)
{
	ರಚನೆ sshauthopt *opts = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ r = SSH_ERR_ಆಂತರಿಕ_ERROR;
	u_char f;
	u_int tmp;

	ಆದರೆ ((opts = ಸೊನ್ನೆ_ಸ್ಮರಣೆ_ಕೊಡು(1, ಗಾತ್ರ(*opts))) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_ALLOC_FAIL;

	/* Flag options */
#ವ್ಯಾಖ್ಯಾನಿಸು OPT_FLAG(x) \
	ಮಾಡು { \
		ಆದರೆ ((r = sshbuf_get_u8(m, &f)) != 0) \
			ಹೋಗು ಹೊರಹೋಗು; \
		opts->x = f; \
	} ಆಗ (0)
	OPT_FLAG(permit_ಪೋರ್ಟ್_forwarding_flag);
	OPT_FLAG(permit_agent_forwarding_flag);
	OPT_FLAG(permit_x11_forwarding_flag);
	OPT_FLAG(permit_pty_flag);
	OPT_FLAG(permit_user_rc);
	OPT_FLAG(restricted);
	OPT_FLAG(cert_authority);
	OPT_FLAG(no_require_user_presence);
	OPT_FLAG(require_verify);
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು OPT_FLAG

	/* Simple integer options */
	ಆದರೆ ((r = sshbuf_get_u64(m, &opts->valid_before)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;

	/* tunnel number can be negative to indicate "unset" */
	ಆದರೆ ((r = sshbuf_get_u8(m, &f)) != 0 ||
	    (r = sshbuf_get_u32(m, &tmp)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	opts->force_tun_device = f ? -1 : (ಪೂರ್ಣಾಂಕ)tmp;

	/* String options may be NULL */
	ಆದರೆ ((r = deserialise_nullable_string(m, &opts->cert_principals)) != 0 ||
	    (r = deserialise_nullable_string(m, &opts->force_command)) != 0 ||
	    (r = deserialise_nullable_string(m,
	    &opts->required_from_host_cert)) != 0 ||
	    (r = deserialise_nullable_string(m,
	    &opts->required_from_host_ಕೀಲಿಗಳು)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;

	/* Array options */
	ಆದರೆ ((r = deserialise_array(m, &opts->env, &opts->nenv)) != 0 ||
	    (r = deserialise_array(m,
	    &opts->permitopen, &opts->npermitopen)) != 0 ||
	    (r = deserialise_array(m,
	    &opts->permitlisten, &opts->npermitlisten)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;

	/* success */
	r = 0;
	*optsp = opts;
	opts = ಖಾಲಿ;
 ಹೊರಹೋಗು:
	sshauthopt_free(opts);
	ಹಿಂತಿರುಗಿ r;
}
