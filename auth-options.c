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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/queue.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <netdb.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <pwd.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdint.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <ctype.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <limits.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "xmalloc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssherr.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshbuf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "misc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshkey.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "match.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssh2.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "auth-options.h"

ਸਥਿਰ ਪੂਰਨ
dup_ਲੜੀਆਂ(ਅੱਖਰ ***dstp, ਮਾਪ_t *ndstp, ਅੱਖਰ **src, ਮਾਪ_t nsrc)
{
	ਅੱਖਰ **dst;
	ਮਾਪ_t i, j;

	*dstp = ਨਿਰਾ;
	*ndstp = 0;

	ਜੇ (nsrc == 0)
		ਵਾਪਸ 0;
	ਜੇ (nsrc >= SIZE_MAX / ਆਕਾਰ(*src) ||
	    (dst = ਸਿਫਰ_ਸਮ੍ਰਿਤੀ_ਦਿਓ(nsrc, ਆਕਾਰ(*src))) == ਨਿਰਾ)
		ਵਾਪਸ -1;
	ਲਈ (i = 0; i < nsrc; i++) {
		ਜੇ ((dst[i] = strdup(src[i])) == ਨਿਰਾ) {
			ਲਈ (j = 0; j < i; j++)
				ਮੁਕਤ(dst[j]);
			ਮੁਕਤ(dst);
			ਵਾਪਸ -1;
		}
	}
	/* success */
	*dstp = dst;
	*ndstp = nsrc;
	ਵਾਪਸ 0;
}

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ OPTIONS_CRITICAL	1
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ OPTIONS_EXTENSIONS	2
ਸਥਿਰ ਪੂਰਨ
cert_option_list(ਬਣਤਰ sshauthopt *opts, ਬਣਤਰ sshbuf *oblob,
    u_int which, ਪੂਰਨ crit)
{
	ਅੱਖਰ *command, *allowed;
	ਅੱਖਰ *name = ਨਿਰਾ;
	ਬਣਤਰ sshbuf *c = ਨਿਰਾ, *ਅੰਕੜੇ = ਨਿਰਾ;
	ਪੂਰਨ r, ret = -1, ਮਿਲਿਆ;

	ਜੇ ((c = sshbuf_fromb(oblob)) == ਨਿਰਾ) {
		error_f("sshbuf_fromb failed");
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	ਜਦੋਂ (sshbuf_len(c) > 0) {
		sshbuf_free(ਅੰਕੜੇ);
		ਅੰਕੜੇ = ਨਿਰਾ;
		ਜੇ ((r = sshbuf_get_cstring(c, &name, ਨਿਰਾ)) != 0 ||
		    (r = sshbuf_froms(c, &ਅੰਕੜੇ)) != 0) {
			error_r(r, "Unable to parse certificate options");
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		debug3("found certificate option \"%.100s\" len %zu",
		    name, sshbuf_len(ਅੰਕੜੇ));
		ਮਿਲਿਆ = 0;
		ਜੇ ((which & OPTIONS_EXTENSIONS) != 0) {
			ਜੇ (strcmp(name, "no-touch-required") == 0) {
				opts->no_require_user_presence = 1;
				ਮਿਲਿਆ = 1;
			} ਨਹੀਂਤਾਂ ਜੇ (strcmp(name, "permit-X11-forwarding") == 0) {
				opts->permit_x11_forwarding_flag = 1;
				ਮਿਲਿਆ = 1;
			} ਨਹੀਂਤਾਂ ਜੇ (strcmp(name,
			    "permit-agent-forwarding") == 0) {
				opts->permit_agent_forwarding_flag = 1;
				ਮਿਲਿਆ = 1;
			} ਨਹੀਂਤਾਂ ਜੇ (strcmp(name,
			    "permit-port-forwarding") == 0) {
				opts->permit_ਪੋਰਟ_forwarding_flag = 1;
				ਮਿਲਿਆ = 1;
			} ਨਹੀਂਤਾਂ ਜੇ (strcmp(name, "permit-pty") == 0) {
				opts->permit_pty_flag = 1;
				ਮਿਲਿਆ = 1;
			} ਨਹੀਂਤਾਂ ਜੇ (strcmp(name, "permit-user-rc") == 0) {
				opts->permit_user_rc = 1;
				ਮਿਲਿਆ = 1;
			}
		}
		ਜੇ (!ਮਿਲਿਆ && (which & OPTIONS_CRITICAL) != 0) {
			ਜੇ (strcmp(name, "verify-required") == 0) {
				opts->require_verify = 1;
				ਮਿਲਿਆ = 1;
			} ਨਹੀਂਤਾਂ ਜੇ (strcmp(name, "force-command") == 0) {
				ਜੇ ((r = sshbuf_get_cstring(ਅੰਕੜੇ, &command,
				    ਨਿਰਾ)) != 0) {
					error_r(r, "Unable to parse \"%s\" "
					    "section", name);
					ਜਾਓ ਬਾਹਰਲਾ;
				}
				ਜੇ (opts->force_command != ਨਿਰਾ) {
					error("Certificate has multiple "
					    "force-command options");
					ਮੁਕਤ(command);
					ਜਾਓ ਬਾਹਰਲਾ;
				}
				opts->force_command = command;
				ਮਿਲਿਆ = 1;
			} ਨਹੀਂਤਾਂ ਜੇ (strcmp(name, "source-address") == 0) {
				ਜੇ ((r = sshbuf_get_cstring(ਅੰਕੜੇ, &allowed,
				    ਨਿਰਾ)) != 0) {
					error_r(r, "Unable to parse \"%s\" "
					    "section", name);
					ਜਾਓ ਬਾਹਰਲਾ;
				}
				ਜੇ (opts->required_from_host_cert != ਨਿਰਾ) {
					error("Certificate has multiple "
					    "source-address options");
					ਮੁਕਤ(allowed);
					ਜਾਓ ਬਾਹਰਲਾ;
				}
				/* Check syntax */
				ਜੇ (addr_ਮੇਲ_cidr_list(ਨਿਰਾ, allowed) == -1) {
					error("Certificate source-address "
					    "contents invalid");
					ਮੁਕਤ(allowed);
					ਜਾਓ ਬਾਹਰਲਾ;
				}
				opts->required_from_host_cert = allowed;
				ਮਿਲਿਆ = 1;
			}
		}

		ਜੇ (!ਮਿਲਿਆ) {
			ਜੇ (crit) {
				error("Certificate critical option \"%s\" "
				    "is not supported", name);
				ਜਾਓ ਬਾਹਰਲਾ;
			} ਨਹੀਂਤਾਂ {
				logit("Certificate extension \"%s\" "
				    "is not supported", name);
			}
		} ਨਹੀਂਤਾਂ ਜੇ (sshbuf_len(ਅੰਕੜੇ) != 0) {
			error("Certificate option \"%s\" corrupt "
			    "(extra data)", name);
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਮੁਕਤ(name);
		name = ਨਿਰਾ;
	}
	/* successfully parsed all options */
	ret = 0;

 ਬਾਹਰਲਾ:
	ਮੁਕਤ(name);
	sshbuf_free(ਅੰਕੜੇ);
	sshbuf_free(c);
	ਵਾਪਸ ret;
}

ਬਣਤਰ sshauthopt *
sshauthopt_new(ਖਾਲੀ)
{
	ਬਣਤਰ sshauthopt *ret;

	ਜੇ ((ret = ਸਿਫਰ_ਸਮ੍ਰਿਤੀ_ਦਿਓ(1, ਆਕਾਰ(*ret))) == ਨਿਰਾ)
		ਵਾਪਸ ਨਿਰਾ;
	ret->force_tun_device = -1;
	ਵਾਪਸ ret;
}

ਖਾਲੀ
sshauthopt_free(ਬਣਤਰ sshauthopt *opts)
{
	ਮਾਪ_t i;

	ਜੇ (opts == ਨਿਰਾ)
		ਵਾਪਸ;

	ਮੁਕਤ(opts->cert_principals);
	ਮੁਕਤ(opts->force_command);
	ਮੁਕਤ(opts->required_from_host_cert);
	ਮੁਕਤ(opts->required_from_host_ਕੁੰਜੀਆਂ);

	ਲਈ (i = 0; i < opts->nenv; i++)
		ਮੁਕਤ(opts->env[i]);
	ਮੁਕਤ(opts->env);

	ਲਈ (i = 0; i < opts->npermitopen; i++)
		ਮੁਕਤ(opts->permitopen[i]);
	ਮੁਕਤ(opts->permitopen);

	ਲਈ (i = 0; i < opts->npermitlisten; i++)
		ਮੁਕਤ(opts->permitlisten[i]);
	ਮੁਕਤ(opts->permitlisten);

	freezero(opts, ਆਕਾਰ(*opts));
}

ਬਣਤਰ sshauthopt *
sshauthopt_new_with_ਕੁੰਜੀਆਂ_defaults(ਖਾਲੀ)
{
	ਬਣਤਰ sshauthopt *ret = ਨਿਰਾ;

	ਜੇ ((ret = sshauthopt_new()) == ਨਿਰਾ)
		ਵਾਪਸ ਨਿਰਾ;

	/* Defaults for authorized_keys flags */
	ret->permit_ਪੋਰਟ_forwarding_flag = 1;
	ret->permit_agent_forwarding_flag = 1;
	ret->permit_x11_forwarding_flag = 1;
	ret->permit_pty_flag = 1;
	ret->permit_user_rc = 1;
	ਵਾਪਸ ret;
}

/*
 * Parse and record a permitopen/permitlisten directive.
 * Return 0 on success. Return -1 on failure and sets *errstrp to error reason.
 */
ਸਥਿਰ ਪੂਰਨ
handle_permit(ਅਚਲ ਅੱਖਰ **optsp, ਪੂਰਨ allow_bare_ਪੋਰਟ,
    ਅੱਖਰ ***permitsp, ਮਾਪ_t *npermitsp, ਅਚਲ ਅੱਖਰ **errstrp)
{
	ਅੱਖਰ *opt, *tmp, *cp, *host, **permits = *permitsp;
	ਮਾਪ_t npermits = *npermitsp;
	ਅਚਲ ਅੱਖਰ *errstr = "unknown error";

	ਜੇ (npermits > SSH_AUTHOPT_PERMIT_MAX) {
		*errstrp = "too many permission directives";
		ਵਾਪਸ -1;
	}
	ਜੇ ((opt = opt_dequote(optsp, &errstr)) == ਨਿਰਾ) {
		ਵਾਪਸ -1;
	}
	ਜੇ (allow_bare_ਪੋਰਟ && strchr(opt, ':') == ਨਿਰਾ) {
		/*
		 * Allow a bare port number in permitlisten to indicate a
		 * listen_host wildcard.
		 */
		ਜੇ (asprintf(&tmp, "*:%s", opt) == -1) {
			ਮੁਕਤ(opt);
			*errstrp = "memory allocation failed";
			ਵਾਪਸ -1;
		}
		ਮੁਕਤ(opt);
		opt = tmp;
	}
	ਜੇ ((tmp = strdup(opt)) == ਨਿਰਾ) {
		ਮੁਕਤ(opt);
		*errstrp = "memory allocation failed";
		ਵਾਪਸ -1;
	}
	cp = tmp;
	/* validate syntax before recording it. */
	host = hpdelim2(&cp, ਨਿਰਾ);
	ਜੇ (host == ਨਿਰਾ || ਲੜੀ_ਲੰਬਾਈ(host) >= NI_MAXHOST) {
		ਮੁਕਤ(tmp);
		ਮੁਕਤ(opt);
		*errstrp = "invalid permission hostname";
		ਵਾਪਸ -1;
	}
	/*
	 * don't want to use permitopen_port to avoid
	 * dependency on channels.[ch] here.
	 */
	ਜੇ (cp == ਨਿਰਾ ||
	    (strcmp(cp, "*") != 0 && a2port(cp) <= 0)) {
		ਮੁਕਤ(tmp);
		ਮੁਕਤ(opt);
		*errstrp = "invalid permission port";
		ਵਾਪਸ -1;
	}
	/* XXX - add streamlocal support */
	ਮੁਕਤ(tmp);
	/* Record it */
	ਜੇ ((permits = recallocarray(permits, npermits, npermits + 1,
	    ਆਕਾਰ(*permits))) == ਨਿਰਾ) {
		ਮੁਕਤ(opt);
		/* NB. don't update *permitsp if alloc fails */
		*errstrp = "memory allocation failed";
		ਵਾਪਸ -1;
	}
	permits[npermits++] = opt;
	*permitsp = permits;
	*npermitsp = npermits;
	ਵਾਪਸ 0;
}

ਬਣਤਰ sshauthopt *
sshauthopt_parse(ਅਚਲ ਅੱਖਰ *opts, ਅਚਲ ਅੱਖਰ **errstrp)
{
	ਅੱਖਰ **oarray, *opt, *cp, *tmp;
	ਪੂਰਨ r;
	ਬਣਤਰ sshauthopt *ret = ਨਿਰਾ;
	ਅਚਲ ਅੱਖਰ *errstr = "unknown error";
	uint64_t valid_before;
	ਮਾਪ_t i, l;

	ਜੇ (errstrp != ਨਿਰਾ)
		*errstrp = ਨਿਰਾ;
	ਜੇ ((ret = sshauthopt_new_with_ਕੁੰਜੀਆਂ_defaults()) == ਨਿਰਾ)
		ਜਾਓ alloc_fail;

	ਜੇ (opts == ਨਿਰਾ)
		ਵਾਪਸ ret;

	ਜਦੋਂ (*opts && *opts != ' ' && *opts != '\t') {
		/* flag options */
		ਜੇ ((r = opt_flag("restrict", 0, &opts)) != -1) {
			ret->restricted = 1;
			ret->permit_ਪੋਰਟ_forwarding_flag = 0;
			ret->permit_agent_forwarding_flag = 0;
			ret->permit_x11_forwarding_flag = 0;
			ret->permit_pty_flag = 0;
			ret->permit_user_rc = 0;
		} ਨਹੀਂਤਾਂ ਜੇ ((r = opt_flag("cert-authority", 0, &opts)) != -1) {
			ret->cert_authority = r;
		} ਨਹੀਂਤਾਂ ਜੇ ((r = opt_flag("port-forwarding", 1, &opts)) != -1) {
			ret->permit_ਪੋਰਟ_forwarding_flag = r == 1;
		} ਨਹੀਂਤਾਂ ਜੇ ((r = opt_flag("agent-forwarding", 1, &opts)) != -1) {
			ret->permit_agent_forwarding_flag = r == 1;
		} ਨਹੀਂਤਾਂ ਜੇ ((r = opt_flag("x11-forwarding", 1, &opts)) != -1) {
			ret->permit_x11_forwarding_flag = r == 1;
		} ਨਹੀਂਤਾਂ ਜੇ ((r = opt_flag("touch-required", 1, &opts)) != -1) {
			ret->no_require_user_presence = r != 1; /* NB. flip */
		} ਨਹੀਂਤਾਂ ਜੇ ((r = opt_flag("verify-required", 1, &opts)) != -1) {
			ret->require_verify = r == 1;
		} ਨਹੀਂਤਾਂ ਜੇ ((r = opt_flag("pty", 1, &opts)) != -1) {
			ret->permit_pty_flag = r == 1;
		} ਨਹੀਂਤਾਂ ਜੇ ((r = opt_flag("user-rc", 1, &opts)) != -1) {
			ret->permit_user_rc = r == 1;
		} ਨਹੀਂਤਾਂ ਜੇ (opt_ਮੇਲ(&opts, "command")) {
			ਜੇ (ret->force_command != ਨਿਰਾ) {
				errstr = "multiple \"command\" clauses";
				ਜਾਓ fail;
			}
			ret->force_command = opt_dequote(&opts, &errstr);
			ਜੇ (ret->force_command == ਨਿਰਾ)
				ਜਾਓ fail;
		} ਨਹੀਂਤਾਂ ਜੇ (opt_ਮੇਲ(&opts, "principals")) {
			ਜੇ (ret->cert_principals != ਨਿਰਾ) {
				errstr = "multiple \"principals\" clauses";
				ਜਾਓ fail;
			}
			ret->cert_principals = opt_dequote(&opts, &errstr);
			ਜੇ (ret->cert_principals == ਨਿਰਾ)
				ਜਾਓ fail;
		} ਨਹੀਂਤਾਂ ਜੇ (opt_ਮੇਲ(&opts, "from")) {
			ਜੇ (ret->required_from_host_ਕੁੰਜੀਆਂ != ਨਿਰਾ) {
				errstr = "multiple \"from\" clauses";
				ਜਾਓ fail;
			}
			ret->required_from_host_ਕੁੰਜੀਆਂ = opt_dequote(&opts,
			    &errstr);
			ਜੇ (ret->required_from_host_ਕੁੰਜੀਆਂ == ਨਿਰਾ)
				ਜਾਓ fail;
		} ਨਹੀਂਤਾਂ ਜੇ (opt_ਮੇਲ(&opts, "expiry-time")) {
			ਜੇ ((opt = opt_dequote(&opts, &errstr)) == ਨਿਰਾ)
				ਜਾਓ fail;
			ਜੇ (parse_absolute_ਸਮਾਂ(opt, &valid_before) != 0 ||
			    valid_before == 0) {
				ਮੁਕਤ(opt);
				errstr = "invalid expires time";
				ਜਾਓ fail;
			}
			ਮੁਕਤ(opt);
			ਜੇ (ret->valid_before == 0 ||
			    valid_before < ret->valid_before)
				ret->valid_before = valid_before;
		} ਨਹੀਂਤਾਂ ਜੇ (opt_ਮੇਲ(&opts, "environment")) {
			ਜੇ (ret->nenv > SSH_AUTHOPT_ENV_MAX) {
				errstr = "too many environment strings";
				ਜਾਓ fail;
			}
			ਜੇ ((opt = opt_dequote(&opts, &errstr)) == ਨਿਰਾ)
				ਜਾਓ fail;
			/* env name must be alphanumeric and followed by '=' */
			ਜੇ ((tmp = strchr(opt, '=')) == ਨਿਰਾ) {
				ਮੁਕਤ(opt);
				errstr = "invalid environment string";
				ਜਾਓ fail;
			}
			ਜੇ ((cp = strdup(opt)) == ਨਿਰਾ) {
				ਮੁਕਤ(opt);
				ਜਾਓ alloc_fail;
			}
			l = (ਮਾਪ_t)(tmp - opt);
			cp[l] = '\0'; /* truncate at '=' */
			ਜੇ (!valid_env_name(cp)) {
				ਮੁਕਤ(cp);
				ਮੁਕਤ(opt);
				errstr = "invalid environment string";
				ਜਾਓ fail;
			}
			/* Check for duplicates; XXX O(n*log(n)) */
			ਲਈ (i = 0; i < ret->nenv; i++) {
				ਜੇ (ਲੜੀ_ਤੁਲਨਾ(ret->env[i], cp, l) == 0 &&
				    ret->env[i][l] == '=')
					ਰੋਕੋ;
			}
			ਮੁਕਤ(cp);
			/* First match wins */
			ਜੇ (i >= ret->nenv) {
				/* Append it. */
				oarray = ret->env;
				ਜੇ ((ret->env = recallocarray(ret->env,
				    ret->nenv, ret->nenv + 1,
				    ਆਕਾਰ(*ret->env))) == ਨਿਰਾ) {
					ਮੁਕਤ(opt);
					/* put it back for cleanup */
					ret->env = oarray;
					ਜਾਓ alloc_fail;
				}
				ret->env[ret->nenv++] = opt;
				opt = ਨਿਰਾ; /* transferred */
			}
			ਮੁਕਤ(opt);
		} ਨਹੀਂਤਾਂ ਜੇ (opt_ਮੇਲ(&opts, "permitopen")) {
			ਜੇ (handle_permit(&opts, 0, &ret->permitopen,
			    &ret->npermitopen, &errstr) != 0)
				ਜਾਓ fail;
		} ਨਹੀਂਤਾਂ ਜੇ (opt_ਮੇਲ(&opts, "permitlisten")) {
			ਜੇ (handle_permit(&opts, 1, &ret->permitlisten,
			    &ret->npermitlisten, &errstr) != 0)
				ਜਾਓ fail;
		} ਨਹੀਂਤਾਂ ਜੇ (opt_ਮੇਲ(&opts, "tunnel")) {
			ਜੇ ((opt = opt_dequote(&opts, &errstr)) == ਨਿਰਾ)
				ਜਾਓ fail;
			ret->force_tun_device = a2tun(opt, ਨਿਰਾ);
			ਮੁਕਤ(opt);
			ਜੇ (ret->force_tun_device == SSH_TUNID_ERR) {
				errstr = "invalid tun device";
				ਜਾਓ fail;
			}
		}
		/*
		 * Skip the comma, and move to the next option
		 * (or break out if there are no more).
		 */
		ਜੇ (*opts == '\0' || *opts == ' ' || *opts == '\t')
			ਰੋਕੋ;		/* End of options. */
		/* Anything other than a comma is an unknown option */
		ਜੇ (*opts != ',') {
			errstr = "unknown key option";
			ਜਾਓ fail;
		}
		opts++;
		ਜੇ (*opts == '\0') {
			errstr = "unexpected end-of-options";
			ਜਾਓ fail;
		}
	}

	/* success */
	ਜੇ (errstrp != ਨਿਰਾ)
		*errstrp = ਨਿਰਾ;
	ਵਾਪਸ ret;

alloc_fail:
	errstr = "memory allocation failed";
fail:
	sshauthopt_free(ret);
	ਜੇ (errstrp != ਨਿਰਾ)
		*errstrp = errstr;
	ਵਾਪਸ ਨਿਰਾ;
}

ਬਣਤਰ sshauthopt *
sshauthopt_from_cert(ਬਣਤਰ sshkey *k)
{
	ਬਣਤਰ sshauthopt *ret;

	ਜੇ (k == ਨਿਰਾ || !sshkey_type_is_cert(k->type) || k->cert == ਨਿਰਾ ||
	    k->cert->type != SSH2_CERT_TYPE_USER)
		ਵਾਪਸ ਨਿਰਾ;

	ਜੇ ((ret = sshauthopt_new()) == ਨਿਰਾ)
		ਵਾਪਸ ਨਿਰਾ;

	/* Handle options and critical extensions separately */
	ਜੇ (cert_option_list(ret, k->cert->critical,
	    OPTIONS_CRITICAL, 1) == -1) {
		sshauthopt_free(ret);
		ਵਾਪਸ ਨਿਰਾ;
	}
	ਜੇ (cert_option_list(ret, k->cert->extensions,
	    OPTIONS_EXTENSIONS, 0) == -1) {
		sshauthopt_free(ret);
		ਵਾਪਸ ਨਿਰਾ;
	}
	/* success */
	ਵਾਪਸ ret;
}

/*
 * Merges "additional" options to "primary" and returns the result.
 * NB. Some options from primary have primacy.
 */
ਬਣਤਰ sshauthopt *
sshauthopt_ਮਿਲਾਓ(ਅਚਲ ਬਣਤਰ sshauthopt *primary,
    ਅਚਲ ਬਣਤਰ sshauthopt *additional, ਅਚਲ ਅੱਖਰ **errstrp)
{
	ਬਣਤਰ sshauthopt *ret;
	ਅਚਲ ਅੱਖਰ *errstr = "internal error";
	ਅਚਲ ਅੱਖਰ *tmp;

	ਜੇ (errstrp != ਨਿਰਾ)
		*errstrp = ਨਿਰਾ;

	ਜੇ ((ret = sshauthopt_new()) == ਨਿਰਾ)
		ਜਾਓ alloc_fail;

	/* cert_authority and cert_principals are cleared in result */

	/* Prefer access lists from primary. */
	/* XXX err is both set and mismatch? */
	tmp = primary->required_from_host_cert;
	ਜੇ (tmp == ਨਿਰਾ)
		tmp = additional->required_from_host_cert;
	ਜੇ (tmp != ਨਿਰਾ && (ret->required_from_host_cert = strdup(tmp)) == ਨਿਰਾ)
		ਜਾਓ alloc_fail;
	tmp = primary->required_from_host_ਕੁੰਜੀਆਂ;
	ਜੇ (tmp == ਨਿਰਾ)
		tmp = additional->required_from_host_ਕੁੰਜੀਆਂ;
	ਜੇ (tmp != ਨਿਰਾ && (ret->required_from_host_ਕੁੰਜੀਆਂ = strdup(tmp)) == ਨਿਰਾ)
		ਜਾਓ alloc_fail;

	/*
	 * force_tun_device, permitopen/permitlisten and environment all
	 * prefer the primary.
	 */
	ret->force_tun_device = primary->force_tun_device;
	ਜੇ (ret->force_tun_device == -1)
		ret->force_tun_device = additional->force_tun_device;
	ਜੇ (primary->nenv > 0) {
		ਜੇ (dup_ਲੜੀਆਂ(&ret->env, &ret->nenv,
		    primary->env, primary->nenv) != 0)
			ਜਾਓ alloc_fail;
	} ਨਹੀਂਤਾਂ ਜੇ (additional->nenv) {
		ਜੇ (dup_ਲੜੀਆਂ(&ret->env, &ret->nenv,
		    additional->env, additional->nenv) != 0)
			ਜਾਓ alloc_fail;
	}
	ਜੇ (primary->npermitopen > 0) {
		ਜੇ (dup_ਲੜੀਆਂ(&ret->permitopen, &ret->npermitopen,
		    primary->permitopen, primary->npermitopen) != 0)
			ਜਾਓ alloc_fail;
	} ਨਹੀਂਤਾਂ ਜੇ (additional->npermitopen > 0) {
		ਜੇ (dup_ਲੜੀਆਂ(&ret->permitopen, &ret->npermitopen,
		    additional->permitopen, additional->npermitopen) != 0)
			ਜਾਓ alloc_fail;
	}

	ਜੇ (primary->npermitlisten > 0) {
		ਜੇ (dup_ਲੜੀਆਂ(&ret->permitlisten, &ret->npermitlisten,
		    primary->permitlisten, primary->npermitlisten) != 0)
			ਜਾਓ alloc_fail;
	} ਨਹੀਂਤਾਂ ਜੇ (additional->npermitlisten > 0) {
		ਜੇ (dup_ਲੜੀਆਂ(&ret->permitlisten, &ret->npermitlisten,
		    additional->permitlisten, additional->npermitlisten) != 0)
			ਜਾਓ alloc_fail;
	}

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ OPTFLAG_AND(x) ret->x = (primary->x == 1) && (additional->x == 1)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ OPTFLAG_OR(x) ret->x = (primary->x == 1) || (additional->x == 1)
	/* Permissive flags are logical-AND (i.e. must be set in both) */
	OPTFLAG_AND(permit_ਪੋਰਟ_forwarding_flag);
	OPTFLAG_AND(permit_agent_forwarding_flag);
	OPTFLAG_AND(permit_x11_forwarding_flag);
	OPTFLAG_AND(permit_pty_flag);
	OPTFLAG_AND(permit_user_rc);
	OPTFLAG_AND(no_require_user_presence);
	/* Restrictive flags are logical-OR (i.e. must be set in either) */
	OPTFLAG_OR(require_verify);
	OPTFLAG_OR(restricted);
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ OPTFLAG_AND

	/* Earliest expiry time should win */
	ਜੇ (primary->valid_before != 0)
		ret->valid_before = primary->valid_before;
	ਜੇ (additional->valid_before != 0 &&
	    additional->valid_before < ret->valid_before)
		ret->valid_before = additional->valid_before;

	/*
	 * When both multiple forced-command are specified, only
	 * proceed if they are identical, otherwise fail.
	 */
	ਜੇ (primary->force_command != ਨਿਰਾ &&
	    additional->force_command != ਨਿਰਾ) {
		ਜੇ (strcmp(primary->force_command,
		    additional->force_command) == 0) {
			/* ok */
			ret->force_command = strdup(primary->force_command);
			ਜੇ (ret->force_command == ਨਿਰਾ)
				ਜਾਓ alloc_fail;
		} ਨਹੀਂਤਾਂ {
			errstr = "forced command options do not match";
			ਜਾਓ fail;
		}
	} ਨਹੀਂਤਾਂ ਜੇ (primary->force_command != ਨਿਰਾ) {
		ਜੇ ((ret->force_command = strdup(
		    primary->force_command)) == ਨਿਰਾ)
			ਜਾਓ alloc_fail;
	} ਨਹੀਂਤਾਂ ਜੇ (additional->force_command != ਨਿਰਾ) {
		ਜੇ ((ret->force_command = strdup(
		    additional->force_command)) == ਨਿਰਾ)
			ਜਾਓ alloc_fail;
	}
	/* success */
	ਜੇ (errstrp != ਨਿਰਾ)
		*errstrp = ਨਿਰਾ;
	ਵਾਪਸ ret;

 alloc_fail:
	errstr = "memory allocation failed";
 fail:
	ਜੇ (errstrp != ਨਿਰਾ)
		*errstrp = errstr;
	sshauthopt_free(ret);
	ਵਾਪਸ ਨਿਰਾ;
}

/*
 * Copy options
 */
ਬਣਤਰ sshauthopt *
sshauthopt_copy(ਅਚਲ ਬਣਤਰ sshauthopt *orig)
{
	ਬਣਤਰ sshauthopt *ret;

	ਜੇ ((ret = sshauthopt_new()) == ਨਿਰਾ)
		ਵਾਪਸ ਨਿਰਾ;

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ OPTSCALAR(x) ret->x = orig->x
	OPTSCALAR(permit_ਪੋਰਟ_forwarding_flag);
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
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ OPTSCALAR
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ OPTSTRING(x) \
	ਕਰੋ { \
		ਜੇ (orig->x != ਨਿਰਾ && (ret->x = strdup(orig->x)) == ਨਿਰਾ) { \
			sshauthopt_free(ret); \
			ਵਾਪਸ ਨਿਰਾ; \
		} \
	} ਜਦੋਂ (0)
	OPTSTRING(cert_principals);
	OPTSTRING(force_command);
	OPTSTRING(required_from_host_cert);
	OPTSTRING(required_from_host_ਕੁੰਜੀਆਂ);
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ OPTSTRING

	ਜੇ (dup_ਲੜੀਆਂ(&ret->env, &ret->nenv, orig->env, orig->nenv) != 0 ||
	    dup_ਲੜੀਆਂ(&ret->permitopen, &ret->npermitopen,
	    orig->permitopen, orig->npermitopen) != 0 ||
	    dup_ਲੜੀਆਂ(&ret->permitlisten, &ret->npermitlisten,
	    orig->permitlisten, orig->npermitlisten) != 0) {
		sshauthopt_free(ret);
		ਵਾਪਸ ਨਿਰਾ;
	}
	ਵਾਪਸ ret;
}

ਸਥਿਰ ਪੂਰਨ
serialise_array(ਬਣਤਰ sshbuf *m, ਅੱਖਰ **a, ਮਾਪ_t n)
{
	ਬਣਤਰ sshbuf *b;
	ਮਾਪ_t i;
	ਪੂਰਨ r = SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;

	ਜੇ (n > ਵੱਧ_ਤੋਂ_ਵੱਧ_ਅੰਕ)
		ਵਾਪਸ SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;

	ਜੇ ((b = sshbuf_new()) == ਨਿਰਾ) {
		ਵਾਪਸ SSH_ERR_ALLOC_FAIL;
	}
	ਲਈ (i = 0; i < n; i++) {
		ਜੇ ((r = sshbuf_put_cstring(b, a[i])) != 0)
			ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((r = sshbuf_put_u32(m, n)) != 0 ||
	    (r = sshbuf_put_stringb(m, b)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	/* success */
	r = 0;
 ਬਾਹਰਲਾ:
	sshbuf_free(b);
	ਵਾਪਸ r;
}

ਸਥਿਰ ਪੂਰਨ
deserialise_array(ਬਣਤਰ sshbuf *m, ਅੱਖਰ ***ap, ਮਾਪ_t *np)
{
	ਅੱਖਰ **a = ਨਿਰਾ;
	ਮਾਪ_t i, n = 0;
	ਬਣਤਰ sshbuf *b = ਨਿਰਾ;
	u_int tmp;
	ਪੂਰਨ r = SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;

	ਜੇ ((r = sshbuf_get_u32(m, &tmp)) != 0 ||
	    (r = sshbuf_froms(m, &b)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	ਜੇ (tmp > ਵੱਧ_ਤੋਂ_ਵੱਧ_ਅੰਕ) {
		r = SSH_ERR_INVALID_FORMAT;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	n = tmp;
	ਜੇ (n > 0 && (a = ਸਿਫਰ_ਸਮ੍ਰਿਤੀ_ਦਿਓ(n, ਆਕਾਰ(*a))) == ਨਿਰਾ) {
		r = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਲਈ (i = 0; i < n; i++) {
		ਜੇ ((r = sshbuf_get_cstring(b, &a[i], ਨਿਰਾ)) != 0)
			ਜਾਓ ਬਾਹਰਲਾ;
	}
	/* success */
	r = 0;
	*ap = a;
	a = ਨਿਰਾ;
	*np = n;
	n = 0;
 ਬਾਹਰਲਾ:
	ਜੇ (a != ਨਿਰਾ) {
		ਲਈ (i = 0; i < n; i++)
			ਮੁਕਤ(a[i]);
		ਮੁਕਤ(a);
	}
	sshbuf_free(b);
	ਵਾਪਸ r;
}

ਸਥਿਰ ਪੂਰਨ
serialise_nullable_string(ਬਣਤਰ sshbuf *m, ਅਚਲ ਅੱਖਰ *s)
{
	ਪੂਰਨ r;

	ਜੇ ((r = sshbuf_put_u8(m, s == ਨਿਰਾ)) != 0 ||
	    (r = sshbuf_put_cstring(m, s)) != 0)
		ਵਾਪਸ r;
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
deserialise_nullable_string(ਬਣਤਰ sshbuf *m, ਅੱਖਰ **sp)
{
	ਪੂਰਨ r;
	u_char flag;

	*sp = ਨਿਰਾ;
	ਜੇ ((r = sshbuf_get_u8(m, &flag)) != 0 ||
	    (r = sshbuf_get_cstring(m, flag ? ਨਿਰਾ : sp, ਨਿਰਾ)) != 0)
		ਵਾਪਸ r;
	ਵਾਪਸ 0;
}

ਪੂਰਨ
sshauthopt_serialise(ਅਚਲ ਬਣਤਰ sshauthopt *opts, ਬਣਤਰ sshbuf *m,
    ਪੂਰਨ untrusted)
{
	ਪੂਰਨ r = SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;

	/* Flag options */
	ਜੇ ((r = sshbuf_put_u8(m, opts->permit_ਪੋਰਟ_forwarding_flag)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->permit_agent_forwarding_flag)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->permit_x11_forwarding_flag)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->permit_pty_flag)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->permit_user_rc)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->restricted)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->cert_authority)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->no_require_user_presence)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->require_verify)) != 0)
		ਵਾਪਸ r;

	/* Simple integer options */
	ਜੇ ((r = sshbuf_put_u64(m, opts->valid_before)) != 0)
		ਵਾਪਸ r;

	/* tunnel number can be negative to indicate "unset" */
	ਜੇ ((r = sshbuf_put_u8(m, opts->force_tun_device == -1)) != 0 ||
	    (r = sshbuf_put_u32(m, (opts->force_tun_device < 0) ?
	    0 : (u_int)opts->force_tun_device)) != 0)
		ਵਾਪਸ r;

	/* String options; these may be NULL */
	ਜੇ ((r = serialise_nullable_string(m,
	    untrusted ? "yes" : opts->cert_principals)) != 0 ||
	    (r = serialise_nullable_string(m,
	    untrusted ? "true" : opts->force_command)) != 0 ||
	    (r = serialise_nullable_string(m,
	    untrusted ? ਨਿਰਾ : opts->required_from_host_cert)) != 0 ||
	    (r = serialise_nullable_string(m,
	    untrusted ? ਨਿਰਾ : opts->required_from_host_ਕੁੰਜੀਆਂ)) != 0)
		ਵਾਪਸ r;

	/* Array options */
	ਜੇ ((r = serialise_array(m, opts->env,
	    untrusted ? 0 : opts->nenv)) != 0 ||
	    (r = serialise_array(m, opts->permitopen,
	    untrusted ? 0 : opts->npermitopen)) != 0 ||
	    (r = serialise_array(m, opts->permitlisten,
	    untrusted ? 0 : opts->npermitlisten)) != 0)
		ਵਾਪਸ r;

	/* success */
	ਵਾਪਸ 0;
}

ਪੂਰਨ
sshauthopt_deserialise(ਬਣਤਰ sshbuf *m, ਬਣਤਰ sshauthopt **optsp)
{
	ਬਣਤਰ sshauthopt *opts = ਨਿਰਾ;
	ਪੂਰਨ r = SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
	u_char f;
	u_int tmp;

	ਜੇ ((opts = ਸਿਫਰ_ਸਮ੍ਰਿਤੀ_ਦਿਓ(1, ਆਕਾਰ(*opts))) == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_ALLOC_FAIL;

	/* Flag options */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ OPT_FLAG(x) \
	ਕਰੋ { \
		ਜੇ ((r = sshbuf_get_u8(m, &f)) != 0) \
			ਜਾਓ ਬਾਹਰਲਾ; \
		opts->x = f; \
	} ਜਦੋਂ (0)
	OPT_FLAG(permit_ਪੋਰਟ_forwarding_flag);
	OPT_FLAG(permit_agent_forwarding_flag);
	OPT_FLAG(permit_x11_forwarding_flag);
	OPT_FLAG(permit_pty_flag);
	OPT_FLAG(permit_user_rc);
	OPT_FLAG(restricted);
	OPT_FLAG(cert_authority);
	OPT_FLAG(no_require_user_presence);
	OPT_FLAG(require_verify);
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ OPT_FLAG

	/* Simple integer options */
	ਜੇ ((r = sshbuf_get_u64(m, &opts->valid_before)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;

	/* tunnel number can be negative to indicate "unset" */
	ਜੇ ((r = sshbuf_get_u8(m, &f)) != 0 ||
	    (r = sshbuf_get_u32(m, &tmp)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	opts->force_tun_device = f ? -1 : (ਪੂਰਨ)tmp;

	/* String options may be NULL */
	ਜੇ ((r = deserialise_nullable_string(m, &opts->cert_principals)) != 0 ||
	    (r = deserialise_nullable_string(m, &opts->force_command)) != 0 ||
	    (r = deserialise_nullable_string(m,
	    &opts->required_from_host_cert)) != 0 ||
	    (r = deserialise_nullable_string(m,
	    &opts->required_from_host_ਕੁੰਜੀਆਂ)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;

	/* Array options */
	ਜੇ ((r = deserialise_array(m, &opts->env, &opts->nenv)) != 0 ||
	    (r = deserialise_array(m,
	    &opts->permitopen, &opts->npermitopen)) != 0 ||
	    (r = deserialise_array(m,
	    &opts->permitlisten, &opts->npermitlisten)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;

	/* success */
	r = 0;
	*optsp = opts;
	opts = ਨਿਰਾ;
 ਬਾਹਰਲਾ:
	sshauthopt_free(opts);
	ਵਾਪਸ r;
}
