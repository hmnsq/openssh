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

#include "includes.h"

#include <sys/types.h>
#include <sys/queue.h>

#include <stdlib.h>
#include <netdb.h>
#include <pwd.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include <ctype.h>
#include <limits.h>

#include "xmalloc.h"
#include "ssherr.h"
#include "log.h"
#include "sshbuf.h"
#include "misc.h"
#include "sshkey.h"
#include "match.h"
#include "ssh2.h"
#include "auth-options.h"

static puur_naa_nka
dup_strings(var_na ***dstp, size_t *ndstp, var_na **src, size_t nsrc)
{
	var_na **dst;
	size_t i, j;

	*dstp = NULL;
	*ndstp = 0;

	ꦪꦼꦤ꧀ (nsrc == 0)
		ꦮꦭꦶ 0;
	ꦪꦼꦤ꧀ (nsrc >= SIZE_MAX / parimaa_na(*src) ||
	    (dst = calloc(nsrc, parimaa_na(*src))) == NULL)
		ꦮꦭꦶ -1;
	ꦏꦁꦒꦺꦴ (i = 0; i < nsrc; i++) {
		ꦪꦼꦤ꧀ ((dst[i] = strdup(src[i])) == NULL) {
			ꦏꦁꦒꦺꦴ (j = 0; j < i; j++)
				free(dst[j]);
			free(dst);
			ꦮꦭꦶ -1;
		}
	}
	/* success */
	*dstp = dst;
	*ndstp = nsrc;
	ꦮꦭꦶ 0;
}

#define OPTIONS_CRITICAL	1
#define OPTIONS_EXTENSIONS	2
static puur_naa_nka
cert_option_list(sa_nracanaa sshauthopt *opts, sa_nracanaa sshbuf *oblob,
    u_int which, puur_naa_nka crit)
{
	var_na *command, *allowed;
	var_na *name = NULL;
	sa_nracanaa sshbuf *c = NULL, *data = NULL;
	puur_naa_nka r, ret = -1, found;

	ꦪꦼꦤ꧀ ((c = sshbuf_fromb(oblob)) == NULL) {
		error_f("sshbuf_fromb failed");
		goto out;
	}

	ꦱꦼꦢꦼꦭ (sshbuf_len(c) > 0) {
		sshbuf_free(data);
		data = NULL;
		ꦪꦼꦤ꧀ ((r = sshbuf_get_cstring(c, &name, NULL)) != 0 ||
		    (r = sshbuf_froms(c, &data)) != 0) {
			error_r(r, "Unable to parse certificate options");
			goto out;
		}
		debug3("found certificate option \"%.100s\" len %zu",
		    name, sshbuf_len(data));
		found = 0;
		ꦪꦼꦤ꧀ ((which & OPTIONS_EXTENSIONS) != 0) {
			ꦪꦼꦤ꧀ (strcmp(name, "no-touch-required") == 0) {
				opts->no_require_user_presence = 1;
				found = 1;
			} ꦭꦶꦪ ꦪꦼꦤ꧀ (strcmp(name, "permit-X11-forwarding") == 0) {
				opts->permit_x11_forwarding_flag = 1;
				found = 1;
			} ꦭꦶꦪ ꦪꦼꦤ꧀ (strcmp(name,
			    "permit-agent-forwarding") == 0) {
				opts->permit_agent_forwarding_flag = 1;
				found = 1;
			} ꦭꦶꦪ ꦪꦼꦤ꧀ (strcmp(name,
			    "permit-port-forwarding") == 0) {
				opts->permit_port_forwarding_flag = 1;
				found = 1;
			} ꦭꦶꦪ ꦪꦼꦤ꧀ (strcmp(name, "permit-pty") == 0) {
				opts->permit_pty_flag = 1;
				found = 1;
			} ꦭꦶꦪ ꦪꦼꦤ꧀ (strcmp(name, "permit-user-rc") == 0) {
				opts->permit_user_rc = 1;
				found = 1;
			}
		}
		ꦪꦼꦤ꧀ (!found && (which & OPTIONS_CRITICAL) != 0) {
			ꦪꦼꦤ꧀ (strcmp(name, "verify-required") == 0) {
				opts->require_verify = 1;
				found = 1;
			} ꦭꦶꦪ ꦪꦼꦤ꧀ (strcmp(name, "force-command") == 0) {
				ꦪꦼꦤ꧀ ((r = sshbuf_get_cstring(data, &command,
				    NULL)) != 0) {
					error_r(r, "Unable to parse \"%s\" "
					    "section", name);
					goto out;
				}
				ꦪꦼꦤ꧀ (opts->force_command != NULL) {
					error("Certificate has multiple "
					    "force-command options");
					free(command);
					goto out;
				}
				opts->force_command = command;
				found = 1;
			} ꦭꦶꦪ ꦪꦼꦤ꧀ (strcmp(name, "source-address") == 0) {
				ꦪꦼꦤ꧀ ((r = sshbuf_get_cstring(data, &allowed,
				    NULL)) != 0) {
					error_r(r, "Unable to parse \"%s\" "
					    "section", name);
					goto out;
				}
				ꦪꦼꦤ꧀ (opts->required_from_host_cert != NULL) {
					error("Certificate has multiple "
					    "source-address options");
					free(allowed);
					goto out;
				}
				/* Check syntax */
				ꦪꦼꦤ꧀ (addr_match_cidr_list(NULL, allowed) == -1) {
					error("Certificate source-address "
					    "contents invalid");
					free(allowed);
					goto out;
				}
				opts->required_from_host_cert = allowed;
				found = 1;
			}
		}

		ꦪꦼꦤ꧀ (!found) {
			ꦪꦼꦤ꧀ (crit) {
				error("Certificate critical option \"%s\" "
				    "is not supported", name);
				goto out;
			} ꦭꦶꦪ {
				logit("Certificate extension \"%s\" "
				    "is not supported", name);
			}
		} ꦭꦶꦪ ꦪꦼꦤ꧀ (sshbuf_len(data) != 0) {
			error("Certificate option \"%s\" corrupt "
			    "(extra data)", name);
			goto out;
		}
		free(name);
		name = NULL;
	}
	/* successfully parsed all options */
	ret = 0;

 out:
	free(name);
	sshbuf_free(data);
	sshbuf_free(c);
	ꦮꦭꦶ ret;
}

sa_nracanaa sshauthopt *
sshauthopt_new(void)
{
	sa_nracanaa sshauthopt *ret;

	ꦪꦼꦤ꧀ ((ret = calloc(1, parimaa_na(*ret))) == NULL)
		ꦮꦭꦶ NULL;
	ret->force_tun_device = -1;
	ꦮꦭꦶ ret;
}

void
sshauthopt_free(sa_nracanaa sshauthopt *opts)
{
	size_t i;

	ꦪꦼꦤ꧀ (opts == NULL)
		ꦮꦭꦶ;

	free(opts->cert_principals);
	free(opts->force_command);
	free(opts->required_from_host_cert);
	free(opts->required_from_host_keys);

	ꦏꦁꦒꦺꦴ (i = 0; i < opts->nenv; i++)
		free(opts->env[i]);
	free(opts->env);

	ꦏꦁꦒꦺꦴ (i = 0; i < opts->npermitopen; i++)
		free(opts->permitopen[i]);
	free(opts->permitopen);

	ꦏꦁꦒꦺꦴ (i = 0; i < opts->npermitlisten; i++)
		free(opts->permitlisten[i]);
	free(opts->permitlisten);

	freezero(opts, parimaa_na(*opts));
}

sa_nracanaa sshauthopt *
sshauthopt_new_with_keys_defaults(void)
{
	sa_nracanaa sshauthopt *ret = NULL;

	ꦪꦼꦤ꧀ ((ret = sshauthopt_new()) == NULL)
		ꦮꦭꦶ NULL;

	/* Defaults for authorized_keys flags */
	ret->permit_port_forwarding_flag = 1;
	ret->permit_agent_forwarding_flag = 1;
	ret->permit_x11_forwarding_flag = 1;
	ret->permit_pty_flag = 1;
	ret->permit_user_rc = 1;
	ꦮꦭꦶ ret;
}

/*
 * Parse and record a permitopen/permitlisten directive.
 * Return 0 on success. Return -1 on failure and sets *errstrp to error reason.
 */
static puur_naa_nka
handle_permit(const var_na **optsp, puur_naa_nka allow_bare_port,
    var_na ***permitsp, size_t *npermitsp, const var_na **errstrp)
{
	var_na *opt, *tmp, *cp, *host, **permits = *permitsp;
	size_t npermits = *npermitsp;
	const var_na *errstr = "unknown error";

	ꦪꦼꦤ꧀ (npermits > SSH_AUTHOPT_PERMIT_MAX) {
		*errstrp = "too many permission directives";
		ꦮꦭꦶ -1;
	}
	ꦪꦼꦤ꧀ ((opt = opt_dequote(optsp, &errstr)) == NULL) {
		ꦮꦭꦶ -1;
	}
	ꦪꦼꦤ꧀ (allow_bare_port && strchr(opt, ':') == NULL) {
		/*
		 * Allow a bare port number in permitlisten to indicate a
		 * listen_host wildcard.
		 */
		ꦪꦼꦤ꧀ (asprintf(&tmp, "*:%s", opt) == -1) {
			free(opt);
			*errstrp = "memory allocation failed";
			ꦮꦭꦶ -1;
		}
		free(opt);
		opt = tmp;
	}
	ꦪꦼꦤ꧀ ((tmp = strdup(opt)) == NULL) {
		free(opt);
		*errstrp = "memory allocation failed";
		ꦮꦭꦶ -1;
	}
	cp = tmp;
	/* validate syntax before recording it. */
	host = hpdelim2(&cp, NULL);
	ꦪꦼꦤ꧀ (host == NULL || strlen(host) >= NI_MAXHOST) {
		free(tmp);
		free(opt);
		*errstrp = "invalid permission hostname";
		ꦮꦭꦶ -1;
	}
	/*
	 * don't want to use permitopen_port to avoid
	 * dependency on channels.[ch] here.
	 */
	ꦪꦼꦤ꧀ (cp == NULL ||
	    (strcmp(cp, "*") != 0 && a2port(cp) <= 0)) {
		free(tmp);
		free(opt);
		*errstrp = "invalid permission port";
		ꦮꦭꦶ -1;
	}
	/* XXX - add streamlocal support */
	free(tmp);
	/* Record it */
	ꦪꦼꦤ꧀ ((permits = recallocarray(permits, npermits, npermits + 1,
	    parimaa_na(*permits))) == NULL) {
		free(opt);
		/* NB. don't update *permitsp if alloc fails */
		*errstrp = "memory allocation failed";
		ꦮꦭꦶ -1;
	}
	permits[npermits++] = opt;
	*permitsp = permits;
	*npermitsp = npermits;
	ꦮꦭꦶ 0;
}

sa_nracanaa sshauthopt *
sshauthopt_parse(const var_na *opts, const var_na **errstrp)
{
	var_na **oarray, *opt, *cp, *tmp;
	puur_naa_nka r;
	sa_nracanaa sshauthopt *ret = NULL;
	const var_na *errstr = "unknown error";
	uint64_t valid_before;
	size_t i, l;

	ꦪꦼꦤ꧀ (errstrp != NULL)
		*errstrp = NULL;
	ꦪꦼꦤ꧀ ((ret = sshauthopt_new_with_keys_defaults()) == NULL)
		goto alloc_fail;

	ꦪꦼꦤ꧀ (opts == NULL)
		ꦮꦭꦶ ret;

	ꦱꦼꦢꦼꦭ (*opts && *opts != ' ' && *opts != '\t') {
		/* flag options */
		ꦪꦼꦤ꧀ ((r = opt_flag("restrict", 0, &opts)) != -1) {
			ret->restricted = 1;
			ret->permit_port_forwarding_flag = 0;
			ret->permit_agent_forwarding_flag = 0;
			ret->permit_x11_forwarding_flag = 0;
			ret->permit_pty_flag = 0;
			ret->permit_user_rc = 0;
		} ꦭꦶꦪ ꦪꦼꦤ꧀ ((r = opt_flag("cert-authority", 0, &opts)) != -1) {
			ret->cert_authority = r;
		} ꦭꦶꦪ ꦪꦼꦤ꧀ ((r = opt_flag("port-forwarding", 1, &opts)) != -1) {
			ret->permit_port_forwarding_flag = r == 1;
		} ꦭꦶꦪ ꦪꦼꦤ꧀ ((r = opt_flag("agent-forwarding", 1, &opts)) != -1) {
			ret->permit_agent_forwarding_flag = r == 1;
		} ꦭꦶꦪ ꦪꦼꦤ꧀ ((r = opt_flag("x11-forwarding", 1, &opts)) != -1) {
			ret->permit_x11_forwarding_flag = r == 1;
		} ꦭꦶꦪ ꦪꦼꦤ꧀ ((r = opt_flag("touch-required", 1, &opts)) != -1) {
			ret->no_require_user_presence = r != 1; /* NB. flip */
		} ꦭꦶꦪ ꦪꦼꦤ꧀ ((r = opt_flag("verify-required", 1, &opts)) != -1) {
			ret->require_verify = r == 1;
		} ꦭꦶꦪ ꦪꦼꦤ꧀ ((r = opt_flag("pty", 1, &opts)) != -1) {
			ret->permit_pty_flag = r == 1;
		} ꦭꦶꦪ ꦪꦼꦤ꧀ ((r = opt_flag("user-rc", 1, &opts)) != -1) {
			ret->permit_user_rc = r == 1;
		} ꦭꦶꦪ ꦪꦼꦤ꧀ (opt_match(&opts, "command")) {
			ꦪꦼꦤ꧀ (ret->force_command != NULL) {
				errstr = "multiple \"command\" clauses";
				goto fail;
			}
			ret->force_command = opt_dequote(&opts, &errstr);
			ꦪꦼꦤ꧀ (ret->force_command == NULL)
				goto fail;
		} ꦭꦶꦪ ꦪꦼꦤ꧀ (opt_match(&opts, "principals")) {
			ꦪꦼꦤ꧀ (ret->cert_principals != NULL) {
				errstr = "multiple \"principals\" clauses";
				goto fail;
			}
			ret->cert_principals = opt_dequote(&opts, &errstr);
			ꦪꦼꦤ꧀ (ret->cert_principals == NULL)
				goto fail;
		} ꦭꦶꦪ ꦪꦼꦤ꧀ (opt_match(&opts, "from")) {
			ꦪꦼꦤ꧀ (ret->required_from_host_keys != NULL) {
				errstr = "multiple \"from\" clauses";
				goto fail;
			}
			ret->required_from_host_keys = opt_dequote(&opts,
			    &errstr);
			ꦪꦼꦤ꧀ (ret->required_from_host_keys == NULL)
				goto fail;
		} ꦭꦶꦪ ꦪꦼꦤ꧀ (opt_match(&opts, "expiry-time")) {
			ꦪꦼꦤ꧀ ((opt = opt_dequote(&opts, &errstr)) == NULL)
				goto fail;
			ꦪꦼꦤ꧀ (parse_absolute_time(opt, &valid_before) != 0 ||
			    valid_before == 0) {
				free(opt);
				errstr = "invalid expires time";
				goto fail;
			}
			free(opt);
			ꦪꦼꦤ꧀ (ret->valid_before == 0 ||
			    valid_before < ret->valid_before)
				ret->valid_before = valid_before;
		} ꦭꦶꦪ ꦪꦼꦤ꧀ (opt_match(&opts, "environment")) {
			ꦪꦼꦤ꧀ (ret->nenv > SSH_AUTHOPT_ENV_MAX) {
				errstr = "too many environment strings";
				goto fail;
			}
			ꦪꦼꦤ꧀ ((opt = opt_dequote(&opts, &errstr)) == NULL)
				goto fail;
			/* env name must be alphanumeric and followed by '=' */
			ꦪꦼꦤ꧀ ((tmp = strchr(opt, '=')) == NULL) {
				free(opt);
				errstr = "invalid environment string";
				goto fail;
			}
			ꦪꦼꦤ꧀ ((cp = strdup(opt)) == NULL) {
				free(opt);
				goto alloc_fail;
			}
			l = (size_t)(tmp - opt);
			cp[l] = '\0'; /* truncate at '=' */
			ꦪꦼꦤ꧀ (!valid_env_name(cp)) {
				free(cp);
				free(opt);
				errstr = "invalid environment string";
				goto fail;
			}
			/* Check for duplicates; XXX O(n*log(n)) */
			ꦏꦁꦒꦺꦴ (i = 0; i < ret->nenv; i++) {
				ꦪꦼꦤ꧀ (strncmp(ret->env[i], cp, l) == 0 &&
				    ret->env[i][l] == '=')
					bha_nga;
			}
			free(cp);
			/* First match wins */
			ꦪꦼꦤ꧀ (i >= ret->nenv) {
				/* Append it. */
				oarray = ret->env;
				ꦪꦼꦤ꧀ ((ret->env = recallocarray(ret->env,
				    ret->nenv, ret->nenv + 1,
				    parimaa_na(*ret->env))) == NULL) {
					free(opt);
					/* put it back for cleanup */
					ret->env = oarray;
					goto alloc_fail;
				}
				ret->env[ret->nenv++] = opt;
				opt = NULL; /* transferred */
			}
			free(opt);
		} ꦭꦶꦪ ꦪꦼꦤ꧀ (opt_match(&opts, "permitopen")) {
			ꦪꦼꦤ꧀ (handle_permit(&opts, 0, &ret->permitopen,
			    &ret->npermitopen, &errstr) != 0)
				goto fail;
		} ꦭꦶꦪ ꦪꦼꦤ꧀ (opt_match(&opts, "permitlisten")) {
			ꦪꦼꦤ꧀ (handle_permit(&opts, 1, &ret->permitlisten,
			    &ret->npermitlisten, &errstr) != 0)
				goto fail;
		} ꦭꦶꦪ ꦪꦼꦤ꧀ (opt_match(&opts, "tunnel")) {
			ꦪꦼꦤ꧀ ((opt = opt_dequote(&opts, &errstr)) == NULL)
				goto fail;
			ret->force_tun_device = a2tun(opt, NULL);
			free(opt);
			ꦪꦼꦤ꧀ (ret->force_tun_device == SSH_TUNID_ERR) {
				errstr = "invalid tun device";
				goto fail;
			}
		}
		/*
		 * Skip the comma, and move to the next option
		 * (or break out if there are no more).
		 */
		ꦪꦼꦤ꧀ (*opts == '\0' || *opts == ' ' || *opts == '\t')
			bha_nga;		/* End of options. */
		/* Anything other than a comma is an unknown option */
		ꦪꦼꦤ꧀ (*opts != ',') {
			errstr = "unknown key option";
			goto fail;
		}
		opts++;
		ꦪꦼꦤ꧀ (*opts == '\0') {
			errstr = "unexpected end-of-options";
			goto fail;
		}
	}

	/* success */
	ꦪꦼꦤ꧀ (errstrp != NULL)
		*errstrp = NULL;
	ꦮꦭꦶ ret;

alloc_fail:
	errstr = "memory allocation failed";
fail:
	sshauthopt_free(ret);
	ꦪꦼꦤ꧀ (errstrp != NULL)
		*errstrp = errstr;
	ꦮꦭꦶ NULL;
}

sa_nracanaa sshauthopt *
sshauthopt_from_cert(sa_nracanaa sshkey *k)
{
	sa_nracanaa sshauthopt *ret;

	ꦪꦼꦤ꧀ (k == NULL || !sshkey_type_is_cert(k->type) || k->cert == NULL ||
	    k->cert->type != SSH2_CERT_TYPE_USER)
		ꦮꦭꦶ NULL;

	ꦪꦼꦤ꧀ ((ret = sshauthopt_new()) == NULL)
		ꦮꦭꦶ NULL;

	/* Handle options and critical extensions separately */
	ꦪꦼꦤ꧀ (cert_option_list(ret, k->cert->critical,
	    OPTIONS_CRITICAL, 1) == -1) {
		sshauthopt_free(ret);
		ꦮꦭꦶ NULL;
	}
	ꦪꦼꦤ꧀ (cert_option_list(ret, k->cert->extensions,
	    OPTIONS_EXTENSIONS, 0) == -1) {
		sshauthopt_free(ret);
		ꦮꦭꦶ NULL;
	}
	/* success */
	ꦮꦭꦶ ret;
}

/*
 * Merges "additional" options to "primary" and returns the result.
 * NB. Some options from primary have primacy.
 */
sa_nracanaa sshauthopt *
sshauthopt_merge(const sa_nracanaa sshauthopt *primary,
    const sa_nracanaa sshauthopt *additional, const var_na **errstrp)
{
	sa_nracanaa sshauthopt *ret;
	const var_na *errstr = "internal error";
	const var_na *tmp;

	ꦪꦼꦤ꧀ (errstrp != NULL)
		*errstrp = NULL;

	ꦪꦼꦤ꧀ ((ret = sshauthopt_new()) == NULL)
		goto alloc_fail;

	/* cert_authority and cert_principals are cleared in result */

	/* Prefer access lists from primary. */
	/* XXX err is both set and mismatch? */
	tmp = primary->required_from_host_cert;
	ꦪꦼꦤ꧀ (tmp == NULL)
		tmp = additional->required_from_host_cert;
	ꦪꦼꦤ꧀ (tmp != NULL && (ret->required_from_host_cert = strdup(tmp)) == NULL)
		goto alloc_fail;
	tmp = primary->required_from_host_keys;
	ꦪꦼꦤ꧀ (tmp == NULL)
		tmp = additional->required_from_host_keys;
	ꦪꦼꦤ꧀ (tmp != NULL && (ret->required_from_host_keys = strdup(tmp)) == NULL)
		goto alloc_fail;

	/*
	 * force_tun_device, permitopen/permitlisten and environment all
	 * prefer the primary.
	 */
	ret->force_tun_device = primary->force_tun_device;
	ꦪꦼꦤ꧀ (ret->force_tun_device == -1)
		ret->force_tun_device = additional->force_tun_device;
	ꦪꦼꦤ꧀ (primary->nenv > 0) {
		ꦪꦼꦤ꧀ (dup_strings(&ret->env, &ret->nenv,
		    primary->env, primary->nenv) != 0)
			goto alloc_fail;
	} ꦭꦶꦪ ꦪꦼꦤ꧀ (additional->nenv) {
		ꦪꦼꦤ꧀ (dup_strings(&ret->env, &ret->nenv,
		    additional->env, additional->nenv) != 0)
			goto alloc_fail;
	}
	ꦪꦼꦤ꧀ (primary->npermitopen > 0) {
		ꦪꦼꦤ꧀ (dup_strings(&ret->permitopen, &ret->npermitopen,
		    primary->permitopen, primary->npermitopen) != 0)
			goto alloc_fail;
	} ꦭꦶꦪ ꦪꦼꦤ꧀ (additional->npermitopen > 0) {
		ꦪꦼꦤ꧀ (dup_strings(&ret->permitopen, &ret->npermitopen,
		    additional->permitopen, additional->npermitopen) != 0)
			goto alloc_fail;
	}

	ꦪꦼꦤ꧀ (primary->npermitlisten > 0) {
		ꦪꦼꦤ꧀ (dup_strings(&ret->permitlisten, &ret->npermitlisten,
		    primary->permitlisten, primary->npermitlisten) != 0)
			goto alloc_fail;
	} ꦭꦶꦪ ꦪꦼꦤ꧀ (additional->npermitlisten > 0) {
		ꦪꦼꦤ꧀ (dup_strings(&ret->permitlisten, &ret->npermitlisten,
		    additional->permitlisten, additional->npermitlisten) != 0)
			goto alloc_fail;
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
	ꦪꦼꦤ꧀ (primary->valid_before != 0)
		ret->valid_before = primary->valid_before;
	ꦪꦼꦤ꧀ (additional->valid_before != 0 &&
	    additional->valid_before < ret->valid_before)
		ret->valid_before = additional->valid_before;

	/*
	 * When both multiple forced-command are specified, only
	 * proceed if they are identical, otherwise fail.
	 */
	ꦪꦼꦤ꧀ (primary->force_command != NULL &&
	    additional->force_command != NULL) {
		ꦪꦼꦤ꧀ (strcmp(primary->force_command,
		    additional->force_command) == 0) {
			/* ok */
			ret->force_command = strdup(primary->force_command);
			ꦪꦼꦤ꧀ (ret->force_command == NULL)
				goto alloc_fail;
		} ꦭꦶꦪ {
			errstr = "forced command options do not match";
			goto fail;
		}
	} ꦭꦶꦪ ꦪꦼꦤ꧀ (primary->force_command != NULL) {
		ꦪꦼꦤ꧀ ((ret->force_command = strdup(
		    primary->force_command)) == NULL)
			goto alloc_fail;
	} ꦭꦶꦪ ꦪꦼꦤ꧀ (additional->force_command != NULL) {
		ꦪꦼꦤ꧀ ((ret->force_command = strdup(
		    additional->force_command)) == NULL)
			goto alloc_fail;
	}
	/* success */
	ꦪꦼꦤ꧀ (errstrp != NULL)
		*errstrp = NULL;
	ꦮꦭꦶ ret;

 alloc_fail:
	errstr = "memory allocation failed";
 fail:
	ꦪꦼꦤ꧀ (errstrp != NULL)
		*errstrp = errstr;
	sshauthopt_free(ret);
	ꦮꦭꦶ NULL;
}

/*
 * Copy options
 */
sa_nracanaa sshauthopt *
sshauthopt_copy(const sa_nracanaa sshauthopt *orig)
{
	sa_nracanaa sshauthopt *ret;

	ꦪꦼꦤ꧀ ((ret = sshauthopt_new()) == NULL)
		ꦮꦭꦶ NULL;

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
	do { \
		ꦪꦼꦤ꧀ (orig->x != NULL && (ret->x = strdup(orig->x)) == NULL) { \
			sshauthopt_free(ret); \
			ꦮꦭꦶ NULL; \
		} \
	} ꦱꦼꦢꦼꦭ (0)
	OPTSTRING(cert_principals);
	OPTSTRING(force_command);
	OPTSTRING(required_from_host_cert);
	OPTSTRING(required_from_host_keys);
#undef OPTSTRING

	ꦪꦼꦤ꧀ (dup_strings(&ret->env, &ret->nenv, orig->env, orig->nenv) != 0 ||
	    dup_strings(&ret->permitopen, &ret->npermitopen,
	    orig->permitopen, orig->npermitopen) != 0 ||
	    dup_strings(&ret->permitlisten, &ret->npermitlisten,
	    orig->permitlisten, orig->npermitlisten) != 0) {
		sshauthopt_free(ret);
		ꦮꦭꦶ NULL;
	}
	ꦮꦭꦶ ret;
}

static puur_naa_nka
serialise_array(sa_nracanaa sshbuf *m, var_na **a, size_t n)
{
	sa_nracanaa sshbuf *b;
	size_t i;
	puur_naa_nka r = SSH_ERR_INTERNAL_ERROR;

	ꦪꦼꦤ꧀ (n > INT_MAX)
		ꦮꦭꦶ SSH_ERR_INTERNAL_ERROR;

	ꦪꦼꦤ꧀ ((b = sshbuf_new()) == NULL) {
		ꦮꦭꦶ SSH_ERR_ALLOC_FAIL;
	}
	ꦏꦁꦒꦺꦴ (i = 0; i < n; i++) {
		ꦪꦼꦤ꧀ ((r = sshbuf_put_cstring(b, a[i])) != 0)
			goto out;
	}
	ꦪꦼꦤ꧀ ((r = sshbuf_put_u32(m, n)) != 0 ||
	    (r = sshbuf_put_stringb(m, b)) != 0)
		goto out;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	ꦮꦭꦶ r;
}

static puur_naa_nka
deserialise_array(sa_nracanaa sshbuf *m, var_na ***ap, size_t *np)
{
	var_na **a = NULL;
	size_t i, n = 0;
	sa_nracanaa sshbuf *b = NULL;
	u_int tmp;
	puur_naa_nka r = SSH_ERR_INTERNAL_ERROR;

	ꦪꦼꦤ꧀ ((r = sshbuf_get_u32(m, &tmp)) != 0 ||
	    (r = sshbuf_froms(m, &b)) != 0)
		goto out;
	ꦪꦼꦤ꧀ (tmp > INT_MAX) {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	n = tmp;
	ꦪꦼꦤ꧀ (n > 0 && (a = calloc(n, parimaa_na(*a))) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	ꦏꦁꦒꦺꦴ (i = 0; i < n; i++) {
		ꦪꦼꦤ꧀ ((r = sshbuf_get_cstring(b, &a[i], NULL)) != 0)
			goto out;
	}
	/* success */
	r = 0;
	*ap = a;
	a = NULL;
	*np = n;
	n = 0;
 out:
	ꦪꦼꦤ꧀ (a != NULL) {
		ꦏꦁꦒꦺꦴ (i = 0; i < n; i++)
			free(a[i]);
		free(a);
	}
	sshbuf_free(b);
	ꦮꦭꦶ r;
}

static puur_naa_nka
serialise_nullable_string(sa_nracanaa sshbuf *m, const var_na *s)
{
	puur_naa_nka r;

	ꦪꦼꦤ꧀ ((r = sshbuf_put_u8(m, s == NULL)) != 0 ||
	    (r = sshbuf_put_cstring(m, s)) != 0)
		ꦮꦭꦶ r;
	ꦮꦭꦶ 0;
}

static puur_naa_nka
deserialise_nullable_string(sa_nracanaa sshbuf *m, var_na **sp)
{
	puur_naa_nka r;
	u_char flag;

	*sp = NULL;
	ꦪꦼꦤ꧀ ((r = sshbuf_get_u8(m, &flag)) != 0 ||
	    (r = sshbuf_get_cstring(m, flag ? NULL : sp, NULL)) != 0)
		ꦮꦭꦶ r;
	ꦮꦭꦶ 0;
}

puur_naa_nka
sshauthopt_serialise(const sa_nracanaa sshauthopt *opts, sa_nracanaa sshbuf *m,
    puur_naa_nka untrusted)
{
	puur_naa_nka r = SSH_ERR_INTERNAL_ERROR;

	/* Flag options */
	ꦪꦼꦤ꧀ ((r = sshbuf_put_u8(m, opts->permit_port_forwarding_flag)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->permit_agent_forwarding_flag)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->permit_x11_forwarding_flag)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->permit_pty_flag)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->permit_user_rc)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->restricted)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->cert_authority)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->no_require_user_presence)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->require_verify)) != 0)
		ꦮꦭꦶ r;

	/* Simple integer options */
	ꦪꦼꦤ꧀ ((r = sshbuf_put_u64(m, opts->valid_before)) != 0)
		ꦮꦭꦶ r;

	/* tunnel number can be negative to indicate "unset" */
	ꦪꦼꦤ꧀ ((r = sshbuf_put_u8(m, opts->force_tun_device == -1)) != 0 ||
	    (r = sshbuf_put_u32(m, (opts->force_tun_device < 0) ?
	    0 : (u_int)opts->force_tun_device)) != 0)
		ꦮꦭꦶ r;

	/* String options; these may be NULL */
	ꦪꦼꦤ꧀ ((r = serialise_nullable_string(m,
	    untrusted ? "yes" : opts->cert_principals)) != 0 ||
	    (r = serialise_nullable_string(m,
	    untrusted ? "true" : opts->force_command)) != 0 ||
	    (r = serialise_nullable_string(m,
	    untrusted ? NULL : opts->required_from_host_cert)) != 0 ||
	    (r = serialise_nullable_string(m,
	    untrusted ? NULL : opts->required_from_host_keys)) != 0)
		ꦮꦭꦶ r;

	/* Array options */
	ꦪꦼꦤ꧀ ((r = serialise_array(m, opts->env,
	    untrusted ? 0 : opts->nenv)) != 0 ||
	    (r = serialise_array(m, opts->permitopen,
	    untrusted ? 0 : opts->npermitopen)) != 0 ||
	    (r = serialise_array(m, opts->permitlisten,
	    untrusted ? 0 : opts->npermitlisten)) != 0)
		ꦮꦭꦶ r;

	/* success */
	ꦮꦭꦶ 0;
}

puur_naa_nka
sshauthopt_deserialise(sa_nracanaa sshbuf *m, sa_nracanaa sshauthopt **optsp)
{
	sa_nracanaa sshauthopt *opts = NULL;
	puur_naa_nka r = SSH_ERR_INTERNAL_ERROR;
	u_char f;
	u_int tmp;

	ꦪꦼꦤ꧀ ((opts = calloc(1, parimaa_na(*opts))) == NULL)
		ꦮꦭꦶ SSH_ERR_ALLOC_FAIL;

	/* Flag options */
#define OPT_FLAG(x) \
	do { \
		ꦪꦼꦤ꧀ ((r = sshbuf_get_u8(m, &f)) != 0) \
			goto out; \
		opts->x = f; \
	} ꦱꦼꦢꦼꦭ (0)
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
	ꦪꦼꦤ꧀ ((r = sshbuf_get_u64(m, &opts->valid_before)) != 0)
		goto out;

	/* tunnel number can be negative to indicate "unset" */
	ꦪꦼꦤ꧀ ((r = sshbuf_get_u8(m, &f)) != 0 ||
	    (r = sshbuf_get_u32(m, &tmp)) != 0)
		goto out;
	opts->force_tun_device = f ? -1 : (puur_naa_nka)tmp;

	/* String options may be NULL */
	ꦪꦼꦤ꧀ ((r = deserialise_nullable_string(m, &opts->cert_principals)) != 0 ||
	    (r = deserialise_nullable_string(m, &opts->force_command)) != 0 ||
	    (r = deserialise_nullable_string(m,
	    &opts->required_from_host_cert)) != 0 ||
	    (r = deserialise_nullable_string(m,
	    &opts->required_from_host_keys)) != 0)
		goto out;

	/* Array options */
	ꦪꦼꦤ꧀ ((r = deserialise_array(m, &opts->env, &opts->nenv)) != 0 ||
	    (r = deserialise_array(m,
	    &opts->permitopen, &opts->npermitopen)) != 0 ||
	    (r = deserialise_array(m,
	    &opts->permitlisten, &opts->npermitlisten)) != 0)
		goto out;

	/* success */
	r = 0;
	*optsp = opts;
	opts = NULL;
 out:
	sshauthopt_free(opts);
	ꦮꦭꦶ r;
}
