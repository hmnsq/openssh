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

static 整数
dup_strings(char ***dstp, size_t *ndstp, char **src, size_t nsrc)
{
	char **dst;
	size_t i, j;

	*dstp = NULL;
	*ndstp = 0;

	如果 (nsrc == 0)
		返回 0;
	如果 (nsrc >= SIZE_MAX / sizeof(*src) ||
	    (dst = calloc(nsrc, sizeof(*src))) == NULL)
		返回 -1;
	为 (i = 0; i < nsrc; i++) {
		如果 ((dst[i] = strdup(src[i])) == NULL) {
			为 (j = 0; j < i; j++)
				free(dst[j]);
			free(dst);
			返回 -1;
		}
	}
	/* success */
	*dstp = dst;
	*ndstp = nsrc;
	返回 0;
}

#define OPTIONS_CRITICAL	1
#define OPTIONS_EXTENSIONS	2
static 整数
cert_option_list(struct sshauthopt *opts, struct sshbuf *oblob,
    u_int which, 整数 crit)
{
	char *command, *allowed;
	char *name = NULL;
	struct sshbuf *c = NULL, *data = NULL;
	整数 r, ret = -1, found;

	如果 ((c = sshbuf_fromb(oblob)) == NULL) {
		error_f("sshbuf_fromb failed");
		goto out;
	}

	当 (sshbuf_len(c) > 0) {
		sshbuf_free(data);
		data = NULL;
		如果 ((r = sshbuf_get_cstring(c, &name, NULL)) != 0 ||
		    (r = sshbuf_froms(c, &data)) != 0) {
			error_r(r, "Unable to parse certificate options");
			goto out;
		}
		debug3("found certificate option \"%.100s\" len %zu",
		    name, sshbuf_len(data));
		found = 0;
		如果 ((which & OPTIONS_EXTENSIONS) != 0) {
			如果 (strcmp(name, "no-touch-required") == 0) {
				opts->no_require_user_presence = 1;
				found = 1;
			} 否则 如果 (strcmp(name, "permit-X11-forwarding") == 0) {
				opts->permit_x11_forwarding_flag = 1;
				found = 1;
			} 否则 如果 (strcmp(name,
			    "permit-agent-forwarding") == 0) {
				opts->permit_agent_forwarding_flag = 1;
				found = 1;
			} 否则 如果 (strcmp(name,
			    "permit-port-forwarding") == 0) {
				opts->permit_port_forwarding_flag = 1;
				found = 1;
			} 否则 如果 (strcmp(name, "permit-pty") == 0) {
				opts->permit_pty_flag = 1;
				found = 1;
			} 否则 如果 (strcmp(name, "permit-user-rc") == 0) {
				opts->permit_user_rc = 1;
				found = 1;
			}
		}
		如果 (!found && (which & OPTIONS_CRITICAL) != 0) {
			如果 (strcmp(name, "verify-required") == 0) {
				opts->require_verify = 1;
				found = 1;
			} 否则 如果 (strcmp(name, "force-command") == 0) {
				如果 ((r = sshbuf_get_cstring(data, &command,
				    NULL)) != 0) {
					error_r(r, "Unable to parse \"%s\" "
					    "section", name);
					goto out;
				}
				如果 (opts->force_command != NULL) {
					error("Certificate has multiple "
					    "force-command options");
					free(command);
					goto out;
				}
				opts->force_command = command;
				found = 1;
			} 否则 如果 (strcmp(name, "source-address") == 0) {
				如果 ((r = sshbuf_get_cstring(data, &allowed,
				    NULL)) != 0) {
					error_r(r, "Unable to parse \"%s\" "
					    "section", name);
					goto out;
				}
				如果 (opts->required_from_host_cert != NULL) {
					error("Certificate has multiple "
					    "source-address options");
					free(allowed);
					goto out;
				}
				/* Check syntax */
				如果 (addr_match_cidr_list(NULL, allowed) == -1) {
					error("Certificate source-address "
					    "contents invalid");
					free(allowed);
					goto out;
				}
				opts->required_from_host_cert = allowed;
				found = 1;
			}
		}

		如果 (!found) {
			如果 (crit) {
				error("Certificate critical option \"%s\" "
				    "is not supported", name);
				goto out;
			} 否则 {
				logit("Certificate extension \"%s\" "
				    "is not supported", name);
			}
		} 否则 如果 (sshbuf_len(data) != 0) {
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
	返回 ret;
}

struct sshauthopt *
sshauthopt_new(void)
{
	struct sshauthopt *ret;

	如果 ((ret = calloc(1, sizeof(*ret))) == NULL)
		返回 NULL;
	ret->force_tun_device = -1;
	返回 ret;
}

void
sshauthopt_free(struct sshauthopt *opts)
{
	size_t i;

	如果 (opts == NULL)
		返回;

	free(opts->cert_principals);
	free(opts->force_command);
	free(opts->required_from_host_cert);
	free(opts->required_from_host_keys);

	为 (i = 0; i < opts->nenv; i++)
		free(opts->env[i]);
	free(opts->env);

	为 (i = 0; i < opts->npermitopen; i++)
		free(opts->permitopen[i]);
	free(opts->permitopen);

	为 (i = 0; i < opts->npermitlisten; i++)
		free(opts->permitlisten[i]);
	free(opts->permitlisten);

	freezero(opts, sizeof(*opts));
}

struct sshauthopt *
sshauthopt_new_with_keys_defaults(void)
{
	struct sshauthopt *ret = NULL;

	如果 ((ret = sshauthopt_new()) == NULL)
		返回 NULL;

	/* Defaults for authorized_keys flags */
	ret->permit_port_forwarding_flag = 1;
	ret->permit_agent_forwarding_flag = 1;
	ret->permit_x11_forwarding_flag = 1;
	ret->permit_pty_flag = 1;
	ret->permit_user_rc = 1;
	返回 ret;
}

/*
 * Parse and record a permitopen/permitlisten directive.
 * Return 0 on success. Return -1 on failure and sets *errstrp to error reason.
 */
static 整数
handle_permit(const char **optsp, 整数 allow_bare_port,
    char ***permitsp, size_t *npermitsp, const char **errstrp)
{
	char *opt, *tmp, *cp, *host, **permits = *permitsp;
	size_t npermits = *npermitsp;
	const char *errstr = "unknown error";

	如果 (npermits > SSH_AUTHOPT_PERMIT_MAX) {
		*errstrp = "too many permission directives";
		返回 -1;
	}
	如果 ((opt = opt_dequote(optsp, &errstr)) == NULL) {
		返回 -1;
	}
	如果 (allow_bare_port && strchr(opt, ':') == NULL) {
		/*
		 * Allow a bare port number in permitlisten to indicate a
		 * listen_host wildcard.
		 */
		如果 (asprintf(&tmp, "*:%s", opt) == -1) {
			free(opt);
			*errstrp = "memory allocation failed";
			返回 -1;
		}
		free(opt);
		opt = tmp;
	}
	如果 ((tmp = strdup(opt)) == NULL) {
		free(opt);
		*errstrp = "memory allocation failed";
		返回 -1;
	}
	cp = tmp;
	/* validate syntax before recording it. */
	host = hpdelim2(&cp, NULL);
	如果 (host == NULL || strlen(host) >= NI_MAXHOST) {
		free(tmp);
		free(opt);
		*errstrp = "invalid permission hostname";
		返回 -1;
	}
	/*
	 * don't want to use permitopen_port to avoid
	 * dependency on channels.[ch] here.
	 */
	如果 (cp == NULL ||
	    (strcmp(cp, "*") != 0 && a2port(cp) <= 0)) {
		free(tmp);
		free(opt);
		*errstrp = "invalid permission port";
		返回 -1;
	}
	/* XXX - add streamlocal support */
	free(tmp);
	/* Record it */
	如果 ((permits = recallocarray(permits, npermits, npermits + 1,
	    sizeof(*permits))) == NULL) {
		free(opt);
		/* NB. don't update *permitsp if alloc fails */
		*errstrp = "memory allocation failed";
		返回 -1;
	}
	permits[npermits++] = opt;
	*permitsp = permits;
	*npermitsp = npermits;
	返回 0;
}

struct sshauthopt *
sshauthopt_parse(const char *opts, const char **errstrp)
{
	char **oarray, *opt, *cp, *tmp;
	整数 r;
	struct sshauthopt *ret = NULL;
	const char *errstr = "unknown error";
	uint64_t valid_before;
	size_t i, l;

	如果 (errstrp != NULL)
		*errstrp = NULL;
	如果 ((ret = sshauthopt_new_with_keys_defaults()) == NULL)
		goto alloc_fail;

	如果 (opts == NULL)
		返回 ret;

	当 (*opts && *opts != ' ' && *opts != '\t') {
		/* flag options */
		如果 ((r = opt_flag("restrict", 0, &opts)) != -1) {
			ret->restricted = 1;
			ret->permit_port_forwarding_flag = 0;
			ret->permit_agent_forwarding_flag = 0;
			ret->permit_x11_forwarding_flag = 0;
			ret->permit_pty_flag = 0;
			ret->permit_user_rc = 0;
		} 否则 如果 ((r = opt_flag("cert-authority", 0, &opts)) != -1) {
			ret->cert_authority = r;
		} 否则 如果 ((r = opt_flag("port-forwarding", 1, &opts)) != -1) {
			ret->permit_port_forwarding_flag = r == 1;
		} 否则 如果 ((r = opt_flag("agent-forwarding", 1, &opts)) != -1) {
			ret->permit_agent_forwarding_flag = r == 1;
		} 否则 如果 ((r = opt_flag("x11-forwarding", 1, &opts)) != -1) {
			ret->permit_x11_forwarding_flag = r == 1;
		} 否则 如果 ((r = opt_flag("touch-required", 1, &opts)) != -1) {
			ret->no_require_user_presence = r != 1; /* NB. flip */
		} 否则 如果 ((r = opt_flag("verify-required", 1, &opts)) != -1) {
			ret->require_verify = r == 1;
		} 否则 如果 ((r = opt_flag("pty", 1, &opts)) != -1) {
			ret->permit_pty_flag = r == 1;
		} 否则 如果 ((r = opt_flag("user-rc", 1, &opts)) != -1) {
			ret->permit_user_rc = r == 1;
		} 否则 如果 (opt_match(&opts, "command")) {
			如果 (ret->force_command != NULL) {
				errstr = "multiple \"command\" clauses";
				goto fail;
			}
			ret->force_command = opt_dequote(&opts, &errstr);
			如果 (ret->force_command == NULL)
				goto fail;
		} 否则 如果 (opt_match(&opts, "principals")) {
			如果 (ret->cert_principals != NULL) {
				errstr = "multiple \"principals\" clauses";
				goto fail;
			}
			ret->cert_principals = opt_dequote(&opts, &errstr);
			如果 (ret->cert_principals == NULL)
				goto fail;
		} 否则 如果 (opt_match(&opts, "from")) {
			如果 (ret->required_from_host_keys != NULL) {
				errstr = "multiple \"from\" clauses";
				goto fail;
			}
			ret->required_from_host_keys = opt_dequote(&opts,
			    &errstr);
			如果 (ret->required_from_host_keys == NULL)
				goto fail;
		} 否则 如果 (opt_match(&opts, "expiry-time")) {
			如果 ((opt = opt_dequote(&opts, &errstr)) == NULL)
				goto fail;
			如果 (parse_absolute_time(opt, &valid_before) != 0 ||
			    valid_before == 0) {
				free(opt);
				errstr = "invalid expires time";
				goto fail;
			}
			free(opt);
			如果 (ret->valid_before == 0 ||
			    valid_before < ret->valid_before)
				ret->valid_before = valid_before;
		} 否则 如果 (opt_match(&opts, "environment")) {
			如果 (ret->nenv > SSH_AUTHOPT_ENV_MAX) {
				errstr = "too many environment strings";
				goto fail;
			}
			如果 ((opt = opt_dequote(&opts, &errstr)) == NULL)
				goto fail;
			/* env name must be alphanumeric and followed by '=' */
			如果 ((tmp = strchr(opt, '=')) == NULL) {
				free(opt);
				errstr = "invalid environment string";
				goto fail;
			}
			如果 ((cp = strdup(opt)) == NULL) {
				free(opt);
				goto alloc_fail;
			}
			l = (size_t)(tmp - opt);
			cp[l] = '\0'; /* truncate at '=' */
			如果 (!valid_env_name(cp)) {
				free(cp);
				free(opt);
				errstr = "invalid environment string";
				goto fail;
			}
			/* Check for duplicates; XXX O(n*log(n)) */
			为 (i = 0; i < ret->nenv; i++) {
				如果 (strncmp(ret->env[i], cp, l) == 0 &&
				    ret->env[i][l] == '=')
					break;
			}
			free(cp);
			/* First match wins */
			如果 (i >= ret->nenv) {
				/* Append it. */
				oarray = ret->env;
				如果 ((ret->env = recallocarray(ret->env,
				    ret->nenv, ret->nenv + 1,
				    sizeof(*ret->env))) == NULL) {
					free(opt);
					/* put it back for cleanup */
					ret->env = oarray;
					goto alloc_fail;
				}
				ret->env[ret->nenv++] = opt;
				opt = NULL; /* transferred */
			}
			free(opt);
		} 否则 如果 (opt_match(&opts, "permitopen")) {
			如果 (handle_permit(&opts, 0, &ret->permitopen,
			    &ret->npermitopen, &errstr) != 0)
				goto fail;
		} 否则 如果 (opt_match(&opts, "permitlisten")) {
			如果 (handle_permit(&opts, 1, &ret->permitlisten,
			    &ret->npermitlisten, &errstr) != 0)
				goto fail;
		} 否则 如果 (opt_match(&opts, "tunnel")) {
			如果 ((opt = opt_dequote(&opts, &errstr)) == NULL)
				goto fail;
			ret->force_tun_device = a2tun(opt, NULL);
			free(opt);
			如果 (ret->force_tun_device == SSH_TUNID_ERR) {
				errstr = "invalid tun device";
				goto fail;
			}
		}
		/*
		 * Skip the comma, and move to the next option
		 * (or break out if there are no more).
		 */
		如果 (*opts == '\0' || *opts == ' ' || *opts == '\t')
			break;		/* End of options. */
		/* Anything other than a comma is an unknown option */
		如果 (*opts != ',') {
			errstr = "unknown key option";
			goto fail;
		}
		opts++;
		如果 (*opts == '\0') {
			errstr = "unexpected end-of-options";
			goto fail;
		}
	}

	/* success */
	如果 (errstrp != NULL)
		*errstrp = NULL;
	返回 ret;

alloc_fail:
	errstr = "memory allocation failed";
fail:
	sshauthopt_free(ret);
	如果 (errstrp != NULL)
		*errstrp = errstr;
	返回 NULL;
}

struct sshauthopt *
sshauthopt_from_cert(struct sshkey *k)
{
	struct sshauthopt *ret;

	如果 (k == NULL || !sshkey_type_is_cert(k->type) || k->cert == NULL ||
	    k->cert->type != SSH2_CERT_TYPE_USER)
		返回 NULL;

	如果 ((ret = sshauthopt_new()) == NULL)
		返回 NULL;

	/* Handle options and critical extensions separately */
	如果 (cert_option_list(ret, k->cert->critical,
	    OPTIONS_CRITICAL, 1) == -1) {
		sshauthopt_free(ret);
		返回 NULL;
	}
	如果 (cert_option_list(ret, k->cert->extensions,
	    OPTIONS_EXTENSIONS, 0) == -1) {
		sshauthopt_free(ret);
		返回 NULL;
	}
	/* success */
	返回 ret;
}

/*
 * Merges "additional" options to "primary" and returns the result.
 * NB. Some options from primary have primacy.
 */
struct sshauthopt *
sshauthopt_merge(const struct sshauthopt *primary,
    const struct sshauthopt *additional, const char **errstrp)
{
	struct sshauthopt *ret;
	const char *errstr = "internal error";
	const char *tmp;

	如果 (errstrp != NULL)
		*errstrp = NULL;

	如果 ((ret = sshauthopt_new()) == NULL)
		goto alloc_fail;

	/* cert_authority and cert_principals are cleared in result */

	/* Prefer access lists from primary. */
	/* XXX err is both set and mismatch? */
	tmp = primary->required_from_host_cert;
	如果 (tmp == NULL)
		tmp = additional->required_from_host_cert;
	如果 (tmp != NULL && (ret->required_from_host_cert = strdup(tmp)) == NULL)
		goto alloc_fail;
	tmp = primary->required_from_host_keys;
	如果 (tmp == NULL)
		tmp = additional->required_from_host_keys;
	如果 (tmp != NULL && (ret->required_from_host_keys = strdup(tmp)) == NULL)
		goto alloc_fail;

	/*
	 * force_tun_device, permitopen/permitlisten and environment all
	 * prefer the primary.
	 */
	ret->force_tun_device = primary->force_tun_device;
	如果 (ret->force_tun_device == -1)
		ret->force_tun_device = additional->force_tun_device;
	如果 (primary->nenv > 0) {
		如果 (dup_strings(&ret->env, &ret->nenv,
		    primary->env, primary->nenv) != 0)
			goto alloc_fail;
	} 否则 如果 (additional->nenv) {
		如果 (dup_strings(&ret->env, &ret->nenv,
		    additional->env, additional->nenv) != 0)
			goto alloc_fail;
	}
	如果 (primary->npermitopen > 0) {
		如果 (dup_strings(&ret->permitopen, &ret->npermitopen,
		    primary->permitopen, primary->npermitopen) != 0)
			goto alloc_fail;
	} 否则 如果 (additional->npermitopen > 0) {
		如果 (dup_strings(&ret->permitopen, &ret->npermitopen,
		    additional->permitopen, additional->npermitopen) != 0)
			goto alloc_fail;
	}

	如果 (primary->npermitlisten > 0) {
		如果 (dup_strings(&ret->permitlisten, &ret->npermitlisten,
		    primary->permitlisten, primary->npermitlisten) != 0)
			goto alloc_fail;
	} 否则 如果 (additional->npermitlisten > 0) {
		如果 (dup_strings(&ret->permitlisten, &ret->npermitlisten,
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
	如果 (primary->valid_before != 0)
		ret->valid_before = primary->valid_before;
	如果 (additional->valid_before != 0 &&
	    additional->valid_before < ret->valid_before)
		ret->valid_before = additional->valid_before;

	/*
	 * When both multiple forced-command are specified, only
	 * proceed if they are identical, otherwise fail.
	 */
	如果 (primary->force_command != NULL &&
	    additional->force_command != NULL) {
		如果 (strcmp(primary->force_command,
		    additional->force_command) == 0) {
			/* ok */
			ret->force_command = strdup(primary->force_command);
			如果 (ret->force_command == NULL)
				goto alloc_fail;
		} 否则 {
			errstr = "forced command options do not match";
			goto fail;
		}
	} 否则 如果 (primary->force_command != NULL) {
		如果 ((ret->force_command = strdup(
		    primary->force_command)) == NULL)
			goto alloc_fail;
	} 否则 如果 (additional->force_command != NULL) {
		如果 ((ret->force_command = strdup(
		    additional->force_command)) == NULL)
			goto alloc_fail;
	}
	/* success */
	如果 (errstrp != NULL)
		*errstrp = NULL;
	返回 ret;

 alloc_fail:
	errstr = "memory allocation failed";
 fail:
	如果 (errstrp != NULL)
		*errstrp = errstr;
	sshauthopt_free(ret);
	返回 NULL;
}

/*
 * Copy options
 */
struct sshauthopt *
sshauthopt_copy(const struct sshauthopt *orig)
{
	struct sshauthopt *ret;

	如果 ((ret = sshauthopt_new()) == NULL)
		返回 NULL;

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
		如果 (orig->x != NULL && (ret->x = strdup(orig->x)) == NULL) { \
			sshauthopt_free(ret); \
			返回 NULL; \
		} \
	} 当 (0)
	OPTSTRING(cert_principals);
	OPTSTRING(force_command);
	OPTSTRING(required_from_host_cert);
	OPTSTRING(required_from_host_keys);
#undef OPTSTRING

	如果 (dup_strings(&ret->env, &ret->nenv, orig->env, orig->nenv) != 0 ||
	    dup_strings(&ret->permitopen, &ret->npermitopen,
	    orig->permitopen, orig->npermitopen) != 0 ||
	    dup_strings(&ret->permitlisten, &ret->npermitlisten,
	    orig->permitlisten, orig->npermitlisten) != 0) {
		sshauthopt_free(ret);
		返回 NULL;
	}
	返回 ret;
}

static 整数
serialise_array(struct sshbuf *m, char **a, size_t n)
{
	struct sshbuf *b;
	size_t i;
	整数 r = SSH_ERR_INTERNAL_ERROR;

	如果 (n > INT_MAX)
		返回 SSH_ERR_INTERNAL_ERROR;

	如果 ((b = sshbuf_new()) == NULL) {
		返回 SSH_ERR_ALLOC_FAIL;
	}
	为 (i = 0; i < n; i++) {
		如果 ((r = sshbuf_put_cstring(b, a[i])) != 0)
			goto out;
	}
	如果 ((r = sshbuf_put_u32(m, n)) != 0 ||
	    (r = sshbuf_put_stringb(m, b)) != 0)
		goto out;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	返回 r;
}

static 整数
deserialise_array(struct sshbuf *m, char ***ap, size_t *np)
{
	char **a = NULL;
	size_t i, n = 0;
	struct sshbuf *b = NULL;
	u_int tmp;
	整数 r = SSH_ERR_INTERNAL_ERROR;

	如果 ((r = sshbuf_get_u32(m, &tmp)) != 0 ||
	    (r = sshbuf_froms(m, &b)) != 0)
		goto out;
	如果 (tmp > INT_MAX) {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	n = tmp;
	如果 (n > 0 && (a = calloc(n, sizeof(*a))) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	为 (i = 0; i < n; i++) {
		如果 ((r = sshbuf_get_cstring(b, &a[i], NULL)) != 0)
			goto out;
	}
	/* success */
	r = 0;
	*ap = a;
	a = NULL;
	*np = n;
	n = 0;
 out:
	如果 (a != NULL) {
		为 (i = 0; i < n; i++)
			free(a[i]);
		free(a);
	}
	sshbuf_free(b);
	返回 r;
}

static 整数
serialise_nullable_string(struct sshbuf *m, const char *s)
{
	整数 r;

	如果 ((r = sshbuf_put_u8(m, s == NULL)) != 0 ||
	    (r = sshbuf_put_cstring(m, s)) != 0)
		返回 r;
	返回 0;
}

static 整数
deserialise_nullable_string(struct sshbuf *m, char **sp)
{
	整数 r;
	u_char flag;

	*sp = NULL;
	如果 ((r = sshbuf_get_u8(m, &flag)) != 0 ||
	    (r = sshbuf_get_cstring(m, flag ? NULL : sp, NULL)) != 0)
		返回 r;
	返回 0;
}

整数
sshauthopt_serialise(const struct sshauthopt *opts, struct sshbuf *m,
    整数 untrusted)
{
	整数 r = SSH_ERR_INTERNAL_ERROR;

	/* Flag options */
	如果 ((r = sshbuf_put_u8(m, opts->permit_port_forwarding_flag)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->permit_agent_forwarding_flag)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->permit_x11_forwarding_flag)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->permit_pty_flag)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->permit_user_rc)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->restricted)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->cert_authority)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->no_require_user_presence)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->require_verify)) != 0)
		返回 r;

	/* Simple integer options */
	如果 ((r = sshbuf_put_u64(m, opts->valid_before)) != 0)
		返回 r;

	/* tunnel number can be negative to indicate "unset" */
	如果 ((r = sshbuf_put_u8(m, opts->force_tun_device == -1)) != 0 ||
	    (r = sshbuf_put_u32(m, (opts->force_tun_device < 0) ?
	    0 : (u_int)opts->force_tun_device)) != 0)
		返回 r;

	/* String options; these may be NULL */
	如果 ((r = serialise_nullable_string(m,
	    untrusted ? "yes" : opts->cert_principals)) != 0 ||
	    (r = serialise_nullable_string(m,
	    untrusted ? "true" : opts->force_command)) != 0 ||
	    (r = serialise_nullable_string(m,
	    untrusted ? NULL : opts->required_from_host_cert)) != 0 ||
	    (r = serialise_nullable_string(m,
	    untrusted ? NULL : opts->required_from_host_keys)) != 0)
		返回 r;

	/* Array options */
	如果 ((r = serialise_array(m, opts->env,
	    untrusted ? 0 : opts->nenv)) != 0 ||
	    (r = serialise_array(m, opts->permitopen,
	    untrusted ? 0 : opts->npermitopen)) != 0 ||
	    (r = serialise_array(m, opts->permitlisten,
	    untrusted ? 0 : opts->npermitlisten)) != 0)
		返回 r;

	/* success */
	返回 0;
}

整数
sshauthopt_deserialise(struct sshbuf *m, struct sshauthopt **optsp)
{
	struct sshauthopt *opts = NULL;
	整数 r = SSH_ERR_INTERNAL_ERROR;
	u_char f;
	u_int tmp;

	如果 ((opts = calloc(1, sizeof(*opts))) == NULL)
		返回 SSH_ERR_ALLOC_FAIL;

	/* Flag options */
#define OPT_FLAG(x) \
	do { \
		如果 ((r = sshbuf_get_u8(m, &f)) != 0) \
			goto out; \
		opts->x = f; \
	} 当 (0)
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
	如果 ((r = sshbuf_get_u64(m, &opts->valid_before)) != 0)
		goto out;

	/* tunnel number can be negative to indicate "unset" */
	如果 ((r = sshbuf_get_u8(m, &f)) != 0 ||
	    (r = sshbuf_get_u32(m, &tmp)) != 0)
		goto out;
	opts->force_tun_device = f ? -1 : (整数)tmp;

	/* String options may be NULL */
	如果 ((r = deserialise_nullable_string(m, &opts->cert_principals)) != 0 ||
	    (r = deserialise_nullable_string(m, &opts->force_command)) != 0 ||
	    (r = deserialise_nullable_string(m,
	    &opts->required_from_host_cert)) != 0 ||
	    (r = deserialise_nullable_string(m,
	    &opts->required_from_host_keys)) != 0)
		goto out;

	/* Array options */
	如果 ((r = deserialise_array(m, &opts->env, &opts->nenv)) != 0 ||
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
	返回 r;
}
