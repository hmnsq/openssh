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

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <sys/types.h>
#অন্তর্ভাব <sys/queue.h>

#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <netdb.h>
#অন্তর্ভাব <pwd.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <stdint.h>
#অন্তর্ভাব <stdarg.h>
#অন্তর্ভাব <ctype.h>
#অন্তর্ভাব <limits.h>

#অন্তর্ভাব "xmalloc.h"
#অন্তর্ভাব "ssherr.h"
#অন্তর্ভাব "log.h"
#অন্তর্ভাব "sshbuf.h"
#অন্তর্ভাব "misc.h"
#অন্তর্ভাব "sshkey.h"
#অন্তর্ভাব "match.h"
#অন্তর্ভাব "ssh2.h"
#অন্তর্ভাব "auth-options.h"

স্থির পূর্ণসংখ্যা
dup_strings(অক্ষর ***dstp, আকার_t *ndstp, অক্ষর **src, আকার_t nsrc)
{
	অক্ষর **dst;
	আকার_t i, j;

	*dstp = ফাঁকা;
	*ndstp = 0;

	যদি (nsrc == 0)
		ফেরত 0;
	যদি (nsrc >= SIZE_MAX / আকার(*src) ||
	    (dst = calloc(nsrc, আকার(*src))) == ফাঁকা)
		ফেরত -1;
	জন্য (i = 0; i < nsrc; i++) {
		যদি ((dst[i] = strdup(src[i])) == ফাঁকা) {
			জন্য (j = 0; j < i; j++)
				মুক্ত(dst[j]);
			মুক্ত(dst);
			ফেরত -1;
		}
	}
	/* success */
	*dstp = dst;
	*ndstp = nsrc;
	ফেরত 0;
}

#define OPTIONS_CRITICAL	1
#define OPTIONS_EXTENSIONS	2
স্থির পূর্ণসংখ্যা
cert_option_list(কাঠামো sshauthopt *opts, কাঠামো sshbuf *oblob,
    u_int which, পূর্ণসংখ্যা crit)
{
	অক্ষর *command, *allowed;
	অক্ষর *name = ফাঁকা;
	কাঠামো sshbuf *c = ফাঁকা, *তথ্য = ফাঁকা;
	পূর্ণসংখ্যা r, ret = -1, found;

	যদি ((c = sshbuf_fromb(oblob)) == ফাঁকা) {
		error_f("sshbuf_fromb failed");
		যাও out;
	}

	যখন (sshbuf_len(c) > 0) {
		sshbuf_free(তথ্য);
		তথ্য = ফাঁকা;
		যদি ((r = sshbuf_get_cstring(c, &name, ফাঁকা)) != 0 ||
		    (r = sshbuf_froms(c, &তথ্য)) != 0) {
			error_r(r, "Unable to parse certificate options");
			যাও out;
		}
		debug3("found certificate option \"%.100s\" len %zu",
		    name, sshbuf_len(তথ্য));
		found = 0;
		যদি ((which & OPTIONS_EXTENSIONS) != 0) {
			যদি (strcmp(name, "no-touch-required") == 0) {
				opts->no_require_user_presence = 1;
				found = 1;
			} অন্যথা যদি (strcmp(name, "permit-X11-forwarding") == 0) {
				opts->permit_x11_forwarding_flag = 1;
				found = 1;
			} অন্যথা যদি (strcmp(name,
			    "permit-agent-forwarding") == 0) {
				opts->permit_agent_forwarding_flag = 1;
				found = 1;
			} অন্যথা যদি (strcmp(name,
			    "permit-port-forwarding") == 0) {
				opts->permit_port_forwarding_flag = 1;
				found = 1;
			} অন্যথা যদি (strcmp(name, "permit-pty") == 0) {
				opts->permit_pty_flag = 1;
				found = 1;
			} অন্যথা যদি (strcmp(name, "permit-user-rc") == 0) {
				opts->permit_user_rc = 1;
				found = 1;
			}
		}
		যদি (!found && (which & OPTIONS_CRITICAL) != 0) {
			যদি (strcmp(name, "verify-required") == 0) {
				opts->require_verify = 1;
				found = 1;
			} অন্যথা যদি (strcmp(name, "force-command") == 0) {
				যদি ((r = sshbuf_get_cstring(তথ্য, &command,
				    ফাঁকা)) != 0) {
					error_r(r, "Unable to parse \"%s\" "
					    "section", name);
					যাও out;
				}
				যদি (opts->force_command != ফাঁকা) {
					error("Certificate has multiple "
					    "force-command options");
					মুক্ত(command);
					যাও out;
				}
				opts->force_command = command;
				found = 1;
			} অন্যথা যদি (strcmp(name, "source-address") == 0) {
				যদি ((r = sshbuf_get_cstring(তথ্য, &allowed,
				    ফাঁকা)) != 0) {
					error_r(r, "Unable to parse \"%s\" "
					    "section", name);
					যাও out;
				}
				যদি (opts->required_from_host_cert != ফাঁকা) {
					error("Certificate has multiple "
					    "source-address options");
					মুক্ত(allowed);
					যাও out;
				}
				/* Check syntax */
				যদি (addr_match_cidr_list(ফাঁকা, allowed) == -1) {
					error("Certificate source-address "
					    "contents invalid");
					মুক্ত(allowed);
					যাও out;
				}
				opts->required_from_host_cert = allowed;
				found = 1;
			}
		}

		যদি (!found) {
			যদি (crit) {
				error("Certificate critical option \"%s\" "
				    "is not supported", name);
				যাও out;
			} অন্যথা {
				logit("Certificate extension \"%s\" "
				    "is not supported", name);
			}
		} অন্যথা যদি (sshbuf_len(তথ্য) != 0) {
			error("Certificate option \"%s\" corrupt "
			    "(extra data)", name);
			যাও out;
		}
		মুক্ত(name);
		name = ফাঁকা;
	}
	/* successfully parsed all options */
	ret = 0;

 out:
	মুক্ত(name);
	sshbuf_free(তথ্য);
	sshbuf_free(c);
	ফেরত ret;
}

কাঠামো sshauthopt *
sshauthopt_new(শূন্য)
{
	কাঠামো sshauthopt *ret;

	যদি ((ret = calloc(1, আকার(*ret))) == ফাঁকা)
		ফেরত ফাঁকা;
	ret->force_tun_device = -1;
	ফেরত ret;
}

শূন্য
sshauthopt_free(কাঠামো sshauthopt *opts)
{
	আকার_t i;

	যদি (opts == ফাঁকা)
		ফেরত;

	মুক্ত(opts->cert_principals);
	মুক্ত(opts->force_command);
	মুক্ত(opts->required_from_host_cert);
	মুক্ত(opts->required_from_host_চাবিগুলি);

	জন্য (i = 0; i < opts->nenv; i++)
		মুক্ত(opts->env[i]);
	মুক্ত(opts->env);

	জন্য (i = 0; i < opts->npermitopen; i++)
		মুক্ত(opts->permitopen[i]);
	মুক্ত(opts->permitopen);

	জন্য (i = 0; i < opts->npermitlisten; i++)
		মুক্ত(opts->permitlisten[i]);
	মুক্ত(opts->permitlisten);

	freezero(opts, আকার(*opts));
}

কাঠামো sshauthopt *
sshauthopt_new_with_চাবিগুলি_defaults(শূন্য)
{
	কাঠামো sshauthopt *ret = ফাঁকা;

	যদি ((ret = sshauthopt_new()) == ফাঁকা)
		ফেরত ফাঁকা;

	/* Defaults for authorized_keys flags */
	ret->permit_port_forwarding_flag = 1;
	ret->permit_agent_forwarding_flag = 1;
	ret->permit_x11_forwarding_flag = 1;
	ret->permit_pty_flag = 1;
	ret->permit_user_rc = 1;
	ফেরত ret;
}

/*
 * Parse and record a permitopen/permitlisten directive.
 * Return 0 on success. Return -1 on failure and sets *errstrp to error reason.
 */
স্থির পূর্ণসংখ্যা
handle_permit(ধ্রুবক অক্ষর **optsp, পূর্ণসংখ্যা allow_bare_port,
    অক্ষর ***permitsp, আকার_t *npermitsp, ধ্রুবক অক্ষর **errstrp)
{
	অক্ষর *opt, *tmp, *cp, *host, **permits = *permitsp;
	আকার_t npermits = *npermitsp;
	ধ্রুবক অক্ষর *errstr = "unknown error";

	যদি (npermits > SSH_AUTHOPT_PERMIT_MAX) {
		*errstrp = "too many permission directives";
		ফেরত -1;
	}
	যদি ((opt = opt_dequote(optsp, &errstr)) == ফাঁকা) {
		ফেরত -1;
	}
	যদি (allow_bare_port && strchr(opt, ':') == ফাঁকা) {
		/*
		 * Allow a bare port number in permitlisten to indicate a
		 * listen_host wildcard.
		 */
		যদি (asprintf(&tmp, "*:%s", opt) == -1) {
			মুক্ত(opt);
			*errstrp = "memory allocation failed";
			ফেরত -1;
		}
		মুক্ত(opt);
		opt = tmp;
	}
	যদি ((tmp = strdup(opt)) == ফাঁকা) {
		মুক্ত(opt);
		*errstrp = "memory allocation failed";
		ফেরত -1;
	}
	cp = tmp;
	/* validate syntax before recording it. */
	host = hpdelim2(&cp, ফাঁকা);
	যদি (host == ফাঁকা || strlen(host) >= NI_MAXHOST) {
		মুক্ত(tmp);
		মুক্ত(opt);
		*errstrp = "invalid permission hostname";
		ফেরত -1;
	}
	/*
	 * don't want to use permitopen_port to avoid
	 * dependency on channels.[ch] here.
	 */
	যদি (cp == ফাঁকা ||
	    (strcmp(cp, "*") != 0 && a2port(cp) <= 0)) {
		মুক্ত(tmp);
		মুক্ত(opt);
		*errstrp = "invalid permission port";
		ফেরত -1;
	}
	/* XXX - add streamlocal support */
	মুক্ত(tmp);
	/* Record it */
	যদি ((permits = recallocarray(permits, npermits, npermits + 1,
	    আকার(*permits))) == ফাঁকা) {
		মুক্ত(opt);
		/* NB. don't update *permitsp if alloc fails */
		*errstrp = "memory allocation failed";
		ফেরত -1;
	}
	permits[npermits++] = opt;
	*permitsp = permits;
	*npermitsp = npermits;
	ফেরত 0;
}

কাঠামো sshauthopt *
sshauthopt_parse(ধ্রুবক অক্ষর *opts, ধ্রুবক অক্ষর **errstrp)
{
	অক্ষর **oarray, *opt, *cp, *tmp;
	পূর্ণসংখ্যা r;
	কাঠামো sshauthopt *ret = ফাঁকা;
	ধ্রুবক অক্ষর *errstr = "unknown error";
	uint64_t valid_before;
	আকার_t i, l;

	যদি (errstrp != ফাঁকা)
		*errstrp = ফাঁকা;
	যদি ((ret = sshauthopt_new_with_চাবিগুলি_defaults()) == ফাঁকা)
		যাও alloc_fail;

	যদি (opts == ফাঁকা)
		ফেরত ret;

	যখন (*opts && *opts != ' ' && *opts != '\t') {
		/* flag options */
		যদি ((r = opt_flag("restrict", 0, &opts)) != -1) {
			ret->restricted = 1;
			ret->permit_port_forwarding_flag = 0;
			ret->permit_agent_forwarding_flag = 0;
			ret->permit_x11_forwarding_flag = 0;
			ret->permit_pty_flag = 0;
			ret->permit_user_rc = 0;
		} অন্যথা যদি ((r = opt_flag("cert-authority", 0, &opts)) != -1) {
			ret->cert_authority = r;
		} অন্যথা যদি ((r = opt_flag("port-forwarding", 1, &opts)) != -1) {
			ret->permit_port_forwarding_flag = r == 1;
		} অন্যথা যদি ((r = opt_flag("agent-forwarding", 1, &opts)) != -1) {
			ret->permit_agent_forwarding_flag = r == 1;
		} অন্যথা যদি ((r = opt_flag("x11-forwarding", 1, &opts)) != -1) {
			ret->permit_x11_forwarding_flag = r == 1;
		} অন্যথা যদি ((r = opt_flag("touch-required", 1, &opts)) != -1) {
			ret->no_require_user_presence = r != 1; /* NB. flip */
		} অন্যথা যদি ((r = opt_flag("verify-required", 1, &opts)) != -1) {
			ret->require_verify = r == 1;
		} অন্যথা যদি ((r = opt_flag("pty", 1, &opts)) != -1) {
			ret->permit_pty_flag = r == 1;
		} অন্যথা যদি ((r = opt_flag("user-rc", 1, &opts)) != -1) {
			ret->permit_user_rc = r == 1;
		} অন্যথা যদি (opt_match(&opts, "command")) {
			যদি (ret->force_command != ফাঁকা) {
				errstr = "multiple \"command\" clauses";
				যাও fail;
			}
			ret->force_command = opt_dequote(&opts, &errstr);
			যদি (ret->force_command == ফাঁকা)
				যাও fail;
		} অন্যথা যদি (opt_match(&opts, "principals")) {
			যদি (ret->cert_principals != ফাঁকা) {
				errstr = "multiple \"principals\" clauses";
				যাও fail;
			}
			ret->cert_principals = opt_dequote(&opts, &errstr);
			যদি (ret->cert_principals == ফাঁকা)
				যাও fail;
		} অন্যথা যদি (opt_match(&opts, "from")) {
			যদি (ret->required_from_host_চাবিগুলি != ফাঁকা) {
				errstr = "multiple \"from\" clauses";
				যাও fail;
			}
			ret->required_from_host_চাবিগুলি = opt_dequote(&opts,
			    &errstr);
			যদি (ret->required_from_host_চাবিগুলি == ফাঁকা)
				যাও fail;
		} অন্যথা যদি (opt_match(&opts, "expiry-time")) {
			যদি ((opt = opt_dequote(&opts, &errstr)) == ফাঁকা)
				যাও fail;
			যদি (parse_absolute_time(opt, &valid_before) != 0 ||
			    valid_before == 0) {
				মুক্ত(opt);
				errstr = "invalid expires time";
				যাও fail;
			}
			মুক্ত(opt);
			যদি (ret->valid_before == 0 ||
			    valid_before < ret->valid_before)
				ret->valid_before = valid_before;
		} অন্যথা যদি (opt_match(&opts, "environment")) {
			যদি (ret->nenv > SSH_AUTHOPT_ENV_MAX) {
				errstr = "too many environment strings";
				যাও fail;
			}
			যদি ((opt = opt_dequote(&opts, &errstr)) == ফাঁকা)
				যাও fail;
			/* env name must be alphanumeric and followed by '=' */
			যদি ((tmp = strchr(opt, '=')) == ফাঁকা) {
				মুক্ত(opt);
				errstr = "invalid environment string";
				যাও fail;
			}
			যদি ((cp = strdup(opt)) == ফাঁকা) {
				মুক্ত(opt);
				যাও alloc_fail;
			}
			l = (আকার_t)(tmp - opt);
			cp[l] = '\0'; /* truncate at '=' */
			যদি (!valid_env_name(cp)) {
				মুক্ত(cp);
				মুক্ত(opt);
				errstr = "invalid environment string";
				যাও fail;
			}
			/* Check for duplicates; XXX O(n*log(n)) */
			জন্য (i = 0; i < ret->nenv; i++) {
				যদি (strncmp(ret->env[i], cp, l) == 0 &&
				    ret->env[i][l] == '=')
					বিরতি;
			}
			মুক্ত(cp);
			/* First match wins */
			যদি (i >= ret->nenv) {
				/* Append it. */
				oarray = ret->env;
				যদি ((ret->env = recallocarray(ret->env,
				    ret->nenv, ret->nenv + 1,
				    আকার(*ret->env))) == ফাঁকা) {
					মুক্ত(opt);
					/* put it back for cleanup */
					ret->env = oarray;
					যাও alloc_fail;
				}
				ret->env[ret->nenv++] = opt;
				opt = ফাঁকা; /* transferred */
			}
			মুক্ত(opt);
		} অন্যথা যদি (opt_match(&opts, "permitopen")) {
			যদি (handle_permit(&opts, 0, &ret->permitopen,
			    &ret->npermitopen, &errstr) != 0)
				যাও fail;
		} অন্যথা যদি (opt_match(&opts, "permitlisten")) {
			যদি (handle_permit(&opts, 1, &ret->permitlisten,
			    &ret->npermitlisten, &errstr) != 0)
				যাও fail;
		} অন্যথা যদি (opt_match(&opts, "tunnel")) {
			যদি ((opt = opt_dequote(&opts, &errstr)) == ফাঁকা)
				যাও fail;
			ret->force_tun_device = a2tun(opt, ফাঁকা);
			মুক্ত(opt);
			যদি (ret->force_tun_device == SSH_TUNID_ERR) {
				errstr = "invalid tun device";
				যাও fail;
			}
		}
		/*
		 * Skip the comma, and move to the next option
		 * (or break out if there are no more).
		 */
		যদি (*opts == '\0' || *opts == ' ' || *opts == '\t')
			বিরতি;		/* End of options. */
		/* Anything other than a comma is an unknown option */
		যদি (*opts != ',') {
			errstr = "unknown key option";
			যাও fail;
		}
		opts++;
		যদি (*opts == '\0') {
			errstr = "unexpected end-of-options";
			যাও fail;
		}
	}

	/* success */
	যদি (errstrp != ফাঁকা)
		*errstrp = ফাঁকা;
	ফেরত ret;

alloc_fail:
	errstr = "memory allocation failed";
fail:
	sshauthopt_free(ret);
	যদি (errstrp != ফাঁকা)
		*errstrp = errstr;
	ফেরত ফাঁকা;
}

কাঠামো sshauthopt *
sshauthopt_from_cert(কাঠামো sshkey *k)
{
	কাঠামো sshauthopt *ret;

	যদি (k == ফাঁকা || !sshkey_type_is_cert(k->type) || k->cert == ফাঁকা ||
	    k->cert->type != SSH2_CERT_TYPE_USER)
		ফেরত ফাঁকা;

	যদি ((ret = sshauthopt_new()) == ফাঁকা)
		ফেরত ফাঁকা;

	/* Handle options and critical extensions separately */
	যদি (cert_option_list(ret, k->cert->critical,
	    OPTIONS_CRITICAL, 1) == -1) {
		sshauthopt_free(ret);
		ফেরত ফাঁকা;
	}
	যদি (cert_option_list(ret, k->cert->extensions,
	    OPTIONS_EXTENSIONS, 0) == -1) {
		sshauthopt_free(ret);
		ফেরত ফাঁকা;
	}
	/* success */
	ফেরত ret;
}

/*
 * Merges "additional" options to "primary" and returns the result.
 * NB. Some options from primary have primacy.
 */
কাঠামো sshauthopt *
sshauthopt_merge(ধ্রুবক কাঠামো sshauthopt *primary,
    ধ্রুবক কাঠামো sshauthopt *additional, ধ্রুবক অক্ষর **errstrp)
{
	কাঠামো sshauthopt *ret;
	ধ্রুবক অক্ষর *errstr = "internal error";
	ধ্রুবক অক্ষর *tmp;

	যদি (errstrp != ফাঁকা)
		*errstrp = ফাঁকা;

	যদি ((ret = sshauthopt_new()) == ফাঁকা)
		যাও alloc_fail;

	/* cert_authority and cert_principals are cleared in result */

	/* Prefer access lists from primary. */
	/* XXX err is both set and mismatch? */
	tmp = primary->required_from_host_cert;
	যদি (tmp == ফাঁকা)
		tmp = additional->required_from_host_cert;
	যদি (tmp != ফাঁকা && (ret->required_from_host_cert = strdup(tmp)) == ফাঁকা)
		যাও alloc_fail;
	tmp = primary->required_from_host_চাবিগুলি;
	যদি (tmp == ফাঁকা)
		tmp = additional->required_from_host_চাবিগুলি;
	যদি (tmp != ফাঁকা && (ret->required_from_host_চাবিগুলি = strdup(tmp)) == ফাঁকা)
		যাও alloc_fail;

	/*
	 * force_tun_device, permitopen/permitlisten and environment all
	 * prefer the primary.
	 */
	ret->force_tun_device = primary->force_tun_device;
	যদি (ret->force_tun_device == -1)
		ret->force_tun_device = additional->force_tun_device;
	যদি (primary->nenv > 0) {
		যদি (dup_strings(&ret->env, &ret->nenv,
		    primary->env, primary->nenv) != 0)
			যাও alloc_fail;
	} অন্যথা যদি (additional->nenv) {
		যদি (dup_strings(&ret->env, &ret->nenv,
		    additional->env, additional->nenv) != 0)
			যাও alloc_fail;
	}
	যদি (primary->npermitopen > 0) {
		যদি (dup_strings(&ret->permitopen, &ret->npermitopen,
		    primary->permitopen, primary->npermitopen) != 0)
			যাও alloc_fail;
	} অন্যথা যদি (additional->npermitopen > 0) {
		যদি (dup_strings(&ret->permitopen, &ret->npermitopen,
		    additional->permitopen, additional->npermitopen) != 0)
			যাও alloc_fail;
	}

	যদি (primary->npermitlisten > 0) {
		যদি (dup_strings(&ret->permitlisten, &ret->npermitlisten,
		    primary->permitlisten, primary->npermitlisten) != 0)
			যাও alloc_fail;
	} অন্যথা যদি (additional->npermitlisten > 0) {
		যদি (dup_strings(&ret->permitlisten, &ret->npermitlisten,
		    additional->permitlisten, additional->npermitlisten) != 0)
			যাও alloc_fail;
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
	যদি (primary->valid_before != 0)
		ret->valid_before = primary->valid_before;
	যদি (additional->valid_before != 0 &&
	    additional->valid_before < ret->valid_before)
		ret->valid_before = additional->valid_before;

	/*
	 * When both multiple forced-command are specified, only
	 * proceed if they are identical, otherwise fail.
	 */
	যদি (primary->force_command != ফাঁকা &&
	    additional->force_command != ফাঁকা) {
		যদি (strcmp(primary->force_command,
		    additional->force_command) == 0) {
			/* ok */
			ret->force_command = strdup(primary->force_command);
			যদি (ret->force_command == ফাঁকা)
				যাও alloc_fail;
		} অন্যথা {
			errstr = "forced command options do not match";
			যাও fail;
		}
	} অন্যথা যদি (primary->force_command != ফাঁকা) {
		যদি ((ret->force_command = strdup(
		    primary->force_command)) == ফাঁকা)
			যাও alloc_fail;
	} অন্যথা যদি (additional->force_command != ফাঁকা) {
		যদি ((ret->force_command = strdup(
		    additional->force_command)) == ফাঁকা)
			যাও alloc_fail;
	}
	/* success */
	যদি (errstrp != ফাঁকা)
		*errstrp = ফাঁকা;
	ফেরত ret;

 alloc_fail:
	errstr = "memory allocation failed";
 fail:
	যদি (errstrp != ফাঁকা)
		*errstrp = errstr;
	sshauthopt_free(ret);
	ফেরত ফাঁকা;
}

/*
 * Copy options
 */
কাঠামো sshauthopt *
sshauthopt_copy(ধ্রুবক কাঠামো sshauthopt *orig)
{
	কাঠামো sshauthopt *ret;

	যদি ((ret = sshauthopt_new()) == ফাঁকা)
		ফেরত ফাঁকা;

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
	করো { \
		যদি (orig->x != ফাঁকা && (ret->x = strdup(orig->x)) == ফাঁকা) { \
			sshauthopt_free(ret); \
			ফেরত ফাঁকা; \
		} \
	} যখন (0)
	OPTSTRING(cert_principals);
	OPTSTRING(force_command);
	OPTSTRING(required_from_host_cert);
	OPTSTRING(required_from_host_চাবিগুলি);
#undef OPTSTRING

	যদি (dup_strings(&ret->env, &ret->nenv, orig->env, orig->nenv) != 0 ||
	    dup_strings(&ret->permitopen, &ret->npermitopen,
	    orig->permitopen, orig->npermitopen) != 0 ||
	    dup_strings(&ret->permitlisten, &ret->npermitlisten,
	    orig->permitlisten, orig->npermitlisten) != 0) {
		sshauthopt_free(ret);
		ফেরত ফাঁকা;
	}
	ফেরত ret;
}

স্থির পূর্ণসংখ্যা
serialise_array(কাঠামো sshbuf *m, অক্ষর **a, আকার_t n)
{
	কাঠামো sshbuf *b;
	আকার_t i;
	পূর্ণসংখ্যা r = SSH_ERR_INTERNAL_ERROR;

	যদি (n > INT_MAX)
		ফেরত SSH_ERR_INTERNAL_ERROR;

	যদি ((b = sshbuf_new()) == ফাঁকা) {
		ফেরত SSH_ERR_ALLOC_FAIL;
	}
	জন্য (i = 0; i < n; i++) {
		যদি ((r = sshbuf_put_cstring(b, a[i])) != 0)
			যাও out;
	}
	যদি ((r = sshbuf_put_u32(m, n)) != 0 ||
	    (r = sshbuf_put_stringb(m, b)) != 0)
		যাও out;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	ফেরত r;
}

স্থির পূর্ণসংখ্যা
deserialise_array(কাঠামো sshbuf *m, অক্ষর ***ap, আকার_t *np)
{
	অক্ষর **a = ফাঁকা;
	আকার_t i, n = 0;
	কাঠামো sshbuf *b = ফাঁকা;
	u_int tmp;
	পূর্ণসংখ্যা r = SSH_ERR_INTERNAL_ERROR;

	যদি ((r = sshbuf_get_u32(m, &tmp)) != 0 ||
	    (r = sshbuf_froms(m, &b)) != 0)
		যাও out;
	যদি (tmp > INT_MAX) {
		r = SSH_ERR_INVALID_FORMAT;
		যাও out;
	}
	n = tmp;
	যদি (n > 0 && (a = calloc(n, আকার(*a))) == ফাঁকা) {
		r = SSH_ERR_ALLOC_FAIL;
		যাও out;
	}
	জন্য (i = 0; i < n; i++) {
		যদি ((r = sshbuf_get_cstring(b, &a[i], ফাঁকা)) != 0)
			যাও out;
	}
	/* success */
	r = 0;
	*ap = a;
	a = ফাঁকা;
	*np = n;
	n = 0;
 out:
	যদি (a != ফাঁকা) {
		জন্য (i = 0; i < n; i++)
			মুক্ত(a[i]);
		মুক্ত(a);
	}
	sshbuf_free(b);
	ফেরত r;
}

স্থির পূর্ণসংখ্যা
serialise_nullable_string(কাঠামো sshbuf *m, ধ্রুবক অক্ষর *s)
{
	পূর্ণসংখ্যা r;

	যদি ((r = sshbuf_put_u8(m, s == ফাঁকা)) != 0 ||
	    (r = sshbuf_put_cstring(m, s)) != 0)
		ফেরত r;
	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
deserialise_nullable_string(কাঠামো sshbuf *m, অক্ষর **sp)
{
	পূর্ণসংখ্যা r;
	u_char flag;

	*sp = ফাঁকা;
	যদি ((r = sshbuf_get_u8(m, &flag)) != 0 ||
	    (r = sshbuf_get_cstring(m, flag ? ফাঁকা : sp, ফাঁকা)) != 0)
		ফেরত r;
	ফেরত 0;
}

পূর্ণসংখ্যা
sshauthopt_serialise(ধ্রুবক কাঠামো sshauthopt *opts, কাঠামো sshbuf *m,
    পূর্ণসংখ্যা untrusted)
{
	পূর্ণসংখ্যা r = SSH_ERR_INTERNAL_ERROR;

	/* Flag options */
	যদি ((r = sshbuf_put_u8(m, opts->permit_port_forwarding_flag)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->permit_agent_forwarding_flag)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->permit_x11_forwarding_flag)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->permit_pty_flag)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->permit_user_rc)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->restricted)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->cert_authority)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->no_require_user_presence)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->require_verify)) != 0)
		ফেরত r;

	/* Simple integer options */
	যদি ((r = sshbuf_put_u64(m, opts->valid_before)) != 0)
		ফেরত r;

	/* tunnel number can be negative to indicate "unset" */
	যদি ((r = sshbuf_put_u8(m, opts->force_tun_device == -1)) != 0 ||
	    (r = sshbuf_put_u32(m, (opts->force_tun_device < 0) ?
	    0 : (u_int)opts->force_tun_device)) != 0)
		ফেরত r;

	/* String options; these may be NULL */
	যদি ((r = serialise_nullable_string(m,
	    untrusted ? "yes" : opts->cert_principals)) != 0 ||
	    (r = serialise_nullable_string(m,
	    untrusted ? "true" : opts->force_command)) != 0 ||
	    (r = serialise_nullable_string(m,
	    untrusted ? ফাঁকা : opts->required_from_host_cert)) != 0 ||
	    (r = serialise_nullable_string(m,
	    untrusted ? ফাঁকা : opts->required_from_host_চাবিগুলি)) != 0)
		ফেরত r;

	/* Array options */
	যদি ((r = serialise_array(m, opts->env,
	    untrusted ? 0 : opts->nenv)) != 0 ||
	    (r = serialise_array(m, opts->permitopen,
	    untrusted ? 0 : opts->npermitopen)) != 0 ||
	    (r = serialise_array(m, opts->permitlisten,
	    untrusted ? 0 : opts->npermitlisten)) != 0)
		ফেরত r;

	/* success */
	ফেরত 0;
}

পূর্ণসংখ্যা
sshauthopt_deserialise(কাঠামো sshbuf *m, কাঠামো sshauthopt **optsp)
{
	কাঠামো sshauthopt *opts = ফাঁকা;
	পূর্ণসংখ্যা r = SSH_ERR_INTERNAL_ERROR;
	u_char f;
	u_int tmp;

	যদি ((opts = calloc(1, আকার(*opts))) == ফাঁকা)
		ফেরত SSH_ERR_ALLOC_FAIL;

	/* Flag options */
#define OPT_FLAG(x) \
	করো { \
		যদি ((r = sshbuf_get_u8(m, &f)) != 0) \
			যাও out; \
		opts->x = f; \
	} যখন (0)
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
	যদি ((r = sshbuf_get_u64(m, &opts->valid_before)) != 0)
		যাও out;

	/* tunnel number can be negative to indicate "unset" */
	যদি ((r = sshbuf_get_u8(m, &f)) != 0 ||
	    (r = sshbuf_get_u32(m, &tmp)) != 0)
		যাও out;
	opts->force_tun_device = f ? -1 : (পূর্ণসংখ্যা)tmp;

	/* String options may be NULL */
	যদি ((r = deserialise_nullable_string(m, &opts->cert_principals)) != 0 ||
	    (r = deserialise_nullable_string(m, &opts->force_command)) != 0 ||
	    (r = deserialise_nullable_string(m,
	    &opts->required_from_host_cert)) != 0 ||
	    (r = deserialise_nullable_string(m,
	    &opts->required_from_host_চাবিগুলি)) != 0)
		যাও out;

	/* Array options */
	যদি ((r = deserialise_array(m, &opts->env, &opts->nenv)) != 0 ||
	    (r = deserialise_array(m,
	    &opts->permitopen, &opts->npermitopen)) != 0 ||
	    (r = deserialise_array(m,
	    &opts->permitlisten, &opts->npermitlisten)) != 0)
		যাও out;

	/* success */
	r = 0;
	*optsp = opts;
	opts = ফাঁকা;
 out:
	sshauthopt_free(opts);
	ফেরত r;
}
