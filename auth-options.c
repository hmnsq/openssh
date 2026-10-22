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

স্থির পূর্ণাঙ্ক
dup_strings(বর্ণ ***dstp, size_t *ndstp, বর্ণ **src, size_t nsrc)
{
	বর্ণ **dst;
	size_t i, j;

	*dstp = রিক্ত;
	*ndstp = 0;

	যদি (nsrc == 0)
		প্রত্যাগম 0;
	যদি (nsrc >= SIZE_MAX / পরিমাণ(*src) ||
	    (dst = calloc(nsrc, পরিমাণ(*src))) == রিক্ত)
		প্রত্যাগম -1;
	প্রতি (i = 0; i < nsrc; i++) {
		যদি ((dst[i] = strdup(src[i])) == রিক্ত) {
			প্রতি (j = 0; j < i; j++)
				মুক্ত(dst[j]);
			মুক্ত(dst);
			প্রত্যাগম -1;
		}
	}
	/* success */
	*dstp = dst;
	*ndstp = nsrc;
	প্রত্যাগম 0;
}

#define OPTIONS_CRITICAL	1
#define OPTIONS_EXTENSIONS	2
স্থির পূর্ণাঙ্ক
cert_option_list(সংরচনা sshauthopt *opts, সংরচনা sshbuf *oblob,
    u_int which, পূর্ণাঙ্ক crit)
{
	বর্ণ *command, *allowed;
	বর্ণ *name = রিক্ত;
	সংরচনা sshbuf *c = রিক্ত, *data = রিক্ত;
	পূর্ণাঙ্ক r, ret = -1, found;

	যদি ((c = sshbuf_fromb(oblob)) == রিক্ত) {
		error_f("sshbuf_fromb failed");
		গচ্ছ out;
	}

	যাবত্ (sshbuf_len(c) > 0) {
		sshbuf_free(data);
		data = রিক্ত;
		যদি ((r = sshbuf_get_cstring(c, &name, রিক্ত)) != 0 ||
		    (r = sshbuf_froms(c, &data)) != 0) {
			error_r(r, "Unable to parse certificate options");
			গচ্ছ out;
		}
		debug3("found certificate option \"%.100s\" len %zu",
		    name, sshbuf_len(data));
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
				যদি ((r = sshbuf_get_cstring(data, &command,
				    রিক্ত)) != 0) {
					error_r(r, "Unable to parse \"%s\" "
					    "section", name);
					গচ্ছ out;
				}
				যদি (opts->force_command != রিক্ত) {
					error("Certificate has multiple "
					    "force-command options");
					মুক্ত(command);
					গচ্ছ out;
				}
				opts->force_command = command;
				found = 1;
			} অন্যথা যদি (strcmp(name, "source-address") == 0) {
				যদি ((r = sshbuf_get_cstring(data, &allowed,
				    রিক্ত)) != 0) {
					error_r(r, "Unable to parse \"%s\" "
					    "section", name);
					গচ্ছ out;
				}
				যদি (opts->required_from_host_cert != রিক্ত) {
					error("Certificate has multiple "
					    "source-address options");
					মুক্ত(allowed);
					গচ্ছ out;
				}
				/* Check syntax */
				যদি (addr_match_cidr_list(রিক্ত, allowed) == -1) {
					error("Certificate source-address "
					    "contents invalid");
					মুক্ত(allowed);
					গচ্ছ out;
				}
				opts->required_from_host_cert = allowed;
				found = 1;
			}
		}

		যদি (!found) {
			যদি (crit) {
				error("Certificate critical option \"%s\" "
				    "is not supported", name);
				গচ্ছ out;
			} অন্যথা {
				logit("Certificate extension \"%s\" "
				    "is not supported", name);
			}
		} অন্যথা যদি (sshbuf_len(data) != 0) {
			error("Certificate option \"%s\" corrupt "
			    "(extra data)", name);
			গচ্ছ out;
		}
		মুক্ত(name);
		name = রিক্ত;
	}
	/* successfully parsed all options */
	ret = 0;

 out:
	মুক্ত(name);
	sshbuf_free(data);
	sshbuf_free(c);
	প্রত্যাগম ret;
}

সংরচনা sshauthopt *
sshauthopt_new(শূন্য)
{
	সংরচনা sshauthopt *ret;

	যদি ((ret = calloc(1, পরিমাণ(*ret))) == রিক্ত)
		প্রত্যাগম রিক্ত;
	ret->force_tun_device = -1;
	প্রত্যাগম ret;
}

শূন্য
sshauthopt_free(সংরচনা sshauthopt *opts)
{
	size_t i;

	যদি (opts == রিক্ত)
		প্রত্যাগম;

	মুক্ত(opts->cert_principals);
	মুক্ত(opts->force_command);
	মুক্ত(opts->required_from_host_cert);
	মুক্ত(opts->required_from_host_চাবিগুলি);

	প্রতি (i = 0; i < opts->nenv; i++)
		মুক্ত(opts->env[i]);
	মুক্ত(opts->env);

	প্রতি (i = 0; i < opts->npermitopen; i++)
		মুক্ত(opts->permitopen[i]);
	মুক্ত(opts->permitopen);

	প্রতি (i = 0; i < opts->npermitlisten; i++)
		মুক্ত(opts->permitlisten[i]);
	মুক্ত(opts->permitlisten);

	freezero(opts, পরিমাণ(*opts));
}

সংরচনা sshauthopt *
sshauthopt_new_with_চাবিগুলি_defaults(শূন্য)
{
	সংরচনা sshauthopt *ret = রিক্ত;

	যদি ((ret = sshauthopt_new()) == রিক্ত)
		প্রত্যাগম রিক্ত;

	/* Defaults for authorized_keys flags */
	ret->permit_port_forwarding_flag = 1;
	ret->permit_agent_forwarding_flag = 1;
	ret->permit_x11_forwarding_flag = 1;
	ret->permit_pty_flag = 1;
	ret->permit_user_rc = 1;
	প্রত্যাগম ret;
}

/*
 * Parse and record a permitopen/permitlisten directive.
 * Return 0 on success. Return -1 on failure and sets *errstrp to error reason.
 */
স্থির পূর্ণাঙ্ক
handle_permit(ধ্রুব বর্ণ **optsp, পূর্ণাঙ্ক allow_bare_port,
    বর্ণ ***permitsp, size_t *npermitsp, ধ্রুব বর্ণ **errstrp)
{
	বর্ণ *opt, *tmp, *cp, *host, **permits = *permitsp;
	size_t npermits = *npermitsp;
	ধ্রুব বর্ণ *errstr = "unknown error";

	যদি (npermits > SSH_AUTHOPT_PERMIT_MAX) {
		*errstrp = "too many permission directives";
		প্রত্যাগম -1;
	}
	যদি ((opt = opt_dequote(optsp, &errstr)) == রিক্ত) {
		প্রত্যাগম -1;
	}
	যদি (allow_bare_port && strchr(opt, ':') == রিক্ত) {
		/*
		 * Allow a bare port number in permitlisten to indicate a
		 * listen_host wildcard.
		 */
		যদি (asprintf(&tmp, "*:%s", opt) == -1) {
			মুক্ত(opt);
			*errstrp = "memory allocation failed";
			প্রত্যাগম -1;
		}
		মুক্ত(opt);
		opt = tmp;
	}
	যদি ((tmp = strdup(opt)) == রিক্ত) {
		মুক্ত(opt);
		*errstrp = "memory allocation failed";
		প্রত্যাগম -1;
	}
	cp = tmp;
	/* validate syntax before recording it. */
	host = hpdelim2(&cp, রিক্ত);
	যদি (host == রিক্ত || strlen(host) >= NI_MAXHOST) {
		মুক্ত(tmp);
		মুক্ত(opt);
		*errstrp = "invalid permission hostname";
		প্রত্যাগম -1;
	}
	/*
	 * don't want to use permitopen_port to avoid
	 * dependency on channels.[ch] here.
	 */
	যদি (cp == রিক্ত ||
	    (strcmp(cp, "*") != 0 && a2port(cp) <= 0)) {
		মুক্ত(tmp);
		মুক্ত(opt);
		*errstrp = "invalid permission port";
		প্রত্যাগম -1;
	}
	/* XXX - add streamlocal support */
	মুক্ত(tmp);
	/* Record it */
	যদি ((permits = recallocarray(permits, npermits, npermits + 1,
	    পরিমাণ(*permits))) == রিক্ত) {
		মুক্ত(opt);
		/* NB. don't update *permitsp if alloc fails */
		*errstrp = "memory allocation failed";
		প্রত্যাগম -1;
	}
	permits[npermits++] = opt;
	*permitsp = permits;
	*npermitsp = npermits;
	প্রত্যাগম 0;
}

সংরচনা sshauthopt *
sshauthopt_parse(ধ্রুব বর্ণ *opts, ধ্রুব বর্ণ **errstrp)
{
	বর্ণ **oarray, *opt, *cp, *tmp;
	পূর্ণাঙ্ক r;
	সংরচনা sshauthopt *ret = রিক্ত;
	ধ্রুব বর্ণ *errstr = "unknown error";
	uint64_t valid_before;
	size_t i, l;

	যদি (errstrp != রিক্ত)
		*errstrp = রিক্ত;
	যদি ((ret = sshauthopt_new_with_চাবিগুলি_defaults()) == রিক্ত)
		গচ্ছ alloc_fail;

	যদি (opts == রিক্ত)
		প্রত্যাগম ret;

	যাবত্ (*opts && *opts != ' ' && *opts != '\t') {
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
			যদি (ret->force_command != রিক্ত) {
				errstr = "multiple \"command\" clauses";
				গচ্ছ fail;
			}
			ret->force_command = opt_dequote(&opts, &errstr);
			যদি (ret->force_command == রিক্ত)
				গচ্ছ fail;
		} অন্যথা যদি (opt_match(&opts, "principals")) {
			যদি (ret->cert_principals != রিক্ত) {
				errstr = "multiple \"principals\" clauses";
				গচ্ছ fail;
			}
			ret->cert_principals = opt_dequote(&opts, &errstr);
			যদি (ret->cert_principals == রিক্ত)
				গচ্ছ fail;
		} অন্যথা যদি (opt_match(&opts, "from")) {
			যদি (ret->required_from_host_চাবিগুলি != রিক্ত) {
				errstr = "multiple \"from\" clauses";
				গচ্ছ fail;
			}
			ret->required_from_host_চাবিগুলি = opt_dequote(&opts,
			    &errstr);
			যদি (ret->required_from_host_চাবিগুলি == রিক্ত)
				গচ্ছ fail;
		} অন্যথা যদি (opt_match(&opts, "expiry-time")) {
			যদি ((opt = opt_dequote(&opts, &errstr)) == রিক্ত)
				গচ্ছ fail;
			যদি (parse_absolute_time(opt, &valid_before) != 0 ||
			    valid_before == 0) {
				মুক্ত(opt);
				errstr = "invalid expires time";
				গচ্ছ fail;
			}
			মুক্ত(opt);
			যদি (ret->valid_before == 0 ||
			    valid_before < ret->valid_before)
				ret->valid_before = valid_before;
		} অন্যথা যদি (opt_match(&opts, "environment")) {
			যদি (ret->nenv > SSH_AUTHOPT_ENV_MAX) {
				errstr = "too many environment strings";
				গচ্ছ fail;
			}
			যদি ((opt = opt_dequote(&opts, &errstr)) == রিক্ত)
				গচ্ছ fail;
			/* env name must be alphanumeric and followed by '=' */
			যদি ((tmp = strchr(opt, '=')) == রিক্ত) {
				মুক্ত(opt);
				errstr = "invalid environment string";
				গচ্ছ fail;
			}
			যদি ((cp = strdup(opt)) == রিক্ত) {
				মুক্ত(opt);
				গচ্ছ alloc_fail;
			}
			l = (size_t)(tmp - opt);
			cp[l] = '\0'; /* truncate at '=' */
			যদি (!valid_env_name(cp)) {
				মুক্ত(cp);
				মুক্ত(opt);
				errstr = "invalid environment string";
				গচ্ছ fail;
			}
			/* Check for duplicates; XXX O(n*log(n)) */
			প্রতি (i = 0; i < ret->nenv; i++) {
				যদি (strncmp(ret->env[i], cp, l) == 0 &&
				    ret->env[i][l] == '=')
					ভঙ্গ;
			}
			মুক্ত(cp);
			/* First match wins */
			যদি (i >= ret->nenv) {
				/* Append it. */
				oarray = ret->env;
				যদি ((ret->env = recallocarray(ret->env,
				    ret->nenv, ret->nenv + 1,
				    পরিমাণ(*ret->env))) == রিক্ত) {
					মুক্ত(opt);
					/* put it back for cleanup */
					ret->env = oarray;
					গচ্ছ alloc_fail;
				}
				ret->env[ret->nenv++] = opt;
				opt = রিক্ত; /* transferred */
			}
			মুক্ত(opt);
		} অন্যথা যদি (opt_match(&opts, "permitopen")) {
			যদি (handle_permit(&opts, 0, &ret->permitopen,
			    &ret->npermitopen, &errstr) != 0)
				গচ্ছ fail;
		} অন্যথা যদি (opt_match(&opts, "permitlisten")) {
			যদি (handle_permit(&opts, 1, &ret->permitlisten,
			    &ret->npermitlisten, &errstr) != 0)
				গচ্ছ fail;
		} অন্যথা যদি (opt_match(&opts, "tunnel")) {
			যদি ((opt = opt_dequote(&opts, &errstr)) == রিক্ত)
				গচ্ছ fail;
			ret->force_tun_device = a2tun(opt, রিক্ত);
			মুক্ত(opt);
			যদি (ret->force_tun_device == SSH_TUNID_ERR) {
				errstr = "invalid tun device";
				গচ্ছ fail;
			}
		}
		/*
		 * Skip the comma, and move to the next option
		 * (or break out if there are no more).
		 */
		যদি (*opts == '\0' || *opts == ' ' || *opts == '\t')
			ভঙ্গ;		/* End of options. */
		/* Anything other than a comma is an unknown option */
		যদি (*opts != ',') {
			errstr = "unknown key option";
			গচ্ছ fail;
		}
		opts++;
		যদি (*opts == '\0') {
			errstr = "unexpected end-of-options";
			গচ্ছ fail;
		}
	}

	/* success */
	যদি (errstrp != রিক্ত)
		*errstrp = রিক্ত;
	প্রত্যাগম ret;

alloc_fail:
	errstr = "memory allocation failed";
fail:
	sshauthopt_free(ret);
	যদি (errstrp != রিক্ত)
		*errstrp = errstr;
	প্রত্যাগম রিক্ত;
}

সংরচনা sshauthopt *
sshauthopt_from_cert(সংরচনা sshkey *k)
{
	সংরচনা sshauthopt *ret;

	যদি (k == রিক্ত || !sshkey_type_is_cert(k->type) || k->cert == রিক্ত ||
	    k->cert->type != SSH2_CERT_TYPE_USER)
		প্রত্যাগম রিক্ত;

	যদি ((ret = sshauthopt_new()) == রিক্ত)
		প্রত্যাগম রিক্ত;

	/* Handle options and critical extensions separately */
	যদি (cert_option_list(ret, k->cert->critical,
	    OPTIONS_CRITICAL, 1) == -1) {
		sshauthopt_free(ret);
		প্রত্যাগম রিক্ত;
	}
	যদি (cert_option_list(ret, k->cert->extensions,
	    OPTIONS_EXTENSIONS, 0) == -1) {
		sshauthopt_free(ret);
		প্রত্যাগম রিক্ত;
	}
	/* success */
	প্রত্যাগম ret;
}

/*
 * Merges "additional" options to "primary" and returns the result.
 * NB. Some options from primary have primacy.
 */
সংরচনা sshauthopt *
sshauthopt_merge(ধ্রুব সংরচনা sshauthopt *primary,
    ধ্রুব সংরচনা sshauthopt *additional, ধ্রুব বর্ণ **errstrp)
{
	সংরচনা sshauthopt *ret;
	ধ্রুব বর্ণ *errstr = "internal error";
	ধ্রুব বর্ণ *tmp;

	যদি (errstrp != রিক্ত)
		*errstrp = রিক্ত;

	যদি ((ret = sshauthopt_new()) == রিক্ত)
		গচ্ছ alloc_fail;

	/* cert_authority and cert_principals are cleared in result */

	/* Prefer access lists from primary. */
	/* XXX err is both set and mismatch? */
	tmp = primary->required_from_host_cert;
	যদি (tmp == রিক্ত)
		tmp = additional->required_from_host_cert;
	যদি (tmp != রিক্ত && (ret->required_from_host_cert = strdup(tmp)) == রিক্ত)
		গচ্ছ alloc_fail;
	tmp = primary->required_from_host_চাবিগুলি;
	যদি (tmp == রিক্ত)
		tmp = additional->required_from_host_চাবিগুলি;
	যদি (tmp != রিক্ত && (ret->required_from_host_চাবিগুলি = strdup(tmp)) == রিক্ত)
		গচ্ছ alloc_fail;

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
			গচ্ছ alloc_fail;
	} অন্যথা যদি (additional->nenv) {
		যদি (dup_strings(&ret->env, &ret->nenv,
		    additional->env, additional->nenv) != 0)
			গচ্ছ alloc_fail;
	}
	যদি (primary->npermitopen > 0) {
		যদি (dup_strings(&ret->permitopen, &ret->npermitopen,
		    primary->permitopen, primary->npermitopen) != 0)
			গচ্ছ alloc_fail;
	} অন্যথা যদি (additional->npermitopen > 0) {
		যদি (dup_strings(&ret->permitopen, &ret->npermitopen,
		    additional->permitopen, additional->npermitopen) != 0)
			গচ্ছ alloc_fail;
	}

	যদি (primary->npermitlisten > 0) {
		যদি (dup_strings(&ret->permitlisten, &ret->npermitlisten,
		    primary->permitlisten, primary->npermitlisten) != 0)
			গচ্ছ alloc_fail;
	} অন্যথা যদি (additional->npermitlisten > 0) {
		যদি (dup_strings(&ret->permitlisten, &ret->npermitlisten,
		    additional->permitlisten, additional->npermitlisten) != 0)
			গচ্ছ alloc_fail;
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
	যদি (primary->force_command != রিক্ত &&
	    additional->force_command != রিক্ত) {
		যদি (strcmp(primary->force_command,
		    additional->force_command) == 0) {
			/* ok */
			ret->force_command = strdup(primary->force_command);
			যদি (ret->force_command == রিক্ত)
				গচ্ছ alloc_fail;
		} অন্যথা {
			errstr = "forced command options do not match";
			গচ্ছ fail;
		}
	} অন্যথা যদি (primary->force_command != রিক্ত) {
		যদি ((ret->force_command = strdup(
		    primary->force_command)) == রিক্ত)
			গচ্ছ alloc_fail;
	} অন্যথা যদি (additional->force_command != রিক্ত) {
		যদি ((ret->force_command = strdup(
		    additional->force_command)) == রিক্ত)
			গচ্ছ alloc_fail;
	}
	/* success */
	যদি (errstrp != রিক্ত)
		*errstrp = রিক্ত;
	প্রত্যাগম ret;

 alloc_fail:
	errstr = "memory allocation failed";
 fail:
	যদি (errstrp != রিক্ত)
		*errstrp = errstr;
	sshauthopt_free(ret);
	প্রত্যাগম রিক্ত;
}

/*
 * Copy options
 */
সংরচনা sshauthopt *
sshauthopt_copy(ধ্রুব সংরচনা sshauthopt *orig)
{
	সংরচনা sshauthopt *ret;

	যদি ((ret = sshauthopt_new()) == রিক্ত)
		প্রত্যাগম রিক্ত;

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
	কুরু { \
		যদি (orig->x != রিক্ত && (ret->x = strdup(orig->x)) == রিক্ত) { \
			sshauthopt_free(ret); \
			প্রত্যাগম রিক্ত; \
		} \
	} যাবত্ (0)
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
		প্রত্যাগম রিক্ত;
	}
	প্রত্যাগম ret;
}

স্থির পূর্ণাঙ্ক
serialise_array(সংরচনা sshbuf *m, বর্ণ **a, size_t n)
{
	সংরচনা sshbuf *b;
	size_t i;
	পূর্ণাঙ্ক r = SSH_ERR_INTERNAL_ERROR;

	যদি (n > INT_MAX)
		প্রত্যাগম SSH_ERR_INTERNAL_ERROR;

	যদি ((b = sshbuf_new()) == রিক্ত) {
		প্রত্যাগম SSH_ERR_ALLOC_FAIL;
	}
	প্রতি (i = 0; i < n; i++) {
		যদি ((r = sshbuf_put_cstring(b, a[i])) != 0)
			গচ্ছ out;
	}
	যদি ((r = sshbuf_put_u32(m, n)) != 0 ||
	    (r = sshbuf_put_stringb(m, b)) != 0)
		গচ্ছ out;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	প্রত্যাগম r;
}

স্থির পূর্ণাঙ্ক
deserialise_array(সংরচনা sshbuf *m, বর্ণ ***ap, size_t *np)
{
	বর্ণ **a = রিক্ত;
	size_t i, n = 0;
	সংরচনা sshbuf *b = রিক্ত;
	u_int tmp;
	পূর্ণাঙ্ক r = SSH_ERR_INTERNAL_ERROR;

	যদি ((r = sshbuf_get_u32(m, &tmp)) != 0 ||
	    (r = sshbuf_froms(m, &b)) != 0)
		গচ্ছ out;
	যদি (tmp > INT_MAX) {
		r = SSH_ERR_INVALID_FORMAT;
		গচ্ছ out;
	}
	n = tmp;
	যদি (n > 0 && (a = calloc(n, পরিমাণ(*a))) == রিক্ত) {
		r = SSH_ERR_ALLOC_FAIL;
		গচ্ছ out;
	}
	প্রতি (i = 0; i < n; i++) {
		যদি ((r = sshbuf_get_cstring(b, &a[i], রিক্ত)) != 0)
			গচ্ছ out;
	}
	/* success */
	r = 0;
	*ap = a;
	a = রিক্ত;
	*np = n;
	n = 0;
 out:
	যদি (a != রিক্ত) {
		প্রতি (i = 0; i < n; i++)
			মুক্ত(a[i]);
		মুক্ত(a);
	}
	sshbuf_free(b);
	প্রত্যাগম r;
}

স্থির পূর্ণাঙ্ক
serialise_nullable_string(সংরচনা sshbuf *m, ধ্রুব বর্ণ *s)
{
	পূর্ণাঙ্ক r;

	যদি ((r = sshbuf_put_u8(m, s == রিক্ত)) != 0 ||
	    (r = sshbuf_put_cstring(m, s)) != 0)
		প্রত্যাগম r;
	প্রত্যাগম 0;
}

স্থির পূর্ণাঙ্ক
deserialise_nullable_string(সংরচনা sshbuf *m, বর্ণ **sp)
{
	পূর্ণাঙ্ক r;
	u_char flag;

	*sp = রিক্ত;
	যদি ((r = sshbuf_get_u8(m, &flag)) != 0 ||
	    (r = sshbuf_get_cstring(m, flag ? রিক্ত : sp, রিক্ত)) != 0)
		প্রত্যাগম r;
	প্রত্যাগম 0;
}

পূর্ণাঙ্ক
sshauthopt_serialise(ধ্রুব সংরচনা sshauthopt *opts, সংরচনা sshbuf *m,
    পূর্ণাঙ্ক untrusted)
{
	পূর্ণাঙ্ক r = SSH_ERR_INTERNAL_ERROR;

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
		প্রত্যাগম r;

	/* Simple integer options */
	যদি ((r = sshbuf_put_u64(m, opts->valid_before)) != 0)
		প্রত্যাগম r;

	/* tunnel number can be negative to indicate "unset" */
	যদি ((r = sshbuf_put_u8(m, opts->force_tun_device == -1)) != 0 ||
	    (r = sshbuf_put_u32(m, (opts->force_tun_device < 0) ?
	    0 : (u_int)opts->force_tun_device)) != 0)
		প্রত্যাগম r;

	/* String options; these may be NULL */
	যদি ((r = serialise_nullable_string(m,
	    untrusted ? "yes" : opts->cert_principals)) != 0 ||
	    (r = serialise_nullable_string(m,
	    untrusted ? "true" : opts->force_command)) != 0 ||
	    (r = serialise_nullable_string(m,
	    untrusted ? রিক্ত : opts->required_from_host_cert)) != 0 ||
	    (r = serialise_nullable_string(m,
	    untrusted ? রিক্ত : opts->required_from_host_চাবিগুলি)) != 0)
		প্রত্যাগম r;

	/* Array options */
	যদি ((r = serialise_array(m, opts->env,
	    untrusted ? 0 : opts->nenv)) != 0 ||
	    (r = serialise_array(m, opts->permitopen,
	    untrusted ? 0 : opts->npermitopen)) != 0 ||
	    (r = serialise_array(m, opts->permitlisten,
	    untrusted ? 0 : opts->npermitlisten)) != 0)
		প্রত্যাগম r;

	/* success */
	প্রত্যাগম 0;
}

পূর্ণাঙ্ক
sshauthopt_deserialise(সংরচনা sshbuf *m, সংরচনা sshauthopt **optsp)
{
	সংরচনা sshauthopt *opts = রিক্ত;
	পূর্ণাঙ্ক r = SSH_ERR_INTERNAL_ERROR;
	u_char f;
	u_int tmp;

	যদি ((opts = calloc(1, পরিমাণ(*opts))) == রিক্ত)
		প্রত্যাগম SSH_ERR_ALLOC_FAIL;

	/* Flag options */
#define OPT_FLAG(x) \
	কুরু { \
		যদি ((r = sshbuf_get_u8(m, &f)) != 0) \
			গচ্ছ out; \
		opts->x = f; \
	} যাবত্ (0)
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
		গচ্ছ out;

	/* tunnel number can be negative to indicate "unset" */
	যদি ((r = sshbuf_get_u8(m, &f)) != 0 ||
	    (r = sshbuf_get_u32(m, &tmp)) != 0)
		গচ্ছ out;
	opts->force_tun_device = f ? -1 : (পূর্ণাঙ্ক)tmp;

	/* String options may be NULL */
	যদি ((r = deserialise_nullable_string(m, &opts->cert_principals)) != 0 ||
	    (r = deserialise_nullable_string(m, &opts->force_command)) != 0 ||
	    (r = deserialise_nullable_string(m,
	    &opts->required_from_host_cert)) != 0 ||
	    (r = deserialise_nullable_string(m,
	    &opts->required_from_host_চাবিগুলি)) != 0)
		গচ্ছ out;

	/* Array options */
	যদি ((r = deserialise_array(m, &opts->env, &opts->nenv)) != 0 ||
	    (r = deserialise_array(m,
	    &opts->permitopen, &opts->npermitopen)) != 0 ||
	    (r = deserialise_array(m,
	    &opts->permitlisten, &opts->npermitlisten)) != 0)
		গচ্ছ out;

	/* success */
	r = 0;
	*optsp = opts;
	opts = রিক্ত;
 out:
	sshauthopt_free(opts);
	প্রত্যাগম r;
}
