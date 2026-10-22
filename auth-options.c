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

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <sys/queue.h>

#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <netdb.h>
#అన్తర్భావ <pwd.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <stdint.h>
#అన్తర్భావ <stdarg.h>
#అన్తర్భావ <ctype.h>
#అన్తర్భావ <limits.h>

#అన్తర్భావ "xmalloc.h"
#అన్తర్భావ "ssherr.h"
#అన్తర్భావ "log.h"
#అన్తర్భావ "sshbuf.h"
#అన్తర్భావ "misc.h"
#అన్తర్భావ "sshkey.h"
#అన్తర్భావ "match.h"
#అన్తర్భావ "ssh2.h"
#అన్తర్భావ "auth-options.h"

స్థిర పూర్ణాంకం
dup_అక్షరశ్రేణులు(అక్షరం ***dstp, కొలత_t *ndstp, అక్షరం **src, కొలత_t nsrc)
{
	అక్షరం **dst;
	కొలత_t i, j;

	*dstp = ఖాళీ;
	*ndstp = 0;

	ఒకవేళ (nsrc == 0)
		తిరిగి 0;
	ఒకవేళ (nsrc >= SIZE_MAX / పరిమాణం(*src) ||
	    (dst = సున్నా_జ్ఞాపకం_ఇవ్వు(nsrc, పరిమాణం(*src))) == ఖాళీ)
		తిరిగి -1;
	కొరకు (i = 0; i < nsrc; i++) {
		ఒకవేళ ((dst[i] = strdup(src[i])) == ఖాళీ) {
			కొరకు (j = 0; j < i; j++)
				విడుదల(dst[j]);
			విడుదల(dst);
			తిరిగి -1;
		}
	}
	/* success */
	*dstp = dst;
	*ndstp = nsrc;
	తిరిగి 0;
}

#నిర్వచించు OPTIONS_CRITICAL	1
#నిర్వచించు OPTIONS_EXTENSIONS	2
స్థిర పూర్ణాంకం
cert_option_list(నిర్మాణం sshauthopt *opts, నిర్మాణం sshbuf *oblob,
    u_int which, పూర్ణాంకం crit)
{
	అక్షరం *command, *allowed;
	అక్షరం *name = ఖాళీ;
	నిర్మాణం sshbuf *c = ఖాళీ, *దత్తాంశం = ఖాళీ;
	పూర్ణాంకం r, ret = -1, దొరికింది;

	ఒకవేళ ((c = sshbuf_fromb(oblob)) == ఖాళీ) {
		error_f("sshbuf_fromb failed");
		వెళ్ళు బహిర్గతం;
	}

	అయితే (sshbuf_len(c) > 0) {
		sshbuf_free(దత్తాంశం);
		దత్తాంశం = ఖాళీ;
		ఒకవేళ ((r = sshbuf_get_cstring(c, &name, ఖాళీ)) != 0 ||
		    (r = sshbuf_froms(c, &దత్తాంశం)) != 0) {
			error_r(r, "Unable to parse certificate options");
			వెళ్ళు బహిర్గతం;
		}
		debug3("found certificate option \"%.100s\" len %zu",
		    name, sshbuf_len(దత్తాంశం));
		దొరికింది = 0;
		ఒకవేళ ((which & OPTIONS_EXTENSIONS) != 0) {
			ఒకవేళ (strcmp(name, "no-touch-required") == 0) {
				opts->no_require_user_presence = 1;
				దొరికింది = 1;
			} లేకపోతే ఒకవేళ (strcmp(name, "permit-X11-forwarding") == 0) {
				opts->permit_x11_forwarding_flag = 1;
				దొరికింది = 1;
			} లేకపోతే ఒకవేళ (strcmp(name,
			    "permit-agent-forwarding") == 0) {
				opts->permit_agent_forwarding_flag = 1;
				దొరికింది = 1;
			} లేకపోతే ఒకవేళ (strcmp(name,
			    "permit-port-forwarding") == 0) {
				opts->permit_పోర్టు_forwarding_flag = 1;
				దొరికింది = 1;
			} లేకపోతే ఒకవేళ (strcmp(name, "permit-pty") == 0) {
				opts->permit_pty_flag = 1;
				దొరికింది = 1;
			} లేకపోతే ఒకవేళ (strcmp(name, "permit-user-rc") == 0) {
				opts->permit_user_rc = 1;
				దొరికింది = 1;
			}
		}
		ఒకవేళ (!దొరికింది && (which & OPTIONS_CRITICAL) != 0) {
			ఒకవేళ (strcmp(name, "verify-required") == 0) {
				opts->require_verify = 1;
				దొరికింది = 1;
			} లేకపోతే ఒకవేళ (strcmp(name, "force-command") == 0) {
				ఒకవేళ ((r = sshbuf_get_cstring(దత్తాంశం, &command,
				    ఖాళీ)) != 0) {
					error_r(r, "Unable to parse \"%s\" "
					    "section", name);
					వెళ్ళు బహిర్గతం;
				}
				ఒకవేళ (opts->force_command != ఖాళీ) {
					error("Certificate has multiple "
					    "force-command options");
					విడుదల(command);
					వెళ్ళు బహిర్గతం;
				}
				opts->force_command = command;
				దొరికింది = 1;
			} లేకపోతే ఒకవేళ (strcmp(name, "source-address") == 0) {
				ఒకవేళ ((r = sshbuf_get_cstring(దత్తాంశం, &allowed,
				    ఖాళీ)) != 0) {
					error_r(r, "Unable to parse \"%s\" "
					    "section", name);
					వెళ్ళు బహిర్గతం;
				}
				ఒకవేళ (opts->required_from_host_cert != ఖాళీ) {
					error("Certificate has multiple "
					    "source-address options");
					విడుదల(allowed);
					వెళ్ళు బహిర్గతం;
				}
				/* Check syntax */
				ఒకవేళ (addr_సరిపోలిక_cidr_list(ఖాళీ, allowed) == -1) {
					error("Certificate source-address "
					    "contents invalid");
					విడుదల(allowed);
					వెళ్ళు బహిర్గతం;
				}
				opts->required_from_host_cert = allowed;
				దొరికింది = 1;
			}
		}

		ఒకవేళ (!దొరికింది) {
			ఒకవేళ (crit) {
				error("Certificate critical option \"%s\" "
				    "is not supported", name);
				వెళ్ళు బహిర్గతం;
			} లేకపోతే {
				logit("Certificate extension \"%s\" "
				    "is not supported", name);
			}
		} లేకపోతే ఒకవేళ (sshbuf_len(దత్తాంశం) != 0) {
			error("Certificate option \"%s\" corrupt "
			    "(extra data)", name);
			వెళ్ళు బహిర్గతం;
		}
		విడుదల(name);
		name = ఖాళీ;
	}
	/* successfully parsed all options */
	ret = 0;

 బహిర్గతం:
	విడుదల(name);
	sshbuf_free(దత్తాంశం);
	sshbuf_free(c);
	తిరిగి ret;
}

నిర్మాణం sshauthopt *
sshauthopt_new(శూన్య)
{
	నిర్మాణం sshauthopt *ret;

	ఒకవేళ ((ret = సున్నా_జ్ఞాపకం_ఇవ్వు(1, పరిమాణం(*ret))) == ఖాళీ)
		తిరిగి ఖాళీ;
	ret->force_tun_device = -1;
	తిరిగి ret;
}

శూన్య
sshauthopt_free(నిర్మాణం sshauthopt *opts)
{
	కొలత_t i;

	ఒకవేళ (opts == ఖాళీ)
		తిరిగి;

	విడుదల(opts->cert_principals);
	విడుదల(opts->force_command);
	విడుదల(opts->required_from_host_cert);
	విడుదల(opts->required_from_host_కీలకాలు);

	కొరకు (i = 0; i < opts->nenv; i++)
		విడుదల(opts->env[i]);
	విడుదల(opts->env);

	కొరకు (i = 0; i < opts->npermitopen; i++)
		విడుదల(opts->permitopen[i]);
	విడుదల(opts->permitopen);

	కొరకు (i = 0; i < opts->npermitlisten; i++)
		విడుదల(opts->permitlisten[i]);
	విడుదల(opts->permitlisten);

	freezero(opts, పరిమాణం(*opts));
}

నిర్మాణం sshauthopt *
sshauthopt_new_with_కీలకాలు_defaults(శూన్య)
{
	నిర్మాణం sshauthopt *ret = ఖాళీ;

	ఒకవేళ ((ret = sshauthopt_new()) == ఖాళీ)
		తిరిగి ఖాళీ;

	/* Defaults for authorized_keys flags */
	ret->permit_పోర్టు_forwarding_flag = 1;
	ret->permit_agent_forwarding_flag = 1;
	ret->permit_x11_forwarding_flag = 1;
	ret->permit_pty_flag = 1;
	ret->permit_user_rc = 1;
	తిరిగి ret;
}

/*
 * Parse and record a permitopen/permitlisten directive.
 * Return 0 on success. Return -1 on failure and sets *errstrp to error reason.
 */
స్థిర పూర్ణాంకం
handle_permit(స్థిరరాశి అక్షరం **optsp, పూర్ణాంకం allow_bare_పోర్టు,
    అక్షరం ***permitsp, కొలత_t *npermitsp, స్థిరరాశి అక్షరం **errstrp)
{
	అక్షరం *opt, *tmp, *cp, *host, **permits = *permitsp;
	కొలత_t npermits = *npermitsp;
	స్థిరరాశి అక్షరం *errstr = "unknown error";

	ఒకవేళ (npermits > SSH_AUTHOPT_PERMIT_MAX) {
		*errstrp = "too many permission directives";
		తిరిగి -1;
	}
	ఒకవేళ ((opt = opt_dequote(optsp, &errstr)) == ఖాళీ) {
		తిరిగి -1;
	}
	ఒకవేళ (allow_bare_పోర్టు && strchr(opt, ':') == ఖాళీ) {
		/*
		 * Allow a bare port number in permitlisten to indicate a
		 * listen_host wildcard.
		 */
		ఒకవేళ (asprintf(&tmp, "*:%s", opt) == -1) {
			విడుదల(opt);
			*errstrp = "memory allocation failed";
			తిరిగి -1;
		}
		విడుదల(opt);
		opt = tmp;
	}
	ఒకవేళ ((tmp = strdup(opt)) == ఖాళీ) {
		విడుదల(opt);
		*errstrp = "memory allocation failed";
		తిరిగి -1;
	}
	cp = tmp;
	/* validate syntax before recording it. */
	host = hpdelim2(&cp, ఖాళీ);
	ఒకవేళ (host == ఖాళీ || అక్షరశ్రేణి_పొడవు(host) >= NI_MAXHOST) {
		విడుదల(tmp);
		విడుదల(opt);
		*errstrp = "invalid permission hostname";
		తిరిగి -1;
	}
	/*
	 * don't want to use permitopen_port to avoid
	 * dependency on channels.[ch] here.
	 */
	ఒకవేళ (cp == ఖాళీ ||
	    (strcmp(cp, "*") != 0 && a2port(cp) <= 0)) {
		విడుదల(tmp);
		విడుదల(opt);
		*errstrp = "invalid permission port";
		తిరిగి -1;
	}
	/* XXX - add streamlocal support */
	విడుదల(tmp);
	/* Record it */
	ఒకవేళ ((permits = recallocarray(permits, npermits, npermits + 1,
	    పరిమాణం(*permits))) == ఖాళీ) {
		విడుదల(opt);
		/* NB. don't update *permitsp if alloc fails */
		*errstrp = "memory allocation failed";
		తిరిగి -1;
	}
	permits[npermits++] = opt;
	*permitsp = permits;
	*npermitsp = npermits;
	తిరిగి 0;
}

నిర్మాణం sshauthopt *
sshauthopt_parse(స్థిరరాశి అక్షరం *opts, స్థిరరాశి అక్షరం **errstrp)
{
	అక్షరం **oarray, *opt, *cp, *tmp;
	పూర్ణాంకం r;
	నిర్మాణం sshauthopt *ret = ఖాళీ;
	స్థిరరాశి అక్షరం *errstr = "unknown error";
	uint64_t valid_before;
	కొలత_t i, l;

	ఒకవేళ (errstrp != ఖాళీ)
		*errstrp = ఖాళీ;
	ఒకవేళ ((ret = sshauthopt_new_with_కీలకాలు_defaults()) == ఖాళీ)
		వెళ్ళు alloc_fail;

	ఒకవేళ (opts == ఖాళీ)
		తిరిగి ret;

	అయితే (*opts && *opts != ' ' && *opts != '\t') {
		/* flag options */
		ఒకవేళ ((r = opt_flag("restrict", 0, &opts)) != -1) {
			ret->restricted = 1;
			ret->permit_పోర్టు_forwarding_flag = 0;
			ret->permit_agent_forwarding_flag = 0;
			ret->permit_x11_forwarding_flag = 0;
			ret->permit_pty_flag = 0;
			ret->permit_user_rc = 0;
		} లేకపోతే ఒకవేళ ((r = opt_flag("cert-authority", 0, &opts)) != -1) {
			ret->cert_authority = r;
		} లేకపోతే ఒకవేళ ((r = opt_flag("port-forwarding", 1, &opts)) != -1) {
			ret->permit_పోర్టు_forwarding_flag = r == 1;
		} లేకపోతే ఒకవేళ ((r = opt_flag("agent-forwarding", 1, &opts)) != -1) {
			ret->permit_agent_forwarding_flag = r == 1;
		} లేకపోతే ఒకవేళ ((r = opt_flag("x11-forwarding", 1, &opts)) != -1) {
			ret->permit_x11_forwarding_flag = r == 1;
		} లేకపోతే ఒకవేళ ((r = opt_flag("touch-required", 1, &opts)) != -1) {
			ret->no_require_user_presence = r != 1; /* NB. flip */
		} లేకపోతే ఒకవేళ ((r = opt_flag("verify-required", 1, &opts)) != -1) {
			ret->require_verify = r == 1;
		} లేకపోతే ఒకవేళ ((r = opt_flag("pty", 1, &opts)) != -1) {
			ret->permit_pty_flag = r == 1;
		} లేకపోతే ఒకవేళ ((r = opt_flag("user-rc", 1, &opts)) != -1) {
			ret->permit_user_rc = r == 1;
		} లేకపోతే ఒకవేళ (opt_సరిపోలిక(&opts, "command")) {
			ఒకవేళ (ret->force_command != ఖాళీ) {
				errstr = "multiple \"command\" clauses";
				వెళ్ళు fail;
			}
			ret->force_command = opt_dequote(&opts, &errstr);
			ఒకవేళ (ret->force_command == ఖాళీ)
				వెళ్ళు fail;
		} లేకపోతే ఒకవేళ (opt_సరిపోలిక(&opts, "principals")) {
			ఒకవేళ (ret->cert_principals != ఖాళీ) {
				errstr = "multiple \"principals\" clauses";
				వెళ్ళు fail;
			}
			ret->cert_principals = opt_dequote(&opts, &errstr);
			ఒకవేళ (ret->cert_principals == ఖాళీ)
				వెళ్ళు fail;
		} లేకపోతే ఒకవేళ (opt_సరిపోలిక(&opts, "from")) {
			ఒకవేళ (ret->required_from_host_కీలకాలు != ఖాళీ) {
				errstr = "multiple \"from\" clauses";
				వెళ్ళు fail;
			}
			ret->required_from_host_కీలకాలు = opt_dequote(&opts,
			    &errstr);
			ఒకవేళ (ret->required_from_host_కీలకాలు == ఖాళీ)
				వెళ్ళు fail;
		} లేకపోతే ఒకవేళ (opt_సరిపోలిక(&opts, "expiry-time")) {
			ఒకవేళ ((opt = opt_dequote(&opts, &errstr)) == ఖాళీ)
				వెళ్ళు fail;
			ఒకవేళ (parse_absolute_సమయం(opt, &valid_before) != 0 ||
			    valid_before == 0) {
				విడుదల(opt);
				errstr = "invalid expires time";
				వెళ్ళు fail;
			}
			విడుదల(opt);
			ఒకవేళ (ret->valid_before == 0 ||
			    valid_before < ret->valid_before)
				ret->valid_before = valid_before;
		} లేకపోతే ఒకవేళ (opt_సరిపోలిక(&opts, "environment")) {
			ఒకవేళ (ret->nenv > SSH_AUTHOPT_ENV_MAX) {
				errstr = "too many environment strings";
				వెళ్ళు fail;
			}
			ఒకవేళ ((opt = opt_dequote(&opts, &errstr)) == ఖాళీ)
				వెళ్ళు fail;
			/* env name must be alphanumeric and followed by '=' */
			ఒకవేళ ((tmp = strchr(opt, '=')) == ఖాళీ) {
				విడుదల(opt);
				errstr = "invalid environment string";
				వెళ్ళు fail;
			}
			ఒకవేళ ((cp = strdup(opt)) == ఖాళీ) {
				విడుదల(opt);
				వెళ్ళు alloc_fail;
			}
			l = (కొలత_t)(tmp - opt);
			cp[l] = '\0'; /* truncate at '=' */
			ఒకవేళ (!valid_env_name(cp)) {
				విడుదల(cp);
				విడుదల(opt);
				errstr = "invalid environment string";
				వెళ్ళు fail;
			}
			/* Check for duplicates; XXX O(n*log(n)) */
			కొరకు (i = 0; i < ret->nenv; i++) {
				ఒకవేళ (అక్షరశ్రేణి_పోలిక(ret->env[i], cp, l) == 0 &&
				    ret->env[i][l] == '=')
					ఆపు;
			}
			విడుదల(cp);
			/* First match wins */
			ఒకవేళ (i >= ret->nenv) {
				/* Append it. */
				oarray = ret->env;
				ఒకవేళ ((ret->env = recallocarray(ret->env,
				    ret->nenv, ret->nenv + 1,
				    పరిమాణం(*ret->env))) == ఖాళీ) {
					విడుదల(opt);
					/* put it back for cleanup */
					ret->env = oarray;
					వెళ్ళు alloc_fail;
				}
				ret->env[ret->nenv++] = opt;
				opt = ఖాళీ; /* transferred */
			}
			విడుదల(opt);
		} లేకపోతే ఒకవేళ (opt_సరిపోలిక(&opts, "permitopen")) {
			ఒకవేళ (handle_permit(&opts, 0, &ret->permitopen,
			    &ret->npermitopen, &errstr) != 0)
				వెళ్ళు fail;
		} లేకపోతే ఒకవేళ (opt_సరిపోలిక(&opts, "permitlisten")) {
			ఒకవేళ (handle_permit(&opts, 1, &ret->permitlisten,
			    &ret->npermitlisten, &errstr) != 0)
				వెళ్ళు fail;
		} లేకపోతే ఒకవేళ (opt_సరిపోలిక(&opts, "tunnel")) {
			ఒకవేళ ((opt = opt_dequote(&opts, &errstr)) == ఖాళీ)
				వెళ్ళు fail;
			ret->force_tun_device = a2tun(opt, ఖాళీ);
			విడుదల(opt);
			ఒకవేళ (ret->force_tun_device == SSH_TUNID_ERR) {
				errstr = "invalid tun device";
				వెళ్ళు fail;
			}
		}
		/*
		 * Skip the comma, and move to the next option
		 * (or break out if there are no more).
		 */
		ఒకవేళ (*opts == '\0' || *opts == ' ' || *opts == '\t')
			ఆపు;		/* End of options. */
		/* Anything other than a comma is an unknown option */
		ఒకవేళ (*opts != ',') {
			errstr = "unknown key option";
			వెళ్ళు fail;
		}
		opts++;
		ఒకవేళ (*opts == '\0') {
			errstr = "unexpected end-of-options";
			వెళ్ళు fail;
		}
	}

	/* success */
	ఒకవేళ (errstrp != ఖాళీ)
		*errstrp = ఖాళీ;
	తిరిగి ret;

alloc_fail:
	errstr = "memory allocation failed";
fail:
	sshauthopt_free(ret);
	ఒకవేళ (errstrp != ఖాళీ)
		*errstrp = errstr;
	తిరిగి ఖాళీ;
}

నిర్మాణం sshauthopt *
sshauthopt_from_cert(నిర్మాణం sshkey *k)
{
	నిర్మాణం sshauthopt *ret;

	ఒకవేళ (k == ఖాళీ || !sshkey_type_is_cert(k->type) || k->cert == ఖాళీ ||
	    k->cert->type != SSH2_CERT_TYPE_USER)
		తిరిగి ఖాళీ;

	ఒకవేళ ((ret = sshauthopt_new()) == ఖాళీ)
		తిరిగి ఖాళీ;

	/* Handle options and critical extensions separately */
	ఒకవేళ (cert_option_list(ret, k->cert->critical,
	    OPTIONS_CRITICAL, 1) == -1) {
		sshauthopt_free(ret);
		తిరిగి ఖాళీ;
	}
	ఒకవేళ (cert_option_list(ret, k->cert->extensions,
	    OPTIONS_EXTENSIONS, 0) == -1) {
		sshauthopt_free(ret);
		తిరిగి ఖాళీ;
	}
	/* success */
	తిరిగి ret;
}

/*
 * Merges "additional" options to "primary" and returns the result.
 * NB. Some options from primary have primacy.
 */
నిర్మాణం sshauthopt *
sshauthopt_విలీనం(స్థిరరాశి నిర్మాణం sshauthopt *primary,
    స్థిరరాశి నిర్మాణం sshauthopt *additional, స్థిరరాశి అక్షరం **errstrp)
{
	నిర్మాణం sshauthopt *ret;
	స్థిరరాశి అక్షరం *errstr = "internal error";
	స్థిరరాశి అక్షరం *tmp;

	ఒకవేళ (errstrp != ఖాళీ)
		*errstrp = ఖాళీ;

	ఒకవేళ ((ret = sshauthopt_new()) == ఖాళీ)
		వెళ్ళు alloc_fail;

	/* cert_authority and cert_principals are cleared in result */

	/* Prefer access lists from primary. */
	/* XXX err is both set and mismatch? */
	tmp = primary->required_from_host_cert;
	ఒకవేళ (tmp == ఖాళీ)
		tmp = additional->required_from_host_cert;
	ఒకవేళ (tmp != ఖాళీ && (ret->required_from_host_cert = strdup(tmp)) == ఖాళీ)
		వెళ్ళు alloc_fail;
	tmp = primary->required_from_host_కీలకాలు;
	ఒకవేళ (tmp == ఖాళీ)
		tmp = additional->required_from_host_కీలకాలు;
	ఒకవేళ (tmp != ఖాళీ && (ret->required_from_host_కీలకాలు = strdup(tmp)) == ఖాళీ)
		వెళ్ళు alloc_fail;

	/*
	 * force_tun_device, permitopen/permitlisten and environment all
	 * prefer the primary.
	 */
	ret->force_tun_device = primary->force_tun_device;
	ఒకవేళ (ret->force_tun_device == -1)
		ret->force_tun_device = additional->force_tun_device;
	ఒకవేళ (primary->nenv > 0) {
		ఒకవేళ (dup_అక్షరశ్రేణులు(&ret->env, &ret->nenv,
		    primary->env, primary->nenv) != 0)
			వెళ్ళు alloc_fail;
	} లేకపోతే ఒకవేళ (additional->nenv) {
		ఒకవేళ (dup_అక్షరశ్రేణులు(&ret->env, &ret->nenv,
		    additional->env, additional->nenv) != 0)
			వెళ్ళు alloc_fail;
	}
	ఒకవేళ (primary->npermitopen > 0) {
		ఒకవేళ (dup_అక్షరశ్రేణులు(&ret->permitopen, &ret->npermitopen,
		    primary->permitopen, primary->npermitopen) != 0)
			వెళ్ళు alloc_fail;
	} లేకపోతే ఒకవేళ (additional->npermitopen > 0) {
		ఒకవేళ (dup_అక్షరశ్రేణులు(&ret->permitopen, &ret->npermitopen,
		    additional->permitopen, additional->npermitopen) != 0)
			వెళ్ళు alloc_fail;
	}

	ఒకవేళ (primary->npermitlisten > 0) {
		ఒకవేళ (dup_అక్షరశ్రేణులు(&ret->permitlisten, &ret->npermitlisten,
		    primary->permitlisten, primary->npermitlisten) != 0)
			వెళ్ళు alloc_fail;
	} లేకపోతే ఒకవేళ (additional->npermitlisten > 0) {
		ఒకవేళ (dup_అక్షరశ్రేణులు(&ret->permitlisten, &ret->npermitlisten,
		    additional->permitlisten, additional->npermitlisten) != 0)
			వెళ్ళు alloc_fail;
	}

#నిర్వచించు OPTFLAG_AND(x) ret->x = (primary->x == 1) && (additional->x == 1)
#నిర్వచించు OPTFLAG_OR(x) ret->x = (primary->x == 1) || (additional->x == 1)
	/* Permissive flags are logical-AND (i.e. must be set in both) */
	OPTFLAG_AND(permit_పోర్టు_forwarding_flag);
	OPTFLAG_AND(permit_agent_forwarding_flag);
	OPTFLAG_AND(permit_x11_forwarding_flag);
	OPTFLAG_AND(permit_pty_flag);
	OPTFLAG_AND(permit_user_rc);
	OPTFLAG_AND(no_require_user_presence);
	/* Restrictive flags are logical-OR (i.e. must be set in either) */
	OPTFLAG_OR(require_verify);
	OPTFLAG_OR(restricted);
#నిర్వచనం_రద్దు OPTFLAG_AND

	/* Earliest expiry time should win */
	ఒకవేళ (primary->valid_before != 0)
		ret->valid_before = primary->valid_before;
	ఒకవేళ (additional->valid_before != 0 &&
	    additional->valid_before < ret->valid_before)
		ret->valid_before = additional->valid_before;

	/*
	 * When both multiple forced-command are specified, only
	 * proceed if they are identical, otherwise fail.
	 */
	ఒకవేళ (primary->force_command != ఖాళీ &&
	    additional->force_command != ఖాళీ) {
		ఒకవేళ (strcmp(primary->force_command,
		    additional->force_command) == 0) {
			/* ok */
			ret->force_command = strdup(primary->force_command);
			ఒకవేళ (ret->force_command == ఖాళీ)
				వెళ్ళు alloc_fail;
		} లేకపోతే {
			errstr = "forced command options do not match";
			వెళ్ళు fail;
		}
	} లేకపోతే ఒకవేళ (primary->force_command != ఖాళీ) {
		ఒకవేళ ((ret->force_command = strdup(
		    primary->force_command)) == ఖాళీ)
			వెళ్ళు alloc_fail;
	} లేకపోతే ఒకవేళ (additional->force_command != ఖాళీ) {
		ఒకవేళ ((ret->force_command = strdup(
		    additional->force_command)) == ఖాళీ)
			వెళ్ళు alloc_fail;
	}
	/* success */
	ఒకవేళ (errstrp != ఖాళీ)
		*errstrp = ఖాళీ;
	తిరిగి ret;

 alloc_fail:
	errstr = "memory allocation failed";
 fail:
	ఒకవేళ (errstrp != ఖాళీ)
		*errstrp = errstr;
	sshauthopt_free(ret);
	తిరిగి ఖాళీ;
}

/*
 * Copy options
 */
నిర్మాణం sshauthopt *
sshauthopt_copy(స్థిరరాశి నిర్మాణం sshauthopt *orig)
{
	నిర్మాణం sshauthopt *ret;

	ఒకవేళ ((ret = sshauthopt_new()) == ఖాళీ)
		తిరిగి ఖాళీ;

#నిర్వచించు OPTSCALAR(x) ret->x = orig->x
	OPTSCALAR(permit_పోర్టు_forwarding_flag);
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
#నిర్వచనం_రద్దు OPTSCALAR
#నిర్వచించు OPTSTRING(x) \
	చేయి { \
		ఒకవేళ (orig->x != ఖాళీ && (ret->x = strdup(orig->x)) == ఖాళీ) { \
			sshauthopt_free(ret); \
			తిరిగి ఖాళీ; \
		} \
	} అయితే (0)
	OPTSTRING(cert_principals);
	OPTSTRING(force_command);
	OPTSTRING(required_from_host_cert);
	OPTSTRING(required_from_host_కీలకాలు);
#నిర్వచనం_రద్దు OPTSTRING

	ఒకవేళ (dup_అక్షరశ్రేణులు(&ret->env, &ret->nenv, orig->env, orig->nenv) != 0 ||
	    dup_అక్షరశ్రేణులు(&ret->permitopen, &ret->npermitopen,
	    orig->permitopen, orig->npermitopen) != 0 ||
	    dup_అక్షరశ్రేణులు(&ret->permitlisten, &ret->npermitlisten,
	    orig->permitlisten, orig->npermitlisten) != 0) {
		sshauthopt_free(ret);
		తిరిగి ఖాళీ;
	}
	తిరిగి ret;
}

స్థిర పూర్ణాంకం
serialise_array(నిర్మాణం sshbuf *m, అక్షరం **a, కొలత_t n)
{
	నిర్మాణం sshbuf *b;
	కొలత_t i;
	పూర్ణాంకం r = SSH_ERR_అంతర్గత_ERROR;

	ఒకవేళ (n > గరిష్ఠ_పూర్ణాంకం)
		తిరిగి SSH_ERR_అంతర్గత_ERROR;

	ఒకవేళ ((b = sshbuf_new()) == ఖాళీ) {
		తిరిగి SSH_ERR_ALLOC_FAIL;
	}
	కొరకు (i = 0; i < n; i++) {
		ఒకవేళ ((r = sshbuf_put_cstring(b, a[i])) != 0)
			వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((r = sshbuf_put_u32(m, n)) != 0 ||
	    (r = sshbuf_put_stringb(m, b)) != 0)
		వెళ్ళు బహిర్గతం;
	/* success */
	r = 0;
 బహిర్గతం:
	sshbuf_free(b);
	తిరిగి r;
}

స్థిర పూర్ణాంకం
deserialise_array(నిర్మాణం sshbuf *m, అక్షరం ***ap, కొలత_t *np)
{
	అక్షరం **a = ఖాళీ;
	కొలత_t i, n = 0;
	నిర్మాణం sshbuf *b = ఖాళీ;
	u_int tmp;
	పూర్ణాంకం r = SSH_ERR_అంతర్గత_ERROR;

	ఒకవేళ ((r = sshbuf_get_u32(m, &tmp)) != 0 ||
	    (r = sshbuf_froms(m, &b)) != 0)
		వెళ్ళు బహిర్గతం;
	ఒకవేళ (tmp > గరిష్ఠ_పూర్ణాంకం) {
		r = SSH_ERR_INVALID_FORMAT;
		వెళ్ళు బహిర్గతం;
	}
	n = tmp;
	ఒకవేళ (n > 0 && (a = సున్నా_జ్ఞాపకం_ఇవ్వు(n, పరిమాణం(*a))) == ఖాళీ) {
		r = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు బహిర్గతం;
	}
	కొరకు (i = 0; i < n; i++) {
		ఒకవేళ ((r = sshbuf_get_cstring(b, &a[i], ఖాళీ)) != 0)
			వెళ్ళు బహిర్గతం;
	}
	/* success */
	r = 0;
	*ap = a;
	a = ఖాళీ;
	*np = n;
	n = 0;
 బహిర్గతం:
	ఒకవేళ (a != ఖాళీ) {
		కొరకు (i = 0; i < n; i++)
			విడుదల(a[i]);
		విడుదల(a);
	}
	sshbuf_free(b);
	తిరిగి r;
}

స్థిర పూర్ణాంకం
serialise_nullable_string(నిర్మాణం sshbuf *m, స్థిరరాశి అక్షరం *s)
{
	పూర్ణాంకం r;

	ఒకవేళ ((r = sshbuf_put_u8(m, s == ఖాళీ)) != 0 ||
	    (r = sshbuf_put_cstring(m, s)) != 0)
		తిరిగి r;
	తిరిగి 0;
}

స్థిర పూర్ణాంకం
deserialise_nullable_string(నిర్మాణం sshbuf *m, అక్షరం **sp)
{
	పూర్ణాంకం r;
	u_char flag;

	*sp = ఖాళీ;
	ఒకవేళ ((r = sshbuf_get_u8(m, &flag)) != 0 ||
	    (r = sshbuf_get_cstring(m, flag ? ఖాళీ : sp, ఖాళీ)) != 0)
		తిరిగి r;
	తిరిగి 0;
}

పూర్ణాంకం
sshauthopt_serialise(స్థిరరాశి నిర్మాణం sshauthopt *opts, నిర్మాణం sshbuf *m,
    పూర్ణాంకం untrusted)
{
	పూర్ణాంకం r = SSH_ERR_అంతర్గత_ERROR;

	/* Flag options */
	ఒకవేళ ((r = sshbuf_put_u8(m, opts->permit_పోర్టు_forwarding_flag)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->permit_agent_forwarding_flag)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->permit_x11_forwarding_flag)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->permit_pty_flag)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->permit_user_rc)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->restricted)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->cert_authority)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->no_require_user_presence)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->require_verify)) != 0)
		తిరిగి r;

	/* Simple integer options */
	ఒకవేళ ((r = sshbuf_put_u64(m, opts->valid_before)) != 0)
		తిరిగి r;

	/* tunnel number can be negative to indicate "unset" */
	ఒకవేళ ((r = sshbuf_put_u8(m, opts->force_tun_device == -1)) != 0 ||
	    (r = sshbuf_put_u32(m, (opts->force_tun_device < 0) ?
	    0 : (u_int)opts->force_tun_device)) != 0)
		తిరిగి r;

	/* String options; these may be NULL */
	ఒకవేళ ((r = serialise_nullable_string(m,
	    untrusted ? "yes" : opts->cert_principals)) != 0 ||
	    (r = serialise_nullable_string(m,
	    untrusted ? "true" : opts->force_command)) != 0 ||
	    (r = serialise_nullable_string(m,
	    untrusted ? ఖాళీ : opts->required_from_host_cert)) != 0 ||
	    (r = serialise_nullable_string(m,
	    untrusted ? ఖాళీ : opts->required_from_host_కీలకాలు)) != 0)
		తిరిగి r;

	/* Array options */
	ఒకవేళ ((r = serialise_array(m, opts->env,
	    untrusted ? 0 : opts->nenv)) != 0 ||
	    (r = serialise_array(m, opts->permitopen,
	    untrusted ? 0 : opts->npermitopen)) != 0 ||
	    (r = serialise_array(m, opts->permitlisten,
	    untrusted ? 0 : opts->npermitlisten)) != 0)
		తిరిగి r;

	/* success */
	తిరిగి 0;
}

పూర్ణాంకం
sshauthopt_deserialise(నిర్మాణం sshbuf *m, నిర్మాణం sshauthopt **optsp)
{
	నిర్మాణం sshauthopt *opts = ఖాళీ;
	పూర్ణాంకం r = SSH_ERR_అంతర్గత_ERROR;
	u_char f;
	u_int tmp;

	ఒకవేళ ((opts = సున్నా_జ్ఞాపకం_ఇవ్వు(1, పరిమాణం(*opts))) == ఖాళీ)
		తిరిగి SSH_ERR_ALLOC_FAIL;

	/* Flag options */
#నిర్వచించు OPT_FLAG(x) \
	చేయి { \
		ఒకవేళ ((r = sshbuf_get_u8(m, &f)) != 0) \
			వెళ్ళు బహిర్గతం; \
		opts->x = f; \
	} అయితే (0)
	OPT_FLAG(permit_పోర్టు_forwarding_flag);
	OPT_FLAG(permit_agent_forwarding_flag);
	OPT_FLAG(permit_x11_forwarding_flag);
	OPT_FLAG(permit_pty_flag);
	OPT_FLAG(permit_user_rc);
	OPT_FLAG(restricted);
	OPT_FLAG(cert_authority);
	OPT_FLAG(no_require_user_presence);
	OPT_FLAG(require_verify);
#నిర్వచనం_రద్దు OPT_FLAG

	/* Simple integer options */
	ఒకవేళ ((r = sshbuf_get_u64(m, &opts->valid_before)) != 0)
		వెళ్ళు బహిర్గతం;

	/* tunnel number can be negative to indicate "unset" */
	ఒకవేళ ((r = sshbuf_get_u8(m, &f)) != 0 ||
	    (r = sshbuf_get_u32(m, &tmp)) != 0)
		వెళ్ళు బహిర్గతం;
	opts->force_tun_device = f ? -1 : (పూర్ణాంకం)tmp;

	/* String options may be NULL */
	ఒకవేళ ((r = deserialise_nullable_string(m, &opts->cert_principals)) != 0 ||
	    (r = deserialise_nullable_string(m, &opts->force_command)) != 0 ||
	    (r = deserialise_nullable_string(m,
	    &opts->required_from_host_cert)) != 0 ||
	    (r = deserialise_nullable_string(m,
	    &opts->required_from_host_కీలకాలు)) != 0)
		వెళ్ళు బహిర్గతం;

	/* Array options */
	ఒకవేళ ((r = deserialise_array(m, &opts->env, &opts->nenv)) != 0 ||
	    (r = deserialise_array(m,
	    &opts->permitopen, &opts->npermitopen)) != 0 ||
	    (r = deserialise_array(m,
	    &opts->permitlisten, &opts->npermitlisten)) != 0)
		వెళ్ళు బహిర్గతం;

	/* success */
	r = 0;
	*optsp = opts;
	opts = ఖాళీ;
 బహిర్గతం:
	sshauthopt_free(opts);
	తిరిగి r;
}
