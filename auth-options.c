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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <sys/queue.h>

#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <netdb.h>
#अन्तर्भाव <pwd.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <stdint.h>
#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <ctype.h>
#अन्तर्भाव <limits.h>

#अन्तर्भाव "xmalloc.h"
#अन्तर्भाव "ssherr.h"
#अन्तर्भाव "log.h"
#अन्तर्भाव "sshbuf.h"
#अन्तर्भाव "misc.h"
#अन्तर्भाव "sshkey.h"
#अन्तर्भाव "match.h"
#अन्तर्भाव "ssh2.h"
#अन्तर्भाव "auth-options.h"

स्थिर पूर्णाङ्क
dup_वाक्यानि(वर्ण ***dstp, आकार_t *ndstp, वर्ण **src, आकार_t nsrc)
{
	वर्ण **dst;
	आकार_t i, j;

	*dstp = रिक्त;
	*ndstp = 0;

	यदि (nsrc == 0)
		प्रत्यागम 0;
	यदि (nsrc >= SIZE_MAX / परिमाण(*src) ||
	    (dst = शून्यस्मृतिं_देहि(nsrc, परिमाण(*src))) == रिक्त)
		प्रत्यागम -1;
	प्रति (i = 0; i < nsrc; i++) {
		यदि ((dst[i] = strdup(src[i])) == रिक्त) {
			प्रति (j = 0; j < i; j++)
				मुक्त(dst[j]);
			मुक्त(dst);
			प्रत्यागम -1;
		}
	}
	/* success */
	*dstp = dst;
	*ndstp = nsrc;
	प्रत्यागम 0;
}

#परिभाषय OPTIONS_CRITICAL	1
#परिभाषय OPTIONS_EXTENSIONS	2
स्थिर पूर्णाङ्क
cert_option_list(संरचना sshauthopt *opts, संरचना sshbuf *oblob,
    u_int which, पूर्णाङ्क crit)
{
	वर्ण *command, *allowed;
	वर्ण *name = रिक्त;
	संरचना sshbuf *c = रिक्त, *दत्त = रिक्त;
	पूर्णाङ्क r, ret = -1, प्राप्तम्;

	यदि ((c = sshbuf_fromb(oblob)) == रिक्त) {
		error_f("sshbuf_fromb failed");
		गच्छ बहिर्गमनम्;
	}

	यावत् (sshbuf_len(c) > 0) {
		sshbuf_free(दत्त);
		दत्त = रिक्त;
		यदि ((r = sshbuf_get_cstring(c, &name, रिक्त)) != 0 ||
		    (r = sshbuf_froms(c, &दत्त)) != 0) {
			error_r(r, "Unable to parse certificate options");
			गच्छ बहिर्गमनम्;
		}
		debug3("found certificate option \"%.100s\" len %zu",
		    name, sshbuf_len(दत्त));
		प्राप्तम् = 0;
		यदि ((which & OPTIONS_EXTENSIONS) != 0) {
			यदि (वाक्यं_तुलय(name, "no-touch-required") == 0) {
				opts->no_require_user_presence = 1;
				प्राप्तम् = 1;
			} अन्यथा यदि (वाक्यं_तुलय(name, "permit-X11-forwarding") == 0) {
				opts->permit_x11_forwarding_flag = 1;
				प्राप्तम् = 1;
			} अन्यथा यदि (वाक्यं_तुलय(name,
			    "permit-agent-forwarding") == 0) {
				opts->permit_agent_forwarding_flag = 1;
				प्राप्तम् = 1;
			} अन्यथा यदि (वाक्यं_तुलय(name,
			    "permit-port-forwarding") == 0) {
				opts->permit_पत्तनम्_forwarding_flag = 1;
				प्राप्तम् = 1;
			} अन्यथा यदि (वाक्यं_तुलय(name, "permit-pty") == 0) {
				opts->permit_pty_flag = 1;
				प्राप्तम् = 1;
			} अन्यथा यदि (वाक्यं_तुलय(name, "permit-user-rc") == 0) {
				opts->permit_user_rc = 1;
				प्राप्तम् = 1;
			}
		}
		यदि (!प्राप्तम् && (which & OPTIONS_CRITICAL) != 0) {
			यदि (वाक्यं_तुलय(name, "verify-required") == 0) {
				opts->require_verify = 1;
				प्राप्तम् = 1;
			} अन्यथा यदि (वाक्यं_तुलय(name, "force-command") == 0) {
				यदि ((r = sshbuf_get_cstring(दत्त, &command,
				    रिक्त)) != 0) {
					error_r(r, "Unable to parse \"%s\" "
					    "section", name);
					गच्छ बहिर्गमनम्;
				}
				यदि (opts->force_command != रिक्त) {
					error("Certificate has multiple "
					    "force-command options");
					मुक्त(command);
					गच्छ बहिर्गमनम्;
				}
				opts->force_command = command;
				प्राप्तम् = 1;
			} अन्यथा यदि (वाक्यं_तुलय(name, "source-address") == 0) {
				यदि ((r = sshbuf_get_cstring(दत्त, &allowed,
				    रिक्त)) != 0) {
					error_r(r, "Unable to parse \"%s\" "
					    "section", name);
					गच्छ बहिर्गमनम्;
				}
				यदि (opts->required_from_host_cert != रिक्त) {
					error("Certificate has multiple "
					    "source-address options");
					मुक्त(allowed);
					गच्छ बहिर्गमनम्;
				}
				/* Check syntax */
				यदि (addr_मेलनम्_cidr_list(रिक्त, allowed) == -1) {
					error("Certificate source-address "
					    "contents invalid");
					मुक्त(allowed);
					गच्छ बहिर्गमनम्;
				}
				opts->required_from_host_cert = allowed;
				प्राप्तम् = 1;
			}
		}

		यदि (!प्राप्तम्) {
			यदि (crit) {
				error("Certificate critical option \"%s\" "
				    "is not supported", name);
				गच्छ बहिर्गमनम्;
			} अन्यथा {
				logit("Certificate extension \"%s\" "
				    "is not supported", name);
			}
		} अन्यथा यदि (sshbuf_len(दत्त) != 0) {
			error("Certificate option \"%s\" corrupt "
			    "(extra data)", name);
			गच्छ बहिर्गमनम्;
		}
		मुक्त(name);
		name = रिक्त;
	}
	/* successfully parsed all options */
	ret = 0;

 बहिर्गमनम्:
	मुक्त(name);
	sshbuf_free(दत्त);
	sshbuf_free(c);
	प्रत्यागम ret;
}

संरचना sshauthopt *
sshauthopt_new(शून्य)
{
	संरचना sshauthopt *ret;

	यदि ((ret = शून्यस्मृतिं_देहि(1, परिमाण(*ret))) == रिक्त)
		प्रत्यागम रिक्त;
	ret->force_tun_device = -1;
	प्रत्यागम ret;
}

शून्य
sshauthopt_free(संरचना sshauthopt *opts)
{
	आकार_t i;

	यदि (opts == रिक्त)
		प्रत्यागम;

	मुक्त(opts->cert_principals);
	मुक्त(opts->force_command);
	मुक्त(opts->required_from_host_cert);
	मुक्त(opts->required_from_host_कुञ्चिकाः);

	प्रति (i = 0; i < opts->nenv; i++)
		मुक्त(opts->env[i]);
	मुक्त(opts->env);

	प्रति (i = 0; i < opts->npermitopen; i++)
		मुक्त(opts->permitopen[i]);
	मुक्त(opts->permitopen);

	प्रति (i = 0; i < opts->npermitlisten; i++)
		मुक्त(opts->permitlisten[i]);
	मुक्त(opts->permitlisten);

	freezero(opts, परिमाण(*opts));
}

संरचना sshauthopt *
sshauthopt_new_with_कुञ्चिकाः_defaults(शून्य)
{
	संरचना sshauthopt *ret = रिक्त;

	यदि ((ret = sshauthopt_new()) == रिक्त)
		प्रत्यागम रिक्त;

	/* Defaults for authorized_keys flags */
	ret->permit_पत्तनम्_forwarding_flag = 1;
	ret->permit_agent_forwarding_flag = 1;
	ret->permit_x11_forwarding_flag = 1;
	ret->permit_pty_flag = 1;
	ret->permit_user_rc = 1;
	प्रत्यागम ret;
}

/*
 * Parse and record a permitopen/permitlisten directive.
 * Return 0 on success. Return -1 on failure and sets *errstrp to error reason.
 */
स्थिर पूर्णाङ्क
handle_permit(ध्रुव वर्ण **optsp, पूर्णाङ्क allow_bare_पत्तनम्,
    वर्ण ***permitsp, आकार_t *npermitsp, ध्रुव वर्ण **errstrp)
{
	वर्ण *opt, *tmp, *cp, *host, **permits = *permitsp;
	आकार_t npermits = *npermitsp;
	ध्रुव वर्ण *errstr = "unknown error";

	यदि (npermits > SSH_AUTHOPT_PERMIT_MAX) {
		*errstrp = "too many permission directives";
		प्रत्यागम -1;
	}
	यदि ((opt = opt_dequote(optsp, &errstr)) == रिक्त) {
		प्रत्यागम -1;
	}
	यदि (allow_bare_पत्तनम् && strchr(opt, ':') == रिक्त) {
		/*
		 * Allow a bare port number in permitlisten to indicate a
		 * listen_host wildcard.
		 */
		यदि (asprintf(&tmp, "*:%s", opt) == -1) {
			मुक्त(opt);
			*errstrp = "memory allocation failed";
			प्रत्यागम -1;
		}
		मुक्त(opt);
		opt = tmp;
	}
	यदि ((tmp = strdup(opt)) == रिक्त) {
		मुक्त(opt);
		*errstrp = "memory allocation failed";
		प्रत्यागम -1;
	}
	cp = tmp;
	/* validate syntax before recording it. */
	host = hpdelim2(&cp, रिक्त);
	यदि (host == रिक्त || वाक्यदैर्घ्यम्(host) >= NI_MAXHOST) {
		मुक्त(tmp);
		मुक्त(opt);
		*errstrp = "invalid permission hostname";
		प्रत्यागम -1;
	}
	/*
	 * don't want to use permitopen_port to avoid
	 * dependency on channels.[ch] here.
	 */
	यदि (cp == रिक्त ||
	    (वाक्यं_तुलय(cp, "*") != 0 && a2port(cp) <= 0)) {
		मुक्त(tmp);
		मुक्त(opt);
		*errstrp = "invalid permission port";
		प्रत्यागम -1;
	}
	/* XXX - add streamlocal support */
	मुक्त(tmp);
	/* Record it */
	यदि ((permits = recallocarray(permits, npermits, npermits + 1,
	    परिमाण(*permits))) == रिक्त) {
		मुक्त(opt);
		/* NB. don't update *permitsp if alloc fails */
		*errstrp = "memory allocation failed";
		प्रत्यागम -1;
	}
	permits[npermits++] = opt;
	*permitsp = permits;
	*npermitsp = npermits;
	प्रत्यागम 0;
}

संरचना sshauthopt *
sshauthopt_parse(ध्रुव वर्ण *opts, ध्रुव वर्ण **errstrp)
{
	वर्ण **oarray, *opt, *cp, *tmp;
	पूर्णाङ्क r;
	संरचना sshauthopt *ret = रिक्त;
	ध्रुव वर्ण *errstr = "unknown error";
	uint64_t valid_before;
	आकार_t i, l;

	यदि (errstrp != रिक्त)
		*errstrp = रिक्त;
	यदि ((ret = sshauthopt_new_with_कुञ्चिकाः_defaults()) == रिक्त)
		गच्छ alloc_fail;

	यदि (opts == रिक्त)
		प्रत्यागम ret;

	यावत् (*opts && *opts != ' ' && *opts != '\t') {
		/* flag options */
		यदि ((r = opt_flag("restrict", 0, &opts)) != -1) {
			ret->restricted = 1;
			ret->permit_पत्तनम्_forwarding_flag = 0;
			ret->permit_agent_forwarding_flag = 0;
			ret->permit_x11_forwarding_flag = 0;
			ret->permit_pty_flag = 0;
			ret->permit_user_rc = 0;
		} अन्यथा यदि ((r = opt_flag("cert-authority", 0, &opts)) != -1) {
			ret->cert_authority = r;
		} अन्यथा यदि ((r = opt_flag("port-forwarding", 1, &opts)) != -1) {
			ret->permit_पत्तनम्_forwarding_flag = r == 1;
		} अन्यथा यदि ((r = opt_flag("agent-forwarding", 1, &opts)) != -1) {
			ret->permit_agent_forwarding_flag = r == 1;
		} अन्यथा यदि ((r = opt_flag("x11-forwarding", 1, &opts)) != -1) {
			ret->permit_x11_forwarding_flag = r == 1;
		} अन्यथा यदि ((r = opt_flag("touch-required", 1, &opts)) != -1) {
			ret->no_require_user_presence = r != 1; /* NB. flip */
		} अन्यथा यदि ((r = opt_flag("verify-required", 1, &opts)) != -1) {
			ret->require_verify = r == 1;
		} अन्यथा यदि ((r = opt_flag("pty", 1, &opts)) != -1) {
			ret->permit_pty_flag = r == 1;
		} अन्यथा यदि ((r = opt_flag("user-rc", 1, &opts)) != -1) {
			ret->permit_user_rc = r == 1;
		} अन्यथा यदि (opt_मेलनम्(&opts, "command")) {
			यदि (ret->force_command != रिक्त) {
				errstr = "multiple \"command\" clauses";
				गच्छ fail;
			}
			ret->force_command = opt_dequote(&opts, &errstr);
			यदि (ret->force_command == रिक्त)
				गच्छ fail;
		} अन्यथा यदि (opt_मेलनम्(&opts, "principals")) {
			यदि (ret->cert_principals != रिक्त) {
				errstr = "multiple \"principals\" clauses";
				गच्छ fail;
			}
			ret->cert_principals = opt_dequote(&opts, &errstr);
			यदि (ret->cert_principals == रिक्त)
				गच्छ fail;
		} अन्यथा यदि (opt_मेलनम्(&opts, "from")) {
			यदि (ret->required_from_host_कुञ्चिकाः != रिक्त) {
				errstr = "multiple \"from\" clauses";
				गच्छ fail;
			}
			ret->required_from_host_कुञ्चिकाः = opt_dequote(&opts,
			    &errstr);
			यदि (ret->required_from_host_कुञ्चिकाः == रिक्त)
				गच्छ fail;
		} अन्यथा यदि (opt_मेलनम्(&opts, "expiry-time")) {
			यदि ((opt = opt_dequote(&opts, &errstr)) == रिक्त)
				गच्छ fail;
			यदि (parse_absolute_time(opt, &valid_before) != 0 ||
			    valid_before == 0) {
				मुक्त(opt);
				errstr = "invalid expires time";
				गच्छ fail;
			}
			मुक्त(opt);
			यदि (ret->valid_before == 0 ||
			    valid_before < ret->valid_before)
				ret->valid_before = valid_before;
		} अन्यथा यदि (opt_मेलनम्(&opts, "environment")) {
			यदि (ret->nenv > SSH_AUTHOPT_ENV_MAX) {
				errstr = "too many environment strings";
				गच्छ fail;
			}
			यदि ((opt = opt_dequote(&opts, &errstr)) == रिक्त)
				गच्छ fail;
			/* env name must be alphanumeric and followed by '=' */
			यदि ((tmp = strchr(opt, '=')) == रिक्त) {
				मुक्त(opt);
				errstr = "invalid environment string";
				गच्छ fail;
			}
			यदि ((cp = strdup(opt)) == रिक्त) {
				मुक्त(opt);
				गच्छ alloc_fail;
			}
			l = (आकार_t)(tmp - opt);
			cp[l] = '\0'; /* truncate at '=' */
			यदि (!valid_env_name(cp)) {
				मुक्त(cp);
				मुक्त(opt);
				errstr = "invalid environment string";
				गच्छ fail;
			}
			/* Check for duplicates; XXX O(n*log(n)) */
			प्रति (i = 0; i < ret->nenv; i++) {
				यदि (वाक्ये_तुलय(ret->env[i], cp, l) == 0 &&
				    ret->env[i][l] == '=')
					भङ्ग;
			}
			मुक्त(cp);
			/* First match wins */
			यदि (i >= ret->nenv) {
				/* Append it. */
				oarray = ret->env;
				यदि ((ret->env = recallocarray(ret->env,
				    ret->nenv, ret->nenv + 1,
				    परिमाण(*ret->env))) == रिक्त) {
					मुक्त(opt);
					/* put it back for cleanup */
					ret->env = oarray;
					गच्छ alloc_fail;
				}
				ret->env[ret->nenv++] = opt;
				opt = रिक्त; /* transferred */
			}
			मुक्त(opt);
		} अन्यथा यदि (opt_मेलनम्(&opts, "permitopen")) {
			यदि (handle_permit(&opts, 0, &ret->permitopen,
			    &ret->npermitopen, &errstr) != 0)
				गच्छ fail;
		} अन्यथा यदि (opt_मेलनम्(&opts, "permitlisten")) {
			यदि (handle_permit(&opts, 1, &ret->permitlisten,
			    &ret->npermitlisten, &errstr) != 0)
				गच्छ fail;
		} अन्यथा यदि (opt_मेलनम्(&opts, "tunnel")) {
			यदि ((opt = opt_dequote(&opts, &errstr)) == रिक्त)
				गच्छ fail;
			ret->force_tun_device = a2tun(opt, रिक्त);
			मुक्त(opt);
			यदि (ret->force_tun_device == SSH_TUNID_ERR) {
				errstr = "invalid tun device";
				गच्छ fail;
			}
		}
		/*
		 * Skip the comma, and move to the next option
		 * (or break out if there are no more).
		 */
		यदि (*opts == '\0' || *opts == ' ' || *opts == '\t')
			भङ्ग;		/* End of options. */
		/* Anything other than a comma is an unknown option */
		यदि (*opts != ',') {
			errstr = "unknown key option";
			गच्छ fail;
		}
		opts++;
		यदि (*opts == '\0') {
			errstr = "unexpected end-of-options";
			गच्छ fail;
		}
	}

	/* success */
	यदि (errstrp != रिक्त)
		*errstrp = रिक्त;
	प्रत्यागम ret;

alloc_fail:
	errstr = "memory allocation failed";
fail:
	sshauthopt_free(ret);
	यदि (errstrp != रिक्त)
		*errstrp = errstr;
	प्रत्यागम रिक्त;
}

संरचना sshauthopt *
sshauthopt_from_cert(संरचना sshkey *k)
{
	संरचना sshauthopt *ret;

	यदि (k == रिक्त || !sshkey_type_is_cert(k->type) || k->cert == रिक्त ||
	    k->cert->type != SSH2_CERT_TYPE_USER)
		प्रत्यागम रिक्त;

	यदि ((ret = sshauthopt_new()) == रिक्त)
		प्रत्यागम रिक्त;

	/* Handle options and critical extensions separately */
	यदि (cert_option_list(ret, k->cert->critical,
	    OPTIONS_CRITICAL, 1) == -1) {
		sshauthopt_free(ret);
		प्रत्यागम रिक्त;
	}
	यदि (cert_option_list(ret, k->cert->extensions,
	    OPTIONS_EXTENSIONS, 0) == -1) {
		sshauthopt_free(ret);
		प्रत्यागम रिक्त;
	}
	/* success */
	प्रत्यागम ret;
}

/*
 * Merges "additional" options to "primary" and returns the result.
 * NB. Some options from primary have primacy.
 */
संरचना sshauthopt *
sshauthopt_merge(ध्रुव संरचना sshauthopt *primary,
    ध्रुव संरचना sshauthopt *additional, ध्रुव वर्ण **errstrp)
{
	संरचना sshauthopt *ret;
	ध्रुव वर्ण *errstr = "internal error";
	ध्रुव वर्ण *tmp;

	यदि (errstrp != रिक्त)
		*errstrp = रिक्त;

	यदि ((ret = sshauthopt_new()) == रिक्त)
		गच्छ alloc_fail;

	/* cert_authority and cert_principals are cleared in result */

	/* Prefer access lists from primary. */
	/* XXX err is both set and mismatch? */
	tmp = primary->required_from_host_cert;
	यदि (tmp == रिक्त)
		tmp = additional->required_from_host_cert;
	यदि (tmp != रिक्त && (ret->required_from_host_cert = strdup(tmp)) == रिक्त)
		गच्छ alloc_fail;
	tmp = primary->required_from_host_कुञ्चिकाः;
	यदि (tmp == रिक्त)
		tmp = additional->required_from_host_कुञ्चिकाः;
	यदि (tmp != रिक्त && (ret->required_from_host_कुञ्चिकाः = strdup(tmp)) == रिक्त)
		गच्छ alloc_fail;

	/*
	 * force_tun_device, permitopen/permitlisten and environment all
	 * prefer the primary.
	 */
	ret->force_tun_device = primary->force_tun_device;
	यदि (ret->force_tun_device == -1)
		ret->force_tun_device = additional->force_tun_device;
	यदि (primary->nenv > 0) {
		यदि (dup_वाक्यानि(&ret->env, &ret->nenv,
		    primary->env, primary->nenv) != 0)
			गच्छ alloc_fail;
	} अन्यथा यदि (additional->nenv) {
		यदि (dup_वाक्यानि(&ret->env, &ret->nenv,
		    additional->env, additional->nenv) != 0)
			गच्छ alloc_fail;
	}
	यदि (primary->npermitopen > 0) {
		यदि (dup_वाक्यानि(&ret->permitopen, &ret->npermitopen,
		    primary->permitopen, primary->npermitopen) != 0)
			गच्छ alloc_fail;
	} अन्यथा यदि (additional->npermitopen > 0) {
		यदि (dup_वाक्यानि(&ret->permitopen, &ret->npermitopen,
		    additional->permitopen, additional->npermitopen) != 0)
			गच्छ alloc_fail;
	}

	यदि (primary->npermitlisten > 0) {
		यदि (dup_वाक्यानि(&ret->permitlisten, &ret->npermitlisten,
		    primary->permitlisten, primary->npermitlisten) != 0)
			गच्छ alloc_fail;
	} अन्यथा यदि (additional->npermitlisten > 0) {
		यदि (dup_वाक्यानि(&ret->permitlisten, &ret->npermitlisten,
		    additional->permitlisten, additional->npermitlisten) != 0)
			गच्छ alloc_fail;
	}

#परिभाषय OPTFLAG_AND(x) ret->x = (primary->x == 1) && (additional->x == 1)
#परिभाषय OPTFLAG_OR(x) ret->x = (primary->x == 1) || (additional->x == 1)
	/* Permissive flags are logical-AND (i.e. must be set in both) */
	OPTFLAG_AND(permit_पत्तनम्_forwarding_flag);
	OPTFLAG_AND(permit_agent_forwarding_flag);
	OPTFLAG_AND(permit_x11_forwarding_flag);
	OPTFLAG_AND(permit_pty_flag);
	OPTFLAG_AND(permit_user_rc);
	OPTFLAG_AND(no_require_user_presence);
	/* Restrictive flags are logical-OR (i.e. must be set in either) */
	OPTFLAG_OR(require_verify);
	OPTFLAG_OR(restricted);
#अपरिभाषय OPTFLAG_AND

	/* Earliest expiry time should win */
	यदि (primary->valid_before != 0)
		ret->valid_before = primary->valid_before;
	यदि (additional->valid_before != 0 &&
	    additional->valid_before < ret->valid_before)
		ret->valid_before = additional->valid_before;

	/*
	 * When both multiple forced-command are specified, only
	 * proceed if they are identical, otherwise fail.
	 */
	यदि (primary->force_command != रिक्त &&
	    additional->force_command != रिक्त) {
		यदि (वाक्यं_तुलय(primary->force_command,
		    additional->force_command) == 0) {
			/* ok */
			ret->force_command = strdup(primary->force_command);
			यदि (ret->force_command == रिक्त)
				गच्छ alloc_fail;
		} अन्यथा {
			errstr = "forced command options do not match";
			गच्छ fail;
		}
	} अन्यथा यदि (primary->force_command != रिक्त) {
		यदि ((ret->force_command = strdup(
		    primary->force_command)) == रिक्त)
			गच्छ alloc_fail;
	} अन्यथा यदि (additional->force_command != रिक्त) {
		यदि ((ret->force_command = strdup(
		    additional->force_command)) == रिक्त)
			गच्छ alloc_fail;
	}
	/* success */
	यदि (errstrp != रिक्त)
		*errstrp = रिक्त;
	प्रत्यागम ret;

 alloc_fail:
	errstr = "memory allocation failed";
 fail:
	यदि (errstrp != रिक्त)
		*errstrp = errstr;
	sshauthopt_free(ret);
	प्रत्यागम रिक्त;
}

/*
 * Copy options
 */
संरचना sshauthopt *
sshauthopt_copy(ध्रुव संरचना sshauthopt *orig)
{
	संरचना sshauthopt *ret;

	यदि ((ret = sshauthopt_new()) == रिक्त)
		प्रत्यागम रिक्त;

#परिभाषय OPTSCALAR(x) ret->x = orig->x
	OPTSCALAR(permit_पत्तनम्_forwarding_flag);
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
#अपरिभाषय OPTSCALAR
#परिभाषय OPTSTRING(x) \
	कुरु { \
		यदि (orig->x != रिक्त && (ret->x = strdup(orig->x)) == रिक्त) { \
			sshauthopt_free(ret); \
			प्रत्यागम रिक्त; \
		} \
	} यावत् (0)
	OPTSTRING(cert_principals);
	OPTSTRING(force_command);
	OPTSTRING(required_from_host_cert);
	OPTSTRING(required_from_host_कुञ्चिकाः);
#अपरिभाषय OPTSTRING

	यदि (dup_वाक्यानि(&ret->env, &ret->nenv, orig->env, orig->nenv) != 0 ||
	    dup_वाक्यानि(&ret->permitopen, &ret->npermitopen,
	    orig->permitopen, orig->npermitopen) != 0 ||
	    dup_वाक्यानि(&ret->permitlisten, &ret->npermitlisten,
	    orig->permitlisten, orig->npermitlisten) != 0) {
		sshauthopt_free(ret);
		प्रत्यागम रिक्त;
	}
	प्रत्यागम ret;
}

स्थिर पूर्णाङ्क
serialise_array(संरचना sshbuf *m, वर्ण **a, आकार_t n)
{
	संरचना sshbuf *b;
	आकार_t i;
	पूर्णाङ्क r = SSH_ERR_आन्तरिकम्_ERROR;

	यदि (n > अधिकतम_पूर्णाङ्कः)
		प्रत्यागम SSH_ERR_आन्तरिकम्_ERROR;

	यदि ((b = sshbuf_new()) == रिक्त) {
		प्रत्यागम SSH_ERR_ALLOC_FAIL;
	}
	प्रति (i = 0; i < n; i++) {
		यदि ((r = sshbuf_put_cstring(b, a[i])) != 0)
			गच्छ बहिर्गमनम्;
	}
	यदि ((r = sshbuf_put_u32(m, n)) != 0 ||
	    (r = sshbuf_put_stringb(m, b)) != 0)
		गच्छ बहिर्गमनम्;
	/* success */
	r = 0;
 बहिर्गमनम्:
	sshbuf_free(b);
	प्रत्यागम r;
}

स्थिर पूर्णाङ्क
deserialise_array(संरचना sshbuf *m, वर्ण ***ap, आकार_t *np)
{
	वर्ण **a = रिक्त;
	आकार_t i, n = 0;
	संरचना sshbuf *b = रिक्त;
	u_int tmp;
	पूर्णाङ्क r = SSH_ERR_आन्तरिकम्_ERROR;

	यदि ((r = sshbuf_get_u32(m, &tmp)) != 0 ||
	    (r = sshbuf_froms(m, &b)) != 0)
		गच्छ बहिर्गमनम्;
	यदि (tmp > अधिकतम_पूर्णाङ्कः) {
		r = SSH_ERR_INVALID_FORMAT;
		गच्छ बहिर्गमनम्;
	}
	n = tmp;
	यदि (n > 0 && (a = शून्यस्मृतिं_देहि(n, परिमाण(*a))) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ बहिर्गमनम्;
	}
	प्रति (i = 0; i < n; i++) {
		यदि ((r = sshbuf_get_cstring(b, &a[i], रिक्त)) != 0)
			गच्छ बहिर्गमनम्;
	}
	/* success */
	r = 0;
	*ap = a;
	a = रिक्त;
	*np = n;
	n = 0;
 बहिर्गमनम्:
	यदि (a != रिक्त) {
		प्रति (i = 0; i < n; i++)
			मुक्त(a[i]);
		मुक्त(a);
	}
	sshbuf_free(b);
	प्रत्यागम r;
}

स्थिर पूर्णाङ्क
serialise_nullable_string(संरचना sshbuf *m, ध्रुव वर्ण *s)
{
	पूर्णाङ्क r;

	यदि ((r = sshbuf_put_u8(m, s == रिक्त)) != 0 ||
	    (r = sshbuf_put_cstring(m, s)) != 0)
		प्रत्यागम r;
	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
deserialise_nullable_string(संरचना sshbuf *m, वर्ण **sp)
{
	पूर्णाङ्क r;
	u_char flag;

	*sp = रिक्त;
	यदि ((r = sshbuf_get_u8(m, &flag)) != 0 ||
	    (r = sshbuf_get_cstring(m, flag ? रिक्त : sp, रिक्त)) != 0)
		प्रत्यागम r;
	प्रत्यागम 0;
}

पूर्णाङ्क
sshauthopt_serialise(ध्रुव संरचना sshauthopt *opts, संरचना sshbuf *m,
    पूर्णाङ्क untrusted)
{
	पूर्णाङ्क r = SSH_ERR_आन्तरिकम्_ERROR;

	/* Flag options */
	यदि ((r = sshbuf_put_u8(m, opts->permit_पत्तनम्_forwarding_flag)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->permit_agent_forwarding_flag)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->permit_x11_forwarding_flag)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->permit_pty_flag)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->permit_user_rc)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->restricted)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->cert_authority)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->no_require_user_presence)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->require_verify)) != 0)
		प्रत्यागम r;

	/* Simple integer options */
	यदि ((r = sshbuf_put_u64(m, opts->valid_before)) != 0)
		प्रत्यागम r;

	/* tunnel number can be negative to indicate "unset" */
	यदि ((r = sshbuf_put_u8(m, opts->force_tun_device == -1)) != 0 ||
	    (r = sshbuf_put_u32(m, (opts->force_tun_device < 0) ?
	    0 : (u_int)opts->force_tun_device)) != 0)
		प्रत्यागम r;

	/* String options; these may be NULL */
	यदि ((r = serialise_nullable_string(m,
	    untrusted ? "yes" : opts->cert_principals)) != 0 ||
	    (r = serialise_nullable_string(m,
	    untrusted ? "true" : opts->force_command)) != 0 ||
	    (r = serialise_nullable_string(m,
	    untrusted ? रिक्त : opts->required_from_host_cert)) != 0 ||
	    (r = serialise_nullable_string(m,
	    untrusted ? रिक्त : opts->required_from_host_कुञ्चिकाः)) != 0)
		प्रत्यागम r;

	/* Array options */
	यदि ((r = serialise_array(m, opts->env,
	    untrusted ? 0 : opts->nenv)) != 0 ||
	    (r = serialise_array(m, opts->permitopen,
	    untrusted ? 0 : opts->npermitopen)) != 0 ||
	    (r = serialise_array(m, opts->permitlisten,
	    untrusted ? 0 : opts->npermitlisten)) != 0)
		प्रत्यागम r;

	/* success */
	प्रत्यागम 0;
}

पूर्णाङ्क
sshauthopt_deserialise(संरचना sshbuf *m, संरचना sshauthopt **optsp)
{
	संरचना sshauthopt *opts = रिक्त;
	पूर्णाङ्क r = SSH_ERR_आन्तरिकम्_ERROR;
	u_char f;
	u_int tmp;

	यदि ((opts = शून्यस्मृतिं_देहि(1, परिमाण(*opts))) == रिक्त)
		प्रत्यागम SSH_ERR_ALLOC_FAIL;

	/* Flag options */
#परिभाषय OPT_FLAG(x) \
	कुरु { \
		यदि ((r = sshbuf_get_u8(m, &f)) != 0) \
			गच्छ बहिर्गमनम्; \
		opts->x = f; \
	} यावत् (0)
	OPT_FLAG(permit_पत्तनम्_forwarding_flag);
	OPT_FLAG(permit_agent_forwarding_flag);
	OPT_FLAG(permit_x11_forwarding_flag);
	OPT_FLAG(permit_pty_flag);
	OPT_FLAG(permit_user_rc);
	OPT_FLAG(restricted);
	OPT_FLAG(cert_authority);
	OPT_FLAG(no_require_user_presence);
	OPT_FLAG(require_verify);
#अपरिभाषय OPT_FLAG

	/* Simple integer options */
	यदि ((r = sshbuf_get_u64(m, &opts->valid_before)) != 0)
		गच्छ बहिर्गमनम्;

	/* tunnel number can be negative to indicate "unset" */
	यदि ((r = sshbuf_get_u8(m, &f)) != 0 ||
	    (r = sshbuf_get_u32(m, &tmp)) != 0)
		गच्छ बहिर्गमनम्;
	opts->force_tun_device = f ? -1 : (पूर्णाङ्क)tmp;

	/* String options may be NULL */
	यदि ((r = deserialise_nullable_string(m, &opts->cert_principals)) != 0 ||
	    (r = deserialise_nullable_string(m, &opts->force_command)) != 0 ||
	    (r = deserialise_nullable_string(m,
	    &opts->required_from_host_cert)) != 0 ||
	    (r = deserialise_nullable_string(m,
	    &opts->required_from_host_कुञ्चिकाः)) != 0)
		गच्छ बहिर्गमनम्;

	/* Array options */
	यदि ((r = deserialise_array(m, &opts->env, &opts->nenv)) != 0 ||
	    (r = deserialise_array(m,
	    &opts->permitopen, &opts->npermitopen)) != 0 ||
	    (r = deserialise_array(m,
	    &opts->permitlisten, &opts->npermitlisten)) != 0)
		गच्छ बहिर्गमनम्;

	/* success */
	r = 0;
	*optsp = opts;
	opts = रिक्त;
 बहिर्गमनम्:
	sshauthopt_free(opts);
	प्रत्यागम r;
}
