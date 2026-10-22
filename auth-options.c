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

स्थिर पूर्णांक
dup_strings(अक्षर ***dstp, माप_प्रकार *ndstp, अक्षर **src, माप_प्रकार nsrc)
{
	अक्षर **dst;
	माप_प्रकार i, j;

	*dstp = रिक्त;
	*ndstp = 0;

	जर (nsrc == 0)
		परत 0;
	जर (nsrc >= SIZE_MAX / आकार(*src) ||
	    (dst = सुस्मृति(nsrc, आकार(*src))) == रिक्त)
		परत -1;
	साठी (i = 0; i < nsrc; i++) {
		जर ((dst[i] = strdup(src[i])) == रिक्त) {
			साठी (j = 0; j < i; j++)
				मुक्त(dst[j]);
			मुक्त(dst);
			परत -1;
		}
	}
	/* success */
	*dstp = dst;
	*ndstp = nsrc;
	परत 0;
}

#define OPTIONS_CRITICAL	1
#define OPTIONS_EXTENSIONS	2
स्थिर पूर्णांक
cert_option_list(संरचना sshauthopt *opts, संरचना sshbuf *oblob,
    u_int which, पूर्णांक crit)
{
	अक्षर *command, *allowed;
	अक्षर *name = रिक्त;
	संरचना sshbuf *c = रिक्त, *data = रिक्त;
	पूर्णांक r, ret = -1, found;

	जर ((c = sshbuf_fromb(oblob)) == रिक्त) {
		error_f("sshbuf_fromb failed");
		जा out;
	}

	पर्यंत (sshbuf_len(c) > 0) {
		sshbuf_free(data);
		data = रिक्त;
		जर ((r = sshbuf_get_cstring(c, &name, रिक्त)) != 0 ||
		    (r = sshbuf_froms(c, &data)) != 0) {
			error_r(r, "Unable to parse certificate options");
			जा out;
		}
		debug3("found certificate option \"%.100s\" len %zu",
		    name, sshbuf_len(data));
		found = 0;
		जर ((which & OPTIONS_EXTENSIONS) != 0) {
			जर (म_भेद(name, "no-touch-required") == 0) {
				opts->no_require_user_presence = 1;
				found = 1;
			} अन्यथा जर (म_भेद(name, "permit-X11-forwarding") == 0) {
				opts->permit_x11_forwarding_flag = 1;
				found = 1;
			} अन्यथा जर (म_भेद(name,
			    "permit-agent-forwarding") == 0) {
				opts->permit_agent_forwarding_flag = 1;
				found = 1;
			} अन्यथा जर (म_भेद(name,
			    "permit-port-forwarding") == 0) {
				opts->permit_port_forwarding_flag = 1;
				found = 1;
			} अन्यथा जर (म_भेद(name, "permit-pty") == 0) {
				opts->permit_pty_flag = 1;
				found = 1;
			} अन्यथा जर (म_भेद(name, "permit-user-rc") == 0) {
				opts->permit_user_rc = 1;
				found = 1;
			}
		}
		जर (!found && (which & OPTIONS_CRITICAL) != 0) {
			जर (म_भेद(name, "verify-required") == 0) {
				opts->require_verify = 1;
				found = 1;
			} अन्यथा जर (म_भेद(name, "force-command") == 0) {
				जर ((r = sshbuf_get_cstring(data, &command,
				    रिक्त)) != 0) {
					error_r(r, "Unable to parse \"%s\" "
					    "section", name);
					जा out;
				}
				जर (opts->force_command != रिक्त) {
					error("Certificate has multiple "
					    "force-command options");
					मुक्त(command);
					जा out;
				}
				opts->force_command = command;
				found = 1;
			} अन्यथा जर (म_भेद(name, "source-address") == 0) {
				जर ((r = sshbuf_get_cstring(data, &allowed,
				    रिक्त)) != 0) {
					error_r(r, "Unable to parse \"%s\" "
					    "section", name);
					जा out;
				}
				जर (opts->required_from_host_cert != रिक्त) {
					error("Certificate has multiple "
					    "source-address options");
					मुक्त(allowed);
					जा out;
				}
				/* Check syntax */
				जर (addr_match_cidr_list(रिक्त, allowed) == -1) {
					error("Certificate source-address "
					    "contents invalid");
					मुक्त(allowed);
					जा out;
				}
				opts->required_from_host_cert = allowed;
				found = 1;
			}
		}

		जर (!found) {
			जर (crit) {
				error("Certificate critical option \"%s\" "
				    "is not supported", name);
				जा out;
			} अन्यथा {
				logit("Certificate extension \"%s\" "
				    "is not supported", name);
			}
		} अन्यथा जर (sshbuf_len(data) != 0) {
			error("Certificate option \"%s\" corrupt "
			    "(extra data)", name);
			जा out;
		}
		मुक्त(name);
		name = रिक्त;
	}
	/* successfully parsed all options */
	ret = 0;

 out:
	मुक्त(name);
	sshbuf_free(data);
	sshbuf_free(c);
	परत ret;
}

संरचना sshauthopt *
sshauthopt_new(शून्य)
{
	संरचना sshauthopt *ret;

	जर ((ret = सुस्मृति(1, आकार(*ret))) == रिक्त)
		परत रिक्त;
	ret->force_tun_device = -1;
	परत ret;
}

शून्य
sshauthopt_free(संरचना sshauthopt *opts)
{
	माप_प्रकार i;

	जर (opts == रिक्त)
		परत;

	मुक्त(opts->cert_principals);
	मुक्त(opts->force_command);
	मुक्त(opts->required_from_host_cert);
	मुक्त(opts->required_from_host_किल्ल्या);

	साठी (i = 0; i < opts->nenv; i++)
		मुक्त(opts->env[i]);
	मुक्त(opts->env);

	साठी (i = 0; i < opts->npermitopen; i++)
		मुक्त(opts->permitopen[i]);
	मुक्त(opts->permitopen);

	साठी (i = 0; i < opts->npermitlisten; i++)
		मुक्त(opts->permitlisten[i]);
	मुक्त(opts->permitlisten);

	freezero(opts, आकार(*opts));
}

संरचना sshauthopt *
sshauthopt_new_with_किल्ल्या_defaults(शून्य)
{
	संरचना sshauthopt *ret = रिक्त;

	जर ((ret = sshauthopt_new()) == रिक्त)
		परत रिक्त;

	/* Defaults for authorized_keys flags */
	ret->permit_port_forwarding_flag = 1;
	ret->permit_agent_forwarding_flag = 1;
	ret->permit_x11_forwarding_flag = 1;
	ret->permit_pty_flag = 1;
	ret->permit_user_rc = 1;
	परत ret;
}

/*
 * Parse and record a permitopen/permitlisten directive.
 * Return 0 on success. Return -1 on failure and sets *errstrp to error reason.
 */
स्थिर पूर्णांक
handle_permit(स्थिरांक अक्षर **optsp, पूर्णांक allow_bare_port,
    अक्षर ***permitsp, माप_प्रकार *npermitsp, स्थिरांक अक्षर **errstrp)
{
	अक्षर *opt, *tmp, *cp, *host, **permits = *permitsp;
	माप_प्रकार npermits = *npermitsp;
	स्थिरांक अक्षर *errstr = "unknown error";

	जर (npermits > SSH_AUTHOPT_PERMIT_MAX) {
		*errstrp = "too many permission directives";
		परत -1;
	}
	जर ((opt = opt_dequote(optsp, &errstr)) == रिक्त) {
		परत -1;
	}
	जर (allow_bare_port && म_अक्षर(opt, ':') == रिक्त) {
		/*
		 * Allow a bare port number in permitlisten to indicate a
		 * listen_host wildcard.
		 */
		जर (asprintf(&tmp, "*:%s", opt) == -1) {
			मुक्त(opt);
			*errstrp = "memory allocation failed";
			परत -1;
		}
		मुक्त(opt);
		opt = tmp;
	}
	जर ((tmp = strdup(opt)) == रिक्त) {
		मुक्त(opt);
		*errstrp = "memory allocation failed";
		परत -1;
	}
	cp = tmp;
	/* validate syntax before recording it. */
	host = hpdelim2(&cp, रिक्त);
	जर (host == रिक्त || म_माप(host) >= NI_MAXHOST) {
		मुक्त(tmp);
		मुक्त(opt);
		*errstrp = "invalid permission hostname";
		परत -1;
	}
	/*
	 * don't want to use permitopen_port to avoid
	 * dependency on channels.[ch] here.
	 */
	जर (cp == रिक्त ||
	    (म_भेद(cp, "*") != 0 && a2port(cp) <= 0)) {
		मुक्त(tmp);
		मुक्त(opt);
		*errstrp = "invalid permission port";
		परत -1;
	}
	/* XXX - add streamlocal support */
	मुक्त(tmp);
	/* Record it */
	जर ((permits = recallocarray(permits, npermits, npermits + 1,
	    आकार(*permits))) == रिक्त) {
		मुक्त(opt);
		/* NB. don't update *permitsp if alloc fails */
		*errstrp = "memory allocation failed";
		परत -1;
	}
	permits[npermits++] = opt;
	*permitsp = permits;
	*npermitsp = npermits;
	परत 0;
}

संरचना sshauthopt *
sshauthopt_parse(स्थिरांक अक्षर *opts, स्थिरांक अक्षर **errstrp)
{
	अक्षर **oarray, *opt, *cp, *tmp;
	पूर्णांक r;
	संरचना sshauthopt *ret = रिक्त;
	स्थिरांक अक्षर *errstr = "unknown error";
	uint64_t valid_before;
	माप_प्रकार i, l;

	जर (errstrp != रिक्त)
		*errstrp = रिक्त;
	जर ((ret = sshauthopt_new_with_किल्ल्या_defaults()) == रिक्त)
		जा alloc_fail;

	जर (opts == रिक्त)
		परत ret;

	पर्यंत (*opts && *opts != ' ' && *opts != '\t') {
		/* flag options */
		जर ((r = opt_flag("restrict", 0, &opts)) != -1) {
			ret->restricted = 1;
			ret->permit_port_forwarding_flag = 0;
			ret->permit_agent_forwarding_flag = 0;
			ret->permit_x11_forwarding_flag = 0;
			ret->permit_pty_flag = 0;
			ret->permit_user_rc = 0;
		} अन्यथा जर ((r = opt_flag("cert-authority", 0, &opts)) != -1) {
			ret->cert_authority = r;
		} अन्यथा जर ((r = opt_flag("port-forwarding", 1, &opts)) != -1) {
			ret->permit_port_forwarding_flag = r == 1;
		} अन्यथा जर ((r = opt_flag("agent-forwarding", 1, &opts)) != -1) {
			ret->permit_agent_forwarding_flag = r == 1;
		} अन्यथा जर ((r = opt_flag("x11-forwarding", 1, &opts)) != -1) {
			ret->permit_x11_forwarding_flag = r == 1;
		} अन्यथा जर ((r = opt_flag("touch-required", 1, &opts)) != -1) {
			ret->no_require_user_presence = r != 1; /* NB. flip */
		} अन्यथा जर ((r = opt_flag("verify-required", 1, &opts)) != -1) {
			ret->require_verify = r == 1;
		} अन्यथा जर ((r = opt_flag("pty", 1, &opts)) != -1) {
			ret->permit_pty_flag = r == 1;
		} अन्यथा जर ((r = opt_flag("user-rc", 1, &opts)) != -1) {
			ret->permit_user_rc = r == 1;
		} अन्यथा जर (opt_match(&opts, "command")) {
			जर (ret->force_command != रिक्त) {
				errstr = "multiple \"command\" clauses";
				जा fail;
			}
			ret->force_command = opt_dequote(&opts, &errstr);
			जर (ret->force_command == रिक्त)
				जा fail;
		} अन्यथा जर (opt_match(&opts, "principals")) {
			जर (ret->cert_principals != रिक्त) {
				errstr = "multiple \"principals\" clauses";
				जा fail;
			}
			ret->cert_principals = opt_dequote(&opts, &errstr);
			जर (ret->cert_principals == रिक्त)
				जा fail;
		} अन्यथा जर (opt_match(&opts, "from")) {
			जर (ret->required_from_host_किल्ल्या != रिक्त) {
				errstr = "multiple \"from\" clauses";
				जा fail;
			}
			ret->required_from_host_किल्ल्या = opt_dequote(&opts,
			    &errstr);
			जर (ret->required_from_host_किल्ल्या == रिक्त)
				जा fail;
		} अन्यथा जर (opt_match(&opts, "expiry-time")) {
			जर ((opt = opt_dequote(&opts, &errstr)) == रिक्त)
				जा fail;
			जर (parse_absolute_time(opt, &valid_before) != 0 ||
			    valid_before == 0) {
				मुक्त(opt);
				errstr = "invalid expires time";
				जा fail;
			}
			मुक्त(opt);
			जर (ret->valid_before == 0 ||
			    valid_before < ret->valid_before)
				ret->valid_before = valid_before;
		} अन्यथा जर (opt_match(&opts, "environment")) {
			जर (ret->nenv > SSH_AUTHOPT_ENV_MAX) {
				errstr = "too many environment strings";
				जा fail;
			}
			जर ((opt = opt_dequote(&opts, &errstr)) == रिक्त)
				जा fail;
			/* env name must be alphanumeric and followed by '=' */
			जर ((tmp = म_अक्षर(opt, '=')) == रिक्त) {
				मुक्त(opt);
				errstr = "invalid environment string";
				जा fail;
			}
			जर ((cp = strdup(opt)) == रिक्त) {
				मुक्त(opt);
				जा alloc_fail;
			}
			l = (माप_प्रकार)(tmp - opt);
			cp[l] = '\0'; /* truncate at '=' */
			जर (!valid_env_name(cp)) {
				मुक्त(cp);
				मुक्त(opt);
				errstr = "invalid environment string";
				जा fail;
			}
			/* Check for duplicates; XXX O(n*log(n)) */
			साठी (i = 0; i < ret->nenv; i++) {
				जर (म_भेदन(ret->env[i], cp, l) == 0 &&
				    ret->env[i][l] == '=')
					थांबा;
			}
			मुक्त(cp);
			/* First match wins */
			जर (i >= ret->nenv) {
				/* Append it. */
				oarray = ret->env;
				जर ((ret->env = recallocarray(ret->env,
				    ret->nenv, ret->nenv + 1,
				    आकार(*ret->env))) == रिक्त) {
					मुक्त(opt);
					/* put it back for cleanup */
					ret->env = oarray;
					जा alloc_fail;
				}
				ret->env[ret->nenv++] = opt;
				opt = रिक्त; /* transferred */
			}
			मुक्त(opt);
		} अन्यथा जर (opt_match(&opts, "permitopen")) {
			जर (handle_permit(&opts, 0, &ret->permitopen,
			    &ret->npermitopen, &errstr) != 0)
				जा fail;
		} अन्यथा जर (opt_match(&opts, "permitlisten")) {
			जर (handle_permit(&opts, 1, &ret->permitlisten,
			    &ret->npermitlisten, &errstr) != 0)
				जा fail;
		} अन्यथा जर (opt_match(&opts, "tunnel")) {
			जर ((opt = opt_dequote(&opts, &errstr)) == रिक्त)
				जा fail;
			ret->force_tun_device = a2tun(opt, रिक्त);
			मुक्त(opt);
			जर (ret->force_tun_device == SSH_TUNID_ERR) {
				errstr = "invalid tun device";
				जा fail;
			}
		}
		/*
		 * Skip the comma, and move to the next option
		 * (or break out if there are no more).
		 */
		जर (*opts == '\0' || *opts == ' ' || *opts == '\t')
			थांबा;		/* End of options. */
		/* Anything other than a comma is an unknown option */
		जर (*opts != ',') {
			errstr = "unknown key option";
			जा fail;
		}
		opts++;
		जर (*opts == '\0') {
			errstr = "unexpected end-of-options";
			जा fail;
		}
	}

	/* success */
	जर (errstrp != रिक्त)
		*errstrp = रिक्त;
	परत ret;

alloc_fail:
	errstr = "memory allocation failed";
fail:
	sshauthopt_free(ret);
	जर (errstrp != रिक्त)
		*errstrp = errstr;
	परत रिक्त;
}

संरचना sshauthopt *
sshauthopt_from_cert(संरचना sshkey *k)
{
	संरचना sshauthopt *ret;

	जर (k == रिक्त || !sshkey_type_is_cert(k->type) || k->cert == रिक्त ||
	    k->cert->type != SSH2_CERT_TYPE_USER)
		परत रिक्त;

	जर ((ret = sshauthopt_new()) == रिक्त)
		परत रिक्त;

	/* Handle options and critical extensions separately */
	जर (cert_option_list(ret, k->cert->critical,
	    OPTIONS_CRITICAL, 1) == -1) {
		sshauthopt_free(ret);
		परत रिक्त;
	}
	जर (cert_option_list(ret, k->cert->extensions,
	    OPTIONS_EXTENSIONS, 0) == -1) {
		sshauthopt_free(ret);
		परत रिक्त;
	}
	/* success */
	परत ret;
}

/*
 * Merges "additional" options to "primary" and returns the result.
 * NB. Some options from primary have primacy.
 */
संरचना sshauthopt *
sshauthopt_merge(स्थिरांक संरचना sshauthopt *primary,
    स्थिरांक संरचना sshauthopt *additional, स्थिरांक अक्षर **errstrp)
{
	संरचना sshauthopt *ret;
	स्थिरांक अक्षर *errstr = "internal error";
	स्थिरांक अक्षर *tmp;

	जर (errstrp != रिक्त)
		*errstrp = रिक्त;

	जर ((ret = sshauthopt_new()) == रिक्त)
		जा alloc_fail;

	/* cert_authority and cert_principals are cleared in result */

	/* Prefer access lists from primary. */
	/* XXX err is both set and mismatch? */
	tmp = primary->required_from_host_cert;
	जर (tmp == रिक्त)
		tmp = additional->required_from_host_cert;
	जर (tmp != रिक्त && (ret->required_from_host_cert = strdup(tmp)) == रिक्त)
		जा alloc_fail;
	tmp = primary->required_from_host_किल्ल्या;
	जर (tmp == रिक्त)
		tmp = additional->required_from_host_किल्ल्या;
	जर (tmp != रिक्त && (ret->required_from_host_किल्ल्या = strdup(tmp)) == रिक्त)
		जा alloc_fail;

	/*
	 * force_tun_device, permitopen/permitlisten and environment all
	 * prefer the primary.
	 */
	ret->force_tun_device = primary->force_tun_device;
	जर (ret->force_tun_device == -1)
		ret->force_tun_device = additional->force_tun_device;
	जर (primary->nenv > 0) {
		जर (dup_strings(&ret->env, &ret->nenv,
		    primary->env, primary->nenv) != 0)
			जा alloc_fail;
	} अन्यथा जर (additional->nenv) {
		जर (dup_strings(&ret->env, &ret->nenv,
		    additional->env, additional->nenv) != 0)
			जा alloc_fail;
	}
	जर (primary->npermitopen > 0) {
		जर (dup_strings(&ret->permitopen, &ret->npermitopen,
		    primary->permitopen, primary->npermitopen) != 0)
			जा alloc_fail;
	} अन्यथा जर (additional->npermitopen > 0) {
		जर (dup_strings(&ret->permitopen, &ret->npermitopen,
		    additional->permitopen, additional->npermitopen) != 0)
			जा alloc_fail;
	}

	जर (primary->npermitlisten > 0) {
		जर (dup_strings(&ret->permitlisten, &ret->npermitlisten,
		    primary->permitlisten, primary->npermitlisten) != 0)
			जा alloc_fail;
	} अन्यथा जर (additional->npermitlisten > 0) {
		जर (dup_strings(&ret->permitlisten, &ret->npermitlisten,
		    additional->permitlisten, additional->npermitlisten) != 0)
			जा alloc_fail;
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
	जर (primary->valid_before != 0)
		ret->valid_before = primary->valid_before;
	जर (additional->valid_before != 0 &&
	    additional->valid_before < ret->valid_before)
		ret->valid_before = additional->valid_before;

	/*
	 * When both multiple forced-command are specified, only
	 * proceed if they are identical, otherwise fail.
	 */
	जर (primary->force_command != रिक्त &&
	    additional->force_command != रिक्त) {
		जर (म_भेद(primary->force_command,
		    additional->force_command) == 0) {
			/* ok */
			ret->force_command = strdup(primary->force_command);
			जर (ret->force_command == रिक्त)
				जा alloc_fail;
		} अन्यथा {
			errstr = "forced command options do not match";
			जा fail;
		}
	} अन्यथा जर (primary->force_command != रिक्त) {
		जर ((ret->force_command = strdup(
		    primary->force_command)) == रिक्त)
			जा alloc_fail;
	} अन्यथा जर (additional->force_command != रिक्त) {
		जर ((ret->force_command = strdup(
		    additional->force_command)) == रिक्त)
			जा alloc_fail;
	}
	/* success */
	जर (errstrp != रिक्त)
		*errstrp = रिक्त;
	परत ret;

 alloc_fail:
	errstr = "memory allocation failed";
 fail:
	जर (errstrp != रिक्त)
		*errstrp = errstr;
	sshauthopt_free(ret);
	परत रिक्त;
}

/*
 * Copy options
 */
संरचना sshauthopt *
sshauthopt_copy(स्थिरांक संरचना sshauthopt *orig)
{
	संरचना sshauthopt *ret;

	जर ((ret = sshauthopt_new()) == रिक्त)
		परत रिक्त;

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
	करा { \
		जर (orig->x != रिक्त && (ret->x = strdup(orig->x)) == रिक्त) { \
			sshauthopt_free(ret); \
			परत रिक्त; \
		} \
	} पर्यंत (0)
	OPTSTRING(cert_principals);
	OPTSTRING(force_command);
	OPTSTRING(required_from_host_cert);
	OPTSTRING(required_from_host_किल्ल्या);
#undef OPTSTRING

	जर (dup_strings(&ret->env, &ret->nenv, orig->env, orig->nenv) != 0 ||
	    dup_strings(&ret->permitopen, &ret->npermitopen,
	    orig->permitopen, orig->npermitopen) != 0 ||
	    dup_strings(&ret->permitlisten, &ret->npermitlisten,
	    orig->permitlisten, orig->npermitlisten) != 0) {
		sshauthopt_free(ret);
		परत रिक्त;
	}
	परत ret;
}

स्थिर पूर्णांक
serialise_array(संरचना sshbuf *m, अक्षर **a, माप_प्रकार n)
{
	संरचना sshbuf *b;
	माप_प्रकार i;
	पूर्णांक r = SSH_ERR_INTERNAL_ERROR;

	जर (n > पूर्णांक_उच्च)
		परत SSH_ERR_INTERNAL_ERROR;

	जर ((b = sshbuf_new()) == रिक्त) {
		परत SSH_ERR_ALLOC_FAIL;
	}
	साठी (i = 0; i < n; i++) {
		जर ((r = sshbuf_put_cstring(b, a[i])) != 0)
			जा out;
	}
	जर ((r = sshbuf_put_u32(m, n)) != 0 ||
	    (r = sshbuf_put_stringb(m, b)) != 0)
		जा out;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	परत r;
}

स्थिर पूर्णांक
deserialise_array(संरचना sshbuf *m, अक्षर ***ap, माप_प्रकार *np)
{
	अक्षर **a = रिक्त;
	माप_प्रकार i, n = 0;
	संरचना sshbuf *b = रिक्त;
	u_int tmp;
	पूर्णांक r = SSH_ERR_INTERNAL_ERROR;

	जर ((r = sshbuf_get_u32(m, &tmp)) != 0 ||
	    (r = sshbuf_froms(m, &b)) != 0)
		जा out;
	जर (tmp > पूर्णांक_उच्च) {
		r = SSH_ERR_INVALID_FORMAT;
		जा out;
	}
	n = tmp;
	जर (n > 0 && (a = सुस्मृति(n, आकार(*a))) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		जा out;
	}
	साठी (i = 0; i < n; i++) {
		जर ((r = sshbuf_get_cstring(b, &a[i], रिक्त)) != 0)
			जा out;
	}
	/* success */
	r = 0;
	*ap = a;
	a = रिक्त;
	*np = n;
	n = 0;
 out:
	जर (a != रिक्त) {
		साठी (i = 0; i < n; i++)
			मुक्त(a[i]);
		मुक्त(a);
	}
	sshbuf_free(b);
	परत r;
}

स्थिर पूर्णांक
serialise_nullable_string(संरचना sshbuf *m, स्थिरांक अक्षर *s)
{
	पूर्णांक r;

	जर ((r = sshbuf_put_u8(m, s == रिक्त)) != 0 ||
	    (r = sshbuf_put_cstring(m, s)) != 0)
		परत r;
	परत 0;
}

स्थिर पूर्णांक
deserialise_nullable_string(संरचना sshbuf *m, अक्षर **sp)
{
	पूर्णांक r;
	u_char flag;

	*sp = रिक्त;
	जर ((r = sshbuf_get_u8(m, &flag)) != 0 ||
	    (r = sshbuf_get_cstring(m, flag ? रिक्त : sp, रिक्त)) != 0)
		परत r;
	परत 0;
}

पूर्णांक
sshauthopt_serialise(स्थिरांक संरचना sshauthopt *opts, संरचना sshbuf *m,
    पूर्णांक untrusted)
{
	पूर्णांक r = SSH_ERR_INTERNAL_ERROR;

	/* Flag options */
	जर ((r = sshbuf_put_u8(m, opts->permit_port_forwarding_flag)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->permit_agent_forwarding_flag)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->permit_x11_forwarding_flag)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->permit_pty_flag)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->permit_user_rc)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->restricted)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->cert_authority)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->no_require_user_presence)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->require_verify)) != 0)
		परत r;

	/* Simple integer options */
	जर ((r = sshbuf_put_u64(m, opts->valid_before)) != 0)
		परत r;

	/* tunnel number can be negative to indicate "unset" */
	जर ((r = sshbuf_put_u8(m, opts->force_tun_device == -1)) != 0 ||
	    (r = sshbuf_put_u32(m, (opts->force_tun_device < 0) ?
	    0 : (u_int)opts->force_tun_device)) != 0)
		परत r;

	/* String options; these may be NULL */
	जर ((r = serialise_nullable_string(m,
	    untrusted ? "yes" : opts->cert_principals)) != 0 ||
	    (r = serialise_nullable_string(m,
	    untrusted ? "true" : opts->force_command)) != 0 ||
	    (r = serialise_nullable_string(m,
	    untrusted ? रिक्त : opts->required_from_host_cert)) != 0 ||
	    (r = serialise_nullable_string(m,
	    untrusted ? रिक्त : opts->required_from_host_किल्ल्या)) != 0)
		परत r;

	/* Array options */
	जर ((r = serialise_array(m, opts->env,
	    untrusted ? 0 : opts->nenv)) != 0 ||
	    (r = serialise_array(m, opts->permitopen,
	    untrusted ? 0 : opts->npermitopen)) != 0 ||
	    (r = serialise_array(m, opts->permitlisten,
	    untrusted ? 0 : opts->npermitlisten)) != 0)
		परत r;

	/* success */
	परत 0;
}

पूर्णांक
sshauthopt_deserialise(संरचना sshbuf *m, संरचना sshauthopt **optsp)
{
	संरचना sshauthopt *opts = रिक्त;
	पूर्णांक r = SSH_ERR_INTERNAL_ERROR;
	u_char f;
	u_int tmp;

	जर ((opts = सुस्मृति(1, आकार(*opts))) == रिक्त)
		परत SSH_ERR_ALLOC_FAIL;

	/* Flag options */
#define OPT_FLAG(x) \
	करा { \
		जर ((r = sshbuf_get_u8(m, &f)) != 0) \
			जा out; \
		opts->x = f; \
	} पर्यंत (0)
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
	जर ((r = sshbuf_get_u64(m, &opts->valid_before)) != 0)
		जा out;

	/* tunnel number can be negative to indicate "unset" */
	जर ((r = sshbuf_get_u8(m, &f)) != 0 ||
	    (r = sshbuf_get_u32(m, &tmp)) != 0)
		जा out;
	opts->force_tun_device = f ? -1 : (पूर्णांक)tmp;

	/* String options may be NULL */
	जर ((r = deserialise_nullable_string(m, &opts->cert_principals)) != 0 ||
	    (r = deserialise_nullable_string(m, &opts->force_command)) != 0 ||
	    (r = deserialise_nullable_string(m,
	    &opts->required_from_host_cert)) != 0 ||
	    (r = deserialise_nullable_string(m,
	    &opts->required_from_host_किल्ल्या)) != 0)
		जा out;

	/* Array options */
	जर ((r = deserialise_array(m, &opts->env, &opts->nenv)) != 0 ||
	    (r = deserialise_array(m,
	    &opts->permitopen, &opts->npermitopen)) != 0 ||
	    (r = deserialise_array(m,
	    &opts->permitlisten, &opts->npermitlisten)) != 0)
		जा out;

	/* success */
	r = 0;
	*optsp = opts;
	opts = रिक्त;
 out:
	sshauthopt_free(opts);
	परत r;
}
