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

#समावेश "includes.h"

#समावेश <sys/types.h>
#समावेश <sys/queue.h>

#समावेश <stdlib.h>
#समावेश <netdb.h>
#समावेश <pwd.h>
#समावेश <string.h>
#समावेश <stdio.h>
#समावेश <stdint.h>
#समावेश <stdarg.h>
#समावेश <ctype.h>
#समावेश <limits.h>

#समावेश "xmalloc.h"
#समावेश "ssherr.h"
#समावेश "log.h"
#समावेश "sshbuf.h"
#समावेश "misc.h"
#समावेश "sshkey.h"
#समावेश "match.h"
#समावेश "ssh2.h"
#समावेश "auth-options.h"

अटल पूर्णांक
dup_strings(अक्षर ***dstp, माप_प्रकार *ndstp, अक्षर **src, माप_प्रकार nsrc)
{
	अक्षर **dst;
	माप_प्रकार i, j;

	*dstp = शून्य;
	*ndstp = 0;

	अगर (nsrc == 0)
		वापस 0;
	अगर (nsrc >= SIZE_MAX / माप(*src) ||
	    (dst = सुस्मृति(nsrc, माप(*src))) == शून्य)
		वापस -1;
	क्रम (i = 0; i < nsrc; i++) {
		अगर ((dst[i] = strdup(src[i])) == शून्य) {
			क्रम (j = 0; j < i; j++)
				मुक्त(dst[j]);
			मुक्त(dst);
			वापस -1;
		}
	}
	/* success */
	*dstp = dst;
	*ndstp = nsrc;
	वापस 0;
}

#घोषणा OPTIONS_CRITICAL	1
#घोषणा OPTIONS_EXTENSIONS	2
अटल पूर्णांक
cert_option_list(काष्ठा sshauthopt *opts, काष्ठा sshbuf *oblob,
    u_int which, पूर्णांक crit)
{
	अक्षर *command, *allowed;
	अक्षर *name = शून्य;
	काष्ठा sshbuf *c = शून्य, *तथ्य = शून्य;
	पूर्णांक r, ret = -1, found;

	अगर ((c = sshbuf_fromb(oblob)) == शून्य) {
		error_f("sshbuf_fromb failed");
		जाओ out;
	}

	जबतक (sshbuf_len(c) > 0) {
		sshbuf_free(तथ्य);
		तथ्य = शून्य;
		अगर ((r = sshbuf_get_cstring(c, &name, शून्य)) != 0 ||
		    (r = sshbuf_froms(c, &तथ्य)) != 0) {
			error_r(r, "Unable to parse certificate options");
			जाओ out;
		}
		debug3("found certificate option \"%.100s\" len %zu",
		    name, sshbuf_len(तथ्य));
		found = 0;
		अगर ((which & OPTIONS_EXTENSIONS) != 0) {
			अगर (म_भेद(name, "no-touch-required") == 0) {
				opts->no_require_user_presence = 1;
				found = 1;
			} अन्यथा अगर (म_भेद(name, "permit-X11-forwarding") == 0) {
				opts->permit_x11_forwarding_flag = 1;
				found = 1;
			} अन्यथा अगर (म_भेद(name,
			    "permit-agent-forwarding") == 0) {
				opts->permit_agent_forwarding_flag = 1;
				found = 1;
			} अन्यथा अगर (म_भेद(name,
			    "permit-port-forwarding") == 0) {
				opts->permit_port_forwarding_flag = 1;
				found = 1;
			} अन्यथा अगर (म_भेद(name, "permit-pty") == 0) {
				opts->permit_pty_flag = 1;
				found = 1;
			} अन्यथा अगर (म_भेद(name, "permit-user-rc") == 0) {
				opts->permit_user_rc = 1;
				found = 1;
			}
		}
		अगर (!found && (which & OPTIONS_CRITICAL) != 0) {
			अगर (म_भेद(name, "verify-required") == 0) {
				opts->require_verify = 1;
				found = 1;
			} अन्यथा अगर (म_भेद(name, "force-command") == 0) {
				अगर ((r = sshbuf_get_cstring(तथ्य, &command,
				    शून्य)) != 0) {
					error_r(r, "Unable to parse \"%s\" "
					    "section", name);
					जाओ out;
				}
				अगर (opts->force_command != शून्य) {
					error("Certificate has multiple "
					    "force-command options");
					मुक्त(command);
					जाओ out;
				}
				opts->force_command = command;
				found = 1;
			} अन्यथा अगर (म_भेद(name, "source-address") == 0) {
				अगर ((r = sshbuf_get_cstring(तथ्य, &allowed,
				    शून्य)) != 0) {
					error_r(r, "Unable to parse \"%s\" "
					    "section", name);
					जाओ out;
				}
				अगर (opts->required_from_host_cert != शून्य) {
					error("Certificate has multiple "
					    "source-address options");
					मुक्त(allowed);
					जाओ out;
				}
				/* Check syntax */
				अगर (addr_match_cidr_list(शून्य, allowed) == -1) {
					error("Certificate source-address "
					    "contents invalid");
					मुक्त(allowed);
					जाओ out;
				}
				opts->required_from_host_cert = allowed;
				found = 1;
			}
		}

		अगर (!found) {
			अगर (crit) {
				error("Certificate critical option \"%s\" "
				    "is not supported", name);
				जाओ out;
			} अन्यथा {
				logit("Certificate extension \"%s\" "
				    "is not supported", name);
			}
		} अन्यथा अगर (sshbuf_len(तथ्य) != 0) {
			error("Certificate option \"%s\" corrupt "
			    "(extra data)", name);
			जाओ out;
		}
		मुक्त(name);
		name = शून्य;
	}
	/* successfully parsed all options */
	ret = 0;

 out:
	मुक्त(name);
	sshbuf_free(तथ्य);
	sshbuf_free(c);
	वापस ret;
}

काष्ठा sshauthopt *
sshauthopt_new(व्योम)
{
	काष्ठा sshauthopt *ret;

	अगर ((ret = सुस्मृति(1, माप(*ret))) == शून्य)
		वापस शून्य;
	ret->force_tun_device = -1;
	वापस ret;
}

व्योम
sshauthopt_free(काष्ठा sshauthopt *opts)
{
	माप_प्रकार i;

	अगर (opts == शून्य)
		वापस;

	मुक्त(opts->cert_principals);
	मुक्त(opts->force_command);
	मुक्त(opts->required_from_host_cert);
	मुक्त(opts->required_from_host_कुंजियाँ);

	क्रम (i = 0; i < opts->nenv; i++)
		मुक्त(opts->env[i]);
	मुक्त(opts->env);

	क्रम (i = 0; i < opts->npermitopen; i++)
		मुक्त(opts->permitopen[i]);
	मुक्त(opts->permitopen);

	क्रम (i = 0; i < opts->npermitlisten; i++)
		मुक्त(opts->permitlisten[i]);
	मुक्त(opts->permitlisten);

	freezero(opts, माप(*opts));
}

काष्ठा sshauthopt *
sshauthopt_new_with_कुंजियाँ_defaults(व्योम)
{
	काष्ठा sshauthopt *ret = शून्य;

	अगर ((ret = sshauthopt_new()) == शून्य)
		वापस शून्य;

	/* Defaults for authorized_keys flags */
	ret->permit_port_forwarding_flag = 1;
	ret->permit_agent_forwarding_flag = 1;
	ret->permit_x11_forwarding_flag = 1;
	ret->permit_pty_flag = 1;
	ret->permit_user_rc = 1;
	वापस ret;
}

/*
 * Parse and record a permitopen/permitlisten directive.
 * Return 0 on success. Return -1 on failure and sets *errstrp to error reason.
 */
अटल पूर्णांक
handle_permit(स्थिर अक्षर **optsp, पूर्णांक allow_bare_port,
    अक्षर ***permitsp, माप_प्रकार *npermitsp, स्थिर अक्षर **errstrp)
{
	अक्षर *opt, *tmp, *cp, *host, **permits = *permitsp;
	माप_प्रकार npermits = *npermitsp;
	स्थिर अक्षर *errstr = "unknown error";

	अगर (npermits > SSH_AUTHOPT_PERMIT_MAX) {
		*errstrp = "too many permission directives";
		वापस -1;
	}
	अगर ((opt = opt_dequote(optsp, &errstr)) == शून्य) {
		वापस -1;
	}
	अगर (allow_bare_port && म_अक्षर(opt, ':') == शून्य) {
		/*
		 * Allow a bare port number in permitlisten to indicate a
		 * listen_host wildcard.
		 */
		अगर (asprintf(&tmp, "*:%s", opt) == -1) {
			मुक्त(opt);
			*errstrp = "memory allocation failed";
			वापस -1;
		}
		मुक्त(opt);
		opt = tmp;
	}
	अगर ((tmp = strdup(opt)) == शून्य) {
		मुक्त(opt);
		*errstrp = "memory allocation failed";
		वापस -1;
	}
	cp = tmp;
	/* validate syntax before recording it. */
	host = hpdelim2(&cp, शून्य);
	अगर (host == शून्य || म_माप(host) >= NI_MAXHOST) {
		मुक्त(tmp);
		मुक्त(opt);
		*errstrp = "invalid permission hostname";
		वापस -1;
	}
	/*
	 * don't want to use permitopen_port to avoid
	 * dependency on channels.[ch] here.
	 */
	अगर (cp == शून्य ||
	    (म_भेद(cp, "*") != 0 && a2port(cp) <= 0)) {
		मुक्त(tmp);
		मुक्त(opt);
		*errstrp = "invalid permission port";
		वापस -1;
	}
	/* XXX - add streamlocal support */
	मुक्त(tmp);
	/* Record it */
	अगर ((permits = recallocarray(permits, npermits, npermits + 1,
	    माप(*permits))) == शून्य) {
		मुक्त(opt);
		/* NB. don't update *permitsp if alloc fails */
		*errstrp = "memory allocation failed";
		वापस -1;
	}
	permits[npermits++] = opt;
	*permitsp = permits;
	*npermitsp = npermits;
	वापस 0;
}

काष्ठा sshauthopt *
sshauthopt_parse(स्थिर अक्षर *opts, स्थिर अक्षर **errstrp)
{
	अक्षर **oarray, *opt, *cp, *tmp;
	पूर्णांक r;
	काष्ठा sshauthopt *ret = शून्य;
	स्थिर अक्षर *errstr = "unknown error";
	uint64_t valid_before;
	माप_प्रकार i, l;

	अगर (errstrp != शून्य)
		*errstrp = शून्य;
	अगर ((ret = sshauthopt_new_with_कुंजियाँ_defaults()) == शून्य)
		जाओ alloc_fail;

	अगर (opts == शून्य)
		वापस ret;

	जबतक (*opts && *opts != ' ' && *opts != '\t') {
		/* flag options */
		अगर ((r = opt_flag("restrict", 0, &opts)) != -1) {
			ret->restricted = 1;
			ret->permit_port_forwarding_flag = 0;
			ret->permit_agent_forwarding_flag = 0;
			ret->permit_x11_forwarding_flag = 0;
			ret->permit_pty_flag = 0;
			ret->permit_user_rc = 0;
		} अन्यथा अगर ((r = opt_flag("cert-authority", 0, &opts)) != -1) {
			ret->cert_authority = r;
		} अन्यथा अगर ((r = opt_flag("port-forwarding", 1, &opts)) != -1) {
			ret->permit_port_forwarding_flag = r == 1;
		} अन्यथा अगर ((r = opt_flag("agent-forwarding", 1, &opts)) != -1) {
			ret->permit_agent_forwarding_flag = r == 1;
		} अन्यथा अगर ((r = opt_flag("x11-forwarding", 1, &opts)) != -1) {
			ret->permit_x11_forwarding_flag = r == 1;
		} अन्यथा अगर ((r = opt_flag("touch-required", 1, &opts)) != -1) {
			ret->no_require_user_presence = r != 1; /* NB. flip */
		} अन्यथा अगर ((r = opt_flag("verify-required", 1, &opts)) != -1) {
			ret->require_verify = r == 1;
		} अन्यथा अगर ((r = opt_flag("pty", 1, &opts)) != -1) {
			ret->permit_pty_flag = r == 1;
		} अन्यथा अगर ((r = opt_flag("user-rc", 1, &opts)) != -1) {
			ret->permit_user_rc = r == 1;
		} अन्यथा अगर (opt_match(&opts, "command")) {
			अगर (ret->force_command != शून्य) {
				errstr = "multiple \"command\" clauses";
				जाओ fail;
			}
			ret->force_command = opt_dequote(&opts, &errstr);
			अगर (ret->force_command == शून्य)
				जाओ fail;
		} अन्यथा अगर (opt_match(&opts, "principals")) {
			अगर (ret->cert_principals != शून्य) {
				errstr = "multiple \"principals\" clauses";
				जाओ fail;
			}
			ret->cert_principals = opt_dequote(&opts, &errstr);
			अगर (ret->cert_principals == शून्य)
				जाओ fail;
		} अन्यथा अगर (opt_match(&opts, "from")) {
			अगर (ret->required_from_host_कुंजियाँ != शून्य) {
				errstr = "multiple \"from\" clauses";
				जाओ fail;
			}
			ret->required_from_host_कुंजियाँ = opt_dequote(&opts,
			    &errstr);
			अगर (ret->required_from_host_कुंजियाँ == शून्य)
				जाओ fail;
		} अन्यथा अगर (opt_match(&opts, "expiry-time")) {
			अगर ((opt = opt_dequote(&opts, &errstr)) == शून्य)
				जाओ fail;
			अगर (parse_absolute_time(opt, &valid_before) != 0 ||
			    valid_before == 0) {
				मुक्त(opt);
				errstr = "invalid expires time";
				जाओ fail;
			}
			मुक्त(opt);
			अगर (ret->valid_before == 0 ||
			    valid_before < ret->valid_before)
				ret->valid_before = valid_before;
		} अन्यथा अगर (opt_match(&opts, "environment")) {
			अगर (ret->nenv > SSH_AUTHOPT_ENV_MAX) {
				errstr = "too many environment strings";
				जाओ fail;
			}
			अगर ((opt = opt_dequote(&opts, &errstr)) == शून्य)
				जाओ fail;
			/* env name must be alphanumeric and followed by '=' */
			अगर ((tmp = म_अक्षर(opt, '=')) == शून्य) {
				मुक्त(opt);
				errstr = "invalid environment string";
				जाओ fail;
			}
			अगर ((cp = strdup(opt)) == शून्य) {
				मुक्त(opt);
				जाओ alloc_fail;
			}
			l = (माप_प्रकार)(tmp - opt);
			cp[l] = '\0'; /* truncate at '=' */
			अगर (!valid_env_name(cp)) {
				मुक्त(cp);
				मुक्त(opt);
				errstr = "invalid environment string";
				जाओ fail;
			}
			/* Check for duplicates; XXX O(n*log(n)) */
			क्रम (i = 0; i < ret->nenv; i++) {
				अगर (म_भेदन(ret->env[i], cp, l) == 0 &&
				    ret->env[i][l] == '=')
					अवरोध;
			}
			मुक्त(cp);
			/* First match wins */
			अगर (i >= ret->nenv) {
				/* Append it. */
				oarray = ret->env;
				अगर ((ret->env = recallocarray(ret->env,
				    ret->nenv, ret->nenv + 1,
				    माप(*ret->env))) == शून्य) {
					मुक्त(opt);
					/* put it back for cleanup */
					ret->env = oarray;
					जाओ alloc_fail;
				}
				ret->env[ret->nenv++] = opt;
				opt = शून्य; /* transferred */
			}
			मुक्त(opt);
		} अन्यथा अगर (opt_match(&opts, "permitopen")) {
			अगर (handle_permit(&opts, 0, &ret->permitopen,
			    &ret->npermitopen, &errstr) != 0)
				जाओ fail;
		} अन्यथा अगर (opt_match(&opts, "permitlisten")) {
			अगर (handle_permit(&opts, 1, &ret->permitlisten,
			    &ret->npermitlisten, &errstr) != 0)
				जाओ fail;
		} अन्यथा अगर (opt_match(&opts, "tunnel")) {
			अगर ((opt = opt_dequote(&opts, &errstr)) == शून्य)
				जाओ fail;
			ret->force_tun_device = a2tun(opt, शून्य);
			मुक्त(opt);
			अगर (ret->force_tun_device == SSH_TUNID_ERR) {
				errstr = "invalid tun device";
				जाओ fail;
			}
		}
		/*
		 * Skip the comma, and move to the next option
		 * (or break out if there are no more).
		 */
		अगर (*opts == '\0' || *opts == ' ' || *opts == '\t')
			अवरोध;		/* End of options. */
		/* Anything other than a comma is an unknown option */
		अगर (*opts != ',') {
			errstr = "unknown key option";
			जाओ fail;
		}
		opts++;
		अगर (*opts == '\0') {
			errstr = "unexpected end-of-options";
			जाओ fail;
		}
	}

	/* success */
	अगर (errstrp != शून्य)
		*errstrp = शून्य;
	वापस ret;

alloc_fail:
	errstr = "memory allocation failed";
fail:
	sshauthopt_free(ret);
	अगर (errstrp != शून्य)
		*errstrp = errstr;
	वापस शून्य;
}

काष्ठा sshauthopt *
sshauthopt_from_cert(काष्ठा sshkey *k)
{
	काष्ठा sshauthopt *ret;

	अगर (k == शून्य || !sshkey_type_is_cert(k->type) || k->cert == शून्य ||
	    k->cert->type != SSH2_CERT_TYPE_USER)
		वापस शून्य;

	अगर ((ret = sshauthopt_new()) == शून्य)
		वापस शून्य;

	/* Handle options and critical extensions separately */
	अगर (cert_option_list(ret, k->cert->critical,
	    OPTIONS_CRITICAL, 1) == -1) {
		sshauthopt_free(ret);
		वापस शून्य;
	}
	अगर (cert_option_list(ret, k->cert->extensions,
	    OPTIONS_EXTENSIONS, 0) == -1) {
		sshauthopt_free(ret);
		वापस शून्य;
	}
	/* success */
	वापस ret;
}

/*
 * Merges "additional" options to "primary" and returns the result.
 * NB. Some options from primary have primacy.
 */
काष्ठा sshauthopt *
sshauthopt_merge(स्थिर काष्ठा sshauthopt *primary,
    स्थिर काष्ठा sshauthopt *additional, स्थिर अक्षर **errstrp)
{
	काष्ठा sshauthopt *ret;
	स्थिर अक्षर *errstr = "internal error";
	स्थिर अक्षर *tmp;

	अगर (errstrp != शून्य)
		*errstrp = शून्य;

	अगर ((ret = sshauthopt_new()) == शून्य)
		जाओ alloc_fail;

	/* cert_authority and cert_principals are cleared in result */

	/* Prefer access lists from primary. */
	/* XXX err is both set and mismatch? */
	tmp = primary->required_from_host_cert;
	अगर (tmp == शून्य)
		tmp = additional->required_from_host_cert;
	अगर (tmp != शून्य && (ret->required_from_host_cert = strdup(tmp)) == शून्य)
		जाओ alloc_fail;
	tmp = primary->required_from_host_कुंजियाँ;
	अगर (tmp == शून्य)
		tmp = additional->required_from_host_कुंजियाँ;
	अगर (tmp != शून्य && (ret->required_from_host_कुंजियाँ = strdup(tmp)) == शून्य)
		जाओ alloc_fail;

	/*
	 * force_tun_device, permitopen/permitlisten and environment all
	 * prefer the primary.
	 */
	ret->force_tun_device = primary->force_tun_device;
	अगर (ret->force_tun_device == -1)
		ret->force_tun_device = additional->force_tun_device;
	अगर (primary->nenv > 0) {
		अगर (dup_strings(&ret->env, &ret->nenv,
		    primary->env, primary->nenv) != 0)
			जाओ alloc_fail;
	} अन्यथा अगर (additional->nenv) {
		अगर (dup_strings(&ret->env, &ret->nenv,
		    additional->env, additional->nenv) != 0)
			जाओ alloc_fail;
	}
	अगर (primary->npermitopen > 0) {
		अगर (dup_strings(&ret->permitopen, &ret->npermitopen,
		    primary->permitopen, primary->npermitopen) != 0)
			जाओ alloc_fail;
	} अन्यथा अगर (additional->npermitopen > 0) {
		अगर (dup_strings(&ret->permitopen, &ret->npermitopen,
		    additional->permitopen, additional->npermitopen) != 0)
			जाओ alloc_fail;
	}

	अगर (primary->npermitlisten > 0) {
		अगर (dup_strings(&ret->permitlisten, &ret->npermitlisten,
		    primary->permitlisten, primary->npermitlisten) != 0)
			जाओ alloc_fail;
	} अन्यथा अगर (additional->npermitlisten > 0) {
		अगर (dup_strings(&ret->permitlisten, &ret->npermitlisten,
		    additional->permitlisten, additional->npermitlisten) != 0)
			जाओ alloc_fail;
	}

#घोषणा OPTFLAG_AND(x) ret->x = (primary->x == 1) && (additional->x == 1)
#घोषणा OPTFLAG_OR(x) ret->x = (primary->x == 1) || (additional->x == 1)
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
#अघोषित OPTFLAG_AND

	/* Earliest expiry time should win */
	अगर (primary->valid_before != 0)
		ret->valid_before = primary->valid_before;
	अगर (additional->valid_before != 0 &&
	    additional->valid_before < ret->valid_before)
		ret->valid_before = additional->valid_before;

	/*
	 * When both multiple forced-command are specified, only
	 * proceed if they are identical, otherwise fail.
	 */
	अगर (primary->force_command != शून्य &&
	    additional->force_command != शून्य) {
		अगर (म_भेद(primary->force_command,
		    additional->force_command) == 0) {
			/* ok */
			ret->force_command = strdup(primary->force_command);
			अगर (ret->force_command == शून्य)
				जाओ alloc_fail;
		} अन्यथा {
			errstr = "forced command options do not match";
			जाओ fail;
		}
	} अन्यथा अगर (primary->force_command != शून्य) {
		अगर ((ret->force_command = strdup(
		    primary->force_command)) == शून्य)
			जाओ alloc_fail;
	} अन्यथा अगर (additional->force_command != शून्य) {
		अगर ((ret->force_command = strdup(
		    additional->force_command)) == शून्य)
			जाओ alloc_fail;
	}
	/* success */
	अगर (errstrp != शून्य)
		*errstrp = शून्य;
	वापस ret;

 alloc_fail:
	errstr = "memory allocation failed";
 fail:
	अगर (errstrp != शून्य)
		*errstrp = errstr;
	sshauthopt_free(ret);
	वापस शून्य;
}

/*
 * Copy options
 */
काष्ठा sshauthopt *
sshauthopt_copy(स्थिर काष्ठा sshauthopt *orig)
{
	काष्ठा sshauthopt *ret;

	अगर ((ret = sshauthopt_new()) == शून्य)
		वापस शून्य;

#घोषणा OPTSCALAR(x) ret->x = orig->x
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
#अघोषित OPTSCALAR
#घोषणा OPTSTRING(x) \
	करो { \
		अगर (orig->x != शून्य && (ret->x = strdup(orig->x)) == शून्य) { \
			sshauthopt_free(ret); \
			वापस शून्य; \
		} \
	} जबतक (0)
	OPTSTRING(cert_principals);
	OPTSTRING(force_command);
	OPTSTRING(required_from_host_cert);
	OPTSTRING(required_from_host_कुंजियाँ);
#अघोषित OPTSTRING

	अगर (dup_strings(&ret->env, &ret->nenv, orig->env, orig->nenv) != 0 ||
	    dup_strings(&ret->permitopen, &ret->npermitopen,
	    orig->permitopen, orig->npermitopen) != 0 ||
	    dup_strings(&ret->permitlisten, &ret->npermitlisten,
	    orig->permitlisten, orig->npermitlisten) != 0) {
		sshauthopt_free(ret);
		वापस शून्य;
	}
	वापस ret;
}

अटल पूर्णांक
serialise_array(काष्ठा sshbuf *m, अक्षर **a, माप_प्रकार n)
{
	काष्ठा sshbuf *b;
	माप_प्रकार i;
	पूर्णांक r = SSH_ERR_INTERNAL_ERROR;

	अगर (n > पूर्णांक_उच्च)
		वापस SSH_ERR_INTERNAL_ERROR;

	अगर ((b = sshbuf_new()) == शून्य) {
		वापस SSH_ERR_ALLOC_FAIL;
	}
	क्रम (i = 0; i < n; i++) {
		अगर ((r = sshbuf_put_cstring(b, a[i])) != 0)
			जाओ out;
	}
	अगर ((r = sshbuf_put_u32(m, n)) != 0 ||
	    (r = sshbuf_put_stringb(m, b)) != 0)
		जाओ out;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	वापस r;
}

अटल पूर्णांक
deserialise_array(काष्ठा sshbuf *m, अक्षर ***ap, माप_प्रकार *np)
{
	अक्षर **a = शून्य;
	माप_प्रकार i, n = 0;
	काष्ठा sshbuf *b = शून्य;
	u_int tmp;
	पूर्णांक r = SSH_ERR_INTERNAL_ERROR;

	अगर ((r = sshbuf_get_u32(m, &tmp)) != 0 ||
	    (r = sshbuf_froms(m, &b)) != 0)
		जाओ out;
	अगर (tmp > पूर्णांक_उच्च) {
		r = SSH_ERR_INVALID_FORMAT;
		जाओ out;
	}
	n = tmp;
	अगर (n > 0 && (a = सुस्मृति(n, माप(*a))) == शून्य) {
		r = SSH_ERR_ALLOC_FAIL;
		जाओ out;
	}
	क्रम (i = 0; i < n; i++) {
		अगर ((r = sshbuf_get_cstring(b, &a[i], शून्य)) != 0)
			जाओ out;
	}
	/* success */
	r = 0;
	*ap = a;
	a = शून्य;
	*np = n;
	n = 0;
 out:
	अगर (a != शून्य) {
		क्रम (i = 0; i < n; i++)
			मुक्त(a[i]);
		मुक्त(a);
	}
	sshbuf_free(b);
	वापस r;
}

अटल पूर्णांक
serialise_nullable_string(काष्ठा sshbuf *m, स्थिर अक्षर *s)
{
	पूर्णांक r;

	अगर ((r = sshbuf_put_u8(m, s == शून्य)) != 0 ||
	    (r = sshbuf_put_cstring(m, s)) != 0)
		वापस r;
	वापस 0;
}

अटल पूर्णांक
deserialise_nullable_string(काष्ठा sshbuf *m, अक्षर **sp)
{
	पूर्णांक r;
	u_char flag;

	*sp = शून्य;
	अगर ((r = sshbuf_get_u8(m, &flag)) != 0 ||
	    (r = sshbuf_get_cstring(m, flag ? शून्य : sp, शून्य)) != 0)
		वापस r;
	वापस 0;
}

पूर्णांक
sshauthopt_serialise(स्थिर काष्ठा sshauthopt *opts, काष्ठा sshbuf *m,
    पूर्णांक untrusted)
{
	पूर्णांक r = SSH_ERR_INTERNAL_ERROR;

	/* Flag options */
	अगर ((r = sshbuf_put_u8(m, opts->permit_port_forwarding_flag)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->permit_agent_forwarding_flag)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->permit_x11_forwarding_flag)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->permit_pty_flag)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->permit_user_rc)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->restricted)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->cert_authority)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->no_require_user_presence)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->require_verify)) != 0)
		वापस r;

	/* Simple integer options */
	अगर ((r = sshbuf_put_u64(m, opts->valid_before)) != 0)
		वापस r;

	/* tunnel number can be negative to indicate "unset" */
	अगर ((r = sshbuf_put_u8(m, opts->force_tun_device == -1)) != 0 ||
	    (r = sshbuf_put_u32(m, (opts->force_tun_device < 0) ?
	    0 : (u_int)opts->force_tun_device)) != 0)
		वापस r;

	/* String options; these may be NULL */
	अगर ((r = serialise_nullable_string(m,
	    untrusted ? "yes" : opts->cert_principals)) != 0 ||
	    (r = serialise_nullable_string(m,
	    untrusted ? "true" : opts->force_command)) != 0 ||
	    (r = serialise_nullable_string(m,
	    untrusted ? शून्य : opts->required_from_host_cert)) != 0 ||
	    (r = serialise_nullable_string(m,
	    untrusted ? शून्य : opts->required_from_host_कुंजियाँ)) != 0)
		वापस r;

	/* Array options */
	अगर ((r = serialise_array(m, opts->env,
	    untrusted ? 0 : opts->nenv)) != 0 ||
	    (r = serialise_array(m, opts->permitopen,
	    untrusted ? 0 : opts->npermitopen)) != 0 ||
	    (r = serialise_array(m, opts->permitlisten,
	    untrusted ? 0 : opts->npermitlisten)) != 0)
		वापस r;

	/* success */
	वापस 0;
}

पूर्णांक
sshauthopt_deserialise(काष्ठा sshbuf *m, काष्ठा sshauthopt **optsp)
{
	काष्ठा sshauthopt *opts = शून्य;
	पूर्णांक r = SSH_ERR_INTERNAL_ERROR;
	u_char f;
	u_int tmp;

	अगर ((opts = सुस्मृति(1, माप(*opts))) == शून्य)
		वापस SSH_ERR_ALLOC_FAIL;

	/* Flag options */
#घोषणा OPT_FLAG(x) \
	करो { \
		अगर ((r = sshbuf_get_u8(m, &f)) != 0) \
			जाओ out; \
		opts->x = f; \
	} जबतक (0)
	OPT_FLAG(permit_port_forwarding_flag);
	OPT_FLAG(permit_agent_forwarding_flag);
	OPT_FLAG(permit_x11_forwarding_flag);
	OPT_FLAG(permit_pty_flag);
	OPT_FLAG(permit_user_rc);
	OPT_FLAG(restricted);
	OPT_FLAG(cert_authority);
	OPT_FLAG(no_require_user_presence);
	OPT_FLAG(require_verify);
#अघोषित OPT_FLAG

	/* Simple integer options */
	अगर ((r = sshbuf_get_u64(m, &opts->valid_before)) != 0)
		जाओ out;

	/* tunnel number can be negative to indicate "unset" */
	अगर ((r = sshbuf_get_u8(m, &f)) != 0 ||
	    (r = sshbuf_get_u32(m, &tmp)) != 0)
		जाओ out;
	opts->force_tun_device = f ? -1 : (पूर्णांक)tmp;

	/* String options may be NULL */
	अगर ((r = deserialise_nullable_string(m, &opts->cert_principals)) != 0 ||
	    (r = deserialise_nullable_string(m, &opts->force_command)) != 0 ||
	    (r = deserialise_nullable_string(m,
	    &opts->required_from_host_cert)) != 0 ||
	    (r = deserialise_nullable_string(m,
	    &opts->required_from_host_कुंजियाँ)) != 0)
		जाओ out;

	/* Array options */
	अगर ((r = deserialise_array(m, &opts->env, &opts->nenv)) != 0 ||
	    (r = deserialise_array(m,
	    &opts->permitopen, &opts->npermitopen)) != 0 ||
	    (r = deserialise_array(m,
	    &opts->permitlisten, &opts->npermitlisten)) != 0)
		जाओ out;

	/* success */
	r = 0;
	*optsp = opts;
	opts = शून्य;
 out:
	sshauthopt_free(opts);
	वापस r;
}
