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

#ضمن "includes.h"

#ضمن <sys/types.h>
#ضمن <sys/queue.h>

#ضمن <stdlib.h>
#ضمن <netdb.h>
#ضمن <pwd.h>
#ضمن <string.h>
#ضمن <stdio.h>
#ضمن <stdint.h>
#ضمن <stdarg.h>
#ضمن <ctype.h>
#ضمن <limits.h>

#ضمن "xmalloc.h"
#ضمن "ssherr.h"
#ضمن "log.h"
#ضمن "sshbuf.h"
#ضمن "misc.h"
#ضمن "sshkey.h"
#ضمن "match.h"
#ضمن "ssh2.h"
#ضمن "auth-options.h"

ساكن صحيح
dup_رشتهها(حرف ***dstp, اندازه_t *ndstp, حرف **src, اندازه_t nsrc)
{
	حرف **dst;
	اندازه_t i, j;

	*dstp = عدم;
	*ndstp = 0;

	إذا (nsrc == 0)
		أرجع 0;
	إذا (nsrc >= SIZE_MAX / حجم(*src) ||
	    (dst = حافظه_صفر_بده(nsrc, حجم(*src))) == عدم)
		أرجع -1;
	لكل (i = 0; i < nsrc; i++) {
		إذا ((dst[i] = strdup(src[i])) == عدم) {
			لكل (j = 0; j < i; j++)
				حرر(dst[j]);
			حرر(dst);
			أرجع -1;
		}
	}
	/* success */
	*dstp = dst;
	*ndstp = nsrc;
	أرجع 0;
}

#تعریف_کن OPTIONS_CRITICAL	1
#تعریف_کن OPTIONS_EXTENSIONS	2
ساكن صحيح
cert_option_list(بنية sshauthopt *opts, بنية sshbuf *oblob,
    u_int which, صحيح crit)
{
	حرف *command, *allowed;
	حرف *name = عدم;
	بنية sshbuf *c = عدم, *داده = عدم;
	صحيح r, ret = -1, یافت;

	إذا ((c = sshbuf_fromb(oblob)) == عدم) {
		error_f("sshbuf_fromb failed");
		اذهب بیرون;
	}

	طالما (sshbuf_len(c) > 0) {
		sshbuf_free(داده);
		داده = عدم;
		إذا ((r = sshbuf_get_cstring(c, &name, عدم)) != 0 ||
		    (r = sshbuf_froms(c, &داده)) != 0) {
			error_r(r, "Unable to parse certificate options");
			اذهب بیرون;
		}
		debug3("found certificate option \"%.100s\" len %zu",
		    name, sshbuf_len(داده));
		یافت = 0;
		إذا ((which & OPTIONS_EXTENSIONS) != 0) {
			إذا (strcmp(name, "no-touch-required") == 0) {
				opts->no_require_user_presence = 1;
				یافت = 1;
			} وإلا إذا (strcmp(name, "permit-X11-forwarding") == 0) {
				opts->permit_x11_forwarding_flag = 1;
				یافت = 1;
			} وإلا إذا (strcmp(name,
			    "permit-agent-forwarding") == 0) {
				opts->permit_agent_forwarding_flag = 1;
				یافت = 1;
			} وإلا إذا (strcmp(name,
			    "permit-port-forwarding") == 0) {
				opts->permit_پورت_forwarding_flag = 1;
				یافت = 1;
			} وإلا إذا (strcmp(name, "permit-pty") == 0) {
				opts->permit_pty_flag = 1;
				یافت = 1;
			} وإلا إذا (strcmp(name, "permit-user-rc") == 0) {
				opts->permit_user_rc = 1;
				یافت = 1;
			}
		}
		إذا (!یافت && (which & OPTIONS_CRITICAL) != 0) {
			إذا (strcmp(name, "verify-required") == 0) {
				opts->require_verify = 1;
				یافت = 1;
			} وإلا إذا (strcmp(name, "force-command") == 0) {
				إذا ((r = sshbuf_get_cstring(داده, &command,
				    عدم)) != 0) {
					error_r(r, "Unable to parse \"%s\" "
					    "section", name);
					اذهب بیرون;
				}
				إذا (opts->force_command != عدم) {
					error("Certificate has multiple "
					    "force-command options");
					حرر(command);
					اذهب بیرون;
				}
				opts->force_command = command;
				یافت = 1;
			} وإلا إذا (strcmp(name, "source-address") == 0) {
				إذا ((r = sshbuf_get_cstring(داده, &allowed,
				    عدم)) != 0) {
					error_r(r, "Unable to parse \"%s\" "
					    "section", name);
					اذهب بیرون;
				}
				إذا (opts->required_from_host_cert != عدم) {
					error("Certificate has multiple "
					    "source-address options");
					حرر(allowed);
					اذهب بیرون;
				}
				/* Check syntax */
				إذا (addr_تطابق_cidr_list(عدم, allowed) == -1) {
					error("Certificate source-address "
					    "contents invalid");
					حرر(allowed);
					اذهب بیرون;
				}
				opts->required_from_host_cert = allowed;
				یافت = 1;
			}
		}

		إذا (!یافت) {
			إذا (crit) {
				error("Certificate critical option \"%s\" "
				    "is not supported", name);
				اذهب بیرون;
			} وإلا {
				logit("Certificate extension \"%s\" "
				    "is not supported", name);
			}
		} وإلا إذا (sshbuf_len(داده) != 0) {
			error("Certificate option \"%s\" corrupt "
			    "(extra data)", name);
			اذهب بیرون;
		}
		حرر(name);
		name = عدم;
	}
	/* successfully parsed all options */
	ret = 0;

 بیرون:
	حرر(name);
	sshbuf_free(داده);
	sshbuf_free(c);
	أرجع ret;
}

بنية sshauthopt *
sshauthopt_new(فراغ)
{
	بنية sshauthopt *ret;

	إذا ((ret = حافظه_صفر_بده(1, حجم(*ret))) == عدم)
		أرجع عدم;
	ret->force_tun_device = -1;
	أرجع ret;
}

فراغ
sshauthopt_free(بنية sshauthopt *opts)
{
	اندازه_t i;

	إذا (opts == عدم)
		أرجع;

	حرر(opts->cert_principals);
	حرر(opts->force_command);
	حرر(opts->required_from_host_cert);
	حرر(opts->required_from_host_کلیدها);

	لكل (i = 0; i < opts->nenv; i++)
		حرر(opts->env[i]);
	حرر(opts->env);

	لكل (i = 0; i < opts->npermitopen; i++)
		حرر(opts->permitopen[i]);
	حرر(opts->permitopen);

	لكل (i = 0; i < opts->npermitlisten; i++)
		حرر(opts->permitlisten[i]);
	حرر(opts->permitlisten);

	freezero(opts, حجم(*opts));
}

بنية sshauthopt *
sshauthopt_new_with_کلیدها_defaults(فراغ)
{
	بنية sshauthopt *ret = عدم;

	إذا ((ret = sshauthopt_new()) == عدم)
		أرجع عدم;

	/* Defaults for authorized_keys flags */
	ret->permit_پورت_forwarding_flag = 1;
	ret->permit_agent_forwarding_flag = 1;
	ret->permit_x11_forwarding_flag = 1;
	ret->permit_pty_flag = 1;
	ret->permit_user_rc = 1;
	أرجع ret;
}

/*
 * Parse and record a permitopen/permitlisten directive.
 * Return 0 on success. Return -1 on failure and sets *errstrp to error reason.
 */
ساكن صحيح
handle_permit(ثابت حرف **optsp, صحيح allow_bare_پورت,
    حرف ***permitsp, اندازه_t *npermitsp, ثابت حرف **errstrp)
{
	حرف *opt, *tmp, *cp, *host, **permits = *permitsp;
	اندازه_t npermits = *npermitsp;
	ثابت حرف *errstr = "unknown error";

	إذا (npermits > SSH_AUTHOPT_PERMIT_MAX) {
		*errstrp = "too many permission directives";
		أرجع -1;
	}
	إذا ((opt = opt_dequote(optsp, &errstr)) == عدم) {
		أرجع -1;
	}
	إذا (allow_bare_پورت && strchr(opt, ':') == عدم) {
		/*
		 * Allow a bare port number in permitlisten to indicate a
		 * listen_host wildcard.
		 */
		إذا (asprintf(&tmp, "*:%s", opt) == -1) {
			حرر(opt);
			*errstrp = "memory allocation failed";
			أرجع -1;
		}
		حرر(opt);
		opt = tmp;
	}
	إذا ((tmp = strdup(opt)) == عدم) {
		حرر(opt);
		*errstrp = "memory allocation failed";
		أرجع -1;
	}
	cp = tmp;
	/* validate syntax before recording it. */
	host = hpdelim2(&cp, عدم);
	إذا (host == عدم || طول_رشته(host) >= NI_MAXHOST) {
		حرر(tmp);
		حرر(opt);
		*errstrp = "invalid permission hostname";
		أرجع -1;
	}
	/*
	 * don't want to use permitopen_port to avoid
	 * dependency on channels.[ch] here.
	 */
	إذا (cp == عدم ||
	    (strcmp(cp, "*") != 0 && a2port(cp) <= 0)) {
		حرر(tmp);
		حرر(opt);
		*errstrp = "invalid permission port";
		أرجع -1;
	}
	/* XXX - add streamlocal support */
	حرر(tmp);
	/* Record it */
	إذا ((permits = recallocarray(permits, npermits, npermits + 1,
	    حجم(*permits))) == عدم) {
		حرر(opt);
		/* NB. don't update *permitsp if alloc fails */
		*errstrp = "memory allocation failed";
		أرجع -1;
	}
	permits[npermits++] = opt;
	*permitsp = permits;
	*npermitsp = npermits;
	أرجع 0;
}

بنية sshauthopt *
sshauthopt_parse(ثابت حرف *opts, ثابت حرف **errstrp)
{
	حرف **oarray, *opt, *cp, *tmp;
	صحيح r;
	بنية sshauthopt *ret = عدم;
	ثابت حرف *errstr = "unknown error";
	uint64_t valid_before;
	اندازه_t i, l;

	إذا (errstrp != عدم)
		*errstrp = عدم;
	إذا ((ret = sshauthopt_new_with_کلیدها_defaults()) == عدم)
		اذهب alloc_fail;

	إذا (opts == عدم)
		أرجع ret;

	طالما (*opts && *opts != ' ' && *opts != '\t') {
		/* flag options */
		إذا ((r = opt_flag("restrict", 0, &opts)) != -1) {
			ret->restricted = 1;
			ret->permit_پورت_forwarding_flag = 0;
			ret->permit_agent_forwarding_flag = 0;
			ret->permit_x11_forwarding_flag = 0;
			ret->permit_pty_flag = 0;
			ret->permit_user_rc = 0;
		} وإلا إذا ((r = opt_flag("cert-authority", 0, &opts)) != -1) {
			ret->cert_authority = r;
		} وإلا إذا ((r = opt_flag("port-forwarding", 1, &opts)) != -1) {
			ret->permit_پورت_forwarding_flag = r == 1;
		} وإلا إذا ((r = opt_flag("agent-forwarding", 1, &opts)) != -1) {
			ret->permit_agent_forwarding_flag = r == 1;
		} وإلا إذا ((r = opt_flag("x11-forwarding", 1, &opts)) != -1) {
			ret->permit_x11_forwarding_flag = r == 1;
		} وإلا إذا ((r = opt_flag("touch-required", 1, &opts)) != -1) {
			ret->no_require_user_presence = r != 1; /* NB. flip */
		} وإلا إذا ((r = opt_flag("verify-required", 1, &opts)) != -1) {
			ret->require_verify = r == 1;
		} وإلا إذا ((r = opt_flag("pty", 1, &opts)) != -1) {
			ret->permit_pty_flag = r == 1;
		} وإلا إذا ((r = opt_flag("user-rc", 1, &opts)) != -1) {
			ret->permit_user_rc = r == 1;
		} وإلا إذا (opt_تطابق(&opts, "command")) {
			إذا (ret->force_command != عدم) {
				errstr = "multiple \"command\" clauses";
				اذهب fail;
			}
			ret->force_command = opt_dequote(&opts, &errstr);
			إذا (ret->force_command == عدم)
				اذهب fail;
		} وإلا إذا (opt_تطابق(&opts, "principals")) {
			إذا (ret->cert_principals != عدم) {
				errstr = "multiple \"principals\" clauses";
				اذهب fail;
			}
			ret->cert_principals = opt_dequote(&opts, &errstr);
			إذا (ret->cert_principals == عدم)
				اذهب fail;
		} وإلا إذا (opt_تطابق(&opts, "from")) {
			إذا (ret->required_from_host_کلیدها != عدم) {
				errstr = "multiple \"from\" clauses";
				اذهب fail;
			}
			ret->required_from_host_کلیدها = opt_dequote(&opts,
			    &errstr);
			إذا (ret->required_from_host_کلیدها == عدم)
				اذهب fail;
		} وإلا إذا (opt_تطابق(&opts, "expiry-time")) {
			إذا ((opt = opt_dequote(&opts, &errstr)) == عدم)
				اذهب fail;
			إذا (parse_absolute_زمان(opt, &valid_before) != 0 ||
			    valid_before == 0) {
				حرر(opt);
				errstr = "invalid expires time";
				اذهب fail;
			}
			حرر(opt);
			إذا (ret->valid_before == 0 ||
			    valid_before < ret->valid_before)
				ret->valid_before = valid_before;
		} وإلا إذا (opt_تطابق(&opts, "environment")) {
			إذا (ret->nenv > SSH_AUTHOPT_ENV_MAX) {
				errstr = "too many environment strings";
				اذهب fail;
			}
			إذا ((opt = opt_dequote(&opts, &errstr)) == عدم)
				اذهب fail;
			/* env name must be alphanumeric and followed by '=' */
			إذا ((tmp = strchr(opt, '=')) == عدم) {
				حرر(opt);
				errstr = "invalid environment string";
				اذهب fail;
			}
			إذا ((cp = strdup(opt)) == عدم) {
				حرر(opt);
				اذهب alloc_fail;
			}
			l = (اندازه_t)(tmp - opt);
			cp[l] = '\0'; /* truncate at '=' */
			إذا (!valid_env_name(cp)) {
				حرر(cp);
				حرر(opt);
				errstr = "invalid environment string";
				اذهب fail;
			}
			/* Check for duplicates; XXX O(n*log(n)) */
			لكل (i = 0; i < ret->nenv; i++) {
				إذا (مقایسه_رشته(ret->env[i], cp, l) == 0 &&
				    ret->env[i][l] == '=')
					اكسر;
			}
			حرر(cp);
			/* First match wins */
			إذا (i >= ret->nenv) {
				/* Append it. */
				oarray = ret->env;
				إذا ((ret->env = recallocarray(ret->env,
				    ret->nenv, ret->nenv + 1,
				    حجم(*ret->env))) == عدم) {
					حرر(opt);
					/* put it back for cleanup */
					ret->env = oarray;
					اذهب alloc_fail;
				}
				ret->env[ret->nenv++] = opt;
				opt = عدم; /* transferred */
			}
			حرر(opt);
		} وإلا إذا (opt_تطابق(&opts, "permitopen")) {
			إذا (handle_permit(&opts, 0, &ret->permitopen,
			    &ret->npermitopen, &errstr) != 0)
				اذهب fail;
		} وإلا إذا (opt_تطابق(&opts, "permitlisten")) {
			إذا (handle_permit(&opts, 1, &ret->permitlisten,
			    &ret->npermitlisten, &errstr) != 0)
				اذهب fail;
		} وإلا إذا (opt_تطابق(&opts, "tunnel")) {
			إذا ((opt = opt_dequote(&opts, &errstr)) == عدم)
				اذهب fail;
			ret->force_tun_device = a2tun(opt, عدم);
			حرر(opt);
			إذا (ret->force_tun_device == SSH_TUNID_ERR) {
				errstr = "invalid tun device";
				اذهب fail;
			}
		}
		/*
		 * Skip the comma, and move to the next option
		 * (or break out if there are no more).
		 */
		إذا (*opts == '\0' || *opts == ' ' || *opts == '\t')
			اكسر;		/* End of options. */
		/* Anything other than a comma is an unknown option */
		إذا (*opts != ',') {
			errstr = "unknown key option";
			اذهب fail;
		}
		opts++;
		إذا (*opts == '\0') {
			errstr = "unexpected end-of-options";
			اذهب fail;
		}
	}

	/* success */
	إذا (errstrp != عدم)
		*errstrp = عدم;
	أرجع ret;

alloc_fail:
	errstr = "memory allocation failed";
fail:
	sshauthopt_free(ret);
	إذا (errstrp != عدم)
		*errstrp = errstr;
	أرجع عدم;
}

بنية sshauthopt *
sshauthopt_from_cert(بنية sshkey *k)
{
	بنية sshauthopt *ret;

	إذا (k == عدم || !sshkey_type_is_cert(k->type) || k->cert == عدم ||
	    k->cert->type != SSH2_CERT_TYPE_USER)
		أرجع عدم;

	إذا ((ret = sshauthopt_new()) == عدم)
		أرجع عدم;

	/* Handle options and critical extensions separately */
	إذا (cert_option_list(ret, k->cert->critical,
	    OPTIONS_CRITICAL, 1) == -1) {
		sshauthopt_free(ret);
		أرجع عدم;
	}
	إذا (cert_option_list(ret, k->cert->extensions,
	    OPTIONS_EXTENSIONS, 0) == -1) {
		sshauthopt_free(ret);
		أرجع عدم;
	}
	/* success */
	أرجع ret;
}

/*
 * Merges "additional" options to "primary" and returns the result.
 * NB. Some options from primary have primacy.
 */
بنية sshauthopt *
sshauthopt_ادغام(ثابت بنية sshauthopt *primary,
    ثابت بنية sshauthopt *additional, ثابت حرف **errstrp)
{
	بنية sshauthopt *ret;
	ثابت حرف *errstr = "internal error";
	ثابت حرف *tmp;

	إذا (errstrp != عدم)
		*errstrp = عدم;

	إذا ((ret = sshauthopt_new()) == عدم)
		اذهب alloc_fail;

	/* cert_authority and cert_principals are cleared in result */

	/* Prefer access lists from primary. */
	/* XXX err is both set and mismatch? */
	tmp = primary->required_from_host_cert;
	إذا (tmp == عدم)
		tmp = additional->required_from_host_cert;
	إذا (tmp != عدم && (ret->required_from_host_cert = strdup(tmp)) == عدم)
		اذهب alloc_fail;
	tmp = primary->required_from_host_کلیدها;
	إذا (tmp == عدم)
		tmp = additional->required_from_host_کلیدها;
	إذا (tmp != عدم && (ret->required_from_host_کلیدها = strdup(tmp)) == عدم)
		اذهب alloc_fail;

	/*
	 * force_tun_device, permitopen/permitlisten and environment all
	 * prefer the primary.
	 */
	ret->force_tun_device = primary->force_tun_device;
	إذا (ret->force_tun_device == -1)
		ret->force_tun_device = additional->force_tun_device;
	إذا (primary->nenv > 0) {
		إذا (dup_رشتهها(&ret->env, &ret->nenv,
		    primary->env, primary->nenv) != 0)
			اذهب alloc_fail;
	} وإلا إذا (additional->nenv) {
		إذا (dup_رشتهها(&ret->env, &ret->nenv,
		    additional->env, additional->nenv) != 0)
			اذهب alloc_fail;
	}
	إذا (primary->npermitopen > 0) {
		إذا (dup_رشتهها(&ret->permitopen, &ret->npermitopen,
		    primary->permitopen, primary->npermitopen) != 0)
			اذهب alloc_fail;
	} وإلا إذا (additional->npermitopen > 0) {
		إذا (dup_رشتهها(&ret->permitopen, &ret->npermitopen,
		    additional->permitopen, additional->npermitopen) != 0)
			اذهب alloc_fail;
	}

	إذا (primary->npermitlisten > 0) {
		إذا (dup_رشتهها(&ret->permitlisten, &ret->npermitlisten,
		    primary->permitlisten, primary->npermitlisten) != 0)
			اذهب alloc_fail;
	} وإلا إذا (additional->npermitlisten > 0) {
		إذا (dup_رشتهها(&ret->permitlisten, &ret->npermitlisten,
		    additional->permitlisten, additional->npermitlisten) != 0)
			اذهب alloc_fail;
	}

#تعریف_کن OPTFLAG_AND(x) ret->x = (primary->x == 1) && (additional->x == 1)
#تعریف_کن OPTFLAG_OR(x) ret->x = (primary->x == 1) || (additional->x == 1)
	/* Permissive flags are logical-AND (i.e. must be set in both) */
	OPTFLAG_AND(permit_پورت_forwarding_flag);
	OPTFLAG_AND(permit_agent_forwarding_flag);
	OPTFLAG_AND(permit_x11_forwarding_flag);
	OPTFLAG_AND(permit_pty_flag);
	OPTFLAG_AND(permit_user_rc);
	OPTFLAG_AND(no_require_user_presence);
	/* Restrictive flags are logical-OR (i.e. must be set in either) */
	OPTFLAG_OR(require_verify);
	OPTFLAG_OR(restricted);
#لغو_تعریف OPTFLAG_AND

	/* Earliest expiry time should win */
	إذا (primary->valid_before != 0)
		ret->valid_before = primary->valid_before;
	إذا (additional->valid_before != 0 &&
	    additional->valid_before < ret->valid_before)
		ret->valid_before = additional->valid_before;

	/*
	 * When both multiple forced-command are specified, only
	 * proceed if they are identical, otherwise fail.
	 */
	إذا (primary->force_command != عدم &&
	    additional->force_command != عدم) {
		إذا (strcmp(primary->force_command,
		    additional->force_command) == 0) {
			/* ok */
			ret->force_command = strdup(primary->force_command);
			إذا (ret->force_command == عدم)
				اذهب alloc_fail;
		} وإلا {
			errstr = "forced command options do not match";
			اذهب fail;
		}
	} وإلا إذا (primary->force_command != عدم) {
		إذا ((ret->force_command = strdup(
		    primary->force_command)) == عدم)
			اذهب alloc_fail;
	} وإلا إذا (additional->force_command != عدم) {
		إذا ((ret->force_command = strdup(
		    additional->force_command)) == عدم)
			اذهب alloc_fail;
	}
	/* success */
	إذا (errstrp != عدم)
		*errstrp = عدم;
	أرجع ret;

 alloc_fail:
	errstr = "memory allocation failed";
 fail:
	إذا (errstrp != عدم)
		*errstrp = errstr;
	sshauthopt_free(ret);
	أرجع عدم;
}

/*
 * Copy options
 */
بنية sshauthopt *
sshauthopt_copy(ثابت بنية sshauthopt *orig)
{
	بنية sshauthopt *ret;

	إذا ((ret = sshauthopt_new()) == عدم)
		أرجع عدم;

#تعریف_کن OPTSCALAR(x) ret->x = orig->x
	OPTSCALAR(permit_پورت_forwarding_flag);
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
#لغو_تعریف OPTSCALAR
#تعریف_کن OPTSTRING(x) \
	افعل { \
		إذا (orig->x != عدم && (ret->x = strdup(orig->x)) == عدم) { \
			sshauthopt_free(ret); \
			أرجع عدم; \
		} \
	} طالما (0)
	OPTSTRING(cert_principals);
	OPTSTRING(force_command);
	OPTSTRING(required_from_host_cert);
	OPTSTRING(required_from_host_کلیدها);
#لغو_تعریف OPTSTRING

	إذا (dup_رشتهها(&ret->env, &ret->nenv, orig->env, orig->nenv) != 0 ||
	    dup_رشتهها(&ret->permitopen, &ret->npermitopen,
	    orig->permitopen, orig->npermitopen) != 0 ||
	    dup_رشتهها(&ret->permitlisten, &ret->npermitlisten,
	    orig->permitlisten, orig->npermitlisten) != 0) {
		sshauthopt_free(ret);
		أرجع عدم;
	}
	أرجع ret;
}

ساكن صحيح
serialise_array(بنية sshbuf *m, حرف **a, اندازه_t n)
{
	بنية sshbuf *b;
	اندازه_t i;
	صحيح r = SSH_ERR_داخلی_ERROR;

	إذا (n > بیشترین_صحیح)
		أرجع SSH_ERR_داخلی_ERROR;

	إذا ((b = sshbuf_new()) == عدم) {
		أرجع SSH_ERR_ALLOC_FAIL;
	}
	لكل (i = 0; i < n; i++) {
		إذا ((r = sshbuf_put_cstring(b, a[i])) != 0)
			اذهب بیرون;
	}
	إذا ((r = sshbuf_put_u32(m, n)) != 0 ||
	    (r = sshbuf_put_stringb(m, b)) != 0)
		اذهب بیرون;
	/* success */
	r = 0;
 بیرون:
	sshbuf_free(b);
	أرجع r;
}

ساكن صحيح
deserialise_array(بنية sshbuf *m, حرف ***ap, اندازه_t *np)
{
	حرف **a = عدم;
	اندازه_t i, n = 0;
	بنية sshbuf *b = عدم;
	u_int tmp;
	صحيح r = SSH_ERR_داخلی_ERROR;

	إذا ((r = sshbuf_get_u32(m, &tmp)) != 0 ||
	    (r = sshbuf_froms(m, &b)) != 0)
		اذهب بیرون;
	إذا (tmp > بیشترین_صحیح) {
		r = SSH_ERR_INVALID_FORMAT;
		اذهب بیرون;
	}
	n = tmp;
	إذا (n > 0 && (a = حافظه_صفر_بده(n, حجم(*a))) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب بیرون;
	}
	لكل (i = 0; i < n; i++) {
		إذا ((r = sshbuf_get_cstring(b, &a[i], عدم)) != 0)
			اذهب بیرون;
	}
	/* success */
	r = 0;
	*ap = a;
	a = عدم;
	*np = n;
	n = 0;
 بیرون:
	إذا (a != عدم) {
		لكل (i = 0; i < n; i++)
			حرر(a[i]);
		حرر(a);
	}
	sshbuf_free(b);
	أرجع r;
}

ساكن صحيح
serialise_nullable_string(بنية sshbuf *m, ثابت حرف *s)
{
	صحيح r;

	إذا ((r = sshbuf_put_u8(m, s == عدم)) != 0 ||
	    (r = sshbuf_put_cstring(m, s)) != 0)
		أرجع r;
	أرجع 0;
}

ساكن صحيح
deserialise_nullable_string(بنية sshbuf *m, حرف **sp)
{
	صحيح r;
	u_char flag;

	*sp = عدم;
	إذا ((r = sshbuf_get_u8(m, &flag)) != 0 ||
	    (r = sshbuf_get_cstring(m, flag ? عدم : sp, عدم)) != 0)
		أرجع r;
	أرجع 0;
}

صحيح
sshauthopt_serialise(ثابت بنية sshauthopt *opts, بنية sshbuf *m,
    صحيح untrusted)
{
	صحيح r = SSH_ERR_داخلی_ERROR;

	/* Flag options */
	إذا ((r = sshbuf_put_u8(m, opts->permit_پورت_forwarding_flag)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->permit_agent_forwarding_flag)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->permit_x11_forwarding_flag)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->permit_pty_flag)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->permit_user_rc)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->restricted)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->cert_authority)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->no_require_user_presence)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->require_verify)) != 0)
		أرجع r;

	/* Simple integer options */
	إذا ((r = sshbuf_put_u64(m, opts->valid_before)) != 0)
		أرجع r;

	/* tunnel number can be negative to indicate "unset" */
	إذا ((r = sshbuf_put_u8(m, opts->force_tun_device == -1)) != 0 ||
	    (r = sshbuf_put_u32(m, (opts->force_tun_device < 0) ?
	    0 : (u_int)opts->force_tun_device)) != 0)
		أرجع r;

	/* String options; these may be NULL */
	إذا ((r = serialise_nullable_string(m,
	    untrusted ? "yes" : opts->cert_principals)) != 0 ||
	    (r = serialise_nullable_string(m,
	    untrusted ? "true" : opts->force_command)) != 0 ||
	    (r = serialise_nullable_string(m,
	    untrusted ? عدم : opts->required_from_host_cert)) != 0 ||
	    (r = serialise_nullable_string(m,
	    untrusted ? عدم : opts->required_from_host_کلیدها)) != 0)
		أرجع r;

	/* Array options */
	إذا ((r = serialise_array(m, opts->env,
	    untrusted ? 0 : opts->nenv)) != 0 ||
	    (r = serialise_array(m, opts->permitopen,
	    untrusted ? 0 : opts->npermitopen)) != 0 ||
	    (r = serialise_array(m, opts->permitlisten,
	    untrusted ? 0 : opts->npermitlisten)) != 0)
		أرجع r;

	/* success */
	أرجع 0;
}

صحيح
sshauthopt_deserialise(بنية sshbuf *m, بنية sshauthopt **optsp)
{
	بنية sshauthopt *opts = عدم;
	صحيح r = SSH_ERR_داخلی_ERROR;
	u_char f;
	u_int tmp;

	إذا ((opts = حافظه_صفر_بده(1, حجم(*opts))) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;

	/* Flag options */
#تعریف_کن OPT_FLAG(x) \
	افعل { \
		إذا ((r = sshbuf_get_u8(m, &f)) != 0) \
			اذهب بیرون; \
		opts->x = f; \
	} طالما (0)
	OPT_FLAG(permit_پورت_forwarding_flag);
	OPT_FLAG(permit_agent_forwarding_flag);
	OPT_FLAG(permit_x11_forwarding_flag);
	OPT_FLAG(permit_pty_flag);
	OPT_FLAG(permit_user_rc);
	OPT_FLAG(restricted);
	OPT_FLAG(cert_authority);
	OPT_FLAG(no_require_user_presence);
	OPT_FLAG(require_verify);
#لغو_تعریف OPT_FLAG

	/* Simple integer options */
	إذا ((r = sshbuf_get_u64(m, &opts->valid_before)) != 0)
		اذهب بیرون;

	/* tunnel number can be negative to indicate "unset" */
	إذا ((r = sshbuf_get_u8(m, &f)) != 0 ||
	    (r = sshbuf_get_u32(m, &tmp)) != 0)
		اذهب بیرون;
	opts->force_tun_device = f ? -1 : (صحيح)tmp;

	/* String options may be NULL */
	إذا ((r = deserialise_nullable_string(m, &opts->cert_principals)) != 0 ||
	    (r = deserialise_nullable_string(m, &opts->force_command)) != 0 ||
	    (r = deserialise_nullable_string(m,
	    &opts->required_from_host_cert)) != 0 ||
	    (r = deserialise_nullable_string(m,
	    &opts->required_from_host_کلیدها)) != 0)
		اذهب بیرون;

	/* Array options */
	إذا ((r = deserialise_array(m, &opts->env, &opts->nenv)) != 0 ||
	    (r = deserialise_array(m,
	    &opts->permitopen, &opts->npermitopen)) != 0 ||
	    (r = deserialise_array(m,
	    &opts->permitlisten, &opts->npermitlisten)) != 0)
		اذهب بیرون;

	/* success */
	r = 0;
	*optsp = opts;
	opts = عدم;
 بیرون:
	sshauthopt_free(opts);
	أرجع r;
}
