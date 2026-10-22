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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <sys/types.h>
#ଅନ୍ତର୍ଭାଵ <sys/queue.h>

#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <netdb.h>
#ଅନ୍ତର୍ଭାଵ <pwd.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <stdint.h>
#ଅନ୍ତର୍ଭାଵ <stdarg.h>
#ଅନ୍ତର୍ଭାଵ <ctype.h>
#ଅନ୍ତର୍ଭାଵ <limits.h>

#ଅନ୍ତର୍ଭାଵ "xmalloc.h"
#ଅନ୍ତର୍ଭାଵ "ssherr.h"
#ଅନ୍ତର୍ଭାଵ "log.h"
#ଅନ୍ତର୍ଭାଵ "sshbuf.h"
#ଅନ୍ତର୍ଭାଵ "misc.h"
#ଅନ୍ତର୍ଭାଵ "sshkey.h"
#ଅନ୍ତର୍ଭାଵ "match.h"
#ଅନ୍ତର୍ଭାଵ "ssh2.h"
#ଅନ୍ତର୍ଭାଵ "auth-options.h"

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
dup_strings(ଅକ୍ଷର ***dstp, size_t *ndstp, ଅକ୍ଷର **src, size_t nsrc)
{
	ଅକ୍ଷର **dst;
	size_t i, j;

	*dstp = ଖାଲି;
	*ndstp = 0;

	ଯଦି (nsrc == 0)
		ଫେରନ୍ତୁ 0;
	ଯଦି (nsrc >= SIZE_MAX / ଆକାର(*src) ||
	    (dst = calloc(nsrc, ଆକାର(*src))) == ଖାଲି)
		ଫେରନ୍ତୁ -1;
	ପାଇଁ (i = 0; i < nsrc; i++) {
		ଯଦି ((dst[i] = strdup(src[i])) == ଖାଲି) {
			ପାଇଁ (j = 0; j < i; j++)
				ମୁକ୍ତ(dst[j]);
			ମୁକ୍ତ(dst);
			ଫେରନ୍ତୁ -1;
		}
	}
	/* success */
	*dstp = dst;
	*ndstp = nsrc;
	ଫେରନ୍ତୁ 0;
}

#define OPTIONS_CRITICAL	1
#define OPTIONS_EXTENSIONS	2
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
cert_option_list(ସଂରଚନା sshauthopt *opts, ସଂରଚନା sshbuf *oblob,
    u_int which, ପୂର୍ଣ୍ଣସଂଖ୍ୟା crit)
{
	ଅକ୍ଷର *command, *allowed;
	ଅକ୍ଷର *name = ଖାଲି;
	ସଂରଚନା sshbuf *c = ଖାଲି, *data = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, ret = -1, found;

	ଯଦି ((c = sshbuf_fromb(oblob)) == ଖାଲି) {
		error_f("sshbuf_fromb failed");
		ଯାଅ out;
	}

	ଯେତେବେଳେ (sshbuf_len(c) > 0) {
		sshbuf_free(data);
		data = ଖାଲି;
		ଯଦି ((r = sshbuf_get_cstring(c, &name, ଖାଲି)) != 0 ||
		    (r = sshbuf_froms(c, &data)) != 0) {
			error_r(r, "Unable to parse certificate options");
			ଯାଅ out;
		}
		debug3("found certificate option \"%.100s\" len %zu",
		    name, sshbuf_len(data));
		found = 0;
		ଯଦି ((which & OPTIONS_EXTENSIONS) != 0) {
			ଯଦି (strcmp(name, "no-touch-required") == 0) {
				opts->no_require_user_presence = 1;
				found = 1;
			} ଅନ୍ୟଥା ଯଦି (strcmp(name, "permit-X11-forwarding") == 0) {
				opts->permit_x11_forwarding_flag = 1;
				found = 1;
			} ଅନ୍ୟଥା ଯଦି (strcmp(name,
			    "permit-agent-forwarding") == 0) {
				opts->permit_agent_forwarding_flag = 1;
				found = 1;
			} ଅନ୍ୟଥା ଯଦି (strcmp(name,
			    "permit-port-forwarding") == 0) {
				opts->permit_port_forwarding_flag = 1;
				found = 1;
			} ଅନ୍ୟଥା ଯଦି (strcmp(name, "permit-pty") == 0) {
				opts->permit_pty_flag = 1;
				found = 1;
			} ଅନ୍ୟଥା ଯଦି (strcmp(name, "permit-user-rc") == 0) {
				opts->permit_user_rc = 1;
				found = 1;
			}
		}
		ଯଦି (!found && (which & OPTIONS_CRITICAL) != 0) {
			ଯଦି (strcmp(name, "verify-required") == 0) {
				opts->require_verify = 1;
				found = 1;
			} ଅନ୍ୟଥା ଯଦି (strcmp(name, "force-command") == 0) {
				ଯଦି ((r = sshbuf_get_cstring(data, &command,
				    ଖାଲି)) != 0) {
					error_r(r, "Unable to parse \"%s\" "
					    "section", name);
					ଯାଅ out;
				}
				ଯଦି (opts->force_command != ଖାଲି) {
					error("Certificate has multiple "
					    "force-command options");
					ମୁକ୍ତ(command);
					ଯାଅ out;
				}
				opts->force_command = command;
				found = 1;
			} ଅନ୍ୟଥା ଯଦି (strcmp(name, "source-address") == 0) {
				ଯଦି ((r = sshbuf_get_cstring(data, &allowed,
				    ଖାଲି)) != 0) {
					error_r(r, "Unable to parse \"%s\" "
					    "section", name);
					ଯାଅ out;
				}
				ଯଦି (opts->required_from_host_cert != ଖାଲି) {
					error("Certificate has multiple "
					    "source-address options");
					ମୁକ୍ତ(allowed);
					ଯାଅ out;
				}
				/* Check syntax */
				ଯଦି (addr_match_cidr_list(ଖାଲି, allowed) == -1) {
					error("Certificate source-address "
					    "contents invalid");
					ମୁକ୍ତ(allowed);
					ଯାଅ out;
				}
				opts->required_from_host_cert = allowed;
				found = 1;
			}
		}

		ଯଦି (!found) {
			ଯଦି (crit) {
				error("Certificate critical option \"%s\" "
				    "is not supported", name);
				ଯାଅ out;
			} ଅନ୍ୟଥା {
				logit("Certificate extension \"%s\" "
				    "is not supported", name);
			}
		} ଅନ୍ୟଥା ଯଦି (sshbuf_len(data) != 0) {
			error("Certificate option \"%s\" corrupt "
			    "(extra data)", name);
			ଯାଅ out;
		}
		ମୁକ୍ତ(name);
		name = ଖାଲି;
	}
	/* successfully parsed all options */
	ret = 0;

 out:
	ମୁକ୍ତ(name);
	sshbuf_free(data);
	sshbuf_free(c);
	ଫେରନ୍ତୁ ret;
}

ସଂରଚନା sshauthopt *
sshauthopt_new(ଶୂନ୍ୟ)
{
	ସଂରଚନା sshauthopt *ret;

	ଯଦି ((ret = calloc(1, ଆକାର(*ret))) == ଖାଲି)
		ଫେରନ୍ତୁ ଖାଲି;
	ret->force_tun_device = -1;
	ଫେରନ୍ତୁ ret;
}

ଶୂନ୍ୟ
sshauthopt_free(ସଂରଚନା sshauthopt *opts)
{
	size_t i;

	ଯଦି (opts == ଖାଲି)
		ଫେରନ୍ତୁ;

	ମୁକ୍ତ(opts->cert_principals);
	ମୁକ୍ତ(opts->force_command);
	ମୁକ୍ତ(opts->required_from_host_cert);
	ମୁକ୍ତ(opts->required_from_host_ଚାବିଗୁଡ଼ିକ);

	ପାଇଁ (i = 0; i < opts->nenv; i++)
		ମୁକ୍ତ(opts->env[i]);
	ମୁକ୍ତ(opts->env);

	ପାଇଁ (i = 0; i < opts->npermitopen; i++)
		ମୁକ୍ତ(opts->permitopen[i]);
	ମୁକ୍ତ(opts->permitopen);

	ପାଇଁ (i = 0; i < opts->npermitlisten; i++)
		ମୁକ୍ତ(opts->permitlisten[i]);
	ମୁକ୍ତ(opts->permitlisten);

	freezero(opts, ଆକାର(*opts));
}

ସଂରଚନା sshauthopt *
sshauthopt_new_with_ଚାବିଗୁଡ଼ିକ_defaults(ଶୂନ୍ୟ)
{
	ସଂରଚନା sshauthopt *ret = ଖାଲି;

	ଯଦି ((ret = sshauthopt_new()) == ଖାଲି)
		ଫେରନ୍ତୁ ଖାଲି;

	/* Defaults for authorized_keys flags */
	ret->permit_port_forwarding_flag = 1;
	ret->permit_agent_forwarding_flag = 1;
	ret->permit_x11_forwarding_flag = 1;
	ret->permit_pty_flag = 1;
	ret->permit_user_rc = 1;
	ଫେରନ୍ତୁ ret;
}

/*
 * Parse and record a permitopen/permitlisten directive.
 * Return 0 on success. Return -1 on failure and sets *errstrp to error reason.
 */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
handle_permit(ଅଚଳ ଅକ୍ଷର **optsp, ପୂର୍ଣ୍ଣସଂଖ୍ୟା allow_bare_port,
    ଅକ୍ଷର ***permitsp, size_t *npermitsp, ଅଚଳ ଅକ୍ଷର **errstrp)
{
	ଅକ୍ଷର *opt, *tmp, *cp, *host, **permits = *permitsp;
	size_t npermits = *npermitsp;
	ଅଚଳ ଅକ୍ଷର *errstr = "unknown error";

	ଯଦି (npermits > SSH_AUTHOPT_PERMIT_MAX) {
		*errstrp = "too many permission directives";
		ଫେରନ୍ତୁ -1;
	}
	ଯଦି ((opt = opt_dequote(optsp, &errstr)) == ଖାଲି) {
		ଫେରନ୍ତୁ -1;
	}
	ଯଦି (allow_bare_port && strchr(opt, ':') == ଖାଲି) {
		/*
		 * Allow a bare port number in permitlisten to indicate a
		 * listen_host wildcard.
		 */
		ଯଦି (asprintf(&tmp, "*:%s", opt) == -1) {
			ମୁକ୍ତ(opt);
			*errstrp = "memory allocation failed";
			ଫେରନ୍ତୁ -1;
		}
		ମୁକ୍ତ(opt);
		opt = tmp;
	}
	ଯଦି ((tmp = strdup(opt)) == ଖାଲି) {
		ମୁକ୍ତ(opt);
		*errstrp = "memory allocation failed";
		ଫେରନ୍ତୁ -1;
	}
	cp = tmp;
	/* validate syntax before recording it. */
	host = hpdelim2(&cp, ଖାଲି);
	ଯଦି (host == ଖାଲି || strlen(host) >= NI_MAXHOST) {
		ମୁକ୍ତ(tmp);
		ମୁକ୍ତ(opt);
		*errstrp = "invalid permission hostname";
		ଫେରନ୍ତୁ -1;
	}
	/*
	 * don't want to use permitopen_port to avoid
	 * dependency on channels.[ch] here.
	 */
	ଯଦି (cp == ଖାଲି ||
	    (strcmp(cp, "*") != 0 && a2port(cp) <= 0)) {
		ମୁକ୍ତ(tmp);
		ମୁକ୍ତ(opt);
		*errstrp = "invalid permission port";
		ଫେରନ୍ତୁ -1;
	}
	/* XXX - add streamlocal support */
	ମୁକ୍ତ(tmp);
	/* Record it */
	ଯଦି ((permits = recallocarray(permits, npermits, npermits + 1,
	    ଆକାର(*permits))) == ଖାଲି) {
		ମୁକ୍ତ(opt);
		/* NB. don't update *permitsp if alloc fails */
		*errstrp = "memory allocation failed";
		ଫେରନ୍ତୁ -1;
	}
	permits[npermits++] = opt;
	*permitsp = permits;
	*npermitsp = npermits;
	ଫେରନ୍ତୁ 0;
}

ସଂରଚନା sshauthopt *
sshauthopt_parse(ଅଚଳ ଅକ୍ଷର *opts, ଅଚଳ ଅକ୍ଷର **errstrp)
{
	ଅକ୍ଷର **oarray, *opt, *cp, *tmp;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	ସଂରଚନା sshauthopt *ret = ଖାଲି;
	ଅଚଳ ଅକ୍ଷର *errstr = "unknown error";
	uint64_t valid_before;
	size_t i, l;

	ଯଦି (errstrp != ଖାଲି)
		*errstrp = ଖାଲି;
	ଯଦି ((ret = sshauthopt_new_with_ଚାବିଗୁଡ଼ିକ_defaults()) == ଖାଲି)
		ଯାଅ alloc_fail;

	ଯଦି (opts == ଖାଲି)
		ଫେରନ୍ତୁ ret;

	ଯେତେବେଳେ (*opts && *opts != ' ' && *opts != '\t') {
		/* flag options */
		ଯଦି ((r = opt_flag("restrict", 0, &opts)) != -1) {
			ret->restricted = 1;
			ret->permit_port_forwarding_flag = 0;
			ret->permit_agent_forwarding_flag = 0;
			ret->permit_x11_forwarding_flag = 0;
			ret->permit_pty_flag = 0;
			ret->permit_user_rc = 0;
		} ଅନ୍ୟଥା ଯଦି ((r = opt_flag("cert-authority", 0, &opts)) != -1) {
			ret->cert_authority = r;
		} ଅନ୍ୟଥା ଯଦି ((r = opt_flag("port-forwarding", 1, &opts)) != -1) {
			ret->permit_port_forwarding_flag = r == 1;
		} ଅନ୍ୟଥା ଯଦି ((r = opt_flag("agent-forwarding", 1, &opts)) != -1) {
			ret->permit_agent_forwarding_flag = r == 1;
		} ଅନ୍ୟଥା ଯଦି ((r = opt_flag("x11-forwarding", 1, &opts)) != -1) {
			ret->permit_x11_forwarding_flag = r == 1;
		} ଅନ୍ୟଥା ଯଦି ((r = opt_flag("touch-required", 1, &opts)) != -1) {
			ret->no_require_user_presence = r != 1; /* NB. flip */
		} ଅନ୍ୟଥା ଯଦି ((r = opt_flag("verify-required", 1, &opts)) != -1) {
			ret->require_verify = r == 1;
		} ଅନ୍ୟଥା ଯଦି ((r = opt_flag("pty", 1, &opts)) != -1) {
			ret->permit_pty_flag = r == 1;
		} ଅନ୍ୟଥା ଯଦି ((r = opt_flag("user-rc", 1, &opts)) != -1) {
			ret->permit_user_rc = r == 1;
		} ଅନ୍ୟଥା ଯଦି (opt_match(&opts, "command")) {
			ଯଦି (ret->force_command != ଖାଲି) {
				errstr = "multiple \"command\" clauses";
				ଯାଅ fail;
			}
			ret->force_command = opt_dequote(&opts, &errstr);
			ଯଦି (ret->force_command == ଖାଲି)
				ଯାଅ fail;
		} ଅନ୍ୟଥା ଯଦି (opt_match(&opts, "principals")) {
			ଯଦି (ret->cert_principals != ଖାଲି) {
				errstr = "multiple \"principals\" clauses";
				ଯାଅ fail;
			}
			ret->cert_principals = opt_dequote(&opts, &errstr);
			ଯଦି (ret->cert_principals == ଖାଲି)
				ଯାଅ fail;
		} ଅନ୍ୟଥା ଯଦି (opt_match(&opts, "from")) {
			ଯଦି (ret->required_from_host_ଚାବିଗୁଡ଼ିକ != ଖାଲି) {
				errstr = "multiple \"from\" clauses";
				ଯାଅ fail;
			}
			ret->required_from_host_ଚାବିଗୁଡ଼ିକ = opt_dequote(&opts,
			    &errstr);
			ଯଦି (ret->required_from_host_ଚାବିଗୁଡ଼ିକ == ଖାଲି)
				ଯାଅ fail;
		} ଅନ୍ୟଥା ଯଦି (opt_match(&opts, "expiry-time")) {
			ଯଦି ((opt = opt_dequote(&opts, &errstr)) == ଖାଲି)
				ଯାଅ fail;
			ଯଦି (parse_absolute_time(opt, &valid_before) != 0 ||
			    valid_before == 0) {
				ମୁକ୍ତ(opt);
				errstr = "invalid expires time";
				ଯାଅ fail;
			}
			ମୁକ୍ତ(opt);
			ଯଦି (ret->valid_before == 0 ||
			    valid_before < ret->valid_before)
				ret->valid_before = valid_before;
		} ଅନ୍ୟଥା ଯଦି (opt_match(&opts, "environment")) {
			ଯଦି (ret->nenv > SSH_AUTHOPT_ENV_MAX) {
				errstr = "too many environment strings";
				ଯାଅ fail;
			}
			ଯଦି ((opt = opt_dequote(&opts, &errstr)) == ଖାଲି)
				ଯାଅ fail;
			/* env name must be alphanumeric and followed by '=' */
			ଯଦି ((tmp = strchr(opt, '=')) == ଖାଲି) {
				ମୁକ୍ତ(opt);
				errstr = "invalid environment string";
				ଯାଅ fail;
			}
			ଯଦି ((cp = strdup(opt)) == ଖାଲି) {
				ମୁକ୍ତ(opt);
				ଯାଅ alloc_fail;
			}
			l = (size_t)(tmp - opt);
			cp[l] = '\0'; /* truncate at '=' */
			ଯଦି (!valid_env_name(cp)) {
				ମୁକ୍ତ(cp);
				ମୁକ୍ତ(opt);
				errstr = "invalid environment string";
				ଯାଅ fail;
			}
			/* Check for duplicates; XXX O(n*log(n)) */
			ପାଇଁ (i = 0; i < ret->nenv; i++) {
				ଯଦି (strncmp(ret->env[i], cp, l) == 0 &&
				    ret->env[i][l] == '=')
					ଭାଙ୍ଗ;
			}
			ମୁକ୍ତ(cp);
			/* First match wins */
			ଯଦି (i >= ret->nenv) {
				/* Append it. */
				oarray = ret->env;
				ଯଦି ((ret->env = recallocarray(ret->env,
				    ret->nenv, ret->nenv + 1,
				    ଆକାର(*ret->env))) == ଖାଲି) {
					ମୁକ୍ତ(opt);
					/* put it back for cleanup */
					ret->env = oarray;
					ଯାଅ alloc_fail;
				}
				ret->env[ret->nenv++] = opt;
				opt = ଖାଲି; /* transferred */
			}
			ମୁକ୍ତ(opt);
		} ଅନ୍ୟଥା ଯଦି (opt_match(&opts, "permitopen")) {
			ଯଦି (handle_permit(&opts, 0, &ret->permitopen,
			    &ret->npermitopen, &errstr) != 0)
				ଯାଅ fail;
		} ଅନ୍ୟଥା ଯଦି (opt_match(&opts, "permitlisten")) {
			ଯଦି (handle_permit(&opts, 1, &ret->permitlisten,
			    &ret->npermitlisten, &errstr) != 0)
				ଯାଅ fail;
		} ଅନ୍ୟଥା ଯଦି (opt_match(&opts, "tunnel")) {
			ଯଦି ((opt = opt_dequote(&opts, &errstr)) == ଖାଲି)
				ଯାଅ fail;
			ret->force_tun_device = a2tun(opt, ଖାଲି);
			ମୁକ୍ତ(opt);
			ଯଦି (ret->force_tun_device == SSH_TUNID_ERR) {
				errstr = "invalid tun device";
				ଯାଅ fail;
			}
		}
		/*
		 * Skip the comma, and move to the next option
		 * (or break out if there are no more).
		 */
		ଯଦି (*opts == '\0' || *opts == ' ' || *opts == '\t')
			ଭାଙ୍ଗ;		/* End of options. */
		/* Anything other than a comma is an unknown option */
		ଯଦି (*opts != ',') {
			errstr = "unknown key option";
			ଯାଅ fail;
		}
		opts++;
		ଯଦି (*opts == '\0') {
			errstr = "unexpected end-of-options";
			ଯାଅ fail;
		}
	}

	/* success */
	ଯଦି (errstrp != ଖାଲି)
		*errstrp = ଖାଲି;
	ଫେରନ୍ତୁ ret;

alloc_fail:
	errstr = "memory allocation failed";
fail:
	sshauthopt_free(ret);
	ଯଦି (errstrp != ଖାଲି)
		*errstrp = errstr;
	ଫେରନ୍ତୁ ଖାଲି;
}

ସଂରଚନା sshauthopt *
sshauthopt_from_cert(ସଂରଚନା sshkey *k)
{
	ସଂରଚନା sshauthopt *ret;

	ଯଦି (k == ଖାଲି || !sshkey_type_is_cert(k->type) || k->cert == ଖାଲି ||
	    k->cert->type != SSH2_CERT_TYPE_USER)
		ଫେରନ୍ତୁ ଖାଲି;

	ଯଦି ((ret = sshauthopt_new()) == ଖାଲି)
		ଫେରନ୍ତୁ ଖାଲି;

	/* Handle options and critical extensions separately */
	ଯଦି (cert_option_list(ret, k->cert->critical,
	    OPTIONS_CRITICAL, 1) == -1) {
		sshauthopt_free(ret);
		ଫେରନ୍ତୁ ଖାଲି;
	}
	ଯଦି (cert_option_list(ret, k->cert->extensions,
	    OPTIONS_EXTENSIONS, 0) == -1) {
		sshauthopt_free(ret);
		ଫେରନ୍ତୁ ଖାଲି;
	}
	/* success */
	ଫେରନ୍ତୁ ret;
}

/*
 * Merges "additional" options to "primary" and returns the result.
 * NB. Some options from primary have primacy.
 */
ସଂରଚନା sshauthopt *
sshauthopt_merge(ଅଚଳ ସଂରଚନା sshauthopt *primary,
    ଅଚଳ ସଂରଚନା sshauthopt *additional, ଅଚଳ ଅକ୍ଷର **errstrp)
{
	ସଂରଚନା sshauthopt *ret;
	ଅଚଳ ଅକ୍ଷର *errstr = "internal error";
	ଅଚଳ ଅକ୍ଷର *tmp;

	ଯଦି (errstrp != ଖାଲି)
		*errstrp = ଖାଲି;

	ଯଦି ((ret = sshauthopt_new()) == ଖାଲି)
		ଯାଅ alloc_fail;

	/* cert_authority and cert_principals are cleared in result */

	/* Prefer access lists from primary. */
	/* XXX err is both set and mismatch? */
	tmp = primary->required_from_host_cert;
	ଯଦି (tmp == ଖାଲି)
		tmp = additional->required_from_host_cert;
	ଯଦି (tmp != ଖାଲି && (ret->required_from_host_cert = strdup(tmp)) == ଖାଲି)
		ଯାଅ alloc_fail;
	tmp = primary->required_from_host_ଚାବିଗୁଡ଼ିକ;
	ଯଦି (tmp == ଖାଲି)
		tmp = additional->required_from_host_ଚାବିଗୁଡ଼ିକ;
	ଯଦି (tmp != ଖାଲି && (ret->required_from_host_ଚାବିଗୁଡ଼ିକ = strdup(tmp)) == ଖାଲି)
		ଯାଅ alloc_fail;

	/*
	 * force_tun_device, permitopen/permitlisten and environment all
	 * prefer the primary.
	 */
	ret->force_tun_device = primary->force_tun_device;
	ଯଦି (ret->force_tun_device == -1)
		ret->force_tun_device = additional->force_tun_device;
	ଯଦି (primary->nenv > 0) {
		ଯଦି (dup_strings(&ret->env, &ret->nenv,
		    primary->env, primary->nenv) != 0)
			ଯାଅ alloc_fail;
	} ଅନ୍ୟଥା ଯଦି (additional->nenv) {
		ଯଦି (dup_strings(&ret->env, &ret->nenv,
		    additional->env, additional->nenv) != 0)
			ଯାଅ alloc_fail;
	}
	ଯଦି (primary->npermitopen > 0) {
		ଯଦି (dup_strings(&ret->permitopen, &ret->npermitopen,
		    primary->permitopen, primary->npermitopen) != 0)
			ଯାଅ alloc_fail;
	} ଅନ୍ୟଥା ଯଦି (additional->npermitopen > 0) {
		ଯଦି (dup_strings(&ret->permitopen, &ret->npermitopen,
		    additional->permitopen, additional->npermitopen) != 0)
			ଯାଅ alloc_fail;
	}

	ଯଦି (primary->npermitlisten > 0) {
		ଯଦି (dup_strings(&ret->permitlisten, &ret->npermitlisten,
		    primary->permitlisten, primary->npermitlisten) != 0)
			ଯାଅ alloc_fail;
	} ଅନ୍ୟଥା ଯଦି (additional->npermitlisten > 0) {
		ଯଦି (dup_strings(&ret->permitlisten, &ret->npermitlisten,
		    additional->permitlisten, additional->npermitlisten) != 0)
			ଯାଅ alloc_fail;
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
	ଯଦି (primary->valid_before != 0)
		ret->valid_before = primary->valid_before;
	ଯଦି (additional->valid_before != 0 &&
	    additional->valid_before < ret->valid_before)
		ret->valid_before = additional->valid_before;

	/*
	 * When both multiple forced-command are specified, only
	 * proceed if they are identical, otherwise fail.
	 */
	ଯଦି (primary->force_command != ଖାଲି &&
	    additional->force_command != ଖାଲି) {
		ଯଦି (strcmp(primary->force_command,
		    additional->force_command) == 0) {
			/* ok */
			ret->force_command = strdup(primary->force_command);
			ଯଦି (ret->force_command == ଖାଲି)
				ଯାଅ alloc_fail;
		} ଅନ୍ୟଥା {
			errstr = "forced command options do not match";
			ଯାଅ fail;
		}
	} ଅନ୍ୟଥା ଯଦି (primary->force_command != ଖାଲି) {
		ଯଦି ((ret->force_command = strdup(
		    primary->force_command)) == ଖାଲି)
			ଯାଅ alloc_fail;
	} ଅନ୍ୟଥା ଯଦି (additional->force_command != ଖାଲି) {
		ଯଦି ((ret->force_command = strdup(
		    additional->force_command)) == ଖାଲି)
			ଯାଅ alloc_fail;
	}
	/* success */
	ଯଦି (errstrp != ଖାଲି)
		*errstrp = ଖାଲି;
	ଫେରନ୍ତୁ ret;

 alloc_fail:
	errstr = "memory allocation failed";
 fail:
	ଯଦି (errstrp != ଖାଲି)
		*errstrp = errstr;
	sshauthopt_free(ret);
	ଫେରନ୍ତୁ ଖାଲି;
}

/*
 * Copy options
 */
ସଂରଚନା sshauthopt *
sshauthopt_copy(ଅଚଳ ସଂରଚନା sshauthopt *orig)
{
	ସଂରଚନା sshauthopt *ret;

	ଯଦି ((ret = sshauthopt_new()) == ଖାଲି)
		ଫେରନ୍ତୁ ଖାଲି;

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
	କର { \
		ଯଦି (orig->x != ଖାଲି && (ret->x = strdup(orig->x)) == ଖାଲି) { \
			sshauthopt_free(ret); \
			ଫେରନ୍ତୁ ଖାଲି; \
		} \
	} ଯେତେବେଳେ (0)
	OPTSTRING(cert_principals);
	OPTSTRING(force_command);
	OPTSTRING(required_from_host_cert);
	OPTSTRING(required_from_host_ଚାବିଗୁଡ଼ିକ);
#undef OPTSTRING

	ଯଦି (dup_strings(&ret->env, &ret->nenv, orig->env, orig->nenv) != 0 ||
	    dup_strings(&ret->permitopen, &ret->npermitopen,
	    orig->permitopen, orig->npermitopen) != 0 ||
	    dup_strings(&ret->permitlisten, &ret->npermitlisten,
	    orig->permitlisten, orig->npermitlisten) != 0) {
		sshauthopt_free(ret);
		ଫେରନ୍ତୁ ଖାଲି;
	}
	ଫେରନ୍ତୁ ret;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
serialise_array(ସଂରଚନା sshbuf *m, ଅକ୍ଷର **a, size_t n)
{
	ସଂରଚନା sshbuf *b;
	size_t i;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r = SSH_ERR_INTERNAL_ERROR;

	ଯଦି (n > INT_MAX)
		ଫେରନ୍ତୁ SSH_ERR_INTERNAL_ERROR;

	ଯଦି ((b = sshbuf_new()) == ଖାଲି) {
		ଫେରନ୍ତୁ SSH_ERR_ALLOC_FAIL;
	}
	ପାଇଁ (i = 0; i < n; i++) {
		ଯଦି ((r = sshbuf_put_cstring(b, a[i])) != 0)
			ଯାଅ out;
	}
	ଯଦି ((r = sshbuf_put_u32(m, n)) != 0 ||
	    (r = sshbuf_put_stringb(m, b)) != 0)
		ଯାଅ out;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	ଫେରନ୍ତୁ r;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
deserialise_array(ସଂରଚନା sshbuf *m, ଅକ୍ଷର ***ap, size_t *np)
{
	ଅକ୍ଷର **a = ଖାଲି;
	size_t i, n = 0;
	ସଂରଚନା sshbuf *b = ଖାଲି;
	u_int tmp;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r = SSH_ERR_INTERNAL_ERROR;

	ଯଦି ((r = sshbuf_get_u32(m, &tmp)) != 0 ||
	    (r = sshbuf_froms(m, &b)) != 0)
		ଯାଅ out;
	ଯଦି (tmp > INT_MAX) {
		r = SSH_ERR_INVALID_FORMAT;
		ଯାଅ out;
	}
	n = tmp;
	ଯଦି (n > 0 && (a = calloc(n, ଆକାର(*a))) == ଖାଲି) {
		r = SSH_ERR_ALLOC_FAIL;
		ଯାଅ out;
	}
	ପାଇଁ (i = 0; i < n; i++) {
		ଯଦି ((r = sshbuf_get_cstring(b, &a[i], ଖାଲି)) != 0)
			ଯାଅ out;
	}
	/* success */
	r = 0;
	*ap = a;
	a = ଖାଲି;
	*np = n;
	n = 0;
 out:
	ଯଦି (a != ଖାଲି) {
		ପାଇଁ (i = 0; i < n; i++)
			ମୁକ୍ତ(a[i]);
		ମୁକ୍ତ(a);
	}
	sshbuf_free(b);
	ଫେରନ୍ତୁ r;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
serialise_nullable_string(ସଂରଚନା sshbuf *m, ଅଚଳ ଅକ୍ଷର *s)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((r = sshbuf_put_u8(m, s == ଖାଲି)) != 0 ||
	    (r = sshbuf_put_cstring(m, s)) != 0)
		ଫେରନ୍ତୁ r;
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
deserialise_nullable_string(ସଂରଚନା sshbuf *m, ଅକ୍ଷର **sp)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	u_char flag;

	*sp = ଖାଲି;
	ଯଦି ((r = sshbuf_get_u8(m, &flag)) != 0 ||
	    (r = sshbuf_get_cstring(m, flag ? ଖାଲି : sp, ଖାଲି)) != 0)
		ଫେରନ୍ତୁ r;
	ଫେରନ୍ତୁ 0;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshauthopt_serialise(ଅଚଳ ସଂରଚନା sshauthopt *opts, ସଂରଚନା sshbuf *m,
    ପୂର୍ଣ୍ଣସଂଖ୍ୟା untrusted)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r = SSH_ERR_INTERNAL_ERROR;

	/* Flag options */
	ଯଦି ((r = sshbuf_put_u8(m, opts->permit_port_forwarding_flag)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->permit_agent_forwarding_flag)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->permit_x11_forwarding_flag)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->permit_pty_flag)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->permit_user_rc)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->restricted)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->cert_authority)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->no_require_user_presence)) != 0 ||
	    (r = sshbuf_put_u8(m, opts->require_verify)) != 0)
		ଫେରନ୍ତୁ r;

	/* Simple integer options */
	ଯଦି ((r = sshbuf_put_u64(m, opts->valid_before)) != 0)
		ଫେରନ୍ତୁ r;

	/* tunnel number can be negative to indicate "unset" */
	ଯଦି ((r = sshbuf_put_u8(m, opts->force_tun_device == -1)) != 0 ||
	    (r = sshbuf_put_u32(m, (opts->force_tun_device < 0) ?
	    0 : (u_int)opts->force_tun_device)) != 0)
		ଫେରନ୍ତୁ r;

	/* String options; these may be NULL */
	ଯଦି ((r = serialise_nullable_string(m,
	    untrusted ? "yes" : opts->cert_principals)) != 0 ||
	    (r = serialise_nullable_string(m,
	    untrusted ? "true" : opts->force_command)) != 0 ||
	    (r = serialise_nullable_string(m,
	    untrusted ? ଖାଲି : opts->required_from_host_cert)) != 0 ||
	    (r = serialise_nullable_string(m,
	    untrusted ? ଖାଲି : opts->required_from_host_ଚାବିଗୁଡ଼ିକ)) != 0)
		ଫେରନ୍ତୁ r;

	/* Array options */
	ଯଦି ((r = serialise_array(m, opts->env,
	    untrusted ? 0 : opts->nenv)) != 0 ||
	    (r = serialise_array(m, opts->permitopen,
	    untrusted ? 0 : opts->npermitopen)) != 0 ||
	    (r = serialise_array(m, opts->permitlisten,
	    untrusted ? 0 : opts->npermitlisten)) != 0)
		ଫେରନ୍ତୁ r;

	/* success */
	ଫେରନ୍ତୁ 0;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshauthopt_deserialise(ସଂରଚନା sshbuf *m, ସଂରଚନା sshauthopt **optsp)
{
	ସଂରଚନା sshauthopt *opts = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r = SSH_ERR_INTERNAL_ERROR;
	u_char f;
	u_int tmp;

	ଯଦି ((opts = calloc(1, ଆକାର(*opts))) == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_ALLOC_FAIL;

	/* Flag options */
#define OPT_FLAG(x) \
	କର { \
		ଯଦି ((r = sshbuf_get_u8(m, &f)) != 0) \
			ଯାଅ out; \
		opts->x = f; \
	} ଯେତେବେଳେ (0)
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
	ଯଦି ((r = sshbuf_get_u64(m, &opts->valid_before)) != 0)
		ଯାଅ out;

	/* tunnel number can be negative to indicate "unset" */
	ଯଦି ((r = sshbuf_get_u8(m, &f)) != 0 ||
	    (r = sshbuf_get_u32(m, &tmp)) != 0)
		ଯାଅ out;
	opts->force_tun_device = f ? -1 : (ପୂର୍ଣ୍ଣସଂଖ୍ୟା)tmp;

	/* String options may be NULL */
	ଯଦି ((r = deserialise_nullable_string(m, &opts->cert_principals)) != 0 ||
	    (r = deserialise_nullable_string(m, &opts->force_command)) != 0 ||
	    (r = deserialise_nullable_string(m,
	    &opts->required_from_host_cert)) != 0 ||
	    (r = deserialise_nullable_string(m,
	    &opts->required_from_host_ଚାବିଗୁଡ଼ିକ)) != 0)
		ଯାଅ out;

	/* Array options */
	ଯଦି ((r = deserialise_array(m, &opts->env, &opts->nenv)) != 0 ||
	    (r = deserialise_array(m,
	    &opts->permitopen, &opts->npermitopen)) != 0 ||
	    (r = deserialise_array(m,
	    &opts->permitlisten, &opts->npermitlisten)) != 0)
		ଯାଅ out;

	/* success */
	r = 0;
	*optsp = opts;
	opts = ଖାଲି;
 out:
	sshauthopt_free(opts);
	ଫେରନ୍ତୁ r;
}
