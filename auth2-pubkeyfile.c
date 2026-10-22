/* $OpenBSD: auth2-pubkeyfile.c,v 1.8 2026/04/02 07:48:13 djm Exp $ */
/*
 * Copyright (c) 2000 Markus Friedl.  All rights reserved.
 * Copyright (c) 2010 Damien Miller.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <sys/stat.h>

#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <errno.h>
#अन्तर्भाव <fcntl.h>
#अन्तर्भाव <pwd.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <time.h>
#अन्तर्भाव <unistd.h>

#अन्तर्भाव "ssh.h"
#अन्तर्भाव "log.h"
#अन्तर्भाव "misc.h"
#अन्तर्भाव "sshkey.h"
#अन्तर्भाव "digest.h"
#अन्तर्भाव "hostfile.h"
#अन्तर्भाव "auth.h"
#अन्तर्भाव "auth-options.h"
#अन्तर्भाव "authfile.h"
#अन्तर्भाव "match.h"
#अन्तर्भाव "ssherr.h"
#अन्तर्भाव "xmalloc.h"

पूर्णांक
auth_authorise_keyopts(संरचना passwd *pw, संरचना sshauthopt *opts,
    पूर्णांक allow_cert_authority, स्थिरांक अक्षर *remote_ip, स्थिरांक अक्षर *remote_host,
    स्थिरांक अक्षर *loc)
{
	समय_प्रकार now = समय(रिक्त);
	अक्षर buf[64];

	/*
	 * Check keys/principals file expiry time.
	 * NB. validity interval in certificate is handled elsewhere.
	 */
	जर (opts->valid_before && now > 0 &&
	    opts->valid_before < (uint64_t)now) {
		format_absolute_time(opts->valid_before, buf, आकार(buf));
		debug("%s: entry expired at %s", loc, buf);
		auth_debug_add("%s: entry expired at %s", loc, buf);
		परत -1;
	}
	/* Consistency checks */
	जर (opts->cert_principals != रिक्त && !opts->cert_authority) {
		debug("%s: principals on non-CA key", loc);
		auth_debug_add("%s: principals on non-CA key", loc);
		/* deny access */
		परत -1;
	}
	/* cert-authority flag isn't valid in authorized_principals files */
	जर (!allow_cert_authority && opts->cert_authority) {
		debug("%s: cert-authority flag invalid here", loc);
		auth_debug_add("%s: cert-authority flag invalid here", loc);
		/* deny access */
		परत -1;
	}

	/* Perform from= checks */
	जर (opts->required_from_host_किल्ल्या != रिक्त) {
		निवड (match_host_and_ip(remote_host, remote_ip,
		    opts->required_from_host_किल्ल्या )) {
		स्थिती 1:
			/* Host name matches. */
			थांबा;
		स्थिती -1:
		पूर्वनिर्धारित:
			debug("%s: invalid from criteria", loc);
			auth_debug_add("%s: invalid from criteria", loc);
			/* FALLTHROUGH */
		स्थिती 0:
			logit("%s: Authentication tried for %.100s with "
			    "correct key but not from a permitted "
			    "host (host=%.200s, ip=%.200s, required=%.200s).",
			    loc, pw->pw_name, remote_host, remote_ip,
			    opts->required_from_host_किल्ल्या);
			auth_debug_add("%s: Your host '%.200s' is not "
			    "permitted to use this key for login.",
			    loc, remote_host);
			/* deny access */
			परत -1;
		}
	}
	/* Check source-address restriction from certificate */
	जर (opts->required_from_host_cert != रिक्त) {
		निवड (addr_match_cidr_list(remote_ip,
		    opts->required_from_host_cert)) {
		स्थिती 1:
			/* accepted */
			थांबा;
		स्थिती -1:
		पूर्वनिर्धारित:
			/* invalid */
			error("%s: Certificate source-address invalid", loc);
			/* FALLTHROUGH */
		स्थिती 0:
			logit("%s: Authentication tried for %.100s with valid "
			    "certificate but not from a permitted source "
			    "address (%.200s).", loc, pw->pw_name, remote_ip);
			auth_debug_add("%s: Your address '%.200s' is not "
			    "permitted to use this certificate for login.",
			    loc, remote_ip);
			परत -1;
		}
	}
	/*
	 *
	 * XXX this is spammy. We should report remotely only for keys
	 *     that are successful in actual auth attempts, and not PK_OK
	 *     tests.
	 */
	auth_log_authopts(loc, opts, 1);

	परत 0;
}

स्थिर पूर्णांक
match_principals_option(स्थिरांक अक्षर *principal_list, संरचना sshkey_cert *cert)
{
	अक्षर *list, *olist, *entry;
	u_int i;

	olist = list = xstrdup(principal_list);
	साठी (;;) {
		जर ((entry = strsep(&list, ",")) == रिक्त || *entry == '\0')
			थांबा;
		साठी (i = 0; i < cert->nprincipals; i++) {
			जर (म_भेद(entry, cert->principals[i]) == 0) {
				debug3("matched principal from key i"
				    "options \"%.100s\"", entry);
				मुक्त(olist);
				परत 1;
			}
		}
	}
	मुक्त(olist);
	परत 0;
}

/*
 * Process a single authorized_principals format line. Returns 0 and sets
 * authoptsp is principal is authorised, -1 otherwise. "loc" is used as a
 * log preamble for file/line information.
 */
पूर्णांक
auth_check_principals_ओळ(अक्षर *cp, स्थिरांक संरचना sshkey_cert *cert,
    स्थिरांक अक्षर *loc, संरचना sshauthopt **authoptsp)
{
	u_int i, found = 0;
	अक्षर *ep, *ओळ_opts;
	स्थिरांक अक्षर *reason = रिक्त;
	संरचना sshauthopt *opts = रिक्त;

	जर (authoptsp != रिक्त)
		*authoptsp = रिक्त;

	/* Trim trailing whitespace. */
	ep = cp + म_माप(cp) - 1;
	पर्यंत (ep > cp && (*ep == '\n' || *ep == ' ' || *ep == '\t'))
		*ep-- = '\0';

	/*
	 * If the line has internal whitespace then assume it has
	 * key options.
	 */
	ओळ_opts = रिक्त;
	जर ((ep = म_खोजप(cp, ' ')) != रिक्त ||
	    (ep = म_खोजप(cp, '\t')) != रिक्त) {
		साठी (; *ep == ' ' || *ep == '\t'; ep++)
			;
		ओळ_opts = cp;
		cp = ep;
	}
	जर ((opts = sshauthopt_parse(ओळ_opts, &reason)) == रिक्त) {
		debug("%s: bad principals options: %s", loc, reason);
		auth_debug_add("%s: bad principals options: %s", loc, reason);
		परत -1;
	}
	/* Check principals in cert against those on line */
	साठी (i = 0; i < cert->nprincipals; i++) {
		जर (म_भेद(cp, cert->principals[i]) != 0)
			सुरूठेवा;
		debug3("%s: matched principal \"%.100s\"",
		    loc, cert->principals[i]);
		found = 1;
	}
	जर (found && authoptsp != रिक्त) {
		*authoptsp = opts;
		opts = रिक्त;
	}
	sshauthopt_free(opts);
	परत found ? 0 : -1;
}

पूर्णांक
auth_process_principals(खाता *f, स्थिरांक अक्षर *file,
    स्थिरांक संरचना sshkey_cert *cert, संरचना sshauthopt **authoptsp)
{
	अक्षर loc[256], *ओळ = रिक्त, *cp, *ep;
	माप_प्रकार linesize = 0;
	u_long linenum = 0, nonblank = 0;
	u_int found_principal = 0;

	जर (authoptsp != रिक्त)
		*authoptsp = रिक्त;

	पर्यंत (getline(&ओळ, &linesize, f) != -1) {
		linenum++;
		/* Always consume entire input */
		जर (found_principal)
			सुरूठेवा;

		/* Skip leading whitespace. */
		साठी (cp = ओळ; *cp == ' ' || *cp == '\t'; cp++)
			;
		/* Skip blank and comment lines. */
		जर ((ep = म_अक्षर(cp, '#')) != रिक्त)
			*ep = '\0';
		जर (!*cp || *cp == '\n')
			सुरूठेवा;

		nonblank++;
		snprintf(loc, आकार(loc), "%.200s:%lu", file, linenum);
		जर (auth_check_principals_ओळ(cp, cert, loc, authoptsp) == 0)
			found_principal = 1;
	}
	debug2_f("%s: processed %lu/%lu lines", file, nonblank, linenum);
	मुक्त(ओळ);
	परत found_principal;
}

/*
 * Check a single line of an authorized_keys-format file. Returns 0 if key
 * matches, -1 otherwise. Will return key/cert options via *authoptsp
 * on success. "loc" is used as file/line location in log messages.
 */
पूर्णांक
auth_check_authkey_ओळ(संरचना passwd *pw, संरचना sshkey *किल्ली,
    अक्षर *cp, स्थिरांक अक्षर *remote_ip, स्थिरांक अक्षर *remote_host, स्थिरांक अक्षर *loc,
    संरचना sshauthopt **authoptsp)
{
	पूर्णांक want_keytype = sshkey_is_cert(किल्ली) ? किल्ली_UNSPEC : किल्ली->type;
	संरचना sshkey *found = रिक्त;
	संरचना sshauthopt *keyopts = रिक्त, *certopts = रिक्त, *finalopts = रिक्त;
	अक्षर *किल्ली_options = रिक्त, *fp = रिक्त;
	स्थिरांक अक्षर *reason = रिक्त;
	पूर्णांक ret = -1;

	जर (authoptsp != रिक्त)
		*authoptsp = रिक्त;

	जर ((found = sshkey_new(want_keytype)) == रिक्त) {
		debug3_f("keytype %d failed", want_keytype);
		जा out;
	}

	/* XXX djm: peek at key type in line and skip if unwanted */

	जर (sshkey_read(found, &cp) != 0) {
		/* no key?  check for options */
		debug2("%s: check options: '%s'", loc, cp);
		किल्ली_options = cp;
		जर (sshkey_advance_past_options(&cp) != 0) {
			reason = "invalid key option string";
			जा fail_reason;
		}
		skip_space(&cp);
		जर (sshkey_read(found, &cp) != 0) {
			/* still no key?  advance to next line*/
			debug2("%s: advance: '%s'", loc, cp);
			जा out;
		}
	}
	/* Parse key options now; we need to know if this is a CA key */
	जर ((keyopts = sshauthopt_parse(किल्ली_options, &reason)) == रिक्त) {
		debug("%s: bad key options: %s", loc, reason);
		auth_debug_add("%s: bad key options: %s", loc, reason);
		जा out;
	}
	/* Ignore keys that don't match or incorrectly marked as CAs */
	जर (sshkey_is_cert(किल्ली)) {
		/* Certificate; check signature key against CA */
		जर (!sshkey_equal(found, किल्ली->cert->signature_किल्ली) ||
		    !keyopts->cert_authority)
			जा out;
	} अन्यथा {
		/* Plain key: check it against key found in file */
		जर (!sshkey_equal(found, किल्ली) || keyopts->cert_authority)
			जा out;
	}

	/* We have a candidate key, perform authorisation checks */
	जर ((fp = sshkey_fingerprint(found,
	    SSH_FP_HASH_DEFAULT, SSH_FP_DEFAULT)) == रिक्त)
		fatal_f("fingerprint failed");

	debug("%s: matching %s found: %s %s", loc,
	    sshkey_is_cert(किल्ली) ? "CA" : "key", sshkey_type(found), fp);

	जर (auth_authorise_keyopts(pw, keyopts,
	    sshkey_is_cert(किल्ली), remote_ip, remote_host, loc) != 0) {
		reason = "Refused by key options";
		जा fail_reason;
	}
	/* That's all we need for plain keys. */
	जर (!sshkey_is_cert(किल्ली)) {
		verbose("Accepted key %s %s found at %s",
		    sshkey_type(found), fp, loc);
		finalopts = keyopts;
		keyopts = रिक्त;
		जा success;
	}

	/*
	 * Additional authorisation for certificates.
	 */

	/* Parse and check options present in certificate */
	जर ((certopts = sshauthopt_from_cert(किल्ली)) == रिक्त) {
		reason = "Invalid certificate options";
		जा cert_fail_reason;
	}
	जर (auth_authorise_keyopts(pw, certopts, 0,
	    remote_ip, remote_host, loc) != 0) {
		reason = "Refused by certificate options";
		जा cert_fail_reason;
	}
	जर ((finalopts = sshauthopt_merge(keyopts, certopts, &reason)) == रिक्त)
		जा cert_fail_reason;

	/*
	 * If the user has specified a list of principals as
	 * a key option, then prefer that list to matching
	 * their username in the certificate principals list.
	 */
	जर (keyopts->cert_principals != रिक्त &&
	    !match_principals_option(keyopts->cert_principals, किल्ली->cert)) {
		reason = "Certificate does not contain an authorized principal";
		जा cert_fail_reason;
	}
	जर (sshkey_cert_check_authority_now(किल्ली, 0, 0,
	    keyopts->cert_principals == रिक्त ? pw->pw_name : रिक्त,
	    &reason) != 0)
		जा cert_fail_reason;

	verbose("Accepted certificate ID \"%s\" (serial %llu) "
	    "signed by CA %s %s found at %s",
	    किल्ली->cert->किल्ली_id,
	    (अचिन्हित दीर्घ दीर्घ)किल्ली->cert->serial,
	    sshkey_type(found), fp, loc);

 success:
	जर (finalopts == रिक्त)
		fatal_f("internal error: missing options");
	जर (authoptsp != रिक्त) {
		*authoptsp = finalopts;
		finalopts = रिक्त;
	}
	/* success */
	ret = 0;
	जा out;

 cert_fail_reason:
	error("Refusing certificate ID \"%s\" serial=%llu "
	    "signed by %s CA %s via %s: %s", किल्ली->cert->किल्ली_id,
	    (अचिन्हित दीर्घ दीर्घ)किल्ली->cert->serial,
	    sshkey_type(किल्ली->cert->signature_किल्ली), fp, loc, reason);
	auth_debug_add("Refused Certificate ID \"%s\" serial=%llu: %s",
	    किल्ली->cert->किल्ली_id, (अचिन्हित दीर्घ दीर्घ)किल्ली->cert->serial, reason);
	जा out;

 fail_reason:
	error("%s at %s", reason, loc);
	auth_debug_add("%s", reason);
 out:
	मुक्त(fp);
	sshauthopt_free(keyopts);
	sshauthopt_free(certopts);
	sshauthopt_free(finalopts);
	sshkey_free(found);
	परत ret;
}

/*
 * Checks whether key is allowed in authorized_keys-format file,
 * returns 1 if the key is allowed or 0 otherwise.
 */
पूर्णांक
auth_check_authkeys_file(संरचना passwd *pw, खाता *f, अक्षर *file,
    संरचना sshkey *किल्ली, स्थिरांक अक्षर *remote_ip,
    स्थिरांक अक्षर *remote_host, संरचना sshauthopt **authoptsp)
{
	अक्षर *cp, *ओळ = रिक्त, loc[256];
	माप_प्रकार linesize = 0;
	पूर्णांक found_किल्ली = 0;
	u_long linenum = 0, nonblank = 0;

	जर (authoptsp != रिक्त)
		*authoptsp = रिक्त;

	पर्यंत (getline(&ओळ, &linesize, f) != -1) {
		linenum++;
		/* Always consume entire file */
		जर (found_किल्ली)
			सुरूठेवा;

		/* Skip leading whitespace, empty and comment lines. */
		cp = ओळ;
		skip_space(&cp);
		जर (!*cp || *cp == '\n' || *cp == '#')
			सुरूठेवा;

		nonblank++;
		snprintf(loc, आकार(loc), "%.200s:%lu", file, linenum);
		जर (auth_check_authkey_ओळ(pw, किल्ली, cp,
		    remote_ip, remote_host, loc, authoptsp) == 0)
			found_किल्ली = 1;
	}
	मुक्त(ओळ);
	debug2_f("%s: processed %lu/%lu lines", file, nonblank, linenum);
	परत found_किल्ली;
}

स्थिर खाता *
auth_openfile(स्थिरांक अक्षर *file, संरचना passwd *pw, पूर्णांक strict_modes,
    पूर्णांक log_missing, अक्षर *file_type)
{
	अक्षर ओळ[1024];
	संरचना stat st;
	पूर्णांक fd;
	खाता *f;

	जर ((fd = खोलो(file, O_RDONLY|O_NONBLOCK)) == -1) {
		जर (त्रुटि_सं != ENOENT) {
			logit("Could not open user '%s' %s '%s': %s",
			    pw->pw_name, file_type, file, म_त्रुटि(त्रुटि_सं));
		} अन्यथा जर (log_missing) {
			debug("Could not open user '%s' %s '%s': %s",
			    pw->pw_name, file_type, file, म_त्रुटि(त्रुटि_सं));
		}
		परत रिक्त;
	}

	जर (ख_स्थिति(fd, &st) == -1) {
		बंद(fd);
		परत रिक्त;
	}
	जर (!S_ISREG(st.st_mode)) {
		logit("User '%s' %s '%s' is not a regular file",
		    pw->pw_name, file_type, file);
		बंद(fd);
		परत रिक्त;
	}
	unset_nonblock(fd);
	जर ((f = fdopen(fd, "r")) == रिक्त) {
		बंद(fd);
		परत रिक्त;
	}
	जर (strict_modes &&
	    safe_path_fd(fileno(f), file, pw, ओळ, आकार(ओळ)) != 0) {
		ख_बंद(f);
		logit("Authentication refused: %s", ओळ);
		auth_debug_add("Ignored %s: %s", file_type, ओळ);
		परत रिक्त;
	}

	परत f;
}


खाता *
auth_openkeyfile(स्थिरांक अक्षर *file, संरचना passwd *pw, पूर्णांक strict_modes)
{
	परत auth_openfile(file, pw, strict_modes, 1, "authorized keys");
}

खाता *
auth_openprincipals(स्थिरांक अक्षर *file, संरचना passwd *pw, पूर्णांक strict_modes)
{
	परत auth_openfile(file, pw, strict_modes, 0,
	    "authorized principals");
}

