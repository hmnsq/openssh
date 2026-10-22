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

#समावेश "includes.h"

#समावेश <sys/types.h>
#समावेश <sys/stat.h>

#समावेश <stdlib.h>
#समावेश <errno.h>
#समावेश <fcntl.h>
#समावेश <pwd.h>
#समावेश <stdio.h>
#समावेश <stdarg.h>
#समावेश <string.h>
#समावेश <time.h>
#समावेश <unistd.h>

#समावेश "ssh.h"
#समावेश "log.h"
#समावेश "misc.h"
#समावेश "sshkey.h"
#समावेश "digest.h"
#समावेश "hostfile.h"
#समावेश "auth.h"
#समावेश "auth-options.h"
#समावेश "authfile.h"
#समावेश "match.h"
#समावेश "ssherr.h"
#समावेश "xmalloc.h"

पूर्णांक
auth_authorise_keyopts(काष्ठा passwd *pw, काष्ठा sshauthopt *opts,
    पूर्णांक allow_cert_authority, स्थिर अक्षर *remote_ip, स्थिर अक्षर *remote_host,
    स्थिर अक्षर *loc)
{
	समय_प्रकार now = समय(शून्य);
	अक्षर buf[64];

	/*
	 * Check keys/principals file expiry time.
	 * NB. validity interval in certificate is handled elsewhere.
	 */
	अगर (opts->valid_before && now > 0 &&
	    opts->valid_before < (uint64_t)now) {
		format_absolute_time(opts->valid_before, buf, माप(buf));
		debug("%s: entry expired at %s", loc, buf);
		auth_debug_add("%s: entry expired at %s", loc, buf);
		वापस -1;
	}
	/* Consistency checks */
	अगर (opts->cert_principals != शून्य && !opts->cert_authority) {
		debug("%s: principals on non-CA key", loc);
		auth_debug_add("%s: principals on non-CA key", loc);
		/* deny access */
		वापस -1;
	}
	/* cert-authority flag isn't valid in authorized_principals files */
	अगर (!allow_cert_authority && opts->cert_authority) {
		debug("%s: cert-authority flag invalid here", loc);
		auth_debug_add("%s: cert-authority flag invalid here", loc);
		/* deny access */
		वापस -1;
	}

	/* Perform from= checks */
	अगर (opts->required_from_host_कुंजियाँ != शून्य) {
		चयन (match_host_and_ip(remote_host, remote_ip,
		    opts->required_from_host_कुंजियाँ )) {
		हाल 1:
			/* Host name matches. */
			अवरोध;
		हाल -1:
		शेष:
			debug("%s: invalid from criteria", loc);
			auth_debug_add("%s: invalid from criteria", loc);
			/* FALLTHROUGH */
		हाल 0:
			logit("%s: Authentication tried for %.100s with "
			    "correct key but not from a permitted "
			    "host (host=%.200s, ip=%.200s, required=%.200s).",
			    loc, pw->pw_name, remote_host, remote_ip,
			    opts->required_from_host_कुंजियाँ);
			auth_debug_add("%s: Your host '%.200s' is not "
			    "permitted to use this key for login.",
			    loc, remote_host);
			/* deny access */
			वापस -1;
		}
	}
	/* Check source-address restriction from certificate */
	अगर (opts->required_from_host_cert != शून्य) {
		चयन (addr_match_cidr_list(remote_ip,
		    opts->required_from_host_cert)) {
		हाल 1:
			/* accepted */
			अवरोध;
		हाल -1:
		शेष:
			/* invalid */
			error("%s: Certificate source-address invalid", loc);
			/* FALLTHROUGH */
		हाल 0:
			logit("%s: Authentication tried for %.100s with valid "
			    "certificate but not from a permitted source "
			    "address (%.200s).", loc, pw->pw_name, remote_ip);
			auth_debug_add("%s: Your address '%.200s' is not "
			    "permitted to use this certificate for login.",
			    loc, remote_ip);
			वापस -1;
		}
	}
	/*
	 *
	 * XXX this is spammy. We should report remotely only for keys
	 *     that are successful in actual auth attempts, and not PK_OK
	 *     tests.
	 */
	auth_log_authopts(loc, opts, 1);

	वापस 0;
}

अटल पूर्णांक
match_principals_option(स्थिर अक्षर *principal_list, काष्ठा sshkey_cert *cert)
{
	अक्षर *list, *olist, *entry;
	u_int i;

	olist = list = xstrdup(principal_list);
	क्रम (;;) {
		अगर ((entry = strsep(&list, ",")) == शून्य || *entry == '\0')
			अवरोध;
		क्रम (i = 0; i < cert->nprincipals; i++) {
			अगर (म_भेद(entry, cert->principals[i]) == 0) {
				debug3("matched principal from key i"
				    "options \"%.100s\"", entry);
				मुक्त(olist);
				वापस 1;
			}
		}
	}
	मुक्त(olist);
	वापस 0;
}

/*
 * Process a single authorized_principals format line. Returns 0 and sets
 * authoptsp is principal is authorised, -1 otherwise. "loc" is used as a
 * log preamble for file/line information.
 */
पूर्णांक
auth_check_principals_पंक्ति(अक्षर *cp, स्थिर काष्ठा sshkey_cert *cert,
    स्थिर अक्षर *loc, काष्ठा sshauthopt **authoptsp)
{
	u_int i, found = 0;
	अक्षर *ep, *पंक्ति_opts;
	स्थिर अक्षर *reason = शून्य;
	काष्ठा sshauthopt *opts = शून्य;

	अगर (authoptsp != शून्य)
		*authoptsp = शून्य;

	/* Trim trailing whitespace. */
	ep = cp + म_माप(cp) - 1;
	जबतक (ep > cp && (*ep == '\n' || *ep == ' ' || *ep == '\t'))
		*ep-- = '\0';

	/*
	 * If the line has internal whitespace then assume it has
	 * key options.
	 */
	पंक्ति_opts = शून्य;
	अगर ((ep = म_खोजप(cp, ' ')) != शून्य ||
	    (ep = म_खोजप(cp, '\t')) != शून्य) {
		क्रम (; *ep == ' ' || *ep == '\t'; ep++)
			;
		पंक्ति_opts = cp;
		cp = ep;
	}
	अगर ((opts = sshauthopt_parse(पंक्ति_opts, &reason)) == शून्य) {
		debug("%s: bad principals options: %s", loc, reason);
		auth_debug_add("%s: bad principals options: %s", loc, reason);
		वापस -1;
	}
	/* Check principals in cert against those on line */
	क्रम (i = 0; i < cert->nprincipals; i++) {
		अगर (म_भेद(cp, cert->principals[i]) != 0)
			जारी;
		debug3("%s: matched principal \"%.100s\"",
		    loc, cert->principals[i]);
		found = 1;
	}
	अगर (found && authoptsp != शून्य) {
		*authoptsp = opts;
		opts = शून्य;
	}
	sshauthopt_free(opts);
	वापस found ? 0 : -1;
}

पूर्णांक
auth_process_principals(खाता *f, स्थिर अक्षर *file,
    स्थिर काष्ठा sshkey_cert *cert, काष्ठा sshauthopt **authoptsp)
{
	अक्षर loc[256], *पंक्ति = शून्य, *cp, *ep;
	माप_प्रकार linesize = 0;
	u_long linenum = 0, nonblank = 0;
	u_int found_principal = 0;

	अगर (authoptsp != शून्य)
		*authoptsp = शून्य;

	जबतक (getline(&पंक्ति, &linesize, f) != -1) {
		linenum++;
		/* Always consume entire input */
		अगर (found_principal)
			जारी;

		/* Skip leading whitespace. */
		क्रम (cp = पंक्ति; *cp == ' ' || *cp == '\t'; cp++)
			;
		/* Skip blank and comment lines. */
		अगर ((ep = म_अक्षर(cp, '#')) != शून्य)
			*ep = '\0';
		अगर (!*cp || *cp == '\n')
			जारी;

		nonblank++;
		snprintf(loc, माप(loc), "%.200s:%lu", file, linenum);
		अगर (auth_check_principals_पंक्ति(cp, cert, loc, authoptsp) == 0)
			found_principal = 1;
	}
	debug2_f("%s: processed %lu/%lu lines", file, nonblank, linenum);
	मुक्त(पंक्ति);
	वापस found_principal;
}

/*
 * Check a single line of an authorized_keys-format file. Returns 0 if key
 * matches, -1 otherwise. Will return key/cert options via *authoptsp
 * on success. "loc" is used as file/line location in log messages.
 */
पूर्णांक
auth_check_authkey_पंक्ति(काष्ठा passwd *pw, काष्ठा sshkey *कुंजी,
    अक्षर *cp, स्थिर अक्षर *remote_ip, स्थिर अक्षर *remote_host, स्थिर अक्षर *loc,
    काष्ठा sshauthopt **authoptsp)
{
	पूर्णांक want_keytype = sshkey_is_cert(कुंजी) ? कुंजी_UNSPEC : कुंजी->type;
	काष्ठा sshkey *found = शून्य;
	काष्ठा sshauthopt *keyopts = शून्य, *certopts = शून्य, *finalopts = शून्य;
	अक्षर *कुंजी_options = शून्य, *fp = शून्य;
	स्थिर अक्षर *reason = शून्य;
	पूर्णांक ret = -1;

	अगर (authoptsp != शून्य)
		*authoptsp = शून्य;

	अगर ((found = sshkey_new(want_keytype)) == शून्य) {
		debug3_f("keytype %d failed", want_keytype);
		जाओ out;
	}

	/* XXX djm: peek at key type in line and skip if unwanted */

	अगर (sshkey_read(found, &cp) != 0) {
		/* no key?  check for options */
		debug2("%s: check options: '%s'", loc, cp);
		कुंजी_options = cp;
		अगर (sshkey_advance_past_options(&cp) != 0) {
			reason = "invalid key option string";
			जाओ fail_reason;
		}
		skip_space(&cp);
		अगर (sshkey_read(found, &cp) != 0) {
			/* still no key?  advance to next line*/
			debug2("%s: advance: '%s'", loc, cp);
			जाओ out;
		}
	}
	/* Parse key options now; we need to know if this is a CA key */
	अगर ((keyopts = sshauthopt_parse(कुंजी_options, &reason)) == शून्य) {
		debug("%s: bad key options: %s", loc, reason);
		auth_debug_add("%s: bad key options: %s", loc, reason);
		जाओ out;
	}
	/* Ignore keys that don't match or incorrectly marked as CAs */
	अगर (sshkey_is_cert(कुंजी)) {
		/* Certificate; check signature key against CA */
		अगर (!sshkey_equal(found, कुंजी->cert->signature_कुंजी) ||
		    !keyopts->cert_authority)
			जाओ out;
	} अन्यथा {
		/* Plain key: check it against key found in file */
		अगर (!sshkey_equal(found, कुंजी) || keyopts->cert_authority)
			जाओ out;
	}

	/* We have a candidate key, perform authorisation checks */
	अगर ((fp = sshkey_fingerprint(found,
	    SSH_FP_HASH_DEFAULT, SSH_FP_DEFAULT)) == शून्य)
		fatal_f("fingerprint failed");

	debug("%s: matching %s found: %s %s", loc,
	    sshkey_is_cert(कुंजी) ? "CA" : "key", sshkey_type(found), fp);

	अगर (auth_authorise_keyopts(pw, keyopts,
	    sshkey_is_cert(कुंजी), remote_ip, remote_host, loc) != 0) {
		reason = "Refused by key options";
		जाओ fail_reason;
	}
	/* That's all we need for plain keys. */
	अगर (!sshkey_is_cert(कुंजी)) {
		verbose("Accepted key %s %s found at %s",
		    sshkey_type(found), fp, loc);
		finalopts = keyopts;
		keyopts = शून्य;
		जाओ success;
	}

	/*
	 * Additional authorisation for certificates.
	 */

	/* Parse and check options present in certificate */
	अगर ((certopts = sshauthopt_from_cert(कुंजी)) == शून्य) {
		reason = "Invalid certificate options";
		जाओ cert_fail_reason;
	}
	अगर (auth_authorise_keyopts(pw, certopts, 0,
	    remote_ip, remote_host, loc) != 0) {
		reason = "Refused by certificate options";
		जाओ cert_fail_reason;
	}
	अगर ((finalopts = sshauthopt_merge(keyopts, certopts, &reason)) == शून्य)
		जाओ cert_fail_reason;

	/*
	 * If the user has specified a list of principals as
	 * a key option, then prefer that list to matching
	 * their username in the certificate principals list.
	 */
	अगर (keyopts->cert_principals != शून्य &&
	    !match_principals_option(keyopts->cert_principals, कुंजी->cert)) {
		reason = "Certificate does not contain an authorized principal";
		जाओ cert_fail_reason;
	}
	अगर (sshkey_cert_check_authority_now(कुंजी, 0, 0,
	    keyopts->cert_principals == शून्य ? pw->pw_name : शून्य,
	    &reason) != 0)
		जाओ cert_fail_reason;

	verbose("Accepted certificate ID \"%s\" (serial %llu) "
	    "signed by CA %s %s found at %s",
	    कुंजी->cert->कुंजी_id,
	    (अचिन्हित दीर्घ दीर्घ)कुंजी->cert->serial,
	    sshkey_type(found), fp, loc);

 success:
	अगर (finalopts == शून्य)
		fatal_f("internal error: missing options");
	अगर (authoptsp != शून्य) {
		*authoptsp = finalopts;
		finalopts = शून्य;
	}
	/* success */
	ret = 0;
	जाओ out;

 cert_fail_reason:
	error("Refusing certificate ID \"%s\" serial=%llu "
	    "signed by %s CA %s via %s: %s", कुंजी->cert->कुंजी_id,
	    (अचिन्हित दीर्घ दीर्घ)कुंजी->cert->serial,
	    sshkey_type(कुंजी->cert->signature_कुंजी), fp, loc, reason);
	auth_debug_add("Refused Certificate ID \"%s\" serial=%llu: %s",
	    कुंजी->cert->कुंजी_id, (अचिन्हित दीर्घ दीर्घ)कुंजी->cert->serial, reason);
	जाओ out;

 fail_reason:
	error("%s at %s", reason, loc);
	auth_debug_add("%s", reason);
 out:
	मुक्त(fp);
	sshauthopt_free(keyopts);
	sshauthopt_free(certopts);
	sshauthopt_free(finalopts);
	sshkey_free(found);
	वापस ret;
}

/*
 * Checks whether key is allowed in authorized_keys-format file,
 * returns 1 if the key is allowed or 0 otherwise.
 */
पूर्णांक
auth_check_authkeys_file(काष्ठा passwd *pw, खाता *f, अक्षर *file,
    काष्ठा sshkey *कुंजी, स्थिर अक्षर *remote_ip,
    स्थिर अक्षर *remote_host, काष्ठा sshauthopt **authoptsp)
{
	अक्षर *cp, *पंक्ति = शून्य, loc[256];
	माप_प्रकार linesize = 0;
	पूर्णांक found_कुंजी = 0;
	u_long linenum = 0, nonblank = 0;

	अगर (authoptsp != शून्य)
		*authoptsp = शून्य;

	जबतक (getline(&पंक्ति, &linesize, f) != -1) {
		linenum++;
		/* Always consume entire file */
		अगर (found_कुंजी)
			जारी;

		/* Skip leading whitespace, empty and comment lines. */
		cp = पंक्ति;
		skip_space(&cp);
		अगर (!*cp || *cp == '\n' || *cp == '#')
			जारी;

		nonblank++;
		snprintf(loc, माप(loc), "%.200s:%lu", file, linenum);
		अगर (auth_check_authkey_पंक्ति(pw, कुंजी, cp,
		    remote_ip, remote_host, loc, authoptsp) == 0)
			found_कुंजी = 1;
	}
	मुक्त(पंक्ति);
	debug2_f("%s: processed %lu/%lu lines", file, nonblank, linenum);
	वापस found_कुंजी;
}

अटल खाता *
auth_openfile(स्थिर अक्षर *file, काष्ठा passwd *pw, पूर्णांक strict_modes,
    पूर्णांक log_missing, अक्षर *file_type)
{
	अक्षर पंक्ति[1024];
	काष्ठा stat st;
	पूर्णांक fd;
	खाता *f;

	अगर ((fd = खोलो(file, O_RDONLY|O_NONBLOCK)) == -1) {
		अगर (त्रुटि_सं != ENOENT) {
			logit("Could not open user '%s' %s '%s': %s",
			    pw->pw_name, file_type, file, म_त्रुटि(त्रुटि_सं));
		} अन्यथा अगर (log_missing) {
			debug("Could not open user '%s' %s '%s': %s",
			    pw->pw_name, file_type, file, म_त्रुटि(त्रुटि_सं));
		}
		वापस शून्य;
	}

	अगर (ख_स्थिति(fd, &st) == -1) {
		बंद(fd);
		वापस शून्य;
	}
	अगर (!S_ISREG(st.st_mode)) {
		logit("User '%s' %s '%s' is not a regular file",
		    pw->pw_name, file_type, file);
		बंद(fd);
		वापस शून्य;
	}
	unset_nonblock(fd);
	अगर ((f = fdopen(fd, "r")) == शून्य) {
		बंद(fd);
		वापस शून्य;
	}
	अगर (strict_modes &&
	    safe_path_fd(fileno(f), file, pw, पंक्ति, माप(पंक्ति)) != 0) {
		ख_बंद(f);
		logit("Authentication refused: %s", पंक्ति);
		auth_debug_add("Ignored %s: %s", file_type, पंक्ति);
		वापस शून्य;
	}

	वापस f;
}


खाता *
auth_openkeyfile(स्थिर अक्षर *file, काष्ठा passwd *pw, पूर्णांक strict_modes)
{
	वापस auth_openfile(file, pw, strict_modes, 1, "authorized keys");
}

खाता *
auth_openprincipals(स्थिर अक्षर *file, काष्ठा passwd *pw, पूर्णांक strict_modes)
{
	वापस auth_openfile(file, pw, strict_modes, 0,
	    "authorized principals");
}

