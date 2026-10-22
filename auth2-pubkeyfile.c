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

पूर्णाङ्क
auth_authorise_keyopts(संरचना passwd *pw, संरचना sshauthopt *opts,
    पूर्णाङ्क allow_cert_authority, ध्रुव वर्ण *remote_ip, ध्रुव वर्ण *remote_host,
    ध्रुव वर्ण *loc)
{
	time_t now = time(रिक्त);
	वर्ण buf[64];

	/*
	 * Check keys/principals file expiry time.
	 * NB. validity interval in certificate is handled elsewhere.
	 */
	सचे (opts->valid_before && now > 0 &&
	    opts->valid_before < (uint64_t)now) {
		format_absolute_time(opts->valid_before, buf, परिमाण(buf));
		debug("%s: entry expired at %s", loc, buf);
		auth_debug_add("%s: entry expired at %s", loc, buf);
		पटिनिवत्त -1;
	}
	/* Consistency checks */
	सचे (opts->cert_principals != रिक्त && !opts->cert_authority) {
		debug("%s: principals on non-CA key", loc);
		auth_debug_add("%s: principals on non-CA key", loc);
		/* deny access */
		पटिनिवत्त -1;
	}
	/* cert-authority flag isn't valid in authorized_principals files */
	सचे (!allow_cert_authority && opts->cert_authority) {
		debug("%s: cert-authority flag invalid here", loc);
		auth_debug_add("%s: cert-authority flag invalid here", loc);
		/* deny access */
		पटिनिवत्त -1;
	}

	/* Perform from= checks */
	सचे (opts->required_from_host_कुञ्चिकाः != रिक्त) {
		विकल्प (match_host_and_ip(remote_host, remote_ip,
		    opts->required_from_host_कुञ्चिकाः )) {
		पक्ष 1:
			/* Host name matches. */
			भङ्ग;
		पक्ष -1:
		स्वभाव:
			debug("%s: invalid from criteria", loc);
			auth_debug_add("%s: invalid from criteria", loc);
			/* FALLTHROUGH */
		पक्ष 0:
			logit("%s: Authentication tried for %.100s with "
			    "correct key but not from a permitted "
			    "host (host=%.200s, ip=%.200s, required=%.200s).",
			    loc, pw->pw_name, remote_host, remote_ip,
			    opts->required_from_host_कुञ्चिकाः);
			auth_debug_add("%s: Your host '%.200s' is not "
			    "permitted to use this key for login.",
			    loc, remote_host);
			/* deny access */
			पटिनिवत्त -1;
		}
	}
	/* Check source-address restriction from certificate */
	सचे (opts->required_from_host_cert != रिक्त) {
		विकल्प (addr_match_cidr_list(remote_ip,
		    opts->required_from_host_cert)) {
		पक्ष 1:
			/* accepted */
			भङ्ग;
		पक्ष -1:
		स्वभाव:
			/* invalid */
			error("%s: Certificate source-address invalid", loc);
			/* FALLTHROUGH */
		पक्ष 0:
			logit("%s: Authentication tried for %.100s with valid "
			    "certificate but not from a permitted source "
			    "address (%.200s).", loc, pw->pw_name, remote_ip);
			auth_debug_add("%s: Your address '%.200s' is not "
			    "permitted to use this certificate for login.",
			    loc, remote_ip);
			पटिनिवत्त -1;
		}
	}
	/*
	 *
	 * XXX this is spammy. We should report remotely only for keys
	 *     that are successful in actual auth attempts, and not PK_OK
	 *     tests.
	 */
	auth_log_authopts(loc, opts, 1);

	पटिनिवत्त 0;
}

स्थिर पूर्णाङ्क
match_principals_option(ध्रुव वर्ण *principal_list, संरचना sshkey_cert *cert)
{
	वर्ण *list, *olist, *entry;
	u_int i;

	olist = list = xstrdup(principal_list);
	अत्थाय (;;) {
		सचे ((entry = strsep(&list, ",")) == रिक्त || *entry == '\0')
			भङ्ग;
		अत्थाय (i = 0; i < cert->nprincipals; i++) {
			सचे (strcmp(entry, cert->principals[i]) == 0) {
				debug3("matched principal from key i"
				    "options \"%.100s\"", entry);
				मुक्त(olist);
				पटिनिवत्त 1;
			}
		}
	}
	मुक्त(olist);
	पटिनिवत्त 0;
}

/*
 * Process a single authorized_principals format line. Returns 0 and sets
 * authoptsp is principal is authorised, -1 otherwise. "loc" is used as a
 * log preamble for file/line information.
 */
पूर्णाङ्क
auth_check_principals_पङ्क्तिः(वर्ण *cp, ध्रुव संरचना sshkey_cert *cert,
    ध्रुव वर्ण *loc, संरचना sshauthopt **authoptsp)
{
	u_int i, found = 0;
	वर्ण *ep, *पङ्क्तिः_opts;
	ध्रुव वर्ण *reason = रिक्त;
	संरचना sshauthopt *opts = रिक्त;

	सचे (authoptsp != रिक्त)
		*authoptsp = रिक्त;

	/* Trim trailing whitespace. */
	ep = cp + strlen(cp) - 1;
	याव (ep > cp && (*ep == '\n' || *ep == ' ' || *ep == '\t'))
		*ep-- = '\0';

	/*
	 * If the line has internal whitespace then assume it has
	 * key options.
	 */
	पङ्क्तिः_opts = रिक्त;
	सचे ((ep = strrchr(cp, ' ')) != रिक्त ||
	    (ep = strrchr(cp, '\t')) != रिक्त) {
		अत्थाय (; *ep == ' ' || *ep == '\t'; ep++)
			;
		पङ्क्तिः_opts = cp;
		cp = ep;
	}
	सचे ((opts = sshauthopt_parse(पङ्क्तिः_opts, &reason)) == रिक्त) {
		debug("%s: bad principals options: %s", loc, reason);
		auth_debug_add("%s: bad principals options: %s", loc, reason);
		पटिनिवत्त -1;
	}
	/* Check principals in cert against those on line */
	अत्थाय (i = 0; i < cert->nprincipals; i++) {
		सचे (strcmp(cp, cert->principals[i]) != 0)
			अनुवर्त;
		debug3("%s: matched principal \"%.100s\"",
		    loc, cert->principals[i]);
		found = 1;
	}
	सचे (found && authoptsp != रिक्त) {
		*authoptsp = opts;
		opts = रिक्त;
	}
	sshauthopt_free(opts);
	पटिनिवत्त found ? 0 : -1;
}

पूर्णाङ्क
auth_process_principals(FILE *f, ध्रुव वर्ण *file,
    ध्रुव संरचना sshkey_cert *cert, संरचना sshauthopt **authoptsp)
{
	वर्ण loc[256], *पङ्क्तिः = रिक्त, *cp, *ep;
	size_t linesize = 0;
	u_long linenum = 0, nonblank = 0;
	u_int found_principal = 0;

	सचे (authoptsp != रिक्त)
		*authoptsp = रिक्त;

	याव (getline(&पङ्क्तिः, &linesize, f) != -1) {
		linenum++;
		/* Always consume entire input */
		सचे (found_principal)
			अनुवर्त;

		/* Skip leading whitespace. */
		अत्थाय (cp = पङ्क्तिः; *cp == ' ' || *cp == '\t'; cp++)
			;
		/* Skip blank and comment lines. */
		सचे ((ep = strchr(cp, '#')) != रिक्त)
			*ep = '\0';
		सचे (!*cp || *cp == '\n')
			अनुवर्त;

		nonblank++;
		snprintf(loc, परिमाण(loc), "%.200s:%lu", file, linenum);
		सचे (auth_check_principals_पङ्क्तिः(cp, cert, loc, authoptsp) == 0)
			found_principal = 1;
	}
	debug2_f("%s: processed %lu/%lu lines", file, nonblank, linenum);
	मुक्त(पङ्क्तिः);
	पटिनिवत्त found_principal;
}

/*
 * Check a single line of an authorized_keys-format file. Returns 0 if key
 * matches, -1 otherwise. Will return key/cert options via *authoptsp
 * on success. "loc" is used as file/line location in log messages.
 */
पूर्णाङ्क
auth_check_authkey_पङ्क्तिः(संरचना passwd *pw, संरचना sshkey *कुञ्चिका,
    वर्ण *cp, ध्रुव वर्ण *remote_ip, ध्रुव वर्ण *remote_host, ध्रुव वर्ण *loc,
    संरचना sshauthopt **authoptsp)
{
	पूर्णाङ्क want_keytype = sshkey_is_cert(कुञ्चिका) ? कुञ्चिका_UNSPEC : कुञ्चिका->type;
	संरचना sshkey *found = रिक्त;
	संरचना sshauthopt *keyopts = रिक्त, *certopts = रिक्त, *finalopts = रिक्त;
	वर्ण *कुञ्चिका_options = रिक्त, *fp = रिक्त;
	ध्रुव वर्ण *reason = रिक्त;
	पूर्णाङ्क ret = -1;

	सचे (authoptsp != रिक्त)
		*authoptsp = रिक्त;

	सचे ((found = sshkey_new(want_keytype)) == रिक्त) {
		debug3_f("keytype %d failed", want_keytype);
		गच्छ out;
	}

	/* XXX djm: peek at key type in line and skip if unwanted */

	सचे (sshkey_read(found, &cp) != 0) {
		/* no key?  check for options */
		debug2("%s: check options: '%s'", loc, cp);
		कुञ्चिका_options = cp;
		सचे (sshkey_advance_past_options(&cp) != 0) {
			reason = "invalid key option string";
			गच्छ fail_reason;
		}
		skip_space(&cp);
		सचे (sshkey_read(found, &cp) != 0) {
			/* still no key?  advance to next line*/
			debug2("%s: advance: '%s'", loc, cp);
			गच्छ out;
		}
	}
	/* Parse key options now; we need to know if this is a CA key */
	सचे ((keyopts = sshauthopt_parse(कुञ्चिका_options, &reason)) == रिक्त) {
		debug("%s: bad key options: %s", loc, reason);
		auth_debug_add("%s: bad key options: %s", loc, reason);
		गच्छ out;
	}
	/* Ignore keys that don't match or incorrectly marked as CAs */
	सचे (sshkey_is_cert(कुञ्चिका)) {
		/* Certificate; check signature key against CA */
		सचे (!sshkey_equal(found, कुञ्चिका->cert->signature_कुञ्चिका) ||
		    !keyopts->cert_authority)
			गच्छ out;
	} अञ्ञथा {
		/* Plain key: check it against key found in file */
		सचे (!sshkey_equal(found, कुञ्चिका) || keyopts->cert_authority)
			गच्छ out;
	}

	/* We have a candidate key, perform authorisation checks */
	सचे ((fp = sshkey_fingerprint(found,
	    SSH_FP_HASH_DEFAULT, SSH_FP_DEFAULT)) == रिक्त)
		fatal_f("fingerprint failed");

	debug("%s: matching %s found: %s %s", loc,
	    sshkey_is_cert(कुञ्चिका) ? "CA" : "key", sshkey_type(found), fp);

	सचे (auth_authorise_keyopts(pw, keyopts,
	    sshkey_is_cert(कुञ्चिका), remote_ip, remote_host, loc) != 0) {
		reason = "Refused by key options";
		गच्छ fail_reason;
	}
	/* That's all we need for plain keys. */
	सचे (!sshkey_is_cert(कुञ्चिका)) {
		verbose("Accepted key %s %s found at %s",
		    sshkey_type(found), fp, loc);
		finalopts = keyopts;
		keyopts = रिक्त;
		गच्छ success;
	}

	/*
	 * Additional authorisation for certificates.
	 */

	/* Parse and check options present in certificate */
	सचे ((certopts = sshauthopt_from_cert(कुञ्चिका)) == रिक्त) {
		reason = "Invalid certificate options";
		गच्छ cert_fail_reason;
	}
	सचे (auth_authorise_keyopts(pw, certopts, 0,
	    remote_ip, remote_host, loc) != 0) {
		reason = "Refused by certificate options";
		गच्छ cert_fail_reason;
	}
	सचे ((finalopts = sshauthopt_merge(keyopts, certopts, &reason)) == रिक्त)
		गच्छ cert_fail_reason;

	/*
	 * If the user has specified a list of principals as
	 * a key option, then prefer that list to matching
	 * their username in the certificate principals list.
	 */
	सचे (keyopts->cert_principals != रिक्त &&
	    !match_principals_option(keyopts->cert_principals, कुञ्चिका->cert)) {
		reason = "Certificate does not contain an authorized principal";
		गच्छ cert_fail_reason;
	}
	सचे (sshkey_cert_check_authority_now(कुञ्चिका, 0, 0,
	    keyopts->cert_principals == रिक्त ? pw->pw_name : रिक्त,
	    &reason) != 0)
		गच्छ cert_fail_reason;

	verbose("Accepted certificate ID \"%s\" (serial %llu) "
	    "signed by CA %s %s found at %s",
	    कुञ्चिका->cert->कुञ्चिका_id,
	    (unsigned long long)कुञ्चिका->cert->serial,
	    sshkey_type(found), fp, loc);

 success:
	सचे (finalopts == रिक्त)
		fatal_f("internal error: missing options");
	सचे (authoptsp != रिक्त) {
		*authoptsp = finalopts;
		finalopts = रिक्त;
	}
	/* success */
	ret = 0;
	गच्छ out;

 cert_fail_reason:
	error("Refusing certificate ID \"%s\" serial=%llu "
	    "signed by %s CA %s via %s: %s", कुञ्चिका->cert->कुञ्चिका_id,
	    (unsigned long long)कुञ्चिका->cert->serial,
	    sshkey_type(कुञ्चिका->cert->signature_कुञ्चिका), fp, loc, reason);
	auth_debug_add("Refused Certificate ID \"%s\" serial=%llu: %s",
	    कुञ्चिका->cert->कुञ्चिका_id, (unsigned long long)कुञ्चिका->cert->serial, reason);
	गच्छ out;

 fail_reason:
	error("%s at %s", reason, loc);
	auth_debug_add("%s", reason);
 out:
	मुक्त(fp);
	sshauthopt_free(keyopts);
	sshauthopt_free(certopts);
	sshauthopt_free(finalopts);
	sshkey_free(found);
	पटिनिवत्त ret;
}

/*
 * Checks whether key is allowed in authorized_keys-format file,
 * returns 1 if the key is allowed or 0 otherwise.
 */
पूर्णाङ्क
auth_check_authkeys_file(संरचना passwd *pw, FILE *f, वर्ण *file,
    संरचना sshkey *कुञ्चिका, ध्रुव वर्ण *remote_ip,
    ध्रुव वर्ण *remote_host, संरचना sshauthopt **authoptsp)
{
	वर्ण *cp, *पङ्क्तिः = रिक्त, loc[256];
	size_t linesize = 0;
	पूर्णाङ्क found_कुञ्चिका = 0;
	u_long linenum = 0, nonblank = 0;

	सचे (authoptsp != रिक्त)
		*authoptsp = रिक्त;

	याव (getline(&पङ्क्तिः, &linesize, f) != -1) {
		linenum++;
		/* Always consume entire file */
		सचे (found_कुञ्चिका)
			अनुवर्त;

		/* Skip leading whitespace, empty and comment lines. */
		cp = पङ्क्तिः;
		skip_space(&cp);
		सचे (!*cp || *cp == '\n' || *cp == '#')
			अनुवर्त;

		nonblank++;
		snprintf(loc, परिमाण(loc), "%.200s:%lu", file, linenum);
		सचे (auth_check_authkey_पङ्क्तिः(pw, कुञ्चिका, cp,
		    remote_ip, remote_host, loc, authoptsp) == 0)
			found_कुञ्चिका = 1;
	}
	मुक्त(पङ्क्तिः);
	debug2_f("%s: processed %lu/%lu lines", file, nonblank, linenum);
	पटिनिवत्त found_कुञ्चिका;
}

स्थिर FILE *
auth_openfile(ध्रुव वर्ण *file, संरचना passwd *pw, पूर्णाङ्क strict_modes,
    पूर्णाङ्क log_missing, वर्ण *file_type)
{
	वर्ण पङ्क्तिः[1024];
	संरचना stat st;
	पूर्णाङ्क fd;
	FILE *f;

	सचे ((fd = open(file, O_RDONLY|O_NONBLOCK)) == -1) {
		सचे (errno != ENOENT) {
			logit("Could not open user '%s' %s '%s': %s",
			    pw->pw_name, file_type, file, strerror(errno));
		} अञ्ञथा सचे (log_missing) {
			debug("Could not open user '%s' %s '%s': %s",
			    pw->pw_name, file_type, file, strerror(errno));
		}
		पटिनिवत्त रिक्त;
	}

	सचे (fstat(fd, &st) == -1) {
		close(fd);
		पटिनिवत्त रिक्त;
	}
	सचे (!S_ISREG(st.st_mode)) {
		logit("User '%s' %s '%s' is not a regular file",
		    pw->pw_name, file_type, file);
		close(fd);
		पटिनिवत्त रिक्त;
	}
	unset_nonblock(fd);
	सचे ((f = fdopen(fd, "r")) == रिक्त) {
		close(fd);
		पटिनिवत्त रिक्त;
	}
	सचे (strict_modes &&
	    safe_path_fd(fileno(f), file, pw, पङ्क्तिः, परिमाण(पङ्क्तिः)) != 0) {
		fclose(f);
		logit("Authentication refused: %s", पङ्क्तिः);
		auth_debug_add("Ignored %s: %s", file_type, पङ्क्तिः);
		पटिनिवत्त रिक्त;
	}

	पटिनिवत्त f;
}


FILE *
auth_openkeyfile(ध्रुव वर्ण *file, संरचना passwd *pw, पूर्णाङ्क strict_modes)
{
	पटिनिवत्त auth_openfile(file, pw, strict_modes, 1, "authorized keys");
}

FILE *
auth_openprincipals(ध्रुव वर्ण *file, संरचना passwd *pw, पूर्णाङ्क strict_modes)
{
	पटिनिवत्त auth_openfile(file, pw, strict_modes, 0,
	    "authorized principals");
}

