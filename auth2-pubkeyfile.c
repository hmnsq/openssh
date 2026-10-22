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

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <sys/types.h>
#অন্তর্ভাব <sys/stat.h>

#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <errno.h>
#অন্তর্ভাব <fcntl.h>
#অন্তর্ভাব <pwd.h>
#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <stdarg.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <time.h>
#অন্তর্ভাব <unistd.h>

#অন্তর্ভাব "ssh.h"
#অন্তর্ভাব "log.h"
#অন্তর্ভাব "misc.h"
#অন্তর্ভাব "sshkey.h"
#অন্তর্ভাব "digest.h"
#অন্তর্ভাব "hostfile.h"
#অন্তর্ভাব "auth.h"
#অন্তর্ভাব "auth-options.h"
#অন্তর্ভাব "authfile.h"
#অন্তর্ভাব "match.h"
#অন্তর্ভাব "ssherr.h"
#অন্তর্ভাব "xmalloc.h"

পূর্ণসংখ্যা
auth_authorise_keyopts(কাঠামো passwd *pw, কাঠামো sshauthopt *opts,
    পূর্ণসংখ্যা allow_cert_authority, ধ্রুবক অক্ষর *remote_ip, ধ্রুবক অক্ষর *remote_host,
    ধ্রুবক অক্ষর *loc)
{
	time_t now = time(ফাঁকা);
	অক্ষর buf[64];

	/*
	 * Check keys/principals file expiry time.
	 * NB. validity interval in certificate is handled elsewhere.
	 */
	যদি (opts->valid_before && now > 0 &&
	    opts->valid_before < (uint64_t)now) {
		format_absolute_time(opts->valid_before, buf, আকার(buf));
		debug("%s: entry expired at %s", loc, buf);
		auth_debug_add("%s: entry expired at %s", loc, buf);
		ফেরত -1;
	}
	/* Consistency checks */
	যদি (opts->cert_principals != ফাঁকা && !opts->cert_authority) {
		debug("%s: principals on non-CA key", loc);
		auth_debug_add("%s: principals on non-CA key", loc);
		/* deny access */
		ফেরত -1;
	}
	/* cert-authority flag isn't valid in authorized_principals files */
	যদি (!allow_cert_authority && opts->cert_authority) {
		debug("%s: cert-authority flag invalid here", loc);
		auth_debug_add("%s: cert-authority flag invalid here", loc);
		/* deny access */
		ফেরত -1;
	}

	/* Perform from= checks */
	যদি (opts->required_from_host_চাবিগুলি != ফাঁকা) {
		নির্বাচন (match_host_and_ip(remote_host, remote_ip,
		    opts->required_from_host_চাবিগুলি )) {
		ক্ষেত্র 1:
			/* Host name matches. */
			বিরতি;
		ক্ষেত্র -1:
		পূর্বনির্ধারিত:
			debug("%s: invalid from criteria", loc);
			auth_debug_add("%s: invalid from criteria", loc);
			/* FALLTHROUGH */
		ক্ষেত্র 0:
			logit("%s: Authentication tried for %.100s with "
			    "correct key but not from a permitted "
			    "host (host=%.200s, ip=%.200s, required=%.200s).",
			    loc, pw->pw_name, remote_host, remote_ip,
			    opts->required_from_host_চাবিগুলি);
			auth_debug_add("%s: Your host '%.200s' is not "
			    "permitted to use this key for login.",
			    loc, remote_host);
			/* deny access */
			ফেরত -1;
		}
	}
	/* Check source-address restriction from certificate */
	যদি (opts->required_from_host_cert != ফাঁকা) {
		নির্বাচন (addr_match_cidr_list(remote_ip,
		    opts->required_from_host_cert)) {
		ক্ষেত্র 1:
			/* accepted */
			বিরতি;
		ক্ষেত্র -1:
		পূর্বনির্ধারিত:
			/* invalid */
			error("%s: Certificate source-address invalid", loc);
			/* FALLTHROUGH */
		ক্ষেত্র 0:
			logit("%s: Authentication tried for %.100s with valid "
			    "certificate but not from a permitted source "
			    "address (%.200s).", loc, pw->pw_name, remote_ip);
			auth_debug_add("%s: Your address '%.200s' is not "
			    "permitted to use this certificate for login.",
			    loc, remote_ip);
			ফেরত -1;
		}
	}
	/*
	 *
	 * XXX this is spammy. We should report remotely only for keys
	 *     that are successful in actual auth attempts, and not PK_OK
	 *     tests.
	 */
	auth_log_authopts(loc, opts, 1);

	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
match_principals_option(ধ্রুবক অক্ষর *principal_list, কাঠামো sshkey_cert *cert)
{
	অক্ষর *list, *olist, *entry;
	u_int i;

	olist = list = xstrdup(principal_list);
	জন্য (;;) {
		যদি ((entry = strsep(&list, ",")) == ফাঁকা || *entry == '\0')
			বিরতি;
		জন্য (i = 0; i < cert->nprincipals; i++) {
			যদি (strcmp(entry, cert->principals[i]) == 0) {
				debug3("matched principal from key i"
				    "options \"%.100s\"", entry);
				মুক্ত(olist);
				ফেরত 1;
			}
		}
	}
	মুক্ত(olist);
	ফেরত 0;
}

/*
 * Process a single authorized_principals format line. Returns 0 and sets
 * authoptsp is principal is authorised, -1 otherwise. "loc" is used as a
 * log preamble for file/line information.
 */
পূর্ণসংখ্যা
auth_check_principals_সারি(অক্ষর *cp, ধ্রুবক কাঠামো sshkey_cert *cert,
    ধ্রুবক অক্ষর *loc, কাঠামো sshauthopt **authoptsp)
{
	u_int i, found = 0;
	অক্ষর *ep, *সারি_opts;
	ধ্রুবক অক্ষর *reason = ফাঁকা;
	কাঠামো sshauthopt *opts = ফাঁকা;

	যদি (authoptsp != ফাঁকা)
		*authoptsp = ফাঁকা;

	/* Trim trailing whitespace. */
	ep = cp + strlen(cp) - 1;
	যখন (ep > cp && (*ep == '\n' || *ep == ' ' || *ep == '\t'))
		*ep-- = '\0';

	/*
	 * If the line has internal whitespace then assume it has
	 * key options.
	 */
	সারি_opts = ফাঁকা;
	যদি ((ep = strrchr(cp, ' ')) != ফাঁকা ||
	    (ep = strrchr(cp, '\t')) != ফাঁকা) {
		জন্য (; *ep == ' ' || *ep == '\t'; ep++)
			;
		সারি_opts = cp;
		cp = ep;
	}
	যদি ((opts = sshauthopt_parse(সারি_opts, &reason)) == ফাঁকা) {
		debug("%s: bad principals options: %s", loc, reason);
		auth_debug_add("%s: bad principals options: %s", loc, reason);
		ফেরত -1;
	}
	/* Check principals in cert against those on line */
	জন্য (i = 0; i < cert->nprincipals; i++) {
		যদি (strcmp(cp, cert->principals[i]) != 0)
			চালু;
		debug3("%s: matched principal \"%.100s\"",
		    loc, cert->principals[i]);
		found = 1;
	}
	যদি (found && authoptsp != ফাঁকা) {
		*authoptsp = opts;
		opts = ফাঁকা;
	}
	sshauthopt_free(opts);
	ফেরত found ? 0 : -1;
}

পূর্ণসংখ্যা
auth_process_principals(FILE *f, ধ্রুবক অক্ষর *file,
    ধ্রুবক কাঠামো sshkey_cert *cert, কাঠামো sshauthopt **authoptsp)
{
	অক্ষর loc[256], *সারি = ফাঁকা, *cp, *ep;
	আকার_t linesize = 0;
	u_long linenum = 0, nonblank = 0;
	u_int found_principal = 0;

	যদি (authoptsp != ফাঁকা)
		*authoptsp = ফাঁকা;

	যখন (getline(&সারি, &linesize, f) != -1) {
		linenum++;
		/* Always consume entire input */
		যদি (found_principal)
			চালু;

		/* Skip leading whitespace. */
		জন্য (cp = সারি; *cp == ' ' || *cp == '\t'; cp++)
			;
		/* Skip blank and comment lines. */
		যদি ((ep = strchr(cp, '#')) != ফাঁকা)
			*ep = '\0';
		যদি (!*cp || *cp == '\n')
			চালু;

		nonblank++;
		snprintf(loc, আকার(loc), "%.200s:%lu", file, linenum);
		যদি (auth_check_principals_সারি(cp, cert, loc, authoptsp) == 0)
			found_principal = 1;
	}
	debug2_f("%s: processed %lu/%lu lines", file, nonblank, linenum);
	মুক্ত(সারি);
	ফেরত found_principal;
}

/*
 * Check a single line of an authorized_keys-format file. Returns 0 if key
 * matches, -1 otherwise. Will return key/cert options via *authoptsp
 * on success. "loc" is used as file/line location in log messages.
 */
পূর্ণসংখ্যা
auth_check_authkey_সারি(কাঠামো passwd *pw, কাঠামো sshkey *চাবি,
    অক্ষর *cp, ধ্রুবক অক্ষর *remote_ip, ধ্রুবক অক্ষর *remote_host, ধ্রুবক অক্ষর *loc,
    কাঠামো sshauthopt **authoptsp)
{
	পূর্ণসংখ্যা want_keytype = sshkey_is_cert(চাবি) ? চাবি_UNSPEC : চাবি->type;
	কাঠামো sshkey *found = ফাঁকা;
	কাঠামো sshauthopt *keyopts = ফাঁকা, *certopts = ফাঁকা, *finalopts = ফাঁকা;
	অক্ষর *চাবি_options = ফাঁকা, *fp = ফাঁকা;
	ধ্রুবক অক্ষর *reason = ফাঁকা;
	পূর্ণসংখ্যা ret = -1;

	যদি (authoptsp != ফাঁকা)
		*authoptsp = ফাঁকা;

	যদি ((found = sshkey_new(want_keytype)) == ফাঁকা) {
		debug3_f("keytype %d failed", want_keytype);
		যাও out;
	}

	/* XXX djm: peek at key type in line and skip if unwanted */

	যদি (sshkey_read(found, &cp) != 0) {
		/* no key?  check for options */
		debug2("%s: check options: '%s'", loc, cp);
		চাবি_options = cp;
		যদি (sshkey_advance_past_options(&cp) != 0) {
			reason = "invalid key option string";
			যাও fail_reason;
		}
		skip_space(&cp);
		যদি (sshkey_read(found, &cp) != 0) {
			/* still no key?  advance to next line*/
			debug2("%s: advance: '%s'", loc, cp);
			যাও out;
		}
	}
	/* Parse key options now; we need to know if this is a CA key */
	যদি ((keyopts = sshauthopt_parse(চাবি_options, &reason)) == ফাঁকা) {
		debug("%s: bad key options: %s", loc, reason);
		auth_debug_add("%s: bad key options: %s", loc, reason);
		যাও out;
	}
	/* Ignore keys that don't match or incorrectly marked as CAs */
	যদি (sshkey_is_cert(চাবি)) {
		/* Certificate; check signature key against CA */
		যদি (!sshkey_equal(found, চাবি->cert->signature_চাবি) ||
		    !keyopts->cert_authority)
			যাও out;
	} অন্যথা {
		/* Plain key: check it against key found in file */
		যদি (!sshkey_equal(found, চাবি) || keyopts->cert_authority)
			যাও out;
	}

	/* We have a candidate key, perform authorisation checks */
	যদি ((fp = sshkey_fingerprint(found,
	    SSH_FP_HASH_DEFAULT, SSH_FP_DEFAULT)) == ফাঁকা)
		fatal_f("fingerprint failed");

	debug("%s: matching %s found: %s %s", loc,
	    sshkey_is_cert(চাবি) ? "CA" : "key", sshkey_type(found), fp);

	যদি (auth_authorise_keyopts(pw, keyopts,
	    sshkey_is_cert(চাবি), remote_ip, remote_host, loc) != 0) {
		reason = "Refused by key options";
		যাও fail_reason;
	}
	/* That's all we need for plain keys. */
	যদি (!sshkey_is_cert(চাবি)) {
		verbose("Accepted key %s %s found at %s",
		    sshkey_type(found), fp, loc);
		finalopts = keyopts;
		keyopts = ফাঁকা;
		যাও success;
	}

	/*
	 * Additional authorisation for certificates.
	 */

	/* Parse and check options present in certificate */
	যদি ((certopts = sshauthopt_from_cert(চাবি)) == ফাঁকা) {
		reason = "Invalid certificate options";
		যাও cert_fail_reason;
	}
	যদি (auth_authorise_keyopts(pw, certopts, 0,
	    remote_ip, remote_host, loc) != 0) {
		reason = "Refused by certificate options";
		যাও cert_fail_reason;
	}
	যদি ((finalopts = sshauthopt_merge(keyopts, certopts, &reason)) == ফাঁকা)
		যাও cert_fail_reason;

	/*
	 * If the user has specified a list of principals as
	 * a key option, then prefer that list to matching
	 * their username in the certificate principals list.
	 */
	যদি (keyopts->cert_principals != ফাঁকা &&
	    !match_principals_option(keyopts->cert_principals, চাবি->cert)) {
		reason = "Certificate does not contain an authorized principal";
		যাও cert_fail_reason;
	}
	যদি (sshkey_cert_check_authority_now(চাবি, 0, 0,
	    keyopts->cert_principals == ফাঁকা ? pw->pw_name : ফাঁকা,
	    &reason) != 0)
		যাও cert_fail_reason;

	verbose("Accepted certificate ID \"%s\" (serial %llu) "
	    "signed by CA %s %s found at %s",
	    চাবি->cert->চাবি_id,
	    (unsigned long long)চাবি->cert->serial,
	    sshkey_type(found), fp, loc);

 success:
	যদি (finalopts == ফাঁকা)
		fatal_f("internal error: missing options");
	যদি (authoptsp != ফাঁকা) {
		*authoptsp = finalopts;
		finalopts = ফাঁকা;
	}
	/* success */
	ret = 0;
	যাও out;

 cert_fail_reason:
	error("Refusing certificate ID \"%s\" serial=%llu "
	    "signed by %s CA %s via %s: %s", চাবি->cert->চাবি_id,
	    (unsigned long long)চাবি->cert->serial,
	    sshkey_type(চাবি->cert->signature_চাবি), fp, loc, reason);
	auth_debug_add("Refused Certificate ID \"%s\" serial=%llu: %s",
	    চাবি->cert->চাবি_id, (unsigned long long)চাবি->cert->serial, reason);
	যাও out;

 fail_reason:
	error("%s at %s", reason, loc);
	auth_debug_add("%s", reason);
 out:
	মুক্ত(fp);
	sshauthopt_free(keyopts);
	sshauthopt_free(certopts);
	sshauthopt_free(finalopts);
	sshkey_free(found);
	ফেরত ret;
}

/*
 * Checks whether key is allowed in authorized_keys-format file,
 * returns 1 if the key is allowed or 0 otherwise.
 */
পূর্ণসংখ্যা
auth_check_authkeys_file(কাঠামো passwd *pw, FILE *f, অক্ষর *file,
    কাঠামো sshkey *চাবি, ধ্রুবক অক্ষর *remote_ip,
    ধ্রুবক অক্ষর *remote_host, কাঠামো sshauthopt **authoptsp)
{
	অক্ষর *cp, *সারি = ফাঁকা, loc[256];
	আকার_t linesize = 0;
	পূর্ণসংখ্যা found_চাবি = 0;
	u_long linenum = 0, nonblank = 0;

	যদি (authoptsp != ফাঁকা)
		*authoptsp = ফাঁকা;

	যখন (getline(&সারি, &linesize, f) != -1) {
		linenum++;
		/* Always consume entire file */
		যদি (found_চাবি)
			চালু;

		/* Skip leading whitespace, empty and comment lines. */
		cp = সারি;
		skip_space(&cp);
		যদি (!*cp || *cp == '\n' || *cp == '#')
			চালু;

		nonblank++;
		snprintf(loc, আকার(loc), "%.200s:%lu", file, linenum);
		যদি (auth_check_authkey_সারি(pw, চাবি, cp,
		    remote_ip, remote_host, loc, authoptsp) == 0)
			found_চাবি = 1;
	}
	মুক্ত(সারি);
	debug2_f("%s: processed %lu/%lu lines", file, nonblank, linenum);
	ফেরত found_চাবি;
}

স্থির FILE *
auth_openfile(ধ্রুবক অক্ষর *file, কাঠামো passwd *pw, পূর্ণসংখ্যা strict_modes,
    পূর্ণসংখ্যা log_missing, অক্ষর *file_type)
{
	অক্ষর সারি[1024];
	কাঠামো stat st;
	পূর্ণসংখ্যা fd;
	FILE *f;

	যদি ((fd = open(file, O_RDONLY|O_NONBLOCK)) == -1) {
		যদি (errno != ENOENT) {
			logit("Could not open user '%s' %s '%s': %s",
			    pw->pw_name, file_type, file, strerror(errno));
		} অন্যথা যদি (log_missing) {
			debug("Could not open user '%s' %s '%s': %s",
			    pw->pw_name, file_type, file, strerror(errno));
		}
		ফেরত ফাঁকা;
	}

	যদি (fstat(fd, &st) == -1) {
		close(fd);
		ফেরত ফাঁকা;
	}
	যদি (!S_ISREG(st.st_mode)) {
		logit("User '%s' %s '%s' is not a regular file",
		    pw->pw_name, file_type, file);
		close(fd);
		ফেরত ফাঁকা;
	}
	unset_nonblock(fd);
	যদি ((f = fdopen(fd, "r")) == ফাঁকা) {
		close(fd);
		ফেরত ফাঁকা;
	}
	যদি (strict_modes &&
	    safe_path_fd(fileno(f), file, pw, সারি, আকার(সারি)) != 0) {
		fclose(f);
		logit("Authentication refused: %s", সারি);
		auth_debug_add("Ignored %s: %s", file_type, সারি);
		ফেরত ফাঁকা;
	}

	ফেরত f;
}


FILE *
auth_openkeyfile(ধ্রুবক অক্ষর *file, কাঠামো passwd *pw, পূর্ণসংখ্যা strict_modes)
{
	ফেরত auth_openfile(file, pw, strict_modes, 1, "authorized keys");
}

FILE *
auth_openprincipals(ধ্রুবক অক্ষর *file, কাঠামো passwd *pw, পূর্ণসংখ্যা strict_modes)
{
	ফেরত auth_openfile(file, pw, strict_modes, 0,
	    "authorized principals");
}

