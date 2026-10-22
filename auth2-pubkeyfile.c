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

#شامل "includes.h"

#شامل <sys/types.h>
#شامل <sys/stat.h>

#شامل <stdlib.h>
#شامل <errno.h>
#شامل <fcntl.h>
#شامل <pwd.h>
#شامل <stdio.h>
#شامل <stdarg.h>
#شامل <string.h>
#شامل <time.h>
#شامل <unistd.h>

#شامل "ssh.h"
#شامل "log.h"
#شامل "misc.h"
#شامل "sshkey.h"
#شامل "digest.h"
#شامل "hostfile.h"
#شامل "auth.h"
#شامل "auth-options.h"
#شامل "authfile.h"
#شامل "match.h"
#شامل "ssherr.h"
#شامل "xmalloc.h"

صحیح
auth_authorise_keyopts(ساختار passwd *pw, ساختار sshauthopt *opts,
    صحیح allow_cert_authority, ثابت نویسه *remote_ip, ثابت نویسه *remote_host,
    ثابت نویسه *loc)
{
	time_t now = time(پوچ);
	نویسه buf[64];

	/*
	 * Check keys/principals file expiry time.
	 * NB. validity interval in certificate is handled elsewhere.
	 */
	اگر (opts->valid_before && now > 0 &&
	    opts->valid_before < (uint64_t)now) {
		format_absolute_time(opts->valid_before, buf, اندازه(buf));
		debug("%s: entry expired at %s", loc, buf);
		auth_debug_add("%s: entry expired at %s", loc, buf);
		بازگشت -1;
	}
	/* Consistency checks */
	اگر (opts->cert_principals != پوچ && !opts->cert_authority) {
		debug("%s: principals on non-CA key", loc);
		auth_debug_add("%s: principals on non-CA key", loc);
		/* deny access */
		بازگشت -1;
	}
	/* cert-authority flag isn't valid in authorized_principals files */
	اگر (!allow_cert_authority && opts->cert_authority) {
		debug("%s: cert-authority flag invalid here", loc);
		auth_debug_add("%s: cert-authority flag invalid here", loc);
		/* deny access */
		بازگشت -1;
	}

	/* Perform from= checks */
	اگر (opts->required_from_host_کلیدها != پوچ) {
		انتخاب (match_host_and_ip(remote_host, remote_ip,
		    opts->required_from_host_کلیدها )) {
		حالت 1:
			/* Host name matches. */
			بشکن;
		حالت -1:
		پیشفرض:
			debug("%s: invalid from criteria", loc);
			auth_debug_add("%s: invalid from criteria", loc);
			/* FALLTHROUGH */
		حالت 0:
			logit("%s: Authentication tried for %.100s with "
			    "correct key but not from a permitted "
			    "host (host=%.200s, ip=%.200s, required=%.200s).",
			    loc, pw->pw_name, remote_host, remote_ip,
			    opts->required_from_host_کلیدها);
			auth_debug_add("%s: Your host '%.200s' is not "
			    "permitted to use this key for login.",
			    loc, remote_host);
			/* deny access */
			بازگشت -1;
		}
	}
	/* Check source-address restriction from certificate */
	اگر (opts->required_from_host_cert != پوچ) {
		انتخاب (addr_match_cidr_list(remote_ip,
		    opts->required_from_host_cert)) {
		حالت 1:
			/* accepted */
			بشکن;
		حالت -1:
		پیشفرض:
			/* invalid */
			error("%s: Certificate source-address invalid", loc);
			/* FALLTHROUGH */
		حالت 0:
			logit("%s: Authentication tried for %.100s with valid "
			    "certificate but not from a permitted source "
			    "address (%.200s).", loc, pw->pw_name, remote_ip);
			auth_debug_add("%s: Your address '%.200s' is not "
			    "permitted to use this certificate for login.",
			    loc, remote_ip);
			بازگشت -1;
		}
	}
	/*
	 *
	 * XXX this is spammy. We should report remotely only for keys
	 *     that are successful in actual auth attempts, and not PK_OK
	 *     tests.
	 */
	auth_log_authopts(loc, opts, 1);

	بازگشت 0;
}

ایستا صحیح
match_principals_option(ثابت نویسه *principal_list, ساختار sshkey_cert *cert)
{
	نویسه *list, *olist, *entry;
	u_int i;

	olist = list = xstrdup(principal_list);
	برای (;;) {
		اگر ((entry = strsep(&list, ",")) == پوچ || *entry == '\0')
			بشکن;
		برای (i = 0; i < cert->nprincipals; i++) {
			اگر (strcmp(entry, cert->principals[i]) == 0) {
				debug3("matched principal from key i"
				    "options \"%.100s\"", entry);
				آزاد(olist);
				بازگشت 1;
			}
		}
	}
	آزاد(olist);
	بازگشت 0;
}

/*
 * Process a single authorized_principals format line. Returns 0 and sets
 * authoptsp is principal is authorised, -1 otherwise. "loc" is used as a
 * log preamble for file/line information.
 */
صحیح
auth_check_principals_سطر(نویسه *cp, ثابت ساختار sshkey_cert *cert,
    ثابت نویسه *loc, ساختار sshauthopt **authoptsp)
{
	u_int i, found = 0;
	نویسه *ep, *سطر_opts;
	ثابت نویسه *reason = پوچ;
	ساختار sshauthopt *opts = پوچ;

	اگر (authoptsp != پوچ)
		*authoptsp = پوچ;

	/* Trim trailing whitespace. */
	ep = cp + strlen(cp) - 1;
	وقتی (ep > cp && (*ep == '\n' || *ep == ' ' || *ep == '\t'))
		*ep-- = '\0';

	/*
	 * If the line has internal whitespace then assume it has
	 * key options.
	 */
	سطر_opts = پوچ;
	اگر ((ep = strrchr(cp, ' ')) != پوچ ||
	    (ep = strrchr(cp, '\t')) != پوچ) {
		برای (; *ep == ' ' || *ep == '\t'; ep++)
			;
		سطر_opts = cp;
		cp = ep;
	}
	اگر ((opts = sshauthopt_parse(سطر_opts, &reason)) == پوچ) {
		debug("%s: bad principals options: %s", loc, reason);
		auth_debug_add("%s: bad principals options: %s", loc, reason);
		بازگشت -1;
	}
	/* Check principals in cert against those on line */
	برای (i = 0; i < cert->nprincipals; i++) {
		اگر (strcmp(cp, cert->principals[i]) != 0)
			ادامه;
		debug3("%s: matched principal \"%.100s\"",
		    loc, cert->principals[i]);
		found = 1;
	}
	اگر (found && authoptsp != پوچ) {
		*authoptsp = opts;
		opts = پوچ;
	}
	sshauthopt_free(opts);
	بازگشت found ? 0 : -1;
}

صحیح
auth_process_principals(FILE *f, ثابت نویسه *file,
    ثابت ساختار sshkey_cert *cert, ساختار sshauthopt **authoptsp)
{
	نویسه loc[256], *سطر = پوچ, *cp, *ep;
	size_t linesize = 0;
	u_long linenum = 0, nonblank = 0;
	u_int found_principal = 0;

	اگر (authoptsp != پوچ)
		*authoptsp = پوچ;

	وقتی (getline(&سطر, &linesize, f) != -1) {
		linenum++;
		/* Always consume entire input */
		اگر (found_principal)
			ادامه;

		/* Skip leading whitespace. */
		برای (cp = سطر; *cp == ' ' || *cp == '\t'; cp++)
			;
		/* Skip blank and comment lines. */
		اگر ((ep = strchr(cp, '#')) != پوچ)
			*ep = '\0';
		اگر (!*cp || *cp == '\n')
			ادامه;

		nonblank++;
		snprintf(loc, اندازه(loc), "%.200s:%lu", file, linenum);
		اگر (auth_check_principals_سطر(cp, cert, loc, authoptsp) == 0)
			found_principal = 1;
	}
	debug2_f("%s: processed %lu/%lu lines", file, nonblank, linenum);
	آزاد(سطر);
	بازگشت found_principal;
}

/*
 * Check a single line of an authorized_keys-format file. Returns 0 if key
 * matches, -1 otherwise. Will return key/cert options via *authoptsp
 * on success. "loc" is used as file/line location in log messages.
 */
صحیح
auth_check_authkey_سطر(ساختار passwd *pw, ساختار sshkey *کلید,
    نویسه *cp, ثابت نویسه *remote_ip, ثابت نویسه *remote_host, ثابت نویسه *loc,
    ساختار sshauthopt **authoptsp)
{
	صحیح want_keytype = sshkey_is_cert(کلید) ? کلید_UNSPEC : کلید->type;
	ساختار sshkey *found = پوچ;
	ساختار sshauthopt *keyopts = پوچ, *certopts = پوچ, *finalopts = پوچ;
	نویسه *کلید_options = پوچ, *fp = پوچ;
	ثابت نویسه *reason = پوچ;
	صحیح ret = -1;

	اگر (authoptsp != پوچ)
		*authoptsp = پوچ;

	اگر ((found = sshkey_new(want_keytype)) == پوچ) {
		debug3_f("keytype %d failed", want_keytype);
		برو out;
	}

	/* XXX djm: peek at key type in line and skip if unwanted */

	اگر (sshkey_read(found, &cp) != 0) {
		/* no key?  check for options */
		debug2("%s: check options: '%s'", loc, cp);
		کلید_options = cp;
		اگر (sshkey_advance_past_options(&cp) != 0) {
			reason = "invalid key option string";
			برو fail_reason;
		}
		skip_space(&cp);
		اگر (sshkey_read(found, &cp) != 0) {
			/* still no key?  advance to next line*/
			debug2("%s: advance: '%s'", loc, cp);
			برو out;
		}
	}
	/* Parse key options now; we need to know if this is a CA key */
	اگر ((keyopts = sshauthopt_parse(کلید_options, &reason)) == پوچ) {
		debug("%s: bad key options: %s", loc, reason);
		auth_debug_add("%s: bad key options: %s", loc, reason);
		برو out;
	}
	/* Ignore keys that don't match or incorrectly marked as CAs */
	اگر (sshkey_is_cert(کلید)) {
		/* Certificate; check signature key against CA */
		اگر (!sshkey_equal(found, کلید->cert->signature_کلید) ||
		    !keyopts->cert_authority)
			برو out;
	} وگرنه {
		/* Plain key: check it against key found in file */
		اگر (!sshkey_equal(found, کلید) || keyopts->cert_authority)
			برو out;
	}

	/* We have a candidate key, perform authorisation checks */
	اگر ((fp = sshkey_fingerprint(found,
	    SSH_FP_HASH_DEFAULT, SSH_FP_DEFAULT)) == پوچ)
		fatal_f("fingerprint failed");

	debug("%s: matching %s found: %s %s", loc,
	    sshkey_is_cert(کلید) ? "CA" : "key", sshkey_type(found), fp);

	اگر (auth_authorise_keyopts(pw, keyopts,
	    sshkey_is_cert(کلید), remote_ip, remote_host, loc) != 0) {
		reason = "Refused by key options";
		برو fail_reason;
	}
	/* That's all we need for plain keys. */
	اگر (!sshkey_is_cert(کلید)) {
		verbose("Accepted key %s %s found at %s",
		    sshkey_type(found), fp, loc);
		finalopts = keyopts;
		keyopts = پوچ;
		برو success;
	}

	/*
	 * Additional authorisation for certificates.
	 */

	/* Parse and check options present in certificate */
	اگر ((certopts = sshauthopt_from_cert(کلید)) == پوچ) {
		reason = "Invalid certificate options";
		برو cert_fail_reason;
	}
	اگر (auth_authorise_keyopts(pw, certopts, 0,
	    remote_ip, remote_host, loc) != 0) {
		reason = "Refused by certificate options";
		برو cert_fail_reason;
	}
	اگر ((finalopts = sshauthopt_merge(keyopts, certopts, &reason)) == پوچ)
		برو cert_fail_reason;

	/*
	 * If the user has specified a list of principals as
	 * a key option, then prefer that list to matching
	 * their username in the certificate principals list.
	 */
	اگر (keyopts->cert_principals != پوچ &&
	    !match_principals_option(keyopts->cert_principals, کلید->cert)) {
		reason = "Certificate does not contain an authorized principal";
		برو cert_fail_reason;
	}
	اگر (sshkey_cert_check_authority_now(کلید, 0, 0,
	    keyopts->cert_principals == پوچ ? pw->pw_name : پوچ,
	    &reason) != 0)
		برو cert_fail_reason;

	verbose("Accepted certificate ID \"%s\" (serial %llu) "
	    "signed by CA %s %s found at %s",
	    کلید->cert->کلید_id,
	    (unsigned long long)کلید->cert->serial,
	    sshkey_type(found), fp, loc);

 success:
	اگر (finalopts == پوچ)
		fatal_f("internal error: missing options");
	اگر (authoptsp != پوچ) {
		*authoptsp = finalopts;
		finalopts = پوچ;
	}
	/* success */
	ret = 0;
	برو out;

 cert_fail_reason:
	error("Refusing certificate ID \"%s\" serial=%llu "
	    "signed by %s CA %s via %s: %s", کلید->cert->کلید_id,
	    (unsigned long long)کلید->cert->serial,
	    sshkey_type(کلید->cert->signature_کلید), fp, loc, reason);
	auth_debug_add("Refused Certificate ID \"%s\" serial=%llu: %s",
	    کلید->cert->کلید_id, (unsigned long long)کلید->cert->serial, reason);
	برو out;

 fail_reason:
	error("%s at %s", reason, loc);
	auth_debug_add("%s", reason);
 out:
	آزاد(fp);
	sshauthopt_free(keyopts);
	sshauthopt_free(certopts);
	sshauthopt_free(finalopts);
	sshkey_free(found);
	بازگشت ret;
}

/*
 * Checks whether key is allowed in authorized_keys-format file,
 * returns 1 if the key is allowed or 0 otherwise.
 */
صحیح
auth_check_authkeys_file(ساختار passwd *pw, FILE *f, نویسه *file,
    ساختار sshkey *کلید, ثابت نویسه *remote_ip,
    ثابت نویسه *remote_host, ساختار sshauthopt **authoptsp)
{
	نویسه *cp, *سطر = پوچ, loc[256];
	size_t linesize = 0;
	صحیح found_کلید = 0;
	u_long linenum = 0, nonblank = 0;

	اگر (authoptsp != پوچ)
		*authoptsp = پوچ;

	وقتی (getline(&سطر, &linesize, f) != -1) {
		linenum++;
		/* Always consume entire file */
		اگر (found_کلید)
			ادامه;

		/* Skip leading whitespace, empty and comment lines. */
		cp = سطر;
		skip_space(&cp);
		اگر (!*cp || *cp == '\n' || *cp == '#')
			ادامه;

		nonblank++;
		snprintf(loc, اندازه(loc), "%.200s:%lu", file, linenum);
		اگر (auth_check_authkey_سطر(pw, کلید, cp,
		    remote_ip, remote_host, loc, authoptsp) == 0)
			found_کلید = 1;
	}
	آزاد(سطر);
	debug2_f("%s: processed %lu/%lu lines", file, nonblank, linenum);
	بازگشت found_کلید;
}

ایستا FILE *
auth_openfile(ثابت نویسه *file, ساختار passwd *pw, صحیح strict_modes,
    صحیح log_missing, نویسه *file_type)
{
	نویسه سطر[1024];
	ساختار stat st;
	صحیح fd;
	FILE *f;

	اگر ((fd = open(file, O_RDONLY|O_NONBLOCK)) == -1) {
		اگر (errno != ENOENT) {
			logit("Could not open user '%s' %s '%s': %s",
			    pw->pw_name, file_type, file, strerror(errno));
		} وگرنه اگر (log_missing) {
			debug("Could not open user '%s' %s '%s': %s",
			    pw->pw_name, file_type, file, strerror(errno));
		}
		بازگشت پوچ;
	}

	اگر (fstat(fd, &st) == -1) {
		close(fd);
		بازگشت پوچ;
	}
	اگر (!S_ISREG(st.st_mode)) {
		logit("User '%s' %s '%s' is not a regular file",
		    pw->pw_name, file_type, file);
		close(fd);
		بازگشت پوچ;
	}
	unset_nonblock(fd);
	اگر ((f = fdopen(fd, "r")) == پوچ) {
		close(fd);
		بازگشت پوچ;
	}
	اگر (strict_modes &&
	    safe_path_fd(fileno(f), file, pw, سطر, اندازه(سطر)) != 0) {
		fclose(f);
		logit("Authentication refused: %s", سطر);
		auth_debug_add("Ignored %s: %s", file_type, سطر);
		بازگشت پوچ;
	}

	بازگشت f;
}


FILE *
auth_openkeyfile(ثابت نویسه *file, ساختار passwd *pw, صحیح strict_modes)
{
	بازگشت auth_openfile(file, pw, strict_modes, 1, "authorized keys");
}

FILE *
auth_openprincipals(ثابت نویسه *file, ساختار passwd *pw, صحیح strict_modes)
{
	بازگشت auth_openfile(file, pw, strict_modes, 0,
	    "authorized principals");
}

