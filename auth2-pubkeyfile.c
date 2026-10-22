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

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <sys/stat.h>

#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <errno.h>
#அந்தர்பாவ <fcntl.h>
#அந்தர்பாவ <pwd.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <stdarg.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <time.h>
#அந்தர்பாவ <unistd.h>

#அந்தர்பாவ "ssh.h"
#அந்தர்பாவ "log.h"
#அந்தர்பாவ "misc.h"
#அந்தர்பாவ "sshkey.h"
#அந்தர்பாவ "digest.h"
#அந்தர்பாவ "hostfile.h"
#அந்தர்பாவ "auth.h"
#அந்தர்பாவ "auth-options.h"
#அந்தர்பாவ "authfile.h"
#அந்தர்பாவ "match.h"
#அந்தர்பாவ "ssherr.h"
#அந்தர்பாவ "xmalloc.h"

முழு
auth_authorise_keyopts(கட்டமைப்பு passwd *pw, கட்டமைப்பு sshauthopt *opts,
    முழு allow_cert_authority, மாறிலி எழுத்து *remote_ip, மாறிலி எழுத்து *remote_host,
    மாறிலி எழுத்து *loc)
{
	time_t now = time(வெற்று);
	எழுத்து buf[64];

	/*
	 * Check keys/principals file expiry time.
	 * NB. validity interval in certificate is handled elsewhere.
	 */
	எனில் (opts->valid_before && now > 0 &&
	    opts->valid_before < (uint64_t)now) {
		format_absolute_time(opts->valid_before, buf, அளவு(buf));
		debug("%s: entry expired at %s", loc, buf);
		auth_debug_add("%s: entry expired at %s", loc, buf);
		திரும்பு -1;
	}
	/* Consistency checks */
	எனில் (opts->cert_principals != வெற்று && !opts->cert_authority) {
		debug("%s: principals on non-CA key", loc);
		auth_debug_add("%s: principals on non-CA key", loc);
		/* deny access */
		திரும்பு -1;
	}
	/* cert-authority flag isn't valid in authorized_principals files */
	எனில் (!allow_cert_authority && opts->cert_authority) {
		debug("%s: cert-authority flag invalid here", loc);
		auth_debug_add("%s: cert-authority flag invalid here", loc);
		/* deny access */
		திரும்பு -1;
	}

	/* Perform from= checks */
	எனில் (opts->required_from_host_சாவிகள் != வெற்று) {
		தேர்வு (match_host_and_ip(remote_host, remote_ip,
		    opts->required_from_host_சாவிகள் )) {
		நிலை 1:
			/* Host name matches. */
			நிறுத்து;
		நிலை -1:
		இயல்பு:
			debug("%s: invalid from criteria", loc);
			auth_debug_add("%s: invalid from criteria", loc);
			/* FALLTHROUGH */
		நிலை 0:
			logit("%s: Authentication tried for %.100s with "
			    "correct key but not from a permitted "
			    "host (host=%.200s, ip=%.200s, required=%.200s).",
			    loc, pw->pw_name, remote_host, remote_ip,
			    opts->required_from_host_சாவிகள்);
			auth_debug_add("%s: Your host '%.200s' is not "
			    "permitted to use this key for login.",
			    loc, remote_host);
			/* deny access */
			திரும்பு -1;
		}
	}
	/* Check source-address restriction from certificate */
	எனில் (opts->required_from_host_cert != வெற்று) {
		தேர்வு (addr_match_cidr_list(remote_ip,
		    opts->required_from_host_cert)) {
		நிலை 1:
			/* accepted */
			நிறுத்து;
		நிலை -1:
		இயல்பு:
			/* invalid */
			error("%s: Certificate source-address invalid", loc);
			/* FALLTHROUGH */
		நிலை 0:
			logit("%s: Authentication tried for %.100s with valid "
			    "certificate but not from a permitted source "
			    "address (%.200s).", loc, pw->pw_name, remote_ip);
			auth_debug_add("%s: Your address '%.200s' is not "
			    "permitted to use this certificate for login.",
			    loc, remote_ip);
			திரும்பு -1;
		}
	}
	/*
	 *
	 * XXX this is spammy. We should report remotely only for keys
	 *     that are successful in actual auth attempts, and not PK_OK
	 *     tests.
	 */
	auth_log_authopts(loc, opts, 1);

	திரும்பு 0;
}

நிலையான முழு
match_principals_option(மாறிலி எழுத்து *principal_list, கட்டமைப்பு sshkey_cert *cert)
{
	எழுத்து *list, *olist, *entry;
	u_int i;

	olist = list = xstrdup(principal_list);
	க்கு (;;) {
		எனில் ((entry = strsep(&list, ",")) == வெற்று || *entry == '\0')
			நிறுத்து;
		க்கு (i = 0; i < cert->nprincipals; i++) {
			எனில் (strcmp(entry, cert->principals[i]) == 0) {
				debug3("matched principal from key i"
				    "options \"%.100s\"", entry);
				விடுவி(olist);
				திரும்பு 1;
			}
		}
	}
	விடுவி(olist);
	திரும்பு 0;
}

/*
 * Process a single authorized_principals format line. Returns 0 and sets
 * authoptsp is principal is authorised, -1 otherwise. "loc" is used as a
 * log preamble for file/line information.
 */
முழு
auth_check_principals_வரி(எழுத்து *cp, மாறிலி கட்டமைப்பு sshkey_cert *cert,
    மாறிலி எழுத்து *loc, கட்டமைப்பு sshauthopt **authoptsp)
{
	u_int i, found = 0;
	எழுத்து *ep, *வரி_opts;
	மாறிலி எழுத்து *reason = வெற்று;
	கட்டமைப்பு sshauthopt *opts = வெற்று;

	எனில் (authoptsp != வெற்று)
		*authoptsp = வெற்று;

	/* Trim trailing whitespace. */
	ep = cp + strlen(cp) - 1;
	போது (ep > cp && (*ep == '\n' || *ep == ' ' || *ep == '\t'))
		*ep-- = '\0';

	/*
	 * If the line has internal whitespace then assume it has
	 * key options.
	 */
	வரி_opts = வெற்று;
	எனில் ((ep = strrchr(cp, ' ')) != வெற்று ||
	    (ep = strrchr(cp, '\t')) != வெற்று) {
		க்கு (; *ep == ' ' || *ep == '\t'; ep++)
			;
		வரி_opts = cp;
		cp = ep;
	}
	எனில் ((opts = sshauthopt_parse(வரி_opts, &reason)) == வெற்று) {
		debug("%s: bad principals options: %s", loc, reason);
		auth_debug_add("%s: bad principals options: %s", loc, reason);
		திரும்பு -1;
	}
	/* Check principals in cert against those on line */
	க்கு (i = 0; i < cert->nprincipals; i++) {
		எனில் (strcmp(cp, cert->principals[i]) != 0)
			தொடர்;
		debug3("%s: matched principal \"%.100s\"",
		    loc, cert->principals[i]);
		found = 1;
	}
	எனில் (found && authoptsp != வெற்று) {
		*authoptsp = opts;
		opts = வெற்று;
	}
	sshauthopt_free(opts);
	திரும்பு found ? 0 : -1;
}

முழு
auth_process_principals(FILE *f, மாறிலி எழுத்து *file,
    மாறிலி கட்டமைப்பு sshkey_cert *cert, கட்டமைப்பு sshauthopt **authoptsp)
{
	எழுத்து loc[256], *வரி = வெற்று, *cp, *ep;
	size_t linesize = 0;
	u_long linenum = 0, nonblank = 0;
	u_int found_principal = 0;

	எனில் (authoptsp != வெற்று)
		*authoptsp = வெற்று;

	போது (getline(&வரி, &linesize, f) != -1) {
		linenum++;
		/* Always consume entire input */
		எனில் (found_principal)
			தொடர்;

		/* Skip leading whitespace. */
		க்கு (cp = வரி; *cp == ' ' || *cp == '\t'; cp++)
			;
		/* Skip blank and comment lines. */
		எனில் ((ep = strchr(cp, '#')) != வெற்று)
			*ep = '\0';
		எனில் (!*cp || *cp == '\n')
			தொடர்;

		nonblank++;
		snprintf(loc, அளவு(loc), "%.200s:%lu", file, linenum);
		எனில் (auth_check_principals_வரி(cp, cert, loc, authoptsp) == 0)
			found_principal = 1;
	}
	debug2_f("%s: processed %lu/%lu lines", file, nonblank, linenum);
	விடுவி(வரி);
	திரும்பு found_principal;
}

/*
 * Check a single line of an authorized_keys-format file. Returns 0 if key
 * matches, -1 otherwise. Will return key/cert options via *authoptsp
 * on success. "loc" is used as file/line location in log messages.
 */
முழு
auth_check_authkey_வரி(கட்டமைப்பு passwd *pw, கட்டமைப்பு sshkey *சாவி,
    எழுத்து *cp, மாறிலி எழுத்து *remote_ip, மாறிலி எழுத்து *remote_host, மாறிலி எழுத்து *loc,
    கட்டமைப்பு sshauthopt **authoptsp)
{
	முழு want_keytype = sshkey_is_cert(சாவி) ? சாவி_UNSPEC : சாவி->type;
	கட்டமைப்பு sshkey *found = வெற்று;
	கட்டமைப்பு sshauthopt *keyopts = வெற்று, *certopts = வெற்று, *finalopts = வெற்று;
	எழுத்து *சாவி_options = வெற்று, *fp = வெற்று;
	மாறிலி எழுத்து *reason = வெற்று;
	முழு ret = -1;

	எனில் (authoptsp != வெற்று)
		*authoptsp = வெற்று;

	எனில் ((found = sshkey_new(want_keytype)) == வெற்று) {
		debug3_f("keytype %d failed", want_keytype);
		செல் out;
	}

	/* XXX djm: peek at key type in line and skip if unwanted */

	எனில் (sshkey_read(found, &cp) != 0) {
		/* no key?  check for options */
		debug2("%s: check options: '%s'", loc, cp);
		சாவி_options = cp;
		எனில் (sshkey_advance_past_options(&cp) != 0) {
			reason = "invalid key option string";
			செல் fail_reason;
		}
		skip_space(&cp);
		எனில் (sshkey_read(found, &cp) != 0) {
			/* still no key?  advance to next line*/
			debug2("%s: advance: '%s'", loc, cp);
			செல் out;
		}
	}
	/* Parse key options now; we need to know if this is a CA key */
	எனில் ((keyopts = sshauthopt_parse(சாவி_options, &reason)) == வெற்று) {
		debug("%s: bad key options: %s", loc, reason);
		auth_debug_add("%s: bad key options: %s", loc, reason);
		செல் out;
	}
	/* Ignore keys that don't match or incorrectly marked as CAs */
	எனில் (sshkey_is_cert(சாவி)) {
		/* Certificate; check signature key against CA */
		எனில் (!sshkey_equal(found, சாவி->cert->signature_சாவி) ||
		    !keyopts->cert_authority)
			செல் out;
	} இல்லையெனில் {
		/* Plain key: check it against key found in file */
		எனில் (!sshkey_equal(found, சாவி) || keyopts->cert_authority)
			செல் out;
	}

	/* We have a candidate key, perform authorisation checks */
	எனில் ((fp = sshkey_fingerprint(found,
	    SSH_FP_HASH_DEFAULT, SSH_FP_DEFAULT)) == வெற்று)
		fatal_f("fingerprint failed");

	debug("%s: matching %s found: %s %s", loc,
	    sshkey_is_cert(சாவி) ? "CA" : "key", sshkey_type(found), fp);

	எனில் (auth_authorise_keyopts(pw, keyopts,
	    sshkey_is_cert(சாவி), remote_ip, remote_host, loc) != 0) {
		reason = "Refused by key options";
		செல் fail_reason;
	}
	/* That's all we need for plain keys. */
	எனில் (!sshkey_is_cert(சாவி)) {
		verbose("Accepted key %s %s found at %s",
		    sshkey_type(found), fp, loc);
		finalopts = keyopts;
		keyopts = வெற்று;
		செல் success;
	}

	/*
	 * Additional authorisation for certificates.
	 */

	/* Parse and check options present in certificate */
	எனில் ((certopts = sshauthopt_from_cert(சாவி)) == வெற்று) {
		reason = "Invalid certificate options";
		செல் cert_fail_reason;
	}
	எனில் (auth_authorise_keyopts(pw, certopts, 0,
	    remote_ip, remote_host, loc) != 0) {
		reason = "Refused by certificate options";
		செல் cert_fail_reason;
	}
	எனில் ((finalopts = sshauthopt_merge(keyopts, certopts, &reason)) == வெற்று)
		செல் cert_fail_reason;

	/*
	 * If the user has specified a list of principals as
	 * a key option, then prefer that list to matching
	 * their username in the certificate principals list.
	 */
	எனில் (keyopts->cert_principals != வெற்று &&
	    !match_principals_option(keyopts->cert_principals, சாவி->cert)) {
		reason = "Certificate does not contain an authorized principal";
		செல் cert_fail_reason;
	}
	எனில் (sshkey_cert_check_authority_now(சாவி, 0, 0,
	    keyopts->cert_principals == வெற்று ? pw->pw_name : வெற்று,
	    &reason) != 0)
		செல் cert_fail_reason;

	verbose("Accepted certificate ID \"%s\" (serial %llu) "
	    "signed by CA %s %s found at %s",
	    சாவி->cert->சாவி_id,
	    (unsigned long long)சாவி->cert->serial,
	    sshkey_type(found), fp, loc);

 success:
	எனில் (finalopts == வெற்று)
		fatal_f("internal error: missing options");
	எனில் (authoptsp != வெற்று) {
		*authoptsp = finalopts;
		finalopts = வெற்று;
	}
	/* success */
	ret = 0;
	செல் out;

 cert_fail_reason:
	error("Refusing certificate ID \"%s\" serial=%llu "
	    "signed by %s CA %s via %s: %s", சாவி->cert->சாவி_id,
	    (unsigned long long)சாவி->cert->serial,
	    sshkey_type(சாவி->cert->signature_சாவி), fp, loc, reason);
	auth_debug_add("Refused Certificate ID \"%s\" serial=%llu: %s",
	    சாவி->cert->சாவி_id, (unsigned long long)சாவி->cert->serial, reason);
	செல் out;

 fail_reason:
	error("%s at %s", reason, loc);
	auth_debug_add("%s", reason);
 out:
	விடுவி(fp);
	sshauthopt_free(keyopts);
	sshauthopt_free(certopts);
	sshauthopt_free(finalopts);
	sshkey_free(found);
	திரும்பு ret;
}

/*
 * Checks whether key is allowed in authorized_keys-format file,
 * returns 1 if the key is allowed or 0 otherwise.
 */
முழு
auth_check_authkeys_file(கட்டமைப்பு passwd *pw, FILE *f, எழுத்து *file,
    கட்டமைப்பு sshkey *சாவி, மாறிலி எழுத்து *remote_ip,
    மாறிலி எழுத்து *remote_host, கட்டமைப்பு sshauthopt **authoptsp)
{
	எழுத்து *cp, *வரி = வெற்று, loc[256];
	size_t linesize = 0;
	முழு found_சாவி = 0;
	u_long linenum = 0, nonblank = 0;

	எனில் (authoptsp != வெற்று)
		*authoptsp = வெற்று;

	போது (getline(&வரி, &linesize, f) != -1) {
		linenum++;
		/* Always consume entire file */
		எனில் (found_சாவி)
			தொடர்;

		/* Skip leading whitespace, empty and comment lines. */
		cp = வரி;
		skip_space(&cp);
		எனில் (!*cp || *cp == '\n' || *cp == '#')
			தொடர்;

		nonblank++;
		snprintf(loc, அளவு(loc), "%.200s:%lu", file, linenum);
		எனில் (auth_check_authkey_வரி(pw, சாவி, cp,
		    remote_ip, remote_host, loc, authoptsp) == 0)
			found_சாவி = 1;
	}
	விடுவி(வரி);
	debug2_f("%s: processed %lu/%lu lines", file, nonblank, linenum);
	திரும்பு found_சாவி;
}

நிலையான FILE *
auth_openfile(மாறிலி எழுத்து *file, கட்டமைப்பு passwd *pw, முழு strict_modes,
    முழு log_missing, எழுத்து *file_type)
{
	எழுத்து வரி[1024];
	கட்டமைப்பு stat st;
	முழு fd;
	FILE *f;

	எனில் ((fd = open(file, O_RDONLY|O_NONBLOCK)) == -1) {
		எனில் (errno != ENOENT) {
			logit("Could not open user '%s' %s '%s': %s",
			    pw->pw_name, file_type, file, strerror(errno));
		} இல்லையெனில் எனில் (log_missing) {
			debug("Could not open user '%s' %s '%s': %s",
			    pw->pw_name, file_type, file, strerror(errno));
		}
		திரும்பு வெற்று;
	}

	எனில் (fstat(fd, &st) == -1) {
		close(fd);
		திரும்பு வெற்று;
	}
	எனில் (!S_ISREG(st.st_mode)) {
		logit("User '%s' %s '%s' is not a regular file",
		    pw->pw_name, file_type, file);
		close(fd);
		திரும்பு வெற்று;
	}
	unset_nonblock(fd);
	எனில் ((f = fdopen(fd, "r")) == வெற்று) {
		close(fd);
		திரும்பு வெற்று;
	}
	எனில் (strict_modes &&
	    safe_path_fd(fileno(f), file, pw, வரி, அளவு(வரி)) != 0) {
		fclose(f);
		logit("Authentication refused: %s", வரி);
		auth_debug_add("Ignored %s: %s", file_type, வரி);
		திரும்பு வெற்று;
	}

	திரும்பு f;
}


FILE *
auth_openkeyfile(மாறிலி எழுத்து *file, கட்டமைப்பு passwd *pw, முழு strict_modes)
{
	திரும்பு auth_openfile(file, pw, strict_modes, 1, "authorized keys");
}

FILE *
auth_openprincipals(மாறிலி எழுத்து *file, கட்டமைப்பு passwd *pw, முழு strict_modes)
{
	திரும்பு auth_openfile(file, pw, strict_modes, 0,
	    "authorized principals");
}

