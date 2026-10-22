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

#অন্তর্ভাৱ "includes.h"

#অন্তর্ভাৱ <sys/types.h>
#অন্তর্ভাৱ <sys/stat.h>

#অন্তর্ভাৱ <stdlib.h>
#অন্তর্ভাৱ <errno.h>
#অন্তর্ভাৱ <fcntl.h>
#অন্তর্ভাৱ <pwd.h>
#অন্তর্ভাৱ <stdio.h>
#অন্তর্ভাৱ <stdarg.h>
#অন্তর্ভাৱ <string.h>
#অন্তর্ভাৱ <time.h>
#অন্তর্ভাৱ <unistd.h>

#অন্তর্ভাৱ "ssh.h"
#অন্তর্ভাৱ "log.h"
#অন্তর্ভাৱ "misc.h"
#অন্তর্ভাৱ "sshkey.h"
#অন্তর্ভাৱ "digest.h"
#অন্তর্ভাৱ "hostfile.h"
#অন্তর্ভাৱ "auth.h"
#অন্তর্ভাৱ "auth-options.h"
#অন্তর্ভাৱ "authfile.h"
#অন্তর্ভাৱ "match.h"
#অন্তর্ভাৱ "ssherr.h"
#অন্তর্ভাৱ "xmalloc.h"

পূর্ণাঙ্ক
auth_authorise_keyopts(সংরচনা passwd *pw, সংরচনা sshauthopt *opts,
    পূর্ণাঙ্ক allow_cert_authority, ধ্রুৱ ৱর্ণ *remote_ip, ধ্রুৱ ৱর্ণ *remote_host,
    ধ্রুৱ ৱর্ণ *loc)
{
	time_t now = time(রিক্ত);
	ৱর্ণ buf[64];

	/*
	 * Check keys/principals file expiry time.
	 * NB. validity interval in certificate is handled elsewhere.
	 */
	যদি (opts->valid_before && now > 0 &&
	    opts->valid_before < (uint64_t)now) {
		format_absolute_time(opts->valid_before, buf, পরিমাণ(buf));
		debug("%s: entry expired at %s", loc, buf);
		auth_debug_add("%s: entry expired at %s", loc, buf);
		ঘূৰাই -1;
	}
	/* Consistency checks */
	যদি (opts->cert_principals != রিক্ত && !opts->cert_authority) {
		debug("%s: principals on non-CA key", loc);
		auth_debug_add("%s: principals on non-CA key", loc);
		/* deny access */
		ঘূৰাই -1;
	}
	/* cert-authority flag isn't valid in authorized_principals files */
	যদি (!allow_cert_authority && opts->cert_authority) {
		debug("%s: cert-authority flag invalid here", loc);
		auth_debug_add("%s: cert-authority flag invalid here", loc);
		/* deny access */
		ঘূৰাই -1;
	}

	/* Perform from= checks */
	যদি (opts->required_from_host_চাবিগুলি != রিক্ত) {
		ৱিকল্প (match_host_and_ip(remote_host, remote_ip,
		    opts->required_from_host_চাবিগুলি )) {
		পক্ষ 1:
			/* Host name matches. */
			ভঙ্গ;
		পক্ষ -1:
		স্ৱভাৱ:
			debug("%s: invalid from criteria", loc);
			auth_debug_add("%s: invalid from criteria", loc);
			/* FALLTHROUGH */
		পক্ষ 0:
			logit("%s: Authentication tried for %.100s with "
			    "correct key but not from a permitted "
			    "host (host=%.200s, ip=%.200s, required=%.200s).",
			    loc, pw->pw_name, remote_host, remote_ip,
			    opts->required_from_host_চাবিগুলি);
			auth_debug_add("%s: Your host '%.200s' is not "
			    "permitted to use this key for login.",
			    loc, remote_host);
			/* deny access */
			ঘূৰাই -1;
		}
	}
	/* Check source-address restriction from certificate */
	যদি (opts->required_from_host_cert != রিক্ত) {
		ৱিকল্প (addr_match_cidr_list(remote_ip,
		    opts->required_from_host_cert)) {
		পক্ষ 1:
			/* accepted */
			ভঙ্গ;
		পক্ষ -1:
		স্ৱভাৱ:
			/* invalid */
			error("%s: Certificate source-address invalid", loc);
			/* FALLTHROUGH */
		পক্ষ 0:
			logit("%s: Authentication tried for %.100s with valid "
			    "certificate but not from a permitted source "
			    "address (%.200s).", loc, pw->pw_name, remote_ip);
			auth_debug_add("%s: Your address '%.200s' is not "
			    "permitted to use this certificate for login.",
			    loc, remote_ip);
			ঘূৰাই -1;
		}
	}
	/*
	 *
	 * XXX this is spammy. We should report remotely only for keys
	 *     that are successful in actual auth attempts, and not PK_OK
	 *     tests.
	 */
	auth_log_authopts(loc, opts, 1);

	ঘূৰাই 0;
}

স্থির পূর্ণাঙ্ক
match_principals_option(ধ্রুৱ ৱর্ণ *principal_list, সংরচনা sshkey_cert *cert)
{
	ৱর্ণ *list, *olist, *entry;
	u_int i;

	olist = list = xstrdup(principal_list);
	বাবে (;;) {
		যদি ((entry = strsep(&list, ",")) == রিক্ত || *entry == '\0')
			ভঙ্গ;
		বাবে (i = 0; i < cert->nprincipals; i++) {
			যদি (strcmp(entry, cert->principals[i]) == 0) {
				debug3("matched principal from key i"
				    "options \"%.100s\"", entry);
				মুক্ত(olist);
				ঘূৰাই 1;
			}
		}
	}
	মুক্ত(olist);
	ঘূৰাই 0;
}

/*
 * Process a single authorized_principals format line. Returns 0 and sets
 * authoptsp is principal is authorised, -1 otherwise. "loc" is used as a
 * log preamble for file/line information.
 */
পূর্ণাঙ্ক
auth_check_principals_সাৰি(ৱর্ণ *cp, ধ্রুৱ সংরচনা sshkey_cert *cert,
    ধ্রুৱ ৱর্ণ *loc, সংরচনা sshauthopt **authoptsp)
{
	u_int i, found = 0;
	ৱর্ণ *ep, *সাৰি_opts;
	ধ্রুৱ ৱর্ণ *reason = রিক্ত;
	সংরচনা sshauthopt *opts = রিক্ত;

	যদি (authoptsp != রিক্ত)
		*authoptsp = রিক্ত;

	/* Trim trailing whitespace. */
	ep = cp + strlen(cp) - 1;
	যেতিয়ালৈ (ep > cp && (*ep == '\n' || *ep == ' ' || *ep == '\t'))
		*ep-- = '\0';

	/*
	 * If the line has internal whitespace then assume it has
	 * key options.
	 */
	সাৰি_opts = রিক্ত;
	যদি ((ep = strrchr(cp, ' ')) != রিক্ত ||
	    (ep = strrchr(cp, '\t')) != রিক্ত) {
		বাবে (; *ep == ' ' || *ep == '\t'; ep++)
			;
		সাৰি_opts = cp;
		cp = ep;
	}
	যদি ((opts = sshauthopt_parse(সাৰি_opts, &reason)) == রিক্ত) {
		debug("%s: bad principals options: %s", loc, reason);
		auth_debug_add("%s: bad principals options: %s", loc, reason);
		ঘূৰাই -1;
	}
	/* Check principals in cert against those on line */
	বাবে (i = 0; i < cert->nprincipals; i++) {
		যদি (strcmp(cp, cert->principals[i]) != 0)
			অনুৱর্ত;
		debug3("%s: matched principal \"%.100s\"",
		    loc, cert->principals[i]);
		found = 1;
	}
	যদি (found && authoptsp != রিক্ত) {
		*authoptsp = opts;
		opts = রিক্ত;
	}
	sshauthopt_free(opts);
	ঘূৰাই found ? 0 : -1;
}

পূর্ণাঙ্ক
auth_process_principals(FILE *f, ধ্রুৱ ৱর্ণ *file,
    ধ্রুৱ সংরচনা sshkey_cert *cert, সংরচনা sshauthopt **authoptsp)
{
	ৱর্ণ loc[256], *সাৰি = রিক্ত, *cp, *ep;
	size_t linesize = 0;
	u_long linenum = 0, nonblank = 0;
	u_int found_principal = 0;

	যদি (authoptsp != রিক্ত)
		*authoptsp = রিক্ত;

	যেতিয়ালৈ (getline(&সাৰি, &linesize, f) != -1) {
		linenum++;
		/* Always consume entire input */
		যদি (found_principal)
			অনুৱর্ত;

		/* Skip leading whitespace. */
		বাবে (cp = সাৰি; *cp == ' ' || *cp == '\t'; cp++)
			;
		/* Skip blank and comment lines. */
		যদি ((ep = strchr(cp, '#')) != রিক্ত)
			*ep = '\0';
		যদি (!*cp || *cp == '\n')
			অনুৱর্ত;

		nonblank++;
		snprintf(loc, পরিমাণ(loc), "%.200s:%lu", file, linenum);
		যদি (auth_check_principals_সাৰি(cp, cert, loc, authoptsp) == 0)
			found_principal = 1;
	}
	debug2_f("%s: processed %lu/%lu lines", file, nonblank, linenum);
	মুক্ত(সাৰি);
	ঘূৰাই found_principal;
}

/*
 * Check a single line of an authorized_keys-format file. Returns 0 if key
 * matches, -1 otherwise. Will return key/cert options via *authoptsp
 * on success. "loc" is used as file/line location in log messages.
 */
পূর্ণাঙ্ক
auth_check_authkey_সাৰি(সংরচনা passwd *pw, সংরচনা sshkey *চাবি,
    ৱর্ণ *cp, ধ্রুৱ ৱর্ণ *remote_ip, ধ্রুৱ ৱর্ণ *remote_host, ধ্রুৱ ৱর্ণ *loc,
    সংরচনা sshauthopt **authoptsp)
{
	পূর্ণাঙ্ক want_keytype = sshkey_is_cert(চাবি) ? চাবি_UNSPEC : চাবি->type;
	সংরচনা sshkey *found = রিক্ত;
	সংরচনা sshauthopt *keyopts = রিক্ত, *certopts = রিক্ত, *finalopts = রিক্ত;
	ৱর্ণ *চাবি_options = রিক্ত, *fp = রিক্ত;
	ধ্রুৱ ৱর্ণ *reason = রিক্ত;
	পূর্ণাঙ্ক ret = -1;

	যদি (authoptsp != রিক্ত)
		*authoptsp = রিক্ত;

	যদি ((found = sshkey_new(want_keytype)) == রিক্ত) {
		debug3_f("keytype %d failed", want_keytype);
		গচ্ছ out;
	}

	/* XXX djm: peek at key type in line and skip if unwanted */

	যদি (sshkey_read(found, &cp) != 0) {
		/* no key?  check for options */
		debug2("%s: check options: '%s'", loc, cp);
		চাবি_options = cp;
		যদি (sshkey_advance_past_options(&cp) != 0) {
			reason = "invalid key option string";
			গচ্ছ fail_reason;
		}
		skip_space(&cp);
		যদি (sshkey_read(found, &cp) != 0) {
			/* still no key?  advance to next line*/
			debug2("%s: advance: '%s'", loc, cp);
			গচ্ছ out;
		}
	}
	/* Parse key options now; we need to know if this is a CA key */
	যদি ((keyopts = sshauthopt_parse(চাবি_options, &reason)) == রিক্ত) {
		debug("%s: bad key options: %s", loc, reason);
		auth_debug_add("%s: bad key options: %s", loc, reason);
		গচ্ছ out;
	}
	/* Ignore keys that don't match or incorrectly marked as CAs */
	যদি (sshkey_is_cert(চাবি)) {
		/* Certificate; check signature key against CA */
		যদি (!sshkey_equal(found, চাবি->cert->signature_চাবি) ||
		    !keyopts->cert_authority)
			গচ্ছ out;
	} অন্যথা {
		/* Plain key: check it against key found in file */
		যদি (!sshkey_equal(found, চাবি) || keyopts->cert_authority)
			গচ্ছ out;
	}

	/* We have a candidate key, perform authorisation checks */
	যদি ((fp = sshkey_fingerprint(found,
	    SSH_FP_HASH_DEFAULT, SSH_FP_DEFAULT)) == রিক্ত)
		fatal_f("fingerprint failed");

	debug("%s: matching %s found: %s %s", loc,
	    sshkey_is_cert(চাবি) ? "CA" : "key", sshkey_type(found), fp);

	যদি (auth_authorise_keyopts(pw, keyopts,
	    sshkey_is_cert(চাবি), remote_ip, remote_host, loc) != 0) {
		reason = "Refused by key options";
		গচ্ছ fail_reason;
	}
	/* That's all we need for plain keys. */
	যদি (!sshkey_is_cert(চাবি)) {
		verbose("Accepted key %s %s found at %s",
		    sshkey_type(found), fp, loc);
		finalopts = keyopts;
		keyopts = রিক্ত;
		গচ্ছ success;
	}

	/*
	 * Additional authorisation for certificates.
	 */

	/* Parse and check options present in certificate */
	যদি ((certopts = sshauthopt_from_cert(চাবি)) == রিক্ত) {
		reason = "Invalid certificate options";
		গচ্ছ cert_fail_reason;
	}
	যদি (auth_authorise_keyopts(pw, certopts, 0,
	    remote_ip, remote_host, loc) != 0) {
		reason = "Refused by certificate options";
		গচ্ছ cert_fail_reason;
	}
	যদি ((finalopts = sshauthopt_merge(keyopts, certopts, &reason)) == রিক্ত)
		গচ্ছ cert_fail_reason;

	/*
	 * If the user has specified a list of principals as
	 * a key option, then prefer that list to matching
	 * their username in the certificate principals list.
	 */
	যদি (keyopts->cert_principals != রিক্ত &&
	    !match_principals_option(keyopts->cert_principals, চাবি->cert)) {
		reason = "Certificate does not contain an authorized principal";
		গচ্ছ cert_fail_reason;
	}
	যদি (sshkey_cert_check_authority_now(চাবি, 0, 0,
	    keyopts->cert_principals == রিক্ত ? pw->pw_name : রিক্ত,
	    &reason) != 0)
		গচ্ছ cert_fail_reason;

	verbose("Accepted certificate ID \"%s\" (serial %llu) "
	    "signed by CA %s %s found at %s",
	    চাবি->cert->চাবি_id,
	    (unsigned long long)চাবি->cert->serial,
	    sshkey_type(found), fp, loc);

 success:
	যদি (finalopts == রিক্ত)
		fatal_f("internal error: missing options");
	যদি (authoptsp != রিক্ত) {
		*authoptsp = finalopts;
		finalopts = রিক্ত;
	}
	/* success */
	ret = 0;
	গচ্ছ out;

 cert_fail_reason:
	error("Refusing certificate ID \"%s\" serial=%llu "
	    "signed by %s CA %s via %s: %s", চাবি->cert->চাবি_id,
	    (unsigned long long)চাবি->cert->serial,
	    sshkey_type(চাবি->cert->signature_চাবি), fp, loc, reason);
	auth_debug_add("Refused Certificate ID \"%s\" serial=%llu: %s",
	    চাবি->cert->চাবি_id, (unsigned long long)চাবি->cert->serial, reason);
	গচ্ছ out;

 fail_reason:
	error("%s at %s", reason, loc);
	auth_debug_add("%s", reason);
 out:
	মুক্ত(fp);
	sshauthopt_free(keyopts);
	sshauthopt_free(certopts);
	sshauthopt_free(finalopts);
	sshkey_free(found);
	ঘূৰাই ret;
}

/*
 * Checks whether key is allowed in authorized_keys-format file,
 * returns 1 if the key is allowed or 0 otherwise.
 */
পূর্ণাঙ্ক
auth_check_authkeys_file(সংরচনা passwd *pw, FILE *f, ৱর্ণ *file,
    সংরচনা sshkey *চাবি, ধ্রুৱ ৱর্ণ *remote_ip,
    ধ্রুৱ ৱর্ণ *remote_host, সংরচনা sshauthopt **authoptsp)
{
	ৱর্ণ *cp, *সাৰি = রিক্ত, loc[256];
	size_t linesize = 0;
	পূর্ণাঙ্ক found_চাবি = 0;
	u_long linenum = 0, nonblank = 0;

	যদি (authoptsp != রিক্ত)
		*authoptsp = রিক্ত;

	যেতিয়ালৈ (getline(&সাৰি, &linesize, f) != -1) {
		linenum++;
		/* Always consume entire file */
		যদি (found_চাবি)
			অনুৱর্ত;

		/* Skip leading whitespace, empty and comment lines. */
		cp = সাৰি;
		skip_space(&cp);
		যদি (!*cp || *cp == '\n' || *cp == '#')
			অনুৱর্ত;

		nonblank++;
		snprintf(loc, পরিমাণ(loc), "%.200s:%lu", file, linenum);
		যদি (auth_check_authkey_সাৰি(pw, চাবি, cp,
		    remote_ip, remote_host, loc, authoptsp) == 0)
			found_চাবি = 1;
	}
	মুক্ত(সাৰি);
	debug2_f("%s: processed %lu/%lu lines", file, nonblank, linenum);
	ঘূৰাই found_চাবি;
}

স্থির FILE *
auth_openfile(ধ্রুৱ ৱর্ণ *file, সংরচনা passwd *pw, পূর্ণাঙ্ক strict_modes,
    পূর্ণাঙ্ক log_missing, ৱর্ণ *file_type)
{
	ৱর্ণ সাৰি[1024];
	সংরচনা stat st;
	পূর্ণাঙ্ক fd;
	FILE *f;

	যদি ((fd = open(file, O_RDONLY|O_NONBLOCK)) == -1) {
		যদি (errno != ENOENT) {
			logit("Could not open user '%s' %s '%s': %s",
			    pw->pw_name, file_type, file, strerror(errno));
		} অন্যথা যদি (log_missing) {
			debug("Could not open user '%s' %s '%s': %s",
			    pw->pw_name, file_type, file, strerror(errno));
		}
		ঘূৰাই রিক্ত;
	}

	যদি (fstat(fd, &st) == -1) {
		close(fd);
		ঘূৰাই রিক্ত;
	}
	যদি (!S_ISREG(st.st_mode)) {
		logit("User '%s' %s '%s' is not a regular file",
		    pw->pw_name, file_type, file);
		close(fd);
		ঘূৰাই রিক্ত;
	}
	unset_nonblock(fd);
	যদি ((f = fdopen(fd, "r")) == রিক্ত) {
		close(fd);
		ঘূৰাই রিক্ত;
	}
	যদি (strict_modes &&
	    safe_path_fd(fileno(f), file, pw, সাৰি, পরিমাণ(সাৰি)) != 0) {
		fclose(f);
		logit("Authentication refused: %s", সাৰি);
		auth_debug_add("Ignored %s: %s", file_type, সাৰি);
		ঘূৰাই রিক্ত;
	}

	ঘূৰাই f;
}


FILE *
auth_openkeyfile(ধ্রুৱ ৱর্ণ *file, সংরচনা passwd *pw, পূর্ণাঙ্ক strict_modes)
{
	ঘূৰাই auth_openfile(file, pw, strict_modes, 1, "authorized keys");
}

FILE *
auth_openprincipals(ধ্রুৱ ৱর্ণ *file, সংরচনা passwd *pw, পূর্ণাঙ্ক strict_modes)
{
	ঘূৰাই auth_openfile(file, pw, strict_modes, 0,
	    "authorized principals");
}

