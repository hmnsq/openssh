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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <sys/stat.h>

#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <fcntl.h>
#ಅನ್ತರ್ಭಾವ <pwd.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <time.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>

#ಅನ್ತರ್ಭಾವ "ssh.h"
#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "misc.h"
#ಅನ್ತರ್ಭಾವ "sshkey.h"
#ಅನ್ತರ್ಭಾವ "digest.h"
#ಅನ್ತರ್ಭಾವ "hostfile.h"
#ಅನ್ತರ್ಭಾವ "auth.h"
#ಅನ್ತರ್ಭಾವ "auth-options.h"
#ಅನ್ತರ್ಭಾವ "authfile.h"
#ಅನ್ತರ್ಭಾವ "match.h"
#ಅನ್ತರ್ಭಾವ "ssherr.h"
#ಅನ್ತರ್ಭಾವ "xmalloc.h"

ಪೂರ್ಣಾಙ್ಕ
auth_authorise_keyopts(ಸಂರಚನಾ passwd *pw, ಸಂರಚನಾ sshauthopt *opts,
    ಪೂರ್ಣಾಙ್ಕ allow_cert_authority, ಧ್ರುವ ವರ್ಣ *remote_ip, ಧ್ರುವ ವರ್ಣ *remote_host,
    ಧ್ರುವ ವರ್ಣ *loc)
{
	time_t now = time(ರಿಕ್ತ);
	ವರ್ಣ buf[64];

	/*
	 * Check keys/principals file expiry time.
	 * NB. validity interval in certificate is handled elsewhere.
	 */
	ಯದಿ (opts->valid_before && now > 0 &&
	    opts->valid_before < (uint64_t)now) {
		format_absolute_time(opts->valid_before, buf, ಪರಿಮಾಣ(buf));
		debug("%s: entry expired at %s", loc, buf);
		auth_debug_add("%s: entry expired at %s", loc, buf);
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	/* Consistency checks */
	ಯದಿ (opts->cert_principals != ರಿಕ್ತ && !opts->cert_authority) {
		debug("%s: principals on non-CA key", loc);
		auth_debug_add("%s: principals on non-CA key", loc);
		/* deny access */
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	/* cert-authority flag isn't valid in authorized_principals files */
	ಯದಿ (!allow_cert_authority && opts->cert_authority) {
		debug("%s: cert-authority flag invalid here", loc);
		auth_debug_add("%s: cert-authority flag invalid here", loc);
		/* deny access */
		ಪ್ರತ್ಯಾಗಮ -1;
	}

	/* Perform from= checks */
	ಯದಿ (opts->required_from_host_ಕೀಲಿಗಳು != ರಿಕ್ತ) {
		ವಿಕಲ್ಪ (match_host_and_ip(remote_host, remote_ip,
		    opts->required_from_host_ಕೀಲಿಗಳು )) {
		ಪಕ್ಷ 1:
			/* Host name matches. */
			ಭಙ್ಗ;
		ಪಕ್ಷ -1:
		ಸ್ವಭಾವ:
			debug("%s: invalid from criteria", loc);
			auth_debug_add("%s: invalid from criteria", loc);
			/* FALLTHROUGH */
		ಪಕ್ಷ 0:
			logit("%s: Authentication tried for %.100s with "
			    "correct key but not from a permitted "
			    "host (host=%.200s, ip=%.200s, required=%.200s).",
			    loc, pw->pw_name, remote_host, remote_ip,
			    opts->required_from_host_ಕೀಲಿಗಳು);
			auth_debug_add("%s: Your host '%.200s' is not "
			    "permitted to use this key for login.",
			    loc, remote_host);
			/* deny access */
			ಪ್ರತ್ಯಾಗಮ -1;
		}
	}
	/* Check source-address restriction from certificate */
	ಯದಿ (opts->required_from_host_cert != ರಿಕ್ತ) {
		ವಿಕಲ್ಪ (addr_match_cidr_list(remote_ip,
		    opts->required_from_host_cert)) {
		ಪಕ್ಷ 1:
			/* accepted */
			ಭಙ್ಗ;
		ಪಕ್ಷ -1:
		ಸ್ವಭಾವ:
			/* invalid */
			error("%s: Certificate source-address invalid", loc);
			/* FALLTHROUGH */
		ಪಕ್ಷ 0:
			logit("%s: Authentication tried for %.100s with valid "
			    "certificate but not from a permitted source "
			    "address (%.200s).", loc, pw->pw_name, remote_ip);
			auth_debug_add("%s: Your address '%.200s' is not "
			    "permitted to use this certificate for login.",
			    loc, remote_ip);
			ಪ್ರತ್ಯಾಗಮ -1;
		}
	}
	/*
	 *
	 * XXX this is spammy. We should report remotely only for keys
	 *     that are successful in actual auth attempts, and not PK_OK
	 *     tests.
	 */
	auth_log_authopts(loc, opts, 1);

	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
match_principals_option(ಧ್ರುವ ವರ್ಣ *principal_list, ಸಂರಚನಾ sshkey_cert *cert)
{
	ವರ್ಣ *list, *olist, *entry;
	u_int i;

	olist = list = xstrdup(principal_list);
	ಪ್ರತಿ (;;) {
		ಯದಿ ((entry = strsep(&list, ",")) == ರಿಕ್ತ || *entry == '\0')
			ಭಙ್ಗ;
		ಪ್ರತಿ (i = 0; i < cert->nprincipals; i++) {
			ಯದಿ (strcmp(entry, cert->principals[i]) == 0) {
				debug3("matched principal from key i"
				    "options \"%.100s\"", entry);
				ಮುಕ್ತ(olist);
				ಪ್ರತ್ಯಾಗಮ 1;
			}
		}
	}
	ಮುಕ್ತ(olist);
	ಪ್ರತ್ಯಾಗಮ 0;
}

/*
 * Process a single authorized_principals format line. Returns 0 and sets
 * authoptsp is principal is authorised, -1 otherwise. "loc" is used as a
 * log preamble for file/line information.
 */
ಪೂರ್ಣಾಙ್ಕ
auth_check_principals_ಸಾಲು(ವರ್ಣ *cp, ಧ್ರುವ ಸಂರಚನಾ sshkey_cert *cert,
    ಧ್ರುವ ವರ್ಣ *loc, ಸಂರಚನಾ sshauthopt **authoptsp)
{
	u_int i, found = 0;
	ವರ್ಣ *ep, *ಸಾಲು_opts;
	ಧ್ರುವ ವರ್ಣ *reason = ರಿಕ್ತ;
	ಸಂರಚನಾ sshauthopt *opts = ರಿಕ್ತ;

	ಯದಿ (authoptsp != ರಿಕ್ತ)
		*authoptsp = ರಿಕ್ತ;

	/* Trim trailing whitespace. */
	ep = cp + strlen(cp) - 1;
	ಯಾವತ್ (ep > cp && (*ep == '\n' || *ep == ' ' || *ep == '\t'))
		*ep-- = '\0';

	/*
	 * If the line has internal whitespace then assume it has
	 * key options.
	 */
	ಸಾಲು_opts = ರಿಕ್ತ;
	ಯದಿ ((ep = strrchr(cp, ' ')) != ರಿಕ್ತ ||
	    (ep = strrchr(cp, '\t')) != ರಿಕ್ತ) {
		ಪ್ರತಿ (; *ep == ' ' || *ep == '\t'; ep++)
			;
		ಸಾಲು_opts = cp;
		cp = ep;
	}
	ಯದಿ ((opts = sshauthopt_parse(ಸಾಲು_opts, &reason)) == ರಿಕ್ತ) {
		debug("%s: bad principals options: %s", loc, reason);
		auth_debug_add("%s: bad principals options: %s", loc, reason);
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	/* Check principals in cert against those on line */
	ಪ್ರತಿ (i = 0; i < cert->nprincipals; i++) {
		ಯದಿ (strcmp(cp, cert->principals[i]) != 0)
			ಅನುವರ್ತ;
		debug3("%s: matched principal \"%.100s\"",
		    loc, cert->principals[i]);
		found = 1;
	}
	ಯದಿ (found && authoptsp != ರಿಕ್ತ) {
		*authoptsp = opts;
		opts = ರಿಕ್ತ;
	}
	sshauthopt_free(opts);
	ಪ್ರತ್ಯಾಗಮ found ? 0 : -1;
}

ಪೂರ್ಣಾಙ್ಕ
auth_process_principals(FILE *f, ಧ್ರುವ ವರ್ಣ *file,
    ಧ್ರುವ ಸಂರಚನಾ sshkey_cert *cert, ಸಂರಚನಾ sshauthopt **authoptsp)
{
	ವರ್ಣ loc[256], *ಸಾಲು = ರಿಕ್ತ, *cp, *ep;
	size_t linesize = 0;
	u_long linenum = 0, nonblank = 0;
	u_int found_principal = 0;

	ಯದಿ (authoptsp != ರಿಕ್ತ)
		*authoptsp = ರಿಕ್ತ;

	ಯಾವತ್ (getline(&ಸಾಲು, &linesize, f) != -1) {
		linenum++;
		/* Always consume entire input */
		ಯದಿ (found_principal)
			ಅನುವರ್ತ;

		/* Skip leading whitespace. */
		ಪ್ರತಿ (cp = ಸಾಲು; *cp == ' ' || *cp == '\t'; cp++)
			;
		/* Skip blank and comment lines. */
		ಯದಿ ((ep = strchr(cp, '#')) != ರಿಕ್ತ)
			*ep = '\0';
		ಯದಿ (!*cp || *cp == '\n')
			ಅನುವರ್ತ;

		nonblank++;
		snprintf(loc, ಪರಿಮಾಣ(loc), "%.200s:%lu", file, linenum);
		ಯದಿ (auth_check_principals_ಸಾಲು(cp, cert, loc, authoptsp) == 0)
			found_principal = 1;
	}
	debug2_f("%s: processed %lu/%lu lines", file, nonblank, linenum);
	ಮುಕ್ತ(ಸಾಲು);
	ಪ್ರತ್ಯಾಗಮ found_principal;
}

/*
 * Check a single line of an authorized_keys-format file. Returns 0 if key
 * matches, -1 otherwise. Will return key/cert options via *authoptsp
 * on success. "loc" is used as file/line location in log messages.
 */
ಪೂರ್ಣಾಙ್ಕ
auth_check_authkey_ಸಾಲು(ಸಂರಚನಾ passwd *pw, ಸಂರಚನಾ sshkey *ಕೀಲಿ,
    ವರ್ಣ *cp, ಧ್ರುವ ವರ್ಣ *remote_ip, ಧ್ರುವ ವರ್ಣ *remote_host, ಧ್ರುವ ವರ್ಣ *loc,
    ಸಂರಚನಾ sshauthopt **authoptsp)
{
	ಪೂರ್ಣಾಙ್ಕ want_keytype = sshkey_is_cert(ಕೀಲಿ) ? ಕೀಲಿ_UNSPEC : ಕೀಲಿ->type;
	ಸಂರಚನಾ sshkey *found = ರಿಕ್ತ;
	ಸಂರಚನಾ sshauthopt *keyopts = ರಿಕ್ತ, *certopts = ರಿಕ್ತ, *finalopts = ರಿಕ್ತ;
	ವರ್ಣ *ಕೀಲಿ_options = ರಿಕ್ತ, *fp = ರಿಕ್ತ;
	ಧ್ರುವ ವರ್ಣ *reason = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ ret = -1;

	ಯದಿ (authoptsp != ರಿಕ್ತ)
		*authoptsp = ರಿಕ್ತ;

	ಯದಿ ((found = sshkey_new(want_keytype)) == ರಿಕ್ತ) {
		debug3_f("keytype %d failed", want_keytype);
		ಗಚ್ಛ out;
	}

	/* XXX djm: peek at key type in line and skip if unwanted */

	ಯದಿ (sshkey_read(found, &cp) != 0) {
		/* no key?  check for options */
		debug2("%s: check options: '%s'", loc, cp);
		ಕೀಲಿ_options = cp;
		ಯದಿ (sshkey_advance_past_options(&cp) != 0) {
			reason = "invalid key option string";
			ಗಚ್ಛ fail_reason;
		}
		skip_space(&cp);
		ಯದಿ (sshkey_read(found, &cp) != 0) {
			/* still no key?  advance to next line*/
			debug2("%s: advance: '%s'", loc, cp);
			ಗಚ್ಛ out;
		}
	}
	/* Parse key options now; we need to know if this is a CA key */
	ಯದಿ ((keyopts = sshauthopt_parse(ಕೀಲಿ_options, &reason)) == ರಿಕ್ತ) {
		debug("%s: bad key options: %s", loc, reason);
		auth_debug_add("%s: bad key options: %s", loc, reason);
		ಗಚ್ಛ out;
	}
	/* Ignore keys that don't match or incorrectly marked as CAs */
	ಯದಿ (sshkey_is_cert(ಕೀಲಿ)) {
		/* Certificate; check signature key against CA */
		ಯದಿ (!sshkey_equal(found, ಕೀಲಿ->cert->signature_ಕೀಲಿ) ||
		    !keyopts->cert_authority)
			ಗಚ್ಛ out;
	} ಅನ್ಯಥಾ {
		/* Plain key: check it against key found in file */
		ಯದಿ (!sshkey_equal(found, ಕೀಲಿ) || keyopts->cert_authority)
			ಗಚ್ಛ out;
	}

	/* We have a candidate key, perform authorisation checks */
	ಯದಿ ((fp = sshkey_fingerprint(found,
	    SSH_FP_HASH_DEFAULT, SSH_FP_DEFAULT)) == ರಿಕ್ತ)
		fatal_f("fingerprint failed");

	debug("%s: matching %s found: %s %s", loc,
	    sshkey_is_cert(ಕೀಲಿ) ? "CA" : "key", sshkey_type(found), fp);

	ಯದಿ (auth_authorise_keyopts(pw, keyopts,
	    sshkey_is_cert(ಕೀಲಿ), remote_ip, remote_host, loc) != 0) {
		reason = "Refused by key options";
		ಗಚ್ಛ fail_reason;
	}
	/* That's all we need for plain keys. */
	ಯದಿ (!sshkey_is_cert(ಕೀಲಿ)) {
		verbose("Accepted key %s %s found at %s",
		    sshkey_type(found), fp, loc);
		finalopts = keyopts;
		keyopts = ರಿಕ್ತ;
		ಗಚ್ಛ success;
	}

	/*
	 * Additional authorisation for certificates.
	 */

	/* Parse and check options present in certificate */
	ಯದಿ ((certopts = sshauthopt_from_cert(ಕೀಲಿ)) == ರಿಕ್ತ) {
		reason = "Invalid certificate options";
		ಗಚ್ಛ cert_fail_reason;
	}
	ಯದಿ (auth_authorise_keyopts(pw, certopts, 0,
	    remote_ip, remote_host, loc) != 0) {
		reason = "Refused by certificate options";
		ಗಚ್ಛ cert_fail_reason;
	}
	ಯದಿ ((finalopts = sshauthopt_merge(keyopts, certopts, &reason)) == ರಿಕ್ತ)
		ಗಚ್ಛ cert_fail_reason;

	/*
	 * If the user has specified a list of principals as
	 * a key option, then prefer that list to matching
	 * their username in the certificate principals list.
	 */
	ಯದಿ (keyopts->cert_principals != ರಿಕ್ತ &&
	    !match_principals_option(keyopts->cert_principals, ಕೀಲಿ->cert)) {
		reason = "Certificate does not contain an authorized principal";
		ಗಚ್ಛ cert_fail_reason;
	}
	ಯದಿ (sshkey_cert_check_authority_now(ಕೀಲಿ, 0, 0,
	    keyopts->cert_principals == ರಿಕ್ತ ? pw->pw_name : ರಿಕ್ತ,
	    &reason) != 0)
		ಗಚ್ಛ cert_fail_reason;

	verbose("Accepted certificate ID \"%s\" (serial %llu) "
	    "signed by CA %s %s found at %s",
	    ಕೀಲಿ->cert->ಕೀಲಿ_id,
	    (unsigned long long)ಕೀಲಿ->cert->serial,
	    sshkey_type(found), fp, loc);

 success:
	ಯದಿ (finalopts == ರಿಕ್ತ)
		fatal_f("internal error: missing options");
	ಯದಿ (authoptsp != ರಿಕ್ತ) {
		*authoptsp = finalopts;
		finalopts = ರಿಕ್ತ;
	}
	/* success */
	ret = 0;
	ಗಚ್ಛ out;

 cert_fail_reason:
	error("Refusing certificate ID \"%s\" serial=%llu "
	    "signed by %s CA %s via %s: %s", ಕೀಲಿ->cert->ಕೀಲಿ_id,
	    (unsigned long long)ಕೀಲಿ->cert->serial,
	    sshkey_type(ಕೀಲಿ->cert->signature_ಕೀಲಿ), fp, loc, reason);
	auth_debug_add("Refused Certificate ID \"%s\" serial=%llu: %s",
	    ಕೀಲಿ->cert->ಕೀಲಿ_id, (unsigned long long)ಕೀಲಿ->cert->serial, reason);
	ಗಚ್ಛ out;

 fail_reason:
	error("%s at %s", reason, loc);
	auth_debug_add("%s", reason);
 out:
	ಮುಕ್ತ(fp);
	sshauthopt_free(keyopts);
	sshauthopt_free(certopts);
	sshauthopt_free(finalopts);
	sshkey_free(found);
	ಪ್ರತ್ಯಾಗಮ ret;
}

/*
 * Checks whether key is allowed in authorized_keys-format file,
 * returns 1 if the key is allowed or 0 otherwise.
 */
ಪೂರ್ಣಾಙ್ಕ
auth_check_authkeys_file(ಸಂರಚನಾ passwd *pw, FILE *f, ವರ್ಣ *file,
    ಸಂರಚನಾ sshkey *ಕೀಲಿ, ಧ್ರುವ ವರ್ಣ *remote_ip,
    ಧ್ರುವ ವರ್ಣ *remote_host, ಸಂರಚನಾ sshauthopt **authoptsp)
{
	ವರ್ಣ *cp, *ಸಾಲು = ರಿಕ್ತ, loc[256];
	size_t linesize = 0;
	ಪೂರ್ಣಾಙ್ಕ found_ಕೀಲಿ = 0;
	u_long linenum = 0, nonblank = 0;

	ಯದಿ (authoptsp != ರಿಕ್ತ)
		*authoptsp = ರಿಕ್ತ;

	ಯಾವತ್ (getline(&ಸಾಲು, &linesize, f) != -1) {
		linenum++;
		/* Always consume entire file */
		ಯದಿ (found_ಕೀಲಿ)
			ಅನುವರ್ತ;

		/* Skip leading whitespace, empty and comment lines. */
		cp = ಸಾಲು;
		skip_space(&cp);
		ಯದಿ (!*cp || *cp == '\n' || *cp == '#')
			ಅನುವರ್ತ;

		nonblank++;
		snprintf(loc, ಪರಿಮಾಣ(loc), "%.200s:%lu", file, linenum);
		ಯದಿ (auth_check_authkey_ಸಾಲು(pw, ಕೀಲಿ, cp,
		    remote_ip, remote_host, loc, authoptsp) == 0)
			found_ಕೀಲಿ = 1;
	}
	ಮುಕ್ತ(ಸಾಲು);
	debug2_f("%s: processed %lu/%lu lines", file, nonblank, linenum);
	ಪ್ರತ್ಯಾಗಮ found_ಕೀಲಿ;
}

ಸ್ಥಿರ FILE *
auth_openfile(ಧ್ರುವ ವರ್ಣ *file, ಸಂರಚನಾ passwd *pw, ಪೂರ್ಣಾಙ್ಕ strict_modes,
    ಪೂರ್ಣಾಙ್ಕ log_missing, ವರ್ಣ *file_type)
{
	ವರ್ಣ ಸಾಲು[1024];
	ಸಂರಚನಾ stat st;
	ಪೂರ್ಣಾಙ್ಕ fd;
	FILE *f;

	ಯದಿ ((fd = open(file, O_RDONLY|O_NONBLOCK)) == -1) {
		ಯದಿ (errno != ENOENT) {
			logit("Could not open user '%s' %s '%s': %s",
			    pw->pw_name, file_type, file, strerror(errno));
		} ಅನ್ಯಥಾ ಯದಿ (log_missing) {
			debug("Could not open user '%s' %s '%s': %s",
			    pw->pw_name, file_type, file, strerror(errno));
		}
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	}

	ಯದಿ (fstat(fd, &st) == -1) {
		close(fd);
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	}
	ಯದಿ (!S_ISREG(st.st_mode)) {
		logit("User '%s' %s '%s' is not a regular file",
		    pw->pw_name, file_type, file);
		close(fd);
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	}
	unset_nonblock(fd);
	ಯದಿ ((f = fdopen(fd, "r")) == ರಿಕ್ತ) {
		close(fd);
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	}
	ಯದಿ (strict_modes &&
	    safe_path_fd(fileno(f), file, pw, ಸಾಲು, ಪರಿಮಾಣ(ಸಾಲು)) != 0) {
		fclose(f);
		logit("Authentication refused: %s", ಸಾಲು);
		auth_debug_add("Ignored %s: %s", file_type, ಸಾಲು);
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	}

	ಪ್ರತ್ಯಾಗಮ f;
}


FILE *
auth_openkeyfile(ಧ್ರುವ ವರ್ಣ *file, ಸಂರಚನಾ passwd *pw, ಪೂರ್ಣಾಙ್ಕ strict_modes)
{
	ಪ್ರತ್ಯಾಗಮ auth_openfile(file, pw, strict_modes, 1, "authorized keys");
}

FILE *
auth_openprincipals(ಧ್ರುವ ವರ್ಣ *file, ಸಂರಚನಾ passwd *pw, ಪೂರ್ಣಾಙ್ಕ strict_modes)
{
	ಪ್ರತ್ಯಾಗಮ auth_openfile(file, pw, strict_modes, 0,
	    "authorized principals");
}

