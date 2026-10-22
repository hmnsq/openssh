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

ಪೂರ್ಣಾಂಕ
auth_authorise_keyopts(ರಚನೆ passwd *pw, ರಚನೆ sshauthopt *opts,
    ಪೂರ್ಣಾಂಕ allow_cert_authority, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *remote_ip, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *remote_host,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *loc)
{
	time_t now = time(ಖಾಲಿ);
	ಅಕ್ಷರ buf[64];

	/*
	 * Check keys/principals file expiry time.
	 * NB. validity interval in certificate is handled elsewhere.
	 */
	ಆದರೆ (opts->valid_before && now > 0 &&
	    opts->valid_before < (uint64_t)now) {
		format_absolute_ಸಮಯ(opts->valid_before, buf, ಗಾತ್ರ(buf));
		debug("%s: entry expired at %s", loc, buf);
		auth_debug_ಕೂಡಿಸು("%s: entry expired at %s", loc, buf);
		ಹಿಂತಿರುಗಿ -1;
	}
	/* Consistency checks */
	ಆದರೆ (opts->cert_principals != ಖಾಲಿ && !opts->cert_authority) {
		debug("%s: principals on non-CA key", loc);
		auth_debug_ಕೂಡಿಸು("%s: principals on non-CA key", loc);
		/* deny access */
		ಹಿಂತಿರುಗಿ -1;
	}
	/* cert-authority flag isn't valid in authorized_principals files */
	ಆದರೆ (!allow_cert_authority && opts->cert_authority) {
		debug("%s: cert-authority flag invalid here", loc);
		auth_debug_ಕೂಡಿಸು("%s: cert-authority flag invalid here", loc);
		/* deny access */
		ಹಿಂತಿರುಗಿ -1;
	}

	/* Perform from= checks */
	ಆದರೆ (opts->required_from_host_ಕೀಲಿಗಳು != ಖಾಲಿ) {
		ಆಯ್ಕೆ (ಹೊಂದಿಕೆ_host_and_ip(remote_host, remote_ip,
		    opts->required_from_host_ಕೀಲಿಗಳು )) {
		ಸ್ಥಿತಿ 1:
			/* Host name matches. */
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ -1:
		ಪೂರ್ವನಿಯೋಜಿತ:
			debug("%s: invalid from criteria", loc);
			auth_debug_ಕೂಡಿಸು("%s: invalid from criteria", loc);
			/* FALLTHROUGH */
		ಸ್ಥಿತಿ 0:
			logit("%s: Authentication tried for %.100s with "
			    "correct key but not from a permitted "
			    "host (host=%.200s, ip=%.200s, required=%.200s).",
			    loc, pw->pw_name, remote_host, remote_ip,
			    opts->required_from_host_ಕೀಲಿಗಳು);
			auth_debug_ಕೂಡಿಸು("%s: Your host '%.200s' is not "
			    "permitted to use this key for login.",
			    loc, remote_host);
			/* deny access */
			ಹಿಂತಿರುಗಿ -1;
		}
	}
	/* Check source-address restriction from certificate */
	ಆದರೆ (opts->required_from_host_cert != ಖಾಲಿ) {
		ಆಯ್ಕೆ (addr_ಹೊಂದಿಕೆ_cidr_list(remote_ip,
		    opts->required_from_host_cert)) {
		ಸ್ಥಿತಿ 1:
			/* accepted */
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ -1:
		ಪೂರ್ವನಿಯೋಜಿತ:
			/* invalid */
			error("%s: Certificate source-address invalid", loc);
			/* FALLTHROUGH */
		ಸ್ಥಿತಿ 0:
			logit("%s: Authentication tried for %.100s with valid "
			    "certificate but not from a permitted source "
			    "address (%.200s).", loc, pw->pw_name, remote_ip);
			auth_debug_ಕೂಡಿಸು("%s: Your address '%.200s' is not "
			    "permitted to use this certificate for login.",
			    loc, remote_ip);
			ಹಿಂತಿರುಗಿ -1;
		}
	}
	/*
	 *
	 * XXX this is spammy. We should report remotely only for keys
	 *     that are successful in actual auth attempts, and not PK_OK
	 *     tests.
	 */
	auth_log_authopts(loc, opts, 1);

	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ಹೊಂದಿಕೆ_principals_option(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *principal_list, ರಚನೆ sshkey_cert *cert)
{
	ಅಕ್ಷರ *list, *olist, *ನಮೂದು;
	u_int i;

	olist = list = xstrdup(principal_list);
	ಗಾಗಿ (;;) {
		ಆದರೆ ((ನಮೂದು = strsep(&list, ",")) == ಖಾಲಿ || *ನಮೂದು == '\0')
			ನಿಲ್ಲಿಸು;
		ಗಾಗಿ (i = 0; i < cert->nprincipals; i++) {
			ಆದರೆ (strcmp(ನಮೂದು, cert->principals[i]) == 0) {
				debug3("matched principal from key i"
				    "options \"%.100s\"", ನಮೂದು);
				ಬಿಡುಗಡೆ(olist);
				ಹಿಂತಿರುಗಿ 1;
			}
		}
	}
	ಬಿಡುಗಡೆ(olist);
	ಹಿಂತಿರುಗಿ 0;
}

/*
 * Process a single authorized_principals format line. Returns 0 and sets
 * authoptsp is principal is authorised, -1 otherwise. "loc" is used as a
 * log preamble for file/line information.
 */
ಪೂರ್ಣಾಂಕ
auth_check_principals_ಸಾಲು(ಅಕ್ಷರ *cp, ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey_cert *cert,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *loc, ರಚನೆ sshauthopt **authoptsp)
{
	u_int i, ಸಿಕ್ಕಿತು = 0;
	ಅಕ್ಷರ *ep, *ಸಾಲು_opts;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *reason = ಖಾಲಿ;
	ರಚನೆ sshauthopt *opts = ಖಾಲಿ;

	ಆದರೆ (authoptsp != ಖಾಲಿ)
		*authoptsp = ಖಾಲಿ;

	/* Trim trailing whitespace. */
	ep = cp + ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(cp) - 1;
	ಆಗ (ep > cp && (*ep == '\n' || *ep == ' ' || *ep == '\t'))
		*ep-- = '\0';

	/*
	 * If the line has internal whitespace then assume it has
	 * key options.
	 */
	ಸಾಲು_opts = ಖಾಲಿ;
	ಆದರೆ ((ep = strrchr(cp, ' ')) != ಖಾಲಿ ||
	    (ep = strrchr(cp, '\t')) != ಖಾಲಿ) {
		ಗಾಗಿ (; *ep == ' ' || *ep == '\t'; ep++)
			;
		ಸಾಲು_opts = cp;
		cp = ep;
	}
	ಆದರೆ ((opts = sshauthopt_parse(ಸಾಲು_opts, &reason)) == ಖಾಲಿ) {
		debug("%s: bad principals options: %s", loc, reason);
		auth_debug_ಕೂಡಿಸು("%s: bad principals options: %s", loc, reason);
		ಹಿಂತಿರುಗಿ -1;
	}
	/* Check principals in cert against those on line */
	ಗಾಗಿ (i = 0; i < cert->nprincipals; i++) {
		ಆದರೆ (strcmp(cp, cert->principals[i]) != 0)
			ಮುಂದುವರಿ;
		debug3("%s: matched principal \"%.100s\"",
		    loc, cert->principals[i]);
		ಸಿಕ್ಕಿತು = 1;
	}
	ಆದರೆ (ಸಿಕ್ಕಿತು && authoptsp != ಖಾಲಿ) {
		*authoptsp = opts;
		opts = ಖಾಲಿ;
	}
	sshauthopt_free(opts);
	ಹಿಂತಿರುಗಿ ಸಿಕ್ಕಿತು ? 0 : -1;
}

ಪೂರ್ಣಾಂಕ
auth_process_principals(FILE *f, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *file,
    ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey_cert *cert, ರಚನೆ sshauthopt **authoptsp)
{
	ಅಕ್ಷರ loc[256], *ಸಾಲು = ಖಾಲಿ, *cp, *ep;
	ಗಾತ್ರ_t linesize = 0;
	u_long linenum = 0, nonblank = 0;
	u_int ಸಿಕ್ಕಿತು_principal = 0;

	ಆದರೆ (authoptsp != ಖಾಲಿ)
		*authoptsp = ಖಾಲಿ;

	ಆಗ (getline(&ಸಾಲು, &linesize, f) != -1) {
		linenum++;
		/* Always consume entire input */
		ಆದರೆ (ಸಿಕ್ಕಿತು_principal)
			ಮುಂದುವರಿ;

		/* Skip leading whitespace. */
		ಗಾಗಿ (cp = ಸಾಲು; *cp == ' ' || *cp == '\t'; cp++)
			;
		/* Skip blank and comment lines. */
		ಆದರೆ ((ep = strchr(cp, '#')) != ಖಾಲಿ)
			*ep = '\0';
		ಆದರೆ (!*cp || *cp == '\n')
			ಮುಂದುವರಿ;

		nonblank++;
		snprintf(loc, ಗಾತ್ರ(loc), "%.200s:%lu", file, linenum);
		ಆದರೆ (auth_check_principals_ಸಾಲು(cp, cert, loc, authoptsp) == 0)
			ಸಿಕ್ಕಿತು_principal = 1;
	}
	debug2_f("%s: processed %lu/%lu lines", file, nonblank, linenum);
	ಬಿಡುಗಡೆ(ಸಾಲು);
	ಹಿಂತಿರುಗಿ ಸಿಕ್ಕಿತು_principal;
}

/*
 * Check a single line of an authorized_keys-format file. Returns 0 if key
 * matches, -1 otherwise. Will return key/cert options via *authoptsp
 * on success. "loc" is used as file/line location in log messages.
 */
ಪೂರ್ಣಾಂಕ
auth_check_authkey_ಸಾಲು(ರಚನೆ passwd *pw, ರಚನೆ sshkey *ಕೀಲಿ,
    ಅಕ್ಷರ *cp, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *remote_ip, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *remote_host, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *loc,
    ರಚನೆ sshauthopt **authoptsp)
{
	ಪೂರ್ಣಾಂಕ want_keytype = sshkey_is_cert(ಕೀಲಿ) ? ಕೀಲಿ_UNSPEC : ಕೀಲಿ->type;
	ರಚನೆ sshkey *ಸಿಕ್ಕಿತು = ಖಾಲಿ;
	ರಚನೆ sshauthopt *keyopts = ಖಾಲಿ, *certopts = ಖಾಲಿ, *finalopts = ಖಾಲಿ;
	ಅಕ್ಷರ *ಕೀಲಿ_options = ಖಾಲಿ, *fp = ಖಾಲಿ;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *reason = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ ret = -1;

	ಆದರೆ (authoptsp != ಖಾಲಿ)
		*authoptsp = ಖಾಲಿ;

	ಆದರೆ ((ಸಿಕ್ಕಿತು = sshkey_new(want_keytype)) == ಖಾಲಿ) {
		debug3_f("keytype %d failed", want_keytype);
		ಹೋಗು ಹೊರಹೋಗು;
	}

	/* XXX djm: peek at key type in line and skip if unwanted */

	ಆದರೆ (sshkey_read(ಸಿಕ್ಕಿತು, &cp) != 0) {
		/* no key?  check for options */
		debug2("%s: check options: '%s'", loc, cp);
		ಕೀಲಿ_options = cp;
		ಆದರೆ (sshkey_advance_past_options(&cp) != 0) {
			reason = "invalid key option string";
			ಹೋಗು fail_reason;
		}
		skip_space(&cp);
		ಆದರೆ (sshkey_read(ಸಿಕ್ಕಿತು, &cp) != 0) {
			/* still no key?  advance to next line*/
			debug2("%s: advance: '%s'", loc, cp);
			ಹೋಗು ಹೊರಹೋಗು;
		}
	}
	/* Parse key options now; we need to know if this is a CA key */
	ಆದರೆ ((keyopts = sshauthopt_parse(ಕೀಲಿ_options, &reason)) == ಖಾಲಿ) {
		debug("%s: bad key options: %s", loc, reason);
		auth_debug_ಕೂಡಿಸು("%s: bad key options: %s", loc, reason);
		ಹೋಗು ಹೊರಹೋಗು;
	}
	/* Ignore keys that don't match or incorrectly marked as CAs */
	ಆದರೆ (sshkey_is_cert(ಕೀಲಿ)) {
		/* Certificate; check signature key against CA */
		ಆದರೆ (!sshkey_equal(ಸಿಕ್ಕಿತು, ಕೀಲಿ->cert->signature_ಕೀಲಿ) ||
		    !keyopts->cert_authority)
			ಹೋಗು ಹೊರಹೋಗು;
	} ಇಲ್ಲದಿದ್ದರೆ {
		/* Plain key: check it against key found in file */
		ಆದರೆ (!sshkey_equal(ಸಿಕ್ಕಿತು, ಕೀಲಿ) || keyopts->cert_authority)
			ಹೋಗು ಹೊರಹೋಗು;
	}

	/* We have a candidate key, perform authorisation checks */
	ಆದರೆ ((fp = sshkey_fingerprint(ಸಿಕ್ಕಿತು,
	    SSH_FP_HASH_DEFAULT, SSH_FP_DEFAULT)) == ಖಾಲಿ)
		fatal_f("fingerprint failed");

	debug("%s: matching %s found: %s %s", loc,
	    sshkey_is_cert(ಕೀಲಿ) ? "CA" : "key", sshkey_type(ಸಿಕ್ಕಿತು), fp);

	ಆದರೆ (auth_authorise_keyopts(pw, keyopts,
	    sshkey_is_cert(ಕೀಲಿ), remote_ip, remote_host, loc) != 0) {
		reason = "Refused by key options";
		ಹೋಗು fail_reason;
	}
	/* That's all we need for plain keys. */
	ಆದರೆ (!sshkey_is_cert(ಕೀಲಿ)) {
		verbose("Accepted key %s %s found at %s",
		    sshkey_type(ಸಿಕ್ಕಿತು), fp, loc);
		finalopts = keyopts;
		keyopts = ಖಾಲಿ;
		ಹೋಗು success;
	}

	/*
	 * Additional authorisation for certificates.
	 */

	/* Parse and check options present in certificate */
	ಆದರೆ ((certopts = sshauthopt_from_cert(ಕೀಲಿ)) == ಖಾಲಿ) {
		reason = "Invalid certificate options";
		ಹೋಗು cert_fail_reason;
	}
	ಆದರೆ (auth_authorise_keyopts(pw, certopts, 0,
	    remote_ip, remote_host, loc) != 0) {
		reason = "Refused by certificate options";
		ಹೋಗು cert_fail_reason;
	}
	ಆದರೆ ((finalopts = sshauthopt_ವಿಲೀನ(keyopts, certopts, &reason)) == ಖಾಲಿ)
		ಹೋಗು cert_fail_reason;

	/*
	 * If the user has specified a list of principals as
	 * a key option, then prefer that list to matching
	 * their username in the certificate principals list.
	 */
	ಆದರೆ (keyopts->cert_principals != ಖಾಲಿ &&
	    !ಹೊಂದಿಕೆ_principals_option(keyopts->cert_principals, ಕೀಲಿ->cert)) {
		reason = "Certificate does not contain an authorized principal";
		ಹೋಗು cert_fail_reason;
	}
	ಆದರೆ (sshkey_cert_check_authority_now(ಕೀಲಿ, 0, 0,
	    keyopts->cert_principals == ಖಾಲಿ ? pw->pw_name : ಖಾಲಿ,
	    &reason) != 0)
		ಹೋಗು cert_fail_reason;

	verbose("Accepted certificate ID \"%s\" (serial %llu) "
	    "signed by CA %s %s found at %s",
	    ಕೀಲಿ->cert->ಕೀಲಿ_id,
	    (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)ಕೀಲಿ->cert->serial,
	    sshkey_type(ಸಿಕ್ಕಿತು), fp, loc);

 success:
	ಆದರೆ (finalopts == ಖಾಲಿ)
		fatal_f("internal error: missing options");
	ಆದರೆ (authoptsp != ಖಾಲಿ) {
		*authoptsp = finalopts;
		finalopts = ಖಾಲಿ;
	}
	/* success */
	ret = 0;
	ಹೋಗು ಹೊರಹೋಗು;

 cert_fail_reason:
	error("Refusing certificate ID \"%s\" serial=%llu "
	    "signed by %s CA %s via %s: %s", ಕೀಲಿ->cert->ಕೀಲಿ_id,
	    (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)ಕೀಲಿ->cert->serial,
	    sshkey_type(ಕೀಲಿ->cert->signature_ಕೀಲಿ), fp, loc, reason);
	auth_debug_ಕೂಡಿಸು("Refused Certificate ID \"%s\" serial=%llu: %s",
	    ಕೀಲಿ->cert->ಕೀಲಿ_id, (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)ಕೀಲಿ->cert->serial, reason);
	ಹೋಗು ಹೊರಹೋಗು;

 fail_reason:
	error("%s at %s", reason, loc);
	auth_debug_ಕೂಡಿಸು("%s", reason);
 ಹೊರಹೋಗು:
	ಬಿಡುಗಡೆ(fp);
	sshauthopt_free(keyopts);
	sshauthopt_free(certopts);
	sshauthopt_free(finalopts);
	sshkey_free(ಸಿಕ್ಕಿತು);
	ಹಿಂತಿರುಗಿ ret;
}

/*
 * Checks whether key is allowed in authorized_keys-format file,
 * returns 1 if the key is allowed or 0 otherwise.
 */
ಪೂರ್ಣಾಂಕ
auth_check_authkeys_file(ರಚನೆ passwd *pw, FILE *f, ಅಕ್ಷರ *file,
    ರಚನೆ sshkey *ಕೀಲಿ, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *remote_ip,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *remote_host, ರಚನೆ sshauthopt **authoptsp)
{
	ಅಕ್ಷರ *cp, *ಸಾಲು = ಖಾಲಿ, loc[256];
	ಗಾತ್ರ_t linesize = 0;
	ಪೂರ್ಣಾಂಕ ಸಿಕ್ಕಿತು_ಕೀಲಿ = 0;
	u_long linenum = 0, nonblank = 0;

	ಆದರೆ (authoptsp != ಖಾಲಿ)
		*authoptsp = ಖಾಲಿ;

	ಆಗ (getline(&ಸಾಲು, &linesize, f) != -1) {
		linenum++;
		/* Always consume entire file */
		ಆದರೆ (ಸಿಕ್ಕಿತು_ಕೀಲಿ)
			ಮುಂದುವರಿ;

		/* Skip leading whitespace, empty and comment lines. */
		cp = ಸಾಲು;
		skip_space(&cp);
		ಆದರೆ (!*cp || *cp == '\n' || *cp == '#')
			ಮುಂದುವರಿ;

		nonblank++;
		snprintf(loc, ಗಾತ್ರ(loc), "%.200s:%lu", file, linenum);
		ಆದರೆ (auth_check_authkey_ಸಾಲು(pw, ಕೀಲಿ, cp,
		    remote_ip, remote_host, loc, authoptsp) == 0)
			ಸಿಕ್ಕಿತು_ಕೀಲಿ = 1;
	}
	ಬಿಡುಗಡೆ(ಸಾಲು);
	debug2_f("%s: processed %lu/%lu lines", file, nonblank, linenum);
	ಹಿಂತಿರುಗಿ ಸಿಕ್ಕಿತು_ಕೀಲಿ;
}

ಸ್ಥಿರ FILE *
auth_openfile(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *file, ರಚನೆ passwd *pw, ಪೂರ್ಣಾಂಕ strict_modes,
    ಪೂರ್ಣಾಂಕ log_missing, ಅಕ್ಷರ *file_type)
{
	ಅಕ್ಷರ ಸಾಲು[1024];
	ರಚನೆ stat st;
	ಪೂರ್ಣಾಂಕ fd;
	FILE *f;

	ಆದರೆ ((fd = open(file, O_RDONLY|O_NONBLOCK)) == -1) {
		ಆದರೆ (errno != ENOENT) {
			logit("Could not open user '%s' %s '%s': %s",
			    pw->pw_name, file_type, file, strerror(errno));
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (log_missing) {
			debug("Could not open user '%s' %s '%s': %s",
			    pw->pw_name, file_type, file, strerror(errno));
		}
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	}

	ಆದರೆ (fstat(fd, &st) == -1) {
		close(fd);
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	}
	ಆದರೆ (!S_ISREG(st.st_mode)) {
		logit("User '%s' %s '%s' is not a regular file",
		    pw->pw_name, file_type, file);
		close(fd);
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	}
	unset_nonblock(fd);
	ಆದರೆ ((f = fdopen(fd, "r")) == ಖಾಲಿ) {
		close(fd);
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	}
	ಆದರೆ (strict_modes &&
	    ಸುರಕ್ಷಿತ_ಮಾರ್ಗ_fd(fileno(f), file, pw, ಸಾಲು, ಗಾತ್ರ(ಸಾಲು)) != 0) {
		fclose(f);
		logit("Authentication refused: %s", ಸಾಲು);
		auth_debug_ಕೂಡಿಸು("Ignored %s: %s", file_type, ಸಾಲು);
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	}

	ಹಿಂತಿರುಗಿ f;
}


FILE *
auth_openkeyfile(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *file, ರಚನೆ passwd *pw, ಪೂರ್ಣಾಂಕ strict_modes)
{
	ಹಿಂತಿರುಗಿ auth_openfile(file, pw, strict_modes, 1, "authorized keys");
}

FILE *
auth_openprincipals(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *file, ರಚನೆ passwd *pw, ಪೂರ್ಣಾಂಕ strict_modes)
{
	ಹಿಂತಿರುಗಿ auth_openfile(file, pw, strict_modes, 0,
	    "authorized principals");
}

