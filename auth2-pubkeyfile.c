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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/stat.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <errno.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <fcntl.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <pwd.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <time.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "ssh.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "misc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshkey.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "digest.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "hostfile.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "auth.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "auth-options.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "authfile.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "match.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssherr.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "xmalloc.h"

ਪੂਰਨ
auth_authorise_keyopts(ਬਣਤਰ passwd *pw, ਬਣਤਰ sshauthopt *opts,
    ਪੂਰਨ allow_cert_authority, ਅਚਲ ਅੱਖਰ *remote_ip, ਅਚਲ ਅੱਖਰ *remote_host,
    ਅਚਲ ਅੱਖਰ *loc)
{
	time_t now = time(ਨਿਰਾ);
	ਅੱਖਰ buf[64];

	/*
	 * Check keys/principals file expiry time.
	 * NB. validity interval in certificate is handled elsewhere.
	 */
	ਜੇ (opts->valid_before && now > 0 &&
	    opts->valid_before < (uint64_t)now) {
		format_absolute_ਸਮਾਂ(opts->valid_before, buf, ਆਕਾਰ(buf));
		debug("%s: entry expired at %s", loc, buf);
		auth_debug_ਜੋੜੋ("%s: entry expired at %s", loc, buf);
		ਵਾਪਸ -1;
	}
	/* Consistency checks */
	ਜੇ (opts->cert_principals != ਨਿਰਾ && !opts->cert_authority) {
		debug("%s: principals on non-CA key", loc);
		auth_debug_ਜੋੜੋ("%s: principals on non-CA key", loc);
		/* deny access */
		ਵਾਪਸ -1;
	}
	/* cert-authority flag isn't valid in authorized_principals files */
	ਜੇ (!allow_cert_authority && opts->cert_authority) {
		debug("%s: cert-authority flag invalid here", loc);
		auth_debug_ਜੋੜੋ("%s: cert-authority flag invalid here", loc);
		/* deny access */
		ਵਾਪਸ -1;
	}

	/* Perform from= checks */
	ਜੇ (opts->required_from_host_ਕੁੰਜੀਆਂ != ਨਿਰਾ) {
		ਚੋਣ (ਮੇਲ_host_and_ip(remote_host, remote_ip,
		    opts->required_from_host_ਕੁੰਜੀਆਂ )) {
		ਹਾਲਤ 1:
			/* Host name matches. */
			ਰੋਕੋ;
		ਹਾਲਤ -1:
		ਮੂਲ:
			debug("%s: invalid from criteria", loc);
			auth_debug_ਜੋੜੋ("%s: invalid from criteria", loc);
			/* FALLTHROUGH */
		ਹਾਲਤ 0:
			logit("%s: Authentication tried for %.100s with "
			    "correct key but not from a permitted "
			    "host (host=%.200s, ip=%.200s, required=%.200s).",
			    loc, pw->pw_name, remote_host, remote_ip,
			    opts->required_from_host_ਕੁੰਜੀਆਂ);
			auth_debug_ਜੋੜੋ("%s: Your host '%.200s' is not "
			    "permitted to use this key for login.",
			    loc, remote_host);
			/* deny access */
			ਵਾਪਸ -1;
		}
	}
	/* Check source-address restriction from certificate */
	ਜੇ (opts->required_from_host_cert != ਨਿਰਾ) {
		ਚੋਣ (addr_ਮੇਲ_cidr_list(remote_ip,
		    opts->required_from_host_cert)) {
		ਹਾਲਤ 1:
			/* accepted */
			ਰੋਕੋ;
		ਹਾਲਤ -1:
		ਮੂਲ:
			/* invalid */
			error("%s: Certificate source-address invalid", loc);
			/* FALLTHROUGH */
		ਹਾਲਤ 0:
			logit("%s: Authentication tried for %.100s with valid "
			    "certificate but not from a permitted source "
			    "address (%.200s).", loc, pw->pw_name, remote_ip);
			auth_debug_ਜੋੜੋ("%s: Your address '%.200s' is not "
			    "permitted to use this certificate for login.",
			    loc, remote_ip);
			ਵਾਪਸ -1;
		}
	}
	/*
	 *
	 * XXX this is spammy. We should report remotely only for keys
	 *     that are successful in actual auth attempts, and not PK_OK
	 *     tests.
	 */
	auth_log_authopts(loc, opts, 1);

	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
ਮੇਲ_principals_option(ਅਚਲ ਅੱਖਰ *principal_list, ਬਣਤਰ sshkey_cert *cert)
{
	ਅੱਖਰ *list, *olist, *ਇੰਦਰਾਜ;
	u_int i;

	olist = list = xstrdup(principal_list);
	ਲਈ (;;) {
		ਜੇ ((ਇੰਦਰਾਜ = strsep(&list, ",")) == ਨਿਰਾ || *ਇੰਦਰਾਜ == '\0')
			ਰੋਕੋ;
		ਲਈ (i = 0; i < cert->nprincipals; i++) {
			ਜੇ (strcmp(ਇੰਦਰਾਜ, cert->principals[i]) == 0) {
				debug3("matched principal from key i"
				    "options \"%.100s\"", ਇੰਦਰਾਜ);
				ਮੁਕਤ(olist);
				ਵਾਪਸ 1;
			}
		}
	}
	ਮੁਕਤ(olist);
	ਵਾਪਸ 0;
}

/*
 * Process a single authorized_principals format line. Returns 0 and sets
 * authoptsp is principal is authorised, -1 otherwise. "loc" is used as a
 * log preamble for file/line information.
 */
ਪੂਰਨ
auth_check_principals_ਸਤਰ(ਅੱਖਰ *cp, ਅਚਲ ਬਣਤਰ sshkey_cert *cert,
    ਅਚਲ ਅੱਖਰ *loc, ਬਣਤਰ sshauthopt **authoptsp)
{
	u_int i, ਮਿਲਿਆ = 0;
	ਅੱਖਰ *ep, *ਸਤਰ_opts;
	ਅਚਲ ਅੱਖਰ *reason = ਨਿਰਾ;
	ਬਣਤਰ sshauthopt *opts = ਨਿਰਾ;

	ਜੇ (authoptsp != ਨਿਰਾ)
		*authoptsp = ਨਿਰਾ;

	/* Trim trailing whitespace. */
	ep = cp + ਲੜੀ_ਲੰਬਾਈ(cp) - 1;
	ਜਦੋਂ (ep > cp && (*ep == '\n' || *ep == ' ' || *ep == '\t'))
		*ep-- = '\0';

	/*
	 * If the line has internal whitespace then assume it has
	 * key options.
	 */
	ਸਤਰ_opts = ਨਿਰਾ;
	ਜੇ ((ep = strrchr(cp, ' ')) != ਨਿਰਾ ||
	    (ep = strrchr(cp, '\t')) != ਨਿਰਾ) {
		ਲਈ (; *ep == ' ' || *ep == '\t'; ep++)
			;
		ਸਤਰ_opts = cp;
		cp = ep;
	}
	ਜੇ ((opts = sshauthopt_parse(ਸਤਰ_opts, &reason)) == ਨਿਰਾ) {
		debug("%s: bad principals options: %s", loc, reason);
		auth_debug_ਜੋੜੋ("%s: bad principals options: %s", loc, reason);
		ਵਾਪਸ -1;
	}
	/* Check principals in cert against those on line */
	ਲਈ (i = 0; i < cert->nprincipals; i++) {
		ਜੇ (strcmp(cp, cert->principals[i]) != 0)
			ਜਾਰੀ;
		debug3("%s: matched principal \"%.100s\"",
		    loc, cert->principals[i]);
		ਮਿਲਿਆ = 1;
	}
	ਜੇ (ਮਿਲਿਆ && authoptsp != ਨਿਰਾ) {
		*authoptsp = opts;
		opts = ਨਿਰਾ;
	}
	sshauthopt_free(opts);
	ਵਾਪਸ ਮਿਲਿਆ ? 0 : -1;
}

ਪੂਰਨ
auth_process_principals(FILE *f, ਅਚਲ ਅੱਖਰ *file,
    ਅਚਲ ਬਣਤਰ sshkey_cert *cert, ਬਣਤਰ sshauthopt **authoptsp)
{
	ਅੱਖਰ loc[256], *ਸਤਰ = ਨਿਰਾ, *cp, *ep;
	ਮਾਪ_t linesize = 0;
	u_long linenum = 0, nonblank = 0;
	u_int ਮਿਲਿਆ_principal = 0;

	ਜੇ (authoptsp != ਨਿਰਾ)
		*authoptsp = ਨਿਰਾ;

	ਜਦੋਂ (getline(&ਸਤਰ, &linesize, f) != -1) {
		linenum++;
		/* Always consume entire input */
		ਜੇ (ਮਿਲਿਆ_principal)
			ਜਾਰੀ;

		/* Skip leading whitespace. */
		ਲਈ (cp = ਸਤਰ; *cp == ' ' || *cp == '\t'; cp++)
			;
		/* Skip blank and comment lines. */
		ਜੇ ((ep = strchr(cp, '#')) != ਨਿਰਾ)
			*ep = '\0';
		ਜੇ (!*cp || *cp == '\n')
			ਜਾਰੀ;

		nonblank++;
		snprintf(loc, ਆਕਾਰ(loc), "%.200s:%lu", file, linenum);
		ਜੇ (auth_check_principals_ਸਤਰ(cp, cert, loc, authoptsp) == 0)
			ਮਿਲਿਆ_principal = 1;
	}
	debug2_f("%s: processed %lu/%lu lines", file, nonblank, linenum);
	ਮੁਕਤ(ਸਤਰ);
	ਵਾਪਸ ਮਿਲਿਆ_principal;
}

/*
 * Check a single line of an authorized_keys-format file. Returns 0 if key
 * matches, -1 otherwise. Will return key/cert options via *authoptsp
 * on success. "loc" is used as file/line location in log messages.
 */
ਪੂਰਨ
auth_check_authkey_ਸਤਰ(ਬਣਤਰ passwd *pw, ਬਣਤਰ sshkey *ਕੁੰਜੀ,
    ਅੱਖਰ *cp, ਅਚਲ ਅੱਖਰ *remote_ip, ਅਚਲ ਅੱਖਰ *remote_host, ਅਚਲ ਅੱਖਰ *loc,
    ਬਣਤਰ sshauthopt **authoptsp)
{
	ਪੂਰਨ want_keytype = sshkey_is_cert(ਕੁੰਜੀ) ? ਕੁੰਜੀ_UNSPEC : ਕੁੰਜੀ->type;
	ਬਣਤਰ sshkey *ਮਿਲਿਆ = ਨਿਰਾ;
	ਬਣਤਰ sshauthopt *keyopts = ਨਿਰਾ, *certopts = ਨਿਰਾ, *finalopts = ਨਿਰਾ;
	ਅੱਖਰ *ਕੁੰਜੀ_options = ਨਿਰਾ, *fp = ਨਿਰਾ;
	ਅਚਲ ਅੱਖਰ *reason = ਨਿਰਾ;
	ਪੂਰਨ ret = -1;

	ਜੇ (authoptsp != ਨਿਰਾ)
		*authoptsp = ਨਿਰਾ;

	ਜੇ ((ਮਿਲਿਆ = sshkey_new(want_keytype)) == ਨਿਰਾ) {
		debug3_f("keytype %d failed", want_keytype);
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	/* XXX djm: peek at key type in line and skip if unwanted */

	ਜੇ (sshkey_read(ਮਿਲਿਆ, &cp) != 0) {
		/* no key?  check for options */
		debug2("%s: check options: '%s'", loc, cp);
		ਕੁੰਜੀ_options = cp;
		ਜੇ (sshkey_advance_past_options(&cp) != 0) {
			reason = "invalid key option string";
			ਜਾਓ fail_reason;
		}
		skip_space(&cp);
		ਜੇ (sshkey_read(ਮਿਲਿਆ, &cp) != 0) {
			/* still no key?  advance to next line*/
			debug2("%s: advance: '%s'", loc, cp);
			ਜਾਓ ਬਾਹਰਲਾ;
		}
	}
	/* Parse key options now; we need to know if this is a CA key */
	ਜੇ ((keyopts = sshauthopt_parse(ਕੁੰਜੀ_options, &reason)) == ਨਿਰਾ) {
		debug("%s: bad key options: %s", loc, reason);
		auth_debug_ਜੋੜੋ("%s: bad key options: %s", loc, reason);
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	/* Ignore keys that don't match or incorrectly marked as CAs */
	ਜੇ (sshkey_is_cert(ਕੁੰਜੀ)) {
		/* Certificate; check signature key against CA */
		ਜੇ (!sshkey_equal(ਮਿਲਿਆ, ਕੁੰਜੀ->cert->signature_ਕੁੰਜੀ) ||
		    !keyopts->cert_authority)
			ਜਾਓ ਬਾਹਰਲਾ;
	} ਨਹੀਂਤਾਂ {
		/* Plain key: check it against key found in file */
		ਜੇ (!sshkey_equal(ਮਿਲਿਆ, ਕੁੰਜੀ) || keyopts->cert_authority)
			ਜਾਓ ਬਾਹਰਲਾ;
	}

	/* We have a candidate key, perform authorisation checks */
	ਜੇ ((fp = sshkey_fingerprint(ਮਿਲਿਆ,
	    SSH_FP_HASH_DEFAULT, SSH_FP_DEFAULT)) == ਨਿਰਾ)
		fatal_f("fingerprint failed");

	debug("%s: matching %s found: %s %s", loc,
	    sshkey_is_cert(ਕੁੰਜੀ) ? "CA" : "key", sshkey_type(ਮਿਲਿਆ), fp);

	ਜੇ (auth_authorise_keyopts(pw, keyopts,
	    sshkey_is_cert(ਕੁੰਜੀ), remote_ip, remote_host, loc) != 0) {
		reason = "Refused by key options";
		ਜਾਓ fail_reason;
	}
	/* That's all we need for plain keys. */
	ਜੇ (!sshkey_is_cert(ਕੁੰਜੀ)) {
		verbose("Accepted key %s %s found at %s",
		    sshkey_type(ਮਿਲਿਆ), fp, loc);
		finalopts = keyopts;
		keyopts = ਨਿਰਾ;
		ਜਾਓ success;
	}

	/*
	 * Additional authorisation for certificates.
	 */

	/* Parse and check options present in certificate */
	ਜੇ ((certopts = sshauthopt_from_cert(ਕੁੰਜੀ)) == ਨਿਰਾ) {
		reason = "Invalid certificate options";
		ਜਾਓ cert_fail_reason;
	}
	ਜੇ (auth_authorise_keyopts(pw, certopts, 0,
	    remote_ip, remote_host, loc) != 0) {
		reason = "Refused by certificate options";
		ਜਾਓ cert_fail_reason;
	}
	ਜੇ ((finalopts = sshauthopt_ਮਿਲਾਓ(keyopts, certopts, &reason)) == ਨਿਰਾ)
		ਜਾਓ cert_fail_reason;

	/*
	 * If the user has specified a list of principals as
	 * a key option, then prefer that list to matching
	 * their username in the certificate principals list.
	 */
	ਜੇ (keyopts->cert_principals != ਨਿਰਾ &&
	    !ਮੇਲ_principals_option(keyopts->cert_principals, ਕੁੰਜੀ->cert)) {
		reason = "Certificate does not contain an authorized principal";
		ਜਾਓ cert_fail_reason;
	}
	ਜੇ (sshkey_cert_check_authority_now(ਕੁੰਜੀ, 0, 0,
	    keyopts->cert_principals == ਨਿਰਾ ? pw->pw_name : ਨਿਰਾ,
	    &reason) != 0)
		ਜਾਓ cert_fail_reason;

	verbose("Accepted certificate ID \"%s\" (serial %llu) "
	    "signed by CA %s %s found at %s",
	    ਕੁੰਜੀ->cert->ਕੁੰਜੀ_id,
	    (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)ਕੁੰਜੀ->cert->serial,
	    sshkey_type(ਮਿਲਿਆ), fp, loc);

 success:
	ਜੇ (finalopts == ਨਿਰਾ)
		fatal_f("internal error: missing options");
	ਜੇ (authoptsp != ਨਿਰਾ) {
		*authoptsp = finalopts;
		finalopts = ਨਿਰਾ;
	}
	/* success */
	ret = 0;
	ਜਾਓ ਬਾਹਰਲਾ;

 cert_fail_reason:
	error("Refusing certificate ID \"%s\" serial=%llu "
	    "signed by %s CA %s via %s: %s", ਕੁੰਜੀ->cert->ਕੁੰਜੀ_id,
	    (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)ਕੁੰਜੀ->cert->serial,
	    sshkey_type(ਕੁੰਜੀ->cert->signature_ਕੁੰਜੀ), fp, loc, reason);
	auth_debug_ਜੋੜੋ("Refused Certificate ID \"%s\" serial=%llu: %s",
	    ਕੁੰਜੀ->cert->ਕੁੰਜੀ_id, (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)ਕੁੰਜੀ->cert->serial, reason);
	ਜਾਓ ਬਾਹਰਲਾ;

 fail_reason:
	error("%s at %s", reason, loc);
	auth_debug_ਜੋੜੋ("%s", reason);
 ਬਾਹਰਲਾ:
	ਮੁਕਤ(fp);
	sshauthopt_free(keyopts);
	sshauthopt_free(certopts);
	sshauthopt_free(finalopts);
	sshkey_free(ਮਿਲਿਆ);
	ਵਾਪਸ ret;
}

/*
 * Checks whether key is allowed in authorized_keys-format file,
 * returns 1 if the key is allowed or 0 otherwise.
 */
ਪੂਰਨ
auth_check_authkeys_file(ਬਣਤਰ passwd *pw, FILE *f, ਅੱਖਰ *file,
    ਬਣਤਰ sshkey *ਕੁੰਜੀ, ਅਚਲ ਅੱਖਰ *remote_ip,
    ਅਚਲ ਅੱਖਰ *remote_host, ਬਣਤਰ sshauthopt **authoptsp)
{
	ਅੱਖਰ *cp, *ਸਤਰ = ਨਿਰਾ, loc[256];
	ਮਾਪ_t linesize = 0;
	ਪੂਰਨ ਮਿਲਿਆ_ਕੁੰਜੀ = 0;
	u_long linenum = 0, nonblank = 0;

	ਜੇ (authoptsp != ਨਿਰਾ)
		*authoptsp = ਨਿਰਾ;

	ਜਦੋਂ (getline(&ਸਤਰ, &linesize, f) != -1) {
		linenum++;
		/* Always consume entire file */
		ਜੇ (ਮਿਲਿਆ_ਕੁੰਜੀ)
			ਜਾਰੀ;

		/* Skip leading whitespace, empty and comment lines. */
		cp = ਸਤਰ;
		skip_space(&cp);
		ਜੇ (!*cp || *cp == '\n' || *cp == '#')
			ਜਾਰੀ;

		nonblank++;
		snprintf(loc, ਆਕਾਰ(loc), "%.200s:%lu", file, linenum);
		ਜੇ (auth_check_authkey_ਸਤਰ(pw, ਕੁੰਜੀ, cp,
		    remote_ip, remote_host, loc, authoptsp) == 0)
			ਮਿਲਿਆ_ਕੁੰਜੀ = 1;
	}
	ਮੁਕਤ(ਸਤਰ);
	debug2_f("%s: processed %lu/%lu lines", file, nonblank, linenum);
	ਵਾਪਸ ਮਿਲਿਆ_ਕੁੰਜੀ;
}

ਸਥਿਰ FILE *
auth_openfile(ਅਚਲ ਅੱਖਰ *file, ਬਣਤਰ passwd *pw, ਪੂਰਨ strict_modes,
    ਪੂਰਨ log_missing, ਅੱਖਰ *file_type)
{
	ਅੱਖਰ ਸਤਰ[1024];
	ਬਣਤਰ stat st;
	ਪੂਰਨ fd;
	FILE *f;

	ਜੇ ((fd = open(file, O_RDONLY|O_NONBLOCK)) == -1) {
		ਜੇ (errno != ENOENT) {
			logit("Could not open user '%s' %s '%s': %s",
			    pw->pw_name, file_type, file, strerror(errno));
		} ਨਹੀਂਤਾਂ ਜੇ (log_missing) {
			debug("Could not open user '%s' %s '%s': %s",
			    pw->pw_name, file_type, file, strerror(errno));
		}
		ਵਾਪਸ ਨਿਰਾ;
	}

	ਜੇ (fstat(fd, &st) == -1) {
		close(fd);
		ਵਾਪਸ ਨਿਰਾ;
	}
	ਜੇ (!S_ISREG(st.st_mode)) {
		logit("User '%s' %s '%s' is not a regular file",
		    pw->pw_name, file_type, file);
		close(fd);
		ਵਾਪਸ ਨਿਰਾ;
	}
	unset_nonblock(fd);
	ਜੇ ((f = fdopen(fd, "r")) == ਨਿਰਾ) {
		close(fd);
		ਵਾਪਸ ਨਿਰਾ;
	}
	ਜੇ (strict_modes &&
	    ਸੁਰੱਖਿਅਤ_ਰਸਤਾ_fd(fileno(f), file, pw, ਸਤਰ, ਆਕਾਰ(ਸਤਰ)) != 0) {
		fclose(f);
		logit("Authentication refused: %s", ਸਤਰ);
		auth_debug_ਜੋੜੋ("Ignored %s: %s", file_type, ਸਤਰ);
		ਵਾਪਸ ਨਿਰਾ;
	}

	ਵਾਪਸ f;
}


FILE *
auth_openkeyfile(ਅਚਲ ਅੱਖਰ *file, ਬਣਤਰ passwd *pw, ਪੂਰਨ strict_modes)
{
	ਵਾਪਸ auth_openfile(file, pw, strict_modes, 1, "authorized keys");
}

FILE *
auth_openprincipals(ਅਚਲ ਅੱਖਰ *file, ਬਣਤਰ passwd *pw, ਪੂਰਨ strict_modes)
{
	ਵਾਪਸ auth_openfile(file, pw, strict_modes, 0,
	    "authorized principals");
}

