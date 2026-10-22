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

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <sys/stat.h>

#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <errno.h>
#અન્તર્ભાવ <fcntl.h>
#અન્તર્ભાવ <pwd.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <stdarg.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <time.h>
#અન્તર્ભાવ <unistd.h>

#અન્તર્ભાવ "ssh.h"
#અન્તર્ભાવ "log.h"
#અન્તર્ભાવ "misc.h"
#અન્તર્ભાવ "sshkey.h"
#અન્તર્ભાવ "digest.h"
#અન્તર્ભાવ "hostfile.h"
#અન્તર્ભાવ "auth.h"
#અન્તર્ભાવ "auth-options.h"
#અન્તર્ભાવ "authfile.h"
#અન્તર્ભાવ "match.h"
#અન્તર્ભાવ "ssherr.h"
#અન્તર્ભાવ "xmalloc.h"

પૂર્ણાંક
auth_authorise_keyopts(સંરચના passwd *pw, સંરચના sshauthopt *opts,
    પૂર્ણાંક allow_cert_authority, અચલ અક્ષર *remote_ip, અચલ અક્ષર *remote_host,
    અચલ અક્ષર *loc)
{
	time_t now = time(ખાલી);
	અક્ષર buf[64];

	/*
	 * Check keys/principals file expiry time.
	 * NB. validity interval in certificate is handled elsewhere.
	 */
	જો (opts->valid_before && now > 0 &&
	    opts->valid_before < (uint64_t)now) {
		format_absolute_time(opts->valid_before, buf, કદ(buf));
		debug("%s: entry expired at %s", loc, buf);
		auth_debug_add("%s: entry expired at %s", loc, buf);
		પાછા -1;
	}
	/* Consistency checks */
	જો (opts->cert_principals != ખાલી && !opts->cert_authority) {
		debug("%s: principals on non-CA key", loc);
		auth_debug_add("%s: principals on non-CA key", loc);
		/* deny access */
		પાછા -1;
	}
	/* cert-authority flag isn't valid in authorized_principals files */
	જો (!allow_cert_authority && opts->cert_authority) {
		debug("%s: cert-authority flag invalid here", loc);
		auth_debug_add("%s: cert-authority flag invalid here", loc);
		/* deny access */
		પાછા -1;
	}

	/* Perform from= checks */
	જો (opts->required_from_host_ચાવીઓ != ખાલી) {
		પસંદગી (match_host_and_ip(remote_host, remote_ip,
		    opts->required_from_host_ચાવીઓ )) {
		સ્થિતિ 1:
			/* Host name matches. */
			તોડો;
		સ્થિતિ -1:
		મૂળભૂત:
			debug("%s: invalid from criteria", loc);
			auth_debug_add("%s: invalid from criteria", loc);
			/* FALLTHROUGH */
		સ્થિતિ 0:
			logit("%s: Authentication tried for %.100s with "
			    "correct key but not from a permitted "
			    "host (host=%.200s, ip=%.200s, required=%.200s).",
			    loc, pw->pw_name, remote_host, remote_ip,
			    opts->required_from_host_ચાવીઓ);
			auth_debug_add("%s: Your host '%.200s' is not "
			    "permitted to use this key for login.",
			    loc, remote_host);
			/* deny access */
			પાછા -1;
		}
	}
	/* Check source-address restriction from certificate */
	જો (opts->required_from_host_cert != ખાલી) {
		પસંદગી (addr_match_cidr_list(remote_ip,
		    opts->required_from_host_cert)) {
		સ્થિતિ 1:
			/* accepted */
			તોડો;
		સ્થિતિ -1:
		મૂળભૂત:
			/* invalid */
			error("%s: Certificate source-address invalid", loc);
			/* FALLTHROUGH */
		સ્થિતિ 0:
			logit("%s: Authentication tried for %.100s with valid "
			    "certificate but not from a permitted source "
			    "address (%.200s).", loc, pw->pw_name, remote_ip);
			auth_debug_add("%s: Your address '%.200s' is not "
			    "permitted to use this certificate for login.",
			    loc, remote_ip);
			પાછા -1;
		}
	}
	/*
	 *
	 * XXX this is spammy. We should report remotely only for keys
	 *     that are successful in actual auth attempts, and not PK_OK
	 *     tests.
	 */
	auth_log_authopts(loc, opts, 1);

	પાછા 0;
}

સ્થિર પૂર્ણાંક
match_principals_option(અચલ અક્ષર *principal_list, સંરચના sshkey_cert *cert)
{
	અક્ષર *list, *olist, *entry;
	u_int i;

	olist = list = xstrdup(principal_list);
	માટે (;;) {
		જો ((entry = strsep(&list, ",")) == ખાલી || *entry == '\0')
			તોડો;
		માટે (i = 0; i < cert->nprincipals; i++) {
			જો (strcmp(entry, cert->principals[i]) == 0) {
				debug3("matched principal from key i"
				    "options \"%.100s\"", entry);
				મુક્ત(olist);
				પાછા 1;
			}
		}
	}
	મુક્ત(olist);
	પાછા 0;
}

/*
 * Process a single authorized_principals format line. Returns 0 and sets
 * authoptsp is principal is authorised, -1 otherwise. "loc" is used as a
 * log preamble for file/line information.
 */
પૂર્ણાંક
auth_check_principals_લીટી(અક્ષર *cp, અચલ સંરચના sshkey_cert *cert,
    અચલ અક્ષર *loc, સંરચના sshauthopt **authoptsp)
{
	u_int i, found = 0;
	અક્ષર *ep, *લીટી_opts;
	અચલ અક્ષર *reason = ખાલી;
	સંરચના sshauthopt *opts = ખાલી;

	જો (authoptsp != ખાલી)
		*authoptsp = ખાલી;

	/* Trim trailing whitespace. */
	ep = cp + strlen(cp) - 1;
	જ્યારે (ep > cp && (*ep == '\n' || *ep == ' ' || *ep == '\t'))
		*ep-- = '\0';

	/*
	 * If the line has internal whitespace then assume it has
	 * key options.
	 */
	લીટી_opts = ખાલી;
	જો ((ep = strrchr(cp, ' ')) != ખાલી ||
	    (ep = strrchr(cp, '\t')) != ખાલી) {
		માટે (; *ep == ' ' || *ep == '\t'; ep++)
			;
		લીટી_opts = cp;
		cp = ep;
	}
	જો ((opts = sshauthopt_parse(લીટી_opts, &reason)) == ખાલી) {
		debug("%s: bad principals options: %s", loc, reason);
		auth_debug_add("%s: bad principals options: %s", loc, reason);
		પાછા -1;
	}
	/* Check principals in cert against those on line */
	માટે (i = 0; i < cert->nprincipals; i++) {
		જો (strcmp(cp, cert->principals[i]) != 0)
			ચાલુ;
		debug3("%s: matched principal \"%.100s\"",
		    loc, cert->principals[i]);
		found = 1;
	}
	જો (found && authoptsp != ખાલી) {
		*authoptsp = opts;
		opts = ખાલી;
	}
	sshauthopt_free(opts);
	પાછા found ? 0 : -1;
}

પૂર્ણાંક
auth_process_principals(FILE *f, અચલ અક્ષર *file,
    અચલ સંરચના sshkey_cert *cert, સંરચના sshauthopt **authoptsp)
{
	અક્ષર loc[256], *લીટી = ખાલી, *cp, *ep;
	size_t linesize = 0;
	u_long linenum = 0, nonblank = 0;
	u_int found_principal = 0;

	જો (authoptsp != ખાલી)
		*authoptsp = ખાલી;

	જ્યારે (getline(&લીટી, &linesize, f) != -1) {
		linenum++;
		/* Always consume entire input */
		જો (found_principal)
			ચાલુ;

		/* Skip leading whitespace. */
		માટે (cp = લીટી; *cp == ' ' || *cp == '\t'; cp++)
			;
		/* Skip blank and comment lines. */
		જો ((ep = strchr(cp, '#')) != ખાલી)
			*ep = '\0';
		જો (!*cp || *cp == '\n')
			ચાલુ;

		nonblank++;
		snprintf(loc, કદ(loc), "%.200s:%lu", file, linenum);
		જો (auth_check_principals_લીટી(cp, cert, loc, authoptsp) == 0)
			found_principal = 1;
	}
	debug2_f("%s: processed %lu/%lu lines", file, nonblank, linenum);
	મુક્ત(લીટી);
	પાછા found_principal;
}

/*
 * Check a single line of an authorized_keys-format file. Returns 0 if key
 * matches, -1 otherwise. Will return key/cert options via *authoptsp
 * on success. "loc" is used as file/line location in log messages.
 */
પૂર્ણાંક
auth_check_authkey_લીટી(સંરચના passwd *pw, સંરચના sshkey *ચાવી,
    અક્ષર *cp, અચલ અક્ષર *remote_ip, અચલ અક્ષર *remote_host, અચલ અક્ષર *loc,
    સંરચના sshauthopt **authoptsp)
{
	પૂર્ણાંક want_keytype = sshkey_is_cert(ચાવી) ? ચાવી_UNSPEC : ચાવી->type;
	સંરચના sshkey *found = ખાલી;
	સંરચના sshauthopt *keyopts = ખાલી, *certopts = ખાલી, *finalopts = ખાલી;
	અક્ષર *ચાવી_options = ખાલી, *fp = ખાલી;
	અચલ અક્ષર *reason = ખાલી;
	પૂર્ણાંક ret = -1;

	જો (authoptsp != ખાલી)
		*authoptsp = ખાલી;

	જો ((found = sshkey_new(want_keytype)) == ખાલી) {
		debug3_f("keytype %d failed", want_keytype);
		જાઓ out;
	}

	/* XXX djm: peek at key type in line and skip if unwanted */

	જો (sshkey_read(found, &cp) != 0) {
		/* no key?  check for options */
		debug2("%s: check options: '%s'", loc, cp);
		ચાવી_options = cp;
		જો (sshkey_advance_past_options(&cp) != 0) {
			reason = "invalid key option string";
			જાઓ fail_reason;
		}
		skip_space(&cp);
		જો (sshkey_read(found, &cp) != 0) {
			/* still no key?  advance to next line*/
			debug2("%s: advance: '%s'", loc, cp);
			જાઓ out;
		}
	}
	/* Parse key options now; we need to know if this is a CA key */
	જો ((keyopts = sshauthopt_parse(ચાવી_options, &reason)) == ખાલી) {
		debug("%s: bad key options: %s", loc, reason);
		auth_debug_add("%s: bad key options: %s", loc, reason);
		જાઓ out;
	}
	/* Ignore keys that don't match or incorrectly marked as CAs */
	જો (sshkey_is_cert(ચાવી)) {
		/* Certificate; check signature key against CA */
		જો (!sshkey_equal(found, ચાવી->cert->signature_ચાવી) ||
		    !keyopts->cert_authority)
			જાઓ out;
	} નહીંતર {
		/* Plain key: check it against key found in file */
		જો (!sshkey_equal(found, ચાવી) || keyopts->cert_authority)
			જાઓ out;
	}

	/* We have a candidate key, perform authorisation checks */
	જો ((fp = sshkey_fingerprint(found,
	    SSH_FP_HASH_DEFAULT, SSH_FP_DEFAULT)) == ખાલી)
		fatal_f("fingerprint failed");

	debug("%s: matching %s found: %s %s", loc,
	    sshkey_is_cert(ચાવી) ? "CA" : "key", sshkey_type(found), fp);

	જો (auth_authorise_keyopts(pw, keyopts,
	    sshkey_is_cert(ચાવી), remote_ip, remote_host, loc) != 0) {
		reason = "Refused by key options";
		જાઓ fail_reason;
	}
	/* That's all we need for plain keys. */
	જો (!sshkey_is_cert(ચાવી)) {
		verbose("Accepted key %s %s found at %s",
		    sshkey_type(found), fp, loc);
		finalopts = keyopts;
		keyopts = ખાલી;
		જાઓ success;
	}

	/*
	 * Additional authorisation for certificates.
	 */

	/* Parse and check options present in certificate */
	જો ((certopts = sshauthopt_from_cert(ચાવી)) == ખાલી) {
		reason = "Invalid certificate options";
		જાઓ cert_fail_reason;
	}
	જો (auth_authorise_keyopts(pw, certopts, 0,
	    remote_ip, remote_host, loc) != 0) {
		reason = "Refused by certificate options";
		જાઓ cert_fail_reason;
	}
	જો ((finalopts = sshauthopt_merge(keyopts, certopts, &reason)) == ખાલી)
		જાઓ cert_fail_reason;

	/*
	 * If the user has specified a list of principals as
	 * a key option, then prefer that list to matching
	 * their username in the certificate principals list.
	 */
	જો (keyopts->cert_principals != ખાલી &&
	    !match_principals_option(keyopts->cert_principals, ચાવી->cert)) {
		reason = "Certificate does not contain an authorized principal";
		જાઓ cert_fail_reason;
	}
	જો (sshkey_cert_check_authority_now(ચાવી, 0, 0,
	    keyopts->cert_principals == ખાલી ? pw->pw_name : ખાલી,
	    &reason) != 0)
		જાઓ cert_fail_reason;

	verbose("Accepted certificate ID \"%s\" (serial %llu) "
	    "signed by CA %s %s found at %s",
	    ચાવી->cert->ચાવી_id,
	    (unsigned long long)ચાવી->cert->serial,
	    sshkey_type(found), fp, loc);

 success:
	જો (finalopts == ખાલી)
		fatal_f("internal error: missing options");
	જો (authoptsp != ખાલી) {
		*authoptsp = finalopts;
		finalopts = ખાલી;
	}
	/* success */
	ret = 0;
	જાઓ out;

 cert_fail_reason:
	error("Refusing certificate ID \"%s\" serial=%llu "
	    "signed by %s CA %s via %s: %s", ચાવી->cert->ચાવી_id,
	    (unsigned long long)ચાવી->cert->serial,
	    sshkey_type(ચાવી->cert->signature_ચાવી), fp, loc, reason);
	auth_debug_add("Refused Certificate ID \"%s\" serial=%llu: %s",
	    ચાવી->cert->ચાવી_id, (unsigned long long)ચાવી->cert->serial, reason);
	જાઓ out;

 fail_reason:
	error("%s at %s", reason, loc);
	auth_debug_add("%s", reason);
 out:
	મુક્ત(fp);
	sshauthopt_free(keyopts);
	sshauthopt_free(certopts);
	sshauthopt_free(finalopts);
	sshkey_free(found);
	પાછા ret;
}

/*
 * Checks whether key is allowed in authorized_keys-format file,
 * returns 1 if the key is allowed or 0 otherwise.
 */
પૂર્ણાંક
auth_check_authkeys_file(સંરચના passwd *pw, FILE *f, અક્ષર *file,
    સંરચના sshkey *ચાવી, અચલ અક્ષર *remote_ip,
    અચલ અક્ષર *remote_host, સંરચના sshauthopt **authoptsp)
{
	અક્ષર *cp, *લીટી = ખાલી, loc[256];
	size_t linesize = 0;
	પૂર્ણાંક found_ચાવી = 0;
	u_long linenum = 0, nonblank = 0;

	જો (authoptsp != ખાલી)
		*authoptsp = ખાલી;

	જ્યારે (getline(&લીટી, &linesize, f) != -1) {
		linenum++;
		/* Always consume entire file */
		જો (found_ચાવી)
			ચાલુ;

		/* Skip leading whitespace, empty and comment lines. */
		cp = લીટી;
		skip_space(&cp);
		જો (!*cp || *cp == '\n' || *cp == '#')
			ચાલુ;

		nonblank++;
		snprintf(loc, કદ(loc), "%.200s:%lu", file, linenum);
		જો (auth_check_authkey_લીટી(pw, ચાવી, cp,
		    remote_ip, remote_host, loc, authoptsp) == 0)
			found_ચાવી = 1;
	}
	મુક્ત(લીટી);
	debug2_f("%s: processed %lu/%lu lines", file, nonblank, linenum);
	પાછા found_ચાવી;
}

સ્થિર FILE *
auth_openfile(અચલ અક્ષર *file, સંરચના passwd *pw, પૂર્ણાંક strict_modes,
    પૂર્ણાંક log_missing, અક્ષર *file_type)
{
	અક્ષર લીટી[1024];
	સંરચના stat st;
	પૂર્ણાંક fd;
	FILE *f;

	જો ((fd = open(file, O_RDONLY|O_NONBLOCK)) == -1) {
		જો (errno != ENOENT) {
			logit("Could not open user '%s' %s '%s': %s",
			    pw->pw_name, file_type, file, strerror(errno));
		} નહીંતર જો (log_missing) {
			debug("Could not open user '%s' %s '%s': %s",
			    pw->pw_name, file_type, file, strerror(errno));
		}
		પાછા ખાલી;
	}

	જો (fstat(fd, &st) == -1) {
		close(fd);
		પાછા ખાલી;
	}
	જો (!S_ISREG(st.st_mode)) {
		logit("User '%s' %s '%s' is not a regular file",
		    pw->pw_name, file_type, file);
		close(fd);
		પાછા ખાલી;
	}
	unset_nonblock(fd);
	જો ((f = fdopen(fd, "r")) == ખાલી) {
		close(fd);
		પાછા ખાલી;
	}
	જો (strict_modes &&
	    safe_path_fd(fileno(f), file, pw, લીટી, કદ(લીટી)) != 0) {
		fclose(f);
		logit("Authentication refused: %s", લીટી);
		auth_debug_add("Ignored %s: %s", file_type, લીટી);
		પાછા ખાલી;
	}

	પાછા f;
}


FILE *
auth_openkeyfile(અચલ અક્ષર *file, સંરચના passwd *pw, પૂર્ણાંક strict_modes)
{
	પાછા auth_openfile(file, pw, strict_modes, 1, "authorized keys");
}

FILE *
auth_openprincipals(અચલ અક્ષર *file, સંરચના passwd *pw, પૂર્ણાંક strict_modes)
{
	પાછા auth_openfile(file, pw, strict_modes, 0,
	    "authorized principals");
}

