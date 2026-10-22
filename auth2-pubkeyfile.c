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

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <sys/stat.h>

#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <errno.h>
#അന്തര്ഭാവ <fcntl.h>
#അന്തര്ഭാവ <pwd.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <stdarg.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <time.h>
#അന്തര്ഭാവ <unistd.h>

#അന്തര്ഭാവ "ssh.h"
#അന്തര്ഭാവ "log.h"
#അന്തര്ഭാവ "misc.h"
#അന്തര്ഭാവ "sshkey.h"
#അന്തര്ഭാവ "digest.h"
#അന്തര്ഭാവ "hostfile.h"
#അന്തര്ഭാവ "auth.h"
#അന്തര്ഭാവ "auth-options.h"
#അന്തര്ഭാവ "authfile.h"
#അന്തര്ഭാവ "match.h"
#അന്തര്ഭാവ "ssherr.h"
#അന്തര്ഭാവ "xmalloc.h"

പൂർണ്ണസംഖ്യ
auth_authorise_keyopts(ഘടന passwd *pw, ഘടന sshauthopt *opts,
    പൂർണ്ണസംഖ്യ allow_cert_authority, സ്ഥിരം അക്ഷരം *remote_ip, സ്ഥിരം അക്ഷരം *remote_host,
    സ്ഥിരം അക്ഷരം *loc)
{
	time_t now = time(ശൂന്യ);
	അക്ഷരം buf[64];

	/*
	 * Check keys/principals file expiry time.
	 * NB. validity interval in certificate is handled elsewhere.
	 */
	എങ്കിൽ (opts->valid_before && now > 0 &&
	    opts->valid_before < (uint64_t)now) {
		format_absolute_time(opts->valid_before, buf, വലുപ്പം(buf));
		debug("%s: entry expired at %s", loc, buf);
		auth_debug_add("%s: entry expired at %s", loc, buf);
		തിരികെ -1;
	}
	/* Consistency checks */
	എങ്കിൽ (opts->cert_principals != ശൂന്യ && !opts->cert_authority) {
		debug("%s: principals on non-CA key", loc);
		auth_debug_add("%s: principals on non-CA key", loc);
		/* deny access */
		തിരികെ -1;
	}
	/* cert-authority flag isn't valid in authorized_principals files */
	എങ്കിൽ (!allow_cert_authority && opts->cert_authority) {
		debug("%s: cert-authority flag invalid here", loc);
		auth_debug_add("%s: cert-authority flag invalid here", loc);
		/* deny access */
		തിരികെ -1;
	}

	/* Perform from= checks */
	എങ്കിൽ (opts->required_from_host_താക്കോലുകൾ != ശൂന്യ) {
		തിരഞ്ഞെടുപ്പ് (match_host_and_ip(remote_host, remote_ip,
		    opts->required_from_host_താക്കോലുകൾ )) {
		അവസ്ഥ 1:
			/* Host name matches. */
			നിർത്തുക;
		അവസ്ഥ -1:
		സ്ഥിരസ്ഥിതി:
			debug("%s: invalid from criteria", loc);
			auth_debug_add("%s: invalid from criteria", loc);
			/* FALLTHROUGH */
		അവസ്ഥ 0:
			logit("%s: Authentication tried for %.100s with "
			    "correct key but not from a permitted "
			    "host (host=%.200s, ip=%.200s, required=%.200s).",
			    loc, pw->pw_name, remote_host, remote_ip,
			    opts->required_from_host_താക്കോലുകൾ);
			auth_debug_add("%s: Your host '%.200s' is not "
			    "permitted to use this key for login.",
			    loc, remote_host);
			/* deny access */
			തിരികെ -1;
		}
	}
	/* Check source-address restriction from certificate */
	എങ്കിൽ (opts->required_from_host_cert != ശൂന്യ) {
		തിരഞ്ഞെടുപ്പ് (addr_match_cidr_list(remote_ip,
		    opts->required_from_host_cert)) {
		അവസ്ഥ 1:
			/* accepted */
			നിർത്തുക;
		അവസ്ഥ -1:
		സ്ഥിരസ്ഥിതി:
			/* invalid */
			error("%s: Certificate source-address invalid", loc);
			/* FALLTHROUGH */
		അവസ്ഥ 0:
			logit("%s: Authentication tried for %.100s with valid "
			    "certificate but not from a permitted source "
			    "address (%.200s).", loc, pw->pw_name, remote_ip);
			auth_debug_add("%s: Your address '%.200s' is not "
			    "permitted to use this certificate for login.",
			    loc, remote_ip);
			തിരികെ -1;
		}
	}
	/*
	 *
	 * XXX this is spammy. We should report remotely only for keys
	 *     that are successful in actual auth attempts, and not PK_OK
	 *     tests.
	 */
	auth_log_authopts(loc, opts, 1);

	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
match_principals_option(സ്ഥിരം അക്ഷരം *principal_list, ഘടന sshkey_cert *cert)
{
	അക്ഷരം *list, *olist, *entry;
	u_int i;

	olist = list = xstrdup(principal_list);
	വേണ്ടി (;;) {
		എങ്കിൽ ((entry = strsep(&list, ",")) == ശൂന്യ || *entry == '\0')
			നിർത്തുക;
		വേണ്ടി (i = 0; i < cert->nprincipals; i++) {
			എങ്കിൽ (strcmp(entry, cert->principals[i]) == 0) {
				debug3("matched principal from key i"
				    "options \"%.100s\"", entry);
				സ്വതന്ത്രം(olist);
				തിരികെ 1;
			}
		}
	}
	സ്വതന്ത്രം(olist);
	തിരികെ 0;
}

/*
 * Process a single authorized_principals format line. Returns 0 and sets
 * authoptsp is principal is authorised, -1 otherwise. "loc" is used as a
 * log preamble for file/line information.
 */
പൂർണ്ണസംഖ്യ
auth_check_principals_വരി(അക്ഷരം *cp, സ്ഥിരം ഘടന sshkey_cert *cert,
    സ്ഥിരം അക്ഷരം *loc, ഘടന sshauthopt **authoptsp)
{
	u_int i, found = 0;
	അക്ഷരം *ep, *വരി_opts;
	സ്ഥിരം അക്ഷരം *reason = ശൂന്യ;
	ഘടന sshauthopt *opts = ശൂന്യ;

	എങ്കിൽ (authoptsp != ശൂന്യ)
		*authoptsp = ശൂന്യ;

	/* Trim trailing whitespace. */
	ep = cp + strlen(cp) - 1;
	ആകുമ്പോൾ (ep > cp && (*ep == '\n' || *ep == ' ' || *ep == '\t'))
		*ep-- = '\0';

	/*
	 * If the line has internal whitespace then assume it has
	 * key options.
	 */
	വരി_opts = ശൂന്യ;
	എങ്കിൽ ((ep = strrchr(cp, ' ')) != ശൂന്യ ||
	    (ep = strrchr(cp, '\t')) != ശൂന്യ) {
		വേണ്ടി (; *ep == ' ' || *ep == '\t'; ep++)
			;
		വരി_opts = cp;
		cp = ep;
	}
	എങ്കിൽ ((opts = sshauthopt_parse(വരി_opts, &reason)) == ശൂന്യ) {
		debug("%s: bad principals options: %s", loc, reason);
		auth_debug_add("%s: bad principals options: %s", loc, reason);
		തിരികെ -1;
	}
	/* Check principals in cert against those on line */
	വേണ്ടി (i = 0; i < cert->nprincipals; i++) {
		എങ്കിൽ (strcmp(cp, cert->principals[i]) != 0)
			തുടരുക;
		debug3("%s: matched principal \"%.100s\"",
		    loc, cert->principals[i]);
		found = 1;
	}
	എങ്കിൽ (found && authoptsp != ശൂന്യ) {
		*authoptsp = opts;
		opts = ശൂന്യ;
	}
	sshauthopt_free(opts);
	തിരികെ found ? 0 : -1;
}

പൂർണ്ണസംഖ്യ
auth_process_principals(FILE *f, സ്ഥിരം അക്ഷരം *file,
    സ്ഥിരം ഘടന sshkey_cert *cert, ഘടന sshauthopt **authoptsp)
{
	അക്ഷരം loc[256], *വരി = ശൂന്യ, *cp, *ep;
	size_t linesize = 0;
	u_long linenum = 0, nonblank = 0;
	u_int found_principal = 0;

	എങ്കിൽ (authoptsp != ശൂന്യ)
		*authoptsp = ശൂന്യ;

	ആകുമ്പോൾ (getline(&വരി, &linesize, f) != -1) {
		linenum++;
		/* Always consume entire input */
		എങ്കിൽ (found_principal)
			തുടരുക;

		/* Skip leading whitespace. */
		വേണ്ടി (cp = വരി; *cp == ' ' || *cp == '\t'; cp++)
			;
		/* Skip blank and comment lines. */
		എങ്കിൽ ((ep = strchr(cp, '#')) != ശൂന്യ)
			*ep = '\0';
		എങ്കിൽ (!*cp || *cp == '\n')
			തുടരുക;

		nonblank++;
		snprintf(loc, വലുപ്പം(loc), "%.200s:%lu", file, linenum);
		എങ്കിൽ (auth_check_principals_വരി(cp, cert, loc, authoptsp) == 0)
			found_principal = 1;
	}
	debug2_f("%s: processed %lu/%lu lines", file, nonblank, linenum);
	സ്വതന്ത്രം(വരി);
	തിരികെ found_principal;
}

/*
 * Check a single line of an authorized_keys-format file. Returns 0 if key
 * matches, -1 otherwise. Will return key/cert options via *authoptsp
 * on success. "loc" is used as file/line location in log messages.
 */
പൂർണ്ണസംഖ്യ
auth_check_authkey_വരി(ഘടന passwd *pw, ഘടന sshkey *താക്കോൽ,
    അക്ഷരം *cp, സ്ഥിരം അക്ഷരം *remote_ip, സ്ഥിരം അക്ഷരം *remote_host, സ്ഥിരം അക്ഷരം *loc,
    ഘടന sshauthopt **authoptsp)
{
	പൂർണ്ണസംഖ്യ want_keytype = sshkey_is_cert(താക്കോൽ) ? താക്കോൽ_UNSPEC : താക്കോൽ->type;
	ഘടന sshkey *found = ശൂന്യ;
	ഘടന sshauthopt *keyopts = ശൂന്യ, *certopts = ശൂന്യ, *finalopts = ശൂന്യ;
	അക്ഷരം *താക്കോൽ_options = ശൂന്യ, *fp = ശൂന്യ;
	സ്ഥിരം അക്ഷരം *reason = ശൂന്യ;
	പൂർണ്ണസംഖ്യ ret = -1;

	എങ്കിൽ (authoptsp != ശൂന്യ)
		*authoptsp = ശൂന്യ;

	എങ്കിൽ ((found = sshkey_new(want_keytype)) == ശൂന്യ) {
		debug3_f("keytype %d failed", want_keytype);
		പോകുക out;
	}

	/* XXX djm: peek at key type in line and skip if unwanted */

	എങ്കിൽ (sshkey_read(found, &cp) != 0) {
		/* no key?  check for options */
		debug2("%s: check options: '%s'", loc, cp);
		താക്കോൽ_options = cp;
		എങ്കിൽ (sshkey_advance_past_options(&cp) != 0) {
			reason = "invalid key option string";
			പോകുക fail_reason;
		}
		skip_space(&cp);
		എങ്കിൽ (sshkey_read(found, &cp) != 0) {
			/* still no key?  advance to next line*/
			debug2("%s: advance: '%s'", loc, cp);
			പോകുക out;
		}
	}
	/* Parse key options now; we need to know if this is a CA key */
	എങ്കിൽ ((keyopts = sshauthopt_parse(താക്കോൽ_options, &reason)) == ശൂന്യ) {
		debug("%s: bad key options: %s", loc, reason);
		auth_debug_add("%s: bad key options: %s", loc, reason);
		പോകുക out;
	}
	/* Ignore keys that don't match or incorrectly marked as CAs */
	എങ്കിൽ (sshkey_is_cert(താക്കോൽ)) {
		/* Certificate; check signature key against CA */
		എങ്കിൽ (!sshkey_equal(found, താക്കോൽ->cert->signature_താക്കോൽ) ||
		    !keyopts->cert_authority)
			പോകുക out;
	} അല്ലെങ്കിൽ {
		/* Plain key: check it against key found in file */
		എങ്കിൽ (!sshkey_equal(found, താക്കോൽ) || keyopts->cert_authority)
			പോകുക out;
	}

	/* We have a candidate key, perform authorisation checks */
	എങ്കിൽ ((fp = sshkey_fingerprint(found,
	    SSH_FP_HASH_DEFAULT, SSH_FP_DEFAULT)) == ശൂന്യ)
		fatal_f("fingerprint failed");

	debug("%s: matching %s found: %s %s", loc,
	    sshkey_is_cert(താക്കോൽ) ? "CA" : "key", sshkey_type(found), fp);

	എങ്കിൽ (auth_authorise_keyopts(pw, keyopts,
	    sshkey_is_cert(താക്കോൽ), remote_ip, remote_host, loc) != 0) {
		reason = "Refused by key options";
		പോകുക fail_reason;
	}
	/* That's all we need for plain keys. */
	എങ്കിൽ (!sshkey_is_cert(താക്കോൽ)) {
		verbose("Accepted key %s %s found at %s",
		    sshkey_type(found), fp, loc);
		finalopts = keyopts;
		keyopts = ശൂന്യ;
		പോകുക success;
	}

	/*
	 * Additional authorisation for certificates.
	 */

	/* Parse and check options present in certificate */
	എങ്കിൽ ((certopts = sshauthopt_from_cert(താക്കോൽ)) == ശൂന്യ) {
		reason = "Invalid certificate options";
		പോകുക cert_fail_reason;
	}
	എങ്കിൽ (auth_authorise_keyopts(pw, certopts, 0,
	    remote_ip, remote_host, loc) != 0) {
		reason = "Refused by certificate options";
		പോകുക cert_fail_reason;
	}
	എങ്കിൽ ((finalopts = sshauthopt_merge(keyopts, certopts, &reason)) == ശൂന്യ)
		പോകുക cert_fail_reason;

	/*
	 * If the user has specified a list of principals as
	 * a key option, then prefer that list to matching
	 * their username in the certificate principals list.
	 */
	എങ്കിൽ (keyopts->cert_principals != ശൂന്യ &&
	    !match_principals_option(keyopts->cert_principals, താക്കോൽ->cert)) {
		reason = "Certificate does not contain an authorized principal";
		പോകുക cert_fail_reason;
	}
	എങ്കിൽ (sshkey_cert_check_authority_now(താക്കോൽ, 0, 0,
	    keyopts->cert_principals == ശൂന്യ ? pw->pw_name : ശൂന്യ,
	    &reason) != 0)
		പോകുക cert_fail_reason;

	verbose("Accepted certificate ID \"%s\" (serial %llu) "
	    "signed by CA %s %s found at %s",
	    താക്കോൽ->cert->താക്കോൽ_id,
	    (unsigned long long)താക്കോൽ->cert->serial,
	    sshkey_type(found), fp, loc);

 success:
	എങ്കിൽ (finalopts == ശൂന്യ)
		fatal_f("internal error: missing options");
	എങ്കിൽ (authoptsp != ശൂന്യ) {
		*authoptsp = finalopts;
		finalopts = ശൂന്യ;
	}
	/* success */
	ret = 0;
	പോകുക out;

 cert_fail_reason:
	error("Refusing certificate ID \"%s\" serial=%llu "
	    "signed by %s CA %s via %s: %s", താക്കോൽ->cert->താക്കോൽ_id,
	    (unsigned long long)താക്കോൽ->cert->serial,
	    sshkey_type(താക്കോൽ->cert->signature_താക്കോൽ), fp, loc, reason);
	auth_debug_add("Refused Certificate ID \"%s\" serial=%llu: %s",
	    താക്കോൽ->cert->താക്കോൽ_id, (unsigned long long)താക്കോൽ->cert->serial, reason);
	പോകുക out;

 fail_reason:
	error("%s at %s", reason, loc);
	auth_debug_add("%s", reason);
 out:
	സ്വതന്ത്രം(fp);
	sshauthopt_free(keyopts);
	sshauthopt_free(certopts);
	sshauthopt_free(finalopts);
	sshkey_free(found);
	തിരികെ ret;
}

/*
 * Checks whether key is allowed in authorized_keys-format file,
 * returns 1 if the key is allowed or 0 otherwise.
 */
പൂർണ്ണസംഖ്യ
auth_check_authkeys_file(ഘടന passwd *pw, FILE *f, അക്ഷരം *file,
    ഘടന sshkey *താക്കോൽ, സ്ഥിരം അക്ഷരം *remote_ip,
    സ്ഥിരം അക്ഷരം *remote_host, ഘടന sshauthopt **authoptsp)
{
	അക്ഷരം *cp, *വരി = ശൂന്യ, loc[256];
	size_t linesize = 0;
	പൂർണ്ണസംഖ്യ found_താക്കോൽ = 0;
	u_long linenum = 0, nonblank = 0;

	എങ്കിൽ (authoptsp != ശൂന്യ)
		*authoptsp = ശൂന്യ;

	ആകുമ്പോൾ (getline(&വരി, &linesize, f) != -1) {
		linenum++;
		/* Always consume entire file */
		എങ്കിൽ (found_താക്കോൽ)
			തുടരുക;

		/* Skip leading whitespace, empty and comment lines. */
		cp = വരി;
		skip_space(&cp);
		എങ്കിൽ (!*cp || *cp == '\n' || *cp == '#')
			തുടരുക;

		nonblank++;
		snprintf(loc, വലുപ്പം(loc), "%.200s:%lu", file, linenum);
		എങ്കിൽ (auth_check_authkey_വരി(pw, താക്കോൽ, cp,
		    remote_ip, remote_host, loc, authoptsp) == 0)
			found_താക്കോൽ = 1;
	}
	സ്വതന്ത്രം(വരി);
	debug2_f("%s: processed %lu/%lu lines", file, nonblank, linenum);
	തിരികെ found_താക്കോൽ;
}

സ്ഥിതം FILE *
auth_openfile(സ്ഥിരം അക്ഷരം *file, ഘടന passwd *pw, പൂർണ്ണസംഖ്യ strict_modes,
    പൂർണ്ണസംഖ്യ log_missing, അക്ഷരം *file_type)
{
	അക്ഷരം വരി[1024];
	ഘടന stat st;
	പൂർണ്ണസംഖ്യ fd;
	FILE *f;

	എങ്കിൽ ((fd = open(file, O_RDONLY|O_NONBLOCK)) == -1) {
		എങ്കിൽ (errno != ENOENT) {
			logit("Could not open user '%s' %s '%s': %s",
			    pw->pw_name, file_type, file, strerror(errno));
		} അല്ലെങ്കിൽ എങ്കിൽ (log_missing) {
			debug("Could not open user '%s' %s '%s': %s",
			    pw->pw_name, file_type, file, strerror(errno));
		}
		തിരികെ ശൂന്യ;
	}

	എങ്കിൽ (fstat(fd, &st) == -1) {
		close(fd);
		തിരികെ ശൂന്യ;
	}
	എങ്കിൽ (!S_ISREG(st.st_mode)) {
		logit("User '%s' %s '%s' is not a regular file",
		    pw->pw_name, file_type, file);
		close(fd);
		തിരികെ ശൂന്യ;
	}
	unset_nonblock(fd);
	എങ്കിൽ ((f = fdopen(fd, "r")) == ശൂന്യ) {
		close(fd);
		തിരികെ ശൂന്യ;
	}
	എങ്കിൽ (strict_modes &&
	    safe_path_fd(fileno(f), file, pw, വരി, വലുപ്പം(വരി)) != 0) {
		fclose(f);
		logit("Authentication refused: %s", വരി);
		auth_debug_add("Ignored %s: %s", file_type, വരി);
		തിരികെ ശൂന്യ;
	}

	തിരികെ f;
}


FILE *
auth_openkeyfile(സ്ഥിരം അക്ഷരം *file, ഘടന passwd *pw, പൂർണ്ണസംഖ്യ strict_modes)
{
	തിരികെ auth_openfile(file, pw, strict_modes, 1, "authorized keys");
}

FILE *
auth_openprincipals(സ്ഥിരം അക്ഷരം *file, ഘടന passwd *pw, പൂർണ്ണസംഖ്യ strict_modes)
{
	തിരികെ auth_openfile(file, pw, strict_modes, 0,
	    "authorized principals");
}

