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

#include "includes.h"

#include <sys/types.h>
#include <sys/stat.h>

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "ssh.h"
#include "log.h"
#include "misc.h"
#include "sshkey.h"
#include "digest.h"
#include "hostfile.h"
#include "auth.h"
#include "auth-options.h"
#include "authfile.h"
#include "match.h"
#include "ssherr.h"
#include "xmalloc.h"

puur_naa_nka
auth_authorise_keyopts(sa_nracanaa passwd *pw, sa_nracanaa sshauthopt *opts,
    puur_naa_nka allow_cert_authority, const var_na *remote_ip, const var_na *remote_host,
    const var_na *loc)
{
	time_t now = time(NULL);
	var_na buf[64];

	/*
	 * Check keys/principals file expiry time.
	 * NB. validity interval in certificate is handled elsewhere.
	 */
	ꦪꦼꦤ꧀ (opts->valid_before && now > 0 &&
	    opts->valid_before < (uint64_t)now) {
		format_absolute_time(opts->valid_before, buf, parimaa_na(buf));
		debug("%s: entry expired at %s", loc, buf);
		auth_debug_add("%s: entry expired at %s", loc, buf);
		ꦮꦭꦶ -1;
	}
	/* Consistency checks */
	ꦪꦼꦤ꧀ (opts->cert_principals != NULL && !opts->cert_authority) {
		debug("%s: principals on non-CA key", loc);
		auth_debug_add("%s: principals on non-CA key", loc);
		/* deny access */
		ꦮꦭꦶ -1;
	}
	/* cert-authority flag isn't valid in authorized_principals files */
	ꦪꦼꦤ꧀ (!allow_cert_authority && opts->cert_authority) {
		debug("%s: cert-authority flag invalid here", loc);
		auth_debug_add("%s: cert-authority flag invalid here", loc);
		/* deny access */
		ꦮꦭꦶ -1;
	}

	/* Perform from= checks */
	ꦪꦼꦤ꧀ (opts->required_from_host_keys != NULL) {
		switch (match_host_and_ip(remote_host, remote_ip,
		    opts->required_from_host_keys )) {
		pak_sa 1:
			/* Host name matches. */
			bha_nga;
		pak_sa -1:
		default:
			debug("%s: invalid from criteria", loc);
			auth_debug_add("%s: invalid from criteria", loc);
			/* FALLTHROUGH */
		pak_sa 0:
			logit("%s: Authentication tried for %.100s with "
			    "correct key but not from a permitted "
			    "host (host=%.200s, ip=%.200s, required=%.200s).",
			    loc, pw->pw_name, remote_host, remote_ip,
			    opts->required_from_host_keys);
			auth_debug_add("%s: Your host '%.200s' is not "
			    "permitted to use this key for login.",
			    loc, remote_host);
			/* deny access */
			ꦮꦭꦶ -1;
		}
	}
	/* Check source-address restriction from certificate */
	ꦪꦼꦤ꧀ (opts->required_from_host_cert != NULL) {
		switch (addr_match_cidr_list(remote_ip,
		    opts->required_from_host_cert)) {
		pak_sa 1:
			/* accepted */
			bha_nga;
		pak_sa -1:
		default:
			/* invalid */
			error("%s: Certificate source-address invalid", loc);
			/* FALLTHROUGH */
		pak_sa 0:
			logit("%s: Authentication tried for %.100s with valid "
			    "certificate but not from a permitted source "
			    "address (%.200s).", loc, pw->pw_name, remote_ip);
			auth_debug_add("%s: Your address '%.200s' is not "
			    "permitted to use this certificate for login.",
			    loc, remote_ip);
			ꦮꦭꦶ -1;
		}
	}
	/*
	 *
	 * XXX this is spammy. We should report remotely only for keys
	 *     that are successful in actual auth attempts, and not PK_OK
	 *     tests.
	 */
	auth_log_authopts(loc, opts, 1);

	ꦮꦭꦶ 0;
}

static puur_naa_nka
match_principals_option(const var_na *principal_list, sa_nracanaa sshkey_cert *cert)
{
	var_na *list, *olist, *entry;
	u_int i;

	olist = list = xstrdup(principal_list);
	ꦏꦁꦒꦺꦴ (;;) {
		ꦪꦼꦤ꧀ ((entry = strsep(&list, ",")) == NULL || *entry == '\0')
			bha_nga;
		ꦏꦁꦒꦺꦴ (i = 0; i < cert->nprincipals; i++) {
			ꦪꦼꦤ꧀ (strcmp(entry, cert->principals[i]) == 0) {
				debug3("matched principal from key i"
				    "options \"%.100s\"", entry);
				free(olist);
				ꦮꦭꦶ 1;
			}
		}
	}
	free(olist);
	ꦮꦭꦶ 0;
}

/*
 * Process a single authorized_principals format line. Returns 0 and sets
 * authoptsp is principal is authorised, -1 otherwise. "loc" is used as a
 * log preamble for file/line information.
 */
puur_naa_nka
auth_check_principals_line(var_na *cp, const sa_nracanaa sshkey_cert *cert,
    const var_na *loc, sa_nracanaa sshauthopt **authoptsp)
{
	u_int i, found = 0;
	var_na *ep, *line_opts;
	const var_na *reason = NULL;
	sa_nracanaa sshauthopt *opts = NULL;

	ꦪꦼꦤ꧀ (authoptsp != NULL)
		*authoptsp = NULL;

	/* Trim trailing whitespace. */
	ep = cp + strlen(cp) - 1;
	ꦱꦼꦢꦼꦭ (ep > cp && (*ep == '\n' || *ep == ' ' || *ep == '\t'))
		*ep-- = '\0';

	/*
	 * If the line has internal whitespace then assume it has
	 * key options.
	 */
	line_opts = NULL;
	ꦪꦼꦤ꧀ ((ep = strrchr(cp, ' ')) != NULL ||
	    (ep = strrchr(cp, '\t')) != NULL) {
		ꦏꦁꦒꦺꦴ (; *ep == ' ' || *ep == '\t'; ep++)
			;
		line_opts = cp;
		cp = ep;
	}
	ꦪꦼꦤ꧀ ((opts = sshauthopt_parse(line_opts, &reason)) == NULL) {
		debug("%s: bad principals options: %s", loc, reason);
		auth_debug_add("%s: bad principals options: %s", loc, reason);
		ꦮꦭꦶ -1;
	}
	/* Check principals in cert against those on line */
	ꦏꦁꦒꦺꦴ (i = 0; i < cert->nprincipals; i++) {
		ꦪꦼꦤ꧀ (strcmp(cp, cert->principals[i]) != 0)
			continue;
		debug3("%s: matched principal \"%.100s\"",
		    loc, cert->principals[i]);
		found = 1;
	}
	ꦪꦼꦤ꧀ (found && authoptsp != NULL) {
		*authoptsp = opts;
		opts = NULL;
	}
	sshauthopt_free(opts);
	ꦮꦭꦶ found ? 0 : -1;
}

puur_naa_nka
auth_process_principals(FILE *f, const var_na *file,
    const sa_nracanaa sshkey_cert *cert, sa_nracanaa sshauthopt **authoptsp)
{
	var_na loc[256], *line = NULL, *cp, *ep;
	size_t linesize = 0;
	u_long linenum = 0, nonblank = 0;
	u_int found_principal = 0;

	ꦪꦼꦤ꧀ (authoptsp != NULL)
		*authoptsp = NULL;

	ꦱꦼꦢꦼꦭ (getline(&line, &linesize, f) != -1) {
		linenum++;
		/* Always consume entire input */
		ꦪꦼꦤ꧀ (found_principal)
			continue;

		/* Skip leading whitespace. */
		ꦏꦁꦒꦺꦴ (cp = line; *cp == ' ' || *cp == '\t'; cp++)
			;
		/* Skip blank and comment lines. */
		ꦪꦼꦤ꧀ ((ep = strchr(cp, '#')) != NULL)
			*ep = '\0';
		ꦪꦼꦤ꧀ (!*cp || *cp == '\n')
			continue;

		nonblank++;
		snprintf(loc, parimaa_na(loc), "%.200s:%lu", file, linenum);
		ꦪꦼꦤ꧀ (auth_check_principals_line(cp, cert, loc, authoptsp) == 0)
			found_principal = 1;
	}
	debug2_f("%s: processed %lu/%lu lines", file, nonblank, linenum);
	free(line);
	ꦮꦭꦶ found_principal;
}

/*
 * Check a single line of an authorized_keys-format file. Returns 0 if key
 * matches, -1 otherwise. Will return key/cert options via *authoptsp
 * on success. "loc" is used as file/line location in log messages.
 */
puur_naa_nka
auth_check_authkey_line(sa_nracanaa passwd *pw, sa_nracanaa sshkey *key,
    var_na *cp, const var_na *remote_ip, const var_na *remote_host, const var_na *loc,
    sa_nracanaa sshauthopt **authoptsp)
{
	puur_naa_nka want_keytype = sshkey_is_cert(key) ? KEY_UNSPEC : key->type;
	sa_nracanaa sshkey *found = NULL;
	sa_nracanaa sshauthopt *keyopts = NULL, *certopts = NULL, *finalopts = NULL;
	var_na *key_options = NULL, *fp = NULL;
	const var_na *reason = NULL;
	puur_naa_nka ret = -1;

	ꦪꦼꦤ꧀ (authoptsp != NULL)
		*authoptsp = NULL;

	ꦪꦼꦤ꧀ ((found = sshkey_new(want_keytype)) == NULL) {
		debug3_f("keytype %d failed", want_keytype);
		goto out;
	}

	/* XXX djm: peek at key type in line and skip if unwanted */

	ꦪꦼꦤ꧀ (sshkey_read(found, &cp) != 0) {
		/* no key?  check for options */
		debug2("%s: check options: '%s'", loc, cp);
		key_options = cp;
		ꦪꦼꦤ꧀ (sshkey_advance_past_options(&cp) != 0) {
			reason = "invalid key option string";
			goto fail_reason;
		}
		skip_space(&cp);
		ꦪꦼꦤ꧀ (sshkey_read(found, &cp) != 0) {
			/* still no key?  advance to next line*/
			debug2("%s: advance: '%s'", loc, cp);
			goto out;
		}
	}
	/* Parse key options now; we need to know if this is a CA key */
	ꦪꦼꦤ꧀ ((keyopts = sshauthopt_parse(key_options, &reason)) == NULL) {
		debug("%s: bad key options: %s", loc, reason);
		auth_debug_add("%s: bad key options: %s", loc, reason);
		goto out;
	}
	/* Ignore keys that don't match or incorrectly marked as CAs */
	ꦪꦼꦤ꧀ (sshkey_is_cert(key)) {
		/* Certificate; check signature key against CA */
		ꦪꦼꦤ꧀ (!sshkey_equal(found, key->cert->signature_key) ||
		    !keyopts->cert_authority)
			goto out;
	} ꦭꦶꦪ {
		/* Plain key: check it against key found in file */
		ꦪꦼꦤ꧀ (!sshkey_equal(found, key) || keyopts->cert_authority)
			goto out;
	}

	/* We have a candidate key, perform authorisation checks */
	ꦪꦼꦤ꧀ ((fp = sshkey_fingerprint(found,
	    SSH_FP_HASH_DEFAULT, SSH_FP_DEFAULT)) == NULL)
		fatal_f("fingerprint failed");

	debug("%s: matching %s found: %s %s", loc,
	    sshkey_is_cert(key) ? "CA" : "key", sshkey_type(found), fp);

	ꦪꦼꦤ꧀ (auth_authorise_keyopts(pw, keyopts,
	    sshkey_is_cert(key), remote_ip, remote_host, loc) != 0) {
		reason = "Refused by key options";
		goto fail_reason;
	}
	/* That's all we need for plain keys. */
	ꦪꦼꦤ꧀ (!sshkey_is_cert(key)) {
		verbose("Accepted key %s %s found at %s",
		    sshkey_type(found), fp, loc);
		finalopts = keyopts;
		keyopts = NULL;
		goto success;
	}

	/*
	 * Additional authorisation for certificates.
	 */

	/* Parse and check options present in certificate */
	ꦪꦼꦤ꧀ ((certopts = sshauthopt_from_cert(key)) == NULL) {
		reason = "Invalid certificate options";
		goto cert_fail_reason;
	}
	ꦪꦼꦤ꧀ (auth_authorise_keyopts(pw, certopts, 0,
	    remote_ip, remote_host, loc) != 0) {
		reason = "Refused by certificate options";
		goto cert_fail_reason;
	}
	ꦪꦼꦤ꧀ ((finalopts = sshauthopt_merge(keyopts, certopts, &reason)) == NULL)
		goto cert_fail_reason;

	/*
	 * If the user has specified a list of principals as
	 * a key option, then prefer that list to matching
	 * their username in the certificate principals list.
	 */
	ꦪꦼꦤ꧀ (keyopts->cert_principals != NULL &&
	    !match_principals_option(keyopts->cert_principals, key->cert)) {
		reason = "Certificate does not contain an authorized principal";
		goto cert_fail_reason;
	}
	ꦪꦼꦤ꧀ (sshkey_cert_check_authority_now(key, 0, 0,
	    keyopts->cert_principals == NULL ? pw->pw_name : NULL,
	    &reason) != 0)
		goto cert_fail_reason;

	verbose("Accepted certificate ID \"%s\" (serial %llu) "
	    "signed by CA %s %s found at %s",
	    key->cert->key_id,
	    (unsigned long long)key->cert->serial,
	    sshkey_type(found), fp, loc);

 success:
	ꦪꦼꦤ꧀ (finalopts == NULL)
		fatal_f("internal error: missing options");
	ꦪꦼꦤ꧀ (authoptsp != NULL) {
		*authoptsp = finalopts;
		finalopts = NULL;
	}
	/* success */
	ret = 0;
	goto out;

 cert_fail_reason:
	error("Refusing certificate ID \"%s\" serial=%llu "
	    "signed by %s CA %s via %s: %s", key->cert->key_id,
	    (unsigned long long)key->cert->serial,
	    sshkey_type(key->cert->signature_key), fp, loc, reason);
	auth_debug_add("Refused Certificate ID \"%s\" serial=%llu: %s",
	    key->cert->key_id, (unsigned long long)key->cert->serial, reason);
	goto out;

 fail_reason:
	error("%s at %s", reason, loc);
	auth_debug_add("%s", reason);
 out:
	free(fp);
	sshauthopt_free(keyopts);
	sshauthopt_free(certopts);
	sshauthopt_free(finalopts);
	sshkey_free(found);
	ꦮꦭꦶ ret;
}

/*
 * Checks whether key is allowed in authorized_keys-format file,
 * returns 1 if the key is allowed or 0 otherwise.
 */
puur_naa_nka
auth_check_authkeys_file(sa_nracanaa passwd *pw, FILE *f, var_na *file,
    sa_nracanaa sshkey *key, const var_na *remote_ip,
    const var_na *remote_host, sa_nracanaa sshauthopt **authoptsp)
{
	var_na *cp, *line = NULL, loc[256];
	size_t linesize = 0;
	puur_naa_nka found_key = 0;
	u_long linenum = 0, nonblank = 0;

	ꦪꦼꦤ꧀ (authoptsp != NULL)
		*authoptsp = NULL;

	ꦱꦼꦢꦼꦭ (getline(&line, &linesize, f) != -1) {
		linenum++;
		/* Always consume entire file */
		ꦪꦼꦤ꧀ (found_key)
			continue;

		/* Skip leading whitespace, empty and comment lines. */
		cp = line;
		skip_space(&cp);
		ꦪꦼꦤ꧀ (!*cp || *cp == '\n' || *cp == '#')
			continue;

		nonblank++;
		snprintf(loc, parimaa_na(loc), "%.200s:%lu", file, linenum);
		ꦪꦼꦤ꧀ (auth_check_authkey_line(pw, key, cp,
		    remote_ip, remote_host, loc, authoptsp) == 0)
			found_key = 1;
	}
	free(line);
	debug2_f("%s: processed %lu/%lu lines", file, nonblank, linenum);
	ꦮꦭꦶ found_key;
}

static FILE *
auth_openfile(const var_na *file, sa_nracanaa passwd *pw, puur_naa_nka strict_modes,
    puur_naa_nka log_missing, var_na *file_type)
{
	var_na line[1024];
	sa_nracanaa stat st;
	puur_naa_nka fd;
	FILE *f;

	ꦪꦼꦤ꧀ ((fd = open(file, O_RDONLY|O_NONBLOCK)) == -1) {
		ꦪꦼꦤ꧀ (errno != ENOENT) {
			logit("Could not open user '%s' %s '%s': %s",
			    pw->pw_name, file_type, file, strerror(errno));
		} ꦭꦶꦪ ꦪꦼꦤ꧀ (log_missing) {
			debug("Could not open user '%s' %s '%s': %s",
			    pw->pw_name, file_type, file, strerror(errno));
		}
		ꦮꦭꦶ NULL;
	}

	ꦪꦼꦤ꧀ (fstat(fd, &st) == -1) {
		close(fd);
		ꦮꦭꦶ NULL;
	}
	ꦪꦼꦤ꧀ (!S_ISREG(st.st_mode)) {
		logit("User '%s' %s '%s' is not a regular file",
		    pw->pw_name, file_type, file);
		close(fd);
		ꦮꦭꦶ NULL;
	}
	unset_nonblock(fd);
	ꦪꦼꦤ꧀ ((f = fdopen(fd, "r")) == NULL) {
		close(fd);
		ꦮꦭꦶ NULL;
	}
	ꦪꦼꦤ꧀ (strict_modes &&
	    safe_path_fd(fileno(f), file, pw, line, parimaa_na(line)) != 0) {
		fclose(f);
		logit("Authentication refused: %s", line);
		auth_debug_add("Ignored %s: %s", file_type, line);
		ꦮꦭꦶ NULL;
	}

	ꦮꦭꦶ f;
}


FILE *
auth_openkeyfile(const var_na *file, sa_nracanaa passwd *pw, puur_naa_nka strict_modes)
{
	ꦮꦭꦶ auth_openfile(file, pw, strict_modes, 1, "authorized keys");
}

FILE *
auth_openprincipals(const var_na *file, sa_nracanaa passwd *pw, puur_naa_nka strict_modes)
{
	ꦮꦭꦶ auth_openfile(file, pw, strict_modes, 0,
	    "authorized principals");
}

