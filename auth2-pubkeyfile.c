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

පූර්ණ_සංඛ්‍යා
auth_authorise_keyopts(sa_nracanaa passwd *pw, sa_nracanaa sshauthopt *opts,
    පූර්ණ_සංඛ්‍යා allow_cert_authority, const var_na *remote_ip, const var_na *remote_host,
    const var_na *loc)
{
	time_t now = time(NULL);
	var_na buf[64];

	/*
	 * Check keys/principals file expiry time.
	 * NB. validity interval in certificate is handled elsewhere.
	 */
	නම් (opts->valid_before && now > 0 &&
	    opts->valid_before < (uint64_t)now) {
		format_absolute_time(opts->valid_before, buf, parimaa_na(buf));
		debug("%s: entry expired at %s", loc, buf);
		auth_debug_add("%s: entry expired at %s", loc, buf);
		ආපසු -1;
	}
	/* Consistency checks */
	නම් (opts->cert_principals != NULL && !opts->cert_authority) {
		debug("%s: principals on non-CA key", loc);
		auth_debug_add("%s: principals on non-CA key", loc);
		/* deny access */
		ආපසු -1;
	}
	/* cert-authority flag isn't valid in authorized_principals files */
	නම් (!allow_cert_authority && opts->cert_authority) {
		debug("%s: cert-authority flag invalid here", loc);
		auth_debug_add("%s: cert-authority flag invalid here", loc);
		/* deny access */
		ආපසු -1;
	}

	/* Perform from= checks */
	නම් (opts->required_from_host_keys != NULL) {
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
			ආපසු -1;
		}
	}
	/* Check source-address restriction from certificate */
	නම් (opts->required_from_host_cert != NULL) {
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
			ආපසු -1;
		}
	}
	/*
	 *
	 * XXX this is spammy. We should report remotely only for keys
	 *     that are successful in actual auth attempts, and not PK_OK
	 *     tests.
	 */
	auth_log_authopts(loc, opts, 1);

	ආපසු 0;
}

static පූර්ණ_සංඛ්‍යා
match_principals_option(const var_na *principal_list, sa_nracanaa sshkey_cert *cert)
{
	var_na *list, *olist, *entry;
	u_int i;

	olist = list = xstrdup(principal_list);
	සඳහා (;;) {
		නම් ((entry = strsep(&list, ",")) == NULL || *entry == '\0')
			bha_nga;
		සඳහා (i = 0; i < cert->nprincipals; i++) {
			නම් (strcmp(entry, cert->principals[i]) == 0) {
				debug3("matched principal from key i"
				    "options \"%.100s\"", entry);
				free(olist);
				ආපසු 1;
			}
		}
	}
	free(olist);
	ආපසු 0;
}

/*
 * Process a single authorized_principals format line. Returns 0 and sets
 * authoptsp is principal is authorised, -1 otherwise. "loc" is used as a
 * log preamble for file/line information.
 */
පූර්ණ_සංඛ්‍යා
auth_check_principals_line(var_na *cp, const sa_nracanaa sshkey_cert *cert,
    const var_na *loc, sa_nracanaa sshauthopt **authoptsp)
{
	u_int i, found = 0;
	var_na *ep, *line_opts;
	const var_na *reason = NULL;
	sa_nracanaa sshauthopt *opts = NULL;

	නම් (authoptsp != NULL)
		*authoptsp = NULL;

	/* Trim trailing whitespace. */
	ep = cp + strlen(cp) - 1;
	අතරතුර (ep > cp && (*ep == '\n' || *ep == ' ' || *ep == '\t'))
		*ep-- = '\0';

	/*
	 * If the line has internal whitespace then assume it has
	 * key options.
	 */
	line_opts = NULL;
	නම් ((ep = strrchr(cp, ' ')) != NULL ||
	    (ep = strrchr(cp, '\t')) != NULL) {
		සඳහා (; *ep == ' ' || *ep == '\t'; ep++)
			;
		line_opts = cp;
		cp = ep;
	}
	නම් ((opts = sshauthopt_parse(line_opts, &reason)) == NULL) {
		debug("%s: bad principals options: %s", loc, reason);
		auth_debug_add("%s: bad principals options: %s", loc, reason);
		ආපසු -1;
	}
	/* Check principals in cert against those on line */
	සඳහා (i = 0; i < cert->nprincipals; i++) {
		නම් (strcmp(cp, cert->principals[i]) != 0)
			continue;
		debug3("%s: matched principal \"%.100s\"",
		    loc, cert->principals[i]);
		found = 1;
	}
	නම් (found && authoptsp != NULL) {
		*authoptsp = opts;
		opts = NULL;
	}
	sshauthopt_free(opts);
	ආපසු found ? 0 : -1;
}

පූර්ණ_සංඛ්‍යා
auth_process_principals(FILE *f, const var_na *file,
    const sa_nracanaa sshkey_cert *cert, sa_nracanaa sshauthopt **authoptsp)
{
	var_na loc[256], *line = NULL, *cp, *ep;
	size_t linesize = 0;
	u_long linenum = 0, nonblank = 0;
	u_int found_principal = 0;

	නම් (authoptsp != NULL)
		*authoptsp = NULL;

	අතරතුර (getline(&line, &linesize, f) != -1) {
		linenum++;
		/* Always consume entire input */
		නම් (found_principal)
			continue;

		/* Skip leading whitespace. */
		සඳහා (cp = line; *cp == ' ' || *cp == '\t'; cp++)
			;
		/* Skip blank and comment lines. */
		නම් ((ep = strchr(cp, '#')) != NULL)
			*ep = '\0';
		නම් (!*cp || *cp == '\n')
			continue;

		nonblank++;
		snprintf(loc, parimaa_na(loc), "%.200s:%lu", file, linenum);
		නම් (auth_check_principals_line(cp, cert, loc, authoptsp) == 0)
			found_principal = 1;
	}
	debug2_f("%s: processed %lu/%lu lines", file, nonblank, linenum);
	free(line);
	ආපසු found_principal;
}

/*
 * Check a single line of an authorized_keys-format file. Returns 0 if key
 * matches, -1 otherwise. Will return key/cert options via *authoptsp
 * on success. "loc" is used as file/line location in log messages.
 */
පූර්ණ_සංඛ්‍යා
auth_check_authkey_line(sa_nracanaa passwd *pw, sa_nracanaa sshkey *key,
    var_na *cp, const var_na *remote_ip, const var_na *remote_host, const var_na *loc,
    sa_nracanaa sshauthopt **authoptsp)
{
	පූර්ණ_සංඛ්‍යා want_keytype = sshkey_is_cert(key) ? KEY_UNSPEC : key->type;
	sa_nracanaa sshkey *found = NULL;
	sa_nracanaa sshauthopt *keyopts = NULL, *certopts = NULL, *finalopts = NULL;
	var_na *key_options = NULL, *fp = NULL;
	const var_na *reason = NULL;
	පූර්ණ_සංඛ්‍යා ret = -1;

	නම් (authoptsp != NULL)
		*authoptsp = NULL;

	නම් ((found = sshkey_new(want_keytype)) == NULL) {
		debug3_f("keytype %d failed", want_keytype);
		goto out;
	}

	/* XXX djm: peek at key type in line and skip if unwanted */

	නම් (sshkey_read(found, &cp) != 0) {
		/* no key?  check for options */
		debug2("%s: check options: '%s'", loc, cp);
		key_options = cp;
		නම් (sshkey_advance_past_options(&cp) != 0) {
			reason = "invalid key option string";
			goto fail_reason;
		}
		skip_space(&cp);
		නම් (sshkey_read(found, &cp) != 0) {
			/* still no key?  advance to next line*/
			debug2("%s: advance: '%s'", loc, cp);
			goto out;
		}
	}
	/* Parse key options now; we need to know if this is a CA key */
	නම් ((keyopts = sshauthopt_parse(key_options, &reason)) == NULL) {
		debug("%s: bad key options: %s", loc, reason);
		auth_debug_add("%s: bad key options: %s", loc, reason);
		goto out;
	}
	/* Ignore keys that don't match or incorrectly marked as CAs */
	නම් (sshkey_is_cert(key)) {
		/* Certificate; check signature key against CA */
		නම් (!sshkey_equal(found, key->cert->signature_key) ||
		    !keyopts->cert_authority)
			goto out;
	} නැතහොත් {
		/* Plain key: check it against key found in file */
		නම් (!sshkey_equal(found, key) || keyopts->cert_authority)
			goto out;
	}

	/* We have a candidate key, perform authorisation checks */
	නම් ((fp = sshkey_fingerprint(found,
	    SSH_FP_HASH_DEFAULT, SSH_FP_DEFAULT)) == NULL)
		fatal_f("fingerprint failed");

	debug("%s: matching %s found: %s %s", loc,
	    sshkey_is_cert(key) ? "CA" : "key", sshkey_type(found), fp);

	නම් (auth_authorise_keyopts(pw, keyopts,
	    sshkey_is_cert(key), remote_ip, remote_host, loc) != 0) {
		reason = "Refused by key options";
		goto fail_reason;
	}
	/* That's all we need for plain keys. */
	නම් (!sshkey_is_cert(key)) {
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
	නම් ((certopts = sshauthopt_from_cert(key)) == NULL) {
		reason = "Invalid certificate options";
		goto cert_fail_reason;
	}
	නම් (auth_authorise_keyopts(pw, certopts, 0,
	    remote_ip, remote_host, loc) != 0) {
		reason = "Refused by certificate options";
		goto cert_fail_reason;
	}
	නම් ((finalopts = sshauthopt_merge(keyopts, certopts, &reason)) == NULL)
		goto cert_fail_reason;

	/*
	 * If the user has specified a list of principals as
	 * a key option, then prefer that list to matching
	 * their username in the certificate principals list.
	 */
	නම් (keyopts->cert_principals != NULL &&
	    !match_principals_option(keyopts->cert_principals, key->cert)) {
		reason = "Certificate does not contain an authorized principal";
		goto cert_fail_reason;
	}
	නම් (sshkey_cert_check_authority_now(key, 0, 0,
	    keyopts->cert_principals == NULL ? pw->pw_name : NULL,
	    &reason) != 0)
		goto cert_fail_reason;

	verbose("Accepted certificate ID \"%s\" (serial %llu) "
	    "signed by CA %s %s found at %s",
	    key->cert->key_id,
	    (unsigned long long)key->cert->serial,
	    sshkey_type(found), fp, loc);

 success:
	නම් (finalopts == NULL)
		fatal_f("internal error: missing options");
	නම් (authoptsp != NULL) {
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
	ආපසු ret;
}

/*
 * Checks whether key is allowed in authorized_keys-format file,
 * returns 1 if the key is allowed or 0 otherwise.
 */
පූර්ණ_සංඛ්‍යා
auth_check_authkeys_file(sa_nracanaa passwd *pw, FILE *f, var_na *file,
    sa_nracanaa sshkey *key, const var_na *remote_ip,
    const var_na *remote_host, sa_nracanaa sshauthopt **authoptsp)
{
	var_na *cp, *line = NULL, loc[256];
	size_t linesize = 0;
	පූර්ණ_සංඛ්‍යා found_key = 0;
	u_long linenum = 0, nonblank = 0;

	නම් (authoptsp != NULL)
		*authoptsp = NULL;

	අතරතුර (getline(&line, &linesize, f) != -1) {
		linenum++;
		/* Always consume entire file */
		නම් (found_key)
			continue;

		/* Skip leading whitespace, empty and comment lines. */
		cp = line;
		skip_space(&cp);
		නම් (!*cp || *cp == '\n' || *cp == '#')
			continue;

		nonblank++;
		snprintf(loc, parimaa_na(loc), "%.200s:%lu", file, linenum);
		නම් (auth_check_authkey_line(pw, key, cp,
		    remote_ip, remote_host, loc, authoptsp) == 0)
			found_key = 1;
	}
	free(line);
	debug2_f("%s: processed %lu/%lu lines", file, nonblank, linenum);
	ආපසු found_key;
}

static FILE *
auth_openfile(const var_na *file, sa_nracanaa passwd *pw, පූර්ණ_සංඛ්‍යා strict_modes,
    පූර්ණ_සංඛ්‍යා log_missing, var_na *file_type)
{
	var_na line[1024];
	sa_nracanaa stat st;
	පූර්ණ_සංඛ්‍යා fd;
	FILE *f;

	නම් ((fd = open(file, O_RDONLY|O_NONBLOCK)) == -1) {
		නම් (errno != ENOENT) {
			logit("Could not open user '%s' %s '%s': %s",
			    pw->pw_name, file_type, file, strerror(errno));
		} නැතහොත් නම් (log_missing) {
			debug("Could not open user '%s' %s '%s': %s",
			    pw->pw_name, file_type, file, strerror(errno));
		}
		ආපසු NULL;
	}

	නම් (fstat(fd, &st) == -1) {
		close(fd);
		ආපසු NULL;
	}
	නම් (!S_ISREG(st.st_mode)) {
		logit("User '%s' %s '%s' is not a regular file",
		    pw->pw_name, file_type, file);
		close(fd);
		ආපසු NULL;
	}
	unset_nonblock(fd);
	නම් ((f = fdopen(fd, "r")) == NULL) {
		close(fd);
		ආපසු NULL;
	}
	නම් (strict_modes &&
	    safe_path_fd(fileno(f), file, pw, line, parimaa_na(line)) != 0) {
		fclose(f);
		logit("Authentication refused: %s", line);
		auth_debug_add("Ignored %s: %s", file_type, line);
		ආපසු NULL;
	}

	ආපසු f;
}


FILE *
auth_openkeyfile(const var_na *file, sa_nracanaa passwd *pw, පූර්ණ_සංඛ්‍යා strict_modes)
{
	ආපසු auth_openfile(file, pw, strict_modes, 1, "authorized keys");
}

FILE *
auth_openprincipals(const var_na *file, sa_nracanaa passwd *pw, පූර්ණ_සංඛ්‍යා strict_modes)
{
	ආපසු auth_openfile(file, pw, strict_modes, 0,
	    "authorized principals");
}

