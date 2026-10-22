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

整数
auth_authorise_keyopts(struct passwd *pw, struct sshauthopt *opts,
    整数 allow_cert_authority, const char *remote_ip, const char *remote_host,
    const char *loc)
{
	time_t now = time(NULL);
	char buf[64];

	/*
	 * Check keys/principals file expiry time.
	 * NB. validity interval in certificate is handled elsewhere.
	 */
	如果 (opts->valid_before && now > 0 &&
	    opts->valid_before < (uint64_t)now) {
		format_absolute_time(opts->valid_before, buf, sizeof(buf));
		debug("%s: entry expired at %s", loc, buf);
		auth_debug_add("%s: entry expired at %s", loc, buf);
		返回 -1;
	}
	/* Consistency checks */
	如果 (opts->cert_principals != NULL && !opts->cert_authority) {
		debug("%s: principals on non-CA key", loc);
		auth_debug_add("%s: principals on non-CA key", loc);
		/* deny access */
		返回 -1;
	}
	/* cert-authority flag isn't valid in authorized_principals files */
	如果 (!allow_cert_authority && opts->cert_authority) {
		debug("%s: cert-authority flag invalid here", loc);
		auth_debug_add("%s: cert-authority flag invalid here", loc);
		/* deny access */
		返回 -1;
	}

	/* Perform from= checks */
	如果 (opts->required_from_host_keys != NULL) {
		switch (match_host_and_ip(remote_host, remote_ip,
		    opts->required_from_host_keys )) {
		case 1:
			/* Host name matches. */
			break;
		case -1:
		default:
			debug("%s: invalid from criteria", loc);
			auth_debug_add("%s: invalid from criteria", loc);
			/* FALLTHROUGH */
		case 0:
			logit("%s: Authentication tried for %.100s with "
			    "correct key but not from a permitted "
			    "host (host=%.200s, ip=%.200s, required=%.200s).",
			    loc, pw->pw_name, remote_host, remote_ip,
			    opts->required_from_host_keys);
			auth_debug_add("%s: Your host '%.200s' is not "
			    "permitted to use this key for login.",
			    loc, remote_host);
			/* deny access */
			返回 -1;
		}
	}
	/* Check source-address restriction from certificate */
	如果 (opts->required_from_host_cert != NULL) {
		switch (addr_match_cidr_list(remote_ip,
		    opts->required_from_host_cert)) {
		case 1:
			/* accepted */
			break;
		case -1:
		default:
			/* invalid */
			error("%s: Certificate source-address invalid", loc);
			/* FALLTHROUGH */
		case 0:
			logit("%s: Authentication tried for %.100s with valid "
			    "certificate but not from a permitted source "
			    "address (%.200s).", loc, pw->pw_name, remote_ip);
			auth_debug_add("%s: Your address '%.200s' is not "
			    "permitted to use this certificate for login.",
			    loc, remote_ip);
			返回 -1;
		}
	}
	/*
	 *
	 * XXX this is spammy. We should report remotely only for keys
	 *     that are successful in actual auth attempts, and not PK_OK
	 *     tests.
	 */
	auth_log_authopts(loc, opts, 1);

	返回 0;
}

static 整数
match_principals_option(const char *principal_list, struct sshkey_cert *cert)
{
	char *list, *olist, *entry;
	u_int i;

	olist = list = xstrdup(principal_list);
	为 (;;) {
		如果 ((entry = strsep(&list, ",")) == NULL || *entry == '\0')
			break;
		为 (i = 0; i < cert->nprincipals; i++) {
			如果 (strcmp(entry, cert->principals[i]) == 0) {
				debug3("matched principal from key i"
				    "options \"%.100s\"", entry);
				free(olist);
				返回 1;
			}
		}
	}
	free(olist);
	返回 0;
}

/*
 * Process a single authorized_principals format line. Returns 0 and sets
 * authoptsp is principal is authorised, -1 otherwise. "loc" is used as a
 * log preamble for file/line information.
 */
整数
auth_check_principals_line(char *cp, const struct sshkey_cert *cert,
    const char *loc, struct sshauthopt **authoptsp)
{
	u_int i, found = 0;
	char *ep, *line_opts;
	const char *reason = NULL;
	struct sshauthopt *opts = NULL;

	如果 (authoptsp != NULL)
		*authoptsp = NULL;

	/* Trim trailing whitespace. */
	ep = cp + strlen(cp) - 1;
	当 (ep > cp && (*ep == '\n' || *ep == ' ' || *ep == '\t'))
		*ep-- = '\0';

	/*
	 * If the line has internal whitespace then assume it has
	 * key options.
	 */
	line_opts = NULL;
	如果 ((ep = strrchr(cp, ' ')) != NULL ||
	    (ep = strrchr(cp, '\t')) != NULL) {
		为 (; *ep == ' ' || *ep == '\t'; ep++)
			;
		line_opts = cp;
		cp = ep;
	}
	如果 ((opts = sshauthopt_parse(line_opts, &reason)) == NULL) {
		debug("%s: bad principals options: %s", loc, reason);
		auth_debug_add("%s: bad principals options: %s", loc, reason);
		返回 -1;
	}
	/* Check principals in cert against those on line */
	为 (i = 0; i < cert->nprincipals; i++) {
		如果 (strcmp(cp, cert->principals[i]) != 0)
			continue;
		debug3("%s: matched principal \"%.100s\"",
		    loc, cert->principals[i]);
		found = 1;
	}
	如果 (found && authoptsp != NULL) {
		*authoptsp = opts;
		opts = NULL;
	}
	sshauthopt_free(opts);
	返回 found ? 0 : -1;
}

整数
auth_process_principals(FILE *f, const char *file,
    const struct sshkey_cert *cert, struct sshauthopt **authoptsp)
{
	char loc[256], *line = NULL, *cp, *ep;
	size_t linesize = 0;
	u_long linenum = 0, nonblank = 0;
	u_int found_principal = 0;

	如果 (authoptsp != NULL)
		*authoptsp = NULL;

	当 (getline(&line, &linesize, f) != -1) {
		linenum++;
		/* Always consume entire input */
		如果 (found_principal)
			continue;

		/* Skip leading whitespace. */
		为 (cp = line; *cp == ' ' || *cp == '\t'; cp++)
			;
		/* Skip blank and comment lines. */
		如果 ((ep = strchr(cp, '#')) != NULL)
			*ep = '\0';
		如果 (!*cp || *cp == '\n')
			continue;

		nonblank++;
		snprintf(loc, sizeof(loc), "%.200s:%lu", file, linenum);
		如果 (auth_check_principals_line(cp, cert, loc, authoptsp) == 0)
			found_principal = 1;
	}
	debug2_f("%s: processed %lu/%lu lines", file, nonblank, linenum);
	free(line);
	返回 found_principal;
}

/*
 * Check a single line of an authorized_keys-format file. Returns 0 if key
 * matches, -1 otherwise. Will return key/cert options via *authoptsp
 * on success. "loc" is used as file/line location in log messages.
 */
整数
auth_check_authkey_line(struct passwd *pw, struct sshkey *key,
    char *cp, const char *remote_ip, const char *remote_host, const char *loc,
    struct sshauthopt **authoptsp)
{
	整数 want_keytype = sshkey_is_cert(key) ? KEY_UNSPEC : key->type;
	struct sshkey *found = NULL;
	struct sshauthopt *keyopts = NULL, *certopts = NULL, *finalopts = NULL;
	char *key_options = NULL, *fp = NULL;
	const char *reason = NULL;
	整数 ret = -1;

	如果 (authoptsp != NULL)
		*authoptsp = NULL;

	如果 ((found = sshkey_new(want_keytype)) == NULL) {
		debug3_f("keytype %d failed", want_keytype);
		goto out;
	}

	/* XXX djm: peek at key type in line and skip if unwanted */

	如果 (sshkey_read(found, &cp) != 0) {
		/* no key?  check for options */
		debug2("%s: check options: '%s'", loc, cp);
		key_options = cp;
		如果 (sshkey_advance_past_options(&cp) != 0) {
			reason = "invalid key option string";
			goto fail_reason;
		}
		skip_space(&cp);
		如果 (sshkey_read(found, &cp) != 0) {
			/* still no key?  advance to next line*/
			debug2("%s: advance: '%s'", loc, cp);
			goto out;
		}
	}
	/* Parse key options now; we need to know if this is a CA key */
	如果 ((keyopts = sshauthopt_parse(key_options, &reason)) == NULL) {
		debug("%s: bad key options: %s", loc, reason);
		auth_debug_add("%s: bad key options: %s", loc, reason);
		goto out;
	}
	/* Ignore keys that don't match or incorrectly marked as CAs */
	如果 (sshkey_is_cert(key)) {
		/* Certificate; check signature key against CA */
		如果 (!sshkey_equal(found, key->cert->signature_key) ||
		    !keyopts->cert_authority)
			goto out;
	} 否则 {
		/* Plain key: check it against key found in file */
		如果 (!sshkey_equal(found, key) || keyopts->cert_authority)
			goto out;
	}

	/* We have a candidate key, perform authorisation checks */
	如果 ((fp = sshkey_fingerprint(found,
	    SSH_FP_HASH_DEFAULT, SSH_FP_DEFAULT)) == NULL)
		fatal_f("fingerprint failed");

	debug("%s: matching %s found: %s %s", loc,
	    sshkey_is_cert(key) ? "CA" : "key", sshkey_type(found), fp);

	如果 (auth_authorise_keyopts(pw, keyopts,
	    sshkey_is_cert(key), remote_ip, remote_host, loc) != 0) {
		reason = "Refused by key options";
		goto fail_reason;
	}
	/* That's all we need for plain keys. */
	如果 (!sshkey_is_cert(key)) {
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
	如果 ((certopts = sshauthopt_from_cert(key)) == NULL) {
		reason = "Invalid certificate options";
		goto cert_fail_reason;
	}
	如果 (auth_authorise_keyopts(pw, certopts, 0,
	    remote_ip, remote_host, loc) != 0) {
		reason = "Refused by certificate options";
		goto cert_fail_reason;
	}
	如果 ((finalopts = sshauthopt_merge(keyopts, certopts, &reason)) == NULL)
		goto cert_fail_reason;

	/*
	 * If the user has specified a list of principals as
	 * a key option, then prefer that list to matching
	 * their username in the certificate principals list.
	 */
	如果 (keyopts->cert_principals != NULL &&
	    !match_principals_option(keyopts->cert_principals, key->cert)) {
		reason = "Certificate does not contain an authorized principal";
		goto cert_fail_reason;
	}
	如果 (sshkey_cert_check_authority_now(key, 0, 0,
	    keyopts->cert_principals == NULL ? pw->pw_name : NULL,
	    &reason) != 0)
		goto cert_fail_reason;

	verbose("Accepted certificate ID \"%s\" (serial %llu) "
	    "signed by CA %s %s found at %s",
	    key->cert->key_id,
	    (unsigned long long)key->cert->serial,
	    sshkey_type(found), fp, loc);

 success:
	如果 (finalopts == NULL)
		fatal_f("internal error: missing options");
	如果 (authoptsp != NULL) {
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
	返回 ret;
}

/*
 * Checks whether key is allowed in authorized_keys-format file,
 * returns 1 if the key is allowed or 0 otherwise.
 */
整数
auth_check_authkeys_file(struct passwd *pw, FILE *f, char *file,
    struct sshkey *key, const char *remote_ip,
    const char *remote_host, struct sshauthopt **authoptsp)
{
	char *cp, *line = NULL, loc[256];
	size_t linesize = 0;
	整数 found_key = 0;
	u_long linenum = 0, nonblank = 0;

	如果 (authoptsp != NULL)
		*authoptsp = NULL;

	当 (getline(&line, &linesize, f) != -1) {
		linenum++;
		/* Always consume entire file */
		如果 (found_key)
			continue;

		/* Skip leading whitespace, empty and comment lines. */
		cp = line;
		skip_space(&cp);
		如果 (!*cp || *cp == '\n' || *cp == '#')
			continue;

		nonblank++;
		snprintf(loc, sizeof(loc), "%.200s:%lu", file, linenum);
		如果 (auth_check_authkey_line(pw, key, cp,
		    remote_ip, remote_host, loc, authoptsp) == 0)
			found_key = 1;
	}
	free(line);
	debug2_f("%s: processed %lu/%lu lines", file, nonblank, linenum);
	返回 found_key;
}

static FILE *
auth_openfile(const char *file, struct passwd *pw, 整数 strict_modes,
    整数 log_missing, char *file_type)
{
	char line[1024];
	struct stat st;
	整数 fd;
	FILE *f;

	如果 ((fd = open(file, O_RDONLY|O_NONBLOCK)) == -1) {
		如果 (errno != ENOENT) {
			logit("Could not open user '%s' %s '%s': %s",
			    pw->pw_name, file_type, file, strerror(errno));
		} 否则 如果 (log_missing) {
			debug("Could not open user '%s' %s '%s': %s",
			    pw->pw_name, file_type, file, strerror(errno));
		}
		返回 NULL;
	}

	如果 (fstat(fd, &st) == -1) {
		close(fd);
		返回 NULL;
	}
	如果 (!S_ISREG(st.st_mode)) {
		logit("User '%s' %s '%s' is not a regular file",
		    pw->pw_name, file_type, file);
		close(fd);
		返回 NULL;
	}
	unset_nonblock(fd);
	如果 ((f = fdopen(fd, "r")) == NULL) {
		close(fd);
		返回 NULL;
	}
	如果 (strict_modes &&
	    safe_path_fd(fileno(f), file, pw, line, sizeof(line)) != 0) {
		fclose(f);
		logit("Authentication refused: %s", line);
		auth_debug_add("Ignored %s: %s", file_type, line);
		返回 NULL;
	}

	返回 f;
}


FILE *
auth_openkeyfile(const char *file, struct passwd *pw, 整数 strict_modes)
{
	返回 auth_openfile(file, pw, strict_modes, 1, "authorized keys");
}

FILE *
auth_openprincipals(const char *file, struct passwd *pw, 整数 strict_modes)
{
	返回 auth_openfile(file, pw, strict_modes, 0,
	    "authorized principals");
}

