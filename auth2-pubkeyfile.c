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

#ضمن "includes.h"

#ضمن <sys/types.h>
#ضمن <sys/stat.h>

#ضمن <stdlib.h>
#ضمن <errno.h>
#ضمن <fcntl.h>
#ضمن <pwd.h>
#ضمن <stdio.h>
#ضمن <stdarg.h>
#ضمن <string.h>
#ضمن <time.h>
#ضمن <unistd.h>

#ضمن "ssh.h"
#ضمن "log.h"
#ضمن "misc.h"
#ضمن "sshkey.h"
#ضمن "digest.h"
#ضمن "hostfile.h"
#ضمن "auth.h"
#ضمن "auth-options.h"
#ضمن "authfile.h"
#ضمن "match.h"
#ضمن "ssherr.h"
#ضمن "xmalloc.h"

صحيح
auth_authorise_keyopts(بنية passwd *pw, بنية sshauthopt *opts,
    صحيح allow_cert_authority, ثابت حرف *remote_ip, ثابت حرف *remote_host,
    ثابت حرف *loc)
{
	time_t now = time(عدم);
	حرف buf[64];

	/*
	 * Check keys/principals file expiry time.
	 * NB. validity interval in certificate is handled elsewhere.
	 */
	إذا (opts->valid_before && now > 0 &&
	    opts->valid_before < (uint64_t)now) {
		format_absolute_ویلا(opts->valid_before, buf, حجم(buf));
		debug("%s: entry expired at %s", loc, buf);
		auth_debug_جوڑو("%s: entry expired at %s", loc, buf);
		أرجع -1;
	}
	/* Consistency checks */
	إذا (opts->cert_principals != عدم && !opts->cert_authority) {
		debug("%s: principals on non-CA key", loc);
		auth_debug_جوڑو("%s: principals on non-CA key", loc);
		/* deny access */
		أرجع -1;
	}
	/* cert-authority flag isn't valid in authorized_principals files */
	إذا (!allow_cert_authority && opts->cert_authority) {
		debug("%s: cert-authority flag invalid here", loc);
		auth_debug_جوڑو("%s: cert-authority flag invalid here", loc);
		/* deny access */
		أرجع -1;
	}

	/* Perform from= checks */
	إذا (opts->required_from_host_کلیدیں != عدم) {
		بدل (میل_host_and_ip(remote_host, remote_ip,
		    opts->required_from_host_کلیدیں )) {
		حالة 1:
			/* Host name matches. */
			اكسر;
		حالة -1:
		افتراضي:
			debug("%s: invalid from criteria", loc);
			auth_debug_جوڑو("%s: invalid from criteria", loc);
			/* FALLTHROUGH */
		حالة 0:
			logit("%s: Authentication tried for %.100s with "
			    "correct key but not from a permitted "
			    "host (host=%.200s, ip=%.200s, required=%.200s).",
			    loc, pw->pw_name, remote_host, remote_ip,
			    opts->required_from_host_کلیدیں);
			auth_debug_جوڑو("%s: Your host '%.200s' is not "
			    "permitted to use this key for login.",
			    loc, remote_host);
			/* deny access */
			أرجع -1;
		}
	}
	/* Check source-address restriction from certificate */
	إذا (opts->required_from_host_cert != عدم) {
		بدل (addr_میل_cidr_list(remote_ip,
		    opts->required_from_host_cert)) {
		حالة 1:
			/* accepted */
			اكسر;
		حالة -1:
		افتراضي:
			/* invalid */
			error("%s: Certificate source-address invalid", loc);
			/* FALLTHROUGH */
		حالة 0:
			logit("%s: Authentication tried for %.100s with valid "
			    "certificate but not from a permitted source "
			    "address (%.200s).", loc, pw->pw_name, remote_ip);
			auth_debug_جوڑو("%s: Your address '%.200s' is not "
			    "permitted to use this certificate for login.",
			    loc, remote_ip);
			أرجع -1;
		}
	}
	/*
	 *
	 * XXX this is spammy. We should report remotely only for keys
	 *     that are successful in actual auth attempts, and not PK_OK
	 *     tests.
	 */
	auth_log_authopts(loc, opts, 1);

	أرجع 0;
}

ساكن صحيح
میل_principals_option(ثابت حرف *principal_list, بنية sshkey_cert *cert)
{
	حرف *list, *olist, *اندراج;
	u_int i;

	olist = list = xstrdup(principal_list);
	لكل (;;) {
		إذا ((اندراج = strsep(&list, ",")) == عدم || *اندراج == '\0')
			اكسر;
		لكل (i = 0; i < cert->nprincipals; i++) {
			إذا (strcmp(اندراج, cert->principals[i]) == 0) {
				debug3("matched principal from key i"
				    "options \"%.100s\"", اندراج);
				حرر(olist);
				أرجع 1;
			}
		}
	}
	حرر(olist);
	أرجع 0;
}

/*
 * Process a single authorized_principals format line. Returns 0 and sets
 * authoptsp is principal is authorised, -1 otherwise. "loc" is used as a
 * log preamble for file/line information.
 */
صحيح
auth_check_principals_سطر(حرف *cp, ثابت بنية sshkey_cert *cert,
    ثابت حرف *loc, بنية sshauthopt **authoptsp)
{
	u_int i, لبھیا = 0;
	حرف *ep, *سطر_opts;
	ثابت حرف *reason = عدم;
	بنية sshauthopt *opts = عدم;

	إذا (authoptsp != عدم)
		*authoptsp = عدم;

	/* Trim trailing whitespace. */
	ep = cp + لڑی_لمبائی(cp) - 1;
	طالما (ep > cp && (*ep == '\n' || *ep == ' ' || *ep == '\t'))
		*ep-- = '\0';

	/*
	 * If the line has internal whitespace then assume it has
	 * key options.
	 */
	سطر_opts = عدم;
	إذا ((ep = strrchr(cp, ' ')) != عدم ||
	    (ep = strrchr(cp, '\t')) != عدم) {
		لكل (; *ep == ' ' || *ep == '\t'; ep++)
			;
		سطر_opts = cp;
		cp = ep;
	}
	إذا ((opts = sshauthopt_parse(سطر_opts, &reason)) == عدم) {
		debug("%s: bad principals options: %s", loc, reason);
		auth_debug_جوڑو("%s: bad principals options: %s", loc, reason);
		أرجع -1;
	}
	/* Check principals in cert against those on line */
	لكل (i = 0; i < cert->nprincipals; i++) {
		إذا (strcmp(cp, cert->principals[i]) != 0)
			استمر;
		debug3("%s: matched principal \"%.100s\"",
		    loc, cert->principals[i]);
		لبھیا = 1;
	}
	إذا (لبھیا && authoptsp != عدم) {
		*authoptsp = opts;
		opts = عدم;
	}
	sshauthopt_free(opts);
	أرجع لبھیا ? 0 : -1;
}

صحيح
auth_process_principals(FILE *f, ثابت حرف *file,
    ثابت بنية sshkey_cert *cert, بنية sshauthopt **authoptsp)
{
	حرف loc[256], *سطر = عدم, *cp, *ep;
	ناپ_t linesize = 0;
	u_long linenum = 0, nonblank = 0;
	u_int لبھیا_principal = 0;

	إذا (authoptsp != عدم)
		*authoptsp = عدم;

	طالما (getline(&سطر, &linesize, f) != -1) {
		linenum++;
		/* Always consume entire input */
		إذا (لبھیا_principal)
			استمر;

		/* Skip leading whitespace. */
		لكل (cp = سطر; *cp == ' ' || *cp == '\t'; cp++)
			;
		/* Skip blank and comment lines. */
		إذا ((ep = strchr(cp, '#')) != عدم)
			*ep = '\0';
		إذا (!*cp || *cp == '\n')
			استمر;

		nonblank++;
		snprintf(loc, حجم(loc), "%.200s:%lu", file, linenum);
		إذا (auth_check_principals_سطر(cp, cert, loc, authoptsp) == 0)
			لبھیا_principal = 1;
	}
	debug2_f("%s: processed %lu/%lu lines", file, nonblank, linenum);
	حرر(سطر);
	أرجع لبھیا_principal;
}

/*
 * Check a single line of an authorized_keys-format file. Returns 0 if key
 * matches, -1 otherwise. Will return key/cert options via *authoptsp
 * on success. "loc" is used as file/line location in log messages.
 */
صحيح
auth_check_authkey_سطر(بنية passwd *pw, بنية sshkey *کلید,
    حرف *cp, ثابت حرف *remote_ip, ثابت حرف *remote_host, ثابت حرف *loc,
    بنية sshauthopt **authoptsp)
{
	صحيح want_keytype = sshkey_is_cert(کلید) ? کلید_UNSPEC : کلید->type;
	بنية sshkey *لبھیا = عدم;
	بنية sshauthopt *keyopts = عدم, *certopts = عدم, *finalopts = عدم;
	حرف *کلید_options = عدم, *fp = عدم;
	ثابت حرف *reason = عدم;
	صحيح ret = -1;

	إذا (authoptsp != عدم)
		*authoptsp = عدم;

	إذا ((لبھیا = sshkey_new(want_keytype)) == عدم) {
		debug3_f("keytype %d failed", want_keytype);
		اذهب باہرلا;
	}

	/* XXX djm: peek at key type in line and skip if unwanted */

	إذا (sshkey_read(لبھیا, &cp) != 0) {
		/* no key?  check for options */
		debug2("%s: check options: '%s'", loc, cp);
		کلید_options = cp;
		إذا (sshkey_advance_past_options(&cp) != 0) {
			reason = "invalid key option string";
			اذهب fail_reason;
		}
		skip_space(&cp);
		إذا (sshkey_read(لبھیا, &cp) != 0) {
			/* still no key?  advance to next line*/
			debug2("%s: advance: '%s'", loc, cp);
			اذهب باہرلا;
		}
	}
	/* Parse key options now; we need to know if this is a CA key */
	إذا ((keyopts = sshauthopt_parse(کلید_options, &reason)) == عدم) {
		debug("%s: bad key options: %s", loc, reason);
		auth_debug_جوڑو("%s: bad key options: %s", loc, reason);
		اذهب باہرلا;
	}
	/* Ignore keys that don't match or incorrectly marked as CAs */
	إذا (sshkey_is_cert(کلید)) {
		/* Certificate; check signature key against CA */
		إذا (!sshkey_equal(لبھیا, کلید->cert->signature_کلید) ||
		    !keyopts->cert_authority)
			اذهب باہرلا;
	} وإلا {
		/* Plain key: check it against key found in file */
		إذا (!sshkey_equal(لبھیا, کلید) || keyopts->cert_authority)
			اذهب باہرلا;
	}

	/* We have a candidate key, perform authorisation checks */
	إذا ((fp = sshkey_fingerprint(لبھیا,
	    SSH_FP_HASH_DEFAULT, SSH_FP_DEFAULT)) == عدم)
		fatal_f("fingerprint failed");

	debug("%s: matching %s found: %s %s", loc,
	    sshkey_is_cert(کلید) ? "CA" : "key", sshkey_type(لبھیا), fp);

	إذا (auth_authorise_keyopts(pw, keyopts,
	    sshkey_is_cert(کلید), remote_ip, remote_host, loc) != 0) {
		reason = "Refused by key options";
		اذهب fail_reason;
	}
	/* That's all we need for plain keys. */
	إذا (!sshkey_is_cert(کلید)) {
		verbose("Accepted key %s %s found at %s",
		    sshkey_type(لبھیا), fp, loc);
		finalopts = keyopts;
		keyopts = عدم;
		اذهب success;
	}

	/*
	 * Additional authorisation for certificates.
	 */

	/* Parse and check options present in certificate */
	إذا ((certopts = sshauthopt_from_cert(کلید)) == عدم) {
		reason = "Invalid certificate options";
		اذهب cert_fail_reason;
	}
	إذا (auth_authorise_keyopts(pw, certopts, 0,
	    remote_ip, remote_host, loc) != 0) {
		reason = "Refused by certificate options";
		اذهب cert_fail_reason;
	}
	إذا ((finalopts = sshauthopt_ملاؤ(keyopts, certopts, &reason)) == عدم)
		اذهب cert_fail_reason;

	/*
	 * If the user has specified a list of principals as
	 * a key option, then prefer that list to matching
	 * their username in the certificate principals list.
	 */
	إذا (keyopts->cert_principals != عدم &&
	    !میل_principals_option(keyopts->cert_principals, کلید->cert)) {
		reason = "Certificate does not contain an authorized principal";
		اذهب cert_fail_reason;
	}
	إذا (sshkey_cert_check_authority_now(کلید, 0, 0,
	    keyopts->cert_principals == عدم ? pw->pw_name : عدم,
	    &reason) != 0)
		اذهب cert_fail_reason;

	verbose("Accepted certificate ID \"%s\" (serial %llu) "
	    "signed by CA %s %s found at %s",
	    کلید->cert->کلید_id,
	    (بنانشانی لما لما)کلید->cert->serial,
	    sshkey_type(لبھیا), fp, loc);

 success:
	إذا (finalopts == عدم)
		fatal_f("internal error: missing options");
	إذا (authoptsp != عدم) {
		*authoptsp = finalopts;
		finalopts = عدم;
	}
	/* success */
	ret = 0;
	اذهب باہرلا;

 cert_fail_reason:
	error("Refusing certificate ID \"%s\" serial=%llu "
	    "signed by %s CA %s via %s: %s", کلید->cert->کلید_id,
	    (بنانشانی لما لما)کلید->cert->serial,
	    sshkey_type(کلید->cert->signature_کلید), fp, loc, reason);
	auth_debug_جوڑو("Refused Certificate ID \"%s\" serial=%llu: %s",
	    کلید->cert->کلید_id, (بنانشانی لما لما)کلید->cert->serial, reason);
	اذهب باہرلا;

 fail_reason:
	error("%s at %s", reason, loc);
	auth_debug_جوڑو("%s", reason);
 باہرلا:
	حرر(fp);
	sshauthopt_free(keyopts);
	sshauthopt_free(certopts);
	sshauthopt_free(finalopts);
	sshkey_free(لبھیا);
	أرجع ret;
}

/*
 * Checks whether key is allowed in authorized_keys-format file,
 * returns 1 if the key is allowed or 0 otherwise.
 */
صحيح
auth_check_authkeys_file(بنية passwd *pw, FILE *f, حرف *file,
    بنية sshkey *کلید, ثابت حرف *remote_ip,
    ثابت حرف *remote_host, بنية sshauthopt **authoptsp)
{
	حرف *cp, *سطر = عدم, loc[256];
	ناپ_t linesize = 0;
	صحيح لبھیا_کلید = 0;
	u_long linenum = 0, nonblank = 0;

	إذا (authoptsp != عدم)
		*authoptsp = عدم;

	طالما (getline(&سطر, &linesize, f) != -1) {
		linenum++;
		/* Always consume entire file */
		إذا (لبھیا_کلید)
			استمر;

		/* Skip leading whitespace, empty and comment lines. */
		cp = سطر;
		skip_space(&cp);
		إذا (!*cp || *cp == '\n' || *cp == '#')
			استمر;

		nonblank++;
		snprintf(loc, حجم(loc), "%.200s:%lu", file, linenum);
		إذا (auth_check_authkey_سطر(pw, کلید, cp,
		    remote_ip, remote_host, loc, authoptsp) == 0)
			لبھیا_کلید = 1;
	}
	حرر(سطر);
	debug2_f("%s: processed %lu/%lu lines", file, nonblank, linenum);
	أرجع لبھیا_کلید;
}

ساكن FILE *
auth_openfile(ثابت حرف *file, بنية passwd *pw, صحيح strict_modes,
    صحيح log_missing, حرف *file_type)
{
	حرف سطر[1024];
	بنية stat st;
	صحيح fd;
	FILE *f;

	إذا ((fd = open(file, O_RDONLY|O_NONBLOCK)) == -1) {
		إذا (errno != ENOENT) {
			logit("Could not open user '%s' %s '%s': %s",
			    pw->pw_name, file_type, file, strerror(errno));
		} وإلا إذا (log_missing) {
			debug("Could not open user '%s' %s '%s': %s",
			    pw->pw_name, file_type, file, strerror(errno));
		}
		أرجع عدم;
	}

	إذا (fstat(fd, &st) == -1) {
		close(fd);
		أرجع عدم;
	}
	إذا (!S_ISREG(st.st_mode)) {
		logit("User '%s' %s '%s' is not a regular file",
		    pw->pw_name, file_type, file);
		close(fd);
		أرجع عدم;
	}
	unset_nonblock(fd);
	إذا ((f = fdopen(fd, "r")) == عدم) {
		close(fd);
		أرجع عدم;
	}
	إذا (strict_modes &&
	    محفوظ_رستہ_fd(fileno(f), file, pw, سطر, حجم(سطر)) != 0) {
		fclose(f);
		logit("Authentication refused: %s", سطر);
		auth_debug_جوڑو("Ignored %s: %s", file_type, سطر);
		أرجع عدم;
	}

	أرجع f;
}


FILE *
auth_openkeyfile(ثابت حرف *file, بنية passwd *pw, صحيح strict_modes)
{
	أرجع auth_openfile(file, pw, strict_modes, 1, "authorized keys");
}

FILE *
auth_openprincipals(ثابت حرف *file, بنية passwd *pw, صحيح strict_modes)
{
	أرجع auth_openfile(file, pw, strict_modes, 0,
	    "authorized principals");
}

