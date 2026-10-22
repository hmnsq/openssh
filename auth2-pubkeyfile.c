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

#شامل "includes.h"

#شامل <sys/types.h>
#شامل <sys/stat.h>

#شامل <stdlib.h>
#شامل <errno.h>
#شامل <fcntl.h>
#شامل <pwd.h>
#شامل <stdio.h>
#شامل <stdarg.h>
#شامل <string.h>
#شامل <time.h>
#شامل <unistd.h>

#شامل "ssh.h"
#شامل "log.h"
#شامل "misc.h"
#شامل "sshkey.h"
#شامل "digest.h"
#شامل "hostfile.h"
#شامل "auth.h"
#شامل "auth-options.h"
#شامل "authfile.h"
#شامل "match.h"
#شامل "ssherr.h"
#شامل "xmalloc.h"

صحیح
auth_authorise_keyopts(ساخت passwd *pw, ساخت sshauthopt *opts,
    صحیح allow_cert_authority, ثابت حرف *remote_ip, ثابت حرف *remote_host,
    ثابت حرف *loc)
{
	time_t now = time(تہی);
	حرف buf[64];

	/*
	 * Check keys/principals file expiry time.
	 * NB. validity interval in certificate is handled elsewhere.
	 */
	اگر (opts->valid_before && now > 0 &&
	    opts->valid_before < (uint64_t)now) {
		format_absolute_وقت(opts->valid_before, buf, حجم(buf));
		debug("%s: entry expired at %s", loc, buf);
		auth_debug_جوڑو("%s: entry expired at %s", loc, buf);
		واپس -1;
	}
	/* Consistency checks */
	اگر (opts->cert_principals != تہی && !opts->cert_authority) {
		debug("%s: principals on non-CA key", loc);
		auth_debug_جوڑو("%s: principals on non-CA key", loc);
		/* deny access */
		واپس -1;
	}
	/* cert-authority flag isn't valid in authorized_principals files */
	اگر (!allow_cert_authority && opts->cert_authority) {
		debug("%s: cert-authority flag invalid here", loc);
		auth_debug_جوڑو("%s: cert-authority flag invalid here", loc);
		/* deny access */
		واپس -1;
	}

	/* Perform from= checks */
	اگر (opts->required_from_host_کلیدیں != تہی) {
		انتخاب (مطابقت_host_and_ip(remote_host, remote_ip,
		    opts->required_from_host_کلیدیں )) {
		حالت 1:
			/* Host name matches. */
			توڑو;
		حالت -1:
		طےشدہ:
			debug("%s: invalid from criteria", loc);
			auth_debug_جوڑو("%s: invalid from criteria", loc);
			/* FALLTHROUGH */
		حالت 0:
			logit("%s: Authentication tried for %.100s with "
			    "correct key but not from a permitted "
			    "host (host=%.200s, ip=%.200s, required=%.200s).",
			    loc, pw->pw_name, remote_host, remote_ip,
			    opts->required_from_host_کلیدیں);
			auth_debug_جوڑو("%s: Your host '%.200s' is not "
			    "permitted to use this key for login.",
			    loc, remote_host);
			/* deny access */
			واپس -1;
		}
	}
	/* Check source-address restriction from certificate */
	اگر (opts->required_from_host_cert != تہی) {
		انتخاب (addr_مطابقت_cidr_list(remote_ip,
		    opts->required_from_host_cert)) {
		حالت 1:
			/* accepted */
			توڑو;
		حالت -1:
		طےشدہ:
			/* invalid */
			error("%s: Certificate source-address invalid", loc);
			/* FALLTHROUGH */
		حالت 0:
			logit("%s: Authentication tried for %.100s with valid "
			    "certificate but not from a permitted source "
			    "address (%.200s).", loc, pw->pw_name, remote_ip);
			auth_debug_جوڑو("%s: Your address '%.200s' is not "
			    "permitted to use this certificate for login.",
			    loc, remote_ip);
			واپس -1;
		}
	}
	/*
	 *
	 * XXX this is spammy. We should report remotely only for keys
	 *     that are successful in actual auth attempts, and not PK_OK
	 *     tests.
	 */
	auth_log_authopts(loc, opts, 1);

	واپس 0;
}

ساکن صحیح
مطابقت_principals_option(ثابت حرف *principal_list, ساخت sshkey_cert *cert)
{
	حرف *list, *olist, *اندراج_2;
	u_int i;

	olist = list = xstrdup(principal_list);
	برائے (;;) {
		اگر ((اندراج_2 = strsep(&list, ",")) == تہی || *اندراج_2 == '\0')
			توڑو;
		برائے (i = 0; i < cert->nprincipals; i++) {
			اگر (strcmp(اندراج_2, cert->principals[i]) == 0) {
				debug3("matched principal from key i"
				    "options \"%.100s\"", اندراج_2);
				آزاد(olist);
				واپس 1;
			}
		}
	}
	آزاد(olist);
	واپس 0;
}

/*
 * Process a single authorized_principals format line. Returns 0 and sets
 * authoptsp is principal is authorised, -1 otherwise. "loc" is used as a
 * log preamble for file/line information.
 */
صحیح
auth_check_principals_سطر(حرف *cp, ثابت ساخت sshkey_cert *cert,
    ثابت حرف *loc, ساخت sshauthopt **authoptsp)
{
	u_int i, ملا = 0;
	حرف *ep, *سطر_opts;
	ثابت حرف *reason = تہی;
	ساخت sshauthopt *opts = تہی;

	اگر (authoptsp != تہی)
		*authoptsp = تہی;

	/* Trim trailing whitespace. */
	ep = cp + لڑی_لمبائی(cp) - 1;
	جب (ep > cp && (*ep == '\n' || *ep == ' ' || *ep == '\t'))
		*ep-- = '\0';

	/*
	 * If the line has internal whitespace then assume it has
	 * key options.
	 */
	سطر_opts = تہی;
	اگر ((ep = strrchr(cp, ' ')) != تہی ||
	    (ep = strrchr(cp, '\t')) != تہی) {
		برائے (; *ep == ' ' || *ep == '\t'; ep++)
			;
		سطر_opts = cp;
		cp = ep;
	}
	اگر ((opts = sshauthopt_parse(سطر_opts, &reason)) == تہی) {
		debug("%s: bad principals options: %s", loc, reason);
		auth_debug_جوڑو("%s: bad principals options: %s", loc, reason);
		واپس -1;
	}
	/* Check principals in cert against those on line */
	برائے (i = 0; i < cert->nprincipals; i++) {
		اگر (strcmp(cp, cert->principals[i]) != 0)
			جاری;
		debug3("%s: matched principal \"%.100s\"",
		    loc, cert->principals[i]);
		ملا = 1;
	}
	اگر (ملا && authoptsp != تہی) {
		*authoptsp = opts;
		opts = تہی;
	}
	sshauthopt_free(opts);
	واپس ملا ? 0 : -1;
}

صحیح
auth_process_principals(FILE *f, ثابت حرف *file,
    ثابت ساخت sshkey_cert *cert, ساخت sshauthopt **authoptsp)
{
	حرف loc[256], *سطر = تہی, *cp, *ep;
	سائز_t linesize = 0;
	u_long linenum = 0, nonblank = 0;
	u_int ملا_principal = 0;

	اگر (authoptsp != تہی)
		*authoptsp = تہی;

	جب (getline(&سطر, &linesize, f) != -1) {
		linenum++;
		/* Always consume entire input */
		اگر (ملا_principal)
			جاری;

		/* Skip leading whitespace. */
		برائے (cp = سطر; *cp == ' ' || *cp == '\t'; cp++)
			;
		/* Skip blank and comment lines. */
		اگر ((ep = strchr(cp, '#')) != تہی)
			*ep = '\0';
		اگر (!*cp || *cp == '\n')
			جاری;

		nonblank++;
		snprintf(loc, حجم(loc), "%.200s:%lu", file, linenum);
		اگر (auth_check_principals_سطر(cp, cert, loc, authoptsp) == 0)
			ملا_principal = 1;
	}
	debug2_f("%s: processed %lu/%lu lines", file, nonblank, linenum);
	آزاد(سطر);
	واپس ملا_principal;
}

/*
 * Check a single line of an authorized_keys-format file. Returns 0 if key
 * matches, -1 otherwise. Will return key/cert options via *authoptsp
 * on success. "loc" is used as file/line location in log messages.
 */
صحیح
auth_check_authkey_سطر(ساخت passwd *pw, ساخت sshkey *کلید,
    حرف *cp, ثابت حرف *remote_ip, ثابت حرف *remote_host, ثابت حرف *loc,
    ساخت sshauthopt **authoptsp)
{
	صحیح want_keytype = sshkey_is_cert(کلید) ? کلید_UNSPEC : کلید->type;
	ساخت sshkey *ملا = تہی;
	ساخت sshauthopt *keyopts = تہی, *certopts = تہی, *finalopts = تہی;
	حرف *کلید_options = تہی, *fp = تہی;
	ثابت حرف *reason = تہی;
	صحیح ret = -1;

	اگر (authoptsp != تہی)
		*authoptsp = تہی;

	اگر ((ملا = sshkey_new(want_keytype)) == تہی) {
		debug3_f("keytype %d failed", want_keytype);
		جاؤ برآمد;
	}

	/* XXX djm: peek at key type in line and skip if unwanted */

	اگر (sshkey_read(ملا, &cp) != 0) {
		/* no key?  check for options */
		debug2("%s: check options: '%s'", loc, cp);
		کلید_options = cp;
		اگر (sshkey_advance_past_options(&cp) != 0) {
			reason = "invalid key option string";
			جاؤ fail_reason;
		}
		skip_space(&cp);
		اگر (sshkey_read(ملا, &cp) != 0) {
			/* still no key?  advance to next line*/
			debug2("%s: advance: '%s'", loc, cp);
			جاؤ برآمد;
		}
	}
	/* Parse key options now; we need to know if this is a CA key */
	اگر ((keyopts = sshauthopt_parse(کلید_options, &reason)) == تہی) {
		debug("%s: bad key options: %s", loc, reason);
		auth_debug_جوڑو("%s: bad key options: %s", loc, reason);
		جاؤ برآمد;
	}
	/* Ignore keys that don't match or incorrectly marked as CAs */
	اگر (sshkey_is_cert(کلید)) {
		/* Certificate; check signature key against CA */
		اگر (!sshkey_equal(ملا, کلید->cert->signature_کلید) ||
		    !keyopts->cert_authority)
			جاؤ برآمد;
	} ورنہ {
		/* Plain key: check it against key found in file */
		اگر (!sshkey_equal(ملا, کلید) || keyopts->cert_authority)
			جاؤ برآمد;
	}

	/* We have a candidate key, perform authorisation checks */
	اگر ((fp = sshkey_fingerprint(ملا,
	    SSH_FP_HASH_DEFAULT, SSH_FP_DEFAULT)) == تہی)
		fatal_f("fingerprint failed");

	debug("%s: matching %s found: %s %s", loc,
	    sshkey_is_cert(کلید) ? "CA" : "key", sshkey_type(ملا), fp);

	اگر (auth_authorise_keyopts(pw, keyopts,
	    sshkey_is_cert(کلید), remote_ip, remote_host, loc) != 0) {
		reason = "Refused by key options";
		جاؤ fail_reason;
	}
	/* That's all we need for plain keys. */
	اگر (!sshkey_is_cert(کلید)) {
		verbose("Accepted key %s %s found at %s",
		    sshkey_type(ملا), fp, loc);
		finalopts = keyopts;
		keyopts = تہی;
		جاؤ success;
	}

	/*
	 * Additional authorisation for certificates.
	 */

	/* Parse and check options present in certificate */
	اگر ((certopts = sshauthopt_from_cert(کلید)) == تہی) {
		reason = "Invalid certificate options";
		جاؤ cert_fail_reason;
	}
	اگر (auth_authorise_keyopts(pw, certopts, 0,
	    remote_ip, remote_host, loc) != 0) {
		reason = "Refused by certificate options";
		جاؤ cert_fail_reason;
	}
	اگر ((finalopts = sshauthopt_ملاؤ(keyopts, certopts, &reason)) == تہی)
		جاؤ cert_fail_reason;

	/*
	 * If the user has specified a list of principals as
	 * a key option, then prefer that list to matching
	 * their username in the certificate principals list.
	 */
	اگر (keyopts->cert_principals != تہی &&
	    !مطابقت_principals_option(keyopts->cert_principals, کلید->cert)) {
		reason = "Certificate does not contain an authorized principal";
		جاؤ cert_fail_reason;
	}
	اگر (sshkey_cert_check_authority_now(کلید, 0, 0,
	    keyopts->cert_principals == تہی ? pw->pw_name : تہی,
	    &reason) != 0)
		جاؤ cert_fail_reason;

	verbose("Accepted certificate ID \"%s\" (serial %llu) "
	    "signed by CA %s %s found at %s",
	    کلید->cert->کلید_id,
	    (غیرعلامتی طویل طویل)کلید->cert->serial,
	    sshkey_type(ملا), fp, loc);

 success:
	اگر (finalopts == تہی)
		fatal_f("internal error: missing options");
	اگر (authoptsp != تہی) {
		*authoptsp = finalopts;
		finalopts = تہی;
	}
	/* success */
	ret = 0;
	جاؤ برآمد;

 cert_fail_reason:
	error("Refusing certificate ID \"%s\" serial=%llu "
	    "signed by %s CA %s via %s: %s", کلید->cert->کلید_id,
	    (غیرعلامتی طویل طویل)کلید->cert->serial,
	    sshkey_type(کلید->cert->signature_کلید), fp, loc, reason);
	auth_debug_جوڑو("Refused Certificate ID \"%s\" serial=%llu: %s",
	    کلید->cert->کلید_id, (غیرعلامتی طویل طویل)کلید->cert->serial, reason);
	جاؤ برآمد;

 fail_reason:
	error("%s at %s", reason, loc);
	auth_debug_جوڑو("%s", reason);
 برآمد:
	آزاد(fp);
	sshauthopt_free(keyopts);
	sshauthopt_free(certopts);
	sshauthopt_free(finalopts);
	sshkey_free(ملا);
	واپس ret;
}

/*
 * Checks whether key is allowed in authorized_keys-format file,
 * returns 1 if the key is allowed or 0 otherwise.
 */
صحیح
auth_check_authkeys_file(ساخت passwd *pw, FILE *f, حرف *file,
    ساخت sshkey *کلید, ثابت حرف *remote_ip,
    ثابت حرف *remote_host, ساخت sshauthopt **authoptsp)
{
	حرف *cp, *سطر = تہی, loc[256];
	سائز_t linesize = 0;
	صحیح ملا_کلید = 0;
	u_long linenum = 0, nonblank = 0;

	اگر (authoptsp != تہی)
		*authoptsp = تہی;

	جب (getline(&سطر, &linesize, f) != -1) {
		linenum++;
		/* Always consume entire file */
		اگر (ملا_کلید)
			جاری;

		/* Skip leading whitespace, empty and comment lines. */
		cp = سطر;
		skip_space(&cp);
		اگر (!*cp || *cp == '\n' || *cp == '#')
			جاری;

		nonblank++;
		snprintf(loc, حجم(loc), "%.200s:%lu", file, linenum);
		اگر (auth_check_authkey_سطر(pw, کلید, cp,
		    remote_ip, remote_host, loc, authoptsp) == 0)
			ملا_کلید = 1;
	}
	آزاد(سطر);
	debug2_f("%s: processed %lu/%lu lines", file, nonblank, linenum);
	واپس ملا_کلید;
}

ساکن FILE *
auth_openfile(ثابت حرف *file, ساخت passwd *pw, صحیح strict_modes,
    صحیح log_missing, حرف *file_type)
{
	حرف سطر[1024];
	ساخت stat st;
	صحیح fd;
	FILE *f;

	اگر ((fd = open(file, O_RDONLY|O_NONBLOCK)) == -1) {
		اگر (errno != ENOENT) {
			logit("Could not open user '%s' %s '%s': %s",
			    pw->pw_name, file_type, file, strerror(errno));
		} ورنہ اگر (log_missing) {
			debug("Could not open user '%s' %s '%s': %s",
			    pw->pw_name, file_type, file, strerror(errno));
		}
		واپس تہی;
	}

	اگر (fstat(fd, &st) == -1) {
		close(fd);
		واپس تہی;
	}
	اگر (!S_ISREG(st.st_mode)) {
		logit("User '%s' %s '%s' is not a regular file",
		    pw->pw_name, file_type, file);
		close(fd);
		واپس تہی;
	}
	unset_nonblock(fd);
	اگر ((f = fdopen(fd, "r")) == تہی) {
		close(fd);
		واپس تہی;
	}
	اگر (strict_modes &&
	    محفوظ_راستہ_fd(fileno(f), file, pw, سطر, حجم(سطر)) != 0) {
		fclose(f);
		logit("Authentication refused: %s", سطر);
		auth_debug_جوڑو("Ignored %s: %s", file_type, سطر);
		واپس تہی;
	}

	واپس f;
}


FILE *
auth_openkeyfile(ثابت حرف *file, ساخت passwd *pw, صحیح strict_modes)
{
	واپس auth_openfile(file, pw, strict_modes, 1, "authorized keys");
}

FILE *
auth_openprincipals(ثابت حرف *file, ساخت passwd *pw, صحیح strict_modes)
{
	واپس auth_openfile(file, pw, strict_modes, 0,
	    "authorized principals");
}

