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

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <sys/stat.h>

#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <errno.h>
#అన్తర్భావ <fcntl.h>
#అన్తర్భావ <pwd.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <stdarg.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <time.h>
#అన్తర్భావ <unistd.h>

#అన్తర్భావ "ssh.h"
#అన్తర్భావ "log.h"
#అన్తర్భావ "misc.h"
#అన్తర్భావ "sshkey.h"
#అన్తర్భావ "digest.h"
#అన్తర్భావ "hostfile.h"
#అన్తర్భావ "auth.h"
#అన్తర్భావ "auth-options.h"
#అన్తర్భావ "authfile.h"
#అన్తర్భావ "match.h"
#అన్తర్భావ "ssherr.h"
#అన్తర్భావ "xmalloc.h"

పూర్ణాంకం
auth_authorise_keyopts(నిర్మాణం passwd *pw, నిర్మాణం sshauthopt *opts,
    పూర్ణాంకం allow_cert_authority, స్థిరరాశి అక్షరం *remote_ip, స్థిరరాశి అక్షరం *remote_host,
    స్థిరరాశి అక్షరం *loc)
{
	time_t now = time(ఖాళీ);
	అక్షరం buf[64];

	/*
	 * Check keys/principals file expiry time.
	 * NB. validity interval in certificate is handled elsewhere.
	 */
	ఒకవేళ (opts->valid_before && now > 0 &&
	    opts->valid_before < (uint64_t)now) {
		format_absolute_సమయం(opts->valid_before, buf, పరిమాణం(buf));
		debug("%s: entry expired at %s", loc, buf);
		auth_debug_కూడు("%s: entry expired at %s", loc, buf);
		తిరిగి -1;
	}
	/* Consistency checks */
	ఒకవేళ (opts->cert_principals != ఖాళీ && !opts->cert_authority) {
		debug("%s: principals on non-CA key", loc);
		auth_debug_కూడు("%s: principals on non-CA key", loc);
		/* deny access */
		తిరిగి -1;
	}
	/* cert-authority flag isn't valid in authorized_principals files */
	ఒకవేళ (!allow_cert_authority && opts->cert_authority) {
		debug("%s: cert-authority flag invalid here", loc);
		auth_debug_కూడు("%s: cert-authority flag invalid here", loc);
		/* deny access */
		తిరిగి -1;
	}

	/* Perform from= checks */
	ఒకవేళ (opts->required_from_host_కీలకాలు != ఖాళీ) {
		ఎంపిక (సరిపోలిక_host_and_ip(remote_host, remote_ip,
		    opts->required_from_host_కీలకాలు )) {
		స్థితి 1:
			/* Host name matches. */
			ఆపు;
		స్థితి -1:
		అప్రమేయ:
			debug("%s: invalid from criteria", loc);
			auth_debug_కూడు("%s: invalid from criteria", loc);
			/* FALLTHROUGH */
		స్థితి 0:
			logit("%s: Authentication tried for %.100s with "
			    "correct key but not from a permitted "
			    "host (host=%.200s, ip=%.200s, required=%.200s).",
			    loc, pw->pw_name, remote_host, remote_ip,
			    opts->required_from_host_కీలకాలు);
			auth_debug_కూడు("%s: Your host '%.200s' is not "
			    "permitted to use this key for login.",
			    loc, remote_host);
			/* deny access */
			తిరిగి -1;
		}
	}
	/* Check source-address restriction from certificate */
	ఒకవేళ (opts->required_from_host_cert != ఖాళీ) {
		ఎంపిక (addr_సరిపోలిక_cidr_list(remote_ip,
		    opts->required_from_host_cert)) {
		స్థితి 1:
			/* accepted */
			ఆపు;
		స్థితి -1:
		అప్రమేయ:
			/* invalid */
			error("%s: Certificate source-address invalid", loc);
			/* FALLTHROUGH */
		స్థితి 0:
			logit("%s: Authentication tried for %.100s with valid "
			    "certificate but not from a permitted source "
			    "address (%.200s).", loc, pw->pw_name, remote_ip);
			auth_debug_కూడు("%s: Your address '%.200s' is not "
			    "permitted to use this certificate for login.",
			    loc, remote_ip);
			తిరిగి -1;
		}
	}
	/*
	 *
	 * XXX this is spammy. We should report remotely only for keys
	 *     that are successful in actual auth attempts, and not PK_OK
	 *     tests.
	 */
	auth_log_authopts(loc, opts, 1);

	తిరిగి 0;
}

స్థిర పూర్ణాంకం
సరిపోలిక_principals_option(స్థిరరాశి అక్షరం *principal_list, నిర్మాణం sshkey_cert *cert)
{
	అక్షరం *list, *olist, *నమోదు_2;
	u_int i;

	olist = list = xstrdup(principal_list);
	కొరకు (;;) {
		ఒకవేళ ((నమోదు_2 = strsep(&list, ",")) == ఖాళీ || *నమోదు_2 == '\0')
			ఆపు;
		కొరకు (i = 0; i < cert->nprincipals; i++) {
			ఒకవేళ (strcmp(నమోదు_2, cert->principals[i]) == 0) {
				debug3("matched principal from key i"
				    "options \"%.100s\"", నమోదు_2);
				విడుదల(olist);
				తిరిగి 1;
			}
		}
	}
	విడుదల(olist);
	తిరిగి 0;
}

/*
 * Process a single authorized_principals format line. Returns 0 and sets
 * authoptsp is principal is authorised, -1 otherwise. "loc" is used as a
 * log preamble for file/line information.
 */
పూర్ణాంకం
auth_check_principals_పంక్తి(అక్షరం *cp, స్థిరరాశి నిర్మాణం sshkey_cert *cert,
    స్థిరరాశి అక్షరం *loc, నిర్మాణం sshauthopt **authoptsp)
{
	u_int i, దొరికింది = 0;
	అక్షరం *ep, *పంక్తి_opts;
	స్థిరరాశి అక్షరం *reason = ఖాళీ;
	నిర్మాణం sshauthopt *opts = ఖాళీ;

	ఒకవేళ (authoptsp != ఖాళీ)
		*authoptsp = ఖాళీ;

	/* Trim trailing whitespace. */
	ep = cp + అక్షరశ్రేణి_పొడవు(cp) - 1;
	అయితే (ep > cp && (*ep == '\n' || *ep == ' ' || *ep == '\t'))
		*ep-- = '\0';

	/*
	 * If the line has internal whitespace then assume it has
	 * key options.
	 */
	పంక్తి_opts = ఖాళీ;
	ఒకవేళ ((ep = strrchr(cp, ' ')) != ఖాళీ ||
	    (ep = strrchr(cp, '\t')) != ఖాళీ) {
		కొరకు (; *ep == ' ' || *ep == '\t'; ep++)
			;
		పంక్తి_opts = cp;
		cp = ep;
	}
	ఒకవేళ ((opts = sshauthopt_parse(పంక్తి_opts, &reason)) == ఖాళీ) {
		debug("%s: bad principals options: %s", loc, reason);
		auth_debug_కూడు("%s: bad principals options: %s", loc, reason);
		తిరిగి -1;
	}
	/* Check principals in cert against those on line */
	కొరకు (i = 0; i < cert->nprincipals; i++) {
		ఒకవేళ (strcmp(cp, cert->principals[i]) != 0)
			కొనసాగు;
		debug3("%s: matched principal \"%.100s\"",
		    loc, cert->principals[i]);
		దొరికింది = 1;
	}
	ఒకవేళ (దొరికింది && authoptsp != ఖాళీ) {
		*authoptsp = opts;
		opts = ఖాళీ;
	}
	sshauthopt_free(opts);
	తిరిగి దొరికింది ? 0 : -1;
}

పూర్ణాంకం
auth_process_principals(FILE *f, స్థిరరాశి అక్షరం *file,
    స్థిరరాశి నిర్మాణం sshkey_cert *cert, నిర్మాణం sshauthopt **authoptsp)
{
	అక్షరం loc[256], *పంక్తి = ఖాళీ, *cp, *ep;
	కొలత_t linesize = 0;
	u_long linenum = 0, nonblank = 0;
	u_int దొరికింది_principal = 0;

	ఒకవేళ (authoptsp != ఖాళీ)
		*authoptsp = ఖాళీ;

	అయితే (getline(&పంక్తి, &linesize, f) != -1) {
		linenum++;
		/* Always consume entire input */
		ఒకవేళ (దొరికింది_principal)
			కొనసాగు;

		/* Skip leading whitespace. */
		కొరకు (cp = పంక్తి; *cp == ' ' || *cp == '\t'; cp++)
			;
		/* Skip blank and comment lines. */
		ఒకవేళ ((ep = strchr(cp, '#')) != ఖాళీ)
			*ep = '\0';
		ఒకవేళ (!*cp || *cp == '\n')
			కొనసాగు;

		nonblank++;
		snprintf(loc, పరిమాణం(loc), "%.200s:%lu", file, linenum);
		ఒకవేళ (auth_check_principals_పంక్తి(cp, cert, loc, authoptsp) == 0)
			దొరికింది_principal = 1;
	}
	debug2_f("%s: processed %lu/%lu lines", file, nonblank, linenum);
	విడుదల(పంక్తి);
	తిరిగి దొరికింది_principal;
}

/*
 * Check a single line of an authorized_keys-format file. Returns 0 if key
 * matches, -1 otherwise. Will return key/cert options via *authoptsp
 * on success. "loc" is used as file/line location in log messages.
 */
పూర్ణాంకం
auth_check_authkey_పంక్తి(నిర్మాణం passwd *pw, నిర్మాణం sshkey *కీలకం,
    అక్షరం *cp, స్థిరరాశి అక్షరం *remote_ip, స్థిరరాశి అక్షరం *remote_host, స్థిరరాశి అక్షరం *loc,
    నిర్మాణం sshauthopt **authoptsp)
{
	పూర్ణాంకం want_keytype = sshkey_is_cert(కీలకం) ? కీలకం_UNSPEC : కీలకం->type;
	నిర్మాణం sshkey *దొరికింది = ఖాళీ;
	నిర్మాణం sshauthopt *keyopts = ఖాళీ, *certopts = ఖాళీ, *finalopts = ఖాళీ;
	అక్షరం *కీలకం_options = ఖాళీ, *fp = ఖాళీ;
	స్థిరరాశి అక్షరం *reason = ఖాళీ;
	పూర్ణాంకం ret = -1;

	ఒకవేళ (authoptsp != ఖాళీ)
		*authoptsp = ఖాళీ;

	ఒకవేళ ((దొరికింది = sshkey_new(want_keytype)) == ఖాళీ) {
		debug3_f("keytype %d failed", want_keytype);
		వెళ్ళు బహిర్గతం;
	}

	/* XXX djm: peek at key type in line and skip if unwanted */

	ఒకవేళ (sshkey_read(దొరికింది, &cp) != 0) {
		/* no key?  check for options */
		debug2("%s: check options: '%s'", loc, cp);
		కీలకం_options = cp;
		ఒకవేళ (sshkey_advance_past_options(&cp) != 0) {
			reason = "invalid key option string";
			వెళ్ళు fail_reason;
		}
		skip_space(&cp);
		ఒకవేళ (sshkey_read(దొరికింది, &cp) != 0) {
			/* still no key?  advance to next line*/
			debug2("%s: advance: '%s'", loc, cp);
			వెళ్ళు బహిర్గతం;
		}
	}
	/* Parse key options now; we need to know if this is a CA key */
	ఒకవేళ ((keyopts = sshauthopt_parse(కీలకం_options, &reason)) == ఖాళీ) {
		debug("%s: bad key options: %s", loc, reason);
		auth_debug_కూడు("%s: bad key options: %s", loc, reason);
		వెళ్ళు బహిర్గతం;
	}
	/* Ignore keys that don't match or incorrectly marked as CAs */
	ఒకవేళ (sshkey_is_cert(కీలకం)) {
		/* Certificate; check signature key against CA */
		ఒకవేళ (!sshkey_equal(దొరికింది, కీలకం->cert->signature_కీలకం) ||
		    !keyopts->cert_authority)
			వెళ్ళు బహిర్గతం;
	} లేకపోతే {
		/* Plain key: check it against key found in file */
		ఒకవేళ (!sshkey_equal(దొరికింది, కీలకం) || keyopts->cert_authority)
			వెళ్ళు బహిర్గతం;
	}

	/* We have a candidate key, perform authorisation checks */
	ఒకవేళ ((fp = sshkey_fingerprint(దొరికింది,
	    SSH_FP_HASH_DEFAULT, SSH_FP_DEFAULT)) == ఖాళీ)
		fatal_f("fingerprint failed");

	debug("%s: matching %s found: %s %s", loc,
	    sshkey_is_cert(కీలకం) ? "CA" : "key", sshkey_type(దొరికింది), fp);

	ఒకవేళ (auth_authorise_keyopts(pw, keyopts,
	    sshkey_is_cert(కీలకం), remote_ip, remote_host, loc) != 0) {
		reason = "Refused by key options";
		వెళ్ళు fail_reason;
	}
	/* That's all we need for plain keys. */
	ఒకవేళ (!sshkey_is_cert(కీలకం)) {
		verbose("Accepted key %s %s found at %s",
		    sshkey_type(దొరికింది), fp, loc);
		finalopts = keyopts;
		keyopts = ఖాళీ;
		వెళ్ళు success;
	}

	/*
	 * Additional authorisation for certificates.
	 */

	/* Parse and check options present in certificate */
	ఒకవేళ ((certopts = sshauthopt_from_cert(కీలకం)) == ఖాళీ) {
		reason = "Invalid certificate options";
		వెళ్ళు cert_fail_reason;
	}
	ఒకవేళ (auth_authorise_keyopts(pw, certopts, 0,
	    remote_ip, remote_host, loc) != 0) {
		reason = "Refused by certificate options";
		వెళ్ళు cert_fail_reason;
	}
	ఒకవేళ ((finalopts = sshauthopt_విలీనం(keyopts, certopts, &reason)) == ఖాళీ)
		వెళ్ళు cert_fail_reason;

	/*
	 * If the user has specified a list of principals as
	 * a key option, then prefer that list to matching
	 * their username in the certificate principals list.
	 */
	ఒకవేళ (keyopts->cert_principals != ఖాళీ &&
	    !సరిపోలిక_principals_option(keyopts->cert_principals, కీలకం->cert)) {
		reason = "Certificate does not contain an authorized principal";
		వెళ్ళు cert_fail_reason;
	}
	ఒకవేళ (sshkey_cert_check_authority_now(కీలకం, 0, 0,
	    keyopts->cert_principals == ఖాళీ ? pw->pw_name : ఖాళీ,
	    &reason) != 0)
		వెళ్ళు cert_fail_reason;

	verbose("Accepted certificate ID \"%s\" (serial %llu) "
	    "signed by CA %s %s found at %s",
	    కీలకం->cert->కీలకం_id,
	    (గుర్తులేని దీర్ఘ దీర్ఘ)కీలకం->cert->serial,
	    sshkey_type(దొరికింది), fp, loc);

 success:
	ఒకవేళ (finalopts == ఖాళీ)
		fatal_f("internal error: missing options");
	ఒకవేళ (authoptsp != ఖాళీ) {
		*authoptsp = finalopts;
		finalopts = ఖాళీ;
	}
	/* success */
	ret = 0;
	వెళ్ళు బహిర్గతం;

 cert_fail_reason:
	error("Refusing certificate ID \"%s\" serial=%llu "
	    "signed by %s CA %s via %s: %s", కీలకం->cert->కీలకం_id,
	    (గుర్తులేని దీర్ఘ దీర్ఘ)కీలకం->cert->serial,
	    sshkey_type(కీలకం->cert->signature_కీలకం), fp, loc, reason);
	auth_debug_కూడు("Refused Certificate ID \"%s\" serial=%llu: %s",
	    కీలకం->cert->కీలకం_id, (గుర్తులేని దీర్ఘ దీర్ఘ)కీలకం->cert->serial, reason);
	వెళ్ళు బహిర్గతం;

 fail_reason:
	error("%s at %s", reason, loc);
	auth_debug_కూడు("%s", reason);
 బహిర్గతం:
	విడుదల(fp);
	sshauthopt_free(keyopts);
	sshauthopt_free(certopts);
	sshauthopt_free(finalopts);
	sshkey_free(దొరికింది);
	తిరిగి ret;
}

/*
 * Checks whether key is allowed in authorized_keys-format file,
 * returns 1 if the key is allowed or 0 otherwise.
 */
పూర్ణాంకం
auth_check_authkeys_file(నిర్మాణం passwd *pw, FILE *f, అక్షరం *file,
    నిర్మాణం sshkey *కీలకం, స్థిరరాశి అక్షరం *remote_ip,
    స్థిరరాశి అక్షరం *remote_host, నిర్మాణం sshauthopt **authoptsp)
{
	అక్షరం *cp, *పంక్తి = ఖాళీ, loc[256];
	కొలత_t linesize = 0;
	పూర్ణాంకం దొరికింది_కీలకం = 0;
	u_long linenum = 0, nonblank = 0;

	ఒకవేళ (authoptsp != ఖాళీ)
		*authoptsp = ఖాళీ;

	అయితే (getline(&పంక్తి, &linesize, f) != -1) {
		linenum++;
		/* Always consume entire file */
		ఒకవేళ (దొరికింది_కీలకం)
			కొనసాగు;

		/* Skip leading whitespace, empty and comment lines. */
		cp = పంక్తి;
		skip_space(&cp);
		ఒకవేళ (!*cp || *cp == '\n' || *cp == '#')
			కొనసాగు;

		nonblank++;
		snprintf(loc, పరిమాణం(loc), "%.200s:%lu", file, linenum);
		ఒకవేళ (auth_check_authkey_పంక్తి(pw, కీలకం, cp,
		    remote_ip, remote_host, loc, authoptsp) == 0)
			దొరికింది_కీలకం = 1;
	}
	విడుదల(పంక్తి);
	debug2_f("%s: processed %lu/%lu lines", file, nonblank, linenum);
	తిరిగి దొరికింది_కీలకం;
}

స్థిర FILE *
auth_openfile(స్థిరరాశి అక్షరం *file, నిర్మాణం passwd *pw, పూర్ణాంకం strict_modes,
    పూర్ణాంకం log_missing, అక్షరం *file_type)
{
	అక్షరం పంక్తి[1024];
	నిర్మాణం stat st;
	పూర్ణాంకం fd;
	FILE *f;

	ఒకవేళ ((fd = open(file, O_RDONLY|O_NONBLOCK)) == -1) {
		ఒకవేళ (errno != ENOENT) {
			logit("Could not open user '%s' %s '%s': %s",
			    pw->pw_name, file_type, file, strerror(errno));
		} లేకపోతే ఒకవేళ (log_missing) {
			debug("Could not open user '%s' %s '%s': %s",
			    pw->pw_name, file_type, file, strerror(errno));
		}
		తిరిగి ఖాళీ;
	}

	ఒకవేళ (fstat(fd, &st) == -1) {
		close(fd);
		తిరిగి ఖాళీ;
	}
	ఒకవేళ (!S_ISREG(st.st_mode)) {
		logit("User '%s' %s '%s' is not a regular file",
		    pw->pw_name, file_type, file);
		close(fd);
		తిరిగి ఖాళీ;
	}
	unset_nonblock(fd);
	ఒకవేళ ((f = fdopen(fd, "r")) == ఖాళీ) {
		close(fd);
		తిరిగి ఖాళీ;
	}
	ఒకవేళ (strict_modes &&
	    సురక్షిత_మార్గం_fd(fileno(f), file, pw, పంక్తి, పరిమాణం(పంక్తి)) != 0) {
		fclose(f);
		logit("Authentication refused: %s", పంక్తి);
		auth_debug_కూడు("Ignored %s: %s", file_type, పంక్తి);
		తిరిగి ఖాళీ;
	}

	తిరిగి f;
}


FILE *
auth_openkeyfile(స్థిరరాశి అక్షరం *file, నిర్మాణం passwd *pw, పూర్ణాంకం strict_modes)
{
	తిరిగి auth_openfile(file, pw, strict_modes, 1, "authorized keys");
}

FILE *
auth_openprincipals(స్థిరరాశి అక్షరం *file, నిర్మాణం passwd *pw, పూర్ణాంకం strict_modes)
{
	తిరిగి auth_openfile(file, pw, strict_modes, 0,
	    "authorized principals");
}

