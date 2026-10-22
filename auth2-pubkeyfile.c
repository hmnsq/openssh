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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <sys/types.h>
#ଅନ୍ତର୍ଭାଵ <sys/stat.h>

#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <errno.h>
#ଅନ୍ତର୍ଭାଵ <fcntl.h>
#ଅନ୍ତର୍ଭାଵ <pwd.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <stdarg.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <time.h>
#ଅନ୍ତର୍ଭାଵ <unistd.h>

#ଅନ୍ତର୍ଭାଵ "ssh.h"
#ଅନ୍ତର୍ଭାଵ "log.h"
#ଅନ୍ତର୍ଭାଵ "misc.h"
#ଅନ୍ତର୍ଭାଵ "sshkey.h"
#ଅନ୍ତର୍ଭାଵ "digest.h"
#ଅନ୍ତର୍ଭାଵ "hostfile.h"
#ଅନ୍ତର୍ଭାଵ "auth.h"
#ଅନ୍ତର୍ଭାଵ "auth-options.h"
#ଅନ୍ତର୍ଭାଵ "authfile.h"
#ଅନ୍ତର୍ଭାଵ "match.h"
#ଅନ୍ତର୍ଭାଵ "ssherr.h"
#ଅନ୍ତର୍ଭାଵ "xmalloc.h"

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
auth_authorise_keyopts(ସଂରଚନା passwd *pw, ସଂରଚନା sshauthopt *opts,
    ପୂର୍ଣ୍ଣସଂଖ୍ୟା allow_cert_authority, ଅଚଳ ଅକ୍ଷର *remote_ip, ଅଚଳ ଅକ୍ଷର *remote_host,
    ଅଚଳ ଅକ୍ଷର *loc)
{
	time_t now = time(ଖାଲି);
	ଅକ୍ଷର buf[64];

	/*
	 * Check keys/principals file expiry time.
	 * NB. validity interval in certificate is handled elsewhere.
	 */
	ଯଦି (opts->valid_before && now > 0 &&
	    opts->valid_before < (uint64_t)now) {
		format_absolute_time(opts->valid_before, buf, ଆକାର(buf));
		debug("%s: entry expired at %s", loc, buf);
		auth_debug_add("%s: entry expired at %s", loc, buf);
		ଫେରନ୍ତୁ -1;
	}
	/* Consistency checks */
	ଯଦି (opts->cert_principals != ଖାଲି && !opts->cert_authority) {
		debug("%s: principals on non-CA key", loc);
		auth_debug_add("%s: principals on non-CA key", loc);
		/* deny access */
		ଫେରନ୍ତୁ -1;
	}
	/* cert-authority flag isn't valid in authorized_principals files */
	ଯଦି (!allow_cert_authority && opts->cert_authority) {
		debug("%s: cert-authority flag invalid here", loc);
		auth_debug_add("%s: cert-authority flag invalid here", loc);
		/* deny access */
		ଫେରନ୍ତୁ -1;
	}

	/* Perform from= checks */
	ଯଦି (opts->required_from_host_ଚାବିଗୁଡ଼ିକ != ଖାଲି) {
		ବାଛ (match_host_and_ip(remote_host, remote_ip,
		    opts->required_from_host_ଚାବିଗୁଡ଼ିକ )) {
		ସ୍ଥିତି 1:
			/* Host name matches. */
			ଭାଙ୍ଗ;
		ସ୍ଥିତି -1:
		ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
			debug("%s: invalid from criteria", loc);
			auth_debug_add("%s: invalid from criteria", loc);
			/* FALLTHROUGH */
		ସ୍ଥିତି 0:
			logit("%s: Authentication tried for %.100s with "
			    "correct key but not from a permitted "
			    "host (host=%.200s, ip=%.200s, required=%.200s).",
			    loc, pw->pw_name, remote_host, remote_ip,
			    opts->required_from_host_ଚାବିଗୁଡ଼ିକ);
			auth_debug_add("%s: Your host '%.200s' is not "
			    "permitted to use this key for login.",
			    loc, remote_host);
			/* deny access */
			ଫେରନ୍ତୁ -1;
		}
	}
	/* Check source-address restriction from certificate */
	ଯଦି (opts->required_from_host_cert != ଖାଲି) {
		ବାଛ (addr_match_cidr_list(remote_ip,
		    opts->required_from_host_cert)) {
		ସ୍ଥିତି 1:
			/* accepted */
			ଭାଙ୍ଗ;
		ସ୍ଥିତି -1:
		ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
			/* invalid */
			error("%s: Certificate source-address invalid", loc);
			/* FALLTHROUGH */
		ସ୍ଥିତି 0:
			logit("%s: Authentication tried for %.100s with valid "
			    "certificate but not from a permitted source "
			    "address (%.200s).", loc, pw->pw_name, remote_ip);
			auth_debug_add("%s: Your address '%.200s' is not "
			    "permitted to use this certificate for login.",
			    loc, remote_ip);
			ଫେରନ୍ତୁ -1;
		}
	}
	/*
	 *
	 * XXX this is spammy. We should report remotely only for keys
	 *     that are successful in actual auth attempts, and not PK_OK
	 *     tests.
	 */
	auth_log_authopts(loc, opts, 1);

	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
match_principals_option(ଅଚଳ ଅକ୍ଷର *principal_list, ସଂରଚନା sshkey_cert *cert)
{
	ଅକ୍ଷର *list, *olist, *entry;
	u_int i;

	olist = list = xstrdup(principal_list);
	ପାଇଁ (;;) {
		ଯଦି ((entry = strsep(&list, ",")) == ଖାଲି || *entry == '\0')
			ଭାଙ୍ଗ;
		ପାଇଁ (i = 0; i < cert->nprincipals; i++) {
			ଯଦି (strcmp(entry, cert->principals[i]) == 0) {
				debug3("matched principal from key i"
				    "options \"%.100s\"", entry);
				ମୁକ୍ତ(olist);
				ଫେରନ୍ତୁ 1;
			}
		}
	}
	ମୁକ୍ତ(olist);
	ଫେରନ୍ତୁ 0;
}

/*
 * Process a single authorized_principals format line. Returns 0 and sets
 * authoptsp is principal is authorised, -1 otherwise. "loc" is used as a
 * log preamble for file/line information.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
auth_check_principals_ଧାଡ଼ି(ଅକ୍ଷର *cp, ଅଚଳ ସଂରଚନା sshkey_cert *cert,
    ଅଚଳ ଅକ୍ଷର *loc, ସଂରଚନା sshauthopt **authoptsp)
{
	u_int i, found = 0;
	ଅକ୍ଷର *ep, *ଧାଡ଼ି_opts;
	ଅଚଳ ଅକ୍ଷର *reason = ଖାଲି;
	ସଂରଚନା sshauthopt *opts = ଖାଲି;

	ଯଦି (authoptsp != ଖାଲି)
		*authoptsp = ଖାଲି;

	/* Trim trailing whitespace. */
	ep = cp + strlen(cp) - 1;
	ଯେତେବେଳେ (ep > cp && (*ep == '\n' || *ep == ' ' || *ep == '\t'))
		*ep-- = '\0';

	/*
	 * If the line has internal whitespace then assume it has
	 * key options.
	 */
	ଧାଡ଼ି_opts = ଖାଲି;
	ଯଦି ((ep = strrchr(cp, ' ')) != ଖାଲି ||
	    (ep = strrchr(cp, '\t')) != ଖାଲି) {
		ପାଇଁ (; *ep == ' ' || *ep == '\t'; ep++)
			;
		ଧାଡ଼ି_opts = cp;
		cp = ep;
	}
	ଯଦି ((opts = sshauthopt_parse(ଧାଡ଼ି_opts, &reason)) == ଖାଲି) {
		debug("%s: bad principals options: %s", loc, reason);
		auth_debug_add("%s: bad principals options: %s", loc, reason);
		ଫେରନ୍ତୁ -1;
	}
	/* Check principals in cert against those on line */
	ପାଇଁ (i = 0; i < cert->nprincipals; i++) {
		ଯଦି (strcmp(cp, cert->principals[i]) != 0)
			ଜାରି;
		debug3("%s: matched principal \"%.100s\"",
		    loc, cert->principals[i]);
		found = 1;
	}
	ଯଦି (found && authoptsp != ଖାଲି) {
		*authoptsp = opts;
		opts = ଖାଲି;
	}
	sshauthopt_free(opts);
	ଫେରନ୍ତୁ found ? 0 : -1;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
auth_process_principals(FILE *f, ଅଚଳ ଅକ୍ଷର *file,
    ଅଚଳ ସଂରଚନା sshkey_cert *cert, ସଂରଚନା sshauthopt **authoptsp)
{
	ଅକ୍ଷର loc[256], *ଧାଡ଼ି = ଖାଲି, *cp, *ep;
	size_t linesize = 0;
	u_long linenum = 0, nonblank = 0;
	u_int found_principal = 0;

	ଯଦି (authoptsp != ଖାଲି)
		*authoptsp = ଖାଲି;

	ଯେତେବେଳେ (getline(&ଧାଡ଼ି, &linesize, f) != -1) {
		linenum++;
		/* Always consume entire input */
		ଯଦି (found_principal)
			ଜାରି;

		/* Skip leading whitespace. */
		ପାଇଁ (cp = ଧାଡ଼ି; *cp == ' ' || *cp == '\t'; cp++)
			;
		/* Skip blank and comment lines. */
		ଯଦି ((ep = strchr(cp, '#')) != ଖାଲି)
			*ep = '\0';
		ଯଦି (!*cp || *cp == '\n')
			ଜାରି;

		nonblank++;
		snprintf(loc, ଆକାର(loc), "%.200s:%lu", file, linenum);
		ଯଦି (auth_check_principals_ଧାଡ଼ି(cp, cert, loc, authoptsp) == 0)
			found_principal = 1;
	}
	debug2_f("%s: processed %lu/%lu lines", file, nonblank, linenum);
	ମୁକ୍ତ(ଧାଡ଼ି);
	ଫେରନ୍ତୁ found_principal;
}

/*
 * Check a single line of an authorized_keys-format file. Returns 0 if key
 * matches, -1 otherwise. Will return key/cert options via *authoptsp
 * on success. "loc" is used as file/line location in log messages.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
auth_check_authkey_ଧାଡ଼ି(ସଂରଚନା passwd *pw, ସଂରଚନା sshkey *ଚାବି,
    ଅକ୍ଷର *cp, ଅଚଳ ଅକ୍ଷର *remote_ip, ଅଚଳ ଅକ୍ଷର *remote_host, ଅଚଳ ଅକ୍ଷର *loc,
    ସଂରଚନା sshauthopt **authoptsp)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା want_keytype = sshkey_is_cert(ଚାବି) ? ଚାବି_UNSPEC : ଚାବି->type;
	ସଂରଚନା sshkey *found = ଖାଲି;
	ସଂରଚନା sshauthopt *keyopts = ଖାଲି, *certopts = ଖାଲି, *finalopts = ଖାଲି;
	ଅକ୍ଷର *ଚାବି_options = ଖାଲି, *fp = ଖାଲି;
	ଅଚଳ ଅକ୍ଷର *reason = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ret = -1;

	ଯଦି (authoptsp != ଖାଲି)
		*authoptsp = ଖାଲି;

	ଯଦି ((found = sshkey_new(want_keytype)) == ଖାଲି) {
		debug3_f("keytype %d failed", want_keytype);
		ଯାଅ out;
	}

	/* XXX djm: peek at key type in line and skip if unwanted */

	ଯଦି (sshkey_read(found, &cp) != 0) {
		/* no key?  check for options */
		debug2("%s: check options: '%s'", loc, cp);
		ଚାବି_options = cp;
		ଯଦି (sshkey_advance_past_options(&cp) != 0) {
			reason = "invalid key option string";
			ଯାଅ fail_reason;
		}
		skip_space(&cp);
		ଯଦି (sshkey_read(found, &cp) != 0) {
			/* still no key?  advance to next line*/
			debug2("%s: advance: '%s'", loc, cp);
			ଯାଅ out;
		}
	}
	/* Parse key options now; we need to know if this is a CA key */
	ଯଦି ((keyopts = sshauthopt_parse(ଚାବି_options, &reason)) == ଖାଲି) {
		debug("%s: bad key options: %s", loc, reason);
		auth_debug_add("%s: bad key options: %s", loc, reason);
		ଯାଅ out;
	}
	/* Ignore keys that don't match or incorrectly marked as CAs */
	ଯଦି (sshkey_is_cert(ଚାବି)) {
		/* Certificate; check signature key against CA */
		ଯଦି (!sshkey_equal(found, ଚାବି->cert->signature_ଚାବି) ||
		    !keyopts->cert_authority)
			ଯାଅ out;
	} ଅନ୍ୟଥା {
		/* Plain key: check it against key found in file */
		ଯଦି (!sshkey_equal(found, ଚାବି) || keyopts->cert_authority)
			ଯାଅ out;
	}

	/* We have a candidate key, perform authorisation checks */
	ଯଦି ((fp = sshkey_fingerprint(found,
	    SSH_FP_HASH_DEFAULT, SSH_FP_DEFAULT)) == ଖାଲି)
		fatal_f("fingerprint failed");

	debug("%s: matching %s found: %s %s", loc,
	    sshkey_is_cert(ଚାବି) ? "CA" : "key", sshkey_type(found), fp);

	ଯଦି (auth_authorise_keyopts(pw, keyopts,
	    sshkey_is_cert(ଚାବି), remote_ip, remote_host, loc) != 0) {
		reason = "Refused by key options";
		ଯାଅ fail_reason;
	}
	/* That's all we need for plain keys. */
	ଯଦି (!sshkey_is_cert(ଚାବି)) {
		verbose("Accepted key %s %s found at %s",
		    sshkey_type(found), fp, loc);
		finalopts = keyopts;
		keyopts = ଖାଲି;
		ଯାଅ success;
	}

	/*
	 * Additional authorisation for certificates.
	 */

	/* Parse and check options present in certificate */
	ଯଦି ((certopts = sshauthopt_from_cert(ଚାବି)) == ଖାଲି) {
		reason = "Invalid certificate options";
		ଯାଅ cert_fail_reason;
	}
	ଯଦି (auth_authorise_keyopts(pw, certopts, 0,
	    remote_ip, remote_host, loc) != 0) {
		reason = "Refused by certificate options";
		ଯାଅ cert_fail_reason;
	}
	ଯଦି ((finalopts = sshauthopt_merge(keyopts, certopts, &reason)) == ଖାଲି)
		ଯାଅ cert_fail_reason;

	/*
	 * If the user has specified a list of principals as
	 * a key option, then prefer that list to matching
	 * their username in the certificate principals list.
	 */
	ଯଦି (keyopts->cert_principals != ଖାଲି &&
	    !match_principals_option(keyopts->cert_principals, ଚାବି->cert)) {
		reason = "Certificate does not contain an authorized principal";
		ଯାଅ cert_fail_reason;
	}
	ଯଦି (sshkey_cert_check_authority_now(ଚାବି, 0, 0,
	    keyopts->cert_principals == ଖାଲି ? pw->pw_name : ଖାଲି,
	    &reason) != 0)
		ଯାଅ cert_fail_reason;

	verbose("Accepted certificate ID \"%s\" (serial %llu) "
	    "signed by CA %s %s found at %s",
	    ଚାବି->cert->ଚାବି_id,
	    (unsigned long long)ଚାବି->cert->serial,
	    sshkey_type(found), fp, loc);

 success:
	ଯଦି (finalopts == ଖାଲି)
		fatal_f("internal error: missing options");
	ଯଦି (authoptsp != ଖାଲି) {
		*authoptsp = finalopts;
		finalopts = ଖାଲି;
	}
	/* success */
	ret = 0;
	ଯାଅ out;

 cert_fail_reason:
	error("Refusing certificate ID \"%s\" serial=%llu "
	    "signed by %s CA %s via %s: %s", ଚାବି->cert->ଚାବି_id,
	    (unsigned long long)ଚାବି->cert->serial,
	    sshkey_type(ଚାବି->cert->signature_ଚାବି), fp, loc, reason);
	auth_debug_add("Refused Certificate ID \"%s\" serial=%llu: %s",
	    ଚାବି->cert->ଚାବି_id, (unsigned long long)ଚାବି->cert->serial, reason);
	ଯାଅ out;

 fail_reason:
	error("%s at %s", reason, loc);
	auth_debug_add("%s", reason);
 out:
	ମୁକ୍ତ(fp);
	sshauthopt_free(keyopts);
	sshauthopt_free(certopts);
	sshauthopt_free(finalopts);
	sshkey_free(found);
	ଫେରନ୍ତୁ ret;
}

/*
 * Checks whether key is allowed in authorized_keys-format file,
 * returns 1 if the key is allowed or 0 otherwise.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
auth_check_authkeys_file(ସଂରଚନା passwd *pw, FILE *f, ଅକ୍ଷର *file,
    ସଂରଚନା sshkey *ଚାବି, ଅଚଳ ଅକ୍ଷର *remote_ip,
    ଅଚଳ ଅକ୍ଷର *remote_host, ସଂରଚନା sshauthopt **authoptsp)
{
	ଅକ୍ଷର *cp, *ଧାଡ଼ି = ଖାଲି, loc[256];
	size_t linesize = 0;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା found_ଚାବି = 0;
	u_long linenum = 0, nonblank = 0;

	ଯଦି (authoptsp != ଖାଲି)
		*authoptsp = ଖାଲି;

	ଯେତେବେଳେ (getline(&ଧାଡ଼ି, &linesize, f) != -1) {
		linenum++;
		/* Always consume entire file */
		ଯଦି (found_ଚାବି)
			ଜାରି;

		/* Skip leading whitespace, empty and comment lines. */
		cp = ଧାଡ଼ି;
		skip_space(&cp);
		ଯଦି (!*cp || *cp == '\n' || *cp == '#')
			ଜାରି;

		nonblank++;
		snprintf(loc, ଆକାର(loc), "%.200s:%lu", file, linenum);
		ଯଦି (auth_check_authkey_ଧାଡ଼ି(pw, ଚାବି, cp,
		    remote_ip, remote_host, loc, authoptsp) == 0)
			found_ଚାବି = 1;
	}
	ମୁକ୍ତ(ଧାଡ଼ି);
	debug2_f("%s: processed %lu/%lu lines", file, nonblank, linenum);
	ଫେରନ୍ତୁ found_ଚାବି;
}

ସ୍ଥିର FILE *
auth_openfile(ଅଚଳ ଅକ୍ଷର *file, ସଂରଚନା passwd *pw, ପୂର୍ଣ୍ଣସଂଖ୍ୟା strict_modes,
    ପୂର୍ଣ୍ଣସଂଖ୍ୟା log_missing, ଅକ୍ଷର *file_type)
{
	ଅକ୍ଷର ଧାଡ଼ି[1024];
	ସଂରଚନା stat st;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd;
	FILE *f;

	ଯଦି ((fd = open(file, O_RDONLY|O_NONBLOCK)) == -1) {
		ଯଦି (errno != ENOENT) {
			logit("Could not open user '%s' %s '%s': %s",
			    pw->pw_name, file_type, file, strerror(errno));
		} ଅନ୍ୟଥା ଯଦି (log_missing) {
			debug("Could not open user '%s' %s '%s': %s",
			    pw->pw_name, file_type, file, strerror(errno));
		}
		ଫେରନ୍ତୁ ଖାଲି;
	}

	ଯଦି (fstat(fd, &st) == -1) {
		close(fd);
		ଫେରନ୍ତୁ ଖାଲି;
	}
	ଯଦି (!S_ISREG(st.st_mode)) {
		logit("User '%s' %s '%s' is not a regular file",
		    pw->pw_name, file_type, file);
		close(fd);
		ଫେରନ୍ତୁ ଖାଲି;
	}
	unset_nonblock(fd);
	ଯଦି ((f = fdopen(fd, "r")) == ଖାଲି) {
		close(fd);
		ଫେରନ୍ତୁ ଖାଲି;
	}
	ଯଦି (strict_modes &&
	    safe_path_fd(fileno(f), file, pw, ଧାଡ଼ି, ଆକାର(ଧାଡ଼ି)) != 0) {
		fclose(f);
		logit("Authentication refused: %s", ଧାଡ଼ି);
		auth_debug_add("Ignored %s: %s", file_type, ଧାଡ଼ି);
		ଫେରନ୍ତୁ ଖାଲି;
	}

	ଫେରନ୍ତୁ f;
}


FILE *
auth_openkeyfile(ଅଚଳ ଅକ୍ଷର *file, ସଂରଚନା passwd *pw, ପୂର୍ଣ୍ଣସଂଖ୍ୟା strict_modes)
{
	ଫେରନ୍ତୁ auth_openfile(file, pw, strict_modes, 1, "authorized keys");
}

FILE *
auth_openprincipals(ଅଚଳ ଅକ୍ଷର *file, ସଂରଚନା passwd *pw, ପୂର୍ଣ୍ଣସଂଖ୍ୟା strict_modes)
{
	ଫେରନ୍ତୁ auth_openfile(file, pw, strict_modes, 0,
	    "authorized principals");
}

