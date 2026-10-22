/* $OpenBSD: auth2-pubkey.c,v 1.132 2026/10/11 20:41:20 dtucker Exp $ */
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

#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <errno.h>
#ଅନ୍ତର୍ଭାଵ <paths.h>
#ଅନ୍ତର୍ଭାଵ <pwd.h>
#ଅନ୍ତର୍ଭାଵ <glob.h>
#ଅନ୍ତର୍ଭାଵ <signal.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <stdarg.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <time.h>
#ଅନ୍ତର୍ଭାଵ <unistd.h>
#ଅନ୍ତର୍ଭାଵ <limits.h>

#ଅନ୍ତର୍ଭାଵ "xmalloc.h"
#ଅନ୍ତର୍ଭାଵ "ssh.h"
#ଅନ୍ତର୍ଭାଵ "ssh2.h"
#ଅନ୍ତର୍ଭାଵ "packet.h"
#ଅନ୍ତର୍ଭାଵ "kex.h"
#ଅନ୍ତର୍ଭାଵ "sshbuf.h"
#ଅନ୍ତର୍ଭାଵ "log.h"
#ଅନ୍ତର୍ଭାଵ "misc.h"
#ଅନ୍ତର୍ଭାଵ "servconf.h"
#ଅନ୍ତର୍ଭାଵ "compat.h"
#ଅନ୍ତର୍ଭାଵ "sshkey.h"
#ଅନ୍ତର୍ଭାଵ "hostfile.h"
#ଅନ୍ତର୍ଭାଵ "auth.h"
#ଅନ୍ତର୍ଭାଵ "pathnames.h"
#ଅନ୍ତର୍ଭାଵ "uidswap.h"
#ଅନ୍ତର୍ଭାଵ "auth-options.h"
#ଅନ୍ତର୍ଭାଵ "canohost.h"
#ifdef GSSAPI
#ଅନ୍ତର୍ଭାଵ "ssh-gss.h"
#endif
#ଅନ୍ତର୍ଭାଵ "monitor_wrap.h"
#ଅନ୍ତର୍ଭାଵ "authfile.h"
#ଅନ୍ତର୍ଭାଵ "match.h"
#ଅନ୍ତର୍ଭାଵ "ssherr.h"
#ଅନ୍ତର୍ଭାଵ "channels.h" /* XXX for session.h */
#ଅନ୍ତର୍ଭାଵ "session.h" /* XXX for child_set_env(); refactor? */
#ଅନ୍ତର୍ଭାଵ "sk-api.h"

/* import */
ବାହ୍ୟ ServerOptions options;
ବାହ୍ୟ ସଂରଚନା authmethod_cfg methodcfg_pubkey;

ସ୍ଥିର ଅକ୍ଷର *
format_ଚାବି(ଅଚଳ ସଂରଚନା sshkey *ଚାବି)
{
	ଅକ୍ଷର *ret, *fp = sshkey_fingerprint(ଚାବି,
	    options.fingerprint_hash, SSH_FP_DEFAULT);

	xasprintf(&ret, "%s %s", sshkey_type(ଚାବି), fp);
	ମୁକ୍ତ(fp);
	ଫେରନ୍ତୁ ret;
}

/*
 * Verify that the hostkey in a publickey-hostbound-v00@openssh.com userauth
 * request matches the hostkey that was negotiated during initial KEX.
 */
ସ୍ଥିର ଶୂନ୍ୟ
check_hostbound_hostkey(ସଂରଚନା ssh *ssh)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	ସଂରଚନା sshbuf *our_hostkey_blob, *their_hostkey_blob;

	ଯଦି (ssh->kex->initial_hostkey == ଖାଲି)
		fatal_f("internal error: initial hostkey not recorded");
	ଯଦି ((our_hostkey_blob = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new failed");
	ଯଦି ((r = sshpkt_getb_froms(ssh, &their_hostkey_blob)) != 0)
		fatal_fr(r, "parse hostkey");
	ଯଦି ((r = sshkey_putb(ssh->kex->initial_hostkey, our_hostkey_blob)) != 0)
		fatal_fr(r, "serialise hostkey");
	ଯଦି ((r = sshbuf_equals(our_hostkey_blob, their_hostkey_blob)) != 0)
		fatal_f("packet contained wrong host key");
	sshbuf_free(our_hostkey_blob);
	sshbuf_free(their_hostkey_blob);
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
userauth_pubkey(ସଂରଚନା ssh *ssh, ଅଚଳ ଅକ୍ଷର *method)
{
	Authctxt *authctxt = ssh->authctxt;
	ସଂରଚନା passwd *pw = authctxt->pw;
	ସଂରଚନା sshbuf *keyblob = ଖାଲି, *b = ଖାଲି;
	ସଂରଚନା sshkey *ଚାବି = ଖାଲି, *hostkey = ଖାଲି;
	ଅକ୍ଷର *pkalg = ଖାଲି, *userstyle = ଖାଲି, *ଚାବି_s = ଖାଲି, *ca_s = ଖାଲି;
	ଅକ୍ଷର *keystring = ଖାଲି;
	u_char *sig = ଖାଲି, have_sig;
	size_t slen;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା hostbound, r, pktype;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା req_presence = 0, req_verify = 0, authenticated = 0;
	ସଂରଚନା sshauthopt *authopts = ଖାଲି;
	ସଂରଚନା sshkey_sig_details *sig_details = ଖାଲି;

	hostbound = strcmp(method, "publickey-hostbound-v00@openssh.com") == 0;

	ଯଦି ((r = sshpkt_get_u8(ssh, &have_sig)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &pkalg, ଖାଲି)) != 0 ||
	    (r = sshpkt_getb_froms(ssh, &keyblob)) != 0)
		fatal_fr(r, "parse %s packet", method);

	/* hostbound auth includes the hostkey offered at initial KEX */
	ଯଦି (hostbound)
		check_hostbound_hostkey(ssh); /* fatals on error */

	ଯଦି (log_level_get() >= SYSLOG_LEVEL_DEBUG2) {
		ଯଦି ((b = sshbuf_fromb(keyblob)) == ଖାଲି)
			fatal_f("sshbuf_fromb failed");
		ଯଦି ((keystring = sshbuf_dtob64_string(b, 0)) == ଖାଲି)
			fatal_f("sshbuf_dtob64 failed");
		debug2_f("%s user %s %s public key %s %s",
		    authctxt->valid ? "valid" : "invalid", authctxt->user,
		    have_sig ? "attempting" : "querying", pkalg, keystring);
		sshbuf_free(b);
		b = ଖାଲି;
	}

	pktype = sshkey_type_from_name(pkalg);
	ଯଦି (pktype == ଚାବି_UNSPEC) {
		/* this is perfectly legal */
		verbose_f("unsupported public key algorithm: %s", pkalg);
		ଯାଅ done;
	}
	ଯଦି (match_pattern_list(pkalg, options.pubkey_accepted_algos, 0) != 1) {
		logit_f("signature algorithm %s not in "
		    "PubkeyAcceptedAlgorithms", pkalg);
		ଯାଅ done;
	}
	ଯଦି ((b = sshbuf_fromb(keyblob)) == ଖାଲି)
		fatal_f("sshbuf_fromb failed");
	ବାଛ ((r = sshkey_fromb_allowlist(b, &ଚାବି,
	    options.pubkey_accepted_algos, options.ca_sign_algorithms))) {
	ସ୍ଥିତି 0:
		/* ok */
		ଭାଙ୍ଗ;
	ସ୍ଥିତି SSH_ERR_ଚାବି_ALG_UNSUPPORTED:
		/* This shouldn't happen unless the client is being weird */
		logit_f("key algorithm differs from signature algorithm %s and "
		    "is not in PubkeyAcceptedAlgorithms", pkalg);
		ଯାଅ done;
	ସ୍ଥିତି SSH_ERR_SIGN_ALG_UNSUPPORTED:
		logit_fr(r, "certificate signature algorithm not in "
		    "CASignatureAlgorithm");
		ଯାଅ done;
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		error_fr(r, "parse key");
		ଯାଅ done;
	}
	sshbuf_free(b);
	b = ଖାଲି;

	/* USERAUTH_REQUEST signature type should match key's type */
	ଯଦି (ଚାବି->type != pktype || (sshkey_type_plain(pktype) == ଚାବି_ECDSA &&
	    sshkey_ecdsa_nid_from_name(pkalg) != ଚାବି->ecdsa_nid)) {
		error_f("key type mismatch for decoded key "
		    "(received %s, expected %s)", sshkey_ssh_name(ଚାବି), pkalg);
		ଯାଅ done;
	}
	ଯଦି (auth2_ଚାବି_already_used(authctxt, ଚାବି)) {
		logit("refusing previously-used %s key", sshkey_type(ଚାବି));
		ଯାଅ done;
	}
	ଯଦି ((r = sshkey_check_rsa_length(ଚାବି,
	    options.required_rsa_size)) != 0) {
		logit_r(r, "refusing %s key", sshkey_type(ଚାବି));
		ଯାଅ done;
	}
	ଚାବି_s = format_ଚାବି(ଚାବି);
	ଯଦି (sshkey_is_cert(ଚାବି))
		ca_s = format_ଚାବି(ଚାବି->cert->signature_ଚାବି);

	ଯଦି (have_sig) {
		debug3_f("%s have %s signature for %s%s%s",
		    method, pkalg, ଚାବି_s,
		    ca_s == ଖାଲି ? "" : " CA ", ca_s == ଖାଲି ? "" : ca_s);
		ଯଦି ((r = sshpkt_get_string(ssh, &sig, &slen)) != 0 ||
		    (r = sshpkt_get_end(ssh)) != 0)
			fatal_fr(r, "parse signature packet");
		ଯଦି ((b = sshbuf_new()) == ଖାଲି)
			fatal_f("sshbuf_new failed");
		ଯଦି ((r = sshbuf_put_stringb(b,
		    ssh->kex->session_id)) != 0)
			fatal_fr(r, "put session id");
		ଯଦି (!authctxt->valid || authctxt->user == ଖାଲି) {
			debug2_f("disabled because of invalid user");
			ଯାଅ done;
		}
		/* reconstruct packet */
		xasprintf(&userstyle, "%s%s%s", authctxt->user,
		    authctxt->style ? ":" : "",
		    authctxt->style ? authctxt->style : "");
		ଯଦି ((r = sshbuf_put_u8(b, SSH2_ସନ୍ଦେଶ_USERAUTH_REQUEST)) != 0 ||
		    (r = sshbuf_put_cstring(b, userstyle)) != 0 ||
		    (r = sshbuf_put_cstring(b, authctxt->service)) != 0 ||
		    (r = sshbuf_put_cstring(b, method)) != 0 ||
		    (r = sshbuf_put_u8(b, have_sig)) != 0 ||
		    (r = sshbuf_put_cstring(b, pkalg)) != 0 ||
		    (r = sshbuf_put_stringb(b, keyblob)) != 0)
			fatal_fr(r, "reconstruct %s packet", method);
		ଯଦି (hostbound &&
		    (r = sshkey_puts(ssh->kex->initial_hostkey, b)) != 0)
			fatal_fr(r, "reconstruct %s packet", method);
#ifdef DEBUG_PK
		sshbuf_dump(b, stderr);
#endif
		/* test for correct signature */
		authenticated = 0;
		ଯଦି (mm_user_ଚାବି_allowed(ssh, pw, ଚାବି, 1, &authopts) &&
		    mm_sshkey_verify(ଚାବି, sig, slen,
		    sshbuf_ptr(b), sshbuf_len(b),
		    (ssh->compat & SSH_BUG_SIGTYPE) == 0 ? pkalg : ଖାଲି,
		    ssh->compat, &sig_details) == 0) {
			authenticated = 1;
		}
		ଯଦି (authenticated == 1 && sig_details != ଖାଲି) {
			auth2_record_info(authctxt, "signature count = %u",
			    sig_details->sk_counter);
			debug_f("sk_counter = %u, sk_flags = 0x%02x",
			    sig_details->sk_counter, sig_details->sk_flags);
			req_presence = (options.pubkey_auth_options &
			    PUBKEYAUTH_TOUCH_REQUIRED) ||
			    !authopts->no_require_user_presence;
			ଯଦି (req_presence && (sig_details->sk_flags &
			    SSH_SK_USER_PRESENCE_REQD) == 0) {
				error("public key %s signature for %s%s from "
				    "%.128s port %d rejected: user presence "
				    "(authenticator touch) requirement "
				    "not met ", ଚାବି_s,
				    authctxt->valid ? "" : "invalid user ",
				    authctxt->user, ssh_remote_ipaddr(ssh),
				    ssh_remote_port(ssh));
				authenticated = 0;
				ଯାଅ done;
			}
			req_verify = (options.pubkey_auth_options &
			    PUBKEYAUTH_VERIFY_REQUIRED) ||
			    authopts->require_verify;
			ଯଦି (req_verify && (sig_details->sk_flags &
			    SSH_SK_USER_VERIFICATION_REQD) == 0) {
				error("public key %s signature for %s%s from "
				    "%.128s port %d rejected: user "
				    "verification requirement not met ", ଚାବି_s,
				    authctxt->valid ? "" : "invalid user ",
				    authctxt->user, ssh_remote_ipaddr(ssh),
				    ssh_remote_port(ssh));
				authenticated = 0;
				ଯାଅ done;
			}
		}
		auth2_record_ଚାବି(authctxt, authenticated, ଚାବି);
	} ଅନ୍ୟଥା {
		debug_f("%s test pkalg %s pkblob %s%s%s", method, pkalg, ଚାବି_s,
		    ca_s == ଖାଲି ? "" : " CA ", ca_s == ଖାଲି ? "" : ca_s);

		ଯଦି ((r = sshpkt_get_end(ssh)) != 0)
			fatal_fr(r, "parse packet");

		/* XXX fake reply and always send PK_OK ? */
		/*
		 * XXX this allows testing whether a user is allowed
		 * to login: if you happen to have a valid pubkey this
		 * message is sent. the message is NEVER sent at all
		 * if a user is not allowed to login. is this an
		 * issue? -markus
		 */
		ଯଦି (authctxt->valid && authctxt->user != ଖାଲି &&
		    mm_user_ଚାବି_allowed(ssh, pw, ଚାବି, 0, ଖାଲି)) {
			ଯଦି ((r = sshpkt_start(ssh, SSH2_ସନ୍ଦେଶ_USERAUTH_PK_OK))
			    != 0 ||
			    (r = sshpkt_put_cstring(ssh, pkalg)) != 0 ||
			    (r = sshpkt_put_stringb(ssh, keyblob)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0 ||
			    (r = ssh_packet_write_wait(ssh)) != 0)
				fatal_fr(r, "send packet");
			authctxt->postponed = 1;
		} ଅନ୍ୟଥା {
			/*
			 * NB. invalid users must be accounted for in exactly
			 * the same way as valid users whose key was refused,
			 * otherwise MaxAuthTries becomes a username oracle.
			 */
			/*
			 * Don't count this as an authentication failure
			 * unless we have already used up the separate
			 * max-pk-ok budget (if any).
			 */
			ଯଦି (authctxt->pk_ok_failures++ < options.max_pubkey_ok)
				authctxt->auth_failure_already_counted = 1;
			debug3_f("pubkey test %d of %d%s",
			    authctxt->pk_ok_failures, options.max_pubkey_ok,
			    authctxt->auth_failure_already_counted ?
			    "" : ": treating as authentication failure");
		 }
	}
done:
	ଯଦି (authenticated == 1 && auth_activate_options(ssh, authopts) != 0) {
		debug_f("key options inconsistent with existing");
		authenticated = 0;
	}
	debug2_f("authenticated %d pkalg %s", authenticated, pkalg);

	sshbuf_free(b);
	sshbuf_free(keyblob);
	sshauthopt_free(authopts);
	sshkey_free(ଚାବି);
	sshkey_free(hostkey);
	ମୁକ୍ତ(keystring);
	ମୁକ୍ତ(userstyle);
	ମୁକ୍ତ(pkalg);
	ମୁକ୍ତ(ଚାବି_s);
	ମୁକ୍ତ(ca_s);
	ମୁକ୍ତ(sig);
	sshkey_sig_details_free(sig_details);
	ଫେରନ୍ତୁ authenticated;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
match_principals_file(ସଂରଚନା passwd *pw, ଅକ୍ଷର *file,
    ସଂରଚନା sshkey_cert *cert, ସଂରଚନା sshauthopt **authoptsp)
{
	FILE *f;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, success = 0;
	size_t i;
	glob_t gl;
	ସଂରଚନା sshauthopt *opts = ଖାଲି;

	ଯଦି (authoptsp != ଖାଲି)
		*authoptsp = ଖାଲି;

	temporarily_use_uid(pw);
	r = glob(file, 0, ଖାଲି, &gl);
	restore_uid();
	ଯଦି (r != 0) {
		ଯଦି (r != GLOB_NOMATCH) {
			logit_f("glob \"%s\" failed", file);
		}
		ଫେରନ୍ତୁ 0;
	} ଅନ୍ୟଥା ଯଦି (gl.gl_pathc > INT_MAX) {
		fatal_f("too many glob results for \"%s\"", file);
	} ଅନ୍ୟଥା ଯଦି (gl.gl_pathc > 1) {
		debug2_f("glob \"%s\" returned %zu matches", file,
		    gl.gl_pathc);
	}
	ପାଇଁ (i = 0; !success && i < gl.gl_pathc; i++) {
		temporarily_use_uid(pw);
		debug("trying authorized principals file %s", file);
		ଯଦି ((f = auth_openprincipals(gl.gl_pathv[i], pw,
		    options.strict_modes)) == ଖାଲି) {
			restore_uid();
			ଜାରି;
		}
		success = auth_process_principals(f, gl.gl_pathv[i],
		    cert, &opts);
		fclose(f);
		restore_uid();
		ଯଦି (!success) {
			sshauthopt_free(opts);
			opts = ଖାଲି;
		}
	}
	globfree(&gl);
	ଯଦି (success && authoptsp != ଖାଲି) {
		*authoptsp = opts;
		opts = ଖାଲି;
	}
	sshauthopt_free(opts);
	ଫେରନ୍ତୁ success;
}

/*
 * Checks whether principal is allowed in output of command.
 * returns 1 if the principal is allowed or 0 otherwise.
 */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
match_principals_command(ସଂରଚନା passwd *user_pw, ଅଚଳ ସଂରଚନା sshkey *ଚାବି,
    ଅଚଳ ଅକ୍ଷର *conn_id, ଅଚଳ ଅକ୍ଷର *rdomain, ସଂରଚନା sshauthopt **authoptsp)
{
	ସଂରଚନା passwd *runas_pw = ଖାଲି;
	ଅଚଳ ସଂରଚନା sshkey_cert *cert = ଚାବି->cert;
	FILE *f = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, ok, found_principal = 0;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i, ac = 0, uid_swapped = 0;
	pid_t pid;
	ଅକ୍ଷର *tmp, *username = ଖାଲି, *command = ଖାଲି, **av = ଖାଲି;
	ଅକ୍ଷର *ca_fp = ଖାଲି, *ଚାବି_fp = ଖାଲି, *catext = ଖାଲି, *keytext = ଖାଲି;
	ଅକ୍ଷର serial_s[32], uidstr[32];
	ଶୂନ୍ୟ (*osigchld)(ପୂର୍ଣ୍ଣସଂଖ୍ୟା);

	ଯଦି (authoptsp != ଖାଲି)
		*authoptsp = ଖାଲି;
	ଯଦି (options.authorized_principals_command == ଖାଲି)
		ଫେରନ୍ତୁ 0;
	ଯଦି (options.authorized_principals_command_user == ଖାଲି) {
		error("No user for AuthorizedPrincipalsCommand specified, "
		    "skipping");
		ଫେରନ୍ତୁ 0;
	}

	/*
	 * NB. all returns later this function should go via "out" to
	 * ensure the original SIGCHLD handler is restored properly.
	 */
	osigchld = ssh_signal(SIGCHLD, SIG_DFL);

	/* Prepare and verify the user for the command */
	username = percent_expand(options.authorized_principals_command_user,
	    "u", user_pw->pw_name, (ଅକ୍ଷର *)ଖାଲି);
	runas_pw = getpwnam(username);
	ଯଦି (runas_pw == ଖାଲି) {
		error("AuthorizedPrincipalsCommandUser \"%s\" not found: %s",
		    username, strerror(errno));
		ଯାଅ out;
	}

	/* Turn the command into an argument vector */
	ଯଦି (argv_split(options.authorized_principals_command,
	    &ac, &av, 0) != 0) {
		error("AuthorizedPrincipalsCommand \"%s\" contains "
		    "invalid quotes", options.authorized_principals_command);
		ଯାଅ out;
	}
	ଯଦି (ac == 0) {
		error("AuthorizedPrincipalsCommand \"%s\" yielded no arguments",
		    options.authorized_principals_command);
		ଯାଅ out;
	}
	ଯଦି ((ca_fp = sshkey_fingerprint(cert->signature_ଚାବି,
	    options.fingerprint_hash, SSH_FP_DEFAULT)) == ଖାଲି) {
		error_f("sshkey_fingerprint failed");
		ଯାଅ out;
	}
	ଯଦି ((ଚାବି_fp = sshkey_fingerprint(ଚାବି,
	    options.fingerprint_hash, SSH_FP_DEFAULT)) == ଖାଲି) {
		error_f("sshkey_fingerprint failed");
		ଯାଅ out;
	}
	ଯଦି ((r = sshkey_to_base64(cert->signature_ଚାବି, &catext)) != 0) {
		error_fr(r, "sshkey_to_base64 failed");
		ଯାଅ out;
	}
	ଯଦି ((r = sshkey_to_base64(ଚାବି, &keytext)) != 0) {
		error_fr(r, "sshkey_to_base64 failed");
		ଯାଅ out;
	}
	snprintf(serial_s, ଆକାର(serial_s), "%llu",
	    (unsigned long long)cert->serial);
	snprintf(uidstr, ଆକାର(uidstr), "%llu",
	    (unsigned long long)user_pw->pw_uid);
	ପାଇଁ (i = 1; i < ac; i++) {
		tmp = percent_expand(av[i],
		    "C", conn_id,
		    "D", rdomain,
		    "U", uidstr,
		    "u", user_pw->pw_name,
		    "h", user_pw->pw_dir,
		    "t", sshkey_ssh_name(ଚାବି),
		    "T", sshkey_ssh_name(cert->signature_ଚାବି),
		    "f", ଚାବି_fp,
		    "F", ca_fp,
		    "k", keytext,
		    "K", catext,
		    "i", cert->ଚାବି_id,
		    "s", serial_s,
		    (ଅକ୍ଷର *)ଖାଲି);
		ଯଦି (tmp == ଖାଲି)
			fatal_f("percent_expand failed");
		ମୁକ୍ତ(av[i]);
		av[i] = tmp;
	}
	/* Prepare a printable command for logs, etc. */
	command = argv_assemble(ac, av);

	ଯଦି ((pid = subprocess("AuthorizedPrincipalsCommand", command,
	    ac, av, &f,
	    SSH_SUBPROCESS_STDOUT_CAPTURE|SSH_SUBPROCESS_STDERR_DISCARD,
	    runas_pw, temporarily_use_uid, restore_uid)) == 0)
		ଯାଅ out;

	uid_swapped = 1;
	temporarily_use_uid(runas_pw);

	ok = auth_process_principals(f, "(command)", cert, authoptsp);

	fclose(f);
	f = ଖାଲି;

	ଯଦି (exited_cleanly(pid, "AuthorizedPrincipalsCommand", command, 0) != 0)
		ଯାଅ out;

	/* Read completed successfully */
	found_principal = ok;
 out:
	ଯଦି (f != ଖାଲି)
		fclose(f);
	ssh_signal(SIGCHLD, osigchld);
	ପାଇଁ (i = 0; i < ac; i++)
		ମୁକ୍ତ(av[i]);
	ମୁକ୍ତ(av);
	ଯଦି (uid_swapped)
		restore_uid();
	ମୁକ୍ତ(command);
	ମୁକ୍ତ(username);
	ମୁକ୍ତ(ca_fp);
	ମୁକ୍ତ(ଚାବି_fp);
	ମୁକ୍ତ(catext);
	ମୁକ୍ତ(keytext);
	ଫେରନ୍ତୁ found_principal;
}

/* Authenticate a certificate key against TrustedUserCAKeys */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
user_cert_trusted_ca(ସଂରଚନା passwd *pw, ସଂରଚନା sshkey *ଚାବି,
    ଅଚଳ ଅକ୍ଷର *remote_ip, ଅଚଳ ଅକ୍ଷର *remote_host,
    ଅଚଳ ଅକ୍ଷର *conn_id, ଅଚଳ ଅକ୍ଷର *rdomain, ସଂରଚନା sshauthopt **authoptsp)
{
	ଅକ୍ଷର *ca_fp, *principals_file = ଖାଲି;
	ଅଚଳ ଅକ୍ଷର *reason;
	ସଂରଚନା sshauthopt *principals_opts = ଖାଲି, *cert_opts = ଖାଲି;
	ସଂରଚନା sshauthopt *final_opts = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, ret = 0, found_principal = 0, use_authorized_principals;

	ଯଦି (authoptsp != ଖାଲି)
		*authoptsp = ଖାଲି;

	ଯଦି (!sshkey_is_cert(ଚାବି) || options.trusted_user_ca_ଚାବିଗୁଡ଼ିକ == ଖାଲି)
		ଫେରନ୍ତୁ 0;

	ଯଦି ((ca_fp = sshkey_fingerprint(ଚାବି->cert->signature_ଚାବି,
	    options.fingerprint_hash, SSH_FP_DEFAULT)) == ଖାଲି)
		ଫେରନ୍ତୁ 0;

	ଯଦି ((r = sshkey_in_file(ଚାବି->cert->signature_ଚାବି,
	    options.trusted_user_ca_ଚାବିଗୁଡ଼ିକ, 1, 0)) != 0) {
		debug2_fr(r, "CA %s %s is not listed in %s",
		    sshkey_type(ଚାବି->cert->signature_ଚାବି), ca_fp,
		    options.trusted_user_ca_ଚାବିଗୁଡ଼ିକ);
		ଯାଅ out;
	}
	/*
	 * If AuthorizedPrincipals is in use, then compare the certificate
	 * principals against the names in that file rather than matching
	 * against the username.
	 */
	ଯଦି ((principals_file = authorized_principals_file(pw)) != ଖାଲି) {
		ଯଦି (match_principals_file(pw, principals_file,
		    ଚାବି->cert, &principals_opts))
			found_principal = 1;
	}
	/* Try querying command if specified */
	ଯଦି (!found_principal && match_principals_command(pw, ଚାବି,
	    conn_id, rdomain, &principals_opts))
		found_principal = 1;
	/* If principals file or command is specified, then require a match */
	use_authorized_principals = principals_file != ଖାଲି ||
	    options.authorized_principals_command != ଖାଲି;
	ଯଦି (!found_principal && use_authorized_principals) {
		reason = "Certificate does not contain an authorized principal";
		ଯାଅ fail_reason;
	}
	ଯଦି (use_authorized_principals && principals_opts == ଖାଲି)
		fatal_f("internal error: missing principals_opts");
	ଯଦି (sshkey_cert_check_authority_now(ଚାବି, 0, 0,
	    use_authorized_principals ? ଖାଲି : pw->pw_name, &reason) != 0)
		ଯାଅ fail_reason;

	/* Check authority from options in key and from principals file/cmd */
	ଯଦି ((cert_opts = sshauthopt_from_cert(ଚାବି)) == ଖାଲି) {
		reason = "Invalid certificate options";
		ଯାଅ fail_reason;
	}
	ଯଦି (auth_authorise_keyopts(pw, cert_opts, 0,
	    remote_ip, remote_host, "cert") != 0) {
		reason = "Refused by certificate options";
		ଯାଅ fail_reason;
	}
	ଯଦି (principals_opts == ଖାଲି) {
		final_opts = cert_opts;
		cert_opts = ଖାଲି;
	} ଅନ୍ୟଥା {
		ଯଦି (auth_authorise_keyopts(pw, principals_opts, 0,
		    remote_ip, remote_host, "principals") != 0) {
			reason = "Refused by certificate principals options";
			ଯାଅ fail_reason;
		}
		ଯଦି ((final_opts = sshauthopt_merge(principals_opts,
		    cert_opts, &reason)) == ଖାଲି) {
 fail_reason:
			error("Refusing certificate ID \"%s\" serial=%llu "
			    "signed by %s CA %s: %s", ଚାବି->cert->ଚାବି_id,
			    (unsigned long long)ଚାବି->cert->serial,
			    sshkey_type(ଚାବି->cert->signature_ଚାବି), ca_fp,
			    reason);
			auth_debug_add("Refused Certificate ID \"%s\" "
			    "serial=%llu: %s", ଚାବି->cert->ଚାବି_id,
			    (unsigned long long)ଚାବି->cert->serial, reason);
			ଯାଅ out;
		}
	}

	/* Success */
	verbose("Accepted certificate ID \"%s\" (serial %llu) signed by "
	    "%s CA %s via %s", ଚାବି->cert->ଚାବି_id,
	    (unsigned long long)ଚାବି->cert->serial,
	    sshkey_type(ଚାବି->cert->signature_ଚାବି), ca_fp,
	    options.trusted_user_ca_ଚାବିଗୁଡ଼ିକ);
	ଯଦି (authoptsp != ଖାଲି) {
		*authoptsp = final_opts;
		final_opts = ଖାଲି;
	}
	ret = 1;
 out:
	sshauthopt_free(principals_opts);
	sshauthopt_free(cert_opts);
	sshauthopt_free(final_opts);
	ମୁକ୍ତ(principals_file);
	ମୁକ୍ତ(ca_fp);
	ଫେରନ୍ତୁ ret;
}

/*
 * Checks whether key is allowed in file.
 * returns 1 if the key is allowed or 0 otherwise.
 */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
user_ଚାବି_allowed2(ସଂରଚନା passwd *pw, ସଂରଚନା sshkey *ଚାବି,
    ଅକ୍ଷର *file, ଅଚଳ ଅକ୍ଷର *remote_ip, ଅଚଳ ଅକ୍ଷର *remote_host,
    ସଂରଚନା sshauthopt **authoptsp)
{
	FILE *f;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା found_ଚାବି = 0;

	ଯଦି (authoptsp != ଖାଲି)
		*authoptsp = ଖାଲି;

	/* Temporarily use the user's uid. */
	temporarily_use_uid(pw);

	debug("trying public key file %s", file);
	ଯଦି ((f = auth_openkeyfile(file, pw, options.strict_modes)) != ଖାଲି) {
		found_ଚାବି = auth_check_authkeys_file(pw, f, file,
		    ଚାବି, remote_ip, remote_host, authoptsp);
		fclose(f);
	}

	restore_uid();
	ଫେରନ୍ତୁ found_ଚାବି;
}

/*
 * Checks whether key is allowed in output of command.
 * returns 1 if the key is allowed or 0 otherwise.
 */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
user_ଚାବି_command_allowed2(ସଂରଚନା passwd *user_pw, ସଂରଚନା sshkey *ଚାବି,
    ଅଚଳ ଅକ୍ଷର *remote_ip, ଅଚଳ ଅକ୍ଷର *remote_host,
    ଅଚଳ ଅକ୍ଷର *conn_id, ଅଚଳ ଅକ୍ଷର *rdomain, ସଂରଚନା sshauthopt **authoptsp)
{
	ସଂରଚନା passwd *runas_pw = ଖାଲି;
	FILE *f = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, ok, found_ଚାବି = 0;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i, uid_swapped = 0, ac = 0;
	pid_t pid;
	ଅକ୍ଷର *username = ଖାଲି, *ଚାବି_fp = ଖାଲି, *keytext = ଖାଲି;
	ଅକ୍ଷର uidstr[32], *tmp, *command = ଖାଲି, **av = ଖାଲି;
	ଶୂନ୍ୟ (*osigchld)(ପୂର୍ଣ୍ଣସଂଖ୍ୟା);

	ଯଦି (authoptsp != ଖାଲି)
		*authoptsp = ଖାଲି;
	ଯଦି (options.authorized_ଚାବିଗୁଡ଼ିକ_command == ଖାଲି)
		ଫେରନ୍ତୁ 0;
	ଯଦି (options.authorized_ଚାବିଗୁଡ଼ିକ_command_user == ଖାଲି) {
		error("No user for AuthorizedKeysCommand specified, skipping");
		ଫେରନ୍ତୁ 0;
	}

	/*
	 * NB. all returns later this function should go via "out" to
	 * ensure the original SIGCHLD handler is restored properly.
	 */
	osigchld = ssh_signal(SIGCHLD, SIG_DFL);

	/* Prepare and verify the user for the command */
	username = percent_expand(options.authorized_ଚାବିଗୁଡ଼ିକ_command_user,
	    "u", user_pw->pw_name, (ଅକ୍ଷର *)ଖାଲି);
	runas_pw = getpwnam(username);
	ଯଦି (runas_pw == ଖାଲି) {
		error("AuthorizedKeysCommandUser \"%s\" not found: %s",
		    username, strerror(errno));
		ଯାଅ out;
	}

	/* Prepare AuthorizedKeysCommand */
	ଯଦି ((ଚାବି_fp = sshkey_fingerprint(ଚାବି, options.fingerprint_hash,
	    SSH_FP_DEFAULT)) == ଖାଲି) {
		error_f("sshkey_fingerprint failed");
		ଯାଅ out;
	}
	ଯଦି ((r = sshkey_to_base64(ଚାବି, &keytext)) != 0) {
		error_fr(r, "sshkey_to_base64 failed");
		ଯାଅ out;
	}

	/* Turn the command into an argument vector */
	ଯଦି (argv_split(options.authorized_ଚାବିଗୁଡ଼ିକ_command, &ac, &av, 0) != 0) {
		error("AuthorizedKeysCommand \"%s\" contains invalid quotes",
		    options.authorized_ଚାବିଗୁଡ଼ିକ_command);
		ଯାଅ out;
	}
	ଯଦି (ac == 0) {
		error("AuthorizedKeysCommand \"%s\" yielded no arguments",
		    options.authorized_ଚାବିଗୁଡ଼ିକ_command);
		ଯାଅ out;
	}
	snprintf(uidstr, ଆକାର(uidstr), "%llu",
	    (unsigned long long)user_pw->pw_uid);
	ପାଇଁ (i = 1; i < ac; i++) {
		tmp = percent_expand(av[i],
		    "C", conn_id,
		    "D", rdomain,
		    "U", uidstr,
		    "u", user_pw->pw_name,
		    "h", user_pw->pw_dir,
		    "t", sshkey_ssh_name(ଚାବି),
		    "f", ଚାବି_fp,
		    "k", keytext,
		    (ଅକ୍ଷର *)ଖାଲି);
		ଯଦି (tmp == ଖାଲି)
			fatal_f("percent_expand failed");
		ମୁକ୍ତ(av[i]);
		av[i] = tmp;
	}
	/* Prepare a printable command for logs, etc. */
	command = argv_assemble(ac, av);

	/*
	 * If AuthorizedKeysCommand was run without arguments
	 * then fall back to the old behaviour of passing the
	 * target username as a single argument.
	 */
	ଯଦି (ac == 1) {
		av = xreallocarray(av, ac + 2, ଆକାର(*av));
		av[1] = xstrdup(user_pw->pw_name);
		av[2] = ଖାଲି;
		/* Fix up command too, since it is used in log messages */
		ମୁକ୍ତ(command);
		xasprintf(&command, "%s %s", av[0], av[1]);
	}

	ଯଦି ((pid = subprocess("AuthorizedKeysCommand", command,
	    ac, av, &f,
	    SSH_SUBPROCESS_STDOUT_CAPTURE|SSH_SUBPROCESS_STDERR_DISCARD,
	    runas_pw, temporarily_use_uid, restore_uid)) == 0)
		ଯାଅ out;

	uid_swapped = 1;
	temporarily_use_uid(runas_pw);

	ok = auth_check_authkeys_file(user_pw, f,
	    options.authorized_ଚାବିଗୁଡ଼ିକ_command, ଚାବି, remote_ip,
	    remote_host, authoptsp);

	fclose(f);
	f = ଖାଲି;

	ଯଦି (exited_cleanly(pid, "AuthorizedKeysCommand", command, 0) != 0)
		ଯାଅ out;

	/* Read completed successfully */
	found_ଚାବି = ok;
 out:
	ଯଦି (f != ଖାଲି)
		fclose(f);
	ssh_signal(SIGCHLD, osigchld);
	ପାଇଁ (i = 0; i < ac; i++)
		ମୁକ୍ତ(av[i]);
	ମୁକ୍ତ(av);
	ଯଦି (uid_swapped)
		restore_uid();
	ମୁକ୍ତ(command);
	ମୁକ୍ତ(username);
	ମୁକ୍ତ(ଚାବି_fp);
	ମୁକ୍ତ(keytext);
	ଫେରନ୍ତୁ found_ଚାବି;
}

/*
 * Check whether key authenticates and authorises the user.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
user_ଚାବି_allowed(ସଂରଚନା ssh *ssh, ସଂରଚନା passwd *pw, ସଂରଚନା sshkey *ଚାବି,
    ପୂର୍ଣ୍ଣସଂଖ୍ୟା auth_attempt, ସଂରଚନା sshauthopt **authoptsp)
{
	u_int success = 0, i, j;
	ଅକ୍ଷର *file = ଖାଲି, *conn_id;
	ସଂରଚନା sshauthopt *opts = ଖାଲି;
	ଅଚଳ ଅକ୍ଷର *rdomain, *remote_ip, *remote_host;

	ଯଦି (authoptsp != ଖାଲି)
		*authoptsp = ଖାଲି;

	ଯଦି (auth_ଚାବି_is_revoked(ଚାବି))
		ଫେରନ୍ତୁ 0;
	ଯଦି (sshkey_is_cert(ଚାବି) &&
	    auth_ଚାବି_is_revoked(ଚାବି->cert->signature_ଚାବି))
		ଫେରନ୍ତୁ 0;

	ଯଦି ((rdomain = ssh_packet_rdomain_in(ssh)) == ଖାଲି)
		rdomain = "";
	remote_ip = ssh_remote_ipaddr(ssh);
	remote_host = auth_get_canonical_hostname(ssh, options.use_dns);
	xasprintf(&conn_id, "%s %d %s %d",
	    ssh_local_ipaddr(ssh), ssh_local_port(ssh),
	    remote_ip, ssh_remote_port(ssh));

	ପାଇଁ (i = 0; !success && i < options.ଅଙ୍କ_authkeys_files; i++) {
		ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
		glob_t gl;

		ଯଦି (strcasecmp(options.authorized_ଚାବିଗୁଡ଼ିକ_files[i], "none") == 0)
			ଜାରି;
		file = expand_authorized_ଚାବିଗୁଡ଼ିକ(
		    options.authorized_ଚାବିଗୁଡ଼ିକ_files[i], pw);
		temporarily_use_uid(pw);
		r = glob(file, 0, ଖାଲି, &gl);
		restore_uid();
		ଯଦି (r != 0) {
			ଯଦି (r != GLOB_NOMATCH) {
				logit_f("glob \"%s\" failed", file);
			}
			ମୁକ୍ତ(file);
			file = ଖାଲି;
			ଜାରି;
		} ଅନ୍ୟଥା ଯଦି (gl.gl_pathc > INT_MAX) {
			fatal_f("too many glob results for \"%s\"", file);
		} ଅନ୍ୟଥା ଯଦି (gl.gl_pathc > 1) {
			debug2_f("glob \"%s\" returned %zu matches", file,
			    gl.gl_pathc);
		}
		ପାଇଁ (j = 0; !success && j < gl.gl_pathc; j++) {
			success = user_ଚାବି_allowed2(pw, ଚାବି, gl.gl_pathv[j],
			    remote_ip, remote_host, &opts);
			ଯଦି (!success) {
				sshauthopt_free(opts);
				opts = ଖାଲି;
			}
		}
		ମୁକ୍ତ(file);
		file = ଖାଲି;
		globfree(&gl);
	}
	ଯଦି (success)
		ଯାଅ out;

	ଯଦି ((success = user_cert_trusted_ca(pw, ଚାବି, remote_ip, remote_host,
	    conn_id, rdomain, &opts)) != 0)
		ଯାଅ out;
	sshauthopt_free(opts);
	opts = ଖାଲି;

	ଯଦି ((success = user_ଚାବି_command_allowed2(pw, ଚାବି, remote_ip,
	    remote_host, conn_id, rdomain, &opts)) != 0)
		ଯାଅ out;
	sshauthopt_free(opts);
	opts = ଖାଲି;

 out:
	ମୁକ୍ତ(conn_id);
	ଯଦି (success && authoptsp != ଖାଲି) {
		*authoptsp = opts;
		opts = ଖାଲି;
	}
	sshauthopt_free(opts);
	ଫେରନ୍ତୁ success;
}

Authmethod method_pubkey = {
	&methodcfg_pubkey,
	userauth_pubkey,
};
