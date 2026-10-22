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

#ضمن "includes.h"

#ضمن <sys/types.h>

#ضمن <stdlib.h>
#ضمن <errno.h>
#ضمن <paths.h>
#ضمن <pwd.h>
#ضمن <glob.h>
#ضمن <signal.h>
#ضمن <stdio.h>
#ضمن <stdarg.h>
#ضمن <string.h>
#ضمن <time.h>
#ضمن <unistd.h>
#ضمن <limits.h>

#ضمن "xmalloc.h"
#ضمن "ssh.h"
#ضمن "ssh2.h"
#ضمن "packet.h"
#ضمن "kex.h"
#ضمن "sshbuf.h"
#ضمن "log.h"
#ضمن "misc.h"
#ضمن "servconf.h"
#ضمن "compat.h"
#ضمن "sshkey.h"
#ضمن "hostfile.h"
#ضمن "auth.h"
#ضمن "pathnames.h"
#ضمن "uidswap.h"
#ضمن "auth-options.h"
#ضمن "canohost.h"
#اگر_تعریف_شده GSSAPI
#ضمن "ssh-gss.h"
#پایان_اگر
#ضمن "monitor_wrap.h"
#ضمن "authfile.h"
#ضمن "match.h"
#ضمن "ssherr.h"
#ضمن "channels.h" /* XXX for session.h */
#ضمن "session.h" /* XXX for child_set_env(); refactor? */
#ضمن "sk-api.h"

/* import */
خارجي ServerOptions options;
خارجي بنية authmethod_cfg methodcfg_pubkey;

ساكن حرف *
format_کلید(ثابت بنية sshkey *کلید)
{
	حرف *ret, *fp = sshkey_fingerprint(کلید,
	    options.fingerprint_hash, SSH_FP_DEFAULT);

	xasprintf(&ret, "%s %s", sshkey_type(کلید), fp);
	حرر(fp);
	أرجع ret;
}

/*
 * Verify that the hostkey in a publickey-hostbound-v00@openssh.com userauth
 * request matches the hostkey that was negotiated during initial KEX.
 */
ساكن فراغ
check_hostbound_hostkey(بنية ssh *ssh)
{
	صحيح r;
	بنية sshbuf *our_hostkey_blob, *their_hostkey_blob;

	إذا (ssh->kex->initial_hostkey == عدم)
		fatal_f("internal error: initial hostkey not recorded");
	إذا ((our_hostkey_blob = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	إذا ((r = sshpkt_getb_froms(ssh, &their_hostkey_blob)) != 0)
		fatal_fr(r, "parse hostkey");
	إذا ((r = sshkey_putb(ssh->kex->initial_hostkey, our_hostkey_blob)) != 0)
		fatal_fr(r, "serialise hostkey");
	إذا ((r = sshbuf_equals(our_hostkey_blob, their_hostkey_blob)) != 0)
		fatal_f("packet contained wrong host key");
	sshbuf_free(our_hostkey_blob);
	sshbuf_free(their_hostkey_blob);
}

ساكن صحيح
userauth_pubkey(بنية ssh *ssh, ثابت حرف *روش)
{
	Authctxt *authctxt = ssh->authctxt;
	بنية passwd *pw = authctxt->pw;
	بنية sshbuf *keyblob = عدم, *b = عدم;
	بنية sshkey *کلید = عدم, *hostkey = عدم;
	حرف *pkalg = عدم, *userstyle = عدم, *کلید_s = عدم, *ca_s = عدم;
	حرف *keystring = عدم;
	u_char *sig = عدم, have_sig;
	اندازه_t slen;
	صحيح hostbound, r, pktype;
	صحيح req_presence = 0, req_verify = 0, authenticated = 0;
	بنية sshauthopt *authopts = عدم;
	بنية sshkey_sig_details *sig_details = عدم;

	hostbound = strcmp(روش, "publickey-hostbound-v00@openssh.com") == 0;

	إذا ((r = sshpkt_get_u8(ssh, &have_sig)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &pkalg, عدم)) != 0 ||
	    (r = sshpkt_getb_froms(ssh, &keyblob)) != 0)
		fatal_fr(r, "parse %s packet", روش);

	/* hostbound auth includes the hostkey offered at initial KEX */
	إذا (hostbound)
		check_hostbound_hostkey(ssh); /* fatals on error */

	إذا (log_level_get() >= SYSLOG_LEVEL_DEBUG2) {
		إذا ((b = sshbuf_fromb(keyblob)) == عدم)
			fatal_f("sshbuf_fromb failed");
		إذا ((keystring = sshbuf_dtob64_string(b, 0)) == عدم)
			fatal_f("sshbuf_dtob64 failed");
		debug2_f("%s user %s %s public key %s %s",
		    authctxt->valid ? "valid" : "invalid", authctxt->user,
		    have_sig ? "attempting" : "querying", pkalg, keystring);
		sshbuf_free(b);
		b = عدم;
	}

	pktype = sshkey_type_from_name(pkalg);
	إذا (pktype == کلید_UNSPEC) {
		/* this is perfectly legal */
		verbose_f("unsupported public key algorithm: %s", pkalg);
		اذهب انجامشده;
	}
	إذا (تطابق_الگو_list(pkalg, options.pubkey_accepted_algos, 0) != 1) {
		logit_f("signature algorithm %s not in "
		    "PubkeyAcceptedAlgorithms", pkalg);
		اذهب انجامشده;
	}
	إذا ((b = sshbuf_fromb(keyblob)) == عدم)
		fatal_f("sshbuf_fromb failed");
	بدل ((r = sshkey_fromb_allowlist(b, &کلید,
	    options.pubkey_accepted_algos, options.ca_sign_algorithms))) {
	حالة 0:
		/* ok */
		اكسر;
	حالة SSH_ERR_کلید_ALG_UNSUPPORTED:
		/* This shouldn't happen unless the client is being weird */
		logit_f("key algorithm differs from signature algorithm %s and "
		    "is not in PubkeyAcceptedAlgorithms", pkalg);
		اذهب انجامشده;
	حالة SSH_ERR_SIGN_ALG_UNSUPPORTED:
		logit_fr(r, "certificate signature algorithm not in "
		    "CASignatureAlgorithm");
		اذهب انجامشده;
	افتراضي:
		error_fr(r, "parse key");
		اذهب انجامشده;
	}
	sshbuf_free(b);
	b = عدم;

	/* USERAUTH_REQUEST signature type should match key's type */
	إذا (کلید->type != pktype || (sshkey_type_plain(pktype) == کلید_ECDSA &&
	    sshkey_ecdsa_nid_from_name(pkalg) != کلید->ecdsa_nid)) {
		error_f("key type mismatch for decoded key "
		    "(received %s, expected %s)", sshkey_ssh_name(کلید), pkalg);
		اذهب انجامشده;
	}
	إذا (auth2_کلید_already_استفاده_شده(authctxt, کلید)) {
		logit("refusing previously-used %s key", sshkey_type(کلید));
		اذهب انجامشده;
	}
	إذا ((r = sshkey_check_rsa_درازی(کلید,
	    options.required_rsa_اندازه)) != 0) {
		logit_r(r, "refusing %s key", sshkey_type(کلید));
		اذهب انجامشده;
	}
	کلید_s = format_کلید(کلید);
	إذا (sshkey_is_cert(کلید))
		ca_s = format_کلید(کلید->cert->signature_کلید);

	إذا (have_sig) {
		debug3_f("%s have %s signature for %s%s%s",
		    روش, pkalg, کلید_s,
		    ca_s == عدم ? "" : " CA ", ca_s == عدم ? "" : ca_s);
		إذا ((r = sshpkt_get_string(ssh, &sig, &slen)) != 0 ||
		    (r = sshpkt_get_انتها(ssh)) != 0)
			fatal_fr(r, "parse signature packet");
		إذا ((b = sshbuf_new()) == عدم)
			fatal_f("sshbuf_new failed");
		إذا ((r = sshbuf_put_stringb(b,
		    ssh->kex->session_id)) != 0)
			fatal_fr(r, "put session id");
		إذا (!authctxt->valid || authctxt->user == عدم) {
			debug2_f("disabled because of invalid user");
			اذهب انجامشده;
		}
		/* reconstruct packet */
		xasprintf(&userstyle, "%s%s%s", authctxt->user,
		    authctxt->style ? ":" : "",
		    authctxt->style ? authctxt->style : "");
		إذا ((r = sshbuf_put_u8(b, SSH2_پیام_USERAUTH_REQUEST)) != 0 ||
		    (r = sshbuf_put_cstring(b, userstyle)) != 0 ||
		    (r = sshbuf_put_cstring(b, authctxt->service)) != 0 ||
		    (r = sshbuf_put_cstring(b, روش)) != 0 ||
		    (r = sshbuf_put_u8(b, have_sig)) != 0 ||
		    (r = sshbuf_put_cstring(b, pkalg)) != 0 ||
		    (r = sshbuf_put_stringb(b, keyblob)) != 0)
			fatal_fr(r, "reconstruct %s packet", روش);
		إذا (hostbound &&
		    (r = sshkey_puts(ssh->kex->initial_hostkey, b)) != 0)
			fatal_fr(r, "reconstruct %s packet", روش);
#اگر_تعریف_شده DEBUG_PK
		sshbuf_dump(b, stderr);
#پایان_اگر
		/* test for correct signature */
		authenticated = 0;
		إذا (mm_user_کلید_allowed(ssh, pw, کلید, 1, &authopts) &&
		    mm_sshkey_verify(کلید, sig, slen,
		    sshbuf_ptr(b), sshbuf_len(b),
		    (ssh->compat & SSH_BUG_SIGTYPE) == 0 ? pkalg : عدم,
		    ssh->compat, &sig_details) == 0) {
			authenticated = 1;
		}
		إذا (authenticated == 1 && sig_details != عدم) {
			auth2_رکورد_info(authctxt, "signature count = %u",
			    sig_details->sk_counter);
			debug_f("sk_counter = %u, sk_flags = 0x%02x",
			    sig_details->sk_counter, sig_details->sk_flags);
			req_presence = (options.pubkey_auth_options &
			    PUBKEYAUTH_TOUCH_REQUIRED) ||
			    !authopts->no_require_user_presence;
			إذا (req_presence && (sig_details->sk_flags &
			    SSH_SK_USER_PRESENCE_REQD) == 0) {
				error("public key %s signature for %s%s from "
				    "%.128s port %d rejected: user presence "
				    "(authenticator touch) requirement "
				    "not met ", کلید_s,
				    authctxt->valid ? "" : "invalid user ",
				    authctxt->user, ssh_remote_ipaddr(ssh),
				    ssh_remote_پورت(ssh));
				authenticated = 0;
				اذهب انجامشده;
			}
			req_verify = (options.pubkey_auth_options &
			    PUBKEYAUTH_VERIFY_REQUIRED) ||
			    authopts->require_verify;
			إذا (req_verify && (sig_details->sk_flags &
			    SSH_SK_USER_VERIFICATION_REQD) == 0) {
				error("public key %s signature for %s%s from "
				    "%.128s port %d rejected: user "
				    "verification requirement not met ", کلید_s,
				    authctxt->valid ? "" : "invalid user ",
				    authctxt->user, ssh_remote_ipaddr(ssh),
				    ssh_remote_پورت(ssh));
				authenticated = 0;
				اذهب انجامشده;
			}
		}
		auth2_رکورد_کلید(authctxt, authenticated, کلید);
	} وإلا {
		debug_f("%s test pkalg %s pkblob %s%s%s", روش, pkalg, کلید_s,
		    ca_s == عدم ? "" : " CA ", ca_s == عدم ? "" : ca_s);

		إذا ((r = sshpkt_get_انتها(ssh)) != 0)
			fatal_fr(r, "parse packet");

		/* XXX fake reply and always send PK_OK ? */
		/*
		 * XXX this allows testing whether a user is allowed
		 * to login: if you happen to have a valid pubkey this
		 * message is sent. the message is NEVER sent at all
		 * if a user is not allowed to login. is this an
		 * issue? -markus
		 */
		إذا (authctxt->valid && authctxt->user != عدم &&
		    mm_user_کلید_allowed(ssh, pw, کلید, 0, عدم)) {
			إذا ((r = sshpkt_شروع(ssh, SSH2_پیام_USERAUTH_PK_OK))
			    != 0 ||
			    (r = sshpkt_put_cstring(ssh, pkalg)) != 0 ||
			    (r = sshpkt_put_stringb(ssh, keyblob)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0 ||
			    (r = ssh_packet_write_wait(ssh)) != 0)
				fatal_fr(r, "send packet");
			authctxt->postponed = 1;
		} وإلا {
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
			إذا (authctxt->pk_ok_failures++ < options.max_pubkey_ok)
				authctxt->auth_failure_already_counted = 1;
			debug3_f("pubkey test %d of %d%s",
			    authctxt->pk_ok_failures, options.max_pubkey_ok,
			    authctxt->auth_failure_already_counted ?
			    "" : ": treating as authentication failure");
		 }
	}
انجامشده:
	إذا (authenticated == 1 && auth_activate_options(ssh, authopts) != 0) {
		debug_f("key options inconsistent with existing");
		authenticated = 0;
	}
	debug2_f("authenticated %d pkalg %s", authenticated, pkalg);

	sshbuf_free(b);
	sshbuf_free(keyblob);
	sshauthopt_free(authopts);
	sshkey_free(کلید);
	sshkey_free(hostkey);
	حرر(keystring);
	حرر(userstyle);
	حرر(pkalg);
	حرر(کلید_s);
	حرر(ca_s);
	حرر(sig);
	sshkey_sig_details_free(sig_details);
	أرجع authenticated;
}

ساكن صحيح
تطابق_principals_file(بنية passwd *pw, حرف *file,
    بنية sshkey_cert *cert, بنية sshauthopt **authoptsp)
{
	FILE *f;
	صحيح r, success = 0;
	اندازه_t i;
	glob_t gl;
	بنية sshauthopt *opts = عدم;

	إذا (authoptsp != عدم)
		*authoptsp = عدم;

	temporarily_use_uid(pw);
	r = glob(file, 0, عدم, &gl);
	restore_uid();
	إذا (r != 0) {
		إذا (r != GLOB_NOMATCH) {
			logit_f("glob \"%s\" failed", file);
		}
		أرجع 0;
	} وإلا إذا (gl.gl_pathc > بیشترین_صحیح) {
		fatal_f("too many glob results for \"%s\"", file);
	} وإلا إذا (gl.gl_pathc > 1) {
		debug2_f("glob \"%s\" returned %zu matches", file,
		    gl.gl_pathc);
	}
	لكل (i = 0; !success && i < gl.gl_pathc; i++) {
		temporarily_use_uid(pw);
		debug("trying authorized principals file %s", file);
		إذا ((f = auth_openprincipals(gl.gl_pathv[i], pw,
		    options.strict_modes)) == عدم) {
			restore_uid();
			استمر;
		}
		success = auth_process_principals(f, gl.gl_pathv[i],
		    cert, &opts);
		fclose(f);
		restore_uid();
		إذا (!success) {
			sshauthopt_free(opts);
			opts = عدم;
		}
	}
	globfree(&gl);
	إذا (success && authoptsp != عدم) {
		*authoptsp = opts;
		opts = عدم;
	}
	sshauthopt_free(opts);
	أرجع success;
}

/*
 * Checks whether principal is allowed in output of command.
 * returns 1 if the principal is allowed or 0 otherwise.
 */
ساكن صحيح
تطابق_principals_command(بنية passwd *user_pw, ثابت بنية sshkey *کلید,
    ثابت حرف *conn_id, ثابت حرف *rdomain, بنية sshauthopt **authoptsp)
{
	بنية passwd *runas_pw = عدم;
	ثابت بنية sshkey_cert *cert = کلید->cert;
	FILE *f = عدم;
	صحيح r, ok, یافت_principal = 0;
	صحيح i, ac = 0, uid_swapped = 0;
	pid_t pid;
	حرف *tmp, *username = عدم, *command = عدم, **av = عدم;
	حرف *ca_fp = عدم, *کلید_fp = عدم, *catext = عدم, *keytext = عدم;
	حرف serial_s[32], uidstr[32];
	فراغ (*osigchld)(صحيح);

	إذا (authoptsp != عدم)
		*authoptsp = عدم;
	إذا (options.authorized_principals_command == عدم)
		أرجع 0;
	إذا (options.authorized_principals_command_user == عدم) {
		error("No user for AuthorizedPrincipalsCommand specified, "
		    "skipping");
		أرجع 0;
	}

	/*
	 * NB. all returns later this function should go via "out" to
	 * ensure the original SIGCHLD handler is restored properly.
	 */
	osigchld = ssh_signal(SIGCHLD, SIG_DFL);

	/* Prepare and verify the user for the command */
	username = percent_expand(options.authorized_principals_command_user,
	    "u", user_pw->pw_name, (حرف *)عدم);
	runas_pw = getpwnam(username);
	إذا (runas_pw == عدم) {
		error("AuthorizedPrincipalsCommandUser \"%s\" not found: %s",
		    username, strerror(errno));
		اذهب بیرون;
	}

	/* Turn the command into an argument vector */
	إذا (argv_تقسیم(options.authorized_principals_command,
	    &ac, &av, 0) != 0) {
		error("AuthorizedPrincipalsCommand \"%s\" contains "
		    "invalid quotes", options.authorized_principals_command);
		اذهب بیرون;
	}
	إذا (ac == 0) {
		error("AuthorizedPrincipalsCommand \"%s\" yielded no arguments",
		    options.authorized_principals_command);
		اذهب بیرون;
	}
	إذا ((ca_fp = sshkey_fingerprint(cert->signature_کلید,
	    options.fingerprint_hash, SSH_FP_DEFAULT)) == عدم) {
		error_f("sshkey_fingerprint failed");
		اذهب بیرون;
	}
	إذا ((کلید_fp = sshkey_fingerprint(کلید,
	    options.fingerprint_hash, SSH_FP_DEFAULT)) == عدم) {
		error_f("sshkey_fingerprint failed");
		اذهب بیرون;
	}
	إذا ((r = sshkey_مقصد_base64(cert->signature_کلید, &catext)) != 0) {
		error_fr(r, "sshkey_to_base64 failed");
		اذهب بیرون;
	}
	إذا ((r = sshkey_مقصد_base64(کلید, &keytext)) != 0) {
		error_fr(r, "sshkey_to_base64 failed");
		اذهب بیرون;
	}
	snprintf(serial_s, حجم(serial_s), "%llu",
	    (بیعلامت دراز دراز)cert->serial);
	snprintf(uidstr, حجم(uidstr), "%llu",
	    (بیعلامت دراز دراز)user_pw->pw_uid);
	لكل (i = 1; i < ac; i++) {
		tmp = percent_expand(av[i],
		    "C", conn_id,
		    "D", rdomain,
		    "U", uidstr,
		    "u", user_pw->pw_name,
		    "h", user_pw->pw_dir,
		    "t", sshkey_ssh_name(کلید),
		    "T", sshkey_ssh_name(cert->signature_کلید),
		    "f", کلید_fp,
		    "F", ca_fp,
		    "k", keytext,
		    "K", catext,
		    "i", cert->کلید_id,
		    "s", serial_s,
		    (حرف *)عدم);
		إذا (tmp == عدم)
			fatal_f("percent_expand failed");
		حرر(av[i]);
		av[i] = tmp;
	}
	/* Prepare a printable command for logs, etc. */
	command = argv_assemble(ac, av);

	إذا ((pid = subprocess("AuthorizedPrincipalsCommand", command,
	    ac, av, &f,
	    SSH_SUBPROCESS_STDOUT_CAPTURE|SSH_SUBPROCESS_STDERR_DISCARD,
	    runas_pw, temporarily_use_uid, restore_uid)) == 0)
		اذهب بیرون;

	uid_swapped = 1;
	temporarily_use_uid(runas_pw);

	ok = auth_process_principals(f, "(command)", cert, authoptsp);

	fclose(f);
	f = عدم;

	إذا (exited_cleanly(pid, "AuthorizedPrincipalsCommand", command, 0) != 0)
		اذهب بیرون;

	/* Read completed successfully */
	یافت_principal = ok;
 بیرون:
	إذا (f != عدم)
		fclose(f);
	ssh_signal(SIGCHLD, osigchld);
	لكل (i = 0; i < ac; i++)
		حرر(av[i]);
	حرر(av);
	إذا (uid_swapped)
		restore_uid();
	حرر(command);
	حرر(username);
	حرر(ca_fp);
	حرر(کلید_fp);
	حرر(catext);
	حرر(keytext);
	أرجع یافت_principal;
}

/* Authenticate a certificate key against TrustedUserCAKeys */
ساكن صحيح
user_cert_trusted_ca(بنية passwd *pw, بنية sshkey *کلید,
    ثابت حرف *remote_ip, ثابت حرف *remote_host,
    ثابت حرف *conn_id, ثابت حرف *rdomain, بنية sshauthopt **authoptsp)
{
	حرف *ca_fp, *principals_file = عدم;
	ثابت حرف *reason;
	بنية sshauthopt *principals_opts = عدم, *cert_opts = عدم;
	بنية sshauthopt *final_opts = عدم;
	صحيح r, ret = 0, یافت_principal = 0, use_authorized_principals;

	إذا (authoptsp != عدم)
		*authoptsp = عدم;

	إذا (!sshkey_is_cert(کلید) || options.trusted_user_ca_کلیدها == عدم)
		أرجع 0;

	إذا ((ca_fp = sshkey_fingerprint(کلید->cert->signature_کلید,
	    options.fingerprint_hash, SSH_FP_DEFAULT)) == عدم)
		أرجع 0;

	إذا ((r = sshkey_درون_file(کلید->cert->signature_کلید,
	    options.trusted_user_ca_کلیدها, 1, 0)) != 0) {
		debug2_fr(r, "CA %s %s is not listed in %s",
		    sshkey_type(کلید->cert->signature_کلید), ca_fp,
		    options.trusted_user_ca_کلیدها);
		اذهب بیرون;
	}
	/*
	 * If AuthorizedPrincipals is in use, then compare the certificate
	 * principals against the names in that file rather than matching
	 * against the username.
	 */
	إذا ((principals_file = authorized_principals_file(pw)) != عدم) {
		إذا (تطابق_principals_file(pw, principals_file,
		    کلید->cert, &principals_opts))
			یافت_principal = 1;
	}
	/* Try querying command if specified */
	إذا (!یافت_principal && تطابق_principals_command(pw, کلید,
	    conn_id, rdomain, &principals_opts))
		یافت_principal = 1;
	/* If principals file or command is specified, then require a match */
	use_authorized_principals = principals_file != عدم ||
	    options.authorized_principals_command != عدم;
	إذا (!یافت_principal && use_authorized_principals) {
		reason = "Certificate does not contain an authorized principal";
		اذهب fail_reason;
	}
	إذا (use_authorized_principals && principals_opts == عدم)
		fatal_f("internal error: missing principals_opts");
	إذا (sshkey_cert_check_authority_now(کلید, 0, 0,
	    use_authorized_principals ? عدم : pw->pw_name, &reason) != 0)
		اذهب fail_reason;

	/* Check authority from options in key and from principals file/cmd */
	إذا ((cert_opts = sshauthopt_from_cert(کلید)) == عدم) {
		reason = "Invalid certificate options";
		اذهب fail_reason;
	}
	إذا (auth_authorise_keyopts(pw, cert_opts, 0,
	    remote_ip, remote_host, "cert") != 0) {
		reason = "Refused by certificate options";
		اذهب fail_reason;
	}
	إذا (principals_opts == عدم) {
		final_opts = cert_opts;
		cert_opts = عدم;
	} وإلا {
		إذا (auth_authorise_keyopts(pw, principals_opts, 0,
		    remote_ip, remote_host, "principals") != 0) {
			reason = "Refused by certificate principals options";
			اذهب fail_reason;
		}
		إذا ((final_opts = sshauthopt_ادغام(principals_opts,
		    cert_opts, &reason)) == عدم) {
 fail_reason:
			error("Refusing certificate ID \"%s\" serial=%llu "
			    "signed by %s CA %s: %s", کلید->cert->کلید_id,
			    (بیعلامت دراز دراز)کلید->cert->serial,
			    sshkey_type(کلید->cert->signature_کلید), ca_fp,
			    reason);
			auth_debug_جمع_کن("Refused Certificate ID \"%s\" "
			    "serial=%llu: %s", کلید->cert->کلید_id,
			    (بیعلامت دراز دراز)کلید->cert->serial, reason);
			اذهب بیرون;
		}
	}

	/* Success */
	verbose("Accepted certificate ID \"%s\" (serial %llu) signed by "
	    "%s CA %s via %s", کلید->cert->کلید_id,
	    (بیعلامت دراز دراز)کلید->cert->serial,
	    sshkey_type(کلید->cert->signature_کلید), ca_fp,
	    options.trusted_user_ca_کلیدها);
	إذا (authoptsp != عدم) {
		*authoptsp = final_opts;
		final_opts = عدم;
	}
	ret = 1;
 بیرون:
	sshauthopt_free(principals_opts);
	sshauthopt_free(cert_opts);
	sshauthopt_free(final_opts);
	حرر(principals_file);
	حرر(ca_fp);
	أرجع ret;
}

/*
 * Checks whether key is allowed in file.
 * returns 1 if the key is allowed or 0 otherwise.
 */
ساكن صحيح
user_کلید_allowed2(بنية passwd *pw, بنية sshkey *کلید,
    حرف *file, ثابت حرف *remote_ip, ثابت حرف *remote_host,
    بنية sshauthopt **authoptsp)
{
	FILE *f;
	صحيح یافت_کلید = 0;

	إذا (authoptsp != عدم)
		*authoptsp = عدم;

	/* Temporarily use the user's uid. */
	temporarily_use_uid(pw);

	debug("trying public key file %s", file);
	إذا ((f = auth_openkeyfile(file, pw, options.strict_modes)) != عدم) {
		یافت_کلید = auth_check_authkeys_file(pw, f, file,
		    کلید, remote_ip, remote_host, authoptsp);
		fclose(f);
	}

	restore_uid();
	أرجع یافت_کلید;
}

/*
 * Checks whether key is allowed in output of command.
 * returns 1 if the key is allowed or 0 otherwise.
 */
ساكن صحيح
user_کلید_command_allowed2(بنية passwd *user_pw, بنية sshkey *کلید,
    ثابت حرف *remote_ip, ثابت حرف *remote_host,
    ثابت حرف *conn_id, ثابت حرف *rdomain, بنية sshauthopt **authoptsp)
{
	بنية passwd *runas_pw = عدم;
	FILE *f = عدم;
	صحيح r, ok, یافت_کلید = 0;
	صحيح i, uid_swapped = 0, ac = 0;
	pid_t pid;
	حرف *username = عدم, *کلید_fp = عدم, *keytext = عدم;
	حرف uidstr[32], *tmp, *command = عدم, **av = عدم;
	فراغ (*osigchld)(صحيح);

	إذا (authoptsp != عدم)
		*authoptsp = عدم;
	إذا (options.authorized_کلیدها_command == عدم)
		أرجع 0;
	إذا (options.authorized_کلیدها_command_user == عدم) {
		error("No user for AuthorizedKeysCommand specified, skipping");
		أرجع 0;
	}

	/*
	 * NB. all returns later this function should go via "out" to
	 * ensure the original SIGCHLD handler is restored properly.
	 */
	osigchld = ssh_signal(SIGCHLD, SIG_DFL);

	/* Prepare and verify the user for the command */
	username = percent_expand(options.authorized_کلیدها_command_user,
	    "u", user_pw->pw_name, (حرف *)عدم);
	runas_pw = getpwnam(username);
	إذا (runas_pw == عدم) {
		error("AuthorizedKeysCommandUser \"%s\" not found: %s",
		    username, strerror(errno));
		اذهب بیرون;
	}

	/* Prepare AuthorizedKeysCommand */
	إذا ((کلید_fp = sshkey_fingerprint(کلید, options.fingerprint_hash,
	    SSH_FP_DEFAULT)) == عدم) {
		error_f("sshkey_fingerprint failed");
		اذهب بیرون;
	}
	إذا ((r = sshkey_مقصد_base64(کلید, &keytext)) != 0) {
		error_fr(r, "sshkey_to_base64 failed");
		اذهب بیرون;
	}

	/* Turn the command into an argument vector */
	إذا (argv_تقسیم(options.authorized_کلیدها_command, &ac, &av, 0) != 0) {
		error("AuthorizedKeysCommand \"%s\" contains invalid quotes",
		    options.authorized_کلیدها_command);
		اذهب بیرون;
	}
	إذا (ac == 0) {
		error("AuthorizedKeysCommand \"%s\" yielded no arguments",
		    options.authorized_کلیدها_command);
		اذهب بیرون;
	}
	snprintf(uidstr, حجم(uidstr), "%llu",
	    (بیعلامت دراز دراز)user_pw->pw_uid);
	لكل (i = 1; i < ac; i++) {
		tmp = percent_expand(av[i],
		    "C", conn_id,
		    "D", rdomain,
		    "U", uidstr,
		    "u", user_pw->pw_name,
		    "h", user_pw->pw_dir,
		    "t", sshkey_ssh_name(کلید),
		    "f", کلید_fp,
		    "k", keytext,
		    (حرف *)عدم);
		إذا (tmp == عدم)
			fatal_f("percent_expand failed");
		حرر(av[i]);
		av[i] = tmp;
	}
	/* Prepare a printable command for logs, etc. */
	command = argv_assemble(ac, av);

	/*
	 * If AuthorizedKeysCommand was run without arguments
	 * then fall back to the old behaviour of passing the
	 * target username as a single argument.
	 */
	إذا (ac == 1) {
		av = xreallocarray(av, ac + 2, حجم(*av));
		av[1] = xstrdup(user_pw->pw_name);
		av[2] = عدم;
		/* Fix up command too, since it is used in log messages */
		حرر(command);
		xasprintf(&command, "%s %s", av[0], av[1]);
	}

	إذا ((pid = subprocess("AuthorizedKeysCommand", command,
	    ac, av, &f,
	    SSH_SUBPROCESS_STDOUT_CAPTURE|SSH_SUBPROCESS_STDERR_DISCARD,
	    runas_pw, temporarily_use_uid, restore_uid)) == 0)
		اذهب بیرون;

	uid_swapped = 1;
	temporarily_use_uid(runas_pw);

	ok = auth_check_authkeys_file(user_pw, f,
	    options.authorized_کلیدها_command, کلید, remote_ip,
	    remote_host, authoptsp);

	fclose(f);
	f = عدم;

	إذا (exited_cleanly(pid, "AuthorizedKeysCommand", command, 0) != 0)
		اذهب بیرون;

	/* Read completed successfully */
	یافت_کلید = ok;
 بیرون:
	إذا (f != عدم)
		fclose(f);
	ssh_signal(SIGCHLD, osigchld);
	لكل (i = 0; i < ac; i++)
		حرر(av[i]);
	حرر(av);
	إذا (uid_swapped)
		restore_uid();
	حرر(command);
	حرر(username);
	حرر(کلید_fp);
	حرر(keytext);
	أرجع یافت_کلید;
}

/*
 * Check whether key authenticates and authorises the user.
 */
صحيح
user_کلید_allowed(بنية ssh *ssh, بنية passwd *pw, بنية sshkey *کلید,
    صحيح auth_attempt, بنية sshauthopt **authoptsp)
{
	u_int success = 0, i, j;
	حرف *file = عدم, *conn_id;
	بنية sshauthopt *opts = عدم;
	ثابت حرف *rdomain, *remote_ip, *remote_host;

	إذا (authoptsp != عدم)
		*authoptsp = عدم;

	إذا (auth_کلید_is_revoked(کلید))
		أرجع 0;
	إذا (sshkey_is_cert(کلید) &&
	    auth_کلید_is_revoked(کلید->cert->signature_کلید))
		أرجع 0;

	إذا ((rdomain = ssh_packet_rdomain_درون(ssh)) == عدم)
		rdomain = "";
	remote_ip = ssh_remote_ipaddr(ssh);
	remote_host = auth_get_canonical_hostname(ssh, options.use_dns);
	xasprintf(&conn_id, "%s %d %s %d",
	    ssh_local_ipaddr(ssh), ssh_local_پورت(ssh),
	    remote_ip, ssh_remote_پورت(ssh));

	لكل (i = 0; !success && i < options.رقم_authkeys_files; i++) {
		صحيح r;
		glob_t gl;

		إذا (strcasecmp(options.authorized_کلیدها_files[i], "none") == 0)
			استمر;
		file = expand_authorized_کلیدها(
		    options.authorized_کلیدها_files[i], pw);
		temporarily_use_uid(pw);
		r = glob(file, 0, عدم, &gl);
		restore_uid();
		إذا (r != 0) {
			إذا (r != GLOB_NOMATCH) {
				logit_f("glob \"%s\" failed", file);
			}
			حرر(file);
			file = عدم;
			استمر;
		} وإلا إذا (gl.gl_pathc > بیشترین_صحیح) {
			fatal_f("too many glob results for \"%s\"", file);
		} وإلا إذا (gl.gl_pathc > 1) {
			debug2_f("glob \"%s\" returned %zu matches", file,
			    gl.gl_pathc);
		}
		لكل (j = 0; !success && j < gl.gl_pathc; j++) {
			success = user_کلید_allowed2(pw, کلید, gl.gl_pathv[j],
			    remote_ip, remote_host, &opts);
			إذا (!success) {
				sshauthopt_free(opts);
				opts = عدم;
			}
		}
		حرر(file);
		file = عدم;
		globfree(&gl);
	}
	إذا (success)
		اذهب بیرون;

	إذا ((success = user_cert_trusted_ca(pw, کلید, remote_ip, remote_host,
	    conn_id, rdomain, &opts)) != 0)
		اذهب بیرون;
	sshauthopt_free(opts);
	opts = عدم;

	إذا ((success = user_کلید_command_allowed2(pw, کلید, remote_ip,
	    remote_host, conn_id, rdomain, &opts)) != 0)
		اذهب بیرون;
	sshauthopt_free(opts);
	opts = عدم;

 بیرون:
	حرر(conn_id);
	إذا (success && authoptsp != عدم) {
		*authoptsp = opts;
		opts = عدم;
	}
	sshauthopt_free(opts);
	أرجع success;
}

Authmethod روش_pubkey = {
	&methodcfg_pubkey,
	userauth_pubkey,
};
