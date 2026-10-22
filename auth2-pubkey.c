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
#که_تعریف_شوی GSSAPI
#ضمن "ssh-gss.h"
#د_که_پای
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
format_کلی(ثابت بنية sshkey *کلی)
{
	حرف *ret, *fp = sshkey_fingerprint(کلی,
	    options.fingerprint_hash, SSH_FP_DEFAULT);

	xasprintf(&ret, "%s %s", sshkey_type(کلی), fp);
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
userauth_pubkey(بنية ssh *ssh, ثابت حرف *لاره)
{
	Authctxt *authctxt = ssh->authctxt;
	بنية passwd *pw = authctxt->pw;
	بنية sshbuf *keyblob = عدم, *b = عدم;
	بنية sshkey *کلی = عدم, *hostkey = عدم;
	حرف *pkalg = عدم, *userstyle = عدم, *کلی_s = عدم, *ca_s = عدم;
	حرف *keystring = عدم;
	u_char *sig = عدم, have_sig;
	اندازه_t slen;
	صحيح hostbound, r, pktype;
	صحيح req_presence = 0, req_verify = 0, authenticated = 0;
	بنية sshauthopt *authopts = عدم;
	بنية sshkey_sig_details *sig_details = عدم;

	hostbound = strcmp(لاره, "publickey-hostbound-v00@openssh.com") == 0;

	إذا ((r = sshpkt_get_u8(ssh, &have_sig)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &pkalg, عدم)) != 0 ||
	    (r = sshpkt_getb_froms(ssh, &keyblob)) != 0)
		fatal_fr(r, "parse %s packet", لاره);

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
	إذا (pktype == کلی_UNSPEC) {
		/* this is perfectly legal */
		verbose_f("unsupported public key algorithm: %s", pkalg);
		اذهب بشپړ;
	}
	إذا (سمون_نمونه_list(pkalg, options.pubkey_accepted_algos, 0) != 1) {
		logit_f("signature algorithm %s not in "
		    "PubkeyAcceptedAlgorithms", pkalg);
		اذهب بشپړ;
	}
	إذا ((b = sshbuf_fromb(keyblob)) == عدم)
		fatal_f("sshbuf_fromb failed");
	بدل ((r = sshkey_fromb_allowlist(b, &کلی,
	    options.pubkey_accepted_algos, options.ca_sign_algorithms))) {
	حالة 0:
		/* ok */
		اكسر;
	حالة SSH_ERR_کلی_ALG_UNSUPPORTED:
		/* This shouldn't happen unless the client is being weird */
		logit_f("key algorithm differs from signature algorithm %s and "
		    "is not in PubkeyAcceptedAlgorithms", pkalg);
		اذهب بشپړ;
	حالة SSH_ERR_SIGN_ALG_UNSUPPORTED:
		logit_fr(r, "certificate signature algorithm not in "
		    "CASignatureAlgorithm");
		اذهب بشپړ;
	افتراضي:
		error_fr(r, "parse key");
		اذهب بشپړ;
	}
	sshbuf_free(b);
	b = عدم;

	/* USERAUTH_REQUEST signature type should match key's type */
	إذا (کلی->type != pktype || (sshkey_type_plain(pktype) == کلی_ECDSA &&
	    sshkey_ecdsa_nid_from_name(pkalg) != کلی->ecdsa_nid)) {
		error_f("key type mismatch for decoded key "
		    "(received %s, expected %s)", sshkey_ssh_name(کلی), pkalg);
		اذهب بشپړ;
	}
	إذا (auth2_کلی_already_کارول_شوی(authctxt, کلی)) {
		logit("refusing previously-used %s key", sshkey_type(کلی));
		اذهب بشپړ;
	}
	إذا ((r = sshkey_check_rsa_اوږدتیا(کلی,
	    options.required_rsa_اندازه)) != 0) {
		logit_r(r, "refusing %s key", sshkey_type(کلی));
		اذهب بشپړ;
	}
	کلی_s = format_کلی(کلی);
	إذا (sshkey_is_cert(کلی))
		ca_s = format_کلی(کلی->cert->signature_کلی);

	إذا (have_sig) {
		debug3_f("%s have %s signature for %s%s%s",
		    لاره, pkalg, کلی_s,
		    ca_s == عدم ? "" : " CA ", ca_s == عدم ? "" : ca_s);
		إذا ((r = sshpkt_get_string(ssh, &sig, &slen)) != 0 ||
		    (r = sshpkt_get_پای_ټکی(ssh)) != 0)
			fatal_fr(r, "parse signature packet");
		إذا ((b = sshbuf_new()) == عدم)
			fatal_f("sshbuf_new failed");
		إذا ((r = sshbuf_put_stringb(b,
		    ssh->kex->session_id)) != 0)
			fatal_fr(r, "put session id");
		إذا (!authctxt->valid || authctxt->user == عدم) {
			debug2_f("disabled because of invalid user");
			اذهب بشپړ;
		}
		/* reconstruct packet */
		xasprintf(&userstyle, "%s%s%s", authctxt->user,
		    authctxt->style ? ":" : "",
		    authctxt->style ? authctxt->style : "");
		إذا ((r = sshbuf_put_u8(b, SSH2_پیغام_USERAUTH_REQUEST)) != 0 ||
		    (r = sshbuf_put_cstring(b, userstyle)) != 0 ||
		    (r = sshbuf_put_cstring(b, authctxt->service)) != 0 ||
		    (r = sshbuf_put_cstring(b, لاره)) != 0 ||
		    (r = sshbuf_put_u8(b, have_sig)) != 0 ||
		    (r = sshbuf_put_cstring(b, pkalg)) != 0 ||
		    (r = sshbuf_put_stringb(b, keyblob)) != 0)
			fatal_fr(r, "reconstruct %s packet", لاره);
		إذا (hostbound &&
		    (r = sshkey_puts(ssh->kex->initial_hostkey, b)) != 0)
			fatal_fr(r, "reconstruct %s packet", لاره);
#که_تعریف_شوی DEBUG_PK
		sshbuf_dump(b, stderr);
#د_که_پای
		/* test for correct signature */
		authenticated = 0;
		إذا (mm_user_کلی_allowed(ssh, pw, کلی, 1, &authopts) &&
		    mm_sshkey_verify(کلی, sig, slen,
		    sshbuf_ptr(b), sshbuf_len(b),
		    (ssh->compat & SSH_BUG_SIGTYPE) == 0 ? pkalg : عدم,
		    ssh->compat, &sig_details) == 0) {
			authenticated = 1;
		}
		إذا (authenticated == 1 && sig_details != عدم) {
			auth2_ریکارډ_info(authctxt, "signature count = %u",
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
				    "not met ", کلی_s,
				    authctxt->valid ? "" : "invalid user ",
				    authctxt->user, ssh_remote_ipaddr(ssh),
				    ssh_remote_پورټ(ssh));
				authenticated = 0;
				اذهب بشپړ;
			}
			req_verify = (options.pubkey_auth_options &
			    PUBKEYAUTH_VERIFY_REQUIRED) ||
			    authopts->require_verify;
			إذا (req_verify && (sig_details->sk_flags &
			    SSH_SK_USER_VERIFICATION_REQD) == 0) {
				error("public key %s signature for %s%s from "
				    "%.128s port %d rejected: user "
				    "verification requirement not met ", کلی_s,
				    authctxt->valid ? "" : "invalid user ",
				    authctxt->user, ssh_remote_ipaddr(ssh),
				    ssh_remote_پورټ(ssh));
				authenticated = 0;
				اذهب بشپړ;
			}
		}
		auth2_ریکارډ_کلی(authctxt, authenticated, کلی);
	} وإلا {
		debug_f("%s test pkalg %s pkblob %s%s%s", لاره, pkalg, کلی_s,
		    ca_s == عدم ? "" : " CA ", ca_s == عدم ? "" : ca_s);

		إذا ((r = sshpkt_get_پای_ټکی(ssh)) != 0)
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
		    mm_user_کلی_allowed(ssh, pw, کلی, 0, عدم)) {
			إذا ((r = sshpkt_پیل(ssh, SSH2_پیغام_USERAUTH_PK_OK))
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
بشپړ:
	إذا (authenticated == 1 && auth_activate_options(ssh, authopts) != 0) {
		debug_f("key options inconsistent with existing");
		authenticated = 0;
	}
	debug2_f("authenticated %d pkalg %s", authenticated, pkalg);

	sshbuf_free(b);
	sshbuf_free(keyblob);
	sshauthopt_free(authopts);
	sshkey_free(کلی);
	sshkey_free(hostkey);
	حرر(keystring);
	حرر(userstyle);
	حرر(pkalg);
	حرر(کلی_s);
	حرر(ca_s);
	حرر(sig);
	sshkey_sig_details_free(sig_details);
	أرجع authenticated;
}

ساكن صحيح
سمون_principals_file(بنية passwd *pw, حرف *file,
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
	} وإلا إذا (gl.gl_pathc > لوی_عدد) {
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
سمون_principals_command(بنية passwd *user_pw, ثابت بنية sshkey *کلی,
    ثابت حرف *conn_id, ثابت حرف *rdomain, بنية sshauthopt **authoptsp)
{
	بنية passwd *runas_pw = عدم;
	ثابت بنية sshkey_cert *cert = کلی->cert;
	FILE *f = عدم;
	صحيح r, ok, وموندل_principal = 0;
	صحيح i, ac = 0, uid_swapped = 0;
	pid_t pid;
	حرف *tmp, *username = عدم, *command = عدم, **av = عدم;
	حرف *ca_fp = عدم, *کلی_fp = عدم, *catext = عدم, *keytext = عدم;
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
		اذهب بهر;
	}

	/* Turn the command into an argument vector */
	إذا (argv_وېشل(options.authorized_principals_command,
	    &ac, &av, 0) != 0) {
		error("AuthorizedPrincipalsCommand \"%s\" contains "
		    "invalid quotes", options.authorized_principals_command);
		اذهب بهر;
	}
	إذا (ac == 0) {
		error("AuthorizedPrincipalsCommand \"%s\" yielded no arguments",
		    options.authorized_principals_command);
		اذهب بهر;
	}
	إذا ((ca_fp = sshkey_fingerprint(cert->signature_کلی,
	    options.fingerprint_hash, SSH_FP_DEFAULT)) == عدم) {
		error_f("sshkey_fingerprint failed");
		اذهب بهر;
	}
	إذا ((کلی_fp = sshkey_fingerprint(کلی,
	    options.fingerprint_hash, SSH_FP_DEFAULT)) == عدم) {
		error_f("sshkey_fingerprint failed");
		اذهب بهر;
	}
	إذا ((r = sshkey_منزل_base64(cert->signature_کلی, &catext)) != 0) {
		error_fr(r, "sshkey_to_base64 failed");
		اذهب بهر;
	}
	إذا ((r = sshkey_منزل_base64(کلی, &keytext)) != 0) {
		error_fr(r, "sshkey_to_base64 failed");
		اذهب بهر;
	}
	snprintf(serial_s, حجم(serial_s), "%llu",
	    (بینښه اوږد اوږد)cert->serial);
	snprintf(uidstr, حجم(uidstr), "%llu",
	    (بینښه اوږد اوږد)user_pw->pw_uid);
	لكل (i = 1; i < ac; i++) {
		tmp = percent_expand(av[i],
		    "C", conn_id,
		    "D", rdomain,
		    "U", uidstr,
		    "u", user_pw->pw_name,
		    "h", user_pw->pw_dir,
		    "t", sshkey_ssh_name(کلی),
		    "T", sshkey_ssh_name(cert->signature_کلی),
		    "f", کلی_fp,
		    "F", ca_fp,
		    "k", keytext,
		    "K", catext,
		    "i", cert->کلی_id,
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
		اذهب بهر;

	uid_swapped = 1;
	temporarily_use_uid(runas_pw);

	ok = auth_process_principals(f, "(command)", cert, authoptsp);

	fclose(f);
	f = عدم;

	إذا (exited_cleanly(pid, "AuthorizedPrincipalsCommand", command, 0) != 0)
		اذهب بهر;

	/* Read completed successfully */
	وموندل_principal = ok;
 بهر:
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
	حرر(کلی_fp);
	حرر(catext);
	حرر(keytext);
	أرجع وموندل_principal;
}

/* Authenticate a certificate key against TrustedUserCAKeys */
ساكن صحيح
user_cert_trusted_ca(بنية passwd *pw, بنية sshkey *کلی,
    ثابت حرف *remote_ip, ثابت حرف *remote_host,
    ثابت حرف *conn_id, ثابت حرف *rdomain, بنية sshauthopt **authoptsp)
{
	حرف *ca_fp, *principals_file = عدم;
	ثابت حرف *reason;
	بنية sshauthopt *principals_opts = عدم, *cert_opts = عدم;
	بنية sshauthopt *final_opts = عدم;
	صحيح r, ret = 0, وموندل_principal = 0, use_authorized_principals;

	إذا (authoptsp != عدم)
		*authoptsp = عدم;

	إذا (!sshkey_is_cert(کلی) || options.trusted_user_ca_کلیګانې == عدم)
		أرجع 0;

	إذا ((ca_fp = sshkey_fingerprint(کلی->cert->signature_کلی,
	    options.fingerprint_hash, SSH_FP_DEFAULT)) == عدم)
		أرجع 0;

	إذا ((r = sshkey_دننه_file(کلی->cert->signature_کلی,
	    options.trusted_user_ca_کلیګانې, 1, 0)) != 0) {
		debug2_fr(r, "CA %s %s is not listed in %s",
		    sshkey_type(کلی->cert->signature_کلی), ca_fp,
		    options.trusted_user_ca_کلیګانې);
		اذهب بهر;
	}
	/*
	 * If AuthorizedPrincipals is in use, then compare the certificate
	 * principals against the names in that file rather than matching
	 * against the username.
	 */
	إذا ((principals_file = authorized_principals_file(pw)) != عدم) {
		إذا (سمون_principals_file(pw, principals_file,
		    کلی->cert, &principals_opts))
			وموندل_principal = 1;
	}
	/* Try querying command if specified */
	إذا (!وموندل_principal && سمون_principals_command(pw, کلی,
	    conn_id, rdomain, &principals_opts))
		وموندل_principal = 1;
	/* If principals file or command is specified, then require a match */
	use_authorized_principals = principals_file != عدم ||
	    options.authorized_principals_command != عدم;
	إذا (!وموندل_principal && use_authorized_principals) {
		reason = "Certificate does not contain an authorized principal";
		اذهب fail_reason;
	}
	إذا (use_authorized_principals && principals_opts == عدم)
		fatal_f("internal error: missing principals_opts");
	إذا (sshkey_cert_check_authority_now(کلی, 0, 0,
	    use_authorized_principals ? عدم : pw->pw_name, &reason) != 0)
		اذهب fail_reason;

	/* Check authority from options in key and from principals file/cmd */
	إذا ((cert_opts = sshauthopt_from_cert(کلی)) == عدم) {
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
		إذا ((final_opts = sshauthopt_یوځای(principals_opts,
		    cert_opts, &reason)) == عدم) {
 fail_reason:
			error("Refusing certificate ID \"%s\" serial=%llu "
			    "signed by %s CA %s: %s", کلی->cert->کلی_id,
			    (بینښه اوږد اوږد)کلی->cert->serial,
			    sshkey_type(کلی->cert->signature_کلی), ca_fp,
			    reason);
			auth_debug_جمع_کړه("Refused Certificate ID \"%s\" "
			    "serial=%llu: %s", کلی->cert->کلی_id,
			    (بینښه اوږد اوږد)کلی->cert->serial, reason);
			اذهب بهر;
		}
	}

	/* Success */
	verbose("Accepted certificate ID \"%s\" (serial %llu) signed by "
	    "%s CA %s via %s", کلی->cert->کلی_id,
	    (بینښه اوږد اوږد)کلی->cert->serial,
	    sshkey_type(کلی->cert->signature_کلی), ca_fp,
	    options.trusted_user_ca_کلیګانې);
	إذا (authoptsp != عدم) {
		*authoptsp = final_opts;
		final_opts = عدم;
	}
	ret = 1;
 بهر:
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
user_کلی_allowed2(بنية passwd *pw, بنية sshkey *کلی,
    حرف *file, ثابت حرف *remote_ip, ثابت حرف *remote_host,
    بنية sshauthopt **authoptsp)
{
	FILE *f;
	صحيح وموندل_کلی = 0;

	إذا (authoptsp != عدم)
		*authoptsp = عدم;

	/* Temporarily use the user's uid. */
	temporarily_use_uid(pw);

	debug("trying public key file %s", file);
	إذا ((f = auth_openkeyfile(file, pw, options.strict_modes)) != عدم) {
		وموندل_کلی = auth_check_authkeys_file(pw, f, file,
		    کلی, remote_ip, remote_host, authoptsp);
		fclose(f);
	}

	restore_uid();
	أرجع وموندل_کلی;
}

/*
 * Checks whether key is allowed in output of command.
 * returns 1 if the key is allowed or 0 otherwise.
 */
ساكن صحيح
user_کلی_command_allowed2(بنية passwd *user_pw, بنية sshkey *کلی,
    ثابت حرف *remote_ip, ثابت حرف *remote_host,
    ثابت حرف *conn_id, ثابت حرف *rdomain, بنية sshauthopt **authoptsp)
{
	بنية passwd *runas_pw = عدم;
	FILE *f = عدم;
	صحيح r, ok, وموندل_کلی = 0;
	صحيح i, uid_swapped = 0, ac = 0;
	pid_t pid;
	حرف *username = عدم, *کلی_fp = عدم, *keytext = عدم;
	حرف uidstr[32], *tmp, *command = عدم, **av = عدم;
	فراغ (*osigchld)(صحيح);

	إذا (authoptsp != عدم)
		*authoptsp = عدم;
	إذا (options.authorized_کلیګانې_command == عدم)
		أرجع 0;
	إذا (options.authorized_کلیګانې_command_user == عدم) {
		error("No user for AuthorizedKeysCommand specified, skipping");
		أرجع 0;
	}

	/*
	 * NB. all returns later this function should go via "out" to
	 * ensure the original SIGCHLD handler is restored properly.
	 */
	osigchld = ssh_signal(SIGCHLD, SIG_DFL);

	/* Prepare and verify the user for the command */
	username = percent_expand(options.authorized_کلیګانې_command_user,
	    "u", user_pw->pw_name, (حرف *)عدم);
	runas_pw = getpwnam(username);
	إذا (runas_pw == عدم) {
		error("AuthorizedKeysCommandUser \"%s\" not found: %s",
		    username, strerror(errno));
		اذهب بهر;
	}

	/* Prepare AuthorizedKeysCommand */
	إذا ((کلی_fp = sshkey_fingerprint(کلی, options.fingerprint_hash,
	    SSH_FP_DEFAULT)) == عدم) {
		error_f("sshkey_fingerprint failed");
		اذهب بهر;
	}
	إذا ((r = sshkey_منزل_base64(کلی, &keytext)) != 0) {
		error_fr(r, "sshkey_to_base64 failed");
		اذهب بهر;
	}

	/* Turn the command into an argument vector */
	إذا (argv_وېشل(options.authorized_کلیګانې_command, &ac, &av, 0) != 0) {
		error("AuthorizedKeysCommand \"%s\" contains invalid quotes",
		    options.authorized_کلیګانې_command);
		اذهب بهر;
	}
	إذا (ac == 0) {
		error("AuthorizedKeysCommand \"%s\" yielded no arguments",
		    options.authorized_کلیګانې_command);
		اذهب بهر;
	}
	snprintf(uidstr, حجم(uidstr), "%llu",
	    (بینښه اوږد اوږد)user_pw->pw_uid);
	لكل (i = 1; i < ac; i++) {
		tmp = percent_expand(av[i],
		    "C", conn_id,
		    "D", rdomain,
		    "U", uidstr,
		    "u", user_pw->pw_name,
		    "h", user_pw->pw_dir,
		    "t", sshkey_ssh_name(کلی),
		    "f", کلی_fp,
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
		اذهب بهر;

	uid_swapped = 1;
	temporarily_use_uid(runas_pw);

	ok = auth_check_authkeys_file(user_pw, f,
	    options.authorized_کلیګانې_command, کلی, remote_ip,
	    remote_host, authoptsp);

	fclose(f);
	f = عدم;

	إذا (exited_cleanly(pid, "AuthorizedKeysCommand", command, 0) != 0)
		اذهب بهر;

	/* Read completed successfully */
	وموندل_کلی = ok;
 بهر:
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
	حرر(کلی_fp);
	حرر(keytext);
	أرجع وموندل_کلی;
}

/*
 * Check whether key authenticates and authorises the user.
 */
صحيح
user_کلی_allowed(بنية ssh *ssh, بنية passwd *pw, بنية sshkey *کلی,
    صحيح auth_attempt, بنية sshauthopt **authoptsp)
{
	u_int success = 0, i, j;
	حرف *file = عدم, *conn_id;
	بنية sshauthopt *opts = عدم;
	ثابت حرف *rdomain, *remote_ip, *remote_host;

	إذا (authoptsp != عدم)
		*authoptsp = عدم;

	إذا (auth_کلی_is_revoked(کلی))
		أرجع 0;
	إذا (sshkey_is_cert(کلی) &&
	    auth_کلی_is_revoked(کلی->cert->signature_کلی))
		أرجع 0;

	إذا ((rdomain = ssh_packet_rdomain_دننه(ssh)) == عدم)
		rdomain = "";
	remote_ip = ssh_remote_ipaddr(ssh);
	remote_host = auth_get_canonical_hostname(ssh, options.use_dns);
	xasprintf(&conn_id, "%s %d %s %d",
	    ssh_local_ipaddr(ssh), ssh_local_پورټ(ssh),
	    remote_ip, ssh_remote_پورټ(ssh));

	لكل (i = 0; !success && i < options.عدد_authkeys_files; i++) {
		صحيح r;
		glob_t gl;

		إذا (strcasecmp(options.authorized_کلیګانې_files[i], "none") == 0)
			استمر;
		file = expand_authorized_کلیګانې(
		    options.authorized_کلیګانې_files[i], pw);
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
		} وإلا إذا (gl.gl_pathc > لوی_عدد) {
			fatal_f("too many glob results for \"%s\"", file);
		} وإلا إذا (gl.gl_pathc > 1) {
			debug2_f("glob \"%s\" returned %zu matches", file,
			    gl.gl_pathc);
		}
		لكل (j = 0; !success && j < gl.gl_pathc; j++) {
			success = user_کلی_allowed2(pw, کلی, gl.gl_pathv[j],
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
		اذهب بهر;

	إذا ((success = user_cert_trusted_ca(pw, کلی, remote_ip, remote_host,
	    conn_id, rdomain, &opts)) != 0)
		اذهب بهر;
	sshauthopt_free(opts);
	opts = عدم;

	إذا ((success = user_کلی_command_allowed2(pw, کلی, remote_ip,
	    remote_host, conn_id, rdomain, &opts)) != 0)
		اذهب بهر;
	sshauthopt_free(opts);
	opts = عدم;

 بهر:
	حرر(conn_id);
	إذا (success && authoptsp != عدم) {
		*authoptsp = opts;
		opts = عدم;
	}
	sshauthopt_free(opts);
	أرجع success;
}

Authmethod لاره_pubkey = {
	&methodcfg_pubkey,
	userauth_pubkey,
};
