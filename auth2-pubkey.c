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

#شامل "includes.h"

#شامل <sys/types.h>

#شامل <stdlib.h>
#شامل <errno.h>
#شامل <paths.h>
#شامل <pwd.h>
#شامل <glob.h>
#شامل <signal.h>
#شامل <stdio.h>
#شامل <stdarg.h>
#شامل <string.h>
#شامل <time.h>
#شامل <unistd.h>
#شامل <limits.h>

#شامل "xmalloc.h"
#شامل "ssh.h"
#شامل "ssh2.h"
#شامل "packet.h"
#شامل "kex.h"
#شامل "sshbuf.h"
#شامل "log.h"
#شامل "misc.h"
#شامل "servconf.h"
#شامل "compat.h"
#شامل "sshkey.h"
#شامل "hostfile.h"
#شامل "auth.h"
#شامل "pathnames.h"
#شامل "uidswap.h"
#شامل "auth-options.h"
#شامل "canohost.h"
#ifdef GSSAPI
#شامل "ssh-gss.h"
#endif
#شامل "monitor_wrap.h"
#شامل "authfile.h"
#شامل "match.h"
#شامل "ssherr.h"
#شامل "channels.h" /* XXX for session.h */
#شامل "session.h" /* XXX for child_set_env(); refactor? */
#شامل "sk-api.h"

/* import */
بیرونی ServerOptions options;
بیرونی ساختار authmethod_cfg methodcfg_pubkey;

ایستا نویسه *
format_کلید(ثابت ساختار sshkey *کلید)
{
	نویسه *ret, *fp = sshkey_fingerprint(کلید,
	    options.fingerprint_hash, SSH_FP_DEFAULT);

	xasprintf(&ret, "%s %s", sshkey_type(کلید), fp);
	آزاد(fp);
	بازگشت ret;
}

/*
 * Verify that the hostkey in a publickey-hostbound-v00@openssh.com userauth
 * request matches the hostkey that was negotiated during initial KEX.
 */
ایستا تهی
check_hostbound_hostkey(ساختار ssh *ssh)
{
	صحیح r;
	ساختار sshbuf *our_hostkey_blob, *their_hostkey_blob;

	اگر (ssh->kex->initial_hostkey == پوچ)
		fatal_f("internal error: initial hostkey not recorded");
	اگر ((our_hostkey_blob = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new failed");
	اگر ((r = sshpkt_getb_froms(ssh, &their_hostkey_blob)) != 0)
		fatal_fr(r, "parse hostkey");
	اگر ((r = sshkey_putb(ssh->kex->initial_hostkey, our_hostkey_blob)) != 0)
		fatal_fr(r, "serialise hostkey");
	اگر ((r = sshbuf_equals(our_hostkey_blob, their_hostkey_blob)) != 0)
		fatal_f("packet contained wrong host key");
	sshbuf_free(our_hostkey_blob);
	sshbuf_free(their_hostkey_blob);
}

ایستا صحیح
userauth_pubkey(ساختار ssh *ssh, ثابت نویسه *method)
{
	Authctxt *authctxt = ssh->authctxt;
	ساختار passwd *pw = authctxt->pw;
	ساختار sshbuf *keyblob = پوچ, *b = پوچ;
	ساختار sshkey *کلید = پوچ, *hostkey = پوچ;
	نویسه *pkalg = پوچ, *userstyle = پوچ, *کلید_s = پوچ, *ca_s = پوچ;
	نویسه *keystring = پوچ;
	u_char *sig = پوچ, have_sig;
	size_t slen;
	صحیح hostbound, r, pktype;
	صحیح req_presence = 0, req_verify = 0, authenticated = 0;
	ساختار sshauthopt *authopts = پوچ;
	ساختار sshkey_sig_details *sig_details = پوچ;

	hostbound = strcmp(method, "publickey-hostbound-v00@openssh.com") == 0;

	اگر ((r = sshpkt_get_u8(ssh, &have_sig)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &pkalg, پوچ)) != 0 ||
	    (r = sshpkt_getb_froms(ssh, &keyblob)) != 0)
		fatal_fr(r, "parse %s packet", method);

	/* hostbound auth includes the hostkey offered at initial KEX */
	اگر (hostbound)
		check_hostbound_hostkey(ssh); /* fatals on error */

	اگر (log_level_get() >= SYSLOG_LEVEL_DEBUG2) {
		اگر ((b = sshbuf_fromb(keyblob)) == پوچ)
			fatal_f("sshbuf_fromb failed");
		اگر ((keystring = sshbuf_dtob64_string(b, 0)) == پوچ)
			fatal_f("sshbuf_dtob64 failed");
		debug2_f("%s user %s %s public key %s %s",
		    authctxt->valid ? "valid" : "invalid", authctxt->user,
		    have_sig ? "attempting" : "querying", pkalg, keystring);
		sshbuf_free(b);
		b = پوچ;
	}

	pktype = sshkey_type_from_name(pkalg);
	اگر (pktype == کلید_UNSPEC) {
		/* this is perfectly legal */
		verbose_f("unsupported public key algorithm: %s", pkalg);
		برو done;
	}
	اگر (match_pattern_list(pkalg, options.pubkey_accepted_algos, 0) != 1) {
		logit_f("signature algorithm %s not in "
		    "PubkeyAcceptedAlgorithms", pkalg);
		برو done;
	}
	اگر ((b = sshbuf_fromb(keyblob)) == پوچ)
		fatal_f("sshbuf_fromb failed");
	انتخاب ((r = sshkey_fromb_allowlist(b, &کلید,
	    options.pubkey_accepted_algos, options.ca_sign_algorithms))) {
	حالت 0:
		/* ok */
		بشکن;
	حالت SSH_ERR_کلید_ALG_UNSUPPORTED:
		/* This shouldn't happen unless the client is being weird */
		logit_f("key algorithm differs from signature algorithm %s and "
		    "is not in PubkeyAcceptedAlgorithms", pkalg);
		برو done;
	حالت SSH_ERR_SIGN_ALG_UNSUPPORTED:
		logit_fr(r, "certificate signature algorithm not in "
		    "CASignatureAlgorithm");
		برو done;
	پیشفرض:
		error_fr(r, "parse key");
		برو done;
	}
	sshbuf_free(b);
	b = پوچ;

	/* USERAUTH_REQUEST signature type should match key's type */
	اگر (کلید->type != pktype || (sshkey_type_plain(pktype) == کلید_ECDSA &&
	    sshkey_ecdsa_nid_from_name(pkalg) != کلید->ecdsa_nid)) {
		error_f("key type mismatch for decoded key "
		    "(received %s, expected %s)", sshkey_ssh_name(کلید), pkalg);
		برو done;
	}
	اگر (auth2_کلید_already_used(authctxt, کلید)) {
		logit("refusing previously-used %s key", sshkey_type(کلید));
		برو done;
	}
	اگر ((r = sshkey_check_rsa_length(کلید,
	    options.required_rsa_size)) != 0) {
		logit_r(r, "refusing %s key", sshkey_type(کلید));
		برو done;
	}
	کلید_s = format_کلید(کلید);
	اگر (sshkey_is_cert(کلید))
		ca_s = format_کلید(کلید->cert->signature_کلید);

	اگر (have_sig) {
		debug3_f("%s have %s signature for %s%s%s",
		    method, pkalg, کلید_s,
		    ca_s == پوچ ? "" : " CA ", ca_s == پوچ ? "" : ca_s);
		اگر ((r = sshpkt_get_string(ssh, &sig, &slen)) != 0 ||
		    (r = sshpkt_get_end(ssh)) != 0)
			fatal_fr(r, "parse signature packet");
		اگر ((b = sshbuf_new()) == پوچ)
			fatal_f("sshbuf_new failed");
		اگر ((r = sshbuf_put_stringb(b,
		    ssh->kex->session_id)) != 0)
			fatal_fr(r, "put session id");
		اگر (!authctxt->valid || authctxt->user == پوچ) {
			debug2_f("disabled because of invalid user");
			برو done;
		}
		/* reconstruct packet */
		xasprintf(&userstyle, "%s%s%s", authctxt->user,
		    authctxt->style ? ":" : "",
		    authctxt->style ? authctxt->style : "");
		اگر ((r = sshbuf_put_u8(b, SSH2_پیام_USERAUTH_REQUEST)) != 0 ||
		    (r = sshbuf_put_cstring(b, userstyle)) != 0 ||
		    (r = sshbuf_put_cstring(b, authctxt->service)) != 0 ||
		    (r = sshbuf_put_cstring(b, method)) != 0 ||
		    (r = sshbuf_put_u8(b, have_sig)) != 0 ||
		    (r = sshbuf_put_cstring(b, pkalg)) != 0 ||
		    (r = sshbuf_put_stringb(b, keyblob)) != 0)
			fatal_fr(r, "reconstruct %s packet", method);
		اگر (hostbound &&
		    (r = sshkey_puts(ssh->kex->initial_hostkey, b)) != 0)
			fatal_fr(r, "reconstruct %s packet", method);
#ifdef DEBUG_PK
		sshbuf_dump(b, stderr);
#endif
		/* test for correct signature */
		authenticated = 0;
		اگر (mm_user_کلید_allowed(ssh, pw, کلید, 1, &authopts) &&
		    mm_sshkey_verify(کلید, sig, slen,
		    sshbuf_ptr(b), sshbuf_len(b),
		    (ssh->compat & SSH_BUG_SIGTYPE) == 0 ? pkalg : پوچ,
		    ssh->compat, &sig_details) == 0) {
			authenticated = 1;
		}
		اگر (authenticated == 1 && sig_details != پوچ) {
			auth2_record_info(authctxt, "signature count = %u",
			    sig_details->sk_counter);
			debug_f("sk_counter = %u, sk_flags = 0x%02x",
			    sig_details->sk_counter, sig_details->sk_flags);
			req_presence = (options.pubkey_auth_options &
			    PUBKEYAUTH_TOUCH_REQUIRED) ||
			    !authopts->no_require_user_presence;
			اگر (req_presence && (sig_details->sk_flags &
			    SSH_SK_USER_PRESENCE_REQD) == 0) {
				error("public key %s signature for %s%s from "
				    "%.128s port %d rejected: user presence "
				    "(authenticator touch) requirement "
				    "not met ", کلید_s,
				    authctxt->valid ? "" : "invalid user ",
				    authctxt->user, ssh_remote_ipaddr(ssh),
				    ssh_remote_port(ssh));
				authenticated = 0;
				برو done;
			}
			req_verify = (options.pubkey_auth_options &
			    PUBKEYAUTH_VERIFY_REQUIRED) ||
			    authopts->require_verify;
			اگر (req_verify && (sig_details->sk_flags &
			    SSH_SK_USER_VERIFICATION_REQD) == 0) {
				error("public key %s signature for %s%s from "
				    "%.128s port %d rejected: user "
				    "verification requirement not met ", کلید_s,
				    authctxt->valid ? "" : "invalid user ",
				    authctxt->user, ssh_remote_ipaddr(ssh),
				    ssh_remote_port(ssh));
				authenticated = 0;
				برو done;
			}
		}
		auth2_record_کلید(authctxt, authenticated, کلید);
	} وگرنه {
		debug_f("%s test pkalg %s pkblob %s%s%s", method, pkalg, کلید_s,
		    ca_s == پوچ ? "" : " CA ", ca_s == پوچ ? "" : ca_s);

		اگر ((r = sshpkt_get_end(ssh)) != 0)
			fatal_fr(r, "parse packet");

		/* XXX fake reply and always send PK_OK ? */
		/*
		 * XXX this allows testing whether a user is allowed
		 * to login: if you happen to have a valid pubkey this
		 * message is sent. the message is NEVER sent at all
		 * if a user is not allowed to login. is this an
		 * issue? -markus
		 */
		اگر (authctxt->valid && authctxt->user != پوچ &&
		    mm_user_کلید_allowed(ssh, pw, کلید, 0, پوچ)) {
			اگر ((r = sshpkt_start(ssh, SSH2_پیام_USERAUTH_PK_OK))
			    != 0 ||
			    (r = sshpkt_put_cstring(ssh, pkalg)) != 0 ||
			    (r = sshpkt_put_stringb(ssh, keyblob)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0 ||
			    (r = ssh_packet_write_wait(ssh)) != 0)
				fatal_fr(r, "send packet");
			authctxt->postponed = 1;
		} وگرنه {
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
			اگر (authctxt->pk_ok_failures++ < options.max_pubkey_ok)
				authctxt->auth_failure_already_counted = 1;
			debug3_f("pubkey test %d of %d%s",
			    authctxt->pk_ok_failures, options.max_pubkey_ok,
			    authctxt->auth_failure_already_counted ?
			    "" : ": treating as authentication failure");
		 }
	}
done:
	اگر (authenticated == 1 && auth_activate_options(ssh, authopts) != 0) {
		debug_f("key options inconsistent with existing");
		authenticated = 0;
	}
	debug2_f("authenticated %d pkalg %s", authenticated, pkalg);

	sshbuf_free(b);
	sshbuf_free(keyblob);
	sshauthopt_free(authopts);
	sshkey_free(کلید);
	sshkey_free(hostkey);
	آزاد(keystring);
	آزاد(userstyle);
	آزاد(pkalg);
	آزاد(کلید_s);
	آزاد(ca_s);
	آزاد(sig);
	sshkey_sig_details_free(sig_details);
	بازگشت authenticated;
}

ایستا صحیح
match_principals_file(ساختار passwd *pw, نویسه *file,
    ساختار sshkey_cert *cert, ساختار sshauthopt **authoptsp)
{
	FILE *f;
	صحیح r, success = 0;
	size_t i;
	glob_t gl;
	ساختار sshauthopt *opts = پوچ;

	اگر (authoptsp != پوچ)
		*authoptsp = پوچ;

	temporarily_use_uid(pw);
	r = glob(file, 0, پوچ, &gl);
	restore_uid();
	اگر (r != 0) {
		اگر (r != GLOB_NOMATCH) {
			logit_f("glob \"%s\" failed", file);
		}
		بازگشت 0;
	} وگرنه اگر (gl.gl_pathc > INT_MAX) {
		fatal_f("too many glob results for \"%s\"", file);
	} وگرنه اگر (gl.gl_pathc > 1) {
		debug2_f("glob \"%s\" returned %zu matches", file,
		    gl.gl_pathc);
	}
	برای (i = 0; !success && i < gl.gl_pathc; i++) {
		temporarily_use_uid(pw);
		debug("trying authorized principals file %s", file);
		اگر ((f = auth_openprincipals(gl.gl_pathv[i], pw,
		    options.strict_modes)) == پوچ) {
			restore_uid();
			ادامه;
		}
		success = auth_process_principals(f, gl.gl_pathv[i],
		    cert, &opts);
		fclose(f);
		restore_uid();
		اگر (!success) {
			sshauthopt_free(opts);
			opts = پوچ;
		}
	}
	globfree(&gl);
	اگر (success && authoptsp != پوچ) {
		*authoptsp = opts;
		opts = پوچ;
	}
	sshauthopt_free(opts);
	بازگشت success;
}

/*
 * Checks whether principal is allowed in output of command.
 * returns 1 if the principal is allowed or 0 otherwise.
 */
ایستا صحیح
match_principals_command(ساختار passwd *user_pw, ثابت ساختار sshkey *کلید,
    ثابت نویسه *conn_id, ثابت نویسه *rdomain, ساختار sshauthopt **authoptsp)
{
	ساختار passwd *runas_pw = پوچ;
	ثابت ساختار sshkey_cert *cert = کلید->cert;
	FILE *f = پوچ;
	صحیح r, ok, found_principal = 0;
	صحیح i, ac = 0, uid_swapped = 0;
	pid_t pid;
	نویسه *tmp, *username = پوچ, *command = پوچ, **av = پوچ;
	نویسه *ca_fp = پوچ, *کلید_fp = پوچ, *catext = پوچ, *keytext = پوچ;
	نویسه serial_s[32], uidstr[32];
	تهی (*osigchld)(صحیح);

	اگر (authoptsp != پوچ)
		*authoptsp = پوچ;
	اگر (options.authorized_principals_command == پوچ)
		بازگشت 0;
	اگر (options.authorized_principals_command_user == پوچ) {
		error("No user for AuthorizedPrincipalsCommand specified, "
		    "skipping");
		بازگشت 0;
	}

	/*
	 * NB. all returns later this function should go via "out" to
	 * ensure the original SIGCHLD handler is restored properly.
	 */
	osigchld = ssh_signal(SIGCHLD, SIG_DFL);

	/* Prepare and verify the user for the command */
	username = percent_expand(options.authorized_principals_command_user,
	    "u", user_pw->pw_name, (نویسه *)پوچ);
	runas_pw = getpwnam(username);
	اگر (runas_pw == پوچ) {
		error("AuthorizedPrincipalsCommandUser \"%s\" not found: %s",
		    username, strerror(errno));
		برو out;
	}

	/* Turn the command into an argument vector */
	اگر (argv_split(options.authorized_principals_command,
	    &ac, &av, 0) != 0) {
		error("AuthorizedPrincipalsCommand \"%s\" contains "
		    "invalid quotes", options.authorized_principals_command);
		برو out;
	}
	اگر (ac == 0) {
		error("AuthorizedPrincipalsCommand \"%s\" yielded no arguments",
		    options.authorized_principals_command);
		برو out;
	}
	اگر ((ca_fp = sshkey_fingerprint(cert->signature_کلید,
	    options.fingerprint_hash, SSH_FP_DEFAULT)) == پوچ) {
		error_f("sshkey_fingerprint failed");
		برو out;
	}
	اگر ((کلید_fp = sshkey_fingerprint(کلید,
	    options.fingerprint_hash, SSH_FP_DEFAULT)) == پوچ) {
		error_f("sshkey_fingerprint failed");
		برو out;
	}
	اگر ((r = sshkey_to_base64(cert->signature_کلید, &catext)) != 0) {
		error_fr(r, "sshkey_to_base64 failed");
		برو out;
	}
	اگر ((r = sshkey_to_base64(کلید, &keytext)) != 0) {
		error_fr(r, "sshkey_to_base64 failed");
		برو out;
	}
	snprintf(serial_s, اندازه(serial_s), "%llu",
	    (unsigned long long)cert->serial);
	snprintf(uidstr, اندازه(uidstr), "%llu",
	    (unsigned long long)user_pw->pw_uid);
	برای (i = 1; i < ac; i++) {
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
		    (نویسه *)پوچ);
		اگر (tmp == پوچ)
			fatal_f("percent_expand failed");
		آزاد(av[i]);
		av[i] = tmp;
	}
	/* Prepare a printable command for logs, etc. */
	command = argv_assemble(ac, av);

	اگر ((pid = subprocess("AuthorizedPrincipalsCommand", command,
	    ac, av, &f,
	    SSH_SUBPROCESS_STDOUT_CAPTURE|SSH_SUBPROCESS_STDERR_DISCARD,
	    runas_pw, temporarily_use_uid, restore_uid)) == 0)
		برو out;

	uid_swapped = 1;
	temporarily_use_uid(runas_pw);

	ok = auth_process_principals(f, "(command)", cert, authoptsp);

	fclose(f);
	f = پوچ;

	اگر (exited_cleanly(pid, "AuthorizedPrincipalsCommand", command, 0) != 0)
		برو out;

	/* Read completed successfully */
	found_principal = ok;
 out:
	اگر (f != پوچ)
		fclose(f);
	ssh_signal(SIGCHLD, osigchld);
	برای (i = 0; i < ac; i++)
		آزاد(av[i]);
	آزاد(av);
	اگر (uid_swapped)
		restore_uid();
	آزاد(command);
	آزاد(username);
	آزاد(ca_fp);
	آزاد(کلید_fp);
	آزاد(catext);
	آزاد(keytext);
	بازگشت found_principal;
}

/* Authenticate a certificate key against TrustedUserCAKeys */
ایستا صحیح
user_cert_trusted_ca(ساختار passwd *pw, ساختار sshkey *کلید,
    ثابت نویسه *remote_ip, ثابت نویسه *remote_host,
    ثابت نویسه *conn_id, ثابت نویسه *rdomain, ساختار sshauthopt **authoptsp)
{
	نویسه *ca_fp, *principals_file = پوچ;
	ثابت نویسه *reason;
	ساختار sshauthopt *principals_opts = پوچ, *cert_opts = پوچ;
	ساختار sshauthopt *final_opts = پوچ;
	صحیح r, ret = 0, found_principal = 0, use_authorized_principals;

	اگر (authoptsp != پوچ)
		*authoptsp = پوچ;

	اگر (!sshkey_is_cert(کلید) || options.trusted_user_ca_کلیدها == پوچ)
		بازگشت 0;

	اگر ((ca_fp = sshkey_fingerprint(کلید->cert->signature_کلید,
	    options.fingerprint_hash, SSH_FP_DEFAULT)) == پوچ)
		بازگشت 0;

	اگر ((r = sshkey_in_file(کلید->cert->signature_کلید,
	    options.trusted_user_ca_کلیدها, 1, 0)) != 0) {
		debug2_fr(r, "CA %s %s is not listed in %s",
		    sshkey_type(کلید->cert->signature_کلید), ca_fp,
		    options.trusted_user_ca_کلیدها);
		برو out;
	}
	/*
	 * If AuthorizedPrincipals is in use, then compare the certificate
	 * principals against the names in that file rather than matching
	 * against the username.
	 */
	اگر ((principals_file = authorized_principals_file(pw)) != پوچ) {
		اگر (match_principals_file(pw, principals_file,
		    کلید->cert, &principals_opts))
			found_principal = 1;
	}
	/* Try querying command if specified */
	اگر (!found_principal && match_principals_command(pw, کلید,
	    conn_id, rdomain, &principals_opts))
		found_principal = 1;
	/* If principals file or command is specified, then require a match */
	use_authorized_principals = principals_file != پوچ ||
	    options.authorized_principals_command != پوچ;
	اگر (!found_principal && use_authorized_principals) {
		reason = "Certificate does not contain an authorized principal";
		برو fail_reason;
	}
	اگر (use_authorized_principals && principals_opts == پوچ)
		fatal_f("internal error: missing principals_opts");
	اگر (sshkey_cert_check_authority_now(کلید, 0, 0,
	    use_authorized_principals ? پوچ : pw->pw_name, &reason) != 0)
		برو fail_reason;

	/* Check authority from options in key and from principals file/cmd */
	اگر ((cert_opts = sshauthopt_from_cert(کلید)) == پوچ) {
		reason = "Invalid certificate options";
		برو fail_reason;
	}
	اگر (auth_authorise_keyopts(pw, cert_opts, 0,
	    remote_ip, remote_host, "cert") != 0) {
		reason = "Refused by certificate options";
		برو fail_reason;
	}
	اگر (principals_opts == پوچ) {
		final_opts = cert_opts;
		cert_opts = پوچ;
	} وگرنه {
		اگر (auth_authorise_keyopts(pw, principals_opts, 0,
		    remote_ip, remote_host, "principals") != 0) {
			reason = "Refused by certificate principals options";
			برو fail_reason;
		}
		اگر ((final_opts = sshauthopt_merge(principals_opts,
		    cert_opts, &reason)) == پوچ) {
 fail_reason:
			error("Refusing certificate ID \"%s\" serial=%llu "
			    "signed by %s CA %s: %s", کلید->cert->کلید_id,
			    (unsigned long long)کلید->cert->serial,
			    sshkey_type(کلید->cert->signature_کلید), ca_fp,
			    reason);
			auth_debug_add("Refused Certificate ID \"%s\" "
			    "serial=%llu: %s", کلید->cert->کلید_id,
			    (unsigned long long)کلید->cert->serial, reason);
			برو out;
		}
	}

	/* Success */
	verbose("Accepted certificate ID \"%s\" (serial %llu) signed by "
	    "%s CA %s via %s", کلید->cert->کلید_id,
	    (unsigned long long)کلید->cert->serial,
	    sshkey_type(کلید->cert->signature_کلید), ca_fp,
	    options.trusted_user_ca_کلیدها);
	اگر (authoptsp != پوچ) {
		*authoptsp = final_opts;
		final_opts = پوچ;
	}
	ret = 1;
 out:
	sshauthopt_free(principals_opts);
	sshauthopt_free(cert_opts);
	sshauthopt_free(final_opts);
	آزاد(principals_file);
	آزاد(ca_fp);
	بازگشت ret;
}

/*
 * Checks whether key is allowed in file.
 * returns 1 if the key is allowed or 0 otherwise.
 */
ایستا صحیح
user_کلید_allowed2(ساختار passwd *pw, ساختار sshkey *کلید,
    نویسه *file, ثابت نویسه *remote_ip, ثابت نویسه *remote_host,
    ساختار sshauthopt **authoptsp)
{
	FILE *f;
	صحیح found_کلید = 0;

	اگر (authoptsp != پوچ)
		*authoptsp = پوچ;

	/* Temporarily use the user's uid. */
	temporarily_use_uid(pw);

	debug("trying public key file %s", file);
	اگر ((f = auth_openkeyfile(file, pw, options.strict_modes)) != پوچ) {
		found_کلید = auth_check_authkeys_file(pw, f, file,
		    کلید, remote_ip, remote_host, authoptsp);
		fclose(f);
	}

	restore_uid();
	بازگشت found_کلید;
}

/*
 * Checks whether key is allowed in output of command.
 * returns 1 if the key is allowed or 0 otherwise.
 */
ایستا صحیح
user_کلید_command_allowed2(ساختار passwd *user_pw, ساختار sshkey *کلید,
    ثابت نویسه *remote_ip, ثابت نویسه *remote_host,
    ثابت نویسه *conn_id, ثابت نویسه *rdomain, ساختار sshauthopt **authoptsp)
{
	ساختار passwd *runas_pw = پوچ;
	FILE *f = پوچ;
	صحیح r, ok, found_کلید = 0;
	صحیح i, uid_swapped = 0, ac = 0;
	pid_t pid;
	نویسه *username = پوچ, *کلید_fp = پوچ, *keytext = پوچ;
	نویسه uidstr[32], *tmp, *command = پوچ, **av = پوچ;
	تهی (*osigchld)(صحیح);

	اگر (authoptsp != پوچ)
		*authoptsp = پوچ;
	اگر (options.authorized_کلیدها_command == پوچ)
		بازگشت 0;
	اگر (options.authorized_کلیدها_command_user == پوچ) {
		error("No user for AuthorizedKeysCommand specified, skipping");
		بازگشت 0;
	}

	/*
	 * NB. all returns later this function should go via "out" to
	 * ensure the original SIGCHLD handler is restored properly.
	 */
	osigchld = ssh_signal(SIGCHLD, SIG_DFL);

	/* Prepare and verify the user for the command */
	username = percent_expand(options.authorized_کلیدها_command_user,
	    "u", user_pw->pw_name, (نویسه *)پوچ);
	runas_pw = getpwnam(username);
	اگر (runas_pw == پوچ) {
		error("AuthorizedKeysCommandUser \"%s\" not found: %s",
		    username, strerror(errno));
		برو out;
	}

	/* Prepare AuthorizedKeysCommand */
	اگر ((کلید_fp = sshkey_fingerprint(کلید, options.fingerprint_hash,
	    SSH_FP_DEFAULT)) == پوچ) {
		error_f("sshkey_fingerprint failed");
		برو out;
	}
	اگر ((r = sshkey_to_base64(کلید, &keytext)) != 0) {
		error_fr(r, "sshkey_to_base64 failed");
		برو out;
	}

	/* Turn the command into an argument vector */
	اگر (argv_split(options.authorized_کلیدها_command, &ac, &av, 0) != 0) {
		error("AuthorizedKeysCommand \"%s\" contains invalid quotes",
		    options.authorized_کلیدها_command);
		برو out;
	}
	اگر (ac == 0) {
		error("AuthorizedKeysCommand \"%s\" yielded no arguments",
		    options.authorized_کلیدها_command);
		برو out;
	}
	snprintf(uidstr, اندازه(uidstr), "%llu",
	    (unsigned long long)user_pw->pw_uid);
	برای (i = 1; i < ac; i++) {
		tmp = percent_expand(av[i],
		    "C", conn_id,
		    "D", rdomain,
		    "U", uidstr,
		    "u", user_pw->pw_name,
		    "h", user_pw->pw_dir,
		    "t", sshkey_ssh_name(کلید),
		    "f", کلید_fp,
		    "k", keytext,
		    (نویسه *)پوچ);
		اگر (tmp == پوچ)
			fatal_f("percent_expand failed");
		آزاد(av[i]);
		av[i] = tmp;
	}
	/* Prepare a printable command for logs, etc. */
	command = argv_assemble(ac, av);

	/*
	 * If AuthorizedKeysCommand was run without arguments
	 * then fall back to the old behaviour of passing the
	 * target username as a single argument.
	 */
	اگر (ac == 1) {
		av = xreallocarray(av, ac + 2, اندازه(*av));
		av[1] = xstrdup(user_pw->pw_name);
		av[2] = پوچ;
		/* Fix up command too, since it is used in log messages */
		آزاد(command);
		xasprintf(&command, "%s %s", av[0], av[1]);
	}

	اگر ((pid = subprocess("AuthorizedKeysCommand", command,
	    ac, av, &f,
	    SSH_SUBPROCESS_STDOUT_CAPTURE|SSH_SUBPROCESS_STDERR_DISCARD,
	    runas_pw, temporarily_use_uid, restore_uid)) == 0)
		برو out;

	uid_swapped = 1;
	temporarily_use_uid(runas_pw);

	ok = auth_check_authkeys_file(user_pw, f,
	    options.authorized_کلیدها_command, کلید, remote_ip,
	    remote_host, authoptsp);

	fclose(f);
	f = پوچ;

	اگر (exited_cleanly(pid, "AuthorizedKeysCommand", command, 0) != 0)
		برو out;

	/* Read completed successfully */
	found_کلید = ok;
 out:
	اگر (f != پوچ)
		fclose(f);
	ssh_signal(SIGCHLD, osigchld);
	برای (i = 0; i < ac; i++)
		آزاد(av[i]);
	آزاد(av);
	اگر (uid_swapped)
		restore_uid();
	آزاد(command);
	آزاد(username);
	آزاد(کلید_fp);
	آزاد(keytext);
	بازگشت found_کلید;
}

/*
 * Check whether key authenticates and authorises the user.
 */
صحیح
user_کلید_allowed(ساختار ssh *ssh, ساختار passwd *pw, ساختار sshkey *کلید,
    صحیح auth_attempt, ساختار sshauthopt **authoptsp)
{
	u_int success = 0, i, j;
	نویسه *file = پوچ, *conn_id;
	ساختار sshauthopt *opts = پوچ;
	ثابت نویسه *rdomain, *remote_ip, *remote_host;

	اگر (authoptsp != پوچ)
		*authoptsp = پوچ;

	اگر (auth_کلید_is_revoked(کلید))
		بازگشت 0;
	اگر (sshkey_is_cert(کلید) &&
	    auth_کلید_is_revoked(کلید->cert->signature_کلید))
		بازگشت 0;

	اگر ((rdomain = ssh_packet_rdomain_in(ssh)) == پوچ)
		rdomain = "";
	remote_ip = ssh_remote_ipaddr(ssh);
	remote_host = auth_get_canonical_hostname(ssh, options.use_dns);
	xasprintf(&conn_id, "%s %d %s %d",
	    ssh_local_ipaddr(ssh), ssh_local_port(ssh),
	    remote_ip, ssh_remote_port(ssh));

	برای (i = 0; !success && i < options.رقم_authkeys_files; i++) {
		صحیح r;
		glob_t gl;

		اگر (strcasecmp(options.authorized_کلیدها_files[i], "none") == 0)
			ادامه;
		file = expand_authorized_کلیدها(
		    options.authorized_کلیدها_files[i], pw);
		temporarily_use_uid(pw);
		r = glob(file, 0, پوچ, &gl);
		restore_uid();
		اگر (r != 0) {
			اگر (r != GLOB_NOMATCH) {
				logit_f("glob \"%s\" failed", file);
			}
			آزاد(file);
			file = پوچ;
			ادامه;
		} وگرنه اگر (gl.gl_pathc > INT_MAX) {
			fatal_f("too many glob results for \"%s\"", file);
		} وگرنه اگر (gl.gl_pathc > 1) {
			debug2_f("glob \"%s\" returned %zu matches", file,
			    gl.gl_pathc);
		}
		برای (j = 0; !success && j < gl.gl_pathc; j++) {
			success = user_کلید_allowed2(pw, کلید, gl.gl_pathv[j],
			    remote_ip, remote_host, &opts);
			اگر (!success) {
				sshauthopt_free(opts);
				opts = پوچ;
			}
		}
		آزاد(file);
		file = پوچ;
		globfree(&gl);
	}
	اگر (success)
		برو out;

	اگر ((success = user_cert_trusted_ca(pw, کلید, remote_ip, remote_host,
	    conn_id, rdomain, &opts)) != 0)
		برو out;
	sshauthopt_free(opts);
	opts = پوچ;

	اگر ((success = user_کلید_command_allowed2(pw, کلید, remote_ip,
	    remote_host, conn_id, rdomain, &opts)) != 0)
		برو out;
	sshauthopt_free(opts);
	opts = پوچ;

 out:
	آزاد(conn_id);
	اگر (success && authoptsp != پوچ) {
		*authoptsp = opts;
		opts = پوچ;
	}
	sshauthopt_free(opts);
	بازگشت success;
}

Authmethod method_pubkey = {
	&methodcfg_pubkey,
	userauth_pubkey,
};
