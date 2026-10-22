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

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>

#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <errno.h>
#அந்தர்பாவ <paths.h>
#அந்தர்பாவ <pwd.h>
#அந்தர்பாவ <glob.h>
#அந்தர்பாவ <signal.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <stdarg.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <time.h>
#அந்தர்பாவ <unistd.h>
#அந்தர்பாவ <limits.h>

#அந்தர்பாவ "xmalloc.h"
#அந்தர்பாவ "ssh.h"
#அந்தர்பாவ "ssh2.h"
#அந்தர்பாவ "packet.h"
#அந்தர்பாவ "kex.h"
#அந்தர்பாவ "sshbuf.h"
#அந்தர்பாவ "log.h"
#அந்தர்பாவ "misc.h"
#அந்தர்பாவ "servconf.h"
#அந்தர்பாவ "compat.h"
#அந்தர்பாவ "sshkey.h"
#அந்தர்பாவ "hostfile.h"
#அந்தர்பாவ "auth.h"
#அந்தர்பாவ "pathnames.h"
#அந்தர்பாவ "uidswap.h"
#அந்தர்பாவ "auth-options.h"
#அந்தர்பாவ "canohost.h"
#ifdef GSSAPI
#அந்தர்பாவ "ssh-gss.h"
#endif
#அந்தர்பாவ "monitor_wrap.h"
#அந்தர்பாவ "authfile.h"
#அந்தர்பாவ "match.h"
#அந்தர்பாவ "ssherr.h"
#அந்தர்பாவ "channels.h" /* XXX for session.h */
#அந்தர்பாவ "session.h" /* XXX for child_set_env(); refactor? */
#அந்தர்பாவ "sk-api.h"

/* import */
வெளி ServerOptions options;
வெளி கட்டமைப்பு authmethod_cfg methodcfg_pubkey;

நிலையான எழுத்து *
format_சாவி(மாறிலி கட்டமைப்பு sshkey *சாவி)
{
	எழுத்து *ret, *fp = sshkey_fingerprint(சாவி,
	    options.fingerprint_hash, SSH_FP_DEFAULT);

	xasprintf(&ret, "%s %s", sshkey_type(சாவி), fp);
	விடுவி(fp);
	திரும்பு ret;
}

/*
 * Verify that the hostkey in a publickey-hostbound-v00@openssh.com userauth
 * request matches the hostkey that was negotiated during initial KEX.
 */
நிலையான வெறுமை
check_hostbound_hostkey(கட்டமைப்பு ssh *ssh)
{
	முழு r;
	கட்டமைப்பு sshbuf *our_hostkey_blob, *their_hostkey_blob;

	எனில் (ssh->kex->initial_hostkey == வெற்று)
		fatal_f("internal error: initial hostkey not recorded");
	எனில் ((our_hostkey_blob = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new failed");
	எனில் ((r = sshpkt_getb_froms(ssh, &their_hostkey_blob)) != 0)
		fatal_fr(r, "parse hostkey");
	எனில் ((r = sshkey_putb(ssh->kex->initial_hostkey, our_hostkey_blob)) != 0)
		fatal_fr(r, "serialise hostkey");
	எனில் ((r = sshbuf_equals(our_hostkey_blob, their_hostkey_blob)) != 0)
		fatal_f("packet contained wrong host key");
	sshbuf_free(our_hostkey_blob);
	sshbuf_free(their_hostkey_blob);
}

நிலையான முழு
userauth_pubkey(கட்டமைப்பு ssh *ssh, மாறிலி எழுத்து *method)
{
	Authctxt *authctxt = ssh->authctxt;
	கட்டமைப்பு passwd *pw = authctxt->pw;
	கட்டமைப்பு sshbuf *keyblob = வெற்று, *b = வெற்று;
	கட்டமைப்பு sshkey *சாவி = வெற்று, *hostkey = வெற்று;
	எழுத்து *pkalg = வெற்று, *userstyle = வெற்று, *சாவி_s = வெற்று, *ca_s = வெற்று;
	எழுத்து *keystring = வெற்று;
	u_char *sig = வெற்று, have_sig;
	size_t slen;
	முழு hostbound, r, pktype;
	முழு req_presence = 0, req_verify = 0, authenticated = 0;
	கட்டமைப்பு sshauthopt *authopts = வெற்று;
	கட்டமைப்பு sshkey_sig_details *sig_details = வெற்று;

	hostbound = strcmp(method, "publickey-hostbound-v00@openssh.com") == 0;

	எனில் ((r = sshpkt_get_u8(ssh, &have_sig)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &pkalg, வெற்று)) != 0 ||
	    (r = sshpkt_getb_froms(ssh, &keyblob)) != 0)
		fatal_fr(r, "parse %s packet", method);

	/* hostbound auth includes the hostkey offered at initial KEX */
	எனில் (hostbound)
		check_hostbound_hostkey(ssh); /* fatals on error */

	எனில் (log_level_get() >= SYSLOG_LEVEL_DEBUG2) {
		எனில் ((b = sshbuf_fromb(keyblob)) == வெற்று)
			fatal_f("sshbuf_fromb failed");
		எனில் ((keystring = sshbuf_dtob64_string(b, 0)) == வெற்று)
			fatal_f("sshbuf_dtob64 failed");
		debug2_f("%s user %s %s public key %s %s",
		    authctxt->valid ? "valid" : "invalid", authctxt->user,
		    have_sig ? "attempting" : "querying", pkalg, keystring);
		sshbuf_free(b);
		b = வெற்று;
	}

	pktype = sshkey_type_from_name(pkalg);
	எனில் (pktype == சாவி_UNSPEC) {
		/* this is perfectly legal */
		verbose_f("unsupported public key algorithm: %s", pkalg);
		செல் done;
	}
	எனில் (match_pattern_list(pkalg, options.pubkey_accepted_algos, 0) != 1) {
		logit_f("signature algorithm %s not in "
		    "PubkeyAcceptedAlgorithms", pkalg);
		செல் done;
	}
	எனில் ((b = sshbuf_fromb(keyblob)) == வெற்று)
		fatal_f("sshbuf_fromb failed");
	தேர்வு ((r = sshkey_fromb_allowlist(b, &சாவி,
	    options.pubkey_accepted_algos, options.ca_sign_algorithms))) {
	நிலை 0:
		/* ok */
		நிறுத்து;
	நிலை SSH_ERR_சாவி_ALG_UNSUPPORTED:
		/* This shouldn't happen unless the client is being weird */
		logit_f("key algorithm differs from signature algorithm %s and "
		    "is not in PubkeyAcceptedAlgorithms", pkalg);
		செல் done;
	நிலை SSH_ERR_SIGN_ALG_UNSUPPORTED:
		logit_fr(r, "certificate signature algorithm not in "
		    "CASignatureAlgorithm");
		செல் done;
	இயல்பு:
		error_fr(r, "parse key");
		செல் done;
	}
	sshbuf_free(b);
	b = வெற்று;

	/* USERAUTH_REQUEST signature type should match key's type */
	எனில் (சாவி->type != pktype || (sshkey_type_plain(pktype) == சாவி_ECDSA &&
	    sshkey_ecdsa_nid_from_name(pkalg) != சாவி->ecdsa_nid)) {
		error_f("key type mismatch for decoded key "
		    "(received %s, expected %s)", sshkey_ssh_name(சாவி), pkalg);
		செல் done;
	}
	எனில் (auth2_சாவி_already_used(authctxt, சாவி)) {
		logit("refusing previously-used %s key", sshkey_type(சாவி));
		செல் done;
	}
	எனில் ((r = sshkey_check_rsa_length(சாவி,
	    options.required_rsa_size)) != 0) {
		logit_r(r, "refusing %s key", sshkey_type(சாவி));
		செல் done;
	}
	சாவி_s = format_சாவி(சாவி);
	எனில் (sshkey_is_cert(சாவி))
		ca_s = format_சாவி(சாவி->cert->signature_சாவி);

	எனில் (have_sig) {
		debug3_f("%s have %s signature for %s%s%s",
		    method, pkalg, சாவி_s,
		    ca_s == வெற்று ? "" : " CA ", ca_s == வெற்று ? "" : ca_s);
		எனில் ((r = sshpkt_get_string(ssh, &sig, &slen)) != 0 ||
		    (r = sshpkt_get_end(ssh)) != 0)
			fatal_fr(r, "parse signature packet");
		எனில் ((b = sshbuf_new()) == வெற்று)
			fatal_f("sshbuf_new failed");
		எனில் ((r = sshbuf_put_stringb(b,
		    ssh->kex->session_id)) != 0)
			fatal_fr(r, "put session id");
		எனில் (!authctxt->valid || authctxt->user == வெற்று) {
			debug2_f("disabled because of invalid user");
			செல் done;
		}
		/* reconstruct packet */
		xasprintf(&userstyle, "%s%s%s", authctxt->user,
		    authctxt->style ? ":" : "",
		    authctxt->style ? authctxt->style : "");
		எனில் ((r = sshbuf_put_u8(b, SSH2_செய்தி_USERAUTH_REQUEST)) != 0 ||
		    (r = sshbuf_put_cstring(b, userstyle)) != 0 ||
		    (r = sshbuf_put_cstring(b, authctxt->service)) != 0 ||
		    (r = sshbuf_put_cstring(b, method)) != 0 ||
		    (r = sshbuf_put_u8(b, have_sig)) != 0 ||
		    (r = sshbuf_put_cstring(b, pkalg)) != 0 ||
		    (r = sshbuf_put_stringb(b, keyblob)) != 0)
			fatal_fr(r, "reconstruct %s packet", method);
		எனில் (hostbound &&
		    (r = sshkey_puts(ssh->kex->initial_hostkey, b)) != 0)
			fatal_fr(r, "reconstruct %s packet", method);
#ifdef DEBUG_PK
		sshbuf_dump(b, stderr);
#endif
		/* test for correct signature */
		authenticated = 0;
		எனில் (mm_user_சாவி_allowed(ssh, pw, சாவி, 1, &authopts) &&
		    mm_sshkey_verify(சாவி, sig, slen,
		    sshbuf_ptr(b), sshbuf_len(b),
		    (ssh->compat & SSH_BUG_SIGTYPE) == 0 ? pkalg : வெற்று,
		    ssh->compat, &sig_details) == 0) {
			authenticated = 1;
		}
		எனில் (authenticated == 1 && sig_details != வெற்று) {
			auth2_record_info(authctxt, "signature count = %u",
			    sig_details->sk_counter);
			debug_f("sk_counter = %u, sk_flags = 0x%02x",
			    sig_details->sk_counter, sig_details->sk_flags);
			req_presence = (options.pubkey_auth_options &
			    PUBKEYAUTH_TOUCH_REQUIRED) ||
			    !authopts->no_require_user_presence;
			எனில் (req_presence && (sig_details->sk_flags &
			    SSH_SK_USER_PRESENCE_REQD) == 0) {
				error("public key %s signature for %s%s from "
				    "%.128s port %d rejected: user presence "
				    "(authenticator touch) requirement "
				    "not met ", சாவி_s,
				    authctxt->valid ? "" : "invalid user ",
				    authctxt->user, ssh_remote_ipaddr(ssh),
				    ssh_remote_port(ssh));
				authenticated = 0;
				செல் done;
			}
			req_verify = (options.pubkey_auth_options &
			    PUBKEYAUTH_VERIFY_REQUIRED) ||
			    authopts->require_verify;
			எனில் (req_verify && (sig_details->sk_flags &
			    SSH_SK_USER_VERIFICATION_REQD) == 0) {
				error("public key %s signature for %s%s from "
				    "%.128s port %d rejected: user "
				    "verification requirement not met ", சாவி_s,
				    authctxt->valid ? "" : "invalid user ",
				    authctxt->user, ssh_remote_ipaddr(ssh),
				    ssh_remote_port(ssh));
				authenticated = 0;
				செல் done;
			}
		}
		auth2_record_சாவி(authctxt, authenticated, சாவி);
	} இல்லையெனில் {
		debug_f("%s test pkalg %s pkblob %s%s%s", method, pkalg, சாவி_s,
		    ca_s == வெற்று ? "" : " CA ", ca_s == வெற்று ? "" : ca_s);

		எனில் ((r = sshpkt_get_end(ssh)) != 0)
			fatal_fr(r, "parse packet");

		/* XXX fake reply and always send PK_OK ? */
		/*
		 * XXX this allows testing whether a user is allowed
		 * to login: if you happen to have a valid pubkey this
		 * message is sent. the message is NEVER sent at all
		 * if a user is not allowed to login. is this an
		 * issue? -markus
		 */
		எனில் (authctxt->valid && authctxt->user != வெற்று &&
		    mm_user_சாவி_allowed(ssh, pw, சாவி, 0, வெற்று)) {
			எனில் ((r = sshpkt_start(ssh, SSH2_செய்தி_USERAUTH_PK_OK))
			    != 0 ||
			    (r = sshpkt_put_cstring(ssh, pkalg)) != 0 ||
			    (r = sshpkt_put_stringb(ssh, keyblob)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0 ||
			    (r = ssh_packet_write_wait(ssh)) != 0)
				fatal_fr(r, "send packet");
			authctxt->postponed = 1;
		} இல்லையெனில் {
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
			எனில் (authctxt->pk_ok_failures++ < options.max_pubkey_ok)
				authctxt->auth_failure_already_counted = 1;
			debug3_f("pubkey test %d of %d%s",
			    authctxt->pk_ok_failures, options.max_pubkey_ok,
			    authctxt->auth_failure_already_counted ?
			    "" : ": treating as authentication failure");
		 }
	}
done:
	எனில் (authenticated == 1 && auth_activate_options(ssh, authopts) != 0) {
		debug_f("key options inconsistent with existing");
		authenticated = 0;
	}
	debug2_f("authenticated %d pkalg %s", authenticated, pkalg);

	sshbuf_free(b);
	sshbuf_free(keyblob);
	sshauthopt_free(authopts);
	sshkey_free(சாவி);
	sshkey_free(hostkey);
	விடுவி(keystring);
	விடுவி(userstyle);
	விடுவி(pkalg);
	விடுவி(சாவி_s);
	விடுவி(ca_s);
	விடுவி(sig);
	sshkey_sig_details_free(sig_details);
	திரும்பு authenticated;
}

நிலையான முழு
match_principals_file(கட்டமைப்பு passwd *pw, எழுத்து *file,
    கட்டமைப்பு sshkey_cert *cert, கட்டமைப்பு sshauthopt **authoptsp)
{
	FILE *f;
	முழு r, success = 0;
	size_t i;
	glob_t gl;
	கட்டமைப்பு sshauthopt *opts = வெற்று;

	எனில் (authoptsp != வெற்று)
		*authoptsp = வெற்று;

	temporarily_use_uid(pw);
	r = glob(file, 0, வெற்று, &gl);
	restore_uid();
	எனில் (r != 0) {
		எனில் (r != GLOB_NOMATCH) {
			logit_f("glob \"%s\" failed", file);
		}
		திரும்பு 0;
	} இல்லையெனில் எனில் (gl.gl_pathc > INT_MAX) {
		fatal_f("too many glob results for \"%s\"", file);
	} இல்லையெனில் எனில் (gl.gl_pathc > 1) {
		debug2_f("glob \"%s\" returned %zu matches", file,
		    gl.gl_pathc);
	}
	க்கு (i = 0; !success && i < gl.gl_pathc; i++) {
		temporarily_use_uid(pw);
		debug("trying authorized principals file %s", file);
		எனில் ((f = auth_openprincipals(gl.gl_pathv[i], pw,
		    options.strict_modes)) == வெற்று) {
			restore_uid();
			தொடர்;
		}
		success = auth_process_principals(f, gl.gl_pathv[i],
		    cert, &opts);
		fclose(f);
		restore_uid();
		எனில் (!success) {
			sshauthopt_free(opts);
			opts = வெற்று;
		}
	}
	globfree(&gl);
	எனில் (success && authoptsp != வெற்று) {
		*authoptsp = opts;
		opts = வெற்று;
	}
	sshauthopt_free(opts);
	திரும்பு success;
}

/*
 * Checks whether principal is allowed in output of command.
 * returns 1 if the principal is allowed or 0 otherwise.
 */
நிலையான முழு
match_principals_command(கட்டமைப்பு passwd *user_pw, மாறிலி கட்டமைப்பு sshkey *சாவி,
    மாறிலி எழுத்து *conn_id, மாறிலி எழுத்து *rdomain, கட்டமைப்பு sshauthopt **authoptsp)
{
	கட்டமைப்பு passwd *runas_pw = வெற்று;
	மாறிலி கட்டமைப்பு sshkey_cert *cert = சாவி->cert;
	FILE *f = வெற்று;
	முழு r, ok, found_principal = 0;
	முழு i, ac = 0, uid_swapped = 0;
	pid_t pid;
	எழுத்து *tmp, *username = வெற்று, *command = வெற்று, **av = வெற்று;
	எழுத்து *ca_fp = வெற்று, *சாவி_fp = வெற்று, *catext = வெற்று, *keytext = வெற்று;
	எழுத்து serial_s[32], uidstr[32];
	வெறுமை (*osigchld)(முழு);

	எனில் (authoptsp != வெற்று)
		*authoptsp = வெற்று;
	எனில் (options.authorized_principals_command == வெற்று)
		திரும்பு 0;
	எனில் (options.authorized_principals_command_user == வெற்று) {
		error("No user for AuthorizedPrincipalsCommand specified, "
		    "skipping");
		திரும்பு 0;
	}

	/*
	 * NB. all returns later this function should go via "out" to
	 * ensure the original SIGCHLD handler is restored properly.
	 */
	osigchld = ssh_signal(SIGCHLD, SIG_DFL);

	/* Prepare and verify the user for the command */
	username = percent_expand(options.authorized_principals_command_user,
	    "u", user_pw->pw_name, (எழுத்து *)வெற்று);
	runas_pw = getpwnam(username);
	எனில் (runas_pw == வெற்று) {
		error("AuthorizedPrincipalsCommandUser \"%s\" not found: %s",
		    username, strerror(errno));
		செல் out;
	}

	/* Turn the command into an argument vector */
	எனில் (argv_split(options.authorized_principals_command,
	    &ac, &av, 0) != 0) {
		error("AuthorizedPrincipalsCommand \"%s\" contains "
		    "invalid quotes", options.authorized_principals_command);
		செல் out;
	}
	எனில் (ac == 0) {
		error("AuthorizedPrincipalsCommand \"%s\" yielded no arguments",
		    options.authorized_principals_command);
		செல் out;
	}
	எனில் ((ca_fp = sshkey_fingerprint(cert->signature_சாவி,
	    options.fingerprint_hash, SSH_FP_DEFAULT)) == வெற்று) {
		error_f("sshkey_fingerprint failed");
		செல் out;
	}
	எனில் ((சாவி_fp = sshkey_fingerprint(சாவி,
	    options.fingerprint_hash, SSH_FP_DEFAULT)) == வெற்று) {
		error_f("sshkey_fingerprint failed");
		செல் out;
	}
	எனில் ((r = sshkey_to_base64(cert->signature_சாவி, &catext)) != 0) {
		error_fr(r, "sshkey_to_base64 failed");
		செல் out;
	}
	எனில் ((r = sshkey_to_base64(சாவி, &keytext)) != 0) {
		error_fr(r, "sshkey_to_base64 failed");
		செல் out;
	}
	snprintf(serial_s, அளவு(serial_s), "%llu",
	    (unsigned long long)cert->serial);
	snprintf(uidstr, அளவு(uidstr), "%llu",
	    (unsigned long long)user_pw->pw_uid);
	க்கு (i = 1; i < ac; i++) {
		tmp = percent_expand(av[i],
		    "C", conn_id,
		    "D", rdomain,
		    "U", uidstr,
		    "u", user_pw->pw_name,
		    "h", user_pw->pw_dir,
		    "t", sshkey_ssh_name(சாவி),
		    "T", sshkey_ssh_name(cert->signature_சாவி),
		    "f", சாவி_fp,
		    "F", ca_fp,
		    "k", keytext,
		    "K", catext,
		    "i", cert->சாவி_id,
		    "s", serial_s,
		    (எழுத்து *)வெற்று);
		எனில் (tmp == வெற்று)
			fatal_f("percent_expand failed");
		விடுவி(av[i]);
		av[i] = tmp;
	}
	/* Prepare a printable command for logs, etc. */
	command = argv_assemble(ac, av);

	எனில் ((pid = subprocess("AuthorizedPrincipalsCommand", command,
	    ac, av, &f,
	    SSH_SUBPROCESS_STDOUT_CAPTURE|SSH_SUBPROCESS_STDERR_DISCARD,
	    runas_pw, temporarily_use_uid, restore_uid)) == 0)
		செல் out;

	uid_swapped = 1;
	temporarily_use_uid(runas_pw);

	ok = auth_process_principals(f, "(command)", cert, authoptsp);

	fclose(f);
	f = வெற்று;

	எனில் (exited_cleanly(pid, "AuthorizedPrincipalsCommand", command, 0) != 0)
		செல் out;

	/* Read completed successfully */
	found_principal = ok;
 out:
	எனில் (f != வெற்று)
		fclose(f);
	ssh_signal(SIGCHLD, osigchld);
	க்கு (i = 0; i < ac; i++)
		விடுவி(av[i]);
	விடுவி(av);
	எனில் (uid_swapped)
		restore_uid();
	விடுவி(command);
	விடுவி(username);
	விடுவி(ca_fp);
	விடுவி(சாவி_fp);
	விடுவி(catext);
	விடுவி(keytext);
	திரும்பு found_principal;
}

/* Authenticate a certificate key against TrustedUserCAKeys */
நிலையான முழு
user_cert_trusted_ca(கட்டமைப்பு passwd *pw, கட்டமைப்பு sshkey *சாவி,
    மாறிலி எழுத்து *remote_ip, மாறிலி எழுத்து *remote_host,
    மாறிலி எழுத்து *conn_id, மாறிலி எழுத்து *rdomain, கட்டமைப்பு sshauthopt **authoptsp)
{
	எழுத்து *ca_fp, *principals_file = வெற்று;
	மாறிலி எழுத்து *reason;
	கட்டமைப்பு sshauthopt *principals_opts = வெற்று, *cert_opts = வெற்று;
	கட்டமைப்பு sshauthopt *final_opts = வெற்று;
	முழு r, ret = 0, found_principal = 0, use_authorized_principals;

	எனில் (authoptsp != வெற்று)
		*authoptsp = வெற்று;

	எனில் (!sshkey_is_cert(சாவி) || options.trusted_user_ca_சாவிகள் == வெற்று)
		திரும்பு 0;

	எனில் ((ca_fp = sshkey_fingerprint(சாவி->cert->signature_சாவி,
	    options.fingerprint_hash, SSH_FP_DEFAULT)) == வெற்று)
		திரும்பு 0;

	எனில் ((r = sshkey_in_file(சாவி->cert->signature_சாவி,
	    options.trusted_user_ca_சாவிகள், 1, 0)) != 0) {
		debug2_fr(r, "CA %s %s is not listed in %s",
		    sshkey_type(சாவி->cert->signature_சாவி), ca_fp,
		    options.trusted_user_ca_சாவிகள்);
		செல் out;
	}
	/*
	 * If AuthorizedPrincipals is in use, then compare the certificate
	 * principals against the names in that file rather than matching
	 * against the username.
	 */
	எனில் ((principals_file = authorized_principals_file(pw)) != வெற்று) {
		எனில் (match_principals_file(pw, principals_file,
		    சாவி->cert, &principals_opts))
			found_principal = 1;
	}
	/* Try querying command if specified */
	எனில் (!found_principal && match_principals_command(pw, சாவி,
	    conn_id, rdomain, &principals_opts))
		found_principal = 1;
	/* If principals file or command is specified, then require a match */
	use_authorized_principals = principals_file != வெற்று ||
	    options.authorized_principals_command != வெற்று;
	எனில் (!found_principal && use_authorized_principals) {
		reason = "Certificate does not contain an authorized principal";
		செல் fail_reason;
	}
	எனில் (use_authorized_principals && principals_opts == வெற்று)
		fatal_f("internal error: missing principals_opts");
	எனில் (sshkey_cert_check_authority_now(சாவி, 0, 0,
	    use_authorized_principals ? வெற்று : pw->pw_name, &reason) != 0)
		செல் fail_reason;

	/* Check authority from options in key and from principals file/cmd */
	எனில் ((cert_opts = sshauthopt_from_cert(சாவி)) == வெற்று) {
		reason = "Invalid certificate options";
		செல் fail_reason;
	}
	எனில் (auth_authorise_keyopts(pw, cert_opts, 0,
	    remote_ip, remote_host, "cert") != 0) {
		reason = "Refused by certificate options";
		செல் fail_reason;
	}
	எனில் (principals_opts == வெற்று) {
		final_opts = cert_opts;
		cert_opts = வெற்று;
	} இல்லையெனில் {
		எனில் (auth_authorise_keyopts(pw, principals_opts, 0,
		    remote_ip, remote_host, "principals") != 0) {
			reason = "Refused by certificate principals options";
			செல் fail_reason;
		}
		எனில் ((final_opts = sshauthopt_merge(principals_opts,
		    cert_opts, &reason)) == வெற்று) {
 fail_reason:
			error("Refusing certificate ID \"%s\" serial=%llu "
			    "signed by %s CA %s: %s", சாவி->cert->சாவி_id,
			    (unsigned long long)சாவி->cert->serial,
			    sshkey_type(சாவி->cert->signature_சாவி), ca_fp,
			    reason);
			auth_debug_add("Refused Certificate ID \"%s\" "
			    "serial=%llu: %s", சாவி->cert->சாவி_id,
			    (unsigned long long)சாவி->cert->serial, reason);
			செல் out;
		}
	}

	/* Success */
	verbose("Accepted certificate ID \"%s\" (serial %llu) signed by "
	    "%s CA %s via %s", சாவி->cert->சாவி_id,
	    (unsigned long long)சாவி->cert->serial,
	    sshkey_type(சாவி->cert->signature_சாவி), ca_fp,
	    options.trusted_user_ca_சாவிகள்);
	எனில் (authoptsp != வெற்று) {
		*authoptsp = final_opts;
		final_opts = வெற்று;
	}
	ret = 1;
 out:
	sshauthopt_free(principals_opts);
	sshauthopt_free(cert_opts);
	sshauthopt_free(final_opts);
	விடுவி(principals_file);
	விடுவி(ca_fp);
	திரும்பு ret;
}

/*
 * Checks whether key is allowed in file.
 * returns 1 if the key is allowed or 0 otherwise.
 */
நிலையான முழு
user_சாவி_allowed2(கட்டமைப்பு passwd *pw, கட்டமைப்பு sshkey *சாவி,
    எழுத்து *file, மாறிலி எழுத்து *remote_ip, மாறிலி எழுத்து *remote_host,
    கட்டமைப்பு sshauthopt **authoptsp)
{
	FILE *f;
	முழு found_சாவி = 0;

	எனில் (authoptsp != வெற்று)
		*authoptsp = வெற்று;

	/* Temporarily use the user's uid. */
	temporarily_use_uid(pw);

	debug("trying public key file %s", file);
	எனில் ((f = auth_openkeyfile(file, pw, options.strict_modes)) != வெற்று) {
		found_சாவி = auth_check_authkeys_file(pw, f, file,
		    சாவி, remote_ip, remote_host, authoptsp);
		fclose(f);
	}

	restore_uid();
	திரும்பு found_சாவி;
}

/*
 * Checks whether key is allowed in output of command.
 * returns 1 if the key is allowed or 0 otherwise.
 */
நிலையான முழு
user_சாவி_command_allowed2(கட்டமைப்பு passwd *user_pw, கட்டமைப்பு sshkey *சாவி,
    மாறிலி எழுத்து *remote_ip, மாறிலி எழுத்து *remote_host,
    மாறிலி எழுத்து *conn_id, மாறிலி எழுத்து *rdomain, கட்டமைப்பு sshauthopt **authoptsp)
{
	கட்டமைப்பு passwd *runas_pw = வெற்று;
	FILE *f = வெற்று;
	முழு r, ok, found_சாவி = 0;
	முழு i, uid_swapped = 0, ac = 0;
	pid_t pid;
	எழுத்து *username = வெற்று, *சாவி_fp = வெற்று, *keytext = வெற்று;
	எழுத்து uidstr[32], *tmp, *command = வெற்று, **av = வெற்று;
	வெறுமை (*osigchld)(முழு);

	எனில் (authoptsp != வெற்று)
		*authoptsp = வெற்று;
	எனில் (options.authorized_சாவிகள்_command == வெற்று)
		திரும்பு 0;
	எனில் (options.authorized_சாவிகள்_command_user == வெற்று) {
		error("No user for AuthorizedKeysCommand specified, skipping");
		திரும்பு 0;
	}

	/*
	 * NB. all returns later this function should go via "out" to
	 * ensure the original SIGCHLD handler is restored properly.
	 */
	osigchld = ssh_signal(SIGCHLD, SIG_DFL);

	/* Prepare and verify the user for the command */
	username = percent_expand(options.authorized_சாவிகள்_command_user,
	    "u", user_pw->pw_name, (எழுத்து *)வெற்று);
	runas_pw = getpwnam(username);
	எனில் (runas_pw == வெற்று) {
		error("AuthorizedKeysCommandUser \"%s\" not found: %s",
		    username, strerror(errno));
		செல் out;
	}

	/* Prepare AuthorizedKeysCommand */
	எனில் ((சாவி_fp = sshkey_fingerprint(சாவி, options.fingerprint_hash,
	    SSH_FP_DEFAULT)) == வெற்று) {
		error_f("sshkey_fingerprint failed");
		செல் out;
	}
	எனில் ((r = sshkey_to_base64(சாவி, &keytext)) != 0) {
		error_fr(r, "sshkey_to_base64 failed");
		செல் out;
	}

	/* Turn the command into an argument vector */
	எனில் (argv_split(options.authorized_சாவிகள்_command, &ac, &av, 0) != 0) {
		error("AuthorizedKeysCommand \"%s\" contains invalid quotes",
		    options.authorized_சாவிகள்_command);
		செல் out;
	}
	எனில் (ac == 0) {
		error("AuthorizedKeysCommand \"%s\" yielded no arguments",
		    options.authorized_சாவிகள்_command);
		செல் out;
	}
	snprintf(uidstr, அளவு(uidstr), "%llu",
	    (unsigned long long)user_pw->pw_uid);
	க்கு (i = 1; i < ac; i++) {
		tmp = percent_expand(av[i],
		    "C", conn_id,
		    "D", rdomain,
		    "U", uidstr,
		    "u", user_pw->pw_name,
		    "h", user_pw->pw_dir,
		    "t", sshkey_ssh_name(சாவி),
		    "f", சாவி_fp,
		    "k", keytext,
		    (எழுத்து *)வெற்று);
		எனில் (tmp == வெற்று)
			fatal_f("percent_expand failed");
		விடுவி(av[i]);
		av[i] = tmp;
	}
	/* Prepare a printable command for logs, etc. */
	command = argv_assemble(ac, av);

	/*
	 * If AuthorizedKeysCommand was run without arguments
	 * then fall back to the old behaviour of passing the
	 * target username as a single argument.
	 */
	எனில் (ac == 1) {
		av = xreallocarray(av, ac + 2, அளவு(*av));
		av[1] = xstrdup(user_pw->pw_name);
		av[2] = வெற்று;
		/* Fix up command too, since it is used in log messages */
		விடுவி(command);
		xasprintf(&command, "%s %s", av[0], av[1]);
	}

	எனில் ((pid = subprocess("AuthorizedKeysCommand", command,
	    ac, av, &f,
	    SSH_SUBPROCESS_STDOUT_CAPTURE|SSH_SUBPROCESS_STDERR_DISCARD,
	    runas_pw, temporarily_use_uid, restore_uid)) == 0)
		செல் out;

	uid_swapped = 1;
	temporarily_use_uid(runas_pw);

	ok = auth_check_authkeys_file(user_pw, f,
	    options.authorized_சாவிகள்_command, சாவி, remote_ip,
	    remote_host, authoptsp);

	fclose(f);
	f = வெற்று;

	எனில் (exited_cleanly(pid, "AuthorizedKeysCommand", command, 0) != 0)
		செல் out;

	/* Read completed successfully */
	found_சாவி = ok;
 out:
	எனில் (f != வெற்று)
		fclose(f);
	ssh_signal(SIGCHLD, osigchld);
	க்கு (i = 0; i < ac; i++)
		விடுவி(av[i]);
	விடுவி(av);
	எனில் (uid_swapped)
		restore_uid();
	விடுவி(command);
	விடுவி(username);
	விடுவி(சாவி_fp);
	விடுவி(keytext);
	திரும்பு found_சாவி;
}

/*
 * Check whether key authenticates and authorises the user.
 */
முழு
user_சாவி_allowed(கட்டமைப்பு ssh *ssh, கட்டமைப்பு passwd *pw, கட்டமைப்பு sshkey *சாவி,
    முழு auth_attempt, கட்டமைப்பு sshauthopt **authoptsp)
{
	u_int success = 0, i, j;
	எழுத்து *file = வெற்று, *conn_id;
	கட்டமைப்பு sshauthopt *opts = வெற்று;
	மாறிலி எழுத்து *rdomain, *remote_ip, *remote_host;

	எனில் (authoptsp != வெற்று)
		*authoptsp = வெற்று;

	எனில் (auth_சாவி_is_revoked(சாவி))
		திரும்பு 0;
	எனில் (sshkey_is_cert(சாவி) &&
	    auth_சாவி_is_revoked(சாவி->cert->signature_சாவி))
		திரும்பு 0;

	எனில் ((rdomain = ssh_packet_rdomain_in(ssh)) == வெற்று)
		rdomain = "";
	remote_ip = ssh_remote_ipaddr(ssh);
	remote_host = auth_get_canonical_hostname(ssh, options.use_dns);
	xasprintf(&conn_id, "%s %d %s %d",
	    ssh_local_ipaddr(ssh), ssh_local_port(ssh),
	    remote_ip, ssh_remote_port(ssh));

	க்கு (i = 0; !success && i < options.இலக்கம்_authkeys_files; i++) {
		முழு r;
		glob_t gl;

		எனில் (strcasecmp(options.authorized_சாவிகள்_files[i], "none") == 0)
			தொடர்;
		file = expand_authorized_சாவிகள்(
		    options.authorized_சாவிகள்_files[i], pw);
		temporarily_use_uid(pw);
		r = glob(file, 0, வெற்று, &gl);
		restore_uid();
		எனில் (r != 0) {
			எனில் (r != GLOB_NOMATCH) {
				logit_f("glob \"%s\" failed", file);
			}
			விடுவி(file);
			file = வெற்று;
			தொடர்;
		} இல்லையெனில் எனில் (gl.gl_pathc > INT_MAX) {
			fatal_f("too many glob results for \"%s\"", file);
		} இல்லையெனில் எனில் (gl.gl_pathc > 1) {
			debug2_f("glob \"%s\" returned %zu matches", file,
			    gl.gl_pathc);
		}
		க்கு (j = 0; !success && j < gl.gl_pathc; j++) {
			success = user_சாவி_allowed2(pw, சாவி, gl.gl_pathv[j],
			    remote_ip, remote_host, &opts);
			எனில் (!success) {
				sshauthopt_free(opts);
				opts = வெற்று;
			}
		}
		விடுவி(file);
		file = வெற்று;
		globfree(&gl);
	}
	எனில் (success)
		செல் out;

	எனில் ((success = user_cert_trusted_ca(pw, சாவி, remote_ip, remote_host,
	    conn_id, rdomain, &opts)) != 0)
		செல் out;
	sshauthopt_free(opts);
	opts = வெற்று;

	எனில் ((success = user_சாவி_command_allowed2(pw, சாவி, remote_ip,
	    remote_host, conn_id, rdomain, &opts)) != 0)
		செல் out;
	sshauthopt_free(opts);
	opts = வெற்று;

 out:
	விடுவி(conn_id);
	எனில் (success && authoptsp != வெற்று) {
		*authoptsp = opts;
		opts = வெற்று;
	}
	sshauthopt_free(opts);
	திரும்பு success;
}

Authmethod method_pubkey = {
	&methodcfg_pubkey,
	userauth_pubkey,
};
