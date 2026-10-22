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

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>

#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <errno.h>
#અન્તર્ભાવ <paths.h>
#અન્તર્ભાવ <pwd.h>
#અન્તર્ભાવ <glob.h>
#અન્તર્ભાવ <signal.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <stdarg.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <time.h>
#અન્તર્ભાવ <unistd.h>
#અન્તર્ભાવ <limits.h>

#અન્તર્ભાવ "xmalloc.h"
#અન્તર્ભાવ "ssh.h"
#અન્તર્ભાવ "ssh2.h"
#અન્તર્ભાવ "packet.h"
#અન્તર્ભાવ "kex.h"
#અન્તર્ભાવ "sshbuf.h"
#અન્તર્ભાવ "log.h"
#અન્તર્ભાવ "misc.h"
#અન્તર્ભાવ "servconf.h"
#અન્તર્ભાવ "compat.h"
#અન્તર્ભાવ "sshkey.h"
#અન્તર્ભાવ "hostfile.h"
#અન્તર્ભાવ "auth.h"
#અન્તર્ભાવ "pathnames.h"
#અન્તર્ભાવ "uidswap.h"
#અન્તર્ભાવ "auth-options.h"
#અન્તર્ભાવ "canohost.h"
#ifdef GSSAPI
#અન્તર્ભાવ "ssh-gss.h"
#endif
#અન્તર્ભાવ "monitor_wrap.h"
#અન્તર્ભાવ "authfile.h"
#અન્તર્ભાવ "match.h"
#અન્તર્ભાવ "ssherr.h"
#અન્તર્ભાવ "channels.h" /* XXX for session.h */
#અન્તર્ભાવ "session.h" /* XXX for child_set_env(); refactor? */
#અન્તર્ભાવ "sk-api.h"

/* import */
બાહ્ય ServerOptions options;
બાહ્ય સંરચના authmethod_cfg methodcfg_pubkey;

સ્થિર અક્ષર *
format_ચાવી(અચલ સંરચના sshkey *ચાવી)
{
	અક્ષર *ret, *fp = sshkey_fingerprint(ચાવી,
	    options.fingerprint_hash, SSH_FP_DEFAULT);

	xasprintf(&ret, "%s %s", sshkey_type(ચાવી), fp);
	મુક્ત(fp);
	પાછા ret;
}

/*
 * Verify that the hostkey in a publickey-hostbound-v00@openssh.com userauth
 * request matches the hostkey that was negotiated during initial KEX.
 */
સ્થિર શૂન્ય
check_hostbound_hostkey(સંરચના ssh *ssh)
{
	પૂર્ણાંક r;
	સંરચના sshbuf *our_hostkey_blob, *their_hostkey_blob;

	જો (ssh->kex->initial_hostkey == ખાલી)
		fatal_f("internal error: initial hostkey not recorded");
	જો ((our_hostkey_blob = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new failed");
	જો ((r = sshpkt_getb_froms(ssh, &their_hostkey_blob)) != 0)
		fatal_fr(r, "parse hostkey");
	જો ((r = sshkey_putb(ssh->kex->initial_hostkey, our_hostkey_blob)) != 0)
		fatal_fr(r, "serialise hostkey");
	જો ((r = sshbuf_equals(our_hostkey_blob, their_hostkey_blob)) != 0)
		fatal_f("packet contained wrong host key");
	sshbuf_free(our_hostkey_blob);
	sshbuf_free(their_hostkey_blob);
}

સ્થિર પૂર્ણાંક
userauth_pubkey(સંરચના ssh *ssh, અચલ અક્ષર *method)
{
	Authctxt *authctxt = ssh->authctxt;
	સંરચના passwd *pw = authctxt->pw;
	સંરચના sshbuf *keyblob = ખાલી, *b = ખાલી;
	સંરચના sshkey *ચાવી = ખાલી, *hostkey = ખાલી;
	અક્ષર *pkalg = ખાલી, *userstyle = ખાલી, *ચાવી_s = ખાલી, *ca_s = ખાલી;
	અક્ષર *keystring = ખાલી;
	u_char *sig = ખાલી, have_sig;
	size_t slen;
	પૂર્ણાંક hostbound, r, pktype;
	પૂર્ણાંક req_presence = 0, req_verify = 0, authenticated = 0;
	સંરચના sshauthopt *authopts = ખાલી;
	સંરચના sshkey_sig_details *sig_details = ખાલી;

	hostbound = strcmp(method, "publickey-hostbound-v00@openssh.com") == 0;

	જો ((r = sshpkt_get_u8(ssh, &have_sig)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &pkalg, ખાલી)) != 0 ||
	    (r = sshpkt_getb_froms(ssh, &keyblob)) != 0)
		fatal_fr(r, "parse %s packet", method);

	/* hostbound auth includes the hostkey offered at initial KEX */
	જો (hostbound)
		check_hostbound_hostkey(ssh); /* fatals on error */

	જો (log_level_get() >= SYSLOG_LEVEL_DEBUG2) {
		જો ((b = sshbuf_fromb(keyblob)) == ખાલી)
			fatal_f("sshbuf_fromb failed");
		જો ((keystring = sshbuf_dtob64_string(b, 0)) == ખાલી)
			fatal_f("sshbuf_dtob64 failed");
		debug2_f("%s user %s %s public key %s %s",
		    authctxt->valid ? "valid" : "invalid", authctxt->user,
		    have_sig ? "attempting" : "querying", pkalg, keystring);
		sshbuf_free(b);
		b = ખાલી;
	}

	pktype = sshkey_type_from_name(pkalg);
	જો (pktype == ચાવી_UNSPEC) {
		/* this is perfectly legal */
		verbose_f("unsupported public key algorithm: %s", pkalg);
		જાઓ done;
	}
	જો (match_pattern_list(pkalg, options.pubkey_accepted_algos, 0) != 1) {
		logit_f("signature algorithm %s not in "
		    "PubkeyAcceptedAlgorithms", pkalg);
		જાઓ done;
	}
	જો ((b = sshbuf_fromb(keyblob)) == ખાલી)
		fatal_f("sshbuf_fromb failed");
	પસંદગી ((r = sshkey_fromb_allowlist(b, &ચાવી,
	    options.pubkey_accepted_algos, options.ca_sign_algorithms))) {
	સ્થિતિ 0:
		/* ok */
		તોડો;
	સ્થિતિ SSH_ERR_ચાવી_ALG_UNSUPPORTED:
		/* This shouldn't happen unless the client is being weird */
		logit_f("key algorithm differs from signature algorithm %s and "
		    "is not in PubkeyAcceptedAlgorithms", pkalg);
		જાઓ done;
	સ્થિતિ SSH_ERR_SIGN_ALG_UNSUPPORTED:
		logit_fr(r, "certificate signature algorithm not in "
		    "CASignatureAlgorithm");
		જાઓ done;
	મૂળભૂત:
		error_fr(r, "parse key");
		જાઓ done;
	}
	sshbuf_free(b);
	b = ખાલી;

	/* USERAUTH_REQUEST signature type should match key's type */
	જો (ચાવી->type != pktype || (sshkey_type_plain(pktype) == ચાવી_ECDSA &&
	    sshkey_ecdsa_nid_from_name(pkalg) != ચાવી->ecdsa_nid)) {
		error_f("key type mismatch for decoded key "
		    "(received %s, expected %s)", sshkey_ssh_name(ચાવી), pkalg);
		જાઓ done;
	}
	જો (auth2_ચાવી_already_used(authctxt, ચાવી)) {
		logit("refusing previously-used %s key", sshkey_type(ચાવી));
		જાઓ done;
	}
	જો ((r = sshkey_check_rsa_length(ચાવી,
	    options.required_rsa_size)) != 0) {
		logit_r(r, "refusing %s key", sshkey_type(ચાવી));
		જાઓ done;
	}
	ચાવી_s = format_ચાવી(ચાવી);
	જો (sshkey_is_cert(ચાવી))
		ca_s = format_ચાવી(ચાવી->cert->signature_ચાવી);

	જો (have_sig) {
		debug3_f("%s have %s signature for %s%s%s",
		    method, pkalg, ચાવી_s,
		    ca_s == ખાલી ? "" : " CA ", ca_s == ખાલી ? "" : ca_s);
		જો ((r = sshpkt_get_string(ssh, &sig, &slen)) != 0 ||
		    (r = sshpkt_get_end(ssh)) != 0)
			fatal_fr(r, "parse signature packet");
		જો ((b = sshbuf_new()) == ખાલી)
			fatal_f("sshbuf_new failed");
		જો ((r = sshbuf_put_stringb(b,
		    ssh->kex->session_id)) != 0)
			fatal_fr(r, "put session id");
		જો (!authctxt->valid || authctxt->user == ખાલી) {
			debug2_f("disabled because of invalid user");
			જાઓ done;
		}
		/* reconstruct packet */
		xasprintf(&userstyle, "%s%s%s", authctxt->user,
		    authctxt->style ? ":" : "",
		    authctxt->style ? authctxt->style : "");
		જો ((r = sshbuf_put_u8(b, SSH2_સંદેશ_USERAUTH_REQUEST)) != 0 ||
		    (r = sshbuf_put_cstring(b, userstyle)) != 0 ||
		    (r = sshbuf_put_cstring(b, authctxt->service)) != 0 ||
		    (r = sshbuf_put_cstring(b, method)) != 0 ||
		    (r = sshbuf_put_u8(b, have_sig)) != 0 ||
		    (r = sshbuf_put_cstring(b, pkalg)) != 0 ||
		    (r = sshbuf_put_stringb(b, keyblob)) != 0)
			fatal_fr(r, "reconstruct %s packet", method);
		જો (hostbound &&
		    (r = sshkey_puts(ssh->kex->initial_hostkey, b)) != 0)
			fatal_fr(r, "reconstruct %s packet", method);
#ifdef DEBUG_PK
		sshbuf_dump(b, stderr);
#endif
		/* test for correct signature */
		authenticated = 0;
		જો (mm_user_ચાવી_allowed(ssh, pw, ચાવી, 1, &authopts) &&
		    mm_sshkey_verify(ચાવી, sig, slen,
		    sshbuf_ptr(b), sshbuf_len(b),
		    (ssh->compat & SSH_BUG_SIGTYPE) == 0 ? pkalg : ખાલી,
		    ssh->compat, &sig_details) == 0) {
			authenticated = 1;
		}
		જો (authenticated == 1 && sig_details != ખાલી) {
			auth2_record_info(authctxt, "signature count = %u",
			    sig_details->sk_counter);
			debug_f("sk_counter = %u, sk_flags = 0x%02x",
			    sig_details->sk_counter, sig_details->sk_flags);
			req_presence = (options.pubkey_auth_options &
			    PUBKEYAUTH_TOUCH_REQUIRED) ||
			    !authopts->no_require_user_presence;
			જો (req_presence && (sig_details->sk_flags &
			    SSH_SK_USER_PRESENCE_REQD) == 0) {
				error("public key %s signature for %s%s from "
				    "%.128s port %d rejected: user presence "
				    "(authenticator touch) requirement "
				    "not met ", ચાવી_s,
				    authctxt->valid ? "" : "invalid user ",
				    authctxt->user, ssh_remote_ipaddr(ssh),
				    ssh_remote_port(ssh));
				authenticated = 0;
				જાઓ done;
			}
			req_verify = (options.pubkey_auth_options &
			    PUBKEYAUTH_VERIFY_REQUIRED) ||
			    authopts->require_verify;
			જો (req_verify && (sig_details->sk_flags &
			    SSH_SK_USER_VERIFICATION_REQD) == 0) {
				error("public key %s signature for %s%s from "
				    "%.128s port %d rejected: user "
				    "verification requirement not met ", ચાવી_s,
				    authctxt->valid ? "" : "invalid user ",
				    authctxt->user, ssh_remote_ipaddr(ssh),
				    ssh_remote_port(ssh));
				authenticated = 0;
				જાઓ done;
			}
		}
		auth2_record_ચાવી(authctxt, authenticated, ચાવી);
	} નહીંતર {
		debug_f("%s test pkalg %s pkblob %s%s%s", method, pkalg, ચાવી_s,
		    ca_s == ખાલી ? "" : " CA ", ca_s == ખાલી ? "" : ca_s);

		જો ((r = sshpkt_get_end(ssh)) != 0)
			fatal_fr(r, "parse packet");

		/* XXX fake reply and always send PK_OK ? */
		/*
		 * XXX this allows testing whether a user is allowed
		 * to login: if you happen to have a valid pubkey this
		 * message is sent. the message is NEVER sent at all
		 * if a user is not allowed to login. is this an
		 * issue? -markus
		 */
		જો (authctxt->valid && authctxt->user != ખાલી &&
		    mm_user_ચાવી_allowed(ssh, pw, ચાવી, 0, ખાલી)) {
			જો ((r = sshpkt_start(ssh, SSH2_સંદેશ_USERAUTH_PK_OK))
			    != 0 ||
			    (r = sshpkt_put_cstring(ssh, pkalg)) != 0 ||
			    (r = sshpkt_put_stringb(ssh, keyblob)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0 ||
			    (r = ssh_packet_write_wait(ssh)) != 0)
				fatal_fr(r, "send packet");
			authctxt->postponed = 1;
		} નહીંતર {
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
			જો (authctxt->pk_ok_failures++ < options.max_pubkey_ok)
				authctxt->auth_failure_already_counted = 1;
			debug3_f("pubkey test %d of %d%s",
			    authctxt->pk_ok_failures, options.max_pubkey_ok,
			    authctxt->auth_failure_already_counted ?
			    "" : ": treating as authentication failure");
		 }
	}
done:
	જો (authenticated == 1 && auth_activate_options(ssh, authopts) != 0) {
		debug_f("key options inconsistent with existing");
		authenticated = 0;
	}
	debug2_f("authenticated %d pkalg %s", authenticated, pkalg);

	sshbuf_free(b);
	sshbuf_free(keyblob);
	sshauthopt_free(authopts);
	sshkey_free(ચાવી);
	sshkey_free(hostkey);
	મુક્ત(keystring);
	મુક્ત(userstyle);
	મુક્ત(pkalg);
	મુક્ત(ચાવી_s);
	મુક્ત(ca_s);
	મુક્ત(sig);
	sshkey_sig_details_free(sig_details);
	પાછા authenticated;
}

સ્થિર પૂર્ણાંક
match_principals_file(સંરચના passwd *pw, અક્ષર *file,
    સંરચના sshkey_cert *cert, સંરચના sshauthopt **authoptsp)
{
	FILE *f;
	પૂર્ણાંક r, success = 0;
	size_t i;
	glob_t gl;
	સંરચના sshauthopt *opts = ખાલી;

	જો (authoptsp != ખાલી)
		*authoptsp = ખાલી;

	temporarily_use_uid(pw);
	r = glob(file, 0, ખાલી, &gl);
	restore_uid();
	જો (r != 0) {
		જો (r != GLOB_NOMATCH) {
			logit_f("glob \"%s\" failed", file);
		}
		પાછા 0;
	} નહીંતર જો (gl.gl_pathc > INT_MAX) {
		fatal_f("too many glob results for \"%s\"", file);
	} નહીંતર જો (gl.gl_pathc > 1) {
		debug2_f("glob \"%s\" returned %zu matches", file,
		    gl.gl_pathc);
	}
	માટે (i = 0; !success && i < gl.gl_pathc; i++) {
		temporarily_use_uid(pw);
		debug("trying authorized principals file %s", file);
		જો ((f = auth_openprincipals(gl.gl_pathv[i], pw,
		    options.strict_modes)) == ખાલી) {
			restore_uid();
			ચાલુ;
		}
		success = auth_process_principals(f, gl.gl_pathv[i],
		    cert, &opts);
		fclose(f);
		restore_uid();
		જો (!success) {
			sshauthopt_free(opts);
			opts = ખાલી;
		}
	}
	globfree(&gl);
	જો (success && authoptsp != ખાલી) {
		*authoptsp = opts;
		opts = ખાલી;
	}
	sshauthopt_free(opts);
	પાછા success;
}

/*
 * Checks whether principal is allowed in output of command.
 * returns 1 if the principal is allowed or 0 otherwise.
 */
સ્થિર પૂર્ણાંક
match_principals_command(સંરચના passwd *user_pw, અચલ સંરચના sshkey *ચાવી,
    અચલ અક્ષર *conn_id, અચલ અક્ષર *rdomain, સંરચના sshauthopt **authoptsp)
{
	સંરચના passwd *runas_pw = ખાલી;
	અચલ સંરચના sshkey_cert *cert = ચાવી->cert;
	FILE *f = ખાલી;
	પૂર્ણાંક r, ok, found_principal = 0;
	પૂર્ણાંક i, ac = 0, uid_swapped = 0;
	pid_t pid;
	અક્ષર *tmp, *username = ખાલી, *command = ખાલી, **av = ખાલી;
	અક્ષર *ca_fp = ખાલી, *ચાવી_fp = ખાલી, *catext = ખાલી, *keytext = ખાલી;
	અક્ષર serial_s[32], uidstr[32];
	શૂન્ય (*osigchld)(પૂર્ણાંક);

	જો (authoptsp != ખાલી)
		*authoptsp = ખાલી;
	જો (options.authorized_principals_command == ખાલી)
		પાછા 0;
	જો (options.authorized_principals_command_user == ખાલી) {
		error("No user for AuthorizedPrincipalsCommand specified, "
		    "skipping");
		પાછા 0;
	}

	/*
	 * NB. all returns later this function should go via "out" to
	 * ensure the original SIGCHLD handler is restored properly.
	 */
	osigchld = ssh_signal(SIGCHLD, SIG_DFL);

	/* Prepare and verify the user for the command */
	username = percent_expand(options.authorized_principals_command_user,
	    "u", user_pw->pw_name, (અક્ષર *)ખાલી);
	runas_pw = getpwnam(username);
	જો (runas_pw == ખાલી) {
		error("AuthorizedPrincipalsCommandUser \"%s\" not found: %s",
		    username, strerror(errno));
		જાઓ out;
	}

	/* Turn the command into an argument vector */
	જો (argv_split(options.authorized_principals_command,
	    &ac, &av, 0) != 0) {
		error("AuthorizedPrincipalsCommand \"%s\" contains "
		    "invalid quotes", options.authorized_principals_command);
		જાઓ out;
	}
	જો (ac == 0) {
		error("AuthorizedPrincipalsCommand \"%s\" yielded no arguments",
		    options.authorized_principals_command);
		જાઓ out;
	}
	જો ((ca_fp = sshkey_fingerprint(cert->signature_ચાવી,
	    options.fingerprint_hash, SSH_FP_DEFAULT)) == ખાલી) {
		error_f("sshkey_fingerprint failed");
		જાઓ out;
	}
	જો ((ચાવી_fp = sshkey_fingerprint(ચાવી,
	    options.fingerprint_hash, SSH_FP_DEFAULT)) == ખાલી) {
		error_f("sshkey_fingerprint failed");
		જાઓ out;
	}
	જો ((r = sshkey_to_base64(cert->signature_ચાવી, &catext)) != 0) {
		error_fr(r, "sshkey_to_base64 failed");
		જાઓ out;
	}
	જો ((r = sshkey_to_base64(ચાવી, &keytext)) != 0) {
		error_fr(r, "sshkey_to_base64 failed");
		જાઓ out;
	}
	snprintf(serial_s, કદ(serial_s), "%llu",
	    (unsigned long long)cert->serial);
	snprintf(uidstr, કદ(uidstr), "%llu",
	    (unsigned long long)user_pw->pw_uid);
	માટે (i = 1; i < ac; i++) {
		tmp = percent_expand(av[i],
		    "C", conn_id,
		    "D", rdomain,
		    "U", uidstr,
		    "u", user_pw->pw_name,
		    "h", user_pw->pw_dir,
		    "t", sshkey_ssh_name(ચાવી),
		    "T", sshkey_ssh_name(cert->signature_ચાવી),
		    "f", ચાવી_fp,
		    "F", ca_fp,
		    "k", keytext,
		    "K", catext,
		    "i", cert->ચાવી_id,
		    "s", serial_s,
		    (અક્ષર *)ખાલી);
		જો (tmp == ખાલી)
			fatal_f("percent_expand failed");
		મુક્ત(av[i]);
		av[i] = tmp;
	}
	/* Prepare a printable command for logs, etc. */
	command = argv_assemble(ac, av);

	જો ((pid = subprocess("AuthorizedPrincipalsCommand", command,
	    ac, av, &f,
	    SSH_SUBPROCESS_STDOUT_CAPTURE|SSH_SUBPROCESS_STDERR_DISCARD,
	    runas_pw, temporarily_use_uid, restore_uid)) == 0)
		જાઓ out;

	uid_swapped = 1;
	temporarily_use_uid(runas_pw);

	ok = auth_process_principals(f, "(command)", cert, authoptsp);

	fclose(f);
	f = ખાલી;

	જો (exited_cleanly(pid, "AuthorizedPrincipalsCommand", command, 0) != 0)
		જાઓ out;

	/* Read completed successfully */
	found_principal = ok;
 out:
	જો (f != ખાલી)
		fclose(f);
	ssh_signal(SIGCHLD, osigchld);
	માટે (i = 0; i < ac; i++)
		મુક્ત(av[i]);
	મુક્ત(av);
	જો (uid_swapped)
		restore_uid();
	મુક્ત(command);
	મુક્ત(username);
	મુક્ત(ca_fp);
	મુક્ત(ચાવી_fp);
	મુક્ત(catext);
	મુક્ત(keytext);
	પાછા found_principal;
}

/* Authenticate a certificate key against TrustedUserCAKeys */
સ્થિર પૂર્ણાંક
user_cert_trusted_ca(સંરચના passwd *pw, સંરચના sshkey *ચાવી,
    અચલ અક્ષર *remote_ip, અચલ અક્ષર *remote_host,
    અચલ અક્ષર *conn_id, અચલ અક્ષર *rdomain, સંરચના sshauthopt **authoptsp)
{
	અક્ષર *ca_fp, *principals_file = ખાલી;
	અચલ અક્ષર *reason;
	સંરચના sshauthopt *principals_opts = ખાલી, *cert_opts = ખાલી;
	સંરચના sshauthopt *final_opts = ખાલી;
	પૂર્ણાંક r, ret = 0, found_principal = 0, use_authorized_principals;

	જો (authoptsp != ખાલી)
		*authoptsp = ખાલી;

	જો (!sshkey_is_cert(ચાવી) || options.trusted_user_ca_ચાવીઓ == ખાલી)
		પાછા 0;

	જો ((ca_fp = sshkey_fingerprint(ચાવી->cert->signature_ચાવી,
	    options.fingerprint_hash, SSH_FP_DEFAULT)) == ખાલી)
		પાછા 0;

	જો ((r = sshkey_in_file(ચાવી->cert->signature_ચાવી,
	    options.trusted_user_ca_ચાવીઓ, 1, 0)) != 0) {
		debug2_fr(r, "CA %s %s is not listed in %s",
		    sshkey_type(ચાવી->cert->signature_ચાવી), ca_fp,
		    options.trusted_user_ca_ચાવીઓ);
		જાઓ out;
	}
	/*
	 * If AuthorizedPrincipals is in use, then compare the certificate
	 * principals against the names in that file rather than matching
	 * against the username.
	 */
	જો ((principals_file = authorized_principals_file(pw)) != ખાલી) {
		જો (match_principals_file(pw, principals_file,
		    ચાવી->cert, &principals_opts))
			found_principal = 1;
	}
	/* Try querying command if specified */
	જો (!found_principal && match_principals_command(pw, ચાવી,
	    conn_id, rdomain, &principals_opts))
		found_principal = 1;
	/* If principals file or command is specified, then require a match */
	use_authorized_principals = principals_file != ખાલી ||
	    options.authorized_principals_command != ખાલી;
	જો (!found_principal && use_authorized_principals) {
		reason = "Certificate does not contain an authorized principal";
		જાઓ fail_reason;
	}
	જો (use_authorized_principals && principals_opts == ખાલી)
		fatal_f("internal error: missing principals_opts");
	જો (sshkey_cert_check_authority_now(ચાવી, 0, 0,
	    use_authorized_principals ? ખાલી : pw->pw_name, &reason) != 0)
		જાઓ fail_reason;

	/* Check authority from options in key and from principals file/cmd */
	જો ((cert_opts = sshauthopt_from_cert(ચાવી)) == ખાલી) {
		reason = "Invalid certificate options";
		જાઓ fail_reason;
	}
	જો (auth_authorise_keyopts(pw, cert_opts, 0,
	    remote_ip, remote_host, "cert") != 0) {
		reason = "Refused by certificate options";
		જાઓ fail_reason;
	}
	જો (principals_opts == ખાલી) {
		final_opts = cert_opts;
		cert_opts = ખાલી;
	} નહીંતર {
		જો (auth_authorise_keyopts(pw, principals_opts, 0,
		    remote_ip, remote_host, "principals") != 0) {
			reason = "Refused by certificate principals options";
			જાઓ fail_reason;
		}
		જો ((final_opts = sshauthopt_merge(principals_opts,
		    cert_opts, &reason)) == ખાલી) {
 fail_reason:
			error("Refusing certificate ID \"%s\" serial=%llu "
			    "signed by %s CA %s: %s", ચાવી->cert->ચાવી_id,
			    (unsigned long long)ચાવી->cert->serial,
			    sshkey_type(ચાવી->cert->signature_ચાવી), ca_fp,
			    reason);
			auth_debug_add("Refused Certificate ID \"%s\" "
			    "serial=%llu: %s", ચાવી->cert->ચાવી_id,
			    (unsigned long long)ચાવી->cert->serial, reason);
			જાઓ out;
		}
	}

	/* Success */
	verbose("Accepted certificate ID \"%s\" (serial %llu) signed by "
	    "%s CA %s via %s", ચાવી->cert->ચાવી_id,
	    (unsigned long long)ચાવી->cert->serial,
	    sshkey_type(ચાવી->cert->signature_ચાવી), ca_fp,
	    options.trusted_user_ca_ચાવીઓ);
	જો (authoptsp != ખાલી) {
		*authoptsp = final_opts;
		final_opts = ખાલી;
	}
	ret = 1;
 out:
	sshauthopt_free(principals_opts);
	sshauthopt_free(cert_opts);
	sshauthopt_free(final_opts);
	મુક્ત(principals_file);
	મુક્ત(ca_fp);
	પાછા ret;
}

/*
 * Checks whether key is allowed in file.
 * returns 1 if the key is allowed or 0 otherwise.
 */
સ્થિર પૂર્ણાંક
user_ચાવી_allowed2(સંરચના passwd *pw, સંરચના sshkey *ચાવી,
    અક્ષર *file, અચલ અક્ષર *remote_ip, અચલ અક્ષર *remote_host,
    સંરચના sshauthopt **authoptsp)
{
	FILE *f;
	પૂર્ણાંક found_ચાવી = 0;

	જો (authoptsp != ખાલી)
		*authoptsp = ખાલી;

	/* Temporarily use the user's uid. */
	temporarily_use_uid(pw);

	debug("trying public key file %s", file);
	જો ((f = auth_openkeyfile(file, pw, options.strict_modes)) != ખાલી) {
		found_ચાવી = auth_check_authkeys_file(pw, f, file,
		    ચાવી, remote_ip, remote_host, authoptsp);
		fclose(f);
	}

	restore_uid();
	પાછા found_ચાવી;
}

/*
 * Checks whether key is allowed in output of command.
 * returns 1 if the key is allowed or 0 otherwise.
 */
સ્થિર પૂર્ણાંક
user_ચાવી_command_allowed2(સંરચના passwd *user_pw, સંરચના sshkey *ચાવી,
    અચલ અક્ષર *remote_ip, અચલ અક્ષર *remote_host,
    અચલ અક્ષર *conn_id, અચલ અક્ષર *rdomain, સંરચના sshauthopt **authoptsp)
{
	સંરચના passwd *runas_pw = ખાલી;
	FILE *f = ખાલી;
	પૂર્ણાંક r, ok, found_ચાવી = 0;
	પૂર્ણાંક i, uid_swapped = 0, ac = 0;
	pid_t pid;
	અક્ષર *username = ખાલી, *ચાવી_fp = ખાલી, *keytext = ખાલી;
	અક્ષર uidstr[32], *tmp, *command = ખાલી, **av = ખાલી;
	શૂન્ય (*osigchld)(પૂર્ણાંક);

	જો (authoptsp != ખાલી)
		*authoptsp = ખાલી;
	જો (options.authorized_ચાવીઓ_command == ખાલી)
		પાછા 0;
	જો (options.authorized_ચાવીઓ_command_user == ખાલી) {
		error("No user for AuthorizedKeysCommand specified, skipping");
		પાછા 0;
	}

	/*
	 * NB. all returns later this function should go via "out" to
	 * ensure the original SIGCHLD handler is restored properly.
	 */
	osigchld = ssh_signal(SIGCHLD, SIG_DFL);

	/* Prepare and verify the user for the command */
	username = percent_expand(options.authorized_ચાવીઓ_command_user,
	    "u", user_pw->pw_name, (અક્ષર *)ખાલી);
	runas_pw = getpwnam(username);
	જો (runas_pw == ખાલી) {
		error("AuthorizedKeysCommandUser \"%s\" not found: %s",
		    username, strerror(errno));
		જાઓ out;
	}

	/* Prepare AuthorizedKeysCommand */
	જો ((ચાવી_fp = sshkey_fingerprint(ચાવી, options.fingerprint_hash,
	    SSH_FP_DEFAULT)) == ખાલી) {
		error_f("sshkey_fingerprint failed");
		જાઓ out;
	}
	જો ((r = sshkey_to_base64(ચાવી, &keytext)) != 0) {
		error_fr(r, "sshkey_to_base64 failed");
		જાઓ out;
	}

	/* Turn the command into an argument vector */
	જો (argv_split(options.authorized_ચાવીઓ_command, &ac, &av, 0) != 0) {
		error("AuthorizedKeysCommand \"%s\" contains invalid quotes",
		    options.authorized_ચાવીઓ_command);
		જાઓ out;
	}
	જો (ac == 0) {
		error("AuthorizedKeysCommand \"%s\" yielded no arguments",
		    options.authorized_ચાવીઓ_command);
		જાઓ out;
	}
	snprintf(uidstr, કદ(uidstr), "%llu",
	    (unsigned long long)user_pw->pw_uid);
	માટે (i = 1; i < ac; i++) {
		tmp = percent_expand(av[i],
		    "C", conn_id,
		    "D", rdomain,
		    "U", uidstr,
		    "u", user_pw->pw_name,
		    "h", user_pw->pw_dir,
		    "t", sshkey_ssh_name(ચાવી),
		    "f", ચાવી_fp,
		    "k", keytext,
		    (અક્ષર *)ખાલી);
		જો (tmp == ખાલી)
			fatal_f("percent_expand failed");
		મુક્ત(av[i]);
		av[i] = tmp;
	}
	/* Prepare a printable command for logs, etc. */
	command = argv_assemble(ac, av);

	/*
	 * If AuthorizedKeysCommand was run without arguments
	 * then fall back to the old behaviour of passing the
	 * target username as a single argument.
	 */
	જો (ac == 1) {
		av = xreallocarray(av, ac + 2, કદ(*av));
		av[1] = xstrdup(user_pw->pw_name);
		av[2] = ખાલી;
		/* Fix up command too, since it is used in log messages */
		મુક્ત(command);
		xasprintf(&command, "%s %s", av[0], av[1]);
	}

	જો ((pid = subprocess("AuthorizedKeysCommand", command,
	    ac, av, &f,
	    SSH_SUBPROCESS_STDOUT_CAPTURE|SSH_SUBPROCESS_STDERR_DISCARD,
	    runas_pw, temporarily_use_uid, restore_uid)) == 0)
		જાઓ out;

	uid_swapped = 1;
	temporarily_use_uid(runas_pw);

	ok = auth_check_authkeys_file(user_pw, f,
	    options.authorized_ચાવીઓ_command, ચાવી, remote_ip,
	    remote_host, authoptsp);

	fclose(f);
	f = ખાલી;

	જો (exited_cleanly(pid, "AuthorizedKeysCommand", command, 0) != 0)
		જાઓ out;

	/* Read completed successfully */
	found_ચાવી = ok;
 out:
	જો (f != ખાલી)
		fclose(f);
	ssh_signal(SIGCHLD, osigchld);
	માટે (i = 0; i < ac; i++)
		મુક્ત(av[i]);
	મુક્ત(av);
	જો (uid_swapped)
		restore_uid();
	મુક્ત(command);
	મુક્ત(username);
	મુક્ત(ચાવી_fp);
	મુક્ત(keytext);
	પાછા found_ચાવી;
}

/*
 * Check whether key authenticates and authorises the user.
 */
પૂર્ણાંક
user_ચાવી_allowed(સંરચના ssh *ssh, સંરચના passwd *pw, સંરચના sshkey *ચાવી,
    પૂર્ણાંક auth_attempt, સંરચના sshauthopt **authoptsp)
{
	u_int success = 0, i, j;
	અક્ષર *file = ખાલી, *conn_id;
	સંરચના sshauthopt *opts = ખાલી;
	અચલ અક્ષર *rdomain, *remote_ip, *remote_host;

	જો (authoptsp != ખાલી)
		*authoptsp = ખાલી;

	જો (auth_ચાવી_is_revoked(ચાવી))
		પાછા 0;
	જો (sshkey_is_cert(ચાવી) &&
	    auth_ચાવી_is_revoked(ચાવી->cert->signature_ચાવી))
		પાછા 0;

	જો ((rdomain = ssh_packet_rdomain_in(ssh)) == ખાલી)
		rdomain = "";
	remote_ip = ssh_remote_ipaddr(ssh);
	remote_host = auth_get_canonical_hostname(ssh, options.use_dns);
	xasprintf(&conn_id, "%s %d %s %d",
	    ssh_local_ipaddr(ssh), ssh_local_port(ssh),
	    remote_ip, ssh_remote_port(ssh));

	માટે (i = 0; !success && i < options.અંક_authkeys_files; i++) {
		પૂર્ણાંક r;
		glob_t gl;

		જો (strcasecmp(options.authorized_ચાવીઓ_files[i], "none") == 0)
			ચાલુ;
		file = expand_authorized_ચાવીઓ(
		    options.authorized_ચાવીઓ_files[i], pw);
		temporarily_use_uid(pw);
		r = glob(file, 0, ખાલી, &gl);
		restore_uid();
		જો (r != 0) {
			જો (r != GLOB_NOMATCH) {
				logit_f("glob \"%s\" failed", file);
			}
			મુક્ત(file);
			file = ખાલી;
			ચાલુ;
		} નહીંતર જો (gl.gl_pathc > INT_MAX) {
			fatal_f("too many glob results for \"%s\"", file);
		} નહીંતર જો (gl.gl_pathc > 1) {
			debug2_f("glob \"%s\" returned %zu matches", file,
			    gl.gl_pathc);
		}
		માટે (j = 0; !success && j < gl.gl_pathc; j++) {
			success = user_ચાવી_allowed2(pw, ચાવી, gl.gl_pathv[j],
			    remote_ip, remote_host, &opts);
			જો (!success) {
				sshauthopt_free(opts);
				opts = ખાલી;
			}
		}
		મુક્ત(file);
		file = ખાલી;
		globfree(&gl);
	}
	જો (success)
		જાઓ out;

	જો ((success = user_cert_trusted_ca(pw, ચાવી, remote_ip, remote_host,
	    conn_id, rdomain, &opts)) != 0)
		જાઓ out;
	sshauthopt_free(opts);
	opts = ખાલી;

	જો ((success = user_ચાવી_command_allowed2(pw, ચાવી, remote_ip,
	    remote_host, conn_id, rdomain, &opts)) != 0)
		જાઓ out;
	sshauthopt_free(opts);
	opts = ખાલી;

 out:
	મુક્ત(conn_id);
	જો (success && authoptsp != ખાલી) {
		*authoptsp = opts;
		opts = ખાલી;
	}
	sshauthopt_free(opts);
	પાછા success;
}

Authmethod method_pubkey = {
	&methodcfg_pubkey,
	userauth_pubkey,
};
