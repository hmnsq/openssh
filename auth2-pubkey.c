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

#समावेश "includes.h"

#समावेश <sys/types.h>

#समावेश <stdlib.h>
#समावेश <errno.h>
#समावेश <paths.h>
#समावेश <pwd.h>
#समावेश <glob.h>
#समावेश <signal.h>
#समावेश <stdio.h>
#समावेश <stdarg.h>
#समावेश <string.h>
#समावेश <time.h>
#समावेश <unistd.h>
#समावेश <limits.h>

#समावेश "xmalloc.h"
#समावेश "ssh.h"
#समावेश "ssh2.h"
#समावेश "packet.h"
#समावेश "kex.h"
#समावेश "sshbuf.h"
#समावेश "log.h"
#समावेश "misc.h"
#समावेश "servconf.h"
#समावेश "compat.h"
#समावेश "sshkey.h"
#समावेश "hostfile.h"
#समावेश "auth.h"
#समावेश "pathnames.h"
#समावेश "uidswap.h"
#समावेश "auth-options.h"
#समावेश "canohost.h"
#अगर_घोषित GSSAPI
#समावेश "ssh-gss.h"
#पूर्ण_अगर
#समावेश "monitor_wrap.h"
#समावेश "authfile.h"
#समावेश "match.h"
#समावेश "ssherr.h"
#समावेश "channels.h" /* XXX for session.h */
#समावेश "session.h" /* XXX for child_set_env(); refactor? */
#समावेश "sk-api.h"

/* import */
बाह्य ServerOptions options;
बाह्य काष्ठा authmethod_cfg methodcfg_pubkey;

अटल अक्षर *
format_कुंजी(स्थिर काष्ठा sshkey *कुंजी)
{
	अक्षर *ret, *fp = sshkey_fingerprint(कुंजी,
	    options.fingerprint_hash, SSH_FP_DEFAULT);

	xasprintf(&ret, "%s %s", sshkey_type(कुंजी), fp);
	मुक्त(fp);
	वापस ret;
}

/*
 * Verify that the hostkey in a publickey-hostbound-v00@openssh.com userauth
 * request matches the hostkey that was negotiated during initial KEX.
 */
अटल व्योम
check_hostbound_hostkey(काष्ठा ssh *ssh)
{
	पूर्णांक r;
	काष्ठा sshbuf *our_hostkey_blob, *their_hostkey_blob;

	अगर (ssh->kex->initial_hostkey == शून्य)
		fatal_f("internal error: initial hostkey not recorded");
	अगर ((our_hostkey_blob = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new failed");
	अगर ((r = sshpkt_getb_froms(ssh, &their_hostkey_blob)) != 0)
		fatal_fr(r, "parse hostkey");
	अगर ((r = sshkey_putb(ssh->kex->initial_hostkey, our_hostkey_blob)) != 0)
		fatal_fr(r, "serialise hostkey");
	अगर ((r = sshbuf_equals(our_hostkey_blob, their_hostkey_blob)) != 0)
		fatal_f("packet contained wrong host key");
	sshbuf_free(our_hostkey_blob);
	sshbuf_free(their_hostkey_blob);
}

अटल पूर्णांक
userauth_pubkey(काष्ठा ssh *ssh, स्थिर अक्षर *method)
{
	Authctxt *authctxt = ssh->authctxt;
	काष्ठा passwd *pw = authctxt->pw;
	काष्ठा sshbuf *keyblob = शून्य, *b = शून्य;
	काष्ठा sshkey *कुंजी = शून्य, *hostkey = शून्य;
	अक्षर *pkalg = शून्य, *userstyle = शून्य, *कुंजी_s = शून्य, *ca_s = शून्य;
	अक्षर *keystring = शून्य;
	u_char *sig = शून्य, have_sig;
	माप_प्रकार slen;
	पूर्णांक hostbound, r, pktype;
	पूर्णांक req_presence = 0, req_verify = 0, authenticated = 0;
	काष्ठा sshauthopt *authopts = शून्य;
	काष्ठा sshkey_sig_details *sig_details = शून्य;

	hostbound = म_भेद(method, "publickey-hostbound-v00@openssh.com") == 0;

	अगर ((r = sshpkt_get_u8(ssh, &have_sig)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &pkalg, शून्य)) != 0 ||
	    (r = sshpkt_getb_froms(ssh, &keyblob)) != 0)
		fatal_fr(r, "parse %s packet", method);

	/* hostbound auth includes the hostkey offered at initial KEX */
	अगर (hostbound)
		check_hostbound_hostkey(ssh); /* fatals on error */

	अगर (log_level_get() >= SYSLOG_LEVEL_DEBUG2) {
		अगर ((b = sshbuf_fromb(keyblob)) == शून्य)
			fatal_f("sshbuf_fromb failed");
		अगर ((keystring = sshbuf_dtob64_string(b, 0)) == शून्य)
			fatal_f("sshbuf_dtob64 failed");
		debug2_f("%s user %s %s public key %s %s",
		    authctxt->valid ? "valid" : "invalid", authctxt->user,
		    have_sig ? "attempting" : "querying", pkalg, keystring);
		sshbuf_free(b);
		b = शून्य;
	}

	pktype = sshkey_type_from_name(pkalg);
	अगर (pktype == कुंजी_UNSPEC) {
		/* this is perfectly legal */
		verbose_f("unsupported public key algorithm: %s", pkalg);
		जाओ done;
	}
	अगर (match_pattern_list(pkalg, options.pubkey_accepted_algos, 0) != 1) {
		logit_f("signature algorithm %s not in "
		    "PubkeyAcceptedAlgorithms", pkalg);
		जाओ done;
	}
	अगर ((b = sshbuf_fromb(keyblob)) == शून्य)
		fatal_f("sshbuf_fromb failed");
	चयन ((r = sshkey_fromb_allowlist(b, &कुंजी,
	    options.pubkey_accepted_algos, options.ca_sign_algorithms))) {
	हाल 0:
		/* ok */
		अवरोध;
	हाल SSH_ERR_कुंजी_ALG_UNSUPPORTED:
		/* This shouldn't happen unless the client is being weird */
		logit_f("key algorithm differs from signature algorithm %s and "
		    "is not in PubkeyAcceptedAlgorithms", pkalg);
		जाओ done;
	हाल SSH_ERR_SIGN_ALG_UNSUPPORTED:
		logit_fr(r, "certificate signature algorithm not in "
		    "CASignatureAlgorithm");
		जाओ done;
	शेष:
		error_fr(r, "parse key");
		जाओ done;
	}
	sshbuf_free(b);
	b = शून्य;

	/* USERAUTH_REQUEST signature type should match key's type */
	अगर (कुंजी->type != pktype || (sshkey_type_plain(pktype) == कुंजी_ECDSA &&
	    sshkey_ecdsa_nid_from_name(pkalg) != कुंजी->ecdsa_nid)) {
		error_f("key type mismatch for decoded key "
		    "(received %s, expected %s)", sshkey_ssh_name(कुंजी), pkalg);
		जाओ done;
	}
	अगर (auth2_कुंजी_already_used(authctxt, कुंजी)) {
		logit("refusing previously-used %s key", sshkey_type(कुंजी));
		जाओ done;
	}
	अगर ((r = sshkey_check_rsa_लंबाई(कुंजी,
	    options.required_rsa_आकार)) != 0) {
		logit_r(r, "refusing %s key", sshkey_type(कुंजी));
		जाओ done;
	}
	कुंजी_s = format_कुंजी(कुंजी);
	अगर (sshkey_is_cert(कुंजी))
		ca_s = format_कुंजी(कुंजी->cert->signature_कुंजी);

	अगर (have_sig) {
		debug3_f("%s have %s signature for %s%s%s",
		    method, pkalg, कुंजी_s,
		    ca_s == शून्य ? "" : " CA ", ca_s == शून्य ? "" : ca_s);
		अगर ((r = sshpkt_get_string(ssh, &sig, &slen)) != 0 ||
		    (r = sshpkt_get_end(ssh)) != 0)
			fatal_fr(r, "parse signature packet");
		अगर ((b = sshbuf_new()) == शून्य)
			fatal_f("sshbuf_new failed");
		अगर ((r = sshbuf_put_stringb(b,
		    ssh->kex->session_id)) != 0)
			fatal_fr(r, "put session id");
		अगर (!authctxt->valid || authctxt->user == शून्य) {
			debug2_f("disabled because of invalid user");
			जाओ done;
		}
		/* reconstruct packet */
		xasprintf(&userstyle, "%s%s%s", authctxt->user,
		    authctxt->style ? ":" : "",
		    authctxt->style ? authctxt->style : "");
		अगर ((r = sshbuf_put_u8(b, SSH2_संदेश_USERAUTH_REQUEST)) != 0 ||
		    (r = sshbuf_put_cstring(b, userstyle)) != 0 ||
		    (r = sshbuf_put_cstring(b, authctxt->service)) != 0 ||
		    (r = sshbuf_put_cstring(b, method)) != 0 ||
		    (r = sshbuf_put_u8(b, have_sig)) != 0 ||
		    (r = sshbuf_put_cstring(b, pkalg)) != 0 ||
		    (r = sshbuf_put_stringb(b, keyblob)) != 0)
			fatal_fr(r, "reconstruct %s packet", method);
		अगर (hostbound &&
		    (r = sshkey_puts(ssh->kex->initial_hostkey, b)) != 0)
			fatal_fr(r, "reconstruct %s packet", method);
#अगर_घोषित DEBUG_PK
		sshbuf_dump(b, मानक_त्रुटि);
#पूर्ण_अगर
		/* test for correct signature */
		authenticated = 0;
		अगर (mm_user_कुंजी_allowed(ssh, pw, कुंजी, 1, &authopts) &&
		    mm_sshkey_verify(कुंजी, sig, slen,
		    sshbuf_ptr(b), sshbuf_len(b),
		    (ssh->compat & SSH_BUG_SIGTYPE) == 0 ? pkalg : शून्य,
		    ssh->compat, &sig_details) == 0) {
			authenticated = 1;
		}
		अगर (authenticated == 1 && sig_details != शून्य) {
			auth2_record_info(authctxt, "signature count = %u",
			    sig_details->sk_गणक);
			debug_f("sk_counter = %u, sk_flags = 0x%02x",
			    sig_details->sk_गणक, sig_details->sk_flags);
			req_presence = (options.pubkey_auth_options &
			    PUBKEYAUTH_TOUCH_REQUIRED) ||
			    !authopts->no_require_user_presence;
			अगर (req_presence && (sig_details->sk_flags &
			    SSH_SK_USER_PRESENCE_REQD) == 0) {
				error("public key %s signature for %s%s from "
				    "%.128s port %d rejected: user presence "
				    "(authenticator touch) requirement "
				    "not met ", कुंजी_s,
				    authctxt->valid ? "" : "invalid user ",
				    authctxt->user, ssh_remote_ipaddr(ssh),
				    ssh_remote_port(ssh));
				authenticated = 0;
				जाओ done;
			}
			req_verify = (options.pubkey_auth_options &
			    PUBKEYAUTH_VERIFY_REQUIRED) ||
			    authopts->require_verify;
			अगर (req_verify && (sig_details->sk_flags &
			    SSH_SK_USER_VERIFICATION_REQD) == 0) {
				error("public key %s signature for %s%s from "
				    "%.128s port %d rejected: user "
				    "verification requirement not met ", कुंजी_s,
				    authctxt->valid ? "" : "invalid user ",
				    authctxt->user, ssh_remote_ipaddr(ssh),
				    ssh_remote_port(ssh));
				authenticated = 0;
				जाओ done;
			}
		}
		auth2_record_कुंजी(authctxt, authenticated, कुंजी);
	} अन्यथा {
		debug_f("%s test pkalg %s pkblob %s%s%s", method, pkalg, कुंजी_s,
		    ca_s == शून्य ? "" : " CA ", ca_s == शून्य ? "" : ca_s);

		अगर ((r = sshpkt_get_end(ssh)) != 0)
			fatal_fr(r, "parse packet");

		/* XXX fake reply and always send PK_OK ? */
		/*
		 * XXX this allows testing whether a user is allowed
		 * to login: if you happen to have a valid pubkey this
		 * message is sent. the message is NEVER sent at all
		 * if a user is not allowed to login. is this an
		 * issue? -markus
		 */
		अगर (authctxt->valid && authctxt->user != शून्य &&
		    mm_user_कुंजी_allowed(ssh, pw, कुंजी, 0, शून्य)) {
			अगर ((r = sshpkt_start(ssh, SSH2_संदेश_USERAUTH_PK_OK))
			    != 0 ||
			    (r = sshpkt_put_cstring(ssh, pkalg)) != 0 ||
			    (r = sshpkt_put_stringb(ssh, keyblob)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0 ||
			    (r = ssh_packet_write_wait(ssh)) != 0)
				fatal_fr(r, "send packet");
			authctxt->postponed = 1;
		} अन्यथा {
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
			अगर (authctxt->pk_ok_failures++ < options.max_pubkey_ok)
				authctxt->auth_failure_already_counted = 1;
			debug3_f("pubkey test %d of %d%s",
			    authctxt->pk_ok_failures, options.max_pubkey_ok,
			    authctxt->auth_failure_already_counted ?
			    "" : ": treating as authentication failure");
		 }
	}
done:
	अगर (authenticated == 1 && auth_activate_options(ssh, authopts) != 0) {
		debug_f("key options inconsistent with existing");
		authenticated = 0;
	}
	debug2_f("authenticated %d pkalg %s", authenticated, pkalg);

	sshbuf_free(b);
	sshbuf_free(keyblob);
	sshauthopt_free(authopts);
	sshkey_free(कुंजी);
	sshkey_free(hostkey);
	मुक्त(keystring);
	मुक्त(userstyle);
	मुक्त(pkalg);
	मुक्त(कुंजी_s);
	मुक्त(ca_s);
	मुक्त(sig);
	sshkey_sig_details_free(sig_details);
	वापस authenticated;
}

अटल पूर्णांक
match_principals_file(काष्ठा passwd *pw, अक्षर *file,
    काष्ठा sshkey_cert *cert, काष्ठा sshauthopt **authoptsp)
{
	खाता *f;
	पूर्णांक r, success = 0;
	माप_प्रकार i;
	glob_t gl;
	काष्ठा sshauthopt *opts = शून्य;

	अगर (authoptsp != शून्य)
		*authoptsp = शून्य;

	temporarily_use_uid(pw);
	r = glob(file, 0, शून्य, &gl);
	restore_uid();
	अगर (r != 0) {
		अगर (r != GLOB_NOMATCH) {
			logit_f("glob \"%s\" failed", file);
		}
		वापस 0;
	} अन्यथा अगर (gl.gl_pathc > पूर्णांक_उच्च) {
		fatal_f("too many glob results for \"%s\"", file);
	} अन्यथा अगर (gl.gl_pathc > 1) {
		debug2_f("glob \"%s\" returned %zu matches", file,
		    gl.gl_pathc);
	}
	क्रम (i = 0; !success && i < gl.gl_pathc; i++) {
		temporarily_use_uid(pw);
		debug("trying authorized principals file %s", file);
		अगर ((f = auth_openprincipals(gl.gl_pathv[i], pw,
		    options.strict_modes)) == शून्य) {
			restore_uid();
			जारी;
		}
		success = auth_process_principals(f, gl.gl_pathv[i],
		    cert, &opts);
		ख_बंद(f);
		restore_uid();
		अगर (!success) {
			sshauthopt_free(opts);
			opts = शून्य;
		}
	}
	globfree(&gl);
	अगर (success && authoptsp != शून्य) {
		*authoptsp = opts;
		opts = शून्य;
	}
	sshauthopt_free(opts);
	वापस success;
}

/*
 * Checks whether principal is allowed in output of command.
 * returns 1 if the principal is allowed or 0 otherwise.
 */
अटल पूर्णांक
match_principals_command(काष्ठा passwd *user_pw, स्थिर काष्ठा sshkey *कुंजी,
    स्थिर अक्षर *conn_id, स्थिर अक्षर *rdomain, काष्ठा sshauthopt **authoptsp)
{
	काष्ठा passwd *runas_pw = शून्य;
	स्थिर काष्ठा sshkey_cert *cert = कुंजी->cert;
	खाता *f = शून्य;
	पूर्णांक r, ok, found_principal = 0;
	पूर्णांक i, ac = 0, uid_swapped = 0;
	pid_t pid;
	अक्षर *tmp, *username = शून्य, *command = शून्य, **av = शून्य;
	अक्षर *ca_fp = शून्य, *कुंजी_fp = शून्य, *catext = शून्य, *keytext = शून्य;
	अक्षर serial_s[32], uidstr[32];
	व्योम (*osigchld)(पूर्णांक);

	अगर (authoptsp != शून्य)
		*authoptsp = शून्य;
	अगर (options.authorized_principals_command == शून्य)
		वापस 0;
	अगर (options.authorized_principals_command_user == शून्य) {
		error("No user for AuthorizedPrincipalsCommand specified, "
		    "skipping");
		वापस 0;
	}

	/*
	 * NB. all returns later this function should go via "out" to
	 * ensure the original SIGCHLD handler is restored properly.
	 */
	osigchld = ssh_signal(SIGCHLD, संक_पूर्व);

	/* Prepare and verify the user for the command */
	username = percent_expand(options.authorized_principals_command_user,
	    "u", user_pw->pw_name, (अक्षर *)शून्य);
	runas_pw = getpwnam(username);
	अगर (runas_pw == शून्य) {
		error("AuthorizedPrincipalsCommandUser \"%s\" not found: %s",
		    username, म_त्रुटि(त्रुटि_सं));
		जाओ out;
	}

	/* Turn the command into an argument vector */
	अगर (argv_split(options.authorized_principals_command,
	    &ac, &av, 0) != 0) {
		error("AuthorizedPrincipalsCommand \"%s\" contains "
		    "invalid quotes", options.authorized_principals_command);
		जाओ out;
	}
	अगर (ac == 0) {
		error("AuthorizedPrincipalsCommand \"%s\" yielded no arguments",
		    options.authorized_principals_command);
		जाओ out;
	}
	अगर ((ca_fp = sshkey_fingerprint(cert->signature_कुंजी,
	    options.fingerprint_hash, SSH_FP_DEFAULT)) == शून्य) {
		error_f("sshkey_fingerprint failed");
		जाओ out;
	}
	अगर ((कुंजी_fp = sshkey_fingerprint(कुंजी,
	    options.fingerprint_hash, SSH_FP_DEFAULT)) == शून्य) {
		error_f("sshkey_fingerprint failed");
		जाओ out;
	}
	अगर ((r = sshkey_to_base64(cert->signature_कुंजी, &catext)) != 0) {
		error_fr(r, "sshkey_to_base64 failed");
		जाओ out;
	}
	अगर ((r = sshkey_to_base64(कुंजी, &keytext)) != 0) {
		error_fr(r, "sshkey_to_base64 failed");
		जाओ out;
	}
	snprintf(serial_s, माप(serial_s), "%llu",
	    (अचिन्हित दीर्घ दीर्घ)cert->serial);
	snprintf(uidstr, माप(uidstr), "%llu",
	    (अचिन्हित दीर्घ दीर्घ)user_pw->pw_uid);
	क्रम (i = 1; i < ac; i++) {
		tmp = percent_expand(av[i],
		    "C", conn_id,
		    "D", rdomain,
		    "U", uidstr,
		    "u", user_pw->pw_name,
		    "h", user_pw->pw_dir,
		    "t", sshkey_ssh_name(कुंजी),
		    "T", sshkey_ssh_name(cert->signature_कुंजी),
		    "f", कुंजी_fp,
		    "F", ca_fp,
		    "k", keytext,
		    "K", catext,
		    "i", cert->कुंजी_id,
		    "s", serial_s,
		    (अक्षर *)शून्य);
		अगर (tmp == शून्य)
			fatal_f("percent_expand failed");
		मुक्त(av[i]);
		av[i] = tmp;
	}
	/* Prepare a printable command for logs, etc. */
	command = argv_assemble(ac, av);

	अगर ((pid = subprocess("AuthorizedPrincipalsCommand", command,
	    ac, av, &f,
	    SSH_SUBPROCESS_STDOUT_CAPTURE|SSH_SUBPROCESS_STDERR_DISCARD,
	    runas_pw, temporarily_use_uid, restore_uid)) == 0)
		जाओ out;

	uid_swapped = 1;
	temporarily_use_uid(runas_pw);

	ok = auth_process_principals(f, "(command)", cert, authoptsp);

	ख_बंद(f);
	f = शून्य;

	अगर (exited_cleanly(pid, "AuthorizedPrincipalsCommand", command, 0) != 0)
		जाओ out;

	/* Read completed successfully */
	found_principal = ok;
 out:
	अगर (f != शून्य)
		ख_बंद(f);
	ssh_signal(SIGCHLD, osigchld);
	क्रम (i = 0; i < ac; i++)
		मुक्त(av[i]);
	मुक्त(av);
	अगर (uid_swapped)
		restore_uid();
	मुक्त(command);
	मुक्त(username);
	मुक्त(ca_fp);
	मुक्त(कुंजी_fp);
	मुक्त(catext);
	मुक्त(keytext);
	वापस found_principal;
}

/* Authenticate a certificate key against TrustedUserCAKeys */
अटल पूर्णांक
user_cert_trusted_ca(काष्ठा passwd *pw, काष्ठा sshkey *कुंजी,
    स्थिर अक्षर *remote_ip, स्थिर अक्षर *remote_host,
    स्थिर अक्षर *conn_id, स्थिर अक्षर *rdomain, काष्ठा sshauthopt **authoptsp)
{
	अक्षर *ca_fp, *principals_file = शून्य;
	स्थिर अक्षर *reason;
	काष्ठा sshauthopt *principals_opts = शून्य, *cert_opts = शून्य;
	काष्ठा sshauthopt *final_opts = शून्य;
	पूर्णांक r, ret = 0, found_principal = 0, use_authorized_principals;

	अगर (authoptsp != शून्य)
		*authoptsp = शून्य;

	अगर (!sshkey_is_cert(कुंजी) || options.trusted_user_ca_कुंजियाँ == शून्य)
		वापस 0;

	अगर ((ca_fp = sshkey_fingerprint(कुंजी->cert->signature_कुंजी,
	    options.fingerprint_hash, SSH_FP_DEFAULT)) == शून्य)
		वापस 0;

	अगर ((r = sshkey_in_file(कुंजी->cert->signature_कुंजी,
	    options.trusted_user_ca_कुंजियाँ, 1, 0)) != 0) {
		debug2_fr(r, "CA %s %s is not listed in %s",
		    sshkey_type(कुंजी->cert->signature_कुंजी), ca_fp,
		    options.trusted_user_ca_कुंजियाँ);
		जाओ out;
	}
	/*
	 * If AuthorizedPrincipals is in use, then compare the certificate
	 * principals against the names in that file rather than matching
	 * against the username.
	 */
	अगर ((principals_file = authorized_principals_file(pw)) != शून्य) {
		अगर (match_principals_file(pw, principals_file,
		    कुंजी->cert, &principals_opts))
			found_principal = 1;
	}
	/* Try querying command if specified */
	अगर (!found_principal && match_principals_command(pw, कुंजी,
	    conn_id, rdomain, &principals_opts))
		found_principal = 1;
	/* If principals file or command is specified, then require a match */
	use_authorized_principals = principals_file != शून्य ||
	    options.authorized_principals_command != शून्य;
	अगर (!found_principal && use_authorized_principals) {
		reason = "Certificate does not contain an authorized principal";
		जाओ fail_reason;
	}
	अगर (use_authorized_principals && principals_opts == शून्य)
		fatal_f("internal error: missing principals_opts");
	अगर (sshkey_cert_check_authority_now(कुंजी, 0, 0,
	    use_authorized_principals ? शून्य : pw->pw_name, &reason) != 0)
		जाओ fail_reason;

	/* Check authority from options in key and from principals file/cmd */
	अगर ((cert_opts = sshauthopt_from_cert(कुंजी)) == शून्य) {
		reason = "Invalid certificate options";
		जाओ fail_reason;
	}
	अगर (auth_authorise_keyopts(pw, cert_opts, 0,
	    remote_ip, remote_host, "cert") != 0) {
		reason = "Refused by certificate options";
		जाओ fail_reason;
	}
	अगर (principals_opts == शून्य) {
		final_opts = cert_opts;
		cert_opts = शून्य;
	} अन्यथा {
		अगर (auth_authorise_keyopts(pw, principals_opts, 0,
		    remote_ip, remote_host, "principals") != 0) {
			reason = "Refused by certificate principals options";
			जाओ fail_reason;
		}
		अगर ((final_opts = sshauthopt_merge(principals_opts,
		    cert_opts, &reason)) == शून्य) {
 fail_reason:
			error("Refusing certificate ID \"%s\" serial=%llu "
			    "signed by %s CA %s: %s", कुंजी->cert->कुंजी_id,
			    (अचिन्हित दीर्घ दीर्घ)कुंजी->cert->serial,
			    sshkey_type(कुंजी->cert->signature_कुंजी), ca_fp,
			    reason);
			auth_debug_add("Refused Certificate ID \"%s\" "
			    "serial=%llu: %s", कुंजी->cert->कुंजी_id,
			    (अचिन्हित दीर्घ दीर्घ)कुंजी->cert->serial, reason);
			जाओ out;
		}
	}

	/* Success */
	verbose("Accepted certificate ID \"%s\" (serial %llu) signed by "
	    "%s CA %s via %s", कुंजी->cert->कुंजी_id,
	    (अचिन्हित दीर्घ दीर्घ)कुंजी->cert->serial,
	    sshkey_type(कुंजी->cert->signature_कुंजी), ca_fp,
	    options.trusted_user_ca_कुंजियाँ);
	अगर (authoptsp != शून्य) {
		*authoptsp = final_opts;
		final_opts = शून्य;
	}
	ret = 1;
 out:
	sshauthopt_free(principals_opts);
	sshauthopt_free(cert_opts);
	sshauthopt_free(final_opts);
	मुक्त(principals_file);
	मुक्त(ca_fp);
	वापस ret;
}

/*
 * Checks whether key is allowed in file.
 * returns 1 if the key is allowed or 0 otherwise.
 */
अटल पूर्णांक
user_कुंजी_allowed2(काष्ठा passwd *pw, काष्ठा sshkey *कुंजी,
    अक्षर *file, स्थिर अक्षर *remote_ip, स्थिर अक्षर *remote_host,
    काष्ठा sshauthopt **authoptsp)
{
	खाता *f;
	पूर्णांक found_कुंजी = 0;

	अगर (authoptsp != शून्य)
		*authoptsp = शून्य;

	/* Temporarily use the user's uid. */
	temporarily_use_uid(pw);

	debug("trying public key file %s", file);
	अगर ((f = auth_openkeyfile(file, pw, options.strict_modes)) != शून्य) {
		found_कुंजी = auth_check_authkeys_file(pw, f, file,
		    कुंजी, remote_ip, remote_host, authoptsp);
		ख_बंद(f);
	}

	restore_uid();
	वापस found_कुंजी;
}

/*
 * Checks whether key is allowed in output of command.
 * returns 1 if the key is allowed or 0 otherwise.
 */
अटल पूर्णांक
user_कुंजी_command_allowed2(काष्ठा passwd *user_pw, काष्ठा sshkey *कुंजी,
    स्थिर अक्षर *remote_ip, स्थिर अक्षर *remote_host,
    स्थिर अक्षर *conn_id, स्थिर अक्षर *rdomain, काष्ठा sshauthopt **authoptsp)
{
	काष्ठा passwd *runas_pw = शून्य;
	खाता *f = शून्य;
	पूर्णांक r, ok, found_कुंजी = 0;
	पूर्णांक i, uid_swapped = 0, ac = 0;
	pid_t pid;
	अक्षर *username = शून्य, *कुंजी_fp = शून्य, *keytext = शून्य;
	अक्षर uidstr[32], *tmp, *command = शून्य, **av = शून्य;
	व्योम (*osigchld)(पूर्णांक);

	अगर (authoptsp != शून्य)
		*authoptsp = शून्य;
	अगर (options.authorized_कुंजियाँ_command == शून्य)
		वापस 0;
	अगर (options.authorized_कुंजियाँ_command_user == शून्य) {
		error("No user for AuthorizedKeysCommand specified, skipping");
		वापस 0;
	}

	/*
	 * NB. all returns later this function should go via "out" to
	 * ensure the original SIGCHLD handler is restored properly.
	 */
	osigchld = ssh_signal(SIGCHLD, संक_पूर्व);

	/* Prepare and verify the user for the command */
	username = percent_expand(options.authorized_कुंजियाँ_command_user,
	    "u", user_pw->pw_name, (अक्षर *)शून्य);
	runas_pw = getpwnam(username);
	अगर (runas_pw == शून्य) {
		error("AuthorizedKeysCommandUser \"%s\" not found: %s",
		    username, म_त्रुटि(त्रुटि_सं));
		जाओ out;
	}

	/* Prepare AuthorizedKeysCommand */
	अगर ((कुंजी_fp = sshkey_fingerprint(कुंजी, options.fingerprint_hash,
	    SSH_FP_DEFAULT)) == शून्य) {
		error_f("sshkey_fingerprint failed");
		जाओ out;
	}
	अगर ((r = sshkey_to_base64(कुंजी, &keytext)) != 0) {
		error_fr(r, "sshkey_to_base64 failed");
		जाओ out;
	}

	/* Turn the command into an argument vector */
	अगर (argv_split(options.authorized_कुंजियाँ_command, &ac, &av, 0) != 0) {
		error("AuthorizedKeysCommand \"%s\" contains invalid quotes",
		    options.authorized_कुंजियाँ_command);
		जाओ out;
	}
	अगर (ac == 0) {
		error("AuthorizedKeysCommand \"%s\" yielded no arguments",
		    options.authorized_कुंजियाँ_command);
		जाओ out;
	}
	snprintf(uidstr, माप(uidstr), "%llu",
	    (अचिन्हित दीर्घ दीर्घ)user_pw->pw_uid);
	क्रम (i = 1; i < ac; i++) {
		tmp = percent_expand(av[i],
		    "C", conn_id,
		    "D", rdomain,
		    "U", uidstr,
		    "u", user_pw->pw_name,
		    "h", user_pw->pw_dir,
		    "t", sshkey_ssh_name(कुंजी),
		    "f", कुंजी_fp,
		    "k", keytext,
		    (अक्षर *)शून्य);
		अगर (tmp == शून्य)
			fatal_f("percent_expand failed");
		मुक्त(av[i]);
		av[i] = tmp;
	}
	/* Prepare a printable command for logs, etc. */
	command = argv_assemble(ac, av);

	/*
	 * If AuthorizedKeysCommand was run without arguments
	 * then fall back to the old behaviour of passing the
	 * target username as a single argument.
	 */
	अगर (ac == 1) {
		av = xreallocarray(av, ac + 2, माप(*av));
		av[1] = xstrdup(user_pw->pw_name);
		av[2] = शून्य;
		/* Fix up command too, since it is used in log messages */
		मुक्त(command);
		xasprintf(&command, "%s %s", av[0], av[1]);
	}

	अगर ((pid = subprocess("AuthorizedKeysCommand", command,
	    ac, av, &f,
	    SSH_SUBPROCESS_STDOUT_CAPTURE|SSH_SUBPROCESS_STDERR_DISCARD,
	    runas_pw, temporarily_use_uid, restore_uid)) == 0)
		जाओ out;

	uid_swapped = 1;
	temporarily_use_uid(runas_pw);

	ok = auth_check_authkeys_file(user_pw, f,
	    options.authorized_कुंजियाँ_command, कुंजी, remote_ip,
	    remote_host, authoptsp);

	ख_बंद(f);
	f = शून्य;

	अगर (exited_cleanly(pid, "AuthorizedKeysCommand", command, 0) != 0)
		जाओ out;

	/* Read completed successfully */
	found_कुंजी = ok;
 out:
	अगर (f != शून्य)
		ख_बंद(f);
	ssh_signal(SIGCHLD, osigchld);
	क्रम (i = 0; i < ac; i++)
		मुक्त(av[i]);
	मुक्त(av);
	अगर (uid_swapped)
		restore_uid();
	मुक्त(command);
	मुक्त(username);
	मुक्त(कुंजी_fp);
	मुक्त(keytext);
	वापस found_कुंजी;
}

/*
 * Check whether key authenticates and authorises the user.
 */
पूर्णांक
user_कुंजी_allowed(काष्ठा ssh *ssh, काष्ठा passwd *pw, काष्ठा sshkey *कुंजी,
    पूर्णांक auth_attempt, काष्ठा sshauthopt **authoptsp)
{
	u_int success = 0, i, j;
	अक्षर *file = शून्य, *conn_id;
	काष्ठा sshauthopt *opts = शून्य;
	स्थिर अक्षर *rdomain, *remote_ip, *remote_host;

	अगर (authoptsp != शून्य)
		*authoptsp = शून्य;

	अगर (auth_कुंजी_is_revoked(कुंजी))
		वापस 0;
	अगर (sshkey_is_cert(कुंजी) &&
	    auth_कुंजी_is_revoked(कुंजी->cert->signature_कुंजी))
		वापस 0;

	अगर ((rdomain = ssh_packet_rdomain_in(ssh)) == शून्य)
		rdomain = "";
	remote_ip = ssh_remote_ipaddr(ssh);
	remote_host = auth_get_canonical_hostname(ssh, options.use_dns);
	xasprintf(&conn_id, "%s %d %s %d",
	    ssh_local_ipaddr(ssh), ssh_local_port(ssh),
	    remote_ip, ssh_remote_port(ssh));

	क्रम (i = 0; !success && i < options.अंक_authkeys_files; i++) {
		पूर्णांक r;
		glob_t gl;

		अगर (strcasecmp(options.authorized_कुंजियाँ_files[i], "none") == 0)
			जारी;
		file = expand_authorized_कुंजियाँ(
		    options.authorized_कुंजियाँ_files[i], pw);
		temporarily_use_uid(pw);
		r = glob(file, 0, शून्य, &gl);
		restore_uid();
		अगर (r != 0) {
			अगर (r != GLOB_NOMATCH) {
				logit_f("glob \"%s\" failed", file);
			}
			मुक्त(file);
			file = शून्य;
			जारी;
		} अन्यथा अगर (gl.gl_pathc > पूर्णांक_उच्च) {
			fatal_f("too many glob results for \"%s\"", file);
		} अन्यथा अगर (gl.gl_pathc > 1) {
			debug2_f("glob \"%s\" returned %zu matches", file,
			    gl.gl_pathc);
		}
		क्रम (j = 0; !success && j < gl.gl_pathc; j++) {
			success = user_कुंजी_allowed2(pw, कुंजी, gl.gl_pathv[j],
			    remote_ip, remote_host, &opts);
			अगर (!success) {
				sshauthopt_free(opts);
				opts = शून्य;
			}
		}
		मुक्त(file);
		file = शून्य;
		globfree(&gl);
	}
	अगर (success)
		जाओ out;

	अगर ((success = user_cert_trusted_ca(pw, कुंजी, remote_ip, remote_host,
	    conn_id, rdomain, &opts)) != 0)
		जाओ out;
	sshauthopt_free(opts);
	opts = शून्य;

	अगर ((success = user_कुंजी_command_allowed2(pw, कुंजी, remote_ip,
	    remote_host, conn_id, rdomain, &opts)) != 0)
		जाओ out;
	sshauthopt_free(opts);
	opts = शून्य;

 out:
	मुक्त(conn_id);
	अगर (success && authoptsp != शून्य) {
		*authoptsp = opts;
		opts = शून्य;
	}
	sshauthopt_free(opts);
	वापस success;
}

Authmethod method_pubkey = {
	&methodcfg_pubkey,
	userauth_pubkey,
};
