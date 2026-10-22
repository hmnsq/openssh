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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>

#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <errno.h>
#अन्तर्भाव <paths.h>
#अन्तर्भाव <pwd.h>
#अन्तर्भाव <glob.h>
#अन्तर्भाव <signal.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <time.h>
#अन्तर्भाव <unistd.h>
#अन्तर्भाव <limits.h>

#अन्तर्भाव "xmalloc.h"
#अन्तर्भाव "ssh.h"
#अन्तर्भाव "ssh2.h"
#अन्तर्भाव "packet.h"
#अन्तर्भाव "kex.h"
#अन्तर्भाव "sshbuf.h"
#अन्तर्भाव "log.h"
#अन्तर्भाव "misc.h"
#अन्तर्भाव "servconf.h"
#अन्तर्भाव "compat.h"
#अन्तर्भाव "sshkey.h"
#अन्तर्भाव "hostfile.h"
#अन्तर्भाव "auth.h"
#अन्तर्भाव "pathnames.h"
#अन्तर्भाव "uidswap.h"
#अन्तर्भाव "auth-options.h"
#अन्तर्भाव "canohost.h"
#ifdef GSSAPI
#अन्तर्भाव "ssh-gss.h"
#endif
#अन्तर्भाव "monitor_wrap.h"
#अन्तर्भाव "authfile.h"
#अन्तर्भाव "match.h"
#अन्तर्भाव "ssherr.h"
#अन्तर्भाव "channels.h" /* XXX for session.h */
#अन्तर्भाव "session.h" /* XXX for child_set_env(); refactor? */
#अन्तर्भाव "sk-api.h"

/* import */
बाह्य ServerOptions options;
बाह्य संरचना authmethod_cfg methodcfg_pubkey;

स्थिर अक्षर *
format_किल्ली(स्थिरांक संरचना sshkey *किल्ली)
{
	अक्षर *ret, *fp = sshkey_fingerprint(किल्ली,
	    options.fingerprint_hash, SSH_FP_DEFAULT);

	xasprintf(&ret, "%s %s", sshkey_type(किल्ली), fp);
	मुक्त(fp);
	परत ret;
}

/*
 * Verify that the hostkey in a publickey-hostbound-v00@openssh.com userauth
 * request matches the hostkey that was negotiated during initial KEX.
 */
स्थिर शून्य
check_hostbound_hostkey(संरचना ssh *ssh)
{
	पूर्णांक r;
	संरचना sshbuf *our_hostkey_blob, *their_hostkey_blob;

	जर (ssh->kex->initial_hostkey == रिक्त)
		fatal_f("internal error: initial hostkey not recorded");
	जर ((our_hostkey_blob = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	जर ((r = sshpkt_getb_froms(ssh, &their_hostkey_blob)) != 0)
		fatal_fr(r, "parse hostkey");
	जर ((r = sshkey_putb(ssh->kex->initial_hostkey, our_hostkey_blob)) != 0)
		fatal_fr(r, "serialise hostkey");
	जर ((r = sshbuf_equals(our_hostkey_blob, their_hostkey_blob)) != 0)
		fatal_f("packet contained wrong host key");
	sshbuf_free(our_hostkey_blob);
	sshbuf_free(their_hostkey_blob);
}

स्थिर पूर्णांक
userauth_pubkey(संरचना ssh *ssh, स्थिरांक अक्षर *method)
{
	Authctxt *authctxt = ssh->authctxt;
	संरचना passwd *pw = authctxt->pw;
	संरचना sshbuf *keyblob = रिक्त, *b = रिक्त;
	संरचना sshkey *किल्ली = रिक्त, *hostkey = रिक्त;
	अक्षर *pkalg = रिक्त, *userstyle = रिक्त, *किल्ली_s = रिक्त, *ca_s = रिक्त;
	अक्षर *keystring = रिक्त;
	u_char *sig = रिक्त, have_sig;
	माप_प्रकार slen;
	पूर्णांक hostbound, r, pktype;
	पूर्णांक req_presence = 0, req_verify = 0, authenticated = 0;
	संरचना sshauthopt *authopts = रिक्त;
	संरचना sshkey_sig_details *sig_details = रिक्त;

	hostbound = म_भेद(method, "publickey-hostbound-v00@openssh.com") == 0;

	जर ((r = sshpkt_get_u8(ssh, &have_sig)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &pkalg, रिक्त)) != 0 ||
	    (r = sshpkt_getb_froms(ssh, &keyblob)) != 0)
		fatal_fr(r, "parse %s packet", method);

	/* hostbound auth includes the hostkey offered at initial KEX */
	जर (hostbound)
		check_hostbound_hostkey(ssh); /* fatals on error */

	जर (log_level_get() >= SYSLOG_LEVEL_DEBUG2) {
		जर ((b = sshbuf_fromb(keyblob)) == रिक्त)
			fatal_f("sshbuf_fromb failed");
		जर ((keystring = sshbuf_dtob64_string(b, 0)) == रिक्त)
			fatal_f("sshbuf_dtob64 failed");
		debug2_f("%s user %s %s public key %s %s",
		    authctxt->valid ? "valid" : "invalid", authctxt->user,
		    have_sig ? "attempting" : "querying", pkalg, keystring);
		sshbuf_free(b);
		b = रिक्त;
	}

	pktype = sshkey_type_from_name(pkalg);
	जर (pktype == किल्ली_UNSPEC) {
		/* this is perfectly legal */
		verbose_f("unsupported public key algorithm: %s", pkalg);
		जा done;
	}
	जर (match_pattern_list(pkalg, options.pubkey_accepted_algos, 0) != 1) {
		logit_f("signature algorithm %s not in "
		    "PubkeyAcceptedAlgorithms", pkalg);
		जा done;
	}
	जर ((b = sshbuf_fromb(keyblob)) == रिक्त)
		fatal_f("sshbuf_fromb failed");
	निवड ((r = sshkey_fromb_allowlist(b, &किल्ली,
	    options.pubkey_accepted_algos, options.ca_sign_algorithms))) {
	स्थिती 0:
		/* ok */
		थांबा;
	स्थिती SSH_ERR_किल्ली_ALG_UNSUPPORTED:
		/* This shouldn't happen unless the client is being weird */
		logit_f("key algorithm differs from signature algorithm %s and "
		    "is not in PubkeyAcceptedAlgorithms", pkalg);
		जा done;
	स्थिती SSH_ERR_SIGN_ALG_UNSUPPORTED:
		logit_fr(r, "certificate signature algorithm not in "
		    "CASignatureAlgorithm");
		जा done;
	पूर्वनिर्धारित:
		error_fr(r, "parse key");
		जा done;
	}
	sshbuf_free(b);
	b = रिक्त;

	/* USERAUTH_REQUEST signature type should match key's type */
	जर (किल्ली->type != pktype || (sshkey_type_plain(pktype) == किल्ली_ECDSA &&
	    sshkey_ecdsa_nid_from_name(pkalg) != किल्ली->ecdsa_nid)) {
		error_f("key type mismatch for decoded key "
		    "(received %s, expected %s)", sshkey_ssh_name(किल्ली), pkalg);
		जा done;
	}
	जर (auth2_किल्ली_already_used(authctxt, किल्ली)) {
		logit("refusing previously-used %s key", sshkey_type(किल्ली));
		जा done;
	}
	जर ((r = sshkey_check_rsa_length(किल्ली,
	    options.required_rsa_size)) != 0) {
		logit_r(r, "refusing %s key", sshkey_type(किल्ली));
		जा done;
	}
	किल्ली_s = format_किल्ली(किल्ली);
	जर (sshkey_is_cert(किल्ली))
		ca_s = format_किल्ली(किल्ली->cert->signature_किल्ली);

	जर (have_sig) {
		debug3_f("%s have %s signature for %s%s%s",
		    method, pkalg, किल्ली_s,
		    ca_s == रिक्त ? "" : " CA ", ca_s == रिक्त ? "" : ca_s);
		जर ((r = sshpkt_get_string(ssh, &sig, &slen)) != 0 ||
		    (r = sshpkt_get_end(ssh)) != 0)
			fatal_fr(r, "parse signature packet");
		जर ((b = sshbuf_new()) == रिक्त)
			fatal_f("sshbuf_new failed");
		जर ((r = sshbuf_put_stringb(b,
		    ssh->kex->session_id)) != 0)
			fatal_fr(r, "put session id");
		जर (!authctxt->valid || authctxt->user == रिक्त) {
			debug2_f("disabled because of invalid user");
			जा done;
		}
		/* reconstruct packet */
		xasprintf(&userstyle, "%s%s%s", authctxt->user,
		    authctxt->style ? ":" : "",
		    authctxt->style ? authctxt->style : "");
		जर ((r = sshbuf_put_u8(b, SSH2_संदेश_USERAUTH_REQUEST)) != 0 ||
		    (r = sshbuf_put_cstring(b, userstyle)) != 0 ||
		    (r = sshbuf_put_cstring(b, authctxt->service)) != 0 ||
		    (r = sshbuf_put_cstring(b, method)) != 0 ||
		    (r = sshbuf_put_u8(b, have_sig)) != 0 ||
		    (r = sshbuf_put_cstring(b, pkalg)) != 0 ||
		    (r = sshbuf_put_stringb(b, keyblob)) != 0)
			fatal_fr(r, "reconstruct %s packet", method);
		जर (hostbound &&
		    (r = sshkey_puts(ssh->kex->initial_hostkey, b)) != 0)
			fatal_fr(r, "reconstruct %s packet", method);
#ifdef DEBUG_PK
		sshbuf_dump(b, मानक_त्रुटि);
#endif
		/* test for correct signature */
		authenticated = 0;
		जर (mm_user_किल्ली_allowed(ssh, pw, किल्ली, 1, &authopts) &&
		    mm_sshkey_verify(किल्ली, sig, slen,
		    sshbuf_ptr(b), sshbuf_len(b),
		    (ssh->compat & SSH_BUG_SIGTYPE) == 0 ? pkalg : रिक्त,
		    ssh->compat, &sig_details) == 0) {
			authenticated = 1;
		}
		जर (authenticated == 1 && sig_details != रिक्त) {
			auth2_record_info(authctxt, "signature count = %u",
			    sig_details->sk_counter);
			debug_f("sk_counter = %u, sk_flags = 0x%02x",
			    sig_details->sk_counter, sig_details->sk_flags);
			req_presence = (options.pubkey_auth_options &
			    PUBKEYAUTH_TOUCH_REQUIRED) ||
			    !authopts->no_require_user_presence;
			जर (req_presence && (sig_details->sk_flags &
			    SSH_SK_USER_PRESENCE_REQD) == 0) {
				error("public key %s signature for %s%s from "
				    "%.128s port %d rejected: user presence "
				    "(authenticator touch) requirement "
				    "not met ", किल्ली_s,
				    authctxt->valid ? "" : "invalid user ",
				    authctxt->user, ssh_remote_ipaddr(ssh),
				    ssh_remote_port(ssh));
				authenticated = 0;
				जा done;
			}
			req_verify = (options.pubkey_auth_options &
			    PUBKEYAUTH_VERIFY_REQUIRED) ||
			    authopts->require_verify;
			जर (req_verify && (sig_details->sk_flags &
			    SSH_SK_USER_VERIFICATION_REQD) == 0) {
				error("public key %s signature for %s%s from "
				    "%.128s port %d rejected: user "
				    "verification requirement not met ", किल्ली_s,
				    authctxt->valid ? "" : "invalid user ",
				    authctxt->user, ssh_remote_ipaddr(ssh),
				    ssh_remote_port(ssh));
				authenticated = 0;
				जा done;
			}
		}
		auth2_record_किल्ली(authctxt, authenticated, किल्ली);
	} अन्यथा {
		debug_f("%s test pkalg %s pkblob %s%s%s", method, pkalg, किल्ली_s,
		    ca_s == रिक्त ? "" : " CA ", ca_s == रिक्त ? "" : ca_s);

		जर ((r = sshpkt_get_end(ssh)) != 0)
			fatal_fr(r, "parse packet");

		/* XXX fake reply and always send PK_OK ? */
		/*
		 * XXX this allows testing whether a user is allowed
		 * to login: if you happen to have a valid pubkey this
		 * message is sent. the message is NEVER sent at all
		 * if a user is not allowed to login. is this an
		 * issue? -markus
		 */
		जर (authctxt->valid && authctxt->user != रिक्त &&
		    mm_user_किल्ली_allowed(ssh, pw, किल्ली, 0, रिक्त)) {
			जर ((r = sshpkt_start(ssh, SSH2_संदेश_USERAUTH_PK_OK))
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
			जर (authctxt->pk_ok_failures++ < options.max_pubkey_ok)
				authctxt->auth_failure_already_counted = 1;
			debug3_f("pubkey test %d of %d%s",
			    authctxt->pk_ok_failures, options.max_pubkey_ok,
			    authctxt->auth_failure_already_counted ?
			    "" : ": treating as authentication failure");
		 }
	}
done:
	जर (authenticated == 1 && auth_activate_options(ssh, authopts) != 0) {
		debug_f("key options inconsistent with existing");
		authenticated = 0;
	}
	debug2_f("authenticated %d pkalg %s", authenticated, pkalg);

	sshbuf_free(b);
	sshbuf_free(keyblob);
	sshauthopt_free(authopts);
	sshkey_free(किल्ली);
	sshkey_free(hostkey);
	मुक्त(keystring);
	मुक्त(userstyle);
	मुक्त(pkalg);
	मुक्त(किल्ली_s);
	मुक्त(ca_s);
	मुक्त(sig);
	sshkey_sig_details_free(sig_details);
	परत authenticated;
}

स्थिर पूर्णांक
match_principals_file(संरचना passwd *pw, अक्षर *file,
    संरचना sshkey_cert *cert, संरचना sshauthopt **authoptsp)
{
	खाता *f;
	पूर्णांक r, success = 0;
	माप_प्रकार i;
	glob_t gl;
	संरचना sshauthopt *opts = रिक्त;

	जर (authoptsp != रिक्त)
		*authoptsp = रिक्त;

	temporarily_use_uid(pw);
	r = glob(file, 0, रिक्त, &gl);
	restore_uid();
	जर (r != 0) {
		जर (r != GLOB_NOMATCH) {
			logit_f("glob \"%s\" failed", file);
		}
		परत 0;
	} अन्यथा जर (gl.gl_pathc > पूर्णांक_उच्च) {
		fatal_f("too many glob results for \"%s\"", file);
	} अन्यथा जर (gl.gl_pathc > 1) {
		debug2_f("glob \"%s\" returned %zu matches", file,
		    gl.gl_pathc);
	}
	साठी (i = 0; !success && i < gl.gl_pathc; i++) {
		temporarily_use_uid(pw);
		debug("trying authorized principals file %s", file);
		जर ((f = auth_openprincipals(gl.gl_pathv[i], pw,
		    options.strict_modes)) == रिक्त) {
			restore_uid();
			सुरूठेवा;
		}
		success = auth_process_principals(f, gl.gl_pathv[i],
		    cert, &opts);
		ख_बंद(f);
		restore_uid();
		जर (!success) {
			sshauthopt_free(opts);
			opts = रिक्त;
		}
	}
	globfree(&gl);
	जर (success && authoptsp != रिक्त) {
		*authoptsp = opts;
		opts = रिक्त;
	}
	sshauthopt_free(opts);
	परत success;
}

/*
 * Checks whether principal is allowed in output of command.
 * returns 1 if the principal is allowed or 0 otherwise.
 */
स्थिर पूर्णांक
match_principals_command(संरचना passwd *user_pw, स्थिरांक संरचना sshkey *किल्ली,
    स्थिरांक अक्षर *conn_id, स्थिरांक अक्षर *rdomain, संरचना sshauthopt **authoptsp)
{
	संरचना passwd *runas_pw = रिक्त;
	स्थिरांक संरचना sshkey_cert *cert = किल्ली->cert;
	खाता *f = रिक्त;
	पूर्णांक r, ok, found_principal = 0;
	पूर्णांक i, ac = 0, uid_swapped = 0;
	pid_t pid;
	अक्षर *tmp, *username = रिक्त, *command = रिक्त, **av = रिक्त;
	अक्षर *ca_fp = रिक्त, *किल्ली_fp = रिक्त, *catext = रिक्त, *keytext = रिक्त;
	अक्षर serial_s[32], uidstr[32];
	शून्य (*osigchld)(पूर्णांक);

	जर (authoptsp != रिक्त)
		*authoptsp = रिक्त;
	जर (options.authorized_principals_command == रिक्त)
		परत 0;
	जर (options.authorized_principals_command_user == रिक्त) {
		error("No user for AuthorizedPrincipalsCommand specified, "
		    "skipping");
		परत 0;
	}

	/*
	 * NB. all returns later this function should go via "out" to
	 * ensure the original SIGCHLD handler is restored properly.
	 */
	osigchld = ssh_signal(SIGCHLD, संक_पूर्व);

	/* Prepare and verify the user for the command */
	username = percent_expand(options.authorized_principals_command_user,
	    "u", user_pw->pw_name, (अक्षर *)रिक्त);
	runas_pw = getpwnam(username);
	जर (runas_pw == रिक्त) {
		error("AuthorizedPrincipalsCommandUser \"%s\" not found: %s",
		    username, म_त्रुटि(त्रुटि_सं));
		जा out;
	}

	/* Turn the command into an argument vector */
	जर (argv_split(options.authorized_principals_command,
	    &ac, &av, 0) != 0) {
		error("AuthorizedPrincipalsCommand \"%s\" contains "
		    "invalid quotes", options.authorized_principals_command);
		जा out;
	}
	जर (ac == 0) {
		error("AuthorizedPrincipalsCommand \"%s\" yielded no arguments",
		    options.authorized_principals_command);
		जा out;
	}
	जर ((ca_fp = sshkey_fingerprint(cert->signature_किल्ली,
	    options.fingerprint_hash, SSH_FP_DEFAULT)) == रिक्त) {
		error_f("sshkey_fingerprint failed");
		जा out;
	}
	जर ((किल्ली_fp = sshkey_fingerprint(किल्ली,
	    options.fingerprint_hash, SSH_FP_DEFAULT)) == रिक्त) {
		error_f("sshkey_fingerprint failed");
		जा out;
	}
	जर ((r = sshkey_to_base64(cert->signature_किल्ली, &catext)) != 0) {
		error_fr(r, "sshkey_to_base64 failed");
		जा out;
	}
	जर ((r = sshkey_to_base64(किल्ली, &keytext)) != 0) {
		error_fr(r, "sshkey_to_base64 failed");
		जा out;
	}
	snprintf(serial_s, आकार(serial_s), "%llu",
	    (अचिन्हित दीर्घ दीर्घ)cert->serial);
	snprintf(uidstr, आकार(uidstr), "%llu",
	    (अचिन्हित दीर्घ दीर्घ)user_pw->pw_uid);
	साठी (i = 1; i < ac; i++) {
		tmp = percent_expand(av[i],
		    "C", conn_id,
		    "D", rdomain,
		    "U", uidstr,
		    "u", user_pw->pw_name,
		    "h", user_pw->pw_dir,
		    "t", sshkey_ssh_name(किल्ली),
		    "T", sshkey_ssh_name(cert->signature_किल्ली),
		    "f", किल्ली_fp,
		    "F", ca_fp,
		    "k", keytext,
		    "K", catext,
		    "i", cert->किल्ली_id,
		    "s", serial_s,
		    (अक्षर *)रिक्त);
		जर (tmp == रिक्त)
			fatal_f("percent_expand failed");
		मुक्त(av[i]);
		av[i] = tmp;
	}
	/* Prepare a printable command for logs, etc. */
	command = argv_assemble(ac, av);

	जर ((pid = subprocess("AuthorizedPrincipalsCommand", command,
	    ac, av, &f,
	    SSH_SUBPROCESS_STDOUT_CAPTURE|SSH_SUBPROCESS_STDERR_DISCARD,
	    runas_pw, temporarily_use_uid, restore_uid)) == 0)
		जा out;

	uid_swapped = 1;
	temporarily_use_uid(runas_pw);

	ok = auth_process_principals(f, "(command)", cert, authoptsp);

	ख_बंद(f);
	f = रिक्त;

	जर (exited_cleanly(pid, "AuthorizedPrincipalsCommand", command, 0) != 0)
		जा out;

	/* Read completed successfully */
	found_principal = ok;
 out:
	जर (f != रिक्त)
		ख_बंद(f);
	ssh_signal(SIGCHLD, osigchld);
	साठी (i = 0; i < ac; i++)
		मुक्त(av[i]);
	मुक्त(av);
	जर (uid_swapped)
		restore_uid();
	मुक्त(command);
	मुक्त(username);
	मुक्त(ca_fp);
	मुक्त(किल्ली_fp);
	मुक्त(catext);
	मुक्त(keytext);
	परत found_principal;
}

/* Authenticate a certificate key against TrustedUserCAKeys */
स्थिर पूर्णांक
user_cert_trusted_ca(संरचना passwd *pw, संरचना sshkey *किल्ली,
    स्थिरांक अक्षर *remote_ip, स्थिरांक अक्षर *remote_host,
    स्थिरांक अक्षर *conn_id, स्थिरांक अक्षर *rdomain, संरचना sshauthopt **authoptsp)
{
	अक्षर *ca_fp, *principals_file = रिक्त;
	स्थिरांक अक्षर *reason;
	संरचना sshauthopt *principals_opts = रिक्त, *cert_opts = रिक्त;
	संरचना sshauthopt *final_opts = रिक्त;
	पूर्णांक r, ret = 0, found_principal = 0, use_authorized_principals;

	जर (authoptsp != रिक्त)
		*authoptsp = रिक्त;

	जर (!sshkey_is_cert(किल्ली) || options.trusted_user_ca_किल्ल्या == रिक्त)
		परत 0;

	जर ((ca_fp = sshkey_fingerprint(किल्ली->cert->signature_किल्ली,
	    options.fingerprint_hash, SSH_FP_DEFAULT)) == रिक्त)
		परत 0;

	जर ((r = sshkey_in_file(किल्ली->cert->signature_किल्ली,
	    options.trusted_user_ca_किल्ल्या, 1, 0)) != 0) {
		debug2_fr(r, "CA %s %s is not listed in %s",
		    sshkey_type(किल्ली->cert->signature_किल्ली), ca_fp,
		    options.trusted_user_ca_किल्ल्या);
		जा out;
	}
	/*
	 * If AuthorizedPrincipals is in use, then compare the certificate
	 * principals against the names in that file rather than matching
	 * against the username.
	 */
	जर ((principals_file = authorized_principals_file(pw)) != रिक्त) {
		जर (match_principals_file(pw, principals_file,
		    किल्ली->cert, &principals_opts))
			found_principal = 1;
	}
	/* Try querying command if specified */
	जर (!found_principal && match_principals_command(pw, किल्ली,
	    conn_id, rdomain, &principals_opts))
		found_principal = 1;
	/* If principals file or command is specified, then require a match */
	use_authorized_principals = principals_file != रिक्त ||
	    options.authorized_principals_command != रिक्त;
	जर (!found_principal && use_authorized_principals) {
		reason = "Certificate does not contain an authorized principal";
		जा fail_reason;
	}
	जर (use_authorized_principals && principals_opts == रिक्त)
		fatal_f("internal error: missing principals_opts");
	जर (sshkey_cert_check_authority_now(किल्ली, 0, 0,
	    use_authorized_principals ? रिक्त : pw->pw_name, &reason) != 0)
		जा fail_reason;

	/* Check authority from options in key and from principals file/cmd */
	जर ((cert_opts = sshauthopt_from_cert(किल्ली)) == रिक्त) {
		reason = "Invalid certificate options";
		जा fail_reason;
	}
	जर (auth_authorise_keyopts(pw, cert_opts, 0,
	    remote_ip, remote_host, "cert") != 0) {
		reason = "Refused by certificate options";
		जा fail_reason;
	}
	जर (principals_opts == रिक्त) {
		final_opts = cert_opts;
		cert_opts = रिक्त;
	} अन्यथा {
		जर (auth_authorise_keyopts(pw, principals_opts, 0,
		    remote_ip, remote_host, "principals") != 0) {
			reason = "Refused by certificate principals options";
			जा fail_reason;
		}
		जर ((final_opts = sshauthopt_merge(principals_opts,
		    cert_opts, &reason)) == रिक्त) {
 fail_reason:
			error("Refusing certificate ID \"%s\" serial=%llu "
			    "signed by %s CA %s: %s", किल्ली->cert->किल्ली_id,
			    (अचिन्हित दीर्घ दीर्घ)किल्ली->cert->serial,
			    sshkey_type(किल्ली->cert->signature_किल्ली), ca_fp,
			    reason);
			auth_debug_add("Refused Certificate ID \"%s\" "
			    "serial=%llu: %s", किल्ली->cert->किल्ली_id,
			    (अचिन्हित दीर्घ दीर्घ)किल्ली->cert->serial, reason);
			जा out;
		}
	}

	/* Success */
	verbose("Accepted certificate ID \"%s\" (serial %llu) signed by "
	    "%s CA %s via %s", किल्ली->cert->किल्ली_id,
	    (अचिन्हित दीर्घ दीर्घ)किल्ली->cert->serial,
	    sshkey_type(किल्ली->cert->signature_किल्ली), ca_fp,
	    options.trusted_user_ca_किल्ल्या);
	जर (authoptsp != रिक्त) {
		*authoptsp = final_opts;
		final_opts = रिक्त;
	}
	ret = 1;
 out:
	sshauthopt_free(principals_opts);
	sshauthopt_free(cert_opts);
	sshauthopt_free(final_opts);
	मुक्त(principals_file);
	मुक्त(ca_fp);
	परत ret;
}

/*
 * Checks whether key is allowed in file.
 * returns 1 if the key is allowed or 0 otherwise.
 */
स्थिर पूर्णांक
user_किल्ली_allowed2(संरचना passwd *pw, संरचना sshkey *किल्ली,
    अक्षर *file, स्थिरांक अक्षर *remote_ip, स्थिरांक अक्षर *remote_host,
    संरचना sshauthopt **authoptsp)
{
	खाता *f;
	पूर्णांक found_किल्ली = 0;

	जर (authoptsp != रिक्त)
		*authoptsp = रिक्त;

	/* Temporarily use the user's uid. */
	temporarily_use_uid(pw);

	debug("trying public key file %s", file);
	जर ((f = auth_openkeyfile(file, pw, options.strict_modes)) != रिक्त) {
		found_किल्ली = auth_check_authkeys_file(pw, f, file,
		    किल्ली, remote_ip, remote_host, authoptsp);
		ख_बंद(f);
	}

	restore_uid();
	परत found_किल्ली;
}

/*
 * Checks whether key is allowed in output of command.
 * returns 1 if the key is allowed or 0 otherwise.
 */
स्थिर पूर्णांक
user_किल्ली_command_allowed2(संरचना passwd *user_pw, संरचना sshkey *किल्ली,
    स्थिरांक अक्षर *remote_ip, स्थिरांक अक्षर *remote_host,
    स्थिरांक अक्षर *conn_id, स्थिरांक अक्षर *rdomain, संरचना sshauthopt **authoptsp)
{
	संरचना passwd *runas_pw = रिक्त;
	खाता *f = रिक्त;
	पूर्णांक r, ok, found_किल्ली = 0;
	पूर्णांक i, uid_swapped = 0, ac = 0;
	pid_t pid;
	अक्षर *username = रिक्त, *किल्ली_fp = रिक्त, *keytext = रिक्त;
	अक्षर uidstr[32], *tmp, *command = रिक्त, **av = रिक्त;
	शून्य (*osigchld)(पूर्णांक);

	जर (authoptsp != रिक्त)
		*authoptsp = रिक्त;
	जर (options.authorized_किल्ल्या_command == रिक्त)
		परत 0;
	जर (options.authorized_किल्ल्या_command_user == रिक्त) {
		error("No user for AuthorizedKeysCommand specified, skipping");
		परत 0;
	}

	/*
	 * NB. all returns later this function should go via "out" to
	 * ensure the original SIGCHLD handler is restored properly.
	 */
	osigchld = ssh_signal(SIGCHLD, संक_पूर्व);

	/* Prepare and verify the user for the command */
	username = percent_expand(options.authorized_किल्ल्या_command_user,
	    "u", user_pw->pw_name, (अक्षर *)रिक्त);
	runas_pw = getpwnam(username);
	जर (runas_pw == रिक्त) {
		error("AuthorizedKeysCommandUser \"%s\" not found: %s",
		    username, म_त्रुटि(त्रुटि_सं));
		जा out;
	}

	/* Prepare AuthorizedKeysCommand */
	जर ((किल्ली_fp = sshkey_fingerprint(किल्ली, options.fingerprint_hash,
	    SSH_FP_DEFAULT)) == रिक्त) {
		error_f("sshkey_fingerprint failed");
		जा out;
	}
	जर ((r = sshkey_to_base64(किल्ली, &keytext)) != 0) {
		error_fr(r, "sshkey_to_base64 failed");
		जा out;
	}

	/* Turn the command into an argument vector */
	जर (argv_split(options.authorized_किल्ल्या_command, &ac, &av, 0) != 0) {
		error("AuthorizedKeysCommand \"%s\" contains invalid quotes",
		    options.authorized_किल्ल्या_command);
		जा out;
	}
	जर (ac == 0) {
		error("AuthorizedKeysCommand \"%s\" yielded no arguments",
		    options.authorized_किल्ल्या_command);
		जा out;
	}
	snprintf(uidstr, आकार(uidstr), "%llu",
	    (अचिन्हित दीर्घ दीर्घ)user_pw->pw_uid);
	साठी (i = 1; i < ac; i++) {
		tmp = percent_expand(av[i],
		    "C", conn_id,
		    "D", rdomain,
		    "U", uidstr,
		    "u", user_pw->pw_name,
		    "h", user_pw->pw_dir,
		    "t", sshkey_ssh_name(किल्ली),
		    "f", किल्ली_fp,
		    "k", keytext,
		    (अक्षर *)रिक्त);
		जर (tmp == रिक्त)
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
	जर (ac == 1) {
		av = xreallocarray(av, ac + 2, आकार(*av));
		av[1] = xstrdup(user_pw->pw_name);
		av[2] = रिक्त;
		/* Fix up command too, since it is used in log messages */
		मुक्त(command);
		xasprintf(&command, "%s %s", av[0], av[1]);
	}

	जर ((pid = subprocess("AuthorizedKeysCommand", command,
	    ac, av, &f,
	    SSH_SUBPROCESS_STDOUT_CAPTURE|SSH_SUBPROCESS_STDERR_DISCARD,
	    runas_pw, temporarily_use_uid, restore_uid)) == 0)
		जा out;

	uid_swapped = 1;
	temporarily_use_uid(runas_pw);

	ok = auth_check_authkeys_file(user_pw, f,
	    options.authorized_किल्ल्या_command, किल्ली, remote_ip,
	    remote_host, authoptsp);

	ख_बंद(f);
	f = रिक्त;

	जर (exited_cleanly(pid, "AuthorizedKeysCommand", command, 0) != 0)
		जा out;

	/* Read completed successfully */
	found_किल्ली = ok;
 out:
	जर (f != रिक्त)
		ख_बंद(f);
	ssh_signal(SIGCHLD, osigchld);
	साठी (i = 0; i < ac; i++)
		मुक्त(av[i]);
	मुक्त(av);
	जर (uid_swapped)
		restore_uid();
	मुक्त(command);
	मुक्त(username);
	मुक्त(किल्ली_fp);
	मुक्त(keytext);
	परत found_किल्ली;
}

/*
 * Check whether key authenticates and authorises the user.
 */
पूर्णांक
user_किल्ली_allowed(संरचना ssh *ssh, संरचना passwd *pw, संरचना sshkey *किल्ली,
    पूर्णांक auth_attempt, संरचना sshauthopt **authoptsp)
{
	u_int success = 0, i, j;
	अक्षर *file = रिक्त, *conn_id;
	संरचना sshauthopt *opts = रिक्त;
	स्थिरांक अक्षर *rdomain, *remote_ip, *remote_host;

	जर (authoptsp != रिक्त)
		*authoptsp = रिक्त;

	जर (auth_किल्ली_is_revoked(किल्ली))
		परत 0;
	जर (sshkey_is_cert(किल्ली) &&
	    auth_किल्ली_is_revoked(किल्ली->cert->signature_किल्ली))
		परत 0;

	जर ((rdomain = ssh_packet_rdomain_in(ssh)) == रिक्त)
		rdomain = "";
	remote_ip = ssh_remote_ipaddr(ssh);
	remote_host = auth_get_canonical_hostname(ssh, options.use_dns);
	xasprintf(&conn_id, "%s %d %s %d",
	    ssh_local_ipaddr(ssh), ssh_local_port(ssh),
	    remote_ip, ssh_remote_port(ssh));

	साठी (i = 0; !success && i < options.अंक_authkeys_files; i++) {
		पूर्णांक r;
		glob_t gl;

		जर (strcasecmp(options.authorized_किल्ल्या_files[i], "none") == 0)
			सुरूठेवा;
		file = expand_authorized_किल्ल्या(
		    options.authorized_किल्ल्या_files[i], pw);
		temporarily_use_uid(pw);
		r = glob(file, 0, रिक्त, &gl);
		restore_uid();
		जर (r != 0) {
			जर (r != GLOB_NOMATCH) {
				logit_f("glob \"%s\" failed", file);
			}
			मुक्त(file);
			file = रिक्त;
			सुरूठेवा;
		} अन्यथा जर (gl.gl_pathc > पूर्णांक_उच्च) {
			fatal_f("too many glob results for \"%s\"", file);
		} अन्यथा जर (gl.gl_pathc > 1) {
			debug2_f("glob \"%s\" returned %zu matches", file,
			    gl.gl_pathc);
		}
		साठी (j = 0; !success && j < gl.gl_pathc; j++) {
			success = user_किल्ली_allowed2(pw, किल्ली, gl.gl_pathv[j],
			    remote_ip, remote_host, &opts);
			जर (!success) {
				sshauthopt_free(opts);
				opts = रिक्त;
			}
		}
		मुक्त(file);
		file = रिक्त;
		globfree(&gl);
	}
	जर (success)
		जा out;

	जर ((success = user_cert_trusted_ca(pw, किल्ली, remote_ip, remote_host,
	    conn_id, rdomain, &opts)) != 0)
		जा out;
	sshauthopt_free(opts);
	opts = रिक्त;

	जर ((success = user_किल्ली_command_allowed2(pw, किल्ली, remote_ip,
	    remote_host, conn_id, rdomain, &opts)) != 0)
		जा out;
	sshauthopt_free(opts);
	opts = रिक्त;

 out:
	मुक्त(conn_id);
	जर (success && authoptsp != रिक्त) {
		*authoptsp = opts;
		opts = रिक्त;
	}
	sshauthopt_free(opts);
	परत success;
}

Authmethod method_pubkey = {
	&methodcfg_pubkey,
	userauth_pubkey,
};
