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

स्थिर वर्ण *
format_साँचो(अचर संरचना sshkey *साँचो)
{
	वर्ण *ret, *fp = sshkey_fingerprint(साँचो,
	    options.fingerprint_hash, SSH_FP_DEFAULT);

	xasprintf(&ret, "%s %s", sshkey_type(साँचो), fp);
	मुक्त(fp);
	फर्काऊ ret;
}

/*
 * Verify that the hostkey in a publickey-hostbound-v00@openssh.com userauth
 * request matches the hostkey that was negotiated during initial KEX.
 */
स्थिर शून्य
check_hostbound_hostkey(संरचना ssh *ssh)
{
	पूर्णाङ्क r;
	संरचना sshbuf *our_hostkey_blob, *their_hostkey_blob;

	यदि (ssh->kex->initial_hostkey == रिक्त)
		fatal_f("internal error: initial hostkey not recorded");
	यदि ((our_hostkey_blob = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	यदि ((r = sshpkt_getb_froms(ssh, &their_hostkey_blob)) != 0)
		fatal_fr(r, "parse hostkey");
	यदि ((r = sshkey_putb(ssh->kex->initial_hostkey, our_hostkey_blob)) != 0)
		fatal_fr(r, "serialise hostkey");
	यदि ((r = sshbuf_equals(our_hostkey_blob, their_hostkey_blob)) != 0)
		fatal_f("packet contained wrong host key");
	sshbuf_free(our_hostkey_blob);
	sshbuf_free(their_hostkey_blob);
}

स्थिर पूर्णाङ्क
userauth_pubkey(संरचना ssh *ssh, अचर वर्ण *method)
{
	Authctxt *authctxt = ssh->authctxt;
	संरचना passwd *pw = authctxt->pw;
	संरचना sshbuf *keyblob = रिक्त, *b = रिक्त;
	संरचना sshkey *साँचो = रिक्त, *hostkey = रिक्त;
	वर्ण *pkalg = रिक्त, *userstyle = रिक्त, *साँचो_s = रिक्त, *ca_s = रिक्त;
	वर्ण *keystring = रिक्त;
	u_char *sig = रिक्त, have_sig;
	माप_प्रकार slen;
	पूर्णाङ्क hostbound, r, pktype;
	पूर्णाङ्क req_presence = 0, req_verify = 0, authenticated = 0;
	संरचना sshauthopt *authopts = रिक्त;
	संरचना sshkey_sig_details *sig_details = रिक्त;

	hostbound = म_भेद(method, "publickey-hostbound-v00@openssh.com") == 0;

	यदि ((r = sshpkt_get_u8(ssh, &have_sig)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &pkalg, रिक्त)) != 0 ||
	    (r = sshpkt_getb_froms(ssh, &keyblob)) != 0)
		fatal_fr(r, "parse %s packet", method);

	/* hostbound auth includes the hostkey offered at initial KEX */
	यदि (hostbound)
		check_hostbound_hostkey(ssh); /* fatals on error */

	यदि (log_level_get() >= SYSLOG_LEVEL_DEBUG2) {
		यदि ((b = sshbuf_fromb(keyblob)) == रिक्त)
			fatal_f("sshbuf_fromb failed");
		यदि ((keystring = sshbuf_dtob64_string(b, 0)) == रिक्त)
			fatal_f("sshbuf_dtob64 failed");
		debug2_f("%s user %s %s public key %s %s",
		    authctxt->valid ? "valid" : "invalid", authctxt->user,
		    have_sig ? "attempting" : "querying", pkalg, keystring);
		sshbuf_free(b);
		b = रिक्त;
	}

	pktype = sshkey_type_from_name(pkalg);
	यदि (pktype == साँचो_UNSPEC) {
		/* this is perfectly legal */
		verbose_f("unsupported public key algorithm: %s", pkalg);
		गच्छ done;
	}
	यदि (match_pattern_list(pkalg, options.pubkey_accepted_algos, 0) != 1) {
		logit_f("signature algorithm %s not in "
		    "PubkeyAcceptedAlgorithms", pkalg);
		गच्छ done;
	}
	यदि ((b = sshbuf_fromb(keyblob)) == रिक्त)
		fatal_f("sshbuf_fromb failed");
	विकल्प ((r = sshkey_fromb_allowlist(b, &साँचो,
	    options.pubkey_accepted_algos, options.ca_sign_algorithms))) {
	पक्ष 0:
		/* ok */
		रोक;
	पक्ष SSH_ERR_साँचो_ALG_UNSUPPORTED:
		/* This shouldn't happen unless the client is being weird */
		logit_f("key algorithm differs from signature algorithm %s and "
		    "is not in PubkeyAcceptedAlgorithms", pkalg);
		गच्छ done;
	पक्ष SSH_ERR_SIGN_ALG_UNSUPPORTED:
		logit_fr(r, "certificate signature algorithm not in "
		    "CASignatureAlgorithm");
		गच्छ done;
	स्वभाव:
		error_fr(r, "parse key");
		गच्छ done;
	}
	sshbuf_free(b);
	b = रिक्त;

	/* USERAUTH_REQUEST signature type should match key's type */
	यदि (साँचो->type != pktype || (sshkey_type_plain(pktype) == साँचो_ECDSA &&
	    sshkey_ecdsa_nid_from_name(pkalg) != साँचो->ecdsa_nid)) {
		error_f("key type mismatch for decoded key "
		    "(received %s, expected %s)", sshkey_ssh_name(साँचो), pkalg);
		गच्छ done;
	}
	यदि (auth2_साँचो_already_used(authctxt, साँचो)) {
		logit("refusing previously-used %s key", sshkey_type(साँचो));
		गच्छ done;
	}
	यदि ((r = sshkey_check_rsa_length(साँचो,
	    options.required_rsa_size)) != 0) {
		logit_r(r, "refusing %s key", sshkey_type(साँचो));
		गच्छ done;
	}
	साँचो_s = format_साँचो(साँचो);
	यदि (sshkey_is_cert(साँचो))
		ca_s = format_साँचो(साँचो->cert->signature_साँचो);

	यदि (have_sig) {
		debug3_f("%s have %s signature for %s%s%s",
		    method, pkalg, साँचो_s,
		    ca_s == रिक्त ? "" : " CA ", ca_s == रिक्त ? "" : ca_s);
		यदि ((r = sshpkt_get_string(ssh, &sig, &slen)) != 0 ||
		    (r = sshpkt_get_end(ssh)) != 0)
			fatal_fr(r, "parse signature packet");
		यदि ((b = sshbuf_new()) == रिक्त)
			fatal_f("sshbuf_new failed");
		यदि ((r = sshbuf_put_stringb(b,
		    ssh->kex->session_id)) != 0)
			fatal_fr(r, "put session id");
		यदि (!authctxt->valid || authctxt->user == रिक्त) {
			debug2_f("disabled because of invalid user");
			गच्छ done;
		}
		/* reconstruct packet */
		xasprintf(&userstyle, "%s%s%s", authctxt->user,
		    authctxt->style ? ":" : "",
		    authctxt->style ? authctxt->style : "");
		यदि ((r = sshbuf_put_u8(b, SSH2_सन्देश_USERAUTH_REQUEST)) != 0 ||
		    (r = sshbuf_put_cstring(b, userstyle)) != 0 ||
		    (r = sshbuf_put_cstring(b, authctxt->service)) != 0 ||
		    (r = sshbuf_put_cstring(b, method)) != 0 ||
		    (r = sshbuf_put_u8(b, have_sig)) != 0 ||
		    (r = sshbuf_put_cstring(b, pkalg)) != 0 ||
		    (r = sshbuf_put_stringb(b, keyblob)) != 0)
			fatal_fr(r, "reconstruct %s packet", method);
		यदि (hostbound &&
		    (r = sshkey_puts(ssh->kex->initial_hostkey, b)) != 0)
			fatal_fr(r, "reconstruct %s packet", method);
#ifdef DEBUG_PK
		sshbuf_dump(b, मानक_त्रुटि);
#endif
		/* test for correct signature */
		authenticated = 0;
		यदि (mm_user_साँचो_allowed(ssh, pw, साँचो, 1, &authopts) &&
		    mm_sshkey_verify(साँचो, sig, slen,
		    sshbuf_ptr(b), sshbuf_len(b),
		    (ssh->compat & SSH_BUG_SIGTYPE) == 0 ? pkalg : रिक्त,
		    ssh->compat, &sig_details) == 0) {
			authenticated = 1;
		}
		यदि (authenticated == 1 && sig_details != रिक्त) {
			auth2_record_info(authctxt, "signature count = %u",
			    sig_details->sk_counter);
			debug_f("sk_counter = %u, sk_flags = 0x%02x",
			    sig_details->sk_counter, sig_details->sk_flags);
			req_presence = (options.pubkey_auth_options &
			    PUBKEYAUTH_TOUCH_REQUIRED) ||
			    !authopts->no_require_user_presence;
			यदि (req_presence && (sig_details->sk_flags &
			    SSH_SK_USER_PRESENCE_REQD) == 0) {
				error("public key %s signature for %s%s from "
				    "%.128s port %d rejected: user presence "
				    "(authenticator touch) requirement "
				    "not met ", साँचो_s,
				    authctxt->valid ? "" : "invalid user ",
				    authctxt->user, ssh_remote_ipaddr(ssh),
				    ssh_remote_port(ssh));
				authenticated = 0;
				गच्छ done;
			}
			req_verify = (options.pubkey_auth_options &
			    PUBKEYAUTH_VERIFY_REQUIRED) ||
			    authopts->require_verify;
			यदि (req_verify && (sig_details->sk_flags &
			    SSH_SK_USER_VERIFICATION_REQD) == 0) {
				error("public key %s signature for %s%s from "
				    "%.128s port %d rejected: user "
				    "verification requirement not met ", साँचो_s,
				    authctxt->valid ? "" : "invalid user ",
				    authctxt->user, ssh_remote_ipaddr(ssh),
				    ssh_remote_port(ssh));
				authenticated = 0;
				गच्छ done;
			}
		}
		auth2_record_साँचो(authctxt, authenticated, साँचो);
	} अन्यथा {
		debug_f("%s test pkalg %s pkblob %s%s%s", method, pkalg, साँचो_s,
		    ca_s == रिक्त ? "" : " CA ", ca_s == रिक्त ? "" : ca_s);

		यदि ((r = sshpkt_get_end(ssh)) != 0)
			fatal_fr(r, "parse packet");

		/* XXX fake reply and always send PK_OK ? */
		/*
		 * XXX this allows testing whether a user is allowed
		 * to login: if you happen to have a valid pubkey this
		 * message is sent. the message is NEVER sent at all
		 * if a user is not allowed to login. is this an
		 * issue? -markus
		 */
		यदि (authctxt->valid && authctxt->user != रिक्त &&
		    mm_user_साँचो_allowed(ssh, pw, साँचो, 0, रिक्त)) {
			यदि ((r = sshpkt_start(ssh, SSH2_सन्देश_USERAUTH_PK_OK))
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
			यदि (authctxt->pk_ok_failures++ < options.max_pubkey_ok)
				authctxt->auth_failure_already_counted = 1;
			debug3_f("pubkey test %d of %d%s",
			    authctxt->pk_ok_failures, options.max_pubkey_ok,
			    authctxt->auth_failure_already_counted ?
			    "" : ": treating as authentication failure");
		 }
	}
done:
	यदि (authenticated == 1 && auth_activate_options(ssh, authopts) != 0) {
		debug_f("key options inconsistent with existing");
		authenticated = 0;
	}
	debug2_f("authenticated %d pkalg %s", authenticated, pkalg);

	sshbuf_free(b);
	sshbuf_free(keyblob);
	sshauthopt_free(authopts);
	sshkey_free(साँचो);
	sshkey_free(hostkey);
	मुक्त(keystring);
	मुक्त(userstyle);
	मुक्त(pkalg);
	मुक्त(साँचो_s);
	मुक्त(ca_s);
	मुक्त(sig);
	sshkey_sig_details_free(sig_details);
	फर्काऊ authenticated;
}

स्थिर पूर्णाङ्क
match_principals_file(संरचना passwd *pw, वर्ण *file,
    संरचना sshkey_cert *cert, संरचना sshauthopt **authoptsp)
{
	खाता *f;
	पूर्णाङ्क r, success = 0;
	माप_प्रकार i;
	glob_t gl;
	संरचना sshauthopt *opts = रिक्त;

	यदि (authoptsp != रिक्त)
		*authoptsp = रिक्त;

	temporarily_use_uid(pw);
	r = glob(file, 0, रिक्त, &gl);
	restore_uid();
	यदि (r != 0) {
		यदि (r != GLOB_NOMATCH) {
			logit_f("glob \"%s\" failed", file);
		}
		फर्काऊ 0;
	} अन्यथा यदि (gl.gl_pathc > पूर्णांक_उच्च) {
		fatal_f("too many glob results for \"%s\"", file);
	} अन्यथा यदि (gl.gl_pathc > 1) {
		debug2_f("glob \"%s\" returned %zu matches", file,
		    gl.gl_pathc);
	}
	लागि (i = 0; !success && i < gl.gl_pathc; i++) {
		temporarily_use_uid(pw);
		debug("trying authorized principals file %s", file);
		यदि ((f = auth_openprincipals(gl.gl_pathv[i], pw,
		    options.strict_modes)) == रिक्त) {
			restore_uid();
			जारी;
		}
		success = auth_process_principals(f, gl.gl_pathv[i],
		    cert, &opts);
		ख_बंद(f);
		restore_uid();
		यदि (!success) {
			sshauthopt_free(opts);
			opts = रिक्त;
		}
	}
	globfree(&gl);
	यदि (success && authoptsp != रिक्त) {
		*authoptsp = opts;
		opts = रिक्त;
	}
	sshauthopt_free(opts);
	फर्काऊ success;
}

/*
 * Checks whether principal is allowed in output of command.
 * returns 1 if the principal is allowed or 0 otherwise.
 */
स्थिर पूर्णाङ्क
match_principals_command(संरचना passwd *user_pw, अचर संरचना sshkey *साँचो,
    अचर वर्ण *conn_id, अचर वर्ण *rdomain, संरचना sshauthopt **authoptsp)
{
	संरचना passwd *runas_pw = रिक्त;
	अचर संरचना sshkey_cert *cert = साँचो->cert;
	खाता *f = रिक्त;
	पूर्णाङ्क r, ok, found_principal = 0;
	पूर्णाङ्क i, ac = 0, uid_swapped = 0;
	pid_t pid;
	वर्ण *tmp, *username = रिक्त, *command = रिक्त, **av = रिक्त;
	वर्ण *ca_fp = रिक्त, *साँचो_fp = रिक्त, *catext = रिक्त, *keytext = रिक्त;
	वर्ण serial_s[32], uidstr[32];
	शून्य (*osigchld)(पूर्णाङ्क);

	यदि (authoptsp != रिक्त)
		*authoptsp = रिक्त;
	यदि (options.authorized_principals_command == रिक्त)
		फर्काऊ 0;
	यदि (options.authorized_principals_command_user == रिक्त) {
		error("No user for AuthorizedPrincipalsCommand specified, "
		    "skipping");
		फर्काऊ 0;
	}

	/*
	 * NB. all returns later this function should go via "out" to
	 * ensure the original SIGCHLD handler is restored properly.
	 */
	osigchld = ssh_signal(SIGCHLD, संक_पूर्व);

	/* Prepare and verify the user for the command */
	username = percent_expand(options.authorized_principals_command_user,
	    "u", user_pw->pw_name, (वर्ण *)रिक्त);
	runas_pw = getpwnam(username);
	यदि (runas_pw == रिक्त) {
		error("AuthorizedPrincipalsCommandUser \"%s\" not found: %s",
		    username, म_त्रुटि(त्रुटि_सं));
		गच्छ out;
	}

	/* Turn the command into an argument vector */
	यदि (argv_split(options.authorized_principals_command,
	    &ac, &av, 0) != 0) {
		error("AuthorizedPrincipalsCommand \"%s\" contains "
		    "invalid quotes", options.authorized_principals_command);
		गच्छ out;
	}
	यदि (ac == 0) {
		error("AuthorizedPrincipalsCommand \"%s\" yielded no arguments",
		    options.authorized_principals_command);
		गच्छ out;
	}
	यदि ((ca_fp = sshkey_fingerprint(cert->signature_साँचो,
	    options.fingerprint_hash, SSH_FP_DEFAULT)) == रिक्त) {
		error_f("sshkey_fingerprint failed");
		गच्छ out;
	}
	यदि ((साँचो_fp = sshkey_fingerprint(साँचो,
	    options.fingerprint_hash, SSH_FP_DEFAULT)) == रिक्त) {
		error_f("sshkey_fingerprint failed");
		गच्छ out;
	}
	यदि ((r = sshkey_to_base64(cert->signature_साँचो, &catext)) != 0) {
		error_fr(r, "sshkey_to_base64 failed");
		गच्छ out;
	}
	यदि ((r = sshkey_to_base64(साँचो, &keytext)) != 0) {
		error_fr(r, "sshkey_to_base64 failed");
		गच्छ out;
	}
	snprintf(serial_s, परिमाण(serial_s), "%llu",
	    (अचिन्हित दीर्घ दीर्घ)cert->serial);
	snprintf(uidstr, परिमाण(uidstr), "%llu",
	    (अचिन्हित दीर्घ दीर्घ)user_pw->pw_uid);
	लागि (i = 1; i < ac; i++) {
		tmp = percent_expand(av[i],
		    "C", conn_id,
		    "D", rdomain,
		    "U", uidstr,
		    "u", user_pw->pw_name,
		    "h", user_pw->pw_dir,
		    "t", sshkey_ssh_name(साँचो),
		    "T", sshkey_ssh_name(cert->signature_साँचो),
		    "f", साँचो_fp,
		    "F", ca_fp,
		    "k", keytext,
		    "K", catext,
		    "i", cert->साँचो_id,
		    "s", serial_s,
		    (वर्ण *)रिक्त);
		यदि (tmp == रिक्त)
			fatal_f("percent_expand failed");
		मुक्त(av[i]);
		av[i] = tmp;
	}
	/* Prepare a printable command for logs, etc. */
	command = argv_assemble(ac, av);

	यदि ((pid = subprocess("AuthorizedPrincipalsCommand", command,
	    ac, av, &f,
	    SSH_SUBPROCESS_STDOUT_CAPTURE|SSH_SUBPROCESS_STDERR_DISCARD,
	    runas_pw, temporarily_use_uid, restore_uid)) == 0)
		गच्छ out;

	uid_swapped = 1;
	temporarily_use_uid(runas_pw);

	ok = auth_process_principals(f, "(command)", cert, authoptsp);

	ख_बंद(f);
	f = रिक्त;

	यदि (exited_cleanly(pid, "AuthorizedPrincipalsCommand", command, 0) != 0)
		गच्छ out;

	/* Read completed successfully */
	found_principal = ok;
 out:
	यदि (f != रिक्त)
		ख_बंद(f);
	ssh_signal(SIGCHLD, osigchld);
	लागि (i = 0; i < ac; i++)
		मुक्त(av[i]);
	मुक्त(av);
	यदि (uid_swapped)
		restore_uid();
	मुक्त(command);
	मुक्त(username);
	मुक्त(ca_fp);
	मुक्त(साँचो_fp);
	मुक्त(catext);
	मुक्त(keytext);
	फर्काऊ found_principal;
}

/* Authenticate a certificate key against TrustedUserCAKeys */
स्थिर पूर्णाङ्क
user_cert_trusted_ca(संरचना passwd *pw, संरचना sshkey *साँचो,
    अचर वर्ण *remote_ip, अचर वर्ण *remote_host,
    अचर वर्ण *conn_id, अचर वर्ण *rdomain, संरचना sshauthopt **authoptsp)
{
	वर्ण *ca_fp, *principals_file = रिक्त;
	अचर वर्ण *reason;
	संरचना sshauthopt *principals_opts = रिक्त, *cert_opts = रिक्त;
	संरचना sshauthopt *final_opts = रिक्त;
	पूर्णाङ्क r, ret = 0, found_principal = 0, use_authorized_principals;

	यदि (authoptsp != रिक्त)
		*authoptsp = रिक्त;

	यदि (!sshkey_is_cert(साँचो) || options.trusted_user_ca_साँचोहरू == रिक्त)
		फर्काऊ 0;

	यदि ((ca_fp = sshkey_fingerprint(साँचो->cert->signature_साँचो,
	    options.fingerprint_hash, SSH_FP_DEFAULT)) == रिक्त)
		फर्काऊ 0;

	यदि ((r = sshkey_in_file(साँचो->cert->signature_साँचो,
	    options.trusted_user_ca_साँचोहरू, 1, 0)) != 0) {
		debug2_fr(r, "CA %s %s is not listed in %s",
		    sshkey_type(साँचो->cert->signature_साँचो), ca_fp,
		    options.trusted_user_ca_साँचोहरू);
		गच्छ out;
	}
	/*
	 * If AuthorizedPrincipals is in use, then compare the certificate
	 * principals against the names in that file rather than matching
	 * against the username.
	 */
	यदि ((principals_file = authorized_principals_file(pw)) != रिक्त) {
		यदि (match_principals_file(pw, principals_file,
		    साँचो->cert, &principals_opts))
			found_principal = 1;
	}
	/* Try querying command if specified */
	यदि (!found_principal && match_principals_command(pw, साँचो,
	    conn_id, rdomain, &principals_opts))
		found_principal = 1;
	/* If principals file or command is specified, then require a match */
	use_authorized_principals = principals_file != रिक्त ||
	    options.authorized_principals_command != रिक्त;
	यदि (!found_principal && use_authorized_principals) {
		reason = "Certificate does not contain an authorized principal";
		गच्छ fail_reason;
	}
	यदि (use_authorized_principals && principals_opts == रिक्त)
		fatal_f("internal error: missing principals_opts");
	यदि (sshkey_cert_check_authority_now(साँचो, 0, 0,
	    use_authorized_principals ? रिक्त : pw->pw_name, &reason) != 0)
		गच्छ fail_reason;

	/* Check authority from options in key and from principals file/cmd */
	यदि ((cert_opts = sshauthopt_from_cert(साँचो)) == रिक्त) {
		reason = "Invalid certificate options";
		गच्छ fail_reason;
	}
	यदि (auth_authorise_keyopts(pw, cert_opts, 0,
	    remote_ip, remote_host, "cert") != 0) {
		reason = "Refused by certificate options";
		गच्छ fail_reason;
	}
	यदि (principals_opts == रिक्त) {
		final_opts = cert_opts;
		cert_opts = रिक्त;
	} अन्यथा {
		यदि (auth_authorise_keyopts(pw, principals_opts, 0,
		    remote_ip, remote_host, "principals") != 0) {
			reason = "Refused by certificate principals options";
			गच्छ fail_reason;
		}
		यदि ((final_opts = sshauthopt_merge(principals_opts,
		    cert_opts, &reason)) == रिक्त) {
 fail_reason:
			error("Refusing certificate ID \"%s\" serial=%llu "
			    "signed by %s CA %s: %s", साँचो->cert->साँचो_id,
			    (अचिन्हित दीर्घ दीर्घ)साँचो->cert->serial,
			    sshkey_type(साँचो->cert->signature_साँचो), ca_fp,
			    reason);
			auth_debug_add("Refused Certificate ID \"%s\" "
			    "serial=%llu: %s", साँचो->cert->साँचो_id,
			    (अचिन्हित दीर्घ दीर्घ)साँचो->cert->serial, reason);
			गच्छ out;
		}
	}

	/* Success */
	verbose("Accepted certificate ID \"%s\" (serial %llu) signed by "
	    "%s CA %s via %s", साँचो->cert->साँचो_id,
	    (अचिन्हित दीर्घ दीर्घ)साँचो->cert->serial,
	    sshkey_type(साँचो->cert->signature_साँचो), ca_fp,
	    options.trusted_user_ca_साँचोहरू);
	यदि (authoptsp != रिक्त) {
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
	फर्काऊ ret;
}

/*
 * Checks whether key is allowed in file.
 * returns 1 if the key is allowed or 0 otherwise.
 */
स्थिर पूर्णाङ्क
user_साँचो_allowed2(संरचना passwd *pw, संरचना sshkey *साँचो,
    वर्ण *file, अचर वर्ण *remote_ip, अचर वर्ण *remote_host,
    संरचना sshauthopt **authoptsp)
{
	खाता *f;
	पूर्णाङ्क found_साँचो = 0;

	यदि (authoptsp != रिक्त)
		*authoptsp = रिक्त;

	/* Temporarily use the user's uid. */
	temporarily_use_uid(pw);

	debug("trying public key file %s", file);
	यदि ((f = auth_openkeyfile(file, pw, options.strict_modes)) != रिक्त) {
		found_साँचो = auth_check_authkeys_file(pw, f, file,
		    साँचो, remote_ip, remote_host, authoptsp);
		ख_बंद(f);
	}

	restore_uid();
	फर्काऊ found_साँचो;
}

/*
 * Checks whether key is allowed in output of command.
 * returns 1 if the key is allowed or 0 otherwise.
 */
स्थिर पूर्णाङ्क
user_साँचो_command_allowed2(संरचना passwd *user_pw, संरचना sshkey *साँचो,
    अचर वर्ण *remote_ip, अचर वर्ण *remote_host,
    अचर वर्ण *conn_id, अचर वर्ण *rdomain, संरचना sshauthopt **authoptsp)
{
	संरचना passwd *runas_pw = रिक्त;
	खाता *f = रिक्त;
	पूर्णाङ्क r, ok, found_साँचो = 0;
	पूर्णाङ्क i, uid_swapped = 0, ac = 0;
	pid_t pid;
	वर्ण *username = रिक्त, *साँचो_fp = रिक्त, *keytext = रिक्त;
	वर्ण uidstr[32], *tmp, *command = रिक्त, **av = रिक्त;
	शून्य (*osigchld)(पूर्णाङ्क);

	यदि (authoptsp != रिक्त)
		*authoptsp = रिक्त;
	यदि (options.authorized_साँचोहरू_command == रिक्त)
		फर्काऊ 0;
	यदि (options.authorized_साँचोहरू_command_user == रिक्त) {
		error("No user for AuthorizedKeysCommand specified, skipping");
		फर्काऊ 0;
	}

	/*
	 * NB. all returns later this function should go via "out" to
	 * ensure the original SIGCHLD handler is restored properly.
	 */
	osigchld = ssh_signal(SIGCHLD, संक_पूर्व);

	/* Prepare and verify the user for the command */
	username = percent_expand(options.authorized_साँचोहरू_command_user,
	    "u", user_pw->pw_name, (वर्ण *)रिक्त);
	runas_pw = getpwnam(username);
	यदि (runas_pw == रिक्त) {
		error("AuthorizedKeysCommandUser \"%s\" not found: %s",
		    username, म_त्रुटि(त्रुटि_सं));
		गच्छ out;
	}

	/* Prepare AuthorizedKeysCommand */
	यदि ((साँचो_fp = sshkey_fingerprint(साँचो, options.fingerprint_hash,
	    SSH_FP_DEFAULT)) == रिक्त) {
		error_f("sshkey_fingerprint failed");
		गच्छ out;
	}
	यदि ((r = sshkey_to_base64(साँचो, &keytext)) != 0) {
		error_fr(r, "sshkey_to_base64 failed");
		गच्छ out;
	}

	/* Turn the command into an argument vector */
	यदि (argv_split(options.authorized_साँचोहरू_command, &ac, &av, 0) != 0) {
		error("AuthorizedKeysCommand \"%s\" contains invalid quotes",
		    options.authorized_साँचोहरू_command);
		गच्छ out;
	}
	यदि (ac == 0) {
		error("AuthorizedKeysCommand \"%s\" yielded no arguments",
		    options.authorized_साँचोहरू_command);
		गच्छ out;
	}
	snprintf(uidstr, परिमाण(uidstr), "%llu",
	    (अचिन्हित दीर्घ दीर्घ)user_pw->pw_uid);
	लागि (i = 1; i < ac; i++) {
		tmp = percent_expand(av[i],
		    "C", conn_id,
		    "D", rdomain,
		    "U", uidstr,
		    "u", user_pw->pw_name,
		    "h", user_pw->pw_dir,
		    "t", sshkey_ssh_name(साँचो),
		    "f", साँचो_fp,
		    "k", keytext,
		    (वर्ण *)रिक्त);
		यदि (tmp == रिक्त)
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
	यदि (ac == 1) {
		av = xreallocarray(av, ac + 2, परिमाण(*av));
		av[1] = xstrdup(user_pw->pw_name);
		av[2] = रिक्त;
		/* Fix up command too, since it is used in log messages */
		मुक्त(command);
		xasprintf(&command, "%s %s", av[0], av[1]);
	}

	यदि ((pid = subprocess("AuthorizedKeysCommand", command,
	    ac, av, &f,
	    SSH_SUBPROCESS_STDOUT_CAPTURE|SSH_SUBPROCESS_STDERR_DISCARD,
	    runas_pw, temporarily_use_uid, restore_uid)) == 0)
		गच्छ out;

	uid_swapped = 1;
	temporarily_use_uid(runas_pw);

	ok = auth_check_authkeys_file(user_pw, f,
	    options.authorized_साँचोहरू_command, साँचो, remote_ip,
	    remote_host, authoptsp);

	ख_बंद(f);
	f = रिक्त;

	यदि (exited_cleanly(pid, "AuthorizedKeysCommand", command, 0) != 0)
		गच्छ out;

	/* Read completed successfully */
	found_साँचो = ok;
 out:
	यदि (f != रिक्त)
		ख_बंद(f);
	ssh_signal(SIGCHLD, osigchld);
	लागि (i = 0; i < ac; i++)
		मुक्त(av[i]);
	मुक्त(av);
	यदि (uid_swapped)
		restore_uid();
	मुक्त(command);
	मुक्त(username);
	मुक्त(साँचो_fp);
	मुक्त(keytext);
	फर्काऊ found_साँचो;
}

/*
 * Check whether key authenticates and authorises the user.
 */
पूर्णाङ्क
user_साँचो_allowed(संरचना ssh *ssh, संरचना passwd *pw, संरचना sshkey *साँचो,
    पूर्णाङ्क auth_attempt, संरचना sshauthopt **authoptsp)
{
	u_int success = 0, i, j;
	वर्ण *file = रिक्त, *conn_id;
	संरचना sshauthopt *opts = रिक्त;
	अचर वर्ण *rdomain, *remote_ip, *remote_host;

	यदि (authoptsp != रिक्त)
		*authoptsp = रिक्त;

	यदि (auth_साँचो_is_revoked(साँचो))
		फर्काऊ 0;
	यदि (sshkey_is_cert(साँचो) &&
	    auth_साँचो_is_revoked(साँचो->cert->signature_साँचो))
		फर्काऊ 0;

	यदि ((rdomain = ssh_packet_rdomain_in(ssh)) == रिक्त)
		rdomain = "";
	remote_ip = ssh_remote_ipaddr(ssh);
	remote_host = auth_get_canonical_hostname(ssh, options.use_dns);
	xasprintf(&conn_id, "%s %d %s %d",
	    ssh_local_ipaddr(ssh), ssh_local_port(ssh),
	    remote_ip, ssh_remote_port(ssh));

	लागि (i = 0; !success && i < options.अङ्क_authkeys_files; i++) {
		पूर्णाङ्क r;
		glob_t gl;

		यदि (strcasecmp(options.authorized_साँचोहरू_files[i], "none") == 0)
			जारी;
		file = expand_authorized_साँचोहरू(
		    options.authorized_साँचोहरू_files[i], pw);
		temporarily_use_uid(pw);
		r = glob(file, 0, रिक्त, &gl);
		restore_uid();
		यदि (r != 0) {
			यदि (r != GLOB_NOMATCH) {
				logit_f("glob \"%s\" failed", file);
			}
			मुक्त(file);
			file = रिक्त;
			जारी;
		} अन्यथा यदि (gl.gl_pathc > पूर्णांक_उच्च) {
			fatal_f("too many glob results for \"%s\"", file);
		} अन्यथा यदि (gl.gl_pathc > 1) {
			debug2_f("glob \"%s\" returned %zu matches", file,
			    gl.gl_pathc);
		}
		लागि (j = 0; !success && j < gl.gl_pathc; j++) {
			success = user_साँचो_allowed2(pw, साँचो, gl.gl_pathv[j],
			    remote_ip, remote_host, &opts);
			यदि (!success) {
				sshauthopt_free(opts);
				opts = रिक्त;
			}
		}
		मुक्त(file);
		file = रिक्त;
		globfree(&gl);
	}
	यदि (success)
		गच्छ out;

	यदि ((success = user_cert_trusted_ca(pw, साँचो, remote_ip, remote_host,
	    conn_id, rdomain, &opts)) != 0)
		गच्छ out;
	sshauthopt_free(opts);
	opts = रिक्त;

	यदि ((success = user_साँचो_command_allowed2(pw, साँचो, remote_ip,
	    remote_host, conn_id, rdomain, &opts)) != 0)
		गच्छ out;
	sshauthopt_free(opts);
	opts = रिक्त;

 out:
	मुक्त(conn_id);
	यदि (success && authoptsp != रिक्त) {
		*authoptsp = opts;
		opts = रिक्त;
	}
	sshauthopt_free(opts);
	फर्काऊ success;
}

Authmethod method_pubkey = {
	&methodcfg_pubkey,
	userauth_pubkey,
};
