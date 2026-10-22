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

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <sys/types.h>

#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <errno.h>
#অন্তর্ভাব <paths.h>
#অন্তর্ভাব <pwd.h>
#অন্তর্ভাব <glob.h>
#অন্তর্ভাব <signal.h>
#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <stdarg.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <time.h>
#অন্তর্ভাব <unistd.h>
#অন্তর্ভাব <limits.h>

#অন্তর্ভাব "xmalloc.h"
#অন্তর্ভাব "ssh.h"
#অন্তর্ভাব "ssh2.h"
#অন্তর্ভাব "packet.h"
#অন্তর্ভাব "kex.h"
#অন্তর্ভাব "sshbuf.h"
#অন্তর্ভাব "log.h"
#অন্তর্ভাব "misc.h"
#অন্তর্ভাব "servconf.h"
#অন্তর্ভাব "compat.h"
#অন্তর্ভাব "sshkey.h"
#অন্তর্ভাব "hostfile.h"
#অন্তর্ভাব "auth.h"
#অন্তর্ভাব "pathnames.h"
#অন্তর্ভাব "uidswap.h"
#অন্তর্ভাব "auth-options.h"
#অন্তর্ভাব "canohost.h"
#ifdef GSSAPI
#অন্তর্ভাব "ssh-gss.h"
#endif
#অন্তর্ভাব "monitor_wrap.h"
#অন্তর্ভাব "authfile.h"
#অন্তর্ভাব "match.h"
#অন্তর্ভাব "ssherr.h"
#অন্তর্ভাব "channels.h" /* XXX for session.h */
#অন্তর্ভাব "session.h" /* XXX for child_set_env(); refactor? */
#অন্তর্ভাব "sk-api.h"

/* import */
বাহ্য ServerOptions options;
বাহ্য সংরচনা authmethod_cfg methodcfg_pubkey;

স্থির বর্ণ *
format_চাবি(ধ্রুব সংরচনা sshkey *চাবি)
{
	বর্ণ *ret, *fp = sshkey_fingerprint(চাবি,
	    options.fingerprint_hash, SSH_FP_DEFAULT);

	xasprintf(&ret, "%s %s", sshkey_type(চাবি), fp);
	মুক্ত(fp);
	প্রত্যাগম ret;
}

/*
 * Verify that the hostkey in a publickey-hostbound-v00@openssh.com userauth
 * request matches the hostkey that was negotiated during initial KEX.
 */
স্থির শূন্য
check_hostbound_hostkey(সংরচনা ssh *ssh)
{
	পূর্ণাঙ্ক r;
	সংরচনা sshbuf *our_hostkey_blob, *their_hostkey_blob;

	যদি (ssh->kex->initial_hostkey == রিক্ত)
		fatal_f("internal error: initial hostkey not recorded");
	যদি ((our_hostkey_blob = sshbuf_new()) == রিক্ত)
		fatal_f("sshbuf_new failed");
	যদি ((r = sshpkt_getb_froms(ssh, &their_hostkey_blob)) != 0)
		fatal_fr(r, "parse hostkey");
	যদি ((r = sshkey_putb(ssh->kex->initial_hostkey, our_hostkey_blob)) != 0)
		fatal_fr(r, "serialise hostkey");
	যদি ((r = sshbuf_equals(our_hostkey_blob, their_hostkey_blob)) != 0)
		fatal_f("packet contained wrong host key");
	sshbuf_free(our_hostkey_blob);
	sshbuf_free(their_hostkey_blob);
}

স্থির পূর্ণাঙ্ক
userauth_pubkey(সংরচনা ssh *ssh, ধ্রুব বর্ণ *method)
{
	Authctxt *authctxt = ssh->authctxt;
	সংরচনা passwd *pw = authctxt->pw;
	সংরচনা sshbuf *keyblob = রিক্ত, *b = রিক্ত;
	সংরচনা sshkey *চাবি = রিক্ত, *hostkey = রিক্ত;
	বর্ণ *pkalg = রিক্ত, *userstyle = রিক্ত, *চাবি_s = রিক্ত, *ca_s = রিক্ত;
	বর্ণ *keystring = রিক্ত;
	u_char *sig = রিক্ত, have_sig;
	size_t slen;
	পূর্ণাঙ্ক hostbound, r, pktype;
	পূর্ণাঙ্ক req_presence = 0, req_verify = 0, authenticated = 0;
	সংরচনা sshauthopt *authopts = রিক্ত;
	সংরচনা sshkey_sig_details *sig_details = রিক্ত;

	hostbound = strcmp(method, "publickey-hostbound-v00@openssh.com") == 0;

	যদি ((r = sshpkt_get_u8(ssh, &have_sig)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &pkalg, রিক্ত)) != 0 ||
	    (r = sshpkt_getb_froms(ssh, &keyblob)) != 0)
		fatal_fr(r, "parse %s packet", method);

	/* hostbound auth includes the hostkey offered at initial KEX */
	যদি (hostbound)
		check_hostbound_hostkey(ssh); /* fatals on error */

	যদি (log_level_get() >= SYSLOG_LEVEL_DEBUG2) {
		যদি ((b = sshbuf_fromb(keyblob)) == রিক্ত)
			fatal_f("sshbuf_fromb failed");
		যদি ((keystring = sshbuf_dtob64_string(b, 0)) == রিক্ত)
			fatal_f("sshbuf_dtob64 failed");
		debug2_f("%s user %s %s public key %s %s",
		    authctxt->valid ? "valid" : "invalid", authctxt->user,
		    have_sig ? "attempting" : "querying", pkalg, keystring);
		sshbuf_free(b);
		b = রিক্ত;
	}

	pktype = sshkey_type_from_name(pkalg);
	যদি (pktype == চাবি_UNSPEC) {
		/* this is perfectly legal */
		verbose_f("unsupported public key algorithm: %s", pkalg);
		গচ্ছ done;
	}
	যদি (match_pattern_list(pkalg, options.pubkey_accepted_algos, 0) != 1) {
		logit_f("signature algorithm %s not in "
		    "PubkeyAcceptedAlgorithms", pkalg);
		গচ্ছ done;
	}
	যদি ((b = sshbuf_fromb(keyblob)) == রিক্ত)
		fatal_f("sshbuf_fromb failed");
	বিকল্প ((r = sshkey_fromb_allowlist(b, &চাবি,
	    options.pubkey_accepted_algos, options.ca_sign_algorithms))) {
	পক্ষ 0:
		/* ok */
		ভঙ্গ;
	পক্ষ SSH_ERR_চাবি_ALG_UNSUPPORTED:
		/* This shouldn't happen unless the client is being weird */
		logit_f("key algorithm differs from signature algorithm %s and "
		    "is not in PubkeyAcceptedAlgorithms", pkalg);
		গচ্ছ done;
	পক্ষ SSH_ERR_SIGN_ALG_UNSUPPORTED:
		logit_fr(r, "certificate signature algorithm not in "
		    "CASignatureAlgorithm");
		গচ্ছ done;
	স্বভাব:
		error_fr(r, "parse key");
		গচ্ছ done;
	}
	sshbuf_free(b);
	b = রিক্ত;

	/* USERAUTH_REQUEST signature type should match key's type */
	যদি (চাবি->type != pktype || (sshkey_type_plain(pktype) == চাবি_ECDSA &&
	    sshkey_ecdsa_nid_from_name(pkalg) != চাবি->ecdsa_nid)) {
		error_f("key type mismatch for decoded key "
		    "(received %s, expected %s)", sshkey_ssh_name(চাবি), pkalg);
		গচ্ছ done;
	}
	যদি (auth2_চাবি_already_used(authctxt, চাবি)) {
		logit("refusing previously-used %s key", sshkey_type(চাবি));
		গচ্ছ done;
	}
	যদি ((r = sshkey_check_rsa_length(চাবি,
	    options.required_rsa_size)) != 0) {
		logit_r(r, "refusing %s key", sshkey_type(চাবি));
		গচ্ছ done;
	}
	চাবি_s = format_চাবি(চাবি);
	যদি (sshkey_is_cert(চাবি))
		ca_s = format_চাবি(চাবি->cert->signature_চাবি);

	যদি (have_sig) {
		debug3_f("%s have %s signature for %s%s%s",
		    method, pkalg, চাবি_s,
		    ca_s == রিক্ত ? "" : " CA ", ca_s == রিক্ত ? "" : ca_s);
		যদি ((r = sshpkt_get_string(ssh, &sig, &slen)) != 0 ||
		    (r = sshpkt_get_end(ssh)) != 0)
			fatal_fr(r, "parse signature packet");
		যদি ((b = sshbuf_new()) == রিক্ত)
			fatal_f("sshbuf_new failed");
		যদি ((r = sshbuf_put_stringb(b,
		    ssh->kex->session_id)) != 0)
			fatal_fr(r, "put session id");
		যদি (!authctxt->valid || authctxt->user == রিক্ত) {
			debug2_f("disabled because of invalid user");
			গচ্ছ done;
		}
		/* reconstruct packet */
		xasprintf(&userstyle, "%s%s%s", authctxt->user,
		    authctxt->style ? ":" : "",
		    authctxt->style ? authctxt->style : "");
		যদি ((r = sshbuf_put_u8(b, SSH2_বার্তা_USERAUTH_REQUEST)) != 0 ||
		    (r = sshbuf_put_cstring(b, userstyle)) != 0 ||
		    (r = sshbuf_put_cstring(b, authctxt->service)) != 0 ||
		    (r = sshbuf_put_cstring(b, method)) != 0 ||
		    (r = sshbuf_put_u8(b, have_sig)) != 0 ||
		    (r = sshbuf_put_cstring(b, pkalg)) != 0 ||
		    (r = sshbuf_put_stringb(b, keyblob)) != 0)
			fatal_fr(r, "reconstruct %s packet", method);
		যদি (hostbound &&
		    (r = sshkey_puts(ssh->kex->initial_hostkey, b)) != 0)
			fatal_fr(r, "reconstruct %s packet", method);
#ifdef DEBUG_PK
		sshbuf_dump(b, stderr);
#endif
		/* test for correct signature */
		authenticated = 0;
		যদি (mm_user_চাবি_allowed(ssh, pw, চাবি, 1, &authopts) &&
		    mm_sshkey_verify(চাবি, sig, slen,
		    sshbuf_ptr(b), sshbuf_len(b),
		    (ssh->compat & SSH_BUG_SIGTYPE) == 0 ? pkalg : রিক্ত,
		    ssh->compat, &sig_details) == 0) {
			authenticated = 1;
		}
		যদি (authenticated == 1 && sig_details != রিক্ত) {
			auth2_record_info(authctxt, "signature count = %u",
			    sig_details->sk_counter);
			debug_f("sk_counter = %u, sk_flags = 0x%02x",
			    sig_details->sk_counter, sig_details->sk_flags);
			req_presence = (options.pubkey_auth_options &
			    PUBKEYAUTH_TOUCH_REQUIRED) ||
			    !authopts->no_require_user_presence;
			যদি (req_presence && (sig_details->sk_flags &
			    SSH_SK_USER_PRESENCE_REQD) == 0) {
				error("public key %s signature for %s%s from "
				    "%.128s port %d rejected: user presence "
				    "(authenticator touch) requirement "
				    "not met ", চাবি_s,
				    authctxt->valid ? "" : "invalid user ",
				    authctxt->user, ssh_remote_ipaddr(ssh),
				    ssh_remote_port(ssh));
				authenticated = 0;
				গচ্ছ done;
			}
			req_verify = (options.pubkey_auth_options &
			    PUBKEYAUTH_VERIFY_REQUIRED) ||
			    authopts->require_verify;
			যদি (req_verify && (sig_details->sk_flags &
			    SSH_SK_USER_VERIFICATION_REQD) == 0) {
				error("public key %s signature for %s%s from "
				    "%.128s port %d rejected: user "
				    "verification requirement not met ", চাবি_s,
				    authctxt->valid ? "" : "invalid user ",
				    authctxt->user, ssh_remote_ipaddr(ssh),
				    ssh_remote_port(ssh));
				authenticated = 0;
				গচ্ছ done;
			}
		}
		auth2_record_চাবি(authctxt, authenticated, চাবি);
	} অন্যথা {
		debug_f("%s test pkalg %s pkblob %s%s%s", method, pkalg, চাবি_s,
		    ca_s == রিক্ত ? "" : " CA ", ca_s == রিক্ত ? "" : ca_s);

		যদি ((r = sshpkt_get_end(ssh)) != 0)
			fatal_fr(r, "parse packet");

		/* XXX fake reply and always send PK_OK ? */
		/*
		 * XXX this allows testing whether a user is allowed
		 * to login: if you happen to have a valid pubkey this
		 * message is sent. the message is NEVER sent at all
		 * if a user is not allowed to login. is this an
		 * issue? -markus
		 */
		যদি (authctxt->valid && authctxt->user != রিক্ত &&
		    mm_user_চাবি_allowed(ssh, pw, চাবি, 0, রিক্ত)) {
			যদি ((r = sshpkt_start(ssh, SSH2_বার্তা_USERAUTH_PK_OK))
			    != 0 ||
			    (r = sshpkt_put_cstring(ssh, pkalg)) != 0 ||
			    (r = sshpkt_put_stringb(ssh, keyblob)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0 ||
			    (r = ssh_packet_write_wait(ssh)) != 0)
				fatal_fr(r, "send packet");
			authctxt->postponed = 1;
		} অন্যথা {
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
			যদি (authctxt->pk_ok_failures++ < options.max_pubkey_ok)
				authctxt->auth_failure_already_counted = 1;
			debug3_f("pubkey test %d of %d%s",
			    authctxt->pk_ok_failures, options.max_pubkey_ok,
			    authctxt->auth_failure_already_counted ?
			    "" : ": treating as authentication failure");
		 }
	}
done:
	যদি (authenticated == 1 && auth_activate_options(ssh, authopts) != 0) {
		debug_f("key options inconsistent with existing");
		authenticated = 0;
	}
	debug2_f("authenticated %d pkalg %s", authenticated, pkalg);

	sshbuf_free(b);
	sshbuf_free(keyblob);
	sshauthopt_free(authopts);
	sshkey_free(চাবি);
	sshkey_free(hostkey);
	মুক্ত(keystring);
	মুক্ত(userstyle);
	মুক্ত(pkalg);
	মুক্ত(চাবি_s);
	মুক্ত(ca_s);
	মুক্ত(sig);
	sshkey_sig_details_free(sig_details);
	প্রত্যাগম authenticated;
}

স্থির পূর্ণাঙ্ক
match_principals_file(সংরচনা passwd *pw, বর্ণ *file,
    সংরচনা sshkey_cert *cert, সংরচনা sshauthopt **authoptsp)
{
	FILE *f;
	পূর্ণাঙ্ক r, success = 0;
	size_t i;
	glob_t gl;
	সংরচনা sshauthopt *opts = রিক্ত;

	যদি (authoptsp != রিক্ত)
		*authoptsp = রিক্ত;

	temporarily_use_uid(pw);
	r = glob(file, 0, রিক্ত, &gl);
	restore_uid();
	যদি (r != 0) {
		যদি (r != GLOB_NOMATCH) {
			logit_f("glob \"%s\" failed", file);
		}
		প্রত্যাগম 0;
	} অন্যথা যদি (gl.gl_pathc > INT_MAX) {
		fatal_f("too many glob results for \"%s\"", file);
	} অন্যথা যদি (gl.gl_pathc > 1) {
		debug2_f("glob \"%s\" returned %zu matches", file,
		    gl.gl_pathc);
	}
	প্রতি (i = 0; !success && i < gl.gl_pathc; i++) {
		temporarily_use_uid(pw);
		debug("trying authorized principals file %s", file);
		যদি ((f = auth_openprincipals(gl.gl_pathv[i], pw,
		    options.strict_modes)) == রিক্ত) {
			restore_uid();
			অনুবর্ত;
		}
		success = auth_process_principals(f, gl.gl_pathv[i],
		    cert, &opts);
		fclose(f);
		restore_uid();
		যদি (!success) {
			sshauthopt_free(opts);
			opts = রিক্ত;
		}
	}
	globfree(&gl);
	যদি (success && authoptsp != রিক্ত) {
		*authoptsp = opts;
		opts = রিক্ত;
	}
	sshauthopt_free(opts);
	প্রত্যাগম success;
}

/*
 * Checks whether principal is allowed in output of command.
 * returns 1 if the principal is allowed or 0 otherwise.
 */
স্থির পূর্ণাঙ্ক
match_principals_command(সংরচনা passwd *user_pw, ধ্রুব সংরচনা sshkey *চাবি,
    ধ্রুব বর্ণ *conn_id, ধ্রুব বর্ণ *rdomain, সংরচনা sshauthopt **authoptsp)
{
	সংরচনা passwd *runas_pw = রিক্ত;
	ধ্রুব সংরচনা sshkey_cert *cert = চাবি->cert;
	FILE *f = রিক্ত;
	পূর্ণাঙ্ক r, ok, found_principal = 0;
	পূর্ণাঙ্ক i, ac = 0, uid_swapped = 0;
	pid_t pid;
	বর্ণ *tmp, *username = রিক্ত, *command = রিক্ত, **av = রিক্ত;
	বর্ণ *ca_fp = রিক্ত, *চাবি_fp = রিক্ত, *catext = রিক্ত, *keytext = রিক্ত;
	বর্ণ serial_s[32], uidstr[32];
	শূন্য (*osigchld)(পূর্ণাঙ্ক);

	যদি (authoptsp != রিক্ত)
		*authoptsp = রিক্ত;
	যদি (options.authorized_principals_command == রিক্ত)
		প্রত্যাগম 0;
	যদি (options.authorized_principals_command_user == রিক্ত) {
		error("No user for AuthorizedPrincipalsCommand specified, "
		    "skipping");
		প্রত্যাগম 0;
	}

	/*
	 * NB. all returns later this function should go via "out" to
	 * ensure the original SIGCHLD handler is restored properly.
	 */
	osigchld = ssh_signal(SIGCHLD, SIG_DFL);

	/* Prepare and verify the user for the command */
	username = percent_expand(options.authorized_principals_command_user,
	    "u", user_pw->pw_name, (বর্ণ *)রিক্ত);
	runas_pw = getpwnam(username);
	যদি (runas_pw == রিক্ত) {
		error("AuthorizedPrincipalsCommandUser \"%s\" not found: %s",
		    username, strerror(errno));
		গচ্ছ out;
	}

	/* Turn the command into an argument vector */
	যদি (argv_split(options.authorized_principals_command,
	    &ac, &av, 0) != 0) {
		error("AuthorizedPrincipalsCommand \"%s\" contains "
		    "invalid quotes", options.authorized_principals_command);
		গচ্ছ out;
	}
	যদি (ac == 0) {
		error("AuthorizedPrincipalsCommand \"%s\" yielded no arguments",
		    options.authorized_principals_command);
		গচ্ছ out;
	}
	যদি ((ca_fp = sshkey_fingerprint(cert->signature_চাবি,
	    options.fingerprint_hash, SSH_FP_DEFAULT)) == রিক্ত) {
		error_f("sshkey_fingerprint failed");
		গচ্ছ out;
	}
	যদি ((চাবি_fp = sshkey_fingerprint(চাবি,
	    options.fingerprint_hash, SSH_FP_DEFAULT)) == রিক্ত) {
		error_f("sshkey_fingerprint failed");
		গচ্ছ out;
	}
	যদি ((r = sshkey_to_base64(cert->signature_চাবি, &catext)) != 0) {
		error_fr(r, "sshkey_to_base64 failed");
		গচ্ছ out;
	}
	যদি ((r = sshkey_to_base64(চাবি, &keytext)) != 0) {
		error_fr(r, "sshkey_to_base64 failed");
		গচ্ছ out;
	}
	snprintf(serial_s, পরিমাণ(serial_s), "%llu",
	    (unsigned long long)cert->serial);
	snprintf(uidstr, পরিমাণ(uidstr), "%llu",
	    (unsigned long long)user_pw->pw_uid);
	প্রতি (i = 1; i < ac; i++) {
		tmp = percent_expand(av[i],
		    "C", conn_id,
		    "D", rdomain,
		    "U", uidstr,
		    "u", user_pw->pw_name,
		    "h", user_pw->pw_dir,
		    "t", sshkey_ssh_name(চাবি),
		    "T", sshkey_ssh_name(cert->signature_চাবি),
		    "f", চাবি_fp,
		    "F", ca_fp,
		    "k", keytext,
		    "K", catext,
		    "i", cert->চাবি_id,
		    "s", serial_s,
		    (বর্ণ *)রিক্ত);
		যদি (tmp == রিক্ত)
			fatal_f("percent_expand failed");
		মুক্ত(av[i]);
		av[i] = tmp;
	}
	/* Prepare a printable command for logs, etc. */
	command = argv_assemble(ac, av);

	যদি ((pid = subprocess("AuthorizedPrincipalsCommand", command,
	    ac, av, &f,
	    SSH_SUBPROCESS_STDOUT_CAPTURE|SSH_SUBPROCESS_STDERR_DISCARD,
	    runas_pw, temporarily_use_uid, restore_uid)) == 0)
		গচ্ছ out;

	uid_swapped = 1;
	temporarily_use_uid(runas_pw);

	ok = auth_process_principals(f, "(command)", cert, authoptsp);

	fclose(f);
	f = রিক্ত;

	যদি (exited_cleanly(pid, "AuthorizedPrincipalsCommand", command, 0) != 0)
		গচ্ছ out;

	/* Read completed successfully */
	found_principal = ok;
 out:
	যদি (f != রিক্ত)
		fclose(f);
	ssh_signal(SIGCHLD, osigchld);
	প্রতি (i = 0; i < ac; i++)
		মুক্ত(av[i]);
	মুক্ত(av);
	যদি (uid_swapped)
		restore_uid();
	মুক্ত(command);
	মুক্ত(username);
	মুক্ত(ca_fp);
	মুক্ত(চাবি_fp);
	মুক্ত(catext);
	মুক্ত(keytext);
	প্রত্যাগম found_principal;
}

/* Authenticate a certificate key against TrustedUserCAKeys */
স্থির পূর্ণাঙ্ক
user_cert_trusted_ca(সংরচনা passwd *pw, সংরচনা sshkey *চাবি,
    ধ্রুব বর্ণ *remote_ip, ধ্রুব বর্ণ *remote_host,
    ধ্রুব বর্ণ *conn_id, ধ্রুব বর্ণ *rdomain, সংরচনা sshauthopt **authoptsp)
{
	বর্ণ *ca_fp, *principals_file = রিক্ত;
	ধ্রুব বর্ণ *reason;
	সংরচনা sshauthopt *principals_opts = রিক্ত, *cert_opts = রিক্ত;
	সংরচনা sshauthopt *final_opts = রিক্ত;
	পূর্ণাঙ্ক r, ret = 0, found_principal = 0, use_authorized_principals;

	যদি (authoptsp != রিক্ত)
		*authoptsp = রিক্ত;

	যদি (!sshkey_is_cert(চাবি) || options.trusted_user_ca_চাবিগুলি == রিক্ত)
		প্রত্যাগম 0;

	যদি ((ca_fp = sshkey_fingerprint(চাবি->cert->signature_চাবি,
	    options.fingerprint_hash, SSH_FP_DEFAULT)) == রিক্ত)
		প্রত্যাগম 0;

	যদি ((r = sshkey_in_file(চাবি->cert->signature_চাবি,
	    options.trusted_user_ca_চাবিগুলি, 1, 0)) != 0) {
		debug2_fr(r, "CA %s %s is not listed in %s",
		    sshkey_type(চাবি->cert->signature_চাবি), ca_fp,
		    options.trusted_user_ca_চাবিগুলি);
		গচ্ছ out;
	}
	/*
	 * If AuthorizedPrincipals is in use, then compare the certificate
	 * principals against the names in that file rather than matching
	 * against the username.
	 */
	যদি ((principals_file = authorized_principals_file(pw)) != রিক্ত) {
		যদি (match_principals_file(pw, principals_file,
		    চাবি->cert, &principals_opts))
			found_principal = 1;
	}
	/* Try querying command if specified */
	যদি (!found_principal && match_principals_command(pw, চাবি,
	    conn_id, rdomain, &principals_opts))
		found_principal = 1;
	/* If principals file or command is specified, then require a match */
	use_authorized_principals = principals_file != রিক্ত ||
	    options.authorized_principals_command != রিক্ত;
	যদি (!found_principal && use_authorized_principals) {
		reason = "Certificate does not contain an authorized principal";
		গচ্ছ fail_reason;
	}
	যদি (use_authorized_principals && principals_opts == রিক্ত)
		fatal_f("internal error: missing principals_opts");
	যদি (sshkey_cert_check_authority_now(চাবি, 0, 0,
	    use_authorized_principals ? রিক্ত : pw->pw_name, &reason) != 0)
		গচ্ছ fail_reason;

	/* Check authority from options in key and from principals file/cmd */
	যদি ((cert_opts = sshauthopt_from_cert(চাবি)) == রিক্ত) {
		reason = "Invalid certificate options";
		গচ্ছ fail_reason;
	}
	যদি (auth_authorise_keyopts(pw, cert_opts, 0,
	    remote_ip, remote_host, "cert") != 0) {
		reason = "Refused by certificate options";
		গচ্ছ fail_reason;
	}
	যদি (principals_opts == রিক্ত) {
		final_opts = cert_opts;
		cert_opts = রিক্ত;
	} অন্যথা {
		যদি (auth_authorise_keyopts(pw, principals_opts, 0,
		    remote_ip, remote_host, "principals") != 0) {
			reason = "Refused by certificate principals options";
			গচ্ছ fail_reason;
		}
		যদি ((final_opts = sshauthopt_merge(principals_opts,
		    cert_opts, &reason)) == রিক্ত) {
 fail_reason:
			error("Refusing certificate ID \"%s\" serial=%llu "
			    "signed by %s CA %s: %s", চাবি->cert->চাবি_id,
			    (unsigned long long)চাবি->cert->serial,
			    sshkey_type(চাবি->cert->signature_চাবি), ca_fp,
			    reason);
			auth_debug_add("Refused Certificate ID \"%s\" "
			    "serial=%llu: %s", চাবি->cert->চাবি_id,
			    (unsigned long long)চাবি->cert->serial, reason);
			গচ্ছ out;
		}
	}

	/* Success */
	verbose("Accepted certificate ID \"%s\" (serial %llu) signed by "
	    "%s CA %s via %s", চাবি->cert->চাবি_id,
	    (unsigned long long)চাবি->cert->serial,
	    sshkey_type(চাবি->cert->signature_চাবি), ca_fp,
	    options.trusted_user_ca_চাবিগুলি);
	যদি (authoptsp != রিক্ত) {
		*authoptsp = final_opts;
		final_opts = রিক্ত;
	}
	ret = 1;
 out:
	sshauthopt_free(principals_opts);
	sshauthopt_free(cert_opts);
	sshauthopt_free(final_opts);
	মুক্ত(principals_file);
	মুক্ত(ca_fp);
	প্রত্যাগম ret;
}

/*
 * Checks whether key is allowed in file.
 * returns 1 if the key is allowed or 0 otherwise.
 */
স্থির পূর্ণাঙ্ক
user_চাবি_allowed2(সংরচনা passwd *pw, সংরচনা sshkey *চাবি,
    বর্ণ *file, ধ্রুব বর্ণ *remote_ip, ধ্রুব বর্ণ *remote_host,
    সংরচনা sshauthopt **authoptsp)
{
	FILE *f;
	পূর্ণাঙ্ক found_চাবি = 0;

	যদি (authoptsp != রিক্ত)
		*authoptsp = রিক্ত;

	/* Temporarily use the user's uid. */
	temporarily_use_uid(pw);

	debug("trying public key file %s", file);
	যদি ((f = auth_openkeyfile(file, pw, options.strict_modes)) != রিক্ত) {
		found_চাবি = auth_check_authkeys_file(pw, f, file,
		    চাবি, remote_ip, remote_host, authoptsp);
		fclose(f);
	}

	restore_uid();
	প্রত্যাগম found_চাবি;
}

/*
 * Checks whether key is allowed in output of command.
 * returns 1 if the key is allowed or 0 otherwise.
 */
স্থির পূর্ণাঙ্ক
user_চাবি_command_allowed2(সংরচনা passwd *user_pw, সংরচনা sshkey *চাবি,
    ধ্রুব বর্ণ *remote_ip, ধ্রুব বর্ণ *remote_host,
    ধ্রুব বর্ণ *conn_id, ধ্রুব বর্ণ *rdomain, সংরচনা sshauthopt **authoptsp)
{
	সংরচনা passwd *runas_pw = রিক্ত;
	FILE *f = রিক্ত;
	পূর্ণাঙ্ক r, ok, found_চাবি = 0;
	পূর্ণাঙ্ক i, uid_swapped = 0, ac = 0;
	pid_t pid;
	বর্ণ *username = রিক্ত, *চাবি_fp = রিক্ত, *keytext = রিক্ত;
	বর্ণ uidstr[32], *tmp, *command = রিক্ত, **av = রিক্ত;
	শূন্য (*osigchld)(পূর্ণাঙ্ক);

	যদি (authoptsp != রিক্ত)
		*authoptsp = রিক্ত;
	যদি (options.authorized_চাবিগুলি_command == রিক্ত)
		প্রত্যাগম 0;
	যদি (options.authorized_চাবিগুলি_command_user == রিক্ত) {
		error("No user for AuthorizedKeysCommand specified, skipping");
		প্রত্যাগম 0;
	}

	/*
	 * NB. all returns later this function should go via "out" to
	 * ensure the original SIGCHLD handler is restored properly.
	 */
	osigchld = ssh_signal(SIGCHLD, SIG_DFL);

	/* Prepare and verify the user for the command */
	username = percent_expand(options.authorized_চাবিগুলি_command_user,
	    "u", user_pw->pw_name, (বর্ণ *)রিক্ত);
	runas_pw = getpwnam(username);
	যদি (runas_pw == রিক্ত) {
		error("AuthorizedKeysCommandUser \"%s\" not found: %s",
		    username, strerror(errno));
		গচ্ছ out;
	}

	/* Prepare AuthorizedKeysCommand */
	যদি ((চাবি_fp = sshkey_fingerprint(চাবি, options.fingerprint_hash,
	    SSH_FP_DEFAULT)) == রিক্ত) {
		error_f("sshkey_fingerprint failed");
		গচ্ছ out;
	}
	যদি ((r = sshkey_to_base64(চাবি, &keytext)) != 0) {
		error_fr(r, "sshkey_to_base64 failed");
		গচ্ছ out;
	}

	/* Turn the command into an argument vector */
	যদি (argv_split(options.authorized_চাবিগুলি_command, &ac, &av, 0) != 0) {
		error("AuthorizedKeysCommand \"%s\" contains invalid quotes",
		    options.authorized_চাবিগুলি_command);
		গচ্ছ out;
	}
	যদি (ac == 0) {
		error("AuthorizedKeysCommand \"%s\" yielded no arguments",
		    options.authorized_চাবিগুলি_command);
		গচ্ছ out;
	}
	snprintf(uidstr, পরিমাণ(uidstr), "%llu",
	    (unsigned long long)user_pw->pw_uid);
	প্রতি (i = 1; i < ac; i++) {
		tmp = percent_expand(av[i],
		    "C", conn_id,
		    "D", rdomain,
		    "U", uidstr,
		    "u", user_pw->pw_name,
		    "h", user_pw->pw_dir,
		    "t", sshkey_ssh_name(চাবি),
		    "f", চাবি_fp,
		    "k", keytext,
		    (বর্ণ *)রিক্ত);
		যদি (tmp == রিক্ত)
			fatal_f("percent_expand failed");
		মুক্ত(av[i]);
		av[i] = tmp;
	}
	/* Prepare a printable command for logs, etc. */
	command = argv_assemble(ac, av);

	/*
	 * If AuthorizedKeysCommand was run without arguments
	 * then fall back to the old behaviour of passing the
	 * target username as a single argument.
	 */
	যদি (ac == 1) {
		av = xreallocarray(av, ac + 2, পরিমাণ(*av));
		av[1] = xstrdup(user_pw->pw_name);
		av[2] = রিক্ত;
		/* Fix up command too, since it is used in log messages */
		মুক্ত(command);
		xasprintf(&command, "%s %s", av[0], av[1]);
	}

	যদি ((pid = subprocess("AuthorizedKeysCommand", command,
	    ac, av, &f,
	    SSH_SUBPROCESS_STDOUT_CAPTURE|SSH_SUBPROCESS_STDERR_DISCARD,
	    runas_pw, temporarily_use_uid, restore_uid)) == 0)
		গচ্ছ out;

	uid_swapped = 1;
	temporarily_use_uid(runas_pw);

	ok = auth_check_authkeys_file(user_pw, f,
	    options.authorized_চাবিগুলি_command, চাবি, remote_ip,
	    remote_host, authoptsp);

	fclose(f);
	f = রিক্ত;

	যদি (exited_cleanly(pid, "AuthorizedKeysCommand", command, 0) != 0)
		গচ্ছ out;

	/* Read completed successfully */
	found_চাবি = ok;
 out:
	যদি (f != রিক্ত)
		fclose(f);
	ssh_signal(SIGCHLD, osigchld);
	প্রতি (i = 0; i < ac; i++)
		মুক্ত(av[i]);
	মুক্ত(av);
	যদি (uid_swapped)
		restore_uid();
	মুক্ত(command);
	মুক্ত(username);
	মুক্ত(চাবি_fp);
	মুক্ত(keytext);
	প্রত্যাগম found_চাবি;
}

/*
 * Check whether key authenticates and authorises the user.
 */
পূর্ণাঙ্ক
user_চাবি_allowed(সংরচনা ssh *ssh, সংরচনা passwd *pw, সংরচনা sshkey *চাবি,
    পূর্ণাঙ্ক auth_attempt, সংরচনা sshauthopt **authoptsp)
{
	u_int success = 0, i, j;
	বর্ণ *file = রিক্ত, *conn_id;
	সংরচনা sshauthopt *opts = রিক্ত;
	ধ্রুব বর্ণ *rdomain, *remote_ip, *remote_host;

	যদি (authoptsp != রিক্ত)
		*authoptsp = রিক্ত;

	যদি (auth_চাবি_is_revoked(চাবি))
		প্রত্যাগম 0;
	যদি (sshkey_is_cert(চাবি) &&
	    auth_চাবি_is_revoked(চাবি->cert->signature_চাবি))
		প্রত্যাগম 0;

	যদি ((rdomain = ssh_packet_rdomain_in(ssh)) == রিক্ত)
		rdomain = "";
	remote_ip = ssh_remote_ipaddr(ssh);
	remote_host = auth_get_canonical_hostname(ssh, options.use_dns);
	xasprintf(&conn_id, "%s %d %s %d",
	    ssh_local_ipaddr(ssh), ssh_local_port(ssh),
	    remote_ip, ssh_remote_port(ssh));

	প্রতি (i = 0; !success && i < options.অঙ্ক_authkeys_files; i++) {
		পূর্ণাঙ্ক r;
		glob_t gl;

		যদি (strcasecmp(options.authorized_চাবিগুলি_files[i], "none") == 0)
			অনুবর্ত;
		file = expand_authorized_চাবিগুলি(
		    options.authorized_চাবিগুলি_files[i], pw);
		temporarily_use_uid(pw);
		r = glob(file, 0, রিক্ত, &gl);
		restore_uid();
		যদি (r != 0) {
			যদি (r != GLOB_NOMATCH) {
				logit_f("glob \"%s\" failed", file);
			}
			মুক্ত(file);
			file = রিক্ত;
			অনুবর্ত;
		} অন্যথা যদি (gl.gl_pathc > INT_MAX) {
			fatal_f("too many glob results for \"%s\"", file);
		} অন্যথা যদি (gl.gl_pathc > 1) {
			debug2_f("glob \"%s\" returned %zu matches", file,
			    gl.gl_pathc);
		}
		প্রতি (j = 0; !success && j < gl.gl_pathc; j++) {
			success = user_চাবি_allowed2(pw, চাবি, gl.gl_pathv[j],
			    remote_ip, remote_host, &opts);
			যদি (!success) {
				sshauthopt_free(opts);
				opts = রিক্ত;
			}
		}
		মুক্ত(file);
		file = রিক্ত;
		globfree(&gl);
	}
	যদি (success)
		গচ্ছ out;

	যদি ((success = user_cert_trusted_ca(pw, চাবি, remote_ip, remote_host,
	    conn_id, rdomain, &opts)) != 0)
		গচ্ছ out;
	sshauthopt_free(opts);
	opts = রিক্ত;

	যদি ((success = user_চাবি_command_allowed2(pw, চাবি, remote_ip,
	    remote_host, conn_id, rdomain, &opts)) != 0)
		গচ্ছ out;
	sshauthopt_free(opts);
	opts = রিক্ত;

 out:
	মুক্ত(conn_id);
	যদি (success && authoptsp != রিক্ত) {
		*authoptsp = opts;
		opts = রিক্ত;
	}
	sshauthopt_free(opts);
	প্রত্যাগম success;
}

Authmethod method_pubkey = {
	&methodcfg_pubkey,
	userauth_pubkey,
};
