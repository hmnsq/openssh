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

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>

#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <errno.h>
#അന്തര്ഭാവ <paths.h>
#അന്തര്ഭാവ <pwd.h>
#അന്തര്ഭാവ <glob.h>
#അന്തര്ഭാവ <signal.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <stdarg.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <time.h>
#അന്തര്ഭാവ <unistd.h>
#അന്തര്ഭാവ <limits.h>

#അന്തര്ഭാവ "xmalloc.h"
#അന്തര്ഭാവ "ssh.h"
#അന്തര്ഭാവ "ssh2.h"
#അന്തര്ഭാവ "packet.h"
#അന്തര്ഭാവ "kex.h"
#അന്തര്ഭാവ "sshbuf.h"
#അന്തര്ഭാവ "log.h"
#അന്തര്ഭാവ "misc.h"
#അന്തര്ഭാവ "servconf.h"
#അന്തര്ഭാവ "compat.h"
#അന്തര്ഭാവ "sshkey.h"
#അന്തര്ഭാവ "hostfile.h"
#അന്തര്ഭാവ "auth.h"
#അന്തര്ഭാവ "pathnames.h"
#അന്തര്ഭാവ "uidswap.h"
#അന്തര്ഭാവ "auth-options.h"
#അന്തര്ഭാവ "canohost.h"
#ifdef GSSAPI
#അന്തര്ഭാവ "ssh-gss.h"
#endif
#അന്തര്ഭാവ "monitor_wrap.h"
#അന്തര്ഭാവ "authfile.h"
#അന്തര്ഭാവ "match.h"
#അന്തര്ഭാവ "ssherr.h"
#അന്തര്ഭാവ "channels.h" /* XXX for session.h */
#അന്തര്ഭാവ "session.h" /* XXX for child_set_env(); refactor? */
#അന്തര്ഭാവ "sk-api.h"

/* import */
ബാഹ്യ ServerOptions options;
ബാഹ്യ ഘടന authmethod_cfg methodcfg_pubkey;

സ്ഥിതം അക്ഷരം *
format_താക്കോൽ(സ്ഥിരം ഘടന sshkey *താക്കോൽ)
{
	അക്ഷരം *ret, *fp = sshkey_fingerprint(താക്കോൽ,
	    options.fingerprint_hash, SSH_FP_DEFAULT);

	xasprintf(&ret, "%s %s", sshkey_type(താക്കോൽ), fp);
	സ്വതന്ത്രം(fp);
	തിരികെ ret;
}

/*
 * Verify that the hostkey in a publickey-hostbound-v00@openssh.com userauth
 * request matches the hostkey that was negotiated during initial KEX.
 */
സ്ഥിതം ശൂന്യം
check_hostbound_hostkey(ഘടന ssh *ssh)
{
	പൂർണ്ണസംഖ്യ r;
	ഘടന sshbuf *our_hostkey_blob, *their_hostkey_blob;

	എങ്കിൽ (ssh->kex->initial_hostkey == ശൂന്യ)
		fatal_f("internal error: initial hostkey not recorded");
	എങ്കിൽ ((our_hostkey_blob = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new failed");
	എങ്കിൽ ((r = sshpkt_getb_froms(ssh, &their_hostkey_blob)) != 0)
		fatal_fr(r, "parse hostkey");
	എങ്കിൽ ((r = sshkey_putb(ssh->kex->initial_hostkey, our_hostkey_blob)) != 0)
		fatal_fr(r, "serialise hostkey");
	എങ്കിൽ ((r = sshbuf_equals(our_hostkey_blob, their_hostkey_blob)) != 0)
		fatal_f("packet contained wrong host key");
	sshbuf_free(our_hostkey_blob);
	sshbuf_free(their_hostkey_blob);
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
userauth_pubkey(ഘടന ssh *ssh, സ്ഥിരം അക്ഷരം *method)
{
	Authctxt *authctxt = ssh->authctxt;
	ഘടന passwd *pw = authctxt->pw;
	ഘടന sshbuf *keyblob = ശൂന്യ, *b = ശൂന്യ;
	ഘടന sshkey *താക്കോൽ = ശൂന്യ, *hostkey = ശൂന്യ;
	അക്ഷരം *pkalg = ശൂന്യ, *userstyle = ശൂന്യ, *താക്കോൽ_s = ശൂന്യ, *ca_s = ശൂന്യ;
	അക്ഷരം *keystring = ശൂന്യ;
	u_char *sig = ശൂന്യ, have_sig;
	size_t slen;
	പൂർണ്ണസംഖ്യ hostbound, r, pktype;
	പൂർണ്ണസംഖ്യ req_presence = 0, req_verify = 0, authenticated = 0;
	ഘടന sshauthopt *authopts = ശൂന്യ;
	ഘടന sshkey_sig_details *sig_details = ശൂന്യ;

	hostbound = strcmp(method, "publickey-hostbound-v00@openssh.com") == 0;

	എങ്കിൽ ((r = sshpkt_get_u8(ssh, &have_sig)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &pkalg, ശൂന്യ)) != 0 ||
	    (r = sshpkt_getb_froms(ssh, &keyblob)) != 0)
		fatal_fr(r, "parse %s packet", method);

	/* hostbound auth includes the hostkey offered at initial KEX */
	എങ്കിൽ (hostbound)
		check_hostbound_hostkey(ssh); /* fatals on error */

	എങ്കിൽ (log_level_get() >= SYSLOG_LEVEL_DEBUG2) {
		എങ്കിൽ ((b = sshbuf_fromb(keyblob)) == ശൂന്യ)
			fatal_f("sshbuf_fromb failed");
		എങ്കിൽ ((keystring = sshbuf_dtob64_string(b, 0)) == ശൂന്യ)
			fatal_f("sshbuf_dtob64 failed");
		debug2_f("%s user %s %s public key %s %s",
		    authctxt->valid ? "valid" : "invalid", authctxt->user,
		    have_sig ? "attempting" : "querying", pkalg, keystring);
		sshbuf_free(b);
		b = ശൂന്യ;
	}

	pktype = sshkey_type_from_name(pkalg);
	എങ്കിൽ (pktype == താക്കോൽ_UNSPEC) {
		/* this is perfectly legal */
		verbose_f("unsupported public key algorithm: %s", pkalg);
		പോകുക done;
	}
	എങ്കിൽ (match_pattern_list(pkalg, options.pubkey_accepted_algos, 0) != 1) {
		logit_f("signature algorithm %s not in "
		    "PubkeyAcceptedAlgorithms", pkalg);
		പോകുക done;
	}
	എങ്കിൽ ((b = sshbuf_fromb(keyblob)) == ശൂന്യ)
		fatal_f("sshbuf_fromb failed");
	തിരഞ്ഞെടുപ്പ് ((r = sshkey_fromb_allowlist(b, &താക്കോൽ,
	    options.pubkey_accepted_algos, options.ca_sign_algorithms))) {
	അവസ്ഥ 0:
		/* ok */
		നിർത്തുക;
	അവസ്ഥ SSH_ERR_താക്കോൽ_ALG_UNSUPPORTED:
		/* This shouldn't happen unless the client is being weird */
		logit_f("key algorithm differs from signature algorithm %s and "
		    "is not in PubkeyAcceptedAlgorithms", pkalg);
		പോകുക done;
	അവസ്ഥ SSH_ERR_SIGN_ALG_UNSUPPORTED:
		logit_fr(r, "certificate signature algorithm not in "
		    "CASignatureAlgorithm");
		പോകുക done;
	സ്ഥിരസ്ഥിതി:
		error_fr(r, "parse key");
		പോകുക done;
	}
	sshbuf_free(b);
	b = ശൂന്യ;

	/* USERAUTH_REQUEST signature type should match key's type */
	എങ്കിൽ (താക്കോൽ->type != pktype || (sshkey_type_plain(pktype) == താക്കോൽ_ECDSA &&
	    sshkey_ecdsa_nid_from_name(pkalg) != താക്കോൽ->ecdsa_nid)) {
		error_f("key type mismatch for decoded key "
		    "(received %s, expected %s)", sshkey_ssh_name(താക്കോൽ), pkalg);
		പോകുക done;
	}
	എങ്കിൽ (auth2_താക്കോൽ_already_used(authctxt, താക്കോൽ)) {
		logit("refusing previously-used %s key", sshkey_type(താക്കോൽ));
		പോകുക done;
	}
	എങ്കിൽ ((r = sshkey_check_rsa_length(താക്കോൽ,
	    options.required_rsa_size)) != 0) {
		logit_r(r, "refusing %s key", sshkey_type(താക്കോൽ));
		പോകുക done;
	}
	താക്കോൽ_s = format_താക്കോൽ(താക്കോൽ);
	എങ്കിൽ (sshkey_is_cert(താക്കോൽ))
		ca_s = format_താക്കോൽ(താക്കോൽ->cert->signature_താക്കോൽ);

	എങ്കിൽ (have_sig) {
		debug3_f("%s have %s signature for %s%s%s",
		    method, pkalg, താക്കോൽ_s,
		    ca_s == ശൂന്യ ? "" : " CA ", ca_s == ശൂന്യ ? "" : ca_s);
		എങ്കിൽ ((r = sshpkt_get_string(ssh, &sig, &slen)) != 0 ||
		    (r = sshpkt_get_end(ssh)) != 0)
			fatal_fr(r, "parse signature packet");
		എങ്കിൽ ((b = sshbuf_new()) == ശൂന്യ)
			fatal_f("sshbuf_new failed");
		എങ്കിൽ ((r = sshbuf_put_stringb(b,
		    ssh->kex->session_id)) != 0)
			fatal_fr(r, "put session id");
		എങ്കിൽ (!authctxt->valid || authctxt->user == ശൂന്യ) {
			debug2_f("disabled because of invalid user");
			പോകുക done;
		}
		/* reconstruct packet */
		xasprintf(&userstyle, "%s%s%s", authctxt->user,
		    authctxt->style ? ":" : "",
		    authctxt->style ? authctxt->style : "");
		എങ്കിൽ ((r = sshbuf_put_u8(b, SSH2_സന്ദേശം_USERAUTH_REQUEST)) != 0 ||
		    (r = sshbuf_put_cstring(b, userstyle)) != 0 ||
		    (r = sshbuf_put_cstring(b, authctxt->service)) != 0 ||
		    (r = sshbuf_put_cstring(b, method)) != 0 ||
		    (r = sshbuf_put_u8(b, have_sig)) != 0 ||
		    (r = sshbuf_put_cstring(b, pkalg)) != 0 ||
		    (r = sshbuf_put_stringb(b, keyblob)) != 0)
			fatal_fr(r, "reconstruct %s packet", method);
		എങ്കിൽ (hostbound &&
		    (r = sshkey_puts(ssh->kex->initial_hostkey, b)) != 0)
			fatal_fr(r, "reconstruct %s packet", method);
#ifdef DEBUG_PK
		sshbuf_dump(b, stderr);
#endif
		/* test for correct signature */
		authenticated = 0;
		എങ്കിൽ (mm_user_താക്കോൽ_allowed(ssh, pw, താക്കോൽ, 1, &authopts) &&
		    mm_sshkey_verify(താക്കോൽ, sig, slen,
		    sshbuf_ptr(b), sshbuf_len(b),
		    (ssh->compat & SSH_BUG_SIGTYPE) == 0 ? pkalg : ശൂന്യ,
		    ssh->compat, &sig_details) == 0) {
			authenticated = 1;
		}
		എങ്കിൽ (authenticated == 1 && sig_details != ശൂന്യ) {
			auth2_record_info(authctxt, "signature count = %u",
			    sig_details->sk_counter);
			debug_f("sk_counter = %u, sk_flags = 0x%02x",
			    sig_details->sk_counter, sig_details->sk_flags);
			req_presence = (options.pubkey_auth_options &
			    PUBKEYAUTH_TOUCH_REQUIRED) ||
			    !authopts->no_require_user_presence;
			എങ്കിൽ (req_presence && (sig_details->sk_flags &
			    SSH_SK_USER_PRESENCE_REQD) == 0) {
				error("public key %s signature for %s%s from "
				    "%.128s port %d rejected: user presence "
				    "(authenticator touch) requirement "
				    "not met ", താക്കോൽ_s,
				    authctxt->valid ? "" : "invalid user ",
				    authctxt->user, ssh_remote_ipaddr(ssh),
				    ssh_remote_port(ssh));
				authenticated = 0;
				പോകുക done;
			}
			req_verify = (options.pubkey_auth_options &
			    PUBKEYAUTH_VERIFY_REQUIRED) ||
			    authopts->require_verify;
			എങ്കിൽ (req_verify && (sig_details->sk_flags &
			    SSH_SK_USER_VERIFICATION_REQD) == 0) {
				error("public key %s signature for %s%s from "
				    "%.128s port %d rejected: user "
				    "verification requirement not met ", താക്കോൽ_s,
				    authctxt->valid ? "" : "invalid user ",
				    authctxt->user, ssh_remote_ipaddr(ssh),
				    ssh_remote_port(ssh));
				authenticated = 0;
				പോകുക done;
			}
		}
		auth2_record_താക്കോൽ(authctxt, authenticated, താക്കോൽ);
	} അല്ലെങ്കിൽ {
		debug_f("%s test pkalg %s pkblob %s%s%s", method, pkalg, താക്കോൽ_s,
		    ca_s == ശൂന്യ ? "" : " CA ", ca_s == ശൂന്യ ? "" : ca_s);

		എങ്കിൽ ((r = sshpkt_get_end(ssh)) != 0)
			fatal_fr(r, "parse packet");

		/* XXX fake reply and always send PK_OK ? */
		/*
		 * XXX this allows testing whether a user is allowed
		 * to login: if you happen to have a valid pubkey this
		 * message is sent. the message is NEVER sent at all
		 * if a user is not allowed to login. is this an
		 * issue? -markus
		 */
		എങ്കിൽ (authctxt->valid && authctxt->user != ശൂന്യ &&
		    mm_user_താക്കോൽ_allowed(ssh, pw, താക്കോൽ, 0, ശൂന്യ)) {
			എങ്കിൽ ((r = sshpkt_start(ssh, SSH2_സന്ദേശം_USERAUTH_PK_OK))
			    != 0 ||
			    (r = sshpkt_put_cstring(ssh, pkalg)) != 0 ||
			    (r = sshpkt_put_stringb(ssh, keyblob)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0 ||
			    (r = ssh_packet_write_wait(ssh)) != 0)
				fatal_fr(r, "send packet");
			authctxt->postponed = 1;
		} അല്ലെങ്കിൽ {
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
			എങ്കിൽ (authctxt->pk_ok_failures++ < options.max_pubkey_ok)
				authctxt->auth_failure_already_counted = 1;
			debug3_f("pubkey test %d of %d%s",
			    authctxt->pk_ok_failures, options.max_pubkey_ok,
			    authctxt->auth_failure_already_counted ?
			    "" : ": treating as authentication failure");
		 }
	}
done:
	എങ്കിൽ (authenticated == 1 && auth_activate_options(ssh, authopts) != 0) {
		debug_f("key options inconsistent with existing");
		authenticated = 0;
	}
	debug2_f("authenticated %d pkalg %s", authenticated, pkalg);

	sshbuf_free(b);
	sshbuf_free(keyblob);
	sshauthopt_free(authopts);
	sshkey_free(താക്കോൽ);
	sshkey_free(hostkey);
	സ്വതന്ത്രം(keystring);
	സ്വതന്ത്രം(userstyle);
	സ്വതന്ത്രം(pkalg);
	സ്വതന്ത്രം(താക്കോൽ_s);
	സ്വതന്ത്രം(ca_s);
	സ്വതന്ത്രം(sig);
	sshkey_sig_details_free(sig_details);
	തിരികെ authenticated;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
match_principals_file(ഘടന passwd *pw, അക്ഷരം *file,
    ഘടന sshkey_cert *cert, ഘടന sshauthopt **authoptsp)
{
	FILE *f;
	പൂർണ്ണസംഖ്യ r, success = 0;
	size_t i;
	glob_t gl;
	ഘടന sshauthopt *opts = ശൂന്യ;

	എങ്കിൽ (authoptsp != ശൂന്യ)
		*authoptsp = ശൂന്യ;

	temporarily_use_uid(pw);
	r = glob(file, 0, ശൂന്യ, &gl);
	restore_uid();
	എങ്കിൽ (r != 0) {
		എങ്കിൽ (r != GLOB_NOMATCH) {
			logit_f("glob \"%s\" failed", file);
		}
		തിരികെ 0;
	} അല്ലെങ്കിൽ എങ്കിൽ (gl.gl_pathc > INT_MAX) {
		fatal_f("too many glob results for \"%s\"", file);
	} അല്ലെങ്കിൽ എങ്കിൽ (gl.gl_pathc > 1) {
		debug2_f("glob \"%s\" returned %zu matches", file,
		    gl.gl_pathc);
	}
	വേണ്ടി (i = 0; !success && i < gl.gl_pathc; i++) {
		temporarily_use_uid(pw);
		debug("trying authorized principals file %s", file);
		എങ്കിൽ ((f = auth_openprincipals(gl.gl_pathv[i], pw,
		    options.strict_modes)) == ശൂന്യ) {
			restore_uid();
			തുടരുക;
		}
		success = auth_process_principals(f, gl.gl_pathv[i],
		    cert, &opts);
		fclose(f);
		restore_uid();
		എങ്കിൽ (!success) {
			sshauthopt_free(opts);
			opts = ശൂന്യ;
		}
	}
	globfree(&gl);
	എങ്കിൽ (success && authoptsp != ശൂന്യ) {
		*authoptsp = opts;
		opts = ശൂന്യ;
	}
	sshauthopt_free(opts);
	തിരികെ success;
}

/*
 * Checks whether principal is allowed in output of command.
 * returns 1 if the principal is allowed or 0 otherwise.
 */
സ്ഥിതം പൂർണ്ണസംഖ്യ
match_principals_command(ഘടന passwd *user_pw, സ്ഥിരം ഘടന sshkey *താക്കോൽ,
    സ്ഥിരം അക്ഷരം *conn_id, സ്ഥിരം അക്ഷരം *rdomain, ഘടന sshauthopt **authoptsp)
{
	ഘടന passwd *runas_pw = ശൂന്യ;
	സ്ഥിരം ഘടന sshkey_cert *cert = താക്കോൽ->cert;
	FILE *f = ശൂന്യ;
	പൂർണ്ണസംഖ്യ r, ok, found_principal = 0;
	പൂർണ്ണസംഖ്യ i, ac = 0, uid_swapped = 0;
	pid_t pid;
	അക്ഷരം *tmp, *username = ശൂന്യ, *command = ശൂന്യ, **av = ശൂന്യ;
	അക്ഷരം *ca_fp = ശൂന്യ, *താക്കോൽ_fp = ശൂന്യ, *catext = ശൂന്യ, *keytext = ശൂന്യ;
	അക്ഷരം serial_s[32], uidstr[32];
	ശൂന്യം (*osigchld)(പൂർണ്ണസംഖ്യ);

	എങ്കിൽ (authoptsp != ശൂന്യ)
		*authoptsp = ശൂന്യ;
	എങ്കിൽ (options.authorized_principals_command == ശൂന്യ)
		തിരികെ 0;
	എങ്കിൽ (options.authorized_principals_command_user == ശൂന്യ) {
		error("No user for AuthorizedPrincipalsCommand specified, "
		    "skipping");
		തിരികെ 0;
	}

	/*
	 * NB. all returns later this function should go via "out" to
	 * ensure the original SIGCHLD handler is restored properly.
	 */
	osigchld = ssh_signal(SIGCHLD, SIG_DFL);

	/* Prepare and verify the user for the command */
	username = percent_expand(options.authorized_principals_command_user,
	    "u", user_pw->pw_name, (അക്ഷരം *)ശൂന്യ);
	runas_pw = getpwnam(username);
	എങ്കിൽ (runas_pw == ശൂന്യ) {
		error("AuthorizedPrincipalsCommandUser \"%s\" not found: %s",
		    username, strerror(errno));
		പോകുക out;
	}

	/* Turn the command into an argument vector */
	എങ്കിൽ (argv_split(options.authorized_principals_command,
	    &ac, &av, 0) != 0) {
		error("AuthorizedPrincipalsCommand \"%s\" contains "
		    "invalid quotes", options.authorized_principals_command);
		പോകുക out;
	}
	എങ്കിൽ (ac == 0) {
		error("AuthorizedPrincipalsCommand \"%s\" yielded no arguments",
		    options.authorized_principals_command);
		പോകുക out;
	}
	എങ്കിൽ ((ca_fp = sshkey_fingerprint(cert->signature_താക്കോൽ,
	    options.fingerprint_hash, SSH_FP_DEFAULT)) == ശൂന്യ) {
		error_f("sshkey_fingerprint failed");
		പോകുക out;
	}
	എങ്കിൽ ((താക്കോൽ_fp = sshkey_fingerprint(താക്കോൽ,
	    options.fingerprint_hash, SSH_FP_DEFAULT)) == ശൂന്യ) {
		error_f("sshkey_fingerprint failed");
		പോകുക out;
	}
	എങ്കിൽ ((r = sshkey_to_base64(cert->signature_താക്കോൽ, &catext)) != 0) {
		error_fr(r, "sshkey_to_base64 failed");
		പോകുക out;
	}
	എങ്കിൽ ((r = sshkey_to_base64(താക്കോൽ, &keytext)) != 0) {
		error_fr(r, "sshkey_to_base64 failed");
		പോകുക out;
	}
	snprintf(serial_s, വലുപ്പം(serial_s), "%llu",
	    (unsigned long long)cert->serial);
	snprintf(uidstr, വലുപ്പം(uidstr), "%llu",
	    (unsigned long long)user_pw->pw_uid);
	വേണ്ടി (i = 1; i < ac; i++) {
		tmp = percent_expand(av[i],
		    "C", conn_id,
		    "D", rdomain,
		    "U", uidstr,
		    "u", user_pw->pw_name,
		    "h", user_pw->pw_dir,
		    "t", sshkey_ssh_name(താക്കോൽ),
		    "T", sshkey_ssh_name(cert->signature_താക്കോൽ),
		    "f", താക്കോൽ_fp,
		    "F", ca_fp,
		    "k", keytext,
		    "K", catext,
		    "i", cert->താക്കോൽ_id,
		    "s", serial_s,
		    (അക്ഷരം *)ശൂന്യ);
		എങ്കിൽ (tmp == ശൂന്യ)
			fatal_f("percent_expand failed");
		സ്വതന്ത്രം(av[i]);
		av[i] = tmp;
	}
	/* Prepare a printable command for logs, etc. */
	command = argv_assemble(ac, av);

	എങ്കിൽ ((pid = subprocess("AuthorizedPrincipalsCommand", command,
	    ac, av, &f,
	    SSH_SUBPROCESS_STDOUT_CAPTURE|SSH_SUBPROCESS_STDERR_DISCARD,
	    runas_pw, temporarily_use_uid, restore_uid)) == 0)
		പോകുക out;

	uid_swapped = 1;
	temporarily_use_uid(runas_pw);

	ok = auth_process_principals(f, "(command)", cert, authoptsp);

	fclose(f);
	f = ശൂന്യ;

	എങ്കിൽ (exited_cleanly(pid, "AuthorizedPrincipalsCommand", command, 0) != 0)
		പോകുക out;

	/* Read completed successfully */
	found_principal = ok;
 out:
	എങ്കിൽ (f != ശൂന്യ)
		fclose(f);
	ssh_signal(SIGCHLD, osigchld);
	വേണ്ടി (i = 0; i < ac; i++)
		സ്വതന്ത്രം(av[i]);
	സ്വതന്ത്രം(av);
	എങ്കിൽ (uid_swapped)
		restore_uid();
	സ്വതന്ത്രം(command);
	സ്വതന്ത്രം(username);
	സ്വതന്ത്രം(ca_fp);
	സ്വതന്ത്രം(താക്കോൽ_fp);
	സ്വതന്ത്രം(catext);
	സ്വതന്ത്രം(keytext);
	തിരികെ found_principal;
}

/* Authenticate a certificate key against TrustedUserCAKeys */
സ്ഥിതം പൂർണ്ണസംഖ്യ
user_cert_trusted_ca(ഘടന passwd *pw, ഘടന sshkey *താക്കോൽ,
    സ്ഥിരം അക്ഷരം *remote_ip, സ്ഥിരം അക്ഷരം *remote_host,
    സ്ഥിരം അക്ഷരം *conn_id, സ്ഥിരം അക്ഷരം *rdomain, ഘടന sshauthopt **authoptsp)
{
	അക്ഷരം *ca_fp, *principals_file = ശൂന്യ;
	സ്ഥിരം അക്ഷരം *reason;
	ഘടന sshauthopt *principals_opts = ശൂന്യ, *cert_opts = ശൂന്യ;
	ഘടന sshauthopt *final_opts = ശൂന്യ;
	പൂർണ്ണസംഖ്യ r, ret = 0, found_principal = 0, use_authorized_principals;

	എങ്കിൽ (authoptsp != ശൂന്യ)
		*authoptsp = ശൂന്യ;

	എങ്കിൽ (!sshkey_is_cert(താക്കോൽ) || options.trusted_user_ca_താക്കോലുകൾ == ശൂന്യ)
		തിരികെ 0;

	എങ്കിൽ ((ca_fp = sshkey_fingerprint(താക്കോൽ->cert->signature_താക്കോൽ,
	    options.fingerprint_hash, SSH_FP_DEFAULT)) == ശൂന്യ)
		തിരികെ 0;

	എങ്കിൽ ((r = sshkey_in_file(താക്കോൽ->cert->signature_താക്കോൽ,
	    options.trusted_user_ca_താക്കോലുകൾ, 1, 0)) != 0) {
		debug2_fr(r, "CA %s %s is not listed in %s",
		    sshkey_type(താക്കോൽ->cert->signature_താക്കോൽ), ca_fp,
		    options.trusted_user_ca_താക്കോലുകൾ);
		പോകുക out;
	}
	/*
	 * If AuthorizedPrincipals is in use, then compare the certificate
	 * principals against the names in that file rather than matching
	 * against the username.
	 */
	എങ്കിൽ ((principals_file = authorized_principals_file(pw)) != ശൂന്യ) {
		എങ്കിൽ (match_principals_file(pw, principals_file,
		    താക്കോൽ->cert, &principals_opts))
			found_principal = 1;
	}
	/* Try querying command if specified */
	എങ്കിൽ (!found_principal && match_principals_command(pw, താക്കോൽ,
	    conn_id, rdomain, &principals_opts))
		found_principal = 1;
	/* If principals file or command is specified, then require a match */
	use_authorized_principals = principals_file != ശൂന്യ ||
	    options.authorized_principals_command != ശൂന്യ;
	എങ്കിൽ (!found_principal && use_authorized_principals) {
		reason = "Certificate does not contain an authorized principal";
		പോകുക fail_reason;
	}
	എങ്കിൽ (use_authorized_principals && principals_opts == ശൂന്യ)
		fatal_f("internal error: missing principals_opts");
	എങ്കിൽ (sshkey_cert_check_authority_now(താക്കോൽ, 0, 0,
	    use_authorized_principals ? ശൂന്യ : pw->pw_name, &reason) != 0)
		പോകുക fail_reason;

	/* Check authority from options in key and from principals file/cmd */
	എങ്കിൽ ((cert_opts = sshauthopt_from_cert(താക്കോൽ)) == ശൂന്യ) {
		reason = "Invalid certificate options";
		പോകുക fail_reason;
	}
	എങ്കിൽ (auth_authorise_keyopts(pw, cert_opts, 0,
	    remote_ip, remote_host, "cert") != 0) {
		reason = "Refused by certificate options";
		പോകുക fail_reason;
	}
	എങ്കിൽ (principals_opts == ശൂന്യ) {
		final_opts = cert_opts;
		cert_opts = ശൂന്യ;
	} അല്ലെങ്കിൽ {
		എങ്കിൽ (auth_authorise_keyopts(pw, principals_opts, 0,
		    remote_ip, remote_host, "principals") != 0) {
			reason = "Refused by certificate principals options";
			പോകുക fail_reason;
		}
		എങ്കിൽ ((final_opts = sshauthopt_merge(principals_opts,
		    cert_opts, &reason)) == ശൂന്യ) {
 fail_reason:
			error("Refusing certificate ID \"%s\" serial=%llu "
			    "signed by %s CA %s: %s", താക്കോൽ->cert->താക്കോൽ_id,
			    (unsigned long long)താക്കോൽ->cert->serial,
			    sshkey_type(താക്കോൽ->cert->signature_താക്കോൽ), ca_fp,
			    reason);
			auth_debug_add("Refused Certificate ID \"%s\" "
			    "serial=%llu: %s", താക്കോൽ->cert->താക്കോൽ_id,
			    (unsigned long long)താക്കോൽ->cert->serial, reason);
			പോകുക out;
		}
	}

	/* Success */
	verbose("Accepted certificate ID \"%s\" (serial %llu) signed by "
	    "%s CA %s via %s", താക്കോൽ->cert->താക്കോൽ_id,
	    (unsigned long long)താക്കോൽ->cert->serial,
	    sshkey_type(താക്കോൽ->cert->signature_താക്കോൽ), ca_fp,
	    options.trusted_user_ca_താക്കോലുകൾ);
	എങ്കിൽ (authoptsp != ശൂന്യ) {
		*authoptsp = final_opts;
		final_opts = ശൂന്യ;
	}
	ret = 1;
 out:
	sshauthopt_free(principals_opts);
	sshauthopt_free(cert_opts);
	sshauthopt_free(final_opts);
	സ്വതന്ത്രം(principals_file);
	സ്വതന്ത്രം(ca_fp);
	തിരികെ ret;
}

/*
 * Checks whether key is allowed in file.
 * returns 1 if the key is allowed or 0 otherwise.
 */
സ്ഥിതം പൂർണ്ണസംഖ്യ
user_താക്കോൽ_allowed2(ഘടന passwd *pw, ഘടന sshkey *താക്കോൽ,
    അക്ഷരം *file, സ്ഥിരം അക്ഷരം *remote_ip, സ്ഥിരം അക്ഷരം *remote_host,
    ഘടന sshauthopt **authoptsp)
{
	FILE *f;
	പൂർണ്ണസംഖ്യ found_താക്കോൽ = 0;

	എങ്കിൽ (authoptsp != ശൂന്യ)
		*authoptsp = ശൂന്യ;

	/* Temporarily use the user's uid. */
	temporarily_use_uid(pw);

	debug("trying public key file %s", file);
	എങ്കിൽ ((f = auth_openkeyfile(file, pw, options.strict_modes)) != ശൂന്യ) {
		found_താക്കോൽ = auth_check_authkeys_file(pw, f, file,
		    താക്കോൽ, remote_ip, remote_host, authoptsp);
		fclose(f);
	}

	restore_uid();
	തിരികെ found_താക്കോൽ;
}

/*
 * Checks whether key is allowed in output of command.
 * returns 1 if the key is allowed or 0 otherwise.
 */
സ്ഥിതം പൂർണ്ണസംഖ്യ
user_താക്കോൽ_command_allowed2(ഘടന passwd *user_pw, ഘടന sshkey *താക്കോൽ,
    സ്ഥിരം അക്ഷരം *remote_ip, സ്ഥിരം അക്ഷരം *remote_host,
    സ്ഥിരം അക്ഷരം *conn_id, സ്ഥിരം അക്ഷരം *rdomain, ഘടന sshauthopt **authoptsp)
{
	ഘടന passwd *runas_pw = ശൂന്യ;
	FILE *f = ശൂന്യ;
	പൂർണ്ണസംഖ്യ r, ok, found_താക്കോൽ = 0;
	പൂർണ്ണസംഖ്യ i, uid_swapped = 0, ac = 0;
	pid_t pid;
	അക്ഷരം *username = ശൂന്യ, *താക്കോൽ_fp = ശൂന്യ, *keytext = ശൂന്യ;
	അക്ഷരം uidstr[32], *tmp, *command = ശൂന്യ, **av = ശൂന്യ;
	ശൂന്യം (*osigchld)(പൂർണ്ണസംഖ്യ);

	എങ്കിൽ (authoptsp != ശൂന്യ)
		*authoptsp = ശൂന്യ;
	എങ്കിൽ (options.authorized_താക്കോലുകൾ_command == ശൂന്യ)
		തിരികെ 0;
	എങ്കിൽ (options.authorized_താക്കോലുകൾ_command_user == ശൂന്യ) {
		error("No user for AuthorizedKeysCommand specified, skipping");
		തിരികെ 0;
	}

	/*
	 * NB. all returns later this function should go via "out" to
	 * ensure the original SIGCHLD handler is restored properly.
	 */
	osigchld = ssh_signal(SIGCHLD, SIG_DFL);

	/* Prepare and verify the user for the command */
	username = percent_expand(options.authorized_താക്കോലുകൾ_command_user,
	    "u", user_pw->pw_name, (അക്ഷരം *)ശൂന്യ);
	runas_pw = getpwnam(username);
	എങ്കിൽ (runas_pw == ശൂന്യ) {
		error("AuthorizedKeysCommandUser \"%s\" not found: %s",
		    username, strerror(errno));
		പോകുക out;
	}

	/* Prepare AuthorizedKeysCommand */
	എങ്കിൽ ((താക്കോൽ_fp = sshkey_fingerprint(താക്കോൽ, options.fingerprint_hash,
	    SSH_FP_DEFAULT)) == ശൂന്യ) {
		error_f("sshkey_fingerprint failed");
		പോകുക out;
	}
	എങ്കിൽ ((r = sshkey_to_base64(താക്കോൽ, &keytext)) != 0) {
		error_fr(r, "sshkey_to_base64 failed");
		പോകുക out;
	}

	/* Turn the command into an argument vector */
	എങ്കിൽ (argv_split(options.authorized_താക്കോലുകൾ_command, &ac, &av, 0) != 0) {
		error("AuthorizedKeysCommand \"%s\" contains invalid quotes",
		    options.authorized_താക്കോലുകൾ_command);
		പോകുക out;
	}
	എങ്കിൽ (ac == 0) {
		error("AuthorizedKeysCommand \"%s\" yielded no arguments",
		    options.authorized_താക്കോലുകൾ_command);
		പോകുക out;
	}
	snprintf(uidstr, വലുപ്പം(uidstr), "%llu",
	    (unsigned long long)user_pw->pw_uid);
	വേണ്ടി (i = 1; i < ac; i++) {
		tmp = percent_expand(av[i],
		    "C", conn_id,
		    "D", rdomain,
		    "U", uidstr,
		    "u", user_pw->pw_name,
		    "h", user_pw->pw_dir,
		    "t", sshkey_ssh_name(താക്കോൽ),
		    "f", താക്കോൽ_fp,
		    "k", keytext,
		    (അക്ഷരം *)ശൂന്യ);
		എങ്കിൽ (tmp == ശൂന്യ)
			fatal_f("percent_expand failed");
		സ്വതന്ത്രം(av[i]);
		av[i] = tmp;
	}
	/* Prepare a printable command for logs, etc. */
	command = argv_assemble(ac, av);

	/*
	 * If AuthorizedKeysCommand was run without arguments
	 * then fall back to the old behaviour of passing the
	 * target username as a single argument.
	 */
	എങ്കിൽ (ac == 1) {
		av = xreallocarray(av, ac + 2, വലുപ്പം(*av));
		av[1] = xstrdup(user_pw->pw_name);
		av[2] = ശൂന്യ;
		/* Fix up command too, since it is used in log messages */
		സ്വതന്ത്രം(command);
		xasprintf(&command, "%s %s", av[0], av[1]);
	}

	എങ്കിൽ ((pid = subprocess("AuthorizedKeysCommand", command,
	    ac, av, &f,
	    SSH_SUBPROCESS_STDOUT_CAPTURE|SSH_SUBPROCESS_STDERR_DISCARD,
	    runas_pw, temporarily_use_uid, restore_uid)) == 0)
		പോകുക out;

	uid_swapped = 1;
	temporarily_use_uid(runas_pw);

	ok = auth_check_authkeys_file(user_pw, f,
	    options.authorized_താക്കോലുകൾ_command, താക്കോൽ, remote_ip,
	    remote_host, authoptsp);

	fclose(f);
	f = ശൂന്യ;

	എങ്കിൽ (exited_cleanly(pid, "AuthorizedKeysCommand", command, 0) != 0)
		പോകുക out;

	/* Read completed successfully */
	found_താക്കോൽ = ok;
 out:
	എങ്കിൽ (f != ശൂന്യ)
		fclose(f);
	ssh_signal(SIGCHLD, osigchld);
	വേണ്ടി (i = 0; i < ac; i++)
		സ്വതന്ത്രം(av[i]);
	സ്വതന്ത്രം(av);
	എങ്കിൽ (uid_swapped)
		restore_uid();
	സ്വതന്ത്രം(command);
	സ്വതന്ത്രം(username);
	സ്വതന്ത്രം(താക്കോൽ_fp);
	സ്വതന്ത്രം(keytext);
	തിരികെ found_താക്കോൽ;
}

/*
 * Check whether key authenticates and authorises the user.
 */
പൂർണ്ണസംഖ്യ
user_താക്കോൽ_allowed(ഘടന ssh *ssh, ഘടന passwd *pw, ഘടന sshkey *താക്കോൽ,
    പൂർണ്ണസംഖ്യ auth_attempt, ഘടന sshauthopt **authoptsp)
{
	u_int success = 0, i, j;
	അക്ഷരം *file = ശൂന്യ, *conn_id;
	ഘടന sshauthopt *opts = ശൂന്യ;
	സ്ഥിരം അക്ഷരം *rdomain, *remote_ip, *remote_host;

	എങ്കിൽ (authoptsp != ശൂന്യ)
		*authoptsp = ശൂന്യ;

	എങ്കിൽ (auth_താക്കോൽ_is_revoked(താക്കോൽ))
		തിരികെ 0;
	എങ്കിൽ (sshkey_is_cert(താക്കോൽ) &&
	    auth_താക്കോൽ_is_revoked(താക്കോൽ->cert->signature_താക്കോൽ))
		തിരികെ 0;

	എങ്കിൽ ((rdomain = ssh_packet_rdomain_in(ssh)) == ശൂന്യ)
		rdomain = "";
	remote_ip = ssh_remote_ipaddr(ssh);
	remote_host = auth_get_canonical_hostname(ssh, options.use_dns);
	xasprintf(&conn_id, "%s %d %s %d",
	    ssh_local_ipaddr(ssh), ssh_local_port(ssh),
	    remote_ip, ssh_remote_port(ssh));

	വേണ്ടി (i = 0; !success && i < options.അക്കം_authkeys_files; i++) {
		പൂർണ്ണസംഖ്യ r;
		glob_t gl;

		എങ്കിൽ (strcasecmp(options.authorized_താക്കോലുകൾ_files[i], "none") == 0)
			തുടരുക;
		file = expand_authorized_താക്കോലുകൾ(
		    options.authorized_താക്കോലുകൾ_files[i], pw);
		temporarily_use_uid(pw);
		r = glob(file, 0, ശൂന്യ, &gl);
		restore_uid();
		എങ്കിൽ (r != 0) {
			എങ്കിൽ (r != GLOB_NOMATCH) {
				logit_f("glob \"%s\" failed", file);
			}
			സ്വതന്ത്രം(file);
			file = ശൂന്യ;
			തുടരുക;
		} അല്ലെങ്കിൽ എങ്കിൽ (gl.gl_pathc > INT_MAX) {
			fatal_f("too many glob results for \"%s\"", file);
		} അല്ലെങ്കിൽ എങ്കിൽ (gl.gl_pathc > 1) {
			debug2_f("glob \"%s\" returned %zu matches", file,
			    gl.gl_pathc);
		}
		വേണ്ടി (j = 0; !success && j < gl.gl_pathc; j++) {
			success = user_താക്കോൽ_allowed2(pw, താക്കോൽ, gl.gl_pathv[j],
			    remote_ip, remote_host, &opts);
			എങ്കിൽ (!success) {
				sshauthopt_free(opts);
				opts = ശൂന്യ;
			}
		}
		സ്വതന്ത്രം(file);
		file = ശൂന്യ;
		globfree(&gl);
	}
	എങ്കിൽ (success)
		പോകുക out;

	എങ്കിൽ ((success = user_cert_trusted_ca(pw, താക്കോൽ, remote_ip, remote_host,
	    conn_id, rdomain, &opts)) != 0)
		പോകുക out;
	sshauthopt_free(opts);
	opts = ശൂന്യ;

	എങ്കിൽ ((success = user_താക്കോൽ_command_allowed2(pw, താക്കോൽ, remote_ip,
	    remote_host, conn_id, rdomain, &opts)) != 0)
		പോകുക out;
	sshauthopt_free(opts);
	opts = ശൂന്യ;

 out:
	സ്വതന്ത്രം(conn_id);
	എങ്കിൽ (success && authoptsp != ശൂന്യ) {
		*authoptsp = opts;
		opts = ശൂന്യ;
	}
	sshauthopt_free(opts);
	തിരികെ success;
}

Authmethod method_pubkey = {
	&methodcfg_pubkey,
	userauth_pubkey,
};
