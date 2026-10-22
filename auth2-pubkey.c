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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>

#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <paths.h>
#ಅನ್ತರ್ಭಾವ <pwd.h>
#ಅನ್ತರ್ಭಾವ <glob.h>
#ಅನ್ತರ್ಭಾವ <signal.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <time.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>
#ಅನ್ತರ್ಭಾವ <limits.h>

#ಅನ್ತರ್ಭಾವ "xmalloc.h"
#ಅನ್ತರ್ಭಾವ "ssh.h"
#ಅನ್ತರ್ಭಾವ "ssh2.h"
#ಅನ್ತರ್ಭಾವ "packet.h"
#ಅನ್ತರ್ಭಾವ "kex.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "misc.h"
#ಅನ್ತರ್ಭಾವ "servconf.h"
#ಅನ್ತರ್ಭಾವ "compat.h"
#ಅನ್ತರ್ಭಾವ "sshkey.h"
#ಅನ್ತರ್ಭಾವ "hostfile.h"
#ಅನ್ತರ್ಭಾವ "auth.h"
#ಅನ್ತರ್ಭಾವ "pathnames.h"
#ಅನ್ತರ್ಭಾವ "uidswap.h"
#ಅನ್ತರ್ಭಾವ "auth-options.h"
#ಅನ್ತರ್ಭಾವ "canohost.h"
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ GSSAPI
#ಅನ್ತರ್ಭಾವ "ssh-gss.h"
#ಆದರೆ_ಅಂತ್ಯ
#ಅನ್ತರ್ಭಾವ "monitor_wrap.h"
#ಅನ್ತರ್ಭಾವ "authfile.h"
#ಅನ್ತರ್ಭಾವ "match.h"
#ಅನ್ತರ್ಭಾವ "ssherr.h"
#ಅನ್ತರ್ಭಾವ "channels.h" /* XXX for session.h */
#ಅನ್ತರ್ಭಾವ "session.h" /* XXX for child_set_env(); refactor? */
#ಅನ್ತರ್ಭಾವ "sk-api.h"

/* import */
ಬಾಹ್ಯ ServerOptions options;
ಬಾಹ್ಯ ರಚನೆ authmethod_cfg methodcfg_pubkey;

ಸ್ಥಿರ ಅಕ್ಷರ *
format_ಕೀಲಿ(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *ಕೀಲಿ)
{
	ಅಕ್ಷರ *ret, *fp = sshkey_fingerprint(ಕೀಲಿ,
	    options.fingerprint_hash, SSH_FP_DEFAULT);

	xasprintf(&ret, "%s %s", sshkey_type(ಕೀಲಿ), fp);
	ಬಿಡುಗಡೆ(fp);
	ಹಿಂತಿರುಗಿ ret;
}

/*
 * Verify that the hostkey in a publickey-hostbound-v00@openssh.com userauth
 * request matches the hostkey that was negotiated during initial KEX.
 */
ಸ್ಥಿರ ಶೂನ್ಯ
check_hostbound_hostkey(ರಚನೆ ssh *ssh)
{
	ಪೂರ್ಣಾಂಕ r;
	ರಚನೆ sshbuf *our_hostkey_blob, *their_hostkey_blob;

	ಆದರೆ (ssh->kex->initial_hostkey == ಖಾಲಿ)
		fatal_f("internal error: initial hostkey not recorded");
	ಆದರೆ ((our_hostkey_blob = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new failed");
	ಆದರೆ ((r = sshpkt_getb_froms(ssh, &their_hostkey_blob)) != 0)
		fatal_fr(r, "parse hostkey");
	ಆದರೆ ((r = sshkey_putb(ssh->kex->initial_hostkey, our_hostkey_blob)) != 0)
		fatal_fr(r, "serialise hostkey");
	ಆದರೆ ((r = sshbuf_equals(our_hostkey_blob, their_hostkey_blob)) != 0)
		fatal_f("packet contained wrong host key");
	sshbuf_free(our_hostkey_blob);
	sshbuf_free(their_hostkey_blob);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
userauth_pubkey(ರಚನೆ ssh *ssh, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ವಿಧಾನ)
{
	Authctxt *authctxt = ssh->authctxt;
	ರಚನೆ passwd *pw = authctxt->pw;
	ರಚನೆ sshbuf *keyblob = ಖಾಲಿ, *b = ಖಾಲಿ;
	ರಚನೆ sshkey *ಕೀಲಿ = ಖಾಲಿ, *hostkey = ಖಾಲಿ;
	ಅಕ್ಷರ *pkalg = ಖಾಲಿ, *userstyle = ಖಾಲಿ, *ಕೀಲಿ_s = ಖಾಲಿ, *ca_s = ಖಾಲಿ;
	ಅಕ್ಷರ *keystring = ಖಾಲಿ;
	u_char *sig = ಖಾಲಿ, have_sig;
	ಗಾತ್ರ_t slen;
	ಪೂರ್ಣಾಂಕ hostbound, r, pktype;
	ಪೂರ್ಣಾಂಕ req_presence = 0, req_verify = 0, authenticated = 0;
	ರಚನೆ sshauthopt *authopts = ಖಾಲಿ;
	ರಚನೆ sshkey_sig_details *sig_details = ಖಾಲಿ;

	hostbound = strcmp(ವಿಧಾನ, "publickey-hostbound-v00@openssh.com") == 0;

	ಆದರೆ ((r = sshpkt_get_u8(ssh, &have_sig)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &pkalg, ಖಾಲಿ)) != 0 ||
	    (r = sshpkt_getb_froms(ssh, &keyblob)) != 0)
		fatal_fr(r, "parse %s packet", ವಿಧಾನ);

	/* hostbound auth includes the hostkey offered at initial KEX */
	ಆದರೆ (hostbound)
		check_hostbound_hostkey(ssh); /* fatals on error */

	ಆದರೆ (log_level_get() >= SYSLOG_LEVEL_DEBUG2) {
		ಆದರೆ ((b = sshbuf_fromb(keyblob)) == ಖಾಲಿ)
			fatal_f("sshbuf_fromb failed");
		ಆದರೆ ((keystring = sshbuf_dtob64_string(b, 0)) == ಖಾಲಿ)
			fatal_f("sshbuf_dtob64 failed");
		debug2_f("%s user %s %s public key %s %s",
		    authctxt->valid ? "valid" : "invalid", authctxt->user,
		    have_sig ? "attempting" : "querying", pkalg, keystring);
		sshbuf_free(b);
		b = ಖಾಲಿ;
	}

	pktype = sshkey_type_from_name(pkalg);
	ಆದರೆ (pktype == ಕೀಲಿ_UNSPEC) {
		/* this is perfectly legal */
		verbose_f("unsupported public key algorithm: %s", pkalg);
		ಹೋಗು ಮುಗಿದ;
	}
	ಆದರೆ (ಹೊಂದಿಕೆ_ನಮೂನೆ_list(pkalg, options.pubkey_accepted_algos, 0) != 1) {
		logit_f("signature algorithm %s not in "
		    "PubkeyAcceptedAlgorithms", pkalg);
		ಹೋಗು ಮುಗಿದ;
	}
	ಆದರೆ ((b = sshbuf_fromb(keyblob)) == ಖಾಲಿ)
		fatal_f("sshbuf_fromb failed");
	ಆಯ್ಕೆ ((r = sshkey_fromb_allowlist(b, &ಕೀಲಿ,
	    options.pubkey_accepted_algos, options.ca_sign_algorithms))) {
	ಸ್ಥಿತಿ 0:
		/* ok */
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ SSH_ERR_ಕೀಲಿ_ALG_UNSUPPORTED:
		/* This shouldn't happen unless the client is being weird */
		logit_f("key algorithm differs from signature algorithm %s and "
		    "is not in PubkeyAcceptedAlgorithms", pkalg);
		ಹೋಗು ಮುಗಿದ;
	ಸ್ಥಿತಿ SSH_ERR_SIGN_ALG_UNSUPPORTED:
		logit_fr(r, "certificate signature algorithm not in "
		    "CASignatureAlgorithm");
		ಹೋಗು ಮುಗಿದ;
	ಪೂರ್ವನಿಯೋಜಿತ:
		error_fr(r, "parse key");
		ಹೋಗು ಮುಗಿದ;
	}
	sshbuf_free(b);
	b = ಖಾಲಿ;

	/* USERAUTH_REQUEST signature type should match key's type */
	ಆದರೆ (ಕೀಲಿ->type != pktype || (sshkey_type_plain(pktype) == ಕೀಲಿ_ECDSA &&
	    sshkey_ecdsa_nid_from_name(pkalg) != ಕೀಲಿ->ecdsa_nid)) {
		error_f("key type mismatch for decoded key "
		    "(received %s, expected %s)", sshkey_ssh_name(ಕೀಲಿ), pkalg);
		ಹೋಗು ಮುಗಿದ;
	}
	ಆದರೆ (auth2_ಕೀಲಿ_already_ಬಳಸಿದ(authctxt, ಕೀಲಿ)) {
		logit("refusing previously-used %s key", sshkey_type(ಕೀಲಿ));
		ಹೋಗು ಮುಗಿದ;
	}
	ಆದರೆ ((r = sshkey_check_rsa_ಉದ್ದಳತೆ(ಕೀಲಿ,
	    options.required_rsa_ಗಾತ್ರ)) != 0) {
		logit_r(r, "refusing %s key", sshkey_type(ಕೀಲಿ));
		ಹೋಗು ಮುಗಿದ;
	}
	ಕೀಲಿ_s = format_ಕೀಲಿ(ಕೀಲಿ);
	ಆದರೆ (sshkey_is_cert(ಕೀಲಿ))
		ca_s = format_ಕೀಲಿ(ಕೀಲಿ->cert->signature_ಕೀಲಿ);

	ಆದರೆ (have_sig) {
		debug3_f("%s have %s signature for %s%s%s",
		    ವಿಧಾನ, pkalg, ಕೀಲಿ_s,
		    ca_s == ಖಾಲಿ ? "" : " CA ", ca_s == ಖಾಲಿ ? "" : ca_s);
		ಆದರೆ ((r = sshpkt_get_string(ssh, &sig, &slen)) != 0 ||
		    (r = sshpkt_get_ಕೊನೆ(ssh)) != 0)
			fatal_fr(r, "parse signature packet");
		ಆದರೆ ((b = sshbuf_new()) == ಖಾಲಿ)
			fatal_f("sshbuf_new failed");
		ಆದರೆ ((r = sshbuf_put_stringb(b,
		    ssh->kex->session_id)) != 0)
			fatal_fr(r, "put session id");
		ಆದರೆ (!authctxt->valid || authctxt->user == ಖಾಲಿ) {
			debug2_f("disabled because of invalid user");
			ಹೋಗು ಮುಗಿದ;
		}
		/* reconstruct packet */
		xasprintf(&userstyle, "%s%s%s", authctxt->user,
		    authctxt->style ? ":" : "",
		    authctxt->style ? authctxt->style : "");
		ಆದರೆ ((r = sshbuf_put_u8(b, SSH2_ಸಂದೇಶ_USERAUTH_REQUEST)) != 0 ||
		    (r = sshbuf_put_cstring(b, userstyle)) != 0 ||
		    (r = sshbuf_put_cstring(b, authctxt->service)) != 0 ||
		    (r = sshbuf_put_cstring(b, ವಿಧಾನ)) != 0 ||
		    (r = sshbuf_put_u8(b, have_sig)) != 0 ||
		    (r = sshbuf_put_cstring(b, pkalg)) != 0 ||
		    (r = sshbuf_put_stringb(b, keyblob)) != 0)
			fatal_fr(r, "reconstruct %s packet", ವಿಧಾನ);
		ಆದರೆ (hostbound &&
		    (r = sshkey_puts(ssh->kex->initial_hostkey, b)) != 0)
			fatal_fr(r, "reconstruct %s packet", ವಿಧಾನ);
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ DEBUG_PK
		sshbuf_dump(b, stderr);
#ಆದರೆ_ಅಂತ್ಯ
		/* test for correct signature */
		authenticated = 0;
		ಆದರೆ (mm_user_ಕೀಲಿ_allowed(ssh, pw, ಕೀಲಿ, 1, &authopts) &&
		    mm_sshkey_verify(ಕೀಲಿ, sig, slen,
		    sshbuf_ptr(b), sshbuf_len(b),
		    (ssh->compat & SSH_BUG_SIGTYPE) == 0 ? pkalg : ಖಾಲಿ,
		    ssh->compat, &sig_details) == 0) {
			authenticated = 1;
		}
		ಆದರೆ (authenticated == 1 && sig_details != ಖಾಲಿ) {
			auth2_ದಾಖಲೆ_info(authctxt, "signature count = %u",
			    sig_details->sk_counter);
			debug_f("sk_counter = %u, sk_flags = 0x%02x",
			    sig_details->sk_counter, sig_details->sk_flags);
			req_presence = (options.pubkey_auth_options &
			    PUBKEYAUTH_TOUCH_REQUIRED) ||
			    !authopts->no_require_user_presence;
			ಆದರೆ (req_presence && (sig_details->sk_flags &
			    SSH_SK_USER_PRESENCE_REQD) == 0) {
				error("public key %s signature for %s%s from "
				    "%.128s port %d rejected: user presence "
				    "(authenticator touch) requirement "
				    "not met ", ಕೀಲಿ_s,
				    authctxt->valid ? "" : "invalid user ",
				    authctxt->user, ssh_remote_ipaddr(ssh),
				    ssh_remote_ಪೋರ್ಟ್(ssh));
				authenticated = 0;
				ಹೋಗು ಮುಗಿದ;
			}
			req_verify = (options.pubkey_auth_options &
			    PUBKEYAUTH_VERIFY_REQUIRED) ||
			    authopts->require_verify;
			ಆದರೆ (req_verify && (sig_details->sk_flags &
			    SSH_SK_USER_VERIFICATION_REQD) == 0) {
				error("public key %s signature for %s%s from "
				    "%.128s port %d rejected: user "
				    "verification requirement not met ", ಕೀಲಿ_s,
				    authctxt->valid ? "" : "invalid user ",
				    authctxt->user, ssh_remote_ipaddr(ssh),
				    ssh_remote_ಪೋರ್ಟ್(ssh));
				authenticated = 0;
				ಹೋಗು ಮುಗಿದ;
			}
		}
		auth2_ದಾಖಲೆ_ಕೀಲಿ(authctxt, authenticated, ಕೀಲಿ);
	} ಇಲ್ಲದಿದ್ದರೆ {
		debug_f("%s test pkalg %s pkblob %s%s%s", ವಿಧಾನ, pkalg, ಕೀಲಿ_s,
		    ca_s == ಖಾಲಿ ? "" : " CA ", ca_s == ಖಾಲಿ ? "" : ca_s);

		ಆದರೆ ((r = sshpkt_get_ಕೊನೆ(ssh)) != 0)
			fatal_fr(r, "parse packet");

		/* XXX fake reply and always send PK_OK ? */
		/*
		 * XXX this allows testing whether a user is allowed
		 * to login: if you happen to have a valid pubkey this
		 * message is sent. the message is NEVER sent at all
		 * if a user is not allowed to login. is this an
		 * issue? -markus
		 */
		ಆದರೆ (authctxt->valid && authctxt->user != ಖಾಲಿ &&
		    mm_user_ಕೀಲಿ_allowed(ssh, pw, ಕೀಲಿ, 0, ಖಾಲಿ)) {
			ಆದರೆ ((r = sshpkt_ಆರಂಭ(ssh, SSH2_ಸಂದೇಶ_USERAUTH_PK_OK))
			    != 0 ||
			    (r = sshpkt_put_cstring(ssh, pkalg)) != 0 ||
			    (r = sshpkt_put_stringb(ssh, keyblob)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0 ||
			    (r = ssh_packet_write_wait(ssh)) != 0)
				fatal_fr(r, "send packet");
			authctxt->postponed = 1;
		} ಇಲ್ಲದಿದ್ದರೆ {
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
			ಆದರೆ (authctxt->pk_ok_failures++ < options.max_pubkey_ok)
				authctxt->auth_failure_already_counted = 1;
			debug3_f("pubkey test %d of %d%s",
			    authctxt->pk_ok_failures, options.max_pubkey_ok,
			    authctxt->auth_failure_already_counted ?
			    "" : ": treating as authentication failure");
		 }
	}
ಮುಗಿದ:
	ಆದರೆ (authenticated == 1 && auth_activate_options(ssh, authopts) != 0) {
		debug_f("key options inconsistent with existing");
		authenticated = 0;
	}
	debug2_f("authenticated %d pkalg %s", authenticated, pkalg);

	sshbuf_free(b);
	sshbuf_free(keyblob);
	sshauthopt_free(authopts);
	sshkey_free(ಕೀಲಿ);
	sshkey_free(hostkey);
	ಬಿಡುಗಡೆ(keystring);
	ಬಿಡುಗಡೆ(userstyle);
	ಬಿಡುಗಡೆ(pkalg);
	ಬಿಡುಗಡೆ(ಕೀಲಿ_s);
	ಬಿಡುಗಡೆ(ca_s);
	ಬಿಡುಗಡೆ(sig);
	sshkey_sig_details_free(sig_details);
	ಹಿಂತಿರುಗಿ authenticated;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ಹೊಂದಿಕೆ_principals_file(ರಚನೆ passwd *pw, ಅಕ್ಷರ *file,
    ರಚನೆ sshkey_cert *cert, ರಚನೆ sshauthopt **authoptsp)
{
	FILE *f;
	ಪೂರ್ಣಾಂಕ r, success = 0;
	ಗಾತ್ರ_t i;
	glob_t gl;
	ರಚನೆ sshauthopt *opts = ಖಾಲಿ;

	ಆದರೆ (authoptsp != ಖಾಲಿ)
		*authoptsp = ಖಾಲಿ;

	temporarily_use_uid(pw);
	r = glob(file, 0, ಖಾಲಿ, &gl);
	restore_uid();
	ಆದರೆ (r != 0) {
		ಆದರೆ (r != GLOB_NOMATCH) {
			logit_f("glob \"%s\" failed", file);
		}
		ಹಿಂತಿರುಗಿ 0;
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (gl.gl_pathc > ಗರಿಷ್ಠ_ಪೂರ್ಣಾಂಕ) {
		fatal_f("too many glob results for \"%s\"", file);
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (gl.gl_pathc > 1) {
		debug2_f("glob \"%s\" returned %zu matches", file,
		    gl.gl_pathc);
	}
	ಗಾಗಿ (i = 0; !success && i < gl.gl_pathc; i++) {
		temporarily_use_uid(pw);
		debug("trying authorized principals file %s", file);
		ಆದರೆ ((f = auth_openprincipals(gl.gl_pathv[i], pw,
		    options.strict_modes)) == ಖಾಲಿ) {
			restore_uid();
			ಮುಂದುವರಿ;
		}
		success = auth_process_principals(f, gl.gl_pathv[i],
		    cert, &opts);
		fclose(f);
		restore_uid();
		ಆದರೆ (!success) {
			sshauthopt_free(opts);
			opts = ಖಾಲಿ;
		}
	}
	globfree(&gl);
	ಆದರೆ (success && authoptsp != ಖಾಲಿ) {
		*authoptsp = opts;
		opts = ಖಾಲಿ;
	}
	sshauthopt_free(opts);
	ಹಿಂತಿರುಗಿ success;
}

/*
 * Checks whether principal is allowed in output of command.
 * returns 1 if the principal is allowed or 0 otherwise.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ಹೊಂದಿಕೆ_principals_command(ರಚನೆ passwd *user_pw, ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *ಕೀಲಿ,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *conn_id, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *rdomain, ರಚನೆ sshauthopt **authoptsp)
{
	ರಚನೆ passwd *runas_pw = ಖಾಲಿ;
	ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey_cert *cert = ಕೀಲಿ->cert;
	FILE *f = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ r, ok, ಸಿಕ್ಕಿತು_principal = 0;
	ಪೂರ್ಣಾಂಕ i, ac = 0, uid_swapped = 0;
	pid_t pid;
	ಅಕ್ಷರ *tmp, *username = ಖಾಲಿ, *command = ಖಾಲಿ, **av = ಖಾಲಿ;
	ಅಕ್ಷರ *ca_fp = ಖಾಲಿ, *ಕೀಲಿ_fp = ಖಾಲಿ, *catext = ಖಾಲಿ, *keytext = ಖಾಲಿ;
	ಅಕ್ಷರ serial_s[32], uidstr[32];
	ಶೂನ್ಯ (*osigchld)(ಪೂರ್ಣಾಂಕ);

	ಆದರೆ (authoptsp != ಖಾಲಿ)
		*authoptsp = ಖಾಲಿ;
	ಆದರೆ (options.authorized_principals_command == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ 0;
	ಆದರೆ (options.authorized_principals_command_user == ಖಾಲಿ) {
		error("No user for AuthorizedPrincipalsCommand specified, "
		    "skipping");
		ಹಿಂತಿರುಗಿ 0;
	}

	/*
	 * NB. all returns later this function should go via "out" to
	 * ensure the original SIGCHLD handler is restored properly.
	 */
	osigchld = ssh_signal(SIGCHLD, SIG_DFL);

	/* Prepare and verify the user for the command */
	username = percent_expand(options.authorized_principals_command_user,
	    "u", user_pw->pw_name, (ಅಕ್ಷರ *)ಖಾಲಿ);
	runas_pw = getpwnam(username);
	ಆದರೆ (runas_pw == ಖಾಲಿ) {
		error("AuthorizedPrincipalsCommandUser \"%s\" not found: %s",
		    username, strerror(errno));
		ಹೋಗು ಹೊರಹೋಗು;
	}

	/* Turn the command into an argument vector */
	ಆದರೆ (argv_ವಿಭಜಿಸು(options.authorized_principals_command,
	    &ac, &av, 0) != 0) {
		error("AuthorizedPrincipalsCommand \"%s\" contains "
		    "invalid quotes", options.authorized_principals_command);
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (ac == 0) {
		error("AuthorizedPrincipalsCommand \"%s\" yielded no arguments",
		    options.authorized_principals_command);
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((ca_fp = sshkey_fingerprint(cert->signature_ಕೀಲಿ,
	    options.fingerprint_hash, SSH_FP_DEFAULT)) == ಖಾಲಿ) {
		error_f("sshkey_fingerprint failed");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((ಕೀಲಿ_fp = sshkey_fingerprint(ಕೀಲಿ,
	    options.fingerprint_hash, SSH_FP_DEFAULT)) == ಖಾಲಿ) {
		error_f("sshkey_fingerprint failed");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((r = sshkey_ಗಮ್ಯ_base64(cert->signature_ಕೀಲಿ, &catext)) != 0) {
		error_fr(r, "sshkey_to_base64 failed");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((r = sshkey_ಗಮ್ಯ_base64(ಕೀಲಿ, &keytext)) != 0) {
		error_fr(r, "sshkey_to_base64 failed");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	snprintf(serial_s, ಗಾತ್ರ(serial_s), "%llu",
	    (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)cert->serial);
	snprintf(uidstr, ಗಾತ್ರ(uidstr), "%llu",
	    (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)user_pw->pw_uid);
	ಗಾಗಿ (i = 1; i < ac; i++) {
		tmp = percent_expand(av[i],
		    "C", conn_id,
		    "D", rdomain,
		    "U", uidstr,
		    "u", user_pw->pw_name,
		    "h", user_pw->pw_dir,
		    "t", sshkey_ssh_name(ಕೀಲಿ),
		    "T", sshkey_ssh_name(cert->signature_ಕೀಲಿ),
		    "f", ಕೀಲಿ_fp,
		    "F", ca_fp,
		    "k", keytext,
		    "K", catext,
		    "i", cert->ಕೀಲಿ_id,
		    "s", serial_s,
		    (ಅಕ್ಷರ *)ಖಾಲಿ);
		ಆದರೆ (tmp == ಖಾಲಿ)
			fatal_f("percent_expand failed");
		ಬಿಡುಗಡೆ(av[i]);
		av[i] = tmp;
	}
	/* Prepare a printable command for logs, etc. */
	command = argv_assemble(ac, av);

	ಆದರೆ ((pid = subprocess("AuthorizedPrincipalsCommand", command,
	    ac, av, &f,
	    SSH_SUBPROCESS_STDOUT_CAPTURE|SSH_SUBPROCESS_STDERR_DISCARD,
	    runas_pw, temporarily_use_uid, restore_uid)) == 0)
		ಹೋಗು ಹೊರಹೋಗು;

	uid_swapped = 1;
	temporarily_use_uid(runas_pw);

	ok = auth_process_principals(f, "(command)", cert, authoptsp);

	fclose(f);
	f = ಖಾಲಿ;

	ಆದರೆ (exited_cleanly(pid, "AuthorizedPrincipalsCommand", command, 0) != 0)
		ಹೋಗು ಹೊರಹೋಗು;

	/* Read completed successfully */
	ಸಿಕ್ಕಿತು_principal = ok;
 ಹೊರಹೋಗು:
	ಆದರೆ (f != ಖಾಲಿ)
		fclose(f);
	ssh_signal(SIGCHLD, osigchld);
	ಗಾಗಿ (i = 0; i < ac; i++)
		ಬಿಡುಗಡೆ(av[i]);
	ಬಿಡುಗಡೆ(av);
	ಆದರೆ (uid_swapped)
		restore_uid();
	ಬಿಡುಗಡೆ(command);
	ಬಿಡುಗಡೆ(username);
	ಬಿಡುಗಡೆ(ca_fp);
	ಬಿಡುಗಡೆ(ಕೀಲಿ_fp);
	ಬಿಡುಗಡೆ(catext);
	ಬಿಡುಗಡೆ(keytext);
	ಹಿಂತಿರುಗಿ ಸಿಕ್ಕಿತು_principal;
}

/* Authenticate a certificate key against TrustedUserCAKeys */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
user_cert_trusted_ca(ರಚನೆ passwd *pw, ರಚನೆ sshkey *ಕೀಲಿ,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *remote_ip, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *remote_host,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *conn_id, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *rdomain, ರಚನೆ sshauthopt **authoptsp)
{
	ಅಕ್ಷರ *ca_fp, *principals_file = ಖಾಲಿ;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *reason;
	ರಚನೆ sshauthopt *principals_opts = ಖಾಲಿ, *cert_opts = ಖಾಲಿ;
	ರಚನೆ sshauthopt *final_opts = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ r, ret = 0, ಸಿಕ್ಕಿತು_principal = 0, use_authorized_principals;

	ಆದರೆ (authoptsp != ಖಾಲಿ)
		*authoptsp = ಖಾಲಿ;

	ಆದರೆ (!sshkey_is_cert(ಕೀಲಿ) || options.trusted_user_ca_ಕೀಲಿಗಳು == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ 0;

	ಆದರೆ ((ca_fp = sshkey_fingerprint(ಕೀಲಿ->cert->signature_ಕೀಲಿ,
	    options.fingerprint_hash, SSH_FP_DEFAULT)) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ 0;

	ಆದರೆ ((r = sshkey_ಒಳ_file(ಕೀಲಿ->cert->signature_ಕೀಲಿ,
	    options.trusted_user_ca_ಕೀಲಿಗಳು, 1, 0)) != 0) {
		debug2_fr(r, "CA %s %s is not listed in %s",
		    sshkey_type(ಕೀಲಿ->cert->signature_ಕೀಲಿ), ca_fp,
		    options.trusted_user_ca_ಕೀಲಿಗಳು);
		ಹೋಗು ಹೊರಹೋಗು;
	}
	/*
	 * If AuthorizedPrincipals is in use, then compare the certificate
	 * principals against the names in that file rather than matching
	 * against the username.
	 */
	ಆದರೆ ((principals_file = authorized_principals_file(pw)) != ಖಾಲಿ) {
		ಆದರೆ (ಹೊಂದಿಕೆ_principals_file(pw, principals_file,
		    ಕೀಲಿ->cert, &principals_opts))
			ಸಿಕ್ಕಿತು_principal = 1;
	}
	/* Try querying command if specified */
	ಆದರೆ (!ಸಿಕ್ಕಿತು_principal && ಹೊಂದಿಕೆ_principals_command(pw, ಕೀಲಿ,
	    conn_id, rdomain, &principals_opts))
		ಸಿಕ್ಕಿತು_principal = 1;
	/* If principals file or command is specified, then require a match */
	use_authorized_principals = principals_file != ಖಾಲಿ ||
	    options.authorized_principals_command != ಖಾಲಿ;
	ಆದರೆ (!ಸಿಕ್ಕಿತು_principal && use_authorized_principals) {
		reason = "Certificate does not contain an authorized principal";
		ಹೋಗು fail_reason;
	}
	ಆದರೆ (use_authorized_principals && principals_opts == ಖಾಲಿ)
		fatal_f("internal error: missing principals_opts");
	ಆದರೆ (sshkey_cert_check_authority_now(ಕೀಲಿ, 0, 0,
	    use_authorized_principals ? ಖಾಲಿ : pw->pw_name, &reason) != 0)
		ಹೋಗು fail_reason;

	/* Check authority from options in key and from principals file/cmd */
	ಆದರೆ ((cert_opts = sshauthopt_from_cert(ಕೀಲಿ)) == ಖಾಲಿ) {
		reason = "Invalid certificate options";
		ಹೋಗು fail_reason;
	}
	ಆದರೆ (auth_authorise_keyopts(pw, cert_opts, 0,
	    remote_ip, remote_host, "cert") != 0) {
		reason = "Refused by certificate options";
		ಹೋಗು fail_reason;
	}
	ಆದರೆ (principals_opts == ಖಾಲಿ) {
		final_opts = cert_opts;
		cert_opts = ಖಾಲಿ;
	} ಇಲ್ಲದಿದ್ದರೆ {
		ಆದರೆ (auth_authorise_keyopts(pw, principals_opts, 0,
		    remote_ip, remote_host, "principals") != 0) {
			reason = "Refused by certificate principals options";
			ಹೋಗು fail_reason;
		}
		ಆದರೆ ((final_opts = sshauthopt_ವಿಲೀನ(principals_opts,
		    cert_opts, &reason)) == ಖಾಲಿ) {
 fail_reason:
			error("Refusing certificate ID \"%s\" serial=%llu "
			    "signed by %s CA %s: %s", ಕೀಲಿ->cert->ಕೀಲಿ_id,
			    (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)ಕೀಲಿ->cert->serial,
			    sshkey_type(ಕೀಲಿ->cert->signature_ಕೀಲಿ), ca_fp,
			    reason);
			auth_debug_ಕೂಡಿಸು("Refused Certificate ID \"%s\" "
			    "serial=%llu: %s", ಕೀಲಿ->cert->ಕೀಲಿ_id,
			    (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)ಕೀಲಿ->cert->serial, reason);
			ಹೋಗು ಹೊರಹೋಗು;
		}
	}

	/* Success */
	verbose("Accepted certificate ID \"%s\" (serial %llu) signed by "
	    "%s CA %s via %s", ಕೀಲಿ->cert->ಕೀಲಿ_id,
	    (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)ಕೀಲಿ->cert->serial,
	    sshkey_type(ಕೀಲಿ->cert->signature_ಕೀಲಿ), ca_fp,
	    options.trusted_user_ca_ಕೀಲಿಗಳು);
	ಆದರೆ (authoptsp != ಖಾಲಿ) {
		*authoptsp = final_opts;
		final_opts = ಖಾಲಿ;
	}
	ret = 1;
 ಹೊರಹೋಗು:
	sshauthopt_free(principals_opts);
	sshauthopt_free(cert_opts);
	sshauthopt_free(final_opts);
	ಬಿಡುಗಡೆ(principals_file);
	ಬಿಡುಗಡೆ(ca_fp);
	ಹಿಂತಿರುಗಿ ret;
}

/*
 * Checks whether key is allowed in file.
 * returns 1 if the key is allowed or 0 otherwise.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
user_ಕೀಲಿ_allowed2(ರಚನೆ passwd *pw, ರಚನೆ sshkey *ಕೀಲಿ,
    ಅಕ್ಷರ *file, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *remote_ip, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *remote_host,
    ರಚನೆ sshauthopt **authoptsp)
{
	FILE *f;
	ಪೂರ್ಣಾಂಕ ಸಿಕ್ಕಿತು_ಕೀಲಿ = 0;

	ಆದರೆ (authoptsp != ಖಾಲಿ)
		*authoptsp = ಖಾಲಿ;

	/* Temporarily use the user's uid. */
	temporarily_use_uid(pw);

	debug("trying public key file %s", file);
	ಆದರೆ ((f = auth_openkeyfile(file, pw, options.strict_modes)) != ಖಾಲಿ) {
		ಸಿಕ್ಕಿತು_ಕೀಲಿ = auth_check_authkeys_file(pw, f, file,
		    ಕೀಲಿ, remote_ip, remote_host, authoptsp);
		fclose(f);
	}

	restore_uid();
	ಹಿಂತಿರುಗಿ ಸಿಕ್ಕಿತು_ಕೀಲಿ;
}

/*
 * Checks whether key is allowed in output of command.
 * returns 1 if the key is allowed or 0 otherwise.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
user_ಕೀಲಿ_command_allowed2(ರಚನೆ passwd *user_pw, ರಚನೆ sshkey *ಕೀಲಿ,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *remote_ip, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *remote_host,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *conn_id, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *rdomain, ರಚನೆ sshauthopt **authoptsp)
{
	ರಚನೆ passwd *runas_pw = ಖಾಲಿ;
	FILE *f = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ r, ok, ಸಿಕ್ಕಿತು_ಕೀಲಿ = 0;
	ಪೂರ್ಣಾಂಕ i, uid_swapped = 0, ac = 0;
	pid_t pid;
	ಅಕ್ಷರ *username = ಖಾಲಿ, *ಕೀಲಿ_fp = ಖಾಲಿ, *keytext = ಖಾಲಿ;
	ಅಕ್ಷರ uidstr[32], *tmp, *command = ಖಾಲಿ, **av = ಖಾಲಿ;
	ಶೂನ್ಯ (*osigchld)(ಪೂರ್ಣಾಂಕ);

	ಆದರೆ (authoptsp != ಖಾಲಿ)
		*authoptsp = ಖಾಲಿ;
	ಆದರೆ (options.authorized_ಕೀಲಿಗಳು_command == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ 0;
	ಆದರೆ (options.authorized_ಕೀಲಿಗಳು_command_user == ಖಾಲಿ) {
		error("No user for AuthorizedKeysCommand specified, skipping");
		ಹಿಂತಿರುಗಿ 0;
	}

	/*
	 * NB. all returns later this function should go via "out" to
	 * ensure the original SIGCHLD handler is restored properly.
	 */
	osigchld = ssh_signal(SIGCHLD, SIG_DFL);

	/* Prepare and verify the user for the command */
	username = percent_expand(options.authorized_ಕೀಲಿಗಳು_command_user,
	    "u", user_pw->pw_name, (ಅಕ್ಷರ *)ಖಾಲಿ);
	runas_pw = getpwnam(username);
	ಆದರೆ (runas_pw == ಖಾಲಿ) {
		error("AuthorizedKeysCommandUser \"%s\" not found: %s",
		    username, strerror(errno));
		ಹೋಗು ಹೊರಹೋಗು;
	}

	/* Prepare AuthorizedKeysCommand */
	ಆದರೆ ((ಕೀಲಿ_fp = sshkey_fingerprint(ಕೀಲಿ, options.fingerprint_hash,
	    SSH_FP_DEFAULT)) == ಖಾಲಿ) {
		error_f("sshkey_fingerprint failed");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((r = sshkey_ಗಮ್ಯ_base64(ಕೀಲಿ, &keytext)) != 0) {
		error_fr(r, "sshkey_to_base64 failed");
		ಹೋಗು ಹೊರಹೋಗು;
	}

	/* Turn the command into an argument vector */
	ಆದರೆ (argv_ವಿಭಜಿಸು(options.authorized_ಕೀಲಿಗಳು_command, &ac, &av, 0) != 0) {
		error("AuthorizedKeysCommand \"%s\" contains invalid quotes",
		    options.authorized_ಕೀಲಿಗಳು_command);
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (ac == 0) {
		error("AuthorizedKeysCommand \"%s\" yielded no arguments",
		    options.authorized_ಕೀಲಿಗಳು_command);
		ಹೋಗು ಹೊರಹೋಗು;
	}
	snprintf(uidstr, ಗಾತ್ರ(uidstr), "%llu",
	    (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)user_pw->pw_uid);
	ಗಾಗಿ (i = 1; i < ac; i++) {
		tmp = percent_expand(av[i],
		    "C", conn_id,
		    "D", rdomain,
		    "U", uidstr,
		    "u", user_pw->pw_name,
		    "h", user_pw->pw_dir,
		    "t", sshkey_ssh_name(ಕೀಲಿ),
		    "f", ಕೀಲಿ_fp,
		    "k", keytext,
		    (ಅಕ್ಷರ *)ಖಾಲಿ);
		ಆದರೆ (tmp == ಖಾಲಿ)
			fatal_f("percent_expand failed");
		ಬಿಡುಗಡೆ(av[i]);
		av[i] = tmp;
	}
	/* Prepare a printable command for logs, etc. */
	command = argv_assemble(ac, av);

	/*
	 * If AuthorizedKeysCommand was run without arguments
	 * then fall back to the old behaviour of passing the
	 * target username as a single argument.
	 */
	ಆದರೆ (ac == 1) {
		av = xreallocarray(av, ac + 2, ಗಾತ್ರ(*av));
		av[1] = xstrdup(user_pw->pw_name);
		av[2] = ಖಾಲಿ;
		/* Fix up command too, since it is used in log messages */
		ಬಿಡುಗಡೆ(command);
		xasprintf(&command, "%s %s", av[0], av[1]);
	}

	ಆದರೆ ((pid = subprocess("AuthorizedKeysCommand", command,
	    ac, av, &f,
	    SSH_SUBPROCESS_STDOUT_CAPTURE|SSH_SUBPROCESS_STDERR_DISCARD,
	    runas_pw, temporarily_use_uid, restore_uid)) == 0)
		ಹೋಗು ಹೊರಹೋಗು;

	uid_swapped = 1;
	temporarily_use_uid(runas_pw);

	ok = auth_check_authkeys_file(user_pw, f,
	    options.authorized_ಕೀಲಿಗಳು_command, ಕೀಲಿ, remote_ip,
	    remote_host, authoptsp);

	fclose(f);
	f = ಖಾಲಿ;

	ಆದರೆ (exited_cleanly(pid, "AuthorizedKeysCommand", command, 0) != 0)
		ಹೋಗು ಹೊರಹೋಗು;

	/* Read completed successfully */
	ಸಿಕ್ಕಿತು_ಕೀಲಿ = ok;
 ಹೊರಹೋಗು:
	ಆದರೆ (f != ಖಾಲಿ)
		fclose(f);
	ssh_signal(SIGCHLD, osigchld);
	ಗಾಗಿ (i = 0; i < ac; i++)
		ಬಿಡುಗಡೆ(av[i]);
	ಬಿಡುಗಡೆ(av);
	ಆದರೆ (uid_swapped)
		restore_uid();
	ಬಿಡುಗಡೆ(command);
	ಬಿಡುಗಡೆ(username);
	ಬಿಡುಗಡೆ(ಕೀಲಿ_fp);
	ಬಿಡುಗಡೆ(keytext);
	ಹಿಂತಿರುಗಿ ಸಿಕ್ಕಿತು_ಕೀಲಿ;
}

/*
 * Check whether key authenticates and authorises the user.
 */
ಪೂರ್ಣಾಂಕ
user_ಕೀಲಿ_allowed(ರಚನೆ ssh *ssh, ರಚನೆ passwd *pw, ರಚನೆ sshkey *ಕೀಲಿ,
    ಪೂರ್ಣಾಂಕ auth_attempt, ರಚನೆ sshauthopt **authoptsp)
{
	u_int success = 0, i, j;
	ಅಕ್ಷರ *file = ಖಾಲಿ, *conn_id;
	ರಚನೆ sshauthopt *opts = ಖಾಲಿ;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *rdomain, *remote_ip, *remote_host;

	ಆದರೆ (authoptsp != ಖಾಲಿ)
		*authoptsp = ಖಾಲಿ;

	ಆದರೆ (auth_ಕೀಲಿ_is_revoked(ಕೀಲಿ))
		ಹಿಂತಿರುಗಿ 0;
	ಆದರೆ (sshkey_is_cert(ಕೀಲಿ) &&
	    auth_ಕೀಲಿ_is_revoked(ಕೀಲಿ->cert->signature_ಕೀಲಿ))
		ಹಿಂತಿರುಗಿ 0;

	ಆದರೆ ((rdomain = ssh_packet_rdomain_ಒಳ(ssh)) == ಖಾಲಿ)
		rdomain = "";
	remote_ip = ssh_remote_ipaddr(ssh);
	remote_host = auth_get_canonical_hostname(ssh, options.use_dns);
	xasprintf(&conn_id, "%s %d %s %d",
	    ssh_local_ipaddr(ssh), ssh_local_ಪೋರ್ಟ್(ssh),
	    remote_ip, ssh_remote_ಪೋರ್ಟ್(ssh));

	ಗಾಗಿ (i = 0; !success && i < options.ಅಂಕೆ_authkeys_files; i++) {
		ಪೂರ್ಣಾಂಕ r;
		glob_t gl;

		ಆದರೆ (strcasecmp(options.authorized_ಕೀಲಿಗಳು_files[i], "none") == 0)
			ಮುಂದುವರಿ;
		file = expand_authorized_ಕೀಲಿಗಳು(
		    options.authorized_ಕೀಲಿಗಳು_files[i], pw);
		temporarily_use_uid(pw);
		r = glob(file, 0, ಖಾಲಿ, &gl);
		restore_uid();
		ಆದರೆ (r != 0) {
			ಆದರೆ (r != GLOB_NOMATCH) {
				logit_f("glob \"%s\" failed", file);
			}
			ಬಿಡುಗಡೆ(file);
			file = ಖಾಲಿ;
			ಮುಂದುವರಿ;
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (gl.gl_pathc > ಗರಿಷ್ಠ_ಪೂರ್ಣಾಂಕ) {
			fatal_f("too many glob results for \"%s\"", file);
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (gl.gl_pathc > 1) {
			debug2_f("glob \"%s\" returned %zu matches", file,
			    gl.gl_pathc);
		}
		ಗಾಗಿ (j = 0; !success && j < gl.gl_pathc; j++) {
			success = user_ಕೀಲಿ_allowed2(pw, ಕೀಲಿ, gl.gl_pathv[j],
			    remote_ip, remote_host, &opts);
			ಆದರೆ (!success) {
				sshauthopt_free(opts);
				opts = ಖಾಲಿ;
			}
		}
		ಬಿಡುಗಡೆ(file);
		file = ಖಾಲಿ;
		globfree(&gl);
	}
	ಆದರೆ (success)
		ಹೋಗು ಹೊರಹೋಗು;

	ಆದರೆ ((success = user_cert_trusted_ca(pw, ಕೀಲಿ, remote_ip, remote_host,
	    conn_id, rdomain, &opts)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	sshauthopt_free(opts);
	opts = ಖಾಲಿ;

	ಆದರೆ ((success = user_ಕೀಲಿ_command_allowed2(pw, ಕೀಲಿ, remote_ip,
	    remote_host, conn_id, rdomain, &opts)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	sshauthopt_free(opts);
	opts = ಖಾಲಿ;

 ಹೊರಹೋಗು:
	ಬಿಡುಗಡೆ(conn_id);
	ಆದರೆ (success && authoptsp != ಖಾಲಿ) {
		*authoptsp = opts;
		opts = ಖಾಲಿ;
	}
	sshauthopt_free(opts);
	ಹಿಂತಿರುಗಿ success;
}

Authmethod ವಿಧಾನ_pubkey = {
	&methodcfg_pubkey,
	userauth_pubkey,
};
