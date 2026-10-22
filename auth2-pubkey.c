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
#ifdef GSSAPI
#ಅನ್ತರ್ಭಾವ "ssh-gss.h"
#endif
#ಅನ್ತರ್ಭಾವ "monitor_wrap.h"
#ಅನ್ತರ್ಭಾವ "authfile.h"
#ಅನ್ತರ್ಭಾವ "match.h"
#ಅನ್ತರ್ಭಾವ "ssherr.h"
#ಅನ್ತರ್ಭಾವ "channels.h" /* XXX for session.h */
#ಅನ್ತರ್ಭಾವ "session.h" /* XXX for child_set_env(); refactor? */
#ಅನ್ತರ್ಭಾವ "sk-api.h"

/* import */
ಬಾಹ್ಯ ServerOptions options;
ಬಾಹ್ಯ ಸಂರಚನಾ authmethod_cfg methodcfg_pubkey;

ಸ್ಥಿರ ವರ್ಣ *
format_ಕೀಲಿ(ಧ್ರುವ ಸಂರಚನಾ sshkey *ಕೀಲಿ)
{
	ವರ್ಣ *ret, *fp = sshkey_fingerprint(ಕೀಲಿ,
	    options.fingerprint_hash, SSH_FP_DEFAULT);

	xasprintf(&ret, "%s %s", sshkey_type(ಕೀಲಿ), fp);
	ಮುಕ್ತ(fp);
	ಪ್ರತ್ಯಾಗಮ ret;
}

/*
 * Verify that the hostkey in a publickey-hostbound-v00@openssh.com userauth
 * request matches the hostkey that was negotiated during initial KEX.
 */
ಸ್ಥಿರ ಶೂನ್ಯ
check_hostbound_hostkey(ಸಂರಚನಾ ssh *ssh)
{
	ಪೂರ್ಣಾಙ್ಕ r;
	ಸಂರಚನಾ sshbuf *our_hostkey_blob, *their_hostkey_blob;

	ಯದಿ (ssh->kex->initial_hostkey == ರಿಕ್ತ)
		fatal_f("internal error: initial hostkey not recorded");
	ಯದಿ ((our_hostkey_blob = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new failed");
	ಯದಿ ((r = sshpkt_getb_froms(ssh, &their_hostkey_blob)) != 0)
		fatal_fr(r, "parse hostkey");
	ಯದಿ ((r = sshkey_putb(ssh->kex->initial_hostkey, our_hostkey_blob)) != 0)
		fatal_fr(r, "serialise hostkey");
	ಯದಿ ((r = sshbuf_equals(our_hostkey_blob, their_hostkey_blob)) != 0)
		fatal_f("packet contained wrong host key");
	sshbuf_free(our_hostkey_blob);
	sshbuf_free(their_hostkey_blob);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
userauth_pubkey(ಸಂರಚನಾ ssh *ssh, ಧ್ರುವ ವರ್ಣ *method)
{
	Authctxt *authctxt = ssh->authctxt;
	ಸಂರಚನಾ passwd *pw = authctxt->pw;
	ಸಂರಚನಾ sshbuf *keyblob = ರಿಕ್ತ, *b = ರಿಕ್ತ;
	ಸಂರಚನಾ sshkey *ಕೀಲಿ = ರಿಕ್ತ, *hostkey = ರಿಕ್ತ;
	ವರ್ಣ *pkalg = ರಿಕ್ತ, *userstyle = ರಿಕ್ತ, *ಕೀಲಿ_s = ರಿಕ್ತ, *ca_s = ರಿಕ್ತ;
	ವರ್ಣ *keystring = ರಿಕ್ತ;
	u_char *sig = ರಿಕ್ತ, have_sig;
	size_t slen;
	ಪೂರ್ಣಾಙ್ಕ hostbound, r, pktype;
	ಪೂರ್ಣಾಙ್ಕ req_presence = 0, req_verify = 0, authenticated = 0;
	ಸಂರಚನಾ sshauthopt *authopts = ರಿಕ್ತ;
	ಸಂರಚನಾ sshkey_sig_details *sig_details = ರಿಕ್ತ;

	hostbound = strcmp(method, "publickey-hostbound-v00@openssh.com") == 0;

	ಯದಿ ((r = sshpkt_get_u8(ssh, &have_sig)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &pkalg, ರಿಕ್ತ)) != 0 ||
	    (r = sshpkt_getb_froms(ssh, &keyblob)) != 0)
		fatal_fr(r, "parse %s packet", method);

	/* hostbound auth includes the hostkey offered at initial KEX */
	ಯದಿ (hostbound)
		check_hostbound_hostkey(ssh); /* fatals on error */

	ಯದಿ (log_level_get() >= SYSLOG_LEVEL_DEBUG2) {
		ಯದಿ ((b = sshbuf_fromb(keyblob)) == ರಿಕ್ತ)
			fatal_f("sshbuf_fromb failed");
		ಯದಿ ((keystring = sshbuf_dtob64_string(b, 0)) == ರಿಕ್ತ)
			fatal_f("sshbuf_dtob64 failed");
		debug2_f("%s user %s %s public key %s %s",
		    authctxt->valid ? "valid" : "invalid", authctxt->user,
		    have_sig ? "attempting" : "querying", pkalg, keystring);
		sshbuf_free(b);
		b = ರಿಕ್ತ;
	}

	pktype = sshkey_type_from_name(pkalg);
	ಯದಿ (pktype == ಕೀಲಿ_UNSPEC) {
		/* this is perfectly legal */
		verbose_f("unsupported public key algorithm: %s", pkalg);
		ಗಚ್ಛ done;
	}
	ಯದಿ (match_pattern_list(pkalg, options.pubkey_accepted_algos, 0) != 1) {
		logit_f("signature algorithm %s not in "
		    "PubkeyAcceptedAlgorithms", pkalg);
		ಗಚ್ಛ done;
	}
	ಯದಿ ((b = sshbuf_fromb(keyblob)) == ರಿಕ್ತ)
		fatal_f("sshbuf_fromb failed");
	ವಿಕಲ್ಪ ((r = sshkey_fromb_allowlist(b, &ಕೀಲಿ,
	    options.pubkey_accepted_algos, options.ca_sign_algorithms))) {
	ಪಕ್ಷ 0:
		/* ok */
		ಭಙ್ಗ;
	ಪಕ್ಷ SSH_ERR_ಕೀಲಿ_ALG_UNSUPPORTED:
		/* This shouldn't happen unless the client is being weird */
		logit_f("key algorithm differs from signature algorithm %s and "
		    "is not in PubkeyAcceptedAlgorithms", pkalg);
		ಗಚ್ಛ done;
	ಪಕ್ಷ SSH_ERR_SIGN_ALG_UNSUPPORTED:
		logit_fr(r, "certificate signature algorithm not in "
		    "CASignatureAlgorithm");
		ಗಚ್ಛ done;
	ಸ್ವಭಾವ:
		error_fr(r, "parse key");
		ಗಚ್ಛ done;
	}
	sshbuf_free(b);
	b = ರಿಕ್ತ;

	/* USERAUTH_REQUEST signature type should match key's type */
	ಯದಿ (ಕೀಲಿ->type != pktype || (sshkey_type_plain(pktype) == ಕೀಲಿ_ECDSA &&
	    sshkey_ecdsa_nid_from_name(pkalg) != ಕೀಲಿ->ecdsa_nid)) {
		error_f("key type mismatch for decoded key "
		    "(received %s, expected %s)", sshkey_ssh_name(ಕೀಲಿ), pkalg);
		ಗಚ್ಛ done;
	}
	ಯದಿ (auth2_ಕೀಲಿ_already_used(authctxt, ಕೀಲಿ)) {
		logit("refusing previously-used %s key", sshkey_type(ಕೀಲಿ));
		ಗಚ್ಛ done;
	}
	ಯದಿ ((r = sshkey_check_rsa_length(ಕೀಲಿ,
	    options.required_rsa_size)) != 0) {
		logit_r(r, "refusing %s key", sshkey_type(ಕೀಲಿ));
		ಗಚ್ಛ done;
	}
	ಕೀಲಿ_s = format_ಕೀಲಿ(ಕೀಲಿ);
	ಯದಿ (sshkey_is_cert(ಕೀಲಿ))
		ca_s = format_ಕೀಲಿ(ಕೀಲಿ->cert->signature_ಕೀಲಿ);

	ಯದಿ (have_sig) {
		debug3_f("%s have %s signature for %s%s%s",
		    method, pkalg, ಕೀಲಿ_s,
		    ca_s == ರಿಕ್ತ ? "" : " CA ", ca_s == ರಿಕ್ತ ? "" : ca_s);
		ಯದಿ ((r = sshpkt_get_string(ssh, &sig, &slen)) != 0 ||
		    (r = sshpkt_get_end(ssh)) != 0)
			fatal_fr(r, "parse signature packet");
		ಯದಿ ((b = sshbuf_new()) == ರಿಕ್ತ)
			fatal_f("sshbuf_new failed");
		ಯದಿ ((r = sshbuf_put_stringb(b,
		    ssh->kex->session_id)) != 0)
			fatal_fr(r, "put session id");
		ಯದಿ (!authctxt->valid || authctxt->user == ರಿಕ್ತ) {
			debug2_f("disabled because of invalid user");
			ಗಚ್ಛ done;
		}
		/* reconstruct packet */
		xasprintf(&userstyle, "%s%s%s", authctxt->user,
		    authctxt->style ? ":" : "",
		    authctxt->style ? authctxt->style : "");
		ಯದಿ ((r = sshbuf_put_u8(b, SSH2_ಸಂದೇಶ_USERAUTH_REQUEST)) != 0 ||
		    (r = sshbuf_put_cstring(b, userstyle)) != 0 ||
		    (r = sshbuf_put_cstring(b, authctxt->service)) != 0 ||
		    (r = sshbuf_put_cstring(b, method)) != 0 ||
		    (r = sshbuf_put_u8(b, have_sig)) != 0 ||
		    (r = sshbuf_put_cstring(b, pkalg)) != 0 ||
		    (r = sshbuf_put_stringb(b, keyblob)) != 0)
			fatal_fr(r, "reconstruct %s packet", method);
		ಯದಿ (hostbound &&
		    (r = sshkey_puts(ssh->kex->initial_hostkey, b)) != 0)
			fatal_fr(r, "reconstruct %s packet", method);
#ifdef DEBUG_PK
		sshbuf_dump(b, stderr);
#endif
		/* test for correct signature */
		authenticated = 0;
		ಯದಿ (mm_user_ಕೀಲಿ_allowed(ssh, pw, ಕೀಲಿ, 1, &authopts) &&
		    mm_sshkey_verify(ಕೀಲಿ, sig, slen,
		    sshbuf_ptr(b), sshbuf_len(b),
		    (ssh->compat & SSH_BUG_SIGTYPE) == 0 ? pkalg : ರಿಕ್ತ,
		    ssh->compat, &sig_details) == 0) {
			authenticated = 1;
		}
		ಯದಿ (authenticated == 1 && sig_details != ರಿಕ್ತ) {
			auth2_record_info(authctxt, "signature count = %u",
			    sig_details->sk_counter);
			debug_f("sk_counter = %u, sk_flags = 0x%02x",
			    sig_details->sk_counter, sig_details->sk_flags);
			req_presence = (options.pubkey_auth_options &
			    PUBKEYAUTH_TOUCH_REQUIRED) ||
			    !authopts->no_require_user_presence;
			ಯದಿ (req_presence && (sig_details->sk_flags &
			    SSH_SK_USER_PRESENCE_REQD) == 0) {
				error("public key %s signature for %s%s from "
				    "%.128s port %d rejected: user presence "
				    "(authenticator touch) requirement "
				    "not met ", ಕೀಲಿ_s,
				    authctxt->valid ? "" : "invalid user ",
				    authctxt->user, ssh_remote_ipaddr(ssh),
				    ssh_remote_port(ssh));
				authenticated = 0;
				ಗಚ್ಛ done;
			}
			req_verify = (options.pubkey_auth_options &
			    PUBKEYAUTH_VERIFY_REQUIRED) ||
			    authopts->require_verify;
			ಯದಿ (req_verify && (sig_details->sk_flags &
			    SSH_SK_USER_VERIFICATION_REQD) == 0) {
				error("public key %s signature for %s%s from "
				    "%.128s port %d rejected: user "
				    "verification requirement not met ", ಕೀಲಿ_s,
				    authctxt->valid ? "" : "invalid user ",
				    authctxt->user, ssh_remote_ipaddr(ssh),
				    ssh_remote_port(ssh));
				authenticated = 0;
				ಗಚ್ಛ done;
			}
		}
		auth2_record_ಕೀಲಿ(authctxt, authenticated, ಕೀಲಿ);
	} ಅನ್ಯಥಾ {
		debug_f("%s test pkalg %s pkblob %s%s%s", method, pkalg, ಕೀಲಿ_s,
		    ca_s == ರಿಕ್ತ ? "" : " CA ", ca_s == ರಿಕ್ತ ? "" : ca_s);

		ಯದಿ ((r = sshpkt_get_end(ssh)) != 0)
			fatal_fr(r, "parse packet");

		/* XXX fake reply and always send PK_OK ? */
		/*
		 * XXX this allows testing whether a user is allowed
		 * to login: if you happen to have a valid pubkey this
		 * message is sent. the message is NEVER sent at all
		 * if a user is not allowed to login. is this an
		 * issue? -markus
		 */
		ಯದಿ (authctxt->valid && authctxt->user != ರಿಕ್ತ &&
		    mm_user_ಕೀಲಿ_allowed(ssh, pw, ಕೀಲಿ, 0, ರಿಕ್ತ)) {
			ಯದಿ ((r = sshpkt_start(ssh, SSH2_ಸಂದೇಶ_USERAUTH_PK_OK))
			    != 0 ||
			    (r = sshpkt_put_cstring(ssh, pkalg)) != 0 ||
			    (r = sshpkt_put_stringb(ssh, keyblob)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0 ||
			    (r = ssh_packet_write_wait(ssh)) != 0)
				fatal_fr(r, "send packet");
			authctxt->postponed = 1;
		} ಅನ್ಯಥಾ {
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
			ಯದಿ (authctxt->pk_ok_failures++ < options.max_pubkey_ok)
				authctxt->auth_failure_already_counted = 1;
			debug3_f("pubkey test %d of %d%s",
			    authctxt->pk_ok_failures, options.max_pubkey_ok,
			    authctxt->auth_failure_already_counted ?
			    "" : ": treating as authentication failure");
		 }
	}
done:
	ಯದಿ (authenticated == 1 && auth_activate_options(ssh, authopts) != 0) {
		debug_f("key options inconsistent with existing");
		authenticated = 0;
	}
	debug2_f("authenticated %d pkalg %s", authenticated, pkalg);

	sshbuf_free(b);
	sshbuf_free(keyblob);
	sshauthopt_free(authopts);
	sshkey_free(ಕೀಲಿ);
	sshkey_free(hostkey);
	ಮುಕ್ತ(keystring);
	ಮುಕ್ತ(userstyle);
	ಮುಕ್ತ(pkalg);
	ಮುಕ್ತ(ಕೀಲಿ_s);
	ಮುಕ್ತ(ca_s);
	ಮುಕ್ತ(sig);
	sshkey_sig_details_free(sig_details);
	ಪ್ರತ್ಯಾಗಮ authenticated;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
match_principals_file(ಸಂರಚನಾ passwd *pw, ವರ್ಣ *file,
    ಸಂರಚನಾ sshkey_cert *cert, ಸಂರಚನಾ sshauthopt **authoptsp)
{
	FILE *f;
	ಪೂರ್ಣಾಙ್ಕ r, success = 0;
	size_t i;
	glob_t gl;
	ಸಂರಚನಾ sshauthopt *opts = ರಿಕ್ತ;

	ಯದಿ (authoptsp != ರಿಕ್ತ)
		*authoptsp = ರಿಕ್ತ;

	temporarily_use_uid(pw);
	r = glob(file, 0, ರಿಕ್ತ, &gl);
	restore_uid();
	ಯದಿ (r != 0) {
		ಯದಿ (r != GLOB_NOMATCH) {
			logit_f("glob \"%s\" failed", file);
		}
		ಪ್ರತ್ಯಾಗಮ 0;
	} ಅನ್ಯಥಾ ಯದಿ (gl.gl_pathc > INT_MAX) {
		fatal_f("too many glob results for \"%s\"", file);
	} ಅನ್ಯಥಾ ಯದಿ (gl.gl_pathc > 1) {
		debug2_f("glob \"%s\" returned %zu matches", file,
		    gl.gl_pathc);
	}
	ಪ್ರತಿ (i = 0; !success && i < gl.gl_pathc; i++) {
		temporarily_use_uid(pw);
		debug("trying authorized principals file %s", file);
		ಯದಿ ((f = auth_openprincipals(gl.gl_pathv[i], pw,
		    options.strict_modes)) == ರಿಕ್ತ) {
			restore_uid();
			ಅನುವರ್ತ;
		}
		success = auth_process_principals(f, gl.gl_pathv[i],
		    cert, &opts);
		fclose(f);
		restore_uid();
		ಯದಿ (!success) {
			sshauthopt_free(opts);
			opts = ರಿಕ್ತ;
		}
	}
	globfree(&gl);
	ಯದಿ (success && authoptsp != ರಿಕ್ತ) {
		*authoptsp = opts;
		opts = ರಿಕ್ತ;
	}
	sshauthopt_free(opts);
	ಪ್ರತ್ಯಾಗಮ success;
}

/*
 * Checks whether principal is allowed in output of command.
 * returns 1 if the principal is allowed or 0 otherwise.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
match_principals_command(ಸಂರಚನಾ passwd *user_pw, ಧ್ರುವ ಸಂರಚನಾ sshkey *ಕೀಲಿ,
    ಧ್ರುವ ವರ್ಣ *conn_id, ಧ್ರುವ ವರ್ಣ *rdomain, ಸಂರಚನಾ sshauthopt **authoptsp)
{
	ಸಂರಚನಾ passwd *runas_pw = ರಿಕ್ತ;
	ಧ್ರುವ ಸಂರಚನಾ sshkey_cert *cert = ಕೀಲಿ->cert;
	FILE *f = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ r, ok, found_principal = 0;
	ಪೂರ್ಣಾಙ್ಕ i, ac = 0, uid_swapped = 0;
	pid_t pid;
	ವರ್ಣ *tmp, *username = ರಿಕ್ತ, *command = ರಿಕ್ತ, **av = ರಿಕ್ತ;
	ವರ್ಣ *ca_fp = ರಿಕ್ತ, *ಕೀಲಿ_fp = ರಿಕ್ತ, *catext = ರಿಕ್ತ, *keytext = ರಿಕ್ತ;
	ವರ್ಣ serial_s[32], uidstr[32];
	ಶೂನ್ಯ (*osigchld)(ಪೂರ್ಣಾಙ್ಕ);

	ಯದಿ (authoptsp != ರಿಕ್ತ)
		*authoptsp = ರಿಕ್ತ;
	ಯದಿ (options.authorized_principals_command == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಯದಿ (options.authorized_principals_command_user == ರಿಕ್ತ) {
		error("No user for AuthorizedPrincipalsCommand specified, "
		    "skipping");
		ಪ್ರತ್ಯಾಗಮ 0;
	}

	/*
	 * NB. all returns later this function should go via "out" to
	 * ensure the original SIGCHLD handler is restored properly.
	 */
	osigchld = ssh_signal(SIGCHLD, SIG_DFL);

	/* Prepare and verify the user for the command */
	username = percent_expand(options.authorized_principals_command_user,
	    "u", user_pw->pw_name, (ವರ್ಣ *)ರಿಕ್ತ);
	runas_pw = getpwnam(username);
	ಯದಿ (runas_pw == ರಿಕ್ತ) {
		error("AuthorizedPrincipalsCommandUser \"%s\" not found: %s",
		    username, strerror(errno));
		ಗಚ್ಛ out;
	}

	/* Turn the command into an argument vector */
	ಯದಿ (argv_split(options.authorized_principals_command,
	    &ac, &av, 0) != 0) {
		error("AuthorizedPrincipalsCommand \"%s\" contains "
		    "invalid quotes", options.authorized_principals_command);
		ಗಚ್ಛ out;
	}
	ಯದಿ (ac == 0) {
		error("AuthorizedPrincipalsCommand \"%s\" yielded no arguments",
		    options.authorized_principals_command);
		ಗಚ್ಛ out;
	}
	ಯದಿ ((ca_fp = sshkey_fingerprint(cert->signature_ಕೀಲಿ,
	    options.fingerprint_hash, SSH_FP_DEFAULT)) == ರಿಕ್ತ) {
		error_f("sshkey_fingerprint failed");
		ಗಚ್ಛ out;
	}
	ಯದಿ ((ಕೀಲಿ_fp = sshkey_fingerprint(ಕೀಲಿ,
	    options.fingerprint_hash, SSH_FP_DEFAULT)) == ರಿಕ್ತ) {
		error_f("sshkey_fingerprint failed");
		ಗಚ್ಛ out;
	}
	ಯದಿ ((r = sshkey_to_base64(cert->signature_ಕೀಲಿ, &catext)) != 0) {
		error_fr(r, "sshkey_to_base64 failed");
		ಗಚ್ಛ out;
	}
	ಯದಿ ((r = sshkey_to_base64(ಕೀಲಿ, &keytext)) != 0) {
		error_fr(r, "sshkey_to_base64 failed");
		ಗಚ್ಛ out;
	}
	snprintf(serial_s, ಪರಿಮಾಣ(serial_s), "%llu",
	    (unsigned long long)cert->serial);
	snprintf(uidstr, ಪರಿಮಾಣ(uidstr), "%llu",
	    (unsigned long long)user_pw->pw_uid);
	ಪ್ರತಿ (i = 1; i < ac; i++) {
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
		    (ವರ್ಣ *)ರಿಕ್ತ);
		ಯದಿ (tmp == ರಿಕ್ತ)
			fatal_f("percent_expand failed");
		ಮುಕ್ತ(av[i]);
		av[i] = tmp;
	}
	/* Prepare a printable command for logs, etc. */
	command = argv_assemble(ac, av);

	ಯದಿ ((pid = subprocess("AuthorizedPrincipalsCommand", command,
	    ac, av, &f,
	    SSH_SUBPROCESS_STDOUT_CAPTURE|SSH_SUBPROCESS_STDERR_DISCARD,
	    runas_pw, temporarily_use_uid, restore_uid)) == 0)
		ಗಚ್ಛ out;

	uid_swapped = 1;
	temporarily_use_uid(runas_pw);

	ok = auth_process_principals(f, "(command)", cert, authoptsp);

	fclose(f);
	f = ರಿಕ್ತ;

	ಯದಿ (exited_cleanly(pid, "AuthorizedPrincipalsCommand", command, 0) != 0)
		ಗಚ್ಛ out;

	/* Read completed successfully */
	found_principal = ok;
 out:
	ಯದಿ (f != ರಿಕ್ತ)
		fclose(f);
	ssh_signal(SIGCHLD, osigchld);
	ಪ್ರತಿ (i = 0; i < ac; i++)
		ಮುಕ್ತ(av[i]);
	ಮುಕ್ತ(av);
	ಯದಿ (uid_swapped)
		restore_uid();
	ಮುಕ್ತ(command);
	ಮುಕ್ತ(username);
	ಮುಕ್ತ(ca_fp);
	ಮುಕ್ತ(ಕೀಲಿ_fp);
	ಮುಕ್ತ(catext);
	ಮುಕ್ತ(keytext);
	ಪ್ರತ್ಯಾಗಮ found_principal;
}

/* Authenticate a certificate key against TrustedUserCAKeys */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
user_cert_trusted_ca(ಸಂರಚನಾ passwd *pw, ಸಂರಚನಾ sshkey *ಕೀಲಿ,
    ಧ್ರುವ ವರ್ಣ *remote_ip, ಧ್ರುವ ವರ್ಣ *remote_host,
    ಧ್ರುವ ವರ್ಣ *conn_id, ಧ್ರುವ ವರ್ಣ *rdomain, ಸಂರಚನಾ sshauthopt **authoptsp)
{
	ವರ್ಣ *ca_fp, *principals_file = ರಿಕ್ತ;
	ಧ್ರುವ ವರ್ಣ *reason;
	ಸಂರಚನಾ sshauthopt *principals_opts = ರಿಕ್ತ, *cert_opts = ರಿಕ್ತ;
	ಸಂರಚನಾ sshauthopt *final_opts = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ r, ret = 0, found_principal = 0, use_authorized_principals;

	ಯದಿ (authoptsp != ರಿಕ್ತ)
		*authoptsp = ರಿಕ್ತ;

	ಯದಿ (!sshkey_is_cert(ಕೀಲಿ) || options.trusted_user_ca_ಕೀಲಿಗಳು == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ 0;

	ಯದಿ ((ca_fp = sshkey_fingerprint(ಕೀಲಿ->cert->signature_ಕೀಲಿ,
	    options.fingerprint_hash, SSH_FP_DEFAULT)) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ 0;

	ಯದಿ ((r = sshkey_in_file(ಕೀಲಿ->cert->signature_ಕೀಲಿ,
	    options.trusted_user_ca_ಕೀಲಿಗಳು, 1, 0)) != 0) {
		debug2_fr(r, "CA %s %s is not listed in %s",
		    sshkey_type(ಕೀಲಿ->cert->signature_ಕೀಲಿ), ca_fp,
		    options.trusted_user_ca_ಕೀಲಿಗಳು);
		ಗಚ್ಛ out;
	}
	/*
	 * If AuthorizedPrincipals is in use, then compare the certificate
	 * principals against the names in that file rather than matching
	 * against the username.
	 */
	ಯದಿ ((principals_file = authorized_principals_file(pw)) != ರಿಕ್ತ) {
		ಯದಿ (match_principals_file(pw, principals_file,
		    ಕೀಲಿ->cert, &principals_opts))
			found_principal = 1;
	}
	/* Try querying command if specified */
	ಯದಿ (!found_principal && match_principals_command(pw, ಕೀಲಿ,
	    conn_id, rdomain, &principals_opts))
		found_principal = 1;
	/* If principals file or command is specified, then require a match */
	use_authorized_principals = principals_file != ರಿಕ್ತ ||
	    options.authorized_principals_command != ರಿಕ್ತ;
	ಯದಿ (!found_principal && use_authorized_principals) {
		reason = "Certificate does not contain an authorized principal";
		ಗಚ್ಛ fail_reason;
	}
	ಯದಿ (use_authorized_principals && principals_opts == ರಿಕ್ತ)
		fatal_f("internal error: missing principals_opts");
	ಯದಿ (sshkey_cert_check_authority_now(ಕೀಲಿ, 0, 0,
	    use_authorized_principals ? ರಿಕ್ತ : pw->pw_name, &reason) != 0)
		ಗಚ್ಛ fail_reason;

	/* Check authority from options in key and from principals file/cmd */
	ಯದಿ ((cert_opts = sshauthopt_from_cert(ಕೀಲಿ)) == ರಿಕ್ತ) {
		reason = "Invalid certificate options";
		ಗಚ್ಛ fail_reason;
	}
	ಯದಿ (auth_authorise_keyopts(pw, cert_opts, 0,
	    remote_ip, remote_host, "cert") != 0) {
		reason = "Refused by certificate options";
		ಗಚ್ಛ fail_reason;
	}
	ಯದಿ (principals_opts == ರಿಕ್ತ) {
		final_opts = cert_opts;
		cert_opts = ರಿಕ್ತ;
	} ಅನ್ಯಥಾ {
		ಯದಿ (auth_authorise_keyopts(pw, principals_opts, 0,
		    remote_ip, remote_host, "principals") != 0) {
			reason = "Refused by certificate principals options";
			ಗಚ್ಛ fail_reason;
		}
		ಯದಿ ((final_opts = sshauthopt_merge(principals_opts,
		    cert_opts, &reason)) == ರಿಕ್ತ) {
 fail_reason:
			error("Refusing certificate ID \"%s\" serial=%llu "
			    "signed by %s CA %s: %s", ಕೀಲಿ->cert->ಕೀಲಿ_id,
			    (unsigned long long)ಕೀಲಿ->cert->serial,
			    sshkey_type(ಕೀಲಿ->cert->signature_ಕೀಲಿ), ca_fp,
			    reason);
			auth_debug_add("Refused Certificate ID \"%s\" "
			    "serial=%llu: %s", ಕೀಲಿ->cert->ಕೀಲಿ_id,
			    (unsigned long long)ಕೀಲಿ->cert->serial, reason);
			ಗಚ್ಛ out;
		}
	}

	/* Success */
	verbose("Accepted certificate ID \"%s\" (serial %llu) signed by "
	    "%s CA %s via %s", ಕೀಲಿ->cert->ಕೀಲಿ_id,
	    (unsigned long long)ಕೀಲಿ->cert->serial,
	    sshkey_type(ಕೀಲಿ->cert->signature_ಕೀಲಿ), ca_fp,
	    options.trusted_user_ca_ಕೀಲಿಗಳು);
	ಯದಿ (authoptsp != ರಿಕ್ತ) {
		*authoptsp = final_opts;
		final_opts = ರಿಕ್ತ;
	}
	ret = 1;
 out:
	sshauthopt_free(principals_opts);
	sshauthopt_free(cert_opts);
	sshauthopt_free(final_opts);
	ಮುಕ್ತ(principals_file);
	ಮುಕ್ತ(ca_fp);
	ಪ್ರತ್ಯಾಗಮ ret;
}

/*
 * Checks whether key is allowed in file.
 * returns 1 if the key is allowed or 0 otherwise.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
user_ಕೀಲಿ_allowed2(ಸಂರಚನಾ passwd *pw, ಸಂರಚನಾ sshkey *ಕೀಲಿ,
    ವರ್ಣ *file, ಧ್ರುವ ವರ್ಣ *remote_ip, ಧ್ರುವ ವರ್ಣ *remote_host,
    ಸಂರಚನಾ sshauthopt **authoptsp)
{
	FILE *f;
	ಪೂರ್ಣಾಙ್ಕ found_ಕೀಲಿ = 0;

	ಯದಿ (authoptsp != ರಿಕ್ತ)
		*authoptsp = ರಿಕ್ತ;

	/* Temporarily use the user's uid. */
	temporarily_use_uid(pw);

	debug("trying public key file %s", file);
	ಯದಿ ((f = auth_openkeyfile(file, pw, options.strict_modes)) != ರಿಕ್ತ) {
		found_ಕೀಲಿ = auth_check_authkeys_file(pw, f, file,
		    ಕೀಲಿ, remote_ip, remote_host, authoptsp);
		fclose(f);
	}

	restore_uid();
	ಪ್ರತ್ಯಾಗಮ found_ಕೀಲಿ;
}

/*
 * Checks whether key is allowed in output of command.
 * returns 1 if the key is allowed or 0 otherwise.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
user_ಕೀಲಿ_command_allowed2(ಸಂರಚನಾ passwd *user_pw, ಸಂರಚನಾ sshkey *ಕೀಲಿ,
    ಧ್ರುವ ವರ್ಣ *remote_ip, ಧ್ರುವ ವರ್ಣ *remote_host,
    ಧ್ರುವ ವರ್ಣ *conn_id, ಧ್ರುವ ವರ್ಣ *rdomain, ಸಂರಚನಾ sshauthopt **authoptsp)
{
	ಸಂರಚನಾ passwd *runas_pw = ರಿಕ್ತ;
	FILE *f = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ r, ok, found_ಕೀಲಿ = 0;
	ಪೂರ್ಣಾಙ್ಕ i, uid_swapped = 0, ac = 0;
	pid_t pid;
	ವರ್ಣ *username = ರಿಕ್ತ, *ಕೀಲಿ_fp = ರಿಕ್ತ, *keytext = ರಿಕ್ತ;
	ವರ್ಣ uidstr[32], *tmp, *command = ರಿಕ್ತ, **av = ರಿಕ್ತ;
	ಶೂನ್ಯ (*osigchld)(ಪೂರ್ಣಾಙ್ಕ);

	ಯದಿ (authoptsp != ರಿಕ್ತ)
		*authoptsp = ರಿಕ್ತ;
	ಯದಿ (options.authorized_ಕೀಲಿಗಳು_command == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಯದಿ (options.authorized_ಕೀಲಿಗಳು_command_user == ರಿಕ್ತ) {
		error("No user for AuthorizedKeysCommand specified, skipping");
		ಪ್ರತ್ಯಾಗಮ 0;
	}

	/*
	 * NB. all returns later this function should go via "out" to
	 * ensure the original SIGCHLD handler is restored properly.
	 */
	osigchld = ssh_signal(SIGCHLD, SIG_DFL);

	/* Prepare and verify the user for the command */
	username = percent_expand(options.authorized_ಕೀಲಿಗಳು_command_user,
	    "u", user_pw->pw_name, (ವರ್ಣ *)ರಿಕ್ತ);
	runas_pw = getpwnam(username);
	ಯದಿ (runas_pw == ರಿಕ್ತ) {
		error("AuthorizedKeysCommandUser \"%s\" not found: %s",
		    username, strerror(errno));
		ಗಚ್ಛ out;
	}

	/* Prepare AuthorizedKeysCommand */
	ಯದಿ ((ಕೀಲಿ_fp = sshkey_fingerprint(ಕೀಲಿ, options.fingerprint_hash,
	    SSH_FP_DEFAULT)) == ರಿಕ್ತ) {
		error_f("sshkey_fingerprint failed");
		ಗಚ್ಛ out;
	}
	ಯದಿ ((r = sshkey_to_base64(ಕೀಲಿ, &keytext)) != 0) {
		error_fr(r, "sshkey_to_base64 failed");
		ಗಚ್ಛ out;
	}

	/* Turn the command into an argument vector */
	ಯದಿ (argv_split(options.authorized_ಕೀಲಿಗಳು_command, &ac, &av, 0) != 0) {
		error("AuthorizedKeysCommand \"%s\" contains invalid quotes",
		    options.authorized_ಕೀಲಿಗಳು_command);
		ಗಚ್ಛ out;
	}
	ಯದಿ (ac == 0) {
		error("AuthorizedKeysCommand \"%s\" yielded no arguments",
		    options.authorized_ಕೀಲಿಗಳು_command);
		ಗಚ್ಛ out;
	}
	snprintf(uidstr, ಪರಿಮಾಣ(uidstr), "%llu",
	    (unsigned long long)user_pw->pw_uid);
	ಪ್ರತಿ (i = 1; i < ac; i++) {
		tmp = percent_expand(av[i],
		    "C", conn_id,
		    "D", rdomain,
		    "U", uidstr,
		    "u", user_pw->pw_name,
		    "h", user_pw->pw_dir,
		    "t", sshkey_ssh_name(ಕೀಲಿ),
		    "f", ಕೀಲಿ_fp,
		    "k", keytext,
		    (ವರ್ಣ *)ರಿಕ್ತ);
		ಯದಿ (tmp == ರಿಕ್ತ)
			fatal_f("percent_expand failed");
		ಮುಕ್ತ(av[i]);
		av[i] = tmp;
	}
	/* Prepare a printable command for logs, etc. */
	command = argv_assemble(ac, av);

	/*
	 * If AuthorizedKeysCommand was run without arguments
	 * then fall back to the old behaviour of passing the
	 * target username as a single argument.
	 */
	ಯದಿ (ac == 1) {
		av = xreallocarray(av, ac + 2, ಪರಿಮಾಣ(*av));
		av[1] = xstrdup(user_pw->pw_name);
		av[2] = ರಿಕ್ತ;
		/* Fix up command too, since it is used in log messages */
		ಮುಕ್ತ(command);
		xasprintf(&command, "%s %s", av[0], av[1]);
	}

	ಯದಿ ((pid = subprocess("AuthorizedKeysCommand", command,
	    ac, av, &f,
	    SSH_SUBPROCESS_STDOUT_CAPTURE|SSH_SUBPROCESS_STDERR_DISCARD,
	    runas_pw, temporarily_use_uid, restore_uid)) == 0)
		ಗಚ್ಛ out;

	uid_swapped = 1;
	temporarily_use_uid(runas_pw);

	ok = auth_check_authkeys_file(user_pw, f,
	    options.authorized_ಕೀಲಿಗಳು_command, ಕೀಲಿ, remote_ip,
	    remote_host, authoptsp);

	fclose(f);
	f = ರಿಕ್ತ;

	ಯದಿ (exited_cleanly(pid, "AuthorizedKeysCommand", command, 0) != 0)
		ಗಚ್ಛ out;

	/* Read completed successfully */
	found_ಕೀಲಿ = ok;
 out:
	ಯದಿ (f != ರಿಕ್ತ)
		fclose(f);
	ssh_signal(SIGCHLD, osigchld);
	ಪ್ರತಿ (i = 0; i < ac; i++)
		ಮುಕ್ತ(av[i]);
	ಮುಕ್ತ(av);
	ಯದಿ (uid_swapped)
		restore_uid();
	ಮುಕ್ತ(command);
	ಮುಕ್ತ(username);
	ಮುಕ್ತ(ಕೀಲಿ_fp);
	ಮುಕ್ತ(keytext);
	ಪ್ರತ್ಯಾಗಮ found_ಕೀಲಿ;
}

/*
 * Check whether key authenticates and authorises the user.
 */
ಪೂರ್ಣಾಙ್ಕ
user_ಕೀಲಿ_allowed(ಸಂರಚನಾ ssh *ssh, ಸಂರಚನಾ passwd *pw, ಸಂರಚನಾ sshkey *ಕೀಲಿ,
    ಪೂರ್ಣಾಙ್ಕ auth_attempt, ಸಂರಚನಾ sshauthopt **authoptsp)
{
	u_int success = 0, i, j;
	ವರ್ಣ *file = ರಿಕ್ತ, *conn_id;
	ಸಂರಚನಾ sshauthopt *opts = ರಿಕ್ತ;
	ಧ್ರುವ ವರ್ಣ *rdomain, *remote_ip, *remote_host;

	ಯದಿ (authoptsp != ರಿಕ್ತ)
		*authoptsp = ರಿಕ್ತ;

	ಯದಿ (auth_ಕೀಲಿ_is_revoked(ಕೀಲಿ))
		ಪ್ರತ್ಯಾಗಮ 0;
	ಯದಿ (sshkey_is_cert(ಕೀಲಿ) &&
	    auth_ಕೀಲಿ_is_revoked(ಕೀಲಿ->cert->signature_ಕೀಲಿ))
		ಪ್ರತ್ಯಾಗಮ 0;

	ಯದಿ ((rdomain = ssh_packet_rdomain_in(ssh)) == ರಿಕ್ತ)
		rdomain = "";
	remote_ip = ssh_remote_ipaddr(ssh);
	remote_host = auth_get_canonical_hostname(ssh, options.use_dns);
	xasprintf(&conn_id, "%s %d %s %d",
	    ssh_local_ipaddr(ssh), ssh_local_port(ssh),
	    remote_ip, ssh_remote_port(ssh));

	ಪ್ರತಿ (i = 0; !success && i < options.ಅಂಕೆ_authkeys_files; i++) {
		ಪೂರ್ಣಾಙ್ಕ r;
		glob_t gl;

		ಯದಿ (strcasecmp(options.authorized_ಕೀಲಿಗಳು_files[i], "none") == 0)
			ಅನುವರ್ತ;
		file = expand_authorized_ಕೀಲಿಗಳು(
		    options.authorized_ಕೀಲಿಗಳು_files[i], pw);
		temporarily_use_uid(pw);
		r = glob(file, 0, ರಿಕ್ತ, &gl);
		restore_uid();
		ಯದಿ (r != 0) {
			ಯದಿ (r != GLOB_NOMATCH) {
				logit_f("glob \"%s\" failed", file);
			}
			ಮುಕ್ತ(file);
			file = ರಿಕ್ತ;
			ಅನುವರ್ತ;
		} ಅನ್ಯಥಾ ಯದಿ (gl.gl_pathc > INT_MAX) {
			fatal_f("too many glob results for \"%s\"", file);
		} ಅನ್ಯಥಾ ಯದಿ (gl.gl_pathc > 1) {
			debug2_f("glob \"%s\" returned %zu matches", file,
			    gl.gl_pathc);
		}
		ಪ್ರತಿ (j = 0; !success && j < gl.gl_pathc; j++) {
			success = user_ಕೀಲಿ_allowed2(pw, ಕೀಲಿ, gl.gl_pathv[j],
			    remote_ip, remote_host, &opts);
			ಯದಿ (!success) {
				sshauthopt_free(opts);
				opts = ರಿಕ್ತ;
			}
		}
		ಮುಕ್ತ(file);
		file = ರಿಕ್ತ;
		globfree(&gl);
	}
	ಯದಿ (success)
		ಗಚ್ಛ out;

	ಯದಿ ((success = user_cert_trusted_ca(pw, ಕೀಲಿ, remote_ip, remote_host,
	    conn_id, rdomain, &opts)) != 0)
		ಗಚ್ಛ out;
	sshauthopt_free(opts);
	opts = ರಿಕ್ತ;

	ಯದಿ ((success = user_ಕೀಲಿ_command_allowed2(pw, ಕೀಲಿ, remote_ip,
	    remote_host, conn_id, rdomain, &opts)) != 0)
		ಗಚ್ಛ out;
	sshauthopt_free(opts);
	opts = ರಿಕ್ತ;

 out:
	ಮುಕ್ತ(conn_id);
	ಯದಿ (success && authoptsp != ರಿಕ್ತ) {
		*authoptsp = opts;
		opts = ರಿಕ್ತ;
	}
	sshauthopt_free(opts);
	ಪ್ರತ್ಯಾಗಮ success;
}

Authmethod method_pubkey = {
	&methodcfg_pubkey,
	userauth_pubkey,
};
