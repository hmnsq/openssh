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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <errno.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <paths.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <pwd.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <glob.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <signal.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <time.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <limits.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "xmalloc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssh.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssh2.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "packet.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "kex.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshbuf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "misc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "servconf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "compat.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshkey.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "hostfile.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "auth.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "pathnames.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "uidswap.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "auth-options.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "canohost.h"
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ GSSAPI
#ਅਨ੍ਤਰ੍ਭਾਵ "ssh-gss.h"
#ਜੇ_ਅੰਤ
#ਅਨ੍ਤਰ੍ਭਾਵ "monitor_wrap.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "authfile.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "match.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssherr.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "channels.h" /* XXX for session.h */
#ਅਨ੍ਤਰ੍ਭਾਵ "session.h" /* XXX for child_set_env(); refactor? */
#ਅਨ੍ਤਰ੍ਭਾਵ "sk-api.h"

/* import */
ਬਾਹਰੀ ServerOptions options;
ਬਾਹਰੀ ਬਣਤਰ authmethod_cfg methodcfg_pubkey;

ਸਥਿਰ ਅੱਖਰ *
format_ਕੁੰਜੀ(ਅਚਲ ਬਣਤਰ sshkey *ਕੁੰਜੀ)
{
	ਅੱਖਰ *ret, *fp = sshkey_fingerprint(ਕੁੰਜੀ,
	    options.fingerprint_hash, SSH_FP_DEFAULT);

	xasprintf(&ret, "%s %s", sshkey_type(ਕੁੰਜੀ), fp);
	ਮੁਕਤ(fp);
	ਵਾਪਸ ret;
}

/*
 * Verify that the hostkey in a publickey-hostbound-v00@openssh.com userauth
 * request matches the hostkey that was negotiated during initial KEX.
 */
ਸਥਿਰ ਖਾਲੀ
check_hostbound_hostkey(ਬਣਤਰ ssh *ssh)
{
	ਪੂਰਨ r;
	ਬਣਤਰ sshbuf *our_hostkey_blob, *their_hostkey_blob;

	ਜੇ (ssh->kex->initial_hostkey == ਨਿਰਾ)
		fatal_f("internal error: initial hostkey not recorded");
	ਜੇ ((our_hostkey_blob = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new failed");
	ਜੇ ((r = sshpkt_getb_froms(ssh, &their_hostkey_blob)) != 0)
		fatal_fr(r, "parse hostkey");
	ਜੇ ((r = sshkey_putb(ssh->kex->initial_hostkey, our_hostkey_blob)) != 0)
		fatal_fr(r, "serialise hostkey");
	ਜੇ ((r = sshbuf_equals(our_hostkey_blob, their_hostkey_blob)) != 0)
		fatal_f("packet contained wrong host key");
	sshbuf_free(our_hostkey_blob);
	sshbuf_free(their_hostkey_blob);
}

ਸਥਿਰ ਪੂਰਨ
userauth_pubkey(ਬਣਤਰ ssh *ssh, ਅਚਲ ਅੱਖਰ *ਵਿਧੀ)
{
	Authctxt *authctxt = ssh->authctxt;
	ਬਣਤਰ passwd *pw = authctxt->pw;
	ਬਣਤਰ sshbuf *keyblob = ਨਿਰਾ, *b = ਨਿਰਾ;
	ਬਣਤਰ sshkey *ਕੁੰਜੀ = ਨਿਰਾ, *hostkey = ਨਿਰਾ;
	ਅੱਖਰ *pkalg = ਨਿਰਾ, *userstyle = ਨਿਰਾ, *ਕੁੰਜੀ_s = ਨਿਰਾ, *ca_s = ਨਿਰਾ;
	ਅੱਖਰ *keystring = ਨਿਰਾ;
	u_char *sig = ਨਿਰਾ, have_sig;
	ਮਾਪ_t slen;
	ਪੂਰਨ hostbound, r, pktype;
	ਪੂਰਨ req_presence = 0, req_verify = 0, authenticated = 0;
	ਬਣਤਰ sshauthopt *authopts = ਨਿਰਾ;
	ਬਣਤਰ sshkey_sig_details *sig_details = ਨਿਰਾ;

	hostbound = strcmp(ਵਿਧੀ, "publickey-hostbound-v00@openssh.com") == 0;

	ਜੇ ((r = sshpkt_get_u8(ssh, &have_sig)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &pkalg, ਨਿਰਾ)) != 0 ||
	    (r = sshpkt_getb_froms(ssh, &keyblob)) != 0)
		fatal_fr(r, "parse %s packet", ਵਿਧੀ);

	/* hostbound auth includes the hostkey offered at initial KEX */
	ਜੇ (hostbound)
		check_hostbound_hostkey(ssh); /* fatals on error */

	ਜੇ (log_level_get() >= SYSLOG_LEVEL_DEBUG2) {
		ਜੇ ((b = sshbuf_fromb(keyblob)) == ਨਿਰਾ)
			fatal_f("sshbuf_fromb failed");
		ਜੇ ((keystring = sshbuf_dtob64_string(b, 0)) == ਨਿਰਾ)
			fatal_f("sshbuf_dtob64 failed");
		debug2_f("%s user %s %s public key %s %s",
		    authctxt->valid ? "valid" : "invalid", authctxt->user,
		    have_sig ? "attempting" : "querying", pkalg, keystring);
		sshbuf_free(b);
		b = ਨਿਰਾ;
	}

	pktype = sshkey_type_from_name(pkalg);
	ਜੇ (pktype == ਕੁੰਜੀ_UNSPEC) {
		/* this is perfectly legal */
		verbose_f("unsupported public key algorithm: %s", pkalg);
		ਜਾਓ ਪੂਰਾ;
	}
	ਜੇ (ਮੇਲ_ਨਮੂਨਾ_list(pkalg, options.pubkey_accepted_algos, 0) != 1) {
		logit_f("signature algorithm %s not in "
		    "PubkeyAcceptedAlgorithms", pkalg);
		ਜਾਓ ਪੂਰਾ;
	}
	ਜੇ ((b = sshbuf_fromb(keyblob)) == ਨਿਰਾ)
		fatal_f("sshbuf_fromb failed");
	ਚੋਣ ((r = sshkey_fromb_allowlist(b, &ਕੁੰਜੀ,
	    options.pubkey_accepted_algos, options.ca_sign_algorithms))) {
	ਹਾਲਤ 0:
		/* ok */
		ਰੋਕੋ;
	ਹਾਲਤ SSH_ERR_ਕੁੰਜੀ_ALG_UNSUPPORTED:
		/* This shouldn't happen unless the client is being weird */
		logit_f("key algorithm differs from signature algorithm %s and "
		    "is not in PubkeyAcceptedAlgorithms", pkalg);
		ਜਾਓ ਪੂਰਾ;
	ਹਾਲਤ SSH_ERR_SIGN_ALG_UNSUPPORTED:
		logit_fr(r, "certificate signature algorithm not in "
		    "CASignatureAlgorithm");
		ਜਾਓ ਪੂਰਾ;
	ਮੂਲ:
		error_fr(r, "parse key");
		ਜਾਓ ਪੂਰਾ;
	}
	sshbuf_free(b);
	b = ਨਿਰਾ;

	/* USERAUTH_REQUEST signature type should match key's type */
	ਜੇ (ਕੁੰਜੀ->type != pktype || (sshkey_type_plain(pktype) == ਕੁੰਜੀ_ECDSA &&
	    sshkey_ecdsa_nid_from_name(pkalg) != ਕੁੰਜੀ->ecdsa_nid)) {
		error_f("key type mismatch for decoded key "
		    "(received %s, expected %s)", sshkey_ssh_name(ਕੁੰਜੀ), pkalg);
		ਜਾਓ ਪੂਰਾ;
	}
	ਜੇ (auth2_ਕੁੰਜੀ_already_ਵਰਤਿਆ(authctxt, ਕੁੰਜੀ)) {
		logit("refusing previously-used %s key", sshkey_type(ਕੁੰਜੀ));
		ਜਾਓ ਪੂਰਾ;
	}
	ਜੇ ((r = sshkey_check_rsa_ਲੰਮਾਈ(ਕੁੰਜੀ,
	    options.required_rsa_ਮਾਪ)) != 0) {
		logit_r(r, "refusing %s key", sshkey_type(ਕੁੰਜੀ));
		ਜਾਓ ਪੂਰਾ;
	}
	ਕੁੰਜੀ_s = format_ਕੁੰਜੀ(ਕੁੰਜੀ);
	ਜੇ (sshkey_is_cert(ਕੁੰਜੀ))
		ca_s = format_ਕੁੰਜੀ(ਕੁੰਜੀ->cert->signature_ਕੁੰਜੀ);

	ਜੇ (have_sig) {
		debug3_f("%s have %s signature for %s%s%s",
		    ਵਿਧੀ, pkalg, ਕੁੰਜੀ_s,
		    ca_s == ਨਿਰਾ ? "" : " CA ", ca_s == ਨਿਰਾ ? "" : ca_s);
		ਜੇ ((r = sshpkt_get_string(ssh, &sig, &slen)) != 0 ||
		    (r = sshpkt_get_ਸਿਰਾ(ssh)) != 0)
			fatal_fr(r, "parse signature packet");
		ਜੇ ((b = sshbuf_new()) == ਨਿਰਾ)
			fatal_f("sshbuf_new failed");
		ਜੇ ((r = sshbuf_put_stringb(b,
		    ssh->kex->session_id)) != 0)
			fatal_fr(r, "put session id");
		ਜੇ (!authctxt->valid || authctxt->user == ਨਿਰਾ) {
			debug2_f("disabled because of invalid user");
			ਜਾਓ ਪੂਰਾ;
		}
		/* reconstruct packet */
		xasprintf(&userstyle, "%s%s%s", authctxt->user,
		    authctxt->style ? ":" : "",
		    authctxt->style ? authctxt->style : "");
		ਜੇ ((r = sshbuf_put_u8(b, SSH2_ਸੁਨੇਹਾ_USERAUTH_REQUEST)) != 0 ||
		    (r = sshbuf_put_cstring(b, userstyle)) != 0 ||
		    (r = sshbuf_put_cstring(b, authctxt->service)) != 0 ||
		    (r = sshbuf_put_cstring(b, ਵਿਧੀ)) != 0 ||
		    (r = sshbuf_put_u8(b, have_sig)) != 0 ||
		    (r = sshbuf_put_cstring(b, pkalg)) != 0 ||
		    (r = sshbuf_put_stringb(b, keyblob)) != 0)
			fatal_fr(r, "reconstruct %s packet", ਵਿਧੀ);
		ਜੇ (hostbound &&
		    (r = sshkey_puts(ssh->kex->initial_hostkey, b)) != 0)
			fatal_fr(r, "reconstruct %s packet", ਵਿਧੀ);
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ DEBUG_PK
		sshbuf_dump(b, stderr);
#ਜੇ_ਅੰਤ
		/* test for correct signature */
		authenticated = 0;
		ਜੇ (mm_user_ਕੁੰਜੀ_allowed(ssh, pw, ਕੁੰਜੀ, 1, &authopts) &&
		    mm_sshkey_verify(ਕੁੰਜੀ, sig, slen,
		    sshbuf_ptr(b), sshbuf_len(b),
		    (ssh->compat & SSH_BUG_SIGTYPE) == 0 ? pkalg : ਨਿਰਾ,
		    ssh->compat, &sig_details) == 0) {
			authenticated = 1;
		}
		ਜੇ (authenticated == 1 && sig_details != ਨਿਰਾ) {
			auth2_ਰਿਕਾਰਡ_info(authctxt, "signature count = %u",
			    sig_details->sk_counter);
			debug_f("sk_counter = %u, sk_flags = 0x%02x",
			    sig_details->sk_counter, sig_details->sk_flags);
			req_presence = (options.pubkey_auth_options &
			    PUBKEYAUTH_TOUCH_REQUIRED) ||
			    !authopts->no_require_user_presence;
			ਜੇ (req_presence && (sig_details->sk_flags &
			    SSH_SK_USER_PRESENCE_REQD) == 0) {
				error("public key %s signature for %s%s from "
				    "%.128s port %d rejected: user presence "
				    "(authenticator touch) requirement "
				    "not met ", ਕੁੰਜੀ_s,
				    authctxt->valid ? "" : "invalid user ",
				    authctxt->user, ssh_remote_ipaddr(ssh),
				    ssh_remote_ਪੋਰਟ(ssh));
				authenticated = 0;
				ਜਾਓ ਪੂਰਾ;
			}
			req_verify = (options.pubkey_auth_options &
			    PUBKEYAUTH_VERIFY_REQUIRED) ||
			    authopts->require_verify;
			ਜੇ (req_verify && (sig_details->sk_flags &
			    SSH_SK_USER_VERIFICATION_REQD) == 0) {
				error("public key %s signature for %s%s from "
				    "%.128s port %d rejected: user "
				    "verification requirement not met ", ਕੁੰਜੀ_s,
				    authctxt->valid ? "" : "invalid user ",
				    authctxt->user, ssh_remote_ipaddr(ssh),
				    ssh_remote_ਪੋਰਟ(ssh));
				authenticated = 0;
				ਜਾਓ ਪੂਰਾ;
			}
		}
		auth2_ਰਿਕਾਰਡ_ਕੁੰਜੀ(authctxt, authenticated, ਕੁੰਜੀ);
	} ਨਹੀਂਤਾਂ {
		debug_f("%s test pkalg %s pkblob %s%s%s", ਵਿਧੀ, pkalg, ਕੁੰਜੀ_s,
		    ca_s == ਨਿਰਾ ? "" : " CA ", ca_s == ਨਿਰਾ ? "" : ca_s);

		ਜੇ ((r = sshpkt_get_ਸਿਰਾ(ssh)) != 0)
			fatal_fr(r, "parse packet");

		/* XXX fake reply and always send PK_OK ? */
		/*
		 * XXX this allows testing whether a user is allowed
		 * to login: if you happen to have a valid pubkey this
		 * message is sent. the message is NEVER sent at all
		 * if a user is not allowed to login. is this an
		 * issue? -markus
		 */
		ਜੇ (authctxt->valid && authctxt->user != ਨਿਰਾ &&
		    mm_user_ਕੁੰਜੀ_allowed(ssh, pw, ਕੁੰਜੀ, 0, ਨਿਰਾ)) {
			ਜੇ ((r = sshpkt_ਸ਼ੁਰੂ(ssh, SSH2_ਸੁਨੇਹਾ_USERAUTH_PK_OK))
			    != 0 ||
			    (r = sshpkt_put_cstring(ssh, pkalg)) != 0 ||
			    (r = sshpkt_put_stringb(ssh, keyblob)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0 ||
			    (r = ssh_packet_write_wait(ssh)) != 0)
				fatal_fr(r, "send packet");
			authctxt->postponed = 1;
		} ਨਹੀਂਤਾਂ {
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
			ਜੇ (authctxt->pk_ok_failures++ < options.max_pubkey_ok)
				authctxt->auth_failure_already_counted = 1;
			debug3_f("pubkey test %d of %d%s",
			    authctxt->pk_ok_failures, options.max_pubkey_ok,
			    authctxt->auth_failure_already_counted ?
			    "" : ": treating as authentication failure");
		 }
	}
ਪੂਰਾ:
	ਜੇ (authenticated == 1 && auth_activate_options(ssh, authopts) != 0) {
		debug_f("key options inconsistent with existing");
		authenticated = 0;
	}
	debug2_f("authenticated %d pkalg %s", authenticated, pkalg);

	sshbuf_free(b);
	sshbuf_free(keyblob);
	sshauthopt_free(authopts);
	sshkey_free(ਕੁੰਜੀ);
	sshkey_free(hostkey);
	ਮੁਕਤ(keystring);
	ਮੁਕਤ(userstyle);
	ਮੁਕਤ(pkalg);
	ਮੁਕਤ(ਕੁੰਜੀ_s);
	ਮੁਕਤ(ca_s);
	ਮੁਕਤ(sig);
	sshkey_sig_details_free(sig_details);
	ਵਾਪਸ authenticated;
}

ਸਥਿਰ ਪੂਰਨ
ਮੇਲ_principals_file(ਬਣਤਰ passwd *pw, ਅੱਖਰ *file,
    ਬਣਤਰ sshkey_cert *cert, ਬਣਤਰ sshauthopt **authoptsp)
{
	FILE *f;
	ਪੂਰਨ r, success = 0;
	ਮਾਪ_t i;
	glob_t gl;
	ਬਣਤਰ sshauthopt *opts = ਨਿਰਾ;

	ਜੇ (authoptsp != ਨਿਰਾ)
		*authoptsp = ਨਿਰਾ;

	temporarily_use_uid(pw);
	r = glob(file, 0, ਨਿਰਾ, &gl);
	restore_uid();
	ਜੇ (r != 0) {
		ਜੇ (r != GLOB_NOMATCH) {
			logit_f("glob \"%s\" failed", file);
		}
		ਵਾਪਸ 0;
	} ਨਹੀਂਤਾਂ ਜੇ (gl.gl_pathc > ਵੱਧ_ਤੋਂ_ਵੱਧ_ਅੰਕ) {
		fatal_f("too many glob results for \"%s\"", file);
	} ਨਹੀਂਤਾਂ ਜੇ (gl.gl_pathc > 1) {
		debug2_f("glob \"%s\" returned %zu matches", file,
		    gl.gl_pathc);
	}
	ਲਈ (i = 0; !success && i < gl.gl_pathc; i++) {
		temporarily_use_uid(pw);
		debug("trying authorized principals file %s", file);
		ਜੇ ((f = auth_openprincipals(gl.gl_pathv[i], pw,
		    options.strict_modes)) == ਨਿਰਾ) {
			restore_uid();
			ਜਾਰੀ;
		}
		success = auth_process_principals(f, gl.gl_pathv[i],
		    cert, &opts);
		fclose(f);
		restore_uid();
		ਜੇ (!success) {
			sshauthopt_free(opts);
			opts = ਨਿਰਾ;
		}
	}
	globfree(&gl);
	ਜੇ (success && authoptsp != ਨਿਰਾ) {
		*authoptsp = opts;
		opts = ਨਿਰਾ;
	}
	sshauthopt_free(opts);
	ਵਾਪਸ success;
}

/*
 * Checks whether principal is allowed in output of command.
 * returns 1 if the principal is allowed or 0 otherwise.
 */
ਸਥਿਰ ਪੂਰਨ
ਮੇਲ_principals_command(ਬਣਤਰ passwd *user_pw, ਅਚਲ ਬਣਤਰ sshkey *ਕੁੰਜੀ,
    ਅਚਲ ਅੱਖਰ *conn_id, ਅਚਲ ਅੱਖਰ *rdomain, ਬਣਤਰ sshauthopt **authoptsp)
{
	ਬਣਤਰ passwd *runas_pw = ਨਿਰਾ;
	ਅਚਲ ਬਣਤਰ sshkey_cert *cert = ਕੁੰਜੀ->cert;
	FILE *f = ਨਿਰਾ;
	ਪੂਰਨ r, ok, ਮਿਲਿਆ_principal = 0;
	ਪੂਰਨ i, ac = 0, uid_swapped = 0;
	pid_t pid;
	ਅੱਖਰ *tmp, *username = ਨਿਰਾ, *command = ਨਿਰਾ, **av = ਨਿਰਾ;
	ਅੱਖਰ *ca_fp = ਨਿਰਾ, *ਕੁੰਜੀ_fp = ਨਿਰਾ, *catext = ਨਿਰਾ, *keytext = ਨਿਰਾ;
	ਅੱਖਰ serial_s[32], uidstr[32];
	ਖਾਲੀ (*osigchld)(ਪੂਰਨ);

	ਜੇ (authoptsp != ਨਿਰਾ)
		*authoptsp = ਨਿਰਾ;
	ਜੇ (options.authorized_principals_command == ਨਿਰਾ)
		ਵਾਪਸ 0;
	ਜੇ (options.authorized_principals_command_user == ਨਿਰਾ) {
		error("No user for AuthorizedPrincipalsCommand specified, "
		    "skipping");
		ਵਾਪਸ 0;
	}

	/*
	 * NB. all returns later this function should go via "out" to
	 * ensure the original SIGCHLD handler is restored properly.
	 */
	osigchld = ssh_signal(SIGCHLD, SIG_DFL);

	/* Prepare and verify the user for the command */
	username = percent_expand(options.authorized_principals_command_user,
	    "u", user_pw->pw_name, (ਅੱਖਰ *)ਨਿਰਾ);
	runas_pw = getpwnam(username);
	ਜੇ (runas_pw == ਨਿਰਾ) {
		error("AuthorizedPrincipalsCommandUser \"%s\" not found: %s",
		    username, strerror(errno));
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	/* Turn the command into an argument vector */
	ਜੇ (argv_ਵੰਡੋ(options.authorized_principals_command,
	    &ac, &av, 0) != 0) {
		error("AuthorizedPrincipalsCommand \"%s\" contains "
		    "invalid quotes", options.authorized_principals_command);
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (ac == 0) {
		error("AuthorizedPrincipalsCommand \"%s\" yielded no arguments",
		    options.authorized_principals_command);
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((ca_fp = sshkey_fingerprint(cert->signature_ਕੁੰਜੀ,
	    options.fingerprint_hash, SSH_FP_DEFAULT)) == ਨਿਰਾ) {
		error_f("sshkey_fingerprint failed");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((ਕੁੰਜੀ_fp = sshkey_fingerprint(ਕੁੰਜੀ,
	    options.fingerprint_hash, SSH_FP_DEFAULT)) == ਨਿਰਾ) {
		error_f("sshkey_fingerprint failed");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((r = sshkey_ਮੰਜ਼ਿਲ_base64(cert->signature_ਕੁੰਜੀ, &catext)) != 0) {
		error_fr(r, "sshkey_to_base64 failed");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((r = sshkey_ਮੰਜ਼ਿਲ_base64(ਕੁੰਜੀ, &keytext)) != 0) {
		error_fr(r, "sshkey_to_base64 failed");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	snprintf(serial_s, ਆਕਾਰ(serial_s), "%llu",
	    (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)cert->serial);
	snprintf(uidstr, ਆਕਾਰ(uidstr), "%llu",
	    (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)user_pw->pw_uid);
	ਲਈ (i = 1; i < ac; i++) {
		tmp = percent_expand(av[i],
		    "C", conn_id,
		    "D", rdomain,
		    "U", uidstr,
		    "u", user_pw->pw_name,
		    "h", user_pw->pw_dir,
		    "t", sshkey_ssh_name(ਕੁੰਜੀ),
		    "T", sshkey_ssh_name(cert->signature_ਕੁੰਜੀ),
		    "f", ਕੁੰਜੀ_fp,
		    "F", ca_fp,
		    "k", keytext,
		    "K", catext,
		    "i", cert->ਕੁੰਜੀ_id,
		    "s", serial_s,
		    (ਅੱਖਰ *)ਨਿਰਾ);
		ਜੇ (tmp == ਨਿਰਾ)
			fatal_f("percent_expand failed");
		ਮੁਕਤ(av[i]);
		av[i] = tmp;
	}
	/* Prepare a printable command for logs, etc. */
	command = argv_assemble(ac, av);

	ਜੇ ((pid = subprocess("AuthorizedPrincipalsCommand", command,
	    ac, av, &f,
	    SSH_SUBPROCESS_STDOUT_CAPTURE|SSH_SUBPROCESS_STDERR_DISCARD,
	    runas_pw, temporarily_use_uid, restore_uid)) == 0)
		ਜਾਓ ਬਾਹਰਲਾ;

	uid_swapped = 1;
	temporarily_use_uid(runas_pw);

	ok = auth_process_principals(f, "(command)", cert, authoptsp);

	fclose(f);
	f = ਨਿਰਾ;

	ਜੇ (exited_cleanly(pid, "AuthorizedPrincipalsCommand", command, 0) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;

	/* Read completed successfully */
	ਮਿਲਿਆ_principal = ok;
 ਬਾਹਰਲਾ:
	ਜੇ (f != ਨਿਰਾ)
		fclose(f);
	ssh_signal(SIGCHLD, osigchld);
	ਲਈ (i = 0; i < ac; i++)
		ਮੁਕਤ(av[i]);
	ਮੁਕਤ(av);
	ਜੇ (uid_swapped)
		restore_uid();
	ਮੁਕਤ(command);
	ਮੁਕਤ(username);
	ਮੁਕਤ(ca_fp);
	ਮੁਕਤ(ਕੁੰਜੀ_fp);
	ਮੁਕਤ(catext);
	ਮੁਕਤ(keytext);
	ਵਾਪਸ ਮਿਲਿਆ_principal;
}

/* Authenticate a certificate key against TrustedUserCAKeys */
ਸਥਿਰ ਪੂਰਨ
user_cert_trusted_ca(ਬਣਤਰ passwd *pw, ਬਣਤਰ sshkey *ਕੁੰਜੀ,
    ਅਚਲ ਅੱਖਰ *remote_ip, ਅਚਲ ਅੱਖਰ *remote_host,
    ਅਚਲ ਅੱਖਰ *conn_id, ਅਚਲ ਅੱਖਰ *rdomain, ਬਣਤਰ sshauthopt **authoptsp)
{
	ਅੱਖਰ *ca_fp, *principals_file = ਨਿਰਾ;
	ਅਚਲ ਅੱਖਰ *reason;
	ਬਣਤਰ sshauthopt *principals_opts = ਨਿਰਾ, *cert_opts = ਨਿਰਾ;
	ਬਣਤਰ sshauthopt *final_opts = ਨਿਰਾ;
	ਪੂਰਨ r, ret = 0, ਮਿਲਿਆ_principal = 0, use_authorized_principals;

	ਜੇ (authoptsp != ਨਿਰਾ)
		*authoptsp = ਨਿਰਾ;

	ਜੇ (!sshkey_is_cert(ਕੁੰਜੀ) || options.trusted_user_ca_ਕੁੰਜੀਆਂ == ਨਿਰਾ)
		ਵਾਪਸ 0;

	ਜੇ ((ca_fp = sshkey_fingerprint(ਕੁੰਜੀ->cert->signature_ਕੁੰਜੀ,
	    options.fingerprint_hash, SSH_FP_DEFAULT)) == ਨਿਰਾ)
		ਵਾਪਸ 0;

	ਜੇ ((r = sshkey_ਵਿੱਚ_file(ਕੁੰਜੀ->cert->signature_ਕੁੰਜੀ,
	    options.trusted_user_ca_ਕੁੰਜੀਆਂ, 1, 0)) != 0) {
		debug2_fr(r, "CA %s %s is not listed in %s",
		    sshkey_type(ਕੁੰਜੀ->cert->signature_ਕੁੰਜੀ), ca_fp,
		    options.trusted_user_ca_ਕੁੰਜੀਆਂ);
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	/*
	 * If AuthorizedPrincipals is in use, then compare the certificate
	 * principals against the names in that file rather than matching
	 * against the username.
	 */
	ਜੇ ((principals_file = authorized_principals_file(pw)) != ਨਿਰਾ) {
		ਜੇ (ਮੇਲ_principals_file(pw, principals_file,
		    ਕੁੰਜੀ->cert, &principals_opts))
			ਮਿਲਿਆ_principal = 1;
	}
	/* Try querying command if specified */
	ਜੇ (!ਮਿਲਿਆ_principal && ਮੇਲ_principals_command(pw, ਕੁੰਜੀ,
	    conn_id, rdomain, &principals_opts))
		ਮਿਲਿਆ_principal = 1;
	/* If principals file or command is specified, then require a match */
	use_authorized_principals = principals_file != ਨਿਰਾ ||
	    options.authorized_principals_command != ਨਿਰਾ;
	ਜੇ (!ਮਿਲਿਆ_principal && use_authorized_principals) {
		reason = "Certificate does not contain an authorized principal";
		ਜਾਓ fail_reason;
	}
	ਜੇ (use_authorized_principals && principals_opts == ਨਿਰਾ)
		fatal_f("internal error: missing principals_opts");
	ਜੇ (sshkey_cert_check_authority_now(ਕੁੰਜੀ, 0, 0,
	    use_authorized_principals ? ਨਿਰਾ : pw->pw_name, &reason) != 0)
		ਜਾਓ fail_reason;

	/* Check authority from options in key and from principals file/cmd */
	ਜੇ ((cert_opts = sshauthopt_from_cert(ਕੁੰਜੀ)) == ਨਿਰਾ) {
		reason = "Invalid certificate options";
		ਜਾਓ fail_reason;
	}
	ਜੇ (auth_authorise_keyopts(pw, cert_opts, 0,
	    remote_ip, remote_host, "cert") != 0) {
		reason = "Refused by certificate options";
		ਜਾਓ fail_reason;
	}
	ਜੇ (principals_opts == ਨਿਰਾ) {
		final_opts = cert_opts;
		cert_opts = ਨਿਰਾ;
	} ਨਹੀਂਤਾਂ {
		ਜੇ (auth_authorise_keyopts(pw, principals_opts, 0,
		    remote_ip, remote_host, "principals") != 0) {
			reason = "Refused by certificate principals options";
			ਜਾਓ fail_reason;
		}
		ਜੇ ((final_opts = sshauthopt_ਮਿਲਾਓ(principals_opts,
		    cert_opts, &reason)) == ਨਿਰਾ) {
 fail_reason:
			error("Refusing certificate ID \"%s\" serial=%llu "
			    "signed by %s CA %s: %s", ਕੁੰਜੀ->cert->ਕੁੰਜੀ_id,
			    (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)ਕੁੰਜੀ->cert->serial,
			    sshkey_type(ਕੁੰਜੀ->cert->signature_ਕੁੰਜੀ), ca_fp,
			    reason);
			auth_debug_ਜੋੜੋ("Refused Certificate ID \"%s\" "
			    "serial=%llu: %s", ਕੁੰਜੀ->cert->ਕੁੰਜੀ_id,
			    (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)ਕੁੰਜੀ->cert->serial, reason);
			ਜਾਓ ਬਾਹਰਲਾ;
		}
	}

	/* Success */
	verbose("Accepted certificate ID \"%s\" (serial %llu) signed by "
	    "%s CA %s via %s", ਕੁੰਜੀ->cert->ਕੁੰਜੀ_id,
	    (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)ਕੁੰਜੀ->cert->serial,
	    sshkey_type(ਕੁੰਜੀ->cert->signature_ਕੁੰਜੀ), ca_fp,
	    options.trusted_user_ca_ਕੁੰਜੀਆਂ);
	ਜੇ (authoptsp != ਨਿਰਾ) {
		*authoptsp = final_opts;
		final_opts = ਨਿਰਾ;
	}
	ret = 1;
 ਬਾਹਰਲਾ:
	sshauthopt_free(principals_opts);
	sshauthopt_free(cert_opts);
	sshauthopt_free(final_opts);
	ਮੁਕਤ(principals_file);
	ਮੁਕਤ(ca_fp);
	ਵਾਪਸ ret;
}

/*
 * Checks whether key is allowed in file.
 * returns 1 if the key is allowed or 0 otherwise.
 */
ਸਥਿਰ ਪੂਰਨ
user_ਕੁੰਜੀ_allowed2(ਬਣਤਰ passwd *pw, ਬਣਤਰ sshkey *ਕੁੰਜੀ,
    ਅੱਖਰ *file, ਅਚਲ ਅੱਖਰ *remote_ip, ਅਚਲ ਅੱਖਰ *remote_host,
    ਬਣਤਰ sshauthopt **authoptsp)
{
	FILE *f;
	ਪੂਰਨ ਮਿਲਿਆ_ਕੁੰਜੀ = 0;

	ਜੇ (authoptsp != ਨਿਰਾ)
		*authoptsp = ਨਿਰਾ;

	/* Temporarily use the user's uid. */
	temporarily_use_uid(pw);

	debug("trying public key file %s", file);
	ਜੇ ((f = auth_openkeyfile(file, pw, options.strict_modes)) != ਨਿਰਾ) {
		ਮਿਲਿਆ_ਕੁੰਜੀ = auth_check_authkeys_file(pw, f, file,
		    ਕੁੰਜੀ, remote_ip, remote_host, authoptsp);
		fclose(f);
	}

	restore_uid();
	ਵਾਪਸ ਮਿਲਿਆ_ਕੁੰਜੀ;
}

/*
 * Checks whether key is allowed in output of command.
 * returns 1 if the key is allowed or 0 otherwise.
 */
ਸਥਿਰ ਪੂਰਨ
user_ਕੁੰਜੀ_command_allowed2(ਬਣਤਰ passwd *user_pw, ਬਣਤਰ sshkey *ਕੁੰਜੀ,
    ਅਚਲ ਅੱਖਰ *remote_ip, ਅਚਲ ਅੱਖਰ *remote_host,
    ਅਚਲ ਅੱਖਰ *conn_id, ਅਚਲ ਅੱਖਰ *rdomain, ਬਣਤਰ sshauthopt **authoptsp)
{
	ਬਣਤਰ passwd *runas_pw = ਨਿਰਾ;
	FILE *f = ਨਿਰਾ;
	ਪੂਰਨ r, ok, ਮਿਲਿਆ_ਕੁੰਜੀ = 0;
	ਪੂਰਨ i, uid_swapped = 0, ac = 0;
	pid_t pid;
	ਅੱਖਰ *username = ਨਿਰਾ, *ਕੁੰਜੀ_fp = ਨਿਰਾ, *keytext = ਨਿਰਾ;
	ਅੱਖਰ uidstr[32], *tmp, *command = ਨਿਰਾ, **av = ਨਿਰਾ;
	ਖਾਲੀ (*osigchld)(ਪੂਰਨ);

	ਜੇ (authoptsp != ਨਿਰਾ)
		*authoptsp = ਨਿਰਾ;
	ਜੇ (options.authorized_ਕੁੰਜੀਆਂ_command == ਨਿਰਾ)
		ਵਾਪਸ 0;
	ਜੇ (options.authorized_ਕੁੰਜੀਆਂ_command_user == ਨਿਰਾ) {
		error("No user for AuthorizedKeysCommand specified, skipping");
		ਵਾਪਸ 0;
	}

	/*
	 * NB. all returns later this function should go via "out" to
	 * ensure the original SIGCHLD handler is restored properly.
	 */
	osigchld = ssh_signal(SIGCHLD, SIG_DFL);

	/* Prepare and verify the user for the command */
	username = percent_expand(options.authorized_ਕੁੰਜੀਆਂ_command_user,
	    "u", user_pw->pw_name, (ਅੱਖਰ *)ਨਿਰਾ);
	runas_pw = getpwnam(username);
	ਜੇ (runas_pw == ਨਿਰਾ) {
		error("AuthorizedKeysCommandUser \"%s\" not found: %s",
		    username, strerror(errno));
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	/* Prepare AuthorizedKeysCommand */
	ਜੇ ((ਕੁੰਜੀ_fp = sshkey_fingerprint(ਕੁੰਜੀ, options.fingerprint_hash,
	    SSH_FP_DEFAULT)) == ਨਿਰਾ) {
		error_f("sshkey_fingerprint failed");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((r = sshkey_ਮੰਜ਼ਿਲ_base64(ਕੁੰਜੀ, &keytext)) != 0) {
		error_fr(r, "sshkey_to_base64 failed");
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	/* Turn the command into an argument vector */
	ਜੇ (argv_ਵੰਡੋ(options.authorized_ਕੁੰਜੀਆਂ_command, &ac, &av, 0) != 0) {
		error("AuthorizedKeysCommand \"%s\" contains invalid quotes",
		    options.authorized_ਕੁੰਜੀਆਂ_command);
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (ac == 0) {
		error("AuthorizedKeysCommand \"%s\" yielded no arguments",
		    options.authorized_ਕੁੰਜੀਆਂ_command);
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	snprintf(uidstr, ਆਕਾਰ(uidstr), "%llu",
	    (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)user_pw->pw_uid);
	ਲਈ (i = 1; i < ac; i++) {
		tmp = percent_expand(av[i],
		    "C", conn_id,
		    "D", rdomain,
		    "U", uidstr,
		    "u", user_pw->pw_name,
		    "h", user_pw->pw_dir,
		    "t", sshkey_ssh_name(ਕੁੰਜੀ),
		    "f", ਕੁੰਜੀ_fp,
		    "k", keytext,
		    (ਅੱਖਰ *)ਨਿਰਾ);
		ਜੇ (tmp == ਨਿਰਾ)
			fatal_f("percent_expand failed");
		ਮੁਕਤ(av[i]);
		av[i] = tmp;
	}
	/* Prepare a printable command for logs, etc. */
	command = argv_assemble(ac, av);

	/*
	 * If AuthorizedKeysCommand was run without arguments
	 * then fall back to the old behaviour of passing the
	 * target username as a single argument.
	 */
	ਜੇ (ac == 1) {
		av = xreallocarray(av, ac + 2, ਆਕਾਰ(*av));
		av[1] = xstrdup(user_pw->pw_name);
		av[2] = ਨਿਰਾ;
		/* Fix up command too, since it is used in log messages */
		ਮੁਕਤ(command);
		xasprintf(&command, "%s %s", av[0], av[1]);
	}

	ਜੇ ((pid = subprocess("AuthorizedKeysCommand", command,
	    ac, av, &f,
	    SSH_SUBPROCESS_STDOUT_CAPTURE|SSH_SUBPROCESS_STDERR_DISCARD,
	    runas_pw, temporarily_use_uid, restore_uid)) == 0)
		ਜਾਓ ਬਾਹਰਲਾ;

	uid_swapped = 1;
	temporarily_use_uid(runas_pw);

	ok = auth_check_authkeys_file(user_pw, f,
	    options.authorized_ਕੁੰਜੀਆਂ_command, ਕੁੰਜੀ, remote_ip,
	    remote_host, authoptsp);

	fclose(f);
	f = ਨਿਰਾ;

	ਜੇ (exited_cleanly(pid, "AuthorizedKeysCommand", command, 0) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;

	/* Read completed successfully */
	ਮਿਲਿਆ_ਕੁੰਜੀ = ok;
 ਬਾਹਰਲਾ:
	ਜੇ (f != ਨਿਰਾ)
		fclose(f);
	ssh_signal(SIGCHLD, osigchld);
	ਲਈ (i = 0; i < ac; i++)
		ਮੁਕਤ(av[i]);
	ਮੁਕਤ(av);
	ਜੇ (uid_swapped)
		restore_uid();
	ਮੁਕਤ(command);
	ਮੁਕਤ(username);
	ਮੁਕਤ(ਕੁੰਜੀ_fp);
	ਮੁਕਤ(keytext);
	ਵਾਪਸ ਮਿਲਿਆ_ਕੁੰਜੀ;
}

/*
 * Check whether key authenticates and authorises the user.
 */
ਪੂਰਨ
user_ਕੁੰਜੀ_allowed(ਬਣਤਰ ssh *ssh, ਬਣਤਰ passwd *pw, ਬਣਤਰ sshkey *ਕੁੰਜੀ,
    ਪੂਰਨ auth_attempt, ਬਣਤਰ sshauthopt **authoptsp)
{
	u_int success = 0, i, j;
	ਅੱਖਰ *file = ਨਿਰਾ, *conn_id;
	ਬਣਤਰ sshauthopt *opts = ਨਿਰਾ;
	ਅਚਲ ਅੱਖਰ *rdomain, *remote_ip, *remote_host;

	ਜੇ (authoptsp != ਨਿਰਾ)
		*authoptsp = ਨਿਰਾ;

	ਜੇ (auth_ਕੁੰਜੀ_is_revoked(ਕੁੰਜੀ))
		ਵਾਪਸ 0;
	ਜੇ (sshkey_is_cert(ਕੁੰਜੀ) &&
	    auth_ਕੁੰਜੀ_is_revoked(ਕੁੰਜੀ->cert->signature_ਕੁੰਜੀ))
		ਵਾਪਸ 0;

	ਜੇ ((rdomain = ssh_packet_rdomain_ਵਿੱਚ(ssh)) == ਨਿਰਾ)
		rdomain = "";
	remote_ip = ssh_remote_ipaddr(ssh);
	remote_host = auth_get_canonical_hostname(ssh, options.use_dns);
	xasprintf(&conn_id, "%s %d %s %d",
	    ssh_local_ipaddr(ssh), ssh_local_ਪੋਰਟ(ssh),
	    remote_ip, ssh_remote_ਪੋਰਟ(ssh));

	ਲਈ (i = 0; !success && i < options.ਅੰਕ_authkeys_files; i++) {
		ਪੂਰਨ r;
		glob_t gl;

		ਜੇ (strcasecmp(options.authorized_ਕੁੰਜੀਆਂ_files[i], "none") == 0)
			ਜਾਰੀ;
		file = expand_authorized_ਕੁੰਜੀਆਂ(
		    options.authorized_ਕੁੰਜੀਆਂ_files[i], pw);
		temporarily_use_uid(pw);
		r = glob(file, 0, ਨਿਰਾ, &gl);
		restore_uid();
		ਜੇ (r != 0) {
			ਜੇ (r != GLOB_NOMATCH) {
				logit_f("glob \"%s\" failed", file);
			}
			ਮੁਕਤ(file);
			file = ਨਿਰਾ;
			ਜਾਰੀ;
		} ਨਹੀਂਤਾਂ ਜੇ (gl.gl_pathc > ਵੱਧ_ਤੋਂ_ਵੱਧ_ਅੰਕ) {
			fatal_f("too many glob results for \"%s\"", file);
		} ਨਹੀਂਤਾਂ ਜੇ (gl.gl_pathc > 1) {
			debug2_f("glob \"%s\" returned %zu matches", file,
			    gl.gl_pathc);
		}
		ਲਈ (j = 0; !success && j < gl.gl_pathc; j++) {
			success = user_ਕੁੰਜੀ_allowed2(pw, ਕੁੰਜੀ, gl.gl_pathv[j],
			    remote_ip, remote_host, &opts);
			ਜੇ (!success) {
				sshauthopt_free(opts);
				opts = ਨਿਰਾ;
			}
		}
		ਮੁਕਤ(file);
		file = ਨਿਰਾ;
		globfree(&gl);
	}
	ਜੇ (success)
		ਜਾਓ ਬਾਹਰਲਾ;

	ਜੇ ((success = user_cert_trusted_ca(pw, ਕੁੰਜੀ, remote_ip, remote_host,
	    conn_id, rdomain, &opts)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	sshauthopt_free(opts);
	opts = ਨਿਰਾ;

	ਜੇ ((success = user_ਕੁੰਜੀ_command_allowed2(pw, ਕੁੰਜੀ, remote_ip,
	    remote_host, conn_id, rdomain, &opts)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	sshauthopt_free(opts);
	opts = ਨਿਰਾ;

 ਬਾਹਰਲਾ:
	ਮੁਕਤ(conn_id);
	ਜੇ (success && authoptsp != ਨਿਰਾ) {
		*authoptsp = opts;
		opts = ਨਿਰਾ;
	}
	sshauthopt_free(opts);
	ਵਾਪਸ success;
}

Authmethod ਵਿਧੀ_pubkey = {
	&methodcfg_pubkey,
	userauth_pubkey,
};
