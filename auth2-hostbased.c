/* $OpenBSD: auth2-hostbased.c,v 1.59 2026/09/16 00:31:27 djm Exp $ */
/*
 * Copyright (c) 2000 Markus Friedl.  All rights reserved.
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
#ਅਨ੍ਤਰ੍ਭਾਵ <pwd.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "xmalloc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssh2.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "packet.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "kex.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshbuf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "misc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "servconf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshkey.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "hostfile.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "auth.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "canohost.h"
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ GSSAPI
#ਅਨ੍ਤਰ੍ਭਾਵ "ssh-gss.h"
#ਜੇ_ਅੰਤ
#ਅਨ੍ਤਰ੍ਭਾਵ "monitor_wrap.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "pathnames.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssherr.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "match.h"

/* import */
ਬਾਹਰੀ ServerOptions options;
ਬਾਹਰੀ ਬਣਤਰ authmethod_cfg methodcfg_hostbased;

ਸਥਿਰ ਪੂਰਨ
userauth_hostbased(ਬਣਤਰ ssh *ssh, ਅਚਲ ਅੱਖਰ *ਵਿਧੀ)
{
	Authctxt *authctxt = ssh->authctxt;
	ਬਣਤਰ sshbuf *keyblob = ਨਿਰਾ, *b = ਨਿਰਾ;
	ਬਣਤਰ sshkey *ਕੁੰਜੀ = ਨਿਰਾ;
	ਅੱਖਰ *pkalg, *cuser, *chost;
	u_char *sig;
	ਮਾਪ_t alen, slen;
	ਪੂਰਨ r, pktype, authenticated = 0;

	ਜੇ ((r = sshpkt_get_cstring(ssh, &pkalg, &alen)) != 0 ||
	    (r = sshpkt_getb_froms(ssh, &keyblob)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &chost, ਨਿਰਾ)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &cuser, ਨਿਰਾ)) != 0 ||
	    (r = sshpkt_get_string(ssh, &sig, &slen)) != 0)
		fatal_fr(r, "parse packet");

	debug_f("cuser %s chost %s pkalg %s slen %zu",
	    cuser, chost, pkalg, slen);
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ DEBUG_PK
	debug("signature:");
	sshbuf_dump_ਅੰਕੜੇ(sig, slen, stderr);
#ਜੇ_ਅੰਤ
	pktype = sshkey_type_from_name(pkalg);
	ਜੇ (pktype == ਕੁੰਜੀ_UNSPEC) {
		/* this is perfectly legal */
		logit_f("unsupported public key algorithm: %s",
		    pkalg);
		ਜਾਓ ਪੂਰਾ;
	}
	ਜੇ (ਮੇਲ_ਨਮੂਨਾ_list(pkalg,
	    options.hostbased_accepted_algos, 0) != 1) {
		logit_f("signature algorithm %s not in "
		    "HostbasedAcceptedAlgorithms", pkalg);
		ਜਾਓ ਪੂਰਾ;
	}
	ਜੇ ((b = sshbuf_fromb(keyblob)) == ਨਿਰਾ)
		fatal_f("sshbuf_fromb failed");
	ਚੋਣ ((r = sshkey_fromb_allowlist(b, &ਕੁੰਜੀ,
	    options.hostbased_accepted_algos, options.ca_sign_algorithms))) {
	ਹਾਲਤ 0:
		/* ok */
		ਰੋਕੋ;
	ਹਾਲਤ SSH_ERR_ਕੁੰਜੀ_ALG_UNSUPPORTED:
		/* This shouldn't happen unless the client is being weird */
		logit_f("key algorithm differs from signature algorithm %s and "
		    "is not in HostbasedAcceptedAlgorithms", pkalg);
		ਜਾਓ ਪੂਰਾ;
	ਹਾਲਤ SSH_ERR_SIGN_ALG_UNSUPPORTED:
		logit_fr(r, "certificate signature algorithm not in "
		    "CASignatureAlgorithms");
		ਜਾਓ ਪੂਰਾ;
	ਮੂਲ:
		error_fr(r, "parse key");
		ਜਾਓ ਪੂਰਾ;
	}
	sshbuf_free(b);
	b = ਨਿਰਾ;

	ਜੇ (ਕੁੰਜੀ->type != pktype || (sshkey_type_plain(pktype) == ਕੁੰਜੀ_ECDSA &&
	    sshkey_ecdsa_nid_from_name(pkalg) != ਕੁੰਜੀ->ecdsa_nid)) {
		error_f("key type mismatch for decoded key "
		    "(received %s, expected %s)", sshkey_ssh_name(ਕੁੰਜੀ), pkalg);
		ਜਾਓ ਪੂਰਾ;
	}
	ਜੇ ((r = sshkey_check_rsa_ਲੰਮਾਈ(ਕੁੰਜੀ,
	    options.required_rsa_ਮਾਪ)) != 0) {
		logit_r(r, "refusing %s key", sshkey_type(ਕੁੰਜੀ));
		ਜਾਓ ਪੂਰਾ;
	}

	ਜੇ (!authctxt->valid || authctxt->user == ਨਿਰਾ) {
		debug2_f("disabled because of invalid user");
		ਜਾਓ ਪੂਰਾ;
	}

	ਜੇ ((b = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new failed");
	/* reconstruct packet */
	ਜੇ ((r = sshbuf_put_stringb(b, ssh->kex->session_id)) != 0 ||
	    (r = sshbuf_put_u8(b, SSH2_ਸੁਨੇਹਾ_USERAUTH_REQUEST)) != 0 ||
	    (r = sshbuf_put_cstring(b, authctxt->user)) != 0 ||
	    (r = sshbuf_put_cstring(b, authctxt->service)) != 0 ||
	    (r = sshbuf_put_cstring(b, ਵਿਧੀ)) != 0 ||
	    (r = sshbuf_put_string(b, pkalg, alen)) != 0 ||
	    (r = sshbuf_put_stringb(b, keyblob)) != 0 ||
	    (r = sshbuf_put_cstring(b, chost)) != 0 ||
	    (r = sshbuf_put_cstring(b, cuser)) != 0)
		fatal_fr(r, "reconstruct packet");
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ DEBUG_PK
	sshbuf_dump(b, stderr);
#ਜੇ_ਅੰਤ

	auth2_ਰਿਕਾਰਡ_info(authctxt,
	    "client user \"%.100s\", client host \"%.100s\"", cuser, chost);

	/* test for allowed key and correct signature */
	authenticated = 0;
	ਜੇ (mm_hostbased_ਕੁੰਜੀ_allowed(ssh, authctxt->pw, cuser,
	    chost, ਕੁੰਜੀ) &&
	    mm_sshkey_verify(ਕੁੰਜੀ, sig, slen,
	    sshbuf_ptr(b), sshbuf_len(b), pkalg, ssh->compat, ਨਿਰਾ) == 0)
		authenticated = 1;

	auth2_ਰਿਕਾਰਡ_ਕੁੰਜੀ(authctxt, authenticated, ਕੁੰਜੀ);
ਪੂਰਾ:
	debug2_f("authenticated %d", authenticated);
	sshkey_free(ਕੁੰਜੀ);
	sshbuf_free(b);
	sshbuf_free(keyblob);
	ਮੁਕਤ(pkalg);
	ਮੁਕਤ(cuser);
	ਮੁਕਤ(chost);
	ਮੁਕਤ(sig);
	ਵਾਪਸ authenticated;
}

/* return 1 if given hostkey is allowed */
ਪੂਰਨ
hostbased_ਕੁੰਜੀ_allowed(ਬਣਤਰ ssh *ssh, ਬਣਤਰ passwd *pw,
    ਅਚਲ ਅੱਖਰ *cuser, ਅੱਖਰ *chost, ਬਣਤਰ sshkey *ਕੁੰਜੀ)
{
	ਅਚਲ ਅੱਖਰ *resolvedname, *ipaddr, *lookup, *reason;
	Host_ਸਥਿਤੀ host_ਸਥਿਤੀ;
	ਪੂਰਨ len;
	ਅੱਖਰ *fp;

	ਜੇ (auth_ਕੁੰਜੀ_is_revoked(ਕੁੰਜੀ))
		ਵਾਪਸ 0;

	resolvedname = auth_get_canonical_hostname(ssh, options.use_dns);
	ipaddr = ssh_remote_ipaddr(ssh);

	debug2_f("chost %s resolvedname %s ipaddr %s",
	    chost, resolvedname, ipaddr);

	ਜੇ (((len = ਲੜੀ_ਲੰਬਾਈ(chost)) > 0) && chost[len - 1] == '.') {
		debug2("stripping trailing dot from chost %s", chost);
		chost[len - 1] = '\0';
	}

	ਜੇ (options.hostbased_ਵਰਤਦਾ_name_from_packet_only) {
		ਜੇ (auth_rhosts2(pw, cuser, chost, chost) == 0) {
			debug2_f("auth_rhosts2 refused user \"%.100s\" "
			    "host \"%.100s\" (from packet)", cuser, chost);
			ਵਾਪਸ 0;
		}
		lookup = chost;
	} ਨਹੀਂਤਾਂ {
		ਜੇ (strcasecmp(resolvedname, chost) != 0)
			logit("userauth_hostbased mismatch: "
			    "client sends %s, but we resolve %s to %s",
			    chost, ipaddr, resolvedname);
		ਜੇ (auth_rhosts2(pw, cuser, resolvedname, ipaddr) == 0) {
			debug2_f("auth_rhosts2 refused "
			    "user \"%.100s\" host \"%.100s\" addr \"%.100s\"",
			    cuser, resolvedname, ipaddr);
			ਵਾਪਸ 0;
		}
		lookup = resolvedname;
	}
	debug2_f("access allowed by auth_rhosts2");

	ਜੇ (sshkey_is_cert(ਕੁੰਜੀ) && sshkey_cert_check_host(ਕੁੰਜੀ, lookup,
	     options.ca_sign_algorithms, &reason) != 0) {
		ਜੇ ((fp = sshkey_fingerprint(ਕੁੰਜੀ->cert->signature_ਕੁੰਜੀ,
		    options.fingerprint_hash, SSH_FP_DEFAULT)) == ਨਿਰਾ)
			fatal_f("sshkey_fingerprint fail");
		error("Refusing certificate ID \"%s\" serial=%llu signed by "
		    "%s CA %s: %s", ਕੁੰਜੀ->cert->ਕੁੰਜੀ_id,
		    (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)ਕੁੰਜੀ->cert->serial,
		    sshkey_type(ਕੁੰਜੀ->cert->signature_ਕੁੰਜੀ), fp, reason);
		auth_debug_ਜੋੜੋ("Refused Certificate ID \"%s\" serial=%llu: %s",
		    ਕੁੰਜੀ->cert->ਕੁੰਜੀ_id, (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)ਕੁੰਜੀ->cert->serial,
		    reason);
		ਮੁਕਤ(fp);
		ਵਾਪਸ 0;
	}

	host_ਸਥਿਤੀ = check_ਕੁੰਜੀ_ਵਿੱਚ_hostfiles(pw, ਕੁੰਜੀ, lookup,
	    ਰਸਤਾ_SSH_SYSTEM_HOSTFILE,
	    options.ignore_user_ਗਿਆਤ_hosts ? ਨਿਰਾ : ਰਸਤਾ_SSH_USER_HOSTFILE);

	/* backward compat if no key has been found. */
	ਜੇ (host_ਸਥਿਤੀ == HOST_NEW) {
		host_ਸਥਿਤੀ = check_ਕੁੰਜੀ_ਵਿੱਚ_hostfiles(pw, ਕੁੰਜੀ, lookup,
		    ਰਸਤਾ_SSH_SYSTEM_HOSTFILE2,
		    options.ignore_user_ਗਿਆਤ_hosts ? ਨਿਰਾ :
		    ਰਸਤਾ_SSH_USER_HOSTFILE2);
	}

	ਜੇ (host_ਸਥਿਤੀ == HOST_OK) {
		ਜੇ (sshkey_is_cert(ਕੁੰਜੀ)) {
			ਜੇ ((fp = sshkey_fingerprint(ਕੁੰਜੀ->cert->signature_ਕੁੰਜੀ,
			    options.fingerprint_hash, SSH_FP_DEFAULT)) == ਨਿਰਾ)
				fatal_f("sshkey_fingerprint fail");
			verbose("Accepted certificate ID \"%s\" signed by "
			    "%s CA %s from %s@%s", ਕੁੰਜੀ->cert->ਕੁੰਜੀ_id,
			    sshkey_type(ਕੁੰਜੀ->cert->signature_ਕੁੰਜੀ), fp,
			    cuser, lookup);
		} ਨਹੀਂਤਾਂ {
			ਜੇ ((fp = sshkey_fingerprint(ਕੁੰਜੀ,
			    options.fingerprint_hash, SSH_FP_DEFAULT)) == ਨਿਰਾ)
				fatal_f("sshkey_fingerprint fail");
			verbose("Accepted %s public key %s from %s@%s",
			    sshkey_type(ਕੁੰਜੀ), fp, cuser, lookup);
		}
		ਮੁਕਤ(fp);
	}

	ਵਾਪਸ (host_ਸਥਿਤੀ == HOST_OK);
}

Authmethod ਵਿਧੀ_hostbased = {
	&methodcfg_hostbased,
	userauth_hostbased,
};
