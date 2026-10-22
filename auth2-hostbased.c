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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>

#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <pwd.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>

#ಅನ್ತರ್ಭಾವ "xmalloc.h"
#ಅನ್ತರ್ಭಾವ "ssh2.h"
#ಅನ್ತರ್ಭಾವ "packet.h"
#ಅನ್ತರ್ಭಾವ "kex.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "misc.h"
#ಅನ್ತರ್ಭಾವ "servconf.h"
#ಅನ್ತರ್ಭಾವ "sshkey.h"
#ಅನ್ತರ್ಭಾವ "hostfile.h"
#ಅನ್ತರ್ಭಾವ "auth.h"
#ಅನ್ತರ್ಭಾವ "canohost.h"
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ GSSAPI
#ಅನ್ತರ್ಭಾವ "ssh-gss.h"
#ಆದರೆ_ಅಂತ್ಯ
#ಅನ್ತರ್ಭಾವ "monitor_wrap.h"
#ಅನ್ತರ್ಭಾವ "pathnames.h"
#ಅನ್ತರ್ಭಾವ "ssherr.h"
#ಅನ್ತರ್ಭಾವ "match.h"

/* import */
ಬಾಹ್ಯ ServerOptions options;
ಬಾಹ್ಯ ರಚನೆ authmethod_cfg methodcfg_hostbased;

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
userauth_hostbased(ರಚನೆ ssh *ssh, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ವಿಧಾನ)
{
	Authctxt *authctxt = ssh->authctxt;
	ರಚನೆ sshbuf *keyblob = ಖಾಲಿ, *b = ಖಾಲಿ;
	ರಚನೆ sshkey *ಕೀಲಿ = ಖಾಲಿ;
	ಅಕ್ಷರ *pkalg, *cuser, *chost;
	u_char *sig;
	ಗಾತ್ರ_t alen, slen;
	ಪೂರ್ಣಾಂಕ r, pktype, authenticated = 0;

	ಆದರೆ ((r = sshpkt_get_cstring(ssh, &pkalg, &alen)) != 0 ||
	    (r = sshpkt_getb_froms(ssh, &keyblob)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &chost, ಖಾಲಿ)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &cuser, ಖಾಲಿ)) != 0 ||
	    (r = sshpkt_get_string(ssh, &sig, &slen)) != 0)
		fatal_fr(r, "parse packet");

	debug_f("cuser %s chost %s pkalg %s slen %zu",
	    cuser, chost, pkalg, slen);
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ DEBUG_PK
	debug("signature:");
	sshbuf_dump_ದತ್ತಾಂಶ(sig, slen, stderr);
#ಆದರೆ_ಅಂತ್ಯ
	pktype = sshkey_type_from_name(pkalg);
	ಆದರೆ (pktype == ಕೀಲಿ_UNSPEC) {
		/* this is perfectly legal */
		logit_f("unsupported public key algorithm: %s",
		    pkalg);
		ಹೋಗು ಮುಗಿದ;
	}
	ಆದರೆ (ಹೊಂದಿಕೆ_ನಮೂನೆ_list(pkalg,
	    options.hostbased_accepted_algos, 0) != 1) {
		logit_f("signature algorithm %s not in "
		    "HostbasedAcceptedAlgorithms", pkalg);
		ಹೋಗು ಮುಗಿದ;
	}
	ಆದರೆ ((b = sshbuf_fromb(keyblob)) == ಖಾಲಿ)
		fatal_f("sshbuf_fromb failed");
	ಆಯ್ಕೆ ((r = sshkey_fromb_allowlist(b, &ಕೀಲಿ,
	    options.hostbased_accepted_algos, options.ca_sign_algorithms))) {
	ಸ್ಥಿತಿ 0:
		/* ok */
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ SSH_ERR_ಕೀಲಿ_ALG_UNSUPPORTED:
		/* This shouldn't happen unless the client is being weird */
		logit_f("key algorithm differs from signature algorithm %s and "
		    "is not in HostbasedAcceptedAlgorithms", pkalg);
		ಹೋಗು ಮುಗಿದ;
	ಸ್ಥಿತಿ SSH_ERR_SIGN_ALG_UNSUPPORTED:
		logit_fr(r, "certificate signature algorithm not in "
		    "CASignatureAlgorithms");
		ಹೋಗು ಮುಗಿದ;
	ಪೂರ್ವನಿಯೋಜಿತ:
		error_fr(r, "parse key");
		ಹೋಗು ಮುಗಿದ;
	}
	sshbuf_free(b);
	b = ಖಾಲಿ;

	ಆದರೆ (ಕೀಲಿ->type != pktype || (sshkey_type_plain(pktype) == ಕೀಲಿ_ECDSA &&
	    sshkey_ecdsa_nid_from_name(pkalg) != ಕೀಲಿ->ecdsa_nid)) {
		error_f("key type mismatch for decoded key "
		    "(received %s, expected %s)", sshkey_ssh_name(ಕೀಲಿ), pkalg);
		ಹೋಗು ಮುಗಿದ;
	}
	ಆದರೆ ((r = sshkey_check_rsa_ಉದ್ದಳತೆ(ಕೀಲಿ,
	    options.required_rsa_ಗಾತ್ರ)) != 0) {
		logit_r(r, "refusing %s key", sshkey_type(ಕೀಲಿ));
		ಹೋಗು ಮುಗಿದ;
	}

	ಆದರೆ (!authctxt->valid || authctxt->user == ಖಾಲಿ) {
		debug2_f("disabled because of invalid user");
		ಹೋಗು ಮುಗಿದ;
	}

	ಆದರೆ ((b = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new failed");
	/* reconstruct packet */
	ಆದರೆ ((r = sshbuf_put_stringb(b, ssh->kex->session_id)) != 0 ||
	    (r = sshbuf_put_u8(b, SSH2_ಸಂದೇಶ_USERAUTH_REQUEST)) != 0 ||
	    (r = sshbuf_put_cstring(b, authctxt->user)) != 0 ||
	    (r = sshbuf_put_cstring(b, authctxt->service)) != 0 ||
	    (r = sshbuf_put_cstring(b, ವಿಧಾನ)) != 0 ||
	    (r = sshbuf_put_string(b, pkalg, alen)) != 0 ||
	    (r = sshbuf_put_stringb(b, keyblob)) != 0 ||
	    (r = sshbuf_put_cstring(b, chost)) != 0 ||
	    (r = sshbuf_put_cstring(b, cuser)) != 0)
		fatal_fr(r, "reconstruct packet");
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ DEBUG_PK
	sshbuf_dump(b, stderr);
#ಆದರೆ_ಅಂತ್ಯ

	auth2_ದಾಖಲೆ_info(authctxt,
	    "client user \"%.100s\", client host \"%.100s\"", cuser, chost);

	/* test for allowed key and correct signature */
	authenticated = 0;
	ಆದರೆ (mm_hostbased_ಕೀಲಿ_allowed(ssh, authctxt->pw, cuser,
	    chost, ಕೀಲಿ) &&
	    mm_sshkey_verify(ಕೀಲಿ, sig, slen,
	    sshbuf_ptr(b), sshbuf_len(b), pkalg, ssh->compat, ಖಾಲಿ) == 0)
		authenticated = 1;

	auth2_ದಾಖಲೆ_ಕೀಲಿ(authctxt, authenticated, ಕೀಲಿ);
ಮುಗಿದ:
	debug2_f("authenticated %d", authenticated);
	sshkey_free(ಕೀಲಿ);
	sshbuf_free(b);
	sshbuf_free(keyblob);
	ಬಿಡುಗಡೆ(pkalg);
	ಬಿಡುಗಡೆ(cuser);
	ಬಿಡುಗಡೆ(chost);
	ಬಿಡುಗಡೆ(sig);
	ಹಿಂತಿರುಗಿ authenticated;
}

/* return 1 if given hostkey is allowed */
ಪೂರ್ಣಾಂಕ
hostbased_ಕೀಲಿ_allowed(ರಚನೆ ssh *ssh, ರಚನೆ passwd *pw,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *cuser, ಅಕ್ಷರ *chost, ರಚನೆ sshkey *ಕೀಲಿ)
{
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *resolvedname, *ipaddr, *lookup, *reason;
	Host_ಸ್ಥಿತಿ host_ಸ್ಥಿತಿ;
	ಪೂರ್ಣಾಂಕ len;
	ಅಕ್ಷರ *fp;

	ಆದರೆ (auth_ಕೀಲಿ_is_revoked(ಕೀಲಿ))
		ಹಿಂತಿರುಗಿ 0;

	resolvedname = auth_get_canonical_hostname(ssh, options.use_dns);
	ipaddr = ssh_remote_ipaddr(ssh);

	debug2_f("chost %s resolvedname %s ipaddr %s",
	    chost, resolvedname, ipaddr);

	ಆದರೆ (((len = ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(chost)) > 0) && chost[len - 1] == '.') {
		debug2("stripping trailing dot from chost %s", chost);
		chost[len - 1] = '\0';
	}

	ಆದರೆ (options.hostbased_ಬಳಸುತ್ತದೆ_name_from_packet_only) {
		ಆದರೆ (auth_rhosts2(pw, cuser, chost, chost) == 0) {
			debug2_f("auth_rhosts2 refused user \"%.100s\" "
			    "host \"%.100s\" (from packet)", cuser, chost);
			ಹಿಂತಿರುಗಿ 0;
		}
		lookup = chost;
	} ಇಲ್ಲದಿದ್ದರೆ {
		ಆದರೆ (strcasecmp(resolvedname, chost) != 0)
			logit("userauth_hostbased mismatch: "
			    "client sends %s, but we resolve %s to %s",
			    chost, ipaddr, resolvedname);
		ಆದರೆ (auth_rhosts2(pw, cuser, resolvedname, ipaddr) == 0) {
			debug2_f("auth_rhosts2 refused "
			    "user \"%.100s\" host \"%.100s\" addr \"%.100s\"",
			    cuser, resolvedname, ipaddr);
			ಹಿಂತಿರುಗಿ 0;
		}
		lookup = resolvedname;
	}
	debug2_f("access allowed by auth_rhosts2");

	ಆದರೆ (sshkey_is_cert(ಕೀಲಿ) && sshkey_cert_check_host(ಕೀಲಿ, lookup,
	     options.ca_sign_algorithms, &reason) != 0) {
		ಆದರೆ ((fp = sshkey_fingerprint(ಕೀಲಿ->cert->signature_ಕೀಲಿ,
		    options.fingerprint_hash, SSH_FP_DEFAULT)) == ಖಾಲಿ)
			fatal_f("sshkey_fingerprint fail");
		error("Refusing certificate ID \"%s\" serial=%llu signed by "
		    "%s CA %s: %s", ಕೀಲಿ->cert->ಕೀಲಿ_id,
		    (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)ಕೀಲಿ->cert->serial,
		    sshkey_type(ಕೀಲಿ->cert->signature_ಕೀಲಿ), fp, reason);
		auth_debug_ಕೂಡಿಸು("Refused Certificate ID \"%s\" serial=%llu: %s",
		    ಕೀಲಿ->cert->ಕೀಲಿ_id, (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)ಕೀಲಿ->cert->serial,
		    reason);
		ಬಿಡುಗಡೆ(fp);
		ಹಿಂತಿರುಗಿ 0;
	}

	host_ಸ್ಥಿತಿ = check_ಕೀಲಿ_ಒಳ_hostfiles(pw, ಕೀಲಿ, lookup,
	    ಮಾರ್ಗ_SSH_SYSTEM_HOSTFILE,
	    options.ignore_user_ತಿಳಿದ_hosts ? ಖಾಲಿ : ಮಾರ್ಗ_SSH_USER_HOSTFILE);

	/* backward compat if no key has been found. */
	ಆದರೆ (host_ಸ್ಥಿತಿ == HOST_NEW) {
		host_ಸ್ಥಿತಿ = check_ಕೀಲಿ_ಒಳ_hostfiles(pw, ಕೀಲಿ, lookup,
		    ಮಾರ್ಗ_SSH_SYSTEM_HOSTFILE2,
		    options.ignore_user_ತಿಳಿದ_hosts ? ಖಾಲಿ :
		    ಮಾರ್ಗ_SSH_USER_HOSTFILE2);
	}

	ಆದರೆ (host_ಸ್ಥಿತಿ == HOST_OK) {
		ಆದರೆ (sshkey_is_cert(ಕೀಲಿ)) {
			ಆದರೆ ((fp = sshkey_fingerprint(ಕೀಲಿ->cert->signature_ಕೀಲಿ,
			    options.fingerprint_hash, SSH_FP_DEFAULT)) == ಖಾಲಿ)
				fatal_f("sshkey_fingerprint fail");
			verbose("Accepted certificate ID \"%s\" signed by "
			    "%s CA %s from %s@%s", ಕೀಲಿ->cert->ಕೀಲಿ_id,
			    sshkey_type(ಕೀಲಿ->cert->signature_ಕೀಲಿ), fp,
			    cuser, lookup);
		} ಇಲ್ಲದಿದ್ದರೆ {
			ಆದರೆ ((fp = sshkey_fingerprint(ಕೀಲಿ,
			    options.fingerprint_hash, SSH_FP_DEFAULT)) == ಖಾಲಿ)
				fatal_f("sshkey_fingerprint fail");
			verbose("Accepted %s public key %s from %s@%s",
			    sshkey_type(ಕೀಲಿ), fp, cuser, lookup);
		}
		ಬಿಡುಗಡೆ(fp);
	}

	ಹಿಂತಿರುಗಿ (host_ಸ್ಥಿತಿ == HOST_OK);
}

Authmethod ವಿಧಾನ_hostbased = {
	&methodcfg_hostbased,
	userauth_hostbased,
};
