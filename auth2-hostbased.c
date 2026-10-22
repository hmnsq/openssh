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
#ifdef GSSAPI
#ಅನ್ತರ್ಭಾವ "ssh-gss.h"
#endif
#ಅನ್ತರ್ಭಾವ "monitor_wrap.h"
#ಅನ್ತರ್ಭಾವ "pathnames.h"
#ಅನ್ತರ್ಭಾವ "ssherr.h"
#ಅನ್ತರ್ಭಾವ "match.h"

/* import */
ಬಾಹ್ಯ ServerOptions options;
ಬಾಹ್ಯ ಸಂರಚನಾ authmethod_cfg methodcfg_hostbased;

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
userauth_hostbased(ಸಂರಚನಾ ssh *ssh, ಧ್ರುವ ವರ್ಣ *method)
{
	Authctxt *authctxt = ssh->authctxt;
	ಸಂರಚನಾ sshbuf *keyblob = ರಿಕ್ತ, *b = ರಿಕ್ತ;
	ಸಂರಚನಾ sshkey *ಕೀಲಿ = ರಿಕ್ತ;
	ವರ್ಣ *pkalg, *cuser, *chost;
	u_char *sig;
	size_t alen, slen;
	ಪೂರ್ಣಾಙ್ಕ r, pktype, authenticated = 0;

	ಯದಿ ((r = sshpkt_get_cstring(ssh, &pkalg, &alen)) != 0 ||
	    (r = sshpkt_getb_froms(ssh, &keyblob)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &chost, ರಿಕ್ತ)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &cuser, ರಿಕ್ತ)) != 0 ||
	    (r = sshpkt_get_string(ssh, &sig, &slen)) != 0)
		fatal_fr(r, "parse packet");

	debug_f("cuser %s chost %s pkalg %s slen %zu",
	    cuser, chost, pkalg, slen);
#ifdef DEBUG_PK
	debug("signature:");
	sshbuf_dump_data(sig, slen, stderr);
#endif
	pktype = sshkey_type_from_name(pkalg);
	ಯದಿ (pktype == ಕೀಲಿ_UNSPEC) {
		/* this is perfectly legal */
		logit_f("unsupported public key algorithm: %s",
		    pkalg);
		ಗಚ್ಛ done;
	}
	ಯದಿ (match_pattern_list(pkalg,
	    options.hostbased_accepted_algos, 0) != 1) {
		logit_f("signature algorithm %s not in "
		    "HostbasedAcceptedAlgorithms", pkalg);
		ಗಚ್ಛ done;
	}
	ಯದಿ ((b = sshbuf_fromb(keyblob)) == ರಿಕ್ತ)
		fatal_f("sshbuf_fromb failed");
	ವಿಕಲ್ಪ ((r = sshkey_fromb_allowlist(b, &ಕೀಲಿ,
	    options.hostbased_accepted_algos, options.ca_sign_algorithms))) {
	ಪಕ್ಷ 0:
		/* ok */
		ಭಙ್ಗ;
	ಪಕ್ಷ SSH_ERR_ಕೀಲಿ_ALG_UNSUPPORTED:
		/* This shouldn't happen unless the client is being weird */
		logit_f("key algorithm differs from signature algorithm %s and "
		    "is not in HostbasedAcceptedAlgorithms", pkalg);
		ಗಚ್ಛ done;
	ಪಕ್ಷ SSH_ERR_SIGN_ALG_UNSUPPORTED:
		logit_fr(r, "certificate signature algorithm not in "
		    "CASignatureAlgorithms");
		ಗಚ್ಛ done;
	ಸ್ವಭಾವ:
		error_fr(r, "parse key");
		ಗಚ್ಛ done;
	}
	sshbuf_free(b);
	b = ರಿಕ್ತ;

	ಯದಿ (ಕೀಲಿ->type != pktype || (sshkey_type_plain(pktype) == ಕೀಲಿ_ECDSA &&
	    sshkey_ecdsa_nid_from_name(pkalg) != ಕೀಲಿ->ecdsa_nid)) {
		error_f("key type mismatch for decoded key "
		    "(received %s, expected %s)", sshkey_ssh_name(ಕೀಲಿ), pkalg);
		ಗಚ್ಛ done;
	}
	ಯದಿ ((r = sshkey_check_rsa_length(ಕೀಲಿ,
	    options.required_rsa_size)) != 0) {
		logit_r(r, "refusing %s key", sshkey_type(ಕೀಲಿ));
		ಗಚ್ಛ done;
	}

	ಯದಿ (!authctxt->valid || authctxt->user == ರಿಕ್ತ) {
		debug2_f("disabled because of invalid user");
		ಗಚ್ಛ done;
	}

	ಯದಿ ((b = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new failed");
	/* reconstruct packet */
	ಯದಿ ((r = sshbuf_put_stringb(b, ssh->kex->session_id)) != 0 ||
	    (r = sshbuf_put_u8(b, SSH2_ಸಂದೇಶ_USERAUTH_REQUEST)) != 0 ||
	    (r = sshbuf_put_cstring(b, authctxt->user)) != 0 ||
	    (r = sshbuf_put_cstring(b, authctxt->service)) != 0 ||
	    (r = sshbuf_put_cstring(b, method)) != 0 ||
	    (r = sshbuf_put_string(b, pkalg, alen)) != 0 ||
	    (r = sshbuf_put_stringb(b, keyblob)) != 0 ||
	    (r = sshbuf_put_cstring(b, chost)) != 0 ||
	    (r = sshbuf_put_cstring(b, cuser)) != 0)
		fatal_fr(r, "reconstruct packet");
#ifdef DEBUG_PK
	sshbuf_dump(b, stderr);
#endif

	auth2_record_info(authctxt,
	    "client user \"%.100s\", client host \"%.100s\"", cuser, chost);

	/* test for allowed key and correct signature */
	authenticated = 0;
	ಯದಿ (mm_hostbased_ಕೀಲಿ_allowed(ssh, authctxt->pw, cuser,
	    chost, ಕೀಲಿ) &&
	    mm_sshkey_verify(ಕೀಲಿ, sig, slen,
	    sshbuf_ptr(b), sshbuf_len(b), pkalg, ssh->compat, ರಿಕ್ತ) == 0)
		authenticated = 1;

	auth2_record_ಕೀಲಿ(authctxt, authenticated, ಕೀಲಿ);
done:
	debug2_f("authenticated %d", authenticated);
	sshkey_free(ಕೀಲಿ);
	sshbuf_free(b);
	sshbuf_free(keyblob);
	ಮುಕ್ತ(pkalg);
	ಮುಕ್ತ(cuser);
	ಮುಕ್ತ(chost);
	ಮುಕ್ತ(sig);
	ಪ್ರತ್ಯಾಗಮ authenticated;
}

/* return 1 if given hostkey is allowed */
ಪೂರ್ಣಾಙ್ಕ
hostbased_ಕೀಲಿ_allowed(ಸಂರಚನಾ ssh *ssh, ಸಂರಚನಾ passwd *pw,
    ಧ್ರುವ ವರ್ಣ *cuser, ವರ್ಣ *chost, ಸಂರಚನಾ sshkey *ಕೀಲಿ)
{
	ಧ್ರುವ ವರ್ಣ *resolvedname, *ipaddr, *lookup, *reason;
	HostStatus host_status;
	ಪೂರ್ಣಾಙ್ಕ len;
	ವರ್ಣ *fp;

	ಯದಿ (auth_ಕೀಲಿ_is_revoked(ಕೀಲಿ))
		ಪ್ರತ್ಯಾಗಮ 0;

	resolvedname = auth_get_canonical_hostname(ssh, options.use_dns);
	ipaddr = ssh_remote_ipaddr(ssh);

	debug2_f("chost %s resolvedname %s ipaddr %s",
	    chost, resolvedname, ipaddr);

	ಯದಿ (((len = strlen(chost)) > 0) && chost[len - 1] == '.') {
		debug2("stripping trailing dot from chost %s", chost);
		chost[len - 1] = '\0';
	}

	ಯದಿ (options.hostbased_uses_name_from_packet_only) {
		ಯದಿ (auth_rhosts2(pw, cuser, chost, chost) == 0) {
			debug2_f("auth_rhosts2 refused user \"%.100s\" "
			    "host \"%.100s\" (from packet)", cuser, chost);
			ಪ್ರತ್ಯಾಗಮ 0;
		}
		lookup = chost;
	} ಅನ್ಯಥಾ {
		ಯದಿ (strcasecmp(resolvedname, chost) != 0)
			logit("userauth_hostbased mismatch: "
			    "client sends %s, but we resolve %s to %s",
			    chost, ipaddr, resolvedname);
		ಯದಿ (auth_rhosts2(pw, cuser, resolvedname, ipaddr) == 0) {
			debug2_f("auth_rhosts2 refused "
			    "user \"%.100s\" host \"%.100s\" addr \"%.100s\"",
			    cuser, resolvedname, ipaddr);
			ಪ್ರತ್ಯಾಗಮ 0;
		}
		lookup = resolvedname;
	}
	debug2_f("access allowed by auth_rhosts2");

	ಯದಿ (sshkey_is_cert(ಕೀಲಿ) && sshkey_cert_check_host(ಕೀಲಿ, lookup,
	     options.ca_sign_algorithms, &reason) != 0) {
		ಯದಿ ((fp = sshkey_fingerprint(ಕೀಲಿ->cert->signature_ಕೀಲಿ,
		    options.fingerprint_hash, SSH_FP_DEFAULT)) == ರಿಕ್ತ)
			fatal_f("sshkey_fingerprint fail");
		error("Refusing certificate ID \"%s\" serial=%llu signed by "
		    "%s CA %s: %s", ಕೀಲಿ->cert->ಕೀಲಿ_id,
		    (unsigned long long)ಕೀಲಿ->cert->serial,
		    sshkey_type(ಕೀಲಿ->cert->signature_ಕೀಲಿ), fp, reason);
		auth_debug_add("Refused Certificate ID \"%s\" serial=%llu: %s",
		    ಕೀಲಿ->cert->ಕೀಲಿ_id, (unsigned long long)ಕೀಲಿ->cert->serial,
		    reason);
		ಮುಕ್ತ(fp);
		ಪ್ರತ್ಯಾಗಮ 0;
	}

	host_status = check_ಕೀಲಿ_in_hostfiles(pw, ಕೀಲಿ, lookup,
	    _PATH_SSH_SYSTEM_HOSTFILE,
	    options.ignore_user_known_hosts ? ರಿಕ್ತ : _PATH_SSH_USER_HOSTFILE);

	/* backward compat if no key has been found. */
	ಯದಿ (host_status == HOST_NEW) {
		host_status = check_ಕೀಲಿ_in_hostfiles(pw, ಕೀಲಿ, lookup,
		    _PATH_SSH_SYSTEM_HOSTFILE2,
		    options.ignore_user_known_hosts ? ರಿಕ್ತ :
		    _PATH_SSH_USER_HOSTFILE2);
	}

	ಯದಿ (host_status == HOST_OK) {
		ಯದಿ (sshkey_is_cert(ಕೀಲಿ)) {
			ಯದಿ ((fp = sshkey_fingerprint(ಕೀಲಿ->cert->signature_ಕೀಲಿ,
			    options.fingerprint_hash, SSH_FP_DEFAULT)) == ರಿಕ್ತ)
				fatal_f("sshkey_fingerprint fail");
			verbose("Accepted certificate ID \"%s\" signed by "
			    "%s CA %s from %s@%s", ಕೀಲಿ->cert->ಕೀಲಿ_id,
			    sshkey_type(ಕೀಲಿ->cert->signature_ಕೀಲಿ), fp,
			    cuser, lookup);
		} ಅನ್ಯಥಾ {
			ಯದಿ ((fp = sshkey_fingerprint(ಕೀಲಿ,
			    options.fingerprint_hash, SSH_FP_DEFAULT)) == ರಿಕ್ತ)
				fatal_f("sshkey_fingerprint fail");
			verbose("Accepted %s public key %s from %s@%s",
			    sshkey_type(ಕೀಲಿ), fp, cuser, lookup);
		}
		ಮುಕ್ತ(fp);
	}

	ಪ್ರತ್ಯಾಗಮ (host_status == HOST_OK);
}

Authmethod method_hostbased = {
	&methodcfg_hostbased,
	userauth_hostbased,
};
