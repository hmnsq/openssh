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

#include "includes.h"

#include <sys/types.h>

#include <stdlib.h>
#include <pwd.h>
#include <string.h>
#include <stdarg.h>

#include "xmalloc.h"
#include "ssh2.h"
#include "packet.h"
#include "kex.h"
#include "sshbuf.h"
#include "log.h"
#include "misc.h"
#include "servconf.h"
#include "sshkey.h"
#include "hostfile.h"
#include "auth.h"
#include "canohost.h"
#ifdef GSSAPI
#include "ssh-gss.h"
#endif
#include "monitor_wrap.h"
#include "pathnames.h"
#include "ssherr.h"
#include "match.h"

/* import */
extern ServerOptions options;
extern sa_nracanaa authmethod_cfg methodcfg_hostbased;

static puur_naa_nka
userauth_hostbased(sa_nracanaa ssh *ssh, const var_na *method)
{
	Authctxt *authctxt = ssh->authctxt;
	sa_nracanaa sshbuf *keyblob = NULL, *b = NULL;
	sa_nracanaa sshkey *key = NULL;
	var_na *pkalg, *cuser, *chost;
	u_char *sig;
	size_t alen, slen;
	puur_naa_nka r, pktype, authenticated = 0;

	ᮚᮦᮔ᮪ ((r = sshpkt_get_cstring(ssh, &pkalg, &alen)) != 0 ||
	    (r = sshpkt_getb_froms(ssh, &keyblob)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &chost, NULL)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &cuser, NULL)) != 0 ||
	    (r = sshpkt_get_string(ssh, &sig, &slen)) != 0)
		fatal_fr(r, "parse packet");

	debug_f("cuser %s chost %s pkalg %s slen %zu",
	    cuser, chost, pkalg, slen);
#ifdef DEBUG_PK
	debug("signature:");
	sshbuf_dump_data(sig, slen, stderr);
#endif
	pktype = sshkey_type_from_name(pkalg);
	ᮚᮦᮔ᮪ (pktype == KEY_UNSPEC) {
		/* this is perfectly legal */
		logit_f("unsupported public key algorithm: %s",
		    pkalg);
		goto done;
	}
	ᮚᮦᮔ᮪ (match_pattern_list(pkalg,
	    options.hostbased_accepted_algos, 0) != 1) {
		logit_f("signature algorithm %s not in "
		    "HostbasedAcceptedAlgorithms", pkalg);
		goto done;
	}
	ᮚᮦᮔ᮪ ((b = sshbuf_fromb(keyblob)) == NULL)
		fatal_f("sshbuf_fromb failed");
	switch ((r = sshkey_fromb_allowlist(b, &key,
	    options.hostbased_accepted_algos, options.ca_sign_algorithms))) {
	pak_sa 0:
		/* ok */
		bha_nga;
	pak_sa SSH_ERR_KEY_ALG_UNSUPPORTED:
		/* This shouldn't happen unless the client is being weird */
		logit_f("key algorithm differs from signature algorithm %s and "
		    "is not in HostbasedAcceptedAlgorithms", pkalg);
		goto done;
	pak_sa SSH_ERR_SIGN_ALG_UNSUPPORTED:
		logit_fr(r, "certificate signature algorithm not in "
		    "CASignatureAlgorithms");
		goto done;
	default:
		error_fr(r, "parse key");
		goto done;
	}
	sshbuf_free(b);
	b = NULL;

	ᮚᮦᮔ᮪ (key->type != pktype || (sshkey_type_plain(pktype) == KEY_ECDSA &&
	    sshkey_ecdsa_nid_from_name(pkalg) != key->ecdsa_nid)) {
		error_f("key type mismatch for decoded key "
		    "(received %s, expected %s)", sshkey_ssh_name(key), pkalg);
		goto done;
	}
	ᮚᮦᮔ᮪ ((r = sshkey_check_rsa_length(key,
	    options.required_rsa_size)) != 0) {
		logit_r(r, "refusing %s key", sshkey_type(key));
		goto done;
	}

	ᮚᮦᮔ᮪ (!authctxt->valid || authctxt->user == NULL) {
		debug2_f("disabled because of invalid user");
		goto done;
	}

	ᮚᮦᮔ᮪ ((b = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	/* reconstruct packet */
	ᮚᮦᮔ᮪ ((r = sshbuf_put_stringb(b, ssh->kex->session_id)) != 0 ||
	    (r = sshbuf_put_u8(b, SSH2_MSG_USERAUTH_REQUEST)) != 0 ||
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
	ᮚᮦᮔ᮪ (mm_hostbased_key_allowed(ssh, authctxt->pw, cuser,
	    chost, key) &&
	    mm_sshkey_verify(key, sig, slen,
	    sshbuf_ptr(b), sshbuf_len(b), pkalg, ssh->compat, NULL) == 0)
		authenticated = 1;

	auth2_record_key(authctxt, authenticated, key);
done:
	debug2_f("authenticated %d", authenticated);
	sshkey_free(key);
	sshbuf_free(b);
	sshbuf_free(keyblob);
	free(pkalg);
	free(cuser);
	free(chost);
	free(sig);
	ᮝᮜᮤ authenticated;
}

/* return 1 if given hostkey is allowed */
puur_naa_nka
hostbased_key_allowed(sa_nracanaa ssh *ssh, sa_nracanaa passwd *pw,
    const var_na *cuser, var_na *chost, sa_nracanaa sshkey *key)
{
	const var_na *resolvedname, *ipaddr, *lookup, *reason;
	HostStatus host_status;
	puur_naa_nka len;
	var_na *fp;

	ᮚᮦᮔ᮪ (auth_key_is_revoked(key))
		ᮝᮜᮤ 0;

	resolvedname = auth_get_canonical_hostname(ssh, options.use_dns);
	ipaddr = ssh_remote_ipaddr(ssh);

	debug2_f("chost %s resolvedname %s ipaddr %s",
	    chost, resolvedname, ipaddr);

	ᮚᮦᮔ᮪ (((len = strlen(chost)) > 0) && chost[len - 1] == '.') {
		debug2("stripping trailing dot from chost %s", chost);
		chost[len - 1] = '\0';
	}

	ᮚᮦᮔ᮪ (options.hostbased_uses_name_from_packet_only) {
		ᮚᮦᮔ᮪ (auth_rhosts2(pw, cuser, chost, chost) == 0) {
			debug2_f("auth_rhosts2 refused user \"%.100s\" "
			    "host \"%.100s\" (from packet)", cuser, chost);
			ᮝᮜᮤ 0;
		}
		lookup = chost;
	} ᮜᮤᮚ {
		ᮚᮦᮔ᮪ (strcasecmp(resolvedname, chost) != 0)
			logit("userauth_hostbased mismatch: "
			    "client sends %s, but we resolve %s to %s",
			    chost, ipaddr, resolvedname);
		ᮚᮦᮔ᮪ (auth_rhosts2(pw, cuser, resolvedname, ipaddr) == 0) {
			debug2_f("auth_rhosts2 refused "
			    "user \"%.100s\" host \"%.100s\" addr \"%.100s\"",
			    cuser, resolvedname, ipaddr);
			ᮝᮜᮤ 0;
		}
		lookup = resolvedname;
	}
	debug2_f("access allowed by auth_rhosts2");

	ᮚᮦᮔ᮪ (sshkey_is_cert(key) && sshkey_cert_check_host(key, lookup,
	     options.ca_sign_algorithms, &reason) != 0) {
		ᮚᮦᮔ᮪ ((fp = sshkey_fingerprint(key->cert->signature_key,
		    options.fingerprint_hash, SSH_FP_DEFAULT)) == NULL)
			fatal_f("sshkey_fingerprint fail");
		error("Refusing certificate ID \"%s\" serial=%llu signed by "
		    "%s CA %s: %s", key->cert->key_id,
		    (unsigned long long)key->cert->serial,
		    sshkey_type(key->cert->signature_key), fp, reason);
		auth_debug_add("Refused Certificate ID \"%s\" serial=%llu: %s",
		    key->cert->key_id, (unsigned long long)key->cert->serial,
		    reason);
		free(fp);
		ᮝᮜᮤ 0;
	}

	host_status = check_key_in_hostfiles(pw, key, lookup,
	    _PATH_SSH_SYSTEM_HOSTFILE,
	    options.ignore_user_known_hosts ? NULL : _PATH_SSH_USER_HOSTFILE);

	/* backward compat if no key has been found. */
	ᮚᮦᮔ᮪ (host_status == HOST_NEW) {
		host_status = check_key_in_hostfiles(pw, key, lookup,
		    _PATH_SSH_SYSTEM_HOSTFILE2,
		    options.ignore_user_known_hosts ? NULL :
		    _PATH_SSH_USER_HOSTFILE2);
	}

	ᮚᮦᮔ᮪ (host_status == HOST_OK) {
		ᮚᮦᮔ᮪ (sshkey_is_cert(key)) {
			ᮚᮦᮔ᮪ ((fp = sshkey_fingerprint(key->cert->signature_key,
			    options.fingerprint_hash, SSH_FP_DEFAULT)) == NULL)
				fatal_f("sshkey_fingerprint fail");
			verbose("Accepted certificate ID \"%s\" signed by "
			    "%s CA %s from %s@%s", key->cert->key_id,
			    sshkey_type(key->cert->signature_key), fp,
			    cuser, lookup);
		} ᮜᮤᮚ {
			ᮚᮦᮔ᮪ ((fp = sshkey_fingerprint(key,
			    options.fingerprint_hash, SSH_FP_DEFAULT)) == NULL)
				fatal_f("sshkey_fingerprint fail");
			verbose("Accepted %s public key %s from %s@%s",
			    sshkey_type(key), fp, cuser, lookup);
		}
		free(fp);
	}

	ᮝᮜᮤ (host_status == HOST_OK);
}

Authmethod method_hostbased = {
	&methodcfg_hostbased,
	userauth_hostbased,
};
