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

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>

#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <pwd.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <stdarg.h>

#அந்தர்பாவ "xmalloc.h"
#அந்தர்பாவ "ssh2.h"
#அந்தர்பாவ "packet.h"
#அந்தர்பாவ "kex.h"
#அந்தர்பாவ "sshbuf.h"
#அந்தர்பாவ "log.h"
#அந்தர்பாவ "misc.h"
#அந்தர்பாவ "servconf.h"
#அந்தர்பாவ "sshkey.h"
#அந்தர்பாவ "hostfile.h"
#அந்தர்பாவ "auth.h"
#அந்தர்பாவ "canohost.h"
#ifdef GSSAPI
#அந்தர்பாவ "ssh-gss.h"
#endif
#அந்தர்பாவ "monitor_wrap.h"
#அந்தர்பாவ "pathnames.h"
#அந்தர்பாவ "ssherr.h"
#அந்தர்பாவ "match.h"

/* import */
வெளி ServerOptions options;
வெளி கட்டமைப்பு authmethod_cfg methodcfg_hostbased;

நிலையான முழு
userauth_hostbased(கட்டமைப்பு ssh *ssh, மாறிலி எழுத்து *method)
{
	Authctxt *authctxt = ssh->authctxt;
	கட்டமைப்பு sshbuf *keyblob = வெற்று, *b = வெற்று;
	கட்டமைப்பு sshkey *சாவி = வெற்று;
	எழுத்து *pkalg, *cuser, *chost;
	u_char *sig;
	size_t alen, slen;
	முழு r, pktype, authenticated = 0;

	எனில் ((r = sshpkt_get_cstring(ssh, &pkalg, &alen)) != 0 ||
	    (r = sshpkt_getb_froms(ssh, &keyblob)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &chost, வெற்று)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &cuser, வெற்று)) != 0 ||
	    (r = sshpkt_get_string(ssh, &sig, &slen)) != 0)
		fatal_fr(r, "parse packet");

	debug_f("cuser %s chost %s pkalg %s slen %zu",
	    cuser, chost, pkalg, slen);
#ifdef DEBUG_PK
	debug("signature:");
	sshbuf_dump_data(sig, slen, stderr);
#endif
	pktype = sshkey_type_from_name(pkalg);
	எனில் (pktype == சாவி_UNSPEC) {
		/* this is perfectly legal */
		logit_f("unsupported public key algorithm: %s",
		    pkalg);
		செல் done;
	}
	எனில் (match_pattern_list(pkalg,
	    options.hostbased_accepted_algos, 0) != 1) {
		logit_f("signature algorithm %s not in "
		    "HostbasedAcceptedAlgorithms", pkalg);
		செல் done;
	}
	எனில் ((b = sshbuf_fromb(keyblob)) == வெற்று)
		fatal_f("sshbuf_fromb failed");
	தேர்வு ((r = sshkey_fromb_allowlist(b, &சாவி,
	    options.hostbased_accepted_algos, options.ca_sign_algorithms))) {
	நிலை 0:
		/* ok */
		நிறுத்து;
	நிலை SSH_ERR_சாவி_ALG_UNSUPPORTED:
		/* This shouldn't happen unless the client is being weird */
		logit_f("key algorithm differs from signature algorithm %s and "
		    "is not in HostbasedAcceptedAlgorithms", pkalg);
		செல் done;
	நிலை SSH_ERR_SIGN_ALG_UNSUPPORTED:
		logit_fr(r, "certificate signature algorithm not in "
		    "CASignatureAlgorithms");
		செல் done;
	இயல்பு:
		error_fr(r, "parse key");
		செல் done;
	}
	sshbuf_free(b);
	b = வெற்று;

	எனில் (சாவி->type != pktype || (sshkey_type_plain(pktype) == சாவி_ECDSA &&
	    sshkey_ecdsa_nid_from_name(pkalg) != சாவி->ecdsa_nid)) {
		error_f("key type mismatch for decoded key "
		    "(received %s, expected %s)", sshkey_ssh_name(சாவி), pkalg);
		செல் done;
	}
	எனில் ((r = sshkey_check_rsa_length(சாவி,
	    options.required_rsa_size)) != 0) {
		logit_r(r, "refusing %s key", sshkey_type(சாவி));
		செல் done;
	}

	எனில் (!authctxt->valid || authctxt->user == வெற்று) {
		debug2_f("disabled because of invalid user");
		செல் done;
	}

	எனில் ((b = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new failed");
	/* reconstruct packet */
	எனில் ((r = sshbuf_put_stringb(b, ssh->kex->session_id)) != 0 ||
	    (r = sshbuf_put_u8(b, SSH2_செய்தி_USERAUTH_REQUEST)) != 0 ||
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
	எனில் (mm_hostbased_சாவி_allowed(ssh, authctxt->pw, cuser,
	    chost, சாவி) &&
	    mm_sshkey_verify(சாவி, sig, slen,
	    sshbuf_ptr(b), sshbuf_len(b), pkalg, ssh->compat, வெற்று) == 0)
		authenticated = 1;

	auth2_record_சாவி(authctxt, authenticated, சாவி);
done:
	debug2_f("authenticated %d", authenticated);
	sshkey_free(சாவி);
	sshbuf_free(b);
	sshbuf_free(keyblob);
	விடுவி(pkalg);
	விடுவி(cuser);
	விடுவி(chost);
	விடுவி(sig);
	திரும்பு authenticated;
}

/* return 1 if given hostkey is allowed */
முழு
hostbased_சாவி_allowed(கட்டமைப்பு ssh *ssh, கட்டமைப்பு passwd *pw,
    மாறிலி எழுத்து *cuser, எழுத்து *chost, கட்டமைப்பு sshkey *சாவி)
{
	மாறிலி எழுத்து *resolvedname, *ipaddr, *lookup, *reason;
	HostStatus host_status;
	முழு len;
	எழுத்து *fp;

	எனில் (auth_சாவி_is_revoked(சாவி))
		திரும்பு 0;

	resolvedname = auth_get_canonical_hostname(ssh, options.use_dns);
	ipaddr = ssh_remote_ipaddr(ssh);

	debug2_f("chost %s resolvedname %s ipaddr %s",
	    chost, resolvedname, ipaddr);

	எனில் (((len = strlen(chost)) > 0) && chost[len - 1] == '.') {
		debug2("stripping trailing dot from chost %s", chost);
		chost[len - 1] = '\0';
	}

	எனில் (options.hostbased_uses_name_from_packet_only) {
		எனில் (auth_rhosts2(pw, cuser, chost, chost) == 0) {
			debug2_f("auth_rhosts2 refused user \"%.100s\" "
			    "host \"%.100s\" (from packet)", cuser, chost);
			திரும்பு 0;
		}
		lookup = chost;
	} இல்லையெனில் {
		எனில் (strcasecmp(resolvedname, chost) != 0)
			logit("userauth_hostbased mismatch: "
			    "client sends %s, but we resolve %s to %s",
			    chost, ipaddr, resolvedname);
		எனில் (auth_rhosts2(pw, cuser, resolvedname, ipaddr) == 0) {
			debug2_f("auth_rhosts2 refused "
			    "user \"%.100s\" host \"%.100s\" addr \"%.100s\"",
			    cuser, resolvedname, ipaddr);
			திரும்பு 0;
		}
		lookup = resolvedname;
	}
	debug2_f("access allowed by auth_rhosts2");

	எனில் (sshkey_is_cert(சாவி) && sshkey_cert_check_host(சாவி, lookup,
	     options.ca_sign_algorithms, &reason) != 0) {
		எனில் ((fp = sshkey_fingerprint(சாவி->cert->signature_சாவி,
		    options.fingerprint_hash, SSH_FP_DEFAULT)) == வெற்று)
			fatal_f("sshkey_fingerprint fail");
		error("Refusing certificate ID \"%s\" serial=%llu signed by "
		    "%s CA %s: %s", சாவி->cert->சாவி_id,
		    (unsigned long long)சாவி->cert->serial,
		    sshkey_type(சாவி->cert->signature_சாவி), fp, reason);
		auth_debug_add("Refused Certificate ID \"%s\" serial=%llu: %s",
		    சாவி->cert->சாவி_id, (unsigned long long)சாவி->cert->serial,
		    reason);
		விடுவி(fp);
		திரும்பு 0;
	}

	host_status = check_சாவி_in_hostfiles(pw, சாவி, lookup,
	    _PATH_SSH_SYSTEM_HOSTFILE,
	    options.ignore_user_known_hosts ? வெற்று : _PATH_SSH_USER_HOSTFILE);

	/* backward compat if no key has been found. */
	எனில் (host_status == HOST_NEW) {
		host_status = check_சாவி_in_hostfiles(pw, சாவி, lookup,
		    _PATH_SSH_SYSTEM_HOSTFILE2,
		    options.ignore_user_known_hosts ? வெற்று :
		    _PATH_SSH_USER_HOSTFILE2);
	}

	எனில் (host_status == HOST_OK) {
		எனில் (sshkey_is_cert(சாவி)) {
			எனில் ((fp = sshkey_fingerprint(சாவி->cert->signature_சாவி,
			    options.fingerprint_hash, SSH_FP_DEFAULT)) == வெற்று)
				fatal_f("sshkey_fingerprint fail");
			verbose("Accepted certificate ID \"%s\" signed by "
			    "%s CA %s from %s@%s", சாவி->cert->சாவி_id,
			    sshkey_type(சாவி->cert->signature_சாவி), fp,
			    cuser, lookup);
		} இல்லையெனில் {
			எனில் ((fp = sshkey_fingerprint(சாவி,
			    options.fingerprint_hash, SSH_FP_DEFAULT)) == வெற்று)
				fatal_f("sshkey_fingerprint fail");
			verbose("Accepted %s public key %s from %s@%s",
			    sshkey_type(சாவி), fp, cuser, lookup);
		}
		விடுவி(fp);
	}

	திரும்பு (host_status == HOST_OK);
}

Authmethod method_hostbased = {
	&methodcfg_hostbased,
	userauth_hostbased,
};
