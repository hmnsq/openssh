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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>

#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <pwd.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <stdarg.h>

#अन्तर्भाव "xmalloc.h"
#अन्तर्भाव "ssh2.h"
#अन्तर्भाव "packet.h"
#अन्तर्भाव "kex.h"
#अन्तर्भाव "sshbuf.h"
#अन्तर्भाव "log.h"
#अन्तर्भाव "misc.h"
#अन्तर्भाव "servconf.h"
#अन्तर्भाव "sshkey.h"
#अन्तर्भाव "hostfile.h"
#अन्तर्भाव "auth.h"
#अन्तर्भाव "canohost.h"
#ifdef GSSAPI
#अन्तर्भाव "ssh-gss.h"
#endif
#अन्तर्भाव "monitor_wrap.h"
#अन्तर्भाव "pathnames.h"
#अन्तर्भाव "ssherr.h"
#अन्तर्भाव "match.h"

/* import */
बाह्य ServerOptions options;
बाह्य संरचना authmethod_cfg methodcfg_hostbased;

स्थिर पूर्णाङ्क
userauth_hostbased(संरचना ssh *ssh, ध्रुव वर्ण *method)
{
	Authctxt *authctxt = ssh->authctxt;
	संरचना sshbuf *keyblob = रिक्त, *b = रिक्त;
	संरचना sshkey *कुञ्चिका = रिक्त;
	वर्ण *pkalg, *cuser, *chost;
	u_char *sig;
	size_t alen, slen;
	पूर्णाङ्क r, pktype, authenticated = 0;

	जइ ((r = sshpkt_get_cstring(ssh, &pkalg, &alen)) != 0 ||
	    (r = sshpkt_getb_froms(ssh, &keyblob)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &chost, रिक्त)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &cuser, रिक्त)) != 0 ||
	    (r = sshpkt_get_string(ssh, &sig, &slen)) != 0)
		fatal_fr(r, "parse packet");

	debug_f("cuser %s chost %s pkalg %s slen %zu",
	    cuser, chost, pkalg, slen);
#ifdef DEBUG_PK
	debug("signature:");
	sshbuf_dump_data(sig, slen, stderr);
#endif
	pktype = sshkey_type_from_name(pkalg);
	जइ (pktype == कुञ्चिका_UNSPEC) {
		/* this is perfectly legal */
		logit_f("unsupported public key algorithm: %s",
		    pkalg);
		गच्छ done;
	}
	जइ (match_pattern_list(pkalg,
	    options.hostbased_accepted_algos, 0) != 1) {
		logit_f("signature algorithm %s not in "
		    "HostbasedAcceptedAlgorithms", pkalg);
		गच्छ done;
	}
	जइ ((b = sshbuf_fromb(keyblob)) == रिक्त)
		fatal_f("sshbuf_fromb failed");
	विकल्प ((r = sshkey_fromb_allowlist(b, &कुञ्चिका,
	    options.hostbased_accepted_algos, options.ca_sign_algorithms))) {
	पक्ष 0:
		/* ok */
		भङ्ग;
	पक्ष SSH_ERR_कुञ्चिका_ALG_UNSUPPORTED:
		/* This shouldn't happen unless the client is being weird */
		logit_f("key algorithm differs from signature algorithm %s and "
		    "is not in HostbasedAcceptedAlgorithms", pkalg);
		गच्छ done;
	पक्ष SSH_ERR_SIGN_ALG_UNSUPPORTED:
		logit_fr(r, "certificate signature algorithm not in "
		    "CASignatureAlgorithms");
		गच्छ done;
	स्वभाव:
		error_fr(r, "parse key");
		गच्छ done;
	}
	sshbuf_free(b);
	b = रिक्त;

	जइ (कुञ्चिका->type != pktype || (sshkey_type_plain(pktype) == कुञ्चिका_ECDSA &&
	    sshkey_ecdsa_nid_from_name(pkalg) != कुञ्चिका->ecdsa_nid)) {
		error_f("key type mismatch for decoded key "
		    "(received %s, expected %s)", sshkey_ssh_name(कुञ्चिका), pkalg);
		गच्छ done;
	}
	जइ ((r = sshkey_check_rsa_length(कुञ्चिका,
	    options.required_rsa_size)) != 0) {
		logit_r(r, "refusing %s key", sshkey_type(कुञ्चिका));
		गच्छ done;
	}

	जइ (!authctxt->valid || authctxt->user == रिक्त) {
		debug2_f("disabled because of invalid user");
		गच्छ done;
	}

	जइ ((b = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	/* reconstruct packet */
	जइ ((r = sshbuf_put_stringb(b, ssh->kex->session_id)) != 0 ||
	    (r = sshbuf_put_u8(b, SSH2_सन्देशः_USERAUTH_REQUEST)) != 0 ||
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
	जइ (mm_hostbased_कुञ्चिका_allowed(ssh, authctxt->pw, cuser,
	    chost, कुञ्चिका) &&
	    mm_sshkey_verify(कुञ्चिका, sig, slen,
	    sshbuf_ptr(b), sshbuf_len(b), pkalg, ssh->compat, रिक्त) == 0)
		authenticated = 1;

	auth2_record_कुञ्चिका(authctxt, authenticated, कुञ्चिका);
done:
	debug2_f("authenticated %d", authenticated);
	sshkey_free(कुञ्चिका);
	sshbuf_free(b);
	sshbuf_free(keyblob);
	मुक्त(pkalg);
	मुक्त(cuser);
	मुक्त(chost);
	मुक्त(sig);
	प्रत्यागम authenticated;
}

/* return 1 if given hostkey is allowed */
पूर्णाङ्क
hostbased_कुञ्चिका_allowed(संरचना ssh *ssh, संरचना passwd *pw,
    ध्रुव वर्ण *cuser, वर्ण *chost, संरचना sshkey *कुञ्चिका)
{
	ध्रुव वर्ण *resolvedname, *ipaddr, *lookup, *reason;
	HostStatus host_status;
	पूर्णाङ्क len;
	वर्ण *fp;

	जइ (auth_कुञ्चिका_is_revoked(कुञ्चिका))
		प्रत्यागम 0;

	resolvedname = auth_get_canonical_hostname(ssh, options.use_dns);
	ipaddr = ssh_remote_ipaddr(ssh);

	debug2_f("chost %s resolvedname %s ipaddr %s",
	    chost, resolvedname, ipaddr);

	जइ (((len = strlen(chost)) > 0) && chost[len - 1] == '.') {
		debug2("stripping trailing dot from chost %s", chost);
		chost[len - 1] = '\0';
	}

	जइ (options.hostbased_uses_name_from_packet_only) {
		जइ (auth_rhosts2(pw, cuser, chost, chost) == 0) {
			debug2_f("auth_rhosts2 refused user \"%.100s\" "
			    "host \"%.100s\" (from packet)", cuser, chost);
			प्रत्यागम 0;
		}
		lookup = chost;
	} अण्णहा {
		जइ (strcasecmp(resolvedname, chost) != 0)
			logit("userauth_hostbased mismatch: "
			    "client sends %s, but we resolve %s to %s",
			    chost, ipaddr, resolvedname);
		जइ (auth_rhosts2(pw, cuser, resolvedname, ipaddr) == 0) {
			debug2_f("auth_rhosts2 refused "
			    "user \"%.100s\" host \"%.100s\" addr \"%.100s\"",
			    cuser, resolvedname, ipaddr);
			प्रत्यागम 0;
		}
		lookup = resolvedname;
	}
	debug2_f("access allowed by auth_rhosts2");

	जइ (sshkey_is_cert(कुञ्चिका) && sshkey_cert_check_host(कुञ्चिका, lookup,
	     options.ca_sign_algorithms, &reason) != 0) {
		जइ ((fp = sshkey_fingerprint(कुञ्चिका->cert->signature_कुञ्चिका,
		    options.fingerprint_hash, SSH_FP_DEFAULT)) == रिक्त)
			fatal_f("sshkey_fingerprint fail");
		error("Refusing certificate ID \"%s\" serial=%llu signed by "
		    "%s CA %s: %s", कुञ्चिका->cert->कुञ्चिका_id,
		    (unsigned long long)कुञ्चिका->cert->serial,
		    sshkey_type(कुञ्चिका->cert->signature_कुञ्चिका), fp, reason);
		auth_debug_add("Refused Certificate ID \"%s\" serial=%llu: %s",
		    कुञ्चिका->cert->कुञ्चिका_id, (unsigned long long)कुञ्चिका->cert->serial,
		    reason);
		मुक्त(fp);
		प्रत्यागम 0;
	}

	host_status = check_कुञ्चिका_in_hostfiles(pw, कुञ्चिका, lookup,
	    _PATH_SSH_SYSTEM_HOSTFILE,
	    options.ignore_user_known_hosts ? रिक्त : _PATH_SSH_USER_HOSTFILE);

	/* backward compat if no key has been found. */
	जइ (host_status == HOST_NEW) {
		host_status = check_कुञ्चिका_in_hostfiles(pw, कुञ्चिका, lookup,
		    _PATH_SSH_SYSTEM_HOSTFILE2,
		    options.ignore_user_known_hosts ? रिक्त :
		    _PATH_SSH_USER_HOSTFILE2);
	}

	जइ (host_status == HOST_OK) {
		जइ (sshkey_is_cert(कुञ्चिका)) {
			जइ ((fp = sshkey_fingerprint(कुञ्चिका->cert->signature_कुञ्चिका,
			    options.fingerprint_hash, SSH_FP_DEFAULT)) == रिक्त)
				fatal_f("sshkey_fingerprint fail");
			verbose("Accepted certificate ID \"%s\" signed by "
			    "%s CA %s from %s@%s", कुञ्चिका->cert->कुञ्चिका_id,
			    sshkey_type(कुञ्चिका->cert->signature_कुञ्चिका), fp,
			    cuser, lookup);
		} अण्णहा {
			जइ ((fp = sshkey_fingerprint(कुञ्चिका,
			    options.fingerprint_hash, SSH_FP_DEFAULT)) == रिक्त)
				fatal_f("sshkey_fingerprint fail");
			verbose("Accepted %s public key %s from %s@%s",
			    sshkey_type(कुञ्चिका), fp, cuser, lookup);
		}
		मुक्त(fp);
	}

	प्रत्यागम (host_status == HOST_OK);
}

Authmethod method_hostbased = {
	&methodcfg_hostbased,
	userauth_hostbased,
};
