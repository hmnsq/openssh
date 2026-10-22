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

#समावेश "includes.h"

#समावेश <sys/types.h>

#समावेश <stdlib.h>
#समावेश <pwd.h>
#समावेश <string.h>
#समावेश <stdarg.h>

#समावेश "xmalloc.h"
#समावेश "ssh2.h"
#समावेश "packet.h"
#समावेश "kex.h"
#समावेश "sshbuf.h"
#समावेश "log.h"
#समावेश "misc.h"
#समावेश "servconf.h"
#समावेश "sshkey.h"
#समावेश "hostfile.h"
#समावेश "auth.h"
#समावेश "canohost.h"
#अगर_घोषित GSSAPI
#समावेश "ssh-gss.h"
#पूर्ण_अगर
#समावेश "monitor_wrap.h"
#समावेश "pathnames.h"
#समावेश "ssherr.h"
#समावेश "match.h"

/* import */
बाह्य ServerOptions options;
बाह्य काष्ठा authmethod_cfg methodcfg_hostbased;

अटल पूर्णांक
userauth_hostbased(काष्ठा ssh *ssh, स्थिर अक्षर *method)
{
	Authctxt *authctxt = ssh->authctxt;
	काष्ठा sshbuf *keyblob = शून्य, *b = शून्य;
	काष्ठा sshkey *कुंजी = शून्य;
	अक्षर *pkalg, *cuser, *chost;
	u_char *sig;
	माप_प्रकार alen, slen;
	पूर्णांक r, pktype, authenticated = 0;

	अगर ((r = sshpkt_get_cstring(ssh, &pkalg, &alen)) != 0 ||
	    (r = sshpkt_getb_froms(ssh, &keyblob)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &chost, शून्य)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &cuser, शून्य)) != 0 ||
	    (r = sshpkt_get_string(ssh, &sig, &slen)) != 0)
		fatal_fr(r, "parse packet");

	debug_f("cuser %s chost %s pkalg %s slen %zu",
	    cuser, chost, pkalg, slen);
#अगर_घोषित DEBUG_PK
	debug("signature:");
	sshbuf_dump_तथ्य(sig, slen, मानक_त्रुटि);
#पूर्ण_अगर
	pktype = sshkey_type_from_name(pkalg);
	अगर (pktype == कुंजी_UNSPEC) {
		/* this is perfectly legal */
		logit_f("unsupported public key algorithm: %s",
		    pkalg);
		जाओ done;
	}
	अगर (match_pattern_list(pkalg,
	    options.hostbased_accepted_algos, 0) != 1) {
		logit_f("signature algorithm %s not in "
		    "HostbasedAcceptedAlgorithms", pkalg);
		जाओ done;
	}
	अगर ((b = sshbuf_fromb(keyblob)) == शून्य)
		fatal_f("sshbuf_fromb failed");
	चयन ((r = sshkey_fromb_allowlist(b, &कुंजी,
	    options.hostbased_accepted_algos, options.ca_sign_algorithms))) {
	हाल 0:
		/* ok */
		अवरोध;
	हाल SSH_ERR_कुंजी_ALG_UNSUPPORTED:
		/* This shouldn't happen unless the client is being weird */
		logit_f("key algorithm differs from signature algorithm %s and "
		    "is not in HostbasedAcceptedAlgorithms", pkalg);
		जाओ done;
	हाल SSH_ERR_SIGN_ALG_UNSUPPORTED:
		logit_fr(r, "certificate signature algorithm not in "
		    "CASignatureAlgorithms");
		जाओ done;
	शेष:
		error_fr(r, "parse key");
		जाओ done;
	}
	sshbuf_free(b);
	b = शून्य;

	अगर (कुंजी->type != pktype || (sshkey_type_plain(pktype) == कुंजी_ECDSA &&
	    sshkey_ecdsa_nid_from_name(pkalg) != कुंजी->ecdsa_nid)) {
		error_f("key type mismatch for decoded key "
		    "(received %s, expected %s)", sshkey_ssh_name(कुंजी), pkalg);
		जाओ done;
	}
	अगर ((r = sshkey_check_rsa_लंबाई(कुंजी,
	    options.required_rsa_आकार)) != 0) {
		logit_r(r, "refusing %s key", sshkey_type(कुंजी));
		जाओ done;
	}

	अगर (!authctxt->valid || authctxt->user == शून्य) {
		debug2_f("disabled because of invalid user");
		जाओ done;
	}

	अगर ((b = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new failed");
	/* reconstruct packet */
	अगर ((r = sshbuf_put_stringb(b, ssh->kex->session_id)) != 0 ||
	    (r = sshbuf_put_u8(b, SSH2_संदेश_USERAUTH_REQUEST)) != 0 ||
	    (r = sshbuf_put_cstring(b, authctxt->user)) != 0 ||
	    (r = sshbuf_put_cstring(b, authctxt->service)) != 0 ||
	    (r = sshbuf_put_cstring(b, method)) != 0 ||
	    (r = sshbuf_put_string(b, pkalg, alen)) != 0 ||
	    (r = sshbuf_put_stringb(b, keyblob)) != 0 ||
	    (r = sshbuf_put_cstring(b, chost)) != 0 ||
	    (r = sshbuf_put_cstring(b, cuser)) != 0)
		fatal_fr(r, "reconstruct packet");
#अगर_घोषित DEBUG_PK
	sshbuf_dump(b, मानक_त्रुटि);
#पूर्ण_अगर

	auth2_record_info(authctxt,
	    "client user \"%.100s\", client host \"%.100s\"", cuser, chost);

	/* test for allowed key and correct signature */
	authenticated = 0;
	अगर (mm_hostbased_कुंजी_allowed(ssh, authctxt->pw, cuser,
	    chost, कुंजी) &&
	    mm_sshkey_verify(कुंजी, sig, slen,
	    sshbuf_ptr(b), sshbuf_len(b), pkalg, ssh->compat, शून्य) == 0)
		authenticated = 1;

	auth2_record_कुंजी(authctxt, authenticated, कुंजी);
done:
	debug2_f("authenticated %d", authenticated);
	sshkey_free(कुंजी);
	sshbuf_free(b);
	sshbuf_free(keyblob);
	मुक्त(pkalg);
	मुक्त(cuser);
	मुक्त(chost);
	मुक्त(sig);
	वापस authenticated;
}

/* return 1 if given hostkey is allowed */
पूर्णांक
hostbased_कुंजी_allowed(काष्ठा ssh *ssh, काष्ठा passwd *pw,
    स्थिर अक्षर *cuser, अक्षर *chost, काष्ठा sshkey *कुंजी)
{
	स्थिर अक्षर *resolvedname, *ipaddr, *lookup, *reason;
	HostStatus host_status;
	पूर्णांक len;
	अक्षर *fp;

	अगर (auth_कुंजी_is_revoked(कुंजी))
		वापस 0;

	resolvedname = auth_get_canonical_hostname(ssh, options.use_dns);
	ipaddr = ssh_remote_ipaddr(ssh);

	debug2_f("chost %s resolvedname %s ipaddr %s",
	    chost, resolvedname, ipaddr);

	अगर (((len = म_माप(chost)) > 0) && chost[len - 1] == '.') {
		debug2("stripping trailing dot from chost %s", chost);
		chost[len - 1] = '\0';
	}

	अगर (options.hostbased_uses_name_from_packet_only) {
		अगर (auth_rhosts2(pw, cuser, chost, chost) == 0) {
			debug2_f("auth_rhosts2 refused user \"%.100s\" "
			    "host \"%.100s\" (from packet)", cuser, chost);
			वापस 0;
		}
		lookup = chost;
	} अन्यथा {
		अगर (strcasecmp(resolvedname, chost) != 0)
			logit("userauth_hostbased mismatch: "
			    "client sends %s, but we resolve %s to %s",
			    chost, ipaddr, resolvedname);
		अगर (auth_rhosts2(pw, cuser, resolvedname, ipaddr) == 0) {
			debug2_f("auth_rhosts2 refused "
			    "user \"%.100s\" host \"%.100s\" addr \"%.100s\"",
			    cuser, resolvedname, ipaddr);
			वापस 0;
		}
		lookup = resolvedname;
	}
	debug2_f("access allowed by auth_rhosts2");

	अगर (sshkey_is_cert(कुंजी) && sshkey_cert_check_host(कुंजी, lookup,
	     options.ca_sign_algorithms, &reason) != 0) {
		अगर ((fp = sshkey_fingerprint(कुंजी->cert->signature_कुंजी,
		    options.fingerprint_hash, SSH_FP_DEFAULT)) == शून्य)
			fatal_f("sshkey_fingerprint fail");
		error("Refusing certificate ID \"%s\" serial=%llu signed by "
		    "%s CA %s: %s", कुंजी->cert->कुंजी_id,
		    (अचिन्हित दीर्घ दीर्घ)कुंजी->cert->serial,
		    sshkey_type(कुंजी->cert->signature_कुंजी), fp, reason);
		auth_debug_add("Refused Certificate ID \"%s\" serial=%llu: %s",
		    कुंजी->cert->कुंजी_id, (अचिन्हित दीर्घ दीर्घ)कुंजी->cert->serial,
		    reason);
		मुक्त(fp);
		वापस 0;
	}

	host_status = check_कुंजी_in_hostfiles(pw, कुंजी, lookup,
	    _PATH_SSH_SYSTEM_HOSTFILE,
	    options.ignore_user_known_hosts ? शून्य : _PATH_SSH_USER_HOSTFILE);

	/* backward compat if no key has been found. */
	अगर (host_status == HOST_NEW) {
		host_status = check_कुंजी_in_hostfiles(pw, कुंजी, lookup,
		    _PATH_SSH_SYSTEM_HOSTFILE2,
		    options.ignore_user_known_hosts ? शून्य :
		    _PATH_SSH_USER_HOSTFILE2);
	}

	अगर (host_status == HOST_OK) {
		अगर (sshkey_is_cert(कुंजी)) {
			अगर ((fp = sshkey_fingerprint(कुंजी->cert->signature_कुंजी,
			    options.fingerprint_hash, SSH_FP_DEFAULT)) == शून्य)
				fatal_f("sshkey_fingerprint fail");
			verbose("Accepted certificate ID \"%s\" signed by "
			    "%s CA %s from %s@%s", कुंजी->cert->कुंजी_id,
			    sshkey_type(कुंजी->cert->signature_कुंजी), fp,
			    cuser, lookup);
		} अन्यथा {
			अगर ((fp = sshkey_fingerprint(कुंजी,
			    options.fingerprint_hash, SSH_FP_DEFAULT)) == शून्य)
				fatal_f("sshkey_fingerprint fail");
			verbose("Accepted %s public key %s from %s@%s",
			    sshkey_type(कुंजी), fp, cuser, lookup);
		}
		मुक्त(fp);
	}

	वापस (host_status == HOST_OK);
}

Authmethod method_hostbased = {
	&methodcfg_hostbased,
	userauth_hostbased,
};
