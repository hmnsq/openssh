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

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>

#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <pwd.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <stdarg.h>

#അന്തര്ഭാവ "xmalloc.h"
#അന്തര്ഭാവ "ssh2.h"
#അന്തര്ഭാവ "packet.h"
#അന്തര്ഭാവ "kex.h"
#അന്തര്ഭാവ "sshbuf.h"
#അന്തര്ഭാവ "log.h"
#അന്തര്ഭാവ "misc.h"
#അന്തര്ഭാവ "servconf.h"
#അന്തര്ഭാവ "sshkey.h"
#അന്തര്ഭാവ "hostfile.h"
#അന്തര്ഭാവ "auth.h"
#അന്തര്ഭാവ "canohost.h"
#ifdef GSSAPI
#അന്തര്ഭാവ "ssh-gss.h"
#endif
#അന്തര്ഭാവ "monitor_wrap.h"
#അന്തര്ഭാവ "pathnames.h"
#അന്തര്ഭാവ "ssherr.h"
#അന്തര്ഭാവ "match.h"

/* import */
ബാഹ്യ ServerOptions options;
ബാഹ്യ ഘടന authmethod_cfg methodcfg_hostbased;

സ്ഥിതം പൂർണ്ണസംഖ്യ
userauth_hostbased(ഘടന ssh *ssh, സ്ഥിരം അക്ഷരം *method)
{
	Authctxt *authctxt = ssh->authctxt;
	ഘടന sshbuf *keyblob = ശൂന്യ, *b = ശൂന്യ;
	ഘടന sshkey *താക്കോൽ = ശൂന്യ;
	അക്ഷരം *pkalg, *cuser, *chost;
	u_char *sig;
	size_t alen, slen;
	പൂർണ്ണസംഖ്യ r, pktype, authenticated = 0;

	എങ്കിൽ ((r = sshpkt_get_cstring(ssh, &pkalg, &alen)) != 0 ||
	    (r = sshpkt_getb_froms(ssh, &keyblob)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &chost, ശൂന്യ)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &cuser, ശൂന്യ)) != 0 ||
	    (r = sshpkt_get_string(ssh, &sig, &slen)) != 0)
		fatal_fr(r, "parse packet");

	debug_f("cuser %s chost %s pkalg %s slen %zu",
	    cuser, chost, pkalg, slen);
#ifdef DEBUG_PK
	debug("signature:");
	sshbuf_dump_data(sig, slen, stderr);
#endif
	pktype = sshkey_type_from_name(pkalg);
	എങ്കിൽ (pktype == താക്കോൽ_UNSPEC) {
		/* this is perfectly legal */
		logit_f("unsupported public key algorithm: %s",
		    pkalg);
		പോകുക done;
	}
	എങ്കിൽ (match_pattern_list(pkalg,
	    options.hostbased_accepted_algos, 0) != 1) {
		logit_f("signature algorithm %s not in "
		    "HostbasedAcceptedAlgorithms", pkalg);
		പോകുക done;
	}
	എങ്കിൽ ((b = sshbuf_fromb(keyblob)) == ശൂന്യ)
		fatal_f("sshbuf_fromb failed");
	തിരഞ്ഞെടുപ്പ് ((r = sshkey_fromb_allowlist(b, &താക്കോൽ,
	    options.hostbased_accepted_algos, options.ca_sign_algorithms))) {
	അവസ്ഥ 0:
		/* ok */
		നിർത്തുക;
	അവസ്ഥ SSH_ERR_താക്കോൽ_ALG_UNSUPPORTED:
		/* This shouldn't happen unless the client is being weird */
		logit_f("key algorithm differs from signature algorithm %s and "
		    "is not in HostbasedAcceptedAlgorithms", pkalg);
		പോകുക done;
	അവസ്ഥ SSH_ERR_SIGN_ALG_UNSUPPORTED:
		logit_fr(r, "certificate signature algorithm not in "
		    "CASignatureAlgorithms");
		പോകുക done;
	സ്ഥിരസ്ഥിതി:
		error_fr(r, "parse key");
		പോകുക done;
	}
	sshbuf_free(b);
	b = ശൂന്യ;

	എങ്കിൽ (താക്കോൽ->type != pktype || (sshkey_type_plain(pktype) == താക്കോൽ_ECDSA &&
	    sshkey_ecdsa_nid_from_name(pkalg) != താക്കോൽ->ecdsa_nid)) {
		error_f("key type mismatch for decoded key "
		    "(received %s, expected %s)", sshkey_ssh_name(താക്കോൽ), pkalg);
		പോകുക done;
	}
	എങ്കിൽ ((r = sshkey_check_rsa_length(താക്കോൽ,
	    options.required_rsa_size)) != 0) {
		logit_r(r, "refusing %s key", sshkey_type(താക്കോൽ));
		പോകുക done;
	}

	എങ്കിൽ (!authctxt->valid || authctxt->user == ശൂന്യ) {
		debug2_f("disabled because of invalid user");
		പോകുക done;
	}

	എങ്കിൽ ((b = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new failed");
	/* reconstruct packet */
	എങ്കിൽ ((r = sshbuf_put_stringb(b, ssh->kex->session_id)) != 0 ||
	    (r = sshbuf_put_u8(b, SSH2_സന്ദേശം_USERAUTH_REQUEST)) != 0 ||
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
	എങ്കിൽ (mm_hostbased_താക്കോൽ_allowed(ssh, authctxt->pw, cuser,
	    chost, താക്കോൽ) &&
	    mm_sshkey_verify(താക്കോൽ, sig, slen,
	    sshbuf_ptr(b), sshbuf_len(b), pkalg, ssh->compat, ശൂന്യ) == 0)
		authenticated = 1;

	auth2_record_താക്കോൽ(authctxt, authenticated, താക്കോൽ);
done:
	debug2_f("authenticated %d", authenticated);
	sshkey_free(താക്കോൽ);
	sshbuf_free(b);
	sshbuf_free(keyblob);
	സ്വതന്ത്രം(pkalg);
	സ്വതന്ത്രം(cuser);
	സ്വതന്ത്രം(chost);
	സ്വതന്ത്രം(sig);
	തിരികെ authenticated;
}

/* return 1 if given hostkey is allowed */
പൂർണ്ണസംഖ്യ
hostbased_താക്കോൽ_allowed(ഘടന ssh *ssh, ഘടന passwd *pw,
    സ്ഥിരം അക്ഷരം *cuser, അക്ഷരം *chost, ഘടന sshkey *താക്കോൽ)
{
	സ്ഥിരം അക്ഷരം *resolvedname, *ipaddr, *lookup, *reason;
	HostStatus host_status;
	പൂർണ്ണസംഖ്യ len;
	അക്ഷരം *fp;

	എങ്കിൽ (auth_താക്കോൽ_is_revoked(താക്കോൽ))
		തിരികെ 0;

	resolvedname = auth_get_canonical_hostname(ssh, options.use_dns);
	ipaddr = ssh_remote_ipaddr(ssh);

	debug2_f("chost %s resolvedname %s ipaddr %s",
	    chost, resolvedname, ipaddr);

	എങ്കിൽ (((len = strlen(chost)) > 0) && chost[len - 1] == '.') {
		debug2("stripping trailing dot from chost %s", chost);
		chost[len - 1] = '\0';
	}

	എങ്കിൽ (options.hostbased_uses_name_from_packet_only) {
		എങ്കിൽ (auth_rhosts2(pw, cuser, chost, chost) == 0) {
			debug2_f("auth_rhosts2 refused user \"%.100s\" "
			    "host \"%.100s\" (from packet)", cuser, chost);
			തിരികെ 0;
		}
		lookup = chost;
	} അല്ലെങ്കിൽ {
		എങ്കിൽ (strcasecmp(resolvedname, chost) != 0)
			logit("userauth_hostbased mismatch: "
			    "client sends %s, but we resolve %s to %s",
			    chost, ipaddr, resolvedname);
		എങ്കിൽ (auth_rhosts2(pw, cuser, resolvedname, ipaddr) == 0) {
			debug2_f("auth_rhosts2 refused "
			    "user \"%.100s\" host \"%.100s\" addr \"%.100s\"",
			    cuser, resolvedname, ipaddr);
			തിരികെ 0;
		}
		lookup = resolvedname;
	}
	debug2_f("access allowed by auth_rhosts2");

	എങ്കിൽ (sshkey_is_cert(താക്കോൽ) && sshkey_cert_check_host(താക്കോൽ, lookup,
	     options.ca_sign_algorithms, &reason) != 0) {
		എങ്കിൽ ((fp = sshkey_fingerprint(താക്കോൽ->cert->signature_താക്കോൽ,
		    options.fingerprint_hash, SSH_FP_DEFAULT)) == ശൂന്യ)
			fatal_f("sshkey_fingerprint fail");
		error("Refusing certificate ID \"%s\" serial=%llu signed by "
		    "%s CA %s: %s", താക്കോൽ->cert->താക്കോൽ_id,
		    (unsigned long long)താക്കോൽ->cert->serial,
		    sshkey_type(താക്കോൽ->cert->signature_താക്കോൽ), fp, reason);
		auth_debug_add("Refused Certificate ID \"%s\" serial=%llu: %s",
		    താക്കോൽ->cert->താക്കോൽ_id, (unsigned long long)താക്കോൽ->cert->serial,
		    reason);
		സ്വതന്ത്രം(fp);
		തിരികെ 0;
	}

	host_status = check_താക്കോൽ_in_hostfiles(pw, താക്കോൽ, lookup,
	    _PATH_SSH_SYSTEM_HOSTFILE,
	    options.ignore_user_known_hosts ? ശൂന്യ : _PATH_SSH_USER_HOSTFILE);

	/* backward compat if no key has been found. */
	എങ്കിൽ (host_status == HOST_NEW) {
		host_status = check_താക്കോൽ_in_hostfiles(pw, താക്കോൽ, lookup,
		    _PATH_SSH_SYSTEM_HOSTFILE2,
		    options.ignore_user_known_hosts ? ശൂന്യ :
		    _PATH_SSH_USER_HOSTFILE2);
	}

	എങ്കിൽ (host_status == HOST_OK) {
		എങ്കിൽ (sshkey_is_cert(താക്കോൽ)) {
			എങ്കിൽ ((fp = sshkey_fingerprint(താക്കോൽ->cert->signature_താക്കോൽ,
			    options.fingerprint_hash, SSH_FP_DEFAULT)) == ശൂന്യ)
				fatal_f("sshkey_fingerprint fail");
			verbose("Accepted certificate ID \"%s\" signed by "
			    "%s CA %s from %s@%s", താക്കോൽ->cert->താക്കോൽ_id,
			    sshkey_type(താക്കോൽ->cert->signature_താക്കോൽ), fp,
			    cuser, lookup);
		} അല്ലെങ്കിൽ {
			എങ്കിൽ ((fp = sshkey_fingerprint(താക്കോൽ,
			    options.fingerprint_hash, SSH_FP_DEFAULT)) == ശൂന്യ)
				fatal_f("sshkey_fingerprint fail");
			verbose("Accepted %s public key %s from %s@%s",
			    sshkey_type(താക്കോൽ), fp, cuser, lookup);
		}
		സ്വതന്ത്രം(fp);
	}

	തിരികെ (host_status == HOST_OK);
}

Authmethod method_hostbased = {
	&methodcfg_hostbased,
	userauth_hostbased,
};
