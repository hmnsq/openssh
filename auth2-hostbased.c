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

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>

#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <pwd.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <stdarg.h>

#અન્તર્ભાવ "xmalloc.h"
#અન્તર્ભાવ "ssh2.h"
#અન્તર્ભાવ "packet.h"
#અન્તર્ભાવ "kex.h"
#અન્તર્ભાવ "sshbuf.h"
#અન્તર્ભાવ "log.h"
#અન્તર્ભાવ "misc.h"
#અન્તર્ભાવ "servconf.h"
#અન્તર્ભાવ "sshkey.h"
#અન્તર્ભાવ "hostfile.h"
#અન્તર્ભાવ "auth.h"
#અન્તર્ભાવ "canohost.h"
#ifdef GSSAPI
#અન્તર્ભાવ "ssh-gss.h"
#endif
#અન્તર્ભાવ "monitor_wrap.h"
#અન્તર્ભાવ "pathnames.h"
#અન્તર્ભાવ "ssherr.h"
#અન્તર્ભાવ "match.h"

/* import */
બાહ્ય ServerOptions options;
બાહ્ય સંરચના authmethod_cfg methodcfg_hostbased;

સ્થિર પૂર્ણાંક
userauth_hostbased(સંરચના ssh *ssh, અચલ અક્ષર *method)
{
	Authctxt *authctxt = ssh->authctxt;
	સંરચના sshbuf *keyblob = ખાલી, *b = ખાલી;
	સંરચના sshkey *ચાવી = ખાલી;
	અક્ષર *pkalg, *cuser, *chost;
	u_char *sig;
	size_t alen, slen;
	પૂર્ણાંક r, pktype, authenticated = 0;

	જો ((r = sshpkt_get_cstring(ssh, &pkalg, &alen)) != 0 ||
	    (r = sshpkt_getb_froms(ssh, &keyblob)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &chost, ખાલી)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &cuser, ખાલી)) != 0 ||
	    (r = sshpkt_get_string(ssh, &sig, &slen)) != 0)
		fatal_fr(r, "parse packet");

	debug_f("cuser %s chost %s pkalg %s slen %zu",
	    cuser, chost, pkalg, slen);
#ifdef DEBUG_PK
	debug("signature:");
	sshbuf_dump_data(sig, slen, stderr);
#endif
	pktype = sshkey_type_from_name(pkalg);
	જો (pktype == ચાવી_UNSPEC) {
		/* this is perfectly legal */
		logit_f("unsupported public key algorithm: %s",
		    pkalg);
		જાઓ done;
	}
	જો (match_pattern_list(pkalg,
	    options.hostbased_accepted_algos, 0) != 1) {
		logit_f("signature algorithm %s not in "
		    "HostbasedAcceptedAlgorithms", pkalg);
		જાઓ done;
	}
	જો ((b = sshbuf_fromb(keyblob)) == ખાલી)
		fatal_f("sshbuf_fromb failed");
	પસંદગી ((r = sshkey_fromb_allowlist(b, &ચાવી,
	    options.hostbased_accepted_algos, options.ca_sign_algorithms))) {
	સ્થિતિ 0:
		/* ok */
		તોડો;
	સ્થિતિ SSH_ERR_ચાવી_ALG_UNSUPPORTED:
		/* This shouldn't happen unless the client is being weird */
		logit_f("key algorithm differs from signature algorithm %s and "
		    "is not in HostbasedAcceptedAlgorithms", pkalg);
		જાઓ done;
	સ્થિતિ SSH_ERR_SIGN_ALG_UNSUPPORTED:
		logit_fr(r, "certificate signature algorithm not in "
		    "CASignatureAlgorithms");
		જાઓ done;
	મૂળભૂત:
		error_fr(r, "parse key");
		જાઓ done;
	}
	sshbuf_free(b);
	b = ખાલી;

	જો (ચાવી->type != pktype || (sshkey_type_plain(pktype) == ચાવી_ECDSA &&
	    sshkey_ecdsa_nid_from_name(pkalg) != ચાવી->ecdsa_nid)) {
		error_f("key type mismatch for decoded key "
		    "(received %s, expected %s)", sshkey_ssh_name(ચાવી), pkalg);
		જાઓ done;
	}
	જો ((r = sshkey_check_rsa_length(ચાવી,
	    options.required_rsa_size)) != 0) {
		logit_r(r, "refusing %s key", sshkey_type(ચાવી));
		જાઓ done;
	}

	જો (!authctxt->valid || authctxt->user == ખાલી) {
		debug2_f("disabled because of invalid user");
		જાઓ done;
	}

	જો ((b = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new failed");
	/* reconstruct packet */
	જો ((r = sshbuf_put_stringb(b, ssh->kex->session_id)) != 0 ||
	    (r = sshbuf_put_u8(b, SSH2_સંદેશ_USERAUTH_REQUEST)) != 0 ||
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
	જો (mm_hostbased_ચાવી_allowed(ssh, authctxt->pw, cuser,
	    chost, ચાવી) &&
	    mm_sshkey_verify(ચાવી, sig, slen,
	    sshbuf_ptr(b), sshbuf_len(b), pkalg, ssh->compat, ખાલી) == 0)
		authenticated = 1;

	auth2_record_ચાવી(authctxt, authenticated, ચાવી);
done:
	debug2_f("authenticated %d", authenticated);
	sshkey_free(ચાવી);
	sshbuf_free(b);
	sshbuf_free(keyblob);
	મુક્ત(pkalg);
	મુક્ત(cuser);
	મુક્ત(chost);
	મુક્ત(sig);
	પાછા authenticated;
}

/* return 1 if given hostkey is allowed */
પૂર્ણાંક
hostbased_ચાવી_allowed(સંરચના ssh *ssh, સંરચના passwd *pw,
    અચલ અક્ષર *cuser, અક્ષર *chost, સંરચના sshkey *ચાવી)
{
	અચલ અક્ષર *resolvedname, *ipaddr, *lookup, *reason;
	HostStatus host_status;
	પૂર્ણાંક len;
	અક્ષર *fp;

	જો (auth_ચાવી_is_revoked(ચાવી))
		પાછા 0;

	resolvedname = auth_get_canonical_hostname(ssh, options.use_dns);
	ipaddr = ssh_remote_ipaddr(ssh);

	debug2_f("chost %s resolvedname %s ipaddr %s",
	    chost, resolvedname, ipaddr);

	જો (((len = strlen(chost)) > 0) && chost[len - 1] == '.') {
		debug2("stripping trailing dot from chost %s", chost);
		chost[len - 1] = '\0';
	}

	જો (options.hostbased_uses_name_from_packet_only) {
		જો (auth_rhosts2(pw, cuser, chost, chost) == 0) {
			debug2_f("auth_rhosts2 refused user \"%.100s\" "
			    "host \"%.100s\" (from packet)", cuser, chost);
			પાછા 0;
		}
		lookup = chost;
	} નહીંતર {
		જો (strcasecmp(resolvedname, chost) != 0)
			logit("userauth_hostbased mismatch: "
			    "client sends %s, but we resolve %s to %s",
			    chost, ipaddr, resolvedname);
		જો (auth_rhosts2(pw, cuser, resolvedname, ipaddr) == 0) {
			debug2_f("auth_rhosts2 refused "
			    "user \"%.100s\" host \"%.100s\" addr \"%.100s\"",
			    cuser, resolvedname, ipaddr);
			પાછા 0;
		}
		lookup = resolvedname;
	}
	debug2_f("access allowed by auth_rhosts2");

	જો (sshkey_is_cert(ચાવી) && sshkey_cert_check_host(ચાવી, lookup,
	     options.ca_sign_algorithms, &reason) != 0) {
		જો ((fp = sshkey_fingerprint(ચાવી->cert->signature_ચાવી,
		    options.fingerprint_hash, SSH_FP_DEFAULT)) == ખાલી)
			fatal_f("sshkey_fingerprint fail");
		error("Refusing certificate ID \"%s\" serial=%llu signed by "
		    "%s CA %s: %s", ચાવી->cert->ચાવી_id,
		    (unsigned long long)ચાવી->cert->serial,
		    sshkey_type(ચાવી->cert->signature_ચાવી), fp, reason);
		auth_debug_add("Refused Certificate ID \"%s\" serial=%llu: %s",
		    ચાવી->cert->ચાવી_id, (unsigned long long)ચાવી->cert->serial,
		    reason);
		મુક્ત(fp);
		પાછા 0;
	}

	host_status = check_ચાવી_in_hostfiles(pw, ચાવી, lookup,
	    _PATH_SSH_SYSTEM_HOSTFILE,
	    options.ignore_user_known_hosts ? ખાલી : _PATH_SSH_USER_HOSTFILE);

	/* backward compat if no key has been found. */
	જો (host_status == HOST_NEW) {
		host_status = check_ચાવી_in_hostfiles(pw, ચાવી, lookup,
		    _PATH_SSH_SYSTEM_HOSTFILE2,
		    options.ignore_user_known_hosts ? ખાલી :
		    _PATH_SSH_USER_HOSTFILE2);
	}

	જો (host_status == HOST_OK) {
		જો (sshkey_is_cert(ચાવી)) {
			જો ((fp = sshkey_fingerprint(ચાવી->cert->signature_ચાવી,
			    options.fingerprint_hash, SSH_FP_DEFAULT)) == ખાલી)
				fatal_f("sshkey_fingerprint fail");
			verbose("Accepted certificate ID \"%s\" signed by "
			    "%s CA %s from %s@%s", ચાવી->cert->ચાવી_id,
			    sshkey_type(ચાવી->cert->signature_ચાવી), fp,
			    cuser, lookup);
		} નહીંતર {
			જો ((fp = sshkey_fingerprint(ચાવી,
			    options.fingerprint_hash, SSH_FP_DEFAULT)) == ખાલી)
				fatal_f("sshkey_fingerprint fail");
			verbose("Accepted %s public key %s from %s@%s",
			    sshkey_type(ચાવી), fp, cuser, lookup);
		}
		મુક્ત(fp);
	}

	પાછા (host_status == HOST_OK);
}

Authmethod method_hostbased = {
	&methodcfg_hostbased,
	userauth_hostbased,
};
