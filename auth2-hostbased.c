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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <sys/types.h>

#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <pwd.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <stdarg.h>

#ଅନ୍ତର୍ଭାଵ "xmalloc.h"
#ଅନ୍ତର୍ଭାଵ "ssh2.h"
#ଅନ୍ତର୍ଭାଵ "packet.h"
#ଅନ୍ତର୍ଭାଵ "kex.h"
#ଅନ୍ତର୍ଭାଵ "sshbuf.h"
#ଅନ୍ତର୍ଭାଵ "log.h"
#ଅନ୍ତର୍ଭାଵ "misc.h"
#ଅନ୍ତର୍ଭାଵ "servconf.h"
#ଅନ୍ତର୍ଭାଵ "sshkey.h"
#ଅନ୍ତର୍ଭାଵ "hostfile.h"
#ଅନ୍ତର୍ଭାଵ "auth.h"
#ଅନ୍ତର୍ଭାଵ "canohost.h"
#ifdef GSSAPI
#ଅନ୍ତର୍ଭାଵ "ssh-gss.h"
#endif
#ଅନ୍ତର୍ଭାଵ "monitor_wrap.h"
#ଅନ୍ତର୍ଭାଵ "pathnames.h"
#ଅନ୍ତର୍ଭାଵ "ssherr.h"
#ଅନ୍ତର୍ଭାଵ "match.h"

/* import */
ବାହ୍ୟ ServerOptions options;
ବାହ୍ୟ ସଂରଚନା authmethod_cfg methodcfg_hostbased;

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
userauth_hostbased(ସଂରଚନା ssh *ssh, ଅଚଳ ଅକ୍ଷର *method)
{
	Authctxt *authctxt = ssh->authctxt;
	ସଂରଚନା sshbuf *keyblob = ଖାଲି, *b = ଖାଲି;
	ସଂରଚନା sshkey *ଚାବି = ଖାଲି;
	ଅକ୍ଷର *pkalg, *cuser, *chost;
	u_char *sig;
	size_t alen, slen;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, pktype, authenticated = 0;

	ଯଦି ((r = sshpkt_get_cstring(ssh, &pkalg, &alen)) != 0 ||
	    (r = sshpkt_getb_froms(ssh, &keyblob)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &chost, ଖାଲି)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &cuser, ଖାଲି)) != 0 ||
	    (r = sshpkt_get_string(ssh, &sig, &slen)) != 0)
		fatal_fr(r, "parse packet");

	debug_f("cuser %s chost %s pkalg %s slen %zu",
	    cuser, chost, pkalg, slen);
#ifdef DEBUG_PK
	debug("signature:");
	sshbuf_dump_data(sig, slen, stderr);
#endif
	pktype = sshkey_type_from_name(pkalg);
	ଯଦି (pktype == ଚାବି_UNSPEC) {
		/* this is perfectly legal */
		logit_f("unsupported public key algorithm: %s",
		    pkalg);
		ଯାଅ done;
	}
	ଯଦି (match_pattern_list(pkalg,
	    options.hostbased_accepted_algos, 0) != 1) {
		logit_f("signature algorithm %s not in "
		    "HostbasedAcceptedAlgorithms", pkalg);
		ଯାଅ done;
	}
	ଯଦି ((b = sshbuf_fromb(keyblob)) == ଖାଲି)
		fatal_f("sshbuf_fromb failed");
	ବାଛ ((r = sshkey_fromb_allowlist(b, &ଚାବି,
	    options.hostbased_accepted_algos, options.ca_sign_algorithms))) {
	ସ୍ଥିତି 0:
		/* ok */
		ଭାଙ୍ଗ;
	ସ୍ଥିତି SSH_ERR_ଚାବି_ALG_UNSUPPORTED:
		/* This shouldn't happen unless the client is being weird */
		logit_f("key algorithm differs from signature algorithm %s and "
		    "is not in HostbasedAcceptedAlgorithms", pkalg);
		ଯାଅ done;
	ସ୍ଥିତି SSH_ERR_SIGN_ALG_UNSUPPORTED:
		logit_fr(r, "certificate signature algorithm not in "
		    "CASignatureAlgorithms");
		ଯାଅ done;
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		error_fr(r, "parse key");
		ଯାଅ done;
	}
	sshbuf_free(b);
	b = ଖାଲି;

	ଯଦି (ଚାବି->type != pktype || (sshkey_type_plain(pktype) == ଚାବି_ECDSA &&
	    sshkey_ecdsa_nid_from_name(pkalg) != ଚାବି->ecdsa_nid)) {
		error_f("key type mismatch for decoded key "
		    "(received %s, expected %s)", sshkey_ssh_name(ଚାବି), pkalg);
		ଯାଅ done;
	}
	ଯଦି ((r = sshkey_check_rsa_length(ଚାବି,
	    options.required_rsa_size)) != 0) {
		logit_r(r, "refusing %s key", sshkey_type(ଚାବି));
		ଯାଅ done;
	}

	ଯଦି (!authctxt->valid || authctxt->user == ଖାଲି) {
		debug2_f("disabled because of invalid user");
		ଯାଅ done;
	}

	ଯଦି ((b = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new failed");
	/* reconstruct packet */
	ଯଦି ((r = sshbuf_put_stringb(b, ssh->kex->session_id)) != 0 ||
	    (r = sshbuf_put_u8(b, SSH2_ସନ୍ଦେଶ_USERAUTH_REQUEST)) != 0 ||
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
	ଯଦି (mm_hostbased_ଚାବି_allowed(ssh, authctxt->pw, cuser,
	    chost, ଚାବି) &&
	    mm_sshkey_verify(ଚାବି, sig, slen,
	    sshbuf_ptr(b), sshbuf_len(b), pkalg, ssh->compat, ଖାଲି) == 0)
		authenticated = 1;

	auth2_record_ଚାବି(authctxt, authenticated, ଚାବି);
done:
	debug2_f("authenticated %d", authenticated);
	sshkey_free(ଚାବି);
	sshbuf_free(b);
	sshbuf_free(keyblob);
	ମୁକ୍ତ(pkalg);
	ମୁକ୍ତ(cuser);
	ମୁକ୍ତ(chost);
	ମୁକ୍ତ(sig);
	ଫେରନ୍ତୁ authenticated;
}

/* return 1 if given hostkey is allowed */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
hostbased_ଚାବି_allowed(ସଂରଚନା ssh *ssh, ସଂରଚନା passwd *pw,
    ଅଚଳ ଅକ୍ଷର *cuser, ଅକ୍ଷର *chost, ସଂରଚନା sshkey *ଚାବି)
{
	ଅଚଳ ଅକ୍ଷର *resolvedname, *ipaddr, *lookup, *reason;
	HostStatus host_status;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା len;
	ଅକ୍ଷର *fp;

	ଯଦି (auth_ଚାବି_is_revoked(ଚାବି))
		ଫେରନ୍ତୁ 0;

	resolvedname = auth_get_canonical_hostname(ssh, options.use_dns);
	ipaddr = ssh_remote_ipaddr(ssh);

	debug2_f("chost %s resolvedname %s ipaddr %s",
	    chost, resolvedname, ipaddr);

	ଯଦି (((len = strlen(chost)) > 0) && chost[len - 1] == '.') {
		debug2("stripping trailing dot from chost %s", chost);
		chost[len - 1] = '\0';
	}

	ଯଦି (options.hostbased_uses_name_from_packet_only) {
		ଯଦି (auth_rhosts2(pw, cuser, chost, chost) == 0) {
			debug2_f("auth_rhosts2 refused user \"%.100s\" "
			    "host \"%.100s\" (from packet)", cuser, chost);
			ଫେରନ୍ତୁ 0;
		}
		lookup = chost;
	} ଅନ୍ୟଥା {
		ଯଦି (strcasecmp(resolvedname, chost) != 0)
			logit("userauth_hostbased mismatch: "
			    "client sends %s, but we resolve %s to %s",
			    chost, ipaddr, resolvedname);
		ଯଦି (auth_rhosts2(pw, cuser, resolvedname, ipaddr) == 0) {
			debug2_f("auth_rhosts2 refused "
			    "user \"%.100s\" host \"%.100s\" addr \"%.100s\"",
			    cuser, resolvedname, ipaddr);
			ଫେରନ୍ତୁ 0;
		}
		lookup = resolvedname;
	}
	debug2_f("access allowed by auth_rhosts2");

	ଯଦି (sshkey_is_cert(ଚାବି) && sshkey_cert_check_host(ଚାବି, lookup,
	     options.ca_sign_algorithms, &reason) != 0) {
		ଯଦି ((fp = sshkey_fingerprint(ଚାବି->cert->signature_ଚାବି,
		    options.fingerprint_hash, SSH_FP_DEFAULT)) == ଖାଲି)
			fatal_f("sshkey_fingerprint fail");
		error("Refusing certificate ID \"%s\" serial=%llu signed by "
		    "%s CA %s: %s", ଚାବି->cert->ଚାବି_id,
		    (unsigned long long)ଚାବି->cert->serial,
		    sshkey_type(ଚାବି->cert->signature_ଚାବି), fp, reason);
		auth_debug_add("Refused Certificate ID \"%s\" serial=%llu: %s",
		    ଚାବି->cert->ଚାବି_id, (unsigned long long)ଚାବି->cert->serial,
		    reason);
		ମୁକ୍ତ(fp);
		ଫେରନ୍ତୁ 0;
	}

	host_status = check_ଚାବି_in_hostfiles(pw, ଚାବି, lookup,
	    _PATH_SSH_SYSTEM_HOSTFILE,
	    options.ignore_user_known_hosts ? ଖାଲି : _PATH_SSH_USER_HOSTFILE);

	/* backward compat if no key has been found. */
	ଯଦି (host_status == HOST_NEW) {
		host_status = check_ଚାବି_in_hostfiles(pw, ଚାବି, lookup,
		    _PATH_SSH_SYSTEM_HOSTFILE2,
		    options.ignore_user_known_hosts ? ଖାଲି :
		    _PATH_SSH_USER_HOSTFILE2);
	}

	ଯଦି (host_status == HOST_OK) {
		ଯଦି (sshkey_is_cert(ଚାବି)) {
			ଯଦି ((fp = sshkey_fingerprint(ଚାବି->cert->signature_ଚାବି,
			    options.fingerprint_hash, SSH_FP_DEFAULT)) == ଖାଲି)
				fatal_f("sshkey_fingerprint fail");
			verbose("Accepted certificate ID \"%s\" signed by "
			    "%s CA %s from %s@%s", ଚାବି->cert->ଚାବି_id,
			    sshkey_type(ଚାବି->cert->signature_ଚାବି), fp,
			    cuser, lookup);
		} ଅନ୍ୟଥା {
			ଯଦି ((fp = sshkey_fingerprint(ଚାବି,
			    options.fingerprint_hash, SSH_FP_DEFAULT)) == ଖାଲି)
				fatal_f("sshkey_fingerprint fail");
			verbose("Accepted %s public key %s from %s@%s",
			    sshkey_type(ଚାବି), fp, cuser, lookup);
		}
		ମୁକ୍ତ(fp);
	}

	ଫେରନ୍ତୁ (host_status == HOST_OK);
}

Authmethod method_hostbased = {
	&methodcfg_hostbased,
	userauth_hostbased,
};
