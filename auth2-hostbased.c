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

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>

#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <pwd.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <stdarg.h>

#అన్తర్భావ "xmalloc.h"
#అన్తర్భావ "ssh2.h"
#అన్తర్భావ "packet.h"
#అన్తర్భావ "kex.h"
#అన్తర్భావ "sshbuf.h"
#అన్తర్భావ "log.h"
#అన్తర్భావ "misc.h"
#అన్తర్భావ "servconf.h"
#అన్తర్భావ "sshkey.h"
#అన్తర్భావ "hostfile.h"
#అన్తర్భావ "auth.h"
#అన్తర్భావ "canohost.h"
#నిర్వచితమైతే GSSAPI
#అన్తర్భావ "ssh-gss.h"
#అయితే_ముగింపు
#అన్తర్భావ "monitor_wrap.h"
#అన్తర్భావ "pathnames.h"
#అన్తర్భావ "ssherr.h"
#అన్తర్భావ "match.h"

/* import */
బాహ్య ServerOptions options;
బాహ్య నిర్మాణం authmethod_cfg methodcfg_hostbased;

స్థిర పూర్ణాంకం
userauth_hostbased(నిర్మాణం ssh *ssh, స్థిరరాశి అక్షరం *పద్ధతి)
{
	Authctxt *authctxt = ssh->authctxt;
	నిర్మాణం sshbuf *keyblob = ఖాళీ, *b = ఖాళీ;
	నిర్మాణం sshkey *కీలకం = ఖాళీ;
	అక్షరం *pkalg, *cuser, *chost;
	u_char *sig;
	కొలత_t alen, slen;
	పూర్ణాంకం r, pktype, authenticated = 0;

	ఒకవేళ ((r = sshpkt_get_cstring(ssh, &pkalg, &alen)) != 0 ||
	    (r = sshpkt_getb_froms(ssh, &keyblob)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &chost, ఖాళీ)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &cuser, ఖాళీ)) != 0 ||
	    (r = sshpkt_get_string(ssh, &sig, &slen)) != 0)
		fatal_fr(r, "parse packet");

	debug_f("cuser %s chost %s pkalg %s slen %zu",
	    cuser, chost, pkalg, slen);
#నిర్వచితమైతే DEBUG_PK
	debug("signature:");
	sshbuf_dump_దత్తాంశం(sig, slen, stderr);
#అయితే_ముగింపు
	pktype = sshkey_type_from_name(pkalg);
	ఒకవేళ (pktype == కీలకం_UNSPEC) {
		/* this is perfectly legal */
		logit_f("unsupported public key algorithm: %s",
		    pkalg);
		వెళ్ళు పూర్తి;
	}
	ఒకవేళ (సరిపోలిక_నమూనా_list(pkalg,
	    options.hostbased_accepted_algos, 0) != 1) {
		logit_f("signature algorithm %s not in "
		    "HostbasedAcceptedAlgorithms", pkalg);
		వెళ్ళు పూర్తి;
	}
	ఒకవేళ ((b = sshbuf_fromb(keyblob)) == ఖాళీ)
		fatal_f("sshbuf_fromb failed");
	ఎంపిక ((r = sshkey_fromb_allowlist(b, &కీలకం,
	    options.hostbased_accepted_algos, options.ca_sign_algorithms))) {
	స్థితి 0:
		/* ok */
		ఆపు;
	స్థితి SSH_ERR_కీలకం_ALG_UNSUPPORTED:
		/* This shouldn't happen unless the client is being weird */
		logit_f("key algorithm differs from signature algorithm %s and "
		    "is not in HostbasedAcceptedAlgorithms", pkalg);
		వెళ్ళు పూర్తి;
	స్థితి SSH_ERR_SIGN_ALG_UNSUPPORTED:
		logit_fr(r, "certificate signature algorithm not in "
		    "CASignatureAlgorithms");
		వెళ్ళు పూర్తి;
	అప్రమేయ:
		error_fr(r, "parse key");
		వెళ్ళు పూర్తి;
	}
	sshbuf_free(b);
	b = ఖాళీ;

	ఒకవేళ (కీలకం->type != pktype || (sshkey_type_plain(pktype) == కీలకం_ECDSA &&
	    sshkey_ecdsa_nid_from_name(pkalg) != కీలకం->ecdsa_nid)) {
		error_f("key type mismatch for decoded key "
		    "(received %s, expected %s)", sshkey_ssh_name(కీలకం), pkalg);
		వెళ్ళు పూర్తి;
	}
	ఒకవేళ ((r = sshkey_check_rsa_నిడివి(కీలకం,
	    options.required_rsa_కొలత)) != 0) {
		logit_r(r, "refusing %s key", sshkey_type(కీలకం));
		వెళ్ళు పూర్తి;
	}

	ఒకవేళ (!authctxt->valid || authctxt->user == ఖాళీ) {
		debug2_f("disabled because of invalid user");
		వెళ్ళు పూర్తి;
	}

	ఒకవేళ ((b = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new failed");
	/* reconstruct packet */
	ఒకవేళ ((r = sshbuf_put_stringb(b, ssh->kex->session_id)) != 0 ||
	    (r = sshbuf_put_u8(b, SSH2_సందేశం_USERAUTH_REQUEST)) != 0 ||
	    (r = sshbuf_put_cstring(b, authctxt->user)) != 0 ||
	    (r = sshbuf_put_cstring(b, authctxt->service)) != 0 ||
	    (r = sshbuf_put_cstring(b, పద్ధతి)) != 0 ||
	    (r = sshbuf_put_string(b, pkalg, alen)) != 0 ||
	    (r = sshbuf_put_stringb(b, keyblob)) != 0 ||
	    (r = sshbuf_put_cstring(b, chost)) != 0 ||
	    (r = sshbuf_put_cstring(b, cuser)) != 0)
		fatal_fr(r, "reconstruct packet");
#నిర్వచితమైతే DEBUG_PK
	sshbuf_dump(b, stderr);
#అయితే_ముగింపు

	auth2_రికార్డు_info(authctxt,
	    "client user \"%.100s\", client host \"%.100s\"", cuser, chost);

	/* test for allowed key and correct signature */
	authenticated = 0;
	ఒకవేళ (mm_hostbased_కీలకం_allowed(ssh, authctxt->pw, cuser,
	    chost, కీలకం) &&
	    mm_sshkey_verify(కీలకం, sig, slen,
	    sshbuf_ptr(b), sshbuf_len(b), pkalg, ssh->compat, ఖాళీ) == 0)
		authenticated = 1;

	auth2_రికార్డు_కీలకం(authctxt, authenticated, కీలకం);
పూర్తి:
	debug2_f("authenticated %d", authenticated);
	sshkey_free(కీలకం);
	sshbuf_free(b);
	sshbuf_free(keyblob);
	విడుదల(pkalg);
	విడుదల(cuser);
	విడుదల(chost);
	విడుదల(sig);
	తిరిగి authenticated;
}

/* return 1 if given hostkey is allowed */
పూర్ణాంకం
hostbased_కీలకం_allowed(నిర్మాణం ssh *ssh, నిర్మాణం passwd *pw,
    స్థిరరాశి అక్షరం *cuser, అక్షరం *chost, నిర్మాణం sshkey *కీలకం)
{
	స్థిరరాశి అక్షరం *resolvedname, *ipaddr, *lookup, *reason;
	Host_స్థితి host_స్థితి;
	పూర్ణాంకం len;
	అక్షరం *fp;

	ఒకవేళ (auth_కీలకం_is_revoked(కీలకం))
		తిరిగి 0;

	resolvedname = auth_get_canonical_hostname(ssh, options.use_dns);
	ipaddr = ssh_remote_ipaddr(ssh);

	debug2_f("chost %s resolvedname %s ipaddr %s",
	    chost, resolvedname, ipaddr);

	ఒకవేళ (((len = అక్షరశ్రేణి_పొడవు(chost)) > 0) && chost[len - 1] == '.') {
		debug2("stripping trailing dot from chost %s", chost);
		chost[len - 1] = '\0';
	}

	ఒకవేళ (options.hostbased_ఉపయోగిస్తుంది_name_from_packet_only) {
		ఒకవేళ (auth_rhosts2(pw, cuser, chost, chost) == 0) {
			debug2_f("auth_rhosts2 refused user \"%.100s\" "
			    "host \"%.100s\" (from packet)", cuser, chost);
			తిరిగి 0;
		}
		lookup = chost;
	} లేకపోతే {
		ఒకవేళ (strcasecmp(resolvedname, chost) != 0)
			logit("userauth_hostbased mismatch: "
			    "client sends %s, but we resolve %s to %s",
			    chost, ipaddr, resolvedname);
		ఒకవేళ (auth_rhosts2(pw, cuser, resolvedname, ipaddr) == 0) {
			debug2_f("auth_rhosts2 refused "
			    "user \"%.100s\" host \"%.100s\" addr \"%.100s\"",
			    cuser, resolvedname, ipaddr);
			తిరిగి 0;
		}
		lookup = resolvedname;
	}
	debug2_f("access allowed by auth_rhosts2");

	ఒకవేళ (sshkey_is_cert(కీలకం) && sshkey_cert_check_host(కీలకం, lookup,
	     options.ca_sign_algorithms, &reason) != 0) {
		ఒకవేళ ((fp = sshkey_fingerprint(కీలకం->cert->signature_కీలకం,
		    options.fingerprint_hash, SSH_FP_DEFAULT)) == ఖాళీ)
			fatal_f("sshkey_fingerprint fail");
		error("Refusing certificate ID \"%s\" serial=%llu signed by "
		    "%s CA %s: %s", కీలకం->cert->కీలకం_id,
		    (గుర్తులేని దీర్ఘ దీర్ఘ)కీలకం->cert->serial,
		    sshkey_type(కీలకం->cert->signature_కీలకం), fp, reason);
		auth_debug_కూడు("Refused Certificate ID \"%s\" serial=%llu: %s",
		    కీలకం->cert->కీలకం_id, (గుర్తులేని దీర్ఘ దీర్ఘ)కీలకం->cert->serial,
		    reason);
		విడుదల(fp);
		తిరిగి 0;
	}

	host_స్థితి = check_కీలకం_లోపల_hostfiles(pw, కీలకం, lookup,
	    మార్గం_SSH_SYSTEM_HOSTFILE,
	    options.ignore_user_తెలిసిన_hosts ? ఖాళీ : మార్గం_SSH_USER_HOSTFILE);

	/* backward compat if no key has been found. */
	ఒకవేళ (host_స్థితి == HOST_NEW) {
		host_స్థితి = check_కీలకం_లోపల_hostfiles(pw, కీలకం, lookup,
		    మార్గం_SSH_SYSTEM_HOSTFILE2,
		    options.ignore_user_తెలిసిన_hosts ? ఖాళీ :
		    మార్గం_SSH_USER_HOSTFILE2);
	}

	ఒకవేళ (host_స్థితి == HOST_OK) {
		ఒకవేళ (sshkey_is_cert(కీలకం)) {
			ఒకవేళ ((fp = sshkey_fingerprint(కీలకం->cert->signature_కీలకం,
			    options.fingerprint_hash, SSH_FP_DEFAULT)) == ఖాళీ)
				fatal_f("sshkey_fingerprint fail");
			verbose("Accepted certificate ID \"%s\" signed by "
			    "%s CA %s from %s@%s", కీలకం->cert->కీలకం_id,
			    sshkey_type(కీలకం->cert->signature_కీలకం), fp,
			    cuser, lookup);
		} లేకపోతే {
			ఒకవేళ ((fp = sshkey_fingerprint(కీలకం,
			    options.fingerprint_hash, SSH_FP_DEFAULT)) == ఖాళీ)
				fatal_f("sshkey_fingerprint fail");
			verbose("Accepted %s public key %s from %s@%s",
			    sshkey_type(కీలకం), fp, cuser, lookup);
		}
		విడుదల(fp);
	}

	తిరిగి (host_స్థితి == HOST_OK);
}

Authmethod పద్ధతి_hostbased = {
	&methodcfg_hostbased,
	userauth_hostbased,
};
