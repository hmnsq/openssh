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

#شامل "includes.h"

#شامل <sys/types.h>

#شامل <stdlib.h>
#شامل <pwd.h>
#شامل <string.h>
#شامل <stdarg.h>

#شامل "xmalloc.h"
#شامل "ssh2.h"
#شامل "packet.h"
#شامل "kex.h"
#شامل "sshbuf.h"
#شامل "log.h"
#شامل "misc.h"
#شامل "servconf.h"
#شامل "sshkey.h"
#شامل "hostfile.h"
#شامل "auth.h"
#شامل "canohost.h"
#اگر_تعریف_شدہ GSSAPI
#شامل "ssh-gss.h"
#اگر_ختم
#شامل "monitor_wrap.h"
#شامل "pathnames.h"
#شامل "ssherr.h"
#شامل "match.h"

/* import */
خارجی ServerOptions options;
خارجی ساخت authmethod_cfg methodcfg_hostbased;

ساکن صحیح
userauth_hostbased(ساخت ssh *ssh, ثابت حرف *طریقہ)
{
	Authctxt *authctxt = ssh->authctxt;
	ساخت sshbuf *keyblob = تہی, *b = تہی;
	ساخت sshkey *کلید = تہی;
	حرف *pkalg, *cuser, *chost;
	u_char *sig;
	سائز_t alen, slen;
	صحیح r, pktype, authenticated = 0;

	اگر ((r = sshpkt_get_cstring(ssh, &pkalg, &alen)) != 0 ||
	    (r = sshpkt_getb_froms(ssh, &keyblob)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &chost, تہی)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &cuser, تہی)) != 0 ||
	    (r = sshpkt_get_string(ssh, &sig, &slen)) != 0)
		fatal_fr(r, "parse packet");

	debug_f("cuser %s chost %s pkalg %s slen %zu",
	    cuser, chost, pkalg, slen);
#اگر_تعریف_شدہ DEBUG_PK
	debug("signature:");
	sshbuf_dump_ڈیٹا(sig, slen, stderr);
#اگر_ختم
	pktype = sshkey_type_from_name(pkalg);
	اگر (pktype == کلید_UNSPEC) {
		/* this is perfectly legal */
		logit_f("unsupported public key algorithm: %s",
		    pkalg);
		جاؤ مکمل;
	}
	اگر (مطابقت_نمونہ_list(pkalg,
	    options.hostbased_accepted_algos, 0) != 1) {
		logit_f("signature algorithm %s not in "
		    "HostbasedAcceptedAlgorithms", pkalg);
		جاؤ مکمل;
	}
	اگر ((b = sshbuf_fromb(keyblob)) == تہی)
		fatal_f("sshbuf_fromb failed");
	انتخاب ((r = sshkey_fromb_allowlist(b, &کلید,
	    options.hostbased_accepted_algos, options.ca_sign_algorithms))) {
	حالت 0:
		/* ok */
		توڑو;
	حالت SSH_ERR_کلید_ALG_UNSUPPORTED:
		/* This shouldn't happen unless the client is being weird */
		logit_f("key algorithm differs from signature algorithm %s and "
		    "is not in HostbasedAcceptedAlgorithms", pkalg);
		جاؤ مکمل;
	حالت SSH_ERR_SIGN_ALG_UNSUPPORTED:
		logit_fr(r, "certificate signature algorithm not in "
		    "CASignatureAlgorithms");
		جاؤ مکمل;
	طےشدہ:
		error_fr(r, "parse key");
		جاؤ مکمل;
	}
	sshbuf_free(b);
	b = تہی;

	اگر (کلید->type != pktype || (sshkey_type_plain(pktype) == کلید_ECDSA &&
	    sshkey_ecdsa_nid_from_name(pkalg) != کلید->ecdsa_nid)) {
		error_f("key type mismatch for decoded key "
		    "(received %s, expected %s)", sshkey_ssh_name(کلید), pkalg);
		جاؤ مکمل;
	}
	اگر ((r = sshkey_check_rsa_لمبائی(کلید,
	    options.required_rsa_سائز)) != 0) {
		logit_r(r, "refusing %s key", sshkey_type(کلید));
		جاؤ مکمل;
	}

	اگر (!authctxt->valid || authctxt->user == تہی) {
		debug2_f("disabled because of invalid user");
		جاؤ مکمل;
	}

	اگر ((b = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new failed");
	/* reconstruct packet */
	اگر ((r = sshbuf_put_stringb(b, ssh->kex->session_id)) != 0 ||
	    (r = sshbuf_put_u8(b, SSH2_پیغام_USERAUTH_REQUEST)) != 0 ||
	    (r = sshbuf_put_cstring(b, authctxt->user)) != 0 ||
	    (r = sshbuf_put_cstring(b, authctxt->service)) != 0 ||
	    (r = sshbuf_put_cstring(b, طریقہ)) != 0 ||
	    (r = sshbuf_put_string(b, pkalg, alen)) != 0 ||
	    (r = sshbuf_put_stringb(b, keyblob)) != 0 ||
	    (r = sshbuf_put_cstring(b, chost)) != 0 ||
	    (r = sshbuf_put_cstring(b, cuser)) != 0)
		fatal_fr(r, "reconstruct packet");
#اگر_تعریف_شدہ DEBUG_PK
	sshbuf_dump(b, stderr);
#اگر_ختم

	auth2_ریکارڈ_info(authctxt,
	    "client user \"%.100s\", client host \"%.100s\"", cuser, chost);

	/* test for allowed key and correct signature */
	authenticated = 0;
	اگر (mm_hostbased_کلید_allowed(ssh, authctxt->pw, cuser,
	    chost, کلید) &&
	    mm_sshkey_verify(کلید, sig, slen,
	    sshbuf_ptr(b), sshbuf_len(b), pkalg, ssh->compat, تہی) == 0)
		authenticated = 1;

	auth2_ریکارڈ_کلید(authctxt, authenticated, کلید);
مکمل:
	debug2_f("authenticated %d", authenticated);
	sshkey_free(کلید);
	sshbuf_free(b);
	sshbuf_free(keyblob);
	آزاد(pkalg);
	آزاد(cuser);
	آزاد(chost);
	آزاد(sig);
	واپس authenticated;
}

/* return 1 if given hostkey is allowed */
صحیح
hostbased_کلید_allowed(ساخت ssh *ssh, ساخت passwd *pw,
    ثابت حرف *cuser, حرف *chost, ساخت sshkey *کلید)
{
	ثابت حرف *resolvedname, *ipaddr, *lookup, *reason;
	Host_حالت host_حالت;
	صحیح len;
	حرف *fp;

	اگر (auth_کلید_is_revoked(کلید))
		واپس 0;

	resolvedname = auth_get_canonical_hostname(ssh, options.use_dns);
	ipaddr = ssh_remote_ipaddr(ssh);

	debug2_f("chost %s resolvedname %s ipaddr %s",
	    chost, resolvedname, ipaddr);

	اگر (((len = لڑی_لمبائی(chost)) > 0) && chost[len - 1] == '.') {
		debug2("stripping trailing dot from chost %s", chost);
		chost[len - 1] = '\0';
	}

	اگر (options.hostbased_استعمال_کرتا_name_from_packet_only) {
		اگر (auth_rhosts2(pw, cuser, chost, chost) == 0) {
			debug2_f("auth_rhosts2 refused user \"%.100s\" "
			    "host \"%.100s\" (from packet)", cuser, chost);
			واپس 0;
		}
		lookup = chost;
	} ورنہ {
		اگر (strcasecmp(resolvedname, chost) != 0)
			logit("userauth_hostbased mismatch: "
			    "client sends %s, but we resolve %s to %s",
			    chost, ipaddr, resolvedname);
		اگر (auth_rhosts2(pw, cuser, resolvedname, ipaddr) == 0) {
			debug2_f("auth_rhosts2 refused "
			    "user \"%.100s\" host \"%.100s\" addr \"%.100s\"",
			    cuser, resolvedname, ipaddr);
			واپس 0;
		}
		lookup = resolvedname;
	}
	debug2_f("access allowed by auth_rhosts2");

	اگر (sshkey_is_cert(کلید) && sshkey_cert_check_host(کلید, lookup,
	     options.ca_sign_algorithms, &reason) != 0) {
		اگر ((fp = sshkey_fingerprint(کلید->cert->signature_کلید,
		    options.fingerprint_hash, SSH_FP_DEFAULT)) == تہی)
			fatal_f("sshkey_fingerprint fail");
		error("Refusing certificate ID \"%s\" serial=%llu signed by "
		    "%s CA %s: %s", کلید->cert->کلید_id,
		    (غیرعلامتی طویل طویل)کلید->cert->serial,
		    sshkey_type(کلید->cert->signature_کلید), fp, reason);
		auth_debug_جوڑو("Refused Certificate ID \"%s\" serial=%llu: %s",
		    کلید->cert->کلید_id, (غیرعلامتی طویل طویل)کلید->cert->serial,
		    reason);
		آزاد(fp);
		واپس 0;
	}

	host_حالت = check_کلید_اندر_hostfiles(pw, کلید, lookup,
	    راستہ_SSH_SYSTEM_HOSTFILE,
	    options.ignore_user_معلوم_hosts ? تہی : راستہ_SSH_USER_HOSTFILE);

	/* backward compat if no key has been found. */
	اگر (host_حالت == HOST_NEW) {
		host_حالت = check_کلید_اندر_hostfiles(pw, کلید, lookup,
		    راستہ_SSH_SYSTEM_HOSTFILE2,
		    options.ignore_user_معلوم_hosts ? تہی :
		    راستہ_SSH_USER_HOSTFILE2);
	}

	اگر (host_حالت == HOST_OK) {
		اگر (sshkey_is_cert(کلید)) {
			اگر ((fp = sshkey_fingerprint(کلید->cert->signature_کلید,
			    options.fingerprint_hash, SSH_FP_DEFAULT)) == تہی)
				fatal_f("sshkey_fingerprint fail");
			verbose("Accepted certificate ID \"%s\" signed by "
			    "%s CA %s from %s@%s", کلید->cert->کلید_id,
			    sshkey_type(کلید->cert->signature_کلید), fp,
			    cuser, lookup);
		} ورنہ {
			اگر ((fp = sshkey_fingerprint(کلید,
			    options.fingerprint_hash, SSH_FP_DEFAULT)) == تہی)
				fatal_f("sshkey_fingerprint fail");
			verbose("Accepted %s public key %s from %s@%s",
			    sshkey_type(کلید), fp, cuser, lookup);
		}
		آزاد(fp);
	}

	واپس (host_حالت == HOST_OK);
}

Authmethod طریقہ_hostbased = {
	&methodcfg_hostbased,
	userauth_hostbased,
};
