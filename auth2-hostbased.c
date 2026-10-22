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

#ضمن "includes.h"

#ضمن <sys/types.h>

#ضمن <stdlib.h>
#ضمن <pwd.h>
#ضمن <string.h>
#ضمن <stdarg.h>

#ضمن "xmalloc.h"
#ضمن "ssh2.h"
#ضمن "packet.h"
#ضمن "kex.h"
#ضمن "sshbuf.h"
#ضمن "log.h"
#ضمن "misc.h"
#ضمن "servconf.h"
#ضمن "sshkey.h"
#ضمن "hostfile.h"
#ضمن "auth.h"
#ضمن "canohost.h"
#اگر_تعریف_شده GSSAPI
#ضمن "ssh-gss.h"
#پایان_اگر
#ضمن "monitor_wrap.h"
#ضمن "pathnames.h"
#ضمن "ssherr.h"
#ضمن "match.h"

/* import */
خارجي ServerOptions options;
خارجي بنية authmethod_cfg methodcfg_hostbased;

ساكن صحيح
userauth_hostbased(بنية ssh *ssh, ثابت حرف *روش)
{
	Authctxt *authctxt = ssh->authctxt;
	بنية sshbuf *keyblob = عدم, *b = عدم;
	بنية sshkey *کلید = عدم;
	حرف *pkalg, *cuser, *chost;
	u_char *sig;
	اندازه_t alen, slen;
	صحيح r, pktype, authenticated = 0;

	إذا ((r = sshpkt_get_cstring(ssh, &pkalg, &alen)) != 0 ||
	    (r = sshpkt_getb_froms(ssh, &keyblob)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &chost, عدم)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &cuser, عدم)) != 0 ||
	    (r = sshpkt_get_string(ssh, &sig, &slen)) != 0)
		fatal_fr(r, "parse packet");

	debug_f("cuser %s chost %s pkalg %s slen %zu",
	    cuser, chost, pkalg, slen);
#اگر_تعریف_شده DEBUG_PK
	debug("signature:");
	sshbuf_dump_داده(sig, slen, stderr);
#پایان_اگر
	pktype = sshkey_type_from_name(pkalg);
	إذا (pktype == کلید_UNSPEC) {
		/* this is perfectly legal */
		logit_f("unsupported public key algorithm: %s",
		    pkalg);
		اذهب انجامشده;
	}
	إذا (تطابق_الگو_list(pkalg,
	    options.hostbased_accepted_algos, 0) != 1) {
		logit_f("signature algorithm %s not in "
		    "HostbasedAcceptedAlgorithms", pkalg);
		اذهب انجامشده;
	}
	إذا ((b = sshbuf_fromb(keyblob)) == عدم)
		fatal_f("sshbuf_fromb failed");
	بدل ((r = sshkey_fromb_allowlist(b, &کلید,
	    options.hostbased_accepted_algos, options.ca_sign_algorithms))) {
	حالة 0:
		/* ok */
		اكسر;
	حالة SSH_ERR_کلید_ALG_UNSUPPORTED:
		/* This shouldn't happen unless the client is being weird */
		logit_f("key algorithm differs from signature algorithm %s and "
		    "is not in HostbasedAcceptedAlgorithms", pkalg);
		اذهب انجامشده;
	حالة SSH_ERR_SIGN_ALG_UNSUPPORTED:
		logit_fr(r, "certificate signature algorithm not in "
		    "CASignatureAlgorithms");
		اذهب انجامشده;
	افتراضي:
		error_fr(r, "parse key");
		اذهب انجامشده;
	}
	sshbuf_free(b);
	b = عدم;

	إذا (کلید->type != pktype || (sshkey_type_plain(pktype) == کلید_ECDSA &&
	    sshkey_ecdsa_nid_from_name(pkalg) != کلید->ecdsa_nid)) {
		error_f("key type mismatch for decoded key "
		    "(received %s, expected %s)", sshkey_ssh_name(کلید), pkalg);
		اذهب انجامشده;
	}
	إذا ((r = sshkey_check_rsa_درازی(کلید,
	    options.required_rsa_اندازه)) != 0) {
		logit_r(r, "refusing %s key", sshkey_type(کلید));
		اذهب انجامشده;
	}

	إذا (!authctxt->valid || authctxt->user == عدم) {
		debug2_f("disabled because of invalid user");
		اذهب انجامشده;
	}

	إذا ((b = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	/* reconstruct packet */
	إذا ((r = sshbuf_put_stringb(b, ssh->kex->session_id)) != 0 ||
	    (r = sshbuf_put_u8(b, SSH2_پیام_USERAUTH_REQUEST)) != 0 ||
	    (r = sshbuf_put_cstring(b, authctxt->user)) != 0 ||
	    (r = sshbuf_put_cstring(b, authctxt->service)) != 0 ||
	    (r = sshbuf_put_cstring(b, روش)) != 0 ||
	    (r = sshbuf_put_string(b, pkalg, alen)) != 0 ||
	    (r = sshbuf_put_stringb(b, keyblob)) != 0 ||
	    (r = sshbuf_put_cstring(b, chost)) != 0 ||
	    (r = sshbuf_put_cstring(b, cuser)) != 0)
		fatal_fr(r, "reconstruct packet");
#اگر_تعریف_شده DEBUG_PK
	sshbuf_dump(b, stderr);
#پایان_اگر

	auth2_رکورد_info(authctxt,
	    "client user \"%.100s\", client host \"%.100s\"", cuser, chost);

	/* test for allowed key and correct signature */
	authenticated = 0;
	إذا (mm_hostbased_کلید_allowed(ssh, authctxt->pw, cuser,
	    chost, کلید) &&
	    mm_sshkey_verify(کلید, sig, slen,
	    sshbuf_ptr(b), sshbuf_len(b), pkalg, ssh->compat, عدم) == 0)
		authenticated = 1;

	auth2_رکورد_کلید(authctxt, authenticated, کلید);
انجامشده:
	debug2_f("authenticated %d", authenticated);
	sshkey_free(کلید);
	sshbuf_free(b);
	sshbuf_free(keyblob);
	حرر(pkalg);
	حرر(cuser);
	حرر(chost);
	حرر(sig);
	أرجع authenticated;
}

/* return 1 if given hostkey is allowed */
صحيح
hostbased_کلید_allowed(بنية ssh *ssh, بنية passwd *pw,
    ثابت حرف *cuser, حرف *chost, بنية sshkey *کلید)
{
	ثابت حرف *resolvedname, *ipaddr, *lookup, *reason;
	Host_وضعیت host_وضعیت;
	صحيح len;
	حرف *fp;

	إذا (auth_کلید_is_revoked(کلید))
		أرجع 0;

	resolvedname = auth_get_canonical_hostname(ssh, options.use_dns);
	ipaddr = ssh_remote_ipaddr(ssh);

	debug2_f("chost %s resolvedname %s ipaddr %s",
	    chost, resolvedname, ipaddr);

	إذا (((len = طول_رشته(chost)) > 0) && chost[len - 1] == '.') {
		debug2("stripping trailing dot from chost %s", chost);
		chost[len - 1] = '\0';
	}

	إذا (options.hostbased_استفاده_میکند_name_from_packet_only) {
		إذا (auth_rhosts2(pw, cuser, chost, chost) == 0) {
			debug2_f("auth_rhosts2 refused user \"%.100s\" "
			    "host \"%.100s\" (from packet)", cuser, chost);
			أرجع 0;
		}
		lookup = chost;
	} وإلا {
		إذا (strcasecmp(resolvedname, chost) != 0)
			logit("userauth_hostbased mismatch: "
			    "client sends %s, but we resolve %s to %s",
			    chost, ipaddr, resolvedname);
		إذا (auth_rhosts2(pw, cuser, resolvedname, ipaddr) == 0) {
			debug2_f("auth_rhosts2 refused "
			    "user \"%.100s\" host \"%.100s\" addr \"%.100s\"",
			    cuser, resolvedname, ipaddr);
			أرجع 0;
		}
		lookup = resolvedname;
	}
	debug2_f("access allowed by auth_rhosts2");

	إذا (sshkey_is_cert(کلید) && sshkey_cert_check_host(کلید, lookup,
	     options.ca_sign_algorithms, &reason) != 0) {
		إذا ((fp = sshkey_fingerprint(کلید->cert->signature_کلید,
		    options.fingerprint_hash, SSH_FP_DEFAULT)) == عدم)
			fatal_f("sshkey_fingerprint fail");
		error("Refusing certificate ID \"%s\" serial=%llu signed by "
		    "%s CA %s: %s", کلید->cert->کلید_id,
		    (بیعلامت دراز دراز)کلید->cert->serial,
		    sshkey_type(کلید->cert->signature_کلید), fp, reason);
		auth_debug_جمع_کن("Refused Certificate ID \"%s\" serial=%llu: %s",
		    کلید->cert->کلید_id, (بیعلامت دراز دراز)کلید->cert->serial,
		    reason);
		حرر(fp);
		أرجع 0;
	}

	host_وضعیت = check_کلید_درون_hostfiles(pw, کلید, lookup,
	    مسیر_SSH_SYSTEM_HOSTFILE,
	    options.ignore_user_معلوم_hosts ? عدم : مسیر_SSH_USER_HOSTFILE);

	/* backward compat if no key has been found. */
	إذا (host_وضعیت == HOST_NEW) {
		host_وضعیت = check_کلید_درون_hostfiles(pw, کلید, lookup,
		    مسیر_SSH_SYSTEM_HOSTFILE2,
		    options.ignore_user_معلوم_hosts ? عدم :
		    مسیر_SSH_USER_HOSTFILE2);
	}

	إذا (host_وضعیت == HOST_OK) {
		إذا (sshkey_is_cert(کلید)) {
			إذا ((fp = sshkey_fingerprint(کلید->cert->signature_کلید,
			    options.fingerprint_hash, SSH_FP_DEFAULT)) == عدم)
				fatal_f("sshkey_fingerprint fail");
			verbose("Accepted certificate ID \"%s\" signed by "
			    "%s CA %s from %s@%s", کلید->cert->کلید_id,
			    sshkey_type(کلید->cert->signature_کلید), fp,
			    cuser, lookup);
		} وإلا {
			إذا ((fp = sshkey_fingerprint(کلید,
			    options.fingerprint_hash, SSH_FP_DEFAULT)) == عدم)
				fatal_f("sshkey_fingerprint fail");
			verbose("Accepted %s public key %s from %s@%s",
			    sshkey_type(کلید), fp, cuser, lookup);
		}
		حرر(fp);
	}

	أرجع (host_وضعیت == HOST_OK);
}

Authmethod روش_hostbased = {
	&methodcfg_hostbased,
	userauth_hostbased,
};
