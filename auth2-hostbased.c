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
#ifdef GSSAPI
#شامل "ssh-gss.h"
#endif
#شامل "monitor_wrap.h"
#شامل "pathnames.h"
#شامل "ssherr.h"
#شامل "match.h"

/* import */
بیرونی ServerOptions options;
بیرونی ساختار authmethod_cfg methodcfg_hostbased;

ایستا صحیح
userauth_hostbased(ساختار ssh *ssh, ثابت نویسه *method)
{
	Authctxt *authctxt = ssh->authctxt;
	ساختار sshbuf *keyblob = پوچ, *b = پوچ;
	ساختار sshkey *کلید = پوچ;
	نویسه *pkalg, *cuser, *chost;
	u_char *sig;
	size_t alen, slen;
	صحیح r, pktype, authenticated = 0;

	اگر ((r = sshpkt_get_cstring(ssh, &pkalg, &alen)) != 0 ||
	    (r = sshpkt_getb_froms(ssh, &keyblob)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &chost, پوچ)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &cuser, پوچ)) != 0 ||
	    (r = sshpkt_get_string(ssh, &sig, &slen)) != 0)
		fatal_fr(r, "parse packet");

	debug_f("cuser %s chost %s pkalg %s slen %zu",
	    cuser, chost, pkalg, slen);
#ifdef DEBUG_PK
	debug("signature:");
	sshbuf_dump_data(sig, slen, stderr);
#endif
	pktype = sshkey_type_from_name(pkalg);
	اگر (pktype == کلید_UNSPEC) {
		/* this is perfectly legal */
		logit_f("unsupported public key algorithm: %s",
		    pkalg);
		برو done;
	}
	اگر (match_pattern_list(pkalg,
	    options.hostbased_accepted_algos, 0) != 1) {
		logit_f("signature algorithm %s not in "
		    "HostbasedAcceptedAlgorithms", pkalg);
		برو done;
	}
	اگر ((b = sshbuf_fromb(keyblob)) == پوچ)
		fatal_f("sshbuf_fromb failed");
	انتخاب ((r = sshkey_fromb_allowlist(b, &کلید,
	    options.hostbased_accepted_algos, options.ca_sign_algorithms))) {
	حالت 0:
		/* ok */
		بشکن;
	حالت SSH_ERR_کلید_ALG_UNSUPPORTED:
		/* This shouldn't happen unless the client is being weird */
		logit_f("key algorithm differs from signature algorithm %s and "
		    "is not in HostbasedAcceptedAlgorithms", pkalg);
		برو done;
	حالت SSH_ERR_SIGN_ALG_UNSUPPORTED:
		logit_fr(r, "certificate signature algorithm not in "
		    "CASignatureAlgorithms");
		برو done;
	پیشفرض:
		error_fr(r, "parse key");
		برو done;
	}
	sshbuf_free(b);
	b = پوچ;

	اگر (کلید->type != pktype || (sshkey_type_plain(pktype) == کلید_ECDSA &&
	    sshkey_ecdsa_nid_from_name(pkalg) != کلید->ecdsa_nid)) {
		error_f("key type mismatch for decoded key "
		    "(received %s, expected %s)", sshkey_ssh_name(کلید), pkalg);
		برو done;
	}
	اگر ((r = sshkey_check_rsa_length(کلید,
	    options.required_rsa_size)) != 0) {
		logit_r(r, "refusing %s key", sshkey_type(کلید));
		برو done;
	}

	اگر (!authctxt->valid || authctxt->user == پوچ) {
		debug2_f("disabled because of invalid user");
		برو done;
	}

	اگر ((b = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new failed");
	/* reconstruct packet */
	اگر ((r = sshbuf_put_stringb(b, ssh->kex->session_id)) != 0 ||
	    (r = sshbuf_put_u8(b, SSH2_پیام_USERAUTH_REQUEST)) != 0 ||
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
	اگر (mm_hostbased_کلید_allowed(ssh, authctxt->pw, cuser,
	    chost, کلید) &&
	    mm_sshkey_verify(کلید, sig, slen,
	    sshbuf_ptr(b), sshbuf_len(b), pkalg, ssh->compat, پوچ) == 0)
		authenticated = 1;

	auth2_record_کلید(authctxt, authenticated, کلید);
done:
	debug2_f("authenticated %d", authenticated);
	sshkey_free(کلید);
	sshbuf_free(b);
	sshbuf_free(keyblob);
	آزاد(pkalg);
	آزاد(cuser);
	آزاد(chost);
	آزاد(sig);
	بازگشت authenticated;
}

/* return 1 if given hostkey is allowed */
صحیح
hostbased_کلید_allowed(ساختار ssh *ssh, ساختار passwd *pw,
    ثابت نویسه *cuser, نویسه *chost, ساختار sshkey *کلید)
{
	ثابت نویسه *resolvedname, *ipaddr, *lookup, *reason;
	HostStatus host_status;
	صحیح len;
	نویسه *fp;

	اگر (auth_کلید_is_revoked(کلید))
		بازگشت 0;

	resolvedname = auth_get_canonical_hostname(ssh, options.use_dns);
	ipaddr = ssh_remote_ipaddr(ssh);

	debug2_f("chost %s resolvedname %s ipaddr %s",
	    chost, resolvedname, ipaddr);

	اگر (((len = strlen(chost)) > 0) && chost[len - 1] == '.') {
		debug2("stripping trailing dot from chost %s", chost);
		chost[len - 1] = '\0';
	}

	اگر (options.hostbased_uses_name_from_packet_only) {
		اگر (auth_rhosts2(pw, cuser, chost, chost) == 0) {
			debug2_f("auth_rhosts2 refused user \"%.100s\" "
			    "host \"%.100s\" (from packet)", cuser, chost);
			بازگشت 0;
		}
		lookup = chost;
	} وگرنه {
		اگر (strcasecmp(resolvedname, chost) != 0)
			logit("userauth_hostbased mismatch: "
			    "client sends %s, but we resolve %s to %s",
			    chost, ipaddr, resolvedname);
		اگر (auth_rhosts2(pw, cuser, resolvedname, ipaddr) == 0) {
			debug2_f("auth_rhosts2 refused "
			    "user \"%.100s\" host \"%.100s\" addr \"%.100s\"",
			    cuser, resolvedname, ipaddr);
			بازگشت 0;
		}
		lookup = resolvedname;
	}
	debug2_f("access allowed by auth_rhosts2");

	اگر (sshkey_is_cert(کلید) && sshkey_cert_check_host(کلید, lookup,
	     options.ca_sign_algorithms, &reason) != 0) {
		اگر ((fp = sshkey_fingerprint(کلید->cert->signature_کلید,
		    options.fingerprint_hash, SSH_FP_DEFAULT)) == پوچ)
			fatal_f("sshkey_fingerprint fail");
		error("Refusing certificate ID \"%s\" serial=%llu signed by "
		    "%s CA %s: %s", کلید->cert->کلید_id,
		    (unsigned long long)کلید->cert->serial,
		    sshkey_type(کلید->cert->signature_کلید), fp, reason);
		auth_debug_add("Refused Certificate ID \"%s\" serial=%llu: %s",
		    کلید->cert->کلید_id, (unsigned long long)کلید->cert->serial,
		    reason);
		آزاد(fp);
		بازگشت 0;
	}

	host_status = check_کلید_in_hostfiles(pw, کلید, lookup,
	    _PATH_SSH_SYSTEM_HOSTFILE,
	    options.ignore_user_known_hosts ? پوچ : _PATH_SSH_USER_HOSTFILE);

	/* backward compat if no key has been found. */
	اگر (host_status == HOST_NEW) {
		host_status = check_کلید_in_hostfiles(pw, کلید, lookup,
		    _PATH_SSH_SYSTEM_HOSTFILE2,
		    options.ignore_user_known_hosts ? پوچ :
		    _PATH_SSH_USER_HOSTFILE2);
	}

	اگر (host_status == HOST_OK) {
		اگر (sshkey_is_cert(کلید)) {
			اگر ((fp = sshkey_fingerprint(کلید->cert->signature_کلید,
			    options.fingerprint_hash, SSH_FP_DEFAULT)) == پوچ)
				fatal_f("sshkey_fingerprint fail");
			verbose("Accepted certificate ID \"%s\" signed by "
			    "%s CA %s from %s@%s", کلید->cert->کلید_id,
			    sshkey_type(کلید->cert->signature_کلید), fp,
			    cuser, lookup);
		} وگرنه {
			اگر ((fp = sshkey_fingerprint(کلید,
			    options.fingerprint_hash, SSH_FP_DEFAULT)) == پوچ)
				fatal_f("sshkey_fingerprint fail");
			verbose("Accepted %s public key %s from %s@%s",
			    sshkey_type(کلید), fp, cuser, lookup);
		}
		آزاد(fp);
	}

	بازگشت (host_status == HOST_OK);
}

Authmethod method_hostbased = {
	&methodcfg_hostbased,
	userauth_hostbased,
};
