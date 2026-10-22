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

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <sys/types.h>

#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <pwd.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <stdarg.h>

#অন্তর্ভাব "xmalloc.h"
#অন্তর্ভাব "ssh2.h"
#অন্তর্ভাব "packet.h"
#অন্তর্ভাব "kex.h"
#অন্তর্ভাব "sshbuf.h"
#অন্তর্ভাব "log.h"
#অন্তর্ভাব "misc.h"
#অন্তর্ভাব "servconf.h"
#অন্তর্ভাব "sshkey.h"
#অন্তর্ভাব "hostfile.h"
#অন্তর্ভাব "auth.h"
#অন্তর্ভাব "canohost.h"
#ifdef GSSAPI
#অন্তর্ভাব "ssh-gss.h"
#endif
#অন্তর্ভাব "monitor_wrap.h"
#অন্তর্ভাব "pathnames.h"
#অন্তর্ভাব "ssherr.h"
#অন্তর্ভাব "match.h"

/* import */
বাহ্য ServerOptions options;
বাহ্য সংরচনা authmethod_cfg methodcfg_hostbased;

স্থির পূর্ণাঙ্ক
userauth_hostbased(সংরচনা ssh *ssh, ধ্রুব বর্ণ *method)
{
	Authctxt *authctxt = ssh->authctxt;
	সংরচনা sshbuf *keyblob = রিক্ত, *b = রিক্ত;
	সংরচনা sshkey *চাবি = রিক্ত;
	বর্ণ *pkalg, *cuser, *chost;
	u_char *sig;
	size_t alen, slen;
	পূর্ণাঙ্ক r, pktype, authenticated = 0;

	যদি ((r = sshpkt_get_cstring(ssh, &pkalg, &alen)) != 0 ||
	    (r = sshpkt_getb_froms(ssh, &keyblob)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &chost, রিক্ত)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &cuser, রিক্ত)) != 0 ||
	    (r = sshpkt_get_string(ssh, &sig, &slen)) != 0)
		fatal_fr(r, "parse packet");

	debug_f("cuser %s chost %s pkalg %s slen %zu",
	    cuser, chost, pkalg, slen);
#ifdef DEBUG_PK
	debug("signature:");
	sshbuf_dump_data(sig, slen, stderr);
#endif
	pktype = sshkey_type_from_name(pkalg);
	যদি (pktype == চাবি_UNSPEC) {
		/* this is perfectly legal */
		logit_f("unsupported public key algorithm: %s",
		    pkalg);
		গচ্ছ done;
	}
	যদি (match_pattern_list(pkalg,
	    options.hostbased_accepted_algos, 0) != 1) {
		logit_f("signature algorithm %s not in "
		    "HostbasedAcceptedAlgorithms", pkalg);
		গচ্ছ done;
	}
	যদি ((b = sshbuf_fromb(keyblob)) == রিক্ত)
		fatal_f("sshbuf_fromb failed");
	বিকল্প ((r = sshkey_fromb_allowlist(b, &চাবি,
	    options.hostbased_accepted_algos, options.ca_sign_algorithms))) {
	পক্ষ 0:
		/* ok */
		ভঙ্গ;
	পক্ষ SSH_ERR_চাবি_ALG_UNSUPPORTED:
		/* This shouldn't happen unless the client is being weird */
		logit_f("key algorithm differs from signature algorithm %s and "
		    "is not in HostbasedAcceptedAlgorithms", pkalg);
		গচ্ছ done;
	পক্ষ SSH_ERR_SIGN_ALG_UNSUPPORTED:
		logit_fr(r, "certificate signature algorithm not in "
		    "CASignatureAlgorithms");
		গচ্ছ done;
	স্বভাব:
		error_fr(r, "parse key");
		গচ্ছ done;
	}
	sshbuf_free(b);
	b = রিক্ত;

	যদি (চাবি->type != pktype || (sshkey_type_plain(pktype) == চাবি_ECDSA &&
	    sshkey_ecdsa_nid_from_name(pkalg) != চাবি->ecdsa_nid)) {
		error_f("key type mismatch for decoded key "
		    "(received %s, expected %s)", sshkey_ssh_name(চাবি), pkalg);
		গচ্ছ done;
	}
	যদি ((r = sshkey_check_rsa_length(চাবি,
	    options.required_rsa_size)) != 0) {
		logit_r(r, "refusing %s key", sshkey_type(চাবি));
		গচ্ছ done;
	}

	যদি (!authctxt->valid || authctxt->user == রিক্ত) {
		debug2_f("disabled because of invalid user");
		গচ্ছ done;
	}

	যদি ((b = sshbuf_new()) == রিক্ত)
		fatal_f("sshbuf_new failed");
	/* reconstruct packet */
	যদি ((r = sshbuf_put_stringb(b, ssh->kex->session_id)) != 0 ||
	    (r = sshbuf_put_u8(b, SSH2_বার্তা_USERAUTH_REQUEST)) != 0 ||
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
	যদি (mm_hostbased_চাবি_allowed(ssh, authctxt->pw, cuser,
	    chost, চাবি) &&
	    mm_sshkey_verify(চাবি, sig, slen,
	    sshbuf_ptr(b), sshbuf_len(b), pkalg, ssh->compat, রিক্ত) == 0)
		authenticated = 1;

	auth2_record_চাবি(authctxt, authenticated, চাবি);
done:
	debug2_f("authenticated %d", authenticated);
	sshkey_free(চাবি);
	sshbuf_free(b);
	sshbuf_free(keyblob);
	মুক্ত(pkalg);
	মুক্ত(cuser);
	মুক্ত(chost);
	মুক্ত(sig);
	প্রত্যাগম authenticated;
}

/* return 1 if given hostkey is allowed */
পূর্ণাঙ্ক
hostbased_চাবি_allowed(সংরচনা ssh *ssh, সংরচনা passwd *pw,
    ধ্রুব বর্ণ *cuser, বর্ণ *chost, সংরচনা sshkey *চাবি)
{
	ধ্রুব বর্ণ *resolvedname, *ipaddr, *lookup, *reason;
	HostStatus host_status;
	পূর্ণাঙ্ক len;
	বর্ণ *fp;

	যদি (auth_চাবি_is_revoked(চাবি))
		প্রত্যাগম 0;

	resolvedname = auth_get_canonical_hostname(ssh, options.use_dns);
	ipaddr = ssh_remote_ipaddr(ssh);

	debug2_f("chost %s resolvedname %s ipaddr %s",
	    chost, resolvedname, ipaddr);

	যদি (((len = strlen(chost)) > 0) && chost[len - 1] == '.') {
		debug2("stripping trailing dot from chost %s", chost);
		chost[len - 1] = '\0';
	}

	যদি (options.hostbased_uses_name_from_packet_only) {
		যদি (auth_rhosts2(pw, cuser, chost, chost) == 0) {
			debug2_f("auth_rhosts2 refused user \"%.100s\" "
			    "host \"%.100s\" (from packet)", cuser, chost);
			প্রত্যাগম 0;
		}
		lookup = chost;
	} অন্যথা {
		যদি (strcasecmp(resolvedname, chost) != 0)
			logit("userauth_hostbased mismatch: "
			    "client sends %s, but we resolve %s to %s",
			    chost, ipaddr, resolvedname);
		যদি (auth_rhosts2(pw, cuser, resolvedname, ipaddr) == 0) {
			debug2_f("auth_rhosts2 refused "
			    "user \"%.100s\" host \"%.100s\" addr \"%.100s\"",
			    cuser, resolvedname, ipaddr);
			প্রত্যাগম 0;
		}
		lookup = resolvedname;
	}
	debug2_f("access allowed by auth_rhosts2");

	যদি (sshkey_is_cert(চাবি) && sshkey_cert_check_host(চাবি, lookup,
	     options.ca_sign_algorithms, &reason) != 0) {
		যদি ((fp = sshkey_fingerprint(চাবি->cert->signature_চাবি,
		    options.fingerprint_hash, SSH_FP_DEFAULT)) == রিক্ত)
			fatal_f("sshkey_fingerprint fail");
		error("Refusing certificate ID \"%s\" serial=%llu signed by "
		    "%s CA %s: %s", চাবি->cert->চাবি_id,
		    (unsigned long long)চাবি->cert->serial,
		    sshkey_type(চাবি->cert->signature_চাবি), fp, reason);
		auth_debug_add("Refused Certificate ID \"%s\" serial=%llu: %s",
		    চাবি->cert->চাবি_id, (unsigned long long)চাবি->cert->serial,
		    reason);
		মুক্ত(fp);
		প্রত্যাগম 0;
	}

	host_status = check_চাবি_in_hostfiles(pw, চাবি, lookup,
	    _PATH_SSH_SYSTEM_HOSTFILE,
	    options.ignore_user_known_hosts ? রিক্ত : _PATH_SSH_USER_HOSTFILE);

	/* backward compat if no key has been found. */
	যদি (host_status == HOST_NEW) {
		host_status = check_চাবি_in_hostfiles(pw, চাবি, lookup,
		    _PATH_SSH_SYSTEM_HOSTFILE2,
		    options.ignore_user_known_hosts ? রিক্ত :
		    _PATH_SSH_USER_HOSTFILE2);
	}

	যদি (host_status == HOST_OK) {
		যদি (sshkey_is_cert(চাবি)) {
			যদি ((fp = sshkey_fingerprint(চাবি->cert->signature_চাবি,
			    options.fingerprint_hash, SSH_FP_DEFAULT)) == রিক্ত)
				fatal_f("sshkey_fingerprint fail");
			verbose("Accepted certificate ID \"%s\" signed by "
			    "%s CA %s from %s@%s", চাবি->cert->চাবি_id,
			    sshkey_type(চাবি->cert->signature_চাবি), fp,
			    cuser, lookup);
		} অন্যথা {
			যদি ((fp = sshkey_fingerprint(চাবি,
			    options.fingerprint_hash, SSH_FP_DEFAULT)) == রিক্ত)
				fatal_f("sshkey_fingerprint fail");
			verbose("Accepted %s public key %s from %s@%s",
			    sshkey_type(চাবি), fp, cuser, lookup);
		}
		মুক্ত(fp);
	}

	প্রত্যাগম (host_status == HOST_OK);
}

Authmethod method_hostbased = {
	&methodcfg_hostbased,
	userauth_hostbased,
};
