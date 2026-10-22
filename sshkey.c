/* $OpenBSD: sshkey.c,v 1.165 2026/10/01 07:07:49 djm Exp $ */
/*
 * Copyright (c) 2000, 2001 Markus Friedl.  All rights reserved.
 * Copyright (c) 2008 Alexander von Gernler.  All rights reserved.
 * Copyright (c) 2010,2011 Damien Miller.  All rights reserved.
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
#అన్తర్భావ <sys/mman.h>
#అన్తర్భావ <netinet/in.h>

#నిర్వచితమైతే WITH_OPENSSL
#అన్తర్భావ <openssl/bn.h>
#అన్తర్భావ <openssl/evp.h>
#అన్తర్భావ <openssl/err.h>
#అన్తర్భావ <openssl/pem.h>
#అయితే_ముగింపు

#అన్తర్భావ "crypto_api.h"

#అన్తర్భావ <errno.h>
#అన్తర్భావ <limits.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <resolv.h>
#అన్తర్భావ <time.h>
#అన్తర్భావ <util.h>

#అన్తర్భావ "ssh2.h"
#అన్తర్భావ "ssherr.h"
#అన్తర్భావ "misc.h"
#అన్తర్భావ "sshbuf.h"
#అన్తర్భావ "cipher.h"
#అన్తర్భావ "digest.h"
#నిర్వచించు SSHKEY_అంతర్గత
#అన్తర్భావ "sshkey.h"
#అన్తర్భావ "match.h"
#అన్తర్భావ "ssh-sk.h"
#అన్తర్భావ "ssh-pkcs11.h"

#అన్తర్భావ "openbsd-compat/openssl-compat.h"

/* openssh private key file format */
#నిర్వచించు MARK_BEGIN		"-----BEGIN OPENSSH PRIVATE KEY-----\n"
#నిర్వచించు MARK_చివర		"-----END OPENSSH PRIVATE KEY-----\n"
#నిర్వచించు MARK_BEGIN_LEN		(పరిమాణం(MARK_BEGIN) - 1)
#నిర్వచించు MARK_చివర_LEN		(పరిమాణం(MARK_చివర) - 1)
#నిర్వచించు KDFNAME			"bcrypt"
#నిర్వచించు AUTH_MAGIC		"openssh-key-v1"
#నిర్వచించు SALT_LEN		16
#నిర్వచించు DEFAULT_CIPHERNAME	"aes256-ctr"
#నిర్వచించు	DEFAULT_విడతలు		32
#నిర్వచించు	MAX_KDF_విడతలు		(1<<20)

/*
 * Constants relating to "shielding" support; protection of keys expected
 * to remain in memory for long durations
 */
#నిర్వచించు SSHKEY_SHIELD_PREKEY_LEN	(16 * 1024)
#నిర్వచించు SSHKEY_SHIELD_CIPHER		"aes256-ctr" /* XXX want AES-EME* */
#నిర్వచించు SSHKEY_SHIELD_PREKEY_HASH	SSH_DIGEST_SHA512

స్థిర పూర్ణాంకం sshkey_from_blob_అంతర్గత(నిర్మాణం sshbuf *buf,
    నిర్మాణం sshkey **keyp, పూర్ణాంకం allow_cert,
    స్థిరరాశి అక్షరం *alg_allowlist, స్థిరరాశి అక్షరం *ca_sigalg_allowlist);

/* Supported key types */
బాహ్య స్థిరరాశి నిర్మాణం sshkey_impl sshkey_ed25519_impl;
బాహ్య స్థిరరాశి నిర్మాణం sshkey_impl sshkey_ed25519_cert_impl;
బాహ్య స్థిరరాశి నిర్మాణం sshkey_impl sshkey_ed25519_sk_impl;
బాహ్య స్థిరరాశి నిర్మాణం sshkey_impl sshkey_ed25519_sk_cert_impl;
# ifdef USE_MLDSA
బాహ్య స్థిరరాశి నిర్మాణం sshkey_impl sshkey_mldsa44_ed25519_impl;
బాహ్య స్థిరరాశి నిర్మాణం sshkey_impl sshkey_mldsa44_ed25519_cert_impl;
# endif /* USE_MLDSA */
#నిర్వచితమైతే WITH_OPENSSL
# ifdef ENABLE_SK
బాహ్య స్థిరరాశి నిర్మాణం sshkey_impl sshkey_ecdsa_sk_impl;
బాహ్య స్థిరరాశి నిర్మాణం sshkey_impl sshkey_ecdsa_sk_cert_impl;
బాహ్య స్థిరరాశి నిర్మాణం sshkey_impl sshkey_ecdsa_sk_webauthn_impl;
బాహ్య స్థిరరాశి నిర్మాణం sshkey_impl sshkey_ecdsa_sk_webauthn_cert_impl;
# endif /* ENABLE_SK */
బాహ్య స్థిరరాశి నిర్మాణం sshkey_impl sshkey_ecdsa_nistp256_impl;
బాహ్య స్థిరరాశి నిర్మాణం sshkey_impl sshkey_ecdsa_nistp256_cert_impl;
బాహ్య స్థిరరాశి నిర్మాణం sshkey_impl sshkey_ecdsa_nistp384_impl;
బాహ్య స్థిరరాశి నిర్మాణం sshkey_impl sshkey_ecdsa_nistp384_cert_impl;
బాహ్య స్థిరరాశి నిర్మాణం sshkey_impl sshkey_ecdsa_nistp521_impl;
బాహ్య స్థిరరాశి నిర్మాణం sshkey_impl sshkey_ecdsa_nistp521_cert_impl;
బాహ్య స్థిరరాశి నిర్మాణం sshkey_impl sshkey_rsa_impl;
బాహ్య స్థిరరాశి నిర్మాణం sshkey_impl sshkey_rsa_cert_impl;
బాహ్య స్థిరరాశి నిర్మాణం sshkey_impl sshkey_rsa_sha256_impl;
బాహ్య స్థిరరాశి నిర్మాణం sshkey_impl sshkey_rsa_sha256_cert_impl;
బాహ్య స్థిరరాశి నిర్మాణం sshkey_impl sshkey_rsa_sha512_impl;
బాహ్య స్థిరరాశి నిర్మాణం sshkey_impl sshkey_rsa_sha512_cert_impl;
#అయితే_ముగింపు /* WITH_OPENSSL */

స్థిరరాశి నిర్మాణం sshkey_impl * స్థిరరాశి keyimpls[] = {
	&sshkey_ed25519_impl,
	&sshkey_ed25519_cert_impl,
#నిర్వచితమైతే ENABLE_SK
	&sshkey_ed25519_sk_impl,
	&sshkey_ed25519_sk_cert_impl,
#అయితే_ముగింపు
#నిర్వచితమైతే USE_MLDSA
	&sshkey_mldsa44_ed25519_impl,
	&sshkey_mldsa44_ed25519_cert_impl,
#అయితే_ముగింపు /* USE_MLDSA */
#నిర్వచితమైతే WITH_OPENSSL
	&sshkey_ecdsa_nistp256_impl,
	&sshkey_ecdsa_nistp256_cert_impl,
	&sshkey_ecdsa_nistp384_impl,
	&sshkey_ecdsa_nistp384_cert_impl,
	&sshkey_ecdsa_nistp521_impl,
	&sshkey_ecdsa_nistp521_cert_impl,
# ifdef ENABLE_SK
	&sshkey_ecdsa_sk_impl,
	&sshkey_ecdsa_sk_cert_impl,
	&sshkey_ecdsa_sk_webauthn_impl,
	&sshkey_ecdsa_sk_webauthn_cert_impl,
# endif /* ENABLE_SK */
	&sshkey_rsa_impl,
	&sshkey_rsa_cert_impl,
	&sshkey_rsa_sha256_impl,
	&sshkey_rsa_sha256_cert_impl,
	&sshkey_rsa_sha512_impl,
	&sshkey_rsa_sha512_cert_impl,
#అయితే_ముగింపు /* WITH_OPENSSL */
	ఖాళీ
};

స్థిర స్థిరరాశి నిర్మాణం sshkey_impl *
sshkey_impl_from_type(పూర్ణాంకం type)
{
	పూర్ణాంకం i;

	కొరకు (i = 0; keyimpls[i] != ఖాళీ; i++) {
		ఒకవేళ (keyimpls[i]->type == type)
			తిరిగి keyimpls[i];
	}
	తిరిగి ఖాళీ;
}

స్థిర స్థిరరాశి నిర్మాణం sshkey_impl *
sshkey_impl_from_type_nid(పూర్ణాంకం type, పూర్ణాంకం nid)
{
	పూర్ణాంకం i;

	కొరకు (i = 0; keyimpls[i] != ఖాళీ; i++) {
		ఒకవేళ (keyimpls[i]->type == type &&
		    (keyimpls[i]->nid == 0 || keyimpls[i]->nid == nid))
			తిరిగి keyimpls[i];
	}
	తిరిగి ఖాళీ;
}

స్థిర స్థిరరాశి నిర్మాణం sshkey_impl *
sshkey_impl_from_కీలకం(స్థిరరాశి నిర్మాణం sshkey *k)
{
	ఒకవేళ (k == ఖాళీ)
		తిరిగి ఖాళీ;
	తిరిగి sshkey_impl_from_type_nid(k->type, k->ecdsa_nid);
}

స్థిరరాశి అక్షరం *
sshkey_type(స్థిరరాశి నిర్మాణం sshkey *k)
{
	స్థిరరాశి నిర్మాణం sshkey_impl *impl;

	ఒకవేళ ((impl = sshkey_impl_from_కీలకం(k)) == ఖాళీ)
		తిరిగి "unknown";
	తిరిగి impl->shortname;
}

స్థిర స్థిరరాశి అక్షరం *
sshkey_ssh_name_from_type_nid(పూర్ణాంకం type, పూర్ణాంకం nid)
{
	స్థిరరాశి నిర్మాణం sshkey_impl *impl;

	ఒకవేళ ((impl = sshkey_impl_from_type_nid(type, nid)) == ఖాళీ)
		తిరిగి "ssh-unknown";
	తిరిగి impl->name;
}

పూర్ణాంకం
sshkey_type_is_cert(పూర్ణాంకం type)
{
	స్థిరరాశి నిర్మాణం sshkey_impl *impl;

	ఒకవేళ ((impl = sshkey_impl_from_type(type)) == ఖాళీ)
		తిరిగి 0;
	తిరిగి impl->cert;
}

స్థిరరాశి అక్షరం *
sshkey_ssh_name(స్థిరరాశి నిర్మాణం sshkey *k)
{
	తిరిగి sshkey_ssh_name_from_type_nid(k->type, k->ecdsa_nid);
}

స్థిరరాశి అక్షరం *
sshkey_ssh_name_plain(స్థిరరాశి నిర్మాణం sshkey *k)
{
	తిరిగి sshkey_ssh_name_from_type_nid(sshkey_type_plain(k->type),
	    k->ecdsa_nid);
}

స్థిర పూర్ణాంకం
type_from_name(స్థిరరాశి అక్షరం *name, పూర్ణాంకం allow_short)
{
	పూర్ణాంకం i;
	స్థిరరాశి నిర్మాణం sshkey_impl *impl;

	కొరకు (i = 0; keyimpls[i] != ఖాళీ; i++) {
		impl = keyimpls[i];
		ఒకవేళ (impl->name != ఖాళీ && strcmp(name, impl->name) == 0)
			తిరిగి impl->type;
		/* Only allow shortname matches for plain key types */
		ఒకవేళ (allow_short && !impl->cert && impl->shortname != ఖాళీ &&
		    strcasecmp(impl->shortname, name) == 0)
			తిరిగి impl->type;
	}
	తిరిగి కీలకం_UNSPEC;
}

పూర్ణాంకం
sshkey_type_from_name(స్థిరరాశి అక్షరం *name)
{
	తిరిగి type_from_name(name, 0);
}

పూర్ణాంకం
sshkey_type_from_shortname(స్థిరరాశి అక్షరం *name)
{
	తిరిగి type_from_name(name, 1);
}

స్థిర పూర్ణాంకం
కీలకం_type_is_ecdsa_variant(పూర్ణాంకం type)
{
	ఎంపిక (type) {
	స్థితి కీలకం_ECDSA:
	స్థితి కీలకం_ECDSA_CERT:
	స్థితి కీలకం_ECDSA_SK:
	స్థితి కీలకం_ECDSA_SK_CERT:
		తిరిగి 1;
	}
	తిరిగి 0;
}

పూర్ణాంకం
sshkey_ecdsa_nid_from_name(స్థిరరాశి అక్షరం *name)
{
	పూర్ణాంకం i;

	కొరకు (i = 0; keyimpls[i] != ఖాళీ; i++) {
		ఒకవేళ (!కీలకం_type_is_ecdsa_variant(keyimpls[i]->type))
			కొనసాగు;
		ఒకవేళ (keyimpls[i]->name != ఖాళీ &&
		    strcmp(name, keyimpls[i]->name) == 0)
			తిరిగి keyimpls[i]->nid;
	}
	తిరిగి -1;
}

పూర్ణాంకం
sshkey_సరిపోలిక_keyname_గమ్యం_sigalgs(స్థిరరాశి అక్షరం *keyname, స్థిరరాశి అక్షరం *sigalgs)
{
	పూర్ణాంకం ktype;

	ఒకవేళ (sigalgs == ఖాళీ || *sigalgs == '\0' ||
	    (ktype = sshkey_type_from_name(keyname)) == కీలకం_UNSPEC)
		తిరిగి 0;
	లేకపోతే ఒకవేళ (ktype == కీలకం_RSA) {
		తిరిగి సరిపోలిక_నమూనా_list("ssh-rsa", sigalgs, 0) == 1 ||
		    సరిపోలిక_నమూనా_list("rsa-sha2-256", sigalgs, 0) == 1 ||
		    సరిపోలిక_నమూనా_list("rsa-sha2-512", sigalgs, 0) == 1;
	} లేకపోతే ఒకవేళ (ktype == కీలకం_RSA_CERT) {
		తిరిగి సరిపోలిక_నమూనా_list("ssh-rsa-cert-v01@openssh.com",
		    sigalgs, 0) == 1 ||
		    సరిపోలిక_నమూనా_list("rsa-sha2-256-cert-v01@openssh.com",
		    sigalgs, 0) == 1 ||
		    సరిపోలిక_నమూనా_list("rsa-sha2-512-cert-v01@openssh.com",
		    sigalgs, 0) == 1;
	} లేకపోతే ఒకవేళ (ktype == కీలకం_ECDSA_SK) {
		తిరిగి సరిపోలిక_నమూనా_list("sk-ecdsa-sha2-nistp256@openssh.com",
		    sigalgs, 0) == 1 || సరిపోలిక_నమూనా_list(
		    "webauthn-sk-ecdsa-sha2-nistp256@openssh.com",
		    sigalgs, 0) == 1;
	} లేకపోతే ఒకవేళ (ktype == కీలకం_ECDSA_SK_CERT) {
		తిరిగి సరిపోలిక_నమూనా_list(
		    "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
		    sigalgs, 0) == 1 || సరిపోలిక_నమూనా_list(
		    "webauthn-sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
		    sigalgs, 0) == 1;
	} లేకపోతే
		తిరిగి సరిపోలిక_నమూనా_list(keyname, sigalgs, 0) == 1;
}

అక్షరం *
sshkey_alg_list(పూర్ణాంకం certs_only, పూర్ణాంకం plain_only, పూర్ణాంకం include_sigonly, అక్షరం sep)
{
	అక్షరం *ret = ఖాళీ;
	కొలత_t i;
	స్థిరరాశి నిర్మాణం sshkey_impl *impl;
	అక్షరం sep_str[2] = {sep, '\0'};

	కొరకు (i = 0; keyimpls[i] != ఖాళీ; i++) {
		impl = keyimpls[i];
		ఒకవేళ (impl->name == ఖాళీ)
			కొనసాగు;
		ఒకవేళ (!include_sigonly && impl->sigonly)
			కొనసాగు;
		ఒకవేళ ((certs_only && !impl->cert) || (plain_only && impl->cert))
			కొనసాగు;
		xextendf(&ret, sep_str, "%s", impl->name);
	}
	తిరిగి ret;
}

పూర్ణాంకం
sshkey_పేర్లు_valid2(స్థిరరాశి అక్షరం *పేర్లు, పూర్ణాంకం allow_wildcard, పూర్ణాంకం plain_only)
{
	అక్షరం *s, *cp, *p;
	స్థిరరాశి నిర్మాణం sshkey_impl *impl;
	పూర్ణాంకం i, type;

	ఒకవేళ (పేర్లు == ఖాళీ || strcmp(పేర్లు, "") == 0)
		తిరిగి 0;
	ఒకవేళ ((s = cp = strdup(పేర్లు)) == ఖాళీ)
		తిరిగి 0;
	కొరకు ((p = strsep(&cp, ",")); p && *p != '\0';
	    (p = strsep(&cp, ","))) {
		type = sshkey_type_from_name(p);
		ఒకవేళ (type == కీలకం_UNSPEC) {
			ఒకవేళ (allow_wildcard) {
				/*
				 * Try matching key types against the string.
				 * If any has a positive or negative match then
				 * the component is accepted.
				 */
				impl = ఖాళీ;
				కొరకు (i = 0; keyimpls[i] != ఖాళీ; i++) {
					ఒకవేళ (సరిపోలిక_నమూనా_list(
					    keyimpls[i]->name, p, 0) != 0) {
						impl = keyimpls[i];
						ఆపు;
					}
				}
				ఒకవేళ (impl != ఖాళీ)
					కొనసాగు;
			}
			విడుదల(s);
			తిరిగి 0;
		} లేకపోతే ఒకవేళ (plain_only && sshkey_type_is_cert(type)) {
			విడుదల(s);
			తిరిగి 0;
		}
	}
	విడుదల(s);
	తిరిగి 1;
}

u_int
sshkey_కొలత(స్థిరరాశి నిర్మాణం sshkey *k)
{
	స్థిరరాశి నిర్మాణం sshkey_impl *impl;

	ఒకవేళ ((impl = sshkey_impl_from_కీలకం(k)) == ఖాళీ)
		తిరిగి 0;
	ఒకవేళ (impl->funcs->కొలత != ఖాళీ)
		తిరిగి impl->funcs->కొలత(k);
	తిరిగి impl->keybits;
}

స్థిర పూర్ణాంకం
sshkey_type_is_valid_ca(పూర్ణాంకం type)
{
	స్థిరరాశి నిర్మాణం sshkey_impl *impl;

	ఒకవేళ ((impl = sshkey_impl_from_type(type)) == ఖాళీ)
		తిరిగి 0;
	/* All non-certificate types may act as CAs */
	తిరిగి !impl->cert;
}

పూర్ణాంకం
sshkey_is_cert(స్థిరరాశి నిర్మాణం sshkey *k)
{
	ఒకవేళ (k == ఖాళీ)
		తిరిగి 0;
	తిరిగి sshkey_type_is_cert(k->type);
}

పూర్ణాంకం
sshkey_is_sk(స్థిరరాశి నిర్మాణం sshkey *k)
{
	ఒకవేళ (k == ఖాళీ)
		తిరిగి 0;
	ఎంపిక (sshkey_type_plain(k->type)) {
	స్థితి కీలకం_ECDSA_SK:
	స్థితి కీలకం_ED25519_SK:
		తిరిగి 1;
	అప్రమేయ:
		తిరిగి 0;
	}
}

/* Return the cert-less equivalent to a certified key type */
పూర్ణాంకం
sshkey_type_plain(పూర్ణాంకం type)
{
	ఎంపిక (type) {
	స్థితి కీలకం_RSA_CERT:
		తిరిగి కీలకం_RSA;
	స్థితి కీలకం_ECDSA_CERT:
		తిరిగి కీలకం_ECDSA;
	స్థితి కీలకం_ECDSA_SK_CERT:
		తిరిగి కీలకం_ECDSA_SK;
	స్థితి కీలకం_ED25519_CERT:
		తిరిగి కీలకం_ED25519;
	స్థితి కీలకం_MLDSA44_ED25519_CERT:
		తిరిగి కీలకం_MLDSA44_ED25519;
	స్థితి కీలకం_ED25519_SK_CERT:
		తిరిగి కీలకం_ED25519_SK;
	అప్రమేయ:
		తిరిగి type;
	}
}

/* Return the cert equivalent to a plain key type */
స్థిర పూర్ణాంకం
sshkey_type_certified(పూర్ణాంకం type)
{
	ఎంపిక (type) {
	స్థితి కీలకం_RSA:
		తిరిగి కీలకం_RSA_CERT;
	స్థితి కీలకం_ECDSA:
		తిరిగి కీలకం_ECDSA_CERT;
	స్థితి కీలకం_ECDSA_SK:
		తిరిగి కీలకం_ECDSA_SK_CERT;
	స్థితి కీలకం_ED25519:
		తిరిగి కీలకం_ED25519_CERT;
	స్థితి కీలకం_MLDSA44_ED25519:
		తిరిగి కీలకం_MLDSA44_ED25519_CERT;
	స్థితి కీలకం_ED25519_SK:
		తిరిగి కీలకం_ED25519_SK_CERT;
	అప్రమేయ:
		తిరిగి -1;
	}
}

#నిర్వచితమైతే WITH_OPENSSL
స్థిర స్థిరరాశి EVP_MD *
ssh_digest_గమ్యం_md(పూర్ణాంకం hash_alg)
{
	ఎంపిక (hash_alg) {
	స్థితి SSH_DIGEST_SHA1:
		తిరిగి EVP_sha1();
	స్థితి SSH_DIGEST_SHA256:
		తిరిగి EVP_sha256();
	స్థితి SSH_DIGEST_SHA384:
		తిరిగి EVP_sha384();
	స్థితి SSH_DIGEST_SHA512:
		తిరిగి EVP_sha512();
	}
	తిరిగి ఖాళీ;
}

పూర్ణాంకం
sshkey_pkey_digest_sign(EVP_PKEY *pkey, పూర్ణాంకం hash_alg, u_char **sigp,
    కొలత_t *lenp, స్థిరరాశి u_char *దత్తాంశం, కొలత_t datalen)
{
	EVP_MD_CTX *ctx = ఖాళీ;
	u_char *sig = ఖాళీ;
	పూర్ణాంకం ret;
	కొలత_t slen;
	స్థిరరాశి EVP_MD *evpmd;

	*sigp = ఖాళీ;
	*lenp = 0;

	slen = EVP_PKEY_కొలత(pkey);
	ఒకవేళ (slen <= 0 || slen > SSHBUF_MAX_BIGNUM ||
	   (evpmd = ssh_digest_గమ్యం_md(hash_alg)) == ఖాళీ)
		తిరిగి SSH_ERR_INVALID_వాదం;

	ఒకవేళ ((sig = జ్ఞాపకం_ఇవ్వు(slen)) == ఖాళీ)
		తిరిగి SSH_ERR_ALLOC_FAIL;

	ఒకవేళ ((ctx = EVP_MD_CTX_new()) == ఖాళీ) {
		ret = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (EVP_DigestSignInit(ctx, ఖాళీ, evpmd, ఖాళీ, pkey) != 1 ||
	    EVP_DigestSign(ctx, sig, &slen, దత్తాంశం, datalen) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		వెళ్ళు బహిర్గతం;
	}

	*sigp = sig;
	*lenp = slen;
	/* Now owned by the caller */
	sig = ఖాళీ;
	ret = 0;

 బహిర్గతం:
	EVP_MD_CTX_free(ctx);
	విడుదల(sig);
	తిరిగి ret;
}

పూర్ణాంకం
sshkey_pkey_digest_verify(EVP_PKEY *pkey, పూర్ణాంకం hash_alg, స్థిరరాశి u_char *దత్తాంశం,
    కొలత_t datalen, u_char *sigbuf, కొలత_t siglen)
{
	EVP_MD_CTX *ctx = ఖాళీ;
	పూర్ణాంకం ret = SSH_ERR_అంతర్గత_ERROR;
	స్థిరరాశి EVP_MD *evpmd;

	ఒకవేళ ((evpmd = ssh_digest_గమ్యం_md(hash_alg)) == ఖాళీ)
		తిరిగి SSH_ERR_INVALID_వాదం;
	ఒకవేళ ((ctx = EVP_MD_CTX_new()) == ఖాళీ)
		తిరిగి SSH_ERR_ALLOC_FAIL;
	ఒకవేళ (EVP_DigestVerifyInit(ctx, ఖాళీ, evpmd, ఖాళీ, pkey) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		వెళ్ళు బహిర్గతం;
	}
	ఎంపిక (EVP_DigestVerify(ctx, sigbuf, siglen, దత్తాంశం, datalen)) {
	స్థితి 1:
		ret = 0;
		ఆపు;
	స్థితి 0:
		ret = SSH_ERR_SIGNATURE_INVALID;
		ఆపు;
	అప్రమేయ:
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		ఆపు;
	}

 బహిర్గతం:
	EVP_MD_CTX_free(ctx);
	తిరిగి ret;
}

/* XXX: these are really begging for a table-driven approach */
పూర్ణాంకం
sshkey_వక్రం_name_గమ్యం_nid(స్థిరరాశి అక్షరం *name)
{
	ఒకవేళ (strcmp(name, "nistp256") == 0)
		తిరిగి NID_X9_62_prime256v1;
	లేకపోతే ఒకవేళ (strcmp(name, "nistp384") == 0)
		తిరిగి NID_secp384r1;
	లేకపోతే ఒకవేళ (strcmp(name, "nistp521") == 0)
		తిరిగి NID_secp521r1;
	లేకపోతే
		తిరిగి -1;
}

u_int
sshkey_వక్రం_nid_గమ్యం_బిట్లు(పూర్ణాంకం nid)
{
	ఎంపిక (nid) {
	స్థితి NID_X9_62_prime256v1:
		తిరిగి 256;
	స్థితి NID_secp384r1:
		తిరిగి 384;
	స్థితి NID_secp521r1:
		తిరిగి 521;
	అప్రమేయ:
		తిరిగి 0;
	}
}

పూర్ణాంకం
sshkey_ecdsa_బిట్లు_గమ్యం_nid(పూర్ణాంకం బిట్లు)
{
	ఎంపిక (బిట్లు) {
	స్థితి 256:
		తిరిగి NID_X9_62_prime256v1;
	స్థితి 384:
		తిరిగి NID_secp384r1;
	స్థితి 521:
		తిరిగి NID_secp521r1;
	అప్రమేయ:
		తిరిగి -1;
	}
}

స్థిరరాశి అక్షరం *
sshkey_వక్రం_nid_గమ్యం_name(పూర్ణాంకం nid)
{
	ఎంపిక (nid) {
	స్థితి NID_X9_62_prime256v1:
		తిరిగి "nistp256";
	స్థితి NID_secp384r1:
		తిరిగి "nistp384";
	స్థితి NID_secp521r1:
		తిరిగి "nistp521";
	అప్రమేయ:
		తిరిగి ఖాళీ;
	}
}

పూర్ణాంకం
sshkey_ec_nid_గమ్యం_hash_alg(పూర్ణాంకం nid)
{
	పూర్ణాంకం kbits = sshkey_వక్రం_nid_గమ్యం_బిట్లు(nid);

	ఒకవేళ (kbits <= 0)
		తిరిగి -1;

	/* RFC5656 section 6.2.1 */
	ఒకవేళ (kbits <= 256)
		తిరిగి SSH_DIGEST_SHA256;
	లేకపోతే ఒకవేళ (kbits <= 384)
		తిరిగి SSH_DIGEST_SHA384;
	లేకపోతే
		తిరిగి SSH_DIGEST_SHA512;
}
#అయితే_ముగింపు /* WITH_OPENSSL */

స్థిర శూన్య
cert_free(నిర్మాణం sshkey_cert *cert)
{
	u_int i;

	ఒకవేళ (cert == ఖాళీ)
		తిరిగి;
	sshbuf_free(cert->certblob);
	sshbuf_free(cert->critical);
	sshbuf_free(cert->extensions);
	విడుదల(cert->కీలకం_id);
	కొరకు (i = 0; i < cert->nprincipals; i++)
		విడుదల(cert->principals[i]);
	విడుదల(cert->principals);
	sshkey_free(cert->signature_కీలకం);
	విడుదల(cert->signature_type);
	freezero(cert, పరిమాణం(*cert));
}

స్థిర నిర్మాణం sshkey_cert *
cert_new(శూన్య)
{
	నిర్మాణం sshkey_cert *cert;

	ఒకవేళ ((cert = సున్నా_జ్ఞాపకం_ఇవ్వు(1, పరిమాణం(*cert))) == ఖాళీ)
		తిరిగి ఖాళీ;
	ఒకవేళ ((cert->certblob = sshbuf_new()) == ఖాళీ ||
	    (cert->critical = sshbuf_new()) == ఖాళీ ||
	    (cert->extensions = sshbuf_new()) == ఖాళీ) {
		cert_free(cert);
		తిరిగి ఖాళీ;
	}
	cert->కీలకం_id = ఖాళీ;
	cert->principals = ఖాళీ;
	cert->signature_కీలకం = ఖాళీ;
	cert->signature_type = ఖాళీ;
	తిరిగి cert;
}

నిర్మాణం sshkey *
sshkey_new(పూర్ణాంకం type)
{
	నిర్మాణం sshkey *k;
	స్థిరరాశి నిర్మాణం sshkey_impl *impl = ఖాళీ;

	ఒకవేళ (type != కీలకం_UNSPEC &&
	    (impl = sshkey_impl_from_type(type)) == ఖాళీ)
		తిరిగి ఖాళీ;

	/* All non-certificate types may act as CAs */
	ఒకవేళ ((k = సున్నా_జ్ఞాపకం_ఇవ్వు(1, పరిమాణం(*k))) == ఖాళీ)
		తిరిగి ఖాళీ;
	k->type = type;
	k->ecdsa_nid = -1;
	ఒకవేళ (impl != ఖాళీ && impl->funcs->alloc != ఖాళీ) {
		ఒకవేళ (impl->funcs->alloc(k) != 0) {
			విడుదల(k);
			తిరిగి ఖాళీ;
		}
	}
	ఒకవేళ (sshkey_is_cert(k)) {
		ఒకవేళ ((k->cert = cert_new()) == ఖాళీ) {
			sshkey_free(k);
			తిరిగి ఖాళీ;
		}
	}

	తిరిగి k;
}

/* Frees common FIDO fields */
శూన్య
sshkey_sk_cleanup(నిర్మాణం sshkey *k)
{
	విడుదల(k->sk_application);
	sshbuf_free(k->sk_కీలకం_handle);
	sshbuf_free(k->sk_reserved);
	k->sk_application = ఖాళీ;
	k->sk_కీలకం_handle = k->sk_reserved = ఖాళీ;
}

#ఒకవేళ defined(MAP_CONCEAL)
# define PREKEY_MMAP_FLAG	MAP_CONCEAL
#లేదావేళ defined(MAP_NOCORE)
# define PREKEY_MMAP_FLAG	MAP_NOCORE
#లేకపోతే
# define PREKEY_MMAP_FLAG	0
#అయితే_ముగింపు

స్థిర పూర్ణాంకం
sshkey_prekey_alloc(u_char **prekeyp, కొలత_t len)
{
#ఒకవేళ defined(HAVE_MMAP) && defined(MAP_ANON) && defined(MAP_PRIVATE)
	u_char *prekey;

	*prekeyp = ఖాళీ;
	ఒకవేళ ((prekey = mmap(ఖాళీ, len, PROT_READ|PROT_WRITE,
	    MAP_ANON|MAP_PRIVATE|PREKEY_MMAP_FLAG, -1, 0)) == MAP_FAILED)
		తిరిగి SSH_ERR_SYSTEM_ERROR;
#ఒకవేళ defined(MADV_DONTDUMP) && !defined(MAP_CONCEAL) && !defined(MAP_NOCORE)
	(శూన్య)madvise(prekey, len, MADV_DONTDUMP);
#అయితే_ముగింపు
	*prekeyp = prekey;
#లేకపోతే
	*prekeyp = సున్నా_జ్ఞాపకం_ఇవ్వు(1, len);
#అయితే_ముగింపు /* HAVE_MMAP et al */
	తిరిగి 0;
}

స్థిర శూన్య
sshkey_prekey_free(శూన్య *prekey, కొలత_t len)
{
#ఒకవేళ defined(HAVE_MMAP) && defined(MAP_ANON) && defined(MAP_PRIVATE)
	ఒకవేళ (prekey == ఖాళీ)
		తిరిగి;
	munmap(prekey, len);
#లేకపోతే
	విడుదల(prekey);
#అయితే_ముగింపు /* HAVE_MMAP et al */
}

స్థిర శూన్య
sshkey_free_contents(నిర్మాణం sshkey *k)
{
	స్థిరరాశి నిర్మాణం sshkey_impl *impl;

	ఒకవేళ (k == ఖాళీ)
		తిరిగి;
	ఒకవేళ ((k->flags & SSHKEY_FLAG_EXT) != 0)
		pkcs11_కీలకం_free(k);
	ఒకవేళ ((impl = sshkey_impl_from_type(k->type)) != ఖాళీ &&
	    impl->funcs->cleanup != ఖాళీ)
		impl->funcs->cleanup(k);
	ఒకవేళ (sshkey_is_cert(k))
		cert_free(k->cert);
	freezero(k->shielded_వ్యక్తిగత, k->shielded_len);
	sshkey_prekey_free(k->shield_prekey, k->shield_prekey_len);
}

శూన్య
sshkey_free(నిర్మాణం sshkey *k)
{
	sshkey_free_contents(k);
	freezero(k, పరిమాణం(*k));
}

స్థిర పూర్ణాంకం
cert_compare(నిర్మాణం sshkey_cert *a, నిర్మాణం sshkey_cert *b)
{
	ఒకవేళ (a == ఖాళీ && b == ఖాళీ)
		తిరిగి 1;
	ఒకవేళ (a == ఖాళీ || b == ఖాళీ)
		తిరిగి 0;
	ఒకవేళ (sshbuf_len(a->certblob) != sshbuf_len(b->certblob))
		తిరిగి 0;
	ఒకవేళ (timingsafe_bcmp(sshbuf_ptr(a->certblob), sshbuf_ptr(b->certblob),
	    sshbuf_len(a->certblob)) != 0)
		తిరిగి 0;
	తిరిగి 1;
}

/* Compares FIDO-specific pubkey fields only */
పూర్ణాంకం
sshkey_sk_fields_equal(స్థిరరాశి నిర్మాణం sshkey *a, స్థిరరాశి నిర్మాణం sshkey *b)
{
	ఒకవేళ (a->sk_application == ఖాళీ || b->sk_application == ఖాళీ)
		తిరిగి 0;
	ఒకవేళ (strcmp(a->sk_application, b->sk_application) != 0)
		తిరిగి 0;
	తిరిగి 1;
}

/*
 * Compare public portions of key only, allowing comparisons between
 * certificates and plain keys too.
 */
పూర్ణాంకం
sshkey_equal_ప్రజా(స్థిరరాశి నిర్మాణం sshkey *a, స్థిరరాశి నిర్మాణం sshkey *b)
{
	స్థిరరాశి నిర్మాణం sshkey_impl *impl;

	ఒకవేళ (a == ఖాళీ || b == ఖాళీ ||
	    sshkey_type_plain(a->type) != sshkey_type_plain(b->type))
		తిరిగి 0;
	ఒకవేళ ((impl = sshkey_impl_from_type(a->type)) == ఖాళీ)
		తిరిగి 0;
	తిరిగి impl->funcs->equal(a, b);
}

పూర్ణాంకం
sshkey_equal(స్థిరరాశి నిర్మాణం sshkey *a, స్థిరరాశి నిర్మాణం sshkey *b)
{
	ఒకవేళ (a == ఖాళీ || b == ఖాళీ || a->type != b->type)
		తిరిగి 0;
	ఒకవేళ (sshkey_is_cert(a)) {
		ఒకవేళ (!cert_compare(a->cert, b->cert))
			తిరిగి 0;
	}
	తిరిగి sshkey_equal_ప్రజా(a, b);
}


/* Serialise common FIDO key parts */
పూర్ణాంకం
sshkey_serialize_sk(స్థిరరాశి నిర్మాణం sshkey *కీలకం, నిర్మాణం sshbuf *b)
{
	పూర్ణాంకం r;

	ఒకవేళ ((r = sshbuf_put_cstring(b, కీలకం->sk_application)) != 0)
		తిరిగి r;

	తిరిగి 0;
}

స్థిర పూర్ణాంకం
గమ్యం_blob_buf(స్థిరరాశి నిర్మాణం sshkey *కీలకం, నిర్మాణం sshbuf *b, పూర్ణాంకం force_plain,
  గణన sshkey_serialize_rep opts)
{
	పూర్ణాంకం type, ret = SSH_ERR_అంతర్గత_ERROR;
	స్థిరరాశి అక్షరం *typename;
	స్థిరరాశి నిర్మాణం sshkey_impl *impl;

	ఒకవేళ (కీలకం == ఖాళీ)
		తిరిగి SSH_ERR_INVALID_వాదం;

	type = force_plain ? sshkey_type_plain(కీలకం->type) : కీలకం->type;

	ఒకవేళ (sshkey_type_is_cert(type)) {
		ఒకవేళ (కీలకం->cert == ఖాళీ)
			తిరిగి SSH_ERR_EXPECTED_CERT;
		ఒకవేళ (sshbuf_len(కీలకం->cert->certblob) == 0)
			తిరిగి SSH_ERR_కీలకం_LACKS_CERTBLOB;
		/* Use the existing blob */
		ఒకవేళ ((ret = sshbuf_putb(b, కీలకం->cert->certblob)) != 0)
			తిరిగి ret;
		తిరిగి 0;
	}
	ఒకవేళ ((impl = sshkey_impl_from_type(type)) == ఖాళీ)
		తిరిగి SSH_ERR_కీలకం_TYPE_UNKNOWN;

	typename = sshkey_ssh_name_from_type_nid(type, కీలకం->ecdsa_nid);
	ఒకవేళ ((ret = sshbuf_put_cstring(b, typename)) != 0)
		తిరిగి ret;
	తిరిగి impl->funcs->serialize_ప్రజా(కీలకం, b, opts);
}

పూర్ణాంకం
sshkey_putb(స్థిరరాశి నిర్మాణం sshkey *కీలకం, నిర్మాణం sshbuf *b)
{
	తిరిగి గమ్యం_blob_buf(కీలకం, b, 0, SSHKEY_SERIALIZE_DEFAULT);
}

స్థిర పూర్ణాంకం
sshkey_puts_opts_అంతర్గత(స్థిరరాశి నిర్మాణం sshkey *కీలకం, నిర్మాణం sshbuf *b,
    గణన sshkey_serialize_rep opts, పూర్ణాంకం force_plain)
{
	నిర్మాణం sshbuf *tmp;
	పూర్ణాంకం r;

	ఒకవేళ ((tmp = sshbuf_new()) == ఖాళీ)
		తిరిగి SSH_ERR_ALLOC_FAIL;
	r = గమ్యం_blob_buf(కీలకం, tmp, force_plain, opts);
	ఒకవేళ (r == 0)
		r = sshbuf_put_stringb(b, tmp);
	sshbuf_free(tmp);
	తిరిగి r;
}

పూర్ణాంకం
sshkey_puts(స్థిరరాశి నిర్మాణం sshkey *కీలకం, నిర్మాణం sshbuf *b)
{
	తిరిగి sshkey_puts_opts_అంతర్గత(కీలకం, b, SSHKEY_SERIALIZE_DEFAULT, 0);
}

పూర్ణాంకం
sshkey_putb_plain(స్థిరరాశి నిర్మాణం sshkey *కీలకం, నిర్మాణం sshbuf *b)
{
	తిరిగి గమ్యం_blob_buf(కీలకం, b, 1, SSHKEY_SERIALIZE_DEFAULT);
}

పూర్ణాంకం
sshkey_puts_plain(స్థిరరాశి నిర్మాణం sshkey *కీలకం, నిర్మాణం sshbuf *b)
{
	తిరిగి sshkey_puts_opts_అంతర్గత(కీలకం, b, SSHKEY_SERIALIZE_DEFAULT, 1);
}

స్థిర పూర్ణాంకం
గమ్యం_blob(స్థిరరాశి నిర్మాణం sshkey *కీలకం, u_char **blobp, కొలత_t *lenp, పూర్ణాంకం force_plain,
    గణన sshkey_serialize_rep opts)
{
	పూర్ణాంకం ret = SSH_ERR_అంతర్గత_ERROR;
	కొలత_t len;
	నిర్మాణం sshbuf *b = ఖాళీ;

	ఒకవేళ (lenp != ఖాళీ)
		*lenp = 0;
	ఒకవేళ (blobp != ఖాళీ)
		*blobp = ఖాళీ;
	ఒకవేళ ((b = sshbuf_new()) == ఖాళీ)
		తిరిగి SSH_ERR_ALLOC_FAIL;
	ఒకవేళ ((ret = గమ్యం_blob_buf(కీలకం, b, force_plain, opts)) != 0)
		వెళ్ళు బహిర్గతం;
	len = sshbuf_len(b);
	ఒకవేళ (lenp != ఖాళీ)
		*lenp = len;
	ఒకవేళ (blobp != ఖాళీ) {
		ఒకవేళ ((*blobp = జ్ఞాపకం_ఇవ్వు(len)) == ఖాళీ) {
			ret = SSH_ERR_ALLOC_FAIL;
			వెళ్ళు బహిర్గతం;
		}
		జ్ఞాపకం_నకలు(*blobp, sshbuf_ptr(b), len);
	}
	ret = 0;
 బహిర్గతం:
	sshbuf_free(b);
	తిరిగి ret;
}

పూర్ణాంకం
sshkey_గమ్యం_blob(స్థిరరాశి నిర్మాణం sshkey *కీలకం, u_char **blobp, కొలత_t *lenp)
{
	తిరిగి గమ్యం_blob(కీలకం, blobp, lenp, 0, SSHKEY_SERIALIZE_DEFAULT);
}

పూర్ణాంకం
sshkey_plain_గమ్యం_blob(స్థిరరాశి నిర్మాణం sshkey *కీలకం, u_char **blobp, కొలత_t *lenp)
{
	తిరిగి గమ్యం_blob(కీలకం, blobp, lenp, 1, SSHKEY_SERIALIZE_DEFAULT);
}

పూర్ణాంకం
sshkey_fingerprint_raw(స్థిరరాశి నిర్మాణం sshkey *k, పూర్ణాంకం dgst_alg,
    u_char **retp, కొలత_t *lenp)
{
	u_char *blob = ఖాళీ, *ret = ఖాళీ;
	కొలత_t blob_len = 0;
	పూర్ణాంకం r = SSH_ERR_అంతర్గత_ERROR;

	ఒకవేళ (retp != ఖాళీ)
		*retp = ఖాళీ;
	ఒకవేళ (lenp != ఖాళీ)
		*lenp = 0;
	ఒకవేళ (ssh_digest_బైట్లు(dgst_alg) == 0) {
		r = SSH_ERR_INVALID_వాదం;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((r = గమ్యం_blob(k, &blob, &blob_len, 1, SSHKEY_SERIALIZE_DEFAULT))
	    != 0)
		వెళ్ళు బహిర్గతం;
	ఒకవేళ ((ret = సున్నా_జ్ఞాపకం_ఇవ్వు(1, SSH_DIGEST_MAX_నిడివి)) == ఖాళీ) {
		r = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((r = ssh_digest_జ్ఞాపకం(dgst_alg, blob, blob_len,
	    ret, SSH_DIGEST_MAX_నిడివి)) != 0)
		వెళ్ళు బహిర్గతం;
	/* success */
	ఒకవేళ (retp != ఖాళీ) {
		*retp = ret;
		ret = ఖాళీ;
	}
	ఒకవేళ (lenp != ఖాళీ)
		*lenp = ssh_digest_బైట్లు(dgst_alg);
	r = 0;
 బహిర్గతం:
	విడుదల(ret);
	ఒకవేళ (blob != ఖాళీ)
		freezero(blob, blob_len);
	తిరిగి r;
}

స్థిర అక్షరం *
fingerprint_b64(స్థిరరాశి అక్షరం *alg, u_char *dgst_raw, కొలత_t dgst_raw_len)
{
	అక్షరం *ret;
	కొలత_t plen = అక్షరశ్రేణి_పొడవు(alg) + 1;
	కొలత_t rlen = ((dgst_raw_len + 2) / 3) * 4 + plen + 1;

	ఒకవేళ (dgst_raw_len > 65536 || (ret = సున్నా_జ్ఞాపకం_ఇవ్వు(1, rlen)) == ఖాళీ)
		తిరిగి ఖాళీ;
	strlcpy(ret, alg, rlen);
	strlcat(ret, ":", rlen);
	ఒకవేళ (dgst_raw_len == 0)
		తిరిగి ret;
	ఒకవేళ (b64_ntop(dgst_raw, dgst_raw_len, ret + plen, rlen - plen) == -1) {
		freezero(ret, rlen);
		తిరిగి ఖాళీ;
	}
	/* Trim padding characters from end */
	ret[strcspn(ret, "=")] = '\0';
	తిరిగి ret;
}

స్థిర అక్షరం *
fingerprint_hex(స్థిరరాశి అక్షరం *alg, u_char *dgst_raw, కొలత_t dgst_raw_len)
{
	అక్షరం *retval, hex[5];
	కొలత_t i, rlen = dgst_raw_len * 3 + అక్షరశ్రేణి_పొడవు(alg) + 2;

	ఒకవేళ (dgst_raw_len > 65536 || (retval = సున్నా_జ్ఞాపకం_ఇవ్వు(1, rlen)) == ఖాళీ)
		తిరిగి ఖాళీ;
	strlcpy(retval, alg, rlen);
	strlcat(retval, ":", rlen);
	కొరకు (i = 0; i < dgst_raw_len; i++) {
		snprintf(hex, పరిమాణం(hex), "%s%02x",
		    i > 0 ? ":" : "", dgst_raw[i]);
		strlcat(retval, hex, rlen);
	}
	తిరిగి retval;
}

స్థిర అక్షరం *
fingerprint_bubblebabble(u_char *dgst_raw, కొలత_t dgst_raw_len)
{
	అక్షరం vowels[] = { 'a', 'e', 'i', 'o', 'u', 'y' };
	అక్షరం consonants[] = { 'b', 'c', 'd', 'f', 'g', 'h', 'k', 'l', 'm',
	    'n', 'p', 'r', 's', 't', 'v', 'z', 'x' };
	u_int i, j = 0, విడతలు, విత్తనం = 1;
	అక్షరం *retval;

	విడతలు = (dgst_raw_len / 2) + 1;
	ఒకవేళ ((retval = సున్నా_జ్ఞాపకం_ఇవ్వు(విడతలు, 6)) == ఖాళీ)
		తిరిగి ఖాళీ;
	retval[j++] = 'x';
	కొరకు (i = 0; i < విడతలు; i++) {
		u_int idx0, idx1, idx2, idx3, idx4;
		ఒకవేళ ((i + 1 < విడతలు) || (dgst_raw_len % 2 != 0)) {
			idx0 = (((((u_int)(dgst_raw[2 * i])) >> 6) & 3) +
			    విత్తనం) % 6;
			idx1 = (((u_int)(dgst_raw[2 * i])) >> 2) & 15;
			idx2 = ((((u_int)(dgst_raw[2 * i])) & 3) +
			    (విత్తనం / 6)) % 6;
			retval[j++] = vowels[idx0];
			retval[j++] = consonants[idx1];
			retval[j++] = vowels[idx2];
			ఒకవేళ ((i + 1) < విడతలు) {
				idx3 = (((u_int)(dgst_raw[(2 * i) + 1])) >> 4) & 15;
				idx4 = (((u_int)(dgst_raw[(2 * i) + 1]))) & 15;
				retval[j++] = consonants[idx3];
				retval[j++] = '-';
				retval[j++] = consonants[idx4];
				విత్తనం = ((విత్తనం * 5) +
				    ((((u_int)(dgst_raw[2 * i])) * 7) +
				    ((u_int)(dgst_raw[(2 * i) + 1])))) % 36;
			}
		} లేకపోతే {
			idx0 = విత్తనం % 6;
			idx1 = 16;
			idx2 = విత్తనం / 6;
			retval[j++] = vowels[idx0];
			retval[j++] = consonants[idx1];
			retval[j++] = vowels[idx2];
		}
	}
	retval[j++] = 'x';
	retval[j++] = '\0';
	తిరిగి retval;
}

/*
 * Draw an ASCII-Art representing the fingerprint so human brain can
 * profit from its built-in pattern recognition ability.
 * This technique is called "random art" and can be found in some
 * scientific publications like this original paper:
 *
 * "Hash Visualization: a New Technique to improve Real-World Security",
 * Perrig A. and Song D., 1999, International Workshop on Cryptographic
 * Techniques and E-Commerce (CrypTEC '99)
 * sparrow.ece.cmu.edu/~adrian/projects/validation/validation.pdf
 *
 * The subject came up in a talk by Dan Kaminsky, too.
 *
 * If you see the picture is different, the key is different.
 * If the picture looks the same, you still know nothing.
 *
 * The algorithm used here is a worm crawling over a discrete plane,
 * leaving a trace (augmenting the field) everywhere it goes.
 * Movement is taken from dgst_raw 2bit-wise.  Bumping into walls
 * makes the respective movement vector be ignored for this turn.
 * Graphs are not unambiguous, because circles in graphs can be
 * walked in either direction.
 */

/*
 * Field sizes for the random art.  Have to be odd, so the starting point
 * can be in the exact middle of the picture, and FLDBASE should be >=8 .
 * Else pictures would be too dense, and drawing the frame would
 * fail, too, because the key type would not fit in anymore.
 */
#నిర్వచించు	FLDBASE		8
#నిర్వచించు	FLDSIZE_Y	(FLDBASE + 1)
#నిర్వచించు	FLDSIZE_X	(FLDBASE * 2 + 1)
స్థిర అక్షరం *
fingerprint_randomart(స్థిరరాశి అక్షరం *alg, u_char *dgst_raw, కొలత_t dgst_raw_len,
    స్థిరరాశి నిర్మాణం sshkey *k)
{
	/*
	 * Chars to be used after each other every time the worm
	 * intersects with itself.  Matter of taste.
	 */
	అక్షరం	*augmentation_string = " .o+=*BOX@%&#/^SE";
	అక్షరం	*retval, *p, title[FLDSIZE_X], hash[FLDSIZE_X];
	u_char	 క్షేత్రం[FLDSIZE_X][FLDSIZE_Y];
	కొలత_t	 i, tlen, hlen;
	u_int	 b;
	పూర్ణాంకం	 x, y, r;
	కొలత_t	 len = అక్షరశ్రేణి_పొడవు(augmentation_string) - 1;

	ఒకవేళ ((retval = సున్నా_జ్ఞాపకం_ఇవ్వు((FLDSIZE_X + 3), (FLDSIZE_Y + 2))) == ఖాళీ)
		తిరిగి ఖాళీ;

	/* initialize field */
	memset(క్షేత్రం, 0, FLDSIZE_X * FLDSIZE_Y * పరిమాణం(అక్షరం));
	x = FLDSIZE_X / 2;
	y = FLDSIZE_Y / 2;

	/* process raw key */
	కొరకు (i = 0; i < dgst_raw_len; i++) {
		పూర్ణాంకం ఆదానం;
		/* each byte conveys four 2-bit move commands */
		ఆదానం = dgst_raw[i];
		కొరకు (b = 0; b < 4; b++) {
			/* evaluate 2 bit, rest is shifted later */
			x += (ఆదానం & 0x1) ? 1 : -1;
			y += (ఆదానం & 0x2) ? 1 : -1;

			/* assure we are still in bounds */
			x = గరిష్ఠ(x, 0);
			y = గరిష్ఠ(y, 0);
			x = MINIMUM(x, FLDSIZE_X - 1);
			y = MINIMUM(y, FLDSIZE_Y - 1);

			/* augment the field */
			ఒకవేళ (క్షేత్రం[x][y] < len - 2)
				క్షేత్రం[x][y]++;
			ఆదానం = ఆదానం >> 2;
		}
	}

	/* mark starting point and end point*/
	క్షేత్రం[FLDSIZE_X / 2][FLDSIZE_Y / 2] = len - 1;
	క్షేత్రం[x][y] = len;

	/* assemble title */
	r = snprintf(title, పరిమాణం(title), "[%s %u]",
		sshkey_type(k), sshkey_కొలత(k));
	/* If [type size] won't fit, then try [type]; fits "[ED25519-CERT]" */
	ఒకవేళ (r < 0 || r > (పూర్ణాంకం)పరిమాణం(title))
		r = snprintf(title, పరిమాణం(title), "[%s]", sshkey_type(k));
	tlen = (r <= 0) ? 0 : అక్షరశ్రేణి_పొడవు(title);

	/* assemble hash ID. */
	r = snprintf(hash, పరిమాణం(hash), "[%s]", alg);
	hlen = (r <= 0) ? 0 : అక్షరశ్రేణి_పొడవు(hash);

	/* output upper border */
	p = retval;
	*p++ = '+';
	కొరకు (i = 0; i < (FLDSIZE_X - tlen) / 2; i++)
		*p++ = '-';
	జ్ఞాపకం_నకలు(p, title, tlen);
	p += tlen;
	కొరకు (i += tlen; i < FLDSIZE_X; i++)
		*p++ = '-';
	*p++ = '+';
	*p++ = '\n';

	/* output content */
	కొరకు (y = 0; y < FLDSIZE_Y; y++) {
		*p++ = '|';
		కొరకు (x = 0; x < FLDSIZE_X; x++)
			*p++ = augmentation_string[MINIMUM(క్షేత్రం[x][y], len)];
		*p++ = '|';
		*p++ = '\n';
	}

	/* output lower border */
	*p++ = '+';
	కొరకు (i = 0; i < (FLDSIZE_X - hlen) / 2; i++)
		*p++ = '-';
	జ్ఞాపకం_నకలు(p, hash, hlen);
	p += hlen;
	కొరకు (i += hlen; i < FLDSIZE_X; i++)
		*p++ = '-';
	*p++ = '+';

	తిరిగి retval;
}

అక్షరం *
sshkey_fingerprint(స్థిరరాశి నిర్మాణం sshkey *k, పూర్ణాంకం dgst_alg,
    గణన sshkey_fp_rep dgst_rep)
{
	అక్షరం *retval = ఖాళీ;
	u_char *dgst_raw;
	కొలత_t dgst_raw_len;

	ఒకవేళ (sshkey_fingerprint_raw(k, dgst_alg, &dgst_raw, &dgst_raw_len) != 0)
		తిరిగి ఖాళీ;
	ఎంపిక (dgst_rep) {
	స్థితి SSH_FP_DEFAULT:
		ఒకవేళ (dgst_alg == SSH_DIGEST_MD5) {
			retval = fingerprint_hex(ssh_digest_alg_name(dgst_alg),
			    dgst_raw, dgst_raw_len);
		} లేకపోతే {
			retval = fingerprint_b64(ssh_digest_alg_name(dgst_alg),
			    dgst_raw, dgst_raw_len);
		}
		ఆపు;
	స్థితి SSH_FP_HEX:
		retval = fingerprint_hex(ssh_digest_alg_name(dgst_alg),
		    dgst_raw, dgst_raw_len);
		ఆపు;
	స్థితి SSH_FP_BASE64:
		retval = fingerprint_b64(ssh_digest_alg_name(dgst_alg),
		    dgst_raw, dgst_raw_len);
		ఆపు;
	స్థితి SSH_FP_BUBBLEBABBLE:
		retval = fingerprint_bubblebabble(dgst_raw, dgst_raw_len);
		ఆపు;
	స్థితి SSH_FP_RANDOMART:
		retval = fingerprint_randomart(ssh_digest_alg_name(dgst_alg),
		    dgst_raw, dgst_raw_len, k);
		ఆపు;
	అప్రమేయ:
		freezero(dgst_raw, dgst_raw_len);
		తిరిగి ఖాళీ;
	}
	freezero(dgst_raw, dgst_raw_len);
	తిరిగి retval;
}

స్థిర పూర్ణాంకం
peek_type_nid(స్థిరరాశి అక్షరం *s, కొలత_t l, పూర్ణాంకం *nid)
{
	స్థిరరాశి నిర్మాణం sshkey_impl *impl;
	పూర్ణాంకం i;

	కొరకు (i = 0; keyimpls[i] != ఖాళీ; i++) {
		impl = keyimpls[i];
		ఒకవేళ (impl->name == ఖాళీ || అక్షరశ్రేణి_పొడవు(impl->name) != l)
			కొనసాగు;
		ఒకవేళ (memcmp(s, impl->name, l) == 0) {
			*nid = -1;
			ఒకవేళ (కీలకం_type_is_ecdsa_variant(impl->type))
				*nid = impl->nid;
			తిరిగి impl->type;
		}
	}
	తిరిగి కీలకం_UNSPEC;
}

/* XXX this can now be made const char * */
పూర్ణాంకం
sshkey_read(నిర్మాణం sshkey *ret, అక్షరం **cpp)
{
	నిర్మాణం sshkey *k;
	అక్షరం *cp, *blobcopy;
	కొలత_t space;
	పూర్ణాంకం r, type, వక్రం_nid = -1;
	నిర్మాణం sshbuf *blob;

	ఒకవేళ (ret == ఖాళీ)
		తిరిగి SSH_ERR_INVALID_వాదం;
	ఒకవేళ (ret->type != కీలకం_UNSPEC && sshkey_impl_from_type(ret->type) == ఖాళీ)
		తిరిగి SSH_ERR_INVALID_వాదం;

	/* Decode type */
	cp = *cpp;
	space = strcspn(cp, " \t");
	ఒకవేళ (space == అక్షరశ్రేణి_పొడవు(cp))
		తిరిగి SSH_ERR_INVALID_FORMAT;
	ఒకవేళ ((type = peek_type_nid(cp, space, &వక్రం_nid)) == కీలకం_UNSPEC)
		తిరిగి SSH_ERR_INVALID_FORMAT;

	/* skip whitespace */
	కొరకు (cp += space; *cp == ' ' || *cp == '\t'; cp++)
		;
	ఒకవేళ (*cp == '\0')
		తిరిగి SSH_ERR_INVALID_FORMAT;
	ఒకవేళ (ret->type != కీలకం_UNSPEC && ret->type != type)
		తిరిగి SSH_ERR_కీలకం_TYPE_MISMATCH;
	ఒకవేళ ((blob = sshbuf_new()) == ఖాళీ)
		తిరిగి SSH_ERR_ALLOC_FAIL;

	/* find end of keyblob and decode */
	space = strcspn(cp, " \t");
	ఒకవేళ ((blobcopy = strndup(cp, space)) == ఖాళీ) {
		sshbuf_free(blob);
		తిరిగి SSH_ERR_ALLOC_FAIL;
	}
	ఒకవేళ ((r = sshbuf_b64tod(blob, blobcopy)) != 0) {
		విడుదల(blobcopy);
		sshbuf_free(blob);
		తిరిగి r;
	}
	విడుదల(blobcopy);
	ఒకవేళ ((r = sshkey_fromb(blob, &k)) != 0) {
		sshbuf_free(blob);
		తిరిగి r;
	}
	sshbuf_free(blob);

	/* skip whitespace and leave cp at start of comment */
	కొరకు (cp += space; *cp == ' ' || *cp == '\t'; cp++)
		;

	/* ensure type of blob matches type at start of line */
	ఒకవేళ (k->type != type) {
		sshkey_free(k);
		తిరిగి SSH_ERR_కీలకం_TYPE_MISMATCH;
	}
	ఒకవేళ (కీలకం_type_is_ecdsa_variant(type) && వక్రం_nid != k->ecdsa_nid) {
		sshkey_free(k);
		తిరిగి SSH_ERR_EC_వక్రం_MISMATCH;
	}

	/* Fill in ret from parsed key */
	sshkey_free_contents(ret);
	*ret = *k;
	freezero(k, పరిమాణం(*k));

	/* success */
	*cpp = cp;
	తిరిగి 0;
}

పూర్ణాంకం
sshkey_గమ్యం_base64(స్థిరరాశి నిర్మాణం sshkey *కీలకం, అక్షరం **b64p)
{
	పూర్ణాంకం r = SSH_ERR_అంతర్గత_ERROR;
	నిర్మాణం sshbuf *b = ఖాళీ;
	అక్షరం *uu = ఖాళీ;

	ఒకవేళ (b64p != ఖాళీ)
		*b64p = ఖాళీ;
	ఒకవేళ ((b = sshbuf_new()) == ఖాళీ)
		తిరిగి SSH_ERR_ALLOC_FAIL;
	ఒకవేళ ((r = sshkey_putb(కీలకం, b)) != 0)
		వెళ్ళు బహిర్గతం;
	ఒకవేళ ((uu = sshbuf_dtob64_string(b, 0)) == ఖాళీ) {
		r = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు బహిర్గతం;
	}
	/* Success */
	ఒకవేళ (b64p != ఖాళీ) {
		*b64p = uu;
		uu = ఖాళీ;
	}
	r = 0;
 బహిర్గతం:
	sshbuf_free(b);
	విడుదల(uu);
	తిరిగి r;
}

పూర్ణాంకం
sshkey_format_పాఠ్యం(స్థిరరాశి నిర్మాణం sshkey *కీలకం, నిర్మాణం sshbuf *b)
{
	పూర్ణాంకం r = SSH_ERR_అంతర్గత_ERROR;
	అక్షరం *uu = ఖాళీ;

	ఒకవేళ ((r = sshkey_గమ్యం_base64(కీలకం, &uu)) != 0)
		వెళ్ళు బహిర్గతం;
	ఒకవేళ ((r = sshbuf_putf(b, "%s %s",
	    sshkey_ssh_name(కీలకం), uu)) != 0)
		వెళ్ళు బహిర్గతం;
	r = 0;
 బహిర్గతం:
	విడుదల(uu);
	తిరిగి r;
}

పూర్ణాంకం
sshkey_write(స్థిరరాశి నిర్మాణం sshkey *కీలకం, FILE *f)
{
	నిర్మాణం sshbuf *b = ఖాళీ;
	పూర్ణాంకం r = SSH_ERR_అంతర్గత_ERROR;

	ఒకవేళ ((b = sshbuf_new()) == ఖాళీ)
		తిరిగి SSH_ERR_ALLOC_FAIL;
	ఒకవేళ ((r = sshkey_format_పాఠ్యం(కీలకం, b)) != 0)
		వెళ్ళు బహిర్గతం;
	ఒకవేళ (fwrite(sshbuf_ptr(b), sshbuf_len(b), 1, f) != 1) {
		ఒకవేళ (feof(f))
			errno = EPIPE;
		r = SSH_ERR_SYSTEM_ERROR;
		వెళ్ళు బహిర్గతం;
	}
	/* Success */
	r = 0;
 బహిర్గతం:
	sshbuf_free(b);
	తిరిగి r;
}

స్థిరరాశి అక్షరం *
sshkey_cert_type(స్థిరరాశి నిర్మాణం sshkey *k)
{
	ఎంపిక (k->cert->type) {
	స్థితి SSH2_CERT_TYPE_USER:
		తిరిగి "user";
	స్థితి SSH2_CERT_TYPE_HOST:
		తిరిగి "host";
	అప్రమేయ:
		తిరిగి "unknown";
	}
}

పూర్ణాంకం
sshkey_check_rsa_నిడివి(స్థిరరాశి నిర్మాణం sshkey *k, పూర్ణాంకం min_కొలత)
{
#నిర్వచితమైతే WITH_OPENSSL
	పూర్ణాంకం nbits;

	ఒకవేళ (k == ఖాళీ || k->pkey == ఖాళీ ||
	    (k->type != కీలకం_RSA && k->type != కీలకం_RSA_CERT))
		తిరిగి 0;
	nbits = EVP_PKEY_బిట్లు(k->pkey);
	ఒకవేళ (nbits < SSH_RSA_MINIMUM_MODULUS_కొలత ||
	    (min_కొలత > 0 && nbits < min_కొలత))
		తిరిగి SSH_ERR_కీలకం_నిడివి;
#అయితే_ముగింపు /* WITH_OPENSSL */
	తిరిగి 0;
}

#నిర్వచితమైతే WITH_OPENSSL
పూర్ణాంకం
sshkey_ecdsa_కీలకం_గమ్యం_nid(స్థిరరాశి EC_కీలకం *k)
{
	స్థిరరాశి EC_సమూహం *g;
	పూర్ణాంకం nid;

	ఒకవేళ (k == ఖాళీ || (g = EC_కీలకం_get0_సమూహం(k)) == ఖాళీ)
		తిరిగి -1;
	ఒకవేళ ((nid = EC_సమూహం_get_వక్రం_name(g)) <= 0)
		తిరిగి -1;
	తిరిగి nid;
}

పూర్ణాంకం
sshkey_ecdsa_pkey_గమ్యం_nid(EVP_PKEY *pkey)
{
	తిరిగి sshkey_ecdsa_కీలకం_గమ్యం_nid(EVP_PKEY_get0_EC_కీలకం(pkey));
}
#అయితే_ముగింపు /* WITH_OPENSSL */

పూర్ణాంకం
sshkey_generate(పూర్ణాంకం type, u_int బిట్లు, నిర్మాణం sshkey **keyp)
{
	నిర్మాణం sshkey *k;
	పూర్ణాంకం ret = SSH_ERR_అంతర్గత_ERROR;
	స్థిరరాశి నిర్మాణం sshkey_impl *impl;

	ఒకవేళ (keyp == ఖాళీ || sshkey_type_is_cert(type))
		తిరిగి SSH_ERR_INVALID_వాదం;
	*keyp = ఖాళీ;
	ఒకవేళ ((impl = sshkey_impl_from_type(type)) == ఖాళీ)
		తిరిగి SSH_ERR_కీలకం_TYPE_UNKNOWN;
	ఒకవేళ (impl->funcs->generate == ఖాళీ)
		తిరిగి SSH_ERR_FEATURE_UNSUPPORTED;
	ఒకవేళ ((k = sshkey_new(కీలకం_UNSPEC)) == ఖాళీ)
		తిరిగి SSH_ERR_ALLOC_FAIL;
	k->type = type;
	ఒకవేళ ((ret = impl->funcs->generate(k, బిట్లు)) != 0) {
		sshkey_free(k);
		తిరిగి ret;
	}
	/* success */
	*keyp = k;
	తిరిగి 0;
}

పూర్ణాంకం
sshkey_cert_copy(స్థిరరాశి నిర్మాణం sshkey *from_కీలకం, నిర్మాణం sshkey *గమ్యం_కీలకం)
{
	u_int i;
	స్థిరరాశి నిర్మాణం sshkey_cert *from;
	నిర్మాణం sshkey_cert *గమ్యం;
	పూర్ణాంకం r = SSH_ERR_అంతర్గత_ERROR;

	ఒకవేళ (గమ్యం_కీలకం == ఖాళీ || (from = from_కీలకం->cert) == ఖాళీ)
		తిరిగి SSH_ERR_INVALID_వాదం;

	ఒకవేళ ((గమ్యం = cert_new()) == ఖాళీ)
		తిరిగి SSH_ERR_ALLOC_FAIL;

	ఒకవేళ ((r = sshbuf_putb(గమ్యం->certblob, from->certblob)) != 0 ||
	    (r = sshbuf_putb(గమ్యం->critical, from->critical)) != 0 ||
	    (r = sshbuf_putb(గమ్యం->extensions, from->extensions)) != 0)
		వెళ్ళు బహిర్గతం;

	గమ్యం->serial = from->serial;
	గమ్యం->type = from->type;
	ఒకవేళ (from->కీలకం_id == ఖాళీ)
		గమ్యం->కీలకం_id = ఖాళీ;
	లేకపోతే ఒకవేళ ((గమ్యం->కీలకం_id = strdup(from->కీలకం_id)) == ఖాళీ) {
		r = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు బహిర్గతం;
	}
	గమ్యం->valid_after = from->valid_after;
	గమ్యం->valid_before = from->valid_before;
	ఒకవేళ (from->signature_కీలకం == ఖాళీ)
		గమ్యం->signature_కీలకం = ఖాళీ;
	లేకపోతే ఒకవేళ ((r = sshkey_from_వ్యక్తిగత(from->signature_కీలకం,
	    &గమ్యం->signature_కీలకం)) != 0)
		వెళ్ళు బహిర్గతం;
	ఒకవేళ (from->signature_type != ఖాళీ &&
	    (గమ్యం->signature_type = strdup(from->signature_type)) == ఖాళీ) {
		r = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (from->nprincipals > SSHKEY_CERT_MAX_PRINCIPALS) {
		r = SSH_ERR_INVALID_వాదం;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (from->nprincipals > 0) {
		ఒకవేళ ((గమ్యం->principals = సున్నా_జ్ఞాపకం_ఇవ్వు(from->nprincipals,
		    పరిమాణం(*గమ్యం->principals))) == ఖాళీ) {
			r = SSH_ERR_ALLOC_FAIL;
			వెళ్ళు బహిర్గతం;
		}
		కొరకు (i = 0; i < from->nprincipals; i++) {
			గమ్యం->principals[i] = strdup(from->principals[i]);
			ఒకవేళ (గమ్యం->principals[i] == ఖాళీ) {
				గమ్యం->nprincipals = i;
				r = SSH_ERR_ALLOC_FAIL;
				వెళ్ళు బహిర్గతం;
			}
		}
	}
	గమ్యం->nprincipals = from->nprincipals;

	/* success */
	cert_free(గమ్యం_కీలకం->cert);
	గమ్యం_కీలకం->cert = గమ్యం;
	గమ్యం = ఖాళీ;
	r = 0;
 బహిర్గతం:
	cert_free(గమ్యం);
	తిరిగి r;
}

పూర్ణాంకం
sshkey_copy_ప్రజా_sk(స్థిరరాశి నిర్మాణం sshkey *from, నిర్మాణం sshkey *గమ్యం)
{
	/* Append security-key application string */
	ఒకవేళ ((గమ్యం->sk_application = strdup(from->sk_application)) == ఖాళీ)
		తిరిగి SSH_ERR_ALLOC_FAIL;
	తిరిగి 0;
}

పూర్ణాంకం
sshkey_from_వ్యక్తిగత(స్థిరరాశి నిర్మాణం sshkey *k, నిర్మాణం sshkey **pkp)
{
	నిర్మాణం sshkey *n = ఖాళీ;
	పూర్ణాంకం r = SSH_ERR_అంతర్గత_ERROR;
	స్థిరరాశి నిర్మాణం sshkey_impl *impl;

	*pkp = ఖాళీ;
	ఒకవేళ ((impl = sshkey_impl_from_కీలకం(k)) == ఖాళీ)
		తిరిగి SSH_ERR_కీలకం_TYPE_UNKNOWN;
	ఒకవేళ ((n = sshkey_new(k->type)) == ఖాళీ) {
		r = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((r = impl->funcs->copy_ప్రజా(k, n)) != 0)
		వెళ్ళు బహిర్గతం;
	ఒకవేళ (sshkey_is_cert(k) && (r = sshkey_cert_copy(k, n)) != 0)
		వెళ్ళు బహిర్గతం;
	/* success */
	*pkp = n;
	n = ఖాళీ;
	r = 0;
 బహిర్గతం:
	sshkey_free(n);
	తిరిగి r;
}

పూర్ణాంకం
sshkey_is_shielded(నిర్మాణం sshkey *k)
{
	తిరిగి k != ఖాళీ && k->shielded_వ్యక్తిగత != ఖాళీ;
}

పూర్ణాంకం
sshkey_shield_వ్యక్తిగత(నిర్మాణం sshkey *k)
{
	నిర్మాణం sshbuf *prvbuf = ఖాళీ;
	u_char *prekey = ఖాళీ, *enc = ఖాళీ, keyiv[SSH_DIGEST_MAX_నిడివి];
	నిర్మాణం sshcipher_ctx *cctx = ఖాళీ;
	స్థిరరాశి నిర్మాణం sshcipher *cipher;
	కొలత_t i, enclen = 0;
	నిర్మాణం sshkey *kswap = ఖాళీ, tmp;
	పూర్ణాంకం r = SSH_ERR_అంతర్గత_ERROR;

#నిర్వచితమైతే DEBUG_PK
	fprintf(stderr, "%s: entering for %s\n", __func__, sshkey_ssh_name(k));
#అయితే_ముగింపు
	ఒకవేళ ((cipher = cipher_by_name(SSHKEY_SHIELD_CIPHER)) == ఖాళీ) {
		r = SSH_ERR_INVALID_వాదం;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (cipher_keylen(cipher) + cipher_ivlen(cipher) >
	    ssh_digest_బైట్లు(SSHKEY_SHIELD_PREKEY_HASH)) {
		r = SSH_ERR_అంతర్గత_ERROR;
		వెళ్ళు బహిర్గతం;
	}

	/* Prepare a random pre-key, and from it an ephemeral key */
	ఒకవేళ ((r = sshkey_prekey_alloc(&prekey, SSHKEY_SHIELD_PREKEY_LEN)) != 0)
		వెళ్ళు బహిర్గతం;
	arc4random_buf(prekey, SSHKEY_SHIELD_PREKEY_LEN);
	ఒకవేళ ((r = ssh_digest_జ్ఞాపకం(SSHKEY_SHIELD_PREKEY_HASH,
	    prekey, SSHKEY_SHIELD_PREKEY_LEN,
	    keyiv, SSH_DIGEST_MAX_నిడివి)) != 0)
		వెళ్ళు బహిర్గతం;
#నిర్వచితమైతే DEBUG_PK
	fprintf(stderr, "%s: key+iv\n", __func__);
	sshbuf_dump_దత్తాంశం(keyiv, ssh_digest_బైట్లు(SSHKEY_SHIELD_PREKEY_HASH),
	    stderr);
#అయితే_ముగింపు
	ఒకవేళ ((r = cipher_init(&cctx, cipher, keyiv, cipher_keylen(cipher),
	    keyiv + cipher_keylen(cipher), cipher_ivlen(cipher), 1)) != 0)
		వెళ్ళు బహిర్గతం;

	/* Serialise and encrypt the private key using the ephemeral key */
	ఒకవేళ ((prvbuf = sshbuf_new()) == ఖాళీ) {
		r = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (sshkey_is_shielded(k) && (r = sshkey_unshield_వ్యక్తిగత(k)) != 0)
		వెళ్ళు బహిర్గతం;
	ఒకవేళ ((r = sshkey_వ్యక్తిగత_serialize(k, prvbuf)) != 0)
		వెళ్ళు బహిర్గతం;
	/* pad to cipher blocksize */
	i = 0;
	అయితే (sshbuf_len(prvbuf) % cipher_blocksize(cipher)) {
		ఒకవేళ ((r = sshbuf_put_u8(prvbuf, ++i & 0xff)) != 0)
			వెళ్ళు బహిర్గతం;
	}
#నిర్వచితమైతే DEBUG_PK
	fprintf(stderr, "%s: serialised\n", __func__);
	sshbuf_dump(prvbuf, stderr);
#అయితే_ముగింపు
	/* encrypt */
	enclen = sshbuf_len(prvbuf);
	ఒకవేళ ((enc = జ్ఞాపకం_ఇవ్వు(enclen)) == ఖాళీ) {
		r = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((r = cipher_crypt(cctx, 0, enc,
	    sshbuf_ptr(prvbuf), sshbuf_len(prvbuf), 0, 0)) != 0)
		వెళ్ళు బహిర్గతం;
#నిర్వచితమైతే DEBUG_PK
	fprintf(stderr, "%s: encrypted\n", __func__);
	sshbuf_dump_దత్తాంశం(enc, enclen, stderr);
#అయితే_ముగింపు

	/* Make a scrubbed, public-only copy of our private key argument */
	ఒకవేళ ((r = sshkey_from_వ్యక్తిగత(k, &kswap)) != 0)
		వెళ్ళు బహిర్గతం;

	/* Swap the private key out (it will be destroyed below) */
	tmp = *kswap;
	*kswap = *k;
	*k = tmp;

	/* Insert the shielded key into our argument */
	k->shielded_వ్యక్తిగత = enc;
	k->shielded_len = enclen;
	k->shield_prekey = prekey;
	k->shield_prekey_len = SSHKEY_SHIELD_PREKEY_LEN;
	enc = prekey = ఖాళీ; /* transferred */
	enclen = 0;

	/* preserve key fields that are required for correct operation */
	k->sk_flags = kswap->sk_flags;

	/* success */
	r = 0;

 బహిర్గతం:
	/* XXX behaviour on error - invalidate original private key? */
	cipher_free(cctx);
	explicit_bzero(keyiv, పరిమాణం(keyiv));
	explicit_bzero(&tmp, పరిమాణం(tmp));
	freezero(enc, enclen);
	sshkey_prekey_free(prekey, SSHKEY_SHIELD_PREKEY_LEN);
	sshkey_free(kswap);
	sshbuf_free(prvbuf);
	తిరిగి r;
}

/* Check deterministic padding after private key */
స్థిర పూర్ణాంకం
private2_check_padding(నిర్మాణం sshbuf *decrypted)
{
	u_char pad;
	కొలత_t i;
	పూర్ణాంకం r;

	i = 0;
	అయితే (sshbuf_len(decrypted)) {
		ఒకవేళ ((r = sshbuf_get_u8(decrypted, &pad)) != 0)
			వెళ్ళు బహిర్గతం;
		ఒకవేళ (pad != (++i & 0xff)) {
			r = SSH_ERR_INVALID_FORMAT;
			వెళ్ళు బహిర్గతం;
		}
	}
	/* success */
	r = 0;
 బహిర్గతం:
	explicit_bzero(&pad, పరిమాణం(pad));
	explicit_bzero(&i, పరిమాణం(i));
	తిరిగి r;
}

పూర్ణాంకం
sshkey_unshield_వ్యక్తిగత(నిర్మాణం sshkey *k)
{
	నిర్మాణం sshbuf *prvbuf = ఖాళీ;
	u_char *cp, keyiv[SSH_DIGEST_MAX_నిడివి];
	నిర్మాణం sshcipher_ctx *cctx = ఖాళీ;
	స్థిరరాశి నిర్మాణం sshcipher *cipher;
	నిర్మాణం sshkey *kswap = ఖాళీ, tmp;
	పూర్ణాంకం r = SSH_ERR_అంతర్గత_ERROR;

#నిర్వచితమైతే DEBUG_PK
	fprintf(stderr, "%s: entering for %s\n", __func__, sshkey_ssh_name(k));
#అయితే_ముగింపు
	ఒకవేళ (!sshkey_is_shielded(k))
		తిరిగి 0; /* nothing to do */

	ఒకవేళ ((cipher = cipher_by_name(SSHKEY_SHIELD_CIPHER)) == ఖాళీ) {
		r = SSH_ERR_INVALID_వాదం;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (cipher_keylen(cipher) + cipher_ivlen(cipher) >
	    ssh_digest_బైట్లు(SSHKEY_SHIELD_PREKEY_HASH)) {
		r = SSH_ERR_అంతర్గత_ERROR;
		వెళ్ళు బహిర్గతం;
	}
	/* check size of shielded key blob */
	ఒకవేళ (k->shielded_len < cipher_blocksize(cipher) ||
	    (k->shielded_len % cipher_blocksize(cipher)) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		వెళ్ళు బహిర్గతం;
	}

	/* Calculate the ephemeral key from the prekey */
	ఒకవేళ ((r = ssh_digest_జ్ఞాపకం(SSHKEY_SHIELD_PREKEY_HASH,
	    k->shield_prekey, k->shield_prekey_len,
	    keyiv, SSH_DIGEST_MAX_నిడివి)) != 0)
		వెళ్ళు బహిర్గతం;
	ఒకవేళ ((r = cipher_init(&cctx, cipher, keyiv, cipher_keylen(cipher),
	    keyiv + cipher_keylen(cipher), cipher_ivlen(cipher), 0)) != 0)
		వెళ్ళు బహిర్గతం;
#నిర్వచితమైతే DEBUG_PK
	fprintf(stderr, "%s: key+iv\n", __func__);
	sshbuf_dump_దత్తాంశం(keyiv, ssh_digest_బైట్లు(SSHKEY_SHIELD_PREKEY_HASH),
	    stderr);
#అయితే_ముగింపు

	/* Decrypt and parse the shielded private key using the ephemeral key */
	ఒకవేళ ((prvbuf = sshbuf_new()) == ఖాళీ) {
		r = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((r = sshbuf_reserve(prvbuf, k->shielded_len, &cp)) != 0)
		వెళ్ళు బహిర్గతం;
	/* decrypt */
#నిర్వచితమైతే DEBUG_PK
	fprintf(stderr, "%s: encrypted\n", __func__);
	sshbuf_dump_దత్తాంశం(k->shielded_వ్యక్తిగత, k->shielded_len, stderr);
#అయితే_ముగింపు
	ఒకవేళ ((r = cipher_crypt(cctx, 0, cp,
	    k->shielded_వ్యక్తిగత, k->shielded_len, 0, 0)) != 0)
		వెళ్ళు బహిర్గతం;
#నిర్వచితమైతే DEBUG_PK
	fprintf(stderr, "%s: serialised\n", __func__);
	sshbuf_dump(prvbuf, stderr);
#అయితే_ముగింపు
	/* Parse private key */
	ఒకవేళ ((r = sshkey_వ్యక్తిగత_deserialize(prvbuf, &kswap)) != 0)
		వెళ్ళు బహిర్గతం;

	ఒకవేళ ((r = private2_check_padding(prvbuf)) != 0)
		వెళ్ళు బహిర్గతం;

	/* Swap the parsed key back into place */
	tmp = *kswap;
	*kswap = *k;
	*k = tmp;

	/* success */
	r = 0;

 బహిర్గతం:
	cipher_free(cctx);
	explicit_bzero(keyiv, పరిమాణం(keyiv));
	explicit_bzero(&tmp, పరిమాణం(tmp));
	sshkey_free(kswap);
	sshbuf_free(prvbuf);
	తిరిగి r;
}

స్థిర పూర్ణాంకం
cert_parse(నిర్మాణం sshbuf *b, నిర్మాణం sshkey *కీలకం, నిర్మాణం sshbuf *certbuf,
    స్థిరరాశి అక్షరం *ca_sigalg_allowlist)
{
	నిర్మాణం sshbuf *principals = ఖాళీ, *crit = ఖాళీ;
	నిర్మాణం sshbuf *exts = ఖాళీ, *ca = ఖాళీ;
	u_char *sig = ఖాళీ;
	అక్షరం *sigtype = ఖాళీ;
	కొలత_t signed_len = 0, slen = 0, kidlen = 0;
	పూర్ణాంకం ret = SSH_ERR_అంతర్గత_ERROR;

	/* Copy the entire key blob for verification and later serialisation */
	ఒకవేళ ((ret = sshbuf_putb(కీలకం->cert->certblob, certbuf)) != 0)
		తిరిగి ret;

	/* Parse body of certificate up to signature */
	ఒకవేళ ((ret = sshbuf_get_u64(b, &కీలకం->cert->serial)) != 0 ||
	    (ret = sshbuf_get_u32(b, &కీలకం->cert->type)) != 0 ||
	    (ret = sshbuf_get_cstring(b, &కీలకం->cert->కీలకం_id, &kidlen)) != 0 ||
	    (ret = sshbuf_froms(b, &principals)) != 0 ||
	    (ret = sshbuf_get_u64(b, &కీలకం->cert->valid_after)) != 0 ||
	    (ret = sshbuf_get_u64(b, &కీలకం->cert->valid_before)) != 0 ||
	    (ret = sshbuf_froms(b, &crit)) != 0 ||
	    (ret = sshbuf_froms(b, &exts)) != 0 ||
	    (ret = sshbuf_get_string_ప్రత్యక్ష(b, ఖాళీ, ఖాళీ)) != 0 ||
	    (ret = sshbuf_froms(b, &ca)) != 0) {
		/* XXX debug print error for ret */
		ret = SSH_ERR_INVALID_FORMAT;
		వెళ్ళు బహిర్గతం;
	}

	/* Signature is left in the buffer so we can calculate this length */
	signed_len = sshbuf_len(కీలకం->cert->certblob) - sshbuf_len(b);

	ఒకవేళ ((ret = sshbuf_get_string(b, &sig, &slen)) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		వెళ్ళు బహిర్గతం;
	}

	/* Is this a signature we're prepared to accept? */
	ఒకవేళ ((ret = sshkey_get_sigtype(sig, slen, &sigtype)) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (ca_sigalg_allowlist != ఖాళీ &&
	    సరిపోలిక_నమూనా_list(sigtype, ca_sigalg_allowlist, 0) != 1) {
		ret = SSH_ERR_SIGN_ALG_UNSUPPORTED;
		వెళ్ళు బహిర్గతం;
	}

	/* Parse CA key and check whether we might accept it */
	ఒకవేళ (sshkey_from_blob_అంతర్గత(ca, &కీలకం->cert->signature_కీలకం, 0,
	    ca_sigalg_allowlist, ఖాళీ) != 0) {
		ret = SSH_ERR_కీలకం_CERT_INVALID_SIGN_కీలకం;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (!sshkey_type_is_valid_ca(కీలకం->cert->signature_కీలకం->type)) {
		ret = SSH_ERR_కీలకం_CERT_INVALID_SIGN_కీలకం;
		వెళ్ళు బహిర్గతం;
	}

	ఒకవేళ (కీలకం->cert->type != SSH2_CERT_TYPE_USER &&
	    కీలకం->cert->type != SSH2_CERT_TYPE_HOST) {
		ret = SSH_ERR_కీలకం_CERT_UNKNOWN_TYPE;
		వెళ్ళు బహిర్గతం;
	}

	/* Parse principals section */
	అయితే (sshbuf_len(principals) > 0) {
		అక్షరం *principal = ఖాళీ;
		అక్షరం **oprincipals = ఖాళీ;

		ఒకవేళ (కీలకం->cert->nprincipals >= SSHKEY_CERT_MAX_PRINCIPALS) {
			ret = SSH_ERR_INVALID_FORMAT;
			వెళ్ళు బహిర్గతం;
		}
		ఒకవేళ ((ret = sshbuf_get_cstring(principals, &principal,
		    ఖాళీ)) != 0) {
			ret = SSH_ERR_INVALID_FORMAT;
			వెళ్ళు బహిర్గతం;
		}
		oprincipals = కీలకం->cert->principals;
		కీలకం->cert->principals = recallocarray(కీలకం->cert->principals,
		    కీలకం->cert->nprincipals, కీలకం->cert->nprincipals + 1,
		    పరిమాణం(*కీలకం->cert->principals));
		ఒకవేళ (కీలకం->cert->principals == ఖాళీ) {
			విడుదల(principal);
			కీలకం->cert->principals = oprincipals;
			ret = SSH_ERR_ALLOC_FAIL;
			వెళ్ళు బహిర్గతం;
		}
		కీలకం->cert->principals[కీలకం->cert->nprincipals++] = principal;
	}

	/*
	 * Stash a copies of the critical options and extensions sections
	 * for later use.
	 */
	ఒకవేళ ((ret = sshbuf_putb(కీలకం->cert->critical, crit)) != 0 ||
	    (exts != ఖాళీ &&
	    (ret = sshbuf_putb(కీలకం->cert->extensions, exts)) != 0))
		వెళ్ళు బహిర్గతం;

	/*
	 * Validate critical options and extensions sections format.
	 */
	అయితే (sshbuf_len(crit) != 0) {
		ఒకవేళ ((ret = sshbuf_get_string_ప్రత్యక్ష(crit, ఖాళీ, ఖాళీ)) != 0 ||
		    (ret = sshbuf_get_string_ప్రత్యక్ష(crit, ఖాళీ, ఖాళీ)) != 0) {
			sshbuf_reset(కీలకం->cert->critical);
			ret = SSH_ERR_INVALID_FORMAT;
			వెళ్ళు బహిర్గతం;
		}
	}
	అయితే (exts != ఖాళీ && sshbuf_len(exts) != 0) {
		ఒకవేళ ((ret = sshbuf_get_string_ప్రత్యక్ష(exts, ఖాళీ, ఖాళీ)) != 0 ||
		    (ret = sshbuf_get_string_ప్రత్యక్ష(exts, ఖాళీ, ఖాళీ)) != 0) {
			sshbuf_reset(కీలకం->cert->extensions);
			ret = SSH_ERR_INVALID_FORMAT;
			వెళ్ళు బహిర్గతం;
		}
	}

	/* Finally, validate signature */
	ఒకవేళ ((ret = sshkey_verify(కీలకం->cert->signature_కీలకం, sig, slen,
	    sshbuf_ptr(కీలకం->cert->certblob), signed_len, ఖాళీ, 0, ఖాళీ)) != 0)
		వెళ్ళు బహిర్గతం;

	/* Success */
	ret = 0;
	కీలకం->cert->signature_type = sigtype;
	sigtype = ఖాళీ;
 బహిర్గతం:
	sshbuf_free(ca);
	sshbuf_free(crit);
	sshbuf_free(exts);
	sshbuf_free(principals);
	విడుదల(sig);
	విడుదల(sigtype);
	తిరిగి ret;
}

పూర్ణాంకం
sshkey_deserialize_sk(నిర్మాణం sshbuf *b, నిర్మాణం sshkey *కీలకం)
{
	/* Parse additional security-key application string */
	ఒకవేళ (sshbuf_get_cstring(b, &కీలకం->sk_application, ఖాళీ) != 0)
		తిరిగి SSH_ERR_INVALID_FORMAT;
	తిరిగి 0;
}

స్థిర పూర్ణాంకం
sshkey_from_blob_అంతర్గత(నిర్మాణం sshbuf *b, నిర్మాణం sshkey **keyp,
    పూర్ణాంకం allow_cert, స్థిరరాశి అక్షరం *alg_allowlist, స్థిరరాశి అక్షరం *ca_sigalg_allowlist)
{
	పూర్ణాంకం type, ret = SSH_ERR_అంతర్గత_ERROR;
	అక్షరం *ktype = ఖాళీ;
	నిర్మాణం sshkey *కీలకం = ఖాళీ;
	నిర్మాణం sshbuf *copy;
	స్థిరరాశి నిర్మాణం sshkey_impl *impl;

#నిర్వచితమైతే DEBUG_PK /* XXX */
	sshbuf_dump(b, stderr);
#అయితే_ముగింపు
	ఒకవేళ (keyp != ఖాళీ)
		*keyp = ఖాళీ;
	ఒకవేళ ((copy = sshbuf_fromb(b)) == ఖాళీ) {
		ret = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (sshbuf_get_cstring(b, &ktype, ఖాళీ) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		వెళ్ళు బహిర్గతం;
	}

	type = sshkey_type_from_name(ktype);
	ఒకవేళ (!allow_cert && sshkey_type_is_cert(type)) {
		ret = SSH_ERR_కీలకం_CERT_INVALID_SIGN_కీలకం;
		వెళ్ళు బహిర్గతం;
	}

	ఒకవేళ (alg_allowlist != ఖాళీ &&
	    !sshkey_సరిపోలిక_keyname_గమ్యం_sigalgs(ktype, alg_allowlist)) {
		ret = SSH_ERR_కీలకం_ALG_UNSUPPORTED;
		వెళ్ళు బహిర్గతం;
	}

	ఒకవేళ ((impl = sshkey_impl_from_type(type)) == ఖాళీ) {
		ret = SSH_ERR_కీలకం_TYPE_UNKNOWN;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((కీలకం = sshkey_new(type)) == ఖాళీ) {
		ret = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (sshkey_type_is_cert(type)) {
		/* Skip nonce that precedes all certificates */
		ఒకవేళ (sshbuf_get_string_ప్రత్యక్ష(b, ఖాళీ, ఖాళీ) != 0) {
			ret = SSH_ERR_INVALID_FORMAT;
			వెళ్ళు బహిర్గతం;
		}
	}
	ఒకవేళ ((ret = impl->funcs->deserialize_ప్రజా(ktype, b, కీలకం)) != 0)
		వెళ్ళు బహిర్గతం;

	/* Parse certificate potion */
	ఒకవేళ (sshkey_is_cert(కీలకం) &&
	    (ret = cert_parse(b, కీలకం, copy, ca_sigalg_allowlist)) != 0)
		వెళ్ళు బహిర్గతం;

	ఒకవేళ (కీలకం != ఖాళీ && sshbuf_len(b) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		వెళ్ళు బహిర్గతం;
	}
	ret = 0;
	ఒకవేళ (keyp != ఖాళీ) {
		*keyp = కీలకం;
		కీలకం = ఖాళీ;
	}
 బహిర్గతం:
	sshbuf_free(copy);
	sshkey_free(కీలకం);
	విడుదల(ktype);
	తిరిగి ret;
}

పూర్ణాంకం
sshkey_from_blob(స్థిరరాశి u_char *blob, కొలత_t blen, నిర్మాణం sshkey **keyp)
{
	నిర్మాణం sshbuf *b;
	పూర్ణాంకం r;

	ఒకవేళ ((b = sshbuf_from(blob, blen)) == ఖాళీ)
		తిరిగి SSH_ERR_ALLOC_FAIL;
	r = sshkey_from_blob_అంతర్గత(b, keyp, 1, ఖాళీ, ఖాళీ);
	sshbuf_free(b);
	తిరిగి r;
}

పూర్ణాంకం
sshkey_fromb(నిర్మాణం sshbuf *b, నిర్మాణం sshkey **keyp)
{
	తిరిగి sshkey_from_blob_అంతర్గత(b, keyp, 1, ఖాళీ, ఖాళీ);
}

పూర్ణాంకం
sshkey_fromb_allowlist(నిర్మాణం sshbuf *b, నిర్మాణం sshkey **keyp,
    స్థిరరాశి అక్షరం *alg_allowlist, స్థిరరాశి అక్షరం *ca_sigalg_allowlist)
{
	తిరిగి sshkey_from_blob_అంతర్గత(b, keyp, 1,
	    alg_allowlist, ca_sigalg_allowlist);
}

పూర్ణాంకం
sshkey_froms(నిర్మాణం sshbuf *buf, నిర్మాణం sshkey **keyp)
{
	నిర్మాణం sshbuf *b;
	పూర్ణాంకం r;

	ఒకవేళ ((r = sshbuf_froms(buf, &b)) != 0)
		తిరిగి r;
	r = sshkey_from_blob_అంతర్గత(b, keyp, 1, ఖాళీ, ఖాళీ);
	sshbuf_free(b);
	తిరిగి r;
}

పూర్ణాంకం
sshkey_get_sigtype(స్థిరరాశి u_char *sig, కొలత_t siglen, అక్షరం **sigtypep)
{
	పూర్ణాంకం r;
	నిర్మాణం sshbuf *b = ఖాళీ;
	అక్షరం *sigtype = ఖాళీ;

	ఒకవేళ (sigtypep != ఖాళీ)
		*sigtypep = ఖాళీ;
	ఒకవేళ ((b = sshbuf_from(sig, siglen)) == ఖాళీ)
		తిరిగి SSH_ERR_ALLOC_FAIL;
	ఒకవేళ ((r = sshbuf_get_cstring(b, &sigtype, ఖాళీ)) != 0)
		వెళ్ళు బహిర్గతం;
	/* success */
	ఒకవేళ (sigtypep != ఖాళీ) {
		*sigtypep = sigtype;
		sigtype = ఖాళీ;
	}
	r = 0;
 బహిర్గతం:
	విడుదల(sigtype);
	sshbuf_free(b);
	తిరిగి r;
}

/*
 *
 * Checks whether a certificate's signature type is allowed.
 * Returns 0 (success) if the certificate signature type appears in the
 * "allowed" pattern-list, or the key is not a certificate to begin with.
 * Otherwise returns a ssherr.h code.
 */
పూర్ణాంకం
sshkey_check_cert_sigtype(స్థిరరాశి నిర్మాణం sshkey *కీలకం, స్థిరరాశి అక్షరం *allowed)
{
	ఒకవేళ (కీలకం == ఖాళీ || allowed == ఖాళీ)
		తిరిగి SSH_ERR_INVALID_వాదం;
	ఒకవేళ (!sshkey_type_is_cert(కీలకం->type))
		తిరిగి 0;
	ఒకవేళ (కీలకం->cert == ఖాళీ || కీలకం->cert->signature_type == ఖాళీ)
		తిరిగి SSH_ERR_INVALID_వాదం;
	ఒకవేళ (సరిపోలిక_నమూనా_list(కీలకం->cert->signature_type, allowed, 0) != 1)
		తిరిగి SSH_ERR_SIGN_ALG_UNSUPPORTED;
	తిరిగి 0;
}

/*
 * Returns the expected signature algorithm for a given public key algorithm.
 */
స్థిరరాశి అక్షరం *
sshkey_sigalg_by_name(స్థిరరాశి అక్షరం *name)
{
	స్థిరరాశి నిర్మాణం sshkey_impl *impl;
	పూర్ణాంకం i;

	కొరకు (i = 0; keyimpls[i] != ఖాళీ; i++) {
		impl = keyimpls[i];
		ఒకవేళ (strcmp(impl->name, name) != 0)
			కొనసాగు;
		ఒకవేళ (impl->sigalg != ఖాళీ)
			తిరిగి impl->sigalg;
		ఒకవేళ (!impl->cert)
			తిరిగి impl->name;
		తిరిగి sshkey_ssh_name_from_type_nid(
		    sshkey_type_plain(impl->type), impl->nid);
	}
	తిరిగి ఖాళీ;
}

/*
 * Verifies that the signature algorithm appearing inside the signature blob
 * matches that which was requested.
 */
పూర్ణాంకం
sshkey_check_sigtype(స్థిరరాశి u_char *sig, కొలత_t siglen,
    స్థిరరాశి అక్షరం *requested_alg)
{
	స్థిరరాశి అక్షరం *expected_alg;
	అక్షరం *sigtype = ఖాళీ;
	పూర్ణాంకం r;

	ఒకవేళ (requested_alg == ఖాళీ)
		తిరిగి 0;
	ఒకవేళ ((expected_alg = sshkey_sigalg_by_name(requested_alg)) == ఖాళీ)
		తిరిగి SSH_ERR_INVALID_వాదం;
	ఒకవేళ ((r = sshkey_get_sigtype(sig, siglen, &sigtype)) != 0)
		తిరిగి r;
	r = strcmp(expected_alg, sigtype) == 0;
	విడుదల(sigtype);
	తిరిగి r ? 0 : SSH_ERR_SIGN_ALG_UNSUPPORTED;
}

పూర్ణాంకం
sshkey_sign(నిర్మాణం sshkey *కీలకం,
    u_char **sigp, కొలత_t *lenp,
    స్థిరరాశి u_char *దత్తాంశం, కొలత_t datalen,
    స్థిరరాశి అక్షరం *alg, స్థిరరాశి అక్షరం *sk_provider, స్థిరరాశి అక్షరం *sk_pin, u_int compat)
{
	పూర్ణాంకం was_shielded = sshkey_is_shielded(కీలకం);
	పూర్ణాంకం r2, r = SSH_ERR_అంతర్గత_ERROR;
	స్థిరరాశి నిర్మాణం sshkey_impl *impl;

	ఒకవేళ (sigp != ఖాళీ)
		*sigp = ఖాళీ;
	ఒకవేళ (lenp != ఖాళీ)
		*lenp = 0;
	ఒకవేళ (datalen > SSH_కీలకం_MAX_SIGN_దత్తాంశం_కొలత)
		తిరిగి SSH_ERR_INVALID_వాదం;
	ఒకవేళ ((impl = sshkey_impl_from_కీలకం(కీలకం)) == ఖాళీ)
		తిరిగి SSH_ERR_కీలకం_TYPE_UNKNOWN;
	ఒకవేళ ((r = sshkey_unshield_వ్యక్తిగత(కీలకం)) != 0)
		తిరిగి r;
	ఒకవేళ (sshkey_is_sk(కీలకం)) {
		r = sshsk_sign(sk_provider, కీలకం, sigp, lenp, దత్తాంశం,
		    datalen, compat, sk_pin);
	} లేకపోతే ఒకవేళ ((కీలకం->flags & SSHKEY_FLAG_EXT) != 0) {
		r = pkcs11_sign(కీలకం, sigp, lenp, దత్తాంశం, datalen,
		    alg, sk_provider, sk_pin, compat);
	} లేకపోతే {
		ఒకవేళ (impl->funcs->sign == ఖాళీ)
			r = SSH_ERR_SIGN_ALG_UNSUPPORTED;
		లేకపోతే {
			r = impl->funcs->sign(కీలకం, sigp, lenp, దత్తాంశం, datalen,
			    alg, sk_provider, sk_pin, compat);
		 }
	}
	ఒకవేళ (was_shielded && (r2 = sshkey_shield_వ్యక్తిగత(కీలకం)) != 0)
		తిరిగి r2;
	తిరిగి r;
}

/*
 * ssh_key_verify returns 0 for a correct signature and < 0 on error.
 * If "alg" specified, then the signature must use that algorithm.
 */
పూర్ణాంకం
sshkey_verify(స్థిరరాశి నిర్మాణం sshkey *కీలకం,
    స్థిరరాశి u_char *sig, కొలత_t siglen,
    స్థిరరాశి u_char *దత్తాంశం, కొలత_t dlen, స్థిరరాశి అక్షరం *alg, u_int compat,
    నిర్మాణం sshkey_sig_details **detailsp)
{
	స్థిరరాశి నిర్మాణం sshkey_impl *impl;

	ఒకవేళ (detailsp != ఖాళీ)
		*detailsp = ఖాళీ;
	ఒకవేళ (siglen == 0 || dlen > SSH_కీలకం_MAX_SIGN_దత్తాంశం_కొలత)
		తిరిగి SSH_ERR_INVALID_వాదం;
	ఒకవేళ ((impl = sshkey_impl_from_కీలకం(కీలకం)) == ఖాళీ)
		తిరిగి SSH_ERR_కీలకం_TYPE_UNKNOWN;
	తిరిగి impl->funcs->verify(కీలకం, sig, siglen, దత్తాంశం, dlen,
	    alg, compat, detailsp);
}

/* Convert a plain key to their _CERT equivalent */
పూర్ణాంకం
sshkey_గమ్యం_certified(నిర్మాణం sshkey *k)
{
	పూర్ణాంకం newtype;

	ఒకవేళ ((newtype = sshkey_type_certified(k->type)) == -1)
		తిరిగి SSH_ERR_INVALID_వాదం;
	ఒకవేళ ((k->cert = cert_new()) == ఖాళీ)
		తిరిగి SSH_ERR_ALLOC_FAIL;
	k->type = newtype;
	తిరిగి 0;
}

/* Convert a certificate to its raw key equivalent */
పూర్ణాంకం
sshkey_drop_cert(నిర్మాణం sshkey *k)
{
	ఒకవేళ (!sshkey_type_is_cert(k->type))
		తిరిగి SSH_ERR_కీలకం_TYPE_UNKNOWN;
	cert_free(k->cert);
	k->cert = ఖాళీ;
	k->type = sshkey_type_plain(k->type);
	తిరిగి 0;
}

/* Sign a certified key, (re-)generating the signed certblob. */
పూర్ణాంకం
sshkey_certify_custom(నిర్మాణం sshkey *k, నిర్మాణం sshkey *ca, స్థిరరాశి అక్షరం *alg,
    స్థిరరాశి అక్షరం *sk_provider, స్థిరరాశి అక్షరం *sk_pin,
    sshkey_certify_signer *signer, శూన్య *signer_ctx)
{
	స్థిరరాశి నిర్మాణం sshkey_impl *impl;
	నిర్మాణం sshbuf *principals = ఖాళీ;
	u_char *ca_blob = ఖాళీ, *sig_blob = ఖాళీ, nonce[32];
	కొలత_t i, ca_len, sig_len;
	పూర్ణాంకం ret = SSH_ERR_అంతర్గత_ERROR;
	నిర్మాణం sshbuf *cert = ఖాళీ;
	అక్షరం *sigtype = ఖాళీ;

	ఒకవేళ (k == ఖాళీ || k->cert == ఖాళీ ||
	    k->cert->certblob == ఖాళీ || ca == ఖాళీ)
		తిరిగి SSH_ERR_INVALID_వాదం;
	ఒకవేళ (!sshkey_is_cert(k))
		తిరిగి SSH_ERR_కీలకం_TYPE_UNKNOWN;
	ఒకవేళ (!sshkey_type_is_valid_ca(ca->type))
		తిరిగి SSH_ERR_కీలకం_CERT_INVALID_SIGN_కీలకం;
	ఒకవేళ ((impl = sshkey_impl_from_కీలకం(k)) == ఖాళీ)
		తిరిగి SSH_ERR_అంతర్గత_ERROR;

	/*
	 * If no alg specified as argument but a signature_type was set,
	 * then prefer that. If both were specified, then they must match.
	 */
	ఒకవేళ (alg == ఖాళీ)
		alg = k->cert->signature_type;
	లేకపోతే ఒకవేళ (k->cert->signature_type != ఖాళీ &&
	    strcmp(alg, k->cert->signature_type) != 0)
		తిరిగి SSH_ERR_INVALID_వాదం;

	/*
	 * If no signing algorithm or signature_type was specified and we're
	 * using a RSA key, then default to a good signature algorithm.
	 */
	ఒకవేళ (alg == ఖాళీ && ca->type == కీలకం_RSA)
		alg = "rsa-sha2-512";

	ఒకవేళ ((ret = sshkey_గమ్యం_blob(ca, &ca_blob, &ca_len)) != 0)
		తిరిగి SSH_ERR_కీలకం_CERT_INVALID_SIGN_కీలకం;

	cert = k->cert->certblob; /* for readability */
	sshbuf_reset(cert);
	ఒకవేళ ((ret = sshbuf_put_cstring(cert, sshkey_ssh_name(k))) != 0)
		వెళ్ళు బహిర్గతం;

	/* -v01 certs put nonce first */
	arc4random_buf(&nonce, పరిమాణం(nonce));
	ఒకవేళ ((ret = sshbuf_put_string(cert, nonce, పరిమాణం(nonce))) != 0)
		వెళ్ళు బహిర్గతం;

	/* Public key next */
	ఒకవేళ ((ret = impl->funcs->serialize_ప్రజా(k, cert,
	    SSHKEY_SERIALIZE_DEFAULT)) != 0)
		వెళ్ళు బహిర్గతం;

	/* Then remaining cert fields */
	ఒకవేళ ((ret = sshbuf_put_u64(cert, k->cert->serial)) != 0 ||
	    (ret = sshbuf_put_u32(cert, k->cert->type)) != 0 ||
	    (ret = sshbuf_put_cstring(cert, k->cert->కీలకం_id)) != 0)
		వెళ్ళు బహిర్గతం;

	ఒకవేళ ((principals = sshbuf_new()) == ఖాళీ) {
		ret = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు బహిర్గతం;
	}
	కొరకు (i = 0; i < k->cert->nprincipals; i++) {
		ఒకవేళ ((ret = sshbuf_put_cstring(principals,
		    k->cert->principals[i])) != 0)
			వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((ret = sshbuf_put_stringb(cert, principals)) != 0 ||
	    (ret = sshbuf_put_u64(cert, k->cert->valid_after)) != 0 ||
	    (ret = sshbuf_put_u64(cert, k->cert->valid_before)) != 0 ||
	    (ret = sshbuf_put_stringb(cert, k->cert->critical)) != 0 ||
	    (ret = sshbuf_put_stringb(cert, k->cert->extensions)) != 0 ||
	    (ret = sshbuf_put_string(cert, ఖాళీ, 0)) != 0 || /* Reserved */
	    (ret = sshbuf_put_string(cert, ca_blob, ca_len)) != 0)
		వెళ్ళు బహిర్గతం;

	/* Sign the whole mess */
	ఒకవేళ ((ret = signer(ca, &sig_blob, &sig_len, sshbuf_ptr(cert),
	    sshbuf_len(cert), alg, sk_provider, sk_pin, 0, signer_ctx)) != 0)
		వెళ్ళు బహిర్గతం;
	/* Check and update signature_type against what was actually used */
	ఒకవేళ ((ret = sshkey_get_sigtype(sig_blob, sig_len, &sigtype)) != 0)
		వెళ్ళు బహిర్గతం;
	ఒకవేళ (alg != ఖాళీ && strcmp(alg, sigtype) != 0) {
		ret = SSH_ERR_SIGN_ALG_UNSUPPORTED;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (k->cert->signature_type == ఖాళీ) {
		k->cert->signature_type = sigtype;
		sigtype = ఖాళీ;
	}
	/* Append signature and we are done */
	ఒకవేళ ((ret = sshbuf_put_string(cert, sig_blob, sig_len)) != 0)
		వెళ్ళు బహిర్గతం;
	ret = 0;
 బహిర్గతం:
	ఒకవేళ (ret != 0)
		sshbuf_reset(cert);
	విడుదల(sig_blob);
	విడుదల(ca_blob);
	విడుదల(sigtype);
	sshbuf_free(principals);
	తిరిగి ret;
}

స్థిర పూర్ణాంకం
default_కీలకం_sign(నిర్మాణం sshkey *కీలకం, u_char **sigp, కొలత_t *lenp,
    స్థిరరాశి u_char *దత్తాంశం, కొలత_t datalen,
    స్థిరరాశి అక్షరం *alg, స్థిరరాశి అక్షరం *sk_provider, స్థిరరాశి అక్షరం *sk_pin,
    u_int compat, శూన్య *ctx)
{
	ఒకవేళ (ctx != ఖాళీ)
		తిరిగి SSH_ERR_INVALID_వాదం;
	తిరిగి sshkey_sign(కీలకం, sigp, lenp, దత్తాంశం, datalen, alg,
	    sk_provider, sk_pin, compat);
}

పూర్ణాంకం
sshkey_certify(నిర్మాణం sshkey *k, నిర్మాణం sshkey *ca, స్థిరరాశి అక్షరం *alg,
    స్థిరరాశి అక్షరం *sk_provider, స్థిరరాశి అక్షరం *sk_pin)
{
	తిరిగి sshkey_certify_custom(k, ca, alg, sk_provider, sk_pin,
	    default_కీలకం_sign, ఖాళీ);
}

పూర్ణాంకం
sshkey_cert_check_authority(స్థిరరాశి నిర్మాణం sshkey *k,
    పూర్ణాంకం want_host, పూర్ణాంకం wildcard_నమూనా, uint64_t verify_సమయం,
    స్థిరరాశి అక్షరం *name, స్థిరరాశి అక్షరం **reason)
{
	u_int i, principal_matches;

	ఒకవేళ (reason == ఖాళీ)
		తిరిగి SSH_ERR_INVALID_వాదం;
	ఒకవేళ (!sshkey_is_cert(k)) {
		*reason = "Key is not a certificate";
		తిరిగి SSH_ERR_కీలకం_CERT_INVALID;
	}
	ఒకవేళ (want_host) {
		ఒకవేళ (k->cert->type != SSH2_CERT_TYPE_HOST) {
			*reason = "Certificate invalid: not a host certificate";
			తిరిగి SSH_ERR_కీలకం_CERT_INVALID;
		}
	} లేకపోతే {
		ఒకవేళ (k->cert->type != SSH2_CERT_TYPE_USER) {
			*reason = "Certificate invalid: not a user certificate";
			తిరిగి SSH_ERR_కీలకం_CERT_INVALID;
		}
	}
	ఒకవేళ (verify_సమయం < k->cert->valid_after) {
		*reason = "Certificate invalid: not yet valid";
		తిరిగి SSH_ERR_కీలకం_CERT_INVALID;
	}
	ఒకవేళ (verify_సమయం >= k->cert->valid_before) {
		*reason = "Certificate invalid: expired";
		తిరిగి SSH_ERR_కీలకం_CERT_INVALID;
	}
	ఒకవేళ (k->cert->nprincipals == 0) {
		*reason = "Certificate lacks principal list";
		తిరిగి SSH_ERR_కీలకం_CERT_INVALID;
	}
	ఒకవేళ (name == ఖాళీ)
		తిరిగి 0; /* principal matching not requested */

	principal_matches = 0;
	కొరకు (i = 0; i < k->cert->nprincipals; i++) {
		ఒకవేళ (wildcard_నమూనా) {
			ఒకవేళ (సరిపోలిక_నమూనా(name, k->cert->principals[i])) {
				principal_matches = 1;
				ఆపు;
			}
		} లేకపోతే ఒకవేళ (strcmp(name, k->cert->principals[i]) == 0) {
			principal_matches = 1;
			ఆపు;
		}
	}
	ఒకవేళ (!principal_matches) {
		*reason = "Certificate invalid: name is not a listed "
		    "principal";
		తిరిగి SSH_ERR_కీలకం_CERT_INVALID;
	}
	తిరిగి 0;
}

పూర్ణాంకం
sshkey_cert_check_authority_now(స్థిరరాశి నిర్మాణం sshkey *k,
    పూర్ణాంకం want_host, పూర్ణాంకం wildcard_నమూనా, స్థిరరాశి అక్షరం *name,
    స్థిరరాశి అక్షరం **reason)
{
	time_t now;

	ఒకవేళ ((now = time(ఖాళీ)) < 0) {
		/* yikes - system clock before epoch! */
		*reason = "Certificate invalid: not yet valid";
		తిరిగి SSH_ERR_కీలకం_CERT_INVALID;
	}
	తిరిగి sshkey_cert_check_authority(k, want_host, wildcard_నమూనా,
	    (uint64_t)now, name, reason);
}

పూర్ణాంకం
sshkey_cert_check_host(స్థిరరాశి నిర్మాణం sshkey *కీలకం, స్థిరరాశి అక్షరం *host,
    స్థిరరాశి అక్షరం *ca_sign_algorithms, స్థిరరాశి అక్షరం **reason)
{
	పూర్ణాంకం r;

	ఒకవేళ ((r = sshkey_cert_check_authority_now(కీలకం, 1, 1, host, reason)) != 0)
		తిరిగి r;
	ఒకవేళ (sshbuf_len(కీలకం->cert->critical) != 0) {
		*reason = "Certificate contains unsupported critical options";
		తిరిగి SSH_ERR_కీలకం_CERT_INVALID;
	}
	ఒకవేళ (ca_sign_algorithms != ఖాళీ &&
	    (r = sshkey_check_cert_sigtype(కీలకం, ca_sign_algorithms)) != 0) {
		*reason = "Certificate signed with disallowed algorithm";
		తిరిగి SSH_ERR_కీలకం_CERT_INVALID;
	}
	తిరిగి 0;
}

కొలత_t
sshkey_format_cert_validity(స్థిరరాశి నిర్మాణం sshkey_cert *cert, అక్షరం *s, కొలత_t l)
{
	అక్షరం from[32], గమ్యం[32], ret[128];

	*from = *గమ్యం = '\0';
	ఒకవేళ (cert->valid_after == 0 &&
	    cert->valid_before == 0xffffffffffffffffULL)
		తిరిగి strlcpy(s, "forever", l);

	ఒకవేళ (cert->valid_after != 0)
		format_absolute_సమయం(cert->valid_after, from, పరిమాణం(from));
	ఒకవేళ (cert->valid_before != 0xffffffffffffffffULL)
		format_absolute_సమయం(cert->valid_before, గమ్యం, పరిమాణం(గమ్యం));

	ఒకవేళ (cert->valid_after == 0)
		snprintf(ret, పరిమాణం(ret), "before %s", గమ్యం);
	లేకపోతే ఒకవేళ (cert->valid_before == 0xffffffffffffffffULL)
		snprintf(ret, పరిమాణం(ret), "after %s", from);
	లేకపోతే
		snprintf(ret, పరిమాణం(ret), "from %s to %s", from, గమ్యం);

	తిరిగి strlcpy(s, ret, l);
}

/* Common serialization for FIDO private keys */
పూర్ణాంకం
sshkey_serialize_వ్యక్తిగత_sk(స్థిరరాశి నిర్మాణం sshkey *కీలకం, నిర్మాణం sshbuf *b)
{
	పూర్ణాంకం r;

	ఒకవేళ ((r = sshbuf_put_cstring(b, కీలకం->sk_application)) != 0 ||
	    (r = sshbuf_put_u8(b, కీలకం->sk_flags)) != 0 ||
	    (r = sshbuf_put_stringb(b, కీలకం->sk_కీలకం_handle)) != 0 ||
	    (r = sshbuf_put_stringb(b, కీలకం->sk_reserved)) != 0)
		తిరిగి r;

	తిరిగి 0;
}

స్థిర పూర్ణాంకం
sshkey_వ్యక్తిగత_serialize_opt(నిర్మాణం sshkey *కీలకం, నిర్మాణం sshbuf *buf,
    గణన sshkey_serialize_rep opts)
{
	పూర్ణాంకం r = SSH_ERR_అంతర్గత_ERROR;
	పూర్ణాంకం was_shielded = sshkey_is_shielded(కీలకం);
	నిర్మాణం sshbuf *b = ఖాళీ;
	స్థిరరాశి నిర్మాణం sshkey_impl *impl;

	ఒకవేళ ((impl = sshkey_impl_from_కీలకం(కీలకం)) == ఖాళీ)
		తిరిగి SSH_ERR_అంతర్గత_ERROR;
	ఒకవేళ ((r = sshkey_unshield_వ్యక్తిగత(కీలకం)) != 0)
		తిరిగి r;
	ఒకవేళ ((b = sshbuf_new()) == ఖాళీ)
		తిరిగి SSH_ERR_ALLOC_FAIL;
	ఒకవేళ ((r = sshbuf_put_cstring(b, sshkey_ssh_name(కీలకం))) != 0)
		వెళ్ళు బహిర్గతం;
	ఒకవేళ (sshkey_is_cert(కీలకం)) {
		ఒకవేళ (కీలకం->cert == ఖాళీ ||
		    sshbuf_len(కీలకం->cert->certblob) == 0) {
			r = SSH_ERR_INVALID_వాదం;
			వెళ్ళు బహిర్గతం;
		}
		ఒకవేళ ((r = sshbuf_put_stringb(b, కీలకం->cert->certblob)) != 0)
			వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((r = impl->funcs->serialize_వ్యక్తిగత(కీలకం, b, opts)) != 0)
		వెళ్ళు బహిర్గతం;

	/*
	 * success (but we still need to append the output to buf after
	 * possibly re-shielding the private key)
	 */
	r = 0;
 బహిర్గతం:
	ఒకవేళ (was_shielded)
		r = sshkey_shield_వ్యక్తిగత(కీలకం);
	ఒకవేళ (r == 0)
		r = sshbuf_putb(buf, b);
	sshbuf_free(b);

	తిరిగి r;
}

పూర్ణాంకం
sshkey_వ్యక్తిగత_serialize(నిర్మాణం sshkey *కీలకం, నిర్మాణం sshbuf *b)
{
	తిరిగి sshkey_వ్యక్తిగత_serialize_opt(కీలకం, b,
	    SSHKEY_SERIALIZE_DEFAULT);
}


/* Shared deserialization of FIDO private key components */
పూర్ణాంకం
sshkey_వ్యక్తిగత_deserialize_sk(నిర్మాణం sshbuf *buf, నిర్మాణం sshkey *k)
{
	పూర్ణాంకం r;

	ఒకవేళ ((k->sk_కీలకం_handle = sshbuf_new()) == ఖాళీ ||
	    (k->sk_reserved = sshbuf_new()) == ఖాళీ)
		తిరిగి SSH_ERR_ALLOC_FAIL;
	ఒకవేళ ((r = sshbuf_get_cstring(buf, &k->sk_application, ఖాళీ)) != 0 ||
	    (r = sshbuf_get_u8(buf, &k->sk_flags)) != 0 ||
	    (r = sshbuf_get_stringb(buf, k->sk_కీలకం_handle)) != 0 ||
	    (r = sshbuf_get_stringb(buf, k->sk_reserved)) != 0)
		తిరిగి r;

	తిరిగి 0;
}

పూర్ణాంకం
sshkey_వ్యక్తిగత_deserialize(నిర్మాణం sshbuf *buf, నిర్మాణం sshkey **kp)
{
	స్థిరరాశి నిర్మాణం sshkey_impl *impl;
	అక్షరం *tname = ఖాళీ;
	అక్షరం *expect_sk_application = ఖాళీ;
	u_char *expect_ed25519_pk = ఖాళీ;
	నిర్మాణం sshkey *k = ఖాళీ;
	పూర్ణాంకం type, r = SSH_ERR_అంతర్గత_ERROR;

	ఒకవేళ (kp != ఖాళీ)
		*kp = ఖాళీ;
	ఒకవేళ ((r = sshbuf_get_cstring(buf, &tname, ఖాళీ)) != 0)
		వెళ్ళు బహిర్గతం;
	type = sshkey_type_from_name(tname);
	ఒకవేళ (sshkey_type_is_cert(type)) {
		/*
		 * Certificate key private keys begin with the certificate
		 * itself. Make sure this matches the type of the enclosing
		 * private key.
		 */
		ఒకవేళ ((r = sshkey_froms(buf, &k)) != 0)
			వెళ్ళు బహిర్గతం;
		ఒకవేళ (k->type != type) {
			r = SSH_ERR_కీలకం_CERT_MISMATCH;
			వెళ్ళు బహిర్గతం;
		}
		/* For ECDSA keys, the group must match too */
		ఒకవేళ (k->type == కీలకం_ECDSA &&
		    k->ecdsa_nid != sshkey_ecdsa_nid_from_name(tname)) {
			r = SSH_ERR_కీలకం_CERT_MISMATCH;
			వెళ్ళు బహిర్గతం;
		}
		/*
		 * Several fields are redundant between certificate and
		 * private key body, we require these to match.
		 */
		expect_sk_application = k->sk_application;
		expect_ed25519_pk = k->ed25519_pk;
		k->sk_application = ఖాళీ;
		k->ed25519_pk = ఖాళీ;
	} లేకపోతే {
		ఒకవేళ ((k = sshkey_new(type)) == ఖాళీ) {
			r = SSH_ERR_ALLOC_FAIL;
			వెళ్ళు బహిర్గతం;
		}
	}
	ఒకవేళ ((impl = sshkey_impl_from_type(type)) == ఖాళీ) {
		r = SSH_ERR_అంతర్గత_ERROR;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((r = impl->funcs->deserialize_వ్యక్తిగత(tname, buf, k)) != 0)
		వెళ్ళు బహిర్గతం;

	ఒకవేళ ((expect_sk_application != ఖాళీ && (k->sk_application == ఖాళీ ||
	    strcmp(expect_sk_application, k->sk_application) != 0)) ||
	    (expect_ed25519_pk != ఖాళీ && (k->ed25519_pk == ఖాళీ ||
	    memcmp(expect_ed25519_pk, k->ed25519_pk, ED25519_PK_SZ) != 0))) {
		r = SSH_ERR_కీలకం_CERT_MISMATCH;
		వెళ్ళు బహిర్గతం;
	}
	/* success */
	r = 0;
	ఒకవేళ (kp != ఖాళీ) {
		*kp = k;
		k = ఖాళీ;
	}
 బహిర్గతం:
	విడుదల(tname);
	sshkey_free(k);
	విడుదల(expect_sk_application);
	విడుదల(expect_ed25519_pk);
	తిరిగి r;
}

#నిర్వచితమైతే WITH_OPENSSL
పూర్ణాంకం
sshkey_ec_validate_ప్రజా(స్థిరరాశి EC_సమూహం *సమూహం, స్థిరరాశి EC_బిందువు *బహిరంగ)
{
	EC_బిందువు *nq = ఖాళీ;
	BIGNUM *క్రమం = ఖాళీ, *cofactor = ఖాళీ;
	పూర్ణాంకం ret = SSH_ERR_కీలకం_INVALID_EC_విలువ;

	/*
	 * NB. This assumes OpenSSL has already verified that the public
	 * point lies on the curve and that its coordinates are in [0, p).
	 * This is done by EC_POINT_oct2point() on at least OpenSSL >= 1.1,
	 * LibreSSL and BoringSSL.
	 */

	/* Q != infinity */
	ఒకవేళ (EC_బిందువు_is_at_infinity(సమూహం, బహిరంగ))
		వెళ్ళు బహిర్గతం;

	ఒకవేళ ((cofactor = BN_new()) == ఖాళీ) {
		ret = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (EC_సమూహం_get_cofactor(సమూహం, cofactor, ఖాళీ) != 1)
		వెళ్ళు బహిర్గతం;

	/*
	 * Verify nQ == infinity (n == order of subgroup)
	 * This check may be skipped for curves with cofactor 1, as per
	 * NIST SP 800-56A, 5.6.2.3.
	 */
	ఒకవేళ (!BN_is_one(cofactor)) {
		ఒకవేళ ((క్రమం = BN_new()) == ఖాళీ) {
			ret = SSH_ERR_ALLOC_FAIL;
			వెళ్ళు బహిర్గతం;
		}
		ఒకవేళ (EC_సమూహం_get_క్రమం(సమూహం, క్రమం, ఖాళీ) != 1) {
			ret = SSH_ERR_LIBCRYPTO_ERROR;
			వెళ్ళు బహిర్గతం;
		}
		ఒకవేళ ((nq = EC_బిందువు_new(సమూహం)) == ఖాళీ) {
			ret = SSH_ERR_ALLOC_FAIL;
			వెళ్ళు బహిర్గతం;
		}
		ఒకవేళ (EC_బిందువు_mul(సమూహం, nq, ఖాళీ, బహిరంగ, క్రమం, ఖాళీ) != 1) {
			ret = SSH_ERR_LIBCRYPTO_ERROR;
			వెళ్ళు బహిర్గతం;
		}
		ఒకవేళ (EC_బిందువు_is_at_infinity(సమూహం, nq) != 1)
			వెళ్ళు బహిర్గతం;
	}

	/* success */
	ret = 0;
 బహిర్గతం:
	BN_clear_free(cofactor);
	BN_clear_free(క్రమం);
	EC_బిందువు_free(nq);
	తిరిగి ret;
}

పూర్ణాంకం
sshkey_ec_validate_వ్యక్తిగత(స్థిరరాశి EC_కీలకం *కీలకం)
{
	BIGNUM *క్రమం = ఖాళీ, *tmp = ఖాళీ;
	పూర్ణాంకం ret = SSH_ERR_కీలకం_INVALID_EC_విలువ;

	ఒకవేళ ((క్రమం = BN_new()) == ఖాళీ || (tmp = BN_new()) == ఖాళీ) {
		ret = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు బహిర్గతం;
	}

	/* log2(private) > log2(order)/2 */
	ఒకవేళ (EC_సమూహం_get_క్రమం(EC_కీలకం_get0_సమూహం(కీలకం), క్రమం, ఖాళీ) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (BN_అంకె_బిట్లు(EC_కీలకం_get0_వ్యక్తిగత_కీలకం(కీలకం)) <=
	    BN_అంకె_బిట్లు(క్రమం) / 2)
		వెళ్ళు బహిర్గతం;

	/* private < order - 1 */
	ఒకవేళ (!BN_sub(tmp, క్రమం, BN_విలువ_one())) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (BN_cmp(EC_కీలకం_get0_వ్యక్తిగత_కీలకం(కీలకం), tmp) >= 0)
		వెళ్ళు బహిర్గతం;
	ret = 0;
 బహిర్గతం:
	BN_clear_free(క్రమం);
	BN_clear_free(tmp);
	తిరిగి ret;
}

శూన్య
sshkey_dump_ec_బిందువు(స్థిరరాశి EC_సమూహం *సమూహం, స్థిరరాశి EC_బిందువు *బిందువు)
{
	BIGNUM *x = ఖాళీ, *y = ఖాళీ;

	ఒకవేళ (బిందువు == ఖాళీ) {
		fputs("point=(NULL)\n", stderr);
		తిరిగి;
	}
	ఒకవేళ ((x = BN_new()) == ఖాళీ || (y = BN_new()) == ఖాళీ) {
		fprintf(stderr, "%s: BN_new failed\n", __func__);
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (EC_బిందువు_get_affine_coordinates(సమూహం, బిందువు, x, y, ఖాళీ) != 1) {
		fprintf(stderr, "%s: EC_POINT_get_affine_coordinates\n",
		    __func__);
		వెళ్ళు బహిర్గతం;
	}
	fputs("x=", stderr);
	BN_print_fp(stderr, x);
	fputs("\ny=", stderr);
	BN_print_fp(stderr, y);
	fputs("\n", stderr);
 బహిర్గతం:
	BN_clear_free(x);
	BN_clear_free(y);
}

శూన్య
sshkey_dump_ec_కీలకం(స్థిరరాశి EC_కీలకం *కీలకం)
{
	స్థిరరాశి BIGNUM *exponent;

	sshkey_dump_ec_బిందువు(EC_కీలకం_get0_సమూహం(కీలకం),
	    EC_కీలకం_get0_ప్రజా_కీలకం(కీలకం));
	fputs("exponent=", stderr);
	ఒకవేళ ((exponent = EC_కీలకం_get0_వ్యక్తిగత_కీలకం(కీలకం)) == ఖాళీ)
		fputs("(NULL)", stderr);
	లేకపోతే
		BN_print_fp(stderr, EC_కీలకం_get0_వ్యక్తిగత_కీలకం(కీలకం));
	fputs("\n", stderr);
}
#అయితే_ముగింపు /* WITH_OPENSSL */

స్థిర పూర్ణాంకం
sshkey_వ్యక్తిగత_గమ్యం_blob2(నిర్మాణం sshkey *prv, నిర్మాణం sshbuf *blob,
    స్థిరరాశి అక్షరం *passphrase, స్థిరరాశి అక్షరం *comment, స్థిరరాశి అక్షరం *ciphername,
    పూర్ణాంకం విడతలు)
{
	u_char *cp, *కీలకం = ఖాళీ, *pubkeyblob = ఖాళీ;
	u_char salt[SALT_LEN];
	కొలత_t i, pubkeylen, keylen, ivlen, blocksize, authlen;
	u_int check;
	పూర్ణాంకం r = SSH_ERR_అంతర్గత_ERROR;
	నిర్మాణం sshcipher_ctx *ciphercontext = ఖాళీ;
	స్థిరరాశి నిర్మాణం sshcipher *cipher;
	స్థిరరాశి అక్షరం *kdfname = KDFNAME;
	నిర్మాణం sshbuf *encoded = ఖాళీ, *encrypted = ఖాళీ, *kdf = ఖాళీ;

	ఒకవేళ (విడతలు <= 0)
		విడతలు = DEFAULT_విడతలు;
	ఒకవేళ (విడతలు > MAX_KDF_విడతలు) {
		r = SSH_ERR_INVALID_వాదం;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (passphrase == ఖాళీ || !అక్షరశ్రేణి_పొడవు(passphrase)) {
		ciphername = "none";
		kdfname = "none";
	} లేకపోతే ఒకవేళ (ciphername == ఖాళీ)
		ciphername = DEFAULT_CIPHERNAME;
	ఒకవేళ ((cipher = cipher_by_name(ciphername)) == ఖాళీ) {
		r = SSH_ERR_INVALID_వాదం;
		వెళ్ళు బహిర్గతం;
	}

	ఒకవేళ ((kdf = sshbuf_new()) == ఖాళీ ||
	    (encoded = sshbuf_new()) == ఖాళీ ||
	    (encrypted = sshbuf_new()) == ఖాళీ) {
		r = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు బహిర్గతం;
	}
	blocksize = cipher_blocksize(cipher);
	keylen = cipher_keylen(cipher);
	ivlen = cipher_ivlen(cipher);
	authlen = cipher_authlen(cipher);
	ఒకవేళ ((కీలకం = సున్నా_జ్ఞాపకం_ఇవ్వు(1, keylen + ivlen)) == ఖాళీ) {
		r = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (strcmp(kdfname, "bcrypt") == 0) {
		arc4random_buf(salt, SALT_LEN);
		ఒకవేళ (bcrypt_pbkdf(passphrase, అక్షరశ్రేణి_పొడవు(passphrase),
		    salt, SALT_LEN, కీలకం, keylen + ivlen, విడతలు) < 0) {
			r = SSH_ERR_INVALID_వాదం;
			వెళ్ళు బహిర్గతం;
		}
		ఒకవేళ ((r = sshbuf_put_string(kdf, salt, SALT_LEN)) != 0 ||
		    (r = sshbuf_put_u32(kdf, విడతలు)) != 0)
			వెళ్ళు బహిర్గతం;
	} లేకపోతే ఒకవేళ (strcmp(kdfname, "none") != 0) {
		/* Unsupported KDF type */
		r = SSH_ERR_కీలకం_UNKNOWN_CIPHER;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((r = cipher_init(&ciphercontext, cipher, కీలకం, keylen,
	    కీలకం + keylen, ivlen, 1)) != 0)
		వెళ్ళు బహిర్గతం;

	ఒకవేళ ((r = sshbuf_put(encoded, AUTH_MAGIC, పరిమాణం(AUTH_MAGIC))) != 0 ||
	    (r = sshbuf_put_cstring(encoded, ciphername)) != 0 ||
	    (r = sshbuf_put_cstring(encoded, kdfname)) != 0 ||
	    (r = sshbuf_put_stringb(encoded, kdf)) != 0 ||
	    (r = sshbuf_put_u32(encoded, 1)) != 0 ||	/* number of keys */
	    (r = sshkey_గమ్యం_blob(prv, &pubkeyblob, &pubkeylen)) != 0 ||
	    (r = sshbuf_put_string(encoded, pubkeyblob, pubkeylen)) != 0)
		వెళ్ళు బహిర్గతం;

	/* set up the buffer that will be encrypted */

	/* Random check bytes */
	check = arc4random();
	ఒకవేళ ((r = sshbuf_put_u32(encrypted, check)) != 0 ||
	    (r = sshbuf_put_u32(encrypted, check)) != 0)
		వెళ్ళు బహిర్గతం;

	/* append private key and comment*/
	ఒకవేళ ((r = sshkey_వ్యక్తిగత_serialize(prv, encrypted)) != 0 ||
	    (r = sshbuf_put_cstring(encrypted, comment)) != 0)
		వెళ్ళు బహిర్గతం;

	/* padding */
	i = 0;
	అయితే (sshbuf_len(encrypted) % blocksize) {
		ఒకవేళ ((r = sshbuf_put_u8(encrypted, ++i & 0xff)) != 0)
			వెళ్ళు బహిర్గతం;
	}

	/* length in destination buffer */
	ఒకవేళ ((r = sshbuf_put_u32(encoded, sshbuf_len(encrypted))) != 0)
		వెళ్ళు బహిర్గతం;

	/* encrypt */
	ఒకవేళ ((r = sshbuf_reserve(encoded,
	    sshbuf_len(encrypted) + authlen, &cp)) != 0)
		వెళ్ళు బహిర్గతం;
	ఒకవేళ ((r = cipher_crypt(ciphercontext, 0, cp,
	    sshbuf_ptr(encrypted), sshbuf_len(encrypted), 0, authlen)) != 0)
		వెళ్ళు బహిర్గతం;

	sshbuf_reset(blob);

	/* assemble uuencoded key */
	ఒకవేళ ((r = sshbuf_put(blob, MARK_BEGIN, MARK_BEGIN_LEN)) != 0 ||
	    (r = sshbuf_dtob64(encoded, blob, 1)) != 0 ||
	    (r = sshbuf_put(blob, MARK_చివర, MARK_చివర_LEN)) != 0)
		వెళ్ళు బహిర్గతం;

	/* success */
	r = 0;

 బహిర్గతం:
	sshbuf_free(kdf);
	sshbuf_free(encoded);
	sshbuf_free(encrypted);
	cipher_free(ciphercontext);
	explicit_bzero(salt, పరిమాణం(salt));
	ఒకవేళ (కీలకం != ఖాళీ)
		freezero(కీలకం, keylen + ivlen);
	ఒకవేళ (pubkeyblob != ఖాళీ)
		freezero(pubkeyblob, pubkeylen);
	తిరిగి r;
}

స్థిర పూర్ణాంకం
private2_uudecode(నిర్మాణం sshbuf *blob, నిర్మాణం sshbuf **decodedp)
{
	స్థిరరాశి u_char *cp;
	కొలత_t encoded_len;
	పూర్ణాంకం r;
	u_char చివరి;
	నిర్మాణం sshbuf *encoded = ఖాళీ, *decoded = ఖాళీ;

	ఒకవేళ (blob == ఖాళీ || decodedp == ఖాళీ)
		తిరిగి SSH_ERR_INVALID_వాదం;

	*decodedp = ఖాళీ;

	ఒకవేళ ((encoded = sshbuf_new()) == ఖాళీ ||
	    (decoded = sshbuf_new()) == ఖాళీ) {
		r = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు బహిర్గతం;
	}

	/* check preamble */
	cp = sshbuf_ptr(blob);
	encoded_len = sshbuf_len(blob);
	ఒకవేళ (encoded_len < (MARK_BEGIN_LEN + MARK_చివర_LEN) ||
	    memcmp(cp, MARK_BEGIN, MARK_BEGIN_LEN) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		వెళ్ళు బహిర్గతం;
	}
	cp += MARK_BEGIN_LEN;
	encoded_len -= MARK_BEGIN_LEN;

	/* Look for end marker, removing whitespace as we go */
	అయితే (encoded_len > 0) {
		ఒకవేళ (*cp != '\n' && *cp != '\r') {
			ఒకవేళ ((r = sshbuf_put_u8(encoded, *cp)) != 0)
				వెళ్ళు బహిర్గతం;
		}
		చివరి = *cp;
		encoded_len--;
		cp++;
		ఒకవేళ (చివరి == '\n') {
			ఒకవేళ (encoded_len >= MARK_చివర_LEN &&
			    memcmp(cp, MARK_చివర, MARK_చివర_LEN) == 0) {
				/* \0 terminate */
				ఒకవేళ ((r = sshbuf_put_u8(encoded, 0)) != 0)
					వెళ్ళు బహిర్గతం;
				ఆపు;
			}
		}
	}
	ఒకవేళ (encoded_len == 0) {
		r = SSH_ERR_INVALID_FORMAT;
		వెళ్ళు బహిర్గతం;
	}

	/* decode base64 */
	ఒకవేళ ((r = sshbuf_b64tod(decoded, (అక్షరం *)sshbuf_ptr(encoded))) != 0)
		వెళ్ళు బహిర్గతం;

	/* check magic */
	ఒకవేళ (sshbuf_len(decoded) < పరిమాణం(AUTH_MAGIC) ||
	    memcmp(sshbuf_ptr(decoded), AUTH_MAGIC, పరిమాణం(AUTH_MAGIC))) {
		r = SSH_ERR_INVALID_FORMAT;
		వెళ్ళు బహిర్గతం;
	}
	/* success */
	*decodedp = decoded;
	decoded = ఖాళీ;
	r = 0;
 బహిర్గతం:
	sshbuf_free(encoded);
	sshbuf_free(decoded);
	తిరిగి r;
}

స్థిర పూర్ణాంకం
private2_decrypt(నిర్మాణం sshbuf *decoded, స్థిరరాశి అక్షరం *passphrase,
    నిర్మాణం sshbuf **decryptedp, నిర్మాణం sshkey **pubkeyp)
{
	అక్షరం *ciphername = ఖాళీ, *kdfname = ఖాళీ;
	స్థిరరాశి నిర్మాణం sshcipher *cipher = ఖాళీ;
	పూర్ణాంకం r = SSH_ERR_అంతర్గత_ERROR;
	కొలత_t keylen = 0, ivlen = 0, authlen = 0, slen = 0;
	నిర్మాణం sshbuf *kdf = ఖాళీ, *decrypted = ఖాళీ;
	నిర్మాణం sshcipher_ctx *ciphercontext = ఖాళీ;
	నిర్మాణం sshkey *pubkey = ఖాళీ;
	u_char *కీలకం = ఖాళీ, *salt = ఖాళీ, *dp;
	u_int blocksize, విడతలు, nkeys, encrypted_len, check1, check2;

	ఒకవేళ (decoded == ఖాళీ || decryptedp == ఖాళీ || pubkeyp == ఖాళీ)
		తిరిగి SSH_ERR_INVALID_వాదం;

	*decryptedp = ఖాళీ;
	*pubkeyp = ఖాళీ;

	ఒకవేళ ((decrypted = sshbuf_new()) == ఖాళీ) {
		r = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు బహిర్గతం;
	}

	/* parse public portion of key */
	ఒకవేళ ((r = sshbuf_consume(decoded, పరిమాణం(AUTH_MAGIC))) != 0 ||
	    (r = sshbuf_get_cstring(decoded, &ciphername, ఖాళీ)) != 0 ||
	    (r = sshbuf_get_cstring(decoded, &kdfname, ఖాళీ)) != 0 ||
	    (r = sshbuf_froms(decoded, &kdf)) != 0 ||
	    (r = sshbuf_get_u32(decoded, &nkeys)) != 0)
		వెళ్ళు బహిర్గతం;

	ఒకవేళ (nkeys != 1) {
		/* XXX only one key supported at present */
		r = SSH_ERR_INVALID_FORMAT;
		వెళ్ళు బహిర్గతం;
	}

	ఒకవేళ ((r = sshkey_froms(decoded, &pubkey)) != 0 ||
	    (r = sshbuf_get_u32(decoded, &encrypted_len)) != 0)
		వెళ్ళు బహిర్గతం;

	ఒకవేళ ((cipher = cipher_by_name(ciphername)) == ఖాళీ) {
		r = SSH_ERR_కీలకం_UNKNOWN_CIPHER;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (strcmp(kdfname, "none") != 0 && strcmp(kdfname, "bcrypt") != 0) {
		r = SSH_ERR_కీలకం_UNKNOWN_CIPHER;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (strcmp(kdfname, "none") == 0 && strcmp(ciphername, "none") != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((passphrase == ఖాళీ || అక్షరశ్రేణి_పొడవు(passphrase) == 0) &&
	    strcmp(kdfname, "none") != 0) {
		/* passphrase required */
		r = SSH_ERR_కీలకం_WRONG_PASSPHRASE;
		వెళ్ళు బహిర్గతం;
	}

	/* check size of encrypted key blob */
	blocksize = cipher_blocksize(cipher);
	ఒకవేళ (encrypted_len < blocksize || (encrypted_len % blocksize) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		వెళ్ళు బహిర్గతం;
	}

	/* setup key */
	keylen = cipher_keylen(cipher);
	ivlen = cipher_ivlen(cipher);
	authlen = cipher_authlen(cipher);
	ఒకవేళ ((కీలకం = సున్నా_జ్ఞాపకం_ఇవ్వు(1, keylen + ivlen)) == ఖాళీ) {
		r = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (strcmp(kdfname, "bcrypt") == 0) {
		ఒకవేళ ((r = sshbuf_get_string(kdf, &salt, &slen)) != 0 ||
		    (r = sshbuf_get_u32(kdf, &విడతలు)) != 0)
			వెళ్ళు బహిర్గతం;
		ఒకవేళ (విడతలు > MAX_KDF_విడతలు) {
			r = SSH_ERR_INVALID_FORMAT;
			వెళ్ళు బహిర్గతం;
		}
		ఒకవేళ (bcrypt_pbkdf(passphrase, అక్షరశ్రేణి_పొడవు(passphrase), salt, slen,
		    కీలకం, keylen + ivlen, విడతలు) < 0) {
			r = SSH_ERR_INVALID_FORMAT;
			వెళ్ళు బహిర్గతం;
		}
	}

	/* check that an appropriate amount of auth data is present */
	ఒకవేళ (sshbuf_len(decoded) < authlen ||
	    sshbuf_len(decoded) - authlen < encrypted_len) {
		r = SSH_ERR_INVALID_FORMAT;
		వెళ్ళు బహిర్గతం;
	}

	/* decrypt private portion of key */
	ఒకవేళ ((r = sshbuf_reserve(decrypted, encrypted_len, &dp)) != 0 ||
	    (r = cipher_init(&ciphercontext, cipher, కీలకం, keylen,
	    కీలకం + keylen, ivlen, 0)) != 0)
		వెళ్ళు బహిర్గతం;
	ఒకవేళ ((r = cipher_crypt(ciphercontext, 0, dp, sshbuf_ptr(decoded),
	    encrypted_len, 0, authlen)) != 0) {
		/* an integrity error here indicates an incorrect passphrase */
		ఒకవేళ (r == SSH_ERR_MAC_INVALID)
			r = SSH_ERR_కీలకం_WRONG_PASSPHRASE;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((r = sshbuf_consume(decoded, encrypted_len + authlen)) != 0)
		వెళ్ళు బహిర్గతం;
	/* there should be no trailing data */
	ఒకవేళ (sshbuf_len(decoded) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		వెళ్ళు బహిర్గతం;
	}

	/* check check bytes */
	ఒకవేళ ((r = sshbuf_get_u32(decrypted, &check1)) != 0 ||
	    (r = sshbuf_get_u32(decrypted, &check2)) != 0)
		వెళ్ళు బహిర్గతం;
	ఒకవేళ (check1 != check2) {
		r = SSH_ERR_కీలకం_WRONG_PASSPHRASE;
		వెళ్ళు బహిర్గతం;
	}
	/* success */
	*decryptedp = decrypted;
	decrypted = ఖాళీ;
	*pubkeyp = pubkey;
	pubkey = ఖాళీ;
	r = 0;
 బహిర్గతం:
	cipher_free(ciphercontext);
	విడుదల(ciphername);
	విడుదల(kdfname);
	sshkey_free(pubkey);
	ఒకవేళ (salt != ఖాళీ) {
		explicit_bzero(salt, slen);
		విడుదల(salt);
	}
	ఒకవేళ (కీలకం != ఖాళీ) {
		explicit_bzero(కీలకం, keylen + ivlen);
		విడుదల(కీలకం);
	}
	sshbuf_free(kdf);
	sshbuf_free(decrypted);
	తిరిగి r;
}

స్థిర పూర్ణాంకం
sshkey_parse_private2(నిర్మాణం sshbuf *blob, పూర్ణాంకం type, స్థిరరాశి అక్షరం *passphrase,
    నిర్మాణం sshkey **keyp, అక్షరం **commentp)
{
	అక్షరం *comment = ఖాళీ;
	పూర్ణాంకం r = SSH_ERR_అంతర్గత_ERROR;
	నిర్మాణం sshbuf *decoded = ఖాళీ, *decrypted = ఖాళీ;
	నిర్మాణం sshkey *k = ఖాళీ, *pubkey = ఖాళీ;

	ఒకవేళ (keyp != ఖాళీ)
		*keyp = ఖాళీ;
	ఒకవేళ (commentp != ఖాళీ)
		*commentp = ఖాళీ;

	/* Undo base64 encoding and decrypt the private section */
	ఒకవేళ ((r = private2_uudecode(blob, &decoded)) != 0 ||
	    (r = private2_decrypt(decoded, passphrase,
	    &decrypted, &pubkey)) != 0)
		వెళ్ళు బహిర్గతం;

	ఒకవేళ (type != కీలకం_UNSPEC &&
	    sshkey_type_plain(type) != sshkey_type_plain(pubkey->type)) {
		r = SSH_ERR_కీలకం_TYPE_MISMATCH;
		వెళ్ళు బహిర్గతం;
	}

	/* Load the private key and comment */
	ఒకవేళ ((r = sshkey_వ్యక్తిగత_deserialize(decrypted, &k)) != 0 ||
	    (r = sshbuf_get_cstring(decrypted, &comment, ఖాళీ)) != 0)
		వెళ్ళు బహిర్గతం;

	/* Check deterministic padding after private section */
	ఒకవేళ ((r = private2_check_padding(decrypted)) != 0)
		వెళ్ళు బహిర్గతం;

	/* Check that the public key in the envelope matches the private key */
	ఒకవేళ (!sshkey_equal(pubkey, k)) {
		r = SSH_ERR_INVALID_FORMAT;
		వెళ్ళు బహిర్గతం;
	}

	/* success */
	r = 0;
	ఒకవేళ (keyp != ఖాళీ) {
		*keyp = k;
		k = ఖాళీ;
	}
	ఒకవేళ (commentp != ఖాళీ) {
		*commentp = comment;
		comment = ఖాళీ;
	}
 బహిర్గతం:
	విడుదల(comment);
	sshbuf_free(decoded);
	sshbuf_free(decrypted);
	sshkey_free(k);
	sshkey_free(pubkey);
	తిరిగి r;
}

స్థిర పూర్ణాంకం
sshkey_parse_private2_pubkey(నిర్మాణం sshbuf *blob, పూర్ణాంకం type,
    నిర్మాణం sshkey **keyp)
{
	పూర్ణాంకం r = SSH_ERR_అంతర్గత_ERROR;
	నిర్మాణం sshbuf *decoded = ఖాళీ;
	నిర్మాణం sshkey *pubkey = ఖాళీ;
	u_int nkeys = 0;

	ఒకవేళ (keyp != ఖాళీ)
		*keyp = ఖాళీ;

	ఒకవేళ ((r = private2_uudecode(blob, &decoded)) != 0)
		వెళ్ళు బహిర్గతం;
	/* parse public key from unencrypted envelope */
	ఒకవేళ ((r = sshbuf_consume(decoded, పరిమాణం(AUTH_MAGIC))) != 0 ||
	    (r = sshbuf_skip_string(decoded)) != 0 || /* cipher */
	    (r = sshbuf_skip_string(decoded)) != 0 || /* KDF alg */
	    (r = sshbuf_skip_string(decoded)) != 0 || /* KDF hint */
	    (r = sshbuf_get_u32(decoded, &nkeys)) != 0)
		వెళ్ళు బహిర్గతం;

	ఒకవేళ (nkeys != 1) {
		/* XXX only one key supported at present */
		r = SSH_ERR_INVALID_FORMAT;
		వెళ్ళు బహిర్గతం;
	}

	/* Parse the public key */
	ఒకవేళ ((r = sshkey_froms(decoded, &pubkey)) != 0)
		వెళ్ళు బహిర్గతం;

	ఒకవేళ (type != కీలకం_UNSPEC &&
	    sshkey_type_plain(type) != sshkey_type_plain(pubkey->type)) {
		r = SSH_ERR_కీలకం_TYPE_MISMATCH;
		వెళ్ళు బహిర్గతం;
	}

	/* success */
	r = 0;
	ఒకవేళ (keyp != ఖాళీ) {
		*keyp = pubkey;
		pubkey = ఖాళీ;
	}
 బహిర్గతం:
	sshbuf_free(decoded);
	sshkey_free(pubkey);
	తిరిగి r;
}

#నిర్వచితమైతే WITH_OPENSSL
/* convert SSH v2 key to PEM or PKCS#8 format */
స్థిర పూర్ణాంకం
sshkey_వ్యక్తిగత_గమ్యం_blob_pem_pkcs8(నిర్మాణం sshkey *కీలకం, నిర్మాణం sshbuf *buf,
    పూర్ణాంకం format, స్థిరరాశి అక్షరం *_passphrase, స్థిరరాశి అక్షరం *comment)
{
	పూర్ణాంకం was_shielded = sshkey_is_shielded(కీలకం);
	పూర్ణాంకం success, r;
	పూర్ణాంకం blen, len = అక్షరశ్రేణి_పొడవు(_passphrase);
	u_char *passphrase = (len > 0) ? (u_char *)_passphrase : ఖాళీ;
	స్థిరరాశి EVP_CIPHER *cipher = (len > 0) ? EVP_aes_128_cbc() : ఖాళీ;
	అక్షరం *bptr;
	BIO *bio = ఖాళీ;
	నిర్మాణం sshbuf *blob;
	EVP_PKEY *pkey = ఖాళీ;

	ఒకవేళ (len > 0 && len <= 4)
		తిరిగి SSH_ERR_PASSPHRASE_TOO_SHORT;
	ఒకవేళ ((blob = sshbuf_new()) == ఖాళీ)
		తిరిగి SSH_ERR_ALLOC_FAIL;
	ఒకవేళ ((bio = BIO_new(BIO_s_mem())) == ఖాళీ) {
		r = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((r = sshkey_unshield_వ్యక్తిగత(కీలకం)) != 0)
		వెళ్ళు బహిర్గతం;

	ఎంపిక (కీలకం->type) {
	స్థితి కీలకం_ECDSA:
		ఒకవేళ (format == SSHKEY_వ్యక్తిగత_PEM) {
			success = PEM_write_bio_ECPrivate_కీలకం(bio,
			    EVP_PKEY_get0_EC_కీలకం(కీలకం->pkey),
			    cipher, passphrase, len, ఖాళీ, ఖాళీ);
		} లేకపోతే {
			pkey = కీలకం->pkey;
			EVP_PKEY_పైకి_ref(కీలకం->pkey);
			success = 1;
		}
		ఆపు;
	స్థితి కీలకం_RSA:
		ఒకవేళ (format == SSHKEY_వ్యక్తిగత_PEM) {
			success = PEM_write_bio_RSAPrivate_కీలకం(bio,
			    EVP_PKEY_get0_RSA(కీలకం->pkey),
			    cipher, passphrase, len, ఖాళీ, ఖాళీ);
		} లేకపోతే {
			pkey = కీలకం->pkey;
			EVP_PKEY_పైకి_ref(కీలకం->pkey);
			success = 1;
		}
		ఆపు;
#నిర్వచితమైతే OPENSSL_HAS_ED25519
	స్థితి కీలకం_ED25519:
		ఒకవేళ (format == SSHKEY_వ్యక్తిగత_PEM) {
			r = SSH_ERR_INVALID_FORMAT;
			వెళ్ళు బహిర్గతం;
		} లేకపోతే {
			pkey = EVP_PKEY_new_raw_వ్యక్తిగత_కీలకం(EVP_PKEY_ED25519,
			    ఖాళీ, కీలకం->ed25519_sk,
			    ED25519_SK_SZ - ED25519_PK_SZ);
			success = pkey != ఖాళీ;
		}
		ఆపు;
#అయితే_ముగింపు
	అప్రమేయ:
		success = 0;
		ఆపు;
	}
	ఒకవేళ (success == 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (format == SSHKEY_వ్యక్తిగత_PKCS8) {
		ఒకవేళ ((success = PEM_write_bio_వ్యక్తిగత_కీలకం(bio, pkey, cipher,
		    passphrase, len, ఖాళీ, ఖాళీ)) == 0) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			వెళ్ళు బహిర్గతం;
		}
	}
	ఒకవేళ ((blen = BIO_get_mem_దత్తాంశం(bio, &bptr)) <= 0) {
		r = SSH_ERR_అంతర్గత_ERROR;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((r = sshbuf_put(blob, bptr, blen)) != 0)
		వెళ్ళు బహిర్గతం;
	r = 0;
 బహిర్గతం:
	ఒకవేళ (was_shielded)
		r = sshkey_shield_వ్యక్తిగత(కీలకం);
	ఒకవేళ (r == 0)
		r = sshbuf_putb(buf, blob);

	EVP_PKEY_free(pkey);
	sshbuf_free(blob);
	BIO_free(bio);
	తిరిగి r;
}
#అయితే_ముగింపు /* WITH_OPENSSL */

/* Serialise "key" to buffer "blob" */
పూర్ణాంకం
sshkey_వ్యక్తిగత_గమ్యం_fileblob(నిర్మాణం sshkey *కీలకం, నిర్మాణం sshbuf *blob,
    స్థిరరాశి అక్షరం *passphrase, స్థిరరాశి అక్షరం *comment,
    పూర్ణాంకం format, స్థిరరాశి అక్షరం *openssh_format_cipher, పూర్ణాంకం openssh_format_విడతలు)
{
	ఎంపిక (కీలకం->type) {
#నిర్వచితమైతే WITH_OPENSSL
	స్థితి కీలకం_ECDSA:
	స్థితి కీలకం_RSA:
	స్థితి కీలకం_ED25519:
		ఆపు; /* see below */
#లేకపోతే /* WITH_OPENSSL */
	స్థితి కీలకం_ED25519:
#అయితే_ముగింపు /* WITH_OPENSSL */
	స్థితి కీలకం_ED25519_SK:
#నిర్వచితమైతే WITH_OPENSSL
	స్థితి కీలకం_ECDSA_SK:
#అయితే_ముగింపు /* WITH_OPENSSL */
	స్థితి కీలకం_MLDSA44_ED25519:
		తిరిగి sshkey_వ్యక్తిగత_గమ్యం_blob2(కీలకం, blob, passphrase,
		    comment, openssh_format_cipher, openssh_format_విడతలు);
	అప్రమేయ:
		తిరిగి SSH_ERR_కీలకం_TYPE_UNKNOWN;
	}

#నిర్వచితమైతే WITH_OPENSSL
	ఎంపిక (format) {
	స్థితి SSHKEY_వ్యక్తిగత_OPENSSH:
		తిరిగి sshkey_వ్యక్తిగత_గమ్యం_blob2(కీలకం, blob, passphrase,
		    comment, openssh_format_cipher, openssh_format_విడతలు);
	స్థితి SSHKEY_వ్యక్తిగత_PEM:
	స్థితి SSHKEY_వ్యక్తిగత_PKCS8:
		తిరిగి sshkey_వ్యక్తిగత_గమ్యం_blob_pem_pkcs8(కీలకం, blob,
		    format, passphrase, comment);
	అప్రమేయ:
		తిరిగి SSH_ERR_INVALID_వాదం;
	}
#అయితే_ముగింపు /* WITH_OPENSSL */
}

#నిర్వచితమైతే WITH_OPENSSL
స్థిర పూర్ణాంకం
translate_libcrypto_error(గుర్తులేని దీర్ఘ pem_err)
{
	పూర్ణాంకం pem_reason = ERR_GET_REASON(pem_err);

	ఎంపిక (ERR_GET_LIB(pem_err)) {
	స్థితి ERR_LIB_PEM:
		ఎంపిక (pem_reason) {
		స్థితి PEM_R_BAD_PASSWORD_READ:
#నిర్వచితమైతే PEM_R_PROBLEMS_GETTING_PASSWORD
		స్థితి PEM_R_PROBLEMS_GETTING_PASSWORD:
#అయితే_ముగింపు
#నిర్వచితమైతే PEM_R_BAD_DECRYPT
		స్థితి PEM_R_BAD_DECRYPT:
#అయితే_ముగింపు
			తిరిగి SSH_ERR_కీలకం_WRONG_PASSPHRASE;
		అప్రమేయ:
			తిరిగి SSH_ERR_INVALID_FORMAT;
		}
	స్థితి ERR_LIB_EVP:
		ఎంపిక (pem_reason) {
#నిర్వచితమైతే EVP_R_BAD_DECRYPT
		స్థితి EVP_R_BAD_DECRYPT:
			తిరిగి SSH_ERR_కీలకం_WRONG_PASSPHRASE;
#అయితే_ముగింపు
#నిర్వచితమైతే EVP_R_BN_DECODE_ERROR
		స్థితి EVP_R_BN_DECODE_ERROR:
#అయితే_ముగింపు
		స్థితి EVP_R_DECODE_ERROR:
#నిర్వచితమైతే EVP_R_వ్యక్తిగత_కీలకం_DECODE_ERROR
		స్థితి EVP_R_వ్యక్తిగత_కీలకం_DECODE_ERROR:
#అయితే_ముగింపు
			తిరిగి SSH_ERR_INVALID_FORMAT;
		అప్రమేయ:
			తిరిగి SSH_ERR_LIBCRYPTO_ERROR;
		}
	స్థితి ERR_LIB_ASN1:
#నిర్వచితమైతే ERR_LIB_OSSL_DECODER
	స్థితి ERR_LIB_OSSL_DECODER:
#అయితే_ముగింపు
		తిరిగి SSH_ERR_INVALID_FORMAT;
	}
	తిరిగి SSH_ERR_LIBCRYPTO_ERROR;
}

స్థిర శూన్య
clear_libcrypto_errors(శూన్య)
{
	అయితే (ERR_get_error() != 0)
		;
}

/*
 * Translate OpenSSL error codes to determine whether
 * passphrase is required/incorrect.
 */
స్థిర పూర్ణాంకం
convert_libcrypto_error(శూన్య)
{
	/*
	 * Some password errors are reported at the beginning
	 * of the error queue.
	 */
	ఒకవేళ (translate_libcrypto_error(ERR_peek_error()) ==
	    SSH_ERR_కీలకం_WRONG_PASSPHRASE)
		తిరిగి SSH_ERR_కీలకం_WRONG_PASSPHRASE;
	తిరిగి translate_libcrypto_error(ERR_peek_చివరి_error());
}

స్థిర పూర్ణాంకం
pem_passphrase_cb(అక్షరం *buf, పూర్ణాంకం కొలత, పూర్ణాంకం rwflag, శూన్య *u)
{
	అక్షరం *p = (అక్షరం *)u;
	కొలత_t len;

	ఒకవేళ (p == ఖాళీ || (len = అక్షరశ్రేణి_పొడవు(p)) == 0)
		తిరిగి -1;
	ఒకవేళ (కొలత < 0 || len > (కొలత_t)కొలత)
		తిరిగి -1;
	జ్ఞాపకం_నకలు(buf, p, len);
	తిరిగి (పూర్ణాంకం)len;
}

స్థిర పూర్ణాంకం
sshkey_parse_వ్యక్తిగత_pem_fileblob(నిర్మాణం sshbuf *blob, పూర్ణాంకం type,
    స్థిరరాశి అక్షరం *passphrase, నిర్మాణం sshkey **keyp)
{
	EVP_PKEY *pk = ఖాళీ;
	నిర్మాణం sshkey *prv = ఖాళీ;
	BIO *bio = ఖాళీ;
	పూర్ణాంకం r;
	RSA *rsa = ఖాళీ;
	EC_కీలకం *ecdsa = ఖాళీ;

	ఒకవేళ (keyp != ఖాళీ)
		*keyp = ఖాళీ;

	ఒకవేళ ((bio = BIO_new(BIO_s_mem())) == ఖాళీ || sshbuf_len(blob) > గరిష్ఠ_పూర్ణాంకం)
		తిరిగి SSH_ERR_ALLOC_FAIL;
	ఒకవేళ (BIO_write(bio, sshbuf_ptr(blob), sshbuf_len(blob)) !=
	    (పూర్ణాంకం)sshbuf_len(blob)) {
		r = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు బహిర్గతం;
	}

	clear_libcrypto_errors();
	ఒకవేళ ((pk = PEM_read_bio_వ్యక్తిగత_కీలకం(bio, ఖాళీ, pem_passphrase_cb,
	    (అక్షరం *)passphrase)) == ఖాళీ) {
		/*
		 * libcrypto may return various ASN.1 errors when attempting
		 * to parse a key with an incorrect passphrase.
		 * Treat all format errors as "incorrect passphrase" if a
		 * passphrase was supplied.
		 */
		ఒకవేళ (passphrase != ఖాళీ && *passphrase != '\0')
			r = SSH_ERR_కీలకం_WRONG_PASSPHRASE;
		లేకపోతే
			r = convert_libcrypto_error();
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (EVP_PKEY_పునాది_id(pk) == EVP_PKEY_RSA &&
	    (type == కీలకం_UNSPEC || type == కీలకం_RSA)) {
		ఒకవేళ ((prv = sshkey_new(కీలకం_UNSPEC)) == ఖాళీ) {
			r = SSH_ERR_ALLOC_FAIL;
			వెళ్ళు బహిర్గతం;
		}
		ఒకవేళ ((rsa = EVP_PKEY_get1_RSA(pk)) == ఖాళీ) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			వెళ్ళు బహిర్గతం;
		}
		prv->type = కీలకం_RSA;
#నిర్వచితమైతే DEBUG_PK
		RSA_print_fp(stderr, rsa, 8);
#అయితే_ముగింపు
		ఒకవేళ (RSA_blinding_on(rsa, ఖాళీ) != 1 ||
		    EVP_PKEY_set1_RSA(pk, rsa) != 1) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			వెళ్ళు బహిర్గతం;
		}
		EVP_PKEY_పైకి_ref(pk);
		prv->pkey = pk;
		ఒకవేళ ((r = sshkey_check_rsa_నిడివి(prv, 0)) != 0)
			వెళ్ళు బహిర్గతం;
	} లేకపోతే ఒకవేళ (EVP_PKEY_పునాది_id(pk) == EVP_PKEY_EC &&
	    (type == కీలకం_UNSPEC || type == కీలకం_ECDSA)) {
		ఒకవేళ ((prv = sshkey_new(కీలకం_UNSPEC)) == ఖాళీ) {
			r = SSH_ERR_ALLOC_FAIL;
			వెళ్ళు బహిర్గతం;
		}
		ఒకవేళ ((prv->ecdsa_nid = sshkey_ecdsa_fixup_సమూహం(pk)) == -1 ||
		    (ecdsa = EVP_PKEY_get1_EC_కీలకం(pk)) == ఖాళీ) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			వెళ్ళు బహిర్గతం;
		}
		prv->type = కీలకం_ECDSA;
		ఒకవేళ (sshkey_వక్రం_nid_గమ్యం_name(prv->ecdsa_nid) == ఖాళీ ||
		    sshkey_ec_validate_ప్రజా(EC_కీలకం_get0_సమూహం(ecdsa),
		    EC_కీలకం_get0_ప్రజా_కీలకం(ecdsa)) != 0 ||
		    sshkey_ec_validate_వ్యక్తిగత(ecdsa) != 0) {
			r = SSH_ERR_INVALID_FORMAT;
			వెళ్ళు బహిర్గతం;
		}
		EVP_PKEY_పైకి_ref(pk);
		prv->pkey = pk;
#నిర్వచితమైతే DEBUG_PK
		ఒకవేళ (prv != ఖాళీ && prv->pkey != ఖాళీ)
			sshkey_dump_ec_కీలకం(EVP_PKEY_get0_EC_కీలకం(prv->pkey));
#అయితే_ముగింపు
#నిర్వచితమైతే OPENSSL_HAS_ED25519
	} లేకపోతే ఒకవేళ (EVP_PKEY_పునాది_id(pk) == EVP_PKEY_ED25519 &&
	    (type == కీలకం_UNSPEC || type == కీలకం_ED25519)) {
		కొలత_t len;

		ఒకవేళ ((prv = sshkey_new(కీలకం_UNSPEC)) == ఖాళీ ||
		    (prv->ed25519_sk = సున్నా_జ్ఞాపకం_ఇవ్వు(1, ED25519_SK_SZ)) == ఖాళీ ||
		    (prv->ed25519_pk = సున్నా_జ్ఞాపకం_ఇవ్వు(1, ED25519_PK_SZ)) == ఖాళీ) {
			r = SSH_ERR_ALLOC_FAIL;
			వెళ్ళు బహిర్గతం;
		}
		prv->type = కీలకం_ED25519;
		len = ED25519_PK_SZ;
		ఒకవేళ (!EVP_PKEY_get_raw_ప్రజా_కీలకం(pk, prv->ed25519_pk, &len)) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			వెళ్ళు బహిర్గతం;
		}
		ఒకవేళ (len != ED25519_PK_SZ) {
			r = SSH_ERR_INVALID_FORMAT;
			వెళ్ళు బహిర్గతం;
		}
		len = ED25519_SK_SZ - ED25519_PK_SZ;
		ఒకవేళ (!EVP_PKEY_get_raw_వ్యక్తిగత_కీలకం(pk, prv->ed25519_sk, &len)) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			వెళ్ళు బహిర్గతం;
		}
		ఒకవేళ (len != ED25519_SK_SZ - ED25519_PK_SZ) {
			r = SSH_ERR_INVALID_FORMAT;
			వెళ్ళు బహిర్గతం;
		}
		/* Append the public key to our private key */
		జ్ఞాపకం_నకలు(prv->ed25519_sk + (ED25519_SK_SZ - ED25519_PK_SZ),
		    prv->ed25519_pk, ED25519_PK_SZ);
#నిర్వచితమైతే DEBUG_PK
		sshbuf_dump_దత్తాంశం(prv->ed25519_sk, ED25519_SK_SZ, stderr);
#అయితే_ముగింపు
#అయితే_ముగింపు /* OPENSSL_HAS_ED25519 */
	} లేకపోతే {
		r = SSH_ERR_INVALID_FORMAT;
		వెళ్ళు బహిర్గతం;
	}
	r = 0;
	ఒకవేళ (keyp != ఖాళీ) {
		*keyp = prv;
		prv = ఖాళీ;
	}
 బహిర్గతం:
	BIO_free(bio);
	EVP_PKEY_free(pk);
	RSA_free(rsa);
	EC_కీలకం_free(ecdsa);
	sshkey_free(prv);
	తిరిగి r;
}
#అయితే_ముగింపు /* WITH_OPENSSL */

పూర్ణాంకం
sshkey_parse_వ్యక్తిగత_fileblob_type(నిర్మాణం sshbuf *blob, పూర్ణాంకం type,
    స్థిరరాశి అక్షరం *passphrase, నిర్మాణం sshkey **keyp, అక్షరం **commentp)
{
	పూర్ణాంకం r = SSH_ERR_అంతర్గత_ERROR;

	ఒకవేళ (keyp != ఖాళీ)
		*keyp = ఖాళీ;
	ఒకవేళ (commentp != ఖాళీ)
		*commentp = ఖాళీ;

	r = sshkey_parse_private2(blob, type, passphrase, keyp, commentp);
	/* Only fallback to PEM parser if a format error occurred. */
	ఒకవేళ (r != SSH_ERR_INVALID_FORMAT)
		తిరిగి r;
#నిర్వచితమైతే WITH_OPENSSL
	తిరిగి sshkey_parse_వ్యక్తిగత_pem_fileblob(blob, type,
	    passphrase, keyp);
#లేకపోతే
	తిరిగి SSH_ERR_INVALID_FORMAT;
#అయితే_ముగింపు /* WITH_OPENSSL */
}

పూర్ణాంకం
sshkey_parse_వ్యక్తిగత_fileblob(నిర్మాణం sshbuf *బఫరు, స్థిరరాశి అక్షరం *passphrase,
    నిర్మాణం sshkey **keyp, అక్షరం **commentp)
{
	ఒకవేళ (keyp != ఖాళీ)
		*keyp = ఖాళీ;
	ఒకవేళ (commentp != ఖాళీ)
		*commentp = ఖాళీ;

	తిరిగి sshkey_parse_వ్యక్తిగత_fileblob_type(బఫరు, కీలకం_UNSPEC,
	    passphrase, keyp, commentp);
}

శూన్య
sshkey_sig_details_free(నిర్మాణం sshkey_sig_details *details)
{
	freezero(details, పరిమాణం(*details));
}

పూర్ణాంకం
sshkey_parse_pubkey_from_వ్యక్తిగత_fileblob_type(నిర్మాణం sshbuf *blob, పూర్ణాంకం type,
    నిర్మాణం sshkey **pubkeyp)
{
	పూర్ణాంకం r = SSH_ERR_అంతర్గత_ERROR;

	ఒకవేళ (pubkeyp != ఖాళీ)
		*pubkeyp = ఖాళీ;
	/* only new-format private keys bundle a public key inside */
	ఒకవేళ ((r = sshkey_parse_private2_pubkey(blob, type, pubkeyp)) != 0)
		తిరిగి r;
	తిరిగి 0;
}
