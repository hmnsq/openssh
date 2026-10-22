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

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <sys/types.h>
#অন্তর্ভাব <sys/mman.h>
#অন্তর্ভাব <netinet/in.h>

#ifdef WITH_OPENSSL
#অন্তর্ভাব <openssl/bn.h>
#অন্তর্ভাব <openssl/evp.h>
#অন্তর্ভাব <openssl/err.h>
#অন্তর্ভাব <openssl/pem.h>
#endif

#অন্তর্ভাব "crypto_api.h"

#অন্তর্ভাব <errno.h>
#অন্তর্ভাব <limits.h>
#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <resolv.h>
#অন্তর্ভাব <time.h>
#অন্তর্ভাব <util.h>

#অন্তর্ভাব "ssh2.h"
#অন্তর্ভাব "ssherr.h"
#অন্তর্ভাব "misc.h"
#অন্তর্ভাব "sshbuf.h"
#অন্তর্ভাব "cipher.h"
#অন্তর্ভাব "digest.h"
#define SSHKEY_INTERNAL
#অন্তর্ভাব "sshkey.h"
#অন্তর্ভাব "match.h"
#অন্তর্ভাব "ssh-sk.h"
#অন্তর্ভাব "ssh-pkcs11.h"

#অন্তর্ভাব "openbsd-compat/openssl-compat.h"

/* openssh private key file format */
#define MARK_BEGIN		"-----BEGIN OPENSSH PRIVATE KEY-----\n"
#define MARK_END		"-----END OPENSSH PRIVATE KEY-----\n"
#define MARK_BEGIN_LEN		(আকার(MARK_BEGIN) - 1)
#define MARK_END_LEN		(আকার(MARK_END) - 1)
#define KDFNAME			"bcrypt"
#define AUTH_MAGIC		"openssh-key-v1"
#define SALT_LEN		16
#define DEFAULT_CIPHERNAME	"aes256-ctr"
#define	DEFAULT_ROUNDS		32
#define	MAX_KDF_ROUNDS		(1<<20)

/*
 * Constants relating to "shielding" support; protection of keys expected
 * to remain in memory for long durations
 */
#define SSHKEY_SHIELD_PREKEY_LEN	(16 * 1024)
#define SSHKEY_SHIELD_CIPHER		"aes256-ctr" /* XXX want AES-EME* */
#define SSHKEY_SHIELD_PREKEY_HASH	SSH_DIGEST_SHA512

স্থির পূর্ণসংখ্যা sshkey_from_blob_internal(কাঠামো sshbuf *buf,
    কাঠামো sshkey **keyp, পূর্ণসংখ্যা allow_cert,
    ধ্রুবক অক্ষর *alg_allowlist, ধ্রুবক অক্ষর *ca_sigalg_allowlist);

/* Supported key types */
বাহ্যিক ধ্রুবক কাঠামো sshkey_impl sshkey_ed25519_impl;
বাহ্যিক ধ্রুবক কাঠামো sshkey_impl sshkey_ed25519_cert_impl;
বাহ্যিক ধ্রুবক কাঠামো sshkey_impl sshkey_ed25519_sk_impl;
বাহ্যিক ধ্রুবক কাঠামো sshkey_impl sshkey_ed25519_sk_cert_impl;
# ifdef USE_MLDSA
বাহ্যিক ধ্রুবক কাঠামো sshkey_impl sshkey_mldsa44_ed25519_impl;
বাহ্যিক ধ্রুবক কাঠামো sshkey_impl sshkey_mldsa44_ed25519_cert_impl;
# endif /* USE_MLDSA */
#ifdef WITH_OPENSSL
# ifdef ENABLE_SK
বাহ্যিক ধ্রুবক কাঠামো sshkey_impl sshkey_ecdsa_sk_impl;
বাহ্যিক ধ্রুবক কাঠামো sshkey_impl sshkey_ecdsa_sk_cert_impl;
বাহ্যিক ধ্রুবক কাঠামো sshkey_impl sshkey_ecdsa_sk_webauthn_impl;
বাহ্যিক ধ্রুবক কাঠামো sshkey_impl sshkey_ecdsa_sk_webauthn_cert_impl;
# endif /* ENABLE_SK */
বাহ্যিক ধ্রুবক কাঠামো sshkey_impl sshkey_ecdsa_nistp256_impl;
বাহ্যিক ধ্রুবক কাঠামো sshkey_impl sshkey_ecdsa_nistp256_cert_impl;
বাহ্যিক ধ্রুবক কাঠামো sshkey_impl sshkey_ecdsa_nistp384_impl;
বাহ্যিক ধ্রুবক কাঠামো sshkey_impl sshkey_ecdsa_nistp384_cert_impl;
বাহ্যিক ধ্রুবক কাঠামো sshkey_impl sshkey_ecdsa_nistp521_impl;
বাহ্যিক ধ্রুবক কাঠামো sshkey_impl sshkey_ecdsa_nistp521_cert_impl;
বাহ্যিক ধ্রুবক কাঠামো sshkey_impl sshkey_rsa_impl;
বাহ্যিক ধ্রুবক কাঠামো sshkey_impl sshkey_rsa_cert_impl;
বাহ্যিক ধ্রুবক কাঠামো sshkey_impl sshkey_rsa_sha256_impl;
বাহ্যিক ধ্রুবক কাঠামো sshkey_impl sshkey_rsa_sha256_cert_impl;
বাহ্যিক ধ্রুবক কাঠামো sshkey_impl sshkey_rsa_sha512_impl;
বাহ্যিক ধ্রুবক কাঠামো sshkey_impl sshkey_rsa_sha512_cert_impl;
#endif /* WITH_OPENSSL */

ধ্রুবক কাঠামো sshkey_impl * ধ্রুবক keyimpls[] = {
	&sshkey_ed25519_impl,
	&sshkey_ed25519_cert_impl,
#ifdef ENABLE_SK
	&sshkey_ed25519_sk_impl,
	&sshkey_ed25519_sk_cert_impl,
#endif
#ifdef USE_MLDSA
	&sshkey_mldsa44_ed25519_impl,
	&sshkey_mldsa44_ed25519_cert_impl,
#endif /* USE_MLDSA */
#ifdef WITH_OPENSSL
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
#endif /* WITH_OPENSSL */
	ফাঁকা
};

স্থির ধ্রুবক কাঠামো sshkey_impl *
sshkey_impl_from_type(পূর্ণসংখ্যা type)
{
	পূর্ণসংখ্যা i;

	জন্য (i = 0; keyimpls[i] != ফাঁকা; i++) {
		যদি (keyimpls[i]->type == type)
			ফেরত keyimpls[i];
	}
	ফেরত ফাঁকা;
}

স্থির ধ্রুবক কাঠামো sshkey_impl *
sshkey_impl_from_type_nid(পূর্ণসংখ্যা type, পূর্ণসংখ্যা nid)
{
	পূর্ণসংখ্যা i;

	জন্য (i = 0; keyimpls[i] != ফাঁকা; i++) {
		যদি (keyimpls[i]->type == type &&
		    (keyimpls[i]->nid == 0 || keyimpls[i]->nid == nid))
			ফেরত keyimpls[i];
	}
	ফেরত ফাঁকা;
}

স্থির ধ্রুবক কাঠামো sshkey_impl *
sshkey_impl_from_চাবি(ধ্রুবক কাঠামো sshkey *k)
{
	যদি (k == ফাঁকা)
		ফেরত ফাঁকা;
	ফেরত sshkey_impl_from_type_nid(k->type, k->ecdsa_nid);
}

ধ্রুবক অক্ষর *
sshkey_type(ধ্রুবক কাঠামো sshkey *k)
{
	ধ্রুবক কাঠামো sshkey_impl *impl;

	যদি ((impl = sshkey_impl_from_চাবি(k)) == ফাঁকা)
		ফেরত "unknown";
	ফেরত impl->shortname;
}

স্থির ধ্রুবক অক্ষর *
sshkey_ssh_name_from_type_nid(পূর্ণসংখ্যা type, পূর্ণসংখ্যা nid)
{
	ধ্রুবক কাঠামো sshkey_impl *impl;

	যদি ((impl = sshkey_impl_from_type_nid(type, nid)) == ফাঁকা)
		ফেরত "ssh-unknown";
	ফেরত impl->name;
}

পূর্ণসংখ্যা
sshkey_type_is_cert(পূর্ণসংখ্যা type)
{
	ধ্রুবক কাঠামো sshkey_impl *impl;

	যদি ((impl = sshkey_impl_from_type(type)) == ফাঁকা)
		ফেরত 0;
	ফেরত impl->cert;
}

ধ্রুবক অক্ষর *
sshkey_ssh_name(ধ্রুবক কাঠামো sshkey *k)
{
	ফেরত sshkey_ssh_name_from_type_nid(k->type, k->ecdsa_nid);
}

ধ্রুবক অক্ষর *
sshkey_ssh_name_plain(ধ্রুবক কাঠামো sshkey *k)
{
	ফেরত sshkey_ssh_name_from_type_nid(sshkey_type_plain(k->type),
	    k->ecdsa_nid);
}

স্থির পূর্ণসংখ্যা
type_from_name(ধ্রুবক অক্ষর *name, পূর্ণসংখ্যা allow_short)
{
	পূর্ণসংখ্যা i;
	ধ্রুবক কাঠামো sshkey_impl *impl;

	জন্য (i = 0; keyimpls[i] != ফাঁকা; i++) {
		impl = keyimpls[i];
		যদি (impl->name != ফাঁকা && strcmp(name, impl->name) == 0)
			ফেরত impl->type;
		/* Only allow shortname matches for plain key types */
		যদি (allow_short && !impl->cert && impl->shortname != ফাঁকা &&
		    strcasecmp(impl->shortname, name) == 0)
			ফেরত impl->type;
	}
	ফেরত চাবি_UNSPEC;
}

পূর্ণসংখ্যা
sshkey_type_from_name(ধ্রুবক অক্ষর *name)
{
	ফেরত type_from_name(name, 0);
}

পূর্ণসংখ্যা
sshkey_type_from_shortname(ধ্রুবক অক্ষর *name)
{
	ফেরত type_from_name(name, 1);
}

স্থির পূর্ণসংখ্যা
চাবি_type_is_ecdsa_variant(পূর্ণসংখ্যা type)
{
	নির্বাচন (type) {
	ক্ষেত্র চাবি_ECDSA:
	ক্ষেত্র চাবি_ECDSA_CERT:
	ক্ষেত্র চাবি_ECDSA_SK:
	ক্ষেত্র চাবি_ECDSA_SK_CERT:
		ফেরত 1;
	}
	ফেরত 0;
}

পূর্ণসংখ্যা
sshkey_ecdsa_nid_from_name(ধ্রুবক অক্ষর *name)
{
	পূর্ণসংখ্যা i;

	জন্য (i = 0; keyimpls[i] != ফাঁকা; i++) {
		যদি (!চাবি_type_is_ecdsa_variant(keyimpls[i]->type))
			চালু;
		যদি (keyimpls[i]->name != ফাঁকা &&
		    strcmp(name, keyimpls[i]->name) == 0)
			ফেরত keyimpls[i]->nid;
	}
	ফেরত -1;
}

পূর্ণসংখ্যা
sshkey_match_keyname_to_sigalgs(ধ্রুবক অক্ষর *keyname, ধ্রুবক অক্ষর *sigalgs)
{
	পূর্ণসংখ্যা ktype;

	যদি (sigalgs == ফাঁকা || *sigalgs == '\0' ||
	    (ktype = sshkey_type_from_name(keyname)) == চাবি_UNSPEC)
		ফেরত 0;
	অন্যথা যদি (ktype == চাবি_RSA) {
		ফেরত match_pattern_list("ssh-rsa", sigalgs, 0) == 1 ||
		    match_pattern_list("rsa-sha2-256", sigalgs, 0) == 1 ||
		    match_pattern_list("rsa-sha2-512", sigalgs, 0) == 1;
	} অন্যথা যদি (ktype == চাবি_RSA_CERT) {
		ফেরত match_pattern_list("ssh-rsa-cert-v01@openssh.com",
		    sigalgs, 0) == 1 ||
		    match_pattern_list("rsa-sha2-256-cert-v01@openssh.com",
		    sigalgs, 0) == 1 ||
		    match_pattern_list("rsa-sha2-512-cert-v01@openssh.com",
		    sigalgs, 0) == 1;
	} অন্যথা যদি (ktype == চাবি_ECDSA_SK) {
		ফেরত match_pattern_list("sk-ecdsa-sha2-nistp256@openssh.com",
		    sigalgs, 0) == 1 || match_pattern_list(
		    "webauthn-sk-ecdsa-sha2-nistp256@openssh.com",
		    sigalgs, 0) == 1;
	} অন্যথা যদি (ktype == চাবি_ECDSA_SK_CERT) {
		ফেরত match_pattern_list(
		    "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
		    sigalgs, 0) == 1 || match_pattern_list(
		    "webauthn-sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
		    sigalgs, 0) == 1;
	} অন্যথা
		ফেরত match_pattern_list(keyname, sigalgs, 0) == 1;
}

অক্ষর *
sshkey_alg_list(পূর্ণসংখ্যা certs_only, পূর্ণসংখ্যা plain_only, পূর্ণসংখ্যা include_sigonly, অক্ষর sep)
{
	অক্ষর *ret = ফাঁকা;
	আকার_t i;
	ধ্রুবক কাঠামো sshkey_impl *impl;
	অক্ষর sep_str[2] = {sep, '\0'};

	জন্য (i = 0; keyimpls[i] != ফাঁকা; i++) {
		impl = keyimpls[i];
		যদি (impl->name == ফাঁকা)
			চালু;
		যদি (!include_sigonly && impl->sigonly)
			চালু;
		যদি ((certs_only && !impl->cert) || (plain_only && impl->cert))
			চালু;
		xextendf(&ret, sep_str, "%s", impl->name);
	}
	ফেরত ret;
}

পূর্ণসংখ্যা
sshkey_names_valid2(ধ্রুবক অক্ষর *names, পূর্ণসংখ্যা allow_wildcard, পূর্ণসংখ্যা plain_only)
{
	অক্ষর *s, *cp, *p;
	ধ্রুবক কাঠামো sshkey_impl *impl;
	পূর্ণসংখ্যা i, type;

	যদি (names == ফাঁকা || strcmp(names, "") == 0)
		ফেরত 0;
	যদি ((s = cp = strdup(names)) == ফাঁকা)
		ফেরত 0;
	জন্য ((p = strsep(&cp, ",")); p && *p != '\0';
	    (p = strsep(&cp, ","))) {
		type = sshkey_type_from_name(p);
		যদি (type == চাবি_UNSPEC) {
			যদি (allow_wildcard) {
				/*
				 * Try matching key types against the string.
				 * If any has a positive or negative match then
				 * the component is accepted.
				 */
				impl = ফাঁকা;
				জন্য (i = 0; keyimpls[i] != ফাঁকা; i++) {
					যদি (match_pattern_list(
					    keyimpls[i]->name, p, 0) != 0) {
						impl = keyimpls[i];
						বিরতি;
					}
				}
				যদি (impl != ফাঁকা)
					চালু;
			}
			মুক্ত(s);
			ফেরত 0;
		} অন্যথা যদি (plain_only && sshkey_type_is_cert(type)) {
			মুক্ত(s);
			ফেরত 0;
		}
	}
	মুক্ত(s);
	ফেরত 1;
}

u_int
sshkey_আকার(ধ্রুবক কাঠামো sshkey *k)
{
	ধ্রুবক কাঠামো sshkey_impl *impl;

	যদি ((impl = sshkey_impl_from_চাবি(k)) == ফাঁকা)
		ফেরত 0;
	যদি (impl->funcs->আকার_2 != ফাঁকা)
		ফেরত impl->funcs->আকার_2(k);
	ফেরত impl->keybits;
}

স্থির পূর্ণসংখ্যা
sshkey_type_is_valid_ca(পূর্ণসংখ্যা type)
{
	ধ্রুবক কাঠামো sshkey_impl *impl;

	যদি ((impl = sshkey_impl_from_type(type)) == ফাঁকা)
		ফেরত 0;
	/* All non-certificate types may act as CAs */
	ফেরত !impl->cert;
}

পূর্ণসংখ্যা
sshkey_is_cert(ধ্রুবক কাঠামো sshkey *k)
{
	যদি (k == ফাঁকা)
		ফেরত 0;
	ফেরত sshkey_type_is_cert(k->type);
}

পূর্ণসংখ্যা
sshkey_is_sk(ধ্রুবক কাঠামো sshkey *k)
{
	যদি (k == ফাঁকা)
		ফেরত 0;
	নির্বাচন (sshkey_type_plain(k->type)) {
	ক্ষেত্র চাবি_ECDSA_SK:
	ক্ষেত্র চাবি_ED25519_SK:
		ফেরত 1;
	পূর্বনির্ধারিত:
		ফেরত 0;
	}
}

/* Return the cert-less equivalent to a certified key type */
পূর্ণসংখ্যা
sshkey_type_plain(পূর্ণসংখ্যা type)
{
	নির্বাচন (type) {
	ক্ষেত্র চাবি_RSA_CERT:
		ফেরত চাবি_RSA;
	ক্ষেত্র চাবি_ECDSA_CERT:
		ফেরত চাবি_ECDSA;
	ক্ষেত্র চাবি_ECDSA_SK_CERT:
		ফেরত চাবি_ECDSA_SK;
	ক্ষেত্র চাবি_ED25519_CERT:
		ফেরত চাবি_ED25519;
	ক্ষেত্র চাবি_MLDSA44_ED25519_CERT:
		ফেরত চাবি_MLDSA44_ED25519;
	ক্ষেত্র চাবি_ED25519_SK_CERT:
		ফেরত চাবি_ED25519_SK;
	পূর্বনির্ধারিত:
		ফেরত type;
	}
}

/* Return the cert equivalent to a plain key type */
স্থির পূর্ণসংখ্যা
sshkey_type_certified(পূর্ণসংখ্যা type)
{
	নির্বাচন (type) {
	ক্ষেত্র চাবি_RSA:
		ফেরত চাবি_RSA_CERT;
	ক্ষেত্র চাবি_ECDSA:
		ফেরত চাবি_ECDSA_CERT;
	ক্ষেত্র চাবি_ECDSA_SK:
		ফেরত চাবি_ECDSA_SK_CERT;
	ক্ষেত্র চাবি_ED25519:
		ফেরত চাবি_ED25519_CERT;
	ক্ষেত্র চাবি_MLDSA44_ED25519:
		ফেরত চাবি_MLDSA44_ED25519_CERT;
	ক্ষেত্র চাবি_ED25519_SK:
		ফেরত চাবি_ED25519_SK_CERT;
	পূর্বনির্ধারিত:
		ফেরত -1;
	}
}

#ifdef WITH_OPENSSL
স্থির ধ্রুবক EVP_MD *
ssh_digest_to_md(পূর্ণসংখ্যা hash_alg)
{
	নির্বাচন (hash_alg) {
	ক্ষেত্র SSH_DIGEST_SHA1:
		ফেরত EVP_sha1();
	ক্ষেত্র SSH_DIGEST_SHA256:
		ফেরত EVP_sha256();
	ক্ষেত্র SSH_DIGEST_SHA384:
		ফেরত EVP_sha384();
	ক্ষেত্র SSH_DIGEST_SHA512:
		ফেরত EVP_sha512();
	}
	ফেরত ফাঁকা;
}

পূর্ণসংখ্যা
sshkey_pkey_digest_sign(EVP_PKEY *pkey, পূর্ণসংখ্যা hash_alg, u_char **sigp,
    আকার_t *lenp, ধ্রুবক u_char *তথ্য, আকার_t datalen)
{
	EVP_MD_CTX *ctx = ফাঁকা;
	u_char *sig = ফাঁকা;
	পূর্ণসংখ্যা ret;
	আকার_t slen;
	ধ্রুবক EVP_MD *evpmd;

	*sigp = ফাঁকা;
	*lenp = 0;

	slen = EVP_PKEY_আকার(pkey);
	যদি (slen <= 0 || slen > SSHBUF_MAX_BIGNUM ||
	   (evpmd = ssh_digest_to_md(hash_alg)) == ফাঁকা)
		ফেরত SSH_ERR_INVALID_ARGUMENT;

	যদি ((sig = malloc(slen)) == ফাঁকা)
		ফেরত SSH_ERR_ALLOC_FAIL;

	যদি ((ctx = EVP_MD_CTX_new()) == ফাঁকা) {
		ret = SSH_ERR_ALLOC_FAIL;
		যাও out;
	}
	যদি (EVP_DigestSignInit(ctx, ফাঁকা, evpmd, ফাঁকা, pkey) != 1 ||
	    EVP_DigestSign(ctx, sig, &slen, তথ্য, datalen) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		যাও out;
	}

	*sigp = sig;
	*lenp = slen;
	/* Now owned by the caller */
	sig = ফাঁকা;
	ret = 0;

 out:
	EVP_MD_CTX_free(ctx);
	মুক্ত(sig);
	ফেরত ret;
}

পূর্ণসংখ্যা
sshkey_pkey_digest_verify(EVP_PKEY *pkey, পূর্ণসংখ্যা hash_alg, ধ্রুবক u_char *তথ্য,
    আকার_t datalen, u_char *sigbuf, আকার_t siglen)
{
	EVP_MD_CTX *ctx = ফাঁকা;
	পূর্ণসংখ্যা ret = SSH_ERR_INTERNAL_ERROR;
	ধ্রুবক EVP_MD *evpmd;

	যদি ((evpmd = ssh_digest_to_md(hash_alg)) == ফাঁকা)
		ফেরত SSH_ERR_INVALID_ARGUMENT;
	যদি ((ctx = EVP_MD_CTX_new()) == ফাঁকা)
		ফেরত SSH_ERR_ALLOC_FAIL;
	যদি (EVP_DigestVerifyInit(ctx, ফাঁকা, evpmd, ফাঁকা, pkey) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		যাও out;
	}
	নির্বাচন (EVP_DigestVerify(ctx, sigbuf, siglen, তথ্য, datalen)) {
	ক্ষেত্র 1:
		ret = 0;
		বিরতি;
	ক্ষেত্র 0:
		ret = SSH_ERR_SIGNATURE_INVALID;
		বিরতি;
	পূর্বনির্ধারিত:
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		বিরতি;
	}

 out:
	EVP_MD_CTX_free(ctx);
	ফেরত ret;
}

/* XXX: these are really begging for a table-driven approach */
পূর্ণসংখ্যা
sshkey_curve_name_to_nid(ধ্রুবক অক্ষর *name)
{
	যদি (strcmp(name, "nistp256") == 0)
		ফেরত NID_X9_62_prime256v1;
	অন্যথা যদি (strcmp(name, "nistp384") == 0)
		ফেরত NID_secp384r1;
	অন্যথা যদি (strcmp(name, "nistp521") == 0)
		ফেরত NID_secp521r1;
	অন্যথা
		ফেরত -1;
}

u_int
sshkey_curve_nid_to_bits(পূর্ণসংখ্যা nid)
{
	নির্বাচন (nid) {
	ক্ষেত্র NID_X9_62_prime256v1:
		ফেরত 256;
	ক্ষেত্র NID_secp384r1:
		ফেরত 384;
	ক্ষেত্র NID_secp521r1:
		ফেরত 521;
	পূর্বনির্ধারিত:
		ফেরত 0;
	}
}

পূর্ণসংখ্যা
sshkey_ecdsa_bits_to_nid(পূর্ণসংখ্যা bits)
{
	নির্বাচন (bits) {
	ক্ষেত্র 256:
		ফেরত NID_X9_62_prime256v1;
	ক্ষেত্র 384:
		ফেরত NID_secp384r1;
	ক্ষেত্র 521:
		ফেরত NID_secp521r1;
	পূর্বনির্ধারিত:
		ফেরত -1;
	}
}

ধ্রুবক অক্ষর *
sshkey_curve_nid_to_name(পূর্ণসংখ্যা nid)
{
	নির্বাচন (nid) {
	ক্ষেত্র NID_X9_62_prime256v1:
		ফেরত "nistp256";
	ক্ষেত্র NID_secp384r1:
		ফেরত "nistp384";
	ক্ষেত্র NID_secp521r1:
		ফেরত "nistp521";
	পূর্বনির্ধারিত:
		ফেরত ফাঁকা;
	}
}

পূর্ণসংখ্যা
sshkey_ec_nid_to_hash_alg(পূর্ণসংখ্যা nid)
{
	পূর্ণসংখ্যা kbits = sshkey_curve_nid_to_bits(nid);

	যদি (kbits <= 0)
		ফেরত -1;

	/* RFC5656 section 6.2.1 */
	যদি (kbits <= 256)
		ফেরত SSH_DIGEST_SHA256;
	অন্যথা যদি (kbits <= 384)
		ফেরত SSH_DIGEST_SHA384;
	অন্যথা
		ফেরত SSH_DIGEST_SHA512;
}
#endif /* WITH_OPENSSL */

স্থির শূন্য
cert_free(কাঠামো sshkey_cert *cert)
{
	u_int i;

	যদি (cert == ফাঁকা)
		ফেরত;
	sshbuf_free(cert->certblob);
	sshbuf_free(cert->critical);
	sshbuf_free(cert->extensions);
	মুক্ত(cert->চাবি_id);
	জন্য (i = 0; i < cert->nprincipals; i++)
		মুক্ত(cert->principals[i]);
	মুক্ত(cert->principals);
	sshkey_free(cert->signature_চাবি);
	মুক্ত(cert->signature_type);
	freezero(cert, আকার(*cert));
}

স্থির কাঠামো sshkey_cert *
cert_new(শূন্য)
{
	কাঠামো sshkey_cert *cert;

	যদি ((cert = calloc(1, আকার(*cert))) == ফাঁকা)
		ফেরত ফাঁকা;
	যদি ((cert->certblob = sshbuf_new()) == ফাঁকা ||
	    (cert->critical = sshbuf_new()) == ফাঁকা ||
	    (cert->extensions = sshbuf_new()) == ফাঁকা) {
		cert_free(cert);
		ফেরত ফাঁকা;
	}
	cert->চাবি_id = ফাঁকা;
	cert->principals = ফাঁকা;
	cert->signature_চাবি = ফাঁকা;
	cert->signature_type = ফাঁকা;
	ফেরত cert;
}

কাঠামো sshkey *
sshkey_new(পূর্ণসংখ্যা type)
{
	কাঠামো sshkey *k;
	ধ্রুবক কাঠামো sshkey_impl *impl = ফাঁকা;

	যদি (type != চাবি_UNSPEC &&
	    (impl = sshkey_impl_from_type(type)) == ফাঁকা)
		ফেরত ফাঁকা;

	/* All non-certificate types may act as CAs */
	যদি ((k = calloc(1, আকার(*k))) == ফাঁকা)
		ফেরত ফাঁকা;
	k->type = type;
	k->ecdsa_nid = -1;
	যদি (impl != ফাঁকা && impl->funcs->alloc != ফাঁকা) {
		যদি (impl->funcs->alloc(k) != 0) {
			মুক্ত(k);
			ফেরত ফাঁকা;
		}
	}
	যদি (sshkey_is_cert(k)) {
		যদি ((k->cert = cert_new()) == ফাঁকা) {
			sshkey_free(k);
			ফেরত ফাঁকা;
		}
	}

	ফেরত k;
}

/* Frees common FIDO fields */
শূন্য
sshkey_sk_cleanup(কাঠামো sshkey *k)
{
	মুক্ত(k->sk_application);
	sshbuf_free(k->sk_চাবি_handle);
	sshbuf_free(k->sk_reserved);
	k->sk_application = ফাঁকা;
	k->sk_চাবি_handle = k->sk_reserved = ফাঁকা;
}

#যদি defined(MAP_CONCEAL)
# define PREKEY_MMAP_FLAG	MAP_CONCEAL
#নতুবা_যদি defined(MAP_NOCORE)
# define PREKEY_MMAP_FLAG	MAP_NOCORE
#অন্যথা
# define PREKEY_MMAP_FLAG	0
#endif

স্থির পূর্ণসংখ্যা
sshkey_prekey_alloc(u_char **prekeyp, আকার_t len)
{
#যদি defined(HAVE_MMAP) && defined(MAP_ANON) && defined(MAP_PRIVATE)
	u_char *prekey;

	*prekeyp = ফাঁকা;
	যদি ((prekey = mmap(ফাঁকা, len, PROT_READ|PROT_WRITE,
	    MAP_ANON|MAP_PRIVATE|PREKEY_MMAP_FLAG, -1, 0)) == MAP_FAILED)
		ফেরত SSH_ERR_SYSTEM_ERROR;
#যদি defined(MADV_DONTDUMP) && !defined(MAP_CONCEAL) && !defined(MAP_NOCORE)
	(শূন্য)madvise(prekey, len, MADV_DONTDUMP);
#endif
	*prekeyp = prekey;
#অন্যথা
	*prekeyp = calloc(1, len);
#endif /* HAVE_MMAP et al */
	ফেরত 0;
}

স্থির শূন্য
sshkey_prekey_free(শূন্য *prekey, আকার_t len)
{
#যদি defined(HAVE_MMAP) && defined(MAP_ANON) && defined(MAP_PRIVATE)
	যদি (prekey == ফাঁকা)
		ফেরত;
	munmap(prekey, len);
#অন্যথা
	মুক্ত(prekey);
#endif /* HAVE_MMAP et al */
}

স্থির শূন্য
sshkey_free_contents(কাঠামো sshkey *k)
{
	ধ্রুবক কাঠামো sshkey_impl *impl;

	যদি (k == ফাঁকা)
		ফেরত;
	যদি ((k->flags & SSHKEY_FLAG_EXT) != 0)
		pkcs11_চাবি_free(k);
	যদি ((impl = sshkey_impl_from_type(k->type)) != ফাঁকা &&
	    impl->funcs->cleanup != ফাঁকা)
		impl->funcs->cleanup(k);
	যদি (sshkey_is_cert(k))
		cert_free(k->cert);
	freezero(k->shielded_private, k->shielded_len);
	sshkey_prekey_free(k->shield_prekey, k->shield_prekey_len);
}

শূন্য
sshkey_free(কাঠামো sshkey *k)
{
	sshkey_free_contents(k);
	freezero(k, আকার(*k));
}

স্থির পূর্ণসংখ্যা
cert_compare(কাঠামো sshkey_cert *a, কাঠামো sshkey_cert *b)
{
	যদি (a == ফাঁকা && b == ফাঁকা)
		ফেরত 1;
	যদি (a == ফাঁকা || b == ফাঁকা)
		ফেরত 0;
	যদি (sshbuf_len(a->certblob) != sshbuf_len(b->certblob))
		ফেরত 0;
	যদি (timingsafe_bcmp(sshbuf_ptr(a->certblob), sshbuf_ptr(b->certblob),
	    sshbuf_len(a->certblob)) != 0)
		ফেরত 0;
	ফেরত 1;
}

/* Compares FIDO-specific pubkey fields only */
পূর্ণসংখ্যা
sshkey_sk_fields_equal(ধ্রুবক কাঠামো sshkey *a, ধ্রুবক কাঠামো sshkey *b)
{
	যদি (a->sk_application == ফাঁকা || b->sk_application == ফাঁকা)
		ফেরত 0;
	যদি (strcmp(a->sk_application, b->sk_application) != 0)
		ফেরত 0;
	ফেরত 1;
}

/*
 * Compare public portions of key only, allowing comparisons between
 * certificates and plain keys too.
 */
পূর্ণসংখ্যা
sshkey_equal_public(ধ্রুবক কাঠামো sshkey *a, ধ্রুবক কাঠামো sshkey *b)
{
	ধ্রুবক কাঠামো sshkey_impl *impl;

	যদি (a == ফাঁকা || b == ফাঁকা ||
	    sshkey_type_plain(a->type) != sshkey_type_plain(b->type))
		ফেরত 0;
	যদি ((impl = sshkey_impl_from_type(a->type)) == ফাঁকা)
		ফেরত 0;
	ফেরত impl->funcs->equal(a, b);
}

পূর্ণসংখ্যা
sshkey_equal(ধ্রুবক কাঠামো sshkey *a, ধ্রুবক কাঠামো sshkey *b)
{
	যদি (a == ফাঁকা || b == ফাঁকা || a->type != b->type)
		ফেরত 0;
	যদি (sshkey_is_cert(a)) {
		যদি (!cert_compare(a->cert, b->cert))
			ফেরত 0;
	}
	ফেরত sshkey_equal_public(a, b);
}


/* Serialise common FIDO key parts */
পূর্ণসংখ্যা
sshkey_serialize_sk(ধ্রুবক কাঠামো sshkey *চাবি, কাঠামো sshbuf *b)
{
	পূর্ণসংখ্যা r;

	যদি ((r = sshbuf_put_cstring(b, চাবি->sk_application)) != 0)
		ফেরত r;

	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
to_blob_buf(ধ্রুবক কাঠামো sshkey *চাবি, কাঠামো sshbuf *b, পূর্ণসংখ্যা force_plain,
  গণনা sshkey_serialize_rep opts)
{
	পূর্ণসংখ্যা type, ret = SSH_ERR_INTERNAL_ERROR;
	ধ্রুবক অক্ষর *typename;
	ধ্রুবক কাঠামো sshkey_impl *impl;

	যদি (চাবি == ফাঁকা)
		ফেরত SSH_ERR_INVALID_ARGUMENT;

	type = force_plain ? sshkey_type_plain(চাবি->type) : চাবি->type;

	যদি (sshkey_type_is_cert(type)) {
		যদি (চাবি->cert == ফাঁকা)
			ফেরত SSH_ERR_EXPECTED_CERT;
		যদি (sshbuf_len(চাবি->cert->certblob) == 0)
			ফেরত SSH_ERR_চাবি_LACKS_CERTBLOB;
		/* Use the existing blob */
		যদি ((ret = sshbuf_putb(b, চাবি->cert->certblob)) != 0)
			ফেরত ret;
		ফেরত 0;
	}
	যদি ((impl = sshkey_impl_from_type(type)) == ফাঁকা)
		ফেরত SSH_ERR_চাবি_TYPE_UNKNOWN;

	typename = sshkey_ssh_name_from_type_nid(type, চাবি->ecdsa_nid);
	যদি ((ret = sshbuf_put_cstring(b, typename)) != 0)
		ফেরত ret;
	ফেরত impl->funcs->serialize_public(চাবি, b, opts);
}

পূর্ণসংখ্যা
sshkey_putb(ধ্রুবক কাঠামো sshkey *চাবি, কাঠামো sshbuf *b)
{
	ফেরত to_blob_buf(চাবি, b, 0, SSHKEY_SERIALIZE_DEFAULT);
}

স্থির পূর্ণসংখ্যা
sshkey_puts_opts_internal(ধ্রুবক কাঠামো sshkey *চাবি, কাঠামো sshbuf *b,
    গণনা sshkey_serialize_rep opts, পূর্ণসংখ্যা force_plain)
{
	কাঠামো sshbuf *tmp;
	পূর্ণসংখ্যা r;

	যদি ((tmp = sshbuf_new()) == ফাঁকা)
		ফেরত SSH_ERR_ALLOC_FAIL;
	r = to_blob_buf(চাবি, tmp, force_plain, opts);
	যদি (r == 0)
		r = sshbuf_put_stringb(b, tmp);
	sshbuf_free(tmp);
	ফেরত r;
}

পূর্ণসংখ্যা
sshkey_puts(ধ্রুবক কাঠামো sshkey *চাবি, কাঠামো sshbuf *b)
{
	ফেরত sshkey_puts_opts_internal(চাবি, b, SSHKEY_SERIALIZE_DEFAULT, 0);
}

পূর্ণসংখ্যা
sshkey_putb_plain(ধ্রুবক কাঠামো sshkey *চাবি, কাঠামো sshbuf *b)
{
	ফেরত to_blob_buf(চাবি, b, 1, SSHKEY_SERIALIZE_DEFAULT);
}

পূর্ণসংখ্যা
sshkey_puts_plain(ধ্রুবক কাঠামো sshkey *চাবি, কাঠামো sshbuf *b)
{
	ফেরত sshkey_puts_opts_internal(চাবি, b, SSHKEY_SERIALIZE_DEFAULT, 1);
}

স্থির পূর্ণসংখ্যা
to_blob(ধ্রুবক কাঠামো sshkey *চাবি, u_char **blobp, আকার_t *lenp, পূর্ণসংখ্যা force_plain,
    গণনা sshkey_serialize_rep opts)
{
	পূর্ণসংখ্যা ret = SSH_ERR_INTERNAL_ERROR;
	আকার_t len;
	কাঠামো sshbuf *b = ফাঁকা;

	যদি (lenp != ফাঁকা)
		*lenp = 0;
	যদি (blobp != ফাঁকা)
		*blobp = ফাঁকা;
	যদি ((b = sshbuf_new()) == ফাঁকা)
		ফেরত SSH_ERR_ALLOC_FAIL;
	যদি ((ret = to_blob_buf(চাবি, b, force_plain, opts)) != 0)
		যাও out;
	len = sshbuf_len(b);
	যদি (lenp != ফাঁকা)
		*lenp = len;
	যদি (blobp != ফাঁকা) {
		যদি ((*blobp = malloc(len)) == ফাঁকা) {
			ret = SSH_ERR_ALLOC_FAIL;
			যাও out;
		}
		memcpy(*blobp, sshbuf_ptr(b), len);
	}
	ret = 0;
 out:
	sshbuf_free(b);
	ফেরত ret;
}

পূর্ণসংখ্যা
sshkey_to_blob(ধ্রুবক কাঠামো sshkey *চাবি, u_char **blobp, আকার_t *lenp)
{
	ফেরত to_blob(চাবি, blobp, lenp, 0, SSHKEY_SERIALIZE_DEFAULT);
}

পূর্ণসংখ্যা
sshkey_plain_to_blob(ধ্রুবক কাঠামো sshkey *চাবি, u_char **blobp, আকার_t *lenp)
{
	ফেরত to_blob(চাবি, blobp, lenp, 1, SSHKEY_SERIALIZE_DEFAULT);
}

পূর্ণসংখ্যা
sshkey_fingerprint_raw(ধ্রুবক কাঠামো sshkey *k, পূর্ণসংখ্যা dgst_alg,
    u_char **retp, আকার_t *lenp)
{
	u_char *blob = ফাঁকা, *ret = ফাঁকা;
	আকার_t blob_len = 0;
	পূর্ণসংখ্যা r = SSH_ERR_INTERNAL_ERROR;

	যদি (retp != ফাঁকা)
		*retp = ফাঁকা;
	যদি (lenp != ফাঁকা)
		*lenp = 0;
	যদি (ssh_digest_bytes(dgst_alg) == 0) {
		r = SSH_ERR_INVALID_ARGUMENT;
		যাও out;
	}
	যদি ((r = to_blob(k, &blob, &blob_len, 1, SSHKEY_SERIALIZE_DEFAULT))
	    != 0)
		যাও out;
	যদি ((ret = calloc(1, SSH_DIGEST_MAX_দৈর্ঘ্য)) == ফাঁকা) {
		r = SSH_ERR_ALLOC_FAIL;
		যাও out;
	}
	যদি ((r = ssh_digest_memory(dgst_alg, blob, blob_len,
	    ret, SSH_DIGEST_MAX_দৈর্ঘ্য)) != 0)
		যাও out;
	/* success */
	যদি (retp != ফাঁকা) {
		*retp = ret;
		ret = ফাঁকা;
	}
	যদি (lenp != ফাঁকা)
		*lenp = ssh_digest_bytes(dgst_alg);
	r = 0;
 out:
	মুক্ত(ret);
	যদি (blob != ফাঁকা)
		freezero(blob, blob_len);
	ফেরত r;
}

স্থির অক্ষর *
fingerprint_b64(ধ্রুবক অক্ষর *alg, u_char *dgst_raw, আকার_t dgst_raw_len)
{
	অক্ষর *ret;
	আকার_t plen = strlen(alg) + 1;
	আকার_t rlen = ((dgst_raw_len + 2) / 3) * 4 + plen + 1;

	যদি (dgst_raw_len > 65536 || (ret = calloc(1, rlen)) == ফাঁকা)
		ফেরত ফাঁকা;
	strlcpy(ret, alg, rlen);
	strlcat(ret, ":", rlen);
	যদি (dgst_raw_len == 0)
		ফেরত ret;
	যদি (b64_ntop(dgst_raw, dgst_raw_len, ret + plen, rlen - plen) == -1) {
		freezero(ret, rlen);
		ফেরত ফাঁকা;
	}
	/* Trim padding characters from end */
	ret[strcspn(ret, "=")] = '\0';
	ফেরত ret;
}

স্থির অক্ষর *
fingerprint_hex(ধ্রুবক অক্ষর *alg, u_char *dgst_raw, আকার_t dgst_raw_len)
{
	অক্ষর *retval, hex[5];
	আকার_t i, rlen = dgst_raw_len * 3 + strlen(alg) + 2;

	যদি (dgst_raw_len > 65536 || (retval = calloc(1, rlen)) == ফাঁকা)
		ফেরত ফাঁকা;
	strlcpy(retval, alg, rlen);
	strlcat(retval, ":", rlen);
	জন্য (i = 0; i < dgst_raw_len; i++) {
		snprintf(hex, আকার(hex), "%s%02x",
		    i > 0 ? ":" : "", dgst_raw[i]);
		strlcat(retval, hex, rlen);
	}
	ফেরত retval;
}

স্থির অক্ষর *
fingerprint_bubblebabble(u_char *dgst_raw, আকার_t dgst_raw_len)
{
	অক্ষর vowels[] = { 'a', 'e', 'i', 'o', 'u', 'y' };
	অক্ষর consonants[] = { 'b', 'c', 'd', 'f', 'g', 'h', 'k', 'l', 'm',
	    'n', 'p', 'r', 's', 't', 'v', 'z', 'x' };
	u_int i, j = 0, rounds, seed = 1;
	অক্ষর *retval;

	rounds = (dgst_raw_len / 2) + 1;
	যদি ((retval = calloc(rounds, 6)) == ফাঁকা)
		ফেরত ফাঁকা;
	retval[j++] = 'x';
	জন্য (i = 0; i < rounds; i++) {
		u_int idx0, idx1, idx2, idx3, idx4;
		যদি ((i + 1 < rounds) || (dgst_raw_len % 2 != 0)) {
			idx0 = (((((u_int)(dgst_raw[2 * i])) >> 6) & 3) +
			    seed) % 6;
			idx1 = (((u_int)(dgst_raw[2 * i])) >> 2) & 15;
			idx2 = ((((u_int)(dgst_raw[2 * i])) & 3) +
			    (seed / 6)) % 6;
			retval[j++] = vowels[idx0];
			retval[j++] = consonants[idx1];
			retval[j++] = vowels[idx2];
			যদি ((i + 1) < rounds) {
				idx3 = (((u_int)(dgst_raw[(2 * i) + 1])) >> 4) & 15;
				idx4 = (((u_int)(dgst_raw[(2 * i) + 1]))) & 15;
				retval[j++] = consonants[idx3];
				retval[j++] = '-';
				retval[j++] = consonants[idx4];
				seed = ((seed * 5) +
				    ((((u_int)(dgst_raw[2 * i])) * 7) +
				    ((u_int)(dgst_raw[(2 * i) + 1])))) % 36;
			}
		} অন্যথা {
			idx0 = seed % 6;
			idx1 = 16;
			idx2 = seed / 6;
			retval[j++] = vowels[idx0];
			retval[j++] = consonants[idx1];
			retval[j++] = vowels[idx2];
		}
	}
	retval[j++] = 'x';
	retval[j++] = '\0';
	ফেরত retval;
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
#define	FLDBASE		8
#define	FLDSIZE_Y	(FLDBASE + 1)
#define	FLDSIZE_X	(FLDBASE * 2 + 1)
স্থির অক্ষর *
fingerprint_randomart(ধ্রুবক অক্ষর *alg, u_char *dgst_raw, আকার_t dgst_raw_len,
    ধ্রুবক কাঠামো sshkey *k)
{
	/*
	 * Chars to be used after each other every time the worm
	 * intersects with itself.  Matter of taste.
	 */
	অক্ষর	*augmentation_string = " .o+=*BOX@%&#/^SE";
	অক্ষর	*retval, *p, title[FLDSIZE_X], hash[FLDSIZE_X];
	u_char	 field[FLDSIZE_X][FLDSIZE_Y];
	আকার_t	 i, tlen, hlen;
	u_int	 b;
	পূর্ণসংখ্যা	 x, y, r;
	আকার_t	 len = strlen(augmentation_string) - 1;

	যদি ((retval = calloc((FLDSIZE_X + 3), (FLDSIZE_Y + 2))) == ফাঁকা)
		ফেরত ফাঁকা;

	/* initialize field */
	memset(field, 0, FLDSIZE_X * FLDSIZE_Y * আকার(অক্ষর));
	x = FLDSIZE_X / 2;
	y = FLDSIZE_Y / 2;

	/* process raw key */
	জন্য (i = 0; i < dgst_raw_len; i++) {
		পূর্ণসংখ্যা প্রবেশ;
		/* each byte conveys four 2-bit move commands */
		প্রবেশ = dgst_raw[i];
		জন্য (b = 0; b < 4; b++) {
			/* evaluate 2 bit, rest is shifted later */
			x += (প্রবেশ & 0x1) ? 1 : -1;
			y += (প্রবেশ & 0x2) ? 1 : -1;

			/* assure we are still in bounds */
			x = MAXIMUM(x, 0);
			y = MAXIMUM(y, 0);
			x = MINIMUM(x, FLDSIZE_X - 1);
			y = MINIMUM(y, FLDSIZE_Y - 1);

			/* augment the field */
			যদি (field[x][y] < len - 2)
				field[x][y]++;
			প্রবেশ = প্রবেশ >> 2;
		}
	}

	/* mark starting point and end point*/
	field[FLDSIZE_X / 2][FLDSIZE_Y / 2] = len - 1;
	field[x][y] = len;

	/* assemble title */
	r = snprintf(title, আকার(title), "[%s %u]",
		sshkey_type(k), sshkey_আকার(k));
	/* If [type size] won't fit, then try [type]; fits "[ED25519-CERT]" */
	যদি (r < 0 || r > (পূর্ণসংখ্যা)আকার(title))
		r = snprintf(title, আকার(title), "[%s]", sshkey_type(k));
	tlen = (r <= 0) ? 0 : strlen(title);

	/* assemble hash ID. */
	r = snprintf(hash, আকার(hash), "[%s]", alg);
	hlen = (r <= 0) ? 0 : strlen(hash);

	/* output upper border */
	p = retval;
	*p++ = '+';
	জন্য (i = 0; i < (FLDSIZE_X - tlen) / 2; i++)
		*p++ = '-';
	memcpy(p, title, tlen);
	p += tlen;
	জন্য (i += tlen; i < FLDSIZE_X; i++)
		*p++ = '-';
	*p++ = '+';
	*p++ = '\n';

	/* output content */
	জন্য (y = 0; y < FLDSIZE_Y; y++) {
		*p++ = '|';
		জন্য (x = 0; x < FLDSIZE_X; x++)
			*p++ = augmentation_string[MINIMUM(field[x][y], len)];
		*p++ = '|';
		*p++ = '\n';
	}

	/* output lower border */
	*p++ = '+';
	জন্য (i = 0; i < (FLDSIZE_X - hlen) / 2; i++)
		*p++ = '-';
	memcpy(p, hash, hlen);
	p += hlen;
	জন্য (i += hlen; i < FLDSIZE_X; i++)
		*p++ = '-';
	*p++ = '+';

	ফেরত retval;
}

অক্ষর *
sshkey_fingerprint(ধ্রুবক কাঠামো sshkey *k, পূর্ণসংখ্যা dgst_alg,
    গণনা sshkey_fp_rep dgst_rep)
{
	অক্ষর *retval = ফাঁকা;
	u_char *dgst_raw;
	আকার_t dgst_raw_len;

	যদি (sshkey_fingerprint_raw(k, dgst_alg, &dgst_raw, &dgst_raw_len) != 0)
		ফেরত ফাঁকা;
	নির্বাচন (dgst_rep) {
	ক্ষেত্র SSH_FP_DEFAULT:
		যদি (dgst_alg == SSH_DIGEST_MD5) {
			retval = fingerprint_hex(ssh_digest_alg_name(dgst_alg),
			    dgst_raw, dgst_raw_len);
		} অন্যথা {
			retval = fingerprint_b64(ssh_digest_alg_name(dgst_alg),
			    dgst_raw, dgst_raw_len);
		}
		বিরতি;
	ক্ষেত্র SSH_FP_HEX:
		retval = fingerprint_hex(ssh_digest_alg_name(dgst_alg),
		    dgst_raw, dgst_raw_len);
		বিরতি;
	ক্ষেত্র SSH_FP_BASE64:
		retval = fingerprint_b64(ssh_digest_alg_name(dgst_alg),
		    dgst_raw, dgst_raw_len);
		বিরতি;
	ক্ষেত্র SSH_FP_BUBBLEBABBLE:
		retval = fingerprint_bubblebabble(dgst_raw, dgst_raw_len);
		বিরতি;
	ক্ষেত্র SSH_FP_RANDOMART:
		retval = fingerprint_randomart(ssh_digest_alg_name(dgst_alg),
		    dgst_raw, dgst_raw_len, k);
		বিরতি;
	পূর্বনির্ধারিত:
		freezero(dgst_raw, dgst_raw_len);
		ফেরত ফাঁকা;
	}
	freezero(dgst_raw, dgst_raw_len);
	ফেরত retval;
}

স্থির পূর্ণসংখ্যা
peek_type_nid(ধ্রুবক অক্ষর *s, আকার_t l, পূর্ণসংখ্যা *nid)
{
	ধ্রুবক কাঠামো sshkey_impl *impl;
	পূর্ণসংখ্যা i;

	জন্য (i = 0; keyimpls[i] != ফাঁকা; i++) {
		impl = keyimpls[i];
		যদি (impl->name == ফাঁকা || strlen(impl->name) != l)
			চালু;
		যদি (memcmp(s, impl->name, l) == 0) {
			*nid = -1;
			যদি (চাবি_type_is_ecdsa_variant(impl->type))
				*nid = impl->nid;
			ফেরত impl->type;
		}
	}
	ফেরত চাবি_UNSPEC;
}

/* XXX this can now be made const char * */
পূর্ণসংখ্যা
sshkey_read(কাঠামো sshkey *ret, অক্ষর **cpp)
{
	কাঠামো sshkey *k;
	অক্ষর *cp, *blobcopy;
	আকার_t space;
	পূর্ণসংখ্যা r, type, curve_nid = -1;
	কাঠামো sshbuf *blob;

	যদি (ret == ফাঁকা)
		ফেরত SSH_ERR_INVALID_ARGUMENT;
	যদি (ret->type != চাবি_UNSPEC && sshkey_impl_from_type(ret->type) == ফাঁকা)
		ফেরত SSH_ERR_INVALID_ARGUMENT;

	/* Decode type */
	cp = *cpp;
	space = strcspn(cp, " \t");
	যদি (space == strlen(cp))
		ফেরত SSH_ERR_INVALID_FORMAT;
	যদি ((type = peek_type_nid(cp, space, &curve_nid)) == চাবি_UNSPEC)
		ফেরত SSH_ERR_INVALID_FORMAT;

	/* skip whitespace */
	জন্য (cp += space; *cp == ' ' || *cp == '\t'; cp++)
		;
	যদি (*cp == '\0')
		ফেরত SSH_ERR_INVALID_FORMAT;
	যদি (ret->type != চাবি_UNSPEC && ret->type != type)
		ফেরত SSH_ERR_চাবি_TYPE_MISMATCH;
	যদি ((blob = sshbuf_new()) == ফাঁকা)
		ফেরত SSH_ERR_ALLOC_FAIL;

	/* find end of keyblob and decode */
	space = strcspn(cp, " \t");
	যদি ((blobcopy = strndup(cp, space)) == ফাঁকা) {
		sshbuf_free(blob);
		ফেরত SSH_ERR_ALLOC_FAIL;
	}
	যদি ((r = sshbuf_b64tod(blob, blobcopy)) != 0) {
		মুক্ত(blobcopy);
		sshbuf_free(blob);
		ফেরত r;
	}
	মুক্ত(blobcopy);
	যদি ((r = sshkey_fromb(blob, &k)) != 0) {
		sshbuf_free(blob);
		ফেরত r;
	}
	sshbuf_free(blob);

	/* skip whitespace and leave cp at start of comment */
	জন্য (cp += space; *cp == ' ' || *cp == '\t'; cp++)
		;

	/* ensure type of blob matches type at start of line */
	যদি (k->type != type) {
		sshkey_free(k);
		ফেরত SSH_ERR_চাবি_TYPE_MISMATCH;
	}
	যদি (চাবি_type_is_ecdsa_variant(type) && curve_nid != k->ecdsa_nid) {
		sshkey_free(k);
		ফেরত SSH_ERR_EC_CURVE_MISMATCH;
	}

	/* Fill in ret from parsed key */
	sshkey_free_contents(ret);
	*ret = *k;
	freezero(k, আকার(*k));

	/* success */
	*cpp = cp;
	ফেরত 0;
}

পূর্ণসংখ্যা
sshkey_to_base64(ধ্রুবক কাঠামো sshkey *চাবি, অক্ষর **b64p)
{
	পূর্ণসংখ্যা r = SSH_ERR_INTERNAL_ERROR;
	কাঠামো sshbuf *b = ফাঁকা;
	অক্ষর *uu = ফাঁকা;

	যদি (b64p != ফাঁকা)
		*b64p = ফাঁকা;
	যদি ((b = sshbuf_new()) == ফাঁকা)
		ফেরত SSH_ERR_ALLOC_FAIL;
	যদি ((r = sshkey_putb(চাবি, b)) != 0)
		যাও out;
	যদি ((uu = sshbuf_dtob64_string(b, 0)) == ফাঁকা) {
		r = SSH_ERR_ALLOC_FAIL;
		যাও out;
	}
	/* Success */
	যদি (b64p != ফাঁকা) {
		*b64p = uu;
		uu = ফাঁকা;
	}
	r = 0;
 out:
	sshbuf_free(b);
	মুক্ত(uu);
	ফেরত r;
}

পূর্ণসংখ্যা
sshkey_format_text(ধ্রুবক কাঠামো sshkey *চাবি, কাঠামো sshbuf *b)
{
	পূর্ণসংখ্যা r = SSH_ERR_INTERNAL_ERROR;
	অক্ষর *uu = ফাঁকা;

	যদি ((r = sshkey_to_base64(চাবি, &uu)) != 0)
		যাও out;
	যদি ((r = sshbuf_putf(b, "%s %s",
	    sshkey_ssh_name(চাবি), uu)) != 0)
		যাও out;
	r = 0;
 out:
	মুক্ত(uu);
	ফেরত r;
}

পূর্ণসংখ্যা
sshkey_write(ধ্রুবক কাঠামো sshkey *চাবি, FILE *f)
{
	কাঠামো sshbuf *b = ফাঁকা;
	পূর্ণসংখ্যা r = SSH_ERR_INTERNAL_ERROR;

	যদি ((b = sshbuf_new()) == ফাঁকা)
		ফেরত SSH_ERR_ALLOC_FAIL;
	যদি ((r = sshkey_format_text(চাবি, b)) != 0)
		যাও out;
	যদি (fwrite(sshbuf_ptr(b), sshbuf_len(b), 1, f) != 1) {
		যদি (feof(f))
			errno = EPIPE;
		r = SSH_ERR_SYSTEM_ERROR;
		যাও out;
	}
	/* Success */
	r = 0;
 out:
	sshbuf_free(b);
	ফেরত r;
}

ধ্রুবক অক্ষর *
sshkey_cert_type(ধ্রুবক কাঠামো sshkey *k)
{
	নির্বাচন (k->cert->type) {
	ক্ষেত্র SSH2_CERT_TYPE_USER:
		ফেরত "user";
	ক্ষেত্র SSH2_CERT_TYPE_HOST:
		ফেরত "host";
	পূর্বনির্ধারিত:
		ফেরত "unknown";
	}
}

পূর্ণসংখ্যা
sshkey_check_rsa_দৈর্ঘ্য(ধ্রুবক কাঠামো sshkey *k, পূর্ণসংখ্যা min_আকার)
{
#ifdef WITH_OPENSSL
	পূর্ণসংখ্যা nbits;

	যদি (k == ফাঁকা || k->pkey == ফাঁকা ||
	    (k->type != চাবি_RSA && k->type != চাবি_RSA_CERT))
		ফেরত 0;
	nbits = EVP_PKEY_bits(k->pkey);
	যদি (nbits < SSH_RSA_MINIMUM_MODULUS_আকার ||
	    (min_আকার > 0 && nbits < min_আকার))
		ফেরত SSH_ERR_চাবি_দৈর্ঘ্য;
#endif /* WITH_OPENSSL */
	ফেরত 0;
}

#ifdef WITH_OPENSSL
পূর্ণসংখ্যা
sshkey_ecdsa_চাবি_to_nid(ধ্রুবক EC_চাবি *k)
{
	ধ্রুবক EC_GROUP *g;
	পূর্ণসংখ্যা nid;

	যদি (k == ফাঁকা || (g = EC_চাবি_get0_group(k)) == ফাঁকা)
		ফেরত -1;
	যদি ((nid = EC_GROUP_get_curve_name(g)) <= 0)
		ফেরত -1;
	ফেরত nid;
}

পূর্ণসংখ্যা
sshkey_ecdsa_pkey_to_nid(EVP_PKEY *pkey)
{
	ফেরত sshkey_ecdsa_চাবি_to_nid(EVP_PKEY_get0_EC_চাবি(pkey));
}
#endif /* WITH_OPENSSL */

পূর্ণসংখ্যা
sshkey_generate(পূর্ণসংখ্যা type, u_int bits, কাঠামো sshkey **keyp)
{
	কাঠামো sshkey *k;
	পূর্ণসংখ্যা ret = SSH_ERR_INTERNAL_ERROR;
	ধ্রুবক কাঠামো sshkey_impl *impl;

	যদি (keyp == ফাঁকা || sshkey_type_is_cert(type))
		ফেরত SSH_ERR_INVALID_ARGUMENT;
	*keyp = ফাঁকা;
	যদি ((impl = sshkey_impl_from_type(type)) == ফাঁকা)
		ফেরত SSH_ERR_চাবি_TYPE_UNKNOWN;
	যদি (impl->funcs->generate == ফাঁকা)
		ফেরত SSH_ERR_FEATURE_UNSUPPORTED;
	যদি ((k = sshkey_new(চাবি_UNSPEC)) == ফাঁকা)
		ফেরত SSH_ERR_ALLOC_FAIL;
	k->type = type;
	যদি ((ret = impl->funcs->generate(k, bits)) != 0) {
		sshkey_free(k);
		ফেরত ret;
	}
	/* success */
	*keyp = k;
	ফেরত 0;
}

পূর্ণসংখ্যা
sshkey_cert_copy(ধ্রুবক কাঠামো sshkey *from_চাবি, কাঠামো sshkey *to_চাবি)
{
	u_int i;
	ধ্রুবক কাঠামো sshkey_cert *from;
	কাঠামো sshkey_cert *to;
	পূর্ণসংখ্যা r = SSH_ERR_INTERNAL_ERROR;

	যদি (to_চাবি == ফাঁকা || (from = from_চাবি->cert) == ফাঁকা)
		ফেরত SSH_ERR_INVALID_ARGUMENT;

	যদি ((to = cert_new()) == ফাঁকা)
		ফেরত SSH_ERR_ALLOC_FAIL;

	যদি ((r = sshbuf_putb(to->certblob, from->certblob)) != 0 ||
	    (r = sshbuf_putb(to->critical, from->critical)) != 0 ||
	    (r = sshbuf_putb(to->extensions, from->extensions)) != 0)
		যাও out;

	to->serial = from->serial;
	to->type = from->type;
	যদি (from->চাবি_id == ফাঁকা)
		to->চাবি_id = ফাঁকা;
	অন্যথা যদি ((to->চাবি_id = strdup(from->চাবি_id)) == ফাঁকা) {
		r = SSH_ERR_ALLOC_FAIL;
		যাও out;
	}
	to->valid_after = from->valid_after;
	to->valid_before = from->valid_before;
	যদি (from->signature_চাবি == ফাঁকা)
		to->signature_চাবি = ফাঁকা;
	অন্যথা যদি ((r = sshkey_from_private(from->signature_চাবি,
	    &to->signature_চাবি)) != 0)
		যাও out;
	যদি (from->signature_type != ফাঁকা &&
	    (to->signature_type = strdup(from->signature_type)) == ফাঁকা) {
		r = SSH_ERR_ALLOC_FAIL;
		যাও out;
	}
	যদি (from->nprincipals > SSHKEY_CERT_MAX_PRINCIPALS) {
		r = SSH_ERR_INVALID_ARGUMENT;
		যাও out;
	}
	যদি (from->nprincipals > 0) {
		যদি ((to->principals = calloc(from->nprincipals,
		    আকার(*to->principals))) == ফাঁকা) {
			r = SSH_ERR_ALLOC_FAIL;
			যাও out;
		}
		জন্য (i = 0; i < from->nprincipals; i++) {
			to->principals[i] = strdup(from->principals[i]);
			যদি (to->principals[i] == ফাঁকা) {
				to->nprincipals = i;
				r = SSH_ERR_ALLOC_FAIL;
				যাও out;
			}
		}
	}
	to->nprincipals = from->nprincipals;

	/* success */
	cert_free(to_চাবি->cert);
	to_চাবি->cert = to;
	to = ফাঁকা;
	r = 0;
 out:
	cert_free(to);
	ফেরত r;
}

পূর্ণসংখ্যা
sshkey_copy_public_sk(ধ্রুবক কাঠামো sshkey *from, কাঠামো sshkey *to)
{
	/* Append security-key application string */
	যদি ((to->sk_application = strdup(from->sk_application)) == ফাঁকা)
		ফেরত SSH_ERR_ALLOC_FAIL;
	ফেরত 0;
}

পূর্ণসংখ্যা
sshkey_from_private(ধ্রুবক কাঠামো sshkey *k, কাঠামো sshkey **pkp)
{
	কাঠামো sshkey *n = ফাঁকা;
	পূর্ণসংখ্যা r = SSH_ERR_INTERNAL_ERROR;
	ধ্রুবক কাঠামো sshkey_impl *impl;

	*pkp = ফাঁকা;
	যদি ((impl = sshkey_impl_from_চাবি(k)) == ফাঁকা)
		ফেরত SSH_ERR_চাবি_TYPE_UNKNOWN;
	যদি ((n = sshkey_new(k->type)) == ফাঁকা) {
		r = SSH_ERR_ALLOC_FAIL;
		যাও out;
	}
	যদি ((r = impl->funcs->copy_public(k, n)) != 0)
		যাও out;
	যদি (sshkey_is_cert(k) && (r = sshkey_cert_copy(k, n)) != 0)
		যাও out;
	/* success */
	*pkp = n;
	n = ফাঁকা;
	r = 0;
 out:
	sshkey_free(n);
	ফেরত r;
}

পূর্ণসংখ্যা
sshkey_is_shielded(কাঠামো sshkey *k)
{
	ফেরত k != ফাঁকা && k->shielded_private != ফাঁকা;
}

পূর্ণসংখ্যা
sshkey_shield_private(কাঠামো sshkey *k)
{
	কাঠামো sshbuf *prvbuf = ফাঁকা;
	u_char *prekey = ফাঁকা, *enc = ফাঁকা, keyiv[SSH_DIGEST_MAX_দৈর্ঘ্য];
	কাঠামো sshcipher_ctx *cctx = ফাঁকা;
	ধ্রুবক কাঠামো sshcipher *cipher;
	আকার_t i, enclen = 0;
	কাঠামো sshkey *kswap = ফাঁকা, tmp;
	পূর্ণসংখ্যা r = SSH_ERR_INTERNAL_ERROR;

#ifdef DEBUG_PK
	fprintf(stderr, "%s: entering for %s\n", __func__, sshkey_ssh_name(k));
#endif
	যদি ((cipher = cipher_by_name(SSHKEY_SHIELD_CIPHER)) == ফাঁকা) {
		r = SSH_ERR_INVALID_ARGUMENT;
		যাও out;
	}
	যদি (cipher_keylen(cipher) + cipher_ivlen(cipher) >
	    ssh_digest_bytes(SSHKEY_SHIELD_PREKEY_HASH)) {
		r = SSH_ERR_INTERNAL_ERROR;
		যাও out;
	}

	/* Prepare a random pre-key, and from it an ephemeral key */
	যদি ((r = sshkey_prekey_alloc(&prekey, SSHKEY_SHIELD_PREKEY_LEN)) != 0)
		যাও out;
	arc4random_buf(prekey, SSHKEY_SHIELD_PREKEY_LEN);
	যদি ((r = ssh_digest_memory(SSHKEY_SHIELD_PREKEY_HASH,
	    prekey, SSHKEY_SHIELD_PREKEY_LEN,
	    keyiv, SSH_DIGEST_MAX_দৈর্ঘ্য)) != 0)
		যাও out;
#ifdef DEBUG_PK
	fprintf(stderr, "%s: key+iv\n", __func__);
	sshbuf_dump_তথ্য(keyiv, ssh_digest_bytes(SSHKEY_SHIELD_PREKEY_HASH),
	    stderr);
#endif
	যদি ((r = cipher_init(&cctx, cipher, keyiv, cipher_keylen(cipher),
	    keyiv + cipher_keylen(cipher), cipher_ivlen(cipher), 1)) != 0)
		যাও out;

	/* Serialise and encrypt the private key using the ephemeral key */
	যদি ((prvbuf = sshbuf_new()) == ফাঁকা) {
		r = SSH_ERR_ALLOC_FAIL;
		যাও out;
	}
	যদি (sshkey_is_shielded(k) && (r = sshkey_unshield_private(k)) != 0)
		যাও out;
	যদি ((r = sshkey_private_serialize(k, prvbuf)) != 0)
		যাও out;
	/* pad to cipher blocksize */
	i = 0;
	যখন (sshbuf_len(prvbuf) % cipher_blocksize(cipher)) {
		যদি ((r = sshbuf_put_u8(prvbuf, ++i & 0xff)) != 0)
			যাও out;
	}
#ifdef DEBUG_PK
	fprintf(stderr, "%s: serialised\n", __func__);
	sshbuf_dump(prvbuf, stderr);
#endif
	/* encrypt */
	enclen = sshbuf_len(prvbuf);
	যদি ((enc = malloc(enclen)) == ফাঁকা) {
		r = SSH_ERR_ALLOC_FAIL;
		যাও out;
	}
	যদি ((r = cipher_crypt(cctx, 0, enc,
	    sshbuf_ptr(prvbuf), sshbuf_len(prvbuf), 0, 0)) != 0)
		যাও out;
#ifdef DEBUG_PK
	fprintf(stderr, "%s: encrypted\n", __func__);
	sshbuf_dump_তথ্য(enc, enclen, stderr);
#endif

	/* Make a scrubbed, public-only copy of our private key argument */
	যদি ((r = sshkey_from_private(k, &kswap)) != 0)
		যাও out;

	/* Swap the private key out (it will be destroyed below) */
	tmp = *kswap;
	*kswap = *k;
	*k = tmp;

	/* Insert the shielded key into our argument */
	k->shielded_private = enc;
	k->shielded_len = enclen;
	k->shield_prekey = prekey;
	k->shield_prekey_len = SSHKEY_SHIELD_PREKEY_LEN;
	enc = prekey = ফাঁকা; /* transferred */
	enclen = 0;

	/* preserve key fields that are required for correct operation */
	k->sk_flags = kswap->sk_flags;

	/* success */
	r = 0;

 out:
	/* XXX behaviour on error - invalidate original private key? */
	cipher_free(cctx);
	explicit_bzero(keyiv, আকার(keyiv));
	explicit_bzero(&tmp, আকার(tmp));
	freezero(enc, enclen);
	sshkey_prekey_free(prekey, SSHKEY_SHIELD_PREKEY_LEN);
	sshkey_free(kswap);
	sshbuf_free(prvbuf);
	ফেরত r;
}

/* Check deterministic padding after private key */
স্থির পূর্ণসংখ্যা
private2_check_padding(কাঠামো sshbuf *decrypted)
{
	u_char pad;
	আকার_t i;
	পূর্ণসংখ্যা r;

	i = 0;
	যখন (sshbuf_len(decrypted)) {
		যদি ((r = sshbuf_get_u8(decrypted, &pad)) != 0)
			যাও out;
		যদি (pad != (++i & 0xff)) {
			r = SSH_ERR_INVALID_FORMAT;
			যাও out;
		}
	}
	/* success */
	r = 0;
 out:
	explicit_bzero(&pad, আকার(pad));
	explicit_bzero(&i, আকার(i));
	ফেরত r;
}

পূর্ণসংখ্যা
sshkey_unshield_private(কাঠামো sshkey *k)
{
	কাঠামো sshbuf *prvbuf = ফাঁকা;
	u_char *cp, keyiv[SSH_DIGEST_MAX_দৈর্ঘ্য];
	কাঠামো sshcipher_ctx *cctx = ফাঁকা;
	ধ্রুবক কাঠামো sshcipher *cipher;
	কাঠামো sshkey *kswap = ফাঁকা, tmp;
	পূর্ণসংখ্যা r = SSH_ERR_INTERNAL_ERROR;

#ifdef DEBUG_PK
	fprintf(stderr, "%s: entering for %s\n", __func__, sshkey_ssh_name(k));
#endif
	যদি (!sshkey_is_shielded(k))
		ফেরত 0; /* nothing to do */

	যদি ((cipher = cipher_by_name(SSHKEY_SHIELD_CIPHER)) == ফাঁকা) {
		r = SSH_ERR_INVALID_ARGUMENT;
		যাও out;
	}
	যদি (cipher_keylen(cipher) + cipher_ivlen(cipher) >
	    ssh_digest_bytes(SSHKEY_SHIELD_PREKEY_HASH)) {
		r = SSH_ERR_INTERNAL_ERROR;
		যাও out;
	}
	/* check size of shielded key blob */
	যদি (k->shielded_len < cipher_blocksize(cipher) ||
	    (k->shielded_len % cipher_blocksize(cipher)) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		যাও out;
	}

	/* Calculate the ephemeral key from the prekey */
	যদি ((r = ssh_digest_memory(SSHKEY_SHIELD_PREKEY_HASH,
	    k->shield_prekey, k->shield_prekey_len,
	    keyiv, SSH_DIGEST_MAX_দৈর্ঘ্য)) != 0)
		যাও out;
	যদি ((r = cipher_init(&cctx, cipher, keyiv, cipher_keylen(cipher),
	    keyiv + cipher_keylen(cipher), cipher_ivlen(cipher), 0)) != 0)
		যাও out;
#ifdef DEBUG_PK
	fprintf(stderr, "%s: key+iv\n", __func__);
	sshbuf_dump_তথ্য(keyiv, ssh_digest_bytes(SSHKEY_SHIELD_PREKEY_HASH),
	    stderr);
#endif

	/* Decrypt and parse the shielded private key using the ephemeral key */
	যদি ((prvbuf = sshbuf_new()) == ফাঁকা) {
		r = SSH_ERR_ALLOC_FAIL;
		যাও out;
	}
	যদি ((r = sshbuf_reserve(prvbuf, k->shielded_len, &cp)) != 0)
		যাও out;
	/* decrypt */
#ifdef DEBUG_PK
	fprintf(stderr, "%s: encrypted\n", __func__);
	sshbuf_dump_তথ্য(k->shielded_private, k->shielded_len, stderr);
#endif
	যদি ((r = cipher_crypt(cctx, 0, cp,
	    k->shielded_private, k->shielded_len, 0, 0)) != 0)
		যাও out;
#ifdef DEBUG_PK
	fprintf(stderr, "%s: serialised\n", __func__);
	sshbuf_dump(prvbuf, stderr);
#endif
	/* Parse private key */
	যদি ((r = sshkey_private_deserialize(prvbuf, &kswap)) != 0)
		যাও out;

	যদি ((r = private2_check_padding(prvbuf)) != 0)
		যাও out;

	/* Swap the parsed key back into place */
	tmp = *kswap;
	*kswap = *k;
	*k = tmp;

	/* success */
	r = 0;

 out:
	cipher_free(cctx);
	explicit_bzero(keyiv, আকার(keyiv));
	explicit_bzero(&tmp, আকার(tmp));
	sshkey_free(kswap);
	sshbuf_free(prvbuf);
	ফেরত r;
}

স্থির পূর্ণসংখ্যা
cert_parse(কাঠামো sshbuf *b, কাঠামো sshkey *চাবি, কাঠামো sshbuf *certbuf,
    ধ্রুবক অক্ষর *ca_sigalg_allowlist)
{
	কাঠামো sshbuf *principals = ফাঁকা, *crit = ফাঁকা;
	কাঠামো sshbuf *exts = ফাঁকা, *ca = ফাঁকা;
	u_char *sig = ফাঁকা;
	অক্ষর *sigtype = ফাঁকা;
	আকার_t signed_len = 0, slen = 0, kidlen = 0;
	পূর্ণসংখ্যা ret = SSH_ERR_INTERNAL_ERROR;

	/* Copy the entire key blob for verification and later serialisation */
	যদি ((ret = sshbuf_putb(চাবি->cert->certblob, certbuf)) != 0)
		ফেরত ret;

	/* Parse body of certificate up to signature */
	যদি ((ret = sshbuf_get_u64(b, &চাবি->cert->serial)) != 0 ||
	    (ret = sshbuf_get_u32(b, &চাবি->cert->type)) != 0 ||
	    (ret = sshbuf_get_cstring(b, &চাবি->cert->চাবি_id, &kidlen)) != 0 ||
	    (ret = sshbuf_froms(b, &principals)) != 0 ||
	    (ret = sshbuf_get_u64(b, &চাবি->cert->valid_after)) != 0 ||
	    (ret = sshbuf_get_u64(b, &চাবি->cert->valid_before)) != 0 ||
	    (ret = sshbuf_froms(b, &crit)) != 0 ||
	    (ret = sshbuf_froms(b, &exts)) != 0 ||
	    (ret = sshbuf_get_string_direct(b, ফাঁকা, ফাঁকা)) != 0 ||
	    (ret = sshbuf_froms(b, &ca)) != 0) {
		/* XXX debug print error for ret */
		ret = SSH_ERR_INVALID_FORMAT;
		যাও out;
	}

	/* Signature is left in the buffer so we can calculate this length */
	signed_len = sshbuf_len(চাবি->cert->certblob) - sshbuf_len(b);

	যদি ((ret = sshbuf_get_string(b, &sig, &slen)) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		যাও out;
	}

	/* Is this a signature we're prepared to accept? */
	যদি ((ret = sshkey_get_sigtype(sig, slen, &sigtype)) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		যাও out;
	}
	যদি (ca_sigalg_allowlist != ফাঁকা &&
	    match_pattern_list(sigtype, ca_sigalg_allowlist, 0) != 1) {
		ret = SSH_ERR_SIGN_ALG_UNSUPPORTED;
		যাও out;
	}

	/* Parse CA key and check whether we might accept it */
	যদি (sshkey_from_blob_internal(ca, &চাবি->cert->signature_চাবি, 0,
	    ca_sigalg_allowlist, ফাঁকা) != 0) {
		ret = SSH_ERR_চাবি_CERT_INVALID_SIGN_চাবি;
		যাও out;
	}
	যদি (!sshkey_type_is_valid_ca(চাবি->cert->signature_চাবি->type)) {
		ret = SSH_ERR_চাবি_CERT_INVALID_SIGN_চাবি;
		যাও out;
	}

	যদি (চাবি->cert->type != SSH2_CERT_TYPE_USER &&
	    চাবি->cert->type != SSH2_CERT_TYPE_HOST) {
		ret = SSH_ERR_চাবি_CERT_UNKNOWN_TYPE;
		যাও out;
	}

	/* Parse principals section */
	যখন (sshbuf_len(principals) > 0) {
		অক্ষর *principal = ফাঁকা;
		অক্ষর **oprincipals = ফাঁকা;

		যদি (চাবি->cert->nprincipals >= SSHKEY_CERT_MAX_PRINCIPALS) {
			ret = SSH_ERR_INVALID_FORMAT;
			যাও out;
		}
		যদি ((ret = sshbuf_get_cstring(principals, &principal,
		    ফাঁকা)) != 0) {
			ret = SSH_ERR_INVALID_FORMAT;
			যাও out;
		}
		oprincipals = চাবি->cert->principals;
		চাবি->cert->principals = recallocarray(চাবি->cert->principals,
		    চাবি->cert->nprincipals, চাবি->cert->nprincipals + 1,
		    আকার(*চাবি->cert->principals));
		যদি (চাবি->cert->principals == ফাঁকা) {
			মুক্ত(principal);
			চাবি->cert->principals = oprincipals;
			ret = SSH_ERR_ALLOC_FAIL;
			যাও out;
		}
		চাবি->cert->principals[চাবি->cert->nprincipals++] = principal;
	}

	/*
	 * Stash a copies of the critical options and extensions sections
	 * for later use.
	 */
	যদি ((ret = sshbuf_putb(চাবি->cert->critical, crit)) != 0 ||
	    (exts != ফাঁকা &&
	    (ret = sshbuf_putb(চাবি->cert->extensions, exts)) != 0))
		যাও out;

	/*
	 * Validate critical options and extensions sections format.
	 */
	যখন (sshbuf_len(crit) != 0) {
		যদি ((ret = sshbuf_get_string_direct(crit, ফাঁকা, ফাঁকা)) != 0 ||
		    (ret = sshbuf_get_string_direct(crit, ফাঁকা, ফাঁকা)) != 0) {
			sshbuf_reset(চাবি->cert->critical);
			ret = SSH_ERR_INVALID_FORMAT;
			যাও out;
		}
	}
	যখন (exts != ফাঁকা && sshbuf_len(exts) != 0) {
		যদি ((ret = sshbuf_get_string_direct(exts, ফাঁকা, ফাঁকা)) != 0 ||
		    (ret = sshbuf_get_string_direct(exts, ফাঁকা, ফাঁকা)) != 0) {
			sshbuf_reset(চাবি->cert->extensions);
			ret = SSH_ERR_INVALID_FORMAT;
			যাও out;
		}
	}

	/* Finally, validate signature */
	যদি ((ret = sshkey_verify(চাবি->cert->signature_চাবি, sig, slen,
	    sshbuf_ptr(চাবি->cert->certblob), signed_len, ফাঁকা, 0, ফাঁকা)) != 0)
		যাও out;

	/* Success */
	ret = 0;
	চাবি->cert->signature_type = sigtype;
	sigtype = ফাঁকা;
 out:
	sshbuf_free(ca);
	sshbuf_free(crit);
	sshbuf_free(exts);
	sshbuf_free(principals);
	মুক্ত(sig);
	মুক্ত(sigtype);
	ফেরত ret;
}

পূর্ণসংখ্যা
sshkey_deserialize_sk(কাঠামো sshbuf *b, কাঠামো sshkey *চাবি)
{
	/* Parse additional security-key application string */
	যদি (sshbuf_get_cstring(b, &চাবি->sk_application, ফাঁকা) != 0)
		ফেরত SSH_ERR_INVALID_FORMAT;
	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
sshkey_from_blob_internal(কাঠামো sshbuf *b, কাঠামো sshkey **keyp,
    পূর্ণসংখ্যা allow_cert, ধ্রুবক অক্ষর *alg_allowlist, ধ্রুবক অক্ষর *ca_sigalg_allowlist)
{
	পূর্ণসংখ্যা type, ret = SSH_ERR_INTERNAL_ERROR;
	অক্ষর *ktype = ফাঁকা;
	কাঠামো sshkey *চাবি = ফাঁকা;
	কাঠামো sshbuf *copy;
	ধ্রুবক কাঠামো sshkey_impl *impl;

#ifdef DEBUG_PK /* XXX */
	sshbuf_dump(b, stderr);
#endif
	যদি (keyp != ফাঁকা)
		*keyp = ফাঁকা;
	যদি ((copy = sshbuf_fromb(b)) == ফাঁকা) {
		ret = SSH_ERR_ALLOC_FAIL;
		যাও out;
	}
	যদি (sshbuf_get_cstring(b, &ktype, ফাঁকা) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		যাও out;
	}

	type = sshkey_type_from_name(ktype);
	যদি (!allow_cert && sshkey_type_is_cert(type)) {
		ret = SSH_ERR_চাবি_CERT_INVALID_SIGN_চাবি;
		যাও out;
	}

	যদি (alg_allowlist != ফাঁকা &&
	    !sshkey_match_keyname_to_sigalgs(ktype, alg_allowlist)) {
		ret = SSH_ERR_চাবি_ALG_UNSUPPORTED;
		যাও out;
	}

	যদি ((impl = sshkey_impl_from_type(type)) == ফাঁকা) {
		ret = SSH_ERR_চাবি_TYPE_UNKNOWN;
		যাও out;
	}
	যদি ((চাবি = sshkey_new(type)) == ফাঁকা) {
		ret = SSH_ERR_ALLOC_FAIL;
		যাও out;
	}
	যদি (sshkey_type_is_cert(type)) {
		/* Skip nonce that precedes all certificates */
		যদি (sshbuf_get_string_direct(b, ফাঁকা, ফাঁকা) != 0) {
			ret = SSH_ERR_INVALID_FORMAT;
			যাও out;
		}
	}
	যদি ((ret = impl->funcs->deserialize_public(ktype, b, চাবি)) != 0)
		যাও out;

	/* Parse certificate potion */
	যদি (sshkey_is_cert(চাবি) &&
	    (ret = cert_parse(b, চাবি, copy, ca_sigalg_allowlist)) != 0)
		যাও out;

	যদি (চাবি != ফাঁকা && sshbuf_len(b) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		যাও out;
	}
	ret = 0;
	যদি (keyp != ফাঁকা) {
		*keyp = চাবি;
		চাবি = ফাঁকা;
	}
 out:
	sshbuf_free(copy);
	sshkey_free(চাবি);
	মুক্ত(ktype);
	ফেরত ret;
}

পূর্ণসংখ্যা
sshkey_from_blob(ধ্রুবক u_char *blob, আকার_t blen, কাঠামো sshkey **keyp)
{
	কাঠামো sshbuf *b;
	পূর্ণসংখ্যা r;

	যদি ((b = sshbuf_from(blob, blen)) == ফাঁকা)
		ফেরত SSH_ERR_ALLOC_FAIL;
	r = sshkey_from_blob_internal(b, keyp, 1, ফাঁকা, ফাঁকা);
	sshbuf_free(b);
	ফেরত r;
}

পূর্ণসংখ্যা
sshkey_fromb(কাঠামো sshbuf *b, কাঠামো sshkey **keyp)
{
	ফেরত sshkey_from_blob_internal(b, keyp, 1, ফাঁকা, ফাঁকা);
}

পূর্ণসংখ্যা
sshkey_fromb_allowlist(কাঠামো sshbuf *b, কাঠামো sshkey **keyp,
    ধ্রুবক অক্ষর *alg_allowlist, ধ্রুবক অক্ষর *ca_sigalg_allowlist)
{
	ফেরত sshkey_from_blob_internal(b, keyp, 1,
	    alg_allowlist, ca_sigalg_allowlist);
}

পূর্ণসংখ্যা
sshkey_froms(কাঠামো sshbuf *buf, কাঠামো sshkey **keyp)
{
	কাঠামো sshbuf *b;
	পূর্ণসংখ্যা r;

	যদি ((r = sshbuf_froms(buf, &b)) != 0)
		ফেরত r;
	r = sshkey_from_blob_internal(b, keyp, 1, ফাঁকা, ফাঁকা);
	sshbuf_free(b);
	ফেরত r;
}

পূর্ণসংখ্যা
sshkey_get_sigtype(ধ্রুবক u_char *sig, আকার_t siglen, অক্ষর **sigtypep)
{
	পূর্ণসংখ্যা r;
	কাঠামো sshbuf *b = ফাঁকা;
	অক্ষর *sigtype = ফাঁকা;

	যদি (sigtypep != ফাঁকা)
		*sigtypep = ফাঁকা;
	যদি ((b = sshbuf_from(sig, siglen)) == ফাঁকা)
		ফেরত SSH_ERR_ALLOC_FAIL;
	যদি ((r = sshbuf_get_cstring(b, &sigtype, ফাঁকা)) != 0)
		যাও out;
	/* success */
	যদি (sigtypep != ফাঁকা) {
		*sigtypep = sigtype;
		sigtype = ফাঁকা;
	}
	r = 0;
 out:
	মুক্ত(sigtype);
	sshbuf_free(b);
	ফেরত r;
}

/*
 *
 * Checks whether a certificate's signature type is allowed.
 * Returns 0 (success) if the certificate signature type appears in the
 * "allowed" pattern-list, or the key is not a certificate to begin with.
 * Otherwise returns a ssherr.h code.
 */
পূর্ণসংখ্যা
sshkey_check_cert_sigtype(ধ্রুবক কাঠামো sshkey *চাবি, ধ্রুবক অক্ষর *allowed)
{
	যদি (চাবি == ফাঁকা || allowed == ফাঁকা)
		ফেরত SSH_ERR_INVALID_ARGUMENT;
	যদি (!sshkey_type_is_cert(চাবি->type))
		ফেরত 0;
	যদি (চাবি->cert == ফাঁকা || চাবি->cert->signature_type == ফাঁকা)
		ফেরত SSH_ERR_INVALID_ARGUMENT;
	যদি (match_pattern_list(চাবি->cert->signature_type, allowed, 0) != 1)
		ফেরত SSH_ERR_SIGN_ALG_UNSUPPORTED;
	ফেরত 0;
}

/*
 * Returns the expected signature algorithm for a given public key algorithm.
 */
ধ্রুবক অক্ষর *
sshkey_sigalg_by_name(ধ্রুবক অক্ষর *name)
{
	ধ্রুবক কাঠামো sshkey_impl *impl;
	পূর্ণসংখ্যা i;

	জন্য (i = 0; keyimpls[i] != ফাঁকা; i++) {
		impl = keyimpls[i];
		যদি (strcmp(impl->name, name) != 0)
			চালু;
		যদি (impl->sigalg != ফাঁকা)
			ফেরত impl->sigalg;
		যদি (!impl->cert)
			ফেরত impl->name;
		ফেরত sshkey_ssh_name_from_type_nid(
		    sshkey_type_plain(impl->type), impl->nid);
	}
	ফেরত ফাঁকা;
}

/*
 * Verifies that the signature algorithm appearing inside the signature blob
 * matches that which was requested.
 */
পূর্ণসংখ্যা
sshkey_check_sigtype(ধ্রুবক u_char *sig, আকার_t siglen,
    ধ্রুবক অক্ষর *requested_alg)
{
	ধ্রুবক অক্ষর *expected_alg;
	অক্ষর *sigtype = ফাঁকা;
	পূর্ণসংখ্যা r;

	যদি (requested_alg == ফাঁকা)
		ফেরত 0;
	যদি ((expected_alg = sshkey_sigalg_by_name(requested_alg)) == ফাঁকা)
		ফেরত SSH_ERR_INVALID_ARGUMENT;
	যদি ((r = sshkey_get_sigtype(sig, siglen, &sigtype)) != 0)
		ফেরত r;
	r = strcmp(expected_alg, sigtype) == 0;
	মুক্ত(sigtype);
	ফেরত r ? 0 : SSH_ERR_SIGN_ALG_UNSUPPORTED;
}

পূর্ণসংখ্যা
sshkey_sign(কাঠামো sshkey *চাবি,
    u_char **sigp, আকার_t *lenp,
    ধ্রুবক u_char *তথ্য, আকার_t datalen,
    ধ্রুবক অক্ষর *alg, ধ্রুবক অক্ষর *sk_provider, ধ্রুবক অক্ষর *sk_pin, u_int compat)
{
	পূর্ণসংখ্যা was_shielded = sshkey_is_shielded(চাবি);
	পূর্ণসংখ্যা r2, r = SSH_ERR_INTERNAL_ERROR;
	ধ্রুবক কাঠামো sshkey_impl *impl;

	যদি (sigp != ফাঁকা)
		*sigp = ফাঁকা;
	যদি (lenp != ফাঁকা)
		*lenp = 0;
	যদি (datalen > SSH_চাবি_MAX_SIGN_তথ্য_আকার)
		ফেরত SSH_ERR_INVALID_ARGUMENT;
	যদি ((impl = sshkey_impl_from_চাবি(চাবি)) == ফাঁকা)
		ফেরত SSH_ERR_চাবি_TYPE_UNKNOWN;
	যদি ((r = sshkey_unshield_private(চাবি)) != 0)
		ফেরত r;
	যদি (sshkey_is_sk(চাবি)) {
		r = sshsk_sign(sk_provider, চাবি, sigp, lenp, তথ্য,
		    datalen, compat, sk_pin);
	} অন্যথা যদি ((চাবি->flags & SSHKEY_FLAG_EXT) != 0) {
		r = pkcs11_sign(চাবি, sigp, lenp, তথ্য, datalen,
		    alg, sk_provider, sk_pin, compat);
	} অন্যথা {
		যদি (impl->funcs->sign == ফাঁকা)
			r = SSH_ERR_SIGN_ALG_UNSUPPORTED;
		অন্যথা {
			r = impl->funcs->sign(চাবি, sigp, lenp, তথ্য, datalen,
			    alg, sk_provider, sk_pin, compat);
		 }
	}
	যদি (was_shielded && (r2 = sshkey_shield_private(চাবি)) != 0)
		ফেরত r2;
	ফেরত r;
}

/*
 * ssh_key_verify returns 0 for a correct signature and < 0 on error.
 * If "alg" specified, then the signature must use that algorithm.
 */
পূর্ণসংখ্যা
sshkey_verify(ধ্রুবক কাঠামো sshkey *চাবি,
    ধ্রুবক u_char *sig, আকার_t siglen,
    ধ্রুবক u_char *তথ্য, আকার_t dlen, ধ্রুবক অক্ষর *alg, u_int compat,
    কাঠামো sshkey_sig_details **detailsp)
{
	ধ্রুবক কাঠামো sshkey_impl *impl;

	যদি (detailsp != ফাঁকা)
		*detailsp = ফাঁকা;
	যদি (siglen == 0 || dlen > SSH_চাবি_MAX_SIGN_তথ্য_আকার)
		ফেরত SSH_ERR_INVALID_ARGUMENT;
	যদি ((impl = sshkey_impl_from_চাবি(চাবি)) == ফাঁকা)
		ফেরত SSH_ERR_চাবি_TYPE_UNKNOWN;
	ফেরত impl->funcs->verify(চাবি, sig, siglen, তথ্য, dlen,
	    alg, compat, detailsp);
}

/* Convert a plain key to their _CERT equivalent */
পূর্ণসংখ্যা
sshkey_to_certified(কাঠামো sshkey *k)
{
	পূর্ণসংখ্যা newtype;

	যদি ((newtype = sshkey_type_certified(k->type)) == -1)
		ফেরত SSH_ERR_INVALID_ARGUMENT;
	যদি ((k->cert = cert_new()) == ফাঁকা)
		ফেরত SSH_ERR_ALLOC_FAIL;
	k->type = newtype;
	ফেরত 0;
}

/* Convert a certificate to its raw key equivalent */
পূর্ণসংখ্যা
sshkey_drop_cert(কাঠামো sshkey *k)
{
	যদি (!sshkey_type_is_cert(k->type))
		ফেরত SSH_ERR_চাবি_TYPE_UNKNOWN;
	cert_free(k->cert);
	k->cert = ফাঁকা;
	k->type = sshkey_type_plain(k->type);
	ফেরত 0;
}

/* Sign a certified key, (re-)generating the signed certblob. */
পূর্ণসংখ্যা
sshkey_certify_custom(কাঠামো sshkey *k, কাঠামো sshkey *ca, ধ্রুবক অক্ষর *alg,
    ধ্রুবক অক্ষর *sk_provider, ধ্রুবক অক্ষর *sk_pin,
    sshkey_certify_signer *signer, শূন্য *signer_ctx)
{
	ধ্রুবক কাঠামো sshkey_impl *impl;
	কাঠামো sshbuf *principals = ফাঁকা;
	u_char *ca_blob = ফাঁকা, *sig_blob = ফাঁকা, nonce[32];
	আকার_t i, ca_len, sig_len;
	পূর্ণসংখ্যা ret = SSH_ERR_INTERNAL_ERROR;
	কাঠামো sshbuf *cert = ফাঁকা;
	অক্ষর *sigtype = ফাঁকা;

	যদি (k == ফাঁকা || k->cert == ফাঁকা ||
	    k->cert->certblob == ফাঁকা || ca == ফাঁকা)
		ফেরত SSH_ERR_INVALID_ARGUMENT;
	যদি (!sshkey_is_cert(k))
		ফেরত SSH_ERR_চাবি_TYPE_UNKNOWN;
	যদি (!sshkey_type_is_valid_ca(ca->type))
		ফেরত SSH_ERR_চাবি_CERT_INVALID_SIGN_চাবি;
	যদি ((impl = sshkey_impl_from_চাবি(k)) == ফাঁকা)
		ফেরত SSH_ERR_INTERNAL_ERROR;

	/*
	 * If no alg specified as argument but a signature_type was set,
	 * then prefer that. If both were specified, then they must match.
	 */
	যদি (alg == ফাঁকা)
		alg = k->cert->signature_type;
	অন্যথা যদি (k->cert->signature_type != ফাঁকা &&
	    strcmp(alg, k->cert->signature_type) != 0)
		ফেরত SSH_ERR_INVALID_ARGUMENT;

	/*
	 * If no signing algorithm or signature_type was specified and we're
	 * using a RSA key, then default to a good signature algorithm.
	 */
	যদি (alg == ফাঁকা && ca->type == চাবি_RSA)
		alg = "rsa-sha2-512";

	যদি ((ret = sshkey_to_blob(ca, &ca_blob, &ca_len)) != 0)
		ফেরত SSH_ERR_চাবি_CERT_INVALID_SIGN_চাবি;

	cert = k->cert->certblob; /* for readability */
	sshbuf_reset(cert);
	যদি ((ret = sshbuf_put_cstring(cert, sshkey_ssh_name(k))) != 0)
		যাও out;

	/* -v01 certs put nonce first */
	arc4random_buf(&nonce, আকার(nonce));
	যদি ((ret = sshbuf_put_string(cert, nonce, আকার(nonce))) != 0)
		যাও out;

	/* Public key next */
	যদি ((ret = impl->funcs->serialize_public(k, cert,
	    SSHKEY_SERIALIZE_DEFAULT)) != 0)
		যাও out;

	/* Then remaining cert fields */
	যদি ((ret = sshbuf_put_u64(cert, k->cert->serial)) != 0 ||
	    (ret = sshbuf_put_u32(cert, k->cert->type)) != 0 ||
	    (ret = sshbuf_put_cstring(cert, k->cert->চাবি_id)) != 0)
		যাও out;

	যদি ((principals = sshbuf_new()) == ফাঁকা) {
		ret = SSH_ERR_ALLOC_FAIL;
		যাও out;
	}
	জন্য (i = 0; i < k->cert->nprincipals; i++) {
		যদি ((ret = sshbuf_put_cstring(principals,
		    k->cert->principals[i])) != 0)
			যাও out;
	}
	যদি ((ret = sshbuf_put_stringb(cert, principals)) != 0 ||
	    (ret = sshbuf_put_u64(cert, k->cert->valid_after)) != 0 ||
	    (ret = sshbuf_put_u64(cert, k->cert->valid_before)) != 0 ||
	    (ret = sshbuf_put_stringb(cert, k->cert->critical)) != 0 ||
	    (ret = sshbuf_put_stringb(cert, k->cert->extensions)) != 0 ||
	    (ret = sshbuf_put_string(cert, ফাঁকা, 0)) != 0 || /* Reserved */
	    (ret = sshbuf_put_string(cert, ca_blob, ca_len)) != 0)
		যাও out;

	/* Sign the whole mess */
	যদি ((ret = signer(ca, &sig_blob, &sig_len, sshbuf_ptr(cert),
	    sshbuf_len(cert), alg, sk_provider, sk_pin, 0, signer_ctx)) != 0)
		যাও out;
	/* Check and update signature_type against what was actually used */
	যদি ((ret = sshkey_get_sigtype(sig_blob, sig_len, &sigtype)) != 0)
		যাও out;
	যদি (alg != ফাঁকা && strcmp(alg, sigtype) != 0) {
		ret = SSH_ERR_SIGN_ALG_UNSUPPORTED;
		যাও out;
	}
	যদি (k->cert->signature_type == ফাঁকা) {
		k->cert->signature_type = sigtype;
		sigtype = ফাঁকা;
	}
	/* Append signature and we are done */
	যদি ((ret = sshbuf_put_string(cert, sig_blob, sig_len)) != 0)
		যাও out;
	ret = 0;
 out:
	যদি (ret != 0)
		sshbuf_reset(cert);
	মুক্ত(sig_blob);
	মুক্ত(ca_blob);
	মুক্ত(sigtype);
	sshbuf_free(principals);
	ফেরত ret;
}

স্থির পূর্ণসংখ্যা
default_চাবি_sign(কাঠামো sshkey *চাবি, u_char **sigp, আকার_t *lenp,
    ধ্রুবক u_char *তথ্য, আকার_t datalen,
    ধ্রুবক অক্ষর *alg, ধ্রুবক অক্ষর *sk_provider, ধ্রুবক অক্ষর *sk_pin,
    u_int compat, শূন্য *ctx)
{
	যদি (ctx != ফাঁকা)
		ফেরত SSH_ERR_INVALID_ARGUMENT;
	ফেরত sshkey_sign(চাবি, sigp, lenp, তথ্য, datalen, alg,
	    sk_provider, sk_pin, compat);
}

পূর্ণসংখ্যা
sshkey_certify(কাঠামো sshkey *k, কাঠামো sshkey *ca, ধ্রুবক অক্ষর *alg,
    ধ্রুবক অক্ষর *sk_provider, ধ্রুবক অক্ষর *sk_pin)
{
	ফেরত sshkey_certify_custom(k, ca, alg, sk_provider, sk_pin,
	    default_চাবি_sign, ফাঁকা);
}

পূর্ণসংখ্যা
sshkey_cert_check_authority(ধ্রুবক কাঠামো sshkey *k,
    পূর্ণসংখ্যা want_host, পূর্ণসংখ্যা wildcard_pattern, uint64_t verify_time,
    ধ্রুবক অক্ষর *name, ধ্রুবক অক্ষর **reason)
{
	u_int i, principal_matches;

	যদি (reason == ফাঁকা)
		ফেরত SSH_ERR_INVALID_ARGUMENT;
	যদি (!sshkey_is_cert(k)) {
		*reason = "Key is not a certificate";
		ফেরত SSH_ERR_চাবি_CERT_INVALID;
	}
	যদি (want_host) {
		যদি (k->cert->type != SSH2_CERT_TYPE_HOST) {
			*reason = "Certificate invalid: not a host certificate";
			ফেরত SSH_ERR_চাবি_CERT_INVALID;
		}
	} অন্যথা {
		যদি (k->cert->type != SSH2_CERT_TYPE_USER) {
			*reason = "Certificate invalid: not a user certificate";
			ফেরত SSH_ERR_চাবি_CERT_INVALID;
		}
	}
	যদি (verify_time < k->cert->valid_after) {
		*reason = "Certificate invalid: not yet valid";
		ফেরত SSH_ERR_চাবি_CERT_INVALID;
	}
	যদি (verify_time >= k->cert->valid_before) {
		*reason = "Certificate invalid: expired";
		ফেরত SSH_ERR_চাবি_CERT_INVALID;
	}
	যদি (k->cert->nprincipals == 0) {
		*reason = "Certificate lacks principal list";
		ফেরত SSH_ERR_চাবি_CERT_INVALID;
	}
	যদি (name == ফাঁকা)
		ফেরত 0; /* principal matching not requested */

	principal_matches = 0;
	জন্য (i = 0; i < k->cert->nprincipals; i++) {
		যদি (wildcard_pattern) {
			যদি (match_pattern(name, k->cert->principals[i])) {
				principal_matches = 1;
				বিরতি;
			}
		} অন্যথা যদি (strcmp(name, k->cert->principals[i]) == 0) {
			principal_matches = 1;
			বিরতি;
		}
	}
	যদি (!principal_matches) {
		*reason = "Certificate invalid: name is not a listed "
		    "principal";
		ফেরত SSH_ERR_চাবি_CERT_INVALID;
	}
	ফেরত 0;
}

পূর্ণসংখ্যা
sshkey_cert_check_authority_now(ধ্রুবক কাঠামো sshkey *k,
    পূর্ণসংখ্যা want_host, পূর্ণসংখ্যা wildcard_pattern, ধ্রুবক অক্ষর *name,
    ধ্রুবক অক্ষর **reason)
{
	time_t now;

	যদি ((now = time(ফাঁকা)) < 0) {
		/* yikes - system clock before epoch! */
		*reason = "Certificate invalid: not yet valid";
		ফেরত SSH_ERR_চাবি_CERT_INVALID;
	}
	ফেরত sshkey_cert_check_authority(k, want_host, wildcard_pattern,
	    (uint64_t)now, name, reason);
}

পূর্ণসংখ্যা
sshkey_cert_check_host(ধ্রুবক কাঠামো sshkey *চাবি, ধ্রুবক অক্ষর *host,
    ধ্রুবক অক্ষর *ca_sign_algorithms, ধ্রুবক অক্ষর **reason)
{
	পূর্ণসংখ্যা r;

	যদি ((r = sshkey_cert_check_authority_now(চাবি, 1, 1, host, reason)) != 0)
		ফেরত r;
	যদি (sshbuf_len(চাবি->cert->critical) != 0) {
		*reason = "Certificate contains unsupported critical options";
		ফেরত SSH_ERR_চাবি_CERT_INVALID;
	}
	যদি (ca_sign_algorithms != ফাঁকা &&
	    (r = sshkey_check_cert_sigtype(চাবি, ca_sign_algorithms)) != 0) {
		*reason = "Certificate signed with disallowed algorithm";
		ফেরত SSH_ERR_চাবি_CERT_INVALID;
	}
	ফেরত 0;
}

আকার_t
sshkey_format_cert_validity(ধ্রুবক কাঠামো sshkey_cert *cert, অক্ষর *s, আকার_t l)
{
	অক্ষর from[32], to[32], ret[128];

	*from = *to = '\0';
	যদি (cert->valid_after == 0 &&
	    cert->valid_before == 0xffffffffffffffffULL)
		ফেরত strlcpy(s, "forever", l);

	যদি (cert->valid_after != 0)
		format_absolute_time(cert->valid_after, from, আকার(from));
	যদি (cert->valid_before != 0xffffffffffffffffULL)
		format_absolute_time(cert->valid_before, to, আকার(to));

	যদি (cert->valid_after == 0)
		snprintf(ret, আকার(ret), "before %s", to);
	অন্যথা যদি (cert->valid_before == 0xffffffffffffffffULL)
		snprintf(ret, আকার(ret), "after %s", from);
	অন্যথা
		snprintf(ret, আকার(ret), "from %s to %s", from, to);

	ফেরত strlcpy(s, ret, l);
}

/* Common serialization for FIDO private keys */
পূর্ণসংখ্যা
sshkey_serialize_private_sk(ধ্রুবক কাঠামো sshkey *চাবি, কাঠামো sshbuf *b)
{
	পূর্ণসংখ্যা r;

	যদি ((r = sshbuf_put_cstring(b, চাবি->sk_application)) != 0 ||
	    (r = sshbuf_put_u8(b, চাবি->sk_flags)) != 0 ||
	    (r = sshbuf_put_stringb(b, চাবি->sk_চাবি_handle)) != 0 ||
	    (r = sshbuf_put_stringb(b, চাবি->sk_reserved)) != 0)
		ফেরত r;

	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
sshkey_private_serialize_opt(কাঠামো sshkey *চাবি, কাঠামো sshbuf *buf,
    গণনা sshkey_serialize_rep opts)
{
	পূর্ণসংখ্যা r = SSH_ERR_INTERNAL_ERROR;
	পূর্ণসংখ্যা was_shielded = sshkey_is_shielded(চাবি);
	কাঠামো sshbuf *b = ফাঁকা;
	ধ্রুবক কাঠামো sshkey_impl *impl;

	যদি ((impl = sshkey_impl_from_চাবি(চাবি)) == ফাঁকা)
		ফেরত SSH_ERR_INTERNAL_ERROR;
	যদি ((r = sshkey_unshield_private(চাবি)) != 0)
		ফেরত r;
	যদি ((b = sshbuf_new()) == ফাঁকা)
		ফেরত SSH_ERR_ALLOC_FAIL;
	যদি ((r = sshbuf_put_cstring(b, sshkey_ssh_name(চাবি))) != 0)
		যাও out;
	যদি (sshkey_is_cert(চাবি)) {
		যদি (চাবি->cert == ফাঁকা ||
		    sshbuf_len(চাবি->cert->certblob) == 0) {
			r = SSH_ERR_INVALID_ARGUMENT;
			যাও out;
		}
		যদি ((r = sshbuf_put_stringb(b, চাবি->cert->certblob)) != 0)
			যাও out;
	}
	যদি ((r = impl->funcs->serialize_private(চাবি, b, opts)) != 0)
		যাও out;

	/*
	 * success (but we still need to append the output to buf after
	 * possibly re-shielding the private key)
	 */
	r = 0;
 out:
	যদি (was_shielded)
		r = sshkey_shield_private(চাবি);
	যদি (r == 0)
		r = sshbuf_putb(buf, b);
	sshbuf_free(b);

	ফেরত r;
}

পূর্ণসংখ্যা
sshkey_private_serialize(কাঠামো sshkey *চাবি, কাঠামো sshbuf *b)
{
	ফেরত sshkey_private_serialize_opt(চাবি, b,
	    SSHKEY_SERIALIZE_DEFAULT);
}


/* Shared deserialization of FIDO private key components */
পূর্ণসংখ্যা
sshkey_private_deserialize_sk(কাঠামো sshbuf *buf, কাঠামো sshkey *k)
{
	পূর্ণসংখ্যা r;

	যদি ((k->sk_চাবি_handle = sshbuf_new()) == ফাঁকা ||
	    (k->sk_reserved = sshbuf_new()) == ফাঁকা)
		ফেরত SSH_ERR_ALLOC_FAIL;
	যদি ((r = sshbuf_get_cstring(buf, &k->sk_application, ফাঁকা)) != 0 ||
	    (r = sshbuf_get_u8(buf, &k->sk_flags)) != 0 ||
	    (r = sshbuf_get_stringb(buf, k->sk_চাবি_handle)) != 0 ||
	    (r = sshbuf_get_stringb(buf, k->sk_reserved)) != 0)
		ফেরত r;

	ফেরত 0;
}

পূর্ণসংখ্যা
sshkey_private_deserialize(কাঠামো sshbuf *buf, কাঠামো sshkey **kp)
{
	ধ্রুবক কাঠামো sshkey_impl *impl;
	অক্ষর *tname = ফাঁকা;
	অক্ষর *expect_sk_application = ফাঁকা;
	u_char *expect_ed25519_pk = ফাঁকা;
	কাঠামো sshkey *k = ফাঁকা;
	পূর্ণসংখ্যা type, r = SSH_ERR_INTERNAL_ERROR;

	যদি (kp != ফাঁকা)
		*kp = ফাঁকা;
	যদি ((r = sshbuf_get_cstring(buf, &tname, ফাঁকা)) != 0)
		যাও out;
	type = sshkey_type_from_name(tname);
	যদি (sshkey_type_is_cert(type)) {
		/*
		 * Certificate key private keys begin with the certificate
		 * itself. Make sure this matches the type of the enclosing
		 * private key.
		 */
		যদি ((r = sshkey_froms(buf, &k)) != 0)
			যাও out;
		যদি (k->type != type) {
			r = SSH_ERR_চাবি_CERT_MISMATCH;
			যাও out;
		}
		/* For ECDSA keys, the group must match too */
		যদি (k->type == চাবি_ECDSA &&
		    k->ecdsa_nid != sshkey_ecdsa_nid_from_name(tname)) {
			r = SSH_ERR_চাবি_CERT_MISMATCH;
			যাও out;
		}
		/*
		 * Several fields are redundant between certificate and
		 * private key body, we require these to match.
		 */
		expect_sk_application = k->sk_application;
		expect_ed25519_pk = k->ed25519_pk;
		k->sk_application = ফাঁকা;
		k->ed25519_pk = ফাঁকা;
	} অন্যথা {
		যদি ((k = sshkey_new(type)) == ফাঁকা) {
			r = SSH_ERR_ALLOC_FAIL;
			যাও out;
		}
	}
	যদি ((impl = sshkey_impl_from_type(type)) == ফাঁকা) {
		r = SSH_ERR_INTERNAL_ERROR;
		যাও out;
	}
	যদি ((r = impl->funcs->deserialize_private(tname, buf, k)) != 0)
		যাও out;

	যদি ((expect_sk_application != ফাঁকা && (k->sk_application == ফাঁকা ||
	    strcmp(expect_sk_application, k->sk_application) != 0)) ||
	    (expect_ed25519_pk != ফাঁকা && (k->ed25519_pk == ফাঁকা ||
	    memcmp(expect_ed25519_pk, k->ed25519_pk, ED25519_PK_SZ) != 0))) {
		r = SSH_ERR_চাবি_CERT_MISMATCH;
		যাও out;
	}
	/* success */
	r = 0;
	যদি (kp != ফাঁকা) {
		*kp = k;
		k = ফাঁকা;
	}
 out:
	মুক্ত(tname);
	sshkey_free(k);
	মুক্ত(expect_sk_application);
	মুক্ত(expect_ed25519_pk);
	ফেরত r;
}

#ifdef WITH_OPENSSL
পূর্ণসংখ্যা
sshkey_ec_validate_public(ধ্রুবক EC_GROUP *group, ধ্রুবক EC_POINT *সর্বজনীন)
{
	EC_POINT *nq = ফাঁকা;
	BIGNUM *order = ফাঁকা, *cofactor = ফাঁকা;
	পূর্ণসংখ্যা ret = SSH_ERR_চাবি_INVALID_EC_মান;

	/*
	 * NB. This assumes OpenSSL has already verified that the public
	 * point lies on the curve and that its coordinates are in [0, p).
	 * This is done by EC_POINT_oct2point() on at least OpenSSL >= 1.1,
	 * LibreSSL and BoringSSL.
	 */

	/* Q != infinity */
	যদি (EC_POINT_is_at_infinity(group, সর্বজনীন))
		যাও out;

	যদি ((cofactor = BN_new()) == ফাঁকা) {
		ret = SSH_ERR_ALLOC_FAIL;
		যাও out;
	}
	যদি (EC_GROUP_get_cofactor(group, cofactor, ফাঁকা) != 1)
		যাও out;

	/*
	 * Verify nQ == infinity (n == order of subgroup)
	 * This check may be skipped for curves with cofactor 1, as per
	 * NIST SP 800-56A, 5.6.2.3.
	 */
	যদি (!BN_is_one(cofactor)) {
		যদি ((order = BN_new()) == ফাঁকা) {
			ret = SSH_ERR_ALLOC_FAIL;
			যাও out;
		}
		যদি (EC_GROUP_get_order(group, order, ফাঁকা) != 1) {
			ret = SSH_ERR_LIBCRYPTO_ERROR;
			যাও out;
		}
		যদি ((nq = EC_POINT_new(group)) == ফাঁকা) {
			ret = SSH_ERR_ALLOC_FAIL;
			যাও out;
		}
		যদি (EC_POINT_mul(group, nq, ফাঁকা, সর্বজনীন, order, ফাঁকা) != 1) {
			ret = SSH_ERR_LIBCRYPTO_ERROR;
			যাও out;
		}
		যদি (EC_POINT_is_at_infinity(group, nq) != 1)
			যাও out;
	}

	/* success */
	ret = 0;
 out:
	BN_clear_free(cofactor);
	BN_clear_free(order);
	EC_POINT_free(nq);
	ফেরত ret;
}

পূর্ণসংখ্যা
sshkey_ec_validate_private(ধ্রুবক EC_চাবি *চাবি)
{
	BIGNUM *order = ফাঁকা, *tmp = ফাঁকা;
	পূর্ণসংখ্যা ret = SSH_ERR_চাবি_INVALID_EC_মান;

	যদি ((order = BN_new()) == ফাঁকা || (tmp = BN_new()) == ফাঁকা) {
		ret = SSH_ERR_ALLOC_FAIL;
		যাও out;
	}

	/* log2(private) > log2(order)/2 */
	যদি (EC_GROUP_get_order(EC_চাবি_get0_group(চাবি), order, ফাঁকা) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		যাও out;
	}
	যদি (BN_অঙ্ক_bits(EC_চাবি_get0_private_চাবি(চাবি)) <=
	    BN_অঙ্ক_bits(order) / 2)
		যাও out;

	/* private < order - 1 */
	যদি (!BN_sub(tmp, order, BN_মান_one())) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		যাও out;
	}
	যদি (BN_cmp(EC_চাবি_get0_private_চাবি(চাবি), tmp) >= 0)
		যাও out;
	ret = 0;
 out:
	BN_clear_free(order);
	BN_clear_free(tmp);
	ফেরত ret;
}

শূন্য
sshkey_dump_ec_point(ধ্রুবক EC_GROUP *group, ধ্রুবক EC_POINT *point)
{
	BIGNUM *x = ফাঁকা, *y = ফাঁকা;

	যদি (point == ফাঁকা) {
		fputs("point=(NULL)\n", stderr);
		ফেরত;
	}
	যদি ((x = BN_new()) == ফাঁকা || (y = BN_new()) == ফাঁকা) {
		fprintf(stderr, "%s: BN_new failed\n", __func__);
		যাও out;
	}
	যদি (EC_POINT_get_affine_coordinates(group, point, x, y, ফাঁকা) != 1) {
		fprintf(stderr, "%s: EC_POINT_get_affine_coordinates\n",
		    __func__);
		যাও out;
	}
	fputs("x=", stderr);
	BN_print_fp(stderr, x);
	fputs("\ny=", stderr);
	BN_print_fp(stderr, y);
	fputs("\n", stderr);
 out:
	BN_clear_free(x);
	BN_clear_free(y);
}

শূন্য
sshkey_dump_ec_চাবি(ধ্রুবক EC_চাবি *চাবি)
{
	ধ্রুবক BIGNUM *exponent;

	sshkey_dump_ec_point(EC_চাবি_get0_group(চাবি),
	    EC_চাবি_get0_public_চাবি(চাবি));
	fputs("exponent=", stderr);
	যদি ((exponent = EC_চাবি_get0_private_চাবি(চাবি)) == ফাঁকা)
		fputs("(NULL)", stderr);
	অন্যথা
		BN_print_fp(stderr, EC_চাবি_get0_private_চাবি(চাবি));
	fputs("\n", stderr);
}
#endif /* WITH_OPENSSL */

স্থির পূর্ণসংখ্যা
sshkey_private_to_blob2(কাঠামো sshkey *prv, কাঠামো sshbuf *blob,
    ধ্রুবক অক্ষর *passphrase, ধ্রুবক অক্ষর *comment, ধ্রুবক অক্ষর *ciphername,
    পূর্ণসংখ্যা rounds)
{
	u_char *cp, *চাবি = ফাঁকা, *pubkeyblob = ফাঁকা;
	u_char salt[SALT_LEN];
	আকার_t i, pubkeylen, keylen, ivlen, blocksize, authlen;
	u_int check;
	পূর্ণসংখ্যা r = SSH_ERR_INTERNAL_ERROR;
	কাঠামো sshcipher_ctx *ciphercontext = ফাঁকা;
	ধ্রুবক কাঠামো sshcipher *cipher;
	ধ্রুবক অক্ষর *kdfname = KDFNAME;
	কাঠামো sshbuf *encoded = ফাঁকা, *encrypted = ফাঁকা, *kdf = ফাঁকা;

	যদি (rounds <= 0)
		rounds = DEFAULT_ROUNDS;
	যদি (rounds > MAX_KDF_ROUNDS) {
		r = SSH_ERR_INVALID_ARGUMENT;
		যাও out;
	}
	যদি (passphrase == ফাঁকা || !strlen(passphrase)) {
		ciphername = "none";
		kdfname = "none";
	} অন্যথা যদি (ciphername == ফাঁকা)
		ciphername = DEFAULT_CIPHERNAME;
	যদি ((cipher = cipher_by_name(ciphername)) == ফাঁকা) {
		r = SSH_ERR_INVALID_ARGUMENT;
		যাও out;
	}

	যদি ((kdf = sshbuf_new()) == ফাঁকা ||
	    (encoded = sshbuf_new()) == ফাঁকা ||
	    (encrypted = sshbuf_new()) == ফাঁকা) {
		r = SSH_ERR_ALLOC_FAIL;
		যাও out;
	}
	blocksize = cipher_blocksize(cipher);
	keylen = cipher_keylen(cipher);
	ivlen = cipher_ivlen(cipher);
	authlen = cipher_authlen(cipher);
	যদি ((চাবি = calloc(1, keylen + ivlen)) == ফাঁকা) {
		r = SSH_ERR_ALLOC_FAIL;
		যাও out;
	}
	যদি (strcmp(kdfname, "bcrypt") == 0) {
		arc4random_buf(salt, SALT_LEN);
		যদি (bcrypt_pbkdf(passphrase, strlen(passphrase),
		    salt, SALT_LEN, চাবি, keylen + ivlen, rounds) < 0) {
			r = SSH_ERR_INVALID_ARGUMENT;
			যাও out;
		}
		যদি ((r = sshbuf_put_string(kdf, salt, SALT_LEN)) != 0 ||
		    (r = sshbuf_put_u32(kdf, rounds)) != 0)
			যাও out;
	} অন্যথা যদি (strcmp(kdfname, "none") != 0) {
		/* Unsupported KDF type */
		r = SSH_ERR_চাবি_UNKNOWN_CIPHER;
		যাও out;
	}
	যদি ((r = cipher_init(&ciphercontext, cipher, চাবি, keylen,
	    চাবি + keylen, ivlen, 1)) != 0)
		যাও out;

	যদি ((r = sshbuf_put(encoded, AUTH_MAGIC, আকার(AUTH_MAGIC))) != 0 ||
	    (r = sshbuf_put_cstring(encoded, ciphername)) != 0 ||
	    (r = sshbuf_put_cstring(encoded, kdfname)) != 0 ||
	    (r = sshbuf_put_stringb(encoded, kdf)) != 0 ||
	    (r = sshbuf_put_u32(encoded, 1)) != 0 ||	/* number of keys */
	    (r = sshkey_to_blob(prv, &pubkeyblob, &pubkeylen)) != 0 ||
	    (r = sshbuf_put_string(encoded, pubkeyblob, pubkeylen)) != 0)
		যাও out;

	/* set up the buffer that will be encrypted */

	/* Random check bytes */
	check = arc4random();
	যদি ((r = sshbuf_put_u32(encrypted, check)) != 0 ||
	    (r = sshbuf_put_u32(encrypted, check)) != 0)
		যাও out;

	/* append private key and comment*/
	যদি ((r = sshkey_private_serialize(prv, encrypted)) != 0 ||
	    (r = sshbuf_put_cstring(encrypted, comment)) != 0)
		যাও out;

	/* padding */
	i = 0;
	যখন (sshbuf_len(encrypted) % blocksize) {
		যদি ((r = sshbuf_put_u8(encrypted, ++i & 0xff)) != 0)
			যাও out;
	}

	/* length in destination buffer */
	যদি ((r = sshbuf_put_u32(encoded, sshbuf_len(encrypted))) != 0)
		যাও out;

	/* encrypt */
	যদি ((r = sshbuf_reserve(encoded,
	    sshbuf_len(encrypted) + authlen, &cp)) != 0)
		যাও out;
	যদি ((r = cipher_crypt(ciphercontext, 0, cp,
	    sshbuf_ptr(encrypted), sshbuf_len(encrypted), 0, authlen)) != 0)
		যাও out;

	sshbuf_reset(blob);

	/* assemble uuencoded key */
	যদি ((r = sshbuf_put(blob, MARK_BEGIN, MARK_BEGIN_LEN)) != 0 ||
	    (r = sshbuf_dtob64(encoded, blob, 1)) != 0 ||
	    (r = sshbuf_put(blob, MARK_END, MARK_END_LEN)) != 0)
		যাও out;

	/* success */
	r = 0;

 out:
	sshbuf_free(kdf);
	sshbuf_free(encoded);
	sshbuf_free(encrypted);
	cipher_free(ciphercontext);
	explicit_bzero(salt, আকার(salt));
	যদি (চাবি != ফাঁকা)
		freezero(চাবি, keylen + ivlen);
	যদি (pubkeyblob != ফাঁকা)
		freezero(pubkeyblob, pubkeylen);
	ফেরত r;
}

স্থির পূর্ণসংখ্যা
private2_uudecode(কাঠামো sshbuf *blob, কাঠামো sshbuf **decodedp)
{
	ধ্রুবক u_char *cp;
	আকার_t encoded_len;
	পূর্ণসংখ্যা r;
	u_char last;
	কাঠামো sshbuf *encoded = ফাঁকা, *decoded = ফাঁকা;

	যদি (blob == ফাঁকা || decodedp == ফাঁকা)
		ফেরত SSH_ERR_INVALID_ARGUMENT;

	*decodedp = ফাঁকা;

	যদি ((encoded = sshbuf_new()) == ফাঁকা ||
	    (decoded = sshbuf_new()) == ফাঁকা) {
		r = SSH_ERR_ALLOC_FAIL;
		যাও out;
	}

	/* check preamble */
	cp = sshbuf_ptr(blob);
	encoded_len = sshbuf_len(blob);
	যদি (encoded_len < (MARK_BEGIN_LEN + MARK_END_LEN) ||
	    memcmp(cp, MARK_BEGIN, MARK_BEGIN_LEN) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		যাও out;
	}
	cp += MARK_BEGIN_LEN;
	encoded_len -= MARK_BEGIN_LEN;

	/* Look for end marker, removing whitespace as we go */
	যখন (encoded_len > 0) {
		যদি (*cp != '\n' && *cp != '\r') {
			যদি ((r = sshbuf_put_u8(encoded, *cp)) != 0)
				যাও out;
		}
		last = *cp;
		encoded_len--;
		cp++;
		যদি (last == '\n') {
			যদি (encoded_len >= MARK_END_LEN &&
			    memcmp(cp, MARK_END, MARK_END_LEN) == 0) {
				/* \0 terminate */
				যদি ((r = sshbuf_put_u8(encoded, 0)) != 0)
					যাও out;
				বিরতি;
			}
		}
	}
	যদি (encoded_len == 0) {
		r = SSH_ERR_INVALID_FORMAT;
		যাও out;
	}

	/* decode base64 */
	যদি ((r = sshbuf_b64tod(decoded, (অক্ষর *)sshbuf_ptr(encoded))) != 0)
		যাও out;

	/* check magic */
	যদি (sshbuf_len(decoded) < আকার(AUTH_MAGIC) ||
	    memcmp(sshbuf_ptr(decoded), AUTH_MAGIC, আকার(AUTH_MAGIC))) {
		r = SSH_ERR_INVALID_FORMAT;
		যাও out;
	}
	/* success */
	*decodedp = decoded;
	decoded = ফাঁকা;
	r = 0;
 out:
	sshbuf_free(encoded);
	sshbuf_free(decoded);
	ফেরত r;
}

স্থির পূর্ণসংখ্যা
private2_decrypt(কাঠামো sshbuf *decoded, ধ্রুবক অক্ষর *passphrase,
    কাঠামো sshbuf **decryptedp, কাঠামো sshkey **pubkeyp)
{
	অক্ষর *ciphername = ফাঁকা, *kdfname = ফাঁকা;
	ধ্রুবক কাঠামো sshcipher *cipher = ফাঁকা;
	পূর্ণসংখ্যা r = SSH_ERR_INTERNAL_ERROR;
	আকার_t keylen = 0, ivlen = 0, authlen = 0, slen = 0;
	কাঠামো sshbuf *kdf = ফাঁকা, *decrypted = ফাঁকা;
	কাঠামো sshcipher_ctx *ciphercontext = ফাঁকা;
	কাঠামো sshkey *pubkey = ফাঁকা;
	u_char *চাবি = ফাঁকা, *salt = ফাঁকা, *dp;
	u_int blocksize, rounds, nkeys, encrypted_len, check1, check2;

	যদি (decoded == ফাঁকা || decryptedp == ফাঁকা || pubkeyp == ফাঁকা)
		ফেরত SSH_ERR_INVALID_ARGUMENT;

	*decryptedp = ফাঁকা;
	*pubkeyp = ফাঁকা;

	যদি ((decrypted = sshbuf_new()) == ফাঁকা) {
		r = SSH_ERR_ALLOC_FAIL;
		যাও out;
	}

	/* parse public portion of key */
	যদি ((r = sshbuf_consume(decoded, আকার(AUTH_MAGIC))) != 0 ||
	    (r = sshbuf_get_cstring(decoded, &ciphername, ফাঁকা)) != 0 ||
	    (r = sshbuf_get_cstring(decoded, &kdfname, ফাঁকা)) != 0 ||
	    (r = sshbuf_froms(decoded, &kdf)) != 0 ||
	    (r = sshbuf_get_u32(decoded, &nkeys)) != 0)
		যাও out;

	যদি (nkeys != 1) {
		/* XXX only one key supported at present */
		r = SSH_ERR_INVALID_FORMAT;
		যাও out;
	}

	যদি ((r = sshkey_froms(decoded, &pubkey)) != 0 ||
	    (r = sshbuf_get_u32(decoded, &encrypted_len)) != 0)
		যাও out;

	যদি ((cipher = cipher_by_name(ciphername)) == ফাঁকা) {
		r = SSH_ERR_চাবি_UNKNOWN_CIPHER;
		যাও out;
	}
	যদি (strcmp(kdfname, "none") != 0 && strcmp(kdfname, "bcrypt") != 0) {
		r = SSH_ERR_চাবি_UNKNOWN_CIPHER;
		যাও out;
	}
	যদি (strcmp(kdfname, "none") == 0 && strcmp(ciphername, "none") != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		যাও out;
	}
	যদি ((passphrase == ফাঁকা || strlen(passphrase) == 0) &&
	    strcmp(kdfname, "none") != 0) {
		/* passphrase required */
		r = SSH_ERR_চাবি_WRONG_PASSPHRASE;
		যাও out;
	}

	/* check size of encrypted key blob */
	blocksize = cipher_blocksize(cipher);
	যদি (encrypted_len < blocksize || (encrypted_len % blocksize) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		যাও out;
	}

	/* setup key */
	keylen = cipher_keylen(cipher);
	ivlen = cipher_ivlen(cipher);
	authlen = cipher_authlen(cipher);
	যদি ((চাবি = calloc(1, keylen + ivlen)) == ফাঁকা) {
		r = SSH_ERR_ALLOC_FAIL;
		যাও out;
	}
	যদি (strcmp(kdfname, "bcrypt") == 0) {
		যদি ((r = sshbuf_get_string(kdf, &salt, &slen)) != 0 ||
		    (r = sshbuf_get_u32(kdf, &rounds)) != 0)
			যাও out;
		যদি (rounds > MAX_KDF_ROUNDS) {
			r = SSH_ERR_INVALID_FORMAT;
			যাও out;
		}
		যদি (bcrypt_pbkdf(passphrase, strlen(passphrase), salt, slen,
		    চাবি, keylen + ivlen, rounds) < 0) {
			r = SSH_ERR_INVALID_FORMAT;
			যাও out;
		}
	}

	/* check that an appropriate amount of auth data is present */
	যদি (sshbuf_len(decoded) < authlen ||
	    sshbuf_len(decoded) - authlen < encrypted_len) {
		r = SSH_ERR_INVALID_FORMAT;
		যাও out;
	}

	/* decrypt private portion of key */
	যদি ((r = sshbuf_reserve(decrypted, encrypted_len, &dp)) != 0 ||
	    (r = cipher_init(&ciphercontext, cipher, চাবি, keylen,
	    চাবি + keylen, ivlen, 0)) != 0)
		যাও out;
	যদি ((r = cipher_crypt(ciphercontext, 0, dp, sshbuf_ptr(decoded),
	    encrypted_len, 0, authlen)) != 0) {
		/* an integrity error here indicates an incorrect passphrase */
		যদি (r == SSH_ERR_MAC_INVALID)
			r = SSH_ERR_চাবি_WRONG_PASSPHRASE;
		যাও out;
	}
	যদি ((r = sshbuf_consume(decoded, encrypted_len + authlen)) != 0)
		যাও out;
	/* there should be no trailing data */
	যদি (sshbuf_len(decoded) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		যাও out;
	}

	/* check check bytes */
	যদি ((r = sshbuf_get_u32(decrypted, &check1)) != 0 ||
	    (r = sshbuf_get_u32(decrypted, &check2)) != 0)
		যাও out;
	যদি (check1 != check2) {
		r = SSH_ERR_চাবি_WRONG_PASSPHRASE;
		যাও out;
	}
	/* success */
	*decryptedp = decrypted;
	decrypted = ফাঁকা;
	*pubkeyp = pubkey;
	pubkey = ফাঁকা;
	r = 0;
 out:
	cipher_free(ciphercontext);
	মুক্ত(ciphername);
	মুক্ত(kdfname);
	sshkey_free(pubkey);
	যদি (salt != ফাঁকা) {
		explicit_bzero(salt, slen);
		মুক্ত(salt);
	}
	যদি (চাবি != ফাঁকা) {
		explicit_bzero(চাবি, keylen + ivlen);
		মুক্ত(চাবি);
	}
	sshbuf_free(kdf);
	sshbuf_free(decrypted);
	ফেরত r;
}

স্থির পূর্ণসংখ্যা
sshkey_parse_private2(কাঠামো sshbuf *blob, পূর্ণসংখ্যা type, ধ্রুবক অক্ষর *passphrase,
    কাঠামো sshkey **keyp, অক্ষর **commentp)
{
	অক্ষর *comment = ফাঁকা;
	পূর্ণসংখ্যা r = SSH_ERR_INTERNAL_ERROR;
	কাঠামো sshbuf *decoded = ফাঁকা, *decrypted = ফাঁকা;
	কাঠামো sshkey *k = ফাঁকা, *pubkey = ফাঁকা;

	যদি (keyp != ফাঁকা)
		*keyp = ফাঁকা;
	যদি (commentp != ফাঁকা)
		*commentp = ফাঁকা;

	/* Undo base64 encoding and decrypt the private section */
	যদি ((r = private2_uudecode(blob, &decoded)) != 0 ||
	    (r = private2_decrypt(decoded, passphrase,
	    &decrypted, &pubkey)) != 0)
		যাও out;

	যদি (type != চাবি_UNSPEC &&
	    sshkey_type_plain(type) != sshkey_type_plain(pubkey->type)) {
		r = SSH_ERR_চাবি_TYPE_MISMATCH;
		যাও out;
	}

	/* Load the private key and comment */
	যদি ((r = sshkey_private_deserialize(decrypted, &k)) != 0 ||
	    (r = sshbuf_get_cstring(decrypted, &comment, ফাঁকা)) != 0)
		যাও out;

	/* Check deterministic padding after private section */
	যদি ((r = private2_check_padding(decrypted)) != 0)
		যাও out;

	/* Check that the public key in the envelope matches the private key */
	যদি (!sshkey_equal(pubkey, k)) {
		r = SSH_ERR_INVALID_FORMAT;
		যাও out;
	}

	/* success */
	r = 0;
	যদি (keyp != ফাঁকা) {
		*keyp = k;
		k = ফাঁকা;
	}
	যদি (commentp != ফাঁকা) {
		*commentp = comment;
		comment = ফাঁকা;
	}
 out:
	মুক্ত(comment);
	sshbuf_free(decoded);
	sshbuf_free(decrypted);
	sshkey_free(k);
	sshkey_free(pubkey);
	ফেরত r;
}

স্থির পূর্ণসংখ্যা
sshkey_parse_private2_pubkey(কাঠামো sshbuf *blob, পূর্ণসংখ্যা type,
    কাঠামো sshkey **keyp)
{
	পূর্ণসংখ্যা r = SSH_ERR_INTERNAL_ERROR;
	কাঠামো sshbuf *decoded = ফাঁকা;
	কাঠামো sshkey *pubkey = ফাঁকা;
	u_int nkeys = 0;

	যদি (keyp != ফাঁকা)
		*keyp = ফাঁকা;

	যদি ((r = private2_uudecode(blob, &decoded)) != 0)
		যাও out;
	/* parse public key from unencrypted envelope */
	যদি ((r = sshbuf_consume(decoded, আকার(AUTH_MAGIC))) != 0 ||
	    (r = sshbuf_skip_string(decoded)) != 0 || /* cipher */
	    (r = sshbuf_skip_string(decoded)) != 0 || /* KDF alg */
	    (r = sshbuf_skip_string(decoded)) != 0 || /* KDF hint */
	    (r = sshbuf_get_u32(decoded, &nkeys)) != 0)
		যাও out;

	যদি (nkeys != 1) {
		/* XXX only one key supported at present */
		r = SSH_ERR_INVALID_FORMAT;
		যাও out;
	}

	/* Parse the public key */
	যদি ((r = sshkey_froms(decoded, &pubkey)) != 0)
		যাও out;

	যদি (type != চাবি_UNSPEC &&
	    sshkey_type_plain(type) != sshkey_type_plain(pubkey->type)) {
		r = SSH_ERR_চাবি_TYPE_MISMATCH;
		যাও out;
	}

	/* success */
	r = 0;
	যদি (keyp != ফাঁকা) {
		*keyp = pubkey;
		pubkey = ফাঁকা;
	}
 out:
	sshbuf_free(decoded);
	sshkey_free(pubkey);
	ফেরত r;
}

#ifdef WITH_OPENSSL
/* convert SSH v2 key to PEM or PKCS#8 format */
স্থির পূর্ণসংখ্যা
sshkey_private_to_blob_pem_pkcs8(কাঠামো sshkey *চাবি, কাঠামো sshbuf *buf,
    পূর্ণসংখ্যা format, ধ্রুবক অক্ষর *_passphrase, ধ্রুবক অক্ষর *comment)
{
	পূর্ণসংখ্যা was_shielded = sshkey_is_shielded(চাবি);
	পূর্ণসংখ্যা success, r;
	পূর্ণসংখ্যা blen, len = strlen(_passphrase);
	u_char *passphrase = (len > 0) ? (u_char *)_passphrase : ফাঁকা;
	ধ্রুবক EVP_CIPHER *cipher = (len > 0) ? EVP_aes_128_cbc() : ফাঁকা;
	অক্ষর *bptr;
	BIO *bio = ফাঁকা;
	কাঠামো sshbuf *blob;
	EVP_PKEY *pkey = ফাঁকা;

	যদি (len > 0 && len <= 4)
		ফেরত SSH_ERR_PASSPHRASE_TOO_SHORT;
	যদি ((blob = sshbuf_new()) == ফাঁকা)
		ফেরত SSH_ERR_ALLOC_FAIL;
	যদি ((bio = BIO_new(BIO_s_mem())) == ফাঁকা) {
		r = SSH_ERR_ALLOC_FAIL;
		যাও out;
	}
	যদি ((r = sshkey_unshield_private(চাবি)) != 0)
		যাও out;

	নির্বাচন (চাবি->type) {
	ক্ষেত্র চাবি_ECDSA:
		যদি (format == SSHKEY_PRIVATE_PEM) {
			success = PEM_write_bio_ECPrivate_চাবি(bio,
			    EVP_PKEY_get0_EC_চাবি(চাবি->pkey),
			    cipher, passphrase, len, ফাঁকা, ফাঁকা);
		} অন্যথা {
			pkey = চাবি->pkey;
			EVP_PKEY_up_ref(চাবি->pkey);
			success = 1;
		}
		বিরতি;
	ক্ষেত্র চাবি_RSA:
		যদি (format == SSHKEY_PRIVATE_PEM) {
			success = PEM_write_bio_RSAPrivate_চাবি(bio,
			    EVP_PKEY_get0_RSA(চাবি->pkey),
			    cipher, passphrase, len, ফাঁকা, ফাঁকা);
		} অন্যথা {
			pkey = চাবি->pkey;
			EVP_PKEY_up_ref(চাবি->pkey);
			success = 1;
		}
		বিরতি;
#ifdef OPENSSL_HAS_ED25519
	ক্ষেত্র চাবি_ED25519:
		যদি (format == SSHKEY_PRIVATE_PEM) {
			r = SSH_ERR_INVALID_FORMAT;
			যাও out;
		} অন্যথা {
			pkey = EVP_PKEY_new_raw_private_চাবি(EVP_PKEY_ED25519,
			    ফাঁকা, চাবি->ed25519_sk,
			    ED25519_SK_SZ - ED25519_PK_SZ);
			success = pkey != ফাঁকা;
		}
		বিরতি;
#endif
	পূর্বনির্ধারিত:
		success = 0;
		বিরতি;
	}
	যদি (success == 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		যাও out;
	}
	যদি (format == SSHKEY_PRIVATE_PKCS8) {
		যদি ((success = PEM_write_bio_Private_চাবি(bio, pkey, cipher,
		    passphrase, len, ফাঁকা, ফাঁকা)) == 0) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			যাও out;
		}
	}
	যদি ((blen = BIO_get_mem_তথ্য(bio, &bptr)) <= 0) {
		r = SSH_ERR_INTERNAL_ERROR;
		যাও out;
	}
	যদি ((r = sshbuf_put(blob, bptr, blen)) != 0)
		যাও out;
	r = 0;
 out:
	যদি (was_shielded)
		r = sshkey_shield_private(চাবি);
	যদি (r == 0)
		r = sshbuf_putb(buf, blob);

	EVP_PKEY_free(pkey);
	sshbuf_free(blob);
	BIO_free(bio);
	ফেরত r;
}
#endif /* WITH_OPENSSL */

/* Serialise "key" to buffer "blob" */
পূর্ণসংখ্যা
sshkey_private_to_fileblob(কাঠামো sshkey *চাবি, কাঠামো sshbuf *blob,
    ধ্রুবক অক্ষর *passphrase, ধ্রুবক অক্ষর *comment,
    পূর্ণসংখ্যা format, ধ্রুবক অক্ষর *openssh_format_cipher, পূর্ণসংখ্যা openssh_format_rounds)
{
	নির্বাচন (চাবি->type) {
#ifdef WITH_OPENSSL
	ক্ষেত্র চাবি_ECDSA:
	ক্ষেত্র চাবি_RSA:
	ক্ষেত্র চাবি_ED25519:
		বিরতি; /* see below */
#অন্যথা /* WITH_OPENSSL */
	ক্ষেত্র চাবি_ED25519:
#endif /* WITH_OPENSSL */
	ক্ষেত্র চাবি_ED25519_SK:
#ifdef WITH_OPENSSL
	ক্ষেত্র চাবি_ECDSA_SK:
#endif /* WITH_OPENSSL */
	ক্ষেত্র চাবি_MLDSA44_ED25519:
		ফেরত sshkey_private_to_blob2(চাবি, blob, passphrase,
		    comment, openssh_format_cipher, openssh_format_rounds);
	পূর্বনির্ধারিত:
		ফেরত SSH_ERR_চাবি_TYPE_UNKNOWN;
	}

#ifdef WITH_OPENSSL
	নির্বাচন (format) {
	ক্ষেত্র SSHKEY_PRIVATE_OPENSSH:
		ফেরত sshkey_private_to_blob2(চাবি, blob, passphrase,
		    comment, openssh_format_cipher, openssh_format_rounds);
	ক্ষেত্র SSHKEY_PRIVATE_PEM:
	ক্ষেত্র SSHKEY_PRIVATE_PKCS8:
		ফেরত sshkey_private_to_blob_pem_pkcs8(চাবি, blob,
		    format, passphrase, comment);
	পূর্বনির্ধারিত:
		ফেরত SSH_ERR_INVALID_ARGUMENT;
	}
#endif /* WITH_OPENSSL */
}

#ifdef WITH_OPENSSL
স্থির পূর্ণসংখ্যা
translate_libcrypto_error(unsigned long pem_err)
{
	পূর্ণসংখ্যা pem_reason = ERR_GET_REASON(pem_err);

	নির্বাচন (ERR_GET_LIB(pem_err)) {
	ক্ষেত্র ERR_LIB_PEM:
		নির্বাচন (pem_reason) {
		ক্ষেত্র PEM_R_BAD_PASSWORD_READ:
#ifdef PEM_R_PROBLEMS_GETTING_PASSWORD
		ক্ষেত্র PEM_R_PROBLEMS_GETTING_PASSWORD:
#endif
#ifdef PEM_R_BAD_DECRYPT
		ক্ষেত্র PEM_R_BAD_DECRYPT:
#endif
			ফেরত SSH_ERR_চাবি_WRONG_PASSPHRASE;
		পূর্বনির্ধারিত:
			ফেরত SSH_ERR_INVALID_FORMAT;
		}
	ক্ষেত্র ERR_LIB_EVP:
		নির্বাচন (pem_reason) {
#ifdef EVP_R_BAD_DECRYPT
		ক্ষেত্র EVP_R_BAD_DECRYPT:
			ফেরত SSH_ERR_চাবি_WRONG_PASSPHRASE;
#endif
#ifdef EVP_R_BN_DECODE_ERROR
		ক্ষেত্র EVP_R_BN_DECODE_ERROR:
#endif
		ক্ষেত্র EVP_R_DECODE_ERROR:
#ifdef EVP_R_PRIVATE_চাবি_DECODE_ERROR
		ক্ষেত্র EVP_R_PRIVATE_চাবি_DECODE_ERROR:
#endif
			ফেরত SSH_ERR_INVALID_FORMAT;
		পূর্বনির্ধারিত:
			ফেরত SSH_ERR_LIBCRYPTO_ERROR;
		}
	ক্ষেত্র ERR_LIB_ASN1:
#ifdef ERR_LIB_OSSL_DECODER
	ক্ষেত্র ERR_LIB_OSSL_DECODER:
#endif
		ফেরত SSH_ERR_INVALID_FORMAT;
	}
	ফেরত SSH_ERR_LIBCRYPTO_ERROR;
}

স্থির শূন্য
clear_libcrypto_errors(শূন্য)
{
	যখন (ERR_get_error() != 0)
		;
}

/*
 * Translate OpenSSL error codes to determine whether
 * passphrase is required/incorrect.
 */
স্থির পূর্ণসংখ্যা
convert_libcrypto_error(শূন্য)
{
	/*
	 * Some password errors are reported at the beginning
	 * of the error queue.
	 */
	যদি (translate_libcrypto_error(ERR_peek_error()) ==
	    SSH_ERR_চাবি_WRONG_PASSPHRASE)
		ফেরত SSH_ERR_চাবি_WRONG_PASSPHRASE;
	ফেরত translate_libcrypto_error(ERR_peek_last_error());
}

স্থির পূর্ণসংখ্যা
pem_passphrase_cb(অক্ষর *buf, পূর্ণসংখ্যা আকার_2, পূর্ণসংখ্যা rwflag, শূন্য *u)
{
	অক্ষর *p = (অক্ষর *)u;
	আকার_t len;

	যদি (p == ফাঁকা || (len = strlen(p)) == 0)
		ফেরত -1;
	যদি (আকার_2 < 0 || len > (আকার_t)আকার_2)
		ফেরত -1;
	memcpy(buf, p, len);
	ফেরত (পূর্ণসংখ্যা)len;
}

স্থির পূর্ণসংখ্যা
sshkey_parse_private_pem_fileblob(কাঠামো sshbuf *blob, পূর্ণসংখ্যা type,
    ধ্রুবক অক্ষর *passphrase, কাঠামো sshkey **keyp)
{
	EVP_PKEY *pk = ফাঁকা;
	কাঠামো sshkey *prv = ফাঁকা;
	BIO *bio = ফাঁকা;
	পূর্ণসংখ্যা r;
	RSA *rsa = ফাঁকা;
	EC_চাবি *ecdsa = ফাঁকা;

	যদি (keyp != ফাঁকা)
		*keyp = ফাঁকা;

	যদি ((bio = BIO_new(BIO_s_mem())) == ফাঁকা || sshbuf_len(blob) > INT_MAX)
		ফেরত SSH_ERR_ALLOC_FAIL;
	যদি (BIO_write(bio, sshbuf_ptr(blob), sshbuf_len(blob)) !=
	    (পূর্ণসংখ্যা)sshbuf_len(blob)) {
		r = SSH_ERR_ALLOC_FAIL;
		যাও out;
	}

	clear_libcrypto_errors();
	যদি ((pk = PEM_read_bio_Private_চাবি(bio, ফাঁকা, pem_passphrase_cb,
	    (অক্ষর *)passphrase)) == ফাঁকা) {
		/*
		 * libcrypto may return various ASN.1 errors when attempting
		 * to parse a key with an incorrect passphrase.
		 * Treat all format errors as "incorrect passphrase" if a
		 * passphrase was supplied.
		 */
		যদি (passphrase != ফাঁকা && *passphrase != '\0')
			r = SSH_ERR_চাবি_WRONG_PASSPHRASE;
		অন্যথা
			r = convert_libcrypto_error();
		যাও out;
	}
	যদি (EVP_PKEY_base_id(pk) == EVP_PKEY_RSA &&
	    (type == চাবি_UNSPEC || type == চাবি_RSA)) {
		যদি ((prv = sshkey_new(চাবি_UNSPEC)) == ফাঁকা) {
			r = SSH_ERR_ALLOC_FAIL;
			যাও out;
		}
		যদি ((rsa = EVP_PKEY_get1_RSA(pk)) == ফাঁকা) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			যাও out;
		}
		prv->type = চাবি_RSA;
#ifdef DEBUG_PK
		RSA_print_fp(stderr, rsa, 8);
#endif
		যদি (RSA_blinding_on(rsa, ফাঁকা) != 1 ||
		    EVP_PKEY_set1_RSA(pk, rsa) != 1) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			যাও out;
		}
		EVP_PKEY_up_ref(pk);
		prv->pkey = pk;
		যদি ((r = sshkey_check_rsa_দৈর্ঘ্য(prv, 0)) != 0)
			যাও out;
	} অন্যথা যদি (EVP_PKEY_base_id(pk) == EVP_PKEY_EC &&
	    (type == চাবি_UNSPEC || type == চাবি_ECDSA)) {
		যদি ((prv = sshkey_new(চাবি_UNSPEC)) == ফাঁকা) {
			r = SSH_ERR_ALLOC_FAIL;
			যাও out;
		}
		যদি ((prv->ecdsa_nid = sshkey_ecdsa_fixup_group(pk)) == -1 ||
		    (ecdsa = EVP_PKEY_get1_EC_চাবি(pk)) == ফাঁকা) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			যাও out;
		}
		prv->type = চাবি_ECDSA;
		যদি (sshkey_curve_nid_to_name(prv->ecdsa_nid) == ফাঁকা ||
		    sshkey_ec_validate_public(EC_চাবি_get0_group(ecdsa),
		    EC_চাবি_get0_public_চাবি(ecdsa)) != 0 ||
		    sshkey_ec_validate_private(ecdsa) != 0) {
			r = SSH_ERR_INVALID_FORMAT;
			যাও out;
		}
		EVP_PKEY_up_ref(pk);
		prv->pkey = pk;
#ifdef DEBUG_PK
		যদি (prv != ফাঁকা && prv->pkey != ফাঁকা)
			sshkey_dump_ec_চাবি(EVP_PKEY_get0_EC_চাবি(prv->pkey));
#endif
#ifdef OPENSSL_HAS_ED25519
	} অন্যথা যদি (EVP_PKEY_base_id(pk) == EVP_PKEY_ED25519 &&
	    (type == চাবি_UNSPEC || type == চাবি_ED25519)) {
		আকার_t len;

		যদি ((prv = sshkey_new(চাবি_UNSPEC)) == ফাঁকা ||
		    (prv->ed25519_sk = calloc(1, ED25519_SK_SZ)) == ফাঁকা ||
		    (prv->ed25519_pk = calloc(1, ED25519_PK_SZ)) == ফাঁকা) {
			r = SSH_ERR_ALLOC_FAIL;
			যাও out;
		}
		prv->type = চাবি_ED25519;
		len = ED25519_PK_SZ;
		যদি (!EVP_PKEY_get_raw_public_চাবি(pk, prv->ed25519_pk, &len)) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			যাও out;
		}
		যদি (len != ED25519_PK_SZ) {
			r = SSH_ERR_INVALID_FORMAT;
			যাও out;
		}
		len = ED25519_SK_SZ - ED25519_PK_SZ;
		যদি (!EVP_PKEY_get_raw_private_চাবি(pk, prv->ed25519_sk, &len)) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			যাও out;
		}
		যদি (len != ED25519_SK_SZ - ED25519_PK_SZ) {
			r = SSH_ERR_INVALID_FORMAT;
			যাও out;
		}
		/* Append the public key to our private key */
		memcpy(prv->ed25519_sk + (ED25519_SK_SZ - ED25519_PK_SZ),
		    prv->ed25519_pk, ED25519_PK_SZ);
#ifdef DEBUG_PK
		sshbuf_dump_তথ্য(prv->ed25519_sk, ED25519_SK_SZ, stderr);
#endif
#endif /* OPENSSL_HAS_ED25519 */
	} অন্যথা {
		r = SSH_ERR_INVALID_FORMAT;
		যাও out;
	}
	r = 0;
	যদি (keyp != ফাঁকা) {
		*keyp = prv;
		prv = ফাঁকা;
	}
 out:
	BIO_free(bio);
	EVP_PKEY_free(pk);
	RSA_free(rsa);
	EC_চাবি_free(ecdsa);
	sshkey_free(prv);
	ফেরত r;
}
#endif /* WITH_OPENSSL */

পূর্ণসংখ্যা
sshkey_parse_private_fileblob_type(কাঠামো sshbuf *blob, পূর্ণসংখ্যা type,
    ধ্রুবক অক্ষর *passphrase, কাঠামো sshkey **keyp, অক্ষর **commentp)
{
	পূর্ণসংখ্যা r = SSH_ERR_INTERNAL_ERROR;

	যদি (keyp != ফাঁকা)
		*keyp = ফাঁকা;
	যদি (commentp != ফাঁকা)
		*commentp = ফাঁকা;

	r = sshkey_parse_private2(blob, type, passphrase, keyp, commentp);
	/* Only fallback to PEM parser if a format error occurred. */
	যদি (r != SSH_ERR_INVALID_FORMAT)
		ফেরত r;
#ifdef WITH_OPENSSL
	ফেরত sshkey_parse_private_pem_fileblob(blob, type,
	    passphrase, keyp);
#অন্যথা
	ফেরত SSH_ERR_INVALID_FORMAT;
#endif /* WITH_OPENSSL */
}

পূর্ণসংখ্যা
sshkey_parse_private_fileblob(কাঠামো sshbuf *বাফার, ধ্রুবক অক্ষর *passphrase,
    কাঠামো sshkey **keyp, অক্ষর **commentp)
{
	যদি (keyp != ফাঁকা)
		*keyp = ফাঁকা;
	যদি (commentp != ফাঁকা)
		*commentp = ফাঁকা;

	ফেরত sshkey_parse_private_fileblob_type(বাফার, চাবি_UNSPEC,
	    passphrase, keyp, commentp);
}

শূন্য
sshkey_sig_details_free(কাঠামো sshkey_sig_details *details)
{
	freezero(details, আকার(*details));
}

পূর্ণসংখ্যা
sshkey_parse_pubkey_from_private_fileblob_type(কাঠামো sshbuf *blob, পূর্ণসংখ্যা type,
    কাঠামো sshkey **pubkeyp)
{
	পূর্ণসংখ্যা r = SSH_ERR_INTERNAL_ERROR;

	যদি (pubkeyp != ফাঁকা)
		*pubkeyp = ফাঁকা;
	/* only new-format private keys bundle a public key inside */
	যদি ((r = sshkey_parse_private2_pubkey(blob, type, pubkeyp)) != 0)
		ফেরত r;
	ফেরত 0;
}
