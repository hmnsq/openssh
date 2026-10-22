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

#شامل "includes.h"

#شامل <sys/types.h>
#شامل <sys/mman.h>
#شامل <netinet/in.h>

#ifdef WITH_OPENSSL
#شامل <openssl/bn.h>
#شامل <openssl/evp.h>
#شامل <openssl/err.h>
#شامل <openssl/pem.h>
#endif

#شامل "crypto_api.h"

#شامل <errno.h>
#شامل <limits.h>
#شامل <stdio.h>
#شامل <stdlib.h>
#شامل <string.h>
#شامل <resolv.h>
#شامل <time.h>
#شامل <util.h>

#شامل "ssh2.h"
#شامل "ssherr.h"
#شامل "misc.h"
#شامل "sshbuf.h"
#شامل "cipher.h"
#شامل "digest.h"
#define SSHKEY_INTERNAL
#شامل "sshkey.h"
#شامل "match.h"
#شامل "ssh-sk.h"
#شامل "ssh-pkcs11.h"

#شامل "openbsd-compat/openssl-compat.h"

/* openssh private key file format */
#define MARK_BEGIN		"-----BEGIN OPENSSH PRIVATE KEY-----\n"
#define MARK_END		"-----END OPENSSH PRIVATE KEY-----\n"
#define MARK_BEGIN_LEN		(اندازه(MARK_BEGIN) - 1)
#define MARK_END_LEN		(اندازه(MARK_END) - 1)
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

ایستا صحیح sshkey_from_blob_internal(ساختار sshbuf *buf,
    ساختار sshkey **keyp, صحیح allow_cert,
    ثابت نویسه *alg_allowlist, ثابت نویسه *ca_sigalg_allowlist);

/* Supported key types */
بیرونی ثابت ساختار sshkey_impl sshkey_ed25519_impl;
بیرونی ثابت ساختار sshkey_impl sshkey_ed25519_cert_impl;
بیرونی ثابت ساختار sshkey_impl sshkey_ed25519_sk_impl;
بیرونی ثابت ساختار sshkey_impl sshkey_ed25519_sk_cert_impl;
# ifdef USE_MLDSA
بیرونی ثابت ساختار sshkey_impl sshkey_mldsa44_ed25519_impl;
بیرونی ثابت ساختار sshkey_impl sshkey_mldsa44_ed25519_cert_impl;
# endif /* USE_MLDSA */
#ifdef WITH_OPENSSL
# ifdef ENABLE_SK
بیرونی ثابت ساختار sshkey_impl sshkey_ecdsa_sk_impl;
بیرونی ثابت ساختار sshkey_impl sshkey_ecdsa_sk_cert_impl;
بیرونی ثابت ساختار sshkey_impl sshkey_ecdsa_sk_webauthn_impl;
بیرونی ثابت ساختار sshkey_impl sshkey_ecdsa_sk_webauthn_cert_impl;
# endif /* ENABLE_SK */
بیرونی ثابت ساختار sshkey_impl sshkey_ecdsa_nistp256_impl;
بیرونی ثابت ساختار sshkey_impl sshkey_ecdsa_nistp256_cert_impl;
بیرونی ثابت ساختار sshkey_impl sshkey_ecdsa_nistp384_impl;
بیرونی ثابت ساختار sshkey_impl sshkey_ecdsa_nistp384_cert_impl;
بیرونی ثابت ساختار sshkey_impl sshkey_ecdsa_nistp521_impl;
بیرونی ثابت ساختار sshkey_impl sshkey_ecdsa_nistp521_cert_impl;
بیرونی ثابت ساختار sshkey_impl sshkey_rsa_impl;
بیرونی ثابت ساختار sshkey_impl sshkey_rsa_cert_impl;
بیرونی ثابت ساختار sshkey_impl sshkey_rsa_sha256_impl;
بیرونی ثابت ساختار sshkey_impl sshkey_rsa_sha256_cert_impl;
بیرونی ثابت ساختار sshkey_impl sshkey_rsa_sha512_impl;
بیرونی ثابت ساختار sshkey_impl sshkey_rsa_sha512_cert_impl;
#endif /* WITH_OPENSSL */

ثابت ساختار sshkey_impl * ثابت keyimpls[] = {
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
	پوچ
};

ایستا ثابت ساختار sshkey_impl *
sshkey_impl_from_type(صحیح type)
{
	صحیح i;

	برای (i = 0; keyimpls[i] != پوچ; i++) {
		اگر (keyimpls[i]->type == type)
			بازگشت keyimpls[i];
	}
	بازگشت پوچ;
}

ایستا ثابت ساختار sshkey_impl *
sshkey_impl_from_type_nid(صحیح type, صحیح nid)
{
	صحیح i;

	برای (i = 0; keyimpls[i] != پوچ; i++) {
		اگر (keyimpls[i]->type == type &&
		    (keyimpls[i]->nid == 0 || keyimpls[i]->nid == nid))
			بازگشت keyimpls[i];
	}
	بازگشت پوچ;
}

ایستا ثابت ساختار sshkey_impl *
sshkey_impl_from_کلید(ثابت ساختار sshkey *k)
{
	اگر (k == پوچ)
		بازگشت پوچ;
	بازگشت sshkey_impl_from_type_nid(k->type, k->ecdsa_nid);
}

ثابت نویسه *
sshkey_type(ثابت ساختار sshkey *k)
{
	ثابت ساختار sshkey_impl *impl;

	اگر ((impl = sshkey_impl_from_کلید(k)) == پوچ)
		بازگشت "unknown";
	بازگشت impl->shortname;
}

ایستا ثابت نویسه *
sshkey_ssh_name_from_type_nid(صحیح type, صحیح nid)
{
	ثابت ساختار sshkey_impl *impl;

	اگر ((impl = sshkey_impl_from_type_nid(type, nid)) == پوچ)
		بازگشت "ssh-unknown";
	بازگشت impl->name;
}

صحیح
sshkey_type_is_cert(صحیح type)
{
	ثابت ساختار sshkey_impl *impl;

	اگر ((impl = sshkey_impl_from_type(type)) == پوچ)
		بازگشت 0;
	بازگشت impl->cert;
}

ثابت نویسه *
sshkey_ssh_name(ثابت ساختار sshkey *k)
{
	بازگشت sshkey_ssh_name_from_type_nid(k->type, k->ecdsa_nid);
}

ثابت نویسه *
sshkey_ssh_name_plain(ثابت ساختار sshkey *k)
{
	بازگشت sshkey_ssh_name_from_type_nid(sshkey_type_plain(k->type),
	    k->ecdsa_nid);
}

ایستا صحیح
type_from_name(ثابت نویسه *name, صحیح allow_short)
{
	صحیح i;
	ثابت ساختار sshkey_impl *impl;

	برای (i = 0; keyimpls[i] != پوچ; i++) {
		impl = keyimpls[i];
		اگر (impl->name != پوچ && strcmp(name, impl->name) == 0)
			بازگشت impl->type;
		/* Only allow shortname matches for plain key types */
		اگر (allow_short && !impl->cert && impl->shortname != پوچ &&
		    strcasecmp(impl->shortname, name) == 0)
			بازگشت impl->type;
	}
	بازگشت کلید_UNSPEC;
}

صحیح
sshkey_type_from_name(ثابت نویسه *name)
{
	بازگشت type_from_name(name, 0);
}

صحیح
sshkey_type_from_shortname(ثابت نویسه *name)
{
	بازگشت type_from_name(name, 1);
}

ایستا صحیح
کلید_type_is_ecdsa_variant(صحیح type)
{
	انتخاب (type) {
	حالت کلید_ECDSA:
	حالت کلید_ECDSA_CERT:
	حالت کلید_ECDSA_SK:
	حالت کلید_ECDSA_SK_CERT:
		بازگشت 1;
	}
	بازگشت 0;
}

صحیح
sshkey_ecdsa_nid_from_name(ثابت نویسه *name)
{
	صحیح i;

	برای (i = 0; keyimpls[i] != پوچ; i++) {
		اگر (!کلید_type_is_ecdsa_variant(keyimpls[i]->type))
			ادامه;
		اگر (keyimpls[i]->name != پوچ &&
		    strcmp(name, keyimpls[i]->name) == 0)
			بازگشت keyimpls[i]->nid;
	}
	بازگشت -1;
}

صحیح
sshkey_match_keyname_to_sigalgs(ثابت نویسه *keyname, ثابت نویسه *sigalgs)
{
	صحیح ktype;

	اگر (sigalgs == پوچ || *sigalgs == '\0' ||
	    (ktype = sshkey_type_from_name(keyname)) == کلید_UNSPEC)
		بازگشت 0;
	وگرنه اگر (ktype == کلید_RSA) {
		بازگشت match_pattern_list("ssh-rsa", sigalgs, 0) == 1 ||
		    match_pattern_list("rsa-sha2-256", sigalgs, 0) == 1 ||
		    match_pattern_list("rsa-sha2-512", sigalgs, 0) == 1;
	} وگرنه اگر (ktype == کلید_RSA_CERT) {
		بازگشت match_pattern_list("ssh-rsa-cert-v01@openssh.com",
		    sigalgs, 0) == 1 ||
		    match_pattern_list("rsa-sha2-256-cert-v01@openssh.com",
		    sigalgs, 0) == 1 ||
		    match_pattern_list("rsa-sha2-512-cert-v01@openssh.com",
		    sigalgs, 0) == 1;
	} وگرنه اگر (ktype == کلید_ECDSA_SK) {
		بازگشت match_pattern_list("sk-ecdsa-sha2-nistp256@openssh.com",
		    sigalgs, 0) == 1 || match_pattern_list(
		    "webauthn-sk-ecdsa-sha2-nistp256@openssh.com",
		    sigalgs, 0) == 1;
	} وگرنه اگر (ktype == کلید_ECDSA_SK_CERT) {
		بازگشت match_pattern_list(
		    "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
		    sigalgs, 0) == 1 || match_pattern_list(
		    "webauthn-sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
		    sigalgs, 0) == 1;
	} وگرنه
		بازگشت match_pattern_list(keyname, sigalgs, 0) == 1;
}

نویسه *
sshkey_alg_list(صحیح certs_only, صحیح plain_only, صحیح include_sigonly, نویسه sep)
{
	نویسه *ret = پوچ;
	size_t i;
	ثابت ساختار sshkey_impl *impl;
	نویسه sep_str[2] = {sep, '\0'};

	برای (i = 0; keyimpls[i] != پوچ; i++) {
		impl = keyimpls[i];
		اگر (impl->name == پوچ)
			ادامه;
		اگر (!include_sigonly && impl->sigonly)
			ادامه;
		اگر ((certs_only && !impl->cert) || (plain_only && impl->cert))
			ادامه;
		xextendf(&ret, sep_str, "%s", impl->name);
	}
	بازگشت ret;
}

صحیح
sshkey_names_valid2(ثابت نویسه *names, صحیح allow_wildcard, صحیح plain_only)
{
	نویسه *s, *cp, *p;
	ثابت ساختار sshkey_impl *impl;
	صحیح i, type;

	اگر (names == پوچ || strcmp(names, "") == 0)
		بازگشت 0;
	اگر ((s = cp = strdup(names)) == پوچ)
		بازگشت 0;
	برای ((p = strsep(&cp, ",")); p && *p != '\0';
	    (p = strsep(&cp, ","))) {
		type = sshkey_type_from_name(p);
		اگر (type == کلید_UNSPEC) {
			اگر (allow_wildcard) {
				/*
				 * Try matching key types against the string.
				 * If any has a positive or negative match then
				 * the component is accepted.
				 */
				impl = پوچ;
				برای (i = 0; keyimpls[i] != پوچ; i++) {
					اگر (match_pattern_list(
					    keyimpls[i]->name, p, 0) != 0) {
						impl = keyimpls[i];
						بشکن;
					}
				}
				اگر (impl != پوچ)
					ادامه;
			}
			آزاد(s);
			بازگشت 0;
		} وگرنه اگر (plain_only && sshkey_type_is_cert(type)) {
			آزاد(s);
			بازگشت 0;
		}
	}
	آزاد(s);
	بازگشت 1;
}

u_int
sshkey_size(ثابت ساختار sshkey *k)
{
	ثابت ساختار sshkey_impl *impl;

	اگر ((impl = sshkey_impl_from_کلید(k)) == پوچ)
		بازگشت 0;
	اگر (impl->funcs->size != پوچ)
		بازگشت impl->funcs->size(k);
	بازگشت impl->keybits;
}

ایستا صحیح
sshkey_type_is_valid_ca(صحیح type)
{
	ثابت ساختار sshkey_impl *impl;

	اگر ((impl = sshkey_impl_from_type(type)) == پوچ)
		بازگشت 0;
	/* All non-certificate types may act as CAs */
	بازگشت !impl->cert;
}

صحیح
sshkey_is_cert(ثابت ساختار sshkey *k)
{
	اگر (k == پوچ)
		بازگشت 0;
	بازگشت sshkey_type_is_cert(k->type);
}

صحیح
sshkey_is_sk(ثابت ساختار sshkey *k)
{
	اگر (k == پوچ)
		بازگشت 0;
	انتخاب (sshkey_type_plain(k->type)) {
	حالت کلید_ECDSA_SK:
	حالت کلید_ED25519_SK:
		بازگشت 1;
	پیشفرض:
		بازگشت 0;
	}
}

/* Return the cert-less equivalent to a certified key type */
صحیح
sshkey_type_plain(صحیح type)
{
	انتخاب (type) {
	حالت کلید_RSA_CERT:
		بازگشت کلید_RSA;
	حالت کلید_ECDSA_CERT:
		بازگشت کلید_ECDSA;
	حالت کلید_ECDSA_SK_CERT:
		بازگشت کلید_ECDSA_SK;
	حالت کلید_ED25519_CERT:
		بازگشت کلید_ED25519;
	حالت کلید_MLDSA44_ED25519_CERT:
		بازگشت کلید_MLDSA44_ED25519;
	حالت کلید_ED25519_SK_CERT:
		بازگشت کلید_ED25519_SK;
	پیشفرض:
		بازگشت type;
	}
}

/* Return the cert equivalent to a plain key type */
ایستا صحیح
sshkey_type_certified(صحیح type)
{
	انتخاب (type) {
	حالت کلید_RSA:
		بازگشت کلید_RSA_CERT;
	حالت کلید_ECDSA:
		بازگشت کلید_ECDSA_CERT;
	حالت کلید_ECDSA_SK:
		بازگشت کلید_ECDSA_SK_CERT;
	حالت کلید_ED25519:
		بازگشت کلید_ED25519_CERT;
	حالت کلید_MLDSA44_ED25519:
		بازگشت کلید_MLDSA44_ED25519_CERT;
	حالت کلید_ED25519_SK:
		بازگشت کلید_ED25519_SK_CERT;
	پیشفرض:
		بازگشت -1;
	}
}

#ifdef WITH_OPENSSL
ایستا ثابت EVP_MD *
ssh_digest_to_md(صحیح hash_alg)
{
	انتخاب (hash_alg) {
	حالت SSH_DIGEST_SHA1:
		بازگشت EVP_sha1();
	حالت SSH_DIGEST_SHA256:
		بازگشت EVP_sha256();
	حالت SSH_DIGEST_SHA384:
		بازگشت EVP_sha384();
	حالت SSH_DIGEST_SHA512:
		بازگشت EVP_sha512();
	}
	بازگشت پوچ;
}

صحیح
sshkey_pkey_digest_sign(EVP_PKEY *pkey, صحیح hash_alg, u_char **sigp,
    size_t *lenp, ثابت u_char *data, size_t datalen)
{
	EVP_MD_CTX *ctx = پوچ;
	u_char *sig = پوچ;
	صحیح ret;
	size_t slen;
	ثابت EVP_MD *evpmd;

	*sigp = پوچ;
	*lenp = 0;

	slen = EVP_PKEY_size(pkey);
	اگر (slen <= 0 || slen > SSHBUF_MAX_BIGNUM ||
	   (evpmd = ssh_digest_to_md(hash_alg)) == پوچ)
		بازگشت SSH_ERR_INVALID_ARGUMENT;

	اگر ((sig = malloc(slen)) == پوچ)
		بازگشت SSH_ERR_ALLOC_FAIL;

	اگر ((ctx = EVP_MD_CTX_new()) == پوچ) {
		ret = SSH_ERR_ALLOC_FAIL;
		برو out;
	}
	اگر (EVP_DigestSignInit(ctx, پوچ, evpmd, پوچ, pkey) != 1 ||
	    EVP_DigestSign(ctx, sig, &slen, data, datalen) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		برو out;
	}

	*sigp = sig;
	*lenp = slen;
	/* Now owned by the caller */
	sig = پوچ;
	ret = 0;

 out:
	EVP_MD_CTX_free(ctx);
	آزاد(sig);
	بازگشت ret;
}

صحیح
sshkey_pkey_digest_verify(EVP_PKEY *pkey, صحیح hash_alg, ثابت u_char *data,
    size_t datalen, u_char *sigbuf, size_t siglen)
{
	EVP_MD_CTX *ctx = پوچ;
	صحیح ret = SSH_ERR_INTERNAL_ERROR;
	ثابت EVP_MD *evpmd;

	اگر ((evpmd = ssh_digest_to_md(hash_alg)) == پوچ)
		بازگشت SSH_ERR_INVALID_ARGUMENT;
	اگر ((ctx = EVP_MD_CTX_new()) == پوچ)
		بازگشت SSH_ERR_ALLOC_FAIL;
	اگر (EVP_DigestVerifyInit(ctx, پوچ, evpmd, پوچ, pkey) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		برو out;
	}
	انتخاب (EVP_DigestVerify(ctx, sigbuf, siglen, data, datalen)) {
	حالت 1:
		ret = 0;
		بشکن;
	حالت 0:
		ret = SSH_ERR_SIGNATURE_INVALID;
		بشکن;
	پیشفرض:
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		بشکن;
	}

 out:
	EVP_MD_CTX_free(ctx);
	بازگشت ret;
}

/* XXX: these are really begging for a table-driven approach */
صحیح
sshkey_curve_name_to_nid(ثابت نویسه *name)
{
	اگر (strcmp(name, "nistp256") == 0)
		بازگشت NID_X9_62_prime256v1;
	وگرنه اگر (strcmp(name, "nistp384") == 0)
		بازگشت NID_secp384r1;
	وگرنه اگر (strcmp(name, "nistp521") == 0)
		بازگشت NID_secp521r1;
	وگرنه
		بازگشت -1;
}

u_int
sshkey_curve_nid_to_bits(صحیح nid)
{
	انتخاب (nid) {
	حالت NID_X9_62_prime256v1:
		بازگشت 256;
	حالت NID_secp384r1:
		بازگشت 384;
	حالت NID_secp521r1:
		بازگشت 521;
	پیشفرض:
		بازگشت 0;
	}
}

صحیح
sshkey_ecdsa_bits_to_nid(صحیح bits)
{
	انتخاب (bits) {
	حالت 256:
		بازگشت NID_X9_62_prime256v1;
	حالت 384:
		بازگشت NID_secp384r1;
	حالت 521:
		بازگشت NID_secp521r1;
	پیشفرض:
		بازگشت -1;
	}
}

ثابت نویسه *
sshkey_curve_nid_to_name(صحیح nid)
{
	انتخاب (nid) {
	حالت NID_X9_62_prime256v1:
		بازگشت "nistp256";
	حالت NID_secp384r1:
		بازگشت "nistp384";
	حالت NID_secp521r1:
		بازگشت "nistp521";
	پیشفرض:
		بازگشت پوچ;
	}
}

صحیح
sshkey_ec_nid_to_hash_alg(صحیح nid)
{
	صحیح kbits = sshkey_curve_nid_to_bits(nid);

	اگر (kbits <= 0)
		بازگشت -1;

	/* RFC5656 section 6.2.1 */
	اگر (kbits <= 256)
		بازگشت SSH_DIGEST_SHA256;
	وگرنه اگر (kbits <= 384)
		بازگشت SSH_DIGEST_SHA384;
	وگرنه
		بازگشت SSH_DIGEST_SHA512;
}
#endif /* WITH_OPENSSL */

ایستا تهی
cert_free(ساختار sshkey_cert *cert)
{
	u_int i;

	اگر (cert == پوچ)
		بازگشت;
	sshbuf_free(cert->certblob);
	sshbuf_free(cert->critical);
	sshbuf_free(cert->extensions);
	آزاد(cert->کلید_id);
	برای (i = 0; i < cert->nprincipals; i++)
		آزاد(cert->principals[i]);
	آزاد(cert->principals);
	sshkey_free(cert->signature_کلید);
	آزاد(cert->signature_type);
	freezero(cert, اندازه(*cert));
}

ایستا ساختار sshkey_cert *
cert_new(تهی)
{
	ساختار sshkey_cert *cert;

	اگر ((cert = calloc(1, اندازه(*cert))) == پوچ)
		بازگشت پوچ;
	اگر ((cert->certblob = sshbuf_new()) == پوچ ||
	    (cert->critical = sshbuf_new()) == پوچ ||
	    (cert->extensions = sshbuf_new()) == پوچ) {
		cert_free(cert);
		بازگشت پوچ;
	}
	cert->کلید_id = پوچ;
	cert->principals = پوچ;
	cert->signature_کلید = پوچ;
	cert->signature_type = پوچ;
	بازگشت cert;
}

ساختار sshkey *
sshkey_new(صحیح type)
{
	ساختار sshkey *k;
	ثابت ساختار sshkey_impl *impl = پوچ;

	اگر (type != کلید_UNSPEC &&
	    (impl = sshkey_impl_from_type(type)) == پوچ)
		بازگشت پوچ;

	/* All non-certificate types may act as CAs */
	اگر ((k = calloc(1, اندازه(*k))) == پوچ)
		بازگشت پوچ;
	k->type = type;
	k->ecdsa_nid = -1;
	اگر (impl != پوچ && impl->funcs->alloc != پوچ) {
		اگر (impl->funcs->alloc(k) != 0) {
			آزاد(k);
			بازگشت پوچ;
		}
	}
	اگر (sshkey_is_cert(k)) {
		اگر ((k->cert = cert_new()) == پوچ) {
			sshkey_free(k);
			بازگشت پوچ;
		}
	}

	بازگشت k;
}

/* Frees common FIDO fields */
تهی
sshkey_sk_cleanup(ساختار sshkey *k)
{
	آزاد(k->sk_application);
	sshbuf_free(k->sk_کلید_handle);
	sshbuf_free(k->sk_reserved);
	k->sk_application = پوچ;
	k->sk_کلید_handle = k->sk_reserved = پوچ;
}

#اگر defined(MAP_CONCEAL)
# define PREKEY_MMAP_FLAG	MAP_CONCEAL
#وگرنهاگر defined(MAP_NOCORE)
# define PREKEY_MMAP_FLAG	MAP_NOCORE
#وگرنه
# define PREKEY_MMAP_FLAG	0
#endif

ایستا صحیح
sshkey_prekey_alloc(u_char **prekeyp, size_t len)
{
#اگر defined(HAVE_MMAP) && defined(MAP_ANON) && defined(MAP_PRIVATE)
	u_char *prekey;

	*prekeyp = پوچ;
	اگر ((prekey = mmap(پوچ, len, PROT_READ|PROT_WRITE,
	    MAP_ANON|MAP_PRIVATE|PREKEY_MMAP_FLAG, -1, 0)) == MAP_FAILED)
		بازگشت SSH_ERR_SYSTEM_ERROR;
#اگر defined(MADV_DONTDUMP) && !defined(MAP_CONCEAL) && !defined(MAP_NOCORE)
	(تهی)madvise(prekey, len, MADV_DONTDUMP);
#endif
	*prekeyp = prekey;
#وگرنه
	*prekeyp = calloc(1, len);
#endif /* HAVE_MMAP et al */
	بازگشت 0;
}

ایستا تهی
sshkey_prekey_free(تهی *prekey, size_t len)
{
#اگر defined(HAVE_MMAP) && defined(MAP_ANON) && defined(MAP_PRIVATE)
	اگر (prekey == پوچ)
		بازگشت;
	munmap(prekey, len);
#وگرنه
	آزاد(prekey);
#endif /* HAVE_MMAP et al */
}

ایستا تهی
sshkey_free_contents(ساختار sshkey *k)
{
	ثابت ساختار sshkey_impl *impl;

	اگر (k == پوچ)
		بازگشت;
	اگر ((k->flags & SSHKEY_FLAG_EXT) != 0)
		pkcs11_کلید_free(k);
	اگر ((impl = sshkey_impl_from_type(k->type)) != پوچ &&
	    impl->funcs->cleanup != پوچ)
		impl->funcs->cleanup(k);
	اگر (sshkey_is_cert(k))
		cert_free(k->cert);
	freezero(k->shielded_private, k->shielded_len);
	sshkey_prekey_free(k->shield_prekey, k->shield_prekey_len);
}

تهی
sshkey_free(ساختار sshkey *k)
{
	sshkey_free_contents(k);
	freezero(k, اندازه(*k));
}

ایستا صحیح
cert_compare(ساختار sshkey_cert *a, ساختار sshkey_cert *b)
{
	اگر (a == پوچ && b == پوچ)
		بازگشت 1;
	اگر (a == پوچ || b == پوچ)
		بازگشت 0;
	اگر (sshbuf_len(a->certblob) != sshbuf_len(b->certblob))
		بازگشت 0;
	اگر (timingsafe_bcmp(sshbuf_ptr(a->certblob), sshbuf_ptr(b->certblob),
	    sshbuf_len(a->certblob)) != 0)
		بازگشت 0;
	بازگشت 1;
}

/* Compares FIDO-specific pubkey fields only */
صحیح
sshkey_sk_fields_equal(ثابت ساختار sshkey *a, ثابت ساختار sshkey *b)
{
	اگر (a->sk_application == پوچ || b->sk_application == پوچ)
		بازگشت 0;
	اگر (strcmp(a->sk_application, b->sk_application) != 0)
		بازگشت 0;
	بازگشت 1;
}

/*
 * Compare public portions of key only, allowing comparisons between
 * certificates and plain keys too.
 */
صحیح
sshkey_equal_public(ثابت ساختار sshkey *a, ثابت ساختار sshkey *b)
{
	ثابت ساختار sshkey_impl *impl;

	اگر (a == پوچ || b == پوچ ||
	    sshkey_type_plain(a->type) != sshkey_type_plain(b->type))
		بازگشت 0;
	اگر ((impl = sshkey_impl_from_type(a->type)) == پوچ)
		بازگشت 0;
	بازگشت impl->funcs->equal(a, b);
}

صحیح
sshkey_equal(ثابت ساختار sshkey *a, ثابت ساختار sshkey *b)
{
	اگر (a == پوچ || b == پوچ || a->type != b->type)
		بازگشت 0;
	اگر (sshkey_is_cert(a)) {
		اگر (!cert_compare(a->cert, b->cert))
			بازگشت 0;
	}
	بازگشت sshkey_equal_public(a, b);
}


/* Serialise common FIDO key parts */
صحیح
sshkey_serialize_sk(ثابت ساختار sshkey *کلید, ساختار sshbuf *b)
{
	صحیح r;

	اگر ((r = sshbuf_put_cstring(b, کلید->sk_application)) != 0)
		بازگشت r;

	بازگشت 0;
}

ایستا صحیح
to_blob_buf(ثابت ساختار sshkey *کلید, ساختار sshbuf *b, صحیح force_plain,
  شمارش sshkey_serialize_rep opts)
{
	صحیح type, ret = SSH_ERR_INTERNAL_ERROR;
	ثابت نویسه *typename;
	ثابت ساختار sshkey_impl *impl;

	اگر (کلید == پوچ)
		بازگشت SSH_ERR_INVALID_ARGUMENT;

	type = force_plain ? sshkey_type_plain(کلید->type) : کلید->type;

	اگر (sshkey_type_is_cert(type)) {
		اگر (کلید->cert == پوچ)
			بازگشت SSH_ERR_EXPECTED_CERT;
		اگر (sshbuf_len(کلید->cert->certblob) == 0)
			بازگشت SSH_ERR_کلید_LACKS_CERTBLOB;
		/* Use the existing blob */
		اگر ((ret = sshbuf_putb(b, کلید->cert->certblob)) != 0)
			بازگشت ret;
		بازگشت 0;
	}
	اگر ((impl = sshkey_impl_from_type(type)) == پوچ)
		بازگشت SSH_ERR_کلید_TYPE_UNKNOWN;

	typename = sshkey_ssh_name_from_type_nid(type, کلید->ecdsa_nid);
	اگر ((ret = sshbuf_put_cstring(b, typename)) != 0)
		بازگشت ret;
	بازگشت impl->funcs->serialize_public(کلید, b, opts);
}

صحیح
sshkey_putb(ثابت ساختار sshkey *کلید, ساختار sshbuf *b)
{
	بازگشت to_blob_buf(کلید, b, 0, SSHKEY_SERIALIZE_DEFAULT);
}

ایستا صحیح
sshkey_puts_opts_internal(ثابت ساختار sshkey *کلید, ساختار sshbuf *b,
    شمارش sshkey_serialize_rep opts, صحیح force_plain)
{
	ساختار sshbuf *tmp;
	صحیح r;

	اگر ((tmp = sshbuf_new()) == پوچ)
		بازگشت SSH_ERR_ALLOC_FAIL;
	r = to_blob_buf(کلید, tmp, force_plain, opts);
	اگر (r == 0)
		r = sshbuf_put_stringb(b, tmp);
	sshbuf_free(tmp);
	بازگشت r;
}

صحیح
sshkey_puts(ثابت ساختار sshkey *کلید, ساختار sshbuf *b)
{
	بازگشت sshkey_puts_opts_internal(کلید, b, SSHKEY_SERIALIZE_DEFAULT, 0);
}

صحیح
sshkey_putb_plain(ثابت ساختار sshkey *کلید, ساختار sshbuf *b)
{
	بازگشت to_blob_buf(کلید, b, 1, SSHKEY_SERIALIZE_DEFAULT);
}

صحیح
sshkey_puts_plain(ثابت ساختار sshkey *کلید, ساختار sshbuf *b)
{
	بازگشت sshkey_puts_opts_internal(کلید, b, SSHKEY_SERIALIZE_DEFAULT, 1);
}

ایستا صحیح
to_blob(ثابت ساختار sshkey *کلید, u_char **blobp, size_t *lenp, صحیح force_plain,
    شمارش sshkey_serialize_rep opts)
{
	صحیح ret = SSH_ERR_INTERNAL_ERROR;
	size_t len;
	ساختار sshbuf *b = پوچ;

	اگر (lenp != پوچ)
		*lenp = 0;
	اگر (blobp != پوچ)
		*blobp = پوچ;
	اگر ((b = sshbuf_new()) == پوچ)
		بازگشت SSH_ERR_ALLOC_FAIL;
	اگر ((ret = to_blob_buf(کلید, b, force_plain, opts)) != 0)
		برو out;
	len = sshbuf_len(b);
	اگر (lenp != پوچ)
		*lenp = len;
	اگر (blobp != پوچ) {
		اگر ((*blobp = malloc(len)) == پوچ) {
			ret = SSH_ERR_ALLOC_FAIL;
			برو out;
		}
		memcpy(*blobp, sshbuf_ptr(b), len);
	}
	ret = 0;
 out:
	sshbuf_free(b);
	بازگشت ret;
}

صحیح
sshkey_to_blob(ثابت ساختار sshkey *کلید, u_char **blobp, size_t *lenp)
{
	بازگشت to_blob(کلید, blobp, lenp, 0, SSHKEY_SERIALIZE_DEFAULT);
}

صحیح
sshkey_plain_to_blob(ثابت ساختار sshkey *کلید, u_char **blobp, size_t *lenp)
{
	بازگشت to_blob(کلید, blobp, lenp, 1, SSHKEY_SERIALIZE_DEFAULT);
}

صحیح
sshkey_fingerprint_raw(ثابت ساختار sshkey *k, صحیح dgst_alg,
    u_char **retp, size_t *lenp)
{
	u_char *blob = پوچ, *ret = پوچ;
	size_t blob_len = 0;
	صحیح r = SSH_ERR_INTERNAL_ERROR;

	اگر (retp != پوچ)
		*retp = پوچ;
	اگر (lenp != پوچ)
		*lenp = 0;
	اگر (ssh_digest_bytes(dgst_alg) == 0) {
		r = SSH_ERR_INVALID_ARGUMENT;
		برو out;
	}
	اگر ((r = to_blob(k, &blob, &blob_len, 1, SSHKEY_SERIALIZE_DEFAULT))
	    != 0)
		برو out;
	اگر ((ret = calloc(1, SSH_DIGEST_MAX_LENGTH)) == پوچ) {
		r = SSH_ERR_ALLOC_FAIL;
		برو out;
	}
	اگر ((r = ssh_digest_memory(dgst_alg, blob, blob_len,
	    ret, SSH_DIGEST_MAX_LENGTH)) != 0)
		برو out;
	/* success */
	اگر (retp != پوچ) {
		*retp = ret;
		ret = پوچ;
	}
	اگر (lenp != پوچ)
		*lenp = ssh_digest_bytes(dgst_alg);
	r = 0;
 out:
	آزاد(ret);
	اگر (blob != پوچ)
		freezero(blob, blob_len);
	بازگشت r;
}

ایستا نویسه *
fingerprint_b64(ثابت نویسه *alg, u_char *dgst_raw, size_t dgst_raw_len)
{
	نویسه *ret;
	size_t plen = strlen(alg) + 1;
	size_t rlen = ((dgst_raw_len + 2) / 3) * 4 + plen + 1;

	اگر (dgst_raw_len > 65536 || (ret = calloc(1, rlen)) == پوچ)
		بازگشت پوچ;
	strlcpy(ret, alg, rlen);
	strlcat(ret, ":", rlen);
	اگر (dgst_raw_len == 0)
		بازگشت ret;
	اگر (b64_ntop(dgst_raw, dgst_raw_len, ret + plen, rlen - plen) == -1) {
		freezero(ret, rlen);
		بازگشت پوچ;
	}
	/* Trim padding characters from end */
	ret[strcspn(ret, "=")] = '\0';
	بازگشت ret;
}

ایستا نویسه *
fingerprint_hex(ثابت نویسه *alg, u_char *dgst_raw, size_t dgst_raw_len)
{
	نویسه *retval, hex[5];
	size_t i, rlen = dgst_raw_len * 3 + strlen(alg) + 2;

	اگر (dgst_raw_len > 65536 || (retval = calloc(1, rlen)) == پوچ)
		بازگشت پوچ;
	strlcpy(retval, alg, rlen);
	strlcat(retval, ":", rlen);
	برای (i = 0; i < dgst_raw_len; i++) {
		snprintf(hex, اندازه(hex), "%s%02x",
		    i > 0 ? ":" : "", dgst_raw[i]);
		strlcat(retval, hex, rlen);
	}
	بازگشت retval;
}

ایستا نویسه *
fingerprint_bubblebabble(u_char *dgst_raw, size_t dgst_raw_len)
{
	نویسه vowels[] = { 'a', 'e', 'i', 'o', 'u', 'y' };
	نویسه consonants[] = { 'b', 'c', 'd', 'f', 'g', 'h', 'k', 'l', 'm',
	    'n', 'p', 'r', 's', 't', 'v', 'z', 'x' };
	u_int i, j = 0, rounds, seed = 1;
	نویسه *retval;

	rounds = (dgst_raw_len / 2) + 1;
	اگر ((retval = calloc(rounds, 6)) == پوچ)
		بازگشت پوچ;
	retval[j++] = 'x';
	برای (i = 0; i < rounds; i++) {
		u_int idx0, idx1, idx2, idx3, idx4;
		اگر ((i + 1 < rounds) || (dgst_raw_len % 2 != 0)) {
			idx0 = (((((u_int)(dgst_raw[2 * i])) >> 6) & 3) +
			    seed) % 6;
			idx1 = (((u_int)(dgst_raw[2 * i])) >> 2) & 15;
			idx2 = ((((u_int)(dgst_raw[2 * i])) & 3) +
			    (seed / 6)) % 6;
			retval[j++] = vowels[idx0];
			retval[j++] = consonants[idx1];
			retval[j++] = vowels[idx2];
			اگر ((i + 1) < rounds) {
				idx3 = (((u_int)(dgst_raw[(2 * i) + 1])) >> 4) & 15;
				idx4 = (((u_int)(dgst_raw[(2 * i) + 1]))) & 15;
				retval[j++] = consonants[idx3];
				retval[j++] = '-';
				retval[j++] = consonants[idx4];
				seed = ((seed * 5) +
				    ((((u_int)(dgst_raw[2 * i])) * 7) +
				    ((u_int)(dgst_raw[(2 * i) + 1])))) % 36;
			}
		} وگرنه {
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
	بازگشت retval;
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
ایستا نویسه *
fingerprint_randomart(ثابت نویسه *alg, u_char *dgst_raw, size_t dgst_raw_len,
    ثابت ساختار sshkey *k)
{
	/*
	 * Chars to be used after each other every time the worm
	 * intersects with itself.  Matter of taste.
	 */
	نویسه	*augmentation_string = " .o+=*BOX@%&#/^SE";
	نویسه	*retval, *p, title[FLDSIZE_X], hash[FLDSIZE_X];
	u_char	 field[FLDSIZE_X][FLDSIZE_Y];
	size_t	 i, tlen, hlen;
	u_int	 b;
	صحیح	 x, y, r;
	size_t	 len = strlen(augmentation_string) - 1;

	اگر ((retval = calloc((FLDSIZE_X + 3), (FLDSIZE_Y + 2))) == پوچ)
		بازگشت پوچ;

	/* initialize field */
	memset(field, 0, FLDSIZE_X * FLDSIZE_Y * اندازه(نویسه));
	x = FLDSIZE_X / 2;
	y = FLDSIZE_Y / 2;

	/* process raw key */
	برای (i = 0; i < dgst_raw_len; i++) {
		صحیح درون_داد;
		/* each byte conveys four 2-bit move commands */
		درون_داد = dgst_raw[i];
		برای (b = 0; b < 4; b++) {
			/* evaluate 2 bit, rest is shifted later */
			x += (درون_داد & 0x1) ? 1 : -1;
			y += (درون_داد & 0x2) ? 1 : -1;

			/* assure we are still in bounds */
			x = MAXIMUM(x, 0);
			y = MAXIMUM(y, 0);
			x = MINIMUM(x, FLDSIZE_X - 1);
			y = MINIMUM(y, FLDSIZE_Y - 1);

			/* augment the field */
			اگر (field[x][y] < len - 2)
				field[x][y]++;
			درون_داد = درون_داد >> 2;
		}
	}

	/* mark starting point and end point*/
	field[FLDSIZE_X / 2][FLDSIZE_Y / 2] = len - 1;
	field[x][y] = len;

	/* assemble title */
	r = snprintf(title, اندازه(title), "[%s %u]",
		sshkey_type(k), sshkey_size(k));
	/* If [type size] won't fit, then try [type]; fits "[ED25519-CERT]" */
	اگر (r < 0 || r > (صحیح)اندازه(title))
		r = snprintf(title, اندازه(title), "[%s]", sshkey_type(k));
	tlen = (r <= 0) ? 0 : strlen(title);

	/* assemble hash ID. */
	r = snprintf(hash, اندازه(hash), "[%s]", alg);
	hlen = (r <= 0) ? 0 : strlen(hash);

	/* output upper border */
	p = retval;
	*p++ = '+';
	برای (i = 0; i < (FLDSIZE_X - tlen) / 2; i++)
		*p++ = '-';
	memcpy(p, title, tlen);
	p += tlen;
	برای (i += tlen; i < FLDSIZE_X; i++)
		*p++ = '-';
	*p++ = '+';
	*p++ = '\n';

	/* output content */
	برای (y = 0; y < FLDSIZE_Y; y++) {
		*p++ = '|';
		برای (x = 0; x < FLDSIZE_X; x++)
			*p++ = augmentation_string[MINIMUM(field[x][y], len)];
		*p++ = '|';
		*p++ = '\n';
	}

	/* output lower border */
	*p++ = '+';
	برای (i = 0; i < (FLDSIZE_X - hlen) / 2; i++)
		*p++ = '-';
	memcpy(p, hash, hlen);
	p += hlen;
	برای (i += hlen; i < FLDSIZE_X; i++)
		*p++ = '-';
	*p++ = '+';

	بازگشت retval;
}

نویسه *
sshkey_fingerprint(ثابت ساختار sshkey *k, صحیح dgst_alg,
    شمارش sshkey_fp_rep dgst_rep)
{
	نویسه *retval = پوچ;
	u_char *dgst_raw;
	size_t dgst_raw_len;

	اگر (sshkey_fingerprint_raw(k, dgst_alg, &dgst_raw, &dgst_raw_len) != 0)
		بازگشت پوچ;
	انتخاب (dgst_rep) {
	حالت SSH_FP_DEFAULT:
		اگر (dgst_alg == SSH_DIGEST_MD5) {
			retval = fingerprint_hex(ssh_digest_alg_name(dgst_alg),
			    dgst_raw, dgst_raw_len);
		} وگرنه {
			retval = fingerprint_b64(ssh_digest_alg_name(dgst_alg),
			    dgst_raw, dgst_raw_len);
		}
		بشکن;
	حالت SSH_FP_HEX:
		retval = fingerprint_hex(ssh_digest_alg_name(dgst_alg),
		    dgst_raw, dgst_raw_len);
		بشکن;
	حالت SSH_FP_BASE64:
		retval = fingerprint_b64(ssh_digest_alg_name(dgst_alg),
		    dgst_raw, dgst_raw_len);
		بشکن;
	حالت SSH_FP_BUBBLEBABBLE:
		retval = fingerprint_bubblebabble(dgst_raw, dgst_raw_len);
		بشکن;
	حالت SSH_FP_RANDOMART:
		retval = fingerprint_randomart(ssh_digest_alg_name(dgst_alg),
		    dgst_raw, dgst_raw_len, k);
		بشکن;
	پیشفرض:
		freezero(dgst_raw, dgst_raw_len);
		بازگشت پوچ;
	}
	freezero(dgst_raw, dgst_raw_len);
	بازگشت retval;
}

ایستا صحیح
peek_type_nid(ثابت نویسه *s, size_t l, صحیح *nid)
{
	ثابت ساختار sshkey_impl *impl;
	صحیح i;

	برای (i = 0; keyimpls[i] != پوچ; i++) {
		impl = keyimpls[i];
		اگر (impl->name == پوچ || strlen(impl->name) != l)
			ادامه;
		اگر (memcmp(s, impl->name, l) == 0) {
			*nid = -1;
			اگر (کلید_type_is_ecdsa_variant(impl->type))
				*nid = impl->nid;
			بازگشت impl->type;
		}
	}
	بازگشت کلید_UNSPEC;
}

/* XXX this can now be made const char * */
صحیح
sshkey_read(ساختار sshkey *ret, نویسه **cpp)
{
	ساختار sshkey *k;
	نویسه *cp, *blobcopy;
	size_t space;
	صحیح r, type, curve_nid = -1;
	ساختار sshbuf *blob;

	اگر (ret == پوچ)
		بازگشت SSH_ERR_INVALID_ARGUMENT;
	اگر (ret->type != کلید_UNSPEC && sshkey_impl_from_type(ret->type) == پوچ)
		بازگشت SSH_ERR_INVALID_ARGUMENT;

	/* Decode type */
	cp = *cpp;
	space = strcspn(cp, " \t");
	اگر (space == strlen(cp))
		بازگشت SSH_ERR_INVALID_FORMAT;
	اگر ((type = peek_type_nid(cp, space, &curve_nid)) == کلید_UNSPEC)
		بازگشت SSH_ERR_INVALID_FORMAT;

	/* skip whitespace */
	برای (cp += space; *cp == ' ' || *cp == '\t'; cp++)
		;
	اگر (*cp == '\0')
		بازگشت SSH_ERR_INVALID_FORMAT;
	اگر (ret->type != کلید_UNSPEC && ret->type != type)
		بازگشت SSH_ERR_کلید_TYPE_MISMATCH;
	اگر ((blob = sshbuf_new()) == پوچ)
		بازگشت SSH_ERR_ALLOC_FAIL;

	/* find end of keyblob and decode */
	space = strcspn(cp, " \t");
	اگر ((blobcopy = strndup(cp, space)) == پوچ) {
		sshbuf_free(blob);
		بازگشت SSH_ERR_ALLOC_FAIL;
	}
	اگر ((r = sshbuf_b64tod(blob, blobcopy)) != 0) {
		آزاد(blobcopy);
		sshbuf_free(blob);
		بازگشت r;
	}
	آزاد(blobcopy);
	اگر ((r = sshkey_fromb(blob, &k)) != 0) {
		sshbuf_free(blob);
		بازگشت r;
	}
	sshbuf_free(blob);

	/* skip whitespace and leave cp at start of comment */
	برای (cp += space; *cp == ' ' || *cp == '\t'; cp++)
		;

	/* ensure type of blob matches type at start of line */
	اگر (k->type != type) {
		sshkey_free(k);
		بازگشت SSH_ERR_کلید_TYPE_MISMATCH;
	}
	اگر (کلید_type_is_ecdsa_variant(type) && curve_nid != k->ecdsa_nid) {
		sshkey_free(k);
		بازگشت SSH_ERR_EC_CURVE_MISMATCH;
	}

	/* Fill in ret from parsed key */
	sshkey_free_contents(ret);
	*ret = *k;
	freezero(k, اندازه(*k));

	/* success */
	*cpp = cp;
	بازگشت 0;
}

صحیح
sshkey_to_base64(ثابت ساختار sshkey *کلید, نویسه **b64p)
{
	صحیح r = SSH_ERR_INTERNAL_ERROR;
	ساختار sshbuf *b = پوچ;
	نویسه *uu = پوچ;

	اگر (b64p != پوچ)
		*b64p = پوچ;
	اگر ((b = sshbuf_new()) == پوچ)
		بازگشت SSH_ERR_ALLOC_FAIL;
	اگر ((r = sshkey_putb(کلید, b)) != 0)
		برو out;
	اگر ((uu = sshbuf_dtob64_string(b, 0)) == پوچ) {
		r = SSH_ERR_ALLOC_FAIL;
		برو out;
	}
	/* Success */
	اگر (b64p != پوچ) {
		*b64p = uu;
		uu = پوچ;
	}
	r = 0;
 out:
	sshbuf_free(b);
	آزاد(uu);
	بازگشت r;
}

صحیح
sshkey_format_text(ثابت ساختار sshkey *کلید, ساختار sshbuf *b)
{
	صحیح r = SSH_ERR_INTERNAL_ERROR;
	نویسه *uu = پوچ;

	اگر ((r = sshkey_to_base64(کلید, &uu)) != 0)
		برو out;
	اگر ((r = sshbuf_putf(b, "%s %s",
	    sshkey_ssh_name(کلید), uu)) != 0)
		برو out;
	r = 0;
 out:
	آزاد(uu);
	بازگشت r;
}

صحیح
sshkey_write(ثابت ساختار sshkey *کلید, FILE *f)
{
	ساختار sshbuf *b = پوچ;
	صحیح r = SSH_ERR_INTERNAL_ERROR;

	اگر ((b = sshbuf_new()) == پوچ)
		بازگشت SSH_ERR_ALLOC_FAIL;
	اگر ((r = sshkey_format_text(کلید, b)) != 0)
		برو out;
	اگر (fwrite(sshbuf_ptr(b), sshbuf_len(b), 1, f) != 1) {
		اگر (feof(f))
			errno = EPIPE;
		r = SSH_ERR_SYSTEM_ERROR;
		برو out;
	}
	/* Success */
	r = 0;
 out:
	sshbuf_free(b);
	بازگشت r;
}

ثابت نویسه *
sshkey_cert_type(ثابت ساختار sshkey *k)
{
	انتخاب (k->cert->type) {
	حالت SSH2_CERT_TYPE_USER:
		بازگشت "user";
	حالت SSH2_CERT_TYPE_HOST:
		بازگشت "host";
	پیشفرض:
		بازگشت "unknown";
	}
}

صحیح
sshkey_check_rsa_length(ثابت ساختار sshkey *k, صحیح min_size)
{
#ifdef WITH_OPENSSL
	صحیح nbits;

	اگر (k == پوچ || k->pkey == پوچ ||
	    (k->type != کلید_RSA && k->type != کلید_RSA_CERT))
		بازگشت 0;
	nbits = EVP_PKEY_bits(k->pkey);
	اگر (nbits < SSH_RSA_MINIMUM_MODULUS_SIZE ||
	    (min_size > 0 && nbits < min_size))
		بازگشت SSH_ERR_کلید_LENGTH;
#endif /* WITH_OPENSSL */
	بازگشت 0;
}

#ifdef WITH_OPENSSL
صحیح
sshkey_ecdsa_کلید_to_nid(ثابت EC_کلید *k)
{
	ثابت EC_GROUP *g;
	صحیح nid;

	اگر (k == پوچ || (g = EC_کلید_get0_group(k)) == پوچ)
		بازگشت -1;
	اگر ((nid = EC_GROUP_get_curve_name(g)) <= 0)
		بازگشت -1;
	بازگشت nid;
}

صحیح
sshkey_ecdsa_pkey_to_nid(EVP_PKEY *pkey)
{
	بازگشت sshkey_ecdsa_کلید_to_nid(EVP_PKEY_get0_EC_کلید(pkey));
}
#endif /* WITH_OPENSSL */

صحیح
sshkey_generate(صحیح type, u_int bits, ساختار sshkey **keyp)
{
	ساختار sshkey *k;
	صحیح ret = SSH_ERR_INTERNAL_ERROR;
	ثابت ساختار sshkey_impl *impl;

	اگر (keyp == پوچ || sshkey_type_is_cert(type))
		بازگشت SSH_ERR_INVALID_ARGUMENT;
	*keyp = پوچ;
	اگر ((impl = sshkey_impl_from_type(type)) == پوچ)
		بازگشت SSH_ERR_کلید_TYPE_UNKNOWN;
	اگر (impl->funcs->generate == پوچ)
		بازگشت SSH_ERR_FEATURE_UNSUPPORTED;
	اگر ((k = sshkey_new(کلید_UNSPEC)) == پوچ)
		بازگشت SSH_ERR_ALLOC_FAIL;
	k->type = type;
	اگر ((ret = impl->funcs->generate(k, bits)) != 0) {
		sshkey_free(k);
		بازگشت ret;
	}
	/* success */
	*keyp = k;
	بازگشت 0;
}

صحیح
sshkey_cert_copy(ثابت ساختار sshkey *from_کلید, ساختار sshkey *to_کلید)
{
	u_int i;
	ثابت ساختار sshkey_cert *from;
	ساختار sshkey_cert *to;
	صحیح r = SSH_ERR_INTERNAL_ERROR;

	اگر (to_کلید == پوچ || (from = from_کلید->cert) == پوچ)
		بازگشت SSH_ERR_INVALID_ARGUMENT;

	اگر ((to = cert_new()) == پوچ)
		بازگشت SSH_ERR_ALLOC_FAIL;

	اگر ((r = sshbuf_putb(to->certblob, from->certblob)) != 0 ||
	    (r = sshbuf_putb(to->critical, from->critical)) != 0 ||
	    (r = sshbuf_putb(to->extensions, from->extensions)) != 0)
		برو out;

	to->serial = from->serial;
	to->type = from->type;
	اگر (from->کلید_id == پوچ)
		to->کلید_id = پوچ;
	وگرنه اگر ((to->کلید_id = strdup(from->کلید_id)) == پوچ) {
		r = SSH_ERR_ALLOC_FAIL;
		برو out;
	}
	to->valid_after = from->valid_after;
	to->valid_before = from->valid_before;
	اگر (from->signature_کلید == پوچ)
		to->signature_کلید = پوچ;
	وگرنه اگر ((r = sshkey_from_private(from->signature_کلید,
	    &to->signature_کلید)) != 0)
		برو out;
	اگر (from->signature_type != پوچ &&
	    (to->signature_type = strdup(from->signature_type)) == پوچ) {
		r = SSH_ERR_ALLOC_FAIL;
		برو out;
	}
	اگر (from->nprincipals > SSHKEY_CERT_MAX_PRINCIPALS) {
		r = SSH_ERR_INVALID_ARGUMENT;
		برو out;
	}
	اگر (from->nprincipals > 0) {
		اگر ((to->principals = calloc(from->nprincipals,
		    اندازه(*to->principals))) == پوچ) {
			r = SSH_ERR_ALLOC_FAIL;
			برو out;
		}
		برای (i = 0; i < from->nprincipals; i++) {
			to->principals[i] = strdup(from->principals[i]);
			اگر (to->principals[i] == پوچ) {
				to->nprincipals = i;
				r = SSH_ERR_ALLOC_FAIL;
				برو out;
			}
		}
	}
	to->nprincipals = from->nprincipals;

	/* success */
	cert_free(to_کلید->cert);
	to_کلید->cert = to;
	to = پوچ;
	r = 0;
 out:
	cert_free(to);
	بازگشت r;
}

صحیح
sshkey_copy_public_sk(ثابت ساختار sshkey *from, ساختار sshkey *to)
{
	/* Append security-key application string */
	اگر ((to->sk_application = strdup(from->sk_application)) == پوچ)
		بازگشت SSH_ERR_ALLOC_FAIL;
	بازگشت 0;
}

صحیح
sshkey_from_private(ثابت ساختار sshkey *k, ساختار sshkey **pkp)
{
	ساختار sshkey *n = پوچ;
	صحیح r = SSH_ERR_INTERNAL_ERROR;
	ثابت ساختار sshkey_impl *impl;

	*pkp = پوچ;
	اگر ((impl = sshkey_impl_from_کلید(k)) == پوچ)
		بازگشت SSH_ERR_کلید_TYPE_UNKNOWN;
	اگر ((n = sshkey_new(k->type)) == پوچ) {
		r = SSH_ERR_ALLOC_FAIL;
		برو out;
	}
	اگر ((r = impl->funcs->copy_public(k, n)) != 0)
		برو out;
	اگر (sshkey_is_cert(k) && (r = sshkey_cert_copy(k, n)) != 0)
		برو out;
	/* success */
	*pkp = n;
	n = پوچ;
	r = 0;
 out:
	sshkey_free(n);
	بازگشت r;
}

صحیح
sshkey_is_shielded(ساختار sshkey *k)
{
	بازگشت k != پوچ && k->shielded_private != پوچ;
}

صحیح
sshkey_shield_private(ساختار sshkey *k)
{
	ساختار sshbuf *prvbuf = پوچ;
	u_char *prekey = پوچ, *enc = پوچ, keyiv[SSH_DIGEST_MAX_LENGTH];
	ساختار sshcipher_ctx *cctx = پوچ;
	ثابت ساختار sshcipher *cipher;
	size_t i, enclen = 0;
	ساختار sshkey *kswap = پوچ, tmp;
	صحیح r = SSH_ERR_INTERNAL_ERROR;

#ifdef DEBUG_PK
	fprintf(stderr, "%s: entering for %s\n", __func__, sshkey_ssh_name(k));
#endif
	اگر ((cipher = cipher_by_name(SSHKEY_SHIELD_CIPHER)) == پوچ) {
		r = SSH_ERR_INVALID_ARGUMENT;
		برو out;
	}
	اگر (cipher_keylen(cipher) + cipher_ivlen(cipher) >
	    ssh_digest_bytes(SSHKEY_SHIELD_PREKEY_HASH)) {
		r = SSH_ERR_INTERNAL_ERROR;
		برو out;
	}

	/* Prepare a random pre-key, and from it an ephemeral key */
	اگر ((r = sshkey_prekey_alloc(&prekey, SSHKEY_SHIELD_PREKEY_LEN)) != 0)
		برو out;
	arc4random_buf(prekey, SSHKEY_SHIELD_PREKEY_LEN);
	اگر ((r = ssh_digest_memory(SSHKEY_SHIELD_PREKEY_HASH,
	    prekey, SSHKEY_SHIELD_PREKEY_LEN,
	    keyiv, SSH_DIGEST_MAX_LENGTH)) != 0)
		برو out;
#ifdef DEBUG_PK
	fprintf(stderr, "%s: key+iv\n", __func__);
	sshbuf_dump_data(keyiv, ssh_digest_bytes(SSHKEY_SHIELD_PREKEY_HASH),
	    stderr);
#endif
	اگر ((r = cipher_init(&cctx, cipher, keyiv, cipher_keylen(cipher),
	    keyiv + cipher_keylen(cipher), cipher_ivlen(cipher), 1)) != 0)
		برو out;

	/* Serialise and encrypt the private key using the ephemeral key */
	اگر ((prvbuf = sshbuf_new()) == پوچ) {
		r = SSH_ERR_ALLOC_FAIL;
		برو out;
	}
	اگر (sshkey_is_shielded(k) && (r = sshkey_unshield_private(k)) != 0)
		برو out;
	اگر ((r = sshkey_private_serialize(k, prvbuf)) != 0)
		برو out;
	/* pad to cipher blocksize */
	i = 0;
	وقتی (sshbuf_len(prvbuf) % cipher_blocksize(cipher)) {
		اگر ((r = sshbuf_put_u8(prvbuf, ++i & 0xff)) != 0)
			برو out;
	}
#ifdef DEBUG_PK
	fprintf(stderr, "%s: serialised\n", __func__);
	sshbuf_dump(prvbuf, stderr);
#endif
	/* encrypt */
	enclen = sshbuf_len(prvbuf);
	اگر ((enc = malloc(enclen)) == پوچ) {
		r = SSH_ERR_ALLOC_FAIL;
		برو out;
	}
	اگر ((r = cipher_crypt(cctx, 0, enc,
	    sshbuf_ptr(prvbuf), sshbuf_len(prvbuf), 0, 0)) != 0)
		برو out;
#ifdef DEBUG_PK
	fprintf(stderr, "%s: encrypted\n", __func__);
	sshbuf_dump_data(enc, enclen, stderr);
#endif

	/* Make a scrubbed, public-only copy of our private key argument */
	اگر ((r = sshkey_from_private(k, &kswap)) != 0)
		برو out;

	/* Swap the private key out (it will be destroyed below) */
	tmp = *kswap;
	*kswap = *k;
	*k = tmp;

	/* Insert the shielded key into our argument */
	k->shielded_private = enc;
	k->shielded_len = enclen;
	k->shield_prekey = prekey;
	k->shield_prekey_len = SSHKEY_SHIELD_PREKEY_LEN;
	enc = prekey = پوچ; /* transferred */
	enclen = 0;

	/* preserve key fields that are required for correct operation */
	k->sk_flags = kswap->sk_flags;

	/* success */
	r = 0;

 out:
	/* XXX behaviour on error - invalidate original private key? */
	cipher_free(cctx);
	explicit_bzero(keyiv, اندازه(keyiv));
	explicit_bzero(&tmp, اندازه(tmp));
	freezero(enc, enclen);
	sshkey_prekey_free(prekey, SSHKEY_SHIELD_PREKEY_LEN);
	sshkey_free(kswap);
	sshbuf_free(prvbuf);
	بازگشت r;
}

/* Check deterministic padding after private key */
ایستا صحیح
private2_check_padding(ساختار sshbuf *decrypted)
{
	u_char pad;
	size_t i;
	صحیح r;

	i = 0;
	وقتی (sshbuf_len(decrypted)) {
		اگر ((r = sshbuf_get_u8(decrypted, &pad)) != 0)
			برو out;
		اگر (pad != (++i & 0xff)) {
			r = SSH_ERR_INVALID_FORMAT;
			برو out;
		}
	}
	/* success */
	r = 0;
 out:
	explicit_bzero(&pad, اندازه(pad));
	explicit_bzero(&i, اندازه(i));
	بازگشت r;
}

صحیح
sshkey_unshield_private(ساختار sshkey *k)
{
	ساختار sshbuf *prvbuf = پوچ;
	u_char *cp, keyiv[SSH_DIGEST_MAX_LENGTH];
	ساختار sshcipher_ctx *cctx = پوچ;
	ثابت ساختار sshcipher *cipher;
	ساختار sshkey *kswap = پوچ, tmp;
	صحیح r = SSH_ERR_INTERNAL_ERROR;

#ifdef DEBUG_PK
	fprintf(stderr, "%s: entering for %s\n", __func__, sshkey_ssh_name(k));
#endif
	اگر (!sshkey_is_shielded(k))
		بازگشت 0; /* nothing to do */

	اگر ((cipher = cipher_by_name(SSHKEY_SHIELD_CIPHER)) == پوچ) {
		r = SSH_ERR_INVALID_ARGUMENT;
		برو out;
	}
	اگر (cipher_keylen(cipher) + cipher_ivlen(cipher) >
	    ssh_digest_bytes(SSHKEY_SHIELD_PREKEY_HASH)) {
		r = SSH_ERR_INTERNAL_ERROR;
		برو out;
	}
	/* check size of shielded key blob */
	اگر (k->shielded_len < cipher_blocksize(cipher) ||
	    (k->shielded_len % cipher_blocksize(cipher)) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		برو out;
	}

	/* Calculate the ephemeral key from the prekey */
	اگر ((r = ssh_digest_memory(SSHKEY_SHIELD_PREKEY_HASH,
	    k->shield_prekey, k->shield_prekey_len,
	    keyiv, SSH_DIGEST_MAX_LENGTH)) != 0)
		برو out;
	اگر ((r = cipher_init(&cctx, cipher, keyiv, cipher_keylen(cipher),
	    keyiv + cipher_keylen(cipher), cipher_ivlen(cipher), 0)) != 0)
		برو out;
#ifdef DEBUG_PK
	fprintf(stderr, "%s: key+iv\n", __func__);
	sshbuf_dump_data(keyiv, ssh_digest_bytes(SSHKEY_SHIELD_PREKEY_HASH),
	    stderr);
#endif

	/* Decrypt and parse the shielded private key using the ephemeral key */
	اگر ((prvbuf = sshbuf_new()) == پوچ) {
		r = SSH_ERR_ALLOC_FAIL;
		برو out;
	}
	اگر ((r = sshbuf_reserve(prvbuf, k->shielded_len, &cp)) != 0)
		برو out;
	/* decrypt */
#ifdef DEBUG_PK
	fprintf(stderr, "%s: encrypted\n", __func__);
	sshbuf_dump_data(k->shielded_private, k->shielded_len, stderr);
#endif
	اگر ((r = cipher_crypt(cctx, 0, cp,
	    k->shielded_private, k->shielded_len, 0, 0)) != 0)
		برو out;
#ifdef DEBUG_PK
	fprintf(stderr, "%s: serialised\n", __func__);
	sshbuf_dump(prvbuf, stderr);
#endif
	/* Parse private key */
	اگر ((r = sshkey_private_deserialize(prvbuf, &kswap)) != 0)
		برو out;

	اگر ((r = private2_check_padding(prvbuf)) != 0)
		برو out;

	/* Swap the parsed key back into place */
	tmp = *kswap;
	*kswap = *k;
	*k = tmp;

	/* success */
	r = 0;

 out:
	cipher_free(cctx);
	explicit_bzero(keyiv, اندازه(keyiv));
	explicit_bzero(&tmp, اندازه(tmp));
	sshkey_free(kswap);
	sshbuf_free(prvbuf);
	بازگشت r;
}

ایستا صحیح
cert_parse(ساختار sshbuf *b, ساختار sshkey *کلید, ساختار sshbuf *certbuf,
    ثابت نویسه *ca_sigalg_allowlist)
{
	ساختار sshbuf *principals = پوچ, *crit = پوچ;
	ساختار sshbuf *exts = پوچ, *ca = پوچ;
	u_char *sig = پوچ;
	نویسه *sigtype = پوچ;
	size_t signed_len = 0, slen = 0, kidlen = 0;
	صحیح ret = SSH_ERR_INTERNAL_ERROR;

	/* Copy the entire key blob for verification and later serialisation */
	اگر ((ret = sshbuf_putb(کلید->cert->certblob, certbuf)) != 0)
		بازگشت ret;

	/* Parse body of certificate up to signature */
	اگر ((ret = sshbuf_get_u64(b, &کلید->cert->serial)) != 0 ||
	    (ret = sshbuf_get_u32(b, &کلید->cert->type)) != 0 ||
	    (ret = sshbuf_get_cstring(b, &کلید->cert->کلید_id, &kidlen)) != 0 ||
	    (ret = sshbuf_froms(b, &principals)) != 0 ||
	    (ret = sshbuf_get_u64(b, &کلید->cert->valid_after)) != 0 ||
	    (ret = sshbuf_get_u64(b, &کلید->cert->valid_before)) != 0 ||
	    (ret = sshbuf_froms(b, &crit)) != 0 ||
	    (ret = sshbuf_froms(b, &exts)) != 0 ||
	    (ret = sshbuf_get_string_direct(b, پوچ, پوچ)) != 0 ||
	    (ret = sshbuf_froms(b, &ca)) != 0) {
		/* XXX debug print error for ret */
		ret = SSH_ERR_INVALID_FORMAT;
		برو out;
	}

	/* Signature is left in the buffer so we can calculate this length */
	signed_len = sshbuf_len(کلید->cert->certblob) - sshbuf_len(b);

	اگر ((ret = sshbuf_get_string(b, &sig, &slen)) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		برو out;
	}

	/* Is this a signature we're prepared to accept? */
	اگر ((ret = sshkey_get_sigtype(sig, slen, &sigtype)) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		برو out;
	}
	اگر (ca_sigalg_allowlist != پوچ &&
	    match_pattern_list(sigtype, ca_sigalg_allowlist, 0) != 1) {
		ret = SSH_ERR_SIGN_ALG_UNSUPPORTED;
		برو out;
	}

	/* Parse CA key and check whether we might accept it */
	اگر (sshkey_from_blob_internal(ca, &کلید->cert->signature_کلید, 0,
	    ca_sigalg_allowlist, پوچ) != 0) {
		ret = SSH_ERR_کلید_CERT_INVALID_SIGN_کلید;
		برو out;
	}
	اگر (!sshkey_type_is_valid_ca(کلید->cert->signature_کلید->type)) {
		ret = SSH_ERR_کلید_CERT_INVALID_SIGN_کلید;
		برو out;
	}

	اگر (کلید->cert->type != SSH2_CERT_TYPE_USER &&
	    کلید->cert->type != SSH2_CERT_TYPE_HOST) {
		ret = SSH_ERR_کلید_CERT_UNKNOWN_TYPE;
		برو out;
	}

	/* Parse principals section */
	وقتی (sshbuf_len(principals) > 0) {
		نویسه *principal = پوچ;
		نویسه **oprincipals = پوچ;

		اگر (کلید->cert->nprincipals >= SSHKEY_CERT_MAX_PRINCIPALS) {
			ret = SSH_ERR_INVALID_FORMAT;
			برو out;
		}
		اگر ((ret = sshbuf_get_cstring(principals, &principal,
		    پوچ)) != 0) {
			ret = SSH_ERR_INVALID_FORMAT;
			برو out;
		}
		oprincipals = کلید->cert->principals;
		کلید->cert->principals = recallocarray(کلید->cert->principals,
		    کلید->cert->nprincipals, کلید->cert->nprincipals + 1,
		    اندازه(*کلید->cert->principals));
		اگر (کلید->cert->principals == پوچ) {
			آزاد(principal);
			کلید->cert->principals = oprincipals;
			ret = SSH_ERR_ALLOC_FAIL;
			برو out;
		}
		کلید->cert->principals[کلید->cert->nprincipals++] = principal;
	}

	/*
	 * Stash a copies of the critical options and extensions sections
	 * for later use.
	 */
	اگر ((ret = sshbuf_putb(کلید->cert->critical, crit)) != 0 ||
	    (exts != پوچ &&
	    (ret = sshbuf_putb(کلید->cert->extensions, exts)) != 0))
		برو out;

	/*
	 * Validate critical options and extensions sections format.
	 */
	وقتی (sshbuf_len(crit) != 0) {
		اگر ((ret = sshbuf_get_string_direct(crit, پوچ, پوچ)) != 0 ||
		    (ret = sshbuf_get_string_direct(crit, پوچ, پوچ)) != 0) {
			sshbuf_reset(کلید->cert->critical);
			ret = SSH_ERR_INVALID_FORMAT;
			برو out;
		}
	}
	وقتی (exts != پوچ && sshbuf_len(exts) != 0) {
		اگر ((ret = sshbuf_get_string_direct(exts, پوچ, پوچ)) != 0 ||
		    (ret = sshbuf_get_string_direct(exts, پوچ, پوچ)) != 0) {
			sshbuf_reset(کلید->cert->extensions);
			ret = SSH_ERR_INVALID_FORMAT;
			برو out;
		}
	}

	/* Finally, validate signature */
	اگر ((ret = sshkey_verify(کلید->cert->signature_کلید, sig, slen,
	    sshbuf_ptr(کلید->cert->certblob), signed_len, پوچ, 0, پوچ)) != 0)
		برو out;

	/* Success */
	ret = 0;
	کلید->cert->signature_type = sigtype;
	sigtype = پوچ;
 out:
	sshbuf_free(ca);
	sshbuf_free(crit);
	sshbuf_free(exts);
	sshbuf_free(principals);
	آزاد(sig);
	آزاد(sigtype);
	بازگشت ret;
}

صحیح
sshkey_deserialize_sk(ساختار sshbuf *b, ساختار sshkey *کلید)
{
	/* Parse additional security-key application string */
	اگر (sshbuf_get_cstring(b, &کلید->sk_application, پوچ) != 0)
		بازگشت SSH_ERR_INVALID_FORMAT;
	بازگشت 0;
}

ایستا صحیح
sshkey_from_blob_internal(ساختار sshbuf *b, ساختار sshkey **keyp,
    صحیح allow_cert, ثابت نویسه *alg_allowlist, ثابت نویسه *ca_sigalg_allowlist)
{
	صحیح type, ret = SSH_ERR_INTERNAL_ERROR;
	نویسه *ktype = پوچ;
	ساختار sshkey *کلید = پوچ;
	ساختار sshbuf *copy;
	ثابت ساختار sshkey_impl *impl;

#ifdef DEBUG_PK /* XXX */
	sshbuf_dump(b, stderr);
#endif
	اگر (keyp != پوچ)
		*keyp = پوچ;
	اگر ((copy = sshbuf_fromb(b)) == پوچ) {
		ret = SSH_ERR_ALLOC_FAIL;
		برو out;
	}
	اگر (sshbuf_get_cstring(b, &ktype, پوچ) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		برو out;
	}

	type = sshkey_type_from_name(ktype);
	اگر (!allow_cert && sshkey_type_is_cert(type)) {
		ret = SSH_ERR_کلید_CERT_INVALID_SIGN_کلید;
		برو out;
	}

	اگر (alg_allowlist != پوچ &&
	    !sshkey_match_keyname_to_sigalgs(ktype, alg_allowlist)) {
		ret = SSH_ERR_کلید_ALG_UNSUPPORTED;
		برو out;
	}

	اگر ((impl = sshkey_impl_from_type(type)) == پوچ) {
		ret = SSH_ERR_کلید_TYPE_UNKNOWN;
		برو out;
	}
	اگر ((کلید = sshkey_new(type)) == پوچ) {
		ret = SSH_ERR_ALLOC_FAIL;
		برو out;
	}
	اگر (sshkey_type_is_cert(type)) {
		/* Skip nonce that precedes all certificates */
		اگر (sshbuf_get_string_direct(b, پوچ, پوچ) != 0) {
			ret = SSH_ERR_INVALID_FORMAT;
			برو out;
		}
	}
	اگر ((ret = impl->funcs->deserialize_public(ktype, b, کلید)) != 0)
		برو out;

	/* Parse certificate potion */
	اگر (sshkey_is_cert(کلید) &&
	    (ret = cert_parse(b, کلید, copy, ca_sigalg_allowlist)) != 0)
		برو out;

	اگر (کلید != پوچ && sshbuf_len(b) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		برو out;
	}
	ret = 0;
	اگر (keyp != پوچ) {
		*keyp = کلید;
		کلید = پوچ;
	}
 out:
	sshbuf_free(copy);
	sshkey_free(کلید);
	آزاد(ktype);
	بازگشت ret;
}

صحیح
sshkey_from_blob(ثابت u_char *blob, size_t blen, ساختار sshkey **keyp)
{
	ساختار sshbuf *b;
	صحیح r;

	اگر ((b = sshbuf_from(blob, blen)) == پوچ)
		بازگشت SSH_ERR_ALLOC_FAIL;
	r = sshkey_from_blob_internal(b, keyp, 1, پوچ, پوچ);
	sshbuf_free(b);
	بازگشت r;
}

صحیح
sshkey_fromb(ساختار sshbuf *b, ساختار sshkey **keyp)
{
	بازگشت sshkey_from_blob_internal(b, keyp, 1, پوچ, پوچ);
}

صحیح
sshkey_fromb_allowlist(ساختار sshbuf *b, ساختار sshkey **keyp,
    ثابت نویسه *alg_allowlist, ثابت نویسه *ca_sigalg_allowlist)
{
	بازگشت sshkey_from_blob_internal(b, keyp, 1,
	    alg_allowlist, ca_sigalg_allowlist);
}

صحیح
sshkey_froms(ساختار sshbuf *buf, ساختار sshkey **keyp)
{
	ساختار sshbuf *b;
	صحیح r;

	اگر ((r = sshbuf_froms(buf, &b)) != 0)
		بازگشت r;
	r = sshkey_from_blob_internal(b, keyp, 1, پوچ, پوچ);
	sshbuf_free(b);
	بازگشت r;
}

صحیح
sshkey_get_sigtype(ثابت u_char *sig, size_t siglen, نویسه **sigtypep)
{
	صحیح r;
	ساختار sshbuf *b = پوچ;
	نویسه *sigtype = پوچ;

	اگر (sigtypep != پوچ)
		*sigtypep = پوچ;
	اگر ((b = sshbuf_from(sig, siglen)) == پوچ)
		بازگشت SSH_ERR_ALLOC_FAIL;
	اگر ((r = sshbuf_get_cstring(b, &sigtype, پوچ)) != 0)
		برو out;
	/* success */
	اگر (sigtypep != پوچ) {
		*sigtypep = sigtype;
		sigtype = پوچ;
	}
	r = 0;
 out:
	آزاد(sigtype);
	sshbuf_free(b);
	بازگشت r;
}

/*
 *
 * Checks whether a certificate's signature type is allowed.
 * Returns 0 (success) if the certificate signature type appears in the
 * "allowed" pattern-list, or the key is not a certificate to begin with.
 * Otherwise returns a ssherr.h code.
 */
صحیح
sshkey_check_cert_sigtype(ثابت ساختار sshkey *کلید, ثابت نویسه *allowed)
{
	اگر (کلید == پوچ || allowed == پوچ)
		بازگشت SSH_ERR_INVALID_ARGUMENT;
	اگر (!sshkey_type_is_cert(کلید->type))
		بازگشت 0;
	اگر (کلید->cert == پوچ || کلید->cert->signature_type == پوچ)
		بازگشت SSH_ERR_INVALID_ARGUMENT;
	اگر (match_pattern_list(کلید->cert->signature_type, allowed, 0) != 1)
		بازگشت SSH_ERR_SIGN_ALG_UNSUPPORTED;
	بازگشت 0;
}

/*
 * Returns the expected signature algorithm for a given public key algorithm.
 */
ثابت نویسه *
sshkey_sigalg_by_name(ثابت نویسه *name)
{
	ثابت ساختار sshkey_impl *impl;
	صحیح i;

	برای (i = 0; keyimpls[i] != پوچ; i++) {
		impl = keyimpls[i];
		اگر (strcmp(impl->name, name) != 0)
			ادامه;
		اگر (impl->sigalg != پوچ)
			بازگشت impl->sigalg;
		اگر (!impl->cert)
			بازگشت impl->name;
		بازگشت sshkey_ssh_name_from_type_nid(
		    sshkey_type_plain(impl->type), impl->nid);
	}
	بازگشت پوچ;
}

/*
 * Verifies that the signature algorithm appearing inside the signature blob
 * matches that which was requested.
 */
صحیح
sshkey_check_sigtype(ثابت u_char *sig, size_t siglen,
    ثابت نویسه *requested_alg)
{
	ثابت نویسه *expected_alg;
	نویسه *sigtype = پوچ;
	صحیح r;

	اگر (requested_alg == پوچ)
		بازگشت 0;
	اگر ((expected_alg = sshkey_sigalg_by_name(requested_alg)) == پوچ)
		بازگشت SSH_ERR_INVALID_ARGUMENT;
	اگر ((r = sshkey_get_sigtype(sig, siglen, &sigtype)) != 0)
		بازگشت r;
	r = strcmp(expected_alg, sigtype) == 0;
	آزاد(sigtype);
	بازگشت r ? 0 : SSH_ERR_SIGN_ALG_UNSUPPORTED;
}

صحیح
sshkey_sign(ساختار sshkey *کلید,
    u_char **sigp, size_t *lenp,
    ثابت u_char *data, size_t datalen,
    ثابت نویسه *alg, ثابت نویسه *sk_provider, ثابت نویسه *sk_pin, u_int compat)
{
	صحیح was_shielded = sshkey_is_shielded(کلید);
	صحیح r2, r = SSH_ERR_INTERNAL_ERROR;
	ثابت ساختار sshkey_impl *impl;

	اگر (sigp != پوچ)
		*sigp = پوچ;
	اگر (lenp != پوچ)
		*lenp = 0;
	اگر (datalen > SSH_کلید_MAX_SIGN_DATA_SIZE)
		بازگشت SSH_ERR_INVALID_ARGUMENT;
	اگر ((impl = sshkey_impl_from_کلید(کلید)) == پوچ)
		بازگشت SSH_ERR_کلید_TYPE_UNKNOWN;
	اگر ((r = sshkey_unshield_private(کلید)) != 0)
		بازگشت r;
	اگر (sshkey_is_sk(کلید)) {
		r = sshsk_sign(sk_provider, کلید, sigp, lenp, data,
		    datalen, compat, sk_pin);
	} وگرنه اگر ((کلید->flags & SSHKEY_FLAG_EXT) != 0) {
		r = pkcs11_sign(کلید, sigp, lenp, data, datalen,
		    alg, sk_provider, sk_pin, compat);
	} وگرنه {
		اگر (impl->funcs->sign == پوچ)
			r = SSH_ERR_SIGN_ALG_UNSUPPORTED;
		وگرنه {
			r = impl->funcs->sign(کلید, sigp, lenp, data, datalen,
			    alg, sk_provider, sk_pin, compat);
		 }
	}
	اگر (was_shielded && (r2 = sshkey_shield_private(کلید)) != 0)
		بازگشت r2;
	بازگشت r;
}

/*
 * ssh_key_verify returns 0 for a correct signature and < 0 on error.
 * If "alg" specified, then the signature must use that algorithm.
 */
صحیح
sshkey_verify(ثابت ساختار sshkey *کلید,
    ثابت u_char *sig, size_t siglen,
    ثابت u_char *data, size_t dlen, ثابت نویسه *alg, u_int compat,
    ساختار sshkey_sig_details **detailsp)
{
	ثابت ساختار sshkey_impl *impl;

	اگر (detailsp != پوچ)
		*detailsp = پوچ;
	اگر (siglen == 0 || dlen > SSH_کلید_MAX_SIGN_DATA_SIZE)
		بازگشت SSH_ERR_INVALID_ARGUMENT;
	اگر ((impl = sshkey_impl_from_کلید(کلید)) == پوچ)
		بازگشت SSH_ERR_کلید_TYPE_UNKNOWN;
	بازگشت impl->funcs->verify(کلید, sig, siglen, data, dlen,
	    alg, compat, detailsp);
}

/* Convert a plain key to their _CERT equivalent */
صحیح
sshkey_to_certified(ساختار sshkey *k)
{
	صحیح newtype;

	اگر ((newtype = sshkey_type_certified(k->type)) == -1)
		بازگشت SSH_ERR_INVALID_ARGUMENT;
	اگر ((k->cert = cert_new()) == پوچ)
		بازگشت SSH_ERR_ALLOC_FAIL;
	k->type = newtype;
	بازگشت 0;
}

/* Convert a certificate to its raw key equivalent */
صحیح
sshkey_drop_cert(ساختار sshkey *k)
{
	اگر (!sshkey_type_is_cert(k->type))
		بازگشت SSH_ERR_کلید_TYPE_UNKNOWN;
	cert_free(k->cert);
	k->cert = پوچ;
	k->type = sshkey_type_plain(k->type);
	بازگشت 0;
}

/* Sign a certified key, (re-)generating the signed certblob. */
صحیح
sshkey_certify_custom(ساختار sshkey *k, ساختار sshkey *ca, ثابت نویسه *alg,
    ثابت نویسه *sk_provider, ثابت نویسه *sk_pin,
    sshkey_certify_signer *signer, تهی *signer_ctx)
{
	ثابت ساختار sshkey_impl *impl;
	ساختار sshbuf *principals = پوچ;
	u_char *ca_blob = پوچ, *sig_blob = پوچ, nonce[32];
	size_t i, ca_len, sig_len;
	صحیح ret = SSH_ERR_INTERNAL_ERROR;
	ساختار sshbuf *cert = پوچ;
	نویسه *sigtype = پوچ;

	اگر (k == پوچ || k->cert == پوچ ||
	    k->cert->certblob == پوچ || ca == پوچ)
		بازگشت SSH_ERR_INVALID_ARGUMENT;
	اگر (!sshkey_is_cert(k))
		بازگشت SSH_ERR_کلید_TYPE_UNKNOWN;
	اگر (!sshkey_type_is_valid_ca(ca->type))
		بازگشت SSH_ERR_کلید_CERT_INVALID_SIGN_کلید;
	اگر ((impl = sshkey_impl_from_کلید(k)) == پوچ)
		بازگشت SSH_ERR_INTERNAL_ERROR;

	/*
	 * If no alg specified as argument but a signature_type was set,
	 * then prefer that. If both were specified, then they must match.
	 */
	اگر (alg == پوچ)
		alg = k->cert->signature_type;
	وگرنه اگر (k->cert->signature_type != پوچ &&
	    strcmp(alg, k->cert->signature_type) != 0)
		بازگشت SSH_ERR_INVALID_ARGUMENT;

	/*
	 * If no signing algorithm or signature_type was specified and we're
	 * using a RSA key, then default to a good signature algorithm.
	 */
	اگر (alg == پوچ && ca->type == کلید_RSA)
		alg = "rsa-sha2-512";

	اگر ((ret = sshkey_to_blob(ca, &ca_blob, &ca_len)) != 0)
		بازگشت SSH_ERR_کلید_CERT_INVALID_SIGN_کلید;

	cert = k->cert->certblob; /* for readability */
	sshbuf_reset(cert);
	اگر ((ret = sshbuf_put_cstring(cert, sshkey_ssh_name(k))) != 0)
		برو out;

	/* -v01 certs put nonce first */
	arc4random_buf(&nonce, اندازه(nonce));
	اگر ((ret = sshbuf_put_string(cert, nonce, اندازه(nonce))) != 0)
		برو out;

	/* Public key next */
	اگر ((ret = impl->funcs->serialize_public(k, cert,
	    SSHKEY_SERIALIZE_DEFAULT)) != 0)
		برو out;

	/* Then remaining cert fields */
	اگر ((ret = sshbuf_put_u64(cert, k->cert->serial)) != 0 ||
	    (ret = sshbuf_put_u32(cert, k->cert->type)) != 0 ||
	    (ret = sshbuf_put_cstring(cert, k->cert->کلید_id)) != 0)
		برو out;

	اگر ((principals = sshbuf_new()) == پوچ) {
		ret = SSH_ERR_ALLOC_FAIL;
		برو out;
	}
	برای (i = 0; i < k->cert->nprincipals; i++) {
		اگر ((ret = sshbuf_put_cstring(principals,
		    k->cert->principals[i])) != 0)
			برو out;
	}
	اگر ((ret = sshbuf_put_stringb(cert, principals)) != 0 ||
	    (ret = sshbuf_put_u64(cert, k->cert->valid_after)) != 0 ||
	    (ret = sshbuf_put_u64(cert, k->cert->valid_before)) != 0 ||
	    (ret = sshbuf_put_stringb(cert, k->cert->critical)) != 0 ||
	    (ret = sshbuf_put_stringb(cert, k->cert->extensions)) != 0 ||
	    (ret = sshbuf_put_string(cert, پوچ, 0)) != 0 || /* Reserved */
	    (ret = sshbuf_put_string(cert, ca_blob, ca_len)) != 0)
		برو out;

	/* Sign the whole mess */
	اگر ((ret = signer(ca, &sig_blob, &sig_len, sshbuf_ptr(cert),
	    sshbuf_len(cert), alg, sk_provider, sk_pin, 0, signer_ctx)) != 0)
		برو out;
	/* Check and update signature_type against what was actually used */
	اگر ((ret = sshkey_get_sigtype(sig_blob, sig_len, &sigtype)) != 0)
		برو out;
	اگر (alg != پوچ && strcmp(alg, sigtype) != 0) {
		ret = SSH_ERR_SIGN_ALG_UNSUPPORTED;
		برو out;
	}
	اگر (k->cert->signature_type == پوچ) {
		k->cert->signature_type = sigtype;
		sigtype = پوچ;
	}
	/* Append signature and we are done */
	اگر ((ret = sshbuf_put_string(cert, sig_blob, sig_len)) != 0)
		برو out;
	ret = 0;
 out:
	اگر (ret != 0)
		sshbuf_reset(cert);
	آزاد(sig_blob);
	آزاد(ca_blob);
	آزاد(sigtype);
	sshbuf_free(principals);
	بازگشت ret;
}

ایستا صحیح
default_کلید_sign(ساختار sshkey *کلید, u_char **sigp, size_t *lenp,
    ثابت u_char *data, size_t datalen,
    ثابت نویسه *alg, ثابت نویسه *sk_provider, ثابت نویسه *sk_pin,
    u_int compat, تهی *ctx)
{
	اگر (ctx != پوچ)
		بازگشت SSH_ERR_INVALID_ARGUMENT;
	بازگشت sshkey_sign(کلید, sigp, lenp, data, datalen, alg,
	    sk_provider, sk_pin, compat);
}

صحیح
sshkey_certify(ساختار sshkey *k, ساختار sshkey *ca, ثابت نویسه *alg,
    ثابت نویسه *sk_provider, ثابت نویسه *sk_pin)
{
	بازگشت sshkey_certify_custom(k, ca, alg, sk_provider, sk_pin,
	    default_کلید_sign, پوچ);
}

صحیح
sshkey_cert_check_authority(ثابت ساختار sshkey *k,
    صحیح want_host, صحیح wildcard_pattern, uint64_t verify_time,
    ثابت نویسه *name, ثابت نویسه **reason)
{
	u_int i, principal_matches;

	اگر (reason == پوچ)
		بازگشت SSH_ERR_INVALID_ARGUMENT;
	اگر (!sshkey_is_cert(k)) {
		*reason = "Key is not a certificate";
		بازگشت SSH_ERR_کلید_CERT_INVALID;
	}
	اگر (want_host) {
		اگر (k->cert->type != SSH2_CERT_TYPE_HOST) {
			*reason = "Certificate invalid: not a host certificate";
			بازگشت SSH_ERR_کلید_CERT_INVALID;
		}
	} وگرنه {
		اگر (k->cert->type != SSH2_CERT_TYPE_USER) {
			*reason = "Certificate invalid: not a user certificate";
			بازگشت SSH_ERR_کلید_CERT_INVALID;
		}
	}
	اگر (verify_time < k->cert->valid_after) {
		*reason = "Certificate invalid: not yet valid";
		بازگشت SSH_ERR_کلید_CERT_INVALID;
	}
	اگر (verify_time >= k->cert->valid_before) {
		*reason = "Certificate invalid: expired";
		بازگشت SSH_ERR_کلید_CERT_INVALID;
	}
	اگر (k->cert->nprincipals == 0) {
		*reason = "Certificate lacks principal list";
		بازگشت SSH_ERR_کلید_CERT_INVALID;
	}
	اگر (name == پوچ)
		بازگشت 0; /* principal matching not requested */

	principal_matches = 0;
	برای (i = 0; i < k->cert->nprincipals; i++) {
		اگر (wildcard_pattern) {
			اگر (match_pattern(name, k->cert->principals[i])) {
				principal_matches = 1;
				بشکن;
			}
		} وگرنه اگر (strcmp(name, k->cert->principals[i]) == 0) {
			principal_matches = 1;
			بشکن;
		}
	}
	اگر (!principal_matches) {
		*reason = "Certificate invalid: name is not a listed "
		    "principal";
		بازگشت SSH_ERR_کلید_CERT_INVALID;
	}
	بازگشت 0;
}

صحیح
sshkey_cert_check_authority_now(ثابت ساختار sshkey *k,
    صحیح want_host, صحیح wildcard_pattern, ثابت نویسه *name,
    ثابت نویسه **reason)
{
	time_t now;

	اگر ((now = time(پوچ)) < 0) {
		/* yikes - system clock before epoch! */
		*reason = "Certificate invalid: not yet valid";
		بازگشت SSH_ERR_کلید_CERT_INVALID;
	}
	بازگشت sshkey_cert_check_authority(k, want_host, wildcard_pattern,
	    (uint64_t)now, name, reason);
}

صحیح
sshkey_cert_check_host(ثابت ساختار sshkey *کلید, ثابت نویسه *host,
    ثابت نویسه *ca_sign_algorithms, ثابت نویسه **reason)
{
	صحیح r;

	اگر ((r = sshkey_cert_check_authority_now(کلید, 1, 1, host, reason)) != 0)
		بازگشت r;
	اگر (sshbuf_len(کلید->cert->critical) != 0) {
		*reason = "Certificate contains unsupported critical options";
		بازگشت SSH_ERR_کلید_CERT_INVALID;
	}
	اگر (ca_sign_algorithms != پوچ &&
	    (r = sshkey_check_cert_sigtype(کلید, ca_sign_algorithms)) != 0) {
		*reason = "Certificate signed with disallowed algorithm";
		بازگشت SSH_ERR_کلید_CERT_INVALID;
	}
	بازگشت 0;
}

size_t
sshkey_format_cert_validity(ثابت ساختار sshkey_cert *cert, نویسه *s, size_t l)
{
	نویسه from[32], to[32], ret[128];

	*from = *to = '\0';
	اگر (cert->valid_after == 0 &&
	    cert->valid_before == 0xffffffffffffffffULL)
		بازگشت strlcpy(s, "forever", l);

	اگر (cert->valid_after != 0)
		format_absolute_time(cert->valid_after, from, اندازه(from));
	اگر (cert->valid_before != 0xffffffffffffffffULL)
		format_absolute_time(cert->valid_before, to, اندازه(to));

	اگر (cert->valid_after == 0)
		snprintf(ret, اندازه(ret), "before %s", to);
	وگرنه اگر (cert->valid_before == 0xffffffffffffffffULL)
		snprintf(ret, اندازه(ret), "after %s", from);
	وگرنه
		snprintf(ret, اندازه(ret), "from %s to %s", from, to);

	بازگشت strlcpy(s, ret, l);
}

/* Common serialization for FIDO private keys */
صحیح
sshkey_serialize_private_sk(ثابت ساختار sshkey *کلید, ساختار sshbuf *b)
{
	صحیح r;

	اگر ((r = sshbuf_put_cstring(b, کلید->sk_application)) != 0 ||
	    (r = sshbuf_put_u8(b, کلید->sk_flags)) != 0 ||
	    (r = sshbuf_put_stringb(b, کلید->sk_کلید_handle)) != 0 ||
	    (r = sshbuf_put_stringb(b, کلید->sk_reserved)) != 0)
		بازگشت r;

	بازگشت 0;
}

ایستا صحیح
sshkey_private_serialize_opt(ساختار sshkey *کلید, ساختار sshbuf *buf,
    شمارش sshkey_serialize_rep opts)
{
	صحیح r = SSH_ERR_INTERNAL_ERROR;
	صحیح was_shielded = sshkey_is_shielded(کلید);
	ساختار sshbuf *b = پوچ;
	ثابت ساختار sshkey_impl *impl;

	اگر ((impl = sshkey_impl_from_کلید(کلید)) == پوچ)
		بازگشت SSH_ERR_INTERNAL_ERROR;
	اگر ((r = sshkey_unshield_private(کلید)) != 0)
		بازگشت r;
	اگر ((b = sshbuf_new()) == پوچ)
		بازگشت SSH_ERR_ALLOC_FAIL;
	اگر ((r = sshbuf_put_cstring(b, sshkey_ssh_name(کلید))) != 0)
		برو out;
	اگر (sshkey_is_cert(کلید)) {
		اگر (کلید->cert == پوچ ||
		    sshbuf_len(کلید->cert->certblob) == 0) {
			r = SSH_ERR_INVALID_ARGUMENT;
			برو out;
		}
		اگر ((r = sshbuf_put_stringb(b, کلید->cert->certblob)) != 0)
			برو out;
	}
	اگر ((r = impl->funcs->serialize_private(کلید, b, opts)) != 0)
		برو out;

	/*
	 * success (but we still need to append the output to buf after
	 * possibly re-shielding the private key)
	 */
	r = 0;
 out:
	اگر (was_shielded)
		r = sshkey_shield_private(کلید);
	اگر (r == 0)
		r = sshbuf_putb(buf, b);
	sshbuf_free(b);

	بازگشت r;
}

صحیح
sshkey_private_serialize(ساختار sshkey *کلید, ساختار sshbuf *b)
{
	بازگشت sshkey_private_serialize_opt(کلید, b,
	    SSHKEY_SERIALIZE_DEFAULT);
}


/* Shared deserialization of FIDO private key components */
صحیح
sshkey_private_deserialize_sk(ساختار sshbuf *buf, ساختار sshkey *k)
{
	صحیح r;

	اگر ((k->sk_کلید_handle = sshbuf_new()) == پوچ ||
	    (k->sk_reserved = sshbuf_new()) == پوچ)
		بازگشت SSH_ERR_ALLOC_FAIL;
	اگر ((r = sshbuf_get_cstring(buf, &k->sk_application, پوچ)) != 0 ||
	    (r = sshbuf_get_u8(buf, &k->sk_flags)) != 0 ||
	    (r = sshbuf_get_stringb(buf, k->sk_کلید_handle)) != 0 ||
	    (r = sshbuf_get_stringb(buf, k->sk_reserved)) != 0)
		بازگشت r;

	بازگشت 0;
}

صحیح
sshkey_private_deserialize(ساختار sshbuf *buf, ساختار sshkey **kp)
{
	ثابت ساختار sshkey_impl *impl;
	نویسه *tname = پوچ;
	نویسه *expect_sk_application = پوچ;
	u_char *expect_ed25519_pk = پوچ;
	ساختار sshkey *k = پوچ;
	صحیح type, r = SSH_ERR_INTERNAL_ERROR;

	اگر (kp != پوچ)
		*kp = پوچ;
	اگر ((r = sshbuf_get_cstring(buf, &tname, پوچ)) != 0)
		برو out;
	type = sshkey_type_from_name(tname);
	اگر (sshkey_type_is_cert(type)) {
		/*
		 * Certificate key private keys begin with the certificate
		 * itself. Make sure this matches the type of the enclosing
		 * private key.
		 */
		اگر ((r = sshkey_froms(buf, &k)) != 0)
			برو out;
		اگر (k->type != type) {
			r = SSH_ERR_کلید_CERT_MISMATCH;
			برو out;
		}
		/* For ECDSA keys, the group must match too */
		اگر (k->type == کلید_ECDSA &&
		    k->ecdsa_nid != sshkey_ecdsa_nid_from_name(tname)) {
			r = SSH_ERR_کلید_CERT_MISMATCH;
			برو out;
		}
		/*
		 * Several fields are redundant between certificate and
		 * private key body, we require these to match.
		 */
		expect_sk_application = k->sk_application;
		expect_ed25519_pk = k->ed25519_pk;
		k->sk_application = پوچ;
		k->ed25519_pk = پوچ;
	} وگرنه {
		اگر ((k = sshkey_new(type)) == پوچ) {
			r = SSH_ERR_ALLOC_FAIL;
			برو out;
		}
	}
	اگر ((impl = sshkey_impl_from_type(type)) == پوچ) {
		r = SSH_ERR_INTERNAL_ERROR;
		برو out;
	}
	اگر ((r = impl->funcs->deserialize_private(tname, buf, k)) != 0)
		برو out;

	اگر ((expect_sk_application != پوچ && (k->sk_application == پوچ ||
	    strcmp(expect_sk_application, k->sk_application) != 0)) ||
	    (expect_ed25519_pk != پوچ && (k->ed25519_pk == پوچ ||
	    memcmp(expect_ed25519_pk, k->ed25519_pk, ED25519_PK_SZ) != 0))) {
		r = SSH_ERR_کلید_CERT_MISMATCH;
		برو out;
	}
	/* success */
	r = 0;
	اگر (kp != پوچ) {
		*kp = k;
		k = پوچ;
	}
 out:
	آزاد(tname);
	sshkey_free(k);
	آزاد(expect_sk_application);
	آزاد(expect_ed25519_pk);
	بازگشت r;
}

#ifdef WITH_OPENSSL
صحیح
sshkey_ec_validate_public(ثابت EC_GROUP *group, ثابت EC_POINT *عمومی)
{
	EC_POINT *nq = پوچ;
	BIGNUM *order = پوچ, *cofactor = پوچ;
	صحیح ret = SSH_ERR_کلید_INVALID_EC_مقدار;

	/*
	 * NB. This assumes OpenSSL has already verified that the public
	 * point lies on the curve and that its coordinates are in [0, p).
	 * This is done by EC_POINT_oct2point() on at least OpenSSL >= 1.1,
	 * LibreSSL and BoringSSL.
	 */

	/* Q != infinity */
	اگر (EC_POINT_is_at_infinity(group, عمومی))
		برو out;

	اگر ((cofactor = BN_new()) == پوچ) {
		ret = SSH_ERR_ALLOC_FAIL;
		برو out;
	}
	اگر (EC_GROUP_get_cofactor(group, cofactor, پوچ) != 1)
		برو out;

	/*
	 * Verify nQ == infinity (n == order of subgroup)
	 * This check may be skipped for curves with cofactor 1, as per
	 * NIST SP 800-56A, 5.6.2.3.
	 */
	اگر (!BN_is_one(cofactor)) {
		اگر ((order = BN_new()) == پوچ) {
			ret = SSH_ERR_ALLOC_FAIL;
			برو out;
		}
		اگر (EC_GROUP_get_order(group, order, پوچ) != 1) {
			ret = SSH_ERR_LIBCRYPTO_ERROR;
			برو out;
		}
		اگر ((nq = EC_POINT_new(group)) == پوچ) {
			ret = SSH_ERR_ALLOC_FAIL;
			برو out;
		}
		اگر (EC_POINT_mul(group, nq, پوچ, عمومی, order, پوچ) != 1) {
			ret = SSH_ERR_LIBCRYPTO_ERROR;
			برو out;
		}
		اگر (EC_POINT_is_at_infinity(group, nq) != 1)
			برو out;
	}

	/* success */
	ret = 0;
 out:
	BN_clear_free(cofactor);
	BN_clear_free(order);
	EC_POINT_free(nq);
	بازگشت ret;
}

صحیح
sshkey_ec_validate_private(ثابت EC_کلید *کلید)
{
	BIGNUM *order = پوچ, *tmp = پوچ;
	صحیح ret = SSH_ERR_کلید_INVALID_EC_مقدار;

	اگر ((order = BN_new()) == پوچ || (tmp = BN_new()) == پوچ) {
		ret = SSH_ERR_ALLOC_FAIL;
		برو out;
	}

	/* log2(private) > log2(order)/2 */
	اگر (EC_GROUP_get_order(EC_کلید_get0_group(کلید), order, پوچ) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		برو out;
	}
	اگر (BN_رقم_bits(EC_کلید_get0_private_کلید(کلید)) <=
	    BN_رقم_bits(order) / 2)
		برو out;

	/* private < order - 1 */
	اگر (!BN_sub(tmp, order, BN_مقدار_one())) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		برو out;
	}
	اگر (BN_cmp(EC_کلید_get0_private_کلید(کلید), tmp) >= 0)
		برو out;
	ret = 0;
 out:
	BN_clear_free(order);
	BN_clear_free(tmp);
	بازگشت ret;
}

تهی
sshkey_dump_ec_point(ثابت EC_GROUP *group, ثابت EC_POINT *point)
{
	BIGNUM *x = پوچ, *y = پوچ;

	اگر (point == پوچ) {
		fputs("point=(NULL)\n", stderr);
		بازگشت;
	}
	اگر ((x = BN_new()) == پوچ || (y = BN_new()) == پوچ) {
		fprintf(stderr, "%s: BN_new failed\n", __func__);
		برو out;
	}
	اگر (EC_POINT_get_affine_coordinates(group, point, x, y, پوچ) != 1) {
		fprintf(stderr, "%s: EC_POINT_get_affine_coordinates\n",
		    __func__);
		برو out;
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

تهی
sshkey_dump_ec_کلید(ثابت EC_کلید *کلید)
{
	ثابت BIGNUM *exponent;

	sshkey_dump_ec_point(EC_کلید_get0_group(کلید),
	    EC_کلید_get0_public_کلید(کلید));
	fputs("exponent=", stderr);
	اگر ((exponent = EC_کلید_get0_private_کلید(کلید)) == پوچ)
		fputs("(NULL)", stderr);
	وگرنه
		BN_print_fp(stderr, EC_کلید_get0_private_کلید(کلید));
	fputs("\n", stderr);
}
#endif /* WITH_OPENSSL */

ایستا صحیح
sshkey_private_to_blob2(ساختار sshkey *prv, ساختار sshbuf *blob,
    ثابت نویسه *passphrase, ثابت نویسه *comment, ثابت نویسه *ciphername,
    صحیح rounds)
{
	u_char *cp, *کلید = پوچ, *pubkeyblob = پوچ;
	u_char salt[SALT_LEN];
	size_t i, pubkeylen, keylen, ivlen, blocksize, authlen;
	u_int check;
	صحیح r = SSH_ERR_INTERNAL_ERROR;
	ساختار sshcipher_ctx *ciphercontext = پوچ;
	ثابت ساختار sshcipher *cipher;
	ثابت نویسه *kdfname = KDFNAME;
	ساختار sshbuf *encoded = پوچ, *encrypted = پوچ, *kdf = پوچ;

	اگر (rounds <= 0)
		rounds = DEFAULT_ROUNDS;
	اگر (rounds > MAX_KDF_ROUNDS) {
		r = SSH_ERR_INVALID_ARGUMENT;
		برو out;
	}
	اگر (passphrase == پوچ || !strlen(passphrase)) {
		ciphername = "none";
		kdfname = "none";
	} وگرنه اگر (ciphername == پوچ)
		ciphername = DEFAULT_CIPHERNAME;
	اگر ((cipher = cipher_by_name(ciphername)) == پوچ) {
		r = SSH_ERR_INVALID_ARGUMENT;
		برو out;
	}

	اگر ((kdf = sshbuf_new()) == پوچ ||
	    (encoded = sshbuf_new()) == پوچ ||
	    (encrypted = sshbuf_new()) == پوچ) {
		r = SSH_ERR_ALLOC_FAIL;
		برو out;
	}
	blocksize = cipher_blocksize(cipher);
	keylen = cipher_keylen(cipher);
	ivlen = cipher_ivlen(cipher);
	authlen = cipher_authlen(cipher);
	اگر ((کلید = calloc(1, keylen + ivlen)) == پوچ) {
		r = SSH_ERR_ALLOC_FAIL;
		برو out;
	}
	اگر (strcmp(kdfname, "bcrypt") == 0) {
		arc4random_buf(salt, SALT_LEN);
		اگر (bcrypt_pbkdf(passphrase, strlen(passphrase),
		    salt, SALT_LEN, کلید, keylen + ivlen, rounds) < 0) {
			r = SSH_ERR_INVALID_ARGUMENT;
			برو out;
		}
		اگر ((r = sshbuf_put_string(kdf, salt, SALT_LEN)) != 0 ||
		    (r = sshbuf_put_u32(kdf, rounds)) != 0)
			برو out;
	} وگرنه اگر (strcmp(kdfname, "none") != 0) {
		/* Unsupported KDF type */
		r = SSH_ERR_کلید_UNKNOWN_CIPHER;
		برو out;
	}
	اگر ((r = cipher_init(&ciphercontext, cipher, کلید, keylen,
	    کلید + keylen, ivlen, 1)) != 0)
		برو out;

	اگر ((r = sshbuf_put(encoded, AUTH_MAGIC, اندازه(AUTH_MAGIC))) != 0 ||
	    (r = sshbuf_put_cstring(encoded, ciphername)) != 0 ||
	    (r = sshbuf_put_cstring(encoded, kdfname)) != 0 ||
	    (r = sshbuf_put_stringb(encoded, kdf)) != 0 ||
	    (r = sshbuf_put_u32(encoded, 1)) != 0 ||	/* number of keys */
	    (r = sshkey_to_blob(prv, &pubkeyblob, &pubkeylen)) != 0 ||
	    (r = sshbuf_put_string(encoded, pubkeyblob, pubkeylen)) != 0)
		برو out;

	/* set up the buffer that will be encrypted */

	/* Random check bytes */
	check = arc4random();
	اگر ((r = sshbuf_put_u32(encrypted, check)) != 0 ||
	    (r = sshbuf_put_u32(encrypted, check)) != 0)
		برو out;

	/* append private key and comment*/
	اگر ((r = sshkey_private_serialize(prv, encrypted)) != 0 ||
	    (r = sshbuf_put_cstring(encrypted, comment)) != 0)
		برو out;

	/* padding */
	i = 0;
	وقتی (sshbuf_len(encrypted) % blocksize) {
		اگر ((r = sshbuf_put_u8(encrypted, ++i & 0xff)) != 0)
			برو out;
	}

	/* length in destination buffer */
	اگر ((r = sshbuf_put_u32(encoded, sshbuf_len(encrypted))) != 0)
		برو out;

	/* encrypt */
	اگر ((r = sshbuf_reserve(encoded,
	    sshbuf_len(encrypted) + authlen, &cp)) != 0)
		برو out;
	اگر ((r = cipher_crypt(ciphercontext, 0, cp,
	    sshbuf_ptr(encrypted), sshbuf_len(encrypted), 0, authlen)) != 0)
		برو out;

	sshbuf_reset(blob);

	/* assemble uuencoded key */
	اگر ((r = sshbuf_put(blob, MARK_BEGIN, MARK_BEGIN_LEN)) != 0 ||
	    (r = sshbuf_dtob64(encoded, blob, 1)) != 0 ||
	    (r = sshbuf_put(blob, MARK_END, MARK_END_LEN)) != 0)
		برو out;

	/* success */
	r = 0;

 out:
	sshbuf_free(kdf);
	sshbuf_free(encoded);
	sshbuf_free(encrypted);
	cipher_free(ciphercontext);
	explicit_bzero(salt, اندازه(salt));
	اگر (کلید != پوچ)
		freezero(کلید, keylen + ivlen);
	اگر (pubkeyblob != پوچ)
		freezero(pubkeyblob, pubkeylen);
	بازگشت r;
}

ایستا صحیح
private2_uudecode(ساختار sshbuf *blob, ساختار sshbuf **decodedp)
{
	ثابت u_char *cp;
	size_t encoded_len;
	صحیح r;
	u_char last;
	ساختار sshbuf *encoded = پوچ, *decoded = پوچ;

	اگر (blob == پوچ || decodedp == پوچ)
		بازگشت SSH_ERR_INVALID_ARGUMENT;

	*decodedp = پوچ;

	اگر ((encoded = sshbuf_new()) == پوچ ||
	    (decoded = sshbuf_new()) == پوچ) {
		r = SSH_ERR_ALLOC_FAIL;
		برو out;
	}

	/* check preamble */
	cp = sshbuf_ptr(blob);
	encoded_len = sshbuf_len(blob);
	اگر (encoded_len < (MARK_BEGIN_LEN + MARK_END_LEN) ||
	    memcmp(cp, MARK_BEGIN, MARK_BEGIN_LEN) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		برو out;
	}
	cp += MARK_BEGIN_LEN;
	encoded_len -= MARK_BEGIN_LEN;

	/* Look for end marker, removing whitespace as we go */
	وقتی (encoded_len > 0) {
		اگر (*cp != '\n' && *cp != '\r') {
			اگر ((r = sshbuf_put_u8(encoded, *cp)) != 0)
				برو out;
		}
		last = *cp;
		encoded_len--;
		cp++;
		اگر (last == '\n') {
			اگر (encoded_len >= MARK_END_LEN &&
			    memcmp(cp, MARK_END, MARK_END_LEN) == 0) {
				/* \0 terminate */
				اگر ((r = sshbuf_put_u8(encoded, 0)) != 0)
					برو out;
				بشکن;
			}
		}
	}
	اگر (encoded_len == 0) {
		r = SSH_ERR_INVALID_FORMAT;
		برو out;
	}

	/* decode base64 */
	اگر ((r = sshbuf_b64tod(decoded, (نویسه *)sshbuf_ptr(encoded))) != 0)
		برو out;

	/* check magic */
	اگر (sshbuf_len(decoded) < اندازه(AUTH_MAGIC) ||
	    memcmp(sshbuf_ptr(decoded), AUTH_MAGIC, اندازه(AUTH_MAGIC))) {
		r = SSH_ERR_INVALID_FORMAT;
		برو out;
	}
	/* success */
	*decodedp = decoded;
	decoded = پوچ;
	r = 0;
 out:
	sshbuf_free(encoded);
	sshbuf_free(decoded);
	بازگشت r;
}

ایستا صحیح
private2_decrypt(ساختار sshbuf *decoded, ثابت نویسه *passphrase,
    ساختار sshbuf **decryptedp, ساختار sshkey **pubkeyp)
{
	نویسه *ciphername = پوچ, *kdfname = پوچ;
	ثابت ساختار sshcipher *cipher = پوچ;
	صحیح r = SSH_ERR_INTERNAL_ERROR;
	size_t keylen = 0, ivlen = 0, authlen = 0, slen = 0;
	ساختار sshbuf *kdf = پوچ, *decrypted = پوچ;
	ساختار sshcipher_ctx *ciphercontext = پوچ;
	ساختار sshkey *pubkey = پوچ;
	u_char *کلید = پوچ, *salt = پوچ, *dp;
	u_int blocksize, rounds, nkeys, encrypted_len, check1, check2;

	اگر (decoded == پوچ || decryptedp == پوچ || pubkeyp == پوچ)
		بازگشت SSH_ERR_INVALID_ARGUMENT;

	*decryptedp = پوچ;
	*pubkeyp = پوچ;

	اگر ((decrypted = sshbuf_new()) == پوچ) {
		r = SSH_ERR_ALLOC_FAIL;
		برو out;
	}

	/* parse public portion of key */
	اگر ((r = sshbuf_consume(decoded, اندازه(AUTH_MAGIC))) != 0 ||
	    (r = sshbuf_get_cstring(decoded, &ciphername, پوچ)) != 0 ||
	    (r = sshbuf_get_cstring(decoded, &kdfname, پوچ)) != 0 ||
	    (r = sshbuf_froms(decoded, &kdf)) != 0 ||
	    (r = sshbuf_get_u32(decoded, &nkeys)) != 0)
		برو out;

	اگر (nkeys != 1) {
		/* XXX only one key supported at present */
		r = SSH_ERR_INVALID_FORMAT;
		برو out;
	}

	اگر ((r = sshkey_froms(decoded, &pubkey)) != 0 ||
	    (r = sshbuf_get_u32(decoded, &encrypted_len)) != 0)
		برو out;

	اگر ((cipher = cipher_by_name(ciphername)) == پوچ) {
		r = SSH_ERR_کلید_UNKNOWN_CIPHER;
		برو out;
	}
	اگر (strcmp(kdfname, "none") != 0 && strcmp(kdfname, "bcrypt") != 0) {
		r = SSH_ERR_کلید_UNKNOWN_CIPHER;
		برو out;
	}
	اگر (strcmp(kdfname, "none") == 0 && strcmp(ciphername, "none") != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		برو out;
	}
	اگر ((passphrase == پوچ || strlen(passphrase) == 0) &&
	    strcmp(kdfname, "none") != 0) {
		/* passphrase required */
		r = SSH_ERR_کلید_WRONG_PASSPHRASE;
		برو out;
	}

	/* check size of encrypted key blob */
	blocksize = cipher_blocksize(cipher);
	اگر (encrypted_len < blocksize || (encrypted_len % blocksize) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		برو out;
	}

	/* setup key */
	keylen = cipher_keylen(cipher);
	ivlen = cipher_ivlen(cipher);
	authlen = cipher_authlen(cipher);
	اگر ((کلید = calloc(1, keylen + ivlen)) == پوچ) {
		r = SSH_ERR_ALLOC_FAIL;
		برو out;
	}
	اگر (strcmp(kdfname, "bcrypt") == 0) {
		اگر ((r = sshbuf_get_string(kdf, &salt, &slen)) != 0 ||
		    (r = sshbuf_get_u32(kdf, &rounds)) != 0)
			برو out;
		اگر (rounds > MAX_KDF_ROUNDS) {
			r = SSH_ERR_INVALID_FORMAT;
			برو out;
		}
		اگر (bcrypt_pbkdf(passphrase, strlen(passphrase), salt, slen,
		    کلید, keylen + ivlen, rounds) < 0) {
			r = SSH_ERR_INVALID_FORMAT;
			برو out;
		}
	}

	/* check that an appropriate amount of auth data is present */
	اگر (sshbuf_len(decoded) < authlen ||
	    sshbuf_len(decoded) - authlen < encrypted_len) {
		r = SSH_ERR_INVALID_FORMAT;
		برو out;
	}

	/* decrypt private portion of key */
	اگر ((r = sshbuf_reserve(decrypted, encrypted_len, &dp)) != 0 ||
	    (r = cipher_init(&ciphercontext, cipher, کلید, keylen,
	    کلید + keylen, ivlen, 0)) != 0)
		برو out;
	اگر ((r = cipher_crypt(ciphercontext, 0, dp, sshbuf_ptr(decoded),
	    encrypted_len, 0, authlen)) != 0) {
		/* an integrity error here indicates an incorrect passphrase */
		اگر (r == SSH_ERR_MAC_INVALID)
			r = SSH_ERR_کلید_WRONG_PASSPHRASE;
		برو out;
	}
	اگر ((r = sshbuf_consume(decoded, encrypted_len + authlen)) != 0)
		برو out;
	/* there should be no trailing data */
	اگر (sshbuf_len(decoded) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		برو out;
	}

	/* check check bytes */
	اگر ((r = sshbuf_get_u32(decrypted, &check1)) != 0 ||
	    (r = sshbuf_get_u32(decrypted, &check2)) != 0)
		برو out;
	اگر (check1 != check2) {
		r = SSH_ERR_کلید_WRONG_PASSPHRASE;
		برو out;
	}
	/* success */
	*decryptedp = decrypted;
	decrypted = پوچ;
	*pubkeyp = pubkey;
	pubkey = پوچ;
	r = 0;
 out:
	cipher_free(ciphercontext);
	آزاد(ciphername);
	آزاد(kdfname);
	sshkey_free(pubkey);
	اگر (salt != پوچ) {
		explicit_bzero(salt, slen);
		آزاد(salt);
	}
	اگر (کلید != پوچ) {
		explicit_bzero(کلید, keylen + ivlen);
		آزاد(کلید);
	}
	sshbuf_free(kdf);
	sshbuf_free(decrypted);
	بازگشت r;
}

ایستا صحیح
sshkey_parse_private2(ساختار sshbuf *blob, صحیح type, ثابت نویسه *passphrase,
    ساختار sshkey **keyp, نویسه **commentp)
{
	نویسه *comment = پوچ;
	صحیح r = SSH_ERR_INTERNAL_ERROR;
	ساختار sshbuf *decoded = پوچ, *decrypted = پوچ;
	ساختار sshkey *k = پوچ, *pubkey = پوچ;

	اگر (keyp != پوچ)
		*keyp = پوچ;
	اگر (commentp != پوچ)
		*commentp = پوچ;

	/* Undo base64 encoding and decrypt the private section */
	اگر ((r = private2_uudecode(blob, &decoded)) != 0 ||
	    (r = private2_decrypt(decoded, passphrase,
	    &decrypted, &pubkey)) != 0)
		برو out;

	اگر (type != کلید_UNSPEC &&
	    sshkey_type_plain(type) != sshkey_type_plain(pubkey->type)) {
		r = SSH_ERR_کلید_TYPE_MISMATCH;
		برو out;
	}

	/* Load the private key and comment */
	اگر ((r = sshkey_private_deserialize(decrypted, &k)) != 0 ||
	    (r = sshbuf_get_cstring(decrypted, &comment, پوچ)) != 0)
		برو out;

	/* Check deterministic padding after private section */
	اگر ((r = private2_check_padding(decrypted)) != 0)
		برو out;

	/* Check that the public key in the envelope matches the private key */
	اگر (!sshkey_equal(pubkey, k)) {
		r = SSH_ERR_INVALID_FORMAT;
		برو out;
	}

	/* success */
	r = 0;
	اگر (keyp != پوچ) {
		*keyp = k;
		k = پوچ;
	}
	اگر (commentp != پوچ) {
		*commentp = comment;
		comment = پوچ;
	}
 out:
	آزاد(comment);
	sshbuf_free(decoded);
	sshbuf_free(decrypted);
	sshkey_free(k);
	sshkey_free(pubkey);
	بازگشت r;
}

ایستا صحیح
sshkey_parse_private2_pubkey(ساختار sshbuf *blob, صحیح type,
    ساختار sshkey **keyp)
{
	صحیح r = SSH_ERR_INTERNAL_ERROR;
	ساختار sshbuf *decoded = پوچ;
	ساختار sshkey *pubkey = پوچ;
	u_int nkeys = 0;

	اگر (keyp != پوچ)
		*keyp = پوچ;

	اگر ((r = private2_uudecode(blob, &decoded)) != 0)
		برو out;
	/* parse public key from unencrypted envelope */
	اگر ((r = sshbuf_consume(decoded, اندازه(AUTH_MAGIC))) != 0 ||
	    (r = sshbuf_skip_string(decoded)) != 0 || /* cipher */
	    (r = sshbuf_skip_string(decoded)) != 0 || /* KDF alg */
	    (r = sshbuf_skip_string(decoded)) != 0 || /* KDF hint */
	    (r = sshbuf_get_u32(decoded, &nkeys)) != 0)
		برو out;

	اگر (nkeys != 1) {
		/* XXX only one key supported at present */
		r = SSH_ERR_INVALID_FORMAT;
		برو out;
	}

	/* Parse the public key */
	اگر ((r = sshkey_froms(decoded, &pubkey)) != 0)
		برو out;

	اگر (type != کلید_UNSPEC &&
	    sshkey_type_plain(type) != sshkey_type_plain(pubkey->type)) {
		r = SSH_ERR_کلید_TYPE_MISMATCH;
		برو out;
	}

	/* success */
	r = 0;
	اگر (keyp != پوچ) {
		*keyp = pubkey;
		pubkey = پوچ;
	}
 out:
	sshbuf_free(decoded);
	sshkey_free(pubkey);
	بازگشت r;
}

#ifdef WITH_OPENSSL
/* convert SSH v2 key to PEM or PKCS#8 format */
ایستا صحیح
sshkey_private_to_blob_pem_pkcs8(ساختار sshkey *کلید, ساختار sshbuf *buf,
    صحیح format, ثابت نویسه *_passphrase, ثابت نویسه *comment)
{
	صحیح was_shielded = sshkey_is_shielded(کلید);
	صحیح success, r;
	صحیح blen, len = strlen(_passphrase);
	u_char *passphrase = (len > 0) ? (u_char *)_passphrase : پوچ;
	ثابت EVP_CIPHER *cipher = (len > 0) ? EVP_aes_128_cbc() : پوچ;
	نویسه *bptr;
	BIO *bio = پوچ;
	ساختار sshbuf *blob;
	EVP_PKEY *pkey = پوچ;

	اگر (len > 0 && len <= 4)
		بازگشت SSH_ERR_PASSPHRASE_TOO_SHORT;
	اگر ((blob = sshbuf_new()) == پوچ)
		بازگشت SSH_ERR_ALLOC_FAIL;
	اگر ((bio = BIO_new(BIO_s_mem())) == پوچ) {
		r = SSH_ERR_ALLOC_FAIL;
		برو out;
	}
	اگر ((r = sshkey_unshield_private(کلید)) != 0)
		برو out;

	انتخاب (کلید->type) {
	حالت کلید_ECDSA:
		اگر (format == SSHKEY_PRIVATE_PEM) {
			success = PEM_write_bio_ECPrivate_کلید(bio,
			    EVP_PKEY_get0_EC_کلید(کلید->pkey),
			    cipher, passphrase, len, پوچ, پوچ);
		} وگرنه {
			pkey = کلید->pkey;
			EVP_PKEY_up_ref(کلید->pkey);
			success = 1;
		}
		بشکن;
	حالت کلید_RSA:
		اگر (format == SSHKEY_PRIVATE_PEM) {
			success = PEM_write_bio_RSAPrivate_کلید(bio,
			    EVP_PKEY_get0_RSA(کلید->pkey),
			    cipher, passphrase, len, پوچ, پوچ);
		} وگرنه {
			pkey = کلید->pkey;
			EVP_PKEY_up_ref(کلید->pkey);
			success = 1;
		}
		بشکن;
#ifdef OPENSSL_HAS_ED25519
	حالت کلید_ED25519:
		اگر (format == SSHKEY_PRIVATE_PEM) {
			r = SSH_ERR_INVALID_FORMAT;
			برو out;
		} وگرنه {
			pkey = EVP_PKEY_new_raw_private_کلید(EVP_PKEY_ED25519,
			    پوچ, کلید->ed25519_sk,
			    ED25519_SK_SZ - ED25519_PK_SZ);
			success = pkey != پوچ;
		}
		بشکن;
#endif
	پیشفرض:
		success = 0;
		بشکن;
	}
	اگر (success == 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		برو out;
	}
	اگر (format == SSHKEY_PRIVATE_PKCS8) {
		اگر ((success = PEM_write_bio_Private_کلید(bio, pkey, cipher,
		    passphrase, len, پوچ, پوچ)) == 0) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			برو out;
		}
	}
	اگر ((blen = BIO_get_mem_data(bio, &bptr)) <= 0) {
		r = SSH_ERR_INTERNAL_ERROR;
		برو out;
	}
	اگر ((r = sshbuf_put(blob, bptr, blen)) != 0)
		برو out;
	r = 0;
 out:
	اگر (was_shielded)
		r = sshkey_shield_private(کلید);
	اگر (r == 0)
		r = sshbuf_putb(buf, blob);

	EVP_PKEY_free(pkey);
	sshbuf_free(blob);
	BIO_free(bio);
	بازگشت r;
}
#endif /* WITH_OPENSSL */

/* Serialise "key" to buffer "blob" */
صحیح
sshkey_private_to_fileblob(ساختار sshkey *کلید, ساختار sshbuf *blob,
    ثابت نویسه *passphrase, ثابت نویسه *comment,
    صحیح format, ثابت نویسه *openssh_format_cipher, صحیح openssh_format_rounds)
{
	انتخاب (کلید->type) {
#ifdef WITH_OPENSSL
	حالت کلید_ECDSA:
	حالت کلید_RSA:
	حالت کلید_ED25519:
		بشکن; /* see below */
#وگرنه /* WITH_OPENSSL */
	حالت کلید_ED25519:
#endif /* WITH_OPENSSL */
	حالت کلید_ED25519_SK:
#ifdef WITH_OPENSSL
	حالت کلید_ECDSA_SK:
#endif /* WITH_OPENSSL */
	حالت کلید_MLDSA44_ED25519:
		بازگشت sshkey_private_to_blob2(کلید, blob, passphrase,
		    comment, openssh_format_cipher, openssh_format_rounds);
	پیشفرض:
		بازگشت SSH_ERR_کلید_TYPE_UNKNOWN;
	}

#ifdef WITH_OPENSSL
	انتخاب (format) {
	حالت SSHKEY_PRIVATE_OPENSSH:
		بازگشت sshkey_private_to_blob2(کلید, blob, passphrase,
		    comment, openssh_format_cipher, openssh_format_rounds);
	حالت SSHKEY_PRIVATE_PEM:
	حالت SSHKEY_PRIVATE_PKCS8:
		بازگشت sshkey_private_to_blob_pem_pkcs8(کلید, blob,
		    format, passphrase, comment);
	پیشفرض:
		بازگشت SSH_ERR_INVALID_ARGUMENT;
	}
#endif /* WITH_OPENSSL */
}

#ifdef WITH_OPENSSL
ایستا صحیح
translate_libcrypto_error(unsigned long pem_err)
{
	صحیح pem_reason = ERR_GET_REASON(pem_err);

	انتخاب (ERR_GET_LIB(pem_err)) {
	حالت ERR_LIB_PEM:
		انتخاب (pem_reason) {
		حالت PEM_R_BAD_PASSWORD_READ:
#ifdef PEM_R_PROBLEMS_GETTING_PASSWORD
		حالت PEM_R_PROBLEMS_GETTING_PASSWORD:
#endif
#ifdef PEM_R_BAD_DECRYPT
		حالت PEM_R_BAD_DECRYPT:
#endif
			بازگشت SSH_ERR_کلید_WRONG_PASSPHRASE;
		پیشفرض:
			بازگشت SSH_ERR_INVALID_FORMAT;
		}
	حالت ERR_LIB_EVP:
		انتخاب (pem_reason) {
#ifdef EVP_R_BAD_DECRYPT
		حالت EVP_R_BAD_DECRYPT:
			بازگشت SSH_ERR_کلید_WRONG_PASSPHRASE;
#endif
#ifdef EVP_R_BN_DECODE_ERROR
		حالت EVP_R_BN_DECODE_ERROR:
#endif
		حالت EVP_R_DECODE_ERROR:
#ifdef EVP_R_PRIVATE_کلید_DECODE_ERROR
		حالت EVP_R_PRIVATE_کلید_DECODE_ERROR:
#endif
			بازگشت SSH_ERR_INVALID_FORMAT;
		پیشفرض:
			بازگشت SSH_ERR_LIBCRYPTO_ERROR;
		}
	حالت ERR_LIB_ASN1:
#ifdef ERR_LIB_OSSL_DECODER
	حالت ERR_LIB_OSSL_DECODER:
#endif
		بازگشت SSH_ERR_INVALID_FORMAT;
	}
	بازگشت SSH_ERR_LIBCRYPTO_ERROR;
}

ایستا تهی
clear_libcrypto_errors(تهی)
{
	وقتی (ERR_get_error() != 0)
		;
}

/*
 * Translate OpenSSL error codes to determine whether
 * passphrase is required/incorrect.
 */
ایستا صحیح
convert_libcrypto_error(تهی)
{
	/*
	 * Some password errors are reported at the beginning
	 * of the error queue.
	 */
	اگر (translate_libcrypto_error(ERR_peek_error()) ==
	    SSH_ERR_کلید_WRONG_PASSPHRASE)
		بازگشت SSH_ERR_کلید_WRONG_PASSPHRASE;
	بازگشت translate_libcrypto_error(ERR_peek_last_error());
}

ایستا صحیح
pem_passphrase_cb(نویسه *buf, صحیح size, صحیح rwflag, تهی *u)
{
	نویسه *p = (نویسه *)u;
	size_t len;

	اگر (p == پوچ || (len = strlen(p)) == 0)
		بازگشت -1;
	اگر (size < 0 || len > (size_t)size)
		بازگشت -1;
	memcpy(buf, p, len);
	بازگشت (صحیح)len;
}

ایستا صحیح
sshkey_parse_private_pem_fileblob(ساختار sshbuf *blob, صحیح type,
    ثابت نویسه *passphrase, ساختار sshkey **keyp)
{
	EVP_PKEY *pk = پوچ;
	ساختار sshkey *prv = پوچ;
	BIO *bio = پوچ;
	صحیح r;
	RSA *rsa = پوچ;
	EC_کلید *ecdsa = پوچ;

	اگر (keyp != پوچ)
		*keyp = پوچ;

	اگر ((bio = BIO_new(BIO_s_mem())) == پوچ || sshbuf_len(blob) > INT_MAX)
		بازگشت SSH_ERR_ALLOC_FAIL;
	اگر (BIO_write(bio, sshbuf_ptr(blob), sshbuf_len(blob)) !=
	    (صحیح)sshbuf_len(blob)) {
		r = SSH_ERR_ALLOC_FAIL;
		برو out;
	}

	clear_libcrypto_errors();
	اگر ((pk = PEM_read_bio_Private_کلید(bio, پوچ, pem_passphrase_cb,
	    (نویسه *)passphrase)) == پوچ) {
		/*
		 * libcrypto may return various ASN.1 errors when attempting
		 * to parse a key with an incorrect passphrase.
		 * Treat all format errors as "incorrect passphrase" if a
		 * passphrase was supplied.
		 */
		اگر (passphrase != پوچ && *passphrase != '\0')
			r = SSH_ERR_کلید_WRONG_PASSPHRASE;
		وگرنه
			r = convert_libcrypto_error();
		برو out;
	}
	اگر (EVP_PKEY_base_id(pk) == EVP_PKEY_RSA &&
	    (type == کلید_UNSPEC || type == کلید_RSA)) {
		اگر ((prv = sshkey_new(کلید_UNSPEC)) == پوچ) {
			r = SSH_ERR_ALLOC_FAIL;
			برو out;
		}
		اگر ((rsa = EVP_PKEY_get1_RSA(pk)) == پوچ) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			برو out;
		}
		prv->type = کلید_RSA;
#ifdef DEBUG_PK
		RSA_print_fp(stderr, rsa, 8);
#endif
		اگر (RSA_blinding_on(rsa, پوچ) != 1 ||
		    EVP_PKEY_set1_RSA(pk, rsa) != 1) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			برو out;
		}
		EVP_PKEY_up_ref(pk);
		prv->pkey = pk;
		اگر ((r = sshkey_check_rsa_length(prv, 0)) != 0)
			برو out;
	} وگرنه اگر (EVP_PKEY_base_id(pk) == EVP_PKEY_EC &&
	    (type == کلید_UNSPEC || type == کلید_ECDSA)) {
		اگر ((prv = sshkey_new(کلید_UNSPEC)) == پوچ) {
			r = SSH_ERR_ALLOC_FAIL;
			برو out;
		}
		اگر ((prv->ecdsa_nid = sshkey_ecdsa_fixup_group(pk)) == -1 ||
		    (ecdsa = EVP_PKEY_get1_EC_کلید(pk)) == پوچ) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			برو out;
		}
		prv->type = کلید_ECDSA;
		اگر (sshkey_curve_nid_to_name(prv->ecdsa_nid) == پوچ ||
		    sshkey_ec_validate_public(EC_کلید_get0_group(ecdsa),
		    EC_کلید_get0_public_کلید(ecdsa)) != 0 ||
		    sshkey_ec_validate_private(ecdsa) != 0) {
			r = SSH_ERR_INVALID_FORMAT;
			برو out;
		}
		EVP_PKEY_up_ref(pk);
		prv->pkey = pk;
#ifdef DEBUG_PK
		اگر (prv != پوچ && prv->pkey != پوچ)
			sshkey_dump_ec_کلید(EVP_PKEY_get0_EC_کلید(prv->pkey));
#endif
#ifdef OPENSSL_HAS_ED25519
	} وگرنه اگر (EVP_PKEY_base_id(pk) == EVP_PKEY_ED25519 &&
	    (type == کلید_UNSPEC || type == کلید_ED25519)) {
		size_t len;

		اگر ((prv = sshkey_new(کلید_UNSPEC)) == پوچ ||
		    (prv->ed25519_sk = calloc(1, ED25519_SK_SZ)) == پوچ ||
		    (prv->ed25519_pk = calloc(1, ED25519_PK_SZ)) == پوچ) {
			r = SSH_ERR_ALLOC_FAIL;
			برو out;
		}
		prv->type = کلید_ED25519;
		len = ED25519_PK_SZ;
		اگر (!EVP_PKEY_get_raw_public_کلید(pk, prv->ed25519_pk, &len)) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			برو out;
		}
		اگر (len != ED25519_PK_SZ) {
			r = SSH_ERR_INVALID_FORMAT;
			برو out;
		}
		len = ED25519_SK_SZ - ED25519_PK_SZ;
		اگر (!EVP_PKEY_get_raw_private_کلید(pk, prv->ed25519_sk, &len)) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			برو out;
		}
		اگر (len != ED25519_SK_SZ - ED25519_PK_SZ) {
			r = SSH_ERR_INVALID_FORMAT;
			برو out;
		}
		/* Append the public key to our private key */
		memcpy(prv->ed25519_sk + (ED25519_SK_SZ - ED25519_PK_SZ),
		    prv->ed25519_pk, ED25519_PK_SZ);
#ifdef DEBUG_PK
		sshbuf_dump_data(prv->ed25519_sk, ED25519_SK_SZ, stderr);
#endif
#endif /* OPENSSL_HAS_ED25519 */
	} وگرنه {
		r = SSH_ERR_INVALID_FORMAT;
		برو out;
	}
	r = 0;
	اگر (keyp != پوچ) {
		*keyp = prv;
		prv = پوچ;
	}
 out:
	BIO_free(bio);
	EVP_PKEY_free(pk);
	RSA_free(rsa);
	EC_کلید_free(ecdsa);
	sshkey_free(prv);
	بازگشت r;
}
#endif /* WITH_OPENSSL */

صحیح
sshkey_parse_private_fileblob_type(ساختار sshbuf *blob, صحیح type,
    ثابت نویسه *passphrase, ساختار sshkey **keyp, نویسه **commentp)
{
	صحیح r = SSH_ERR_INTERNAL_ERROR;

	اگر (keyp != پوچ)
		*keyp = پوچ;
	اگر (commentp != پوچ)
		*commentp = پوچ;

	r = sshkey_parse_private2(blob, type, passphrase, keyp, commentp);
	/* Only fallback to PEM parser if a format error occurred. */
	اگر (r != SSH_ERR_INVALID_FORMAT)
		بازگشت r;
#ifdef WITH_OPENSSL
	بازگشت sshkey_parse_private_pem_fileblob(blob, type,
	    passphrase, keyp);
#وگرنه
	بازگشت SSH_ERR_INVALID_FORMAT;
#endif /* WITH_OPENSSL */
}

صحیح
sshkey_parse_private_fileblob(ساختار sshbuf *buffer, ثابت نویسه *passphrase,
    ساختار sshkey **keyp, نویسه **commentp)
{
	اگر (keyp != پوچ)
		*keyp = پوچ;
	اگر (commentp != پوچ)
		*commentp = پوچ;

	بازگشت sshkey_parse_private_fileblob_type(buffer, کلید_UNSPEC,
	    passphrase, keyp, commentp);
}

تهی
sshkey_sig_details_free(ساختار sshkey_sig_details *details)
{
	freezero(details, اندازه(*details));
}

صحیح
sshkey_parse_pubkey_from_private_fileblob_type(ساختار sshbuf *blob, صحیح type,
    ساختار sshkey **pubkeyp)
{
	صحیح r = SSH_ERR_INTERNAL_ERROR;

	اگر (pubkeyp != پوچ)
		*pubkeyp = پوچ;
	/* only new-format private keys bundle a public key inside */
	اگر ((r = sshkey_parse_private2_pubkey(blob, type, pubkeyp)) != 0)
		بازگشت r;
	بازگشت 0;
}
