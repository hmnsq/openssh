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

#ضمن "includes.h"

#ضمن <sys/types.h>
#ضمن <sys/mman.h>
#ضمن <netinet/in.h>

#ifdef WITH_OPENSSL
#ضمن <openssl/bn.h>
#ضمن <openssl/evp.h>
#ضمن <openssl/err.h>
#ضمن <openssl/pem.h>
#endif

#ضمن "crypto_api.h"

#ضمن <errno.h>
#ضمن <limits.h>
#ضمن <stdio.h>
#ضمن <stdlib.h>
#ضمن <string.h>
#ضمن <resolv.h>
#ضمن <time.h>
#ضمن <util.h>

#ضمن "ssh2.h"
#ضمن "ssherr.h"
#ضمن "misc.h"
#ضمن "sshbuf.h"
#ضمن "cipher.h"
#ضمن "digest.h"
#define SSHKEY_INTERNAL
#ضمن "sshkey.h"
#ضمن "match.h"
#ضمن "ssh-sk.h"
#ضمن "ssh-pkcs11.h"

#ضمن "openbsd-compat/openssl-compat.h"

/* openssh private key file format */
#define MARK_BEGIN		"-----BEGIN OPENSSH PRIVATE KEY-----\n"
#define MARK_END		"-----END OPENSSH PRIVATE KEY-----\n"
#define MARK_BEGIN_LEN		(حجم(MARK_BEGIN) - 1)
#define MARK_END_LEN		(حجم(MARK_END) - 1)
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

ساكن صحيح sshkey_from_blob_internal(بنية sshbuf *buf,
    بنية sshkey **keyp, صحيح allow_cert,
    ثابت حرف *alg_allowlist, ثابت حرف *ca_sigalg_allowlist);

/* Supported key types */
خارجي ثابت بنية sshkey_impl sshkey_ed25519_impl;
خارجي ثابت بنية sshkey_impl sshkey_ed25519_cert_impl;
خارجي ثابت بنية sshkey_impl sshkey_ed25519_sk_impl;
خارجي ثابت بنية sshkey_impl sshkey_ed25519_sk_cert_impl;
# ifdef USE_MLDSA
خارجي ثابت بنية sshkey_impl sshkey_mldsa44_ed25519_impl;
خارجي ثابت بنية sshkey_impl sshkey_mldsa44_ed25519_cert_impl;
# endif /* USE_MLDSA */
#ifdef WITH_OPENSSL
# ifdef ENABLE_SK
خارجي ثابت بنية sshkey_impl sshkey_ecdsa_sk_impl;
خارجي ثابت بنية sshkey_impl sshkey_ecdsa_sk_cert_impl;
خارجي ثابت بنية sshkey_impl sshkey_ecdsa_sk_webauthn_impl;
خارجي ثابت بنية sshkey_impl sshkey_ecdsa_sk_webauthn_cert_impl;
# endif /* ENABLE_SK */
خارجي ثابت بنية sshkey_impl sshkey_ecdsa_nistp256_impl;
خارجي ثابت بنية sshkey_impl sshkey_ecdsa_nistp256_cert_impl;
خارجي ثابت بنية sshkey_impl sshkey_ecdsa_nistp384_impl;
خارجي ثابت بنية sshkey_impl sshkey_ecdsa_nistp384_cert_impl;
خارجي ثابت بنية sshkey_impl sshkey_ecdsa_nistp521_impl;
خارجي ثابت بنية sshkey_impl sshkey_ecdsa_nistp521_cert_impl;
خارجي ثابت بنية sshkey_impl sshkey_rsa_impl;
خارجي ثابت بنية sshkey_impl sshkey_rsa_cert_impl;
خارجي ثابت بنية sshkey_impl sshkey_rsa_sha256_impl;
خارجي ثابت بنية sshkey_impl sshkey_rsa_sha256_cert_impl;
خارجي ثابت بنية sshkey_impl sshkey_rsa_sha512_impl;
خارجي ثابت بنية sshkey_impl sshkey_rsa_sha512_cert_impl;
#endif /* WITH_OPENSSL */

ثابت بنية sshkey_impl * ثابت keyimpls[] = {
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
	عدم
};

ساكن ثابت بنية sshkey_impl *
sshkey_impl_from_type(صحيح type)
{
	صحيح i;

	لكل (i = 0; keyimpls[i] != عدم; i++) {
		إذا (keyimpls[i]->type == type)
			إرجاع keyimpls[i];
	}
	إرجاع عدم;
}

ساكن ثابت بنية sshkey_impl *
sshkey_impl_from_type_nid(صحيح type, صحيح nid)
{
	صحيح i;

	لكل (i = 0; keyimpls[i] != عدم; i++) {
		إذا (keyimpls[i]->type == type &&
		    (keyimpls[i]->nid == 0 || keyimpls[i]->nid == nid))
			إرجاع keyimpls[i];
	}
	إرجاع عدم;
}

ساكن ثابت بنية sshkey_impl *
sshkey_impl_from_مفتاح(ثابت بنية sshkey *k)
{
	إذا (k == عدم)
		إرجاع عدم;
	إرجاع sshkey_impl_from_type_nid(k->type, k->ecdsa_nid);
}

ثابت حرف *
sshkey_type(ثابت بنية sshkey *k)
{
	ثابت بنية sshkey_impl *impl;

	إذا ((impl = sshkey_impl_from_مفتاح(k)) == عدم)
		إرجاع "unknown";
	إرجاع impl->shortname;
}

ساكن ثابت حرف *
sshkey_ssh_name_from_type_nid(صحيح type, صحيح nid)
{
	ثابت بنية sshkey_impl *impl;

	إذا ((impl = sshkey_impl_from_type_nid(type, nid)) == عدم)
		إرجاع "ssh-unknown";
	إرجاع impl->name;
}

صحيح
sshkey_type_is_cert(صحيح type)
{
	ثابت بنية sshkey_impl *impl;

	إذا ((impl = sshkey_impl_from_type(type)) == عدم)
		إرجاع 0;
	إرجاع impl->cert;
}

ثابت حرف *
sshkey_ssh_name(ثابت بنية sshkey *k)
{
	إرجاع sshkey_ssh_name_from_type_nid(k->type, k->ecdsa_nid);
}

ثابت حرف *
sshkey_ssh_name_plain(ثابت بنية sshkey *k)
{
	إرجاع sshkey_ssh_name_from_type_nid(sshkey_type_plain(k->type),
	    k->ecdsa_nid);
}

ساكن صحيح
type_from_name(ثابت حرف *name, صحيح allow_short)
{
	صحيح i;
	ثابت بنية sshkey_impl *impl;

	لكل (i = 0; keyimpls[i] != عدم; i++) {
		impl = keyimpls[i];
		إذا (impl->name != عدم && strcmp(name, impl->name) == 0)
			إرجاع impl->type;
		/* Only allow shortname matches for plain key types */
		إذا (allow_short && !impl->cert && impl->shortname != عدم &&
		    strcasecmp(impl->shortname, name) == 0)
			إرجاع impl->type;
	}
	إرجاع مفتاح_UNSPEC;
}

صحيح
sshkey_type_from_name(ثابت حرف *name)
{
	إرجاع type_from_name(name, 0);
}

صحيح
sshkey_type_from_shortname(ثابت حرف *name)
{
	إرجاع type_from_name(name, 1);
}

ساكن صحيح
مفتاح_type_is_ecdsa_variant(صحيح type)
{
	بدل (type) {
	حالة مفتاح_ECDSA:
	حالة مفتاح_ECDSA_CERT:
	حالة مفتاح_ECDSA_SK:
	حالة مفتاح_ECDSA_SK_CERT:
		إرجاع 1;
	}
	إرجاع 0;
}

صحيح
sshkey_ecdsa_nid_from_name(ثابت حرف *name)
{
	صحيح i;

	لكل (i = 0; keyimpls[i] != عدم; i++) {
		إذا (!مفتاح_type_is_ecdsa_variant(keyimpls[i]->type))
			استمر;
		إذا (keyimpls[i]->name != عدم &&
		    strcmp(name, keyimpls[i]->name) == 0)
			إرجاع keyimpls[i]->nid;
	}
	إرجاع -1;
}

صحيح
sshkey_match_keyname_to_sigalgs(ثابت حرف *keyname, ثابت حرف *sigalgs)
{
	صحيح ktype;

	إذا (sigalgs == عدم || *sigalgs == '\0' ||
	    (ktype = sshkey_type_from_name(keyname)) == مفتاح_UNSPEC)
		إرجاع 0;
	وإلا إذا (ktype == مفتاح_RSA) {
		إرجاع match_pattern_list("ssh-rsa", sigalgs, 0) == 1 ||
		    match_pattern_list("rsa-sha2-256", sigalgs, 0) == 1 ||
		    match_pattern_list("rsa-sha2-512", sigalgs, 0) == 1;
	} وإلا إذا (ktype == مفتاح_RSA_CERT) {
		إرجاع match_pattern_list("ssh-rsa-cert-v01@openssh.com",
		    sigalgs, 0) == 1 ||
		    match_pattern_list("rsa-sha2-256-cert-v01@openssh.com",
		    sigalgs, 0) == 1 ||
		    match_pattern_list("rsa-sha2-512-cert-v01@openssh.com",
		    sigalgs, 0) == 1;
	} وإلا إذا (ktype == مفتاح_ECDSA_SK) {
		إرجاع match_pattern_list("sk-ecdsa-sha2-nistp256@openssh.com",
		    sigalgs, 0) == 1 || match_pattern_list(
		    "webauthn-sk-ecdsa-sha2-nistp256@openssh.com",
		    sigalgs, 0) == 1;
	} وإلا إذا (ktype == مفتاح_ECDSA_SK_CERT) {
		إرجاع match_pattern_list(
		    "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
		    sigalgs, 0) == 1 || match_pattern_list(
		    "webauthn-sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
		    sigalgs, 0) == 1;
	} وإلا
		إرجاع match_pattern_list(keyname, sigalgs, 0) == 1;
}

حرف *
sshkey_alg_list(صحيح certs_only, صحيح plain_only, صحيح include_sigonly, حرف sep)
{
	حرف *ret = عدم;
	size_t i;
	ثابت بنية sshkey_impl *impl;
	حرف sep_str[2] = {sep, '\0'};

	لكل (i = 0; keyimpls[i] != عدم; i++) {
		impl = keyimpls[i];
		إذا (impl->name == عدم)
			استمر;
		إذا (!include_sigonly && impl->sigonly)
			استمر;
		إذا ((certs_only && !impl->cert) || (plain_only && impl->cert))
			استمر;
		xextendf(&ret, sep_str, "%s", impl->name);
	}
	إرجاع ret;
}

صحيح
sshkey_names_valid2(ثابت حرف *names, صحيح allow_wildcard, صحيح plain_only)
{
	حرف *s, *cp, *p;
	ثابت بنية sshkey_impl *impl;
	صحيح i, type;

	إذا (names == عدم || strcmp(names, "") == 0)
		إرجاع 0;
	إذا ((s = cp = strdup(names)) == عدم)
		إرجاع 0;
	لكل ((p = strsep(&cp, ",")); p && *p != '\0';
	    (p = strsep(&cp, ","))) {
		type = sshkey_type_from_name(p);
		إذا (type == مفتاح_UNSPEC) {
			إذا (allow_wildcard) {
				/*
				 * Try matching key types against the string.
				 * If any has a positive or negative match then
				 * the component is accepted.
				 */
				impl = عدم;
				لكل (i = 0; keyimpls[i] != عدم; i++) {
					إذا (match_pattern_list(
					    keyimpls[i]->name, p, 0) != 0) {
						impl = keyimpls[i];
						اكسر;
					}
				}
				إذا (impl != عدم)
					استمر;
			}
			حرر(s);
			إرجاع 0;
		} وإلا إذا (plain_only && sshkey_type_is_cert(type)) {
			حرر(s);
			إرجاع 0;
		}
	}
	حرر(s);
	إرجاع 1;
}

u_int
sshkey_size(ثابت بنية sshkey *k)
{
	ثابت بنية sshkey_impl *impl;

	إذا ((impl = sshkey_impl_from_مفتاح(k)) == عدم)
		إرجاع 0;
	إذا (impl->funcs->size != عدم)
		إرجاع impl->funcs->size(k);
	إرجاع impl->keybits;
}

ساكن صحيح
sshkey_type_is_valid_ca(صحيح type)
{
	ثابت بنية sshkey_impl *impl;

	إذا ((impl = sshkey_impl_from_type(type)) == عدم)
		إرجاع 0;
	/* All non-certificate types may act as CAs */
	إرجاع !impl->cert;
}

صحيح
sshkey_is_cert(ثابت بنية sshkey *k)
{
	إذا (k == عدم)
		إرجاع 0;
	إرجاع sshkey_type_is_cert(k->type);
}

صحيح
sshkey_is_sk(ثابت بنية sshkey *k)
{
	إذا (k == عدم)
		إرجاع 0;
	بدل (sshkey_type_plain(k->type)) {
	حالة مفتاح_ECDSA_SK:
	حالة مفتاح_ED25519_SK:
		إرجاع 1;
	افتراضي:
		إرجاع 0;
	}
}

/* Return the cert-less equivalent to a certified key type */
صحيح
sshkey_type_plain(صحيح type)
{
	بدل (type) {
	حالة مفتاح_RSA_CERT:
		إرجاع مفتاح_RSA;
	حالة مفتاح_ECDSA_CERT:
		إرجاع مفتاح_ECDSA;
	حالة مفتاح_ECDSA_SK_CERT:
		إرجاع مفتاح_ECDSA_SK;
	حالة مفتاح_ED25519_CERT:
		إرجاع مفتاح_ED25519;
	حالة مفتاح_MLDSA44_ED25519_CERT:
		إرجاع مفتاح_MLDSA44_ED25519;
	حالة مفتاح_ED25519_SK_CERT:
		إرجاع مفتاح_ED25519_SK;
	افتراضي:
		إرجاع type;
	}
}

/* Return the cert equivalent to a plain key type */
ساكن صحيح
sshkey_type_certified(صحيح type)
{
	بدل (type) {
	حالة مفتاح_RSA:
		إرجاع مفتاح_RSA_CERT;
	حالة مفتاح_ECDSA:
		إرجاع مفتاح_ECDSA_CERT;
	حالة مفتاح_ECDSA_SK:
		إرجاع مفتاح_ECDSA_SK_CERT;
	حالة مفتاح_ED25519:
		إرجاع مفتاح_ED25519_CERT;
	حالة مفتاح_MLDSA44_ED25519:
		إرجاع مفتاح_MLDSA44_ED25519_CERT;
	حالة مفتاح_ED25519_SK:
		إرجاع مفتاح_ED25519_SK_CERT;
	افتراضي:
		إرجاع -1;
	}
}

#ifdef WITH_OPENSSL
ساكن ثابت EVP_MD *
ssh_digest_to_md(صحيح hash_alg)
{
	بدل (hash_alg) {
	حالة SSH_DIGEST_SHA1:
		إرجاع EVP_sha1();
	حالة SSH_DIGEST_SHA256:
		إرجاع EVP_sha256();
	حالة SSH_DIGEST_SHA384:
		إرجاع EVP_sha384();
	حالة SSH_DIGEST_SHA512:
		إرجاع EVP_sha512();
	}
	إرجاع عدم;
}

صحيح
sshkey_pkey_digest_sign(EVP_PKEY *pkey, صحيح hash_alg, u_char **sigp,
    size_t *lenp, ثابت u_char *data, size_t datalen)
{
	EVP_MD_CTX *ctx = عدم;
	u_char *sig = عدم;
	صحيح ret;
	size_t slen;
	ثابت EVP_MD *evpmd;

	*sigp = عدم;
	*lenp = 0;

	slen = EVP_PKEY_size(pkey);
	إذا (slen <= 0 || slen > SSHBUF_MAX_BIGNUM ||
	   (evpmd = ssh_digest_to_md(hash_alg)) == عدم)
		إرجاع SSH_ERR_INVALID_ARGUMENT;

	إذا ((sig = malloc(slen)) == عدم)
		إرجاع SSH_ERR_ALLOC_FAIL;

	إذا ((ctx = EVP_MD_CTX_new()) == عدم) {
		ret = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}
	إذا (EVP_DigestSignInit(ctx, عدم, evpmd, عدم, pkey) != 1 ||
	    EVP_DigestSign(ctx, sig, &slen, data, datalen) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		اذهب out;
	}

	*sigp = sig;
	*lenp = slen;
	/* Now owned by the caller */
	sig = عدم;
	ret = 0;

 out:
	EVP_MD_CTX_free(ctx);
	حرر(sig);
	إرجاع ret;
}

صحيح
sshkey_pkey_digest_verify(EVP_PKEY *pkey, صحيح hash_alg, ثابت u_char *data,
    size_t datalen, u_char *sigbuf, size_t siglen)
{
	EVP_MD_CTX *ctx = عدم;
	صحيح ret = SSH_ERR_INTERNAL_ERROR;
	ثابت EVP_MD *evpmd;

	إذا ((evpmd = ssh_digest_to_md(hash_alg)) == عدم)
		إرجاع SSH_ERR_INVALID_ARGUMENT;
	إذا ((ctx = EVP_MD_CTX_new()) == عدم)
		إرجاع SSH_ERR_ALLOC_FAIL;
	إذا (EVP_DigestVerifyInit(ctx, عدم, evpmd, عدم, pkey) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		اذهب out;
	}
	بدل (EVP_DigestVerify(ctx, sigbuf, siglen, data, datalen)) {
	حالة 1:
		ret = 0;
		اكسر;
	حالة 0:
		ret = SSH_ERR_SIGNATURE_INVALID;
		اكسر;
	افتراضي:
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		اكسر;
	}

 out:
	EVP_MD_CTX_free(ctx);
	إرجاع ret;
}

/* XXX: these are really begging for a table-driven approach */
صحيح
sshkey_curve_name_to_nid(ثابت حرف *name)
{
	إذا (strcmp(name, "nistp256") == 0)
		إرجاع NID_X9_62_prime256v1;
	وإلا إذا (strcmp(name, "nistp384") == 0)
		إرجاع NID_secp384r1;
	وإلا إذا (strcmp(name, "nistp521") == 0)
		إرجاع NID_secp521r1;
	وإلا
		إرجاع -1;
}

u_int
sshkey_curve_nid_to_bits(صحيح nid)
{
	بدل (nid) {
	حالة NID_X9_62_prime256v1:
		إرجاع 256;
	حالة NID_secp384r1:
		إرجاع 384;
	حالة NID_secp521r1:
		إرجاع 521;
	افتراضي:
		إرجاع 0;
	}
}

صحيح
sshkey_ecdsa_bits_to_nid(صحيح bits)
{
	بدل (bits) {
	حالة 256:
		إرجاع NID_X9_62_prime256v1;
	حالة 384:
		إرجاع NID_secp384r1;
	حالة 521:
		إرجاع NID_secp521r1;
	افتراضي:
		إرجاع -1;
	}
}

ثابت حرف *
sshkey_curve_nid_to_name(صحيح nid)
{
	بدل (nid) {
	حالة NID_X9_62_prime256v1:
		إرجاع "nistp256";
	حالة NID_secp384r1:
		إرجاع "nistp384";
	حالة NID_secp521r1:
		إرجاع "nistp521";
	افتراضي:
		إرجاع عدم;
	}
}

صحيح
sshkey_ec_nid_to_hash_alg(صحيح nid)
{
	صحيح kbits = sshkey_curve_nid_to_bits(nid);

	إذا (kbits <= 0)
		إرجاع -1;

	/* RFC5656 section 6.2.1 */
	إذا (kbits <= 256)
		إرجاع SSH_DIGEST_SHA256;
	وإلا إذا (kbits <= 384)
		إرجاع SSH_DIGEST_SHA384;
	وإلا
		إرجاع SSH_DIGEST_SHA512;
}
#endif /* WITH_OPENSSL */

ساكن فراغ
cert_free(بنية sshkey_cert *cert)
{
	u_int i;

	إذا (cert == عدم)
		إرجاع;
	sshbuf_free(cert->certblob);
	sshbuf_free(cert->critical);
	sshbuf_free(cert->extensions);
	حرر(cert->مفتاح_id);
	لكل (i = 0; i < cert->nprincipals; i++)
		حرر(cert->principals[i]);
	حرر(cert->principals);
	sshkey_free(cert->signature_مفتاح);
	حرر(cert->signature_type);
	freezero(cert, حجم(*cert));
}

ساكن بنية sshkey_cert *
cert_new(فراغ)
{
	بنية sshkey_cert *cert;

	إذا ((cert = calloc(1, حجم(*cert))) == عدم)
		إرجاع عدم;
	إذا ((cert->certblob = sshbuf_new()) == عدم ||
	    (cert->critical = sshbuf_new()) == عدم ||
	    (cert->extensions = sshbuf_new()) == عدم) {
		cert_free(cert);
		إرجاع عدم;
	}
	cert->مفتاح_id = عدم;
	cert->principals = عدم;
	cert->signature_مفتاح = عدم;
	cert->signature_type = عدم;
	إرجاع cert;
}

بنية sshkey *
sshkey_new(صحيح type)
{
	بنية sshkey *k;
	ثابت بنية sshkey_impl *impl = عدم;

	إذا (type != مفتاح_UNSPEC &&
	    (impl = sshkey_impl_from_type(type)) == عدم)
		إرجاع عدم;

	/* All non-certificate types may act as CAs */
	إذا ((k = calloc(1, حجم(*k))) == عدم)
		إرجاع عدم;
	k->type = type;
	k->ecdsa_nid = -1;
	إذا (impl != عدم && impl->funcs->alloc != عدم) {
		إذا (impl->funcs->alloc(k) != 0) {
			حرر(k);
			إرجاع عدم;
		}
	}
	إذا (sshkey_is_cert(k)) {
		إذا ((k->cert = cert_new()) == عدم) {
			sshkey_free(k);
			إرجاع عدم;
		}
	}

	إرجاع k;
}

/* Frees common FIDO fields */
فراغ
sshkey_sk_cleanup(بنية sshkey *k)
{
	حرر(k->sk_application);
	sshbuf_free(k->sk_مفتاح_handle);
	sshbuf_free(k->sk_reserved);
	k->sk_application = عدم;
	k->sk_مفتاح_handle = k->sk_reserved = عدم;
}

#إذا defined(MAP_CONCEAL)
# define PREKEY_MMAP_FLAG	MAP_CONCEAL
#وإلاإذا defined(MAP_NOCORE)
# define PREKEY_MMAP_FLAG	MAP_NOCORE
#وإلا
# define PREKEY_MMAP_FLAG	0
#endif

ساكن صحيح
sshkey_prekey_alloc(u_char **prekeyp, size_t len)
{
#إذا defined(HAVE_MMAP) && defined(MAP_ANON) && defined(MAP_PRIVATE)
	u_char *prekey;

	*prekeyp = عدم;
	إذا ((prekey = mmap(عدم, len, PROT_READ|PROT_WRITE,
	    MAP_ANON|MAP_PRIVATE|PREKEY_MMAP_FLAG, -1, 0)) == MAP_FAILED)
		إرجاع SSH_ERR_SYSTEM_ERROR;
#إذا defined(MADV_DONTDUMP) && !defined(MAP_CONCEAL) && !defined(MAP_NOCORE)
	(فراغ)madvise(prekey, len, MADV_DONTDUMP);
#endif
	*prekeyp = prekey;
#وإلا
	*prekeyp = calloc(1, len);
#endif /* HAVE_MMAP et al */
	إرجاع 0;
}

ساكن فراغ
sshkey_prekey_free(فراغ *prekey, size_t len)
{
#إذا defined(HAVE_MMAP) && defined(MAP_ANON) && defined(MAP_PRIVATE)
	إذا (prekey == عدم)
		إرجاع;
	munmap(prekey, len);
#وإلا
	حرر(prekey);
#endif /* HAVE_MMAP et al */
}

ساكن فراغ
sshkey_free_contents(بنية sshkey *k)
{
	ثابت بنية sshkey_impl *impl;

	إذا (k == عدم)
		إرجاع;
	إذا ((k->flags & SSHKEY_FLAG_EXT) != 0)
		pkcs11_مفتاح_free(k);
	إذا ((impl = sshkey_impl_from_type(k->type)) != عدم &&
	    impl->funcs->cleanup != عدم)
		impl->funcs->cleanup(k);
	إذا (sshkey_is_cert(k))
		cert_free(k->cert);
	freezero(k->shielded_private, k->shielded_len);
	sshkey_prekey_free(k->shield_prekey, k->shield_prekey_len);
}

فراغ
sshkey_free(بنية sshkey *k)
{
	sshkey_free_contents(k);
	freezero(k, حجم(*k));
}

ساكن صحيح
cert_compare(بنية sshkey_cert *a, بنية sshkey_cert *b)
{
	إذا (a == عدم && b == عدم)
		إرجاع 1;
	إذا (a == عدم || b == عدم)
		إرجاع 0;
	إذا (sshbuf_len(a->certblob) != sshbuf_len(b->certblob))
		إرجاع 0;
	إذا (timingsafe_bcmp(sshbuf_ptr(a->certblob), sshbuf_ptr(b->certblob),
	    sshbuf_len(a->certblob)) != 0)
		إرجاع 0;
	إرجاع 1;
}

/* Compares FIDO-specific pubkey fields only */
صحيح
sshkey_sk_fields_equal(ثابت بنية sshkey *a, ثابت بنية sshkey *b)
{
	إذا (a->sk_application == عدم || b->sk_application == عدم)
		إرجاع 0;
	إذا (strcmp(a->sk_application, b->sk_application) != 0)
		إرجاع 0;
	إرجاع 1;
}

/*
 * Compare public portions of key only, allowing comparisons between
 * certificates and plain keys too.
 */
صحيح
sshkey_equal_public(ثابت بنية sshkey *a, ثابت بنية sshkey *b)
{
	ثابت بنية sshkey_impl *impl;

	إذا (a == عدم || b == عدم ||
	    sshkey_type_plain(a->type) != sshkey_type_plain(b->type))
		إرجاع 0;
	إذا ((impl = sshkey_impl_from_type(a->type)) == عدم)
		إرجاع 0;
	إرجاع impl->funcs->equal(a, b);
}

صحيح
sshkey_equal(ثابت بنية sshkey *a, ثابت بنية sshkey *b)
{
	إذا (a == عدم || b == عدم || a->type != b->type)
		إرجاع 0;
	إذا (sshkey_is_cert(a)) {
		إذا (!cert_compare(a->cert, b->cert))
			إرجاع 0;
	}
	إرجاع sshkey_equal_public(a, b);
}


/* Serialise common FIDO key parts */
صحيح
sshkey_serialize_sk(ثابت بنية sshkey *مفتاح, بنية sshbuf *b)
{
	صحيح r;

	إذا ((r = sshbuf_put_cstring(b, مفتاح->sk_application)) != 0)
		إرجاع r;

	إرجاع 0;
}

ساكن صحيح
to_blob_buf(ثابت بنية sshkey *مفتاح, بنية sshbuf *b, صحيح force_plain,
  تعداد sshkey_serialize_rep opts)
{
	صحيح type, ret = SSH_ERR_INTERNAL_ERROR;
	ثابت حرف *typename;
	ثابت بنية sshkey_impl *impl;

	إذا (مفتاح == عدم)
		إرجاع SSH_ERR_INVALID_ARGUMENT;

	type = force_plain ? sshkey_type_plain(مفتاح->type) : مفتاح->type;

	إذا (sshkey_type_is_cert(type)) {
		إذا (مفتاح->cert == عدم)
			إرجاع SSH_ERR_EXPECTED_CERT;
		إذا (sshbuf_len(مفتاح->cert->certblob) == 0)
			إرجاع SSH_ERR_مفتاح_LACKS_CERTBLOB;
		/* Use the existing blob */
		إذا ((ret = sshbuf_putb(b, مفتاح->cert->certblob)) != 0)
			إرجاع ret;
		إرجاع 0;
	}
	إذا ((impl = sshkey_impl_from_type(type)) == عدم)
		إرجاع SSH_ERR_مفتاح_TYPE_UNKNOWN;

	typename = sshkey_ssh_name_from_type_nid(type, مفتاح->ecdsa_nid);
	إذا ((ret = sshbuf_put_cstring(b, typename)) != 0)
		إرجاع ret;
	إرجاع impl->funcs->serialize_public(مفتاح, b, opts);
}

صحيح
sshkey_putb(ثابت بنية sshkey *مفتاح, بنية sshbuf *b)
{
	إرجاع to_blob_buf(مفتاح, b, 0, SSHKEY_SERIALIZE_DEFAULT);
}

ساكن صحيح
sshkey_puts_opts_internal(ثابت بنية sshkey *مفتاح, بنية sshbuf *b,
    تعداد sshkey_serialize_rep opts, صحيح force_plain)
{
	بنية sshbuf *tmp;
	صحيح r;

	إذا ((tmp = sshbuf_new()) == عدم)
		إرجاع SSH_ERR_ALLOC_FAIL;
	r = to_blob_buf(مفتاح, tmp, force_plain, opts);
	إذا (r == 0)
		r = sshbuf_put_stringb(b, tmp);
	sshbuf_free(tmp);
	إرجاع r;
}

صحيح
sshkey_puts(ثابت بنية sshkey *مفتاح, بنية sshbuf *b)
{
	إرجاع sshkey_puts_opts_internal(مفتاح, b, SSHKEY_SERIALIZE_DEFAULT, 0);
}

صحيح
sshkey_putb_plain(ثابت بنية sshkey *مفتاح, بنية sshbuf *b)
{
	إرجاع to_blob_buf(مفتاح, b, 1, SSHKEY_SERIALIZE_DEFAULT);
}

صحيح
sshkey_puts_plain(ثابت بنية sshkey *مفتاح, بنية sshbuf *b)
{
	إرجاع sshkey_puts_opts_internal(مفتاح, b, SSHKEY_SERIALIZE_DEFAULT, 1);
}

ساكن صحيح
to_blob(ثابت بنية sshkey *مفتاح, u_char **blobp, size_t *lenp, صحيح force_plain,
    تعداد sshkey_serialize_rep opts)
{
	صحيح ret = SSH_ERR_INTERNAL_ERROR;
	size_t len;
	بنية sshbuf *b = عدم;

	إذا (lenp != عدم)
		*lenp = 0;
	إذا (blobp != عدم)
		*blobp = عدم;
	إذا ((b = sshbuf_new()) == عدم)
		إرجاع SSH_ERR_ALLOC_FAIL;
	إذا ((ret = to_blob_buf(مفتاح, b, force_plain, opts)) != 0)
		اذهب out;
	len = sshbuf_len(b);
	إذا (lenp != عدم)
		*lenp = len;
	إذا (blobp != عدم) {
		إذا ((*blobp = malloc(len)) == عدم) {
			ret = SSH_ERR_ALLOC_FAIL;
			اذهب out;
		}
		memcpy(*blobp, sshbuf_ptr(b), len);
	}
	ret = 0;
 out:
	sshbuf_free(b);
	إرجاع ret;
}

صحيح
sshkey_to_blob(ثابت بنية sshkey *مفتاح, u_char **blobp, size_t *lenp)
{
	إرجاع to_blob(مفتاح, blobp, lenp, 0, SSHKEY_SERIALIZE_DEFAULT);
}

صحيح
sshkey_plain_to_blob(ثابت بنية sshkey *مفتاح, u_char **blobp, size_t *lenp)
{
	إرجاع to_blob(مفتاح, blobp, lenp, 1, SSHKEY_SERIALIZE_DEFAULT);
}

صحيح
sshkey_fingerprint_raw(ثابت بنية sshkey *k, صحيح dgst_alg,
    u_char **retp, size_t *lenp)
{
	u_char *blob = عدم, *ret = عدم;
	size_t blob_len = 0;
	صحيح r = SSH_ERR_INTERNAL_ERROR;

	إذا (retp != عدم)
		*retp = عدم;
	إذا (lenp != عدم)
		*lenp = 0;
	إذا (ssh_digest_bytes(dgst_alg) == 0) {
		r = SSH_ERR_INVALID_ARGUMENT;
		اذهب out;
	}
	إذا ((r = to_blob(k, &blob, &blob_len, 1, SSHKEY_SERIALIZE_DEFAULT))
	    != 0)
		اذهب out;
	إذا ((ret = calloc(1, SSH_DIGEST_MAX_LENGTH)) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}
	إذا ((r = ssh_digest_memory(dgst_alg, blob, blob_len,
	    ret, SSH_DIGEST_MAX_LENGTH)) != 0)
		اذهب out;
	/* success */
	إذا (retp != عدم) {
		*retp = ret;
		ret = عدم;
	}
	إذا (lenp != عدم)
		*lenp = ssh_digest_bytes(dgst_alg);
	r = 0;
 out:
	حرر(ret);
	إذا (blob != عدم)
		freezero(blob, blob_len);
	إرجاع r;
}

ساكن حرف *
fingerprint_b64(ثابت حرف *alg, u_char *dgst_raw, size_t dgst_raw_len)
{
	حرف *ret;
	size_t plen = strlen(alg) + 1;
	size_t rlen = ((dgst_raw_len + 2) / 3) * 4 + plen + 1;

	إذا (dgst_raw_len > 65536 || (ret = calloc(1, rlen)) == عدم)
		إرجاع عدم;
	strlcpy(ret, alg, rlen);
	strlcat(ret, ":", rlen);
	إذا (dgst_raw_len == 0)
		إرجاع ret;
	إذا (b64_ntop(dgst_raw, dgst_raw_len, ret + plen, rlen - plen) == -1) {
		freezero(ret, rlen);
		إرجاع عدم;
	}
	/* Trim padding characters from end */
	ret[strcspn(ret, "=")] = '\0';
	إرجاع ret;
}

ساكن حرف *
fingerprint_hex(ثابت حرف *alg, u_char *dgst_raw, size_t dgst_raw_len)
{
	حرف *retval, hex[5];
	size_t i, rlen = dgst_raw_len * 3 + strlen(alg) + 2;

	إذا (dgst_raw_len > 65536 || (retval = calloc(1, rlen)) == عدم)
		إرجاع عدم;
	strlcpy(retval, alg, rlen);
	strlcat(retval, ":", rlen);
	لكل (i = 0; i < dgst_raw_len; i++) {
		snprintf(hex, حجم(hex), "%s%02x",
		    i > 0 ? ":" : "", dgst_raw[i]);
		strlcat(retval, hex, rlen);
	}
	إرجاع retval;
}

ساكن حرف *
fingerprint_bubblebabble(u_char *dgst_raw, size_t dgst_raw_len)
{
	حرف vowels[] = { 'a', 'e', 'i', 'o', 'u', 'y' };
	حرف consonants[] = { 'b', 'c', 'd', 'f', 'g', 'h', 'k', 'l', 'm',
	    'n', 'p', 'r', 's', 't', 'v', 'z', 'x' };
	u_int i, j = 0, rounds, seed = 1;
	حرف *retval;

	rounds = (dgst_raw_len / 2) + 1;
	إذا ((retval = calloc(rounds, 6)) == عدم)
		إرجاع عدم;
	retval[j++] = 'x';
	لكل (i = 0; i < rounds; i++) {
		u_int idx0, idx1, idx2, idx3, idx4;
		إذا ((i + 1 < rounds) || (dgst_raw_len % 2 != 0)) {
			idx0 = (((((u_int)(dgst_raw[2 * i])) >> 6) & 3) +
			    seed) % 6;
			idx1 = (((u_int)(dgst_raw[2 * i])) >> 2) & 15;
			idx2 = ((((u_int)(dgst_raw[2 * i])) & 3) +
			    (seed / 6)) % 6;
			retval[j++] = vowels[idx0];
			retval[j++] = consonants[idx1];
			retval[j++] = vowels[idx2];
			إذا ((i + 1) < rounds) {
				idx3 = (((u_int)(dgst_raw[(2 * i) + 1])) >> 4) & 15;
				idx4 = (((u_int)(dgst_raw[(2 * i) + 1]))) & 15;
				retval[j++] = consonants[idx3];
				retval[j++] = '-';
				retval[j++] = consonants[idx4];
				seed = ((seed * 5) +
				    ((((u_int)(dgst_raw[2 * i])) * 7) +
				    ((u_int)(dgst_raw[(2 * i) + 1])))) % 36;
			}
		} وإلا {
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
	إرجاع retval;
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
ساكن حرف *
fingerprint_randomart(ثابت حرف *alg, u_char *dgst_raw, size_t dgst_raw_len,
    ثابت بنية sshkey *k)
{
	/*
	 * Chars to be used after each other every time the worm
	 * intersects with itself.  Matter of taste.
	 */
	حرف	*augmentation_string = " .o+=*BOX@%&#/^SE";
	حرف	*retval, *p, title[FLDSIZE_X], hash[FLDSIZE_X];
	u_char	 field[FLDSIZE_X][FLDSIZE_Y];
	size_t	 i, tlen, hlen;
	u_int	 b;
	صحيح	 x, y, r;
	size_t	 len = strlen(augmentation_string) - 1;

	إذا ((retval = calloc((FLDSIZE_X + 3), (FLDSIZE_Y + 2))) == عدم)
		إرجاع عدم;

	/* initialize field */
	memset(field, 0, FLDSIZE_X * FLDSIZE_Y * حجم(حرف));
	x = FLDSIZE_X / 2;
	y = FLDSIZE_Y / 2;

	/* process raw key */
	لكل (i = 0; i < dgst_raw_len; i++) {
		صحيح إدخال;
		/* each byte conveys four 2-bit move commands */
		إدخال = dgst_raw[i];
		لكل (b = 0; b < 4; b++) {
			/* evaluate 2 bit, rest is shifted later */
			x += (إدخال & 0x1) ? 1 : -1;
			y += (إدخال & 0x2) ? 1 : -1;

			/* assure we are still in bounds */
			x = MAXIMUM(x, 0);
			y = MAXIMUM(y, 0);
			x = MINIMUM(x, FLDSIZE_X - 1);
			y = MINIMUM(y, FLDSIZE_Y - 1);

			/* augment the field */
			إذا (field[x][y] < len - 2)
				field[x][y]++;
			إدخال = إدخال >> 2;
		}
	}

	/* mark starting point and end point*/
	field[FLDSIZE_X / 2][FLDSIZE_Y / 2] = len - 1;
	field[x][y] = len;

	/* assemble title */
	r = snprintf(title, حجم(title), "[%s %u]",
		sshkey_type(k), sshkey_size(k));
	/* If [type size] won't fit, then try [type]; fits "[ED25519-CERT]" */
	إذا (r < 0 || r > (صحيح)حجم(title))
		r = snprintf(title, حجم(title), "[%s]", sshkey_type(k));
	tlen = (r <= 0) ? 0 : strlen(title);

	/* assemble hash ID. */
	r = snprintf(hash, حجم(hash), "[%s]", alg);
	hlen = (r <= 0) ? 0 : strlen(hash);

	/* output upper border */
	p = retval;
	*p++ = '+';
	لكل (i = 0; i < (FLDSIZE_X - tlen) / 2; i++)
		*p++ = '-';
	memcpy(p, title, tlen);
	p += tlen;
	لكل (i += tlen; i < FLDSIZE_X; i++)
		*p++ = '-';
	*p++ = '+';
	*p++ = '\n';

	/* output content */
	لكل (y = 0; y < FLDSIZE_Y; y++) {
		*p++ = '|';
		لكل (x = 0; x < FLDSIZE_X; x++)
			*p++ = augmentation_string[MINIMUM(field[x][y], len)];
		*p++ = '|';
		*p++ = '\n';
	}

	/* output lower border */
	*p++ = '+';
	لكل (i = 0; i < (FLDSIZE_X - hlen) / 2; i++)
		*p++ = '-';
	memcpy(p, hash, hlen);
	p += hlen;
	لكل (i += hlen; i < FLDSIZE_X; i++)
		*p++ = '-';
	*p++ = '+';

	إرجاع retval;
}

حرف *
sshkey_fingerprint(ثابت بنية sshkey *k, صحيح dgst_alg,
    تعداد sshkey_fp_rep dgst_rep)
{
	حرف *retval = عدم;
	u_char *dgst_raw;
	size_t dgst_raw_len;

	إذا (sshkey_fingerprint_raw(k, dgst_alg, &dgst_raw, &dgst_raw_len) != 0)
		إرجاع عدم;
	بدل (dgst_rep) {
	حالة SSH_FP_DEFAULT:
		إذا (dgst_alg == SSH_DIGEST_MD5) {
			retval = fingerprint_hex(ssh_digest_alg_name(dgst_alg),
			    dgst_raw, dgst_raw_len);
		} وإلا {
			retval = fingerprint_b64(ssh_digest_alg_name(dgst_alg),
			    dgst_raw, dgst_raw_len);
		}
		اكسر;
	حالة SSH_FP_HEX:
		retval = fingerprint_hex(ssh_digest_alg_name(dgst_alg),
		    dgst_raw, dgst_raw_len);
		اكسر;
	حالة SSH_FP_BASE64:
		retval = fingerprint_b64(ssh_digest_alg_name(dgst_alg),
		    dgst_raw, dgst_raw_len);
		اكسر;
	حالة SSH_FP_BUBBLEBABBLE:
		retval = fingerprint_bubblebabble(dgst_raw, dgst_raw_len);
		اكسر;
	حالة SSH_FP_RANDOMART:
		retval = fingerprint_randomart(ssh_digest_alg_name(dgst_alg),
		    dgst_raw, dgst_raw_len, k);
		اكسر;
	افتراضي:
		freezero(dgst_raw, dgst_raw_len);
		إرجاع عدم;
	}
	freezero(dgst_raw, dgst_raw_len);
	إرجاع retval;
}

ساكن صحيح
peek_type_nid(ثابت حرف *s, size_t l, صحيح *nid)
{
	ثابت بنية sshkey_impl *impl;
	صحيح i;

	لكل (i = 0; keyimpls[i] != عدم; i++) {
		impl = keyimpls[i];
		إذا (impl->name == عدم || strlen(impl->name) != l)
			استمر;
		إذا (memcmp(s, impl->name, l) == 0) {
			*nid = -1;
			إذا (مفتاح_type_is_ecdsa_variant(impl->type))
				*nid = impl->nid;
			إرجاع impl->type;
		}
	}
	إرجاع مفتاح_UNSPEC;
}

/* XXX this can now be made const char * */
صحيح
sshkey_read(بنية sshkey *ret, حرف **cpp)
{
	بنية sshkey *k;
	حرف *cp, *blobcopy;
	size_t space;
	صحيح r, type, curve_nid = -1;
	بنية sshbuf *blob;

	إذا (ret == عدم)
		إرجاع SSH_ERR_INVALID_ARGUMENT;
	إذا (ret->type != مفتاح_UNSPEC && sshkey_impl_from_type(ret->type) == عدم)
		إرجاع SSH_ERR_INVALID_ARGUMENT;

	/* Decode type */
	cp = *cpp;
	space = strcspn(cp, " \t");
	إذا (space == strlen(cp))
		إرجاع SSH_ERR_INVALID_FORMAT;
	إذا ((type = peek_type_nid(cp, space, &curve_nid)) == مفتاح_UNSPEC)
		إرجاع SSH_ERR_INVALID_FORMAT;

	/* skip whitespace */
	لكل (cp += space; *cp == ' ' || *cp == '\t'; cp++)
		;
	إذا (*cp == '\0')
		إرجاع SSH_ERR_INVALID_FORMAT;
	إذا (ret->type != مفتاح_UNSPEC && ret->type != type)
		إرجاع SSH_ERR_مفتاح_TYPE_MISMATCH;
	إذا ((blob = sshbuf_new()) == عدم)
		إرجاع SSH_ERR_ALLOC_FAIL;

	/* find end of keyblob and decode */
	space = strcspn(cp, " \t");
	إذا ((blobcopy = strndup(cp, space)) == عدم) {
		sshbuf_free(blob);
		إرجاع SSH_ERR_ALLOC_FAIL;
	}
	إذا ((r = sshbuf_b64tod(blob, blobcopy)) != 0) {
		حرر(blobcopy);
		sshbuf_free(blob);
		إرجاع r;
	}
	حرر(blobcopy);
	إذا ((r = sshkey_fromb(blob, &k)) != 0) {
		sshbuf_free(blob);
		إرجاع r;
	}
	sshbuf_free(blob);

	/* skip whitespace and leave cp at start of comment */
	لكل (cp += space; *cp == ' ' || *cp == '\t'; cp++)
		;

	/* ensure type of blob matches type at start of line */
	إذا (k->type != type) {
		sshkey_free(k);
		إرجاع SSH_ERR_مفتاح_TYPE_MISMATCH;
	}
	إذا (مفتاح_type_is_ecdsa_variant(type) && curve_nid != k->ecdsa_nid) {
		sshkey_free(k);
		إرجاع SSH_ERR_EC_CURVE_MISMATCH;
	}

	/* Fill in ret from parsed key */
	sshkey_free_contents(ret);
	*ret = *k;
	freezero(k, حجم(*k));

	/* success */
	*cpp = cp;
	إرجاع 0;
}

صحيح
sshkey_to_base64(ثابت بنية sshkey *مفتاح, حرف **b64p)
{
	صحيح r = SSH_ERR_INTERNAL_ERROR;
	بنية sshbuf *b = عدم;
	حرف *uu = عدم;

	إذا (b64p != عدم)
		*b64p = عدم;
	إذا ((b = sshbuf_new()) == عدم)
		إرجاع SSH_ERR_ALLOC_FAIL;
	إذا ((r = sshkey_putb(مفتاح, b)) != 0)
		اذهب out;
	إذا ((uu = sshbuf_dtob64_string(b, 0)) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}
	/* Success */
	إذا (b64p != عدم) {
		*b64p = uu;
		uu = عدم;
	}
	r = 0;
 out:
	sshbuf_free(b);
	حرر(uu);
	إرجاع r;
}

صحيح
sshkey_format_text(ثابت بنية sshkey *مفتاح, بنية sshbuf *b)
{
	صحيح r = SSH_ERR_INTERNAL_ERROR;
	حرف *uu = عدم;

	إذا ((r = sshkey_to_base64(مفتاح, &uu)) != 0)
		اذهب out;
	إذا ((r = sshbuf_putf(b, "%s %s",
	    sshkey_ssh_name(مفتاح), uu)) != 0)
		اذهب out;
	r = 0;
 out:
	حرر(uu);
	إرجاع r;
}

صحيح
sshkey_write(ثابت بنية sshkey *مفتاح, FILE *f)
{
	بنية sshbuf *b = عدم;
	صحيح r = SSH_ERR_INTERNAL_ERROR;

	إذا ((b = sshbuf_new()) == عدم)
		إرجاع SSH_ERR_ALLOC_FAIL;
	إذا ((r = sshkey_format_text(مفتاح, b)) != 0)
		اذهب out;
	إذا (fwrite(sshbuf_ptr(b), sshbuf_len(b), 1, f) != 1) {
		إذا (feof(f))
			errno = EPIPE;
		r = SSH_ERR_SYSTEM_ERROR;
		اذهب out;
	}
	/* Success */
	r = 0;
 out:
	sshbuf_free(b);
	إرجاع r;
}

ثابت حرف *
sshkey_cert_type(ثابت بنية sshkey *k)
{
	بدل (k->cert->type) {
	حالة SSH2_CERT_TYPE_USER:
		إرجاع "user";
	حالة SSH2_CERT_TYPE_HOST:
		إرجاع "host";
	افتراضي:
		إرجاع "unknown";
	}
}

صحيح
sshkey_check_rsa_length(ثابت بنية sshkey *k, صحيح min_size)
{
#ifdef WITH_OPENSSL
	صحيح nbits;

	إذا (k == عدم || k->pkey == عدم ||
	    (k->type != مفتاح_RSA && k->type != مفتاح_RSA_CERT))
		إرجاع 0;
	nbits = EVP_PKEY_bits(k->pkey);
	إذا (nbits < SSH_RSA_MINIMUM_MODULUS_SIZE ||
	    (min_size > 0 && nbits < min_size))
		إرجاع SSH_ERR_مفتاح_LENGTH;
#endif /* WITH_OPENSSL */
	إرجاع 0;
}

#ifdef WITH_OPENSSL
صحيح
sshkey_ecdsa_مفتاح_to_nid(ثابت EC_مفتاح *k)
{
	ثابت EC_GROUP *g;
	صحيح nid;

	إذا (k == عدم || (g = EC_مفتاح_get0_group(k)) == عدم)
		إرجاع -1;
	إذا ((nid = EC_GROUP_get_curve_name(g)) <= 0)
		إرجاع -1;
	إرجاع nid;
}

صحيح
sshkey_ecdsa_pkey_to_nid(EVP_PKEY *pkey)
{
	إرجاع sshkey_ecdsa_مفتاح_to_nid(EVP_PKEY_get0_EC_مفتاح(pkey));
}
#endif /* WITH_OPENSSL */

صحيح
sshkey_generate(صحيح type, u_int bits, بنية sshkey **keyp)
{
	بنية sshkey *k;
	صحيح ret = SSH_ERR_INTERNAL_ERROR;
	ثابت بنية sshkey_impl *impl;

	إذا (keyp == عدم || sshkey_type_is_cert(type))
		إرجاع SSH_ERR_INVALID_ARGUMENT;
	*keyp = عدم;
	إذا ((impl = sshkey_impl_from_type(type)) == عدم)
		إرجاع SSH_ERR_مفتاح_TYPE_UNKNOWN;
	إذا (impl->funcs->generate == عدم)
		إرجاع SSH_ERR_FEATURE_UNSUPPORTED;
	إذا ((k = sshkey_new(مفتاح_UNSPEC)) == عدم)
		إرجاع SSH_ERR_ALLOC_FAIL;
	k->type = type;
	إذا ((ret = impl->funcs->generate(k, bits)) != 0) {
		sshkey_free(k);
		إرجاع ret;
	}
	/* success */
	*keyp = k;
	إرجاع 0;
}

صحيح
sshkey_cert_copy(ثابت بنية sshkey *from_مفتاح, بنية sshkey *to_مفتاح)
{
	u_int i;
	ثابت بنية sshkey_cert *from;
	بنية sshkey_cert *to;
	صحيح r = SSH_ERR_INTERNAL_ERROR;

	إذا (to_مفتاح == عدم || (from = from_مفتاح->cert) == عدم)
		إرجاع SSH_ERR_INVALID_ARGUMENT;

	إذا ((to = cert_new()) == عدم)
		إرجاع SSH_ERR_ALLOC_FAIL;

	إذا ((r = sshbuf_putb(to->certblob, from->certblob)) != 0 ||
	    (r = sshbuf_putb(to->critical, from->critical)) != 0 ||
	    (r = sshbuf_putb(to->extensions, from->extensions)) != 0)
		اذهب out;

	to->serial = from->serial;
	to->type = from->type;
	إذا (from->مفتاح_id == عدم)
		to->مفتاح_id = عدم;
	وإلا إذا ((to->مفتاح_id = strdup(from->مفتاح_id)) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}
	to->valid_after = from->valid_after;
	to->valid_before = from->valid_before;
	إذا (from->signature_مفتاح == عدم)
		to->signature_مفتاح = عدم;
	وإلا إذا ((r = sshkey_from_private(from->signature_مفتاح,
	    &to->signature_مفتاح)) != 0)
		اذهب out;
	إذا (from->signature_type != عدم &&
	    (to->signature_type = strdup(from->signature_type)) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}
	إذا (from->nprincipals > SSHKEY_CERT_MAX_PRINCIPALS) {
		r = SSH_ERR_INVALID_ARGUMENT;
		اذهب out;
	}
	إذا (from->nprincipals > 0) {
		إذا ((to->principals = calloc(from->nprincipals,
		    حجم(*to->principals))) == عدم) {
			r = SSH_ERR_ALLOC_FAIL;
			اذهب out;
		}
		لكل (i = 0; i < from->nprincipals; i++) {
			to->principals[i] = strdup(from->principals[i]);
			إذا (to->principals[i] == عدم) {
				to->nprincipals = i;
				r = SSH_ERR_ALLOC_FAIL;
				اذهب out;
			}
		}
	}
	to->nprincipals = from->nprincipals;

	/* success */
	cert_free(to_مفتاح->cert);
	to_مفتاح->cert = to;
	to = عدم;
	r = 0;
 out:
	cert_free(to);
	إرجاع r;
}

صحيح
sshkey_copy_public_sk(ثابت بنية sshkey *from, بنية sshkey *to)
{
	/* Append security-key application string */
	إذا ((to->sk_application = strdup(from->sk_application)) == عدم)
		إرجاع SSH_ERR_ALLOC_FAIL;
	إرجاع 0;
}

صحيح
sshkey_from_private(ثابت بنية sshkey *k, بنية sshkey **pkp)
{
	بنية sshkey *n = عدم;
	صحيح r = SSH_ERR_INTERNAL_ERROR;
	ثابت بنية sshkey_impl *impl;

	*pkp = عدم;
	إذا ((impl = sshkey_impl_from_مفتاح(k)) == عدم)
		إرجاع SSH_ERR_مفتاح_TYPE_UNKNOWN;
	إذا ((n = sshkey_new(k->type)) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}
	إذا ((r = impl->funcs->copy_public(k, n)) != 0)
		اذهب out;
	إذا (sshkey_is_cert(k) && (r = sshkey_cert_copy(k, n)) != 0)
		اذهب out;
	/* success */
	*pkp = n;
	n = عدم;
	r = 0;
 out:
	sshkey_free(n);
	إرجاع r;
}

صحيح
sshkey_is_shielded(بنية sshkey *k)
{
	إرجاع k != عدم && k->shielded_private != عدم;
}

صحيح
sshkey_shield_private(بنية sshkey *k)
{
	بنية sshbuf *prvbuf = عدم;
	u_char *prekey = عدم, *enc = عدم, keyiv[SSH_DIGEST_MAX_LENGTH];
	بنية sshcipher_ctx *cctx = عدم;
	ثابت بنية sshcipher *cipher;
	size_t i, enclen = 0;
	بنية sshkey *kswap = عدم, tmp;
	صحيح r = SSH_ERR_INTERNAL_ERROR;

#ifdef DEBUG_PK
	fprintf(stderr, "%s: entering for %s\n", __func__, sshkey_ssh_name(k));
#endif
	إذا ((cipher = cipher_by_name(SSHKEY_SHIELD_CIPHER)) == عدم) {
		r = SSH_ERR_INVALID_ARGUMENT;
		اذهب out;
	}
	إذا (cipher_keylen(cipher) + cipher_ivlen(cipher) >
	    ssh_digest_bytes(SSHKEY_SHIELD_PREKEY_HASH)) {
		r = SSH_ERR_INTERNAL_ERROR;
		اذهب out;
	}

	/* Prepare a random pre-key, and from it an ephemeral key */
	إذا ((r = sshkey_prekey_alloc(&prekey, SSHKEY_SHIELD_PREKEY_LEN)) != 0)
		اذهب out;
	arc4random_buf(prekey, SSHKEY_SHIELD_PREKEY_LEN);
	إذا ((r = ssh_digest_memory(SSHKEY_SHIELD_PREKEY_HASH,
	    prekey, SSHKEY_SHIELD_PREKEY_LEN,
	    keyiv, SSH_DIGEST_MAX_LENGTH)) != 0)
		اذهب out;
#ifdef DEBUG_PK
	fprintf(stderr, "%s: key+iv\n", __func__);
	sshbuf_dump_data(keyiv, ssh_digest_bytes(SSHKEY_SHIELD_PREKEY_HASH),
	    stderr);
#endif
	إذا ((r = cipher_init(&cctx, cipher, keyiv, cipher_keylen(cipher),
	    keyiv + cipher_keylen(cipher), cipher_ivlen(cipher), 1)) != 0)
		اذهب out;

	/* Serialise and encrypt the private key using the ephemeral key */
	إذا ((prvbuf = sshbuf_new()) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}
	إذا (sshkey_is_shielded(k) && (r = sshkey_unshield_private(k)) != 0)
		اذهب out;
	إذا ((r = sshkey_private_serialize(k, prvbuf)) != 0)
		اذهب out;
	/* pad to cipher blocksize */
	i = 0;
	بينما (sshbuf_len(prvbuf) % cipher_blocksize(cipher)) {
		إذا ((r = sshbuf_put_u8(prvbuf, ++i & 0xff)) != 0)
			اذهب out;
	}
#ifdef DEBUG_PK
	fprintf(stderr, "%s: serialised\n", __func__);
	sshbuf_dump(prvbuf, stderr);
#endif
	/* encrypt */
	enclen = sshbuf_len(prvbuf);
	إذا ((enc = malloc(enclen)) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}
	إذا ((r = cipher_crypt(cctx, 0, enc,
	    sshbuf_ptr(prvbuf), sshbuf_len(prvbuf), 0, 0)) != 0)
		اذهب out;
#ifdef DEBUG_PK
	fprintf(stderr, "%s: encrypted\n", __func__);
	sshbuf_dump_data(enc, enclen, stderr);
#endif

	/* Make a scrubbed, public-only copy of our private key argument */
	إذا ((r = sshkey_from_private(k, &kswap)) != 0)
		اذهب out;

	/* Swap the private key out (it will be destroyed below) */
	tmp = *kswap;
	*kswap = *k;
	*k = tmp;

	/* Insert the shielded key into our argument */
	k->shielded_private = enc;
	k->shielded_len = enclen;
	k->shield_prekey = prekey;
	k->shield_prekey_len = SSHKEY_SHIELD_PREKEY_LEN;
	enc = prekey = عدم; /* transferred */
	enclen = 0;

	/* preserve key fields that are required for correct operation */
	k->sk_flags = kswap->sk_flags;

	/* success */
	r = 0;

 out:
	/* XXX behaviour on error - invalidate original private key? */
	cipher_free(cctx);
	explicit_bzero(keyiv, حجم(keyiv));
	explicit_bzero(&tmp, حجم(tmp));
	freezero(enc, enclen);
	sshkey_prekey_free(prekey, SSHKEY_SHIELD_PREKEY_LEN);
	sshkey_free(kswap);
	sshbuf_free(prvbuf);
	إرجاع r;
}

/* Check deterministic padding after private key */
ساكن صحيح
private2_check_padding(بنية sshbuf *decrypted)
{
	u_char pad;
	size_t i;
	صحيح r;

	i = 0;
	بينما (sshbuf_len(decrypted)) {
		إذا ((r = sshbuf_get_u8(decrypted, &pad)) != 0)
			اذهب out;
		إذا (pad != (++i & 0xff)) {
			r = SSH_ERR_INVALID_FORMAT;
			اذهب out;
		}
	}
	/* success */
	r = 0;
 out:
	explicit_bzero(&pad, حجم(pad));
	explicit_bzero(&i, حجم(i));
	إرجاع r;
}

صحيح
sshkey_unshield_private(بنية sshkey *k)
{
	بنية sshbuf *prvbuf = عدم;
	u_char *cp, keyiv[SSH_DIGEST_MAX_LENGTH];
	بنية sshcipher_ctx *cctx = عدم;
	ثابت بنية sshcipher *cipher;
	بنية sshkey *kswap = عدم, tmp;
	صحيح r = SSH_ERR_INTERNAL_ERROR;

#ifdef DEBUG_PK
	fprintf(stderr, "%s: entering for %s\n", __func__, sshkey_ssh_name(k));
#endif
	إذا (!sshkey_is_shielded(k))
		إرجاع 0; /* nothing to do */

	إذا ((cipher = cipher_by_name(SSHKEY_SHIELD_CIPHER)) == عدم) {
		r = SSH_ERR_INVALID_ARGUMENT;
		اذهب out;
	}
	إذا (cipher_keylen(cipher) + cipher_ivlen(cipher) >
	    ssh_digest_bytes(SSHKEY_SHIELD_PREKEY_HASH)) {
		r = SSH_ERR_INTERNAL_ERROR;
		اذهب out;
	}
	/* check size of shielded key blob */
	إذا (k->shielded_len < cipher_blocksize(cipher) ||
	    (k->shielded_len % cipher_blocksize(cipher)) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		اذهب out;
	}

	/* Calculate the ephemeral key from the prekey */
	إذا ((r = ssh_digest_memory(SSHKEY_SHIELD_PREKEY_HASH,
	    k->shield_prekey, k->shield_prekey_len,
	    keyiv, SSH_DIGEST_MAX_LENGTH)) != 0)
		اذهب out;
	إذا ((r = cipher_init(&cctx, cipher, keyiv, cipher_keylen(cipher),
	    keyiv + cipher_keylen(cipher), cipher_ivlen(cipher), 0)) != 0)
		اذهب out;
#ifdef DEBUG_PK
	fprintf(stderr, "%s: key+iv\n", __func__);
	sshbuf_dump_data(keyiv, ssh_digest_bytes(SSHKEY_SHIELD_PREKEY_HASH),
	    stderr);
#endif

	/* Decrypt and parse the shielded private key using the ephemeral key */
	إذا ((prvbuf = sshbuf_new()) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}
	إذا ((r = sshbuf_reserve(prvbuf, k->shielded_len, &cp)) != 0)
		اذهب out;
	/* decrypt */
#ifdef DEBUG_PK
	fprintf(stderr, "%s: encrypted\n", __func__);
	sshbuf_dump_data(k->shielded_private, k->shielded_len, stderr);
#endif
	إذا ((r = cipher_crypt(cctx, 0, cp,
	    k->shielded_private, k->shielded_len, 0, 0)) != 0)
		اذهب out;
#ifdef DEBUG_PK
	fprintf(stderr, "%s: serialised\n", __func__);
	sshbuf_dump(prvbuf, stderr);
#endif
	/* Parse private key */
	إذا ((r = sshkey_private_deserialize(prvbuf, &kswap)) != 0)
		اذهب out;

	إذا ((r = private2_check_padding(prvbuf)) != 0)
		اذهب out;

	/* Swap the parsed key back into place */
	tmp = *kswap;
	*kswap = *k;
	*k = tmp;

	/* success */
	r = 0;

 out:
	cipher_free(cctx);
	explicit_bzero(keyiv, حجم(keyiv));
	explicit_bzero(&tmp, حجم(tmp));
	sshkey_free(kswap);
	sshbuf_free(prvbuf);
	إرجاع r;
}

ساكن صحيح
cert_parse(بنية sshbuf *b, بنية sshkey *مفتاح, بنية sshbuf *certbuf,
    ثابت حرف *ca_sigalg_allowlist)
{
	بنية sshbuf *principals = عدم, *crit = عدم;
	بنية sshbuf *exts = عدم, *ca = عدم;
	u_char *sig = عدم;
	حرف *sigtype = عدم;
	size_t signed_len = 0, slen = 0, kidlen = 0;
	صحيح ret = SSH_ERR_INTERNAL_ERROR;

	/* Copy the entire key blob for verification and later serialisation */
	إذا ((ret = sshbuf_putb(مفتاح->cert->certblob, certbuf)) != 0)
		إرجاع ret;

	/* Parse body of certificate up to signature */
	إذا ((ret = sshbuf_get_u64(b, &مفتاح->cert->serial)) != 0 ||
	    (ret = sshbuf_get_u32(b, &مفتاح->cert->type)) != 0 ||
	    (ret = sshbuf_get_cstring(b, &مفتاح->cert->مفتاح_id, &kidlen)) != 0 ||
	    (ret = sshbuf_froms(b, &principals)) != 0 ||
	    (ret = sshbuf_get_u64(b, &مفتاح->cert->valid_after)) != 0 ||
	    (ret = sshbuf_get_u64(b, &مفتاح->cert->valid_before)) != 0 ||
	    (ret = sshbuf_froms(b, &crit)) != 0 ||
	    (ret = sshbuf_froms(b, &exts)) != 0 ||
	    (ret = sshbuf_get_string_direct(b, عدم, عدم)) != 0 ||
	    (ret = sshbuf_froms(b, &ca)) != 0) {
		/* XXX debug print error for ret */
		ret = SSH_ERR_INVALID_FORMAT;
		اذهب out;
	}

	/* Signature is left in the buffer so we can calculate this length */
	signed_len = sshbuf_len(مفتاح->cert->certblob) - sshbuf_len(b);

	إذا ((ret = sshbuf_get_string(b, &sig, &slen)) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		اذهب out;
	}

	/* Is this a signature we're prepared to accept? */
	إذا ((ret = sshkey_get_sigtype(sig, slen, &sigtype)) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		اذهب out;
	}
	إذا (ca_sigalg_allowlist != عدم &&
	    match_pattern_list(sigtype, ca_sigalg_allowlist, 0) != 1) {
		ret = SSH_ERR_SIGN_ALG_UNSUPPORTED;
		اذهب out;
	}

	/* Parse CA key and check whether we might accept it */
	إذا (sshkey_from_blob_internal(ca, &مفتاح->cert->signature_مفتاح, 0,
	    ca_sigalg_allowlist, عدم) != 0) {
		ret = SSH_ERR_مفتاح_CERT_INVALID_SIGN_مفتاح;
		اذهب out;
	}
	إذا (!sshkey_type_is_valid_ca(مفتاح->cert->signature_مفتاح->type)) {
		ret = SSH_ERR_مفتاح_CERT_INVALID_SIGN_مفتاح;
		اذهب out;
	}

	إذا (مفتاح->cert->type != SSH2_CERT_TYPE_USER &&
	    مفتاح->cert->type != SSH2_CERT_TYPE_HOST) {
		ret = SSH_ERR_مفتاح_CERT_UNKNOWN_TYPE;
		اذهب out;
	}

	/* Parse principals section */
	بينما (sshbuf_len(principals) > 0) {
		حرف *principal = عدم;
		حرف **oprincipals = عدم;

		إذا (مفتاح->cert->nprincipals >= SSHKEY_CERT_MAX_PRINCIPALS) {
			ret = SSH_ERR_INVALID_FORMAT;
			اذهب out;
		}
		إذا ((ret = sshbuf_get_cstring(principals, &principal,
		    عدم)) != 0) {
			ret = SSH_ERR_INVALID_FORMAT;
			اذهب out;
		}
		oprincipals = مفتاح->cert->principals;
		مفتاح->cert->principals = recallocarray(مفتاح->cert->principals,
		    مفتاح->cert->nprincipals, مفتاح->cert->nprincipals + 1,
		    حجم(*مفتاح->cert->principals));
		إذا (مفتاح->cert->principals == عدم) {
			حرر(principal);
			مفتاح->cert->principals = oprincipals;
			ret = SSH_ERR_ALLOC_FAIL;
			اذهب out;
		}
		مفتاح->cert->principals[مفتاح->cert->nprincipals++] = principal;
	}

	/*
	 * Stash a copies of the critical options and extensions sections
	 * for later use.
	 */
	إذا ((ret = sshbuf_putb(مفتاح->cert->critical, crit)) != 0 ||
	    (exts != عدم &&
	    (ret = sshbuf_putb(مفتاح->cert->extensions, exts)) != 0))
		اذهب out;

	/*
	 * Validate critical options and extensions sections format.
	 */
	بينما (sshbuf_len(crit) != 0) {
		إذا ((ret = sshbuf_get_string_direct(crit, عدم, عدم)) != 0 ||
		    (ret = sshbuf_get_string_direct(crit, عدم, عدم)) != 0) {
			sshbuf_reset(مفتاح->cert->critical);
			ret = SSH_ERR_INVALID_FORMAT;
			اذهب out;
		}
	}
	بينما (exts != عدم && sshbuf_len(exts) != 0) {
		إذا ((ret = sshbuf_get_string_direct(exts, عدم, عدم)) != 0 ||
		    (ret = sshbuf_get_string_direct(exts, عدم, عدم)) != 0) {
			sshbuf_reset(مفتاح->cert->extensions);
			ret = SSH_ERR_INVALID_FORMAT;
			اذهب out;
		}
	}

	/* Finally, validate signature */
	إذا ((ret = sshkey_verify(مفتاح->cert->signature_مفتاح, sig, slen,
	    sshbuf_ptr(مفتاح->cert->certblob), signed_len, عدم, 0, عدم)) != 0)
		اذهب out;

	/* Success */
	ret = 0;
	مفتاح->cert->signature_type = sigtype;
	sigtype = عدم;
 out:
	sshbuf_free(ca);
	sshbuf_free(crit);
	sshbuf_free(exts);
	sshbuf_free(principals);
	حرر(sig);
	حرر(sigtype);
	إرجاع ret;
}

صحيح
sshkey_deserialize_sk(بنية sshbuf *b, بنية sshkey *مفتاح)
{
	/* Parse additional security-key application string */
	إذا (sshbuf_get_cstring(b, &مفتاح->sk_application, عدم) != 0)
		إرجاع SSH_ERR_INVALID_FORMAT;
	إرجاع 0;
}

ساكن صحيح
sshkey_from_blob_internal(بنية sshbuf *b, بنية sshkey **keyp,
    صحيح allow_cert, ثابت حرف *alg_allowlist, ثابت حرف *ca_sigalg_allowlist)
{
	صحيح type, ret = SSH_ERR_INTERNAL_ERROR;
	حرف *ktype = عدم;
	بنية sshkey *مفتاح = عدم;
	بنية sshbuf *copy;
	ثابت بنية sshkey_impl *impl;

#ifdef DEBUG_PK /* XXX */
	sshbuf_dump(b, stderr);
#endif
	إذا (keyp != عدم)
		*keyp = عدم;
	إذا ((copy = sshbuf_fromb(b)) == عدم) {
		ret = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}
	إذا (sshbuf_get_cstring(b, &ktype, عدم) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		اذهب out;
	}

	type = sshkey_type_from_name(ktype);
	إذا (!allow_cert && sshkey_type_is_cert(type)) {
		ret = SSH_ERR_مفتاح_CERT_INVALID_SIGN_مفتاح;
		اذهب out;
	}

	إذا (alg_allowlist != عدم &&
	    !sshkey_match_keyname_to_sigalgs(ktype, alg_allowlist)) {
		ret = SSH_ERR_مفتاح_ALG_UNSUPPORTED;
		اذهب out;
	}

	إذا ((impl = sshkey_impl_from_type(type)) == عدم) {
		ret = SSH_ERR_مفتاح_TYPE_UNKNOWN;
		اذهب out;
	}
	إذا ((مفتاح = sshkey_new(type)) == عدم) {
		ret = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}
	إذا (sshkey_type_is_cert(type)) {
		/* Skip nonce that precedes all certificates */
		إذا (sshbuf_get_string_direct(b, عدم, عدم) != 0) {
			ret = SSH_ERR_INVALID_FORMAT;
			اذهب out;
		}
	}
	إذا ((ret = impl->funcs->deserialize_public(ktype, b, مفتاح)) != 0)
		اذهب out;

	/* Parse certificate potion */
	إذا (sshkey_is_cert(مفتاح) &&
	    (ret = cert_parse(b, مفتاح, copy, ca_sigalg_allowlist)) != 0)
		اذهب out;

	إذا (مفتاح != عدم && sshbuf_len(b) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		اذهب out;
	}
	ret = 0;
	إذا (keyp != عدم) {
		*keyp = مفتاح;
		مفتاح = عدم;
	}
 out:
	sshbuf_free(copy);
	sshkey_free(مفتاح);
	حرر(ktype);
	إرجاع ret;
}

صحيح
sshkey_from_blob(ثابت u_char *blob, size_t blen, بنية sshkey **keyp)
{
	بنية sshbuf *b;
	صحيح r;

	إذا ((b = sshbuf_from(blob, blen)) == عدم)
		إرجاع SSH_ERR_ALLOC_FAIL;
	r = sshkey_from_blob_internal(b, keyp, 1, عدم, عدم);
	sshbuf_free(b);
	إرجاع r;
}

صحيح
sshkey_fromb(بنية sshbuf *b, بنية sshkey **keyp)
{
	إرجاع sshkey_from_blob_internal(b, keyp, 1, عدم, عدم);
}

صحيح
sshkey_fromb_allowlist(بنية sshbuf *b, بنية sshkey **keyp,
    ثابت حرف *alg_allowlist, ثابت حرف *ca_sigalg_allowlist)
{
	إرجاع sshkey_from_blob_internal(b, keyp, 1,
	    alg_allowlist, ca_sigalg_allowlist);
}

صحيح
sshkey_froms(بنية sshbuf *buf, بنية sshkey **keyp)
{
	بنية sshbuf *b;
	صحيح r;

	إذا ((r = sshbuf_froms(buf, &b)) != 0)
		إرجاع r;
	r = sshkey_from_blob_internal(b, keyp, 1, عدم, عدم);
	sshbuf_free(b);
	إرجاع r;
}

صحيح
sshkey_get_sigtype(ثابت u_char *sig, size_t siglen, حرف **sigtypep)
{
	صحيح r;
	بنية sshbuf *b = عدم;
	حرف *sigtype = عدم;

	إذا (sigtypep != عدم)
		*sigtypep = عدم;
	إذا ((b = sshbuf_from(sig, siglen)) == عدم)
		إرجاع SSH_ERR_ALLOC_FAIL;
	إذا ((r = sshbuf_get_cstring(b, &sigtype, عدم)) != 0)
		اذهب out;
	/* success */
	إذا (sigtypep != عدم) {
		*sigtypep = sigtype;
		sigtype = عدم;
	}
	r = 0;
 out:
	حرر(sigtype);
	sshbuf_free(b);
	إرجاع r;
}

/*
 *
 * Checks whether a certificate's signature type is allowed.
 * Returns 0 (success) if the certificate signature type appears in the
 * "allowed" pattern-list, or the key is not a certificate to begin with.
 * Otherwise returns a ssherr.h code.
 */
صحيح
sshkey_check_cert_sigtype(ثابت بنية sshkey *مفتاح, ثابت حرف *allowed)
{
	إذا (مفتاح == عدم || allowed == عدم)
		إرجاع SSH_ERR_INVALID_ARGUMENT;
	إذا (!sshkey_type_is_cert(مفتاح->type))
		إرجاع 0;
	إذا (مفتاح->cert == عدم || مفتاح->cert->signature_type == عدم)
		إرجاع SSH_ERR_INVALID_ARGUMENT;
	إذا (match_pattern_list(مفتاح->cert->signature_type, allowed, 0) != 1)
		إرجاع SSH_ERR_SIGN_ALG_UNSUPPORTED;
	إرجاع 0;
}

/*
 * Returns the expected signature algorithm for a given public key algorithm.
 */
ثابت حرف *
sshkey_sigalg_by_name(ثابت حرف *name)
{
	ثابت بنية sshkey_impl *impl;
	صحيح i;

	لكل (i = 0; keyimpls[i] != عدم; i++) {
		impl = keyimpls[i];
		إذا (strcmp(impl->name, name) != 0)
			استمر;
		إذا (impl->sigalg != عدم)
			إرجاع impl->sigalg;
		إذا (!impl->cert)
			إرجاع impl->name;
		إرجاع sshkey_ssh_name_from_type_nid(
		    sshkey_type_plain(impl->type), impl->nid);
	}
	إرجاع عدم;
}

/*
 * Verifies that the signature algorithm appearing inside the signature blob
 * matches that which was requested.
 */
صحيح
sshkey_check_sigtype(ثابت u_char *sig, size_t siglen,
    ثابت حرف *requested_alg)
{
	ثابت حرف *expected_alg;
	حرف *sigtype = عدم;
	صحيح r;

	إذا (requested_alg == عدم)
		إرجاع 0;
	إذا ((expected_alg = sshkey_sigalg_by_name(requested_alg)) == عدم)
		إرجاع SSH_ERR_INVALID_ARGUMENT;
	إذا ((r = sshkey_get_sigtype(sig, siglen, &sigtype)) != 0)
		إرجاع r;
	r = strcmp(expected_alg, sigtype) == 0;
	حرر(sigtype);
	إرجاع r ? 0 : SSH_ERR_SIGN_ALG_UNSUPPORTED;
}

صحيح
sshkey_sign(بنية sshkey *مفتاح,
    u_char **sigp, size_t *lenp,
    ثابت u_char *data, size_t datalen,
    ثابت حرف *alg, ثابت حرف *sk_provider, ثابت حرف *sk_pin, u_int compat)
{
	صحيح was_shielded = sshkey_is_shielded(مفتاح);
	صحيح r2, r = SSH_ERR_INTERNAL_ERROR;
	ثابت بنية sshkey_impl *impl;

	إذا (sigp != عدم)
		*sigp = عدم;
	إذا (lenp != عدم)
		*lenp = 0;
	إذا (datalen > SSH_مفتاح_MAX_SIGN_DATA_SIZE)
		إرجاع SSH_ERR_INVALID_ARGUMENT;
	إذا ((impl = sshkey_impl_from_مفتاح(مفتاح)) == عدم)
		إرجاع SSH_ERR_مفتاح_TYPE_UNKNOWN;
	إذا ((r = sshkey_unshield_private(مفتاح)) != 0)
		إرجاع r;
	إذا (sshkey_is_sk(مفتاح)) {
		r = sshsk_sign(sk_provider, مفتاح, sigp, lenp, data,
		    datalen, compat, sk_pin);
	} وإلا إذا ((مفتاح->flags & SSHKEY_FLAG_EXT) != 0) {
		r = pkcs11_sign(مفتاح, sigp, lenp, data, datalen,
		    alg, sk_provider, sk_pin, compat);
	} وإلا {
		إذا (impl->funcs->sign == عدم)
			r = SSH_ERR_SIGN_ALG_UNSUPPORTED;
		وإلا {
			r = impl->funcs->sign(مفتاح, sigp, lenp, data, datalen,
			    alg, sk_provider, sk_pin, compat);
		 }
	}
	إذا (was_shielded && (r2 = sshkey_shield_private(مفتاح)) != 0)
		إرجاع r2;
	إرجاع r;
}

/*
 * ssh_key_verify returns 0 for a correct signature and < 0 on error.
 * If "alg" specified, then the signature must use that algorithm.
 */
صحيح
sshkey_verify(ثابت بنية sshkey *مفتاح,
    ثابت u_char *sig, size_t siglen,
    ثابت u_char *data, size_t dlen, ثابت حرف *alg, u_int compat,
    بنية sshkey_sig_details **detailsp)
{
	ثابت بنية sshkey_impl *impl;

	إذا (detailsp != عدم)
		*detailsp = عدم;
	إذا (siglen == 0 || dlen > SSH_مفتاح_MAX_SIGN_DATA_SIZE)
		إرجاع SSH_ERR_INVALID_ARGUMENT;
	إذا ((impl = sshkey_impl_from_مفتاح(مفتاح)) == عدم)
		إرجاع SSH_ERR_مفتاح_TYPE_UNKNOWN;
	إرجاع impl->funcs->verify(مفتاح, sig, siglen, data, dlen,
	    alg, compat, detailsp);
}

/* Convert a plain key to their _CERT equivalent */
صحيح
sshkey_to_certified(بنية sshkey *k)
{
	صحيح newtype;

	إذا ((newtype = sshkey_type_certified(k->type)) == -1)
		إرجاع SSH_ERR_INVALID_ARGUMENT;
	إذا ((k->cert = cert_new()) == عدم)
		إرجاع SSH_ERR_ALLOC_FAIL;
	k->type = newtype;
	إرجاع 0;
}

/* Convert a certificate to its raw key equivalent */
صحيح
sshkey_drop_cert(بنية sshkey *k)
{
	إذا (!sshkey_type_is_cert(k->type))
		إرجاع SSH_ERR_مفتاح_TYPE_UNKNOWN;
	cert_free(k->cert);
	k->cert = عدم;
	k->type = sshkey_type_plain(k->type);
	إرجاع 0;
}

/* Sign a certified key, (re-)generating the signed certblob. */
صحيح
sshkey_certify_custom(بنية sshkey *k, بنية sshkey *ca, ثابت حرف *alg,
    ثابت حرف *sk_provider, ثابت حرف *sk_pin,
    sshkey_certify_signer *signer, فراغ *signer_ctx)
{
	ثابت بنية sshkey_impl *impl;
	بنية sshbuf *principals = عدم;
	u_char *ca_blob = عدم, *sig_blob = عدم, nonce[32];
	size_t i, ca_len, sig_len;
	صحيح ret = SSH_ERR_INTERNAL_ERROR;
	بنية sshbuf *cert = عدم;
	حرف *sigtype = عدم;

	إذا (k == عدم || k->cert == عدم ||
	    k->cert->certblob == عدم || ca == عدم)
		إرجاع SSH_ERR_INVALID_ARGUMENT;
	إذا (!sshkey_is_cert(k))
		إرجاع SSH_ERR_مفتاح_TYPE_UNKNOWN;
	إذا (!sshkey_type_is_valid_ca(ca->type))
		إرجاع SSH_ERR_مفتاح_CERT_INVALID_SIGN_مفتاح;
	إذا ((impl = sshkey_impl_from_مفتاح(k)) == عدم)
		إرجاع SSH_ERR_INTERNAL_ERROR;

	/*
	 * If no alg specified as argument but a signature_type was set,
	 * then prefer that. If both were specified, then they must match.
	 */
	إذا (alg == عدم)
		alg = k->cert->signature_type;
	وإلا إذا (k->cert->signature_type != عدم &&
	    strcmp(alg, k->cert->signature_type) != 0)
		إرجاع SSH_ERR_INVALID_ARGUMENT;

	/*
	 * If no signing algorithm or signature_type was specified and we're
	 * using a RSA key, then default to a good signature algorithm.
	 */
	إذا (alg == عدم && ca->type == مفتاح_RSA)
		alg = "rsa-sha2-512";

	إذا ((ret = sshkey_to_blob(ca, &ca_blob, &ca_len)) != 0)
		إرجاع SSH_ERR_مفتاح_CERT_INVALID_SIGN_مفتاح;

	cert = k->cert->certblob; /* for readability */
	sshbuf_reset(cert);
	إذا ((ret = sshbuf_put_cstring(cert, sshkey_ssh_name(k))) != 0)
		اذهب out;

	/* -v01 certs put nonce first */
	arc4random_buf(&nonce, حجم(nonce));
	إذا ((ret = sshbuf_put_string(cert, nonce, حجم(nonce))) != 0)
		اذهب out;

	/* Public key next */
	إذا ((ret = impl->funcs->serialize_public(k, cert,
	    SSHKEY_SERIALIZE_DEFAULT)) != 0)
		اذهب out;

	/* Then remaining cert fields */
	إذا ((ret = sshbuf_put_u64(cert, k->cert->serial)) != 0 ||
	    (ret = sshbuf_put_u32(cert, k->cert->type)) != 0 ||
	    (ret = sshbuf_put_cstring(cert, k->cert->مفتاح_id)) != 0)
		اذهب out;

	إذا ((principals = sshbuf_new()) == عدم) {
		ret = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}
	لكل (i = 0; i < k->cert->nprincipals; i++) {
		إذا ((ret = sshbuf_put_cstring(principals,
		    k->cert->principals[i])) != 0)
			اذهب out;
	}
	إذا ((ret = sshbuf_put_stringb(cert, principals)) != 0 ||
	    (ret = sshbuf_put_u64(cert, k->cert->valid_after)) != 0 ||
	    (ret = sshbuf_put_u64(cert, k->cert->valid_before)) != 0 ||
	    (ret = sshbuf_put_stringb(cert, k->cert->critical)) != 0 ||
	    (ret = sshbuf_put_stringb(cert, k->cert->extensions)) != 0 ||
	    (ret = sshbuf_put_string(cert, عدم, 0)) != 0 || /* Reserved */
	    (ret = sshbuf_put_string(cert, ca_blob, ca_len)) != 0)
		اذهب out;

	/* Sign the whole mess */
	إذا ((ret = signer(ca, &sig_blob, &sig_len, sshbuf_ptr(cert),
	    sshbuf_len(cert), alg, sk_provider, sk_pin, 0, signer_ctx)) != 0)
		اذهب out;
	/* Check and update signature_type against what was actually used */
	إذا ((ret = sshkey_get_sigtype(sig_blob, sig_len, &sigtype)) != 0)
		اذهب out;
	إذا (alg != عدم && strcmp(alg, sigtype) != 0) {
		ret = SSH_ERR_SIGN_ALG_UNSUPPORTED;
		اذهب out;
	}
	إذا (k->cert->signature_type == عدم) {
		k->cert->signature_type = sigtype;
		sigtype = عدم;
	}
	/* Append signature and we are done */
	إذا ((ret = sshbuf_put_string(cert, sig_blob, sig_len)) != 0)
		اذهب out;
	ret = 0;
 out:
	إذا (ret != 0)
		sshbuf_reset(cert);
	حرر(sig_blob);
	حرر(ca_blob);
	حرر(sigtype);
	sshbuf_free(principals);
	إرجاع ret;
}

ساكن صحيح
default_مفتاح_sign(بنية sshkey *مفتاح, u_char **sigp, size_t *lenp,
    ثابت u_char *data, size_t datalen,
    ثابت حرف *alg, ثابت حرف *sk_provider, ثابت حرف *sk_pin,
    u_int compat, فراغ *ctx)
{
	إذا (ctx != عدم)
		إرجاع SSH_ERR_INVALID_ARGUMENT;
	إرجاع sshkey_sign(مفتاح, sigp, lenp, data, datalen, alg,
	    sk_provider, sk_pin, compat);
}

صحيح
sshkey_certify(بنية sshkey *k, بنية sshkey *ca, ثابت حرف *alg,
    ثابت حرف *sk_provider, ثابت حرف *sk_pin)
{
	إرجاع sshkey_certify_custom(k, ca, alg, sk_provider, sk_pin,
	    default_مفتاح_sign, عدم);
}

صحيح
sshkey_cert_check_authority(ثابت بنية sshkey *k,
    صحيح want_host, صحيح wildcard_pattern, uint64_t verify_time,
    ثابت حرف *name, ثابت حرف **reason)
{
	u_int i, principal_matches;

	إذا (reason == عدم)
		إرجاع SSH_ERR_INVALID_ARGUMENT;
	إذا (!sshkey_is_cert(k)) {
		*reason = "Key is not a certificate";
		إرجاع SSH_ERR_مفتاح_CERT_INVALID;
	}
	إذا (want_host) {
		إذا (k->cert->type != SSH2_CERT_TYPE_HOST) {
			*reason = "Certificate invalid: not a host certificate";
			إرجاع SSH_ERR_مفتاح_CERT_INVALID;
		}
	} وإلا {
		إذا (k->cert->type != SSH2_CERT_TYPE_USER) {
			*reason = "Certificate invalid: not a user certificate";
			إرجاع SSH_ERR_مفتاح_CERT_INVALID;
		}
	}
	إذا (verify_time < k->cert->valid_after) {
		*reason = "Certificate invalid: not yet valid";
		إرجاع SSH_ERR_مفتاح_CERT_INVALID;
	}
	إذا (verify_time >= k->cert->valid_before) {
		*reason = "Certificate invalid: expired";
		إرجاع SSH_ERR_مفتاح_CERT_INVALID;
	}
	إذا (k->cert->nprincipals == 0) {
		*reason = "Certificate lacks principal list";
		إرجاع SSH_ERR_مفتاح_CERT_INVALID;
	}
	إذا (name == عدم)
		إرجاع 0; /* principal matching not requested */

	principal_matches = 0;
	لكل (i = 0; i < k->cert->nprincipals; i++) {
		إذا (wildcard_pattern) {
			إذا (match_pattern(name, k->cert->principals[i])) {
				principal_matches = 1;
				اكسر;
			}
		} وإلا إذا (strcmp(name, k->cert->principals[i]) == 0) {
			principal_matches = 1;
			اكسر;
		}
	}
	إذا (!principal_matches) {
		*reason = "Certificate invalid: name is not a listed "
		    "principal";
		إرجاع SSH_ERR_مفتاح_CERT_INVALID;
	}
	إرجاع 0;
}

صحيح
sshkey_cert_check_authority_now(ثابت بنية sshkey *k,
    صحيح want_host, صحيح wildcard_pattern, ثابت حرف *name,
    ثابت حرف **reason)
{
	time_t now;

	إذا ((now = time(عدم)) < 0) {
		/* yikes - system clock before epoch! */
		*reason = "Certificate invalid: not yet valid";
		إرجاع SSH_ERR_مفتاح_CERT_INVALID;
	}
	إرجاع sshkey_cert_check_authority(k, want_host, wildcard_pattern,
	    (uint64_t)now, name, reason);
}

صحيح
sshkey_cert_check_host(ثابت بنية sshkey *مفتاح, ثابت حرف *host,
    ثابت حرف *ca_sign_algorithms, ثابت حرف **reason)
{
	صحيح r;

	إذا ((r = sshkey_cert_check_authority_now(مفتاح, 1, 1, host, reason)) != 0)
		إرجاع r;
	إذا (sshbuf_len(مفتاح->cert->critical) != 0) {
		*reason = "Certificate contains unsupported critical options";
		إرجاع SSH_ERR_مفتاح_CERT_INVALID;
	}
	إذا (ca_sign_algorithms != عدم &&
	    (r = sshkey_check_cert_sigtype(مفتاح, ca_sign_algorithms)) != 0) {
		*reason = "Certificate signed with disallowed algorithm";
		إرجاع SSH_ERR_مفتاح_CERT_INVALID;
	}
	إرجاع 0;
}

size_t
sshkey_format_cert_validity(ثابت بنية sshkey_cert *cert, حرف *s, size_t l)
{
	حرف from[32], to[32], ret[128];

	*from = *to = '\0';
	إذا (cert->valid_after == 0 &&
	    cert->valid_before == 0xffffffffffffffffULL)
		إرجاع strlcpy(s, "forever", l);

	إذا (cert->valid_after != 0)
		format_absolute_time(cert->valid_after, from, حجم(from));
	إذا (cert->valid_before != 0xffffffffffffffffULL)
		format_absolute_time(cert->valid_before, to, حجم(to));

	إذا (cert->valid_after == 0)
		snprintf(ret, حجم(ret), "before %s", to);
	وإلا إذا (cert->valid_before == 0xffffffffffffffffULL)
		snprintf(ret, حجم(ret), "after %s", from);
	وإلا
		snprintf(ret, حجم(ret), "from %s to %s", from, to);

	إرجاع strlcpy(s, ret, l);
}

/* Common serialization for FIDO private keys */
صحيح
sshkey_serialize_private_sk(ثابت بنية sshkey *مفتاح, بنية sshbuf *b)
{
	صحيح r;

	إذا ((r = sshbuf_put_cstring(b, مفتاح->sk_application)) != 0 ||
	    (r = sshbuf_put_u8(b, مفتاح->sk_flags)) != 0 ||
	    (r = sshbuf_put_stringb(b, مفتاح->sk_مفتاح_handle)) != 0 ||
	    (r = sshbuf_put_stringb(b, مفتاح->sk_reserved)) != 0)
		إرجاع r;

	إرجاع 0;
}

ساكن صحيح
sshkey_private_serialize_opt(بنية sshkey *مفتاح, بنية sshbuf *buf,
    تعداد sshkey_serialize_rep opts)
{
	صحيح r = SSH_ERR_INTERNAL_ERROR;
	صحيح was_shielded = sshkey_is_shielded(مفتاح);
	بنية sshbuf *b = عدم;
	ثابت بنية sshkey_impl *impl;

	إذا ((impl = sshkey_impl_from_مفتاح(مفتاح)) == عدم)
		إرجاع SSH_ERR_INTERNAL_ERROR;
	إذا ((r = sshkey_unshield_private(مفتاح)) != 0)
		إرجاع r;
	إذا ((b = sshbuf_new()) == عدم)
		إرجاع SSH_ERR_ALLOC_FAIL;
	إذا ((r = sshbuf_put_cstring(b, sshkey_ssh_name(مفتاح))) != 0)
		اذهب out;
	إذا (sshkey_is_cert(مفتاح)) {
		إذا (مفتاح->cert == عدم ||
		    sshbuf_len(مفتاح->cert->certblob) == 0) {
			r = SSH_ERR_INVALID_ARGUMENT;
			اذهب out;
		}
		إذا ((r = sshbuf_put_stringb(b, مفتاح->cert->certblob)) != 0)
			اذهب out;
	}
	إذا ((r = impl->funcs->serialize_private(مفتاح, b, opts)) != 0)
		اذهب out;

	/*
	 * success (but we still need to append the output to buf after
	 * possibly re-shielding the private key)
	 */
	r = 0;
 out:
	إذا (was_shielded)
		r = sshkey_shield_private(مفتاح);
	إذا (r == 0)
		r = sshbuf_putb(buf, b);
	sshbuf_free(b);

	إرجاع r;
}

صحيح
sshkey_private_serialize(بنية sshkey *مفتاح, بنية sshbuf *b)
{
	إرجاع sshkey_private_serialize_opt(مفتاح, b,
	    SSHKEY_SERIALIZE_DEFAULT);
}


/* Shared deserialization of FIDO private key components */
صحيح
sshkey_private_deserialize_sk(بنية sshbuf *buf, بنية sshkey *k)
{
	صحيح r;

	إذا ((k->sk_مفتاح_handle = sshbuf_new()) == عدم ||
	    (k->sk_reserved = sshbuf_new()) == عدم)
		إرجاع SSH_ERR_ALLOC_FAIL;
	إذا ((r = sshbuf_get_cstring(buf, &k->sk_application, عدم)) != 0 ||
	    (r = sshbuf_get_u8(buf, &k->sk_flags)) != 0 ||
	    (r = sshbuf_get_stringb(buf, k->sk_مفتاح_handle)) != 0 ||
	    (r = sshbuf_get_stringb(buf, k->sk_reserved)) != 0)
		إرجاع r;

	إرجاع 0;
}

صحيح
sshkey_private_deserialize(بنية sshbuf *buf, بنية sshkey **kp)
{
	ثابت بنية sshkey_impl *impl;
	حرف *tname = عدم;
	حرف *expect_sk_application = عدم;
	u_char *expect_ed25519_pk = عدم;
	بنية sshkey *k = عدم;
	صحيح type, r = SSH_ERR_INTERNAL_ERROR;

	إذا (kp != عدم)
		*kp = عدم;
	إذا ((r = sshbuf_get_cstring(buf, &tname, عدم)) != 0)
		اذهب out;
	type = sshkey_type_from_name(tname);
	إذا (sshkey_type_is_cert(type)) {
		/*
		 * Certificate key private keys begin with the certificate
		 * itself. Make sure this matches the type of the enclosing
		 * private key.
		 */
		إذا ((r = sshkey_froms(buf, &k)) != 0)
			اذهب out;
		إذا (k->type != type) {
			r = SSH_ERR_مفتاح_CERT_MISMATCH;
			اذهب out;
		}
		/* For ECDSA keys, the group must match too */
		إذا (k->type == مفتاح_ECDSA &&
		    k->ecdsa_nid != sshkey_ecdsa_nid_from_name(tname)) {
			r = SSH_ERR_مفتاح_CERT_MISMATCH;
			اذهب out;
		}
		/*
		 * Several fields are redundant between certificate and
		 * private key body, we require these to match.
		 */
		expect_sk_application = k->sk_application;
		expect_ed25519_pk = k->ed25519_pk;
		k->sk_application = عدم;
		k->ed25519_pk = عدم;
	} وإلا {
		إذا ((k = sshkey_new(type)) == عدم) {
			r = SSH_ERR_ALLOC_FAIL;
			اذهب out;
		}
	}
	إذا ((impl = sshkey_impl_from_type(type)) == عدم) {
		r = SSH_ERR_INTERNAL_ERROR;
		اذهب out;
	}
	إذا ((r = impl->funcs->deserialize_private(tname, buf, k)) != 0)
		اذهب out;

	إذا ((expect_sk_application != عدم && (k->sk_application == عدم ||
	    strcmp(expect_sk_application, k->sk_application) != 0)) ||
	    (expect_ed25519_pk != عدم && (k->ed25519_pk == عدم ||
	    memcmp(expect_ed25519_pk, k->ed25519_pk, ED25519_PK_SZ) != 0))) {
		r = SSH_ERR_مفتاح_CERT_MISMATCH;
		اذهب out;
	}
	/* success */
	r = 0;
	إذا (kp != عدم) {
		*kp = k;
		k = عدم;
	}
 out:
	حرر(tname);
	sshkey_free(k);
	حرر(expect_sk_application);
	حرر(expect_ed25519_pk);
	إرجاع r;
}

#ifdef WITH_OPENSSL
صحيح
sshkey_ec_validate_public(ثابت EC_GROUP *group, ثابت EC_POINT *عام)
{
	EC_POINT *nq = عدم;
	BIGNUM *order = عدم, *cofactor = عدم;
	صحيح ret = SSH_ERR_مفتاح_INVALID_EC_قيمة;

	/*
	 * NB. This assumes OpenSSL has already verified that the public
	 * point lies on the curve and that its coordinates are in [0, p).
	 * This is done by EC_POINT_oct2point() on at least OpenSSL >= 1.1,
	 * LibreSSL and BoringSSL.
	 */

	/* Q != infinity */
	إذا (EC_POINT_is_at_infinity(group, عام))
		اذهب out;

	إذا ((cofactor = BN_new()) == عدم) {
		ret = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}
	إذا (EC_GROUP_get_cofactor(group, cofactor, عدم) != 1)
		اذهب out;

	/*
	 * Verify nQ == infinity (n == order of subgroup)
	 * This check may be skipped for curves with cofactor 1, as per
	 * NIST SP 800-56A, 5.6.2.3.
	 */
	إذا (!BN_is_one(cofactor)) {
		إذا ((order = BN_new()) == عدم) {
			ret = SSH_ERR_ALLOC_FAIL;
			اذهب out;
		}
		إذا (EC_GROUP_get_order(group, order, عدم) != 1) {
			ret = SSH_ERR_LIBCRYPTO_ERROR;
			اذهب out;
		}
		إذا ((nq = EC_POINT_new(group)) == عدم) {
			ret = SSH_ERR_ALLOC_FAIL;
			اذهب out;
		}
		إذا (EC_POINT_mul(group, nq, عدم, عام, order, عدم) != 1) {
			ret = SSH_ERR_LIBCRYPTO_ERROR;
			اذهب out;
		}
		إذا (EC_POINT_is_at_infinity(group, nq) != 1)
			اذهب out;
	}

	/* success */
	ret = 0;
 out:
	BN_clear_free(cofactor);
	BN_clear_free(order);
	EC_POINT_free(nq);
	إرجاع ret;
}

صحيح
sshkey_ec_validate_private(ثابت EC_مفتاح *مفتاح)
{
	BIGNUM *order = عدم, *tmp = عدم;
	صحيح ret = SSH_ERR_مفتاح_INVALID_EC_قيمة;

	إذا ((order = BN_new()) == عدم || (tmp = BN_new()) == عدم) {
		ret = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}

	/* log2(private) > log2(order)/2 */
	إذا (EC_GROUP_get_order(EC_مفتاح_get0_group(مفتاح), order, عدم) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		اذهب out;
	}
	إذا (BN_رقم_bits(EC_مفتاح_get0_private_مفتاح(مفتاح)) <=
	    BN_رقم_bits(order) / 2)
		اذهب out;

	/* private < order - 1 */
	إذا (!BN_sub(tmp, order, BN_قيمة_one())) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		اذهب out;
	}
	إذا (BN_cmp(EC_مفتاح_get0_private_مفتاح(مفتاح), tmp) >= 0)
		اذهب out;
	ret = 0;
 out:
	BN_clear_free(order);
	BN_clear_free(tmp);
	إرجاع ret;
}

فراغ
sshkey_dump_ec_point(ثابت EC_GROUP *group, ثابت EC_POINT *point)
{
	BIGNUM *x = عدم, *y = عدم;

	إذا (point == عدم) {
		fputs("point=(NULL)\n", stderr);
		إرجاع;
	}
	إذا ((x = BN_new()) == عدم || (y = BN_new()) == عدم) {
		fprintf(stderr, "%s: BN_new failed\n", __func__);
		اذهب out;
	}
	إذا (EC_POINT_get_affine_coordinates(group, point, x, y, عدم) != 1) {
		fprintf(stderr, "%s: EC_POINT_get_affine_coordinates\n",
		    __func__);
		اذهب out;
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

فراغ
sshkey_dump_ec_مفتاح(ثابت EC_مفتاح *مفتاح)
{
	ثابت BIGNUM *exponent;

	sshkey_dump_ec_point(EC_مفتاح_get0_group(مفتاح),
	    EC_مفتاح_get0_public_مفتاح(مفتاح));
	fputs("exponent=", stderr);
	إذا ((exponent = EC_مفتاح_get0_private_مفتاح(مفتاح)) == عدم)
		fputs("(NULL)", stderr);
	وإلا
		BN_print_fp(stderr, EC_مفتاح_get0_private_مفتاح(مفتاح));
	fputs("\n", stderr);
}
#endif /* WITH_OPENSSL */

ساكن صحيح
sshkey_private_to_blob2(بنية sshkey *prv, بنية sshbuf *blob,
    ثابت حرف *passphrase, ثابت حرف *comment, ثابت حرف *ciphername,
    صحيح rounds)
{
	u_char *cp, *مفتاح = عدم, *pubkeyblob = عدم;
	u_char salt[SALT_LEN];
	size_t i, pubkeylen, keylen, ivlen, blocksize, authlen;
	u_int check;
	صحيح r = SSH_ERR_INTERNAL_ERROR;
	بنية sshcipher_ctx *ciphercontext = عدم;
	ثابت بنية sshcipher *cipher;
	ثابت حرف *kdfname = KDFNAME;
	بنية sshbuf *encoded = عدم, *encrypted = عدم, *kdf = عدم;

	إذا (rounds <= 0)
		rounds = DEFAULT_ROUNDS;
	إذا (rounds > MAX_KDF_ROUNDS) {
		r = SSH_ERR_INVALID_ARGUMENT;
		اذهب out;
	}
	إذا (passphrase == عدم || !strlen(passphrase)) {
		ciphername = "none";
		kdfname = "none";
	} وإلا إذا (ciphername == عدم)
		ciphername = DEFAULT_CIPHERNAME;
	إذا ((cipher = cipher_by_name(ciphername)) == عدم) {
		r = SSH_ERR_INVALID_ARGUMENT;
		اذهب out;
	}

	إذا ((kdf = sshbuf_new()) == عدم ||
	    (encoded = sshbuf_new()) == عدم ||
	    (encrypted = sshbuf_new()) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}
	blocksize = cipher_blocksize(cipher);
	keylen = cipher_keylen(cipher);
	ivlen = cipher_ivlen(cipher);
	authlen = cipher_authlen(cipher);
	إذا ((مفتاح = calloc(1, keylen + ivlen)) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}
	إذا (strcmp(kdfname, "bcrypt") == 0) {
		arc4random_buf(salt, SALT_LEN);
		إذا (bcrypt_pbkdf(passphrase, strlen(passphrase),
		    salt, SALT_LEN, مفتاح, keylen + ivlen, rounds) < 0) {
			r = SSH_ERR_INVALID_ARGUMENT;
			اذهب out;
		}
		إذا ((r = sshbuf_put_string(kdf, salt, SALT_LEN)) != 0 ||
		    (r = sshbuf_put_u32(kdf, rounds)) != 0)
			اذهب out;
	} وإلا إذا (strcmp(kdfname, "none") != 0) {
		/* Unsupported KDF type */
		r = SSH_ERR_مفتاح_UNKNOWN_CIPHER;
		اذهب out;
	}
	إذا ((r = cipher_init(&ciphercontext, cipher, مفتاح, keylen,
	    مفتاح + keylen, ivlen, 1)) != 0)
		اذهب out;

	إذا ((r = sshbuf_put(encoded, AUTH_MAGIC, حجم(AUTH_MAGIC))) != 0 ||
	    (r = sshbuf_put_cstring(encoded, ciphername)) != 0 ||
	    (r = sshbuf_put_cstring(encoded, kdfname)) != 0 ||
	    (r = sshbuf_put_stringb(encoded, kdf)) != 0 ||
	    (r = sshbuf_put_u32(encoded, 1)) != 0 ||	/* number of keys */
	    (r = sshkey_to_blob(prv, &pubkeyblob, &pubkeylen)) != 0 ||
	    (r = sshbuf_put_string(encoded, pubkeyblob, pubkeylen)) != 0)
		اذهب out;

	/* set up the buffer that will be encrypted */

	/* Random check bytes */
	check = arc4random();
	إذا ((r = sshbuf_put_u32(encrypted, check)) != 0 ||
	    (r = sshbuf_put_u32(encrypted, check)) != 0)
		اذهب out;

	/* append private key and comment*/
	إذا ((r = sshkey_private_serialize(prv, encrypted)) != 0 ||
	    (r = sshbuf_put_cstring(encrypted, comment)) != 0)
		اذهب out;

	/* padding */
	i = 0;
	بينما (sshbuf_len(encrypted) % blocksize) {
		إذا ((r = sshbuf_put_u8(encrypted, ++i & 0xff)) != 0)
			اذهب out;
	}

	/* length in destination buffer */
	إذا ((r = sshbuf_put_u32(encoded, sshbuf_len(encrypted))) != 0)
		اذهب out;

	/* encrypt */
	إذا ((r = sshbuf_reserve(encoded,
	    sshbuf_len(encrypted) + authlen, &cp)) != 0)
		اذهب out;
	إذا ((r = cipher_crypt(ciphercontext, 0, cp,
	    sshbuf_ptr(encrypted), sshbuf_len(encrypted), 0, authlen)) != 0)
		اذهب out;

	sshbuf_reset(blob);

	/* assemble uuencoded key */
	إذا ((r = sshbuf_put(blob, MARK_BEGIN, MARK_BEGIN_LEN)) != 0 ||
	    (r = sshbuf_dtob64(encoded, blob, 1)) != 0 ||
	    (r = sshbuf_put(blob, MARK_END, MARK_END_LEN)) != 0)
		اذهب out;

	/* success */
	r = 0;

 out:
	sshbuf_free(kdf);
	sshbuf_free(encoded);
	sshbuf_free(encrypted);
	cipher_free(ciphercontext);
	explicit_bzero(salt, حجم(salt));
	إذا (مفتاح != عدم)
		freezero(مفتاح, keylen + ivlen);
	إذا (pubkeyblob != عدم)
		freezero(pubkeyblob, pubkeylen);
	إرجاع r;
}

ساكن صحيح
private2_uudecode(بنية sshbuf *blob, بنية sshbuf **decodedp)
{
	ثابت u_char *cp;
	size_t encoded_len;
	صحيح r;
	u_char last;
	بنية sshbuf *encoded = عدم, *decoded = عدم;

	إذا (blob == عدم || decodedp == عدم)
		إرجاع SSH_ERR_INVALID_ARGUMENT;

	*decodedp = عدم;

	إذا ((encoded = sshbuf_new()) == عدم ||
	    (decoded = sshbuf_new()) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}

	/* check preamble */
	cp = sshbuf_ptr(blob);
	encoded_len = sshbuf_len(blob);
	إذا (encoded_len < (MARK_BEGIN_LEN + MARK_END_LEN) ||
	    memcmp(cp, MARK_BEGIN, MARK_BEGIN_LEN) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		اذهب out;
	}
	cp += MARK_BEGIN_LEN;
	encoded_len -= MARK_BEGIN_LEN;

	/* Look for end marker, removing whitespace as we go */
	بينما (encoded_len > 0) {
		إذا (*cp != '\n' && *cp != '\r') {
			إذا ((r = sshbuf_put_u8(encoded, *cp)) != 0)
				اذهب out;
		}
		last = *cp;
		encoded_len--;
		cp++;
		إذا (last == '\n') {
			إذا (encoded_len >= MARK_END_LEN &&
			    memcmp(cp, MARK_END, MARK_END_LEN) == 0) {
				/* \0 terminate */
				إذا ((r = sshbuf_put_u8(encoded, 0)) != 0)
					اذهب out;
				اكسر;
			}
		}
	}
	إذا (encoded_len == 0) {
		r = SSH_ERR_INVALID_FORMAT;
		اذهب out;
	}

	/* decode base64 */
	إذا ((r = sshbuf_b64tod(decoded, (حرف *)sshbuf_ptr(encoded))) != 0)
		اذهب out;

	/* check magic */
	إذا (sshbuf_len(decoded) < حجم(AUTH_MAGIC) ||
	    memcmp(sshbuf_ptr(decoded), AUTH_MAGIC, حجم(AUTH_MAGIC))) {
		r = SSH_ERR_INVALID_FORMAT;
		اذهب out;
	}
	/* success */
	*decodedp = decoded;
	decoded = عدم;
	r = 0;
 out:
	sshbuf_free(encoded);
	sshbuf_free(decoded);
	إرجاع r;
}

ساكن صحيح
private2_decrypt(بنية sshbuf *decoded, ثابت حرف *passphrase,
    بنية sshbuf **decryptedp, بنية sshkey **pubkeyp)
{
	حرف *ciphername = عدم, *kdfname = عدم;
	ثابت بنية sshcipher *cipher = عدم;
	صحيح r = SSH_ERR_INTERNAL_ERROR;
	size_t keylen = 0, ivlen = 0, authlen = 0, slen = 0;
	بنية sshbuf *kdf = عدم, *decrypted = عدم;
	بنية sshcipher_ctx *ciphercontext = عدم;
	بنية sshkey *pubkey = عدم;
	u_char *مفتاح = عدم, *salt = عدم, *dp;
	u_int blocksize, rounds, nkeys, encrypted_len, check1, check2;

	إذا (decoded == عدم || decryptedp == عدم || pubkeyp == عدم)
		إرجاع SSH_ERR_INVALID_ARGUMENT;

	*decryptedp = عدم;
	*pubkeyp = عدم;

	إذا ((decrypted = sshbuf_new()) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}

	/* parse public portion of key */
	إذا ((r = sshbuf_consume(decoded, حجم(AUTH_MAGIC))) != 0 ||
	    (r = sshbuf_get_cstring(decoded, &ciphername, عدم)) != 0 ||
	    (r = sshbuf_get_cstring(decoded, &kdfname, عدم)) != 0 ||
	    (r = sshbuf_froms(decoded, &kdf)) != 0 ||
	    (r = sshbuf_get_u32(decoded, &nkeys)) != 0)
		اذهب out;

	إذا (nkeys != 1) {
		/* XXX only one key supported at present */
		r = SSH_ERR_INVALID_FORMAT;
		اذهب out;
	}

	إذا ((r = sshkey_froms(decoded, &pubkey)) != 0 ||
	    (r = sshbuf_get_u32(decoded, &encrypted_len)) != 0)
		اذهب out;

	إذا ((cipher = cipher_by_name(ciphername)) == عدم) {
		r = SSH_ERR_مفتاح_UNKNOWN_CIPHER;
		اذهب out;
	}
	إذا (strcmp(kdfname, "none") != 0 && strcmp(kdfname, "bcrypt") != 0) {
		r = SSH_ERR_مفتاح_UNKNOWN_CIPHER;
		اذهب out;
	}
	إذا (strcmp(kdfname, "none") == 0 && strcmp(ciphername, "none") != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		اذهب out;
	}
	إذا ((passphrase == عدم || strlen(passphrase) == 0) &&
	    strcmp(kdfname, "none") != 0) {
		/* passphrase required */
		r = SSH_ERR_مفتاح_WRONG_PASSPHRASE;
		اذهب out;
	}

	/* check size of encrypted key blob */
	blocksize = cipher_blocksize(cipher);
	إذا (encrypted_len < blocksize || (encrypted_len % blocksize) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		اذهب out;
	}

	/* setup key */
	keylen = cipher_keylen(cipher);
	ivlen = cipher_ivlen(cipher);
	authlen = cipher_authlen(cipher);
	إذا ((مفتاح = calloc(1, keylen + ivlen)) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}
	إذا (strcmp(kdfname, "bcrypt") == 0) {
		إذا ((r = sshbuf_get_string(kdf, &salt, &slen)) != 0 ||
		    (r = sshbuf_get_u32(kdf, &rounds)) != 0)
			اذهب out;
		إذا (rounds > MAX_KDF_ROUNDS) {
			r = SSH_ERR_INVALID_FORMAT;
			اذهب out;
		}
		إذا (bcrypt_pbkdf(passphrase, strlen(passphrase), salt, slen,
		    مفتاح, keylen + ivlen, rounds) < 0) {
			r = SSH_ERR_INVALID_FORMAT;
			اذهب out;
		}
	}

	/* check that an appropriate amount of auth data is present */
	إذا (sshbuf_len(decoded) < authlen ||
	    sshbuf_len(decoded) - authlen < encrypted_len) {
		r = SSH_ERR_INVALID_FORMAT;
		اذهب out;
	}

	/* decrypt private portion of key */
	إذا ((r = sshbuf_reserve(decrypted, encrypted_len, &dp)) != 0 ||
	    (r = cipher_init(&ciphercontext, cipher, مفتاح, keylen,
	    مفتاح + keylen, ivlen, 0)) != 0)
		اذهب out;
	إذا ((r = cipher_crypt(ciphercontext, 0, dp, sshbuf_ptr(decoded),
	    encrypted_len, 0, authlen)) != 0) {
		/* an integrity error here indicates an incorrect passphrase */
		إذا (r == SSH_ERR_MAC_INVALID)
			r = SSH_ERR_مفتاح_WRONG_PASSPHRASE;
		اذهب out;
	}
	إذا ((r = sshbuf_consume(decoded, encrypted_len + authlen)) != 0)
		اذهب out;
	/* there should be no trailing data */
	إذا (sshbuf_len(decoded) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		اذهب out;
	}

	/* check check bytes */
	إذا ((r = sshbuf_get_u32(decrypted, &check1)) != 0 ||
	    (r = sshbuf_get_u32(decrypted, &check2)) != 0)
		اذهب out;
	إذا (check1 != check2) {
		r = SSH_ERR_مفتاح_WRONG_PASSPHRASE;
		اذهب out;
	}
	/* success */
	*decryptedp = decrypted;
	decrypted = عدم;
	*pubkeyp = pubkey;
	pubkey = عدم;
	r = 0;
 out:
	cipher_free(ciphercontext);
	حرر(ciphername);
	حرر(kdfname);
	sshkey_free(pubkey);
	إذا (salt != عدم) {
		explicit_bzero(salt, slen);
		حرر(salt);
	}
	إذا (مفتاح != عدم) {
		explicit_bzero(مفتاح, keylen + ivlen);
		حرر(مفتاح);
	}
	sshbuf_free(kdf);
	sshbuf_free(decrypted);
	إرجاع r;
}

ساكن صحيح
sshkey_parse_private2(بنية sshbuf *blob, صحيح type, ثابت حرف *passphrase,
    بنية sshkey **keyp, حرف **commentp)
{
	حرف *comment = عدم;
	صحيح r = SSH_ERR_INTERNAL_ERROR;
	بنية sshbuf *decoded = عدم, *decrypted = عدم;
	بنية sshkey *k = عدم, *pubkey = عدم;

	إذا (keyp != عدم)
		*keyp = عدم;
	إذا (commentp != عدم)
		*commentp = عدم;

	/* Undo base64 encoding and decrypt the private section */
	إذا ((r = private2_uudecode(blob, &decoded)) != 0 ||
	    (r = private2_decrypt(decoded, passphrase,
	    &decrypted, &pubkey)) != 0)
		اذهب out;

	إذا (type != مفتاح_UNSPEC &&
	    sshkey_type_plain(type) != sshkey_type_plain(pubkey->type)) {
		r = SSH_ERR_مفتاح_TYPE_MISMATCH;
		اذهب out;
	}

	/* Load the private key and comment */
	إذا ((r = sshkey_private_deserialize(decrypted, &k)) != 0 ||
	    (r = sshbuf_get_cstring(decrypted, &comment, عدم)) != 0)
		اذهب out;

	/* Check deterministic padding after private section */
	إذا ((r = private2_check_padding(decrypted)) != 0)
		اذهب out;

	/* Check that the public key in the envelope matches the private key */
	إذا (!sshkey_equal(pubkey, k)) {
		r = SSH_ERR_INVALID_FORMAT;
		اذهب out;
	}

	/* success */
	r = 0;
	إذا (keyp != عدم) {
		*keyp = k;
		k = عدم;
	}
	إذا (commentp != عدم) {
		*commentp = comment;
		comment = عدم;
	}
 out:
	حرر(comment);
	sshbuf_free(decoded);
	sshbuf_free(decrypted);
	sshkey_free(k);
	sshkey_free(pubkey);
	إرجاع r;
}

ساكن صحيح
sshkey_parse_private2_pubkey(بنية sshbuf *blob, صحيح type,
    بنية sshkey **keyp)
{
	صحيح r = SSH_ERR_INTERNAL_ERROR;
	بنية sshbuf *decoded = عدم;
	بنية sshkey *pubkey = عدم;
	u_int nkeys = 0;

	إذا (keyp != عدم)
		*keyp = عدم;

	إذا ((r = private2_uudecode(blob, &decoded)) != 0)
		اذهب out;
	/* parse public key from unencrypted envelope */
	إذا ((r = sshbuf_consume(decoded, حجم(AUTH_MAGIC))) != 0 ||
	    (r = sshbuf_skip_string(decoded)) != 0 || /* cipher */
	    (r = sshbuf_skip_string(decoded)) != 0 || /* KDF alg */
	    (r = sshbuf_skip_string(decoded)) != 0 || /* KDF hint */
	    (r = sshbuf_get_u32(decoded, &nkeys)) != 0)
		اذهب out;

	إذا (nkeys != 1) {
		/* XXX only one key supported at present */
		r = SSH_ERR_INVALID_FORMAT;
		اذهب out;
	}

	/* Parse the public key */
	إذا ((r = sshkey_froms(decoded, &pubkey)) != 0)
		اذهب out;

	إذا (type != مفتاح_UNSPEC &&
	    sshkey_type_plain(type) != sshkey_type_plain(pubkey->type)) {
		r = SSH_ERR_مفتاح_TYPE_MISMATCH;
		اذهب out;
	}

	/* success */
	r = 0;
	إذا (keyp != عدم) {
		*keyp = pubkey;
		pubkey = عدم;
	}
 out:
	sshbuf_free(decoded);
	sshkey_free(pubkey);
	إرجاع r;
}

#ifdef WITH_OPENSSL
/* convert SSH v2 key to PEM or PKCS#8 format */
ساكن صحيح
sshkey_private_to_blob_pem_pkcs8(بنية sshkey *مفتاح, بنية sshbuf *buf,
    صحيح format, ثابت حرف *_passphrase, ثابت حرف *comment)
{
	صحيح was_shielded = sshkey_is_shielded(مفتاح);
	صحيح success, r;
	صحيح blen, len = strlen(_passphrase);
	u_char *passphrase = (len > 0) ? (u_char *)_passphrase : عدم;
	ثابت EVP_CIPHER *cipher = (len > 0) ? EVP_aes_128_cbc() : عدم;
	حرف *bptr;
	BIO *bio = عدم;
	بنية sshbuf *blob;
	EVP_PKEY *pkey = عدم;

	إذا (len > 0 && len <= 4)
		إرجاع SSH_ERR_PASSPHRASE_TOO_SHORT;
	إذا ((blob = sshbuf_new()) == عدم)
		إرجاع SSH_ERR_ALLOC_FAIL;
	إذا ((bio = BIO_new(BIO_s_mem())) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}
	إذا ((r = sshkey_unshield_private(مفتاح)) != 0)
		اذهب out;

	بدل (مفتاح->type) {
	حالة مفتاح_ECDSA:
		إذا (format == SSHKEY_PRIVATE_PEM) {
			success = PEM_write_bio_ECPrivate_مفتاح(bio,
			    EVP_PKEY_get0_EC_مفتاح(مفتاح->pkey),
			    cipher, passphrase, len, عدم, عدم);
		} وإلا {
			pkey = مفتاح->pkey;
			EVP_PKEY_up_ref(مفتاح->pkey);
			success = 1;
		}
		اكسر;
	حالة مفتاح_RSA:
		إذا (format == SSHKEY_PRIVATE_PEM) {
			success = PEM_write_bio_RSAPrivate_مفتاح(bio,
			    EVP_PKEY_get0_RSA(مفتاح->pkey),
			    cipher, passphrase, len, عدم, عدم);
		} وإلا {
			pkey = مفتاح->pkey;
			EVP_PKEY_up_ref(مفتاح->pkey);
			success = 1;
		}
		اكسر;
#ifdef OPENSSL_HAS_ED25519
	حالة مفتاح_ED25519:
		إذا (format == SSHKEY_PRIVATE_PEM) {
			r = SSH_ERR_INVALID_FORMAT;
			اذهب out;
		} وإلا {
			pkey = EVP_PKEY_new_raw_private_مفتاح(EVP_PKEY_ED25519,
			    عدم, مفتاح->ed25519_sk,
			    ED25519_SK_SZ - ED25519_PK_SZ);
			success = pkey != عدم;
		}
		اكسر;
#endif
	افتراضي:
		success = 0;
		اكسر;
	}
	إذا (success == 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		اذهب out;
	}
	إذا (format == SSHKEY_PRIVATE_PKCS8) {
		إذا ((success = PEM_write_bio_Private_مفتاح(bio, pkey, cipher,
		    passphrase, len, عدم, عدم)) == 0) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			اذهب out;
		}
	}
	إذا ((blen = BIO_get_mem_data(bio, &bptr)) <= 0) {
		r = SSH_ERR_INTERNAL_ERROR;
		اذهب out;
	}
	إذا ((r = sshbuf_put(blob, bptr, blen)) != 0)
		اذهب out;
	r = 0;
 out:
	إذا (was_shielded)
		r = sshkey_shield_private(مفتاح);
	إذا (r == 0)
		r = sshbuf_putb(buf, blob);

	EVP_PKEY_free(pkey);
	sshbuf_free(blob);
	BIO_free(bio);
	إرجاع r;
}
#endif /* WITH_OPENSSL */

/* Serialise "key" to buffer "blob" */
صحيح
sshkey_private_to_fileblob(بنية sshkey *مفتاح, بنية sshbuf *blob,
    ثابت حرف *passphrase, ثابت حرف *comment,
    صحيح format, ثابت حرف *openssh_format_cipher, صحيح openssh_format_rounds)
{
	بدل (مفتاح->type) {
#ifdef WITH_OPENSSL
	حالة مفتاح_ECDSA:
	حالة مفتاح_RSA:
	حالة مفتاح_ED25519:
		اكسر; /* see below */
#وإلا /* WITH_OPENSSL */
	حالة مفتاح_ED25519:
#endif /* WITH_OPENSSL */
	حالة مفتاح_ED25519_SK:
#ifdef WITH_OPENSSL
	حالة مفتاح_ECDSA_SK:
#endif /* WITH_OPENSSL */
	حالة مفتاح_MLDSA44_ED25519:
		إرجاع sshkey_private_to_blob2(مفتاح, blob, passphrase,
		    comment, openssh_format_cipher, openssh_format_rounds);
	افتراضي:
		إرجاع SSH_ERR_مفتاح_TYPE_UNKNOWN;
	}

#ifdef WITH_OPENSSL
	بدل (format) {
	حالة SSHKEY_PRIVATE_OPENSSH:
		إرجاع sshkey_private_to_blob2(مفتاح, blob, passphrase,
		    comment, openssh_format_cipher, openssh_format_rounds);
	حالة SSHKEY_PRIVATE_PEM:
	حالة SSHKEY_PRIVATE_PKCS8:
		إرجاع sshkey_private_to_blob_pem_pkcs8(مفتاح, blob,
		    format, passphrase, comment);
	افتراضي:
		إرجاع SSH_ERR_INVALID_ARGUMENT;
	}
#endif /* WITH_OPENSSL */
}

#ifdef WITH_OPENSSL
ساكن صحيح
translate_libcrypto_error(unsigned long pem_err)
{
	صحيح pem_reason = ERR_GET_REASON(pem_err);

	بدل (ERR_GET_LIB(pem_err)) {
	حالة ERR_LIB_PEM:
		بدل (pem_reason) {
		حالة PEM_R_BAD_PASSWORD_READ:
#ifdef PEM_R_PROBLEMS_GETTING_PASSWORD
		حالة PEM_R_PROBLEMS_GETTING_PASSWORD:
#endif
#ifdef PEM_R_BAD_DECRYPT
		حالة PEM_R_BAD_DECRYPT:
#endif
			إرجاع SSH_ERR_مفتاح_WRONG_PASSPHRASE;
		افتراضي:
			إرجاع SSH_ERR_INVALID_FORMAT;
		}
	حالة ERR_LIB_EVP:
		بدل (pem_reason) {
#ifdef EVP_R_BAD_DECRYPT
		حالة EVP_R_BAD_DECRYPT:
			إرجاع SSH_ERR_مفتاح_WRONG_PASSPHRASE;
#endif
#ifdef EVP_R_BN_DECODE_ERROR
		حالة EVP_R_BN_DECODE_ERROR:
#endif
		حالة EVP_R_DECODE_ERROR:
#ifdef EVP_R_PRIVATE_مفتاح_DECODE_ERROR
		حالة EVP_R_PRIVATE_مفتاح_DECODE_ERROR:
#endif
			إرجاع SSH_ERR_INVALID_FORMAT;
		افتراضي:
			إرجاع SSH_ERR_LIBCRYPTO_ERROR;
		}
	حالة ERR_LIB_ASN1:
#ifdef ERR_LIB_OSSL_DECODER
	حالة ERR_LIB_OSSL_DECODER:
#endif
		إرجاع SSH_ERR_INVALID_FORMAT;
	}
	إرجاع SSH_ERR_LIBCRYPTO_ERROR;
}

ساكن فراغ
clear_libcrypto_errors(فراغ)
{
	بينما (ERR_get_error() != 0)
		;
}

/*
 * Translate OpenSSL error codes to determine whether
 * passphrase is required/incorrect.
 */
ساكن صحيح
convert_libcrypto_error(فراغ)
{
	/*
	 * Some password errors are reported at the beginning
	 * of the error queue.
	 */
	إذا (translate_libcrypto_error(ERR_peek_error()) ==
	    SSH_ERR_مفتاح_WRONG_PASSPHRASE)
		إرجاع SSH_ERR_مفتاح_WRONG_PASSPHRASE;
	إرجاع translate_libcrypto_error(ERR_peek_last_error());
}

ساكن صحيح
pem_passphrase_cb(حرف *buf, صحيح size, صحيح rwflag, فراغ *u)
{
	حرف *p = (حرف *)u;
	size_t len;

	إذا (p == عدم || (len = strlen(p)) == 0)
		إرجاع -1;
	إذا (size < 0 || len > (size_t)size)
		إرجاع -1;
	memcpy(buf, p, len);
	إرجاع (صحيح)len;
}

ساكن صحيح
sshkey_parse_private_pem_fileblob(بنية sshbuf *blob, صحيح type,
    ثابت حرف *passphrase, بنية sshkey **keyp)
{
	EVP_PKEY *pk = عدم;
	بنية sshkey *prv = عدم;
	BIO *bio = عدم;
	صحيح r;
	RSA *rsa = عدم;
	EC_مفتاح *ecdsa = عدم;

	إذا (keyp != عدم)
		*keyp = عدم;

	إذا ((bio = BIO_new(BIO_s_mem())) == عدم || sshbuf_len(blob) > INT_MAX)
		إرجاع SSH_ERR_ALLOC_FAIL;
	إذا (BIO_write(bio, sshbuf_ptr(blob), sshbuf_len(blob)) !=
	    (صحيح)sshbuf_len(blob)) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}

	clear_libcrypto_errors();
	إذا ((pk = PEM_read_bio_Private_مفتاح(bio, عدم, pem_passphrase_cb,
	    (حرف *)passphrase)) == عدم) {
		/*
		 * libcrypto may return various ASN.1 errors when attempting
		 * to parse a key with an incorrect passphrase.
		 * Treat all format errors as "incorrect passphrase" if a
		 * passphrase was supplied.
		 */
		إذا (passphrase != عدم && *passphrase != '\0')
			r = SSH_ERR_مفتاح_WRONG_PASSPHRASE;
		وإلا
			r = convert_libcrypto_error();
		اذهب out;
	}
	إذا (EVP_PKEY_base_id(pk) == EVP_PKEY_RSA &&
	    (type == مفتاح_UNSPEC || type == مفتاح_RSA)) {
		إذا ((prv = sshkey_new(مفتاح_UNSPEC)) == عدم) {
			r = SSH_ERR_ALLOC_FAIL;
			اذهب out;
		}
		إذا ((rsa = EVP_PKEY_get1_RSA(pk)) == عدم) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			اذهب out;
		}
		prv->type = مفتاح_RSA;
#ifdef DEBUG_PK
		RSA_print_fp(stderr, rsa, 8);
#endif
		إذا (RSA_blinding_on(rsa, عدم) != 1 ||
		    EVP_PKEY_set1_RSA(pk, rsa) != 1) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			اذهب out;
		}
		EVP_PKEY_up_ref(pk);
		prv->pkey = pk;
		إذا ((r = sshkey_check_rsa_length(prv, 0)) != 0)
			اذهب out;
	} وإلا إذا (EVP_PKEY_base_id(pk) == EVP_PKEY_EC &&
	    (type == مفتاح_UNSPEC || type == مفتاح_ECDSA)) {
		إذا ((prv = sshkey_new(مفتاح_UNSPEC)) == عدم) {
			r = SSH_ERR_ALLOC_FAIL;
			اذهب out;
		}
		إذا ((prv->ecdsa_nid = sshkey_ecdsa_fixup_group(pk)) == -1 ||
		    (ecdsa = EVP_PKEY_get1_EC_مفتاح(pk)) == عدم) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			اذهب out;
		}
		prv->type = مفتاح_ECDSA;
		إذا (sshkey_curve_nid_to_name(prv->ecdsa_nid) == عدم ||
		    sshkey_ec_validate_public(EC_مفتاح_get0_group(ecdsa),
		    EC_مفتاح_get0_public_مفتاح(ecdsa)) != 0 ||
		    sshkey_ec_validate_private(ecdsa) != 0) {
			r = SSH_ERR_INVALID_FORMAT;
			اذهب out;
		}
		EVP_PKEY_up_ref(pk);
		prv->pkey = pk;
#ifdef DEBUG_PK
		إذا (prv != عدم && prv->pkey != عدم)
			sshkey_dump_ec_مفتاح(EVP_PKEY_get0_EC_مفتاح(prv->pkey));
#endif
#ifdef OPENSSL_HAS_ED25519
	} وإلا إذا (EVP_PKEY_base_id(pk) == EVP_PKEY_ED25519 &&
	    (type == مفتاح_UNSPEC || type == مفتاح_ED25519)) {
		size_t len;

		إذا ((prv = sshkey_new(مفتاح_UNSPEC)) == عدم ||
		    (prv->ed25519_sk = calloc(1, ED25519_SK_SZ)) == عدم ||
		    (prv->ed25519_pk = calloc(1, ED25519_PK_SZ)) == عدم) {
			r = SSH_ERR_ALLOC_FAIL;
			اذهب out;
		}
		prv->type = مفتاح_ED25519;
		len = ED25519_PK_SZ;
		إذا (!EVP_PKEY_get_raw_public_مفتاح(pk, prv->ed25519_pk, &len)) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			اذهب out;
		}
		إذا (len != ED25519_PK_SZ) {
			r = SSH_ERR_INVALID_FORMAT;
			اذهب out;
		}
		len = ED25519_SK_SZ - ED25519_PK_SZ;
		إذا (!EVP_PKEY_get_raw_private_مفتاح(pk, prv->ed25519_sk, &len)) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			اذهب out;
		}
		إذا (len != ED25519_SK_SZ - ED25519_PK_SZ) {
			r = SSH_ERR_INVALID_FORMAT;
			اذهب out;
		}
		/* Append the public key to our private key */
		memcpy(prv->ed25519_sk + (ED25519_SK_SZ - ED25519_PK_SZ),
		    prv->ed25519_pk, ED25519_PK_SZ);
#ifdef DEBUG_PK
		sshbuf_dump_data(prv->ed25519_sk, ED25519_SK_SZ, stderr);
#endif
#endif /* OPENSSL_HAS_ED25519 */
	} وإلا {
		r = SSH_ERR_INVALID_FORMAT;
		اذهب out;
	}
	r = 0;
	إذا (keyp != عدم) {
		*keyp = prv;
		prv = عدم;
	}
 out:
	BIO_free(bio);
	EVP_PKEY_free(pk);
	RSA_free(rsa);
	EC_مفتاح_free(ecdsa);
	sshkey_free(prv);
	إرجاع r;
}
#endif /* WITH_OPENSSL */

صحيح
sshkey_parse_private_fileblob_type(بنية sshbuf *blob, صحيح type,
    ثابت حرف *passphrase, بنية sshkey **keyp, حرف **commentp)
{
	صحيح r = SSH_ERR_INTERNAL_ERROR;

	إذا (keyp != عدم)
		*keyp = عدم;
	إذا (commentp != عدم)
		*commentp = عدم;

	r = sshkey_parse_private2(blob, type, passphrase, keyp, commentp);
	/* Only fallback to PEM parser if a format error occurred. */
	إذا (r != SSH_ERR_INVALID_FORMAT)
		إرجاع r;
#ifdef WITH_OPENSSL
	إرجاع sshkey_parse_private_pem_fileblob(blob, type,
	    passphrase, keyp);
#وإلا
	إرجاع SSH_ERR_INVALID_FORMAT;
#endif /* WITH_OPENSSL */
}

صحيح
sshkey_parse_private_fileblob(بنية sshbuf *buffer, ثابت حرف *passphrase,
    بنية sshkey **keyp, حرف **commentp)
{
	إذا (keyp != عدم)
		*keyp = عدم;
	إذا (commentp != عدم)
		*commentp = عدم;

	إرجاع sshkey_parse_private_fileblob_type(buffer, مفتاح_UNSPEC,
	    passphrase, keyp, commentp);
}

فراغ
sshkey_sig_details_free(بنية sshkey_sig_details *details)
{
	freezero(details, حجم(*details));
}

صحيح
sshkey_parse_pubkey_from_private_fileblob_type(بنية sshbuf *blob, صحيح type,
    بنية sshkey **pubkeyp)
{
	صحيح r = SSH_ERR_INTERNAL_ERROR;

	إذا (pubkeyp != عدم)
		*pubkeyp = عدم;
	/* only new-format private keys bundle a public key inside */
	إذا ((r = sshkey_parse_private2_pubkey(blob, type, pubkeyp)) != 0)
		إرجاع r;
	إرجاع 0;
}
