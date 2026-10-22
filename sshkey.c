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

	עבור (i = 0; keyimpls[i] != عدم; i++) {
		אם (keyimpls[i]->type == type)
			החזר keyimpls[i];
	}
	החזר عدم;
}

ساكن ثابت بنية sshkey_impl *
sshkey_impl_from_type_nid(صحيح type, صحيح nid)
{
	صحيح i;

	עבור (i = 0; keyimpls[i] != عدم; i++) {
		אם (keyimpls[i]->type == type &&
		    (keyimpls[i]->nid == 0 || keyimpls[i]->nid == nid))
			החזר keyimpls[i];
	}
	החזר عدم;
}

ساكن ثابت بنية sshkey_impl *
sshkey_impl_from_key(ثابت بنية sshkey *k)
{
	אם (k == عدم)
		החזר عدم;
	החזר sshkey_impl_from_type_nid(k->type, k->ecdsa_nid);
}

ثابت حرف *
sshkey_type(ثابت بنية sshkey *k)
{
	ثابت بنية sshkey_impl *impl;

	אם ((impl = sshkey_impl_from_key(k)) == عدم)
		החזר "unknown";
	החזר impl->shortname;
}

ساكن ثابت حرف *
sshkey_ssh_name_from_type_nid(صحيح type, صحيح nid)
{
	ثابت بنية sshkey_impl *impl;

	אם ((impl = sshkey_impl_from_type_nid(type, nid)) == عدم)
		החזר "ssh-unknown";
	החזר impl->name;
}

صحيح
sshkey_type_is_cert(صحيح type)
{
	ثابت بنية sshkey_impl *impl;

	אם ((impl = sshkey_impl_from_type(type)) == عدم)
		החזר 0;
	החזר impl->cert;
}

ثابت حرف *
sshkey_ssh_name(ثابت بنية sshkey *k)
{
	החזר sshkey_ssh_name_from_type_nid(k->type, k->ecdsa_nid);
}

ثابت حرف *
sshkey_ssh_name_plain(ثابت بنية sshkey *k)
{
	החזר sshkey_ssh_name_from_type_nid(sshkey_type_plain(k->type),
	    k->ecdsa_nid);
}

ساكن صحيح
type_from_name(ثابت حرف *name, صحيح allow_short)
{
	صحيح i;
	ثابت بنية sshkey_impl *impl;

	עבור (i = 0; keyimpls[i] != عدم; i++) {
		impl = keyimpls[i];
		אם (impl->name != عدم && strcmp(name, impl->name) == 0)
			החזר impl->type;
		/* Only allow shortname matches for plain key types */
		אם (allow_short && !impl->cert && impl->shortname != عدم &&
		    strcasecmp(impl->shortname, name) == 0)
			החזר impl->type;
	}
	החזר KEY_UNSPEC;
}

صحيح
sshkey_type_from_name(ثابت حرف *name)
{
	החזר type_from_name(name, 0);
}

صحيح
sshkey_type_from_shortname(ثابت حرف *name)
{
	החזר type_from_name(name, 1);
}

ساكن صحيح
key_type_is_ecdsa_variant(صحيح type)
{
	بدل (type) {
	حالة KEY_ECDSA:
	حالة KEY_ECDSA_CERT:
	حالة KEY_ECDSA_SK:
	حالة KEY_ECDSA_SK_CERT:
		החזר 1;
	}
	החזר 0;
}

صحيح
sshkey_ecdsa_nid_from_name(ثابت حرف *name)
{
	صحيح i;

	עבור (i = 0; keyimpls[i] != عدم; i++) {
		אם (!key_type_is_ecdsa_variant(keyimpls[i]->type))
			استمر;
		אם (keyimpls[i]->name != عدم &&
		    strcmp(name, keyimpls[i]->name) == 0)
			החזר keyimpls[i]->nid;
	}
	החזר -1;
}

صحيح
sshkey_match_keyname_to_sigalgs(ثابت حرف *keyname, ثابت حرف *sigalgs)
{
	صحيح ktype;

	אם (sigalgs == عدم || *sigalgs == '\0' ||
	    (ktype = sshkey_type_from_name(keyname)) == KEY_UNSPEC)
		החזר 0;
	אחרת אם (ktype == KEY_RSA) {
		החזר match_pattern_list("ssh-rsa", sigalgs, 0) == 1 ||
		    match_pattern_list("rsa-sha2-256", sigalgs, 0) == 1 ||
		    match_pattern_list("rsa-sha2-512", sigalgs, 0) == 1;
	} אחרת אם (ktype == KEY_RSA_CERT) {
		החזר match_pattern_list("ssh-rsa-cert-v01@openssh.com",
		    sigalgs, 0) == 1 ||
		    match_pattern_list("rsa-sha2-256-cert-v01@openssh.com",
		    sigalgs, 0) == 1 ||
		    match_pattern_list("rsa-sha2-512-cert-v01@openssh.com",
		    sigalgs, 0) == 1;
	} אחרת אם (ktype == KEY_ECDSA_SK) {
		החזר match_pattern_list("sk-ecdsa-sha2-nistp256@openssh.com",
		    sigalgs, 0) == 1 || match_pattern_list(
		    "webauthn-sk-ecdsa-sha2-nistp256@openssh.com",
		    sigalgs, 0) == 1;
	} אחרת אם (ktype == KEY_ECDSA_SK_CERT) {
		החזר match_pattern_list(
		    "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
		    sigalgs, 0) == 1 || match_pattern_list(
		    "webauthn-sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
		    sigalgs, 0) == 1;
	} אחרת
		החזר match_pattern_list(keyname, sigalgs, 0) == 1;
}

حرف *
sshkey_alg_list(صحيح certs_only, صحيح plain_only, صحيح include_sigonly, حرف sep)
{
	حرف *ret = عدم;
	size_t i;
	ثابت بنية sshkey_impl *impl;
	حرف sep_str[2] = {sep, '\0'};

	עבור (i = 0; keyimpls[i] != عدم; i++) {
		impl = keyimpls[i];
		אם (impl->name == عدم)
			استمر;
		אם (!include_sigonly && impl->sigonly)
			استمر;
		אם ((certs_only && !impl->cert) || (plain_only && impl->cert))
			استمر;
		xextendf(&ret, sep_str, "%s", impl->name);
	}
	החזר ret;
}

صحيح
sshkey_names_valid2(ثابت حرف *names, صحيح allow_wildcard, صحيح plain_only)
{
	حرف *s, *cp, *p;
	ثابت بنية sshkey_impl *impl;
	صحيح i, type;

	אם (names == عدم || strcmp(names, "") == 0)
		החזר 0;
	אם ((s = cp = strdup(names)) == عدم)
		החזר 0;
	עבור ((p = strsep(&cp, ",")); p && *p != '\0';
	    (p = strsep(&cp, ","))) {
		type = sshkey_type_from_name(p);
		אם (type == KEY_UNSPEC) {
			אם (allow_wildcard) {
				/*
				 * Try matching key types against the string.
				 * If any has a positive or negative match then
				 * the component is accepted.
				 */
				impl = عدم;
				עבור (i = 0; keyimpls[i] != عدم; i++) {
					אם (match_pattern_list(
					    keyimpls[i]->name, p, 0) != 0) {
						impl = keyimpls[i];
						اكسر;
					}
				}
				אם (impl != عدم)
					استمر;
			}
			حرر(s);
			החזר 0;
		} אחרת אם (plain_only && sshkey_type_is_cert(type)) {
			حرر(s);
			החזר 0;
		}
	}
	حرر(s);
	החזר 1;
}

u_int
sshkey_size(ثابت بنية sshkey *k)
{
	ثابت بنية sshkey_impl *impl;

	אם ((impl = sshkey_impl_from_key(k)) == عدم)
		החזר 0;
	אם (impl->funcs->size != عدم)
		החזר impl->funcs->size(k);
	החזר impl->keybits;
}

ساكن صحيح
sshkey_type_is_valid_ca(صحيح type)
{
	ثابت بنية sshkey_impl *impl;

	אם ((impl = sshkey_impl_from_type(type)) == عدم)
		החזר 0;
	/* All non-certificate types may act as CAs */
	החזר !impl->cert;
}

صحيح
sshkey_is_cert(ثابت بنية sshkey *k)
{
	אם (k == عدم)
		החזר 0;
	החזר sshkey_type_is_cert(k->type);
}

صحيح
sshkey_is_sk(ثابت بنية sshkey *k)
{
	אם (k == عدم)
		החזר 0;
	بدل (sshkey_type_plain(k->type)) {
	حالة KEY_ECDSA_SK:
	حالة KEY_ED25519_SK:
		החזר 1;
	افتراضي:
		החזר 0;
	}
}

/* Return the cert-less equivalent to a certified key type */
صحيح
sshkey_type_plain(صحيح type)
{
	بدل (type) {
	حالة KEY_RSA_CERT:
		החזר KEY_RSA;
	حالة KEY_ECDSA_CERT:
		החזר KEY_ECDSA;
	حالة KEY_ECDSA_SK_CERT:
		החזר KEY_ECDSA_SK;
	حالة KEY_ED25519_CERT:
		החזר KEY_ED25519;
	حالة KEY_MLDSA44_ED25519_CERT:
		החזר KEY_MLDSA44_ED25519;
	حالة KEY_ED25519_SK_CERT:
		החזר KEY_ED25519_SK;
	افتراضي:
		החזר type;
	}
}

/* Return the cert equivalent to a plain key type */
ساكن صحيح
sshkey_type_certified(صحيح type)
{
	بدل (type) {
	حالة KEY_RSA:
		החזר KEY_RSA_CERT;
	حالة KEY_ECDSA:
		החזר KEY_ECDSA_CERT;
	حالة KEY_ECDSA_SK:
		החזר KEY_ECDSA_SK_CERT;
	حالة KEY_ED25519:
		החזר KEY_ED25519_CERT;
	حالة KEY_MLDSA44_ED25519:
		החזר KEY_MLDSA44_ED25519_CERT;
	حالة KEY_ED25519_SK:
		החזר KEY_ED25519_SK_CERT;
	افتراضي:
		החזר -1;
	}
}

#ifdef WITH_OPENSSL
ساكن ثابت EVP_MD *
ssh_digest_to_md(صحيح hash_alg)
{
	بدل (hash_alg) {
	حالة SSH_DIGEST_SHA1:
		החזר EVP_sha1();
	حالة SSH_DIGEST_SHA256:
		החזר EVP_sha256();
	حالة SSH_DIGEST_SHA384:
		החזר EVP_sha384();
	حالة SSH_DIGEST_SHA512:
		החזר EVP_sha512();
	}
	החזר عدم;
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
	אם (slen <= 0 || slen > SSHBUF_MAX_BIGNUM ||
	   (evpmd = ssh_digest_to_md(hash_alg)) == عدم)
		החזר SSH_ERR_INVALID_ARGUMENT;

	אם ((sig = malloc(slen)) == عدم)
		החזר SSH_ERR_ALLOC_FAIL;

	אם ((ctx = EVP_MD_CTX_new()) == عدم) {
		ret = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}
	אם (EVP_DigestSignInit(ctx, عدم, evpmd, عدم, pkey) != 1 ||
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
	החזר ret;
}

صحيح
sshkey_pkey_digest_verify(EVP_PKEY *pkey, صحيح hash_alg, ثابت u_char *data,
    size_t datalen, u_char *sigbuf, size_t siglen)
{
	EVP_MD_CTX *ctx = عدم;
	صحيح ret = SSH_ERR_INTERNAL_ERROR;
	ثابت EVP_MD *evpmd;

	אם ((evpmd = ssh_digest_to_md(hash_alg)) == عدم)
		החזר SSH_ERR_INVALID_ARGUMENT;
	אם ((ctx = EVP_MD_CTX_new()) == عدم)
		החזר SSH_ERR_ALLOC_FAIL;
	אם (EVP_DigestVerifyInit(ctx, عدم, evpmd, عدم, pkey) != 1) {
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
	החזר ret;
}

/* XXX: these are really begging for a table-driven approach */
صحيح
sshkey_curve_name_to_nid(ثابت حرف *name)
{
	אם (strcmp(name, "nistp256") == 0)
		החזר NID_X9_62_prime256v1;
	אחרת אם (strcmp(name, "nistp384") == 0)
		החזר NID_secp384r1;
	אחרת אם (strcmp(name, "nistp521") == 0)
		החזר NID_secp521r1;
	אחרת
		החזר -1;
}

u_int
sshkey_curve_nid_to_bits(صحيح nid)
{
	بدل (nid) {
	حالة NID_X9_62_prime256v1:
		החזר 256;
	حالة NID_secp384r1:
		החזר 384;
	حالة NID_secp521r1:
		החזר 521;
	افتراضي:
		החזר 0;
	}
}

صحيح
sshkey_ecdsa_bits_to_nid(صحيح bits)
{
	بدل (bits) {
	حالة 256:
		החזר NID_X9_62_prime256v1;
	حالة 384:
		החזר NID_secp384r1;
	حالة 521:
		החזר NID_secp521r1;
	افتراضي:
		החזר -1;
	}
}

ثابت حرف *
sshkey_curve_nid_to_name(صحيح nid)
{
	بدل (nid) {
	حالة NID_X9_62_prime256v1:
		החזר "nistp256";
	حالة NID_secp384r1:
		החזר "nistp384";
	حالة NID_secp521r1:
		החזר "nistp521";
	افتراضي:
		החזר عدم;
	}
}

صحيح
sshkey_ec_nid_to_hash_alg(صحيح nid)
{
	صحيح kbits = sshkey_curve_nid_to_bits(nid);

	אם (kbits <= 0)
		החזר -1;

	/* RFC5656 section 6.2.1 */
	אם (kbits <= 256)
		החזר SSH_DIGEST_SHA256;
	אחרת אם (kbits <= 384)
		החזר SSH_DIGEST_SHA384;
	אחרת
		החזר SSH_DIGEST_SHA512;
}
#endif /* WITH_OPENSSL */

ساكن فراغ
cert_free(بنية sshkey_cert *cert)
{
	u_int i;

	אם (cert == عدم)
		החזר;
	sshbuf_free(cert->certblob);
	sshbuf_free(cert->critical);
	sshbuf_free(cert->extensions);
	حرر(cert->key_id);
	עבור (i = 0; i < cert->nprincipals; i++)
		حرر(cert->principals[i]);
	حرر(cert->principals);
	sshkey_free(cert->signature_key);
	حرر(cert->signature_type);
	freezero(cert, حجم(*cert));
}

ساكن بنية sshkey_cert *
cert_new(فراغ)
{
	بنية sshkey_cert *cert;

	אם ((cert = calloc(1, حجم(*cert))) == عدم)
		החזר عدم;
	אם ((cert->certblob = sshbuf_new()) == عدم ||
	    (cert->critical = sshbuf_new()) == عدم ||
	    (cert->extensions = sshbuf_new()) == عدم) {
		cert_free(cert);
		החזר عدم;
	}
	cert->key_id = عدم;
	cert->principals = عدم;
	cert->signature_key = عدم;
	cert->signature_type = عدم;
	החזר cert;
}

بنية sshkey *
sshkey_new(صحيح type)
{
	بنية sshkey *k;
	ثابت بنية sshkey_impl *impl = عدم;

	אם (type != KEY_UNSPEC &&
	    (impl = sshkey_impl_from_type(type)) == عدم)
		החזר عدم;

	/* All non-certificate types may act as CAs */
	אם ((k = calloc(1, حجم(*k))) == عدم)
		החזר عدم;
	k->type = type;
	k->ecdsa_nid = -1;
	אם (impl != عدم && impl->funcs->alloc != عدم) {
		אם (impl->funcs->alloc(k) != 0) {
			حرر(k);
			החזר عدم;
		}
	}
	אם (sshkey_is_cert(k)) {
		אם ((k->cert = cert_new()) == عدم) {
			sshkey_free(k);
			החזר عدم;
		}
	}

	החזר k;
}

/* Frees common FIDO fields */
فراغ
sshkey_sk_cleanup(بنية sshkey *k)
{
	حرر(k->sk_application);
	sshbuf_free(k->sk_key_handle);
	sshbuf_free(k->sk_reserved);
	k->sk_application = عدم;
	k->sk_key_handle = k->sk_reserved = عدم;
}

#אם defined(MAP_CONCEAL)
# define PREKEY_MMAP_FLAG	MAP_CONCEAL
#وإلاإذا defined(MAP_NOCORE)
# define PREKEY_MMAP_FLAG	MAP_NOCORE
#אחרת
# define PREKEY_MMAP_FLAG	0
#endif

ساكن صحيح
sshkey_prekey_alloc(u_char **prekeyp, size_t len)
{
#אם defined(HAVE_MMAP) && defined(MAP_ANON) && defined(MAP_PRIVATE)
	u_char *prekey;

	*prekeyp = عدم;
	אם ((prekey = mmap(عدم, len, PROT_READ|PROT_WRITE,
	    MAP_ANON|MAP_PRIVATE|PREKEY_MMAP_FLAG, -1, 0)) == MAP_FAILED)
		החזר SSH_ERR_SYSTEM_ERROR;
#אם defined(MADV_DONTDUMP) && !defined(MAP_CONCEAL) && !defined(MAP_NOCORE)
	(فراغ)madvise(prekey, len, MADV_DONTDUMP);
#endif
	*prekeyp = prekey;
#אחרת
	*prekeyp = calloc(1, len);
#endif /* HAVE_MMAP et al */
	החזר 0;
}

ساكن فراغ
sshkey_prekey_free(فراغ *prekey, size_t len)
{
#אם defined(HAVE_MMAP) && defined(MAP_ANON) && defined(MAP_PRIVATE)
	אם (prekey == عدم)
		החזר;
	munmap(prekey, len);
#אחרת
	حرر(prekey);
#endif /* HAVE_MMAP et al */
}

ساكن فراغ
sshkey_free_contents(بنية sshkey *k)
{
	ثابت بنية sshkey_impl *impl;

	אם (k == عدم)
		החזר;
	אם ((k->flags & SSHKEY_FLAG_EXT) != 0)
		pkcs11_key_free(k);
	אם ((impl = sshkey_impl_from_type(k->type)) != عدم &&
	    impl->funcs->cleanup != عدم)
		impl->funcs->cleanup(k);
	אם (sshkey_is_cert(k))
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
	אם (a == عدم && b == عدم)
		החזר 1;
	אם (a == عدم || b == عدم)
		החזר 0;
	אם (sshbuf_len(a->certblob) != sshbuf_len(b->certblob))
		החזר 0;
	אם (timingsafe_bcmp(sshbuf_ptr(a->certblob), sshbuf_ptr(b->certblob),
	    sshbuf_len(a->certblob)) != 0)
		החזר 0;
	החזר 1;
}

/* Compares FIDO-specific pubkey fields only */
صحيح
sshkey_sk_fields_equal(ثابت بنية sshkey *a, ثابت بنية sshkey *b)
{
	אם (a->sk_application == عدم || b->sk_application == عدم)
		החזר 0;
	אם (strcmp(a->sk_application, b->sk_application) != 0)
		החזר 0;
	החזר 1;
}

/*
 * Compare public portions of key only, allowing comparisons between
 * certificates and plain keys too.
 */
صحيح
sshkey_equal_public(ثابت بنية sshkey *a, ثابت بنية sshkey *b)
{
	ثابت بنية sshkey_impl *impl;

	אם (a == عدم || b == عدم ||
	    sshkey_type_plain(a->type) != sshkey_type_plain(b->type))
		החזר 0;
	אם ((impl = sshkey_impl_from_type(a->type)) == عدم)
		החזר 0;
	החזר impl->funcs->equal(a, b);
}

صحيح
sshkey_equal(ثابت بنية sshkey *a, ثابت بنية sshkey *b)
{
	אם (a == عدم || b == عدم || a->type != b->type)
		החזר 0;
	אם (sshkey_is_cert(a)) {
		אם (!cert_compare(a->cert, b->cert))
			החזר 0;
	}
	החזר sshkey_equal_public(a, b);
}


/* Serialise common FIDO key parts */
صحيح
sshkey_serialize_sk(ثابت بنية sshkey *key, بنية sshbuf *b)
{
	صحيح r;

	אם ((r = sshbuf_put_cstring(b, key->sk_application)) != 0)
		החזר r;

	החזר 0;
}

ساكن صحيح
to_blob_buf(ثابت بنية sshkey *key, بنية sshbuf *b, صحيح force_plain,
  تعداد sshkey_serialize_rep opts)
{
	صحيح type, ret = SSH_ERR_INTERNAL_ERROR;
	ثابت حرف *typename;
	ثابت بنية sshkey_impl *impl;

	אם (key == عدم)
		החזר SSH_ERR_INVALID_ARGUMENT;

	type = force_plain ? sshkey_type_plain(key->type) : key->type;

	אם (sshkey_type_is_cert(type)) {
		אם (key->cert == عدم)
			החזר SSH_ERR_EXPECTED_CERT;
		אם (sshbuf_len(key->cert->certblob) == 0)
			החזר SSH_ERR_KEY_LACKS_CERTBLOB;
		/* Use the existing blob */
		אם ((ret = sshbuf_putb(b, key->cert->certblob)) != 0)
			החזר ret;
		החזר 0;
	}
	אם ((impl = sshkey_impl_from_type(type)) == عدم)
		החזר SSH_ERR_KEY_TYPE_UNKNOWN;

	typename = sshkey_ssh_name_from_type_nid(type, key->ecdsa_nid);
	אם ((ret = sshbuf_put_cstring(b, typename)) != 0)
		החזר ret;
	החזר impl->funcs->serialize_public(key, b, opts);
}

صحيح
sshkey_putb(ثابت بنية sshkey *key, بنية sshbuf *b)
{
	החזר to_blob_buf(key, b, 0, SSHKEY_SERIALIZE_DEFAULT);
}

ساكن صحيح
sshkey_puts_opts_internal(ثابت بنية sshkey *key, بنية sshbuf *b,
    تعداد sshkey_serialize_rep opts, صحيح force_plain)
{
	بنية sshbuf *tmp;
	صحيح r;

	אם ((tmp = sshbuf_new()) == عدم)
		החזר SSH_ERR_ALLOC_FAIL;
	r = to_blob_buf(key, tmp, force_plain, opts);
	אם (r == 0)
		r = sshbuf_put_stringb(b, tmp);
	sshbuf_free(tmp);
	החזר r;
}

صحيح
sshkey_puts(ثابت بنية sshkey *key, بنية sshbuf *b)
{
	החזר sshkey_puts_opts_internal(key, b, SSHKEY_SERIALIZE_DEFAULT, 0);
}

صحيح
sshkey_putb_plain(ثابت بنية sshkey *key, بنية sshbuf *b)
{
	החזר to_blob_buf(key, b, 1, SSHKEY_SERIALIZE_DEFAULT);
}

صحيح
sshkey_puts_plain(ثابت بنية sshkey *key, بنية sshbuf *b)
{
	החזר sshkey_puts_opts_internal(key, b, SSHKEY_SERIALIZE_DEFAULT, 1);
}

ساكن صحيح
to_blob(ثابت بنية sshkey *key, u_char **blobp, size_t *lenp, صحيح force_plain,
    تعداد sshkey_serialize_rep opts)
{
	صحيح ret = SSH_ERR_INTERNAL_ERROR;
	size_t len;
	بنية sshbuf *b = عدم;

	אם (lenp != عدم)
		*lenp = 0;
	אם (blobp != عدم)
		*blobp = عدم;
	אם ((b = sshbuf_new()) == عدم)
		החזר SSH_ERR_ALLOC_FAIL;
	אם ((ret = to_blob_buf(key, b, force_plain, opts)) != 0)
		اذهب out;
	len = sshbuf_len(b);
	אם (lenp != عدم)
		*lenp = len;
	אם (blobp != عدم) {
		אם ((*blobp = malloc(len)) == عدم) {
			ret = SSH_ERR_ALLOC_FAIL;
			اذهب out;
		}
		memcpy(*blobp, sshbuf_ptr(b), len);
	}
	ret = 0;
 out:
	sshbuf_free(b);
	החזר ret;
}

صحيح
sshkey_to_blob(ثابت بنية sshkey *key, u_char **blobp, size_t *lenp)
{
	החזר to_blob(key, blobp, lenp, 0, SSHKEY_SERIALIZE_DEFAULT);
}

صحيح
sshkey_plain_to_blob(ثابت بنية sshkey *key, u_char **blobp, size_t *lenp)
{
	החזר to_blob(key, blobp, lenp, 1, SSHKEY_SERIALIZE_DEFAULT);
}

صحيح
sshkey_fingerprint_raw(ثابت بنية sshkey *k, صحيح dgst_alg,
    u_char **retp, size_t *lenp)
{
	u_char *blob = عدم, *ret = عدم;
	size_t blob_len = 0;
	صحيح r = SSH_ERR_INTERNAL_ERROR;

	אם (retp != عدم)
		*retp = عدم;
	אם (lenp != عدم)
		*lenp = 0;
	אם (ssh_digest_bytes(dgst_alg) == 0) {
		r = SSH_ERR_INVALID_ARGUMENT;
		اذهب out;
	}
	אם ((r = to_blob(k, &blob, &blob_len, 1, SSHKEY_SERIALIZE_DEFAULT))
	    != 0)
		اذهب out;
	אם ((ret = calloc(1, SSH_DIGEST_MAX_LENGTH)) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}
	אם ((r = ssh_digest_memory(dgst_alg, blob, blob_len,
	    ret, SSH_DIGEST_MAX_LENGTH)) != 0)
		اذهب out;
	/* success */
	אם (retp != عدم) {
		*retp = ret;
		ret = عدم;
	}
	אם (lenp != عدم)
		*lenp = ssh_digest_bytes(dgst_alg);
	r = 0;
 out:
	حرر(ret);
	אם (blob != عدم)
		freezero(blob, blob_len);
	החזר r;
}

ساكن حرف *
fingerprint_b64(ثابت حرف *alg, u_char *dgst_raw, size_t dgst_raw_len)
{
	حرف *ret;
	size_t plen = strlen(alg) + 1;
	size_t rlen = ((dgst_raw_len + 2) / 3) * 4 + plen + 1;

	אם (dgst_raw_len > 65536 || (ret = calloc(1, rlen)) == عدم)
		החזר عدم;
	strlcpy(ret, alg, rlen);
	strlcat(ret, ":", rlen);
	אם (dgst_raw_len == 0)
		החזר ret;
	אם (b64_ntop(dgst_raw, dgst_raw_len, ret + plen, rlen - plen) == -1) {
		freezero(ret, rlen);
		החזר عدم;
	}
	/* Trim padding characters from end */
	ret[strcspn(ret, "=")] = '\0';
	החזר ret;
}

ساكن حرف *
fingerprint_hex(ثابت حرف *alg, u_char *dgst_raw, size_t dgst_raw_len)
{
	حرف *retval, hex[5];
	size_t i, rlen = dgst_raw_len * 3 + strlen(alg) + 2;

	אם (dgst_raw_len > 65536 || (retval = calloc(1, rlen)) == عدم)
		החזר عدم;
	strlcpy(retval, alg, rlen);
	strlcat(retval, ":", rlen);
	עבור (i = 0; i < dgst_raw_len; i++) {
		snprintf(hex, حجم(hex), "%s%02x",
		    i > 0 ? ":" : "", dgst_raw[i]);
		strlcat(retval, hex, rlen);
	}
	החזר retval;
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
	אם ((retval = calloc(rounds, 6)) == عدم)
		החזר عدم;
	retval[j++] = 'x';
	עבור (i = 0; i < rounds; i++) {
		u_int idx0, idx1, idx2, idx3, idx4;
		אם ((i + 1 < rounds) || (dgst_raw_len % 2 != 0)) {
			idx0 = (((((u_int)(dgst_raw[2 * i])) >> 6) & 3) +
			    seed) % 6;
			idx1 = (((u_int)(dgst_raw[2 * i])) >> 2) & 15;
			idx2 = ((((u_int)(dgst_raw[2 * i])) & 3) +
			    (seed / 6)) % 6;
			retval[j++] = vowels[idx0];
			retval[j++] = consonants[idx1];
			retval[j++] = vowels[idx2];
			אם ((i + 1) < rounds) {
				idx3 = (((u_int)(dgst_raw[(2 * i) + 1])) >> 4) & 15;
				idx4 = (((u_int)(dgst_raw[(2 * i) + 1]))) & 15;
				retval[j++] = consonants[idx3];
				retval[j++] = '-';
				retval[j++] = consonants[idx4];
				seed = ((seed * 5) +
				    ((((u_int)(dgst_raw[2 * i])) * 7) +
				    ((u_int)(dgst_raw[(2 * i) + 1])))) % 36;
			}
		} אחרת {
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
	החזר retval;
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

	אם ((retval = calloc((FLDSIZE_X + 3), (FLDSIZE_Y + 2))) == عدم)
		החזר عدم;

	/* initialize field */
	memset(field, 0, FLDSIZE_X * FLDSIZE_Y * حجم(حرف));
	x = FLDSIZE_X / 2;
	y = FLDSIZE_Y / 2;

	/* process raw key */
	עבור (i = 0; i < dgst_raw_len; i++) {
		صحيح input;
		/* each byte conveys four 2-bit move commands */
		input = dgst_raw[i];
		עבור (b = 0; b < 4; b++) {
			/* evaluate 2 bit, rest is shifted later */
			x += (input & 0x1) ? 1 : -1;
			y += (input & 0x2) ? 1 : -1;

			/* assure we are still in bounds */
			x = MAXIMUM(x, 0);
			y = MAXIMUM(y, 0);
			x = MINIMUM(x, FLDSIZE_X - 1);
			y = MINIMUM(y, FLDSIZE_Y - 1);

			/* augment the field */
			אם (field[x][y] < len - 2)
				field[x][y]++;
			input = input >> 2;
		}
	}

	/* mark starting point and end point*/
	field[FLDSIZE_X / 2][FLDSIZE_Y / 2] = len - 1;
	field[x][y] = len;

	/* assemble title */
	r = snprintf(title, حجم(title), "[%s %u]",
		sshkey_type(k), sshkey_size(k));
	/* If [type size] won't fit, then try [type]; fits "[ED25519-CERT]" */
	אם (r < 0 || r > (صحيح)حجم(title))
		r = snprintf(title, حجم(title), "[%s]", sshkey_type(k));
	tlen = (r <= 0) ? 0 : strlen(title);

	/* assemble hash ID. */
	r = snprintf(hash, حجم(hash), "[%s]", alg);
	hlen = (r <= 0) ? 0 : strlen(hash);

	/* output upper border */
	p = retval;
	*p++ = '+';
	עבור (i = 0; i < (FLDSIZE_X - tlen) / 2; i++)
		*p++ = '-';
	memcpy(p, title, tlen);
	p += tlen;
	עבור (i += tlen; i < FLDSIZE_X; i++)
		*p++ = '-';
	*p++ = '+';
	*p++ = '\n';

	/* output content */
	עבור (y = 0; y < FLDSIZE_Y; y++) {
		*p++ = '|';
		עבור (x = 0; x < FLDSIZE_X; x++)
			*p++ = augmentation_string[MINIMUM(field[x][y], len)];
		*p++ = '|';
		*p++ = '\n';
	}

	/* output lower border */
	*p++ = '+';
	עבור (i = 0; i < (FLDSIZE_X - hlen) / 2; i++)
		*p++ = '-';
	memcpy(p, hash, hlen);
	p += hlen;
	עבור (i += hlen; i < FLDSIZE_X; i++)
		*p++ = '-';
	*p++ = '+';

	החזר retval;
}

حرف *
sshkey_fingerprint(ثابت بنية sshkey *k, صحيح dgst_alg,
    تعداد sshkey_fp_rep dgst_rep)
{
	حرف *retval = عدم;
	u_char *dgst_raw;
	size_t dgst_raw_len;

	אם (sshkey_fingerprint_raw(k, dgst_alg, &dgst_raw, &dgst_raw_len) != 0)
		החזר عدم;
	بدل (dgst_rep) {
	حالة SSH_FP_DEFAULT:
		אם (dgst_alg == SSH_DIGEST_MD5) {
			retval = fingerprint_hex(ssh_digest_alg_name(dgst_alg),
			    dgst_raw, dgst_raw_len);
		} אחרת {
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
		החזר عدم;
	}
	freezero(dgst_raw, dgst_raw_len);
	החזר retval;
}

ساكن صحيح
peek_type_nid(ثابت حرف *s, size_t l, صحيح *nid)
{
	ثابت بنية sshkey_impl *impl;
	صحيح i;

	עבור (i = 0; keyimpls[i] != عدم; i++) {
		impl = keyimpls[i];
		אם (impl->name == عدم || strlen(impl->name) != l)
			استمر;
		אם (memcmp(s, impl->name, l) == 0) {
			*nid = -1;
			אם (key_type_is_ecdsa_variant(impl->type))
				*nid = impl->nid;
			החזר impl->type;
		}
	}
	החזר KEY_UNSPEC;
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

	אם (ret == عدم)
		החזר SSH_ERR_INVALID_ARGUMENT;
	אם (ret->type != KEY_UNSPEC && sshkey_impl_from_type(ret->type) == عدم)
		החזר SSH_ERR_INVALID_ARGUMENT;

	/* Decode type */
	cp = *cpp;
	space = strcspn(cp, " \t");
	אם (space == strlen(cp))
		החזר SSH_ERR_INVALID_FORMAT;
	אם ((type = peek_type_nid(cp, space, &curve_nid)) == KEY_UNSPEC)
		החזר SSH_ERR_INVALID_FORMAT;

	/* skip whitespace */
	עבור (cp += space; *cp == ' ' || *cp == '\t'; cp++)
		;
	אם (*cp == '\0')
		החזר SSH_ERR_INVALID_FORMAT;
	אם (ret->type != KEY_UNSPEC && ret->type != type)
		החזר SSH_ERR_KEY_TYPE_MISMATCH;
	אם ((blob = sshbuf_new()) == عدم)
		החזר SSH_ERR_ALLOC_FAIL;

	/* find end of keyblob and decode */
	space = strcspn(cp, " \t");
	אם ((blobcopy = strndup(cp, space)) == عدم) {
		sshbuf_free(blob);
		החזר SSH_ERR_ALLOC_FAIL;
	}
	אם ((r = sshbuf_b64tod(blob, blobcopy)) != 0) {
		حرر(blobcopy);
		sshbuf_free(blob);
		החזר r;
	}
	حرر(blobcopy);
	אם ((r = sshkey_fromb(blob, &k)) != 0) {
		sshbuf_free(blob);
		החזר r;
	}
	sshbuf_free(blob);

	/* skip whitespace and leave cp at start of comment */
	עבור (cp += space; *cp == ' ' || *cp == '\t'; cp++)
		;

	/* ensure type of blob matches type at start of line */
	אם (k->type != type) {
		sshkey_free(k);
		החזר SSH_ERR_KEY_TYPE_MISMATCH;
	}
	אם (key_type_is_ecdsa_variant(type) && curve_nid != k->ecdsa_nid) {
		sshkey_free(k);
		החזר SSH_ERR_EC_CURVE_MISMATCH;
	}

	/* Fill in ret from parsed key */
	sshkey_free_contents(ret);
	*ret = *k;
	freezero(k, حجم(*k));

	/* success */
	*cpp = cp;
	החזר 0;
}

صحيح
sshkey_to_base64(ثابت بنية sshkey *key, حرف **b64p)
{
	صحيح r = SSH_ERR_INTERNAL_ERROR;
	بنية sshbuf *b = عدم;
	حرف *uu = عدم;

	אם (b64p != عدم)
		*b64p = عدم;
	אם ((b = sshbuf_new()) == عدم)
		החזר SSH_ERR_ALLOC_FAIL;
	אם ((r = sshkey_putb(key, b)) != 0)
		اذهب out;
	אם ((uu = sshbuf_dtob64_string(b, 0)) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}
	/* Success */
	אם (b64p != عدم) {
		*b64p = uu;
		uu = عدم;
	}
	r = 0;
 out:
	sshbuf_free(b);
	حرر(uu);
	החזר r;
}

صحيح
sshkey_format_text(ثابت بنية sshkey *key, بنية sshbuf *b)
{
	صحيح r = SSH_ERR_INTERNAL_ERROR;
	حرف *uu = عدم;

	אם ((r = sshkey_to_base64(key, &uu)) != 0)
		اذهب out;
	אם ((r = sshbuf_putf(b, "%s %s",
	    sshkey_ssh_name(key), uu)) != 0)
		اذهب out;
	r = 0;
 out:
	حرر(uu);
	החזר r;
}

صحيح
sshkey_write(ثابت بنية sshkey *key, FILE *f)
{
	بنية sshbuf *b = عدم;
	صحيح r = SSH_ERR_INTERNAL_ERROR;

	אם ((b = sshbuf_new()) == عدم)
		החזר SSH_ERR_ALLOC_FAIL;
	אם ((r = sshkey_format_text(key, b)) != 0)
		اذهب out;
	אם (fwrite(sshbuf_ptr(b), sshbuf_len(b), 1, f) != 1) {
		אם (feof(f))
			errno = EPIPE;
		r = SSH_ERR_SYSTEM_ERROR;
		اذهب out;
	}
	/* Success */
	r = 0;
 out:
	sshbuf_free(b);
	החזר r;
}

ثابت حرف *
sshkey_cert_type(ثابت بنية sshkey *k)
{
	بدل (k->cert->type) {
	حالة SSH2_CERT_TYPE_USER:
		החזר "user";
	حالة SSH2_CERT_TYPE_HOST:
		החזר "host";
	افتراضي:
		החזר "unknown";
	}
}

صحيح
sshkey_check_rsa_length(ثابت بنية sshkey *k, صحيح min_size)
{
#ifdef WITH_OPENSSL
	صحيح nbits;

	אם (k == عدم || k->pkey == عدم ||
	    (k->type != KEY_RSA && k->type != KEY_RSA_CERT))
		החזר 0;
	nbits = EVP_PKEY_bits(k->pkey);
	אם (nbits < SSH_RSA_MINIMUM_MODULUS_SIZE ||
	    (min_size > 0 && nbits < min_size))
		החזר SSH_ERR_KEY_LENGTH;
#endif /* WITH_OPENSSL */
	החזר 0;
}

#ifdef WITH_OPENSSL
صحيح
sshkey_ecdsa_key_to_nid(ثابت EC_KEY *k)
{
	ثابت EC_GROUP *g;
	صحيح nid;

	אם (k == عدم || (g = EC_KEY_get0_group(k)) == عدم)
		החזר -1;
	אם ((nid = EC_GROUP_get_curve_name(g)) <= 0)
		החזר -1;
	החזר nid;
}

صحيح
sshkey_ecdsa_pkey_to_nid(EVP_PKEY *pkey)
{
	החזר sshkey_ecdsa_key_to_nid(EVP_PKEY_get0_EC_KEY(pkey));
}
#endif /* WITH_OPENSSL */

صحيح
sshkey_generate(صحيح type, u_int bits, بنية sshkey **keyp)
{
	بنية sshkey *k;
	صحيح ret = SSH_ERR_INTERNAL_ERROR;
	ثابت بنية sshkey_impl *impl;

	אם (keyp == عدم || sshkey_type_is_cert(type))
		החזר SSH_ERR_INVALID_ARGUMENT;
	*keyp = عدم;
	אם ((impl = sshkey_impl_from_type(type)) == عدم)
		החזר SSH_ERR_KEY_TYPE_UNKNOWN;
	אם (impl->funcs->generate == عدم)
		החזר SSH_ERR_FEATURE_UNSUPPORTED;
	אם ((k = sshkey_new(KEY_UNSPEC)) == عدم)
		החזר SSH_ERR_ALLOC_FAIL;
	k->type = type;
	אם ((ret = impl->funcs->generate(k, bits)) != 0) {
		sshkey_free(k);
		החזר ret;
	}
	/* success */
	*keyp = k;
	החזר 0;
}

صحيح
sshkey_cert_copy(ثابت بنية sshkey *from_key, بنية sshkey *to_key)
{
	u_int i;
	ثابت بنية sshkey_cert *from;
	بنية sshkey_cert *to;
	صحيح r = SSH_ERR_INTERNAL_ERROR;

	אם (to_key == عدم || (from = from_key->cert) == عدم)
		החזר SSH_ERR_INVALID_ARGUMENT;

	אם ((to = cert_new()) == عدم)
		החזר SSH_ERR_ALLOC_FAIL;

	אם ((r = sshbuf_putb(to->certblob, from->certblob)) != 0 ||
	    (r = sshbuf_putb(to->critical, from->critical)) != 0 ||
	    (r = sshbuf_putb(to->extensions, from->extensions)) != 0)
		اذهب out;

	to->serial = from->serial;
	to->type = from->type;
	אם (from->key_id == عدم)
		to->key_id = عدم;
	אחרת אם ((to->key_id = strdup(from->key_id)) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}
	to->valid_after = from->valid_after;
	to->valid_before = from->valid_before;
	אם (from->signature_key == عدم)
		to->signature_key = عدم;
	אחרת אם ((r = sshkey_from_private(from->signature_key,
	    &to->signature_key)) != 0)
		اذهب out;
	אם (from->signature_type != عدم &&
	    (to->signature_type = strdup(from->signature_type)) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}
	אם (from->nprincipals > SSHKEY_CERT_MAX_PRINCIPALS) {
		r = SSH_ERR_INVALID_ARGUMENT;
		اذهب out;
	}
	אם (from->nprincipals > 0) {
		אם ((to->principals = calloc(from->nprincipals,
		    حجم(*to->principals))) == عدم) {
			r = SSH_ERR_ALLOC_FAIL;
			اذهب out;
		}
		עבור (i = 0; i < from->nprincipals; i++) {
			to->principals[i] = strdup(from->principals[i]);
			אם (to->principals[i] == عدم) {
				to->nprincipals = i;
				r = SSH_ERR_ALLOC_FAIL;
				اذهب out;
			}
		}
	}
	to->nprincipals = from->nprincipals;

	/* success */
	cert_free(to_key->cert);
	to_key->cert = to;
	to = عدم;
	r = 0;
 out:
	cert_free(to);
	החזר r;
}

صحيح
sshkey_copy_public_sk(ثابت بنية sshkey *from, بنية sshkey *to)
{
	/* Append security-key application string */
	אם ((to->sk_application = strdup(from->sk_application)) == عدم)
		החזר SSH_ERR_ALLOC_FAIL;
	החזר 0;
}

صحيح
sshkey_from_private(ثابت بنية sshkey *k, بنية sshkey **pkp)
{
	بنية sshkey *n = عدم;
	صحيح r = SSH_ERR_INTERNAL_ERROR;
	ثابت بنية sshkey_impl *impl;

	*pkp = عدم;
	אם ((impl = sshkey_impl_from_key(k)) == عدم)
		החזר SSH_ERR_KEY_TYPE_UNKNOWN;
	אם ((n = sshkey_new(k->type)) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}
	אם ((r = impl->funcs->copy_public(k, n)) != 0)
		اذهب out;
	אם (sshkey_is_cert(k) && (r = sshkey_cert_copy(k, n)) != 0)
		اذهب out;
	/* success */
	*pkp = n;
	n = عدم;
	r = 0;
 out:
	sshkey_free(n);
	החזר r;
}

صحيح
sshkey_is_shielded(بنية sshkey *k)
{
	החזר k != عدم && k->shielded_private != عدم;
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
	אם ((cipher = cipher_by_name(SSHKEY_SHIELD_CIPHER)) == عدم) {
		r = SSH_ERR_INVALID_ARGUMENT;
		اذهب out;
	}
	אם (cipher_keylen(cipher) + cipher_ivlen(cipher) >
	    ssh_digest_bytes(SSHKEY_SHIELD_PREKEY_HASH)) {
		r = SSH_ERR_INTERNAL_ERROR;
		اذهب out;
	}

	/* Prepare a random pre-key, and from it an ephemeral key */
	אם ((r = sshkey_prekey_alloc(&prekey, SSHKEY_SHIELD_PREKEY_LEN)) != 0)
		اذهب out;
	arc4random_buf(prekey, SSHKEY_SHIELD_PREKEY_LEN);
	אם ((r = ssh_digest_memory(SSHKEY_SHIELD_PREKEY_HASH,
	    prekey, SSHKEY_SHIELD_PREKEY_LEN,
	    keyiv, SSH_DIGEST_MAX_LENGTH)) != 0)
		اذهب out;
#ifdef DEBUG_PK
	fprintf(stderr, "%s: key+iv\n", __func__);
	sshbuf_dump_data(keyiv, ssh_digest_bytes(SSHKEY_SHIELD_PREKEY_HASH),
	    stderr);
#endif
	אם ((r = cipher_init(&cctx, cipher, keyiv, cipher_keylen(cipher),
	    keyiv + cipher_keylen(cipher), cipher_ivlen(cipher), 1)) != 0)
		اذهب out;

	/* Serialise and encrypt the private key using the ephemeral key */
	אם ((prvbuf = sshbuf_new()) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}
	אם (sshkey_is_shielded(k) && (r = sshkey_unshield_private(k)) != 0)
		اذهب out;
	אם ((r = sshkey_private_serialize(k, prvbuf)) != 0)
		اذهب out;
	/* pad to cipher blocksize */
	i = 0;
	כלעוד (sshbuf_len(prvbuf) % cipher_blocksize(cipher)) {
		אם ((r = sshbuf_put_u8(prvbuf, ++i & 0xff)) != 0)
			اذهب out;
	}
#ifdef DEBUG_PK
	fprintf(stderr, "%s: serialised\n", __func__);
	sshbuf_dump(prvbuf, stderr);
#endif
	/* encrypt */
	enclen = sshbuf_len(prvbuf);
	אם ((enc = malloc(enclen)) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}
	אם ((r = cipher_crypt(cctx, 0, enc,
	    sshbuf_ptr(prvbuf), sshbuf_len(prvbuf), 0, 0)) != 0)
		اذهب out;
#ifdef DEBUG_PK
	fprintf(stderr, "%s: encrypted\n", __func__);
	sshbuf_dump_data(enc, enclen, stderr);
#endif

	/* Make a scrubbed, public-only copy of our private key argument */
	אם ((r = sshkey_from_private(k, &kswap)) != 0)
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
	החזר r;
}

/* Check deterministic padding after private key */
ساكن صحيح
private2_check_padding(بنية sshbuf *decrypted)
{
	u_char pad;
	size_t i;
	صحيح r;

	i = 0;
	כלעוד (sshbuf_len(decrypted)) {
		אם ((r = sshbuf_get_u8(decrypted, &pad)) != 0)
			اذهب out;
		אם (pad != (++i & 0xff)) {
			r = SSH_ERR_INVALID_FORMAT;
			اذهب out;
		}
	}
	/* success */
	r = 0;
 out:
	explicit_bzero(&pad, حجم(pad));
	explicit_bzero(&i, حجم(i));
	החזר r;
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
	אם (!sshkey_is_shielded(k))
		החזר 0; /* nothing to do */

	אם ((cipher = cipher_by_name(SSHKEY_SHIELD_CIPHER)) == عدم) {
		r = SSH_ERR_INVALID_ARGUMENT;
		اذهب out;
	}
	אם (cipher_keylen(cipher) + cipher_ivlen(cipher) >
	    ssh_digest_bytes(SSHKEY_SHIELD_PREKEY_HASH)) {
		r = SSH_ERR_INTERNAL_ERROR;
		اذهب out;
	}
	/* check size of shielded key blob */
	אם (k->shielded_len < cipher_blocksize(cipher) ||
	    (k->shielded_len % cipher_blocksize(cipher)) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		اذهب out;
	}

	/* Calculate the ephemeral key from the prekey */
	אם ((r = ssh_digest_memory(SSHKEY_SHIELD_PREKEY_HASH,
	    k->shield_prekey, k->shield_prekey_len,
	    keyiv, SSH_DIGEST_MAX_LENGTH)) != 0)
		اذهب out;
	אם ((r = cipher_init(&cctx, cipher, keyiv, cipher_keylen(cipher),
	    keyiv + cipher_keylen(cipher), cipher_ivlen(cipher), 0)) != 0)
		اذهب out;
#ifdef DEBUG_PK
	fprintf(stderr, "%s: key+iv\n", __func__);
	sshbuf_dump_data(keyiv, ssh_digest_bytes(SSHKEY_SHIELD_PREKEY_HASH),
	    stderr);
#endif

	/* Decrypt and parse the shielded private key using the ephemeral key */
	אם ((prvbuf = sshbuf_new()) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}
	אם ((r = sshbuf_reserve(prvbuf, k->shielded_len, &cp)) != 0)
		اذهب out;
	/* decrypt */
#ifdef DEBUG_PK
	fprintf(stderr, "%s: encrypted\n", __func__);
	sshbuf_dump_data(k->shielded_private, k->shielded_len, stderr);
#endif
	אם ((r = cipher_crypt(cctx, 0, cp,
	    k->shielded_private, k->shielded_len, 0, 0)) != 0)
		اذهب out;
#ifdef DEBUG_PK
	fprintf(stderr, "%s: serialised\n", __func__);
	sshbuf_dump(prvbuf, stderr);
#endif
	/* Parse private key */
	אם ((r = sshkey_private_deserialize(prvbuf, &kswap)) != 0)
		اذهب out;

	אם ((r = private2_check_padding(prvbuf)) != 0)
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
	החזר r;
}

ساكن صحيح
cert_parse(بنية sshbuf *b, بنية sshkey *key, بنية sshbuf *certbuf,
    ثابت حرف *ca_sigalg_allowlist)
{
	بنية sshbuf *principals = عدم, *crit = عدم;
	بنية sshbuf *exts = عدم, *ca = عدم;
	u_char *sig = عدم;
	حرف *sigtype = عدم;
	size_t signed_len = 0, slen = 0, kidlen = 0;
	صحيح ret = SSH_ERR_INTERNAL_ERROR;

	/* Copy the entire key blob for verification and later serialisation */
	אם ((ret = sshbuf_putb(key->cert->certblob, certbuf)) != 0)
		החזר ret;

	/* Parse body of certificate up to signature */
	אם ((ret = sshbuf_get_u64(b, &key->cert->serial)) != 0 ||
	    (ret = sshbuf_get_u32(b, &key->cert->type)) != 0 ||
	    (ret = sshbuf_get_cstring(b, &key->cert->key_id, &kidlen)) != 0 ||
	    (ret = sshbuf_froms(b, &principals)) != 0 ||
	    (ret = sshbuf_get_u64(b, &key->cert->valid_after)) != 0 ||
	    (ret = sshbuf_get_u64(b, &key->cert->valid_before)) != 0 ||
	    (ret = sshbuf_froms(b, &crit)) != 0 ||
	    (ret = sshbuf_froms(b, &exts)) != 0 ||
	    (ret = sshbuf_get_string_direct(b, عدم, عدم)) != 0 ||
	    (ret = sshbuf_froms(b, &ca)) != 0) {
		/* XXX debug print error for ret */
		ret = SSH_ERR_INVALID_FORMAT;
		اذهب out;
	}

	/* Signature is left in the buffer so we can calculate this length */
	signed_len = sshbuf_len(key->cert->certblob) - sshbuf_len(b);

	אם ((ret = sshbuf_get_string(b, &sig, &slen)) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		اذهب out;
	}

	/* Is this a signature we're prepared to accept? */
	אם ((ret = sshkey_get_sigtype(sig, slen, &sigtype)) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		اذهب out;
	}
	אם (ca_sigalg_allowlist != عدم &&
	    match_pattern_list(sigtype, ca_sigalg_allowlist, 0) != 1) {
		ret = SSH_ERR_SIGN_ALG_UNSUPPORTED;
		اذهب out;
	}

	/* Parse CA key and check whether we might accept it */
	אם (sshkey_from_blob_internal(ca, &key->cert->signature_key, 0,
	    ca_sigalg_allowlist, عدم) != 0) {
		ret = SSH_ERR_KEY_CERT_INVALID_SIGN_KEY;
		اذهب out;
	}
	אם (!sshkey_type_is_valid_ca(key->cert->signature_key->type)) {
		ret = SSH_ERR_KEY_CERT_INVALID_SIGN_KEY;
		اذهب out;
	}

	אם (key->cert->type != SSH2_CERT_TYPE_USER &&
	    key->cert->type != SSH2_CERT_TYPE_HOST) {
		ret = SSH_ERR_KEY_CERT_UNKNOWN_TYPE;
		اذهب out;
	}

	/* Parse principals section */
	כלעוד (sshbuf_len(principals) > 0) {
		حرف *principal = عدم;
		حرف **oprincipals = عدم;

		אם (key->cert->nprincipals >= SSHKEY_CERT_MAX_PRINCIPALS) {
			ret = SSH_ERR_INVALID_FORMAT;
			اذهب out;
		}
		אם ((ret = sshbuf_get_cstring(principals, &principal,
		    عدم)) != 0) {
			ret = SSH_ERR_INVALID_FORMAT;
			اذهب out;
		}
		oprincipals = key->cert->principals;
		key->cert->principals = recallocarray(key->cert->principals,
		    key->cert->nprincipals, key->cert->nprincipals + 1,
		    حجم(*key->cert->principals));
		אם (key->cert->principals == عدم) {
			حرر(principal);
			key->cert->principals = oprincipals;
			ret = SSH_ERR_ALLOC_FAIL;
			اذهب out;
		}
		key->cert->principals[key->cert->nprincipals++] = principal;
	}

	/*
	 * Stash a copies of the critical options and extensions sections
	 * for later use.
	 */
	אם ((ret = sshbuf_putb(key->cert->critical, crit)) != 0 ||
	    (exts != عدم &&
	    (ret = sshbuf_putb(key->cert->extensions, exts)) != 0))
		اذهب out;

	/*
	 * Validate critical options and extensions sections format.
	 */
	כלעוד (sshbuf_len(crit) != 0) {
		אם ((ret = sshbuf_get_string_direct(crit, عدم, عدم)) != 0 ||
		    (ret = sshbuf_get_string_direct(crit, عدم, عدم)) != 0) {
			sshbuf_reset(key->cert->critical);
			ret = SSH_ERR_INVALID_FORMAT;
			اذهب out;
		}
	}
	כלעוד (exts != عدم && sshbuf_len(exts) != 0) {
		אם ((ret = sshbuf_get_string_direct(exts, عدم, عدم)) != 0 ||
		    (ret = sshbuf_get_string_direct(exts, عدم, عدم)) != 0) {
			sshbuf_reset(key->cert->extensions);
			ret = SSH_ERR_INVALID_FORMAT;
			اذهب out;
		}
	}

	/* Finally, validate signature */
	אם ((ret = sshkey_verify(key->cert->signature_key, sig, slen,
	    sshbuf_ptr(key->cert->certblob), signed_len, عدم, 0, عدم)) != 0)
		اذهب out;

	/* Success */
	ret = 0;
	key->cert->signature_type = sigtype;
	sigtype = عدم;
 out:
	sshbuf_free(ca);
	sshbuf_free(crit);
	sshbuf_free(exts);
	sshbuf_free(principals);
	حرر(sig);
	حرر(sigtype);
	החזר ret;
}

صحيح
sshkey_deserialize_sk(بنية sshbuf *b, بنية sshkey *key)
{
	/* Parse additional security-key application string */
	אם (sshbuf_get_cstring(b, &key->sk_application, عدم) != 0)
		החזר SSH_ERR_INVALID_FORMAT;
	החזר 0;
}

ساكن صحيح
sshkey_from_blob_internal(بنية sshbuf *b, بنية sshkey **keyp,
    صحيح allow_cert, ثابت حرف *alg_allowlist, ثابت حرف *ca_sigalg_allowlist)
{
	صحيح type, ret = SSH_ERR_INTERNAL_ERROR;
	حرف *ktype = عدم;
	بنية sshkey *key = عدم;
	بنية sshbuf *copy;
	ثابت بنية sshkey_impl *impl;

#ifdef DEBUG_PK /* XXX */
	sshbuf_dump(b, stderr);
#endif
	אם (keyp != عدم)
		*keyp = عدم;
	אם ((copy = sshbuf_fromb(b)) == عدم) {
		ret = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}
	אם (sshbuf_get_cstring(b, &ktype, عدم) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		اذهب out;
	}

	type = sshkey_type_from_name(ktype);
	אם (!allow_cert && sshkey_type_is_cert(type)) {
		ret = SSH_ERR_KEY_CERT_INVALID_SIGN_KEY;
		اذهب out;
	}

	אם (alg_allowlist != عدم &&
	    !sshkey_match_keyname_to_sigalgs(ktype, alg_allowlist)) {
		ret = SSH_ERR_KEY_ALG_UNSUPPORTED;
		اذهب out;
	}

	אם ((impl = sshkey_impl_from_type(type)) == عدم) {
		ret = SSH_ERR_KEY_TYPE_UNKNOWN;
		اذهب out;
	}
	אם ((key = sshkey_new(type)) == عدم) {
		ret = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}
	אם (sshkey_type_is_cert(type)) {
		/* Skip nonce that precedes all certificates */
		אם (sshbuf_get_string_direct(b, عدم, عدم) != 0) {
			ret = SSH_ERR_INVALID_FORMAT;
			اذهب out;
		}
	}
	אם ((ret = impl->funcs->deserialize_public(ktype, b, key)) != 0)
		اذهب out;

	/* Parse certificate potion */
	אם (sshkey_is_cert(key) &&
	    (ret = cert_parse(b, key, copy, ca_sigalg_allowlist)) != 0)
		اذهب out;

	אם (key != عدم && sshbuf_len(b) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		اذهب out;
	}
	ret = 0;
	אם (keyp != عدم) {
		*keyp = key;
		key = عدم;
	}
 out:
	sshbuf_free(copy);
	sshkey_free(key);
	حرر(ktype);
	החזר ret;
}

صحيح
sshkey_from_blob(ثابت u_char *blob, size_t blen, بنية sshkey **keyp)
{
	بنية sshbuf *b;
	صحيح r;

	אם ((b = sshbuf_from(blob, blen)) == عدم)
		החזר SSH_ERR_ALLOC_FAIL;
	r = sshkey_from_blob_internal(b, keyp, 1, عدم, عدم);
	sshbuf_free(b);
	החזר r;
}

صحيح
sshkey_fromb(بنية sshbuf *b, بنية sshkey **keyp)
{
	החזר sshkey_from_blob_internal(b, keyp, 1, عدم, عدم);
}

صحيح
sshkey_fromb_allowlist(بنية sshbuf *b, بنية sshkey **keyp,
    ثابت حرف *alg_allowlist, ثابت حرف *ca_sigalg_allowlist)
{
	החזר sshkey_from_blob_internal(b, keyp, 1,
	    alg_allowlist, ca_sigalg_allowlist);
}

صحيح
sshkey_froms(بنية sshbuf *buf, بنية sshkey **keyp)
{
	بنية sshbuf *b;
	صحيح r;

	אם ((r = sshbuf_froms(buf, &b)) != 0)
		החזר r;
	r = sshkey_from_blob_internal(b, keyp, 1, عدم, عدم);
	sshbuf_free(b);
	החזר r;
}

صحيح
sshkey_get_sigtype(ثابت u_char *sig, size_t siglen, حرف **sigtypep)
{
	صحيح r;
	بنية sshbuf *b = عدم;
	حرف *sigtype = عدم;

	אם (sigtypep != عدم)
		*sigtypep = عدم;
	אם ((b = sshbuf_from(sig, siglen)) == عدم)
		החזר SSH_ERR_ALLOC_FAIL;
	אם ((r = sshbuf_get_cstring(b, &sigtype, عدم)) != 0)
		اذهب out;
	/* success */
	אם (sigtypep != عدم) {
		*sigtypep = sigtype;
		sigtype = عدم;
	}
	r = 0;
 out:
	حرر(sigtype);
	sshbuf_free(b);
	החזר r;
}

/*
 *
 * Checks whether a certificate's signature type is allowed.
 * Returns 0 (success) if the certificate signature type appears in the
 * "allowed" pattern-list, or the key is not a certificate to begin with.
 * Otherwise returns a ssherr.h code.
 */
صحيح
sshkey_check_cert_sigtype(ثابت بنية sshkey *key, ثابت حرف *allowed)
{
	אם (key == عدم || allowed == عدم)
		החזר SSH_ERR_INVALID_ARGUMENT;
	אם (!sshkey_type_is_cert(key->type))
		החזר 0;
	אם (key->cert == عدم || key->cert->signature_type == عدم)
		החזר SSH_ERR_INVALID_ARGUMENT;
	אם (match_pattern_list(key->cert->signature_type, allowed, 0) != 1)
		החזר SSH_ERR_SIGN_ALG_UNSUPPORTED;
	החזר 0;
}

/*
 * Returns the expected signature algorithm for a given public key algorithm.
 */
ثابت حرف *
sshkey_sigalg_by_name(ثابت حرف *name)
{
	ثابت بنية sshkey_impl *impl;
	صحيح i;

	עבור (i = 0; keyimpls[i] != عدم; i++) {
		impl = keyimpls[i];
		אם (strcmp(impl->name, name) != 0)
			استمر;
		אם (impl->sigalg != عدم)
			החזר impl->sigalg;
		אם (!impl->cert)
			החזר impl->name;
		החזר sshkey_ssh_name_from_type_nid(
		    sshkey_type_plain(impl->type), impl->nid);
	}
	החזר عدم;
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

	אם (requested_alg == عدم)
		החזר 0;
	אם ((expected_alg = sshkey_sigalg_by_name(requested_alg)) == عدم)
		החזר SSH_ERR_INVALID_ARGUMENT;
	אם ((r = sshkey_get_sigtype(sig, siglen, &sigtype)) != 0)
		החזר r;
	r = strcmp(expected_alg, sigtype) == 0;
	حرر(sigtype);
	החזר r ? 0 : SSH_ERR_SIGN_ALG_UNSUPPORTED;
}

صحيح
sshkey_sign(بنية sshkey *key,
    u_char **sigp, size_t *lenp,
    ثابت u_char *data, size_t datalen,
    ثابت حرف *alg, ثابت حرف *sk_provider, ثابت حرف *sk_pin, u_int compat)
{
	صحيح was_shielded = sshkey_is_shielded(key);
	صحيح r2, r = SSH_ERR_INTERNAL_ERROR;
	ثابت بنية sshkey_impl *impl;

	אם (sigp != عدم)
		*sigp = عدم;
	אם (lenp != عدم)
		*lenp = 0;
	אם (datalen > SSH_KEY_MAX_SIGN_DATA_SIZE)
		החזר SSH_ERR_INVALID_ARGUMENT;
	אם ((impl = sshkey_impl_from_key(key)) == عدم)
		החזר SSH_ERR_KEY_TYPE_UNKNOWN;
	אם ((r = sshkey_unshield_private(key)) != 0)
		החזר r;
	אם (sshkey_is_sk(key)) {
		r = sshsk_sign(sk_provider, key, sigp, lenp, data,
		    datalen, compat, sk_pin);
	} אחרת אם ((key->flags & SSHKEY_FLAG_EXT) != 0) {
		r = pkcs11_sign(key, sigp, lenp, data, datalen,
		    alg, sk_provider, sk_pin, compat);
	} אחרת {
		אם (impl->funcs->sign == عدم)
			r = SSH_ERR_SIGN_ALG_UNSUPPORTED;
		אחרת {
			r = impl->funcs->sign(key, sigp, lenp, data, datalen,
			    alg, sk_provider, sk_pin, compat);
		 }
	}
	אם (was_shielded && (r2 = sshkey_shield_private(key)) != 0)
		החזר r2;
	החזר r;
}

/*
 * ssh_key_verify returns 0 for a correct signature and < 0 on error.
 * If "alg" specified, then the signature must use that algorithm.
 */
صحيح
sshkey_verify(ثابت بنية sshkey *key,
    ثابت u_char *sig, size_t siglen,
    ثابت u_char *data, size_t dlen, ثابت حرف *alg, u_int compat,
    بنية sshkey_sig_details **detailsp)
{
	ثابت بنية sshkey_impl *impl;

	אם (detailsp != عدم)
		*detailsp = عدم;
	אם (siglen == 0 || dlen > SSH_KEY_MAX_SIGN_DATA_SIZE)
		החזר SSH_ERR_INVALID_ARGUMENT;
	אם ((impl = sshkey_impl_from_key(key)) == عدم)
		החזר SSH_ERR_KEY_TYPE_UNKNOWN;
	החזר impl->funcs->verify(key, sig, siglen, data, dlen,
	    alg, compat, detailsp);
}

/* Convert a plain key to their _CERT equivalent */
صحيح
sshkey_to_certified(بنية sshkey *k)
{
	صحيح newtype;

	אם ((newtype = sshkey_type_certified(k->type)) == -1)
		החזר SSH_ERR_INVALID_ARGUMENT;
	אם ((k->cert = cert_new()) == عدم)
		החזר SSH_ERR_ALLOC_FAIL;
	k->type = newtype;
	החזר 0;
}

/* Convert a certificate to its raw key equivalent */
صحيح
sshkey_drop_cert(بنية sshkey *k)
{
	אם (!sshkey_type_is_cert(k->type))
		החזר SSH_ERR_KEY_TYPE_UNKNOWN;
	cert_free(k->cert);
	k->cert = عدم;
	k->type = sshkey_type_plain(k->type);
	החזר 0;
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

	אם (k == عدم || k->cert == عدم ||
	    k->cert->certblob == عدم || ca == عدم)
		החזר SSH_ERR_INVALID_ARGUMENT;
	אם (!sshkey_is_cert(k))
		החזר SSH_ERR_KEY_TYPE_UNKNOWN;
	אם (!sshkey_type_is_valid_ca(ca->type))
		החזר SSH_ERR_KEY_CERT_INVALID_SIGN_KEY;
	אם ((impl = sshkey_impl_from_key(k)) == عدم)
		החזר SSH_ERR_INTERNAL_ERROR;

	/*
	 * If no alg specified as argument but a signature_type was set,
	 * then prefer that. If both were specified, then they must match.
	 */
	אם (alg == عدم)
		alg = k->cert->signature_type;
	אחרת אם (k->cert->signature_type != عدم &&
	    strcmp(alg, k->cert->signature_type) != 0)
		החזר SSH_ERR_INVALID_ARGUMENT;

	/*
	 * If no signing algorithm or signature_type was specified and we're
	 * using a RSA key, then default to a good signature algorithm.
	 */
	אם (alg == عدم && ca->type == KEY_RSA)
		alg = "rsa-sha2-512";

	אם ((ret = sshkey_to_blob(ca, &ca_blob, &ca_len)) != 0)
		החזר SSH_ERR_KEY_CERT_INVALID_SIGN_KEY;

	cert = k->cert->certblob; /* for readability */
	sshbuf_reset(cert);
	אם ((ret = sshbuf_put_cstring(cert, sshkey_ssh_name(k))) != 0)
		اذهب out;

	/* -v01 certs put nonce first */
	arc4random_buf(&nonce, حجم(nonce));
	אם ((ret = sshbuf_put_string(cert, nonce, حجم(nonce))) != 0)
		اذهب out;

	/* Public key next */
	אם ((ret = impl->funcs->serialize_public(k, cert,
	    SSHKEY_SERIALIZE_DEFAULT)) != 0)
		اذهب out;

	/* Then remaining cert fields */
	אם ((ret = sshbuf_put_u64(cert, k->cert->serial)) != 0 ||
	    (ret = sshbuf_put_u32(cert, k->cert->type)) != 0 ||
	    (ret = sshbuf_put_cstring(cert, k->cert->key_id)) != 0)
		اذهب out;

	אם ((principals = sshbuf_new()) == عدم) {
		ret = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}
	עבור (i = 0; i < k->cert->nprincipals; i++) {
		אם ((ret = sshbuf_put_cstring(principals,
		    k->cert->principals[i])) != 0)
			اذهب out;
	}
	אם ((ret = sshbuf_put_stringb(cert, principals)) != 0 ||
	    (ret = sshbuf_put_u64(cert, k->cert->valid_after)) != 0 ||
	    (ret = sshbuf_put_u64(cert, k->cert->valid_before)) != 0 ||
	    (ret = sshbuf_put_stringb(cert, k->cert->critical)) != 0 ||
	    (ret = sshbuf_put_stringb(cert, k->cert->extensions)) != 0 ||
	    (ret = sshbuf_put_string(cert, عدم, 0)) != 0 || /* Reserved */
	    (ret = sshbuf_put_string(cert, ca_blob, ca_len)) != 0)
		اذهب out;

	/* Sign the whole mess */
	אם ((ret = signer(ca, &sig_blob, &sig_len, sshbuf_ptr(cert),
	    sshbuf_len(cert), alg, sk_provider, sk_pin, 0, signer_ctx)) != 0)
		اذهب out;
	/* Check and update signature_type against what was actually used */
	אם ((ret = sshkey_get_sigtype(sig_blob, sig_len, &sigtype)) != 0)
		اذهب out;
	אם (alg != عدم && strcmp(alg, sigtype) != 0) {
		ret = SSH_ERR_SIGN_ALG_UNSUPPORTED;
		اذهب out;
	}
	אם (k->cert->signature_type == عدم) {
		k->cert->signature_type = sigtype;
		sigtype = عدم;
	}
	/* Append signature and we are done */
	אם ((ret = sshbuf_put_string(cert, sig_blob, sig_len)) != 0)
		اذهب out;
	ret = 0;
 out:
	אם (ret != 0)
		sshbuf_reset(cert);
	حرر(sig_blob);
	حرر(ca_blob);
	حرر(sigtype);
	sshbuf_free(principals);
	החזר ret;
}

ساكن صحيح
default_key_sign(بنية sshkey *key, u_char **sigp, size_t *lenp,
    ثابت u_char *data, size_t datalen,
    ثابت حرف *alg, ثابت حرف *sk_provider, ثابت حرف *sk_pin,
    u_int compat, فراغ *ctx)
{
	אם (ctx != عدم)
		החזר SSH_ERR_INVALID_ARGUMENT;
	החזר sshkey_sign(key, sigp, lenp, data, datalen, alg,
	    sk_provider, sk_pin, compat);
}

صحيح
sshkey_certify(بنية sshkey *k, بنية sshkey *ca, ثابت حرف *alg,
    ثابت حرف *sk_provider, ثابت حرف *sk_pin)
{
	החזר sshkey_certify_custom(k, ca, alg, sk_provider, sk_pin,
	    default_key_sign, عدم);
}

صحيح
sshkey_cert_check_authority(ثابت بنية sshkey *k,
    صحيح want_host, صحيح wildcard_pattern, uint64_t verify_time,
    ثابت حرف *name, ثابت حرف **reason)
{
	u_int i, principal_matches;

	אם (reason == عدم)
		החזר SSH_ERR_INVALID_ARGUMENT;
	אם (!sshkey_is_cert(k)) {
		*reason = "Key is not a certificate";
		החזר SSH_ERR_KEY_CERT_INVALID;
	}
	אם (want_host) {
		אם (k->cert->type != SSH2_CERT_TYPE_HOST) {
			*reason = "Certificate invalid: not a host certificate";
			החזר SSH_ERR_KEY_CERT_INVALID;
		}
	} אחרת {
		אם (k->cert->type != SSH2_CERT_TYPE_USER) {
			*reason = "Certificate invalid: not a user certificate";
			החזר SSH_ERR_KEY_CERT_INVALID;
		}
	}
	אם (verify_time < k->cert->valid_after) {
		*reason = "Certificate invalid: not yet valid";
		החזר SSH_ERR_KEY_CERT_INVALID;
	}
	אם (verify_time >= k->cert->valid_before) {
		*reason = "Certificate invalid: expired";
		החזר SSH_ERR_KEY_CERT_INVALID;
	}
	אם (k->cert->nprincipals == 0) {
		*reason = "Certificate lacks principal list";
		החזר SSH_ERR_KEY_CERT_INVALID;
	}
	אם (name == عدم)
		החזר 0; /* principal matching not requested */

	principal_matches = 0;
	עבור (i = 0; i < k->cert->nprincipals; i++) {
		אם (wildcard_pattern) {
			אם (match_pattern(name, k->cert->principals[i])) {
				principal_matches = 1;
				اكسر;
			}
		} אחרת אם (strcmp(name, k->cert->principals[i]) == 0) {
			principal_matches = 1;
			اكسر;
		}
	}
	אם (!principal_matches) {
		*reason = "Certificate invalid: name is not a listed "
		    "principal";
		החזר SSH_ERR_KEY_CERT_INVALID;
	}
	החזר 0;
}

صحيح
sshkey_cert_check_authority_now(ثابت بنية sshkey *k,
    صحيح want_host, صحيح wildcard_pattern, ثابت حرف *name,
    ثابت حرف **reason)
{
	time_t now;

	אם ((now = time(عدم)) < 0) {
		/* yikes - system clock before epoch! */
		*reason = "Certificate invalid: not yet valid";
		החזר SSH_ERR_KEY_CERT_INVALID;
	}
	החזר sshkey_cert_check_authority(k, want_host, wildcard_pattern,
	    (uint64_t)now, name, reason);
}

صحيح
sshkey_cert_check_host(ثابت بنية sshkey *key, ثابت حرف *host,
    ثابت حرف *ca_sign_algorithms, ثابت حرف **reason)
{
	صحيح r;

	אם ((r = sshkey_cert_check_authority_now(key, 1, 1, host, reason)) != 0)
		החזר r;
	אם (sshbuf_len(key->cert->critical) != 0) {
		*reason = "Certificate contains unsupported critical options";
		החזר SSH_ERR_KEY_CERT_INVALID;
	}
	אם (ca_sign_algorithms != عدم &&
	    (r = sshkey_check_cert_sigtype(key, ca_sign_algorithms)) != 0) {
		*reason = "Certificate signed with disallowed algorithm";
		החזר SSH_ERR_KEY_CERT_INVALID;
	}
	החזר 0;
}

size_t
sshkey_format_cert_validity(ثابت بنية sshkey_cert *cert, حرف *s, size_t l)
{
	حرف from[32], to[32], ret[128];

	*from = *to = '\0';
	אם (cert->valid_after == 0 &&
	    cert->valid_before == 0xffffffffffffffffULL)
		החזר strlcpy(s, "forever", l);

	אם (cert->valid_after != 0)
		format_absolute_time(cert->valid_after, from, حجم(from));
	אם (cert->valid_before != 0xffffffffffffffffULL)
		format_absolute_time(cert->valid_before, to, حجم(to));

	אם (cert->valid_after == 0)
		snprintf(ret, حجم(ret), "before %s", to);
	אחרת אם (cert->valid_before == 0xffffffffffffffffULL)
		snprintf(ret, حجم(ret), "after %s", from);
	אחרת
		snprintf(ret, حجم(ret), "from %s to %s", from, to);

	החזר strlcpy(s, ret, l);
}

/* Common serialization for FIDO private keys */
صحيح
sshkey_serialize_private_sk(ثابت بنية sshkey *key, بنية sshbuf *b)
{
	صحيح r;

	אם ((r = sshbuf_put_cstring(b, key->sk_application)) != 0 ||
	    (r = sshbuf_put_u8(b, key->sk_flags)) != 0 ||
	    (r = sshbuf_put_stringb(b, key->sk_key_handle)) != 0 ||
	    (r = sshbuf_put_stringb(b, key->sk_reserved)) != 0)
		החזר r;

	החזר 0;
}

ساكن صحيح
sshkey_private_serialize_opt(بنية sshkey *key, بنية sshbuf *buf,
    تعداد sshkey_serialize_rep opts)
{
	صحيح r = SSH_ERR_INTERNAL_ERROR;
	صحيح was_shielded = sshkey_is_shielded(key);
	بنية sshbuf *b = عدم;
	ثابت بنية sshkey_impl *impl;

	אם ((impl = sshkey_impl_from_key(key)) == عدم)
		החזר SSH_ERR_INTERNAL_ERROR;
	אם ((r = sshkey_unshield_private(key)) != 0)
		החזר r;
	אם ((b = sshbuf_new()) == عدم)
		החזר SSH_ERR_ALLOC_FAIL;
	אם ((r = sshbuf_put_cstring(b, sshkey_ssh_name(key))) != 0)
		اذهب out;
	אם (sshkey_is_cert(key)) {
		אם (key->cert == عدم ||
		    sshbuf_len(key->cert->certblob) == 0) {
			r = SSH_ERR_INVALID_ARGUMENT;
			اذهب out;
		}
		אם ((r = sshbuf_put_stringb(b, key->cert->certblob)) != 0)
			اذهب out;
	}
	אם ((r = impl->funcs->serialize_private(key, b, opts)) != 0)
		اذهب out;

	/*
	 * success (but we still need to append the output to buf after
	 * possibly re-shielding the private key)
	 */
	r = 0;
 out:
	אם (was_shielded)
		r = sshkey_shield_private(key);
	אם (r == 0)
		r = sshbuf_putb(buf, b);
	sshbuf_free(b);

	החזר r;
}

صحيح
sshkey_private_serialize(بنية sshkey *key, بنية sshbuf *b)
{
	החזר sshkey_private_serialize_opt(key, b,
	    SSHKEY_SERIALIZE_DEFAULT);
}


/* Shared deserialization of FIDO private key components */
صحيح
sshkey_private_deserialize_sk(بنية sshbuf *buf, بنية sshkey *k)
{
	صحيح r;

	אם ((k->sk_key_handle = sshbuf_new()) == عدم ||
	    (k->sk_reserved = sshbuf_new()) == عدم)
		החזר SSH_ERR_ALLOC_FAIL;
	אם ((r = sshbuf_get_cstring(buf, &k->sk_application, عدم)) != 0 ||
	    (r = sshbuf_get_u8(buf, &k->sk_flags)) != 0 ||
	    (r = sshbuf_get_stringb(buf, k->sk_key_handle)) != 0 ||
	    (r = sshbuf_get_stringb(buf, k->sk_reserved)) != 0)
		החזר r;

	החזר 0;
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

	אם (kp != عدم)
		*kp = عدم;
	אם ((r = sshbuf_get_cstring(buf, &tname, عدم)) != 0)
		اذهب out;
	type = sshkey_type_from_name(tname);
	אם (sshkey_type_is_cert(type)) {
		/*
		 * Certificate key private keys begin with the certificate
		 * itself. Make sure this matches the type of the enclosing
		 * private key.
		 */
		אם ((r = sshkey_froms(buf, &k)) != 0)
			اذهب out;
		אם (k->type != type) {
			r = SSH_ERR_KEY_CERT_MISMATCH;
			اذهب out;
		}
		/* For ECDSA keys, the group must match too */
		אם (k->type == KEY_ECDSA &&
		    k->ecdsa_nid != sshkey_ecdsa_nid_from_name(tname)) {
			r = SSH_ERR_KEY_CERT_MISMATCH;
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
	} אחרת {
		אם ((k = sshkey_new(type)) == عدم) {
			r = SSH_ERR_ALLOC_FAIL;
			اذهب out;
		}
	}
	אם ((impl = sshkey_impl_from_type(type)) == عدم) {
		r = SSH_ERR_INTERNAL_ERROR;
		اذهب out;
	}
	אם ((r = impl->funcs->deserialize_private(tname, buf, k)) != 0)
		اذهب out;

	אם ((expect_sk_application != عدم && (k->sk_application == عدم ||
	    strcmp(expect_sk_application, k->sk_application) != 0)) ||
	    (expect_ed25519_pk != عدم && (k->ed25519_pk == عدم ||
	    memcmp(expect_ed25519_pk, k->ed25519_pk, ED25519_PK_SZ) != 0))) {
		r = SSH_ERR_KEY_CERT_MISMATCH;
		اذهب out;
	}
	/* success */
	r = 0;
	אם (kp != عدم) {
		*kp = k;
		k = عدم;
	}
 out:
	حرر(tname);
	sshkey_free(k);
	حرر(expect_sk_application);
	حرر(expect_ed25519_pk);
	החזר r;
}

#ifdef WITH_OPENSSL
صحيح
sshkey_ec_validate_public(ثابت EC_GROUP *group, ثابت EC_POINT *عام)
{
	EC_POINT *nq = عدم;
	BIGNUM *order = عدم, *cofactor = عدم;
	صحيح ret = SSH_ERR_KEY_INVALID_EC_VALUE;

	/*
	 * NB. This assumes OpenSSL has already verified that the public
	 * point lies on the curve and that its coordinates are in [0, p).
	 * This is done by EC_POINT_oct2point() on at least OpenSSL >= 1.1,
	 * LibreSSL and BoringSSL.
	 */

	/* Q != infinity */
	אם (EC_POINT_is_at_infinity(group, عام))
		اذهب out;

	אם ((cofactor = BN_new()) == عدم) {
		ret = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}
	אם (EC_GROUP_get_cofactor(group, cofactor, عدم) != 1)
		اذهب out;

	/*
	 * Verify nQ == infinity (n == order of subgroup)
	 * This check may be skipped for curves with cofactor 1, as per
	 * NIST SP 800-56A, 5.6.2.3.
	 */
	אם (!BN_is_one(cofactor)) {
		אם ((order = BN_new()) == عدم) {
			ret = SSH_ERR_ALLOC_FAIL;
			اذهب out;
		}
		אם (EC_GROUP_get_order(group, order, عدم) != 1) {
			ret = SSH_ERR_LIBCRYPTO_ERROR;
			اذهب out;
		}
		אם ((nq = EC_POINT_new(group)) == عدم) {
			ret = SSH_ERR_ALLOC_FAIL;
			اذهب out;
		}
		אם (EC_POINT_mul(group, nq, عدم, عام, order, عدم) != 1) {
			ret = SSH_ERR_LIBCRYPTO_ERROR;
			اذهب out;
		}
		אם (EC_POINT_is_at_infinity(group, nq) != 1)
			اذهب out;
	}

	/* success */
	ret = 0;
 out:
	BN_clear_free(cofactor);
	BN_clear_free(order);
	EC_POINT_free(nq);
	החזר ret;
}

صحيح
sshkey_ec_validate_private(ثابت EC_KEY *key)
{
	BIGNUM *order = عدم, *tmp = عدم;
	صحيح ret = SSH_ERR_KEY_INVALID_EC_VALUE;

	אם ((order = BN_new()) == عدم || (tmp = BN_new()) == عدم) {
		ret = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}

	/* log2(private) > log2(order)/2 */
	אם (EC_GROUP_get_order(EC_KEY_get0_group(key), order, عدم) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		اذهب out;
	}
	אם (BN_num_bits(EC_KEY_get0_private_key(key)) <=
	    BN_num_bits(order) / 2)
		اذهب out;

	/* private < order - 1 */
	אם (!BN_sub(tmp, order, BN_value_one())) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		اذهب out;
	}
	אם (BN_cmp(EC_KEY_get0_private_key(key), tmp) >= 0)
		اذهب out;
	ret = 0;
 out:
	BN_clear_free(order);
	BN_clear_free(tmp);
	החזר ret;
}

فراغ
sshkey_dump_ec_point(ثابت EC_GROUP *group, ثابت EC_POINT *point)
{
	BIGNUM *x = عدم, *y = عدم;

	אם (point == عدم) {
		fputs("point=(NULL)\n", stderr);
		החזר;
	}
	אם ((x = BN_new()) == عدم || (y = BN_new()) == عدم) {
		fprintf(stderr, "%s: BN_new failed\n", __func__);
		اذهب out;
	}
	אם (EC_POINT_get_affine_coordinates(group, point, x, y, عدم) != 1) {
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
sshkey_dump_ec_key(ثابت EC_KEY *key)
{
	ثابت BIGNUM *exponent;

	sshkey_dump_ec_point(EC_KEY_get0_group(key),
	    EC_KEY_get0_public_key(key));
	fputs("exponent=", stderr);
	אם ((exponent = EC_KEY_get0_private_key(key)) == عدم)
		fputs("(NULL)", stderr);
	אחרת
		BN_print_fp(stderr, EC_KEY_get0_private_key(key));
	fputs("\n", stderr);
}
#endif /* WITH_OPENSSL */

ساكن صحيح
sshkey_private_to_blob2(بنية sshkey *prv, بنية sshbuf *blob,
    ثابت حرف *passphrase, ثابت حرف *comment, ثابت حرف *ciphername,
    صحيح rounds)
{
	u_char *cp, *key = عدم, *pubkeyblob = عدم;
	u_char salt[SALT_LEN];
	size_t i, pubkeylen, keylen, ivlen, blocksize, authlen;
	u_int check;
	صحيح r = SSH_ERR_INTERNAL_ERROR;
	بنية sshcipher_ctx *ciphercontext = عدم;
	ثابت بنية sshcipher *cipher;
	ثابت حرف *kdfname = KDFNAME;
	بنية sshbuf *encoded = عدم, *encrypted = عدم, *kdf = عدم;

	אם (rounds <= 0)
		rounds = DEFAULT_ROUNDS;
	אם (rounds > MAX_KDF_ROUNDS) {
		r = SSH_ERR_INVALID_ARGUMENT;
		اذهب out;
	}
	אם (passphrase == عدم || !strlen(passphrase)) {
		ciphername = "none";
		kdfname = "none";
	} אחרת אם (ciphername == عدم)
		ciphername = DEFAULT_CIPHERNAME;
	אם ((cipher = cipher_by_name(ciphername)) == عدم) {
		r = SSH_ERR_INVALID_ARGUMENT;
		اذهب out;
	}

	אם ((kdf = sshbuf_new()) == عدم ||
	    (encoded = sshbuf_new()) == عدم ||
	    (encrypted = sshbuf_new()) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}
	blocksize = cipher_blocksize(cipher);
	keylen = cipher_keylen(cipher);
	ivlen = cipher_ivlen(cipher);
	authlen = cipher_authlen(cipher);
	אם ((key = calloc(1, keylen + ivlen)) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}
	אם (strcmp(kdfname, "bcrypt") == 0) {
		arc4random_buf(salt, SALT_LEN);
		אם (bcrypt_pbkdf(passphrase, strlen(passphrase),
		    salt, SALT_LEN, key, keylen + ivlen, rounds) < 0) {
			r = SSH_ERR_INVALID_ARGUMENT;
			اذهب out;
		}
		אם ((r = sshbuf_put_string(kdf, salt, SALT_LEN)) != 0 ||
		    (r = sshbuf_put_u32(kdf, rounds)) != 0)
			اذهب out;
	} אחרת אם (strcmp(kdfname, "none") != 0) {
		/* Unsupported KDF type */
		r = SSH_ERR_KEY_UNKNOWN_CIPHER;
		اذهب out;
	}
	אם ((r = cipher_init(&ciphercontext, cipher, key, keylen,
	    key + keylen, ivlen, 1)) != 0)
		اذهب out;

	אם ((r = sshbuf_put(encoded, AUTH_MAGIC, حجم(AUTH_MAGIC))) != 0 ||
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
	אם ((r = sshbuf_put_u32(encrypted, check)) != 0 ||
	    (r = sshbuf_put_u32(encrypted, check)) != 0)
		اذهب out;

	/* append private key and comment*/
	אם ((r = sshkey_private_serialize(prv, encrypted)) != 0 ||
	    (r = sshbuf_put_cstring(encrypted, comment)) != 0)
		اذهب out;

	/* padding */
	i = 0;
	כלעוד (sshbuf_len(encrypted) % blocksize) {
		אם ((r = sshbuf_put_u8(encrypted, ++i & 0xff)) != 0)
			اذهب out;
	}

	/* length in destination buffer */
	אם ((r = sshbuf_put_u32(encoded, sshbuf_len(encrypted))) != 0)
		اذهب out;

	/* encrypt */
	אם ((r = sshbuf_reserve(encoded,
	    sshbuf_len(encrypted) + authlen, &cp)) != 0)
		اذهب out;
	אם ((r = cipher_crypt(ciphercontext, 0, cp,
	    sshbuf_ptr(encrypted), sshbuf_len(encrypted), 0, authlen)) != 0)
		اذهب out;

	sshbuf_reset(blob);

	/* assemble uuencoded key */
	אם ((r = sshbuf_put(blob, MARK_BEGIN, MARK_BEGIN_LEN)) != 0 ||
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
	אם (key != عدم)
		freezero(key, keylen + ivlen);
	אם (pubkeyblob != عدم)
		freezero(pubkeyblob, pubkeylen);
	החזר r;
}

ساكن صحيح
private2_uudecode(بنية sshbuf *blob, بنية sshbuf **decodedp)
{
	ثابت u_char *cp;
	size_t encoded_len;
	صحيح r;
	u_char last;
	بنية sshbuf *encoded = عدم, *decoded = عدم;

	אם (blob == عدم || decodedp == عدم)
		החזר SSH_ERR_INVALID_ARGUMENT;

	*decodedp = عدم;

	אם ((encoded = sshbuf_new()) == عدم ||
	    (decoded = sshbuf_new()) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}

	/* check preamble */
	cp = sshbuf_ptr(blob);
	encoded_len = sshbuf_len(blob);
	אם (encoded_len < (MARK_BEGIN_LEN + MARK_END_LEN) ||
	    memcmp(cp, MARK_BEGIN, MARK_BEGIN_LEN) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		اذهب out;
	}
	cp += MARK_BEGIN_LEN;
	encoded_len -= MARK_BEGIN_LEN;

	/* Look for end marker, removing whitespace as we go */
	כלעוד (encoded_len > 0) {
		אם (*cp != '\n' && *cp != '\r') {
			אם ((r = sshbuf_put_u8(encoded, *cp)) != 0)
				اذهب out;
		}
		last = *cp;
		encoded_len--;
		cp++;
		אם (last == '\n') {
			אם (encoded_len >= MARK_END_LEN &&
			    memcmp(cp, MARK_END, MARK_END_LEN) == 0) {
				/* \0 terminate */
				אם ((r = sshbuf_put_u8(encoded, 0)) != 0)
					اذهب out;
				اكسر;
			}
		}
	}
	אם (encoded_len == 0) {
		r = SSH_ERR_INVALID_FORMAT;
		اذهب out;
	}

	/* decode base64 */
	אם ((r = sshbuf_b64tod(decoded, (حرف *)sshbuf_ptr(encoded))) != 0)
		اذهب out;

	/* check magic */
	אם (sshbuf_len(decoded) < حجم(AUTH_MAGIC) ||
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
	החזר r;
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
	u_char *key = عدم, *salt = عدم, *dp;
	u_int blocksize, rounds, nkeys, encrypted_len, check1, check2;

	אם (decoded == عدم || decryptedp == عدم || pubkeyp == عدم)
		החזר SSH_ERR_INVALID_ARGUMENT;

	*decryptedp = عدم;
	*pubkeyp = عدم;

	אם ((decrypted = sshbuf_new()) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}

	/* parse public portion of key */
	אם ((r = sshbuf_consume(decoded, حجم(AUTH_MAGIC))) != 0 ||
	    (r = sshbuf_get_cstring(decoded, &ciphername, عدم)) != 0 ||
	    (r = sshbuf_get_cstring(decoded, &kdfname, عدم)) != 0 ||
	    (r = sshbuf_froms(decoded, &kdf)) != 0 ||
	    (r = sshbuf_get_u32(decoded, &nkeys)) != 0)
		اذهب out;

	אם (nkeys != 1) {
		/* XXX only one key supported at present */
		r = SSH_ERR_INVALID_FORMAT;
		اذهب out;
	}

	אם ((r = sshkey_froms(decoded, &pubkey)) != 0 ||
	    (r = sshbuf_get_u32(decoded, &encrypted_len)) != 0)
		اذهب out;

	אם ((cipher = cipher_by_name(ciphername)) == عدم) {
		r = SSH_ERR_KEY_UNKNOWN_CIPHER;
		اذهب out;
	}
	אם (strcmp(kdfname, "none") != 0 && strcmp(kdfname, "bcrypt") != 0) {
		r = SSH_ERR_KEY_UNKNOWN_CIPHER;
		اذهب out;
	}
	אם (strcmp(kdfname, "none") == 0 && strcmp(ciphername, "none") != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		اذهب out;
	}
	אם ((passphrase == عدم || strlen(passphrase) == 0) &&
	    strcmp(kdfname, "none") != 0) {
		/* passphrase required */
		r = SSH_ERR_KEY_WRONG_PASSPHRASE;
		اذهب out;
	}

	/* check size of encrypted key blob */
	blocksize = cipher_blocksize(cipher);
	אם (encrypted_len < blocksize || (encrypted_len % blocksize) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		اذهب out;
	}

	/* setup key */
	keylen = cipher_keylen(cipher);
	ivlen = cipher_ivlen(cipher);
	authlen = cipher_authlen(cipher);
	אם ((key = calloc(1, keylen + ivlen)) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}
	אם (strcmp(kdfname, "bcrypt") == 0) {
		אם ((r = sshbuf_get_string(kdf, &salt, &slen)) != 0 ||
		    (r = sshbuf_get_u32(kdf, &rounds)) != 0)
			اذهب out;
		אם (rounds > MAX_KDF_ROUNDS) {
			r = SSH_ERR_INVALID_FORMAT;
			اذهب out;
		}
		אם (bcrypt_pbkdf(passphrase, strlen(passphrase), salt, slen,
		    key, keylen + ivlen, rounds) < 0) {
			r = SSH_ERR_INVALID_FORMAT;
			اذهب out;
		}
	}

	/* check that an appropriate amount of auth data is present */
	אם (sshbuf_len(decoded) < authlen ||
	    sshbuf_len(decoded) - authlen < encrypted_len) {
		r = SSH_ERR_INVALID_FORMAT;
		اذهب out;
	}

	/* decrypt private portion of key */
	אם ((r = sshbuf_reserve(decrypted, encrypted_len, &dp)) != 0 ||
	    (r = cipher_init(&ciphercontext, cipher, key, keylen,
	    key + keylen, ivlen, 0)) != 0)
		اذهب out;
	אם ((r = cipher_crypt(ciphercontext, 0, dp, sshbuf_ptr(decoded),
	    encrypted_len, 0, authlen)) != 0) {
		/* an integrity error here indicates an incorrect passphrase */
		אם (r == SSH_ERR_MAC_INVALID)
			r = SSH_ERR_KEY_WRONG_PASSPHRASE;
		اذهب out;
	}
	אם ((r = sshbuf_consume(decoded, encrypted_len + authlen)) != 0)
		اذهب out;
	/* there should be no trailing data */
	אם (sshbuf_len(decoded) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		اذهب out;
	}

	/* check check bytes */
	אם ((r = sshbuf_get_u32(decrypted, &check1)) != 0 ||
	    (r = sshbuf_get_u32(decrypted, &check2)) != 0)
		اذهب out;
	אם (check1 != check2) {
		r = SSH_ERR_KEY_WRONG_PASSPHRASE;
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
	אם (salt != عدم) {
		explicit_bzero(salt, slen);
		حرر(salt);
	}
	אם (key != عدم) {
		explicit_bzero(key, keylen + ivlen);
		حرر(key);
	}
	sshbuf_free(kdf);
	sshbuf_free(decrypted);
	החזר r;
}

ساكن صحيح
sshkey_parse_private2(بنية sshbuf *blob, صحيح type, ثابت حرف *passphrase,
    بنية sshkey **keyp, حرف **commentp)
{
	حرف *comment = عدم;
	صحيح r = SSH_ERR_INTERNAL_ERROR;
	بنية sshbuf *decoded = عدم, *decrypted = عدم;
	بنية sshkey *k = عدم, *pubkey = عدم;

	אם (keyp != عدم)
		*keyp = عدم;
	אם (commentp != عدم)
		*commentp = عدم;

	/* Undo base64 encoding and decrypt the private section */
	אם ((r = private2_uudecode(blob, &decoded)) != 0 ||
	    (r = private2_decrypt(decoded, passphrase,
	    &decrypted, &pubkey)) != 0)
		اذهب out;

	אם (type != KEY_UNSPEC &&
	    sshkey_type_plain(type) != sshkey_type_plain(pubkey->type)) {
		r = SSH_ERR_KEY_TYPE_MISMATCH;
		اذهب out;
	}

	/* Load the private key and comment */
	אם ((r = sshkey_private_deserialize(decrypted, &k)) != 0 ||
	    (r = sshbuf_get_cstring(decrypted, &comment, عدم)) != 0)
		اذهب out;

	/* Check deterministic padding after private section */
	אם ((r = private2_check_padding(decrypted)) != 0)
		اذهب out;

	/* Check that the public key in the envelope matches the private key */
	אם (!sshkey_equal(pubkey, k)) {
		r = SSH_ERR_INVALID_FORMAT;
		اذهب out;
	}

	/* success */
	r = 0;
	אם (keyp != عدم) {
		*keyp = k;
		k = عدم;
	}
	אם (commentp != عدم) {
		*commentp = comment;
		comment = عدم;
	}
 out:
	حرر(comment);
	sshbuf_free(decoded);
	sshbuf_free(decrypted);
	sshkey_free(k);
	sshkey_free(pubkey);
	החזר r;
}

ساكن صحيح
sshkey_parse_private2_pubkey(بنية sshbuf *blob, صحيح type,
    بنية sshkey **keyp)
{
	صحيح r = SSH_ERR_INTERNAL_ERROR;
	بنية sshbuf *decoded = عدم;
	بنية sshkey *pubkey = عدم;
	u_int nkeys = 0;

	אם (keyp != عدم)
		*keyp = عدم;

	אם ((r = private2_uudecode(blob, &decoded)) != 0)
		اذهب out;
	/* parse public key from unencrypted envelope */
	אם ((r = sshbuf_consume(decoded, حجم(AUTH_MAGIC))) != 0 ||
	    (r = sshbuf_skip_string(decoded)) != 0 || /* cipher */
	    (r = sshbuf_skip_string(decoded)) != 0 || /* KDF alg */
	    (r = sshbuf_skip_string(decoded)) != 0 || /* KDF hint */
	    (r = sshbuf_get_u32(decoded, &nkeys)) != 0)
		اذهب out;

	אם (nkeys != 1) {
		/* XXX only one key supported at present */
		r = SSH_ERR_INVALID_FORMAT;
		اذهب out;
	}

	/* Parse the public key */
	אם ((r = sshkey_froms(decoded, &pubkey)) != 0)
		اذهب out;

	אם (type != KEY_UNSPEC &&
	    sshkey_type_plain(type) != sshkey_type_plain(pubkey->type)) {
		r = SSH_ERR_KEY_TYPE_MISMATCH;
		اذهب out;
	}

	/* success */
	r = 0;
	אם (keyp != عدم) {
		*keyp = pubkey;
		pubkey = عدم;
	}
 out:
	sshbuf_free(decoded);
	sshkey_free(pubkey);
	החזר r;
}

#ifdef WITH_OPENSSL
/* convert SSH v2 key to PEM or PKCS#8 format */
ساكن صحيح
sshkey_private_to_blob_pem_pkcs8(بنية sshkey *key, بنية sshbuf *buf,
    صحيح format, ثابت حرف *_passphrase, ثابت حرف *comment)
{
	صحيح was_shielded = sshkey_is_shielded(key);
	صحيح success, r;
	صحيح blen, len = strlen(_passphrase);
	u_char *passphrase = (len > 0) ? (u_char *)_passphrase : عدم;
	ثابت EVP_CIPHER *cipher = (len > 0) ? EVP_aes_128_cbc() : عدم;
	حرف *bptr;
	BIO *bio = عدم;
	بنية sshbuf *blob;
	EVP_PKEY *pkey = عدم;

	אם (len > 0 && len <= 4)
		החזר SSH_ERR_PASSPHRASE_TOO_SHORT;
	אם ((blob = sshbuf_new()) == عدم)
		החזר SSH_ERR_ALLOC_FAIL;
	אם ((bio = BIO_new(BIO_s_mem())) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}
	אם ((r = sshkey_unshield_private(key)) != 0)
		اذهب out;

	بدل (key->type) {
	حالة KEY_ECDSA:
		אם (format == SSHKEY_PRIVATE_PEM) {
			success = PEM_write_bio_ECPrivateKey(bio,
			    EVP_PKEY_get0_EC_KEY(key->pkey),
			    cipher, passphrase, len, عدم, عدم);
		} אחרת {
			pkey = key->pkey;
			EVP_PKEY_up_ref(key->pkey);
			success = 1;
		}
		اكسر;
	حالة KEY_RSA:
		אם (format == SSHKEY_PRIVATE_PEM) {
			success = PEM_write_bio_RSAPrivateKey(bio,
			    EVP_PKEY_get0_RSA(key->pkey),
			    cipher, passphrase, len, عدم, عدم);
		} אחרת {
			pkey = key->pkey;
			EVP_PKEY_up_ref(key->pkey);
			success = 1;
		}
		اكسر;
#ifdef OPENSSL_HAS_ED25519
	حالة KEY_ED25519:
		אם (format == SSHKEY_PRIVATE_PEM) {
			r = SSH_ERR_INVALID_FORMAT;
			اذهب out;
		} אחרת {
			pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519,
			    عدم, key->ed25519_sk,
			    ED25519_SK_SZ - ED25519_PK_SZ);
			success = pkey != عدم;
		}
		اكسر;
#endif
	افتراضي:
		success = 0;
		اكسر;
	}
	אם (success == 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		اذهب out;
	}
	אם (format == SSHKEY_PRIVATE_PKCS8) {
		אם ((success = PEM_write_bio_PrivateKey(bio, pkey, cipher,
		    passphrase, len, عدم, عدم)) == 0) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			اذهب out;
		}
	}
	אם ((blen = BIO_get_mem_data(bio, &bptr)) <= 0) {
		r = SSH_ERR_INTERNAL_ERROR;
		اذهب out;
	}
	אם ((r = sshbuf_put(blob, bptr, blen)) != 0)
		اذهب out;
	r = 0;
 out:
	אם (was_shielded)
		r = sshkey_shield_private(key);
	אם (r == 0)
		r = sshbuf_putb(buf, blob);

	EVP_PKEY_free(pkey);
	sshbuf_free(blob);
	BIO_free(bio);
	החזר r;
}
#endif /* WITH_OPENSSL */

/* Serialise "key" to buffer "blob" */
صحيح
sshkey_private_to_fileblob(بنية sshkey *key, بنية sshbuf *blob,
    ثابت حرف *passphrase, ثابت حرف *comment,
    صحيح format, ثابت حرف *openssh_format_cipher, صحيح openssh_format_rounds)
{
	بدل (key->type) {
#ifdef WITH_OPENSSL
	حالة KEY_ECDSA:
	حالة KEY_RSA:
	حالة KEY_ED25519:
		اكسر; /* see below */
#אחרת /* WITH_OPENSSL */
	حالة KEY_ED25519:
#endif /* WITH_OPENSSL */
	حالة KEY_ED25519_SK:
#ifdef WITH_OPENSSL
	حالة KEY_ECDSA_SK:
#endif /* WITH_OPENSSL */
	حالة KEY_MLDSA44_ED25519:
		החזר sshkey_private_to_blob2(key, blob, passphrase,
		    comment, openssh_format_cipher, openssh_format_rounds);
	افتراضي:
		החזר SSH_ERR_KEY_TYPE_UNKNOWN;
	}

#ifdef WITH_OPENSSL
	بدل (format) {
	حالة SSHKEY_PRIVATE_OPENSSH:
		החזר sshkey_private_to_blob2(key, blob, passphrase,
		    comment, openssh_format_cipher, openssh_format_rounds);
	حالة SSHKEY_PRIVATE_PEM:
	حالة SSHKEY_PRIVATE_PKCS8:
		החזר sshkey_private_to_blob_pem_pkcs8(key, blob,
		    format, passphrase, comment);
	افتراضي:
		החזר SSH_ERR_INVALID_ARGUMENT;
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
			החזר SSH_ERR_KEY_WRONG_PASSPHRASE;
		افتراضي:
			החזר SSH_ERR_INVALID_FORMAT;
		}
	حالة ERR_LIB_EVP:
		بدل (pem_reason) {
#ifdef EVP_R_BAD_DECRYPT
		حالة EVP_R_BAD_DECRYPT:
			החזר SSH_ERR_KEY_WRONG_PASSPHRASE;
#endif
#ifdef EVP_R_BN_DECODE_ERROR
		حالة EVP_R_BN_DECODE_ERROR:
#endif
		حالة EVP_R_DECODE_ERROR:
#ifdef EVP_R_PRIVATE_KEY_DECODE_ERROR
		حالة EVP_R_PRIVATE_KEY_DECODE_ERROR:
#endif
			החזר SSH_ERR_INVALID_FORMAT;
		افتراضي:
			החזר SSH_ERR_LIBCRYPTO_ERROR;
		}
	حالة ERR_LIB_ASN1:
#ifdef ERR_LIB_OSSL_DECODER
	حالة ERR_LIB_OSSL_DECODER:
#endif
		החזר SSH_ERR_INVALID_FORMAT;
	}
	החזר SSH_ERR_LIBCRYPTO_ERROR;
}

ساكن فراغ
clear_libcrypto_errors(فراغ)
{
	כלעוד (ERR_get_error() != 0)
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
	אם (translate_libcrypto_error(ERR_peek_error()) ==
	    SSH_ERR_KEY_WRONG_PASSPHRASE)
		החזר SSH_ERR_KEY_WRONG_PASSPHRASE;
	החזר translate_libcrypto_error(ERR_peek_last_error());
}

ساكن صحيح
pem_passphrase_cb(حرف *buf, صحيح size, صحيح rwflag, فراغ *u)
{
	حرف *p = (حرف *)u;
	size_t len;

	אם (p == عدم || (len = strlen(p)) == 0)
		החזר -1;
	אם (size < 0 || len > (size_t)size)
		החזר -1;
	memcpy(buf, p, len);
	החזר (صحيح)len;
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
	EC_KEY *ecdsa = عدم;

	אם (keyp != عدم)
		*keyp = عدم;

	אם ((bio = BIO_new(BIO_s_mem())) == عدم || sshbuf_len(blob) > INT_MAX)
		החזר SSH_ERR_ALLOC_FAIL;
	אם (BIO_write(bio, sshbuf_ptr(blob), sshbuf_len(blob)) !=
	    (صحيح)sshbuf_len(blob)) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}

	clear_libcrypto_errors();
	אם ((pk = PEM_read_bio_PrivateKey(bio, عدم, pem_passphrase_cb,
	    (حرف *)passphrase)) == عدم) {
		/*
		 * libcrypto may return various ASN.1 errors when attempting
		 * to parse a key with an incorrect passphrase.
		 * Treat all format errors as "incorrect passphrase" if a
		 * passphrase was supplied.
		 */
		אם (passphrase != عدم && *passphrase != '\0')
			r = SSH_ERR_KEY_WRONG_PASSPHRASE;
		אחרת
			r = convert_libcrypto_error();
		اذهب out;
	}
	אם (EVP_PKEY_base_id(pk) == EVP_PKEY_RSA &&
	    (type == KEY_UNSPEC || type == KEY_RSA)) {
		אם ((prv = sshkey_new(KEY_UNSPEC)) == عدم) {
			r = SSH_ERR_ALLOC_FAIL;
			اذهب out;
		}
		אם ((rsa = EVP_PKEY_get1_RSA(pk)) == عدم) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			اذهب out;
		}
		prv->type = KEY_RSA;
#ifdef DEBUG_PK
		RSA_print_fp(stderr, rsa, 8);
#endif
		אם (RSA_blinding_on(rsa, عدم) != 1 ||
		    EVP_PKEY_set1_RSA(pk, rsa) != 1) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			اذهب out;
		}
		EVP_PKEY_up_ref(pk);
		prv->pkey = pk;
		אם ((r = sshkey_check_rsa_length(prv, 0)) != 0)
			اذهب out;
	} אחרת אם (EVP_PKEY_base_id(pk) == EVP_PKEY_EC &&
	    (type == KEY_UNSPEC || type == KEY_ECDSA)) {
		אם ((prv = sshkey_new(KEY_UNSPEC)) == عدم) {
			r = SSH_ERR_ALLOC_FAIL;
			اذهب out;
		}
		אם ((prv->ecdsa_nid = sshkey_ecdsa_fixup_group(pk)) == -1 ||
		    (ecdsa = EVP_PKEY_get1_EC_KEY(pk)) == عدم) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			اذهب out;
		}
		prv->type = KEY_ECDSA;
		אם (sshkey_curve_nid_to_name(prv->ecdsa_nid) == عدم ||
		    sshkey_ec_validate_public(EC_KEY_get0_group(ecdsa),
		    EC_KEY_get0_public_key(ecdsa)) != 0 ||
		    sshkey_ec_validate_private(ecdsa) != 0) {
			r = SSH_ERR_INVALID_FORMAT;
			اذهب out;
		}
		EVP_PKEY_up_ref(pk);
		prv->pkey = pk;
#ifdef DEBUG_PK
		אם (prv != عدم && prv->pkey != عدم)
			sshkey_dump_ec_key(EVP_PKEY_get0_EC_KEY(prv->pkey));
#endif
#ifdef OPENSSL_HAS_ED25519
	} אחרת אם (EVP_PKEY_base_id(pk) == EVP_PKEY_ED25519 &&
	    (type == KEY_UNSPEC || type == KEY_ED25519)) {
		size_t len;

		אם ((prv = sshkey_new(KEY_UNSPEC)) == عدم ||
		    (prv->ed25519_sk = calloc(1, ED25519_SK_SZ)) == عدم ||
		    (prv->ed25519_pk = calloc(1, ED25519_PK_SZ)) == عدم) {
			r = SSH_ERR_ALLOC_FAIL;
			اذهب out;
		}
		prv->type = KEY_ED25519;
		len = ED25519_PK_SZ;
		אם (!EVP_PKEY_get_raw_public_key(pk, prv->ed25519_pk, &len)) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			اذهب out;
		}
		אם (len != ED25519_PK_SZ) {
			r = SSH_ERR_INVALID_FORMAT;
			اذهب out;
		}
		len = ED25519_SK_SZ - ED25519_PK_SZ;
		אם (!EVP_PKEY_get_raw_private_key(pk, prv->ed25519_sk, &len)) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			اذهب out;
		}
		אם (len != ED25519_SK_SZ - ED25519_PK_SZ) {
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
	} אחרת {
		r = SSH_ERR_INVALID_FORMAT;
		اذهب out;
	}
	r = 0;
	אם (keyp != عدم) {
		*keyp = prv;
		prv = عدم;
	}
 out:
	BIO_free(bio);
	EVP_PKEY_free(pk);
	RSA_free(rsa);
	EC_KEY_free(ecdsa);
	sshkey_free(prv);
	החזר r;
}
#endif /* WITH_OPENSSL */

صحيح
sshkey_parse_private_fileblob_type(بنية sshbuf *blob, صحيح type,
    ثابت حرف *passphrase, بنية sshkey **keyp, حرف **commentp)
{
	صحيح r = SSH_ERR_INTERNAL_ERROR;

	אם (keyp != عدم)
		*keyp = عدم;
	אם (commentp != عدم)
		*commentp = عدم;

	r = sshkey_parse_private2(blob, type, passphrase, keyp, commentp);
	/* Only fallback to PEM parser if a format error occurred. */
	אם (r != SSH_ERR_INVALID_FORMAT)
		החזר r;
#ifdef WITH_OPENSSL
	החזר sshkey_parse_private_pem_fileblob(blob, type,
	    passphrase, keyp);
#אחרת
	החזר SSH_ERR_INVALID_FORMAT;
#endif /* WITH_OPENSSL */
}

صحيح
sshkey_parse_private_fileblob(بنية sshbuf *buffer, ثابت حرف *passphrase,
    بنية sshkey **keyp, حرف **commentp)
{
	אם (keyp != عدم)
		*keyp = عدم;
	אם (commentp != عدم)
		*commentp = عدم;

	החזר sshkey_parse_private_fileblob_type(buffer, KEY_UNSPEC,
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

	אם (pubkeyp != عدم)
		*pubkeyp = عدم;
	/* only new-format private keys bundle a public key inside */
	אם ((r = sshkey_parse_private2_pubkey(blob, type, pubkeyp)) != 0)
		החזר r;
	החזר 0;
}
