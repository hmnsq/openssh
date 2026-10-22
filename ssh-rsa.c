/* $OpenBSD: ssh-rsa.c,v 1.84 2026/02/14 00:18:34 jsg Exp $ */
/*
 * Copyright (c) 2000, 2003 Markus Friedl <markus@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "includes.h"

#ifdef WITH_OPENSSL
#include "openbsd-compat/openssl-compat.h"

#include <sys/types.h>

#include <openssl/bn.h>
#include <openssl/evp.h>

#include <stdarg.h>
#include <string.h>

#include "sshbuf.h"
#include "ssherr.h"
#define SSHKEY_INTERNAL
#include "sshkey.h"
#include "digest.h"

static u_int
ssh_rsa_size(const struct sshkey *k)
{
	만약 (k->pkey == NULL)
		반환 0;
	반환 EVP_PKEY_bits(k->pkey);
}

static 정수
ssh_rsa_alloc(struct sshkey *k)
{
	만약 ((k->pkey = EVP_PKEY_new()) == NULL)
		반환 SSH_ERR_ALLOC_FAIL;
	반환 0;
}

static void
ssh_rsa_cleanup(struct sshkey *k)
{
	EVP_PKEY_free(k->pkey);
	k->pkey = NULL;
}

static 정수
ssh_rsa_equal(const struct sshkey *a, const struct sshkey *b)
{
	만약 (a->pkey == NULL || b->pkey == NULL)
		반환 0;
	반환 EVP_PKEY_cmp(a->pkey, b->pkey) == 1;
}

static 정수
ssh_rsa_serialize_public(const struct sshkey *key, struct sshbuf *b,
    enum sshkey_serialize_rep opts)
{
	정수 r;
	const BIGNUM *rsa_n, *rsa_e;
	const RSA *rsa;

	만약 (key->pkey == NULL)
		반환 SSH_ERR_INVALID_ARGUMENT;
	만약 ((rsa = EVP_PKEY_get0_RSA(key->pkey)) == NULL)
		반환 SSH_ERR_LIBCRYPTO_ERROR;

	RSA_get0_key(rsa, &rsa_n, &rsa_e, NULL);
	만약 ((r = sshbuf_put_bignum2(b, rsa_e)) != 0 ||
	    (r = sshbuf_put_bignum2(b, rsa_n)) != 0)
		반환 r;

	반환 0;
}

static 정수
ssh_rsa_serialize_private(const struct sshkey *key, struct sshbuf *b,
    enum sshkey_serialize_rep opts)
{
	정수 r;
	const BIGNUM *rsa_n, *rsa_e, *rsa_d, *rsa_iqmp, *rsa_p, *rsa_q;
	const RSA *rsa;

	만약 ((rsa = EVP_PKEY_get0_RSA(key->pkey)) == NULL)
		반환 SSH_ERR_LIBCRYPTO_ERROR;
	RSA_get0_key(rsa, &rsa_n, &rsa_e, &rsa_d);
	RSA_get0_factors(rsa, &rsa_p, &rsa_q);
	RSA_get0_crt_params(rsa, NULL, NULL, &rsa_iqmp);

	만약 (!sshkey_is_cert(key)) {
		/* Note: can't reuse ssh_rsa_serialize_public: e, n vs. n, e */
		만약 ((r = sshbuf_put_bignum2(b, rsa_n)) != 0 ||
		    (r = sshbuf_put_bignum2(b, rsa_e)) != 0)
			반환 r;
	}
	만약 ((r = sshbuf_put_bignum2(b, rsa_d)) != 0 ||
	    (r = sshbuf_put_bignum2(b, rsa_iqmp)) != 0 ||
	    (r = sshbuf_put_bignum2(b, rsa_p)) != 0 ||
	    (r = sshbuf_put_bignum2(b, rsa_q)) != 0)
		반환 r;

	반환 0;
}

static 정수
ssh_rsa_generate(struct sshkey *k, 정수 bits)
{
	EVP_PKEY_CTX *ctx = NULL;
	EVP_PKEY *res = NULL;

	정수 ret = SSH_ERR_INTERNAL_ERROR;

	만약 (bits < SSH_RSA_MINIMUM_MODULUS_SIZE ||
	    bits > SSHBUF_MAX_BIGNUM * 8)
		반환 SSH_ERR_KEY_LENGTH;

	만약 ((ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL)) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	만약 (EVP_PKEY_keygen_init(ctx) <= 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	만약 (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0) {
		ret = SSH_ERR_KEY_LENGTH;
		goto out;
	}
	만약 (EVP_PKEY_keygen(ctx, &res) <= 0 || res == NULL) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	/* success */
	k->pkey = res;
	ret = 0;
 out:
	EVP_PKEY_CTX_free(ctx);
	반환 ret;
}

static 정수
ssh_rsa_copy_public(const struct sshkey *from, struct sshkey *to)
{
	const BIGNUM *rsa_n, *rsa_e;
	BIGNUM *rsa_n_dup = NULL, *rsa_e_dup = NULL;
	정수 r = SSH_ERR_INTERNAL_ERROR;
	const RSA *rsa_from;
	RSA *rsa_to = NULL;

	만약 ((rsa_from = EVP_PKEY_get0_RSA(from->pkey)) == NULL ||
	    (rsa_to = RSA_new()) == NULL)
		반환 SSH_ERR_LIBCRYPTO_ERROR;

	RSA_get0_key(rsa_from, &rsa_n, &rsa_e, NULL);
	만약 ((rsa_n_dup = BN_dup(rsa_n)) == NULL ||
	    (rsa_e_dup = BN_dup(rsa_e)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	만약 (!RSA_set0_key(rsa_to, rsa_n_dup, rsa_e_dup, NULL)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	rsa_n_dup = rsa_e_dup = NULL; /* transferred */

	만약 (EVP_PKEY_set1_RSA(to->pkey, rsa_to) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	/* success */
	r = 0;
 out:
	RSA_free(rsa_to);
	BN_clear_free(rsa_n_dup);
	BN_clear_free(rsa_e_dup);
	반환 r;
}

static 정수
ssh_rsa_deserialize_public(const char *ktype, struct sshbuf *b,
    struct sshkey *key)
{
	정수 ret = SSH_ERR_INTERNAL_ERROR;
	BIGNUM *rsa_n = NULL, *rsa_e = NULL;
	RSA *rsa = NULL;

	만약 ((rsa = RSA_new()) == NULL)
		반환 SSH_ERR_LIBCRYPTO_ERROR;

	만약 (sshbuf_get_bignum2(b, &rsa_e) != 0 ||
	    sshbuf_get_bignum2(b, &rsa_n) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	만약 (!RSA_set0_key(rsa, rsa_n, rsa_e, NULL)) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	rsa_n = rsa_e = NULL; /* transferred */
	만약 (EVP_PKEY_set1_RSA(key->pkey, rsa) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	만약 ((ret = sshkey_check_rsa_length(key, 0)) != 0)
		goto out;
#ifdef DEBUG_PK
	RSA_print_fp(stderr, rsa, 8);
#endif
	/* success */
	ret = 0;
 out:
	RSA_free(rsa);
	BN_clear_free(rsa_n);
	BN_clear_free(rsa_e);
	반환 ret;
}

static 정수
ssh_rsa_deserialize_private(const char *ktype, struct sshbuf *b,
    struct sshkey *key)
{
	정수 r;
	BIGNUM *rsa_n = NULL, *rsa_e = NULL, *rsa_d = NULL;
	BIGNUM *rsa_iqmp = NULL, *rsa_p = NULL, *rsa_q = NULL;
	BIGNUM *rsa_dmp1 = NULL, *rsa_dmq1 = NULL;
	RSA *rsa = NULL;

	만약 (sshkey_is_cert(key)) {
		/* sshkey_private_deserialize already has pubkey from cert */
		만약 ((rsa = EVP_PKEY_get1_RSA(key->pkey)) == NULL) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			goto out;
		}
	} 아니면 {
		만약 ((rsa = RSA_new()) == NULL) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			goto out;
		}
		/* Note: can't reuse ssh_rsa_deserialize_public: e,n vs. n,e */
		만약 ((r = sshbuf_get_bignum2(b, &rsa_n)) != 0 ||
		    (r = sshbuf_get_bignum2(b, &rsa_e)) != 0)
			goto out;
		만약 (!RSA_set0_key(rsa, rsa_n, rsa_e, NULL)) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			goto out;
		}
		rsa_n = rsa_e = NULL; /* transferred */
	}
	만약 ((r = sshbuf_get_bignum2(b, &rsa_d)) != 0 ||
	    (r = sshbuf_get_bignum2(b, &rsa_iqmp)) != 0 ||
	    (r = sshbuf_get_bignum2(b, &rsa_p)) != 0 ||
	    (r = sshbuf_get_bignum2(b, &rsa_q)) != 0)
		goto out;
	만약 ((r = ssh_rsa_complete_crt_parameters(rsa_d, rsa_p, rsa_q,
	    rsa_iqmp, &rsa_dmp1, &rsa_dmq1)) != 0)
		goto out;
	만약 (!RSA_set0_key(rsa, NULL, NULL, rsa_d)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	rsa_d = NULL; /* transferred */
	만약 (!RSA_set0_factors(rsa, rsa_p, rsa_q)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	rsa_p = rsa_q = NULL; /* transferred */
	만약 (!RSA_set0_crt_params(rsa, rsa_dmp1, rsa_dmq1, rsa_iqmp)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	rsa_dmp1 = rsa_dmq1 = rsa_iqmp = NULL;
	만약 (RSA_blinding_on(rsa, NULL) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	만약 (EVP_PKEY_set1_RSA(key->pkey, rsa) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	만약 ((r = sshkey_check_rsa_length(key, 0)) != 0)
		goto out;
	/* success */
	r = 0;
 out:
	RSA_free(rsa);
	BN_clear_free(rsa_n);
	BN_clear_free(rsa_e);
	BN_clear_free(rsa_d);
	BN_clear_free(rsa_p);
	BN_clear_free(rsa_q);
	BN_clear_free(rsa_iqmp);
	BN_clear_free(rsa_dmp1);
	BN_clear_free(rsa_dmq1);
	반환 r;
}

const char *
ssh_rsa_hash_alg_ident(정수 hash_alg)
{
	switch (hash_alg) {
	case SSH_DIGEST_SHA1:
		반환 "ssh-rsa";
	case SSH_DIGEST_SHA256:
		반환 "rsa-sha2-256";
	case SSH_DIGEST_SHA512:
		반환 "rsa-sha2-512";
	}
	반환 NULL;
}

/*
 * Returns the hash algorithm ID for a given algorithm identifier as used
 * inside the signature blob,
 */
static 정수
rsa_hash_id_from_ident(const char *ident)
{
	만약 (strcmp(ident, "ssh-rsa") == 0)
		반환 SSH_DIGEST_SHA1;
	만약 (strcmp(ident, "rsa-sha2-256") == 0)
		반환 SSH_DIGEST_SHA256;
	만약 (strcmp(ident, "rsa-sha2-512") == 0)
		반환 SSH_DIGEST_SHA512;
	반환 -1;
}

/*
 * Return the hash algorithm ID for the specified key name. This includes
 * all the cases of rsa_hash_id_from_ident() but also the certificate key
 * types.
 */
정수
ssh_rsa_hash_id_from_keyname(const char *alg)
{
	정수 r;

	만약 ((r = rsa_hash_id_from_ident(alg)) != -1)
		반환 r;
	만약 (strcmp(alg, "ssh-rsa-cert-v01@openssh.com") == 0)
		반환 SSH_DIGEST_SHA1;
	만약 (strcmp(alg, "rsa-sha2-256-cert-v01@openssh.com") == 0)
		반환 SSH_DIGEST_SHA256;
	만약 (strcmp(alg, "rsa-sha2-512-cert-v01@openssh.com") == 0)
		반환 SSH_DIGEST_SHA512;
	반환 -1;
}

정수
ssh_rsa_complete_crt_parameters(const BIGNUM *rsa_d, const BIGNUM *rsa_p,
    const BIGNUM *rsa_q, const BIGNUM *rsa_iqmp, BIGNUM **rsa_dmp1,
    BIGNUM **rsa_dmq1)
{
	BIGNUM *aux = NULL, *d_consttime = NULL;
	BN_CTX *ctx = NULL;
	정수 r;

	*rsa_dmq1 = *rsa_dmp1 = NULL;
	만약 ((ctx = BN_CTX_new()) == NULL)
		반환 SSH_ERR_ALLOC_FAIL;
	만약 ((aux = BN_new()) == NULL ||
	    (*rsa_dmq1 = BN_new()) == NULL ||
	    (*rsa_dmp1 = BN_new()) == NULL)
		반환 SSH_ERR_ALLOC_FAIL;
	만약 ((d_consttime = BN_dup(rsa_d)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	BN_set_flags(aux, BN_FLG_CONSTTIME);
	BN_set_flags(d_consttime, BN_FLG_CONSTTIME);

	만약 ((BN_sub(aux, rsa_q, BN_value_one()) == 0) ||
	    (BN_mod(*rsa_dmq1, d_consttime, aux, ctx) == 0) ||
	    (BN_sub(aux, rsa_p, BN_value_one()) == 0) ||
	    (BN_mod(*rsa_dmp1, d_consttime, aux, ctx) == 0)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	/* success */
	r = 0;
 out:
	BN_clear_free(aux);
	BN_clear_free(d_consttime);
	BN_CTX_free(ctx);
	반환 r;
}

/* RSASSA-PKCS1-v1_5 (PKCS #1 v2.0 signature) with SHA1 */
static 정수
ssh_rsa_sign(struct sshkey *key,
    u_char **sigp, size_t *lenp,
    const u_char *data, size_t datalen,
    const char *alg, const char *sk_provider, const char *sk_pin, u_int compat)
{
	u_char *sig = NULL;
	size_t diff, len = 0;
	정수 slen = 0;
	정수 hash_alg, ret = SSH_ERR_INTERNAL_ERROR;

	만약 (lenp != NULL)
		*lenp = 0;
	만약 (sigp != NULL)
		*sigp = NULL;

	만약 (alg == NULL || strlen(alg) == 0)
		hash_alg = SSH_DIGEST_SHA1;
	아니면
		hash_alg = ssh_rsa_hash_id_from_keyname(alg);

	만약 (key == NULL || key->pkey == NULL || hash_alg == -1 ||
	    sshkey_type_plain(key->type) != KEY_RSA)
		반환 SSH_ERR_INVALID_ARGUMENT;
	slen = EVP_PKEY_size(key->pkey);
	만약 (slen <= 0 || slen > SSHBUF_MAX_BIGNUM)
		반환 SSH_ERR_INVALID_ARGUMENT;
	만약 (EVP_PKEY_bits(key->pkey) < SSH_RSA_MINIMUM_MODULUS_SIZE)
		반환 SSH_ERR_KEY_LENGTH;

	만약 ((ret = sshkey_pkey_digest_sign(key->pkey, hash_alg, &sig, &len,
	    data, datalen)) < 0)
		goto out;
	만약 (len < (size_t)slen) {
		diff = slen - len;
		memmove(sig + diff, sig, len);
		explicit_bzero(sig, diff);
	} 아니면 만약 (len > (size_t)slen) {
		ret = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}
	만약 ((ret = ssh_rsa_encode_store_sig(hash_alg, sig, slen,
	    sigp, lenp)) != 0)
		goto out;

	/* success */
	ret = 0;
 out:
	freezero(sig, slen);
	반환 ret;
}

정수
ssh_rsa_encode_store_sig(정수 hash_alg, const u_char *sig, size_t slen,
    u_char **sigp, size_t *lenp)
{
	struct sshbuf *b = NULL;
	정수 ret = SSH_ERR_INTERNAL_ERROR;
	size_t len;

	만약 (lenp != NULL)
		*lenp = 0;
	만약 (sigp != NULL)
		*sigp = NULL;

	/* Encode signature */
	만약 ((b = sshbuf_new()) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	만약 ((ret = sshbuf_put_cstring(b,
	    ssh_rsa_hash_alg_ident(hash_alg))) != 0 ||
	    (ret = sshbuf_put_string(b, sig, slen)) != 0)
		goto out;
	len = sshbuf_len(b);

	/* Store signature */
	만약 (sigp != NULL) {
		만약 ((*sigp = malloc(len)) == NULL) {
			ret = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		memcpy(*sigp, sshbuf_ptr(b), len);
	}
	만약 (lenp != NULL)
		*lenp = len;
	ret = 0;
 out:
	sshbuf_free(b);
	반환 ret;
}

static 정수
ssh_rsa_verify(const struct sshkey *key,
    const u_char *sig, size_t siglen,
    const u_char *data, size_t dlen, const char *alg, u_int compat,
    struct sshkey_sig_details **detailsp)
{
	char *sigtype = NULL;
	정수 hash_alg, want_alg, ret = SSH_ERR_INTERNAL_ERROR;
	size_t len = 0, diff, modlen, rsasize;
	struct sshbuf *b = NULL;
	u_char digest[SSH_DIGEST_MAX_LENGTH], *osigblob, *sigblob = NULL;

	만약 (key == NULL || key->pkey == NULL ||
	    sshkey_type_plain(key->type) != KEY_RSA ||
	    sig == NULL || siglen == 0)
		반환 SSH_ERR_INVALID_ARGUMENT;
	만약 (EVP_PKEY_bits(key->pkey) < SSH_RSA_MINIMUM_MODULUS_SIZE)
		반환 SSH_ERR_KEY_LENGTH;

	만약 ((b = sshbuf_from(sig, siglen)) == NULL)
		반환 SSH_ERR_ALLOC_FAIL;
	만약 (sshbuf_get_cstring(b, &sigtype, NULL) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	만약 ((hash_alg = rsa_hash_id_from_ident(sigtype)) == -1) {
		ret = SSH_ERR_KEY_TYPE_MISMATCH;
		goto out;
	}
	/*
	 * Allow ssh-rsa-cert-v01 certs to generate SHA2 signatures for
	 * legacy reasons, but otherwise the signature type should match.
	 */
	만약 (alg != NULL && strcmp(alg, "ssh-rsa-cert-v01@openssh.com") != 0) {
		만약 ((want_alg = ssh_rsa_hash_id_from_keyname(alg)) == -1) {
			ret = SSH_ERR_INVALID_ARGUMENT;
			goto out;
		}
		만약 (hash_alg != want_alg) {
			ret = SSH_ERR_SIGNATURE_INVALID;
			goto out;
		}
	}
	만약 (sshbuf_get_string(b, &sigblob, &len) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	만약 (sshbuf_len(b) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		goto out;
	}
	/* RSA_verify expects a signature of RSA_size */
	modlen = EVP_PKEY_size(key->pkey);
	만약 (len > modlen) {
		ret = SSH_ERR_KEY_BITS_MISMATCH;
		goto out;
	} 아니면 만약 (len < modlen) {
		diff = modlen - len;
		osigblob = sigblob;
		만약 ((sigblob = realloc(sigblob, modlen)) == NULL) {
			sigblob = osigblob; /* put it back for clear/free */
			ret = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		memmove(sigblob + diff, sigblob, len);
		explicit_bzero(sigblob, diff);
		len = modlen;
	}

	rsasize = EVP_PKEY_size(key->pkey);
	만약 (rsasize <= 0 || rsasize > SSHBUF_MAX_BIGNUM ||
	    len == 0 || len > rsasize) {
		ret = SSH_ERR_INVALID_ARGUMENT;
		goto out;
	}
	ret = sshkey_pkey_digest_verify(key->pkey, hash_alg, data, dlen,
	    sigblob, len);

 out:
	freezero(sigblob, len);
	free(sigtype);
	sshbuf_free(b);
	explicit_bzero(digest, sizeof(digest));
	반환 ret;
}

static const struct sshkey_impl_funcs sshkey_rsa_funcs = {
	/* .size = */		ssh_rsa_size,
	/* .alloc = */		ssh_rsa_alloc,
	/* .cleanup = */	ssh_rsa_cleanup,
	/* .equal = */		ssh_rsa_equal,
	/* .ssh_serialize_public = */ ssh_rsa_serialize_public,
	/* .ssh_deserialize_public = */ ssh_rsa_deserialize_public,
	/* .ssh_serialize_private = */ ssh_rsa_serialize_private,
	/* .ssh_deserialize_private = */ ssh_rsa_deserialize_private,
	/* .generate = */	ssh_rsa_generate,
	/* .copy_public = */	ssh_rsa_copy_public,
	/* .sign = */		ssh_rsa_sign,
	/* .verify = */		ssh_rsa_verify,
};

const struct sshkey_impl sshkey_rsa_impl = {
	/* .name = */		"ssh-rsa",
	/* .shortname = */	"RSA",
	/* .sigalg = */		NULL,
	/* .type = */		KEY_RSA,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};

const struct sshkey_impl sshkey_rsa_cert_impl = {
	/* .name = */		"ssh-rsa-cert-v01@openssh.com",
	/* .shortname = */	"RSA-CERT",
	/* .sigalg = */		NULL,
	/* .type = */		KEY_RSA_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};

/* SHA2 signature algorithms */

const struct sshkey_impl sshkey_rsa_sha256_impl = {
	/* .name = */		"rsa-sha2-256",
	/* .shortname = */	"RSA",
	/* .sigalg = */		NULL,
	/* .type = */		KEY_RSA,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	1,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};

const struct sshkey_impl sshkey_rsa_sha512_impl = {
	/* .name = */		"rsa-sha2-512",
	/* .shortname = */	"RSA",
	/* .sigalg = */		NULL,
	/* .type = */		KEY_RSA,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	1,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};

const struct sshkey_impl sshkey_rsa_sha256_cert_impl = {
	/* .name = */		"rsa-sha2-256-cert-v01@openssh.com",
	/* .shortname = */	"RSA-CERT",
	/* .sigalg = */		"rsa-sha2-256",
	/* .type = */		KEY_RSA_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	1,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};

const struct sshkey_impl sshkey_rsa_sha512_cert_impl = {
	/* .name = */		"rsa-sha2-512-cert-v01@openssh.com",
	/* .shortname = */	"RSA-CERT",
	/* .sigalg = */		"rsa-sha2-512",
	/* .type = */		KEY_RSA_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	1,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};
#endif /* WITH_OPENSSL */
