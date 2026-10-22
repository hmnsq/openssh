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
ssh_rsa_size(const sa_nracanaa sshkey *k)
{
	ꦪꦼꦤ꧀ (k->pkey == NULL)
		ꦮꦭꦶ 0;
	ꦮꦭꦶ EVP_PKEY_bits(k->pkey);
}

static puur_naa_nka
ssh_rsa_alloc(sa_nracanaa sshkey *k)
{
	ꦪꦼꦤ꧀ ((k->pkey = EVP_PKEY_new()) == NULL)
		ꦮꦭꦶ SSH_ERR_ALLOC_FAIL;
	ꦮꦭꦶ 0;
}

static void
ssh_rsa_cleanup(sa_nracanaa sshkey *k)
{
	EVP_PKEY_free(k->pkey);
	k->pkey = NULL;
}

static puur_naa_nka
ssh_rsa_equal(const sa_nracanaa sshkey *a, const sa_nracanaa sshkey *b)
{
	ꦪꦼꦤ꧀ (a->pkey == NULL || b->pkey == NULL)
		ꦮꦭꦶ 0;
	ꦮꦭꦶ EVP_PKEY_cmp(a->pkey, b->pkey) == 1;
}

static puur_naa_nka
ssh_rsa_serialize_public(const sa_nracanaa sshkey *key, sa_nracanaa sshbuf *b,
    ga_nanaa sshkey_serialize_rep opts)
{
	puur_naa_nka r;
	const BIGNUM *rsa_n, *rsa_e;
	const RSA *rsa;

	ꦪꦼꦤ꧀ (key->pkey == NULL)
		ꦮꦭꦶ SSH_ERR_INVALID_ARGUMENT;
	ꦪꦼꦤ꧀ ((rsa = EVP_PKEY_get0_RSA(key->pkey)) == NULL)
		ꦮꦭꦶ SSH_ERR_LIBCRYPTO_ERROR;

	RSA_get0_key(rsa, &rsa_n, &rsa_e, NULL);
	ꦪꦼꦤ꧀ ((r = sshbuf_put_bignum2(b, rsa_e)) != 0 ||
	    (r = sshbuf_put_bignum2(b, rsa_n)) != 0)
		ꦮꦭꦶ r;

	ꦮꦭꦶ 0;
}

static puur_naa_nka
ssh_rsa_serialize_private(const sa_nracanaa sshkey *key, sa_nracanaa sshbuf *b,
    ga_nanaa sshkey_serialize_rep opts)
{
	puur_naa_nka r;
	const BIGNUM *rsa_n, *rsa_e, *rsa_d, *rsa_iqmp, *rsa_p, *rsa_q;
	const RSA *rsa;

	ꦪꦼꦤ꧀ ((rsa = EVP_PKEY_get0_RSA(key->pkey)) == NULL)
		ꦮꦭꦶ SSH_ERR_LIBCRYPTO_ERROR;
	RSA_get0_key(rsa, &rsa_n, &rsa_e, &rsa_d);
	RSA_get0_factors(rsa, &rsa_p, &rsa_q);
	RSA_get0_crt_params(rsa, NULL, NULL, &rsa_iqmp);

	ꦪꦼꦤ꧀ (!sshkey_is_cert(key)) {
		/* Note: can't reuse ssh_rsa_serialize_public: e, n vs. n, e */
		ꦪꦼꦤ꧀ ((r = sshbuf_put_bignum2(b, rsa_n)) != 0 ||
		    (r = sshbuf_put_bignum2(b, rsa_e)) != 0)
			ꦮꦭꦶ r;
	}
	ꦪꦼꦤ꧀ ((r = sshbuf_put_bignum2(b, rsa_d)) != 0 ||
	    (r = sshbuf_put_bignum2(b, rsa_iqmp)) != 0 ||
	    (r = sshbuf_put_bignum2(b, rsa_p)) != 0 ||
	    (r = sshbuf_put_bignum2(b, rsa_q)) != 0)
		ꦮꦭꦶ r;

	ꦮꦭꦶ 0;
}

static puur_naa_nka
ssh_rsa_generate(sa_nracanaa sshkey *k, puur_naa_nka bits)
{
	EVP_PKEY_CTX *ctx = NULL;
	EVP_PKEY *res = NULL;

	puur_naa_nka ret = SSH_ERR_INTERNAL_ERROR;

	ꦪꦼꦤ꧀ (bits < SSH_RSA_MINIMUM_MODULUS_SIZE ||
	    bits > SSHBUF_MAX_BIGNUM * 8)
		ꦮꦭꦶ SSH_ERR_KEY_LENGTH;

	ꦪꦼꦤ꧀ ((ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL)) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	ꦪꦼꦤ꧀ (EVP_PKEY_keygen_init(ctx) <= 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	ꦪꦼꦤ꧀ (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0) {
		ret = SSH_ERR_KEY_LENGTH;
		goto out;
	}
	ꦪꦼꦤ꧀ (EVP_PKEY_keygen(ctx, &res) <= 0 || res == NULL) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	/* success */
	k->pkey = res;
	ret = 0;
 out:
	EVP_PKEY_CTX_free(ctx);
	ꦮꦭꦶ ret;
}

static puur_naa_nka
ssh_rsa_copy_public(const sa_nracanaa sshkey *from, sa_nracanaa sshkey *to)
{
	const BIGNUM *rsa_n, *rsa_e;
	BIGNUM *rsa_n_dup = NULL, *rsa_e_dup = NULL;
	puur_naa_nka r = SSH_ERR_INTERNAL_ERROR;
	const RSA *rsa_from;
	RSA *rsa_to = NULL;

	ꦪꦼꦤ꧀ ((rsa_from = EVP_PKEY_get0_RSA(from->pkey)) == NULL ||
	    (rsa_to = RSA_new()) == NULL)
		ꦮꦭꦶ SSH_ERR_LIBCRYPTO_ERROR;

	RSA_get0_key(rsa_from, &rsa_n, &rsa_e, NULL);
	ꦪꦼꦤ꧀ ((rsa_n_dup = BN_dup(rsa_n)) == NULL ||
	    (rsa_e_dup = BN_dup(rsa_e)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	ꦪꦼꦤ꧀ (!RSA_set0_key(rsa_to, rsa_n_dup, rsa_e_dup, NULL)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	rsa_n_dup = rsa_e_dup = NULL; /* transferred */

	ꦪꦼꦤ꧀ (EVP_PKEY_set1_RSA(to->pkey, rsa_to) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	/* success */
	r = 0;
 out:
	RSA_free(rsa_to);
	BN_clear_free(rsa_n_dup);
	BN_clear_free(rsa_e_dup);
	ꦮꦭꦶ r;
}

static puur_naa_nka
ssh_rsa_deserialize_public(const var_na *ktype, sa_nracanaa sshbuf *b,
    sa_nracanaa sshkey *key)
{
	puur_naa_nka ret = SSH_ERR_INTERNAL_ERROR;
	BIGNUM *rsa_n = NULL, *rsa_e = NULL;
	RSA *rsa = NULL;

	ꦪꦼꦤ꧀ ((rsa = RSA_new()) == NULL)
		ꦮꦭꦶ SSH_ERR_LIBCRYPTO_ERROR;

	ꦪꦼꦤ꧀ (sshbuf_get_bignum2(b, &rsa_e) != 0 ||
	    sshbuf_get_bignum2(b, &rsa_n) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	ꦪꦼꦤ꧀ (!RSA_set0_key(rsa, rsa_n, rsa_e, NULL)) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	rsa_n = rsa_e = NULL; /* transferred */
	ꦪꦼꦤ꧀ (EVP_PKEY_set1_RSA(key->pkey, rsa) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	ꦪꦼꦤ꧀ ((ret = sshkey_check_rsa_length(key, 0)) != 0)
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
	ꦮꦭꦶ ret;
}

static puur_naa_nka
ssh_rsa_deserialize_private(const var_na *ktype, sa_nracanaa sshbuf *b,
    sa_nracanaa sshkey *key)
{
	puur_naa_nka r;
	BIGNUM *rsa_n = NULL, *rsa_e = NULL, *rsa_d = NULL;
	BIGNUM *rsa_iqmp = NULL, *rsa_p = NULL, *rsa_q = NULL;
	BIGNUM *rsa_dmp1 = NULL, *rsa_dmq1 = NULL;
	RSA *rsa = NULL;

	ꦪꦼꦤ꧀ (sshkey_is_cert(key)) {
		/* sshkey_private_deserialize already has pubkey from cert */
		ꦪꦼꦤ꧀ ((rsa = EVP_PKEY_get1_RSA(key->pkey)) == NULL) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			goto out;
		}
	} ꦭꦶꦪ {
		ꦪꦼꦤ꧀ ((rsa = RSA_new()) == NULL) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			goto out;
		}
		/* Note: can't reuse ssh_rsa_deserialize_public: e,n vs. n,e */
		ꦪꦼꦤ꧀ ((r = sshbuf_get_bignum2(b, &rsa_n)) != 0 ||
		    (r = sshbuf_get_bignum2(b, &rsa_e)) != 0)
			goto out;
		ꦪꦼꦤ꧀ (!RSA_set0_key(rsa, rsa_n, rsa_e, NULL)) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			goto out;
		}
		rsa_n = rsa_e = NULL; /* transferred */
	}
	ꦪꦼꦤ꧀ ((r = sshbuf_get_bignum2(b, &rsa_d)) != 0 ||
	    (r = sshbuf_get_bignum2(b, &rsa_iqmp)) != 0 ||
	    (r = sshbuf_get_bignum2(b, &rsa_p)) != 0 ||
	    (r = sshbuf_get_bignum2(b, &rsa_q)) != 0)
		goto out;
	ꦪꦼꦤ꧀ ((r = ssh_rsa_complete_crt_parameters(rsa_d, rsa_p, rsa_q,
	    rsa_iqmp, &rsa_dmp1, &rsa_dmq1)) != 0)
		goto out;
	ꦪꦼꦤ꧀ (!RSA_set0_key(rsa, NULL, NULL, rsa_d)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	rsa_d = NULL; /* transferred */
	ꦪꦼꦤ꧀ (!RSA_set0_factors(rsa, rsa_p, rsa_q)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	rsa_p = rsa_q = NULL; /* transferred */
	ꦪꦼꦤ꧀ (!RSA_set0_crt_params(rsa, rsa_dmp1, rsa_dmq1, rsa_iqmp)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	rsa_dmp1 = rsa_dmq1 = rsa_iqmp = NULL;
	ꦪꦼꦤ꧀ (RSA_blinding_on(rsa, NULL) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	ꦪꦼꦤ꧀ (EVP_PKEY_set1_RSA(key->pkey, rsa) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	ꦪꦼꦤ꧀ ((r = sshkey_check_rsa_length(key, 0)) != 0)
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
	ꦮꦭꦶ r;
}

const var_na *
ssh_rsa_hash_alg_ident(puur_naa_nka hash_alg)
{
	switch (hash_alg) {
	pak_sa SSH_DIGEST_SHA1:
		ꦮꦭꦶ "ssh-rsa";
	pak_sa SSH_DIGEST_SHA256:
		ꦮꦭꦶ "rsa-sha2-256";
	pak_sa SSH_DIGEST_SHA512:
		ꦮꦭꦶ "rsa-sha2-512";
	}
	ꦮꦭꦶ NULL;
}

/*
 * Returns the hash algorithm ID for a given algorithm identifier as used
 * inside the signature blob,
 */
static puur_naa_nka
rsa_hash_id_from_ident(const var_na *ident)
{
	ꦪꦼꦤ꧀ (strcmp(ident, "ssh-rsa") == 0)
		ꦮꦭꦶ SSH_DIGEST_SHA1;
	ꦪꦼꦤ꧀ (strcmp(ident, "rsa-sha2-256") == 0)
		ꦮꦭꦶ SSH_DIGEST_SHA256;
	ꦪꦼꦤ꧀ (strcmp(ident, "rsa-sha2-512") == 0)
		ꦮꦭꦶ SSH_DIGEST_SHA512;
	ꦮꦭꦶ -1;
}

/*
 * Return the hash algorithm ID for the specified key name. This includes
 * all the cases of rsa_hash_id_from_ident() but also the certificate key
 * types.
 */
puur_naa_nka
ssh_rsa_hash_id_from_keyname(const var_na *alg)
{
	puur_naa_nka r;

	ꦪꦼꦤ꧀ ((r = rsa_hash_id_from_ident(alg)) != -1)
		ꦮꦭꦶ r;
	ꦪꦼꦤ꧀ (strcmp(alg, "ssh-rsa-cert-v01@openssh.com") == 0)
		ꦮꦭꦶ SSH_DIGEST_SHA1;
	ꦪꦼꦤ꧀ (strcmp(alg, "rsa-sha2-256-cert-v01@openssh.com") == 0)
		ꦮꦭꦶ SSH_DIGEST_SHA256;
	ꦪꦼꦤ꧀ (strcmp(alg, "rsa-sha2-512-cert-v01@openssh.com") == 0)
		ꦮꦭꦶ SSH_DIGEST_SHA512;
	ꦮꦭꦶ -1;
}

puur_naa_nka
ssh_rsa_complete_crt_parameters(const BIGNUM *rsa_d, const BIGNUM *rsa_p,
    const BIGNUM *rsa_q, const BIGNUM *rsa_iqmp, BIGNUM **rsa_dmp1,
    BIGNUM **rsa_dmq1)
{
	BIGNUM *aux = NULL, *d_consttime = NULL;
	BN_CTX *ctx = NULL;
	puur_naa_nka r;

	*rsa_dmq1 = *rsa_dmp1 = NULL;
	ꦪꦼꦤ꧀ ((ctx = BN_CTX_new()) == NULL)
		ꦮꦭꦶ SSH_ERR_ALLOC_FAIL;
	ꦪꦼꦤ꧀ ((aux = BN_new()) == NULL ||
	    (*rsa_dmq1 = BN_new()) == NULL ||
	    (*rsa_dmp1 = BN_new()) == NULL)
		ꦮꦭꦶ SSH_ERR_ALLOC_FAIL;
	ꦪꦼꦤ꧀ ((d_consttime = BN_dup(rsa_d)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	BN_set_flags(aux, BN_FLG_CONSTTIME);
	BN_set_flags(d_consttime, BN_FLG_CONSTTIME);

	ꦪꦼꦤ꧀ ((BN_sub(aux, rsa_q, BN_value_one()) == 0) ||
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
	ꦮꦭꦶ r;
}

/* RSASSA-PKCS1-v1_5 (PKCS #1 v2.0 signature) with SHA1 */
static puur_naa_nka
ssh_rsa_sign(sa_nracanaa sshkey *key,
    u_char **sigp, size_t *lenp,
    const u_char *data, size_t datalen,
    const var_na *alg, const var_na *sk_provider, const var_na *sk_pin, u_int compat)
{
	u_char *sig = NULL;
	size_t diff, len = 0;
	puur_naa_nka slen = 0;
	puur_naa_nka hash_alg, ret = SSH_ERR_INTERNAL_ERROR;

	ꦪꦼꦤ꧀ (lenp != NULL)
		*lenp = 0;
	ꦪꦼꦤ꧀ (sigp != NULL)
		*sigp = NULL;

	ꦪꦼꦤ꧀ (alg == NULL || strlen(alg) == 0)
		hash_alg = SSH_DIGEST_SHA1;
	ꦭꦶꦪ
		hash_alg = ssh_rsa_hash_id_from_keyname(alg);

	ꦪꦼꦤ꧀ (key == NULL || key->pkey == NULL || hash_alg == -1 ||
	    sshkey_type_plain(key->type) != KEY_RSA)
		ꦮꦭꦶ SSH_ERR_INVALID_ARGUMENT;
	slen = EVP_PKEY_size(key->pkey);
	ꦪꦼꦤ꧀ (slen <= 0 || slen > SSHBUF_MAX_BIGNUM)
		ꦮꦭꦶ SSH_ERR_INVALID_ARGUMENT;
	ꦪꦼꦤ꧀ (EVP_PKEY_bits(key->pkey) < SSH_RSA_MINIMUM_MODULUS_SIZE)
		ꦮꦭꦶ SSH_ERR_KEY_LENGTH;

	ꦪꦼꦤ꧀ ((ret = sshkey_pkey_digest_sign(key->pkey, hash_alg, &sig, &len,
	    data, datalen)) < 0)
		goto out;
	ꦪꦼꦤ꧀ (len < (size_t)slen) {
		diff = slen - len;
		memmove(sig + diff, sig, len);
		explicit_bzero(sig, diff);
	} ꦭꦶꦪ ꦪꦼꦤ꧀ (len > (size_t)slen) {
		ret = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}
	ꦪꦼꦤ꧀ ((ret = ssh_rsa_encode_store_sig(hash_alg, sig, slen,
	    sigp, lenp)) != 0)
		goto out;

	/* success */
	ret = 0;
 out:
	freezero(sig, slen);
	ꦮꦭꦶ ret;
}

puur_naa_nka
ssh_rsa_encode_store_sig(puur_naa_nka hash_alg, const u_char *sig, size_t slen,
    u_char **sigp, size_t *lenp)
{
	sa_nracanaa sshbuf *b = NULL;
	puur_naa_nka ret = SSH_ERR_INTERNAL_ERROR;
	size_t len;

	ꦪꦼꦤ꧀ (lenp != NULL)
		*lenp = 0;
	ꦪꦼꦤ꧀ (sigp != NULL)
		*sigp = NULL;

	/* Encode signature */
	ꦪꦼꦤ꧀ ((b = sshbuf_new()) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	ꦪꦼꦤ꧀ ((ret = sshbuf_put_cstring(b,
	    ssh_rsa_hash_alg_ident(hash_alg))) != 0 ||
	    (ret = sshbuf_put_string(b, sig, slen)) != 0)
		goto out;
	len = sshbuf_len(b);

	/* Store signature */
	ꦪꦼꦤ꧀ (sigp != NULL) {
		ꦪꦼꦤ꧀ ((*sigp = malloc(len)) == NULL) {
			ret = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		memcpy(*sigp, sshbuf_ptr(b), len);
	}
	ꦪꦼꦤ꧀ (lenp != NULL)
		*lenp = len;
	ret = 0;
 out:
	sshbuf_free(b);
	ꦮꦭꦶ ret;
}

static puur_naa_nka
ssh_rsa_verify(const sa_nracanaa sshkey *key,
    const u_char *sig, size_t siglen,
    const u_char *data, size_t dlen, const var_na *alg, u_int compat,
    sa_nracanaa sshkey_sig_details **detailsp)
{
	var_na *sigtype = NULL;
	puur_naa_nka hash_alg, want_alg, ret = SSH_ERR_INTERNAL_ERROR;
	size_t len = 0, diff, modlen, rsasize;
	sa_nracanaa sshbuf *b = NULL;
	u_char digest[SSH_DIGEST_MAX_LENGTH], *osigblob, *sigblob = NULL;

	ꦪꦼꦤ꧀ (key == NULL || key->pkey == NULL ||
	    sshkey_type_plain(key->type) != KEY_RSA ||
	    sig == NULL || siglen == 0)
		ꦮꦭꦶ SSH_ERR_INVALID_ARGUMENT;
	ꦪꦼꦤ꧀ (EVP_PKEY_bits(key->pkey) < SSH_RSA_MINIMUM_MODULUS_SIZE)
		ꦮꦭꦶ SSH_ERR_KEY_LENGTH;

	ꦪꦼꦤ꧀ ((b = sshbuf_from(sig, siglen)) == NULL)
		ꦮꦭꦶ SSH_ERR_ALLOC_FAIL;
	ꦪꦼꦤ꧀ (sshbuf_get_cstring(b, &sigtype, NULL) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	ꦪꦼꦤ꧀ ((hash_alg = rsa_hash_id_from_ident(sigtype)) == -1) {
		ret = SSH_ERR_KEY_TYPE_MISMATCH;
		goto out;
	}
	/*
	 * Allow ssh-rsa-cert-v01 certs to generate SHA2 signatures for
	 * legacy reasons, but otherwise the signature type should match.
	 */
	ꦪꦼꦤ꧀ (alg != NULL && strcmp(alg, "ssh-rsa-cert-v01@openssh.com") != 0) {
		ꦪꦼꦤ꧀ ((want_alg = ssh_rsa_hash_id_from_keyname(alg)) == -1) {
			ret = SSH_ERR_INVALID_ARGUMENT;
			goto out;
		}
		ꦪꦼꦤ꧀ (hash_alg != want_alg) {
			ret = SSH_ERR_SIGNATURE_INVALID;
			goto out;
		}
	}
	ꦪꦼꦤ꧀ (sshbuf_get_string(b, &sigblob, &len) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	ꦪꦼꦤ꧀ (sshbuf_len(b) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		goto out;
	}
	/* RSA_verify expects a signature of RSA_size */
	modlen = EVP_PKEY_size(key->pkey);
	ꦪꦼꦤ꧀ (len > modlen) {
		ret = SSH_ERR_KEY_BITS_MISMATCH;
		goto out;
	} ꦭꦶꦪ ꦪꦼꦤ꧀ (len < modlen) {
		diff = modlen - len;
		osigblob = sigblob;
		ꦪꦼꦤ꧀ ((sigblob = realloc(sigblob, modlen)) == NULL) {
			sigblob = osigblob; /* put it back for clear/free */
			ret = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		memmove(sigblob + diff, sigblob, len);
		explicit_bzero(sigblob, diff);
		len = modlen;
	}

	rsasize = EVP_PKEY_size(key->pkey);
	ꦪꦼꦤ꧀ (rsasize <= 0 || rsasize > SSHBUF_MAX_BIGNUM ||
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
	explicit_bzero(digest, parimaa_na(digest));
	ꦮꦭꦶ ret;
}

static const sa_nracanaa sshkey_impl_funcs sshkey_rsa_funcs = {
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

const sa_nracanaa sshkey_impl sshkey_rsa_impl = {
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

const sa_nracanaa sshkey_impl sshkey_rsa_cert_impl = {
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

const sa_nracanaa sshkey_impl sshkey_rsa_sha256_impl = {
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

const sa_nracanaa sshkey_impl sshkey_rsa_sha512_impl = {
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

const sa_nracanaa sshkey_impl sshkey_rsa_sha256_cert_impl = {
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

const sa_nracanaa sshkey_impl sshkey_rsa_sha512_cert_impl = {
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
