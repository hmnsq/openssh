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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
#ਅਨ੍ਤਰ੍ਭਾਵ "openbsd-compat/openssl-compat.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/bn.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/evp.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "sshbuf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssherr.h"
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHKEY_ਅੰਦਰੂਨੀ
#ਅਨ੍ਤਰ੍ਭਾਵ "sshkey.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "digest.h"

ਸਥਿਰ u_int
ssh_rsa_ਮਾਪ(ਅਚਲ ਬਣਤਰ sshkey *k)
{
	ਜੇ (k->pkey == ਨਿਰਾ)
		ਵਾਪਸ 0;
	ਵਾਪਸ EVP_PKEY_ਬਿੱਟ(k->pkey);
}

ਸਥਿਰ ਪੂਰਨ
ssh_rsa_alloc(ਬਣਤਰ sshkey *k)
{
	ਜੇ ((k->pkey = EVP_PKEY_new()) == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_ALLOC_FAIL;
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਖਾਲੀ
ssh_rsa_cleanup(ਬਣਤਰ sshkey *k)
{
	EVP_PKEY_free(k->pkey);
	k->pkey = ਨਿਰਾ;
}

ਸਥਿਰ ਪੂਰਨ
ssh_rsa_equal(ਅਚਲ ਬਣਤਰ sshkey *a, ਅਚਲ ਬਣਤਰ sshkey *b)
{
	ਜੇ (a->pkey == ਨਿਰਾ || b->pkey == ਨਿਰਾ)
		ਵਾਪਸ 0;
	ਵਾਪਸ EVP_PKEY_cmp(a->pkey, b->pkey) == 1;
}

ਸਥਿਰ ਪੂਰਨ
ssh_rsa_serialize_ਜਨਤਕ(ਅਚਲ ਬਣਤਰ sshkey *ਕੁੰਜੀ, ਬਣਤਰ sshbuf *b,
    ਗਿਣਤੀ sshkey_serialize_rep opts)
{
	ਪੂਰਨ r;
	ਅਚਲ BIGNUM *rsa_n, *rsa_e;
	ਅਚਲ RSA *rsa;

	ਜੇ (ਕੁੰਜੀ->pkey == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_INVALID_ਦਲੀਲ;
	ਜੇ ((rsa = EVP_PKEY_get0_RSA(ਕੁੰਜੀ->pkey)) == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_LIBCRYPTO_ERROR;

	RSA_get0_ਕੁੰਜੀ(rsa, &rsa_n, &rsa_e, ਨਿਰਾ);
	ਜੇ ((r = sshbuf_put_bignum2(b, rsa_e)) != 0 ||
	    (r = sshbuf_put_bignum2(b, rsa_n)) != 0)
		ਵਾਪਸ r;

	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
ssh_rsa_serialize_ਨਿੱਜੀ(ਅਚਲ ਬਣਤਰ sshkey *ਕੁੰਜੀ, ਬਣਤਰ sshbuf *b,
    ਗਿਣਤੀ sshkey_serialize_rep opts)
{
	ਪੂਰਨ r;
	ਅਚਲ BIGNUM *rsa_n, *rsa_e, *rsa_d, *rsa_iqmp, *rsa_p, *rsa_q;
	ਅਚਲ RSA *rsa;

	ਜੇ ((rsa = EVP_PKEY_get0_RSA(ਕੁੰਜੀ->pkey)) == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_LIBCRYPTO_ERROR;
	RSA_get0_ਕੁੰਜੀ(rsa, &rsa_n, &rsa_e, &rsa_d);
	RSA_get0_factors(rsa, &rsa_p, &rsa_q);
	RSA_get0_crt_params(rsa, ਨਿਰਾ, ਨਿਰਾ, &rsa_iqmp);

	ਜੇ (!sshkey_is_cert(ਕੁੰਜੀ)) {
		/* Note: can't reuse ssh_rsa_serialize_public: e, n vs. n, e */
		ਜੇ ((r = sshbuf_put_bignum2(b, rsa_n)) != 0 ||
		    (r = sshbuf_put_bignum2(b, rsa_e)) != 0)
			ਵਾਪਸ r;
	}
	ਜੇ ((r = sshbuf_put_bignum2(b, rsa_d)) != 0 ||
	    (r = sshbuf_put_bignum2(b, rsa_iqmp)) != 0 ||
	    (r = sshbuf_put_bignum2(b, rsa_p)) != 0 ||
	    (r = sshbuf_put_bignum2(b, rsa_q)) != 0)
		ਵਾਪਸ r;

	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
ssh_rsa_generate(ਬਣਤਰ sshkey *k, ਪੂਰਨ ਬਿੱਟ)
{
	EVP_PKEY_CTX *ctx = ਨਿਰਾ;
	EVP_PKEY *res = ਨਿਰਾ;

	ਪੂਰਨ ret = SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;

	ਜੇ (ਬਿੱਟ < SSH_RSA_MINIMUM_MODULUS_ਮਾਪ ||
	    ਬਿੱਟ > SSHBUF_MAX_BIGNUM * 8)
		ਵਾਪਸ SSH_ERR_ਕੁੰਜੀ_ਲੰਮਾਈ;

	ਜੇ ((ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, ਨਿਰਾ)) == ਨਿਰਾ) {
		ret = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (EVP_PKEY_keygen_init(ctx) <= 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (EVP_PKEY_CTX_ਸੈੱਟ_rsa_keygen_ਬਿੱਟ(ctx, ਬਿੱਟ) <= 0) {
		ret = SSH_ERR_ਕੁੰਜੀ_ਲੰਮਾਈ;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (EVP_PKEY_keygen(ctx, &res) <= 0 || res == ਨਿਰਾ) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	/* success */
	k->pkey = res;
	ret = 0;
 ਬਾਹਰਲਾ:
	EVP_PKEY_CTX_free(ctx);
	ਵਾਪਸ ret;
}

ਸਥਿਰ ਪੂਰਨ
ssh_rsa_copy_ਜਨਤਕ(ਅਚਲ ਬਣਤਰ sshkey *from, ਬਣਤਰ sshkey *ਮੰਜ਼ਿਲ)
{
	ਅਚਲ BIGNUM *rsa_n, *rsa_e;
	BIGNUM *rsa_n_dup = ਨਿਰਾ, *rsa_e_dup = ਨਿਰਾ;
	ਪੂਰਨ r = SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
	ਅਚਲ RSA *rsa_from;
	RSA *rsa_ਮੰਜ਼ਿਲ = ਨਿਰਾ;

	ਜੇ ((rsa_from = EVP_PKEY_get0_RSA(from->pkey)) == ਨਿਰਾ ||
	    (rsa_ਮੰਜ਼ਿਲ = RSA_new()) == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_LIBCRYPTO_ERROR;

	RSA_get0_ਕੁੰਜੀ(rsa_from, &rsa_n, &rsa_e, ਨਿਰਾ);
	ਜੇ ((rsa_n_dup = BN_dup(rsa_n)) == ਨਿਰਾ ||
	    (rsa_e_dup = BN_dup(rsa_e)) == ਨਿਰਾ) {
		r = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (!RSA_set0_ਕੁੰਜੀ(rsa_ਮੰਜ਼ਿਲ, rsa_n_dup, rsa_e_dup, ਨਿਰਾ)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	rsa_n_dup = rsa_e_dup = ਨਿਰਾ; /* transferred */

	ਜੇ (EVP_PKEY_set1_RSA(ਮੰਜ਼ਿਲ->pkey, rsa_ਮੰਜ਼ਿਲ) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	/* success */
	r = 0;
 ਬਾਹਰਲਾ:
	RSA_free(rsa_ਮੰਜ਼ਿਲ);
	BN_clear_free(rsa_n_dup);
	BN_clear_free(rsa_e_dup);
	ਵਾਪਸ r;
}

ਸਥਿਰ ਪੂਰਨ
ssh_rsa_deserialize_ਜਨਤਕ(ਅਚਲ ਅੱਖਰ *ktype, ਬਣਤਰ sshbuf *b,
    ਬਣਤਰ sshkey *ਕੁੰਜੀ)
{
	ਪੂਰਨ ret = SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
	BIGNUM *rsa_n = ਨਿਰਾ, *rsa_e = ਨਿਰਾ;
	RSA *rsa = ਨਿਰਾ;

	ਜੇ ((rsa = RSA_new()) == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_LIBCRYPTO_ERROR;

	ਜੇ (sshbuf_get_bignum2(b, &rsa_e) != 0 ||
	    sshbuf_get_bignum2(b, &rsa_n) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (!RSA_set0_ਕੁੰਜੀ(rsa, rsa_n, rsa_e, ਨਿਰਾ)) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	rsa_n = rsa_e = ਨਿਰਾ; /* transferred */
	ਜੇ (EVP_PKEY_set1_RSA(ਕੁੰਜੀ->pkey, rsa) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((ret = sshkey_check_rsa_ਲੰਮਾਈ(ਕੁੰਜੀ, 0)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ DEBUG_PK
	RSA_print_fp(stderr, rsa, 8);
#ਜੇ_ਅੰਤ
	/* success */
	ret = 0;
 ਬਾਹਰਲਾ:
	RSA_free(rsa);
	BN_clear_free(rsa_n);
	BN_clear_free(rsa_e);
	ਵਾਪਸ ret;
}

ਸਥਿਰ ਪੂਰਨ
ssh_rsa_deserialize_ਨਿੱਜੀ(ਅਚਲ ਅੱਖਰ *ktype, ਬਣਤਰ sshbuf *b,
    ਬਣਤਰ sshkey *ਕੁੰਜੀ)
{
	ਪੂਰਨ r;
	BIGNUM *rsa_n = ਨਿਰਾ, *rsa_e = ਨਿਰਾ, *rsa_d = ਨਿਰਾ;
	BIGNUM *rsa_iqmp = ਨਿਰਾ, *rsa_p = ਨਿਰਾ, *rsa_q = ਨਿਰਾ;
	BIGNUM *rsa_dmp1 = ਨਿਰਾ, *rsa_dmq1 = ਨਿਰਾ;
	RSA *rsa = ਨਿਰਾ;

	ਜੇ (sshkey_is_cert(ਕੁੰਜੀ)) {
		/* sshkey_private_deserialize already has pubkey from cert */
		ਜੇ ((rsa = EVP_PKEY_get1_RSA(ਕੁੰਜੀ->pkey)) == ਨਿਰਾ) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
	} ਨਹੀਂਤਾਂ {
		ਜੇ ((rsa = RSA_new()) == ਨਿਰਾ) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		/* Note: can't reuse ssh_rsa_deserialize_public: e,n vs. n,e */
		ਜੇ ((r = sshbuf_get_bignum2(b, &rsa_n)) != 0 ||
		    (r = sshbuf_get_bignum2(b, &rsa_e)) != 0)
			ਜਾਓ ਬਾਹਰਲਾ;
		ਜੇ (!RSA_set0_ਕੁੰਜੀ(rsa, rsa_n, rsa_e, ਨਿਰਾ)) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		rsa_n = rsa_e = ਨਿਰਾ; /* transferred */
	}
	ਜੇ ((r = sshbuf_get_bignum2(b, &rsa_d)) != 0 ||
	    (r = sshbuf_get_bignum2(b, &rsa_iqmp)) != 0 ||
	    (r = sshbuf_get_bignum2(b, &rsa_p)) != 0 ||
	    (r = sshbuf_get_bignum2(b, &rsa_q)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	ਜੇ ((r = ssh_rsa_complete_crt_parameters(rsa_d, rsa_p, rsa_q,
	    rsa_iqmp, &rsa_dmp1, &rsa_dmq1)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	ਜੇ (!RSA_set0_ਕੁੰਜੀ(rsa, ਨਿਰਾ, ਨਿਰਾ, rsa_d)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	rsa_d = ਨਿਰਾ; /* transferred */
	ਜੇ (!RSA_set0_factors(rsa, rsa_p, rsa_q)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	rsa_p = rsa_q = ਨਿਰਾ; /* transferred */
	ਜੇ (!RSA_set0_crt_params(rsa, rsa_dmp1, rsa_dmq1, rsa_iqmp)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	rsa_dmp1 = rsa_dmq1 = rsa_iqmp = ਨਿਰਾ;
	ਜੇ (RSA_blinding_on(rsa, ਨਿਰਾ) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (EVP_PKEY_set1_RSA(ਕੁੰਜੀ->pkey, rsa) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((r = sshkey_check_rsa_ਲੰਮਾਈ(ਕੁੰਜੀ, 0)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	/* success */
	r = 0;
 ਬਾਹਰਲਾ:
	RSA_free(rsa);
	BN_clear_free(rsa_n);
	BN_clear_free(rsa_e);
	BN_clear_free(rsa_d);
	BN_clear_free(rsa_p);
	BN_clear_free(rsa_q);
	BN_clear_free(rsa_iqmp);
	BN_clear_free(rsa_dmp1);
	BN_clear_free(rsa_dmq1);
	ਵਾਪਸ r;
}

ਅਚਲ ਅੱਖਰ *
ssh_rsa_hash_alg_ident(ਪੂਰਨ hash_alg)
{
	ਚੋਣ (hash_alg) {
	ਹਾਲਤ SSH_DIGEST_SHA1:
		ਵਾਪਸ "ssh-rsa";
	ਹਾਲਤ SSH_DIGEST_SHA256:
		ਵਾਪਸ "rsa-sha2-256";
	ਹਾਲਤ SSH_DIGEST_SHA512:
		ਵਾਪਸ "rsa-sha2-512";
	}
	ਵਾਪਸ ਨਿਰਾ;
}

/*
 * Returns the hash algorithm ID for a given algorithm identifier as used
 * inside the signature blob,
 */
ਸਥਿਰ ਪੂਰਨ
rsa_hash_id_from_ident(ਅਚਲ ਅੱਖਰ *ident)
{
	ਜੇ (strcmp(ident, "ssh-rsa") == 0)
		ਵਾਪਸ SSH_DIGEST_SHA1;
	ਜੇ (strcmp(ident, "rsa-sha2-256") == 0)
		ਵਾਪਸ SSH_DIGEST_SHA256;
	ਜੇ (strcmp(ident, "rsa-sha2-512") == 0)
		ਵਾਪਸ SSH_DIGEST_SHA512;
	ਵਾਪਸ -1;
}

/*
 * Return the hash algorithm ID for the specified key name. This includes
 * all the cases of rsa_hash_id_from_ident() but also the certificate key
 * types.
 */
ਪੂਰਨ
ssh_rsa_hash_id_from_keyname(ਅਚਲ ਅੱਖਰ *alg)
{
	ਪੂਰਨ r;

	ਜੇ ((r = rsa_hash_id_from_ident(alg)) != -1)
		ਵਾਪਸ r;
	ਜੇ (strcmp(alg, "ssh-rsa-cert-v01@openssh.com") == 0)
		ਵਾਪਸ SSH_DIGEST_SHA1;
	ਜੇ (strcmp(alg, "rsa-sha2-256-cert-v01@openssh.com") == 0)
		ਵਾਪਸ SSH_DIGEST_SHA256;
	ਜੇ (strcmp(alg, "rsa-sha2-512-cert-v01@openssh.com") == 0)
		ਵਾਪਸ SSH_DIGEST_SHA512;
	ਵਾਪਸ -1;
}

ਪੂਰਨ
ssh_rsa_complete_crt_parameters(ਅਚਲ BIGNUM *rsa_d, ਅਚਲ BIGNUM *rsa_p,
    ਅਚਲ BIGNUM *rsa_q, ਅਚਲ BIGNUM *rsa_iqmp, BIGNUM **rsa_dmp1,
    BIGNUM **rsa_dmq1)
{
	BIGNUM *aux = ਨਿਰਾ, *d_consttime = ਨਿਰਾ;
	BN_CTX *ctx = ਨਿਰਾ;
	ਪੂਰਨ r;

	*rsa_dmq1 = *rsa_dmp1 = ਨਿਰਾ;
	ਜੇ ((ctx = BN_CTX_new()) == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_ALLOC_FAIL;
	ਜੇ ((aux = BN_new()) == ਨਿਰਾ ||
	    (*rsa_dmq1 = BN_new()) == ਨਿਰਾ ||
	    (*rsa_dmp1 = BN_new()) == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_ALLOC_FAIL;
	ਜੇ ((d_consttime = BN_dup(rsa_d)) == ਨਿਰਾ) {
		r = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	BN_ਸੈੱਟ_flags(aux, BN_FLG_CONSTTIME);
	BN_ਸੈੱਟ_flags(d_consttime, BN_FLG_CONSTTIME);

	ਜੇ ((BN_sub(aux, rsa_q, BN_ਮੁੱਲ_one()) == 0) ||
	    (BN_mod(*rsa_dmq1, d_consttime, aux, ctx) == 0) ||
	    (BN_sub(aux, rsa_p, BN_ਮੁੱਲ_one()) == 0) ||
	    (BN_mod(*rsa_dmp1, d_consttime, aux, ctx) == 0)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	/* success */
	r = 0;
 ਬਾਹਰਲਾ:
	BN_clear_free(aux);
	BN_clear_free(d_consttime);
	BN_CTX_free(ctx);
	ਵਾਪਸ r;
}

/* RSASSA-PKCS1-v1_5 (PKCS #1 v2.0 signature) with SHA1 */
ਸਥਿਰ ਪੂਰਨ
ssh_rsa_sign(ਬਣਤਰ sshkey *ਕੁੰਜੀ,
    u_char **sigp, ਮਾਪ_t *lenp,
    ਅਚਲ u_char *ਅੰਕੜੇ, ਮਾਪ_t datalen,
    ਅਚਲ ਅੱਖਰ *alg, ਅਚਲ ਅੱਖਰ *sk_provider, ਅਚਲ ਅੱਖਰ *sk_pin, u_int compat)
{
	u_char *sig = ਨਿਰਾ;
	ਮਾਪ_t diff, len = 0;
	ਪੂਰਨ slen = 0;
	ਪੂਰਨ hash_alg, ret = SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;

	ਜੇ (lenp != ਨਿਰਾ)
		*lenp = 0;
	ਜੇ (sigp != ਨਿਰਾ)
		*sigp = ਨਿਰਾ;

	ਜੇ (alg == ਨਿਰਾ || ਲੜੀ_ਲੰਬਾਈ(alg) == 0)
		hash_alg = SSH_DIGEST_SHA1;
	ਨਹੀਂਤਾਂ
		hash_alg = ssh_rsa_hash_id_from_keyname(alg);

	ਜੇ (ਕੁੰਜੀ == ਨਿਰਾ || ਕੁੰਜੀ->pkey == ਨਿਰਾ || hash_alg == -1 ||
	    sshkey_type_plain(ਕੁੰਜੀ->type) != ਕੁੰਜੀ_RSA)
		ਵਾਪਸ SSH_ERR_INVALID_ਦਲੀਲ;
	slen = EVP_PKEY_ਮਾਪ(ਕੁੰਜੀ->pkey);
	ਜੇ (slen <= 0 || slen > SSHBUF_MAX_BIGNUM)
		ਵਾਪਸ SSH_ERR_INVALID_ਦਲੀਲ;
	ਜੇ (EVP_PKEY_ਬਿੱਟ(ਕੁੰਜੀ->pkey) < SSH_RSA_MINIMUM_MODULUS_ਮਾਪ)
		ਵਾਪਸ SSH_ERR_ਕੁੰਜੀ_ਲੰਮਾਈ;

	ਜੇ ((ret = sshkey_pkey_digest_sign(ਕੁੰਜੀ->pkey, hash_alg, &sig, &len,
	    ਅੰਕੜੇ, datalen)) < 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	ਜੇ (len < (ਮਾਪ_t)slen) {
		diff = slen - len;
		memmove(sig + diff, sig, len);
		explicit_bzero(sig, diff);
	} ਨਹੀਂਤਾਂ ਜੇ (len > (ਮਾਪ_t)slen) {
		ret = SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((ret = ssh_rsa_encode_store_sig(hash_alg, sig, slen,
	    sigp, lenp)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;

	/* success */
	ret = 0;
 ਬਾਹਰਲਾ:
	freezero(sig, slen);
	ਵਾਪਸ ret;
}

ਪੂਰਨ
ssh_rsa_encode_store_sig(ਪੂਰਨ hash_alg, ਅਚਲ u_char *sig, ਮਾਪ_t slen,
    u_char **sigp, ਮਾਪ_t *lenp)
{
	ਬਣਤਰ sshbuf *b = ਨਿਰਾ;
	ਪੂਰਨ ret = SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
	ਮਾਪ_t len;

	ਜੇ (lenp != ਨਿਰਾ)
		*lenp = 0;
	ਜੇ (sigp != ਨਿਰਾ)
		*sigp = ਨਿਰਾ;

	/* Encode signature */
	ਜੇ ((b = sshbuf_new()) == ਨਿਰਾ) {
		ret = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((ret = sshbuf_put_cstring(b,
	    ssh_rsa_hash_alg_ident(hash_alg))) != 0 ||
	    (ret = sshbuf_put_string(b, sig, slen)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	len = sshbuf_len(b);

	/* Store signature */
	ਜੇ (sigp != ਨਿਰਾ) {
		ਜੇ ((*sigp = ਸਮ੍ਰਿਤੀ_ਦਿਓ(len)) == ਨਿਰਾ) {
			ret = SSH_ERR_ALLOC_FAIL;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਸਮ੍ਰਿਤੀ_ਨਕਲ(*sigp, sshbuf_ptr(b), len);
	}
	ਜੇ (lenp != ਨਿਰਾ)
		*lenp = len;
	ret = 0;
 ਬਾਹਰਲਾ:
	sshbuf_free(b);
	ਵਾਪਸ ret;
}

ਸਥਿਰ ਪੂਰਨ
ssh_rsa_verify(ਅਚਲ ਬਣਤਰ sshkey *ਕੁੰਜੀ,
    ਅਚਲ u_char *sig, ਮਾਪ_t siglen,
    ਅਚਲ u_char *ਅੰਕੜੇ, ਮਾਪ_t dlen, ਅਚਲ ਅੱਖਰ *alg, u_int compat,
    ਬਣਤਰ sshkey_sig_details **detailsp)
{
	ਅੱਖਰ *sigtype = ਨਿਰਾ;
	ਪੂਰਨ hash_alg, want_alg, ret = SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
	ਮਾਪ_t len = 0, diff, modlen, rsasize;
	ਬਣਤਰ sshbuf *b = ਨਿਰਾ;
	u_char digest[SSH_DIGEST_MAX_ਲੰਮਾਈ], *osigblob, *sigblob = ਨਿਰਾ;

	ਜੇ (ਕੁੰਜੀ == ਨਿਰਾ || ਕੁੰਜੀ->pkey == ਨਿਰਾ ||
	    sshkey_type_plain(ਕੁੰਜੀ->type) != ਕੁੰਜੀ_RSA ||
	    sig == ਨਿਰਾ || siglen == 0)
		ਵਾਪਸ SSH_ERR_INVALID_ਦਲੀਲ;
	ਜੇ (EVP_PKEY_ਬਿੱਟ(ਕੁੰਜੀ->pkey) < SSH_RSA_MINIMUM_MODULUS_ਮਾਪ)
		ਵਾਪਸ SSH_ERR_ਕੁੰਜੀ_ਲੰਮਾਈ;

	ਜੇ ((b = sshbuf_from(sig, siglen)) == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_ALLOC_FAIL;
	ਜੇ (sshbuf_get_cstring(b, &sigtype, ਨਿਰਾ) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((hash_alg = rsa_hash_id_from_ident(sigtype)) == -1) {
		ret = SSH_ERR_ਕੁੰਜੀ_TYPE_MISMATCH;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	/*
	 * Allow ssh-rsa-cert-v01 certs to generate SHA2 signatures for
	 * legacy reasons, but otherwise the signature type should match.
	 */
	ਜੇ (alg != ਨਿਰਾ && strcmp(alg, "ssh-rsa-cert-v01@openssh.com") != 0) {
		ਜੇ ((want_alg = ssh_rsa_hash_id_from_keyname(alg)) == -1) {
			ret = SSH_ERR_INVALID_ਦਲੀਲ;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਜੇ (hash_alg != want_alg) {
			ret = SSH_ERR_SIGNATURE_INVALID;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
	}
	ਜੇ (sshbuf_get_string(b, &sigblob, &len) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (sshbuf_len(b) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_ਅੰਕੜੇ;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	/* RSA_verify expects a signature of RSA_size */
	modlen = EVP_PKEY_ਮਾਪ(ਕੁੰਜੀ->pkey);
	ਜੇ (len > modlen) {
		ret = SSH_ERR_ਕੁੰਜੀ_ਬਿੱਟ_MISMATCH;
		ਜਾਓ ਬਾਹਰਲਾ;
	} ਨਹੀਂਤਾਂ ਜੇ (len < modlen) {
		diff = modlen - len;
		osigblob = sigblob;
		ਜੇ ((sigblob = realloc(sigblob, modlen)) == ਨਿਰਾ) {
			sigblob = osigblob; /* put it back for clear/free */
			ret = SSH_ERR_ALLOC_FAIL;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		memmove(sigblob + diff, sigblob, len);
		explicit_bzero(sigblob, diff);
		len = modlen;
	}

	rsasize = EVP_PKEY_ਮਾਪ(ਕੁੰਜੀ->pkey);
	ਜੇ (rsasize <= 0 || rsasize > SSHBUF_MAX_BIGNUM ||
	    len == 0 || len > rsasize) {
		ret = SSH_ERR_INVALID_ਦਲੀਲ;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ret = sshkey_pkey_digest_verify(ਕੁੰਜੀ->pkey, hash_alg, ਅੰਕੜੇ, dlen,
	    sigblob, len);

 ਬਾਹਰਲਾ:
	freezero(sigblob, len);
	ਮੁਕਤ(sigtype);
	sshbuf_free(b);
	explicit_bzero(digest, ਆਕਾਰ(digest));
	ਵਾਪਸ ret;
}

ਸਥਿਰ ਅਚਲ ਬਣਤਰ sshkey_impl_funcs sshkey_rsa_funcs = {
	/* .size = */		ssh_rsa_ਮਾਪ,
	/* .alloc = */		ssh_rsa_alloc,
	/* .cleanup = */	ssh_rsa_cleanup,
	/* .equal = */		ssh_rsa_equal,
	/* .ssh_serialize_public = */ ssh_rsa_serialize_ਜਨਤਕ,
	/* .ssh_deserialize_public = */ ssh_rsa_deserialize_ਜਨਤਕ,
	/* .ssh_serialize_private = */ ssh_rsa_serialize_ਨਿੱਜੀ,
	/* .ssh_deserialize_private = */ ssh_rsa_deserialize_ਨਿੱਜੀ,
	/* .generate = */	ssh_rsa_generate,
	/* .copy_public = */	ssh_rsa_copy_ਜਨਤਕ,
	/* .sign = */		ssh_rsa_sign,
	/* .verify = */		ssh_rsa_verify,
};

ਅਚਲ ਬਣਤਰ sshkey_impl sshkey_rsa_impl = {
	/* .name = */		"ssh-rsa",
	/* .shortname = */	"RSA",
	/* .sigalg = */		ਨਿਰਾ,
	/* .type = */		ਕੁੰਜੀ_RSA,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};

ਅਚਲ ਬਣਤਰ sshkey_impl sshkey_rsa_cert_impl = {
	/* .name = */		"ssh-rsa-cert-v01@openssh.com",
	/* .shortname = */	"RSA-CERT",
	/* .sigalg = */		ਨਿਰਾ,
	/* .type = */		ਕੁੰਜੀ_RSA_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};

/* SHA2 signature algorithms */

ਅਚਲ ਬਣਤਰ sshkey_impl sshkey_rsa_sha256_impl = {
	/* .name = */		"rsa-sha2-256",
	/* .shortname = */	"RSA",
	/* .sigalg = */		ਨਿਰਾ,
	/* .type = */		ਕੁੰਜੀ_RSA,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	1,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};

ਅਚਲ ਬਣਤਰ sshkey_impl sshkey_rsa_sha512_impl = {
	/* .name = */		"rsa-sha2-512",
	/* .shortname = */	"RSA",
	/* .sigalg = */		ਨਿਰਾ,
	/* .type = */		ਕੁੰਜੀ_RSA,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	1,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};

ਅਚਲ ਬਣਤਰ sshkey_impl sshkey_rsa_sha256_cert_impl = {
	/* .name = */		"rsa-sha2-256-cert-v01@openssh.com",
	/* .shortname = */	"RSA-CERT",
	/* .sigalg = */		"rsa-sha2-256",
	/* .type = */		ਕੁੰਜੀ_RSA_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	1,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};

ਅਚਲ ਬਣਤਰ sshkey_impl sshkey_rsa_sha512_cert_impl = {
	/* .name = */		"rsa-sha2-512-cert-v01@openssh.com",
	/* .shortname = */	"RSA-CERT",
	/* .sigalg = */		"rsa-sha2-512",
	/* .type = */		ਕੁੰਜੀ_RSA_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	1,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};
#ਜੇ_ਅੰਤ /* WITH_OPENSSL */
