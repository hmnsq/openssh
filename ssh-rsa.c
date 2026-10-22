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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
#ಅನ್ತರ್ಭಾವ "openbsd-compat/openssl-compat.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>

#ಅನ್ತರ್ಭಾವ <openssl/bn.h>
#ಅನ್ತರ್ಭಾವ <openssl/evp.h>

#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <string.h>

#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "ssherr.h"
#ವ್ಯಾಖ್ಯಾನಿಸು SSHKEY_ಆಂತರಿಕ
#ಅನ್ತರ್ಭಾವ "sshkey.h"
#ಅನ್ತರ್ಭಾವ "digest.h"

ಸ್ಥಿರ u_int
ssh_rsa_ಗಾತ್ರ(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *k)
{
	ಆದರೆ (k->pkey == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ 0;
	ಹಿಂತಿರುಗಿ EVP_PKEY_ಬಿಟ್ಟುಗಳು(k->pkey);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ssh_rsa_alloc(ರಚನೆ sshkey *k)
{
	ಆದರೆ ((k->pkey = EVP_PKEY_new()) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_ALLOC_FAIL;
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಶೂನ್ಯ
ssh_rsa_cleanup(ರಚನೆ sshkey *k)
{
	EVP_PKEY_free(k->pkey);
	k->pkey = ಖಾಲಿ;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ssh_rsa_equal(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *a, ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *b)
{
	ಆದರೆ (a->pkey == ಖಾಲಿ || b->pkey == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ 0;
	ಹಿಂತಿರುಗಿ EVP_PKEY_cmp(a->pkey, b->pkey) == 1;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ssh_rsa_serialize_ಬಹಿರಂಗ(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *ಕೀಲಿ, ರಚನೆ sshbuf *b,
    ಎಣಿಕೆ sshkey_serialize_rep opts)
{
	ಪೂರ್ಣಾಂಕ r;
	ಸ್ಥಿರಾಂಕ BIGNUM *rsa_n, *rsa_e;
	ಸ್ಥಿರಾಂಕ RSA *rsa;

	ಆದರೆ (ಕೀಲಿ->pkey == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_ವಾದ;
	ಆದರೆ ((rsa = EVP_PKEY_get0_RSA(ಕೀಲಿ->pkey)) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_LIBCRYPTO_ERROR;

	RSA_get0_ಕೀಲಿ(rsa, &rsa_n, &rsa_e, ಖಾಲಿ);
	ಆದರೆ ((r = sshbuf_put_bignum2(b, rsa_e)) != 0 ||
	    (r = sshbuf_put_bignum2(b, rsa_n)) != 0)
		ಹಿಂತಿರುಗಿ r;

	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ssh_rsa_serialize_ಖಾಸಗಿ(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *ಕೀಲಿ, ರಚನೆ sshbuf *b,
    ಎಣಿಕೆ sshkey_serialize_rep opts)
{
	ಪೂರ್ಣಾಂಕ r;
	ಸ್ಥಿರಾಂಕ BIGNUM *rsa_n, *rsa_e, *rsa_d, *rsa_iqmp, *rsa_p, *rsa_q;
	ಸ್ಥಿರಾಂಕ RSA *rsa;

	ಆದರೆ ((rsa = EVP_PKEY_get0_RSA(ಕೀಲಿ->pkey)) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_LIBCRYPTO_ERROR;
	RSA_get0_ಕೀಲಿ(rsa, &rsa_n, &rsa_e, &rsa_d);
	RSA_get0_factors(rsa, &rsa_p, &rsa_q);
	RSA_get0_crt_params(rsa, ಖಾಲಿ, ಖಾಲಿ, &rsa_iqmp);

	ಆದರೆ (!sshkey_is_cert(ಕೀಲಿ)) {
		/* Note: can't reuse ssh_rsa_serialize_public: e, n vs. n, e */
		ಆದರೆ ((r = sshbuf_put_bignum2(b, rsa_n)) != 0 ||
		    (r = sshbuf_put_bignum2(b, rsa_e)) != 0)
			ಹಿಂತಿರುಗಿ r;
	}
	ಆದರೆ ((r = sshbuf_put_bignum2(b, rsa_d)) != 0 ||
	    (r = sshbuf_put_bignum2(b, rsa_iqmp)) != 0 ||
	    (r = sshbuf_put_bignum2(b, rsa_p)) != 0 ||
	    (r = sshbuf_put_bignum2(b, rsa_q)) != 0)
		ಹಿಂತಿರುಗಿ r;

	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ssh_rsa_generate(ರಚನೆ sshkey *k, ಪೂರ್ಣಾಂಕ ಬಿಟ್ಟುಗಳು)
{
	EVP_PKEY_CTX *ctx = ಖಾಲಿ;
	EVP_PKEY *res = ಖಾಲಿ;

	ಪೂರ್ಣಾಂಕ ret = SSH_ERR_ಆಂತರಿಕ_ERROR;

	ಆದರೆ (ಬಿಟ್ಟುಗಳು < SSH_RSA_MINIMUM_MODULUS_ಗಾತ್ರ ||
	    ಬಿಟ್ಟುಗಳು > SSHBUF_MAX_BIGNUM * 8)
		ಹಿಂತಿರುಗಿ SSH_ERR_ಕೀಲಿ_ಉದ್ದಳತೆ;

	ಆದರೆ ((ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, ಖಾಲಿ)) == ಖಾಲಿ) {
		ret = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (EVP_PKEY_keygen_init(ctx) <= 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (EVP_PKEY_CTX_ಗಣ_rsa_keygen_ಬಿಟ್ಟುಗಳು(ctx, ಬಿಟ್ಟುಗಳು) <= 0) {
		ret = SSH_ERR_ಕೀಲಿ_ಉದ್ದಳತೆ;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (EVP_PKEY_keygen(ctx, &res) <= 0 || res == ಖಾಲಿ) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	/* success */
	k->pkey = res;
	ret = 0;
 ಹೊರಹೋಗು:
	EVP_PKEY_CTX_free(ctx);
	ಹಿಂತಿರುಗಿ ret;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ssh_rsa_copy_ಬಹಿರಂಗ(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *from, ರಚನೆ sshkey *ಗಮ್ಯ)
{
	ಸ್ಥಿರಾಂಕ BIGNUM *rsa_n, *rsa_e;
	BIGNUM *rsa_n_dup = ಖಾಲಿ, *rsa_e_dup = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ r = SSH_ERR_ಆಂತರಿಕ_ERROR;
	ಸ್ಥಿರಾಂಕ RSA *rsa_from;
	RSA *rsa_ಗಮ್ಯ = ಖಾಲಿ;

	ಆದರೆ ((rsa_from = EVP_PKEY_get0_RSA(from->pkey)) == ಖಾಲಿ ||
	    (rsa_ಗಮ್ಯ = RSA_new()) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_LIBCRYPTO_ERROR;

	RSA_get0_ಕೀಲಿ(rsa_from, &rsa_n, &rsa_e, ಖಾಲಿ);
	ಆದರೆ ((rsa_n_dup = BN_dup(rsa_n)) == ಖಾಲಿ ||
	    (rsa_e_dup = BN_dup(rsa_e)) == ಖಾಲಿ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (!RSA_set0_ಕೀಲಿ(rsa_ಗಮ್ಯ, rsa_n_dup, rsa_e_dup, ಖಾಲಿ)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	rsa_n_dup = rsa_e_dup = ಖಾಲಿ; /* transferred */

	ಆದರೆ (EVP_PKEY_set1_RSA(ಗಮ್ಯ->pkey, rsa_ಗಮ್ಯ) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	/* success */
	r = 0;
 ಹೊರಹೋಗು:
	RSA_free(rsa_ಗಮ್ಯ);
	BN_clear_free(rsa_n_dup);
	BN_clear_free(rsa_e_dup);
	ಹಿಂತಿರುಗಿ r;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ssh_rsa_deserialize_ಬಹಿರಂಗ(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ktype, ರಚನೆ sshbuf *b,
    ರಚನೆ sshkey *ಕೀಲಿ)
{
	ಪೂರ್ಣಾಂಕ ret = SSH_ERR_ಆಂತರಿಕ_ERROR;
	BIGNUM *rsa_n = ಖಾಲಿ, *rsa_e = ಖಾಲಿ;
	RSA *rsa = ಖಾಲಿ;

	ಆದರೆ ((rsa = RSA_new()) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_LIBCRYPTO_ERROR;

	ಆದರೆ (sshbuf_get_bignum2(b, &rsa_e) != 0 ||
	    sshbuf_get_bignum2(b, &rsa_n) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (!RSA_set0_ಕೀಲಿ(rsa, rsa_n, rsa_e, ಖಾಲಿ)) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	rsa_n = rsa_e = ಖಾಲಿ; /* transferred */
	ಆದರೆ (EVP_PKEY_set1_RSA(ಕೀಲಿ->pkey, rsa) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((ret = sshkey_check_rsa_ಉದ್ದಳತೆ(ಕೀಲಿ, 0)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ DEBUG_PK
	RSA_print_fp(stderr, rsa, 8);
#ಆದರೆ_ಅಂತ್ಯ
	/* success */
	ret = 0;
 ಹೊರಹೋಗು:
	RSA_free(rsa);
	BN_clear_free(rsa_n);
	BN_clear_free(rsa_e);
	ಹಿಂತಿರುಗಿ ret;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ssh_rsa_deserialize_ಖಾಸಗಿ(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ktype, ರಚನೆ sshbuf *b,
    ರಚನೆ sshkey *ಕೀಲಿ)
{
	ಪೂರ್ಣಾಂಕ r;
	BIGNUM *rsa_n = ಖಾಲಿ, *rsa_e = ಖಾಲಿ, *rsa_d = ಖಾಲಿ;
	BIGNUM *rsa_iqmp = ಖಾಲಿ, *rsa_p = ಖಾಲಿ, *rsa_q = ಖಾಲಿ;
	BIGNUM *rsa_dmp1 = ಖಾಲಿ, *rsa_dmq1 = ಖಾಲಿ;
	RSA *rsa = ಖಾಲಿ;

	ಆದರೆ (sshkey_is_cert(ಕೀಲಿ)) {
		/* sshkey_private_deserialize already has pubkey from cert */
		ಆದರೆ ((rsa = EVP_PKEY_get1_RSA(ಕೀಲಿ->pkey)) == ಖಾಲಿ) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			ಹೋಗು ಹೊರಹೋಗು;
		}
	} ಇಲ್ಲದಿದ್ದರೆ {
		ಆದರೆ ((rsa = RSA_new()) == ಖಾಲಿ) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			ಹೋಗು ಹೊರಹೋಗು;
		}
		/* Note: can't reuse ssh_rsa_deserialize_public: e,n vs. n,e */
		ಆದರೆ ((r = sshbuf_get_bignum2(b, &rsa_n)) != 0 ||
		    (r = sshbuf_get_bignum2(b, &rsa_e)) != 0)
			ಹೋಗು ಹೊರಹೋಗು;
		ಆದರೆ (!RSA_set0_ಕೀಲಿ(rsa, rsa_n, rsa_e, ಖಾಲಿ)) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			ಹೋಗು ಹೊರಹೋಗು;
		}
		rsa_n = rsa_e = ಖಾಲಿ; /* transferred */
	}
	ಆದರೆ ((r = sshbuf_get_bignum2(b, &rsa_d)) != 0 ||
	    (r = sshbuf_get_bignum2(b, &rsa_iqmp)) != 0 ||
	    (r = sshbuf_get_bignum2(b, &rsa_p)) != 0 ||
	    (r = sshbuf_get_bignum2(b, &rsa_q)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	ಆದರೆ ((r = ssh_rsa_complete_crt_parameters(rsa_d, rsa_p, rsa_q,
	    rsa_iqmp, &rsa_dmp1, &rsa_dmq1)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	ಆದರೆ (!RSA_set0_ಕೀಲಿ(rsa, ಖಾಲಿ, ಖಾಲಿ, rsa_d)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	rsa_d = ಖಾಲಿ; /* transferred */
	ಆದರೆ (!RSA_set0_factors(rsa, rsa_p, rsa_q)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	rsa_p = rsa_q = ಖಾಲಿ; /* transferred */
	ಆದರೆ (!RSA_set0_crt_params(rsa, rsa_dmp1, rsa_dmq1, rsa_iqmp)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	rsa_dmp1 = rsa_dmq1 = rsa_iqmp = ಖಾಲಿ;
	ಆದರೆ (RSA_blinding_on(rsa, ಖಾಲಿ) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (EVP_PKEY_set1_RSA(ಕೀಲಿ->pkey, rsa) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((r = sshkey_check_rsa_ಉದ್ದಳತೆ(ಕೀಲಿ, 0)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	/* success */
	r = 0;
 ಹೊರಹೋಗು:
	RSA_free(rsa);
	BN_clear_free(rsa_n);
	BN_clear_free(rsa_e);
	BN_clear_free(rsa_d);
	BN_clear_free(rsa_p);
	BN_clear_free(rsa_q);
	BN_clear_free(rsa_iqmp);
	BN_clear_free(rsa_dmp1);
	BN_clear_free(rsa_dmq1);
	ಹಿಂತಿರುಗಿ r;
}

ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *
ssh_rsa_hash_alg_ident(ಪೂರ್ಣಾಂಕ hash_alg)
{
	ಆಯ್ಕೆ (hash_alg) {
	ಸ್ಥಿತಿ SSH_DIGEST_SHA1:
		ಹಿಂತಿರುಗಿ "ssh-rsa";
	ಸ್ಥಿತಿ SSH_DIGEST_SHA256:
		ಹಿಂತಿರುಗಿ "rsa-sha2-256";
	ಸ್ಥಿತಿ SSH_DIGEST_SHA512:
		ಹಿಂತಿರುಗಿ "rsa-sha2-512";
	}
	ಹಿಂತಿರುಗಿ ಖಾಲಿ;
}

/*
 * Returns the hash algorithm ID for a given algorithm identifier as used
 * inside the signature blob,
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
rsa_hash_id_from_ident(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ident)
{
	ಆದರೆ (strcmp(ident, "ssh-rsa") == 0)
		ಹಿಂತಿರುಗಿ SSH_DIGEST_SHA1;
	ಆದರೆ (strcmp(ident, "rsa-sha2-256") == 0)
		ಹಿಂತಿರುಗಿ SSH_DIGEST_SHA256;
	ಆದರೆ (strcmp(ident, "rsa-sha2-512") == 0)
		ಹಿಂತಿರುಗಿ SSH_DIGEST_SHA512;
	ಹಿಂತಿರುಗಿ -1;
}

/*
 * Return the hash algorithm ID for the specified key name. This includes
 * all the cases of rsa_hash_id_from_ident() but also the certificate key
 * types.
 */
ಪೂರ್ಣಾಂಕ
ssh_rsa_hash_id_from_keyname(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *alg)
{
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((r = rsa_hash_id_from_ident(alg)) != -1)
		ಹಿಂತಿರುಗಿ r;
	ಆದರೆ (strcmp(alg, "ssh-rsa-cert-v01@openssh.com") == 0)
		ಹಿಂತಿರುಗಿ SSH_DIGEST_SHA1;
	ಆದರೆ (strcmp(alg, "rsa-sha2-256-cert-v01@openssh.com") == 0)
		ಹಿಂತಿರುಗಿ SSH_DIGEST_SHA256;
	ಆದರೆ (strcmp(alg, "rsa-sha2-512-cert-v01@openssh.com") == 0)
		ಹಿಂತಿರುಗಿ SSH_DIGEST_SHA512;
	ಹಿಂತಿರುಗಿ -1;
}

ಪೂರ್ಣಾಂಕ
ssh_rsa_complete_crt_parameters(ಸ್ಥಿರಾಂಕ BIGNUM *rsa_d, ಸ್ಥಿರಾಂಕ BIGNUM *rsa_p,
    ಸ್ಥಿರಾಂಕ BIGNUM *rsa_q, ಸ್ಥಿರಾಂಕ BIGNUM *rsa_iqmp, BIGNUM **rsa_dmp1,
    BIGNUM **rsa_dmq1)
{
	BIGNUM *aux = ಖಾಲಿ, *d_consttime = ಖಾಲಿ;
	BN_CTX *ctx = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ r;

	*rsa_dmq1 = *rsa_dmp1 = ಖಾಲಿ;
	ಆದರೆ ((ctx = BN_CTX_new()) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_ALLOC_FAIL;
	ಆದರೆ ((aux = BN_new()) == ಖಾಲಿ ||
	    (*rsa_dmq1 = BN_new()) == ಖಾಲಿ ||
	    (*rsa_dmp1 = BN_new()) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_ALLOC_FAIL;
	ಆದರೆ ((d_consttime = BN_dup(rsa_d)) == ಖಾಲಿ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	BN_ಗಣ_flags(aux, BN_FLG_CONSTTIME);
	BN_ಗಣ_flags(d_consttime, BN_FLG_CONSTTIME);

	ಆದರೆ ((BN_sub(aux, rsa_q, BN_ಮೌಲ್ಯ_one()) == 0) ||
	    (BN_mod(*rsa_dmq1, d_consttime, aux, ctx) == 0) ||
	    (BN_sub(aux, rsa_p, BN_ಮೌಲ್ಯ_one()) == 0) ||
	    (BN_mod(*rsa_dmp1, d_consttime, aux, ctx) == 0)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	/* success */
	r = 0;
 ಹೊರಹೋಗು:
	BN_clear_free(aux);
	BN_clear_free(d_consttime);
	BN_CTX_free(ctx);
	ಹಿಂತಿರುಗಿ r;
}

/* RSASSA-PKCS1-v1_5 (PKCS #1 v2.0 signature) with SHA1 */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ssh_rsa_sign(ರಚನೆ sshkey *ಕೀಲಿ,
    u_char **sigp, ಗಾತ್ರ_t *lenp,
    ಸ್ಥಿರಾಂಕ u_char *ದತ್ತಾಂಶ, ಗಾತ್ರ_t datalen,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *alg, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *sk_provider, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *sk_pin, u_int compat)
{
	u_char *sig = ಖಾಲಿ;
	ಗಾತ್ರ_t diff, len = 0;
	ಪೂರ್ಣಾಂಕ slen = 0;
	ಪೂರ್ಣಾಂಕ hash_alg, ret = SSH_ERR_ಆಂತರಿಕ_ERROR;

	ಆದರೆ (lenp != ಖಾಲಿ)
		*lenp = 0;
	ಆದರೆ (sigp != ಖಾಲಿ)
		*sigp = ಖಾಲಿ;

	ಆದರೆ (alg == ಖಾಲಿ || ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(alg) == 0)
		hash_alg = SSH_DIGEST_SHA1;
	ಇಲ್ಲದಿದ್ದರೆ
		hash_alg = ssh_rsa_hash_id_from_keyname(alg);

	ಆದರೆ (ಕೀಲಿ == ಖಾಲಿ || ಕೀಲಿ->pkey == ಖಾಲಿ || hash_alg == -1 ||
	    sshkey_type_plain(ಕೀಲಿ->type) != ಕೀಲಿ_RSA)
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_ವಾದ;
	slen = EVP_PKEY_ಗಾತ್ರ(ಕೀಲಿ->pkey);
	ಆದರೆ (slen <= 0 || slen > SSHBUF_MAX_BIGNUM)
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_ವಾದ;
	ಆದರೆ (EVP_PKEY_ಬಿಟ್ಟುಗಳು(ಕೀಲಿ->pkey) < SSH_RSA_MINIMUM_MODULUS_ಗಾತ್ರ)
		ಹಿಂತಿರುಗಿ SSH_ERR_ಕೀಲಿ_ಉದ್ದಳತೆ;

	ಆದರೆ ((ret = sshkey_pkey_digest_sign(ಕೀಲಿ->pkey, hash_alg, &sig, &len,
	    ದತ್ತಾಂಶ, datalen)) < 0)
		ಹೋಗು ಹೊರಹೋಗು;
	ಆದರೆ (len < (ಗಾತ್ರ_t)slen) {
		diff = slen - len;
		memmove(sig + diff, sig, len);
		explicit_bzero(sig, diff);
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (len > (ಗಾತ್ರ_t)slen) {
		ret = SSH_ERR_ಆಂತರಿಕ_ERROR;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((ret = ssh_rsa_encode_store_sig(hash_alg, sig, slen,
	    sigp, lenp)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;

	/* success */
	ret = 0;
 ಹೊರಹೋಗು:
	freezero(sig, slen);
	ಹಿಂತಿರುಗಿ ret;
}

ಪೂರ್ಣಾಂಕ
ssh_rsa_encode_store_sig(ಪೂರ್ಣಾಂಕ hash_alg, ಸ್ಥಿರಾಂಕ u_char *sig, ಗಾತ್ರ_t slen,
    u_char **sigp, ಗಾತ್ರ_t *lenp)
{
	ರಚನೆ sshbuf *b = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ ret = SSH_ERR_ಆಂತರಿಕ_ERROR;
	ಗಾತ್ರ_t len;

	ಆದರೆ (lenp != ಖಾಲಿ)
		*lenp = 0;
	ಆದರೆ (sigp != ಖಾಲಿ)
		*sigp = ಖಾಲಿ;

	/* Encode signature */
	ಆದರೆ ((b = sshbuf_new()) == ಖಾಲಿ) {
		ret = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((ret = sshbuf_put_cstring(b,
	    ssh_rsa_hash_alg_ident(hash_alg))) != 0 ||
	    (ret = sshbuf_put_string(b, sig, slen)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	len = sshbuf_len(b);

	/* Store signature */
	ಆದರೆ (sigp != ಖಾಲಿ) {
		ಆದರೆ ((*sigp = ಸ್ಮರಣೆ_ಕೊಡು(len)) == ಖಾಲಿ) {
			ret = SSH_ERR_ALLOC_FAIL;
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಸ್ಮರಣೆ_ನಕಲು(*sigp, sshbuf_ptr(b), len);
	}
	ಆದರೆ (lenp != ಖಾಲಿ)
		*lenp = len;
	ret = 0;
 ಹೊರಹೋಗು:
	sshbuf_free(b);
	ಹಿಂತಿರುಗಿ ret;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ssh_rsa_verify(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *ಕೀಲಿ,
    ಸ್ಥಿರಾಂಕ u_char *sig, ಗಾತ್ರ_t siglen,
    ಸ್ಥಿರಾಂಕ u_char *ದತ್ತಾಂಶ, ಗಾತ್ರ_t dlen, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *alg, u_int compat,
    ರಚನೆ sshkey_sig_details **detailsp)
{
	ಅಕ್ಷರ *sigtype = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ hash_alg, want_alg, ret = SSH_ERR_ಆಂತರಿಕ_ERROR;
	ಗಾತ್ರ_t len = 0, diff, modlen, rsasize;
	ರಚನೆ sshbuf *b = ಖಾಲಿ;
	u_char digest[SSH_DIGEST_MAX_ಉದ್ದಳತೆ], *osigblob, *sigblob = ಖಾಲಿ;

	ಆದರೆ (ಕೀಲಿ == ಖಾಲಿ || ಕೀಲಿ->pkey == ಖಾಲಿ ||
	    sshkey_type_plain(ಕೀಲಿ->type) != ಕೀಲಿ_RSA ||
	    sig == ಖಾಲಿ || siglen == 0)
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_ವಾದ;
	ಆದರೆ (EVP_PKEY_ಬಿಟ್ಟುಗಳು(ಕೀಲಿ->pkey) < SSH_RSA_MINIMUM_MODULUS_ಗಾತ್ರ)
		ಹಿಂತಿರುಗಿ SSH_ERR_ಕೀಲಿ_ಉದ್ದಳತೆ;

	ಆದರೆ ((b = sshbuf_from(sig, siglen)) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_ALLOC_FAIL;
	ಆದರೆ (sshbuf_get_cstring(b, &sigtype, ಖಾಲಿ) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((hash_alg = rsa_hash_id_from_ident(sigtype)) == -1) {
		ret = SSH_ERR_ಕೀಲಿ_TYPE_MISMATCH;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	/*
	 * Allow ssh-rsa-cert-v01 certs to generate SHA2 signatures for
	 * legacy reasons, but otherwise the signature type should match.
	 */
	ಆದರೆ (alg != ಖಾಲಿ && strcmp(alg, "ssh-rsa-cert-v01@openssh.com") != 0) {
		ಆದರೆ ((want_alg = ssh_rsa_hash_id_from_keyname(alg)) == -1) {
			ret = SSH_ERR_INVALID_ವಾದ;
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಆದರೆ (hash_alg != want_alg) {
			ret = SSH_ERR_SIGNATURE_INVALID;
			ಹೋಗು ಹೊರಹೋಗು;
		}
	}
	ಆದರೆ (sshbuf_get_string(b, &sigblob, &len) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (sshbuf_len(b) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_ದತ್ತಾಂಶ;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	/* RSA_verify expects a signature of RSA_size */
	modlen = EVP_PKEY_ಗಾತ್ರ(ಕೀಲಿ->pkey);
	ಆದರೆ (len > modlen) {
		ret = SSH_ERR_ಕೀಲಿ_ಬಿಟ್ಟುಗಳು_MISMATCH;
		ಹೋಗು ಹೊರಹೋಗು;
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (len < modlen) {
		diff = modlen - len;
		osigblob = sigblob;
		ಆದರೆ ((sigblob = realloc(sigblob, modlen)) == ಖಾಲಿ) {
			sigblob = osigblob; /* put it back for clear/free */
			ret = SSH_ERR_ALLOC_FAIL;
			ಹೋಗು ಹೊರಹೋಗು;
		}
		memmove(sigblob + diff, sigblob, len);
		explicit_bzero(sigblob, diff);
		len = modlen;
	}

	rsasize = EVP_PKEY_ಗಾತ್ರ(ಕೀಲಿ->pkey);
	ಆದರೆ (rsasize <= 0 || rsasize > SSHBUF_MAX_BIGNUM ||
	    len == 0 || len > rsasize) {
		ret = SSH_ERR_INVALID_ವಾದ;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ret = sshkey_pkey_digest_verify(ಕೀಲಿ->pkey, hash_alg, ದತ್ತಾಂಶ, dlen,
	    sigblob, len);

 ಹೊರಹೋಗು:
	freezero(sigblob, len);
	ಬಿಡುಗಡೆ(sigtype);
	sshbuf_free(b);
	explicit_bzero(digest, ಗಾತ್ರ(digest));
	ಹಿಂತಿರುಗಿ ret;
}

ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey_impl_funcs sshkey_rsa_funcs = {
	/* .size = */		ssh_rsa_ಗಾತ್ರ,
	/* .alloc = */		ssh_rsa_alloc,
	/* .cleanup = */	ssh_rsa_cleanup,
	/* .equal = */		ssh_rsa_equal,
	/* .ssh_serialize_public = */ ssh_rsa_serialize_ಬಹಿರಂಗ,
	/* .ssh_deserialize_public = */ ssh_rsa_deserialize_ಬಹಿರಂಗ,
	/* .ssh_serialize_private = */ ssh_rsa_serialize_ಖಾಸಗಿ,
	/* .ssh_deserialize_private = */ ssh_rsa_deserialize_ಖಾಸಗಿ,
	/* .generate = */	ssh_rsa_generate,
	/* .copy_public = */	ssh_rsa_copy_ಬಹಿರಂಗ,
	/* .sign = */		ssh_rsa_sign,
	/* .verify = */		ssh_rsa_verify,
};

ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey_impl sshkey_rsa_impl = {
	/* .name = */		"ssh-rsa",
	/* .shortname = */	"RSA",
	/* .sigalg = */		ಖಾಲಿ,
	/* .type = */		ಕೀಲಿ_RSA,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};

ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey_impl sshkey_rsa_cert_impl = {
	/* .name = */		"ssh-rsa-cert-v01@openssh.com",
	/* .shortname = */	"RSA-CERT",
	/* .sigalg = */		ಖಾಲಿ,
	/* .type = */		ಕೀಲಿ_RSA_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};

/* SHA2 signature algorithms */

ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey_impl sshkey_rsa_sha256_impl = {
	/* .name = */		"rsa-sha2-256",
	/* .shortname = */	"RSA",
	/* .sigalg = */		ಖಾಲಿ,
	/* .type = */		ಕೀಲಿ_RSA,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	1,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};

ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey_impl sshkey_rsa_sha512_impl = {
	/* .name = */		"rsa-sha2-512",
	/* .shortname = */	"RSA",
	/* .sigalg = */		ಖಾಲಿ,
	/* .type = */		ಕೀಲಿ_RSA,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	1,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};

ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey_impl sshkey_rsa_sha256_cert_impl = {
	/* .name = */		"rsa-sha2-256-cert-v01@openssh.com",
	/* .shortname = */	"RSA-CERT",
	/* .sigalg = */		"rsa-sha2-256",
	/* .type = */		ಕೀಲಿ_RSA_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	1,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};

ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey_impl sshkey_rsa_sha512_cert_impl = {
	/* .name = */		"rsa-sha2-512-cert-v01@openssh.com",
	/* .shortname = */	"RSA-CERT",
	/* .sigalg = */		"rsa-sha2-512",
	/* .type = */		ಕೀಲಿ_RSA_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	1,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};
#ಆದರೆ_ಅಂತ್ಯ /* WITH_OPENSSL */
