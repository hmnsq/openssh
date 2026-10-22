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

#ifdef WITH_OPENSSL
#ಅನ್ತರ್ಭಾವ "openbsd-compat/openssl-compat.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>

#ಅನ್ತರ್ಭಾವ <openssl/bn.h>
#ಅನ್ತರ್ಭಾವ <openssl/evp.h>

#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <string.h>

#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "ssherr.h"
#define SSHKEY_INTERNAL
#ಅನ್ತರ್ಭಾವ "sshkey.h"
#ಅನ್ತರ್ಭಾವ "digest.h"

ಸ್ಥಿರ u_int
ssh_rsa_size(ಧ್ರುವ ಸಂರಚನಾ sshkey *k)
{
	ಯದಿ (k->pkey == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಪ್ರತ್ಯಾಗಮ EVP_PKEY_bits(k->pkey);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
ssh_rsa_alloc(ಸಂರಚನಾ sshkey *k)
{
	ಯದಿ ((k->pkey = EVP_PKEY_new()) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ALLOC_FAIL;
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಶೂನ್ಯ
ssh_rsa_cleanup(ಸಂರಚನಾ sshkey *k)
{
	EVP_PKEY_free(k->pkey);
	k->pkey = ರಿಕ್ತ;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
ssh_rsa_equal(ಧ್ರುವ ಸಂರಚನಾ sshkey *a, ಧ್ರುವ ಸಂರಚನಾ sshkey *b)
{
	ಯದಿ (a->pkey == ರಿಕ್ತ || b->pkey == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಪ್ರತ್ಯಾಗಮ EVP_PKEY_cmp(a->pkey, b->pkey) == 1;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
ssh_rsa_serialize_public(ಧ್ರುವ ಸಂರಚನಾ sshkey *ಕೀಲಿ, ಸಂರಚನಾ sshbuf *b,
    ಗಣನಾ sshkey_serialize_rep opts)
{
	ಪೂರ್ಣಾಙ್ಕ r;
	ಧ್ರುವ BIGNUM *rsa_n, *rsa_e;
	ಧ್ರುವ RSA *rsa;

	ಯದಿ (ಕೀಲಿ->pkey == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_ARGUMENT;
	ಯದಿ ((rsa = EVP_PKEY_get0_RSA(ಕೀಲಿ->pkey)) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_LIBCRYPTO_ERROR;

	RSA_get0_ಕೀಲಿ(rsa, &rsa_n, &rsa_e, ರಿಕ್ತ);
	ಯದಿ ((r = sshbuf_put_bignum2(b, rsa_e)) != 0 ||
	    (r = sshbuf_put_bignum2(b, rsa_n)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;

	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
ssh_rsa_serialize_private(ಧ್ರುವ ಸಂರಚನಾ sshkey *ಕೀಲಿ, ಸಂರಚನಾ sshbuf *b,
    ಗಣನಾ sshkey_serialize_rep opts)
{
	ಪೂರ್ಣಾಙ್ಕ r;
	ಧ್ರುವ BIGNUM *rsa_n, *rsa_e, *rsa_d, *rsa_iqmp, *rsa_p, *rsa_q;
	ಧ್ರುವ RSA *rsa;

	ಯದಿ ((rsa = EVP_PKEY_get0_RSA(ಕೀಲಿ->pkey)) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_LIBCRYPTO_ERROR;
	RSA_get0_ಕೀಲಿ(rsa, &rsa_n, &rsa_e, &rsa_d);
	RSA_get0_factors(rsa, &rsa_p, &rsa_q);
	RSA_get0_crt_params(rsa, ರಿಕ್ತ, ರಿಕ್ತ, &rsa_iqmp);

	ಯದಿ (!sshkey_is_cert(ಕೀಲಿ)) {
		/* Note: can't reuse ssh_rsa_serialize_public: e, n vs. n, e */
		ಯದಿ ((r = sshbuf_put_bignum2(b, rsa_n)) != 0 ||
		    (r = sshbuf_put_bignum2(b, rsa_e)) != 0)
			ಪ್ರತ್ಯಾಗಮ r;
	}
	ಯದಿ ((r = sshbuf_put_bignum2(b, rsa_d)) != 0 ||
	    (r = sshbuf_put_bignum2(b, rsa_iqmp)) != 0 ||
	    (r = sshbuf_put_bignum2(b, rsa_p)) != 0 ||
	    (r = sshbuf_put_bignum2(b, rsa_q)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;

	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
ssh_rsa_generate(ಸಂರಚನಾ sshkey *k, ಪೂರ್ಣಾಙ್ಕ bits)
{
	EVP_PKEY_CTX *ctx = ರಿಕ್ತ;
	EVP_PKEY *res = ರಿಕ್ತ;

	ಪೂರ್ಣಾಙ್ಕ ret = SSH_ERR_INTERNAL_ERROR;

	ಯದಿ (bits < SSH_RSA_MINIMUM_MODULUS_SIZE ||
	    bits > SSHBUF_MAX_BIGNUM * 8)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ಕೀಲಿ_LENGTH;

	ಯದಿ ((ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, ರಿಕ್ತ)) == ರಿಕ್ತ) {
		ret = SSH_ERR_ALLOC_FAIL;
		ಗಚ್ಛ out;
	}
	ಯದಿ (EVP_PKEY_keygen_init(ctx) <= 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		ಗಚ್ಛ out;
	}
	ಯದಿ (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0) {
		ret = SSH_ERR_ಕೀಲಿ_LENGTH;
		ಗಚ್ಛ out;
	}
	ಯದಿ (EVP_PKEY_keygen(ctx, &res) <= 0 || res == ರಿಕ್ತ) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		ಗಚ್ಛ out;
	}
	/* success */
	k->pkey = res;
	ret = 0;
 out:
	EVP_PKEY_CTX_free(ctx);
	ಪ್ರತ್ಯಾಗಮ ret;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
ssh_rsa_copy_public(ಧ್ರುವ ಸಂರಚನಾ sshkey *from, ಸಂರಚನಾ sshkey *to)
{
	ಧ್ರುವ BIGNUM *rsa_n, *rsa_e;
	BIGNUM *rsa_n_dup = ರಿಕ್ತ, *rsa_e_dup = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ r = SSH_ERR_INTERNAL_ERROR;
	ಧ್ರುವ RSA *rsa_from;
	RSA *rsa_to = ರಿಕ್ತ;

	ಯದಿ ((rsa_from = EVP_PKEY_get0_RSA(from->pkey)) == ರಿಕ್ತ ||
	    (rsa_to = RSA_new()) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_LIBCRYPTO_ERROR;

	RSA_get0_ಕೀಲಿ(rsa_from, &rsa_n, &rsa_e, ರಿಕ್ತ);
	ಯದಿ ((rsa_n_dup = BN_dup(rsa_n)) == ರಿಕ್ತ ||
	    (rsa_e_dup = BN_dup(rsa_e)) == ರಿಕ್ತ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಗಚ್ಛ out;
	}
	ಯದಿ (!RSA_set0_ಕೀಲಿ(rsa_to, rsa_n_dup, rsa_e_dup, ರಿಕ್ತ)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		ಗಚ್ಛ out;
	}
	rsa_n_dup = rsa_e_dup = ರಿಕ್ತ; /* transferred */

	ಯದಿ (EVP_PKEY_set1_RSA(to->pkey, rsa_to) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		ಗಚ್ಛ out;
	}
	/* success */
	r = 0;
 out:
	RSA_free(rsa_to);
	BN_clear_free(rsa_n_dup);
	BN_clear_free(rsa_e_dup);
	ಪ್ರತ್ಯಾಗಮ r;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
ssh_rsa_deserialize_public(ಧ್ರುವ ವರ್ಣ *ktype, ಸಂರಚನಾ sshbuf *b,
    ಸಂರಚನಾ sshkey *ಕೀಲಿ)
{
	ಪೂರ್ಣಾಙ್ಕ ret = SSH_ERR_INTERNAL_ERROR;
	BIGNUM *rsa_n = ರಿಕ್ತ, *rsa_e = ರಿಕ್ತ;
	RSA *rsa = ರಿಕ್ತ;

	ಯದಿ ((rsa = RSA_new()) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_LIBCRYPTO_ERROR;

	ಯದಿ (sshbuf_get_bignum2(b, &rsa_e) != 0 ||
	    sshbuf_get_bignum2(b, &rsa_n) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		ಗಚ್ಛ out;
	}
	ಯದಿ (!RSA_set0_ಕೀಲಿ(rsa, rsa_n, rsa_e, ರಿಕ್ತ)) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		ಗಚ್ಛ out;
	}
	rsa_n = rsa_e = ರಿಕ್ತ; /* transferred */
	ಯದಿ (EVP_PKEY_set1_RSA(ಕೀಲಿ->pkey, rsa) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		ಗಚ್ಛ out;
	}
	ಯದಿ ((ret = sshkey_check_rsa_length(ಕೀಲಿ, 0)) != 0)
		ಗಚ್ಛ out;
#ifdef DEBUG_PK
	RSA_print_fp(stderr, rsa, 8);
#endif
	/* success */
	ret = 0;
 out:
	RSA_free(rsa);
	BN_clear_free(rsa_n);
	BN_clear_free(rsa_e);
	ಪ್ರತ್ಯಾಗಮ ret;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
ssh_rsa_deserialize_private(ಧ್ರುವ ವರ್ಣ *ktype, ಸಂರಚನಾ sshbuf *b,
    ಸಂರಚನಾ sshkey *ಕೀಲಿ)
{
	ಪೂರ್ಣಾಙ್ಕ r;
	BIGNUM *rsa_n = ರಿಕ್ತ, *rsa_e = ರಿಕ್ತ, *rsa_d = ರಿಕ್ತ;
	BIGNUM *rsa_iqmp = ರಿಕ್ತ, *rsa_p = ರಿಕ್ತ, *rsa_q = ರಿಕ್ತ;
	BIGNUM *rsa_dmp1 = ರಿಕ್ತ, *rsa_dmq1 = ರಿಕ್ತ;
	RSA *rsa = ರಿಕ್ತ;

	ಯದಿ (sshkey_is_cert(ಕೀಲಿ)) {
		/* sshkey_private_deserialize already has pubkey from cert */
		ಯದಿ ((rsa = EVP_PKEY_get1_RSA(ಕೀಲಿ->pkey)) == ರಿಕ್ತ) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			ಗಚ್ಛ out;
		}
	} ಅನ್ಯಥಾ {
		ಯದಿ ((rsa = RSA_new()) == ರಿಕ್ತ) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			ಗಚ್ಛ out;
		}
		/* Note: can't reuse ssh_rsa_deserialize_public: e,n vs. n,e */
		ಯದಿ ((r = sshbuf_get_bignum2(b, &rsa_n)) != 0 ||
		    (r = sshbuf_get_bignum2(b, &rsa_e)) != 0)
			ಗಚ್ಛ out;
		ಯದಿ (!RSA_set0_ಕೀಲಿ(rsa, rsa_n, rsa_e, ರಿಕ್ತ)) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			ಗಚ್ಛ out;
		}
		rsa_n = rsa_e = ರಿಕ್ತ; /* transferred */
	}
	ಯದಿ ((r = sshbuf_get_bignum2(b, &rsa_d)) != 0 ||
	    (r = sshbuf_get_bignum2(b, &rsa_iqmp)) != 0 ||
	    (r = sshbuf_get_bignum2(b, &rsa_p)) != 0 ||
	    (r = sshbuf_get_bignum2(b, &rsa_q)) != 0)
		ಗಚ್ಛ out;
	ಯದಿ ((r = ssh_rsa_complete_crt_parameters(rsa_d, rsa_p, rsa_q,
	    rsa_iqmp, &rsa_dmp1, &rsa_dmq1)) != 0)
		ಗಚ್ಛ out;
	ಯದಿ (!RSA_set0_ಕೀಲಿ(rsa, ರಿಕ್ತ, ರಿಕ್ತ, rsa_d)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		ಗಚ್ಛ out;
	}
	rsa_d = ರಿಕ್ತ; /* transferred */
	ಯದಿ (!RSA_set0_factors(rsa, rsa_p, rsa_q)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		ಗಚ್ಛ out;
	}
	rsa_p = rsa_q = ರಿಕ್ತ; /* transferred */
	ಯದಿ (!RSA_set0_crt_params(rsa, rsa_dmp1, rsa_dmq1, rsa_iqmp)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		ಗಚ್ಛ out;
	}
	rsa_dmp1 = rsa_dmq1 = rsa_iqmp = ರಿಕ್ತ;
	ಯದಿ (RSA_blinding_on(rsa, ರಿಕ್ತ) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		ಗಚ್ಛ out;
	}
	ಯದಿ (EVP_PKEY_set1_RSA(ಕೀಲಿ->pkey, rsa) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		ಗಚ್ಛ out;
	}
	ಯದಿ ((r = sshkey_check_rsa_length(ಕೀಲಿ, 0)) != 0)
		ಗಚ್ಛ out;
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
	ಪ್ರತ್ಯಾಗಮ r;
}

ಧ್ರುವ ವರ್ಣ *
ssh_rsa_hash_alg_ident(ಪೂರ್ಣಾಙ್ಕ hash_alg)
{
	ವಿಕಲ್ಪ (hash_alg) {
	ಪಕ್ಷ SSH_DIGEST_SHA1:
		ಪ್ರತ್ಯಾಗಮ "ssh-rsa";
	ಪಕ್ಷ SSH_DIGEST_SHA256:
		ಪ್ರತ್ಯಾಗಮ "rsa-sha2-256";
	ಪಕ್ಷ SSH_DIGEST_SHA512:
		ಪ್ರತ್ಯಾಗಮ "rsa-sha2-512";
	}
	ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
}

/*
 * Returns the hash algorithm ID for a given algorithm identifier as used
 * inside the signature blob,
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
rsa_hash_id_from_ident(ಧ್ರುವ ವರ್ಣ *ident)
{
	ಯದಿ (strcmp(ident, "ssh-rsa") == 0)
		ಪ್ರತ್ಯಾಗಮ SSH_DIGEST_SHA1;
	ಯದಿ (strcmp(ident, "rsa-sha2-256") == 0)
		ಪ್ರತ್ಯಾಗಮ SSH_DIGEST_SHA256;
	ಯದಿ (strcmp(ident, "rsa-sha2-512") == 0)
		ಪ್ರತ್ಯಾಗಮ SSH_DIGEST_SHA512;
	ಪ್ರತ್ಯಾಗಮ -1;
}

/*
 * Return the hash algorithm ID for the specified key name. This includes
 * all the cases of rsa_hash_id_from_ident() but also the certificate key
 * types.
 */
ಪೂರ್ಣಾಙ್ಕ
ssh_rsa_hash_id_from_keyname(ಧ್ರುವ ವರ್ಣ *alg)
{
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((r = rsa_hash_id_from_ident(alg)) != -1)
		ಪ್ರತ್ಯಾಗಮ r;
	ಯದಿ (strcmp(alg, "ssh-rsa-cert-v01@openssh.com") == 0)
		ಪ್ರತ್ಯಾಗಮ SSH_DIGEST_SHA1;
	ಯದಿ (strcmp(alg, "rsa-sha2-256-cert-v01@openssh.com") == 0)
		ಪ್ರತ್ಯಾಗಮ SSH_DIGEST_SHA256;
	ಯದಿ (strcmp(alg, "rsa-sha2-512-cert-v01@openssh.com") == 0)
		ಪ್ರತ್ಯಾಗಮ SSH_DIGEST_SHA512;
	ಪ್ರತ್ಯಾಗಮ -1;
}

ಪೂರ್ಣಾಙ್ಕ
ssh_rsa_complete_crt_parameters(ಧ್ರುವ BIGNUM *rsa_d, ಧ್ರುವ BIGNUM *rsa_p,
    ಧ್ರುವ BIGNUM *rsa_q, ಧ್ರುವ BIGNUM *rsa_iqmp, BIGNUM **rsa_dmp1,
    BIGNUM **rsa_dmq1)
{
	BIGNUM *aux = ರಿಕ್ತ, *d_consttime = ರಿಕ್ತ;
	BN_CTX *ctx = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ r;

	*rsa_dmq1 = *rsa_dmp1 = ರಿಕ್ತ;
	ಯದಿ ((ctx = BN_CTX_new()) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ALLOC_FAIL;
	ಯದಿ ((aux = BN_new()) == ರಿಕ್ತ ||
	    (*rsa_dmq1 = BN_new()) == ರಿಕ್ತ ||
	    (*rsa_dmp1 = BN_new()) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ALLOC_FAIL;
	ಯದಿ ((d_consttime = BN_dup(rsa_d)) == ರಿಕ್ತ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಗಚ್ಛ out;
	}
	BN_set_flags(aux, BN_FLG_CONSTTIME);
	BN_set_flags(d_consttime, BN_FLG_CONSTTIME);

	ಯದಿ ((BN_sub(aux, rsa_q, BN_ಮೌಲ್ಯ_one()) == 0) ||
	    (BN_mod(*rsa_dmq1, d_consttime, aux, ctx) == 0) ||
	    (BN_sub(aux, rsa_p, BN_ಮೌಲ್ಯ_one()) == 0) ||
	    (BN_mod(*rsa_dmp1, d_consttime, aux, ctx) == 0)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		ಗಚ್ಛ out;
	}
	/* success */
	r = 0;
 out:
	BN_clear_free(aux);
	BN_clear_free(d_consttime);
	BN_CTX_free(ctx);
	ಪ್ರತ್ಯಾಗಮ r;
}

/* RSASSA-PKCS1-v1_5 (PKCS #1 v2.0 signature) with SHA1 */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
ssh_rsa_sign(ಸಂರಚನಾ sshkey *ಕೀಲಿ,
    u_char **sigp, size_t *lenp,
    ಧ್ರುವ u_char *data, size_t datalen,
    ಧ್ರುವ ವರ್ಣ *alg, ಧ್ರುವ ವರ್ಣ *sk_provider, ಧ್ರುವ ವರ್ಣ *sk_pin, u_int compat)
{
	u_char *sig = ರಿಕ್ತ;
	size_t diff, len = 0;
	ಪೂರ್ಣಾಙ್ಕ slen = 0;
	ಪೂರ್ಣಾಙ್ಕ hash_alg, ret = SSH_ERR_INTERNAL_ERROR;

	ಯದಿ (lenp != ರಿಕ್ತ)
		*lenp = 0;
	ಯದಿ (sigp != ರಿಕ್ತ)
		*sigp = ರಿಕ್ತ;

	ಯದಿ (alg == ರಿಕ್ತ || strlen(alg) == 0)
		hash_alg = SSH_DIGEST_SHA1;
	ಅನ್ಯಥಾ
		hash_alg = ssh_rsa_hash_id_from_keyname(alg);

	ಯದಿ (ಕೀಲಿ == ರಿಕ್ತ || ಕೀಲಿ->pkey == ರಿಕ್ತ || hash_alg == -1 ||
	    sshkey_type_plain(ಕೀಲಿ->type) != ಕೀಲಿ_RSA)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_ARGUMENT;
	slen = EVP_PKEY_size(ಕೀಲಿ->pkey);
	ಯದಿ (slen <= 0 || slen > SSHBUF_MAX_BIGNUM)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_ARGUMENT;
	ಯದಿ (EVP_PKEY_bits(ಕೀಲಿ->pkey) < SSH_RSA_MINIMUM_MODULUS_SIZE)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ಕೀಲಿ_LENGTH;

	ಯದಿ ((ret = sshkey_pkey_digest_sign(ಕೀಲಿ->pkey, hash_alg, &sig, &len,
	    data, datalen)) < 0)
		ಗಚ್ಛ out;
	ಯದಿ (len < (size_t)slen) {
		diff = slen - len;
		memmove(sig + diff, sig, len);
		explicit_bzero(sig, diff);
	} ಅನ್ಯಥಾ ಯದಿ (len > (size_t)slen) {
		ret = SSH_ERR_INTERNAL_ERROR;
		ಗಚ್ಛ out;
	}
	ಯದಿ ((ret = ssh_rsa_encode_store_sig(hash_alg, sig, slen,
	    sigp, lenp)) != 0)
		ಗಚ್ಛ out;

	/* success */
	ret = 0;
 out:
	freezero(sig, slen);
	ಪ್ರತ್ಯಾಗಮ ret;
}

ಪೂರ್ಣಾಙ್ಕ
ssh_rsa_encode_store_sig(ಪೂರ್ಣಾಙ್ಕ hash_alg, ಧ್ರುವ u_char *sig, size_t slen,
    u_char **sigp, size_t *lenp)
{
	ಸಂರಚನಾ sshbuf *b = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ ret = SSH_ERR_INTERNAL_ERROR;
	size_t len;

	ಯದಿ (lenp != ರಿಕ್ತ)
		*lenp = 0;
	ಯದಿ (sigp != ರಿಕ್ತ)
		*sigp = ರಿಕ್ತ;

	/* Encode signature */
	ಯದಿ ((b = sshbuf_new()) == ರಿಕ್ತ) {
		ret = SSH_ERR_ALLOC_FAIL;
		ಗಚ್ಛ out;
	}
	ಯದಿ ((ret = sshbuf_put_cstring(b,
	    ssh_rsa_hash_alg_ident(hash_alg))) != 0 ||
	    (ret = sshbuf_put_string(b, sig, slen)) != 0)
		ಗಚ್ಛ out;
	len = sshbuf_len(b);

	/* Store signature */
	ಯದಿ (sigp != ರಿಕ್ತ) {
		ಯದಿ ((*sigp = malloc(len)) == ರಿಕ್ತ) {
			ret = SSH_ERR_ALLOC_FAIL;
			ಗಚ್ಛ out;
		}
		memcpy(*sigp, sshbuf_ptr(b), len);
	}
	ಯದಿ (lenp != ರಿಕ್ತ)
		*lenp = len;
	ret = 0;
 out:
	sshbuf_free(b);
	ಪ್ರತ್ಯಾಗಮ ret;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
ssh_rsa_verify(ಧ್ರುವ ಸಂರಚನಾ sshkey *ಕೀಲಿ,
    ಧ್ರುವ u_char *sig, size_t siglen,
    ಧ್ರುವ u_char *data, size_t dlen, ಧ್ರುವ ವರ್ಣ *alg, u_int compat,
    ಸಂರಚನಾ sshkey_sig_details **detailsp)
{
	ವರ್ಣ *sigtype = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ hash_alg, want_alg, ret = SSH_ERR_INTERNAL_ERROR;
	size_t len = 0, diff, modlen, rsasize;
	ಸಂರಚನಾ sshbuf *b = ರಿಕ್ತ;
	u_char digest[SSH_DIGEST_MAX_LENGTH], *osigblob, *sigblob = ರಿಕ್ತ;

	ಯದಿ (ಕೀಲಿ == ರಿಕ್ತ || ಕೀಲಿ->pkey == ರಿಕ್ತ ||
	    sshkey_type_plain(ಕೀಲಿ->type) != ಕೀಲಿ_RSA ||
	    sig == ರಿಕ್ತ || siglen == 0)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_ARGUMENT;
	ಯದಿ (EVP_PKEY_bits(ಕೀಲಿ->pkey) < SSH_RSA_MINIMUM_MODULUS_SIZE)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ಕೀಲಿ_LENGTH;

	ಯದಿ ((b = sshbuf_from(sig, siglen)) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ALLOC_FAIL;
	ಯದಿ (sshbuf_get_cstring(b, &sigtype, ರಿಕ್ತ) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		ಗಚ್ಛ out;
	}
	ಯದಿ ((hash_alg = rsa_hash_id_from_ident(sigtype)) == -1) {
		ret = SSH_ERR_ಕೀಲಿ_TYPE_MISMATCH;
		ಗಚ್ಛ out;
	}
	/*
	 * Allow ssh-rsa-cert-v01 certs to generate SHA2 signatures for
	 * legacy reasons, but otherwise the signature type should match.
	 */
	ಯದಿ (alg != ರಿಕ್ತ && strcmp(alg, "ssh-rsa-cert-v01@openssh.com") != 0) {
		ಯದಿ ((want_alg = ssh_rsa_hash_id_from_keyname(alg)) == -1) {
			ret = SSH_ERR_INVALID_ARGUMENT;
			ಗಚ್ಛ out;
		}
		ಯದಿ (hash_alg != want_alg) {
			ret = SSH_ERR_SIGNATURE_INVALID;
			ಗಚ್ಛ out;
		}
	}
	ಯದಿ (sshbuf_get_string(b, &sigblob, &len) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		ಗಚ್ಛ out;
	}
	ಯದಿ (sshbuf_len(b) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		ಗಚ್ಛ out;
	}
	/* RSA_verify expects a signature of RSA_size */
	modlen = EVP_PKEY_size(ಕೀಲಿ->pkey);
	ಯದಿ (len > modlen) {
		ret = SSH_ERR_ಕೀಲಿ_BITS_MISMATCH;
		ಗಚ್ಛ out;
	} ಅನ್ಯಥಾ ಯದಿ (len < modlen) {
		diff = modlen - len;
		osigblob = sigblob;
		ಯದಿ ((sigblob = realloc(sigblob, modlen)) == ರಿಕ್ತ) {
			sigblob = osigblob; /* put it back for clear/free */
			ret = SSH_ERR_ALLOC_FAIL;
			ಗಚ್ಛ out;
		}
		memmove(sigblob + diff, sigblob, len);
		explicit_bzero(sigblob, diff);
		len = modlen;
	}

	rsasize = EVP_PKEY_size(ಕೀಲಿ->pkey);
	ಯದಿ (rsasize <= 0 || rsasize > SSHBUF_MAX_BIGNUM ||
	    len == 0 || len > rsasize) {
		ret = SSH_ERR_INVALID_ARGUMENT;
		ಗಚ್ಛ out;
	}
	ret = sshkey_pkey_digest_verify(ಕೀಲಿ->pkey, hash_alg, data, dlen,
	    sigblob, len);

 out:
	freezero(sigblob, len);
	ಮುಕ್ತ(sigtype);
	sshbuf_free(b);
	explicit_bzero(digest, ಪರಿಮಾಣ(digest));
	ಪ್ರತ್ಯಾಗಮ ret;
}

ಸ್ಥಿರ ಧ್ರುವ ಸಂರಚನಾ sshkey_impl_funcs sshkey_rsa_funcs = {
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

ಧ್ರುವ ಸಂರಚನಾ sshkey_impl sshkey_rsa_impl = {
	/* .name = */		"ssh-rsa",
	/* .shortname = */	"RSA",
	/* .sigalg = */		ರಿಕ್ತ,
	/* .type = */		ಕೀಲಿ_RSA,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};

ಧ್ರುವ ಸಂರಚನಾ sshkey_impl sshkey_rsa_cert_impl = {
	/* .name = */		"ssh-rsa-cert-v01@openssh.com",
	/* .shortname = */	"RSA-CERT",
	/* .sigalg = */		ರಿಕ್ತ,
	/* .type = */		ಕೀಲಿ_RSA_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};

/* SHA2 signature algorithms */

ಧ್ರುವ ಸಂರಚನಾ sshkey_impl sshkey_rsa_sha256_impl = {
	/* .name = */		"rsa-sha2-256",
	/* .shortname = */	"RSA",
	/* .sigalg = */		ರಿಕ್ತ,
	/* .type = */		ಕೀಲಿ_RSA,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	1,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};

ಧ್ರುವ ಸಂರಚನಾ sshkey_impl sshkey_rsa_sha512_impl = {
	/* .name = */		"rsa-sha2-512",
	/* .shortname = */	"RSA",
	/* .sigalg = */		ರಿಕ್ತ,
	/* .type = */		ಕೀಲಿ_RSA,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	1,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};

ಧ್ರುವ ಸಂರಚನಾ sshkey_impl sshkey_rsa_sha256_cert_impl = {
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

ಧ್ರುವ ಸಂರಚನಾ sshkey_impl sshkey_rsa_sha512_cert_impl = {
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
#endif /* WITH_OPENSSL */
