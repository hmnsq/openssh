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

#அந்தர்பாவ "includes.h"

#ifdef WITH_OPENSSL
#அந்தர்பாவ "openbsd-compat/openssl-compat.h"

#அந்தர்பாவ <sys/types.h>

#அந்தர்பாவ <openssl/bn.h>
#அந்தர்பாவ <openssl/evp.h>

#அந்தர்பாவ <stdarg.h>
#அந்தர்பாவ <string.h>

#அந்தர்பாவ "sshbuf.h"
#அந்தர்பாவ "ssherr.h"
#define SSHKEY_INTERNAL
#அந்தர்பாவ "sshkey.h"
#அந்தர்பாவ "digest.h"

நிலையான u_int
ssh_rsa_size(மாறிலி கட்டமைப்பு sshkey *k)
{
	எனில் (k->pkey == வெற்று)
		திரும்பு 0;
	திரும்பு EVP_PKEY_bits(k->pkey);
}

நிலையான முழு
ssh_rsa_alloc(கட்டமைப்பு sshkey *k)
{
	எனில் ((k->pkey = EVP_PKEY_new()) == வெற்று)
		திரும்பு SSH_ERR_ALLOC_FAIL;
	திரும்பு 0;
}

நிலையான வெறுமை
ssh_rsa_cleanup(கட்டமைப்பு sshkey *k)
{
	EVP_PKEY_free(k->pkey);
	k->pkey = வெற்று;
}

நிலையான முழு
ssh_rsa_equal(மாறிலி கட்டமைப்பு sshkey *a, மாறிலி கட்டமைப்பு sshkey *b)
{
	எனில் (a->pkey == வெற்று || b->pkey == வெற்று)
		திரும்பு 0;
	திரும்பு EVP_PKEY_cmp(a->pkey, b->pkey) == 1;
}

நிலையான முழு
ssh_rsa_serialize_public(மாறிலி கட்டமைப்பு sshkey *சாவி, கட்டமைப்பு sshbuf *b,
    எண்ணிக்கை sshkey_serialize_rep opts)
{
	முழு r;
	மாறிலி BIGNUM *rsa_n, *rsa_e;
	மாறிலி RSA *rsa;

	எனில் (சாவி->pkey == வெற்று)
		திரும்பு SSH_ERR_INVALID_ARGUMENT;
	எனில் ((rsa = EVP_PKEY_get0_RSA(சாவி->pkey)) == வெற்று)
		திரும்பு SSH_ERR_LIBCRYPTO_ERROR;

	RSA_get0_சாவி(rsa, &rsa_n, &rsa_e, வெற்று);
	எனில் ((r = sshbuf_put_bignum2(b, rsa_e)) != 0 ||
	    (r = sshbuf_put_bignum2(b, rsa_n)) != 0)
		திரும்பு r;

	திரும்பு 0;
}

நிலையான முழு
ssh_rsa_serialize_private(மாறிலி கட்டமைப்பு sshkey *சாவி, கட்டமைப்பு sshbuf *b,
    எண்ணிக்கை sshkey_serialize_rep opts)
{
	முழு r;
	மாறிலி BIGNUM *rsa_n, *rsa_e, *rsa_d, *rsa_iqmp, *rsa_p, *rsa_q;
	மாறிலி RSA *rsa;

	எனில் ((rsa = EVP_PKEY_get0_RSA(சாவி->pkey)) == வெற்று)
		திரும்பு SSH_ERR_LIBCRYPTO_ERROR;
	RSA_get0_சாவி(rsa, &rsa_n, &rsa_e, &rsa_d);
	RSA_get0_factors(rsa, &rsa_p, &rsa_q);
	RSA_get0_crt_params(rsa, வெற்று, வெற்று, &rsa_iqmp);

	எனில் (!sshkey_is_cert(சாவி)) {
		/* Note: can't reuse ssh_rsa_serialize_public: e, n vs. n, e */
		எனில் ((r = sshbuf_put_bignum2(b, rsa_n)) != 0 ||
		    (r = sshbuf_put_bignum2(b, rsa_e)) != 0)
			திரும்பு r;
	}
	எனில் ((r = sshbuf_put_bignum2(b, rsa_d)) != 0 ||
	    (r = sshbuf_put_bignum2(b, rsa_iqmp)) != 0 ||
	    (r = sshbuf_put_bignum2(b, rsa_p)) != 0 ||
	    (r = sshbuf_put_bignum2(b, rsa_q)) != 0)
		திரும்பு r;

	திரும்பு 0;
}

நிலையான முழு
ssh_rsa_generate(கட்டமைப்பு sshkey *k, முழு bits)
{
	EVP_PKEY_CTX *ctx = வெற்று;
	EVP_PKEY *res = வெற்று;

	முழு ret = SSH_ERR_INTERNAL_ERROR;

	எனில் (bits < SSH_RSA_MINIMUM_MODULUS_SIZE ||
	    bits > SSHBUF_MAX_BIGNUM * 8)
		திரும்பு SSH_ERR_சாவி_LENGTH;

	எனில் ((ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, வெற்று)) == வெற்று) {
		ret = SSH_ERR_ALLOC_FAIL;
		செல் out;
	}
	எனில் (EVP_PKEY_keygen_init(ctx) <= 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		செல் out;
	}
	எனில் (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0) {
		ret = SSH_ERR_சாவி_LENGTH;
		செல் out;
	}
	எனில் (EVP_PKEY_keygen(ctx, &res) <= 0 || res == வெற்று) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		செல் out;
	}
	/* success */
	k->pkey = res;
	ret = 0;
 out:
	EVP_PKEY_CTX_free(ctx);
	திரும்பு ret;
}

நிலையான முழு
ssh_rsa_copy_public(மாறிலி கட்டமைப்பு sshkey *from, கட்டமைப்பு sshkey *to)
{
	மாறிலி BIGNUM *rsa_n, *rsa_e;
	BIGNUM *rsa_n_dup = வெற்று, *rsa_e_dup = வெற்று;
	முழு r = SSH_ERR_INTERNAL_ERROR;
	மாறிலி RSA *rsa_from;
	RSA *rsa_to = வெற்று;

	எனில் ((rsa_from = EVP_PKEY_get0_RSA(from->pkey)) == வெற்று ||
	    (rsa_to = RSA_new()) == வெற்று)
		திரும்பு SSH_ERR_LIBCRYPTO_ERROR;

	RSA_get0_சாவி(rsa_from, &rsa_n, &rsa_e, வெற்று);
	எனில் ((rsa_n_dup = BN_dup(rsa_n)) == வெற்று ||
	    (rsa_e_dup = BN_dup(rsa_e)) == வெற்று) {
		r = SSH_ERR_ALLOC_FAIL;
		செல் out;
	}
	எனில் (!RSA_set0_சாவி(rsa_to, rsa_n_dup, rsa_e_dup, வெற்று)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		செல் out;
	}
	rsa_n_dup = rsa_e_dup = வெற்று; /* transferred */

	எனில் (EVP_PKEY_set1_RSA(to->pkey, rsa_to) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		செல் out;
	}
	/* success */
	r = 0;
 out:
	RSA_free(rsa_to);
	BN_clear_free(rsa_n_dup);
	BN_clear_free(rsa_e_dup);
	திரும்பு r;
}

நிலையான முழு
ssh_rsa_deserialize_public(மாறிலி எழுத்து *ktype, கட்டமைப்பு sshbuf *b,
    கட்டமைப்பு sshkey *சாவி)
{
	முழு ret = SSH_ERR_INTERNAL_ERROR;
	BIGNUM *rsa_n = வெற்று, *rsa_e = வெற்று;
	RSA *rsa = வெற்று;

	எனில் ((rsa = RSA_new()) == வெற்று)
		திரும்பு SSH_ERR_LIBCRYPTO_ERROR;

	எனில் (sshbuf_get_bignum2(b, &rsa_e) != 0 ||
	    sshbuf_get_bignum2(b, &rsa_n) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		செல் out;
	}
	எனில் (!RSA_set0_சாவி(rsa, rsa_n, rsa_e, வெற்று)) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		செல் out;
	}
	rsa_n = rsa_e = வெற்று; /* transferred */
	எனில் (EVP_PKEY_set1_RSA(சாவி->pkey, rsa) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		செல் out;
	}
	எனில் ((ret = sshkey_check_rsa_length(சாவி, 0)) != 0)
		செல் out;
#ifdef DEBUG_PK
	RSA_print_fp(stderr, rsa, 8);
#endif
	/* success */
	ret = 0;
 out:
	RSA_free(rsa);
	BN_clear_free(rsa_n);
	BN_clear_free(rsa_e);
	திரும்பு ret;
}

நிலையான முழு
ssh_rsa_deserialize_private(மாறிலி எழுத்து *ktype, கட்டமைப்பு sshbuf *b,
    கட்டமைப்பு sshkey *சாவி)
{
	முழு r;
	BIGNUM *rsa_n = வெற்று, *rsa_e = வெற்று, *rsa_d = வெற்று;
	BIGNUM *rsa_iqmp = வெற்று, *rsa_p = வெற்று, *rsa_q = வெற்று;
	BIGNUM *rsa_dmp1 = வெற்று, *rsa_dmq1 = வெற்று;
	RSA *rsa = வெற்று;

	எனில் (sshkey_is_cert(சாவி)) {
		/* sshkey_private_deserialize already has pubkey from cert */
		எனில் ((rsa = EVP_PKEY_get1_RSA(சாவி->pkey)) == வெற்று) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			செல் out;
		}
	} இல்லையெனில் {
		எனில் ((rsa = RSA_new()) == வெற்று) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			செல் out;
		}
		/* Note: can't reuse ssh_rsa_deserialize_public: e,n vs. n,e */
		எனில் ((r = sshbuf_get_bignum2(b, &rsa_n)) != 0 ||
		    (r = sshbuf_get_bignum2(b, &rsa_e)) != 0)
			செல் out;
		எனில் (!RSA_set0_சாவி(rsa, rsa_n, rsa_e, வெற்று)) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			செல் out;
		}
		rsa_n = rsa_e = வெற்று; /* transferred */
	}
	எனில் ((r = sshbuf_get_bignum2(b, &rsa_d)) != 0 ||
	    (r = sshbuf_get_bignum2(b, &rsa_iqmp)) != 0 ||
	    (r = sshbuf_get_bignum2(b, &rsa_p)) != 0 ||
	    (r = sshbuf_get_bignum2(b, &rsa_q)) != 0)
		செல் out;
	எனில் ((r = ssh_rsa_complete_crt_parameters(rsa_d, rsa_p, rsa_q,
	    rsa_iqmp, &rsa_dmp1, &rsa_dmq1)) != 0)
		செல் out;
	எனில் (!RSA_set0_சாவி(rsa, வெற்று, வெற்று, rsa_d)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		செல் out;
	}
	rsa_d = வெற்று; /* transferred */
	எனில் (!RSA_set0_factors(rsa, rsa_p, rsa_q)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		செல் out;
	}
	rsa_p = rsa_q = வெற்று; /* transferred */
	எனில் (!RSA_set0_crt_params(rsa, rsa_dmp1, rsa_dmq1, rsa_iqmp)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		செல் out;
	}
	rsa_dmp1 = rsa_dmq1 = rsa_iqmp = வெற்று;
	எனில் (RSA_blinding_on(rsa, வெற்று) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		செல் out;
	}
	எனில் (EVP_PKEY_set1_RSA(சாவி->pkey, rsa) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		செல் out;
	}
	எனில் ((r = sshkey_check_rsa_length(சாவி, 0)) != 0)
		செல் out;
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
	திரும்பு r;
}

மாறிலி எழுத்து *
ssh_rsa_hash_alg_ident(முழு hash_alg)
{
	தேர்வு (hash_alg) {
	நிலை SSH_DIGEST_SHA1:
		திரும்பு "ssh-rsa";
	நிலை SSH_DIGEST_SHA256:
		திரும்பு "rsa-sha2-256";
	நிலை SSH_DIGEST_SHA512:
		திரும்பு "rsa-sha2-512";
	}
	திரும்பு வெற்று;
}

/*
 * Returns the hash algorithm ID for a given algorithm identifier as used
 * inside the signature blob,
 */
நிலையான முழு
rsa_hash_id_from_ident(மாறிலி எழுத்து *ident)
{
	எனில் (strcmp(ident, "ssh-rsa") == 0)
		திரும்பு SSH_DIGEST_SHA1;
	எனில் (strcmp(ident, "rsa-sha2-256") == 0)
		திரும்பு SSH_DIGEST_SHA256;
	எனில் (strcmp(ident, "rsa-sha2-512") == 0)
		திரும்பு SSH_DIGEST_SHA512;
	திரும்பு -1;
}

/*
 * Return the hash algorithm ID for the specified key name. This includes
 * all the cases of rsa_hash_id_from_ident() but also the certificate key
 * types.
 */
முழு
ssh_rsa_hash_id_from_keyname(மாறிலி எழுத்து *alg)
{
	முழு r;

	எனில் ((r = rsa_hash_id_from_ident(alg)) != -1)
		திரும்பு r;
	எனில் (strcmp(alg, "ssh-rsa-cert-v01@openssh.com") == 0)
		திரும்பு SSH_DIGEST_SHA1;
	எனில் (strcmp(alg, "rsa-sha2-256-cert-v01@openssh.com") == 0)
		திரும்பு SSH_DIGEST_SHA256;
	எனில் (strcmp(alg, "rsa-sha2-512-cert-v01@openssh.com") == 0)
		திரும்பு SSH_DIGEST_SHA512;
	திரும்பு -1;
}

முழு
ssh_rsa_complete_crt_parameters(மாறிலி BIGNUM *rsa_d, மாறிலி BIGNUM *rsa_p,
    மாறிலி BIGNUM *rsa_q, மாறிலி BIGNUM *rsa_iqmp, BIGNUM **rsa_dmp1,
    BIGNUM **rsa_dmq1)
{
	BIGNUM *aux = வெற்று, *d_consttime = வெற்று;
	BN_CTX *ctx = வெற்று;
	முழு r;

	*rsa_dmq1 = *rsa_dmp1 = வெற்று;
	எனில் ((ctx = BN_CTX_new()) == வெற்று)
		திரும்பு SSH_ERR_ALLOC_FAIL;
	எனில் ((aux = BN_new()) == வெற்று ||
	    (*rsa_dmq1 = BN_new()) == வெற்று ||
	    (*rsa_dmp1 = BN_new()) == வெற்று)
		திரும்பு SSH_ERR_ALLOC_FAIL;
	எனில் ((d_consttime = BN_dup(rsa_d)) == வெற்று) {
		r = SSH_ERR_ALLOC_FAIL;
		செல் out;
	}
	BN_set_flags(aux, BN_FLG_CONSTTIME);
	BN_set_flags(d_consttime, BN_FLG_CONSTTIME);

	எனில் ((BN_sub(aux, rsa_q, BN_மதிப்பு_one()) == 0) ||
	    (BN_mod(*rsa_dmq1, d_consttime, aux, ctx) == 0) ||
	    (BN_sub(aux, rsa_p, BN_மதிப்பு_one()) == 0) ||
	    (BN_mod(*rsa_dmp1, d_consttime, aux, ctx) == 0)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		செல் out;
	}
	/* success */
	r = 0;
 out:
	BN_clear_free(aux);
	BN_clear_free(d_consttime);
	BN_CTX_free(ctx);
	திரும்பு r;
}

/* RSASSA-PKCS1-v1_5 (PKCS #1 v2.0 signature) with SHA1 */
நிலையான முழு
ssh_rsa_sign(கட்டமைப்பு sshkey *சாவி,
    u_char **sigp, size_t *lenp,
    மாறிலி u_char *data, size_t datalen,
    மாறிலி எழுத்து *alg, மாறிலி எழுத்து *sk_provider, மாறிலி எழுத்து *sk_pin, u_int compat)
{
	u_char *sig = வெற்று;
	size_t diff, len = 0;
	முழு slen = 0;
	முழு hash_alg, ret = SSH_ERR_INTERNAL_ERROR;

	எனில் (lenp != வெற்று)
		*lenp = 0;
	எனில் (sigp != வெற்று)
		*sigp = வெற்று;

	எனில் (alg == வெற்று || strlen(alg) == 0)
		hash_alg = SSH_DIGEST_SHA1;
	இல்லையெனில்
		hash_alg = ssh_rsa_hash_id_from_keyname(alg);

	எனில் (சாவி == வெற்று || சாவி->pkey == வெற்று || hash_alg == -1 ||
	    sshkey_type_plain(சாவி->type) != சாவி_RSA)
		திரும்பு SSH_ERR_INVALID_ARGUMENT;
	slen = EVP_PKEY_size(சாவி->pkey);
	எனில் (slen <= 0 || slen > SSHBUF_MAX_BIGNUM)
		திரும்பு SSH_ERR_INVALID_ARGUMENT;
	எனில் (EVP_PKEY_bits(சாவி->pkey) < SSH_RSA_MINIMUM_MODULUS_SIZE)
		திரும்பு SSH_ERR_சாவி_LENGTH;

	எனில் ((ret = sshkey_pkey_digest_sign(சாவி->pkey, hash_alg, &sig, &len,
	    data, datalen)) < 0)
		செல் out;
	எனில் (len < (size_t)slen) {
		diff = slen - len;
		memmove(sig + diff, sig, len);
		explicit_bzero(sig, diff);
	} இல்லையெனில் எனில் (len > (size_t)slen) {
		ret = SSH_ERR_INTERNAL_ERROR;
		செல் out;
	}
	எனில் ((ret = ssh_rsa_encode_store_sig(hash_alg, sig, slen,
	    sigp, lenp)) != 0)
		செல் out;

	/* success */
	ret = 0;
 out:
	freezero(sig, slen);
	திரும்பு ret;
}

முழு
ssh_rsa_encode_store_sig(முழு hash_alg, மாறிலி u_char *sig, size_t slen,
    u_char **sigp, size_t *lenp)
{
	கட்டமைப்பு sshbuf *b = வெற்று;
	முழு ret = SSH_ERR_INTERNAL_ERROR;
	size_t len;

	எனில் (lenp != வெற்று)
		*lenp = 0;
	எனில் (sigp != வெற்று)
		*sigp = வெற்று;

	/* Encode signature */
	எனில் ((b = sshbuf_new()) == வெற்று) {
		ret = SSH_ERR_ALLOC_FAIL;
		செல் out;
	}
	எனில் ((ret = sshbuf_put_cstring(b,
	    ssh_rsa_hash_alg_ident(hash_alg))) != 0 ||
	    (ret = sshbuf_put_string(b, sig, slen)) != 0)
		செல் out;
	len = sshbuf_len(b);

	/* Store signature */
	எனில் (sigp != வெற்று) {
		எனில் ((*sigp = malloc(len)) == வெற்று) {
			ret = SSH_ERR_ALLOC_FAIL;
			செல் out;
		}
		memcpy(*sigp, sshbuf_ptr(b), len);
	}
	எனில் (lenp != வெற்று)
		*lenp = len;
	ret = 0;
 out:
	sshbuf_free(b);
	திரும்பு ret;
}

நிலையான முழு
ssh_rsa_verify(மாறிலி கட்டமைப்பு sshkey *சாவி,
    மாறிலி u_char *sig, size_t siglen,
    மாறிலி u_char *data, size_t dlen, மாறிலி எழுத்து *alg, u_int compat,
    கட்டமைப்பு sshkey_sig_details **detailsp)
{
	எழுத்து *sigtype = வெற்று;
	முழு hash_alg, want_alg, ret = SSH_ERR_INTERNAL_ERROR;
	size_t len = 0, diff, modlen, rsasize;
	கட்டமைப்பு sshbuf *b = வெற்று;
	u_char digest[SSH_DIGEST_MAX_LENGTH], *osigblob, *sigblob = வெற்று;

	எனில் (சாவி == வெற்று || சாவி->pkey == வெற்று ||
	    sshkey_type_plain(சாவி->type) != சாவி_RSA ||
	    sig == வெற்று || siglen == 0)
		திரும்பு SSH_ERR_INVALID_ARGUMENT;
	எனில் (EVP_PKEY_bits(சாவி->pkey) < SSH_RSA_MINIMUM_MODULUS_SIZE)
		திரும்பு SSH_ERR_சாவி_LENGTH;

	எனில் ((b = sshbuf_from(sig, siglen)) == வெற்று)
		திரும்பு SSH_ERR_ALLOC_FAIL;
	எனில் (sshbuf_get_cstring(b, &sigtype, வெற்று) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		செல் out;
	}
	எனில் ((hash_alg = rsa_hash_id_from_ident(sigtype)) == -1) {
		ret = SSH_ERR_சாவி_TYPE_MISMATCH;
		செல் out;
	}
	/*
	 * Allow ssh-rsa-cert-v01 certs to generate SHA2 signatures for
	 * legacy reasons, but otherwise the signature type should match.
	 */
	எனில் (alg != வெற்று && strcmp(alg, "ssh-rsa-cert-v01@openssh.com") != 0) {
		எனில் ((want_alg = ssh_rsa_hash_id_from_keyname(alg)) == -1) {
			ret = SSH_ERR_INVALID_ARGUMENT;
			செல் out;
		}
		எனில் (hash_alg != want_alg) {
			ret = SSH_ERR_SIGNATURE_INVALID;
			செல் out;
		}
	}
	எனில் (sshbuf_get_string(b, &sigblob, &len) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		செல் out;
	}
	எனில் (sshbuf_len(b) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		செல் out;
	}
	/* RSA_verify expects a signature of RSA_size */
	modlen = EVP_PKEY_size(சாவி->pkey);
	எனில் (len > modlen) {
		ret = SSH_ERR_சாவி_BITS_MISMATCH;
		செல் out;
	} இல்லையெனில் எனில் (len < modlen) {
		diff = modlen - len;
		osigblob = sigblob;
		எனில் ((sigblob = realloc(sigblob, modlen)) == வெற்று) {
			sigblob = osigblob; /* put it back for clear/free */
			ret = SSH_ERR_ALLOC_FAIL;
			செல் out;
		}
		memmove(sigblob + diff, sigblob, len);
		explicit_bzero(sigblob, diff);
		len = modlen;
	}

	rsasize = EVP_PKEY_size(சாவி->pkey);
	எனில் (rsasize <= 0 || rsasize > SSHBUF_MAX_BIGNUM ||
	    len == 0 || len > rsasize) {
		ret = SSH_ERR_INVALID_ARGUMENT;
		செல் out;
	}
	ret = sshkey_pkey_digest_verify(சாவி->pkey, hash_alg, data, dlen,
	    sigblob, len);

 out:
	freezero(sigblob, len);
	விடுவி(sigtype);
	sshbuf_free(b);
	explicit_bzero(digest, அளவு(digest));
	திரும்பு ret;
}

நிலையான மாறிலி கட்டமைப்பு sshkey_impl_funcs sshkey_rsa_funcs = {
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

மாறிலி கட்டமைப்பு sshkey_impl sshkey_rsa_impl = {
	/* .name = */		"ssh-rsa",
	/* .shortname = */	"RSA",
	/* .sigalg = */		வெற்று,
	/* .type = */		சாவி_RSA,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};

மாறிலி கட்டமைப்பு sshkey_impl sshkey_rsa_cert_impl = {
	/* .name = */		"ssh-rsa-cert-v01@openssh.com",
	/* .shortname = */	"RSA-CERT",
	/* .sigalg = */		வெற்று,
	/* .type = */		சாவி_RSA_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};

/* SHA2 signature algorithms */

மாறிலி கட்டமைப்பு sshkey_impl sshkey_rsa_sha256_impl = {
	/* .name = */		"rsa-sha2-256",
	/* .shortname = */	"RSA",
	/* .sigalg = */		வெற்று,
	/* .type = */		சாவி_RSA,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	1,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};

மாறிலி கட்டமைப்பு sshkey_impl sshkey_rsa_sha512_impl = {
	/* .name = */		"rsa-sha2-512",
	/* .shortname = */	"RSA",
	/* .sigalg = */		வெற்று,
	/* .type = */		சாவி_RSA,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	1,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};

மாறிலி கட்டமைப்பு sshkey_impl sshkey_rsa_sha256_cert_impl = {
	/* .name = */		"rsa-sha2-256-cert-v01@openssh.com",
	/* .shortname = */	"RSA-CERT",
	/* .sigalg = */		"rsa-sha2-256",
	/* .type = */		சாவி_RSA_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	1,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};

மாறிலி கட்டமைப்பு sshkey_impl sshkey_rsa_sha512_cert_impl = {
	/* .name = */		"rsa-sha2-512-cert-v01@openssh.com",
	/* .shortname = */	"RSA-CERT",
	/* .sigalg = */		"rsa-sha2-512",
	/* .type = */		சாவி_RSA_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	1,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};
#endif /* WITH_OPENSSL */
