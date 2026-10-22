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

#شامل "includes.h"

#ifdef WITH_OPENSSL
#شامل "openbsd-compat/openssl-compat.h"

#شامل <sys/types.h>

#شامل <openssl/bn.h>
#شامل <openssl/evp.h>

#شامل <stdarg.h>
#شامل <string.h>

#شامل "sshbuf.h"
#شامل "ssherr.h"
#define SSHKEY_INTERNAL
#شامل "sshkey.h"
#شامل "digest.h"

ایستا u_int
ssh_rsa_size(ثابت ساختار sshkey *k)
{
	اگر (k->pkey == پوچ)
		بازگشت 0;
	بازگشت EVP_PKEY_bits(k->pkey);
}

ایستا صحیح
ssh_rsa_alloc(ساختار sshkey *k)
{
	اگر ((k->pkey = EVP_PKEY_new()) == پوچ)
		بازگشت SSH_ERR_ALLOC_FAIL;
	بازگشت 0;
}

ایستا تهی
ssh_rsa_cleanup(ساختار sshkey *k)
{
	EVP_PKEY_free(k->pkey);
	k->pkey = پوچ;
}

ایستا صحیح
ssh_rsa_equal(ثابت ساختار sshkey *a, ثابت ساختار sshkey *b)
{
	اگر (a->pkey == پوچ || b->pkey == پوچ)
		بازگشت 0;
	بازگشت EVP_PKEY_cmp(a->pkey, b->pkey) == 1;
}

ایستا صحیح
ssh_rsa_serialize_public(ثابت ساختار sshkey *کلید, ساختار sshbuf *b,
    شمارش sshkey_serialize_rep opts)
{
	صحیح r;
	ثابت BIGNUM *rsa_n, *rsa_e;
	ثابت RSA *rsa;

	اگر (کلید->pkey == پوچ)
		بازگشت SSH_ERR_INVALID_ARGUMENT;
	اگر ((rsa = EVP_PKEY_get0_RSA(کلید->pkey)) == پوچ)
		بازگشت SSH_ERR_LIBCRYPTO_ERROR;

	RSA_get0_کلید(rsa, &rsa_n, &rsa_e, پوچ);
	اگر ((r = sshbuf_put_bignum2(b, rsa_e)) != 0 ||
	    (r = sshbuf_put_bignum2(b, rsa_n)) != 0)
		بازگشت r;

	بازگشت 0;
}

ایستا صحیح
ssh_rsa_serialize_private(ثابت ساختار sshkey *کلید, ساختار sshbuf *b,
    شمارش sshkey_serialize_rep opts)
{
	صحیح r;
	ثابت BIGNUM *rsa_n, *rsa_e, *rsa_d, *rsa_iqmp, *rsa_p, *rsa_q;
	ثابت RSA *rsa;

	اگر ((rsa = EVP_PKEY_get0_RSA(کلید->pkey)) == پوچ)
		بازگشت SSH_ERR_LIBCRYPTO_ERROR;
	RSA_get0_کلید(rsa, &rsa_n, &rsa_e, &rsa_d);
	RSA_get0_factors(rsa, &rsa_p, &rsa_q);
	RSA_get0_crt_params(rsa, پوچ, پوچ, &rsa_iqmp);

	اگر (!sshkey_is_cert(کلید)) {
		/* Note: can't reuse ssh_rsa_serialize_public: e, n vs. n, e */
		اگر ((r = sshbuf_put_bignum2(b, rsa_n)) != 0 ||
		    (r = sshbuf_put_bignum2(b, rsa_e)) != 0)
			بازگشت r;
	}
	اگر ((r = sshbuf_put_bignum2(b, rsa_d)) != 0 ||
	    (r = sshbuf_put_bignum2(b, rsa_iqmp)) != 0 ||
	    (r = sshbuf_put_bignum2(b, rsa_p)) != 0 ||
	    (r = sshbuf_put_bignum2(b, rsa_q)) != 0)
		بازگشت r;

	بازگشت 0;
}

ایستا صحیح
ssh_rsa_generate(ساختار sshkey *k, صحیح bits)
{
	EVP_PKEY_CTX *ctx = پوچ;
	EVP_PKEY *res = پوچ;

	صحیح ret = SSH_ERR_INTERNAL_ERROR;

	اگر (bits < SSH_RSA_MINIMUM_MODULUS_SIZE ||
	    bits > SSHBUF_MAX_BIGNUM * 8)
		بازگشت SSH_ERR_کلید_LENGTH;

	اگر ((ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, پوچ)) == پوچ) {
		ret = SSH_ERR_ALLOC_FAIL;
		برو out;
	}
	اگر (EVP_PKEY_keygen_init(ctx) <= 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		برو out;
	}
	اگر (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0) {
		ret = SSH_ERR_کلید_LENGTH;
		برو out;
	}
	اگر (EVP_PKEY_keygen(ctx, &res) <= 0 || res == پوچ) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		برو out;
	}
	/* success */
	k->pkey = res;
	ret = 0;
 out:
	EVP_PKEY_CTX_free(ctx);
	بازگشت ret;
}

ایستا صحیح
ssh_rsa_copy_public(ثابت ساختار sshkey *from, ساختار sshkey *to)
{
	ثابت BIGNUM *rsa_n, *rsa_e;
	BIGNUM *rsa_n_dup = پوچ, *rsa_e_dup = پوچ;
	صحیح r = SSH_ERR_INTERNAL_ERROR;
	ثابت RSA *rsa_from;
	RSA *rsa_to = پوچ;

	اگر ((rsa_from = EVP_PKEY_get0_RSA(from->pkey)) == پوچ ||
	    (rsa_to = RSA_new()) == پوچ)
		بازگشت SSH_ERR_LIBCRYPTO_ERROR;

	RSA_get0_کلید(rsa_from, &rsa_n, &rsa_e, پوچ);
	اگر ((rsa_n_dup = BN_dup(rsa_n)) == پوچ ||
	    (rsa_e_dup = BN_dup(rsa_e)) == پوچ) {
		r = SSH_ERR_ALLOC_FAIL;
		برو out;
	}
	اگر (!RSA_set0_کلید(rsa_to, rsa_n_dup, rsa_e_dup, پوچ)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		برو out;
	}
	rsa_n_dup = rsa_e_dup = پوچ; /* transferred */

	اگر (EVP_PKEY_set1_RSA(to->pkey, rsa_to) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		برو out;
	}
	/* success */
	r = 0;
 out:
	RSA_free(rsa_to);
	BN_clear_free(rsa_n_dup);
	BN_clear_free(rsa_e_dup);
	بازگشت r;
}

ایستا صحیح
ssh_rsa_deserialize_public(ثابت نویسه *ktype, ساختار sshbuf *b,
    ساختار sshkey *کلید)
{
	صحیح ret = SSH_ERR_INTERNAL_ERROR;
	BIGNUM *rsa_n = پوچ, *rsa_e = پوچ;
	RSA *rsa = پوچ;

	اگر ((rsa = RSA_new()) == پوچ)
		بازگشت SSH_ERR_LIBCRYPTO_ERROR;

	اگر (sshbuf_get_bignum2(b, &rsa_e) != 0 ||
	    sshbuf_get_bignum2(b, &rsa_n) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		برو out;
	}
	اگر (!RSA_set0_کلید(rsa, rsa_n, rsa_e, پوچ)) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		برو out;
	}
	rsa_n = rsa_e = پوچ; /* transferred */
	اگر (EVP_PKEY_set1_RSA(کلید->pkey, rsa) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		برو out;
	}
	اگر ((ret = sshkey_check_rsa_length(کلید, 0)) != 0)
		برو out;
#ifdef DEBUG_PK
	RSA_print_fp(stderr, rsa, 8);
#endif
	/* success */
	ret = 0;
 out:
	RSA_free(rsa);
	BN_clear_free(rsa_n);
	BN_clear_free(rsa_e);
	بازگشت ret;
}

ایستا صحیح
ssh_rsa_deserialize_private(ثابت نویسه *ktype, ساختار sshbuf *b,
    ساختار sshkey *کلید)
{
	صحیح r;
	BIGNUM *rsa_n = پوچ, *rsa_e = پوچ, *rsa_d = پوچ;
	BIGNUM *rsa_iqmp = پوچ, *rsa_p = پوچ, *rsa_q = پوچ;
	BIGNUM *rsa_dmp1 = پوچ, *rsa_dmq1 = پوچ;
	RSA *rsa = پوچ;

	اگر (sshkey_is_cert(کلید)) {
		/* sshkey_private_deserialize already has pubkey from cert */
		اگر ((rsa = EVP_PKEY_get1_RSA(کلید->pkey)) == پوچ) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			برو out;
		}
	} وگرنه {
		اگر ((rsa = RSA_new()) == پوچ) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			برو out;
		}
		/* Note: can't reuse ssh_rsa_deserialize_public: e,n vs. n,e */
		اگر ((r = sshbuf_get_bignum2(b, &rsa_n)) != 0 ||
		    (r = sshbuf_get_bignum2(b, &rsa_e)) != 0)
			برو out;
		اگر (!RSA_set0_کلید(rsa, rsa_n, rsa_e, پوچ)) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			برو out;
		}
		rsa_n = rsa_e = پوچ; /* transferred */
	}
	اگر ((r = sshbuf_get_bignum2(b, &rsa_d)) != 0 ||
	    (r = sshbuf_get_bignum2(b, &rsa_iqmp)) != 0 ||
	    (r = sshbuf_get_bignum2(b, &rsa_p)) != 0 ||
	    (r = sshbuf_get_bignum2(b, &rsa_q)) != 0)
		برو out;
	اگر ((r = ssh_rsa_complete_crt_parameters(rsa_d, rsa_p, rsa_q,
	    rsa_iqmp, &rsa_dmp1, &rsa_dmq1)) != 0)
		برو out;
	اگر (!RSA_set0_کلید(rsa, پوچ, پوچ, rsa_d)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		برو out;
	}
	rsa_d = پوچ; /* transferred */
	اگر (!RSA_set0_factors(rsa, rsa_p, rsa_q)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		برو out;
	}
	rsa_p = rsa_q = پوچ; /* transferred */
	اگر (!RSA_set0_crt_params(rsa, rsa_dmp1, rsa_dmq1, rsa_iqmp)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		برو out;
	}
	rsa_dmp1 = rsa_dmq1 = rsa_iqmp = پوچ;
	اگر (RSA_blinding_on(rsa, پوچ) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		برو out;
	}
	اگر (EVP_PKEY_set1_RSA(کلید->pkey, rsa) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		برو out;
	}
	اگر ((r = sshkey_check_rsa_length(کلید, 0)) != 0)
		برو out;
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
	بازگشت r;
}

ثابت نویسه *
ssh_rsa_hash_alg_ident(صحیح hash_alg)
{
	انتخاب (hash_alg) {
	حالت SSH_DIGEST_SHA1:
		بازگشت "ssh-rsa";
	حالت SSH_DIGEST_SHA256:
		بازگشت "rsa-sha2-256";
	حالت SSH_DIGEST_SHA512:
		بازگشت "rsa-sha2-512";
	}
	بازگشت پوچ;
}

/*
 * Returns the hash algorithm ID for a given algorithm identifier as used
 * inside the signature blob,
 */
ایستا صحیح
rsa_hash_id_from_ident(ثابت نویسه *ident)
{
	اگر (strcmp(ident, "ssh-rsa") == 0)
		بازگشت SSH_DIGEST_SHA1;
	اگر (strcmp(ident, "rsa-sha2-256") == 0)
		بازگشت SSH_DIGEST_SHA256;
	اگر (strcmp(ident, "rsa-sha2-512") == 0)
		بازگشت SSH_DIGEST_SHA512;
	بازگشت -1;
}

/*
 * Return the hash algorithm ID for the specified key name. This includes
 * all the cases of rsa_hash_id_from_ident() but also the certificate key
 * types.
 */
صحیح
ssh_rsa_hash_id_from_keyname(ثابت نویسه *alg)
{
	صحیح r;

	اگر ((r = rsa_hash_id_from_ident(alg)) != -1)
		بازگشت r;
	اگر (strcmp(alg, "ssh-rsa-cert-v01@openssh.com") == 0)
		بازگشت SSH_DIGEST_SHA1;
	اگر (strcmp(alg, "rsa-sha2-256-cert-v01@openssh.com") == 0)
		بازگشت SSH_DIGEST_SHA256;
	اگر (strcmp(alg, "rsa-sha2-512-cert-v01@openssh.com") == 0)
		بازگشت SSH_DIGEST_SHA512;
	بازگشت -1;
}

صحیح
ssh_rsa_complete_crt_parameters(ثابت BIGNUM *rsa_d, ثابت BIGNUM *rsa_p,
    ثابت BIGNUM *rsa_q, ثابت BIGNUM *rsa_iqmp, BIGNUM **rsa_dmp1,
    BIGNUM **rsa_dmq1)
{
	BIGNUM *aux = پوچ, *d_consttime = پوچ;
	BN_CTX *ctx = پوچ;
	صحیح r;

	*rsa_dmq1 = *rsa_dmp1 = پوچ;
	اگر ((ctx = BN_CTX_new()) == پوچ)
		بازگشت SSH_ERR_ALLOC_FAIL;
	اگر ((aux = BN_new()) == پوچ ||
	    (*rsa_dmq1 = BN_new()) == پوچ ||
	    (*rsa_dmp1 = BN_new()) == پوچ)
		بازگشت SSH_ERR_ALLOC_FAIL;
	اگر ((d_consttime = BN_dup(rsa_d)) == پوچ) {
		r = SSH_ERR_ALLOC_FAIL;
		برو out;
	}
	BN_set_flags(aux, BN_FLG_CONSTTIME);
	BN_set_flags(d_consttime, BN_FLG_CONSTTIME);

	اگر ((BN_sub(aux, rsa_q, BN_مقدار_one()) == 0) ||
	    (BN_mod(*rsa_dmq1, d_consttime, aux, ctx) == 0) ||
	    (BN_sub(aux, rsa_p, BN_مقدار_one()) == 0) ||
	    (BN_mod(*rsa_dmp1, d_consttime, aux, ctx) == 0)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		برو out;
	}
	/* success */
	r = 0;
 out:
	BN_clear_free(aux);
	BN_clear_free(d_consttime);
	BN_CTX_free(ctx);
	بازگشت r;
}

/* RSASSA-PKCS1-v1_5 (PKCS #1 v2.0 signature) with SHA1 */
ایستا صحیح
ssh_rsa_sign(ساختار sshkey *کلید,
    u_char **sigp, size_t *lenp,
    ثابت u_char *data, size_t datalen,
    ثابت نویسه *alg, ثابت نویسه *sk_provider, ثابت نویسه *sk_pin, u_int compat)
{
	u_char *sig = پوچ;
	size_t diff, len = 0;
	صحیح slen = 0;
	صحیح hash_alg, ret = SSH_ERR_INTERNAL_ERROR;

	اگر (lenp != پوچ)
		*lenp = 0;
	اگر (sigp != پوچ)
		*sigp = پوچ;

	اگر (alg == پوچ || strlen(alg) == 0)
		hash_alg = SSH_DIGEST_SHA1;
	وگرنه
		hash_alg = ssh_rsa_hash_id_from_keyname(alg);

	اگر (کلید == پوچ || کلید->pkey == پوچ || hash_alg == -1 ||
	    sshkey_type_plain(کلید->type) != کلید_RSA)
		بازگشت SSH_ERR_INVALID_ARGUMENT;
	slen = EVP_PKEY_size(کلید->pkey);
	اگر (slen <= 0 || slen > SSHBUF_MAX_BIGNUM)
		بازگشت SSH_ERR_INVALID_ARGUMENT;
	اگر (EVP_PKEY_bits(کلید->pkey) < SSH_RSA_MINIMUM_MODULUS_SIZE)
		بازگشت SSH_ERR_کلید_LENGTH;

	اگر ((ret = sshkey_pkey_digest_sign(کلید->pkey, hash_alg, &sig, &len,
	    data, datalen)) < 0)
		برو out;
	اگر (len < (size_t)slen) {
		diff = slen - len;
		memmove(sig + diff, sig, len);
		explicit_bzero(sig, diff);
	} وگرنه اگر (len > (size_t)slen) {
		ret = SSH_ERR_INTERNAL_ERROR;
		برو out;
	}
	اگر ((ret = ssh_rsa_encode_store_sig(hash_alg, sig, slen,
	    sigp, lenp)) != 0)
		برو out;

	/* success */
	ret = 0;
 out:
	freezero(sig, slen);
	بازگشت ret;
}

صحیح
ssh_rsa_encode_store_sig(صحیح hash_alg, ثابت u_char *sig, size_t slen,
    u_char **sigp, size_t *lenp)
{
	ساختار sshbuf *b = پوچ;
	صحیح ret = SSH_ERR_INTERNAL_ERROR;
	size_t len;

	اگر (lenp != پوچ)
		*lenp = 0;
	اگر (sigp != پوچ)
		*sigp = پوچ;

	/* Encode signature */
	اگر ((b = sshbuf_new()) == پوچ) {
		ret = SSH_ERR_ALLOC_FAIL;
		برو out;
	}
	اگر ((ret = sshbuf_put_cstring(b,
	    ssh_rsa_hash_alg_ident(hash_alg))) != 0 ||
	    (ret = sshbuf_put_string(b, sig, slen)) != 0)
		برو out;
	len = sshbuf_len(b);

	/* Store signature */
	اگر (sigp != پوچ) {
		اگر ((*sigp = malloc(len)) == پوچ) {
			ret = SSH_ERR_ALLOC_FAIL;
			برو out;
		}
		memcpy(*sigp, sshbuf_ptr(b), len);
	}
	اگر (lenp != پوچ)
		*lenp = len;
	ret = 0;
 out:
	sshbuf_free(b);
	بازگشت ret;
}

ایستا صحیح
ssh_rsa_verify(ثابت ساختار sshkey *کلید,
    ثابت u_char *sig, size_t siglen,
    ثابت u_char *data, size_t dlen, ثابت نویسه *alg, u_int compat,
    ساختار sshkey_sig_details **detailsp)
{
	نویسه *sigtype = پوچ;
	صحیح hash_alg, want_alg, ret = SSH_ERR_INTERNAL_ERROR;
	size_t len = 0, diff, modlen, rsasize;
	ساختار sshbuf *b = پوچ;
	u_char digest[SSH_DIGEST_MAX_LENGTH], *osigblob, *sigblob = پوچ;

	اگر (کلید == پوچ || کلید->pkey == پوچ ||
	    sshkey_type_plain(کلید->type) != کلید_RSA ||
	    sig == پوچ || siglen == 0)
		بازگشت SSH_ERR_INVALID_ARGUMENT;
	اگر (EVP_PKEY_bits(کلید->pkey) < SSH_RSA_MINIMUM_MODULUS_SIZE)
		بازگشت SSH_ERR_کلید_LENGTH;

	اگر ((b = sshbuf_from(sig, siglen)) == پوچ)
		بازگشت SSH_ERR_ALLOC_FAIL;
	اگر (sshbuf_get_cstring(b, &sigtype, پوچ) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		برو out;
	}
	اگر ((hash_alg = rsa_hash_id_from_ident(sigtype)) == -1) {
		ret = SSH_ERR_کلید_TYPE_MISMATCH;
		برو out;
	}
	/*
	 * Allow ssh-rsa-cert-v01 certs to generate SHA2 signatures for
	 * legacy reasons, but otherwise the signature type should match.
	 */
	اگر (alg != پوچ && strcmp(alg, "ssh-rsa-cert-v01@openssh.com") != 0) {
		اگر ((want_alg = ssh_rsa_hash_id_from_keyname(alg)) == -1) {
			ret = SSH_ERR_INVALID_ARGUMENT;
			برو out;
		}
		اگر (hash_alg != want_alg) {
			ret = SSH_ERR_SIGNATURE_INVALID;
			برو out;
		}
	}
	اگر (sshbuf_get_string(b, &sigblob, &len) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		برو out;
	}
	اگر (sshbuf_len(b) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		برو out;
	}
	/* RSA_verify expects a signature of RSA_size */
	modlen = EVP_PKEY_size(کلید->pkey);
	اگر (len > modlen) {
		ret = SSH_ERR_کلید_BITS_MISMATCH;
		برو out;
	} وگرنه اگر (len < modlen) {
		diff = modlen - len;
		osigblob = sigblob;
		اگر ((sigblob = realloc(sigblob, modlen)) == پوچ) {
			sigblob = osigblob; /* put it back for clear/free */
			ret = SSH_ERR_ALLOC_FAIL;
			برو out;
		}
		memmove(sigblob + diff, sigblob, len);
		explicit_bzero(sigblob, diff);
		len = modlen;
	}

	rsasize = EVP_PKEY_size(کلید->pkey);
	اگر (rsasize <= 0 || rsasize > SSHBUF_MAX_BIGNUM ||
	    len == 0 || len > rsasize) {
		ret = SSH_ERR_INVALID_ARGUMENT;
		برو out;
	}
	ret = sshkey_pkey_digest_verify(کلید->pkey, hash_alg, data, dlen,
	    sigblob, len);

 out:
	freezero(sigblob, len);
	آزاد(sigtype);
	sshbuf_free(b);
	explicit_bzero(digest, اندازه(digest));
	بازگشت ret;
}

ایستا ثابت ساختار sshkey_impl_funcs sshkey_rsa_funcs = {
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

ثابت ساختار sshkey_impl sshkey_rsa_impl = {
	/* .name = */		"ssh-rsa",
	/* .shortname = */	"RSA",
	/* .sigalg = */		پوچ,
	/* .type = */		کلید_RSA,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};

ثابت ساختار sshkey_impl sshkey_rsa_cert_impl = {
	/* .name = */		"ssh-rsa-cert-v01@openssh.com",
	/* .shortname = */	"RSA-CERT",
	/* .sigalg = */		پوچ,
	/* .type = */		کلید_RSA_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};

/* SHA2 signature algorithms */

ثابت ساختار sshkey_impl sshkey_rsa_sha256_impl = {
	/* .name = */		"rsa-sha2-256",
	/* .shortname = */	"RSA",
	/* .sigalg = */		پوچ,
	/* .type = */		کلید_RSA,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	1,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};

ثابت ساختار sshkey_impl sshkey_rsa_sha512_impl = {
	/* .name = */		"rsa-sha2-512",
	/* .shortname = */	"RSA",
	/* .sigalg = */		پوچ,
	/* .type = */		کلید_RSA,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	1,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};

ثابت ساختار sshkey_impl sshkey_rsa_sha256_cert_impl = {
	/* .name = */		"rsa-sha2-256-cert-v01@openssh.com",
	/* .shortname = */	"RSA-CERT",
	/* .sigalg = */		"rsa-sha2-256",
	/* .type = */		کلید_RSA_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	1,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};

ثابت ساختار sshkey_impl sshkey_rsa_sha512_cert_impl = {
	/* .name = */		"rsa-sha2-512-cert-v01@openssh.com",
	/* .shortname = */	"RSA-CERT",
	/* .sigalg = */		"rsa-sha2-512",
	/* .type = */		کلید_RSA_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	1,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};
#endif /* WITH_OPENSSL */
