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

#অন্তর্ভাব "includes.h"

#ifdef WITH_OPENSSL
#অন্তর্ভাব "openbsd-compat/openssl-compat.h"

#অন্তর্ভাব <sys/types.h>

#অন্তর্ভাব <openssl/bn.h>
#অন্তর্ভাব <openssl/evp.h>

#অন্তর্ভাব <stdarg.h>
#অন্তর্ভাব <string.h>

#অন্তর্ভাব "sshbuf.h"
#অন্তর্ভাব "ssherr.h"
#define SSHKEY_INTERNAL
#অন্তর্ভাব "sshkey.h"
#অন্তর্ভাব "digest.h"

স্থির u_int
ssh_rsa_size(ধ্রুব সংরচনা sshkey *k)
{
	যদি (k->pkey == রিক্ত)
		প্রত্যাগম 0;
	প্রত্যাগম EVP_PKEY_bits(k->pkey);
}

স্থির পূর্ণাঙ্ক
ssh_rsa_alloc(সংরচনা sshkey *k)
{
	যদি ((k->pkey = EVP_PKEY_new()) == রিক্ত)
		প্রত্যাগম SSH_ERR_ALLOC_FAIL;
	প্রত্যাগম 0;
}

স্থির শূন্য
ssh_rsa_cleanup(সংরচনা sshkey *k)
{
	EVP_PKEY_free(k->pkey);
	k->pkey = রিক্ত;
}

স্থির পূর্ণাঙ্ক
ssh_rsa_equal(ধ্রুব সংরচনা sshkey *a, ধ্রুব সংরচনা sshkey *b)
{
	যদি (a->pkey == রিক্ত || b->pkey == রিক্ত)
		প্রত্যাগম 0;
	প্রত্যাগম EVP_PKEY_cmp(a->pkey, b->pkey) == 1;
}

স্থির পূর্ণাঙ্ক
ssh_rsa_serialize_public(ধ্রুব সংরচনা sshkey *চাবি, সংরচনা sshbuf *b,
    গণনা sshkey_serialize_rep opts)
{
	পূর্ণাঙ্ক r;
	ধ্রুব BIGNUM *rsa_n, *rsa_e;
	ধ্রুব RSA *rsa;

	যদি (চাবি->pkey == রিক্ত)
		প্রত্যাগম SSH_ERR_INVALID_ARGUMENT;
	যদি ((rsa = EVP_PKEY_get0_RSA(চাবি->pkey)) == রিক্ত)
		প্রত্যাগম SSH_ERR_LIBCRYPTO_ERROR;

	RSA_get0_চাবি(rsa, &rsa_n, &rsa_e, রিক্ত);
	যদি ((r = sshbuf_put_bignum2(b, rsa_e)) != 0 ||
	    (r = sshbuf_put_bignum2(b, rsa_n)) != 0)
		প্রত্যাগম r;

	প্রত্যাগম 0;
}

স্থির পূর্ণাঙ্ক
ssh_rsa_serialize_private(ধ্রুব সংরচনা sshkey *চাবি, সংরচনা sshbuf *b,
    গণনা sshkey_serialize_rep opts)
{
	পূর্ণাঙ্ক r;
	ধ্রুব BIGNUM *rsa_n, *rsa_e, *rsa_d, *rsa_iqmp, *rsa_p, *rsa_q;
	ধ্রুব RSA *rsa;

	যদি ((rsa = EVP_PKEY_get0_RSA(চাবি->pkey)) == রিক্ত)
		প্রত্যাগম SSH_ERR_LIBCRYPTO_ERROR;
	RSA_get0_চাবি(rsa, &rsa_n, &rsa_e, &rsa_d);
	RSA_get0_factors(rsa, &rsa_p, &rsa_q);
	RSA_get0_crt_params(rsa, রিক্ত, রিক্ত, &rsa_iqmp);

	যদি (!sshkey_is_cert(চাবি)) {
		/* Note: can't reuse ssh_rsa_serialize_public: e, n vs. n, e */
		যদি ((r = sshbuf_put_bignum2(b, rsa_n)) != 0 ||
		    (r = sshbuf_put_bignum2(b, rsa_e)) != 0)
			প্রত্যাগম r;
	}
	যদি ((r = sshbuf_put_bignum2(b, rsa_d)) != 0 ||
	    (r = sshbuf_put_bignum2(b, rsa_iqmp)) != 0 ||
	    (r = sshbuf_put_bignum2(b, rsa_p)) != 0 ||
	    (r = sshbuf_put_bignum2(b, rsa_q)) != 0)
		প্রত্যাগম r;

	প্রত্যাগম 0;
}

স্থির পূর্ণাঙ্ক
ssh_rsa_generate(সংরচনা sshkey *k, পূর্ণাঙ্ক bits)
{
	EVP_PKEY_CTX *ctx = রিক্ত;
	EVP_PKEY *res = রিক্ত;

	পূর্ণাঙ্ক ret = SSH_ERR_INTERNAL_ERROR;

	যদি (bits < SSH_RSA_MINIMUM_MODULUS_SIZE ||
	    bits > SSHBUF_MAX_BIGNUM * 8)
		প্রত্যাগম SSH_ERR_চাবি_LENGTH;

	যদি ((ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, রিক্ত)) == রিক্ত) {
		ret = SSH_ERR_ALLOC_FAIL;
		গচ্ছ out;
	}
	যদি (EVP_PKEY_keygen_init(ctx) <= 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		গচ্ছ out;
	}
	যদি (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0) {
		ret = SSH_ERR_চাবি_LENGTH;
		গচ্ছ out;
	}
	যদি (EVP_PKEY_keygen(ctx, &res) <= 0 || res == রিক্ত) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		গচ্ছ out;
	}
	/* success */
	k->pkey = res;
	ret = 0;
 out:
	EVP_PKEY_CTX_free(ctx);
	প্রত্যাগম ret;
}

স্থির পূর্ণাঙ্ক
ssh_rsa_copy_public(ধ্রুব সংরচনা sshkey *from, সংরচনা sshkey *to)
{
	ধ্রুব BIGNUM *rsa_n, *rsa_e;
	BIGNUM *rsa_n_dup = রিক্ত, *rsa_e_dup = রিক্ত;
	পূর্ণাঙ্ক r = SSH_ERR_INTERNAL_ERROR;
	ধ্রুব RSA *rsa_from;
	RSA *rsa_to = রিক্ত;

	যদি ((rsa_from = EVP_PKEY_get0_RSA(from->pkey)) == রিক্ত ||
	    (rsa_to = RSA_new()) == রিক্ত)
		প্রত্যাগম SSH_ERR_LIBCRYPTO_ERROR;

	RSA_get0_চাবি(rsa_from, &rsa_n, &rsa_e, রিক্ত);
	যদি ((rsa_n_dup = BN_dup(rsa_n)) == রিক্ত ||
	    (rsa_e_dup = BN_dup(rsa_e)) == রিক্ত) {
		r = SSH_ERR_ALLOC_FAIL;
		গচ্ছ out;
	}
	যদি (!RSA_set0_চাবি(rsa_to, rsa_n_dup, rsa_e_dup, রিক্ত)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		গচ্ছ out;
	}
	rsa_n_dup = rsa_e_dup = রিক্ত; /* transferred */

	যদি (EVP_PKEY_set1_RSA(to->pkey, rsa_to) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		গচ্ছ out;
	}
	/* success */
	r = 0;
 out:
	RSA_free(rsa_to);
	BN_clear_free(rsa_n_dup);
	BN_clear_free(rsa_e_dup);
	প্রত্যাগম r;
}

স্থির পূর্ণাঙ্ক
ssh_rsa_deserialize_public(ধ্রুব বর্ণ *ktype, সংরচনা sshbuf *b,
    সংরচনা sshkey *চাবি)
{
	পূর্ণাঙ্ক ret = SSH_ERR_INTERNAL_ERROR;
	BIGNUM *rsa_n = রিক্ত, *rsa_e = রিক্ত;
	RSA *rsa = রিক্ত;

	যদি ((rsa = RSA_new()) == রিক্ত)
		প্রত্যাগম SSH_ERR_LIBCRYPTO_ERROR;

	যদি (sshbuf_get_bignum2(b, &rsa_e) != 0 ||
	    sshbuf_get_bignum2(b, &rsa_n) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		গচ্ছ out;
	}
	যদি (!RSA_set0_চাবি(rsa, rsa_n, rsa_e, রিক্ত)) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		গচ্ছ out;
	}
	rsa_n = rsa_e = রিক্ত; /* transferred */
	যদি (EVP_PKEY_set1_RSA(চাবি->pkey, rsa) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		গচ্ছ out;
	}
	যদি ((ret = sshkey_check_rsa_length(চাবি, 0)) != 0)
		গচ্ছ out;
#ifdef DEBUG_PK
	RSA_print_fp(stderr, rsa, 8);
#endif
	/* success */
	ret = 0;
 out:
	RSA_free(rsa);
	BN_clear_free(rsa_n);
	BN_clear_free(rsa_e);
	প্রত্যাগম ret;
}

স্থির পূর্ণাঙ্ক
ssh_rsa_deserialize_private(ধ্রুব বর্ণ *ktype, সংরচনা sshbuf *b,
    সংরচনা sshkey *চাবি)
{
	পূর্ণাঙ্ক r;
	BIGNUM *rsa_n = রিক্ত, *rsa_e = রিক্ত, *rsa_d = রিক্ত;
	BIGNUM *rsa_iqmp = রিক্ত, *rsa_p = রিক্ত, *rsa_q = রিক্ত;
	BIGNUM *rsa_dmp1 = রিক্ত, *rsa_dmq1 = রিক্ত;
	RSA *rsa = রিক্ত;

	যদি (sshkey_is_cert(চাবি)) {
		/* sshkey_private_deserialize already has pubkey from cert */
		যদি ((rsa = EVP_PKEY_get1_RSA(চাবি->pkey)) == রিক্ত) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			গচ্ছ out;
		}
	} অন্যথা {
		যদি ((rsa = RSA_new()) == রিক্ত) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			গচ্ছ out;
		}
		/* Note: can't reuse ssh_rsa_deserialize_public: e,n vs. n,e */
		যদি ((r = sshbuf_get_bignum2(b, &rsa_n)) != 0 ||
		    (r = sshbuf_get_bignum2(b, &rsa_e)) != 0)
			গচ্ছ out;
		যদি (!RSA_set0_চাবি(rsa, rsa_n, rsa_e, রিক্ত)) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			গচ্ছ out;
		}
		rsa_n = rsa_e = রিক্ত; /* transferred */
	}
	যদি ((r = sshbuf_get_bignum2(b, &rsa_d)) != 0 ||
	    (r = sshbuf_get_bignum2(b, &rsa_iqmp)) != 0 ||
	    (r = sshbuf_get_bignum2(b, &rsa_p)) != 0 ||
	    (r = sshbuf_get_bignum2(b, &rsa_q)) != 0)
		গচ্ছ out;
	যদি ((r = ssh_rsa_complete_crt_parameters(rsa_d, rsa_p, rsa_q,
	    rsa_iqmp, &rsa_dmp1, &rsa_dmq1)) != 0)
		গচ্ছ out;
	যদি (!RSA_set0_চাবি(rsa, রিক্ত, রিক্ত, rsa_d)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		গচ্ছ out;
	}
	rsa_d = রিক্ত; /* transferred */
	যদি (!RSA_set0_factors(rsa, rsa_p, rsa_q)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		গচ্ছ out;
	}
	rsa_p = rsa_q = রিক্ত; /* transferred */
	যদি (!RSA_set0_crt_params(rsa, rsa_dmp1, rsa_dmq1, rsa_iqmp)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		গচ্ছ out;
	}
	rsa_dmp1 = rsa_dmq1 = rsa_iqmp = রিক্ত;
	যদি (RSA_blinding_on(rsa, রিক্ত) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		গচ্ছ out;
	}
	যদি (EVP_PKEY_set1_RSA(চাবি->pkey, rsa) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		গচ্ছ out;
	}
	যদি ((r = sshkey_check_rsa_length(চাবি, 0)) != 0)
		গচ্ছ out;
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
	প্রত্যাগম r;
}

ধ্রুব বর্ণ *
ssh_rsa_hash_alg_ident(পূর্ণাঙ্ক hash_alg)
{
	বিকল্প (hash_alg) {
	পক্ষ SSH_DIGEST_SHA1:
		প্রত্যাগম "ssh-rsa";
	পক্ষ SSH_DIGEST_SHA256:
		প্রত্যাগম "rsa-sha2-256";
	পক্ষ SSH_DIGEST_SHA512:
		প্রত্যাগম "rsa-sha2-512";
	}
	প্রত্যাগম রিক্ত;
}

/*
 * Returns the hash algorithm ID for a given algorithm identifier as used
 * inside the signature blob,
 */
স্থির পূর্ণাঙ্ক
rsa_hash_id_from_ident(ধ্রুব বর্ণ *ident)
{
	যদি (strcmp(ident, "ssh-rsa") == 0)
		প্রত্যাগম SSH_DIGEST_SHA1;
	যদি (strcmp(ident, "rsa-sha2-256") == 0)
		প্রত্যাগম SSH_DIGEST_SHA256;
	যদি (strcmp(ident, "rsa-sha2-512") == 0)
		প্রত্যাগম SSH_DIGEST_SHA512;
	প্রত্যাগম -1;
}

/*
 * Return the hash algorithm ID for the specified key name. This includes
 * all the cases of rsa_hash_id_from_ident() but also the certificate key
 * types.
 */
পূর্ণাঙ্ক
ssh_rsa_hash_id_from_keyname(ধ্রুব বর্ণ *alg)
{
	পূর্ণাঙ্ক r;

	যদি ((r = rsa_hash_id_from_ident(alg)) != -1)
		প্রত্যাগম r;
	যদি (strcmp(alg, "ssh-rsa-cert-v01@openssh.com") == 0)
		প্রত্যাগম SSH_DIGEST_SHA1;
	যদি (strcmp(alg, "rsa-sha2-256-cert-v01@openssh.com") == 0)
		প্রত্যাগম SSH_DIGEST_SHA256;
	যদি (strcmp(alg, "rsa-sha2-512-cert-v01@openssh.com") == 0)
		প্রত্যাগম SSH_DIGEST_SHA512;
	প্রত্যাগম -1;
}

পূর্ণাঙ্ক
ssh_rsa_complete_crt_parameters(ধ্রুব BIGNUM *rsa_d, ধ্রুব BIGNUM *rsa_p,
    ধ্রুব BIGNUM *rsa_q, ধ্রুব BIGNUM *rsa_iqmp, BIGNUM **rsa_dmp1,
    BIGNUM **rsa_dmq1)
{
	BIGNUM *aux = রিক্ত, *d_consttime = রিক্ত;
	BN_CTX *ctx = রিক্ত;
	পূর্ণাঙ্ক r;

	*rsa_dmq1 = *rsa_dmp1 = রিক্ত;
	যদি ((ctx = BN_CTX_new()) == রিক্ত)
		প্রত্যাগম SSH_ERR_ALLOC_FAIL;
	যদি ((aux = BN_new()) == রিক্ত ||
	    (*rsa_dmq1 = BN_new()) == রিক্ত ||
	    (*rsa_dmp1 = BN_new()) == রিক্ত)
		প্রত্যাগম SSH_ERR_ALLOC_FAIL;
	যদি ((d_consttime = BN_dup(rsa_d)) == রিক্ত) {
		r = SSH_ERR_ALLOC_FAIL;
		গচ্ছ out;
	}
	BN_set_flags(aux, BN_FLG_CONSTTIME);
	BN_set_flags(d_consttime, BN_FLG_CONSTTIME);

	যদি ((BN_sub(aux, rsa_q, BN_মান_one()) == 0) ||
	    (BN_mod(*rsa_dmq1, d_consttime, aux, ctx) == 0) ||
	    (BN_sub(aux, rsa_p, BN_মান_one()) == 0) ||
	    (BN_mod(*rsa_dmp1, d_consttime, aux, ctx) == 0)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		গচ্ছ out;
	}
	/* success */
	r = 0;
 out:
	BN_clear_free(aux);
	BN_clear_free(d_consttime);
	BN_CTX_free(ctx);
	প্রত্যাগম r;
}

/* RSASSA-PKCS1-v1_5 (PKCS #1 v2.0 signature) with SHA1 */
স্থির পূর্ণাঙ্ক
ssh_rsa_sign(সংরচনা sshkey *চাবি,
    u_char **sigp, size_t *lenp,
    ধ্রুব u_char *data, size_t datalen,
    ধ্রুব বর্ণ *alg, ধ্রুব বর্ণ *sk_provider, ধ্রুব বর্ণ *sk_pin, u_int compat)
{
	u_char *sig = রিক্ত;
	size_t diff, len = 0;
	পূর্ণাঙ্ক slen = 0;
	পূর্ণাঙ্ক hash_alg, ret = SSH_ERR_INTERNAL_ERROR;

	যদি (lenp != রিক্ত)
		*lenp = 0;
	যদি (sigp != রিক্ত)
		*sigp = রিক্ত;

	যদি (alg == রিক্ত || strlen(alg) == 0)
		hash_alg = SSH_DIGEST_SHA1;
	অন্যথা
		hash_alg = ssh_rsa_hash_id_from_keyname(alg);

	যদি (চাবি == রিক্ত || চাবি->pkey == রিক্ত || hash_alg == -1 ||
	    sshkey_type_plain(চাবি->type) != চাবি_RSA)
		প্রত্যাগম SSH_ERR_INVALID_ARGUMENT;
	slen = EVP_PKEY_size(চাবি->pkey);
	যদি (slen <= 0 || slen > SSHBUF_MAX_BIGNUM)
		প্রত্যাগম SSH_ERR_INVALID_ARGUMENT;
	যদি (EVP_PKEY_bits(চাবি->pkey) < SSH_RSA_MINIMUM_MODULUS_SIZE)
		প্রত্যাগম SSH_ERR_চাবি_LENGTH;

	যদি ((ret = sshkey_pkey_digest_sign(চাবি->pkey, hash_alg, &sig, &len,
	    data, datalen)) < 0)
		গচ্ছ out;
	যদি (len < (size_t)slen) {
		diff = slen - len;
		memmove(sig + diff, sig, len);
		explicit_bzero(sig, diff);
	} অন্যথা যদি (len > (size_t)slen) {
		ret = SSH_ERR_INTERNAL_ERROR;
		গচ্ছ out;
	}
	যদি ((ret = ssh_rsa_encode_store_sig(hash_alg, sig, slen,
	    sigp, lenp)) != 0)
		গচ্ছ out;

	/* success */
	ret = 0;
 out:
	freezero(sig, slen);
	প্রত্যাগম ret;
}

পূর্ণাঙ্ক
ssh_rsa_encode_store_sig(পূর্ণাঙ্ক hash_alg, ধ্রুব u_char *sig, size_t slen,
    u_char **sigp, size_t *lenp)
{
	সংরচনা sshbuf *b = রিক্ত;
	পূর্ণাঙ্ক ret = SSH_ERR_INTERNAL_ERROR;
	size_t len;

	যদি (lenp != রিক্ত)
		*lenp = 0;
	যদি (sigp != রিক্ত)
		*sigp = রিক্ত;

	/* Encode signature */
	যদি ((b = sshbuf_new()) == রিক্ত) {
		ret = SSH_ERR_ALLOC_FAIL;
		গচ্ছ out;
	}
	যদি ((ret = sshbuf_put_cstring(b,
	    ssh_rsa_hash_alg_ident(hash_alg))) != 0 ||
	    (ret = sshbuf_put_string(b, sig, slen)) != 0)
		গচ্ছ out;
	len = sshbuf_len(b);

	/* Store signature */
	যদি (sigp != রিক্ত) {
		যদি ((*sigp = malloc(len)) == রিক্ত) {
			ret = SSH_ERR_ALLOC_FAIL;
			গচ্ছ out;
		}
		memcpy(*sigp, sshbuf_ptr(b), len);
	}
	যদি (lenp != রিক্ত)
		*lenp = len;
	ret = 0;
 out:
	sshbuf_free(b);
	প্রত্যাগম ret;
}

স্থির পূর্ণাঙ্ক
ssh_rsa_verify(ধ্রুব সংরচনা sshkey *চাবি,
    ধ্রুব u_char *sig, size_t siglen,
    ধ্রুব u_char *data, size_t dlen, ধ্রুব বর্ণ *alg, u_int compat,
    সংরচনা sshkey_sig_details **detailsp)
{
	বর্ণ *sigtype = রিক্ত;
	পূর্ণাঙ্ক hash_alg, want_alg, ret = SSH_ERR_INTERNAL_ERROR;
	size_t len = 0, diff, modlen, rsasize;
	সংরচনা sshbuf *b = রিক্ত;
	u_char digest[SSH_DIGEST_MAX_LENGTH], *osigblob, *sigblob = রিক্ত;

	যদি (চাবি == রিক্ত || চাবি->pkey == রিক্ত ||
	    sshkey_type_plain(চাবি->type) != চাবি_RSA ||
	    sig == রিক্ত || siglen == 0)
		প্রত্যাগম SSH_ERR_INVALID_ARGUMENT;
	যদি (EVP_PKEY_bits(চাবি->pkey) < SSH_RSA_MINIMUM_MODULUS_SIZE)
		প্রত্যাগম SSH_ERR_চাবি_LENGTH;

	যদি ((b = sshbuf_from(sig, siglen)) == রিক্ত)
		প্রত্যাগম SSH_ERR_ALLOC_FAIL;
	যদি (sshbuf_get_cstring(b, &sigtype, রিক্ত) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		গচ্ছ out;
	}
	যদি ((hash_alg = rsa_hash_id_from_ident(sigtype)) == -1) {
		ret = SSH_ERR_চাবি_TYPE_MISMATCH;
		গচ্ছ out;
	}
	/*
	 * Allow ssh-rsa-cert-v01 certs to generate SHA2 signatures for
	 * legacy reasons, but otherwise the signature type should match.
	 */
	যদি (alg != রিক্ত && strcmp(alg, "ssh-rsa-cert-v01@openssh.com") != 0) {
		যদি ((want_alg = ssh_rsa_hash_id_from_keyname(alg)) == -1) {
			ret = SSH_ERR_INVALID_ARGUMENT;
			গচ্ছ out;
		}
		যদি (hash_alg != want_alg) {
			ret = SSH_ERR_SIGNATURE_INVALID;
			গচ্ছ out;
		}
	}
	যদি (sshbuf_get_string(b, &sigblob, &len) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		গচ্ছ out;
	}
	যদি (sshbuf_len(b) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		গচ্ছ out;
	}
	/* RSA_verify expects a signature of RSA_size */
	modlen = EVP_PKEY_size(চাবি->pkey);
	যদি (len > modlen) {
		ret = SSH_ERR_চাবি_BITS_MISMATCH;
		গচ্ছ out;
	} অন্যথা যদি (len < modlen) {
		diff = modlen - len;
		osigblob = sigblob;
		যদি ((sigblob = realloc(sigblob, modlen)) == রিক্ত) {
			sigblob = osigblob; /* put it back for clear/free */
			ret = SSH_ERR_ALLOC_FAIL;
			গচ্ছ out;
		}
		memmove(sigblob + diff, sigblob, len);
		explicit_bzero(sigblob, diff);
		len = modlen;
	}

	rsasize = EVP_PKEY_size(চাবি->pkey);
	যদি (rsasize <= 0 || rsasize > SSHBUF_MAX_BIGNUM ||
	    len == 0 || len > rsasize) {
		ret = SSH_ERR_INVALID_ARGUMENT;
		গচ্ছ out;
	}
	ret = sshkey_pkey_digest_verify(চাবি->pkey, hash_alg, data, dlen,
	    sigblob, len);

 out:
	freezero(sigblob, len);
	মুক্ত(sigtype);
	sshbuf_free(b);
	explicit_bzero(digest, পরিমাণ(digest));
	প্রত্যাগম ret;
}

স্থির ধ্রুব সংরচনা sshkey_impl_funcs sshkey_rsa_funcs = {
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

ধ্রুব সংরচনা sshkey_impl sshkey_rsa_impl = {
	/* .name = */		"ssh-rsa",
	/* .shortname = */	"RSA",
	/* .sigalg = */		রিক্ত,
	/* .type = */		চাবি_RSA,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};

ধ্রুব সংরচনা sshkey_impl sshkey_rsa_cert_impl = {
	/* .name = */		"ssh-rsa-cert-v01@openssh.com",
	/* .shortname = */	"RSA-CERT",
	/* .sigalg = */		রিক্ত,
	/* .type = */		চাবি_RSA_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};

/* SHA2 signature algorithms */

ধ্রুব সংরচনা sshkey_impl sshkey_rsa_sha256_impl = {
	/* .name = */		"rsa-sha2-256",
	/* .shortname = */	"RSA",
	/* .sigalg = */		রিক্ত,
	/* .type = */		চাবি_RSA,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	1,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};

ধ্রুব সংরচনা sshkey_impl sshkey_rsa_sha512_impl = {
	/* .name = */		"rsa-sha2-512",
	/* .shortname = */	"RSA",
	/* .sigalg = */		রিক্ত,
	/* .type = */		চাবি_RSA,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	1,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};

ধ্রুব সংরচনা sshkey_impl sshkey_rsa_sha256_cert_impl = {
	/* .name = */		"rsa-sha2-256-cert-v01@openssh.com",
	/* .shortname = */	"RSA-CERT",
	/* .sigalg = */		"rsa-sha2-256",
	/* .type = */		চাবি_RSA_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	1,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};

ধ্রুব সংরচনা sshkey_impl sshkey_rsa_sha512_cert_impl = {
	/* .name = */		"rsa-sha2-512-cert-v01@openssh.com",
	/* .shortname = */	"RSA-CERT",
	/* .sigalg = */		"rsa-sha2-512",
	/* .type = */		চাবি_RSA_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	1,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};
#endif /* WITH_OPENSSL */
