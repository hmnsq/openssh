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
ssh_rsa_আকার(ধ্রুবক কাঠামো sshkey *k)
{
	যদি (k->pkey == ফাঁকা)
		ফেরত 0;
	ফেরত EVP_PKEY_bits(k->pkey);
}

স্থির পূর্ণসংখ্যা
ssh_rsa_alloc(কাঠামো sshkey *k)
{
	যদি ((k->pkey = EVP_PKEY_new()) == ফাঁকা)
		ফেরত SSH_ERR_ALLOC_FAIL;
	ফেরত 0;
}

স্থির শূন্য
ssh_rsa_cleanup(কাঠামো sshkey *k)
{
	EVP_PKEY_free(k->pkey);
	k->pkey = ফাঁকা;
}

স্থির পূর্ণসংখ্যা
ssh_rsa_equal(ধ্রুবক কাঠামো sshkey *a, ধ্রুবক কাঠামো sshkey *b)
{
	যদি (a->pkey == ফাঁকা || b->pkey == ফাঁকা)
		ফেরত 0;
	ফেরত EVP_PKEY_cmp(a->pkey, b->pkey) == 1;
}

স্থির পূর্ণসংখ্যা
ssh_rsa_serialize_public(ধ্রুবক কাঠামো sshkey *চাবি, কাঠামো sshbuf *b,
    গণনা sshkey_serialize_rep opts)
{
	পূর্ণসংখ্যা r;
	ধ্রুবক BIGNUM *rsa_n, *rsa_e;
	ধ্রুবক RSA *rsa;

	যদি (চাবি->pkey == ফাঁকা)
		ফেরত SSH_ERR_INVALID_ARGUMENT;
	যদি ((rsa = EVP_PKEY_get0_RSA(চাবি->pkey)) == ফাঁকা)
		ফেরত SSH_ERR_LIBCRYPTO_ERROR;

	RSA_get0_চাবি(rsa, &rsa_n, &rsa_e, ফাঁকা);
	যদি ((r = sshbuf_put_bignum2(b, rsa_e)) != 0 ||
	    (r = sshbuf_put_bignum2(b, rsa_n)) != 0)
		ফেরত r;

	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
ssh_rsa_serialize_private(ধ্রুবক কাঠামো sshkey *চাবি, কাঠামো sshbuf *b,
    গণনা sshkey_serialize_rep opts)
{
	পূর্ণসংখ্যা r;
	ধ্রুবক BIGNUM *rsa_n, *rsa_e, *rsa_d, *rsa_iqmp, *rsa_p, *rsa_q;
	ধ্রুবক RSA *rsa;

	যদি ((rsa = EVP_PKEY_get0_RSA(চাবি->pkey)) == ফাঁকা)
		ফেরত SSH_ERR_LIBCRYPTO_ERROR;
	RSA_get0_চাবি(rsa, &rsa_n, &rsa_e, &rsa_d);
	RSA_get0_factors(rsa, &rsa_p, &rsa_q);
	RSA_get0_crt_params(rsa, ফাঁকা, ফাঁকা, &rsa_iqmp);

	যদি (!sshkey_is_cert(চাবি)) {
		/* Note: can't reuse ssh_rsa_serialize_public: e, n vs. n, e */
		যদি ((r = sshbuf_put_bignum2(b, rsa_n)) != 0 ||
		    (r = sshbuf_put_bignum2(b, rsa_e)) != 0)
			ফেরত r;
	}
	যদি ((r = sshbuf_put_bignum2(b, rsa_d)) != 0 ||
	    (r = sshbuf_put_bignum2(b, rsa_iqmp)) != 0 ||
	    (r = sshbuf_put_bignum2(b, rsa_p)) != 0 ||
	    (r = sshbuf_put_bignum2(b, rsa_q)) != 0)
		ফেরত r;

	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
ssh_rsa_generate(কাঠামো sshkey *k, পূর্ণসংখ্যা bits)
{
	EVP_PKEY_CTX *ctx = ফাঁকা;
	EVP_PKEY *res = ফাঁকা;

	পূর্ণসংখ্যা ret = SSH_ERR_INTERNAL_ERROR;

	যদি (bits < SSH_RSA_MINIMUM_MODULUS_আকার ||
	    bits > SSHBUF_MAX_BIGNUM * 8)
		ফেরত SSH_ERR_চাবি_দৈর্ঘ্য;

	যদি ((ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, ফাঁকা)) == ফাঁকা) {
		ret = SSH_ERR_ALLOC_FAIL;
		যাও out;
	}
	যদি (EVP_PKEY_keygen_init(ctx) <= 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		যাও out;
	}
	যদি (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0) {
		ret = SSH_ERR_চাবি_দৈর্ঘ্য;
		যাও out;
	}
	যদি (EVP_PKEY_keygen(ctx, &res) <= 0 || res == ফাঁকা) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		যাও out;
	}
	/* success */
	k->pkey = res;
	ret = 0;
 out:
	EVP_PKEY_CTX_free(ctx);
	ফেরত ret;
}

স্থির পূর্ণসংখ্যা
ssh_rsa_copy_public(ধ্রুবক কাঠামো sshkey *from, কাঠামো sshkey *to)
{
	ধ্রুবক BIGNUM *rsa_n, *rsa_e;
	BIGNUM *rsa_n_dup = ফাঁকা, *rsa_e_dup = ফাঁকা;
	পূর্ণসংখ্যা r = SSH_ERR_INTERNAL_ERROR;
	ধ্রুবক RSA *rsa_from;
	RSA *rsa_to = ফাঁকা;

	যদি ((rsa_from = EVP_PKEY_get0_RSA(from->pkey)) == ফাঁকা ||
	    (rsa_to = RSA_new()) == ফাঁকা)
		ফেরত SSH_ERR_LIBCRYPTO_ERROR;

	RSA_get0_চাবি(rsa_from, &rsa_n, &rsa_e, ফাঁকা);
	যদি ((rsa_n_dup = BN_dup(rsa_n)) == ফাঁকা ||
	    (rsa_e_dup = BN_dup(rsa_e)) == ফাঁকা) {
		r = SSH_ERR_ALLOC_FAIL;
		যাও out;
	}
	যদি (!RSA_set0_চাবি(rsa_to, rsa_n_dup, rsa_e_dup, ফাঁকা)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		যাও out;
	}
	rsa_n_dup = rsa_e_dup = ফাঁকা; /* transferred */

	যদি (EVP_PKEY_set1_RSA(to->pkey, rsa_to) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		যাও out;
	}
	/* success */
	r = 0;
 out:
	RSA_free(rsa_to);
	BN_clear_free(rsa_n_dup);
	BN_clear_free(rsa_e_dup);
	ফেরত r;
}

স্থির পূর্ণসংখ্যা
ssh_rsa_deserialize_public(ধ্রুবক অক্ষর *ktype, কাঠামো sshbuf *b,
    কাঠামো sshkey *চাবি)
{
	পূর্ণসংখ্যা ret = SSH_ERR_INTERNAL_ERROR;
	BIGNUM *rsa_n = ফাঁকা, *rsa_e = ফাঁকা;
	RSA *rsa = ফাঁকা;

	যদি ((rsa = RSA_new()) == ফাঁকা)
		ফেরত SSH_ERR_LIBCRYPTO_ERROR;

	যদি (sshbuf_get_bignum2(b, &rsa_e) != 0 ||
	    sshbuf_get_bignum2(b, &rsa_n) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		যাও out;
	}
	যদি (!RSA_set0_চাবি(rsa, rsa_n, rsa_e, ফাঁকা)) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		যাও out;
	}
	rsa_n = rsa_e = ফাঁকা; /* transferred */
	যদি (EVP_PKEY_set1_RSA(চাবি->pkey, rsa) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		যাও out;
	}
	যদি ((ret = sshkey_check_rsa_দৈর্ঘ্য(চাবি, 0)) != 0)
		যাও out;
#ifdef DEBUG_PK
	RSA_print_fp(stderr, rsa, 8);
#endif
	/* success */
	ret = 0;
 out:
	RSA_free(rsa);
	BN_clear_free(rsa_n);
	BN_clear_free(rsa_e);
	ফেরত ret;
}

স্থির পূর্ণসংখ্যা
ssh_rsa_deserialize_private(ধ্রুবক অক্ষর *ktype, কাঠামো sshbuf *b,
    কাঠামো sshkey *চাবি)
{
	পূর্ণসংখ্যা r;
	BIGNUM *rsa_n = ফাঁকা, *rsa_e = ফাঁকা, *rsa_d = ফাঁকা;
	BIGNUM *rsa_iqmp = ফাঁকা, *rsa_p = ফাঁকা, *rsa_q = ফাঁকা;
	BIGNUM *rsa_dmp1 = ফাঁকা, *rsa_dmq1 = ফাঁকা;
	RSA *rsa = ফাঁকা;

	যদি (sshkey_is_cert(চাবি)) {
		/* sshkey_private_deserialize already has pubkey from cert */
		যদি ((rsa = EVP_PKEY_get1_RSA(চাবি->pkey)) == ফাঁকা) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			যাও out;
		}
	} অন্যথা {
		যদি ((rsa = RSA_new()) == ফাঁকা) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			যাও out;
		}
		/* Note: can't reuse ssh_rsa_deserialize_public: e,n vs. n,e */
		যদি ((r = sshbuf_get_bignum2(b, &rsa_n)) != 0 ||
		    (r = sshbuf_get_bignum2(b, &rsa_e)) != 0)
			যাও out;
		যদি (!RSA_set0_চাবি(rsa, rsa_n, rsa_e, ফাঁকা)) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			যাও out;
		}
		rsa_n = rsa_e = ফাঁকা; /* transferred */
	}
	যদি ((r = sshbuf_get_bignum2(b, &rsa_d)) != 0 ||
	    (r = sshbuf_get_bignum2(b, &rsa_iqmp)) != 0 ||
	    (r = sshbuf_get_bignum2(b, &rsa_p)) != 0 ||
	    (r = sshbuf_get_bignum2(b, &rsa_q)) != 0)
		যাও out;
	যদি ((r = ssh_rsa_complete_crt_parameters(rsa_d, rsa_p, rsa_q,
	    rsa_iqmp, &rsa_dmp1, &rsa_dmq1)) != 0)
		যাও out;
	যদি (!RSA_set0_চাবি(rsa, ফাঁকা, ফাঁকা, rsa_d)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		যাও out;
	}
	rsa_d = ফাঁকা; /* transferred */
	যদি (!RSA_set0_factors(rsa, rsa_p, rsa_q)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		যাও out;
	}
	rsa_p = rsa_q = ফাঁকা; /* transferred */
	যদি (!RSA_set0_crt_params(rsa, rsa_dmp1, rsa_dmq1, rsa_iqmp)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		যাও out;
	}
	rsa_dmp1 = rsa_dmq1 = rsa_iqmp = ফাঁকা;
	যদি (RSA_blinding_on(rsa, ফাঁকা) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		যাও out;
	}
	যদি (EVP_PKEY_set1_RSA(চাবি->pkey, rsa) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		যাও out;
	}
	যদি ((r = sshkey_check_rsa_দৈর্ঘ্য(চাবি, 0)) != 0)
		যাও out;
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
	ফেরত r;
}

ধ্রুবক অক্ষর *
ssh_rsa_hash_alg_ident(পূর্ণসংখ্যা hash_alg)
{
	নির্বাচন (hash_alg) {
	ক্ষেত্র SSH_DIGEST_SHA1:
		ফেরত "ssh-rsa";
	ক্ষেত্র SSH_DIGEST_SHA256:
		ফেরত "rsa-sha2-256";
	ক্ষেত্র SSH_DIGEST_SHA512:
		ফেরত "rsa-sha2-512";
	}
	ফেরত ফাঁকা;
}

/*
 * Returns the hash algorithm ID for a given algorithm identifier as used
 * inside the signature blob,
 */
স্থির পূর্ণসংখ্যা
rsa_hash_id_from_ident(ধ্রুবক অক্ষর *ident)
{
	যদি (strcmp(ident, "ssh-rsa") == 0)
		ফেরত SSH_DIGEST_SHA1;
	যদি (strcmp(ident, "rsa-sha2-256") == 0)
		ফেরত SSH_DIGEST_SHA256;
	যদি (strcmp(ident, "rsa-sha2-512") == 0)
		ফেরত SSH_DIGEST_SHA512;
	ফেরত -1;
}

/*
 * Return the hash algorithm ID for the specified key name. This includes
 * all the cases of rsa_hash_id_from_ident() but also the certificate key
 * types.
 */
পূর্ণসংখ্যা
ssh_rsa_hash_id_from_keyname(ধ্রুবক অক্ষর *alg)
{
	পূর্ণসংখ্যা r;

	যদি ((r = rsa_hash_id_from_ident(alg)) != -1)
		ফেরত r;
	যদি (strcmp(alg, "ssh-rsa-cert-v01@openssh.com") == 0)
		ফেরত SSH_DIGEST_SHA1;
	যদি (strcmp(alg, "rsa-sha2-256-cert-v01@openssh.com") == 0)
		ফেরত SSH_DIGEST_SHA256;
	যদি (strcmp(alg, "rsa-sha2-512-cert-v01@openssh.com") == 0)
		ফেরত SSH_DIGEST_SHA512;
	ফেরত -1;
}

পূর্ণসংখ্যা
ssh_rsa_complete_crt_parameters(ধ্রুবক BIGNUM *rsa_d, ধ্রুবক BIGNUM *rsa_p,
    ধ্রুবক BIGNUM *rsa_q, ধ্রুবক BIGNUM *rsa_iqmp, BIGNUM **rsa_dmp1,
    BIGNUM **rsa_dmq1)
{
	BIGNUM *aux = ফাঁকা, *d_consttime = ফাঁকা;
	BN_CTX *ctx = ফাঁকা;
	পূর্ণসংখ্যা r;

	*rsa_dmq1 = *rsa_dmp1 = ফাঁকা;
	যদি ((ctx = BN_CTX_new()) == ফাঁকা)
		ফেরত SSH_ERR_ALLOC_FAIL;
	যদি ((aux = BN_new()) == ফাঁকা ||
	    (*rsa_dmq1 = BN_new()) == ফাঁকা ||
	    (*rsa_dmp1 = BN_new()) == ফাঁকা)
		ফেরত SSH_ERR_ALLOC_FAIL;
	যদি ((d_consttime = BN_dup(rsa_d)) == ফাঁকা) {
		r = SSH_ERR_ALLOC_FAIL;
		যাও out;
	}
	BN_set_flags(aux, BN_FLG_CONSTTIME);
	BN_set_flags(d_consttime, BN_FLG_CONSTTIME);

	যদি ((BN_sub(aux, rsa_q, BN_মান_one()) == 0) ||
	    (BN_mod(*rsa_dmq1, d_consttime, aux, ctx) == 0) ||
	    (BN_sub(aux, rsa_p, BN_মান_one()) == 0) ||
	    (BN_mod(*rsa_dmp1, d_consttime, aux, ctx) == 0)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		যাও out;
	}
	/* success */
	r = 0;
 out:
	BN_clear_free(aux);
	BN_clear_free(d_consttime);
	BN_CTX_free(ctx);
	ফেরত r;
}

/* RSASSA-PKCS1-v1_5 (PKCS #1 v2.0 signature) with SHA1 */
স্থির পূর্ণসংখ্যা
ssh_rsa_sign(কাঠামো sshkey *চাবি,
    u_char **sigp, আকার_t *lenp,
    ধ্রুবক u_char *তথ্য, আকার_t datalen,
    ধ্রুবক অক্ষর *alg, ধ্রুবক অক্ষর *sk_provider, ধ্রুবক অক্ষর *sk_pin, u_int compat)
{
	u_char *sig = ফাঁকা;
	আকার_t diff, len = 0;
	পূর্ণসংখ্যা slen = 0;
	পূর্ণসংখ্যা hash_alg, ret = SSH_ERR_INTERNAL_ERROR;

	যদি (lenp != ফাঁকা)
		*lenp = 0;
	যদি (sigp != ফাঁকা)
		*sigp = ফাঁকা;

	যদি (alg == ফাঁকা || strlen(alg) == 0)
		hash_alg = SSH_DIGEST_SHA1;
	অন্যথা
		hash_alg = ssh_rsa_hash_id_from_keyname(alg);

	যদি (চাবি == ফাঁকা || চাবি->pkey == ফাঁকা || hash_alg == -1 ||
	    sshkey_type_plain(চাবি->type) != চাবি_RSA)
		ফেরত SSH_ERR_INVALID_ARGUMENT;
	slen = EVP_PKEY_আকার(চাবি->pkey);
	যদি (slen <= 0 || slen > SSHBUF_MAX_BIGNUM)
		ফেরত SSH_ERR_INVALID_ARGUMENT;
	যদি (EVP_PKEY_bits(চাবি->pkey) < SSH_RSA_MINIMUM_MODULUS_আকার)
		ফেরত SSH_ERR_চাবি_দৈর্ঘ্য;

	যদি ((ret = sshkey_pkey_digest_sign(চাবি->pkey, hash_alg, &sig, &len,
	    তথ্য, datalen)) < 0)
		যাও out;
	যদি (len < (আকার_t)slen) {
		diff = slen - len;
		memmove(sig + diff, sig, len);
		explicit_bzero(sig, diff);
	} অন্যথা যদি (len > (আকার_t)slen) {
		ret = SSH_ERR_INTERNAL_ERROR;
		যাও out;
	}
	যদি ((ret = ssh_rsa_encode_store_sig(hash_alg, sig, slen,
	    sigp, lenp)) != 0)
		যাও out;

	/* success */
	ret = 0;
 out:
	freezero(sig, slen);
	ফেরত ret;
}

পূর্ণসংখ্যা
ssh_rsa_encode_store_sig(পূর্ণসংখ্যা hash_alg, ধ্রুবক u_char *sig, আকার_t slen,
    u_char **sigp, আকার_t *lenp)
{
	কাঠামো sshbuf *b = ফাঁকা;
	পূর্ণসংখ্যা ret = SSH_ERR_INTERNAL_ERROR;
	আকার_t len;

	যদি (lenp != ফাঁকা)
		*lenp = 0;
	যদি (sigp != ফাঁকা)
		*sigp = ফাঁকা;

	/* Encode signature */
	যদি ((b = sshbuf_new()) == ফাঁকা) {
		ret = SSH_ERR_ALLOC_FAIL;
		যাও out;
	}
	যদি ((ret = sshbuf_put_cstring(b,
	    ssh_rsa_hash_alg_ident(hash_alg))) != 0 ||
	    (ret = sshbuf_put_string(b, sig, slen)) != 0)
		যাও out;
	len = sshbuf_len(b);

	/* Store signature */
	যদি (sigp != ফাঁকা) {
		যদি ((*sigp = malloc(len)) == ফাঁকা) {
			ret = SSH_ERR_ALLOC_FAIL;
			যাও out;
		}
		memcpy(*sigp, sshbuf_ptr(b), len);
	}
	যদি (lenp != ফাঁকা)
		*lenp = len;
	ret = 0;
 out:
	sshbuf_free(b);
	ফেরত ret;
}

স্থির পূর্ণসংখ্যা
ssh_rsa_verify(ধ্রুবক কাঠামো sshkey *চাবি,
    ধ্রুবক u_char *sig, আকার_t siglen,
    ধ্রুবক u_char *তথ্য, আকার_t dlen, ধ্রুবক অক্ষর *alg, u_int compat,
    কাঠামো sshkey_sig_details **detailsp)
{
	অক্ষর *sigtype = ফাঁকা;
	পূর্ণসংখ্যা hash_alg, want_alg, ret = SSH_ERR_INTERNAL_ERROR;
	আকার_t len = 0, diff, modlen, rsasize;
	কাঠামো sshbuf *b = ফাঁকা;
	u_char digest[SSH_DIGEST_MAX_দৈর্ঘ্য], *osigblob, *sigblob = ফাঁকা;

	যদি (চাবি == ফাঁকা || চাবি->pkey == ফাঁকা ||
	    sshkey_type_plain(চাবি->type) != চাবি_RSA ||
	    sig == ফাঁকা || siglen == 0)
		ফেরত SSH_ERR_INVALID_ARGUMENT;
	যদি (EVP_PKEY_bits(চাবি->pkey) < SSH_RSA_MINIMUM_MODULUS_আকার)
		ফেরত SSH_ERR_চাবি_দৈর্ঘ্য;

	যদি ((b = sshbuf_from(sig, siglen)) == ফাঁকা)
		ফেরত SSH_ERR_ALLOC_FAIL;
	যদি (sshbuf_get_cstring(b, &sigtype, ফাঁকা) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		যাও out;
	}
	যদি ((hash_alg = rsa_hash_id_from_ident(sigtype)) == -1) {
		ret = SSH_ERR_চাবি_TYPE_MISMATCH;
		যাও out;
	}
	/*
	 * Allow ssh-rsa-cert-v01 certs to generate SHA2 signatures for
	 * legacy reasons, but otherwise the signature type should match.
	 */
	যদি (alg != ফাঁকা && strcmp(alg, "ssh-rsa-cert-v01@openssh.com") != 0) {
		যদি ((want_alg = ssh_rsa_hash_id_from_keyname(alg)) == -1) {
			ret = SSH_ERR_INVALID_ARGUMENT;
			যাও out;
		}
		যদি (hash_alg != want_alg) {
			ret = SSH_ERR_SIGNATURE_INVALID;
			যাও out;
		}
	}
	যদি (sshbuf_get_string(b, &sigblob, &len) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		যাও out;
	}
	যদি (sshbuf_len(b) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_তথ্য;
		যাও out;
	}
	/* RSA_verify expects a signature of RSA_size */
	modlen = EVP_PKEY_আকার(চাবি->pkey);
	যদি (len > modlen) {
		ret = SSH_ERR_চাবি_BITS_MISMATCH;
		যাও out;
	} অন্যথা যদি (len < modlen) {
		diff = modlen - len;
		osigblob = sigblob;
		যদি ((sigblob = realloc(sigblob, modlen)) == ফাঁকা) {
			sigblob = osigblob; /* put it back for clear/free */
			ret = SSH_ERR_ALLOC_FAIL;
			যাও out;
		}
		memmove(sigblob + diff, sigblob, len);
		explicit_bzero(sigblob, diff);
		len = modlen;
	}

	rsasize = EVP_PKEY_আকার(চাবি->pkey);
	যদি (rsasize <= 0 || rsasize > SSHBUF_MAX_BIGNUM ||
	    len == 0 || len > rsasize) {
		ret = SSH_ERR_INVALID_ARGUMENT;
		যাও out;
	}
	ret = sshkey_pkey_digest_verify(চাবি->pkey, hash_alg, তথ্য, dlen,
	    sigblob, len);

 out:
	freezero(sigblob, len);
	মুক্ত(sigtype);
	sshbuf_free(b);
	explicit_bzero(digest, আকার(digest));
	ফেরত ret;
}

স্থির ধ্রুবক কাঠামো sshkey_impl_funcs sshkey_rsa_funcs = {
	/* .size = */		ssh_rsa_আকার,
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

ধ্রুবক কাঠামো sshkey_impl sshkey_rsa_impl = {
	/* .name = */		"ssh-rsa",
	/* .shortname = */	"RSA",
	/* .sigalg = */		ফাঁকা,
	/* .type = */		চাবি_RSA,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};

ধ্রুবক কাঠামো sshkey_impl sshkey_rsa_cert_impl = {
	/* .name = */		"ssh-rsa-cert-v01@openssh.com",
	/* .shortname = */	"RSA-CERT",
	/* .sigalg = */		ফাঁকা,
	/* .type = */		চাবি_RSA_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};

/* SHA2 signature algorithms */

ধ্রুবক কাঠামো sshkey_impl sshkey_rsa_sha256_impl = {
	/* .name = */		"rsa-sha2-256",
	/* .shortname = */	"RSA",
	/* .sigalg = */		ফাঁকা,
	/* .type = */		চাবি_RSA,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	1,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};

ধ্রুবক কাঠামো sshkey_impl sshkey_rsa_sha512_impl = {
	/* .name = */		"rsa-sha2-512",
	/* .shortname = */	"RSA",
	/* .sigalg = */		ফাঁকা,
	/* .type = */		চাবি_RSA,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	1,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};

ধ্রুবক কাঠামো sshkey_impl sshkey_rsa_sha256_cert_impl = {
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

ধ্রুবক কাঠামো sshkey_impl sshkey_rsa_sha512_cert_impl = {
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
