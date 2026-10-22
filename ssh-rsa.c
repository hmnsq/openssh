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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ifdef WITH_OPENSSL
#ଅନ୍ତର୍ଭାଵ "openbsd-compat/openssl-compat.h"

#ଅନ୍ତର୍ଭାଵ <sys/types.h>

#ଅନ୍ତର୍ଭାଵ <openssl/bn.h>
#ଅନ୍ତର୍ଭାଵ <openssl/evp.h>

#ଅନ୍ତର୍ଭାଵ <stdarg.h>
#ଅନ୍ତର୍ଭାଵ <string.h>

#ଅନ୍ତର୍ଭାଵ "sshbuf.h"
#ଅନ୍ତର୍ଭାଵ "ssherr.h"
#define SSHKEY_INTERNAL
#ଅନ୍ତର୍ଭାଵ "sshkey.h"
#ଅନ୍ତର୍ଭାଵ "digest.h"

ସ୍ଥିର u_int
ssh_rsa_size(ଅଚଳ ସଂରଚନା sshkey *k)
{
	ଯଦି (k->pkey == ଖାଲି)
		ଫେରନ୍ତୁ 0;
	ଫେରନ୍ତୁ EVP_PKEY_bits(k->pkey);
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_rsa_alloc(ସଂରଚନା sshkey *k)
{
	ଯଦି ((k->pkey = EVP_PKEY_new()) == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_ALLOC_FAIL;
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ଶୂନ୍ୟ
ssh_rsa_cleanup(ସଂରଚନା sshkey *k)
{
	EVP_PKEY_free(k->pkey);
	k->pkey = ଖାଲି;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_rsa_equal(ଅଚଳ ସଂରଚନା sshkey *a, ଅଚଳ ସଂରଚନା sshkey *b)
{
	ଯଦି (a->pkey == ଖାଲି || b->pkey == ଖାଲି)
		ଫେରନ୍ତୁ 0;
	ଫେରନ୍ତୁ EVP_PKEY_cmp(a->pkey, b->pkey) == 1;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_rsa_serialize_public(ଅଚଳ ସଂରଚନା sshkey *ଚାବି, ସଂରଚନା sshbuf *b,
    ଗଣନା sshkey_serialize_rep opts)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	ଅଚଳ BIGNUM *rsa_n, *rsa_e;
	ଅଚଳ RSA *rsa;

	ଯଦି (ଚାବି->pkey == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_INVALID_ARGUMENT;
	ଯଦି ((rsa = EVP_PKEY_get0_RSA(ଚାବି->pkey)) == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_LIBCRYPTO_ERROR;

	RSA_get0_ଚାବି(rsa, &rsa_n, &rsa_e, ଖାଲି);
	ଯଦି ((r = sshbuf_put_bignum2(b, rsa_e)) != 0 ||
	    (r = sshbuf_put_bignum2(b, rsa_n)) != 0)
		ଫେରନ୍ତୁ r;

	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_rsa_serialize_private(ଅଚଳ ସଂରଚନା sshkey *ଚାବି, ସଂରଚନା sshbuf *b,
    ଗଣନା sshkey_serialize_rep opts)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	ଅଚଳ BIGNUM *rsa_n, *rsa_e, *rsa_d, *rsa_iqmp, *rsa_p, *rsa_q;
	ଅଚଳ RSA *rsa;

	ଯଦି ((rsa = EVP_PKEY_get0_RSA(ଚାବି->pkey)) == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_LIBCRYPTO_ERROR;
	RSA_get0_ଚାବି(rsa, &rsa_n, &rsa_e, &rsa_d);
	RSA_get0_factors(rsa, &rsa_p, &rsa_q);
	RSA_get0_crt_params(rsa, ଖାଲି, ଖାଲି, &rsa_iqmp);

	ଯଦି (!sshkey_is_cert(ଚାବି)) {
		/* Note: can't reuse ssh_rsa_serialize_public: e, n vs. n, e */
		ଯଦି ((r = sshbuf_put_bignum2(b, rsa_n)) != 0 ||
		    (r = sshbuf_put_bignum2(b, rsa_e)) != 0)
			ଫେରନ୍ତୁ r;
	}
	ଯଦି ((r = sshbuf_put_bignum2(b, rsa_d)) != 0 ||
	    (r = sshbuf_put_bignum2(b, rsa_iqmp)) != 0 ||
	    (r = sshbuf_put_bignum2(b, rsa_p)) != 0 ||
	    (r = sshbuf_put_bignum2(b, rsa_q)) != 0)
		ଫେରନ୍ତୁ r;

	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_rsa_generate(ସଂରଚନା sshkey *k, ପୂର୍ଣ୍ଣସଂଖ୍ୟା bits)
{
	EVP_PKEY_CTX *ctx = ଖାଲି;
	EVP_PKEY *res = ଖାଲି;

	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ret = SSH_ERR_INTERNAL_ERROR;

	ଯଦି (bits < SSH_RSA_MINIMUM_MODULUS_SIZE ||
	    bits > SSHBUF_MAX_BIGNUM * 8)
		ଫେରନ୍ତୁ SSH_ERR_ଚାବି_LENGTH;

	ଯଦି ((ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, ଖାଲି)) == ଖାଲି) {
		ret = SSH_ERR_ALLOC_FAIL;
		ଯାଅ out;
	}
	ଯଦି (EVP_PKEY_keygen_init(ctx) <= 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		ଯାଅ out;
	}
	ଯଦି (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0) {
		ret = SSH_ERR_ଚାବି_LENGTH;
		ଯାଅ out;
	}
	ଯଦି (EVP_PKEY_keygen(ctx, &res) <= 0 || res == ଖାଲି) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		ଯାଅ out;
	}
	/* success */
	k->pkey = res;
	ret = 0;
 out:
	EVP_PKEY_CTX_free(ctx);
	ଫେରନ୍ତୁ ret;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_rsa_copy_public(ଅଚଳ ସଂରଚନା sshkey *from, ସଂରଚନା sshkey *to)
{
	ଅଚଳ BIGNUM *rsa_n, *rsa_e;
	BIGNUM *rsa_n_dup = ଖାଲି, *rsa_e_dup = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r = SSH_ERR_INTERNAL_ERROR;
	ଅଚଳ RSA *rsa_from;
	RSA *rsa_to = ଖାଲି;

	ଯଦି ((rsa_from = EVP_PKEY_get0_RSA(from->pkey)) == ଖାଲି ||
	    (rsa_to = RSA_new()) == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_LIBCRYPTO_ERROR;

	RSA_get0_ଚାବି(rsa_from, &rsa_n, &rsa_e, ଖାଲି);
	ଯଦି ((rsa_n_dup = BN_dup(rsa_n)) == ଖାଲି ||
	    (rsa_e_dup = BN_dup(rsa_e)) == ଖାଲି) {
		r = SSH_ERR_ALLOC_FAIL;
		ଯାଅ out;
	}
	ଯଦି (!RSA_set0_ଚାବି(rsa_to, rsa_n_dup, rsa_e_dup, ଖାଲି)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		ଯାଅ out;
	}
	rsa_n_dup = rsa_e_dup = ଖାଲି; /* transferred */

	ଯଦି (EVP_PKEY_set1_RSA(to->pkey, rsa_to) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		ଯାଅ out;
	}
	/* success */
	r = 0;
 out:
	RSA_free(rsa_to);
	BN_clear_free(rsa_n_dup);
	BN_clear_free(rsa_e_dup);
	ଫେରନ୍ତୁ r;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_rsa_deserialize_public(ଅଚଳ ଅକ୍ଷର *ktype, ସଂରଚନା sshbuf *b,
    ସଂରଚନା sshkey *ଚାବି)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ret = SSH_ERR_INTERNAL_ERROR;
	BIGNUM *rsa_n = ଖାଲି, *rsa_e = ଖାଲି;
	RSA *rsa = ଖାଲି;

	ଯଦି ((rsa = RSA_new()) == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_LIBCRYPTO_ERROR;

	ଯଦି (sshbuf_get_bignum2(b, &rsa_e) != 0 ||
	    sshbuf_get_bignum2(b, &rsa_n) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		ଯାଅ out;
	}
	ଯଦି (!RSA_set0_ଚାବି(rsa, rsa_n, rsa_e, ଖାଲି)) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		ଯାଅ out;
	}
	rsa_n = rsa_e = ଖାଲି; /* transferred */
	ଯଦି (EVP_PKEY_set1_RSA(ଚାବି->pkey, rsa) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		ଯାଅ out;
	}
	ଯଦି ((ret = sshkey_check_rsa_length(ଚାବି, 0)) != 0)
		ଯାଅ out;
#ifdef DEBUG_PK
	RSA_print_fp(stderr, rsa, 8);
#endif
	/* success */
	ret = 0;
 out:
	RSA_free(rsa);
	BN_clear_free(rsa_n);
	BN_clear_free(rsa_e);
	ଫେରନ୍ତୁ ret;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_rsa_deserialize_private(ଅଚଳ ଅକ୍ଷର *ktype, ସଂରଚନା sshbuf *b,
    ସଂରଚନା sshkey *ଚାବି)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	BIGNUM *rsa_n = ଖାଲି, *rsa_e = ଖାଲି, *rsa_d = ଖାଲି;
	BIGNUM *rsa_iqmp = ଖାଲି, *rsa_p = ଖାଲି, *rsa_q = ଖାଲି;
	BIGNUM *rsa_dmp1 = ଖାଲି, *rsa_dmq1 = ଖାଲି;
	RSA *rsa = ଖାଲି;

	ଯଦି (sshkey_is_cert(ଚାବି)) {
		/* sshkey_private_deserialize already has pubkey from cert */
		ଯଦି ((rsa = EVP_PKEY_get1_RSA(ଚାବି->pkey)) == ଖାଲି) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			ଯାଅ out;
		}
	} ଅନ୍ୟଥା {
		ଯଦି ((rsa = RSA_new()) == ଖାଲି) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			ଯାଅ out;
		}
		/* Note: can't reuse ssh_rsa_deserialize_public: e,n vs. n,e */
		ଯଦି ((r = sshbuf_get_bignum2(b, &rsa_n)) != 0 ||
		    (r = sshbuf_get_bignum2(b, &rsa_e)) != 0)
			ଯାଅ out;
		ଯଦି (!RSA_set0_ଚାବି(rsa, rsa_n, rsa_e, ଖାଲି)) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			ଯାଅ out;
		}
		rsa_n = rsa_e = ଖାଲି; /* transferred */
	}
	ଯଦି ((r = sshbuf_get_bignum2(b, &rsa_d)) != 0 ||
	    (r = sshbuf_get_bignum2(b, &rsa_iqmp)) != 0 ||
	    (r = sshbuf_get_bignum2(b, &rsa_p)) != 0 ||
	    (r = sshbuf_get_bignum2(b, &rsa_q)) != 0)
		ଯାଅ out;
	ଯଦି ((r = ssh_rsa_complete_crt_parameters(rsa_d, rsa_p, rsa_q,
	    rsa_iqmp, &rsa_dmp1, &rsa_dmq1)) != 0)
		ଯାଅ out;
	ଯଦି (!RSA_set0_ଚାବି(rsa, ଖାଲି, ଖାଲି, rsa_d)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		ଯାଅ out;
	}
	rsa_d = ଖାଲି; /* transferred */
	ଯଦି (!RSA_set0_factors(rsa, rsa_p, rsa_q)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		ଯାଅ out;
	}
	rsa_p = rsa_q = ଖାଲି; /* transferred */
	ଯଦି (!RSA_set0_crt_params(rsa, rsa_dmp1, rsa_dmq1, rsa_iqmp)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		ଯାଅ out;
	}
	rsa_dmp1 = rsa_dmq1 = rsa_iqmp = ଖାଲି;
	ଯଦି (RSA_blinding_on(rsa, ଖାଲି) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		ଯାଅ out;
	}
	ଯଦି (EVP_PKEY_set1_RSA(ଚାବି->pkey, rsa) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		ଯାଅ out;
	}
	ଯଦି ((r = sshkey_check_rsa_length(ଚାବି, 0)) != 0)
		ଯାଅ out;
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
	ଫେରନ୍ତୁ r;
}

ଅଚଳ ଅକ୍ଷର *
ssh_rsa_hash_alg_ident(ପୂର୍ଣ୍ଣସଂଖ୍ୟା hash_alg)
{
	ବାଛ (hash_alg) {
	ସ୍ଥିତି SSH_DIGEST_SHA1:
		ଫେରନ୍ତୁ "ssh-rsa";
	ସ୍ଥିତି SSH_DIGEST_SHA256:
		ଫେରନ୍ତୁ "rsa-sha2-256";
	ସ୍ଥିତି SSH_DIGEST_SHA512:
		ଫେରନ୍ତୁ "rsa-sha2-512";
	}
	ଫେରନ୍ତୁ ଖାଲି;
}

/*
 * Returns the hash algorithm ID for a given algorithm identifier as used
 * inside the signature blob,
 */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
rsa_hash_id_from_ident(ଅଚଳ ଅକ୍ଷର *ident)
{
	ଯଦି (strcmp(ident, "ssh-rsa") == 0)
		ଫେରନ୍ତୁ SSH_DIGEST_SHA1;
	ଯଦି (strcmp(ident, "rsa-sha2-256") == 0)
		ଫେରନ୍ତୁ SSH_DIGEST_SHA256;
	ଯଦି (strcmp(ident, "rsa-sha2-512") == 0)
		ଫେରନ୍ତୁ SSH_DIGEST_SHA512;
	ଫେରନ୍ତୁ -1;
}

/*
 * Return the hash algorithm ID for the specified key name. This includes
 * all the cases of rsa_hash_id_from_ident() but also the certificate key
 * types.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_rsa_hash_id_from_keyname(ଅଚଳ ଅକ୍ଷର *alg)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((r = rsa_hash_id_from_ident(alg)) != -1)
		ଫେରନ୍ତୁ r;
	ଯଦି (strcmp(alg, "ssh-rsa-cert-v01@openssh.com") == 0)
		ଫେରନ୍ତୁ SSH_DIGEST_SHA1;
	ଯଦି (strcmp(alg, "rsa-sha2-256-cert-v01@openssh.com") == 0)
		ଫେରନ୍ତୁ SSH_DIGEST_SHA256;
	ଯଦି (strcmp(alg, "rsa-sha2-512-cert-v01@openssh.com") == 0)
		ଫେରନ୍ତୁ SSH_DIGEST_SHA512;
	ଫେରନ୍ତୁ -1;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_rsa_complete_crt_parameters(ଅଚଳ BIGNUM *rsa_d, ଅଚଳ BIGNUM *rsa_p,
    ଅଚଳ BIGNUM *rsa_q, ଅଚଳ BIGNUM *rsa_iqmp, BIGNUM **rsa_dmp1,
    BIGNUM **rsa_dmq1)
{
	BIGNUM *aux = ଖାଲି, *d_consttime = ଖାଲି;
	BN_CTX *ctx = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	*rsa_dmq1 = *rsa_dmp1 = ଖାଲି;
	ଯଦି ((ctx = BN_CTX_new()) == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_ALLOC_FAIL;
	ଯଦି ((aux = BN_new()) == ଖାଲି ||
	    (*rsa_dmq1 = BN_new()) == ଖାଲି ||
	    (*rsa_dmp1 = BN_new()) == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_ALLOC_FAIL;
	ଯଦି ((d_consttime = BN_dup(rsa_d)) == ଖାଲି) {
		r = SSH_ERR_ALLOC_FAIL;
		ଯାଅ out;
	}
	BN_set_flags(aux, BN_FLG_CONSTTIME);
	BN_set_flags(d_consttime, BN_FLG_CONSTTIME);

	ଯଦି ((BN_sub(aux, rsa_q, BN_ମୂଲ୍ୟ_one()) == 0) ||
	    (BN_mod(*rsa_dmq1, d_consttime, aux, ctx) == 0) ||
	    (BN_sub(aux, rsa_p, BN_ମୂଲ୍ୟ_one()) == 0) ||
	    (BN_mod(*rsa_dmp1, d_consttime, aux, ctx) == 0)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		ଯାଅ out;
	}
	/* success */
	r = 0;
 out:
	BN_clear_free(aux);
	BN_clear_free(d_consttime);
	BN_CTX_free(ctx);
	ଫେରନ୍ତୁ r;
}

/* RSASSA-PKCS1-v1_5 (PKCS #1 v2.0 signature) with SHA1 */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_rsa_sign(ସଂରଚନା sshkey *ଚାବି,
    u_char **sigp, size_t *lenp,
    ଅଚଳ u_char *data, size_t datalen,
    ଅଚଳ ଅକ୍ଷର *alg, ଅଚଳ ଅକ୍ଷର *sk_provider, ଅଚଳ ଅକ୍ଷର *sk_pin, u_int compat)
{
	u_char *sig = ଖାଲି;
	size_t diff, len = 0;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା slen = 0;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା hash_alg, ret = SSH_ERR_INTERNAL_ERROR;

	ଯଦି (lenp != ଖାଲି)
		*lenp = 0;
	ଯଦି (sigp != ଖାଲି)
		*sigp = ଖାଲି;

	ଯଦି (alg == ଖାଲି || strlen(alg) == 0)
		hash_alg = SSH_DIGEST_SHA1;
	ଅନ୍ୟଥା
		hash_alg = ssh_rsa_hash_id_from_keyname(alg);

	ଯଦି (ଚାବି == ଖାଲି || ଚାବି->pkey == ଖାଲି || hash_alg == -1 ||
	    sshkey_type_plain(ଚାବି->type) != ଚାବି_RSA)
		ଫେରନ୍ତୁ SSH_ERR_INVALID_ARGUMENT;
	slen = EVP_PKEY_size(ଚାବି->pkey);
	ଯଦି (slen <= 0 || slen > SSHBUF_MAX_BIGNUM)
		ଫେରନ୍ତୁ SSH_ERR_INVALID_ARGUMENT;
	ଯଦି (EVP_PKEY_bits(ଚାବି->pkey) < SSH_RSA_MINIMUM_MODULUS_SIZE)
		ଫେରନ୍ତୁ SSH_ERR_ଚାବି_LENGTH;

	ଯଦି ((ret = sshkey_pkey_digest_sign(ଚାବି->pkey, hash_alg, &sig, &len,
	    data, datalen)) < 0)
		ଯାଅ out;
	ଯଦି (len < (size_t)slen) {
		diff = slen - len;
		memmove(sig + diff, sig, len);
		explicit_bzero(sig, diff);
	} ଅନ୍ୟଥା ଯଦି (len > (size_t)slen) {
		ret = SSH_ERR_INTERNAL_ERROR;
		ଯାଅ out;
	}
	ଯଦି ((ret = ssh_rsa_encode_store_sig(hash_alg, sig, slen,
	    sigp, lenp)) != 0)
		ଯାଅ out;

	/* success */
	ret = 0;
 out:
	freezero(sig, slen);
	ଫେରନ୍ତୁ ret;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_rsa_encode_store_sig(ପୂର୍ଣ୍ଣସଂଖ୍ୟା hash_alg, ଅଚଳ u_char *sig, size_t slen,
    u_char **sigp, size_t *lenp)
{
	ସଂରଚନା sshbuf *b = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ret = SSH_ERR_INTERNAL_ERROR;
	size_t len;

	ଯଦି (lenp != ଖାଲି)
		*lenp = 0;
	ଯଦି (sigp != ଖାଲି)
		*sigp = ଖାଲି;

	/* Encode signature */
	ଯଦି ((b = sshbuf_new()) == ଖାଲି) {
		ret = SSH_ERR_ALLOC_FAIL;
		ଯାଅ out;
	}
	ଯଦି ((ret = sshbuf_put_cstring(b,
	    ssh_rsa_hash_alg_ident(hash_alg))) != 0 ||
	    (ret = sshbuf_put_string(b, sig, slen)) != 0)
		ଯାଅ out;
	len = sshbuf_len(b);

	/* Store signature */
	ଯଦି (sigp != ଖାଲି) {
		ଯଦି ((*sigp = malloc(len)) == ଖାଲି) {
			ret = SSH_ERR_ALLOC_FAIL;
			ଯାଅ out;
		}
		memcpy(*sigp, sshbuf_ptr(b), len);
	}
	ଯଦି (lenp != ଖାଲି)
		*lenp = len;
	ret = 0;
 out:
	sshbuf_free(b);
	ଫେରନ୍ତୁ ret;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_rsa_verify(ଅଚଳ ସଂରଚନା sshkey *ଚାବି,
    ଅଚଳ u_char *sig, size_t siglen,
    ଅଚଳ u_char *data, size_t dlen, ଅଚଳ ଅକ୍ଷର *alg, u_int compat,
    ସଂରଚନା sshkey_sig_details **detailsp)
{
	ଅକ୍ଷର *sigtype = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା hash_alg, want_alg, ret = SSH_ERR_INTERNAL_ERROR;
	size_t len = 0, diff, modlen, rsasize;
	ସଂରଚନା sshbuf *b = ଖାଲି;
	u_char digest[SSH_DIGEST_MAX_LENGTH], *osigblob, *sigblob = ଖାଲି;

	ଯଦି (ଚାବି == ଖାଲି || ଚାବି->pkey == ଖାଲି ||
	    sshkey_type_plain(ଚାବି->type) != ଚାବି_RSA ||
	    sig == ଖାଲି || siglen == 0)
		ଫେରନ୍ତୁ SSH_ERR_INVALID_ARGUMENT;
	ଯଦି (EVP_PKEY_bits(ଚାବି->pkey) < SSH_RSA_MINIMUM_MODULUS_SIZE)
		ଫେରନ୍ତୁ SSH_ERR_ଚାବି_LENGTH;

	ଯଦି ((b = sshbuf_from(sig, siglen)) == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_ALLOC_FAIL;
	ଯଦି (sshbuf_get_cstring(b, &sigtype, ଖାଲି) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		ଯାଅ out;
	}
	ଯଦି ((hash_alg = rsa_hash_id_from_ident(sigtype)) == -1) {
		ret = SSH_ERR_ଚାବି_TYPE_MISMATCH;
		ଯାଅ out;
	}
	/*
	 * Allow ssh-rsa-cert-v01 certs to generate SHA2 signatures for
	 * legacy reasons, but otherwise the signature type should match.
	 */
	ଯଦି (alg != ଖାଲି && strcmp(alg, "ssh-rsa-cert-v01@openssh.com") != 0) {
		ଯଦି ((want_alg = ssh_rsa_hash_id_from_keyname(alg)) == -1) {
			ret = SSH_ERR_INVALID_ARGUMENT;
			ଯାଅ out;
		}
		ଯଦି (hash_alg != want_alg) {
			ret = SSH_ERR_SIGNATURE_INVALID;
			ଯାଅ out;
		}
	}
	ଯଦି (sshbuf_get_string(b, &sigblob, &len) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		ଯାଅ out;
	}
	ଯଦି (sshbuf_len(b) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		ଯାଅ out;
	}
	/* RSA_verify expects a signature of RSA_size */
	modlen = EVP_PKEY_size(ଚାବି->pkey);
	ଯଦି (len > modlen) {
		ret = SSH_ERR_ଚାବି_BITS_MISMATCH;
		ଯାଅ out;
	} ଅନ୍ୟଥା ଯଦି (len < modlen) {
		diff = modlen - len;
		osigblob = sigblob;
		ଯଦି ((sigblob = realloc(sigblob, modlen)) == ଖାଲି) {
			sigblob = osigblob; /* put it back for clear/free */
			ret = SSH_ERR_ALLOC_FAIL;
			ଯାଅ out;
		}
		memmove(sigblob + diff, sigblob, len);
		explicit_bzero(sigblob, diff);
		len = modlen;
	}

	rsasize = EVP_PKEY_size(ଚାବି->pkey);
	ଯଦି (rsasize <= 0 || rsasize > SSHBUF_MAX_BIGNUM ||
	    len == 0 || len > rsasize) {
		ret = SSH_ERR_INVALID_ARGUMENT;
		ଯାଅ out;
	}
	ret = sshkey_pkey_digest_verify(ଚାବି->pkey, hash_alg, data, dlen,
	    sigblob, len);

 out:
	freezero(sigblob, len);
	ମୁକ୍ତ(sigtype);
	sshbuf_free(b);
	explicit_bzero(digest, ଆକାର(digest));
	ଫେରନ୍ତୁ ret;
}

ସ୍ଥିର ଅଚଳ ସଂରଚନା sshkey_impl_funcs sshkey_rsa_funcs = {
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

ଅଚଳ ସଂରଚନା sshkey_impl sshkey_rsa_impl = {
	/* .name = */		"ssh-rsa",
	/* .shortname = */	"RSA",
	/* .sigalg = */		ଖାଲି,
	/* .type = */		ଚାବି_RSA,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};

ଅଚଳ ସଂରଚନା sshkey_impl sshkey_rsa_cert_impl = {
	/* .name = */		"ssh-rsa-cert-v01@openssh.com",
	/* .shortname = */	"RSA-CERT",
	/* .sigalg = */		ଖାଲି,
	/* .type = */		ଚାବି_RSA_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};

/* SHA2 signature algorithms */

ଅଚଳ ସଂରଚନା sshkey_impl sshkey_rsa_sha256_impl = {
	/* .name = */		"rsa-sha2-256",
	/* .shortname = */	"RSA",
	/* .sigalg = */		ଖାଲି,
	/* .type = */		ଚାବି_RSA,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	1,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};

ଅଚଳ ସଂରଚନା sshkey_impl sshkey_rsa_sha512_impl = {
	/* .name = */		"rsa-sha2-512",
	/* .shortname = */	"RSA",
	/* .sigalg = */		ଖାଲି,
	/* .type = */		ଚାବି_RSA,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	1,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};

ଅଚଳ ସଂରଚନା sshkey_impl sshkey_rsa_sha256_cert_impl = {
	/* .name = */		"rsa-sha2-256-cert-v01@openssh.com",
	/* .shortname = */	"RSA-CERT",
	/* .sigalg = */		"rsa-sha2-256",
	/* .type = */		ଚାବି_RSA_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	1,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};

ଅଚଳ ସଂରଚନା sshkey_impl sshkey_rsa_sha512_cert_impl = {
	/* .name = */		"rsa-sha2-512-cert-v01@openssh.com",
	/* .shortname = */	"RSA-CERT",
	/* .sigalg = */		"rsa-sha2-512",
	/* .type = */		ଚାବି_RSA_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	1,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};
#endif /* WITH_OPENSSL */
