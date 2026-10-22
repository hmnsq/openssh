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

#अन्तर्भाव "includes.h"

#यदि_परिभाषितम् WITH_OPENSSL
#अन्तर्भाव "openbsd-compat/openssl-compat.h"

#अन्तर्भाव <sys/types.h>

#अन्तर्भाव <openssl/bn.h>
#अन्तर्भाव <openssl/evp.h>

#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <string.h>

#अन्तर्भाव "sshbuf.h"
#अन्तर्भाव "ssherr.h"
#परिभाषय SSHKEY_आन्तरिकम्
#अन्तर्भाव "sshkey.h"
#अन्तर्भाव "digest.h"

स्थिर u_int
ssh_rsa_आकार(ध्रुव संरचना sshkey *k)
{
	यदि (k->pkey == रिक्त)
		प्रत्यागम 0;
	प्रत्यागम EVP_PKEY_द्वयङ्काः(k->pkey);
}

स्थिर पूर्णाङ्क
ssh_rsa_alloc(संरचना sshkey *k)
{
	यदि ((k->pkey = EVP_PKEY_new()) == रिक्त)
		प्रत्यागम SSH_ERR_ALLOC_FAIL;
	प्रत्यागम 0;
}

स्थिर शून्य
ssh_rsa_cleanup(संरचना sshkey *k)
{
	EVP_PKEY_free(k->pkey);
	k->pkey = रिक्त;
}

स्थिर पूर्णाङ्क
ssh_rsa_equal(ध्रुव संरचना sshkey *a, ध्रुव संरचना sshkey *b)
{
	यदि (a->pkey == रिक्त || b->pkey == रिक्त)
		प्रत्यागम 0;
	प्रत्यागम EVP_PKEY_cmp(a->pkey, b->pkey) == 1;
}

स्थिर पूर्णाङ्क
ssh_rsa_serialize_लौकिकम्(ध्रुव संरचना sshkey *कुञ्चिका, संरचना sshbuf *b,
    गणना sshkey_serialize_rep opts)
{
	पूर्णाङ्क r;
	ध्रुव BIGNUM *rsa_n, *rsa_e;
	ध्रुव RSA *rsa;

	यदि (कुञ्चिका->pkey == रिक्त)
		प्रत्यागम SSH_ERR_INVALID_तर्कः;
	यदि ((rsa = EVP_PKEY_get0_RSA(कुञ्चिका->pkey)) == रिक्त)
		प्रत्यागम SSH_ERR_LIBCRYPTO_ERROR;

	RSA_get0_कुञ्चिका(rsa, &rsa_n, &rsa_e, रिक्त);
	यदि ((r = sshbuf_put_bignum2(b, rsa_e)) != 0 ||
	    (r = sshbuf_put_bignum2(b, rsa_n)) != 0)
		प्रत्यागम r;

	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
ssh_rsa_serialize_वैयक्तिकम्(ध्रुव संरचना sshkey *कुञ्चिका, संरचना sshbuf *b,
    गणना sshkey_serialize_rep opts)
{
	पूर्णाङ्क r;
	ध्रुव BIGNUM *rsa_n, *rsa_e, *rsa_d, *rsa_iqmp, *rsa_p, *rsa_q;
	ध्रुव RSA *rsa;

	यदि ((rsa = EVP_PKEY_get0_RSA(कुञ्चिका->pkey)) == रिक्त)
		प्रत्यागम SSH_ERR_LIBCRYPTO_ERROR;
	RSA_get0_कुञ्चिका(rsa, &rsa_n, &rsa_e, &rsa_d);
	RSA_get0_factors(rsa, &rsa_p, &rsa_q);
	RSA_get0_crt_params(rsa, रिक्त, रिक्त, &rsa_iqmp);

	यदि (!sshkey_is_cert(कुञ्चिका)) {
		/* Note: can't reuse ssh_rsa_serialize_public: e, n vs. n, e */
		यदि ((r = sshbuf_put_bignum2(b, rsa_n)) != 0 ||
		    (r = sshbuf_put_bignum2(b, rsa_e)) != 0)
			प्रत्यागम r;
	}
	यदि ((r = sshbuf_put_bignum2(b, rsa_d)) != 0 ||
	    (r = sshbuf_put_bignum2(b, rsa_iqmp)) != 0 ||
	    (r = sshbuf_put_bignum2(b, rsa_p)) != 0 ||
	    (r = sshbuf_put_bignum2(b, rsa_q)) != 0)
		प्रत्यागम r;

	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
ssh_rsa_generate(संरचना sshkey *k, पूर्णाङ्क द्वयङ्काः)
{
	EVP_PKEY_CTX *ctx = रिक्त;
	EVP_PKEY *res = रिक्त;

	पूर्णाङ्क ret = SSH_ERR_आन्तरिकम्_ERROR;

	यदि (द्वयङ्काः < SSH_RSA_MINIMUM_MODULUS_आकार ||
	    द्वयङ्काः > SSHBUF_MAX_BIGNUM * 8)
		प्रत्यागम SSH_ERR_कुञ्चिका_दीर्घता;

	यदि ((ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, रिक्त)) == रिक्त) {
		ret = SSH_ERR_ALLOC_FAIL;
		गच्छ बहिर्गमनम्;
	}
	यदि (EVP_PKEY_keygen_init(ctx) <= 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		गच्छ बहिर्गमनम्;
	}
	यदि (EVP_PKEY_CTX_समुच्चयः_rsa_keygen_द्वयङ्काः(ctx, द्वयङ्काः) <= 0) {
		ret = SSH_ERR_कुञ्चिका_दीर्घता;
		गच्छ बहिर्गमनम्;
	}
	यदि (EVP_PKEY_keygen(ctx, &res) <= 0 || res == रिक्त) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		गच्छ बहिर्गमनम्;
	}
	/* success */
	k->pkey = res;
	ret = 0;
 बहिर्गमनम्:
	EVP_PKEY_CTX_free(ctx);
	प्रत्यागम ret;
}

स्थिर पूर्णाङ्क
ssh_rsa_copy_लौकिकम्(ध्रुव संरचना sshkey *from, संरचना sshkey *गन्तव्यम्)
{
	ध्रुव BIGNUM *rsa_n, *rsa_e;
	BIGNUM *rsa_n_dup = रिक्त, *rsa_e_dup = रिक्त;
	पूर्णाङ्क r = SSH_ERR_आन्तरिकम्_ERROR;
	ध्रुव RSA *rsa_from;
	RSA *rsa_गन्तव्यम् = रिक्त;

	यदि ((rsa_from = EVP_PKEY_get0_RSA(from->pkey)) == रिक्त ||
	    (rsa_गन्तव्यम् = RSA_new()) == रिक्त)
		प्रत्यागम SSH_ERR_LIBCRYPTO_ERROR;

	RSA_get0_कुञ्चिका(rsa_from, &rsa_n, &rsa_e, रिक्त);
	यदि ((rsa_n_dup = BN_dup(rsa_n)) == रिक्त ||
	    (rsa_e_dup = BN_dup(rsa_e)) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ बहिर्गमनम्;
	}
	यदि (!RSA_set0_कुञ्चिका(rsa_गन्तव्यम्, rsa_n_dup, rsa_e_dup, रिक्त)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		गच्छ बहिर्गमनम्;
	}
	rsa_n_dup = rsa_e_dup = रिक्त; /* transferred */

	यदि (EVP_PKEY_set1_RSA(गन्तव्यम्->pkey, rsa_गन्तव्यम्) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		गच्छ बहिर्गमनम्;
	}
	/* success */
	r = 0;
 बहिर्गमनम्:
	RSA_free(rsa_गन्तव्यम्);
	BN_clear_free(rsa_n_dup);
	BN_clear_free(rsa_e_dup);
	प्रत्यागम r;
}

स्थिर पूर्णाङ्क
ssh_rsa_deserialize_लौकिकम्(ध्रुव वर्ण *ktype, संरचना sshbuf *b,
    संरचना sshkey *कुञ्चिका)
{
	पूर्णाङ्क ret = SSH_ERR_आन्तरिकम्_ERROR;
	BIGNUM *rsa_n = रिक्त, *rsa_e = रिक्त;
	RSA *rsa = रिक्त;

	यदि ((rsa = RSA_new()) == रिक्त)
		प्रत्यागम SSH_ERR_LIBCRYPTO_ERROR;

	यदि (sshbuf_get_bignum2(b, &rsa_e) != 0 ||
	    sshbuf_get_bignum2(b, &rsa_n) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		गच्छ बहिर्गमनम्;
	}
	यदि (!RSA_set0_कुञ्चिका(rsa, rsa_n, rsa_e, रिक्त)) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		गच्छ बहिर्गमनम्;
	}
	rsa_n = rsa_e = रिक्त; /* transferred */
	यदि (EVP_PKEY_set1_RSA(कुञ्चिका->pkey, rsa) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		गच्छ बहिर्गमनम्;
	}
	यदि ((ret = sshkey_check_rsa_दीर्घता(कुञ्चिका, 0)) != 0)
		गच्छ बहिर्गमनम्;
#यदि_परिभाषितम् DEBUG_PK
	RSA_print_fp(stderr, rsa, 8);
#यदि_अन्तः
	/* success */
	ret = 0;
 बहिर्गमनम्:
	RSA_free(rsa);
	BN_clear_free(rsa_n);
	BN_clear_free(rsa_e);
	प्रत्यागम ret;
}

स्थिर पूर्णाङ्क
ssh_rsa_deserialize_वैयक्तिकम्(ध्रुव वर्ण *ktype, संरचना sshbuf *b,
    संरचना sshkey *कुञ्चिका)
{
	पूर्णाङ्क r;
	BIGNUM *rsa_n = रिक्त, *rsa_e = रिक्त, *rsa_d = रिक्त;
	BIGNUM *rsa_iqmp = रिक्त, *rsa_p = रिक्त, *rsa_q = रिक्त;
	BIGNUM *rsa_dmp1 = रिक्त, *rsa_dmq1 = रिक्त;
	RSA *rsa = रिक्त;

	यदि (sshkey_is_cert(कुञ्चिका)) {
		/* sshkey_private_deserialize already has pubkey from cert */
		यदि ((rsa = EVP_PKEY_get1_RSA(कुञ्चिका->pkey)) == रिक्त) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			गच्छ बहिर्गमनम्;
		}
	} अन्यथा {
		यदि ((rsa = RSA_new()) == रिक्त) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			गच्छ बहिर्गमनम्;
		}
		/* Note: can't reuse ssh_rsa_deserialize_public: e,n vs. n,e */
		यदि ((r = sshbuf_get_bignum2(b, &rsa_n)) != 0 ||
		    (r = sshbuf_get_bignum2(b, &rsa_e)) != 0)
			गच्छ बहिर्गमनम्;
		यदि (!RSA_set0_कुञ्चिका(rsa, rsa_n, rsa_e, रिक्त)) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			गच्छ बहिर्गमनम्;
		}
		rsa_n = rsa_e = रिक्त; /* transferred */
	}
	यदि ((r = sshbuf_get_bignum2(b, &rsa_d)) != 0 ||
	    (r = sshbuf_get_bignum2(b, &rsa_iqmp)) != 0 ||
	    (r = sshbuf_get_bignum2(b, &rsa_p)) != 0 ||
	    (r = sshbuf_get_bignum2(b, &rsa_q)) != 0)
		गच्छ बहिर्गमनम्;
	यदि ((r = ssh_rsa_complete_crt_parameters(rsa_d, rsa_p, rsa_q,
	    rsa_iqmp, &rsa_dmp1, &rsa_dmq1)) != 0)
		गच्छ बहिर्गमनम्;
	यदि (!RSA_set0_कुञ्चिका(rsa, रिक्त, रिक्त, rsa_d)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		गच्छ बहिर्गमनम्;
	}
	rsa_d = रिक्त; /* transferred */
	यदि (!RSA_set0_factors(rsa, rsa_p, rsa_q)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		गच्छ बहिर्गमनम्;
	}
	rsa_p = rsa_q = रिक्त; /* transferred */
	यदि (!RSA_set0_crt_params(rsa, rsa_dmp1, rsa_dmq1, rsa_iqmp)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		गच्छ बहिर्गमनम्;
	}
	rsa_dmp1 = rsa_dmq1 = rsa_iqmp = रिक्त;
	यदि (RSA_blinding_on(rsa, रिक्त) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		गच्छ बहिर्गमनम्;
	}
	यदि (EVP_PKEY_set1_RSA(कुञ्चिका->pkey, rsa) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		गच्छ बहिर्गमनम्;
	}
	यदि ((r = sshkey_check_rsa_दीर्घता(कुञ्चिका, 0)) != 0)
		गच्छ बहिर्गमनम्;
	/* success */
	r = 0;
 बहिर्गमनम्:
	RSA_free(rsa);
	BN_clear_free(rsa_n);
	BN_clear_free(rsa_e);
	BN_clear_free(rsa_d);
	BN_clear_free(rsa_p);
	BN_clear_free(rsa_q);
	BN_clear_free(rsa_iqmp);
	BN_clear_free(rsa_dmp1);
	BN_clear_free(rsa_dmq1);
	प्रत्यागम r;
}

ध्रुव वर्ण *
ssh_rsa_hash_alg_ident(पूर्णाङ्क hash_alg)
{
	विकल्प (hash_alg) {
	पक्ष SSH_DIGEST_SHA1:
		प्रत्यागम "ssh-rsa";
	पक्ष SSH_DIGEST_SHA256:
		प्रत्यागम "rsa-sha2-256";
	पक्ष SSH_DIGEST_SHA512:
		प्रत्यागम "rsa-sha2-512";
	}
	प्रत्यागम रिक्त;
}

/*
 * Returns the hash algorithm ID for a given algorithm identifier as used
 * inside the signature blob,
 */
स्थिर पूर्णाङ्क
rsa_hash_id_from_ident(ध्रुव वर्ण *ident)
{
	यदि (वाक्यं_तुलय(ident, "ssh-rsa") == 0)
		प्रत्यागम SSH_DIGEST_SHA1;
	यदि (वाक्यं_तुलय(ident, "rsa-sha2-256") == 0)
		प्रत्यागम SSH_DIGEST_SHA256;
	यदि (वाक्यं_तुलय(ident, "rsa-sha2-512") == 0)
		प्रत्यागम SSH_DIGEST_SHA512;
	प्रत्यागम -1;
}

/*
 * Return the hash algorithm ID for the specified key name. This includes
 * all the cases of rsa_hash_id_from_ident() but also the certificate key
 * types.
 */
पूर्णाङ्क
ssh_rsa_hash_id_from_keyname(ध्रुव वर्ण *alg)
{
	पूर्णाङ्क r;

	यदि ((r = rsa_hash_id_from_ident(alg)) != -1)
		प्रत्यागम r;
	यदि (वाक्यं_तुलय(alg, "ssh-rsa-cert-v01@openssh.com") == 0)
		प्रत्यागम SSH_DIGEST_SHA1;
	यदि (वाक्यं_तुलय(alg, "rsa-sha2-256-cert-v01@openssh.com") == 0)
		प्रत्यागम SSH_DIGEST_SHA256;
	यदि (वाक्यं_तुलय(alg, "rsa-sha2-512-cert-v01@openssh.com") == 0)
		प्रत्यागम SSH_DIGEST_SHA512;
	प्रत्यागम -1;
}

पूर्णाङ्क
ssh_rsa_complete_crt_parameters(ध्रुव BIGNUM *rsa_d, ध्रुव BIGNUM *rsa_p,
    ध्रुव BIGNUM *rsa_q, ध्रुव BIGNUM *rsa_iqmp, BIGNUM **rsa_dmp1,
    BIGNUM **rsa_dmq1)
{
	BIGNUM *aux = रिक्त, *d_consttime = रिक्त;
	BN_CTX *ctx = रिक्त;
	पूर्णाङ्क r;

	*rsa_dmq1 = *rsa_dmp1 = रिक्त;
	यदि ((ctx = BN_CTX_new()) == रिक्त)
		प्रत्यागम SSH_ERR_ALLOC_FAIL;
	यदि ((aux = BN_new()) == रिक्त ||
	    (*rsa_dmq1 = BN_new()) == रिक्त ||
	    (*rsa_dmp1 = BN_new()) == रिक्त)
		प्रत्यागम SSH_ERR_ALLOC_FAIL;
	यदि ((d_consttime = BN_dup(rsa_d)) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ बहिर्गमनम्;
	}
	BN_समुच्चयः_flags(aux, BN_FLG_CONSTTIME);
	BN_समुच्चयः_flags(d_consttime, BN_FLG_CONSTTIME);

	यदि ((BN_sub(aux, rsa_q, BN_मानम्_one()) == 0) ||
	    (BN_mod(*rsa_dmq1, d_consttime, aux, ctx) == 0) ||
	    (BN_sub(aux, rsa_p, BN_मानम्_one()) == 0) ||
	    (BN_mod(*rsa_dmp1, d_consttime, aux, ctx) == 0)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		गच्छ बहिर्गमनम्;
	}
	/* success */
	r = 0;
 बहिर्गमनम्:
	BN_clear_free(aux);
	BN_clear_free(d_consttime);
	BN_CTX_free(ctx);
	प्रत्यागम r;
}

/* RSASSA-PKCS1-v1_5 (PKCS #1 v2.0 signature) with SHA1 */
स्थिर पूर्णाङ्क
ssh_rsa_sign(संरचना sshkey *कुञ्चिका,
    u_char **sigp, आकार_t *lenp,
    ध्रुव u_char *दत्त, आकार_t datalen,
    ध्रुव वर्ण *alg, ध्रुव वर्ण *sk_provider, ध्रुव वर्ण *sk_pin, u_int compat)
{
	u_char *sig = रिक्त;
	आकार_t diff, len = 0;
	पूर्णाङ्क slen = 0;
	पूर्णाङ्क hash_alg, ret = SSH_ERR_आन्तरिकम्_ERROR;

	यदि (lenp != रिक्त)
		*lenp = 0;
	यदि (sigp != रिक्त)
		*sigp = रिक्त;

	यदि (alg == रिक्त || वाक्यदैर्घ्यम्(alg) == 0)
		hash_alg = SSH_DIGEST_SHA1;
	अन्यथा
		hash_alg = ssh_rsa_hash_id_from_keyname(alg);

	यदि (कुञ्चिका == रिक्त || कुञ्चिका->pkey == रिक्त || hash_alg == -1 ||
	    sshkey_type_plain(कुञ्चिका->type) != कुञ्चिका_RSA)
		प्रत्यागम SSH_ERR_INVALID_तर्कः;
	slen = EVP_PKEY_आकार(कुञ्चिका->pkey);
	यदि (slen <= 0 || slen > SSHBUF_MAX_BIGNUM)
		प्रत्यागम SSH_ERR_INVALID_तर्कः;
	यदि (EVP_PKEY_द्वयङ्काः(कुञ्चिका->pkey) < SSH_RSA_MINIMUM_MODULUS_आकार)
		प्रत्यागम SSH_ERR_कुञ्चिका_दीर्घता;

	यदि ((ret = sshkey_pkey_digest_sign(कुञ्चिका->pkey, hash_alg, &sig, &len,
	    दत्त, datalen)) < 0)
		गच्छ बहिर्गमनम्;
	यदि (len < (आकार_t)slen) {
		diff = slen - len;
		memmove(sig + diff, sig, len);
		explicit_bzero(sig, diff);
	} अन्यथा यदि (len > (आकार_t)slen) {
		ret = SSH_ERR_आन्तरिकम्_ERROR;
		गच्छ बहिर्गमनम्;
	}
	यदि ((ret = ssh_rsa_encode_store_sig(hash_alg, sig, slen,
	    sigp, lenp)) != 0)
		गच्छ बहिर्गमनम्;

	/* success */
	ret = 0;
 बहिर्गमनम्:
	freezero(sig, slen);
	प्रत्यागम ret;
}

पूर्णाङ्क
ssh_rsa_encode_store_sig(पूर्णाङ्क hash_alg, ध्रुव u_char *sig, आकार_t slen,
    u_char **sigp, आकार_t *lenp)
{
	संरचना sshbuf *b = रिक्त;
	पूर्णाङ्क ret = SSH_ERR_आन्तरिकम्_ERROR;
	आकार_t len;

	यदि (lenp != रिक्त)
		*lenp = 0;
	यदि (sigp != रिक्त)
		*sigp = रिक्त;

	/* Encode signature */
	यदि ((b = sshbuf_new()) == रिक्त) {
		ret = SSH_ERR_ALLOC_FAIL;
		गच्छ बहिर्गमनम्;
	}
	यदि ((ret = sshbuf_put_cstring(b,
	    ssh_rsa_hash_alg_ident(hash_alg))) != 0 ||
	    (ret = sshbuf_put_string(b, sig, slen)) != 0)
		गच्छ बहिर्गमनम्;
	len = sshbuf_len(b);

	/* Store signature */
	यदि (sigp != रिक्त) {
		यदि ((*sigp = स्मृतिं_देहि(len)) == रिक्त) {
			ret = SSH_ERR_ALLOC_FAIL;
			गच्छ बहिर्गमनम्;
		}
		स्मृतिं_प्रतिलिख(*sigp, sshbuf_ptr(b), len);
	}
	यदि (lenp != रिक्त)
		*lenp = len;
	ret = 0;
 बहिर्गमनम्:
	sshbuf_free(b);
	प्रत्यागम ret;
}

स्थिर पूर्णाङ्क
ssh_rsa_verify(ध्रुव संरचना sshkey *कुञ्चिका,
    ध्रुव u_char *sig, आकार_t siglen,
    ध्रुव u_char *दत्त, आकार_t dlen, ध्रुव वर्ण *alg, u_int compat,
    संरचना sshkey_sig_details **detailsp)
{
	वर्ण *sigtype = रिक्त;
	पूर्णाङ्क hash_alg, want_alg, ret = SSH_ERR_आन्तरिकम्_ERROR;
	आकार_t len = 0, diff, modlen, rsasize;
	संरचना sshbuf *b = रिक्त;
	u_char digest[SSH_DIGEST_MAX_दीर्घता], *osigblob, *sigblob = रिक्त;

	यदि (कुञ्चिका == रिक्त || कुञ्चिका->pkey == रिक्त ||
	    sshkey_type_plain(कुञ्चिका->type) != कुञ्चिका_RSA ||
	    sig == रिक्त || siglen == 0)
		प्रत्यागम SSH_ERR_INVALID_तर्कः;
	यदि (EVP_PKEY_द्वयङ्काः(कुञ्चिका->pkey) < SSH_RSA_MINIMUM_MODULUS_आकार)
		प्रत्यागम SSH_ERR_कुञ्चिका_दीर्घता;

	यदि ((b = sshbuf_from(sig, siglen)) == रिक्त)
		प्रत्यागम SSH_ERR_ALLOC_FAIL;
	यदि (sshbuf_get_cstring(b, &sigtype, रिक्त) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		गच्छ बहिर्गमनम्;
	}
	यदि ((hash_alg = rsa_hash_id_from_ident(sigtype)) == -1) {
		ret = SSH_ERR_कुञ्चिका_TYPE_MISMATCH;
		गच्छ बहिर्गमनम्;
	}
	/*
	 * Allow ssh-rsa-cert-v01 certs to generate SHA2 signatures for
	 * legacy reasons, but otherwise the signature type should match.
	 */
	यदि (alg != रिक्त && वाक्यं_तुलय(alg, "ssh-rsa-cert-v01@openssh.com") != 0) {
		यदि ((want_alg = ssh_rsa_hash_id_from_keyname(alg)) == -1) {
			ret = SSH_ERR_INVALID_तर्कः;
			गच्छ बहिर्गमनम्;
		}
		यदि (hash_alg != want_alg) {
			ret = SSH_ERR_SIGNATURE_INVALID;
			गच्छ बहिर्गमनम्;
		}
	}
	यदि (sshbuf_get_string(b, &sigblob, &len) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		गच्छ बहिर्गमनम्;
	}
	यदि (sshbuf_len(b) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_दत्त;
		गच्छ बहिर्गमनम्;
	}
	/* RSA_verify expects a signature of RSA_size */
	modlen = EVP_PKEY_आकार(कुञ्चिका->pkey);
	यदि (len > modlen) {
		ret = SSH_ERR_कुञ्चिका_द्वयङ्काः_MISMATCH;
		गच्छ बहिर्गमनम्;
	} अन्यथा यदि (len < modlen) {
		diff = modlen - len;
		osigblob = sigblob;
		यदि ((sigblob = realloc(sigblob, modlen)) == रिक्त) {
			sigblob = osigblob; /* put it back for clear/free */
			ret = SSH_ERR_ALLOC_FAIL;
			गच्छ बहिर्गमनम्;
		}
		memmove(sigblob + diff, sigblob, len);
		explicit_bzero(sigblob, diff);
		len = modlen;
	}

	rsasize = EVP_PKEY_आकार(कुञ्चिका->pkey);
	यदि (rsasize <= 0 || rsasize > SSHBUF_MAX_BIGNUM ||
	    len == 0 || len > rsasize) {
		ret = SSH_ERR_INVALID_तर्कः;
		गच्छ बहिर्गमनम्;
	}
	ret = sshkey_pkey_digest_verify(कुञ्चिका->pkey, hash_alg, दत्त, dlen,
	    sigblob, len);

 बहिर्गमनम्:
	freezero(sigblob, len);
	मुक्त(sigtype);
	sshbuf_free(b);
	explicit_bzero(digest, परिमाण(digest));
	प्रत्यागम ret;
}

स्थिर ध्रुव संरचना sshkey_impl_funcs sshkey_rsa_funcs = {
	/* .size = */		ssh_rsa_आकार,
	/* .alloc = */		ssh_rsa_alloc,
	/* .cleanup = */	ssh_rsa_cleanup,
	/* .equal = */		ssh_rsa_equal,
	/* .ssh_serialize_public = */ ssh_rsa_serialize_लौकिकम्,
	/* .ssh_deserialize_public = */ ssh_rsa_deserialize_लौकिकम्,
	/* .ssh_serialize_private = */ ssh_rsa_serialize_वैयक्तिकम्,
	/* .ssh_deserialize_private = */ ssh_rsa_deserialize_वैयक्तिकम्,
	/* .generate = */	ssh_rsa_generate,
	/* .copy_public = */	ssh_rsa_copy_लौकिकम्,
	/* .sign = */		ssh_rsa_sign,
	/* .verify = */		ssh_rsa_verify,
};

ध्रुव संरचना sshkey_impl sshkey_rsa_impl = {
	/* .name = */		"ssh-rsa",
	/* .shortname = */	"RSA",
	/* .sigalg = */		रिक्त,
	/* .type = */		कुञ्चिका_RSA,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};

ध्रुव संरचना sshkey_impl sshkey_rsa_cert_impl = {
	/* .name = */		"ssh-rsa-cert-v01@openssh.com",
	/* .shortname = */	"RSA-CERT",
	/* .sigalg = */		रिक्त,
	/* .type = */		कुञ्चिका_RSA_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};

/* SHA2 signature algorithms */

ध्रुव संरचना sshkey_impl sshkey_rsa_sha256_impl = {
	/* .name = */		"rsa-sha2-256",
	/* .shortname = */	"RSA",
	/* .sigalg = */		रिक्त,
	/* .type = */		कुञ्चिका_RSA,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	1,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};

ध्रुव संरचना sshkey_impl sshkey_rsa_sha512_impl = {
	/* .name = */		"rsa-sha2-512",
	/* .shortname = */	"RSA",
	/* .sigalg = */		रिक्त,
	/* .type = */		कुञ्चिका_RSA,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	1,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};

ध्रुव संरचना sshkey_impl sshkey_rsa_sha256_cert_impl = {
	/* .name = */		"rsa-sha2-256-cert-v01@openssh.com",
	/* .shortname = */	"RSA-CERT",
	/* .sigalg = */		"rsa-sha2-256",
	/* .type = */		कुञ्चिका_RSA_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	1,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};

ध्रुव संरचना sshkey_impl sshkey_rsa_sha512_cert_impl = {
	/* .name = */		"rsa-sha2-512-cert-v01@openssh.com",
	/* .shortname = */	"RSA-CERT",
	/* .sigalg = */		"rsa-sha2-512",
	/* .type = */		कुञ्चिका_RSA_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	1,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};
#यदि_अन्तः /* WITH_OPENSSL */
