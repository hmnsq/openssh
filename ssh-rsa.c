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

#ifdef WITH_OPENSSL
#अन्तर्भाव "openbsd-compat/openssl-compat.h"

#अन्तर्भाव <sys/types.h>

#अन्तर्भाव <openssl/bn.h>
#अन्तर्भाव <openssl/evp.h>

#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <string.h>

#अन्तर्भाव "sshbuf.h"
#अन्तर्भाव "ssherr.h"
#define SSHKEY_INTERNAL
#अन्तर्भाव "sshkey.h"
#अन्तर्भाव "digest.h"

स्थिर u_int
ssh_rsa_size(ध्रुव संरचना sshkey *k)
{
	सचे (k->pkey == रिक्त)
		पटिनिवत्त 0;
	पटिनिवत्त EVP_PKEY_bits(k->pkey);
}

स्थिर पूर्णाङ्क
ssh_rsa_alloc(संरचना sshkey *k)
{
	सचे ((k->pkey = EVP_PKEY_new()) == रिक्त)
		पटिनिवत्त SSH_ERR_ALLOC_FAIL;
	पटिनिवत्त 0;
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
	सचे (a->pkey == रिक्त || b->pkey == रिक्त)
		पटिनिवत्त 0;
	पटिनिवत्त EVP_PKEY_cmp(a->pkey, b->pkey) == 1;
}

स्थिर पूर्णाङ्क
ssh_rsa_serialize_public(ध्रुव संरचना sshkey *कुञ्चिका, संरचना sshbuf *b,
    गणना sshkey_serialize_rep opts)
{
	पूर्णाङ्क r;
	ध्रुव BIGNUM *rsa_n, *rsa_e;
	ध्रुव RSA *rsa;

	सचे (कुञ्चिका->pkey == रिक्त)
		पटिनिवत्त SSH_ERR_INVALID_ARGUMENT;
	सचे ((rsa = EVP_PKEY_get0_RSA(कुञ्चिका->pkey)) == रिक्त)
		पटिनिवत्त SSH_ERR_LIBCRYPTO_ERROR;

	RSA_get0_कुञ्चिका(rsa, &rsa_n, &rsa_e, रिक्त);
	सचे ((r = sshbuf_put_bignum2(b, rsa_e)) != 0 ||
	    (r = sshbuf_put_bignum2(b, rsa_n)) != 0)
		पटिनिवत्त r;

	पटिनिवत्त 0;
}

स्थिर पूर्णाङ्क
ssh_rsa_serialize_private(ध्रुव संरचना sshkey *कुञ्चिका, संरचना sshbuf *b,
    गणना sshkey_serialize_rep opts)
{
	पूर्णाङ्क r;
	ध्रुव BIGNUM *rsa_n, *rsa_e, *rsa_d, *rsa_iqmp, *rsa_p, *rsa_q;
	ध्रुव RSA *rsa;

	सचे ((rsa = EVP_PKEY_get0_RSA(कुञ्चिका->pkey)) == रिक्त)
		पटिनिवत्त SSH_ERR_LIBCRYPTO_ERROR;
	RSA_get0_कुञ्चिका(rsa, &rsa_n, &rsa_e, &rsa_d);
	RSA_get0_factors(rsa, &rsa_p, &rsa_q);
	RSA_get0_crt_params(rsa, रिक्त, रिक्त, &rsa_iqmp);

	सचे (!sshkey_is_cert(कुञ्चिका)) {
		/* Note: can't reuse ssh_rsa_serialize_public: e, n vs. n, e */
		सचे ((r = sshbuf_put_bignum2(b, rsa_n)) != 0 ||
		    (r = sshbuf_put_bignum2(b, rsa_e)) != 0)
			पटिनिवत्त r;
	}
	सचे ((r = sshbuf_put_bignum2(b, rsa_d)) != 0 ||
	    (r = sshbuf_put_bignum2(b, rsa_iqmp)) != 0 ||
	    (r = sshbuf_put_bignum2(b, rsa_p)) != 0 ||
	    (r = sshbuf_put_bignum2(b, rsa_q)) != 0)
		पटिनिवत्त r;

	पटिनिवत्त 0;
}

स्थिर पूर्णाङ्क
ssh_rsa_generate(संरचना sshkey *k, पूर्णाङ्क bits)
{
	EVP_PKEY_CTX *ctx = रिक्त;
	EVP_PKEY *res = रिक्त;

	पूर्णाङ्क ret = SSH_ERR_INTERNAL_ERROR;

	सचे (bits < SSH_RSA_MINIMUM_MODULUS_SIZE ||
	    bits > SSHBUF_MAX_BIGNUM * 8)
		पटिनिवत्त SSH_ERR_कुञ्चिका_LENGTH;

	सचे ((ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, रिक्त)) == रिक्त) {
		ret = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	सचे (EVP_PKEY_keygen_init(ctx) <= 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		गच्छ out;
	}
	सचे (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0) {
		ret = SSH_ERR_कुञ्चिका_LENGTH;
		गच्छ out;
	}
	सचे (EVP_PKEY_keygen(ctx, &res) <= 0 || res == रिक्त) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		गच्छ out;
	}
	/* success */
	k->pkey = res;
	ret = 0;
 out:
	EVP_PKEY_CTX_free(ctx);
	पटिनिवत्त ret;
}

स्थिर पूर्णाङ्क
ssh_rsa_copy_public(ध्रुव संरचना sshkey *from, संरचना sshkey *to)
{
	ध्रुव BIGNUM *rsa_n, *rsa_e;
	BIGNUM *rsa_n_dup = रिक्त, *rsa_e_dup = रिक्त;
	पूर्णाङ्क r = SSH_ERR_INTERNAL_ERROR;
	ध्रुव RSA *rsa_from;
	RSA *rsa_to = रिक्त;

	सचे ((rsa_from = EVP_PKEY_get0_RSA(from->pkey)) == रिक्त ||
	    (rsa_to = RSA_new()) == रिक्त)
		पटिनिवत्त SSH_ERR_LIBCRYPTO_ERROR;

	RSA_get0_कुञ्चिका(rsa_from, &rsa_n, &rsa_e, रिक्त);
	सचे ((rsa_n_dup = BN_dup(rsa_n)) == रिक्त ||
	    (rsa_e_dup = BN_dup(rsa_e)) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	सचे (!RSA_set0_कुञ्चिका(rsa_to, rsa_n_dup, rsa_e_dup, रिक्त)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		गच्छ out;
	}
	rsa_n_dup = rsa_e_dup = रिक्त; /* transferred */

	सचे (EVP_PKEY_set1_RSA(to->pkey, rsa_to) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		गच्छ out;
	}
	/* success */
	r = 0;
 out:
	RSA_free(rsa_to);
	BN_clear_free(rsa_n_dup);
	BN_clear_free(rsa_e_dup);
	पटिनिवत्त r;
}

स्थिर पूर्णाङ्क
ssh_rsa_deserialize_public(ध्रुव वर्ण *ktype, संरचना sshbuf *b,
    संरचना sshkey *कुञ्चिका)
{
	पूर्णाङ्क ret = SSH_ERR_INTERNAL_ERROR;
	BIGNUM *rsa_n = रिक्त, *rsa_e = रिक्त;
	RSA *rsa = रिक्त;

	सचे ((rsa = RSA_new()) == रिक्त)
		पटिनिवत्त SSH_ERR_LIBCRYPTO_ERROR;

	सचे (sshbuf_get_bignum2(b, &rsa_e) != 0 ||
	    sshbuf_get_bignum2(b, &rsa_n) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		गच्छ out;
	}
	सचे (!RSA_set0_कुञ्चिका(rsa, rsa_n, rsa_e, रिक्त)) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		गच्छ out;
	}
	rsa_n = rsa_e = रिक्त; /* transferred */
	सचे (EVP_PKEY_set1_RSA(कुञ्चिका->pkey, rsa) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		गच्छ out;
	}
	सचे ((ret = sshkey_check_rsa_length(कुञ्चिका, 0)) != 0)
		गच्छ out;
#ifdef DEBUG_PK
	RSA_print_fp(stderr, rsa, 8);
#endif
	/* success */
	ret = 0;
 out:
	RSA_free(rsa);
	BN_clear_free(rsa_n);
	BN_clear_free(rsa_e);
	पटिनिवत्त ret;
}

स्थिर पूर्णाङ्क
ssh_rsa_deserialize_private(ध्रुव वर्ण *ktype, संरचना sshbuf *b,
    संरचना sshkey *कुञ्चिका)
{
	पूर्णाङ्क r;
	BIGNUM *rsa_n = रिक्त, *rsa_e = रिक्त, *rsa_d = रिक्त;
	BIGNUM *rsa_iqmp = रिक्त, *rsa_p = रिक्त, *rsa_q = रिक्त;
	BIGNUM *rsa_dmp1 = रिक्त, *rsa_dmq1 = रिक्त;
	RSA *rsa = रिक्त;

	सचे (sshkey_is_cert(कुञ्चिका)) {
		/* sshkey_private_deserialize already has pubkey from cert */
		सचे ((rsa = EVP_PKEY_get1_RSA(कुञ्चिका->pkey)) == रिक्त) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			गच्छ out;
		}
	} अञ्ञथा {
		सचे ((rsa = RSA_new()) == रिक्त) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			गच्छ out;
		}
		/* Note: can't reuse ssh_rsa_deserialize_public: e,n vs. n,e */
		सचे ((r = sshbuf_get_bignum2(b, &rsa_n)) != 0 ||
		    (r = sshbuf_get_bignum2(b, &rsa_e)) != 0)
			गच्छ out;
		सचे (!RSA_set0_कुञ्चिका(rsa, rsa_n, rsa_e, रिक्त)) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			गच्छ out;
		}
		rsa_n = rsa_e = रिक्त; /* transferred */
	}
	सचे ((r = sshbuf_get_bignum2(b, &rsa_d)) != 0 ||
	    (r = sshbuf_get_bignum2(b, &rsa_iqmp)) != 0 ||
	    (r = sshbuf_get_bignum2(b, &rsa_p)) != 0 ||
	    (r = sshbuf_get_bignum2(b, &rsa_q)) != 0)
		गच्छ out;
	सचे ((r = ssh_rsa_complete_crt_parameters(rsa_d, rsa_p, rsa_q,
	    rsa_iqmp, &rsa_dmp1, &rsa_dmq1)) != 0)
		गच्छ out;
	सचे (!RSA_set0_कुञ्चिका(rsa, रिक्त, रिक्त, rsa_d)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		गच्छ out;
	}
	rsa_d = रिक्त; /* transferred */
	सचे (!RSA_set0_factors(rsa, rsa_p, rsa_q)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		गच्छ out;
	}
	rsa_p = rsa_q = रिक्त; /* transferred */
	सचे (!RSA_set0_crt_params(rsa, rsa_dmp1, rsa_dmq1, rsa_iqmp)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		गच्छ out;
	}
	rsa_dmp1 = rsa_dmq1 = rsa_iqmp = रिक्त;
	सचे (RSA_blinding_on(rsa, रिक्त) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		गच्छ out;
	}
	सचे (EVP_PKEY_set1_RSA(कुञ्चिका->pkey, rsa) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		गच्छ out;
	}
	सचे ((r = sshkey_check_rsa_length(कुञ्चिका, 0)) != 0)
		गच्छ out;
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
	पटिनिवत्त r;
}

ध्रुव वर्ण *
ssh_rsa_hash_alg_ident(पूर्णाङ्क hash_alg)
{
	विकल्प (hash_alg) {
	पक्ष SSH_DIGEST_SHA1:
		पटिनिवत्त "ssh-rsa";
	पक्ष SSH_DIGEST_SHA256:
		पटिनिवत्त "rsa-sha2-256";
	पक्ष SSH_DIGEST_SHA512:
		पटिनिवत्त "rsa-sha2-512";
	}
	पटिनिवत्त रिक्त;
}

/*
 * Returns the hash algorithm ID for a given algorithm identifier as used
 * inside the signature blob,
 */
स्थिर पूर्णाङ्क
rsa_hash_id_from_ident(ध्रुव वर्ण *ident)
{
	सचे (strcmp(ident, "ssh-rsa") == 0)
		पटिनिवत्त SSH_DIGEST_SHA1;
	सचे (strcmp(ident, "rsa-sha2-256") == 0)
		पटिनिवत्त SSH_DIGEST_SHA256;
	सचे (strcmp(ident, "rsa-sha2-512") == 0)
		पटिनिवत्त SSH_DIGEST_SHA512;
	पटिनिवत्त -1;
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

	सचे ((r = rsa_hash_id_from_ident(alg)) != -1)
		पटिनिवत्त r;
	सचे (strcmp(alg, "ssh-rsa-cert-v01@openssh.com") == 0)
		पटिनिवत्त SSH_DIGEST_SHA1;
	सचे (strcmp(alg, "rsa-sha2-256-cert-v01@openssh.com") == 0)
		पटिनिवत्त SSH_DIGEST_SHA256;
	सचे (strcmp(alg, "rsa-sha2-512-cert-v01@openssh.com") == 0)
		पटिनिवत्त SSH_DIGEST_SHA512;
	पटिनिवत्त -1;
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
	सचे ((ctx = BN_CTX_new()) == रिक्त)
		पटिनिवत्त SSH_ERR_ALLOC_FAIL;
	सचे ((aux = BN_new()) == रिक्त ||
	    (*rsa_dmq1 = BN_new()) == रिक्त ||
	    (*rsa_dmp1 = BN_new()) == रिक्त)
		पटिनिवत्त SSH_ERR_ALLOC_FAIL;
	सचे ((d_consttime = BN_dup(rsa_d)) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	BN_set_flags(aux, BN_FLG_CONSTTIME);
	BN_set_flags(d_consttime, BN_FLG_CONSTTIME);

	सचे ((BN_sub(aux, rsa_q, BN_मानम्_one()) == 0) ||
	    (BN_mod(*rsa_dmq1, d_consttime, aux, ctx) == 0) ||
	    (BN_sub(aux, rsa_p, BN_मानम्_one()) == 0) ||
	    (BN_mod(*rsa_dmp1, d_consttime, aux, ctx) == 0)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		गच्छ out;
	}
	/* success */
	r = 0;
 out:
	BN_clear_free(aux);
	BN_clear_free(d_consttime);
	BN_CTX_free(ctx);
	पटिनिवत्त r;
}

/* RSASSA-PKCS1-v1_5 (PKCS #1 v2.0 signature) with SHA1 */
स्थिर पूर्णाङ्क
ssh_rsa_sign(संरचना sshkey *कुञ्चिका,
    u_char **sigp, size_t *lenp,
    ध्रुव u_char *data, size_t datalen,
    ध्रुव वर्ण *alg, ध्रुव वर्ण *sk_provider, ध्रुव वर्ण *sk_pin, u_int compat)
{
	u_char *sig = रिक्त;
	size_t diff, len = 0;
	पूर्णाङ्क slen = 0;
	पूर्णाङ्क hash_alg, ret = SSH_ERR_INTERNAL_ERROR;

	सचे (lenp != रिक्त)
		*lenp = 0;
	सचे (sigp != रिक्त)
		*sigp = रिक्त;

	सचे (alg == रिक्त || strlen(alg) == 0)
		hash_alg = SSH_DIGEST_SHA1;
	अञ्ञथा
		hash_alg = ssh_rsa_hash_id_from_keyname(alg);

	सचे (कुञ्चिका == रिक्त || कुञ्चिका->pkey == रिक्त || hash_alg == -1 ||
	    sshkey_type_plain(कुञ्चिका->type) != कुञ्चिका_RSA)
		पटिनिवत्त SSH_ERR_INVALID_ARGUMENT;
	slen = EVP_PKEY_size(कुञ्चिका->pkey);
	सचे (slen <= 0 || slen > SSHBUF_MAX_BIGNUM)
		पटिनिवत्त SSH_ERR_INVALID_ARGUMENT;
	सचे (EVP_PKEY_bits(कुञ्चिका->pkey) < SSH_RSA_MINIMUM_MODULUS_SIZE)
		पटिनिवत्त SSH_ERR_कुञ्चिका_LENGTH;

	सचे ((ret = sshkey_pkey_digest_sign(कुञ्चिका->pkey, hash_alg, &sig, &len,
	    data, datalen)) < 0)
		गच्छ out;
	सचे (len < (size_t)slen) {
		diff = slen - len;
		memmove(sig + diff, sig, len);
		explicit_bzero(sig, diff);
	} अञ्ञथा सचे (len > (size_t)slen) {
		ret = SSH_ERR_INTERNAL_ERROR;
		गच्छ out;
	}
	सचे ((ret = ssh_rsa_encode_store_sig(hash_alg, sig, slen,
	    sigp, lenp)) != 0)
		गच्छ out;

	/* success */
	ret = 0;
 out:
	freezero(sig, slen);
	पटिनिवत्त ret;
}

पूर्णाङ्क
ssh_rsa_encode_store_sig(पूर्णाङ्क hash_alg, ध्रुव u_char *sig, size_t slen,
    u_char **sigp, size_t *lenp)
{
	संरचना sshbuf *b = रिक्त;
	पूर्णाङ्क ret = SSH_ERR_INTERNAL_ERROR;
	size_t len;

	सचे (lenp != रिक्त)
		*lenp = 0;
	सचे (sigp != रिक्त)
		*sigp = रिक्त;

	/* Encode signature */
	सचे ((b = sshbuf_new()) == रिक्त) {
		ret = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	सचे ((ret = sshbuf_put_cstring(b,
	    ssh_rsa_hash_alg_ident(hash_alg))) != 0 ||
	    (ret = sshbuf_put_string(b, sig, slen)) != 0)
		गच्छ out;
	len = sshbuf_len(b);

	/* Store signature */
	सचे (sigp != रिक्त) {
		सचे ((*sigp = malloc(len)) == रिक्त) {
			ret = SSH_ERR_ALLOC_FAIL;
			गच्छ out;
		}
		memcpy(*sigp, sshbuf_ptr(b), len);
	}
	सचे (lenp != रिक्त)
		*lenp = len;
	ret = 0;
 out:
	sshbuf_free(b);
	पटिनिवत्त ret;
}

स्थिर पूर्णाङ्क
ssh_rsa_verify(ध्रुव संरचना sshkey *कुञ्चिका,
    ध्रुव u_char *sig, size_t siglen,
    ध्रुव u_char *data, size_t dlen, ध्रुव वर्ण *alg, u_int compat,
    संरचना sshkey_sig_details **detailsp)
{
	वर्ण *sigtype = रिक्त;
	पूर्णाङ्क hash_alg, want_alg, ret = SSH_ERR_INTERNAL_ERROR;
	size_t len = 0, diff, modlen, rsasize;
	संरचना sshbuf *b = रिक्त;
	u_char digest[SSH_DIGEST_MAX_LENGTH], *osigblob, *sigblob = रिक्त;

	सचे (कुञ्चिका == रिक्त || कुञ्चिका->pkey == रिक्त ||
	    sshkey_type_plain(कुञ्चिका->type) != कुञ्चिका_RSA ||
	    sig == रिक्त || siglen == 0)
		पटिनिवत्त SSH_ERR_INVALID_ARGUMENT;
	सचे (EVP_PKEY_bits(कुञ्चिका->pkey) < SSH_RSA_MINIMUM_MODULUS_SIZE)
		पटिनिवत्त SSH_ERR_कुञ्चिका_LENGTH;

	सचे ((b = sshbuf_from(sig, siglen)) == रिक्त)
		पटिनिवत्त SSH_ERR_ALLOC_FAIL;
	सचे (sshbuf_get_cstring(b, &sigtype, रिक्त) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		गच्छ out;
	}
	सचे ((hash_alg = rsa_hash_id_from_ident(sigtype)) == -1) {
		ret = SSH_ERR_कुञ्चिका_TYPE_MISMATCH;
		गच्छ out;
	}
	/*
	 * Allow ssh-rsa-cert-v01 certs to generate SHA2 signatures for
	 * legacy reasons, but otherwise the signature type should match.
	 */
	सचे (alg != रिक्त && strcmp(alg, "ssh-rsa-cert-v01@openssh.com") != 0) {
		सचे ((want_alg = ssh_rsa_hash_id_from_keyname(alg)) == -1) {
			ret = SSH_ERR_INVALID_ARGUMENT;
			गच्छ out;
		}
		सचे (hash_alg != want_alg) {
			ret = SSH_ERR_SIGNATURE_INVALID;
			गच्छ out;
		}
	}
	सचे (sshbuf_get_string(b, &sigblob, &len) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		गच्छ out;
	}
	सचे (sshbuf_len(b) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		गच्छ out;
	}
	/* RSA_verify expects a signature of RSA_size */
	modlen = EVP_PKEY_size(कुञ्चिका->pkey);
	सचे (len > modlen) {
		ret = SSH_ERR_कुञ्चिका_BITS_MISMATCH;
		गच्छ out;
	} अञ्ञथा सचे (len < modlen) {
		diff = modlen - len;
		osigblob = sigblob;
		सचे ((sigblob = realloc(sigblob, modlen)) == रिक्त) {
			sigblob = osigblob; /* put it back for clear/free */
			ret = SSH_ERR_ALLOC_FAIL;
			गच्छ out;
		}
		memmove(sigblob + diff, sigblob, len);
		explicit_bzero(sigblob, diff);
		len = modlen;
	}

	rsasize = EVP_PKEY_size(कुञ्चिका->pkey);
	सचे (rsasize <= 0 || rsasize > SSHBUF_MAX_BIGNUM ||
	    len == 0 || len > rsasize) {
		ret = SSH_ERR_INVALID_ARGUMENT;
		गच्छ out;
	}
	ret = sshkey_pkey_digest_verify(कुञ्चिका->pkey, hash_alg, data, dlen,
	    sigblob, len);

 out:
	freezero(sigblob, len);
	मुक्त(sigtype);
	sshbuf_free(b);
	explicit_bzero(digest, परिमाण(digest));
	पटिनिवत्त ret;
}

स्थिर ध्रुव संरचना sshkey_impl_funcs sshkey_rsa_funcs = {
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
#endif /* WITH_OPENSSL */
