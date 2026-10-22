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
ssh_rsa_size(स्थिरांक संरचना sshkey *k)
{
	जर (k->pkey == रिक्त)
		परत 0;
	परत EVP_PKEY_bits(k->pkey);
}

स्थिर पूर्णांक
ssh_rsa_alloc(संरचना sshkey *k)
{
	जर ((k->pkey = EVP_PKEY_new()) == रिक्त)
		परत SSH_ERR_ALLOC_FAIL;
	परत 0;
}

स्थिर शून्य
ssh_rsa_cleanup(संरचना sshkey *k)
{
	EVP_PKEY_free(k->pkey);
	k->pkey = रिक्त;
}

स्थिर पूर्णांक
ssh_rsa_equal(स्थिरांक संरचना sshkey *a, स्थिरांक संरचना sshkey *b)
{
	जर (a->pkey == रिक्त || b->pkey == रिक्त)
		परत 0;
	परत EVP_PKEY_cmp(a->pkey, b->pkey) == 1;
}

स्थिर पूर्णांक
ssh_rsa_serialize_public(स्थिरांक संरचना sshkey *किल्ली, संरचना sshbuf *b,
    गणना sshkey_serialize_rep opts)
{
	पूर्णांक r;
	स्थिरांक BIGNUM *rsa_n, *rsa_e;
	स्थिरांक RSA *rsa;

	जर (किल्ली->pkey == रिक्त)
		परत SSH_ERR_INVALID_ARGUMENT;
	जर ((rsa = EVP_PKEY_get0_RSA(किल्ली->pkey)) == रिक्त)
		परत SSH_ERR_LIBCRYPTO_ERROR;

	RSA_get0_किल्ली(rsa, &rsa_n, &rsa_e, रिक्त);
	जर ((r = sshbuf_put_bignum2(b, rsa_e)) != 0 ||
	    (r = sshbuf_put_bignum2(b, rsa_n)) != 0)
		परत r;

	परत 0;
}

स्थिर पूर्णांक
ssh_rsa_serialize_private(स्थिरांक संरचना sshkey *किल्ली, संरचना sshbuf *b,
    गणना sshkey_serialize_rep opts)
{
	पूर्णांक r;
	स्थिरांक BIGNUM *rsa_n, *rsa_e, *rsa_d, *rsa_iqmp, *rsa_p, *rsa_q;
	स्थिरांक RSA *rsa;

	जर ((rsa = EVP_PKEY_get0_RSA(किल्ली->pkey)) == रिक्त)
		परत SSH_ERR_LIBCRYPTO_ERROR;
	RSA_get0_किल्ली(rsa, &rsa_n, &rsa_e, &rsa_d);
	RSA_get0_factors(rsa, &rsa_p, &rsa_q);
	RSA_get0_crt_params(rsa, रिक्त, रिक्त, &rsa_iqmp);

	जर (!sshkey_is_cert(किल्ली)) {
		/* Note: can't reuse ssh_rsa_serialize_public: e, n vs. n, e */
		जर ((r = sshbuf_put_bignum2(b, rsa_n)) != 0 ||
		    (r = sshbuf_put_bignum2(b, rsa_e)) != 0)
			परत r;
	}
	जर ((r = sshbuf_put_bignum2(b, rsa_d)) != 0 ||
	    (r = sshbuf_put_bignum2(b, rsa_iqmp)) != 0 ||
	    (r = sshbuf_put_bignum2(b, rsa_p)) != 0 ||
	    (r = sshbuf_put_bignum2(b, rsa_q)) != 0)
		परत r;

	परत 0;
}

स्थिर पूर्णांक
ssh_rsa_generate(संरचना sshkey *k, पूर्णांक bits)
{
	EVP_PKEY_CTX *ctx = रिक्त;
	EVP_PKEY *res = रिक्त;

	पूर्णांक ret = SSH_ERR_INTERNAL_ERROR;

	जर (bits < SSH_RSA_MINIMUM_MODULUS_SIZE ||
	    bits > SSHBUF_MAX_BIGNUM * 8)
		परत SSH_ERR_किल्ली_LENGTH;

	जर ((ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, रिक्त)) == रिक्त) {
		ret = SSH_ERR_ALLOC_FAIL;
		जा out;
	}
	जर (EVP_PKEY_keygen_init(ctx) <= 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		जा out;
	}
	जर (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0) {
		ret = SSH_ERR_किल्ली_LENGTH;
		जा out;
	}
	जर (EVP_PKEY_keygen(ctx, &res) <= 0 || res == रिक्त) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		जा out;
	}
	/* success */
	k->pkey = res;
	ret = 0;
 out:
	EVP_PKEY_CTX_free(ctx);
	परत ret;
}

स्थिर पूर्णांक
ssh_rsa_copy_public(स्थिरांक संरचना sshkey *from, संरचना sshkey *to)
{
	स्थिरांक BIGNUM *rsa_n, *rsa_e;
	BIGNUM *rsa_n_dup = रिक्त, *rsa_e_dup = रिक्त;
	पूर्णांक r = SSH_ERR_INTERNAL_ERROR;
	स्थिरांक RSA *rsa_from;
	RSA *rsa_to = रिक्त;

	जर ((rsa_from = EVP_PKEY_get0_RSA(from->pkey)) == रिक्त ||
	    (rsa_to = RSA_new()) == रिक्त)
		परत SSH_ERR_LIBCRYPTO_ERROR;

	RSA_get0_किल्ली(rsa_from, &rsa_n, &rsa_e, रिक्त);
	जर ((rsa_n_dup = BN_dup(rsa_n)) == रिक्त ||
	    (rsa_e_dup = BN_dup(rsa_e)) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		जा out;
	}
	जर (!RSA_set0_किल्ली(rsa_to, rsa_n_dup, rsa_e_dup, रिक्त)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		जा out;
	}
	rsa_n_dup = rsa_e_dup = रिक्त; /* transferred */

	जर (EVP_PKEY_set1_RSA(to->pkey, rsa_to) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		जा out;
	}
	/* success */
	r = 0;
 out:
	RSA_free(rsa_to);
	BN_clear_free(rsa_n_dup);
	BN_clear_free(rsa_e_dup);
	परत r;
}

स्थिर पूर्णांक
ssh_rsa_deserialize_public(स्थिरांक अक्षर *ktype, संरचना sshbuf *b,
    संरचना sshkey *किल्ली)
{
	पूर्णांक ret = SSH_ERR_INTERNAL_ERROR;
	BIGNUM *rsa_n = रिक्त, *rsa_e = रिक्त;
	RSA *rsa = रिक्त;

	जर ((rsa = RSA_new()) == रिक्त)
		परत SSH_ERR_LIBCRYPTO_ERROR;

	जर (sshbuf_get_bignum2(b, &rsa_e) != 0 ||
	    sshbuf_get_bignum2(b, &rsa_n) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		जा out;
	}
	जर (!RSA_set0_किल्ली(rsa, rsa_n, rsa_e, रिक्त)) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		जा out;
	}
	rsa_n = rsa_e = रिक्त; /* transferred */
	जर (EVP_PKEY_set1_RSA(किल्ली->pkey, rsa) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		जा out;
	}
	जर ((ret = sshkey_check_rsa_length(किल्ली, 0)) != 0)
		जा out;
#ifdef DEBUG_PK
	RSA_print_fp(मानक_त्रुटि, rsa, 8);
#endif
	/* success */
	ret = 0;
 out:
	RSA_free(rsa);
	BN_clear_free(rsa_n);
	BN_clear_free(rsa_e);
	परत ret;
}

स्थिर पूर्णांक
ssh_rsa_deserialize_private(स्थिरांक अक्षर *ktype, संरचना sshbuf *b,
    संरचना sshkey *किल्ली)
{
	पूर्णांक r;
	BIGNUM *rsa_n = रिक्त, *rsa_e = रिक्त, *rsa_d = रिक्त;
	BIGNUM *rsa_iqmp = रिक्त, *rsa_p = रिक्त, *rsa_q = रिक्त;
	BIGNUM *rsa_dmp1 = रिक्त, *rsa_dmq1 = रिक्त;
	RSA *rsa = रिक्त;

	जर (sshkey_is_cert(किल्ली)) {
		/* sshkey_private_deserialize already has pubkey from cert */
		जर ((rsa = EVP_PKEY_get1_RSA(किल्ली->pkey)) == रिक्त) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			जा out;
		}
	} अन्यथा {
		जर ((rsa = RSA_new()) == रिक्त) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			जा out;
		}
		/* Note: can't reuse ssh_rsa_deserialize_public: e,n vs. n,e */
		जर ((r = sshbuf_get_bignum2(b, &rsa_n)) != 0 ||
		    (r = sshbuf_get_bignum2(b, &rsa_e)) != 0)
			जा out;
		जर (!RSA_set0_किल्ली(rsa, rsa_n, rsa_e, रिक्त)) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			जा out;
		}
		rsa_n = rsa_e = रिक्त; /* transferred */
	}
	जर ((r = sshbuf_get_bignum2(b, &rsa_d)) != 0 ||
	    (r = sshbuf_get_bignum2(b, &rsa_iqmp)) != 0 ||
	    (r = sshbuf_get_bignum2(b, &rsa_p)) != 0 ||
	    (r = sshbuf_get_bignum2(b, &rsa_q)) != 0)
		जा out;
	जर ((r = ssh_rsa_complete_crt_parameters(rsa_d, rsa_p, rsa_q,
	    rsa_iqmp, &rsa_dmp1, &rsa_dmq1)) != 0)
		जा out;
	जर (!RSA_set0_किल्ली(rsa, रिक्त, रिक्त, rsa_d)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		जा out;
	}
	rsa_d = रिक्त; /* transferred */
	जर (!RSA_set0_factors(rsa, rsa_p, rsa_q)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		जा out;
	}
	rsa_p = rsa_q = रिक्त; /* transferred */
	जर (!RSA_set0_crt_params(rsa, rsa_dmp1, rsa_dmq1, rsa_iqmp)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		जा out;
	}
	rsa_dmp1 = rsa_dmq1 = rsa_iqmp = रिक्त;
	जर (RSA_blinding_on(rsa, रिक्त) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		जा out;
	}
	जर (EVP_PKEY_set1_RSA(किल्ली->pkey, rsa) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		जा out;
	}
	जर ((r = sshkey_check_rsa_length(किल्ली, 0)) != 0)
		जा out;
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
	परत r;
}

स्थिरांक अक्षर *
ssh_rsa_hash_alg_ident(पूर्णांक hash_alg)
{
	निवड (hash_alg) {
	स्थिती SSH_DIGEST_SHA1:
		परत "ssh-rsa";
	स्थिती SSH_DIGEST_SHA256:
		परत "rsa-sha2-256";
	स्थिती SSH_DIGEST_SHA512:
		परत "rsa-sha2-512";
	}
	परत रिक्त;
}

/*
 * Returns the hash algorithm ID for a given algorithm identifier as used
 * inside the signature blob,
 */
स्थिर पूर्णांक
rsa_hash_id_from_ident(स्थिरांक अक्षर *ident)
{
	जर (म_भेद(ident, "ssh-rsa") == 0)
		परत SSH_DIGEST_SHA1;
	जर (म_भेद(ident, "rsa-sha2-256") == 0)
		परत SSH_DIGEST_SHA256;
	जर (म_भेद(ident, "rsa-sha2-512") == 0)
		परत SSH_DIGEST_SHA512;
	परत -1;
}

/*
 * Return the hash algorithm ID for the specified key name. This includes
 * all the cases of rsa_hash_id_from_ident() but also the certificate key
 * types.
 */
पूर्णांक
ssh_rsa_hash_id_from_keyname(स्थिरांक अक्षर *alg)
{
	पूर्णांक r;

	जर ((r = rsa_hash_id_from_ident(alg)) != -1)
		परत r;
	जर (म_भेद(alg, "ssh-rsa-cert-v01@openssh.com") == 0)
		परत SSH_DIGEST_SHA1;
	जर (म_भेद(alg, "rsa-sha2-256-cert-v01@openssh.com") == 0)
		परत SSH_DIGEST_SHA256;
	जर (म_भेद(alg, "rsa-sha2-512-cert-v01@openssh.com") == 0)
		परत SSH_DIGEST_SHA512;
	परत -1;
}

पूर्णांक
ssh_rsa_complete_crt_parameters(स्थिरांक BIGNUM *rsa_d, स्थिरांक BIGNUM *rsa_p,
    स्थिरांक BIGNUM *rsa_q, स्थिरांक BIGNUM *rsa_iqmp, BIGNUM **rsa_dmp1,
    BIGNUM **rsa_dmq1)
{
	BIGNUM *aux = रिक्त, *d_consttime = रिक्त;
	BN_CTX *ctx = रिक्त;
	पूर्णांक r;

	*rsa_dmq1 = *rsa_dmp1 = रिक्त;
	जर ((ctx = BN_CTX_new()) == रिक्त)
		परत SSH_ERR_ALLOC_FAIL;
	जर ((aux = BN_new()) == रिक्त ||
	    (*rsa_dmq1 = BN_new()) == रिक्त ||
	    (*rsa_dmp1 = BN_new()) == रिक्त)
		परत SSH_ERR_ALLOC_FAIL;
	जर ((d_consttime = BN_dup(rsa_d)) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		जा out;
	}
	BN_set_flags(aux, BN_FLG_CONSTTIME);
	BN_set_flags(d_consttime, BN_FLG_CONSTTIME);

	जर ((BN_sub(aux, rsa_q, BN_मूल्य_one()) == 0) ||
	    (BN_mod(*rsa_dmq1, d_consttime, aux, ctx) == 0) ||
	    (BN_sub(aux, rsa_p, BN_मूल्य_one()) == 0) ||
	    (BN_mod(*rsa_dmp1, d_consttime, aux, ctx) == 0)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		जा out;
	}
	/* success */
	r = 0;
 out:
	BN_clear_free(aux);
	BN_clear_free(d_consttime);
	BN_CTX_free(ctx);
	परत r;
}

/* RSASSA-PKCS1-v1_5 (PKCS #1 v2.0 signature) with SHA1 */
स्थिर पूर्णांक
ssh_rsa_sign(संरचना sshkey *किल्ली,
    u_char **sigp, माप_प्रकार *lenp,
    स्थिरांक u_char *data, माप_प्रकार datalen,
    स्थिरांक अक्षर *alg, स्थिरांक अक्षर *sk_provider, स्थिरांक अक्षर *sk_pin, u_int compat)
{
	u_char *sig = रिक्त;
	माप_प्रकार diff, len = 0;
	पूर्णांक slen = 0;
	पूर्णांक hash_alg, ret = SSH_ERR_INTERNAL_ERROR;

	जर (lenp != रिक्त)
		*lenp = 0;
	जर (sigp != रिक्त)
		*sigp = रिक्त;

	जर (alg == रिक्त || म_माप(alg) == 0)
		hash_alg = SSH_DIGEST_SHA1;
	अन्यथा
		hash_alg = ssh_rsa_hash_id_from_keyname(alg);

	जर (किल्ली == रिक्त || किल्ली->pkey == रिक्त || hash_alg == -1 ||
	    sshkey_type_plain(किल्ली->type) != किल्ली_RSA)
		परत SSH_ERR_INVALID_ARGUMENT;
	slen = EVP_PKEY_size(किल्ली->pkey);
	जर (slen <= 0 || slen > SSHBUF_MAX_BIGNUM)
		परत SSH_ERR_INVALID_ARGUMENT;
	जर (EVP_PKEY_bits(किल्ली->pkey) < SSH_RSA_MINIMUM_MODULUS_SIZE)
		परत SSH_ERR_किल्ली_LENGTH;

	जर ((ret = sshkey_pkey_digest_sign(किल्ली->pkey, hash_alg, &sig, &len,
	    data, datalen)) < 0)
		जा out;
	जर (len < (माप_प्रकार)slen) {
		diff = slen - len;
		स_हटाओ(sig + diff, sig, len);
		explicit_bzero(sig, diff);
	} अन्यथा जर (len > (माप_प्रकार)slen) {
		ret = SSH_ERR_INTERNAL_ERROR;
		जा out;
	}
	जर ((ret = ssh_rsa_encode_store_sig(hash_alg, sig, slen,
	    sigp, lenp)) != 0)
		जा out;

	/* success */
	ret = 0;
 out:
	freezero(sig, slen);
	परत ret;
}

पूर्णांक
ssh_rsa_encode_store_sig(पूर्णांक hash_alg, स्थिरांक u_char *sig, माप_प्रकार slen,
    u_char **sigp, माप_प्रकार *lenp)
{
	संरचना sshbuf *b = रिक्त;
	पूर्णांक ret = SSH_ERR_INTERNAL_ERROR;
	माप_प्रकार len;

	जर (lenp != रिक्त)
		*lenp = 0;
	जर (sigp != रिक्त)
		*sigp = रिक्त;

	/* Encode signature */
	जर ((b = sshbuf_new()) == रिक्त) {
		ret = SSH_ERR_ALLOC_FAIL;
		जा out;
	}
	जर ((ret = sshbuf_put_cstring(b,
	    ssh_rsa_hash_alg_ident(hash_alg))) != 0 ||
	    (ret = sshbuf_put_string(b, sig, slen)) != 0)
		जा out;
	len = sshbuf_len(b);

	/* Store signature */
	जर (sigp != रिक्त) {
		जर ((*sigp = दो_स्मृति(len)) == रिक्त) {
			ret = SSH_ERR_ALLOC_FAIL;
			जा out;
		}
		स_नकल(*sigp, sshbuf_ptr(b), len);
	}
	जर (lenp != रिक्त)
		*lenp = len;
	ret = 0;
 out:
	sshbuf_free(b);
	परत ret;
}

स्थिर पूर्णांक
ssh_rsa_verify(स्थिरांक संरचना sshkey *किल्ली,
    स्थिरांक u_char *sig, माप_प्रकार siglen,
    स्थिरांक u_char *data, माप_प्रकार dlen, स्थिरांक अक्षर *alg, u_int compat,
    संरचना sshkey_sig_details **detailsp)
{
	अक्षर *sigtype = रिक्त;
	पूर्णांक hash_alg, want_alg, ret = SSH_ERR_INTERNAL_ERROR;
	माप_प्रकार len = 0, diff, modlen, rsasize;
	संरचना sshbuf *b = रिक्त;
	u_char digest[SSH_DIGEST_MAX_LENGTH], *osigblob, *sigblob = रिक्त;

	जर (किल्ली == रिक्त || किल्ली->pkey == रिक्त ||
	    sshkey_type_plain(किल्ली->type) != किल्ली_RSA ||
	    sig == रिक्त || siglen == 0)
		परत SSH_ERR_INVALID_ARGUMENT;
	जर (EVP_PKEY_bits(किल्ली->pkey) < SSH_RSA_MINIMUM_MODULUS_SIZE)
		परत SSH_ERR_किल्ली_LENGTH;

	जर ((b = sshbuf_from(sig, siglen)) == रिक्त)
		परत SSH_ERR_ALLOC_FAIL;
	जर (sshbuf_get_cstring(b, &sigtype, रिक्त) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		जा out;
	}
	जर ((hash_alg = rsa_hash_id_from_ident(sigtype)) == -1) {
		ret = SSH_ERR_किल्ली_TYPE_MISMATCH;
		जा out;
	}
	/*
	 * Allow ssh-rsa-cert-v01 certs to generate SHA2 signatures for
	 * legacy reasons, but otherwise the signature type should match.
	 */
	जर (alg != रिक्त && म_भेद(alg, "ssh-rsa-cert-v01@openssh.com") != 0) {
		जर ((want_alg = ssh_rsa_hash_id_from_keyname(alg)) == -1) {
			ret = SSH_ERR_INVALID_ARGUMENT;
			जा out;
		}
		जर (hash_alg != want_alg) {
			ret = SSH_ERR_SIGNATURE_INVALID;
			जा out;
		}
	}
	जर (sshbuf_get_string(b, &sigblob, &len) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		जा out;
	}
	जर (sshbuf_len(b) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		जा out;
	}
	/* RSA_verify expects a signature of RSA_size */
	modlen = EVP_PKEY_size(किल्ली->pkey);
	जर (len > modlen) {
		ret = SSH_ERR_किल्ली_BITS_MISMATCH;
		जा out;
	} अन्यथा जर (len < modlen) {
		diff = modlen - len;
		osigblob = sigblob;
		जर ((sigblob = पुनः_स्मृति(sigblob, modlen)) == रिक्त) {
			sigblob = osigblob; /* put it back for clear/free */
			ret = SSH_ERR_ALLOC_FAIL;
			जा out;
		}
		स_हटाओ(sigblob + diff, sigblob, len);
		explicit_bzero(sigblob, diff);
		len = modlen;
	}

	rsasize = EVP_PKEY_size(किल्ली->pkey);
	जर (rsasize <= 0 || rsasize > SSHBUF_MAX_BIGNUM ||
	    len == 0 || len > rsasize) {
		ret = SSH_ERR_INVALID_ARGUMENT;
		जा out;
	}
	ret = sshkey_pkey_digest_verify(किल्ली->pkey, hash_alg, data, dlen,
	    sigblob, len);

 out:
	freezero(sigblob, len);
	मुक्त(sigtype);
	sshbuf_free(b);
	explicit_bzero(digest, आकार(digest));
	परत ret;
}

स्थिर स्थिरांक संरचना sshkey_impl_funcs sshkey_rsa_funcs = {
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

स्थिरांक संरचना sshkey_impl sshkey_rsa_impl = {
	/* .name = */		"ssh-rsa",
	/* .shortname = */	"RSA",
	/* .sigalg = */		रिक्त,
	/* .type = */		किल्ली_RSA,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};

स्थिरांक संरचना sshkey_impl sshkey_rsa_cert_impl = {
	/* .name = */		"ssh-rsa-cert-v01@openssh.com",
	/* .shortname = */	"RSA-CERT",
	/* .sigalg = */		रिक्त,
	/* .type = */		किल्ली_RSA_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};

/* SHA2 signature algorithms */

स्थिरांक संरचना sshkey_impl sshkey_rsa_sha256_impl = {
	/* .name = */		"rsa-sha2-256",
	/* .shortname = */	"RSA",
	/* .sigalg = */		रिक्त,
	/* .type = */		किल्ली_RSA,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	1,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};

स्थिरांक संरचना sshkey_impl sshkey_rsa_sha512_impl = {
	/* .name = */		"rsa-sha2-512",
	/* .shortname = */	"RSA",
	/* .sigalg = */		रिक्त,
	/* .type = */		किल्ली_RSA,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	1,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};

स्थिरांक संरचना sshkey_impl sshkey_rsa_sha256_cert_impl = {
	/* .name = */		"rsa-sha2-256-cert-v01@openssh.com",
	/* .shortname = */	"RSA-CERT",
	/* .sigalg = */		"rsa-sha2-256",
	/* .type = */		किल्ली_RSA_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	1,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};

स्थिरांक संरचना sshkey_impl sshkey_rsa_sha512_cert_impl = {
	/* .name = */		"rsa-sha2-512-cert-v01@openssh.com",
	/* .shortname = */	"RSA-CERT",
	/* .sigalg = */		"rsa-sha2-512",
	/* .type = */		किल्ली_RSA_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	1,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};
#endif /* WITH_OPENSSL */
