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
ssh_rsa_size(अचर संरचना sshkey *k)
{
	यदि (k->pkey == रिक्त)
		फर्काऊ 0;
	फर्काऊ EVP_PKEY_bits(k->pkey);
}

स्थिर पूर्णाङ्क
ssh_rsa_alloc(संरचना sshkey *k)
{
	यदि ((k->pkey = EVP_PKEY_new()) == रिक्त)
		फर्काऊ SSH_ERR_ALLOC_FAIL;
	फर्काऊ 0;
}

स्थिर शून्य
ssh_rsa_cleanup(संरचना sshkey *k)
{
	EVP_PKEY_free(k->pkey);
	k->pkey = रिक्त;
}

स्थिर पूर्णाङ्क
ssh_rsa_equal(अचर संरचना sshkey *a, अचर संरचना sshkey *b)
{
	यदि (a->pkey == रिक्त || b->pkey == रिक्त)
		फर्काऊ 0;
	फर्काऊ EVP_PKEY_cmp(a->pkey, b->pkey) == 1;
}

स्थिर पूर्णाङ्क
ssh_rsa_serialize_public(अचर संरचना sshkey *साँचो, संरचना sshbuf *b,
    गणना sshkey_serialize_rep opts)
{
	पूर्णाङ्क r;
	अचर BIGNUM *rsa_n, *rsa_e;
	अचर RSA *rsa;

	यदि (साँचो->pkey == रिक्त)
		फर्काऊ SSH_ERR_INVALID_ARGUMENT;
	यदि ((rsa = EVP_PKEY_get0_RSA(साँचो->pkey)) == रिक्त)
		फर्काऊ SSH_ERR_LIBCRYPTO_ERROR;

	RSA_get0_साँचो(rsa, &rsa_n, &rsa_e, रिक्त);
	यदि ((r = sshbuf_put_bignum2(b, rsa_e)) != 0 ||
	    (r = sshbuf_put_bignum2(b, rsa_n)) != 0)
		फर्काऊ r;

	फर्काऊ 0;
}

स्थिर पूर्णाङ्क
ssh_rsa_serialize_private(अचर संरचना sshkey *साँचो, संरचना sshbuf *b,
    गणना sshkey_serialize_rep opts)
{
	पूर्णाङ्क r;
	अचर BIGNUM *rsa_n, *rsa_e, *rsa_d, *rsa_iqmp, *rsa_p, *rsa_q;
	अचर RSA *rsa;

	यदि ((rsa = EVP_PKEY_get0_RSA(साँचो->pkey)) == रिक्त)
		फर्काऊ SSH_ERR_LIBCRYPTO_ERROR;
	RSA_get0_साँचो(rsa, &rsa_n, &rsa_e, &rsa_d);
	RSA_get0_factors(rsa, &rsa_p, &rsa_q);
	RSA_get0_crt_params(rsa, रिक्त, रिक्त, &rsa_iqmp);

	यदि (!sshkey_is_cert(साँचो)) {
		/* Note: can't reuse ssh_rsa_serialize_public: e, n vs. n, e */
		यदि ((r = sshbuf_put_bignum2(b, rsa_n)) != 0 ||
		    (r = sshbuf_put_bignum2(b, rsa_e)) != 0)
			फर्काऊ r;
	}
	यदि ((r = sshbuf_put_bignum2(b, rsa_d)) != 0 ||
	    (r = sshbuf_put_bignum2(b, rsa_iqmp)) != 0 ||
	    (r = sshbuf_put_bignum2(b, rsa_p)) != 0 ||
	    (r = sshbuf_put_bignum2(b, rsa_q)) != 0)
		फर्काऊ r;

	फर्काऊ 0;
}

स्थिर पूर्णाङ्क
ssh_rsa_generate(संरचना sshkey *k, पूर्णाङ्क bits)
{
	EVP_PKEY_CTX *ctx = रिक्त;
	EVP_PKEY *res = रिक्त;

	पूर्णाङ्क ret = SSH_ERR_INTERNAL_ERROR;

	यदि (bits < SSH_RSA_MINIMUM_MODULUS_SIZE ||
	    bits > SSHBUF_MAX_BIGNUM * 8)
		फर्काऊ SSH_ERR_साँचो_LENGTH;

	यदि ((ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, रिक्त)) == रिक्त) {
		ret = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	यदि (EVP_PKEY_keygen_init(ctx) <= 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		गच्छ out;
	}
	यदि (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0) {
		ret = SSH_ERR_साँचो_LENGTH;
		गच्छ out;
	}
	यदि (EVP_PKEY_keygen(ctx, &res) <= 0 || res == रिक्त) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		गच्छ out;
	}
	/* success */
	k->pkey = res;
	ret = 0;
 out:
	EVP_PKEY_CTX_free(ctx);
	फर्काऊ ret;
}

स्थिर पूर्णाङ्क
ssh_rsa_copy_public(अचर संरचना sshkey *from, संरचना sshkey *to)
{
	अचर BIGNUM *rsa_n, *rsa_e;
	BIGNUM *rsa_n_dup = रिक्त, *rsa_e_dup = रिक्त;
	पूर्णाङ्क r = SSH_ERR_INTERNAL_ERROR;
	अचर RSA *rsa_from;
	RSA *rsa_to = रिक्त;

	यदि ((rsa_from = EVP_PKEY_get0_RSA(from->pkey)) == रिक्त ||
	    (rsa_to = RSA_new()) == रिक्त)
		फर्काऊ SSH_ERR_LIBCRYPTO_ERROR;

	RSA_get0_साँचो(rsa_from, &rsa_n, &rsa_e, रिक्त);
	यदि ((rsa_n_dup = BN_dup(rsa_n)) == रिक्त ||
	    (rsa_e_dup = BN_dup(rsa_e)) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	यदि (!RSA_set0_साँचो(rsa_to, rsa_n_dup, rsa_e_dup, रिक्त)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		गच्छ out;
	}
	rsa_n_dup = rsa_e_dup = रिक्त; /* transferred */

	यदि (EVP_PKEY_set1_RSA(to->pkey, rsa_to) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		गच्छ out;
	}
	/* success */
	r = 0;
 out:
	RSA_free(rsa_to);
	BN_clear_free(rsa_n_dup);
	BN_clear_free(rsa_e_dup);
	फर्काऊ r;
}

स्थिर पूर्णाङ्क
ssh_rsa_deserialize_public(अचर वर्ण *ktype, संरचना sshbuf *b,
    संरचना sshkey *साँचो)
{
	पूर्णाङ्क ret = SSH_ERR_INTERNAL_ERROR;
	BIGNUM *rsa_n = रिक्त, *rsa_e = रिक्त;
	RSA *rsa = रिक्त;

	यदि ((rsa = RSA_new()) == रिक्त)
		फर्काऊ SSH_ERR_LIBCRYPTO_ERROR;

	यदि (sshbuf_get_bignum2(b, &rsa_e) != 0 ||
	    sshbuf_get_bignum2(b, &rsa_n) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		गच्छ out;
	}
	यदि (!RSA_set0_साँचो(rsa, rsa_n, rsa_e, रिक्त)) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		गच्छ out;
	}
	rsa_n = rsa_e = रिक्त; /* transferred */
	यदि (EVP_PKEY_set1_RSA(साँचो->pkey, rsa) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		गच्छ out;
	}
	यदि ((ret = sshkey_check_rsa_length(साँचो, 0)) != 0)
		गच्छ out;
#ifdef DEBUG_PK
	RSA_print_fp(मानक_त्रुटि, rsa, 8);
#endif
	/* success */
	ret = 0;
 out:
	RSA_free(rsa);
	BN_clear_free(rsa_n);
	BN_clear_free(rsa_e);
	फर्काऊ ret;
}

स्थिर पूर्णाङ्क
ssh_rsa_deserialize_private(अचर वर्ण *ktype, संरचना sshbuf *b,
    संरचना sshkey *साँचो)
{
	पूर्णाङ्क r;
	BIGNUM *rsa_n = रिक्त, *rsa_e = रिक्त, *rsa_d = रिक्त;
	BIGNUM *rsa_iqmp = रिक्त, *rsa_p = रिक्त, *rsa_q = रिक्त;
	BIGNUM *rsa_dmp1 = रिक्त, *rsa_dmq1 = रिक्त;
	RSA *rsa = रिक्त;

	यदि (sshkey_is_cert(साँचो)) {
		/* sshkey_private_deserialize already has pubkey from cert */
		यदि ((rsa = EVP_PKEY_get1_RSA(साँचो->pkey)) == रिक्त) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			गच्छ out;
		}
	} अन्यथा {
		यदि ((rsa = RSA_new()) == रिक्त) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			गच्छ out;
		}
		/* Note: can't reuse ssh_rsa_deserialize_public: e,n vs. n,e */
		यदि ((r = sshbuf_get_bignum2(b, &rsa_n)) != 0 ||
		    (r = sshbuf_get_bignum2(b, &rsa_e)) != 0)
			गच्छ out;
		यदि (!RSA_set0_साँचो(rsa, rsa_n, rsa_e, रिक्त)) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			गच्छ out;
		}
		rsa_n = rsa_e = रिक्त; /* transferred */
	}
	यदि ((r = sshbuf_get_bignum2(b, &rsa_d)) != 0 ||
	    (r = sshbuf_get_bignum2(b, &rsa_iqmp)) != 0 ||
	    (r = sshbuf_get_bignum2(b, &rsa_p)) != 0 ||
	    (r = sshbuf_get_bignum2(b, &rsa_q)) != 0)
		गच्छ out;
	यदि ((r = ssh_rsa_complete_crt_parameters(rsa_d, rsa_p, rsa_q,
	    rsa_iqmp, &rsa_dmp1, &rsa_dmq1)) != 0)
		गच्छ out;
	यदि (!RSA_set0_साँचो(rsa, रिक्त, रिक्त, rsa_d)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		गच्छ out;
	}
	rsa_d = रिक्त; /* transferred */
	यदि (!RSA_set0_factors(rsa, rsa_p, rsa_q)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		गच्छ out;
	}
	rsa_p = rsa_q = रिक्त; /* transferred */
	यदि (!RSA_set0_crt_params(rsa, rsa_dmp1, rsa_dmq1, rsa_iqmp)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		गच्छ out;
	}
	rsa_dmp1 = rsa_dmq1 = rsa_iqmp = रिक्त;
	यदि (RSA_blinding_on(rsa, रिक्त) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		गच्छ out;
	}
	यदि (EVP_PKEY_set1_RSA(साँचो->pkey, rsa) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		गच्छ out;
	}
	यदि ((r = sshkey_check_rsa_length(साँचो, 0)) != 0)
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
	फर्काऊ r;
}

अचर वर्ण *
ssh_rsa_hash_alg_ident(पूर्णाङ्क hash_alg)
{
	विकल्प (hash_alg) {
	पक्ष SSH_DIGEST_SHA1:
		फर्काऊ "ssh-rsa";
	पक्ष SSH_DIGEST_SHA256:
		फर्काऊ "rsa-sha2-256";
	पक्ष SSH_DIGEST_SHA512:
		फर्काऊ "rsa-sha2-512";
	}
	फर्काऊ रिक्त;
}

/*
 * Returns the hash algorithm ID for a given algorithm identifier as used
 * inside the signature blob,
 */
स्थिर पूर्णाङ्क
rsa_hash_id_from_ident(अचर वर्ण *ident)
{
	यदि (म_भेद(ident, "ssh-rsa") == 0)
		फर्काऊ SSH_DIGEST_SHA1;
	यदि (म_भेद(ident, "rsa-sha2-256") == 0)
		फर्काऊ SSH_DIGEST_SHA256;
	यदि (म_भेद(ident, "rsa-sha2-512") == 0)
		फर्काऊ SSH_DIGEST_SHA512;
	फर्काऊ -1;
}

/*
 * Return the hash algorithm ID for the specified key name. This includes
 * all the cases of rsa_hash_id_from_ident() but also the certificate key
 * types.
 */
पूर्णाङ्क
ssh_rsa_hash_id_from_keyname(अचर वर्ण *alg)
{
	पूर्णाङ्क r;

	यदि ((r = rsa_hash_id_from_ident(alg)) != -1)
		फर्काऊ r;
	यदि (म_भेद(alg, "ssh-rsa-cert-v01@openssh.com") == 0)
		फर्काऊ SSH_DIGEST_SHA1;
	यदि (म_भेद(alg, "rsa-sha2-256-cert-v01@openssh.com") == 0)
		फर्काऊ SSH_DIGEST_SHA256;
	यदि (म_भेद(alg, "rsa-sha2-512-cert-v01@openssh.com") == 0)
		फर्काऊ SSH_DIGEST_SHA512;
	फर्काऊ -1;
}

पूर्णाङ्क
ssh_rsa_complete_crt_parameters(अचर BIGNUM *rsa_d, अचर BIGNUM *rsa_p,
    अचर BIGNUM *rsa_q, अचर BIGNUM *rsa_iqmp, BIGNUM **rsa_dmp1,
    BIGNUM **rsa_dmq1)
{
	BIGNUM *aux = रिक्त, *d_consttime = रिक्त;
	BN_CTX *ctx = रिक्त;
	पूर्णाङ्क r;

	*rsa_dmq1 = *rsa_dmp1 = रिक्त;
	यदि ((ctx = BN_CTX_new()) == रिक्त)
		फर्काऊ SSH_ERR_ALLOC_FAIL;
	यदि ((aux = BN_new()) == रिक्त ||
	    (*rsa_dmq1 = BN_new()) == रिक्त ||
	    (*rsa_dmp1 = BN_new()) == रिक्त)
		फर्काऊ SSH_ERR_ALLOC_FAIL;
	यदि ((d_consttime = BN_dup(rsa_d)) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	BN_set_flags(aux, BN_FLG_CONSTTIME);
	BN_set_flags(d_consttime, BN_FLG_CONSTTIME);

	यदि ((BN_sub(aux, rsa_q, BN_मान_one()) == 0) ||
	    (BN_mod(*rsa_dmq1, d_consttime, aux, ctx) == 0) ||
	    (BN_sub(aux, rsa_p, BN_मान_one()) == 0) ||
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
	फर्काऊ r;
}

/* RSASSA-PKCS1-v1_5 (PKCS #1 v2.0 signature) with SHA1 */
स्थिर पूर्णाङ्क
ssh_rsa_sign(संरचना sshkey *साँचो,
    u_char **sigp, माप_प्रकार *lenp,
    अचर u_char *data, माप_प्रकार datalen,
    अचर वर्ण *alg, अचर वर्ण *sk_provider, अचर वर्ण *sk_pin, u_int compat)
{
	u_char *sig = रिक्त;
	माप_प्रकार diff, len = 0;
	पूर्णाङ्क slen = 0;
	पूर्णाङ्क hash_alg, ret = SSH_ERR_INTERNAL_ERROR;

	यदि (lenp != रिक्त)
		*lenp = 0;
	यदि (sigp != रिक्त)
		*sigp = रिक्त;

	यदि (alg == रिक्त || म_माप(alg) == 0)
		hash_alg = SSH_DIGEST_SHA1;
	अन्यथा
		hash_alg = ssh_rsa_hash_id_from_keyname(alg);

	यदि (साँचो == रिक्त || साँचो->pkey == रिक्त || hash_alg == -1 ||
	    sshkey_type_plain(साँचो->type) != साँचो_RSA)
		फर्काऊ SSH_ERR_INVALID_ARGUMENT;
	slen = EVP_PKEY_size(साँचो->pkey);
	यदि (slen <= 0 || slen > SSHBUF_MAX_BIGNUM)
		फर्काऊ SSH_ERR_INVALID_ARGUMENT;
	यदि (EVP_PKEY_bits(साँचो->pkey) < SSH_RSA_MINIMUM_MODULUS_SIZE)
		फर्काऊ SSH_ERR_साँचो_LENGTH;

	यदि ((ret = sshkey_pkey_digest_sign(साँचो->pkey, hash_alg, &sig, &len,
	    data, datalen)) < 0)
		गच्छ out;
	यदि (len < (माप_प्रकार)slen) {
		diff = slen - len;
		स_हटाओ(sig + diff, sig, len);
		explicit_bzero(sig, diff);
	} अन्यथा यदि (len > (माप_प्रकार)slen) {
		ret = SSH_ERR_INTERNAL_ERROR;
		गच्छ out;
	}
	यदि ((ret = ssh_rsa_encode_store_sig(hash_alg, sig, slen,
	    sigp, lenp)) != 0)
		गच्छ out;

	/* success */
	ret = 0;
 out:
	freezero(sig, slen);
	फर्काऊ ret;
}

पूर्णाङ्क
ssh_rsa_encode_store_sig(पूर्णाङ्क hash_alg, अचर u_char *sig, माप_प्रकार slen,
    u_char **sigp, माप_प्रकार *lenp)
{
	संरचना sshbuf *b = रिक्त;
	पूर्णाङ्क ret = SSH_ERR_INTERNAL_ERROR;
	माप_प्रकार len;

	यदि (lenp != रिक्त)
		*lenp = 0;
	यदि (sigp != रिक्त)
		*sigp = रिक्त;

	/* Encode signature */
	यदि ((b = sshbuf_new()) == रिक्त) {
		ret = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	यदि ((ret = sshbuf_put_cstring(b,
	    ssh_rsa_hash_alg_ident(hash_alg))) != 0 ||
	    (ret = sshbuf_put_string(b, sig, slen)) != 0)
		गच्छ out;
	len = sshbuf_len(b);

	/* Store signature */
	यदि (sigp != रिक्त) {
		यदि ((*sigp = दो_स्मृति(len)) == रिक्त) {
			ret = SSH_ERR_ALLOC_FAIL;
			गच्छ out;
		}
		स_नकल(*sigp, sshbuf_ptr(b), len);
	}
	यदि (lenp != रिक्त)
		*lenp = len;
	ret = 0;
 out:
	sshbuf_free(b);
	फर्काऊ ret;
}

स्थिर पूर्णाङ्क
ssh_rsa_verify(अचर संरचना sshkey *साँचो,
    अचर u_char *sig, माप_प्रकार siglen,
    अचर u_char *data, माप_प्रकार dlen, अचर वर्ण *alg, u_int compat,
    संरचना sshkey_sig_details **detailsp)
{
	वर्ण *sigtype = रिक्त;
	पूर्णाङ्क hash_alg, want_alg, ret = SSH_ERR_INTERNAL_ERROR;
	माप_प्रकार len = 0, diff, modlen, rsasize;
	संरचना sshbuf *b = रिक्त;
	u_char digest[SSH_DIGEST_MAX_LENGTH], *osigblob, *sigblob = रिक्त;

	यदि (साँचो == रिक्त || साँचो->pkey == रिक्त ||
	    sshkey_type_plain(साँचो->type) != साँचो_RSA ||
	    sig == रिक्त || siglen == 0)
		फर्काऊ SSH_ERR_INVALID_ARGUMENT;
	यदि (EVP_PKEY_bits(साँचो->pkey) < SSH_RSA_MINIMUM_MODULUS_SIZE)
		फर्काऊ SSH_ERR_साँचो_LENGTH;

	यदि ((b = sshbuf_from(sig, siglen)) == रिक्त)
		फर्काऊ SSH_ERR_ALLOC_FAIL;
	यदि (sshbuf_get_cstring(b, &sigtype, रिक्त) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		गच्छ out;
	}
	यदि ((hash_alg = rsa_hash_id_from_ident(sigtype)) == -1) {
		ret = SSH_ERR_साँचो_TYPE_MISMATCH;
		गच्छ out;
	}
	/*
	 * Allow ssh-rsa-cert-v01 certs to generate SHA2 signatures for
	 * legacy reasons, but otherwise the signature type should match.
	 */
	यदि (alg != रिक्त && म_भेद(alg, "ssh-rsa-cert-v01@openssh.com") != 0) {
		यदि ((want_alg = ssh_rsa_hash_id_from_keyname(alg)) == -1) {
			ret = SSH_ERR_INVALID_ARGUMENT;
			गच्छ out;
		}
		यदि (hash_alg != want_alg) {
			ret = SSH_ERR_SIGNATURE_INVALID;
			गच्छ out;
		}
	}
	यदि (sshbuf_get_string(b, &sigblob, &len) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		गच्छ out;
	}
	यदि (sshbuf_len(b) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		गच्छ out;
	}
	/* RSA_verify expects a signature of RSA_size */
	modlen = EVP_PKEY_size(साँचो->pkey);
	यदि (len > modlen) {
		ret = SSH_ERR_साँचो_BITS_MISMATCH;
		गच्छ out;
	} अन्यथा यदि (len < modlen) {
		diff = modlen - len;
		osigblob = sigblob;
		यदि ((sigblob = पुनः_स्मृति(sigblob, modlen)) == रिक्त) {
			sigblob = osigblob; /* put it back for clear/free */
			ret = SSH_ERR_ALLOC_FAIL;
			गच्छ out;
		}
		स_हटाओ(sigblob + diff, sigblob, len);
		explicit_bzero(sigblob, diff);
		len = modlen;
	}

	rsasize = EVP_PKEY_size(साँचो->pkey);
	यदि (rsasize <= 0 || rsasize > SSHBUF_MAX_BIGNUM ||
	    len == 0 || len > rsasize) {
		ret = SSH_ERR_INVALID_ARGUMENT;
		गच्छ out;
	}
	ret = sshkey_pkey_digest_verify(साँचो->pkey, hash_alg, data, dlen,
	    sigblob, len);

 out:
	freezero(sigblob, len);
	मुक्त(sigtype);
	sshbuf_free(b);
	explicit_bzero(digest, परिमाण(digest));
	फर्काऊ ret;
}

स्थिर अचर संरचना sshkey_impl_funcs sshkey_rsa_funcs = {
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

अचर संरचना sshkey_impl sshkey_rsa_impl = {
	/* .name = */		"ssh-rsa",
	/* .shortname = */	"RSA",
	/* .sigalg = */		रिक्त,
	/* .type = */		साँचो_RSA,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};

अचर संरचना sshkey_impl sshkey_rsa_cert_impl = {
	/* .name = */		"ssh-rsa-cert-v01@openssh.com",
	/* .shortname = */	"RSA-CERT",
	/* .sigalg = */		रिक्त,
	/* .type = */		साँचो_RSA_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};

/* SHA2 signature algorithms */

अचर संरचना sshkey_impl sshkey_rsa_sha256_impl = {
	/* .name = */		"rsa-sha2-256",
	/* .shortname = */	"RSA",
	/* .sigalg = */		रिक्त,
	/* .type = */		साँचो_RSA,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	1,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};

अचर संरचना sshkey_impl sshkey_rsa_sha512_impl = {
	/* .name = */		"rsa-sha2-512",
	/* .shortname = */	"RSA",
	/* .sigalg = */		रिक्त,
	/* .type = */		साँचो_RSA,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	1,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};

अचर संरचना sshkey_impl sshkey_rsa_sha256_cert_impl = {
	/* .name = */		"rsa-sha2-256-cert-v01@openssh.com",
	/* .shortname = */	"RSA-CERT",
	/* .sigalg = */		"rsa-sha2-256",
	/* .type = */		साँचो_RSA_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	1,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};

अचर संरचना sshkey_impl sshkey_rsa_sha512_cert_impl = {
	/* .name = */		"rsa-sha2-512-cert-v01@openssh.com",
	/* .shortname = */	"RSA-CERT",
	/* .sigalg = */		"rsa-sha2-512",
	/* .type = */		साँचो_RSA_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	1,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};
#endif /* WITH_OPENSSL */
