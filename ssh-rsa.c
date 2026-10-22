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

#समावेश "includes.h"

#अगर_घोषित WITH_OPENSSL
#समावेश "openbsd-compat/openssl-compat.h"

#समावेश <sys/types.h>

#समावेश <openssl/bn.h>
#समावेश <openssl/evp.h>

#समावेश <stdarg.h>
#समावेश <string.h>

#समावेश "sshbuf.h"
#समावेश "ssherr.h"
#घोषणा SSHKEY_INTERNAL
#समावेश "sshkey.h"
#समावेश "digest.h"

अटल u_int
ssh_rsa_आकार(स्थिर काष्ठा sshkey *k)
{
	अगर (k->pkey == शून्य)
		वापस 0;
	वापस EVP_PKEY_bits(k->pkey);
}

अटल पूर्णांक
ssh_rsa_alloc(काष्ठा sshkey *k)
{
	अगर ((k->pkey = EVP_PKEY_new()) == शून्य)
		वापस SSH_ERR_ALLOC_FAIL;
	वापस 0;
}

अटल व्योम
ssh_rsa_cleanup(काष्ठा sshkey *k)
{
	EVP_PKEY_free(k->pkey);
	k->pkey = शून्य;
}

अटल पूर्णांक
ssh_rsa_equal(स्थिर काष्ठा sshkey *a, स्थिर काष्ठा sshkey *b)
{
	अगर (a->pkey == शून्य || b->pkey == शून्य)
		वापस 0;
	वापस EVP_PKEY_cmp(a->pkey, b->pkey) == 1;
}

अटल पूर्णांक
ssh_rsa_serialize_public(स्थिर काष्ठा sshkey *कुंजी, काष्ठा sshbuf *b,
    क्रमागत sshkey_serialize_rep opts)
{
	पूर्णांक r;
	स्थिर BIGNUM *rsa_n, *rsa_e;
	स्थिर RSA *rsa;

	अगर (कुंजी->pkey == शून्य)
		वापस SSH_ERR_INVALID_ARGUMENT;
	अगर ((rsa = EVP_PKEY_get0_RSA(कुंजी->pkey)) == शून्य)
		वापस SSH_ERR_LIBCRYPTO_ERROR;

	RSA_get0_कुंजी(rsa, &rsa_n, &rsa_e, शून्य);
	अगर ((r = sshbuf_put_bignum2(b, rsa_e)) != 0 ||
	    (r = sshbuf_put_bignum2(b, rsa_n)) != 0)
		वापस r;

	वापस 0;
}

अटल पूर्णांक
ssh_rsa_serialize_private(स्थिर काष्ठा sshkey *कुंजी, काष्ठा sshbuf *b,
    क्रमागत sshkey_serialize_rep opts)
{
	पूर्णांक r;
	स्थिर BIGNUM *rsa_n, *rsa_e, *rsa_d, *rsa_iqmp, *rsa_p, *rsa_q;
	स्थिर RSA *rsa;

	अगर ((rsa = EVP_PKEY_get0_RSA(कुंजी->pkey)) == शून्य)
		वापस SSH_ERR_LIBCRYPTO_ERROR;
	RSA_get0_कुंजी(rsa, &rsa_n, &rsa_e, &rsa_d);
	RSA_get0_factors(rsa, &rsa_p, &rsa_q);
	RSA_get0_crt_params(rsa, शून्य, शून्य, &rsa_iqmp);

	अगर (!sshkey_is_cert(कुंजी)) {
		/* Note: can't reuse ssh_rsa_serialize_public: e, n vs. n, e */
		अगर ((r = sshbuf_put_bignum2(b, rsa_n)) != 0 ||
		    (r = sshbuf_put_bignum2(b, rsa_e)) != 0)
			वापस r;
	}
	अगर ((r = sshbuf_put_bignum2(b, rsa_d)) != 0 ||
	    (r = sshbuf_put_bignum2(b, rsa_iqmp)) != 0 ||
	    (r = sshbuf_put_bignum2(b, rsa_p)) != 0 ||
	    (r = sshbuf_put_bignum2(b, rsa_q)) != 0)
		वापस r;

	वापस 0;
}

अटल पूर्णांक
ssh_rsa_generate(काष्ठा sshkey *k, पूर्णांक bits)
{
	EVP_PKEY_CTX *ctx = शून्य;
	EVP_PKEY *res = शून्य;

	पूर्णांक ret = SSH_ERR_INTERNAL_ERROR;

	अगर (bits < SSH_RSA_MINIMUM_MODULUS_आकार ||
	    bits > SSHBUF_MAX_BIGNUM * 8)
		वापस SSH_ERR_कुंजी_लंबाई;

	अगर ((ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, शून्य)) == शून्य) {
		ret = SSH_ERR_ALLOC_FAIL;
		जाओ out;
	}
	अगर (EVP_PKEY_keygen_init(ctx) <= 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		जाओ out;
	}
	अगर (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0) {
		ret = SSH_ERR_कुंजी_लंबाई;
		जाओ out;
	}
	अगर (EVP_PKEY_keygen(ctx, &res) <= 0 || res == शून्य) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		जाओ out;
	}
	/* success */
	k->pkey = res;
	ret = 0;
 out:
	EVP_PKEY_CTX_free(ctx);
	वापस ret;
}

अटल पूर्णांक
ssh_rsa_copy_public(स्थिर काष्ठा sshkey *from, काष्ठा sshkey *to)
{
	स्थिर BIGNUM *rsa_n, *rsa_e;
	BIGNUM *rsa_n_dup = शून्य, *rsa_e_dup = शून्य;
	पूर्णांक r = SSH_ERR_INTERNAL_ERROR;
	स्थिर RSA *rsa_from;
	RSA *rsa_to = शून्य;

	अगर ((rsa_from = EVP_PKEY_get0_RSA(from->pkey)) == शून्य ||
	    (rsa_to = RSA_new()) == शून्य)
		वापस SSH_ERR_LIBCRYPTO_ERROR;

	RSA_get0_कुंजी(rsa_from, &rsa_n, &rsa_e, शून्य);
	अगर ((rsa_n_dup = BN_dup(rsa_n)) == शून्य ||
	    (rsa_e_dup = BN_dup(rsa_e)) == शून्य) {
		r = SSH_ERR_ALLOC_FAIL;
		जाओ out;
	}
	अगर (!RSA_set0_कुंजी(rsa_to, rsa_n_dup, rsa_e_dup, शून्य)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		जाओ out;
	}
	rsa_n_dup = rsa_e_dup = शून्य; /* transferred */

	अगर (EVP_PKEY_set1_RSA(to->pkey, rsa_to) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		जाओ out;
	}
	/* success */
	r = 0;
 out:
	RSA_free(rsa_to);
	BN_clear_free(rsa_n_dup);
	BN_clear_free(rsa_e_dup);
	वापस r;
}

अटल पूर्णांक
ssh_rsa_deserialize_public(स्थिर अक्षर *ktype, काष्ठा sshbuf *b,
    काष्ठा sshkey *कुंजी)
{
	पूर्णांक ret = SSH_ERR_INTERNAL_ERROR;
	BIGNUM *rsa_n = शून्य, *rsa_e = शून्य;
	RSA *rsa = शून्य;

	अगर ((rsa = RSA_new()) == शून्य)
		वापस SSH_ERR_LIBCRYPTO_ERROR;

	अगर (sshbuf_get_bignum2(b, &rsa_e) != 0 ||
	    sshbuf_get_bignum2(b, &rsa_n) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		जाओ out;
	}
	अगर (!RSA_set0_कुंजी(rsa, rsa_n, rsa_e, शून्य)) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		जाओ out;
	}
	rsa_n = rsa_e = शून्य; /* transferred */
	अगर (EVP_PKEY_set1_RSA(कुंजी->pkey, rsa) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		जाओ out;
	}
	अगर ((ret = sshkey_check_rsa_लंबाई(कुंजी, 0)) != 0)
		जाओ out;
#अगर_घोषित DEBUG_PK
	RSA_print_fp(मानक_त्रुटि, rsa, 8);
#पूर्ण_अगर
	/* success */
	ret = 0;
 out:
	RSA_free(rsa);
	BN_clear_free(rsa_n);
	BN_clear_free(rsa_e);
	वापस ret;
}

अटल पूर्णांक
ssh_rsa_deserialize_private(स्थिर अक्षर *ktype, काष्ठा sshbuf *b,
    काष्ठा sshkey *कुंजी)
{
	पूर्णांक r;
	BIGNUM *rsa_n = शून्य, *rsa_e = शून्य, *rsa_d = शून्य;
	BIGNUM *rsa_iqmp = शून्य, *rsa_p = शून्य, *rsa_q = शून्य;
	BIGNUM *rsa_dmp1 = शून्य, *rsa_dmq1 = शून्य;
	RSA *rsa = शून्य;

	अगर (sshkey_is_cert(कुंजी)) {
		/* sshkey_private_deserialize already has pubkey from cert */
		अगर ((rsa = EVP_PKEY_get1_RSA(कुंजी->pkey)) == शून्य) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			जाओ out;
		}
	} अन्यथा {
		अगर ((rsa = RSA_new()) == शून्य) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			जाओ out;
		}
		/* Note: can't reuse ssh_rsa_deserialize_public: e,n vs. n,e */
		अगर ((r = sshbuf_get_bignum2(b, &rsa_n)) != 0 ||
		    (r = sshbuf_get_bignum2(b, &rsa_e)) != 0)
			जाओ out;
		अगर (!RSA_set0_कुंजी(rsa, rsa_n, rsa_e, शून्य)) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			जाओ out;
		}
		rsa_n = rsa_e = शून्य; /* transferred */
	}
	अगर ((r = sshbuf_get_bignum2(b, &rsa_d)) != 0 ||
	    (r = sshbuf_get_bignum2(b, &rsa_iqmp)) != 0 ||
	    (r = sshbuf_get_bignum2(b, &rsa_p)) != 0 ||
	    (r = sshbuf_get_bignum2(b, &rsa_q)) != 0)
		जाओ out;
	अगर ((r = ssh_rsa_complete_crt_parameters(rsa_d, rsa_p, rsa_q,
	    rsa_iqmp, &rsa_dmp1, &rsa_dmq1)) != 0)
		जाओ out;
	अगर (!RSA_set0_कुंजी(rsa, शून्य, शून्य, rsa_d)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		जाओ out;
	}
	rsa_d = शून्य; /* transferred */
	अगर (!RSA_set0_factors(rsa, rsa_p, rsa_q)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		जाओ out;
	}
	rsa_p = rsa_q = शून्य; /* transferred */
	अगर (!RSA_set0_crt_params(rsa, rsa_dmp1, rsa_dmq1, rsa_iqmp)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		जाओ out;
	}
	rsa_dmp1 = rsa_dmq1 = rsa_iqmp = शून्य;
	अगर (RSA_blinding_on(rsa, शून्य) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		जाओ out;
	}
	अगर (EVP_PKEY_set1_RSA(कुंजी->pkey, rsa) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		जाओ out;
	}
	अगर ((r = sshkey_check_rsa_लंबाई(कुंजी, 0)) != 0)
		जाओ out;
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
	वापस r;
}

स्थिर अक्षर *
ssh_rsa_hash_alg_ident(पूर्णांक hash_alg)
{
	चयन (hash_alg) {
	हाल SSH_DIGEST_SHA1:
		वापस "ssh-rsa";
	हाल SSH_DIGEST_SHA256:
		वापस "rsa-sha2-256";
	हाल SSH_DIGEST_SHA512:
		वापस "rsa-sha2-512";
	}
	वापस शून्य;
}

/*
 * Returns the hash algorithm ID for a given algorithm identifier as used
 * inside the signature blob,
 */
अटल पूर्णांक
rsa_hash_id_from_ident(स्थिर अक्षर *ident)
{
	अगर (म_भेद(ident, "ssh-rsa") == 0)
		वापस SSH_DIGEST_SHA1;
	अगर (म_भेद(ident, "rsa-sha2-256") == 0)
		वापस SSH_DIGEST_SHA256;
	अगर (म_भेद(ident, "rsa-sha2-512") == 0)
		वापस SSH_DIGEST_SHA512;
	वापस -1;
}

/*
 * Return the hash algorithm ID for the specified key name. This includes
 * all the cases of rsa_hash_id_from_ident() but also the certificate key
 * types.
 */
पूर्णांक
ssh_rsa_hash_id_from_keyname(स्थिर अक्षर *alg)
{
	पूर्णांक r;

	अगर ((r = rsa_hash_id_from_ident(alg)) != -1)
		वापस r;
	अगर (म_भेद(alg, "ssh-rsa-cert-v01@openssh.com") == 0)
		वापस SSH_DIGEST_SHA1;
	अगर (म_भेद(alg, "rsa-sha2-256-cert-v01@openssh.com") == 0)
		वापस SSH_DIGEST_SHA256;
	अगर (म_भेद(alg, "rsa-sha2-512-cert-v01@openssh.com") == 0)
		वापस SSH_DIGEST_SHA512;
	वापस -1;
}

पूर्णांक
ssh_rsa_complete_crt_parameters(स्थिर BIGNUM *rsa_d, स्थिर BIGNUM *rsa_p,
    स्थिर BIGNUM *rsa_q, स्थिर BIGNUM *rsa_iqmp, BIGNUM **rsa_dmp1,
    BIGNUM **rsa_dmq1)
{
	BIGNUM *aux = शून्य, *d_consttime = शून्य;
	BN_CTX *ctx = शून्य;
	पूर्णांक r;

	*rsa_dmq1 = *rsa_dmp1 = शून्य;
	अगर ((ctx = BN_CTX_new()) == शून्य)
		वापस SSH_ERR_ALLOC_FAIL;
	अगर ((aux = BN_new()) == शून्य ||
	    (*rsa_dmq1 = BN_new()) == शून्य ||
	    (*rsa_dmp1 = BN_new()) == शून्य)
		वापस SSH_ERR_ALLOC_FAIL;
	अगर ((d_consttime = BN_dup(rsa_d)) == शून्य) {
		r = SSH_ERR_ALLOC_FAIL;
		जाओ out;
	}
	BN_set_flags(aux, BN_FLG_CONSTTIME);
	BN_set_flags(d_consttime, BN_FLG_CONSTTIME);

	अगर ((BN_sub(aux, rsa_q, BN_मूल्य_one()) == 0) ||
	    (BN_mod(*rsa_dmq1, d_consttime, aux, ctx) == 0) ||
	    (BN_sub(aux, rsa_p, BN_मूल्य_one()) == 0) ||
	    (BN_mod(*rsa_dmp1, d_consttime, aux, ctx) == 0)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		जाओ out;
	}
	/* success */
	r = 0;
 out:
	BN_clear_free(aux);
	BN_clear_free(d_consttime);
	BN_CTX_free(ctx);
	वापस r;
}

/* RSASSA-PKCS1-v1_5 (PKCS #1 v2.0 signature) with SHA1 */
अटल पूर्णांक
ssh_rsa_sign(काष्ठा sshkey *कुंजी,
    u_char **sigp, माप_प्रकार *lenp,
    स्थिर u_char *तथ्य, माप_प्रकार datalen,
    स्थिर अक्षर *alg, स्थिर अक्षर *sk_provider, स्थिर अक्षर *sk_pin, u_int compat)
{
	u_char *sig = शून्य;
	माप_प्रकार diff, len = 0;
	पूर्णांक slen = 0;
	पूर्णांक hash_alg, ret = SSH_ERR_INTERNAL_ERROR;

	अगर (lenp != शून्य)
		*lenp = 0;
	अगर (sigp != शून्य)
		*sigp = शून्य;

	अगर (alg == शून्य || म_माप(alg) == 0)
		hash_alg = SSH_DIGEST_SHA1;
	अन्यथा
		hash_alg = ssh_rsa_hash_id_from_keyname(alg);

	अगर (कुंजी == शून्य || कुंजी->pkey == शून्य || hash_alg == -1 ||
	    sshkey_type_plain(कुंजी->type) != कुंजी_RSA)
		वापस SSH_ERR_INVALID_ARGUMENT;
	slen = EVP_PKEY_आकार(कुंजी->pkey);
	अगर (slen <= 0 || slen > SSHBUF_MAX_BIGNUM)
		वापस SSH_ERR_INVALID_ARGUMENT;
	अगर (EVP_PKEY_bits(कुंजी->pkey) < SSH_RSA_MINIMUM_MODULUS_आकार)
		वापस SSH_ERR_कुंजी_लंबाई;

	अगर ((ret = sshkey_pkey_digest_sign(कुंजी->pkey, hash_alg, &sig, &len,
	    तथ्य, datalen)) < 0)
		जाओ out;
	अगर (len < (माप_प्रकार)slen) {
		diff = slen - len;
		स_हटाओ(sig + diff, sig, len);
		explicit_bzero(sig, diff);
	} अन्यथा अगर (len > (माप_प्रकार)slen) {
		ret = SSH_ERR_INTERNAL_ERROR;
		जाओ out;
	}
	अगर ((ret = ssh_rsa_encode_store_sig(hash_alg, sig, slen,
	    sigp, lenp)) != 0)
		जाओ out;

	/* success */
	ret = 0;
 out:
	freezero(sig, slen);
	वापस ret;
}

पूर्णांक
ssh_rsa_encode_store_sig(पूर्णांक hash_alg, स्थिर u_char *sig, माप_प्रकार slen,
    u_char **sigp, माप_प्रकार *lenp)
{
	काष्ठा sshbuf *b = शून्य;
	पूर्णांक ret = SSH_ERR_INTERNAL_ERROR;
	माप_प्रकार len;

	अगर (lenp != शून्य)
		*lenp = 0;
	अगर (sigp != शून्य)
		*sigp = शून्य;

	/* Encode signature */
	अगर ((b = sshbuf_new()) == शून्य) {
		ret = SSH_ERR_ALLOC_FAIL;
		जाओ out;
	}
	अगर ((ret = sshbuf_put_cstring(b,
	    ssh_rsa_hash_alg_ident(hash_alg))) != 0 ||
	    (ret = sshbuf_put_string(b, sig, slen)) != 0)
		जाओ out;
	len = sshbuf_len(b);

	/* Store signature */
	अगर (sigp != शून्य) {
		अगर ((*sigp = दो_स्मृति(len)) == शून्य) {
			ret = SSH_ERR_ALLOC_FAIL;
			जाओ out;
		}
		स_नकल(*sigp, sshbuf_ptr(b), len);
	}
	अगर (lenp != शून्य)
		*lenp = len;
	ret = 0;
 out:
	sshbuf_free(b);
	वापस ret;
}

अटल पूर्णांक
ssh_rsa_verify(स्थिर काष्ठा sshkey *कुंजी,
    स्थिर u_char *sig, माप_प्रकार siglen,
    स्थिर u_char *तथ्य, माप_प्रकार dlen, स्थिर अक्षर *alg, u_int compat,
    काष्ठा sshkey_sig_details **detailsp)
{
	अक्षर *sigtype = शून्य;
	पूर्णांक hash_alg, want_alg, ret = SSH_ERR_INTERNAL_ERROR;
	माप_प्रकार len = 0, diff, modlen, rsasize;
	काष्ठा sshbuf *b = शून्य;
	u_char digest[SSH_DIGEST_MAX_लंबाई], *osigblob, *sigblob = शून्य;

	अगर (कुंजी == शून्य || कुंजी->pkey == शून्य ||
	    sshkey_type_plain(कुंजी->type) != कुंजी_RSA ||
	    sig == शून्य || siglen == 0)
		वापस SSH_ERR_INVALID_ARGUMENT;
	अगर (EVP_PKEY_bits(कुंजी->pkey) < SSH_RSA_MINIMUM_MODULUS_आकार)
		वापस SSH_ERR_कुंजी_लंबाई;

	अगर ((b = sshbuf_from(sig, siglen)) == शून्य)
		वापस SSH_ERR_ALLOC_FAIL;
	अगर (sshbuf_get_cstring(b, &sigtype, शून्य) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		जाओ out;
	}
	अगर ((hash_alg = rsa_hash_id_from_ident(sigtype)) == -1) {
		ret = SSH_ERR_कुंजी_TYPE_MISMATCH;
		जाओ out;
	}
	/*
	 * Allow ssh-rsa-cert-v01 certs to generate SHA2 signatures for
	 * legacy reasons, but otherwise the signature type should match.
	 */
	अगर (alg != शून्य && म_भेद(alg, "ssh-rsa-cert-v01@openssh.com") != 0) {
		अगर ((want_alg = ssh_rsa_hash_id_from_keyname(alg)) == -1) {
			ret = SSH_ERR_INVALID_ARGUMENT;
			जाओ out;
		}
		अगर (hash_alg != want_alg) {
			ret = SSH_ERR_SIGNATURE_INVALID;
			जाओ out;
		}
	}
	अगर (sshbuf_get_string(b, &sigblob, &len) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		जाओ out;
	}
	अगर (sshbuf_len(b) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_तथ्य;
		जाओ out;
	}
	/* RSA_verify expects a signature of RSA_size */
	modlen = EVP_PKEY_आकार(कुंजी->pkey);
	अगर (len > modlen) {
		ret = SSH_ERR_कुंजी_BITS_MISMATCH;
		जाओ out;
	} अन्यथा अगर (len < modlen) {
		diff = modlen - len;
		osigblob = sigblob;
		अगर ((sigblob = पुनः_स्मृति(sigblob, modlen)) == शून्य) {
			sigblob = osigblob; /* put it back for clear/free */
			ret = SSH_ERR_ALLOC_FAIL;
			जाओ out;
		}
		स_हटाओ(sigblob + diff, sigblob, len);
		explicit_bzero(sigblob, diff);
		len = modlen;
	}

	rsasize = EVP_PKEY_आकार(कुंजी->pkey);
	अगर (rsasize <= 0 || rsasize > SSHBUF_MAX_BIGNUM ||
	    len == 0 || len > rsasize) {
		ret = SSH_ERR_INVALID_ARGUMENT;
		जाओ out;
	}
	ret = sshkey_pkey_digest_verify(कुंजी->pkey, hash_alg, तथ्य, dlen,
	    sigblob, len);

 out:
	freezero(sigblob, len);
	मुक्त(sigtype);
	sshbuf_free(b);
	explicit_bzero(digest, माप(digest));
	वापस ret;
}

अटल स्थिर काष्ठा sshkey_impl_funcs sshkey_rsa_funcs = {
	/* .size = */		ssh_rsa_आकार,
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

स्थिर काष्ठा sshkey_impl sshkey_rsa_impl = {
	/* .name = */		"ssh-rsa",
	/* .shortname = */	"RSA",
	/* .sigalg = */		शून्य,
	/* .type = */		कुंजी_RSA,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};

स्थिर काष्ठा sshkey_impl sshkey_rsa_cert_impl = {
	/* .name = */		"ssh-rsa-cert-v01@openssh.com",
	/* .shortname = */	"RSA-CERT",
	/* .sigalg = */		शून्य,
	/* .type = */		कुंजी_RSA_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};

/* SHA2 signature algorithms */

स्थिर काष्ठा sshkey_impl sshkey_rsa_sha256_impl = {
	/* .name = */		"rsa-sha2-256",
	/* .shortname = */	"RSA",
	/* .sigalg = */		शून्य,
	/* .type = */		कुंजी_RSA,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	1,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};

स्थिर काष्ठा sshkey_impl sshkey_rsa_sha512_impl = {
	/* .name = */		"rsa-sha2-512",
	/* .shortname = */	"RSA",
	/* .sigalg = */		शून्य,
	/* .type = */		कुंजी_RSA,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	1,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};

स्थिर काष्ठा sshkey_impl sshkey_rsa_sha256_cert_impl = {
	/* .name = */		"rsa-sha2-256-cert-v01@openssh.com",
	/* .shortname = */	"RSA-CERT",
	/* .sigalg = */		"rsa-sha2-256",
	/* .type = */		कुंजी_RSA_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	1,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};

स्थिर काष्ठा sshkey_impl sshkey_rsa_sha512_cert_impl = {
	/* .name = */		"rsa-sha2-512-cert-v01@openssh.com",
	/* .shortname = */	"RSA-CERT",
	/* .sigalg = */		"rsa-sha2-512",
	/* .type = */		कुंजी_RSA_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	1,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};
#पूर्ण_अगर /* WITH_OPENSSL */
