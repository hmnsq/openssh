/* $OpenBSD: ssh-ecdsa.c,v 1.29 2026/02/14 00:18:34 jsg Exp $ */
/*
 * Copyright (c) 2000 Markus Friedl.  All rights reserved.
 * Copyright (c) 2010 Damien Miller.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#अन्तर्भाव "includes.h"

#यदि defined(WITH_OPENSSL)
#अन्तर्भाव "openbsd-compat/openssl-compat.h"

#अन्तर्भाव <sys/types.h>

#अन्तर्भाव <openssl/bn.h>
#अन्तर्भाव <openssl/ec.h>
#अन्तर्भाव <openssl/ecdsa.h>
#अन्तर्भाव <openssl/evp.h>

#अन्तर्भाव <string.h>

#अन्तर्भाव "sshbuf.h"
#अन्तर्भाव "ssherr.h"
#परिभाषय SSHKEY_आन्तरिकम्
#अन्तर्भाव "sshkey.h"

पूर्णाङ्क
sshkey_ecdsa_fixup_गणः(EVP_PKEY *k)
{
	पूर्णाङ्क nids[] = {
		NID_X9_62_prime256v1,
		NID_secp384r1,
		NID_secp521r1,
		-1
	};
	पूर्णाङ्क nid = -1;
	u_int i;
	ध्रुव EC_गणः *g;
	EC_कुञ्चिका *ec = रिक्त;
	EC_गणः *eg = रिक्त;

	यदि ((ec = EVP_PKEY_get1_EC_कुञ्चिका(k)) == रिक्त ||
	    (g = EC_कुञ्चिका_get0_गणः(ec)) == रिक्त)
		गच्छ बहिर्गमनम्;
	/*
	 * The group may be stored in a ASN.1 encoded private key in one of two
	 * ways: as a "named group", which is reconstituted by ASN.1 object ID
	 * or explicit group parameters encoded into the key blob. Only the
	 * "named group" case sets the group NID for us, but we can figure
	 * it out for the other case by comparing against all the groups that
	 * are supported.
	 */
	यदि ((nid = EC_गणः_get_वक्रम्_name(g)) > 0)
		गच्छ बहिर्गमनम्;
	nid = -1;
	प्रति (i = 0; nids[i] != -1; i++) {
		यदि ((eg = EC_गणः_new_by_वक्रम्_name(nids[i])) == रिक्त)
			गच्छ बहिर्गमनम्;
		यदि (EC_गणः_cmp(g, eg, रिक्त) == 0)
			भङ्ग;
		EC_गणः_free(eg);
		eg = रिक्त;
	}
	यदि (nids[i] == -1)
		गच्छ बहिर्गमनम्;

	/* Use the group with the NID attached */
	EC_गणः_समुच्चयः_asn1_flag(eg, OPENSSL_EC_NAMED_वक्रम्);
	यदि (EC_कुञ्चिका_समुच्चयः_गणः(ec, eg) != 1 ||
	    EVP_PKEY_set1_EC_कुञ्चिका(k, ec) != 1)
		गच्छ बहिर्गमनम्;
	/* success */
	nid = nids[i];
 बहिर्गमनम्:
	EC_कुञ्चिका_free(ec);
	EC_गणः_free(eg);
	प्रत्यागम nid;
}

स्थिर u_int
ssh_ecdsa_आकार(ध्रुव संरचना sshkey *कुञ्चिका)
{
	विकल्प (कुञ्चिका->ecdsa_nid) {
	पक्ष NID_X9_62_prime256v1:
		प्रत्यागम 256;
	पक्ष NID_secp384r1:
		प्रत्यागम 384;
	पक्ष NID_secp521r1:
		प्रत्यागम 521;
	स्वभाव:
		प्रत्यागम 0;
	}
}

स्थिर शून्य
ssh_ecdsa_cleanup(संरचना sshkey *k)
{
	EVP_PKEY_free(k->pkey);
	k->pkey = रिक्त;
}

स्थिर पूर्णाङ्क
ssh_ecdsa_equal(ध्रुव संरचना sshkey *a, ध्रुव संरचना sshkey *b)
{
	यदि (a->pkey == रिक्त || b->pkey == रिक्त)
		प्रत्यागम 0;
	प्रत्यागम EVP_PKEY_cmp(a->pkey, b->pkey) == 1;
}

स्थिर पूर्णाङ्क
ssh_ecdsa_serialize_लौकिकम्(ध्रुव संरचना sshkey *कुञ्चिका, संरचना sshbuf *b,
    गणना sshkey_serialize_rep opts)
{
	पूर्णाङ्क r;

	यदि (कुञ्चिका->pkey == रिक्त)
		प्रत्यागम SSH_ERR_INVALID_तर्कः;
	यदि ((r = sshbuf_put_cstring(b,
	    sshkey_वक्रम्_nid_गन्तव्यम्_name(कुञ्चिका->ecdsa_nid))) != 0 ||
	    (r = sshbuf_put_ec_pkey(b, कुञ्चिका->pkey)) != 0)
		प्रत्यागम r;

	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
ssh_ecdsa_serialize_वैयक्तिकम्(ध्रुव संरचना sshkey *कुञ्चिका, संरचना sshbuf *b,
    गणना sshkey_serialize_rep opts)
{
	पूर्णाङ्क r;

	यदि (!sshkey_is_cert(कुञ्चिका)) {
		यदि ((r = ssh_ecdsa_serialize_लौकिकम्(कुञ्चिका, b, opts)) != 0)
			प्रत्यागम r;
	}
	यदि ((r = sshbuf_put_bignum2(b,
	    EC_कुञ्चिका_get0_वैयक्तिकम्_कुञ्चिका(EVP_PKEY_get0_EC_कुञ्चिका(कुञ्चिका->pkey)))) != 0)
		प्रत्यागम r;
	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
ssh_ecdsa_generate(संरचना sshkey *k, पूर्णाङ्क द्वयङ्काः)
{
	EVP_PKEY *res = रिक्त;
	EVP_PKEY_CTX *ctx = रिक्त;
	पूर्णाङ्क ret = SSH_ERR_आन्तरिकम्_ERROR;

	यदि ((k->ecdsa_nid = sshkey_ecdsa_द्वयङ्काः_गन्तव्यम्_nid(द्वयङ्काः)) == -1)
		प्रत्यागम SSH_ERR_कुञ्चिका_दीर्घता;

	यदि ((ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, रिक्त)) == रिक्त)
		प्रत्यागम SSH_ERR_ALLOC_FAIL;

	यदि (EVP_PKEY_keygen_init(ctx) <= 0 ||
	    EVP_PKEY_CTX_समुच्चयः_ec_paramgen_वक्रम्_nid(ctx, k->ecdsa_nid) <= 0 ||
	    EVP_PKEY_keygen(ctx, &res) <= 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		गच्छ बहिर्गमनम्;
	}
	/* success */
	k->pkey = res;
	res = रिक्त;
	ret = 0;
 बहिर्गमनम्:
	EVP_PKEY_free(res);
	EVP_PKEY_CTX_free(ctx);
	प्रत्यागम ret;
}

स्थिर पूर्णाङ्क
ssh_ecdsa_copy_लौकिकम्(ध्रुव संरचना sshkey *from, संरचना sshkey *गन्तव्यम्)
{
	ध्रुव EC_कुञ्चिका *ec_from;
	EC_कुञ्चिका *ec_गन्तव्यम् = रिक्त;
	पूर्णाङ्क ret = SSH_ERR_आन्तरिकम्_ERROR;

	ec_from = EVP_PKEY_get0_EC_कुञ्चिका(from->pkey);
	यदि (ec_from == रिक्त)
		प्रत्यागम SSH_ERR_LIBCRYPTO_ERROR;

	गन्तव्यम्->ecdsa_nid = from->ecdsa_nid;
	यदि ((ec_गन्तव्यम् = EC_कुञ्चिका_new_by_वक्रम्_name(from->ecdsa_nid)) == रिक्त)
		प्रत्यागम SSH_ERR_ALLOC_FAIL;
	यदि (EC_कुञ्चिका_समुच्चयः_लौकिकम्_कुञ्चिका(ec_गन्तव्यम्,
	    EC_कुञ्चिका_get0_लौकिकम्_कुञ्चिका(ec_from)) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		गच्छ बहिर्गमनम्;
	}
	EVP_PKEY_free(गन्तव्यम्->pkey);
	यदि ((गन्तव्यम्->pkey = EVP_PKEY_new()) == रिक्त) {
		ret = SSH_ERR_ALLOC_FAIL;
		गच्छ बहिर्गमनम्;
	}
	यदि (EVP_PKEY_set1_EC_कुञ्चिका(गन्तव्यम्->pkey, ec_गन्तव्यम्) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		गच्छ बहिर्गमनम्;
	}
	ret = 0;
 बहिर्गमनम्:
	EC_कुञ्चिका_free(ec_गन्तव्यम्);
	प्रत्यागम ret;
}

स्थिर पूर्णाङ्क
ssh_ecdsa_deserialize_लौकिकम्(ध्रुव वर्ण *ktype, संरचना sshbuf *b,
    संरचना sshkey *कुञ्चिका)
{
	पूर्णाङ्क r;
	वर्ण *वक्रम् = रिक्त;
	EVP_PKEY *pkey = रिक्त;
	EC_कुञ्चिका *ec = रिक्त;

	यदि ((कुञ्चिका->ecdsa_nid = sshkey_ecdsa_nid_from_name(ktype)) == -1)
		प्रत्यागम SSH_ERR_INVALID_तर्कः;
	यदि ((r = sshbuf_get_cstring(b, &वक्रम्, रिक्त)) != 0)
		गच्छ बहिर्गमनम्;
	यदि (कुञ्चिका->ecdsa_nid != sshkey_वक्रम्_name_गन्तव्यम्_nid(वक्रम्)) {
		r = SSH_ERR_EC_वक्रम्_MISMATCH;
		गच्छ बहिर्गमनम्;
	}
	यदि ((ec = EC_कुञ्चिका_new_by_वक्रम्_name(कुञ्चिका->ecdsa_nid)) == रिक्त) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		गच्छ बहिर्गमनम्;
	}
	यदि ((r = sshbuf_get_eckey(b, ec)) != 0)
		गच्छ बहिर्गमनम्;
	यदि (sshkey_ec_validate_लौकिकम्(EC_कुञ्चिका_get0_गणः(ec),
	    EC_कुञ्चिका_get0_लौकिकम्_कुञ्चिका(ec)) != 0) {
		r = SSH_ERR_कुञ्चिका_INVALID_EC_मानम्;
		गच्छ बहिर्गमनम्;
	}
	यदि ((pkey = EVP_PKEY_new()) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ बहिर्गमनम्;
	}
	यदि (EVP_PKEY_set1_EC_कुञ्चिका(pkey, ec) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		गच्छ बहिर्गमनम्;
	}
	EVP_PKEY_free(कुञ्चिका->pkey);
	कुञ्चिका->pkey = pkey;
	pkey = रिक्त;
	/* success */
	r = 0;
#यदि_परिभाषितम् DEBUG_PK
	sshkey_dump_ec_point(
	    EC_कुञ्चिका_get0_गणः(EVP_PKEY_get0_EC_कुञ्चिका(कुञ्चिका->pkey)),
	    EC_कुञ्चिका_get0_लौकिकम्_कुञ्चिका(EVP_PKEY_get0_EC_कुञ्चिका(कुञ्चिका->pkey)));
#यदि_अन्तः
 बहिर्गमनम्:
	EC_कुञ्चिका_free(ec);
	EVP_PKEY_free(pkey);
	मुक्त(वक्रम्);
	प्रत्यागम r;
}

स्थिर पूर्णाङ्क
ssh_ecdsa_deserialize_वैयक्तिकम्(ध्रुव वर्ण *ktype, संरचना sshbuf *b,
    संरचना sshkey *कुञ्चिका)
{
	पूर्णाङ्क r;
	BIGNUM *exponent = रिक्त;
	EC_कुञ्चिका *ec = रिक्त;

	यदि (!sshkey_is_cert(कुञ्चिका)) {
		यदि ((r = ssh_ecdsa_deserialize_लौकिकम्(ktype, b, कुञ्चिका)) != 0)
			प्रत्यागम r;
	}
	यदि ((r = sshbuf_get_bignum2(b, &exponent)) != 0)
		गच्छ बहिर्गमनम्;
	यदि ((ec = EVP_PKEY_get1_EC_कुञ्चिका(कुञ्चिका->pkey)) == रिक्त) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		गच्छ बहिर्गमनम्;
	}
	यदि (EC_कुञ्चिका_समुच्चयः_वैयक्तिकम्_कुञ्चिका(ec, exponent) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		गच्छ बहिर्गमनम्;
	}
	यदि ((r = sshkey_ec_validate_वैयक्तिकम्(ec)) != 0)
		गच्छ बहिर्गमनम्;
	यदि (EVP_PKEY_set1_EC_कुञ्चिका(कुञ्चिका->pkey, ec) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		गच्छ बहिर्गमनम्;
	}
	/* success */
	r = 0;
 बहिर्गमनम्:
	BN_clear_free(exponent);
	EC_कुञ्चिका_free(ec);
	प्रत्यागम r;
}

स्थिर पूर्णाङ्क
ssh_ecdsa_sign(संरचना sshkey *कुञ्चिका,
    u_char **sigp, आकार_t *lenp,
    ध्रुव u_char *दत्त, आकार_t dlen,
    ध्रुव वर्ण *alg, ध्रुव वर्ण *sk_provider, ध्रुव वर्ण *sk_pin, u_int compat)
{
	ECDSA_SIG *esig = रिक्त;
	अचिह्नित वर्ण *sigb = रिक्त;
	ध्रुव अचिह्नित वर्ण *psig;
	ध्रुव BIGNUM *sig_r, *sig_s;
	पूर्णाङ्क hash_alg;
	आकार_t slen = 0;
	पूर्णाङ्क ret = SSH_ERR_आन्तरिकम्_ERROR;

	यदि (lenp != रिक्त)
		*lenp = 0;
	यदि (sigp != रिक्त)
		*sigp = रिक्त;

	यदि (कुञ्चिका == रिक्त || कुञ्चिका->pkey == रिक्त ||
	    sshkey_type_plain(कुञ्चिका->type) != कुञ्चिका_ECDSA)
		प्रत्यागम SSH_ERR_INVALID_तर्कः;

	यदि ((hash_alg = sshkey_ec_nid_गन्तव्यम्_hash_alg(कुञ्चिका->ecdsa_nid)) == -1)
		प्रत्यागम SSH_ERR_आन्तरिकम्_ERROR;

	यदि ((ret = sshkey_pkey_digest_sign(कुञ्चिका->pkey, hash_alg, &sigb, &slen,
	    दत्त, dlen)) != 0)
		गच्छ बहिर्गमनम्;

	psig = sigb;
	यदि ((esig = d2i_ECDSA_SIG(रिक्त, &psig, slen)) == रिक्त) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		गच्छ बहिर्गमनम्;
	}
	ECDSA_SIG_get0(esig, &sig_r, &sig_s);

	यदि ((ret = ssh_ecdsa_encode_store_sig(कुञ्चिका, sig_r, sig_s,
	    sigp, lenp)) != 0)
		गच्छ बहिर्गमनम्;
	/* success */
	ret = 0;
 बहिर्गमनम्:
	freezero(sigb, slen);
	ECDSA_SIG_free(esig);
	प्रत्यागम ret;
}

पूर्णाङ्क
ssh_ecdsa_encode_store_sig(ध्रुव संरचना sshkey *कुञ्चिका,
    ध्रुव BIGNUM *sig_r, ध्रुव BIGNUM *sig_s,
    u_char **sigp, आकार_t *lenp)
{
	संरचना sshbuf *b = रिक्त, *bb = रिक्त;
	पूर्णाङ्क ret;
	आकार_t len;

	यदि (lenp != रिक्त)
		*lenp = 0;
	यदि (sigp != रिक्त)
		*sigp = रिक्त;

	यदि ((bb = sshbuf_new()) == रिक्त || (b = sshbuf_new()) == रिक्त) {
		ret = SSH_ERR_ALLOC_FAIL;
		गच्छ बहिर्गमनम्;
	}
	यदि ((ret = sshbuf_put_bignum2(bb, sig_r)) != 0 ||
	    (ret = sshbuf_put_bignum2(bb, sig_s)) != 0)
		गच्छ बहिर्गमनम्;
	यदि ((ret = sshbuf_put_cstring(b, sshkey_ssh_name_plain(कुञ्चिका))) != 0 ||
	    (ret = sshbuf_put_stringb(b, bb)) != 0)
		गच्छ बहिर्गमनम्;
	len = sshbuf_len(b);
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
	sshbuf_free(bb);
	प्रत्यागम ret;
}

स्थिर पूर्णाङ्क
ssh_ecdsa_verify(ध्रुव संरचना sshkey *कुञ्चिका,
    ध्रुव u_char *sig, आकार_t siglen,
    ध्रुव u_char *दत्त, आकार_t dlen, ध्रुव वर्ण *alg, u_int compat,
    संरचना sshkey_sig_details **detailsp)
{
	ECDSA_SIG *esig = रिक्त;
	BIGNUM *sig_r = रिक्त, *sig_s = रिक्त;
	पूर्णाङ्क hash_alg, len = 0;
	पूर्णाङ्क ret = SSH_ERR_आन्तरिकम्_ERROR;
	संरचना sshbuf *b = रिक्त, *sigbuf = रिक्त;
	वर्ण *ktype = रिक्त;
	अचिह्नित वर्ण *sigb = रिक्त, *cp;

	यदि (कुञ्चिका == रिक्त || कुञ्चिका->pkey == रिक्त ||
	    sshkey_type_plain(कुञ्चिका->type) != कुञ्चिका_ECDSA ||
	    sig == रिक्त || siglen == 0)
		प्रत्यागम SSH_ERR_INVALID_तर्कः;

	यदि ((hash_alg = sshkey_ec_nid_गन्तव्यम्_hash_alg(कुञ्चिका->ecdsa_nid)) == -1)
		प्रत्यागम SSH_ERR_आन्तरिकम्_ERROR;

	/* fetch signature */
	यदि ((b = sshbuf_from(sig, siglen)) == रिक्त)
		प्रत्यागम SSH_ERR_ALLOC_FAIL;
	यदि (sshbuf_get_cstring(b, &ktype, रिक्त) != 0 ||
	    sshbuf_froms(b, &sigbuf) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		गच्छ बहिर्गमनम्;
	}
	यदि (वाक्यं_तुलय(sshkey_ssh_name_plain(कुञ्चिका), ktype) != 0) {
		ret = SSH_ERR_कुञ्चिका_TYPE_MISMATCH;
		गच्छ बहिर्गमनम्;
	}
	यदि (sshbuf_len(b) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_दत्त;
		गच्छ बहिर्गमनम्;
	}

	/* parse signature */
	यदि (sshbuf_get_bignum2(sigbuf, &sig_r) != 0 ||
	    sshbuf_get_bignum2(sigbuf, &sig_s) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		गच्छ बहिर्गमनम्;
	}
	यदि (sshbuf_len(sigbuf) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_दत्त;
		गच्छ बहिर्गमनम्;
	}

	यदि ((esig = ECDSA_SIG_new()) == रिक्त) {
		ret = SSH_ERR_ALLOC_FAIL;
		गच्छ बहिर्गमनम्;
	}
	यदि (!ECDSA_SIG_set0(esig, sig_r, sig_s)) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		गच्छ बहिर्गमनम्;
	}
	sig_r = sig_s = रिक्त; /* transferred */

	यदि ((len = i2d_ECDSA_SIG(esig, रिक्त)) <= 0) {
		len = 0;
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		गच्छ बहिर्गमनम्;
	}
	यदि ((sigb = शून्यस्मृतिं_देहि(1, len)) == रिक्त) {
		ret = SSH_ERR_ALLOC_FAIL;
		गच्छ बहिर्गमनम्;
	}
	cp = sigb; /* ASN1_item_i2d increments the pointer past the object */
	यदि (i2d_ECDSA_SIG(esig, &cp) != len) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		गच्छ बहिर्गमनम्;
	}
	यदि ((ret = sshkey_pkey_digest_verify(कुञ्चिका->pkey, hash_alg,
	    दत्त, dlen, sigb, len)) != 0)
		गच्छ बहिर्गमनम्;
	/* success */
 बहिर्गमनम्:
	freezero(sigb, len);
	sshbuf_free(sigbuf);
	sshbuf_free(b);
	ECDSA_SIG_free(esig);
	BN_clear_free(sig_r);
	BN_clear_free(sig_s);
	मुक्त(ktype);
	प्रत्यागम ret;
}

/* NB. not static; used by ECDSA-SK */
ध्रुव संरचना sshkey_impl_funcs sshkey_ecdsa_funcs = {
	/* .size = */		ssh_ecdsa_आकार,
	/* .alloc = */		रिक्त,
	/* .cleanup = */	ssh_ecdsa_cleanup,
	/* .equal = */		ssh_ecdsa_equal,
	/* .ssh_serialize_public = */ ssh_ecdsa_serialize_लौकिकम्,
	/* .ssh_deserialize_public = */ ssh_ecdsa_deserialize_लौकिकम्,
	/* .ssh_serialize_private = */ ssh_ecdsa_serialize_वैयक्तिकम्,
	/* .ssh_deserialize_private = */ ssh_ecdsa_deserialize_वैयक्तिकम्,
	/* .generate = */	ssh_ecdsa_generate,
	/* .copy_public = */	ssh_ecdsa_copy_लौकिकम्,
	/* .sign = */		ssh_ecdsa_sign,
	/* .verify = */		ssh_ecdsa_verify,
};

ध्रुव संरचना sshkey_impl sshkey_ecdsa_nistp256_impl = {
	/* .name = */		"ecdsa-sha2-nistp256",
	/* .shortname = */	"ECDSA",
	/* .sigalg = */		रिक्त,
	/* .type = */		कुञ्चिका_ECDSA,
	/* .nid = */		NID_X9_62_prime256v1,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

ध्रुव संरचना sshkey_impl sshkey_ecdsa_nistp256_cert_impl = {
	/* .name = */		"ecdsa-sha2-nistp256-cert-v01@openssh.com",
	/* .shortname = */	"ECDSA-CERT",
	/* .sigalg = */		रिक्त,
	/* .type = */		कुञ्चिका_ECDSA_CERT,
	/* .nid = */		NID_X9_62_prime256v1,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

ध्रुव संरचना sshkey_impl sshkey_ecdsa_nistp384_impl = {
	/* .name = */		"ecdsa-sha2-nistp384",
	/* .shortname = */	"ECDSA",
	/* .sigalg = */		रिक्त,
	/* .type = */		कुञ्चिका_ECDSA,
	/* .nid = */		NID_secp384r1,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

ध्रुव संरचना sshkey_impl sshkey_ecdsa_nistp384_cert_impl = {
	/* .name = */		"ecdsa-sha2-nistp384-cert-v01@openssh.com",
	/* .shortname = */	"ECDSA-CERT",
	/* .sigalg = */		रिक्त,
	/* .type = */		कुञ्चिका_ECDSA_CERT,
	/* .nid = */		NID_secp384r1,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

ध्रुव संरचना sshkey_impl sshkey_ecdsa_nistp521_impl = {
	/* .name = */		"ecdsa-sha2-nistp521",
	/* .shortname = */	"ECDSA",
	/* .sigalg = */		रिक्त,
	/* .type = */		कुञ्चिका_ECDSA,
	/* .nid = */		NID_secp521r1,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

ध्रुव संरचना sshkey_impl sshkey_ecdsa_nistp521_cert_impl = {
	/* .name = */		"ecdsa-sha2-nistp521-cert-v01@openssh.com",
	/* .shortname = */	"ECDSA-CERT",
	/* .sigalg = */		रिक्त,
	/* .type = */		कुञ्चिका_ECDSA_CERT,
	/* .nid = */		NID_secp521r1,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

#यदि_अन्तः /* WITH_OPENSSL */
