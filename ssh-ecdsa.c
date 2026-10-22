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

#सचे defined(WITH_OPENSSL)
#अन्तर्भाव "openbsd-compat/openssl-compat.h"

#अन्तर्भाव <sys/types.h>

#अन्तर्भाव <openssl/bn.h>
#अन्तर्भाव <openssl/ec.h>
#अन्तर्भाव <openssl/ecdsa.h>
#अन्तर्भाव <openssl/evp.h>

#अन्तर्भाव <string.h>

#अन्तर्भाव "sshbuf.h"
#अन्तर्भाव "ssherr.h"
#define SSHKEY_INTERNAL
#अन्तर्भाव "sshkey.h"

पूर्णाङ्क
sshkey_ecdsa_fixup_group(EVP_PKEY *k)
{
	पूर्णाङ्क nids[] = {
		NID_X9_62_prime256v1,
		NID_secp384r1,
		NID_secp521r1,
		-1
	};
	पूर्णाङ्क nid = -1;
	u_int i;
	ध्रुव EC_GROUP *g;
	EC_कुञ्चिका *ec = रिक्त;
	EC_GROUP *eg = रिक्त;

	सचे ((ec = EVP_PKEY_get1_EC_कुञ्चिका(k)) == रिक्त ||
	    (g = EC_कुञ्चिका_get0_group(ec)) == रिक्त)
		गच्छ out;
	/*
	 * The group may be stored in a ASN.1 encoded private key in one of two
	 * ways: as a "named group", which is reconstituted by ASN.1 object ID
	 * or explicit group parameters encoded into the key blob. Only the
	 * "named group" case sets the group NID for us, but we can figure
	 * it out for the other case by comparing against all the groups that
	 * are supported.
	 */
	सचे ((nid = EC_GROUP_get_curve_name(g)) > 0)
		गच्छ out;
	nid = -1;
	अत्थाय (i = 0; nids[i] != -1; i++) {
		सचे ((eg = EC_GROUP_new_by_curve_name(nids[i])) == रिक्त)
			गच्छ out;
		सचे (EC_GROUP_cmp(g, eg, रिक्त) == 0)
			भङ्ग;
		EC_GROUP_free(eg);
		eg = रिक्त;
	}
	सचे (nids[i] == -1)
		गच्छ out;

	/* Use the group with the NID attached */
	EC_GROUP_set_asn1_flag(eg, OPENSSL_EC_NAMED_CURVE);
	सचे (EC_कुञ्चिका_set_group(ec, eg) != 1 ||
	    EVP_PKEY_set1_EC_कुञ्चिका(k, ec) != 1)
		गच्छ out;
	/* success */
	nid = nids[i];
 out:
	EC_कुञ्चिका_free(ec);
	EC_GROUP_free(eg);
	पटिनिवत्त nid;
}

स्थिर u_int
ssh_ecdsa_size(ध्रुव संरचना sshkey *कुञ्चिका)
{
	विकल्प (कुञ्चिका->ecdsa_nid) {
	पक्ष NID_X9_62_prime256v1:
		पटिनिवत्त 256;
	पक्ष NID_secp384r1:
		पटिनिवत्त 384;
	पक्ष NID_secp521r1:
		पटिनिवत्त 521;
	स्वभाव:
		पटिनिवत्त 0;
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
	सचे (a->pkey == रिक्त || b->pkey == रिक्त)
		पटिनिवत्त 0;
	पटिनिवत्त EVP_PKEY_cmp(a->pkey, b->pkey) == 1;
}

स्थिर पूर्णाङ्क
ssh_ecdsa_serialize_public(ध्रुव संरचना sshkey *कुञ्चिका, संरचना sshbuf *b,
    गणना sshkey_serialize_rep opts)
{
	पूर्णाङ्क r;

	सचे (कुञ्चिका->pkey == रिक्त)
		पटिनिवत्त SSH_ERR_INVALID_ARGUMENT;
	सचे ((r = sshbuf_put_cstring(b,
	    sshkey_curve_nid_to_name(कुञ्चिका->ecdsa_nid))) != 0 ||
	    (r = sshbuf_put_ec_pkey(b, कुञ्चिका->pkey)) != 0)
		पटिनिवत्त r;

	पटिनिवत्त 0;
}

स्थिर पूर्णाङ्क
ssh_ecdsa_serialize_private(ध्रुव संरचना sshkey *कुञ्चिका, संरचना sshbuf *b,
    गणना sshkey_serialize_rep opts)
{
	पूर्णाङ्क r;

	सचे (!sshkey_is_cert(कुञ्चिका)) {
		सचे ((r = ssh_ecdsa_serialize_public(कुञ्चिका, b, opts)) != 0)
			पटिनिवत्त r;
	}
	सचे ((r = sshbuf_put_bignum2(b,
	    EC_कुञ्चिका_get0_private_कुञ्चिका(EVP_PKEY_get0_EC_कुञ्चिका(कुञ्चिका->pkey)))) != 0)
		पटिनिवत्त r;
	पटिनिवत्त 0;
}

स्थिर पूर्णाङ्क
ssh_ecdsa_generate(संरचना sshkey *k, पूर्णाङ्क bits)
{
	EVP_PKEY *res = रिक्त;
	EVP_PKEY_CTX *ctx = रिक्त;
	पूर्णाङ्क ret = SSH_ERR_INTERNAL_ERROR;

	सचे ((k->ecdsa_nid = sshkey_ecdsa_bits_to_nid(bits)) == -1)
		पटिनिवत्त SSH_ERR_कुञ्चिका_LENGTH;

	सचे ((ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, रिक्त)) == रिक्त)
		पटिनिवत्त SSH_ERR_ALLOC_FAIL;

	सचे (EVP_PKEY_keygen_init(ctx) <= 0 ||
	    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, k->ecdsa_nid) <= 0 ||
	    EVP_PKEY_keygen(ctx, &res) <= 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		गच्छ out;
	}
	/* success */
	k->pkey = res;
	res = रिक्त;
	ret = 0;
 out:
	EVP_PKEY_free(res);
	EVP_PKEY_CTX_free(ctx);
	पटिनिवत्त ret;
}

स्थिर पूर्णाङ्क
ssh_ecdsa_copy_public(ध्रुव संरचना sshkey *from, संरचना sshkey *to)
{
	ध्रुव EC_कुञ्चिका *ec_from;
	EC_कुञ्चिका *ec_to = रिक्त;
	पूर्णाङ्क ret = SSH_ERR_INTERNAL_ERROR;

	ec_from = EVP_PKEY_get0_EC_कुञ्चिका(from->pkey);
	सचे (ec_from == रिक्त)
		पटिनिवत्त SSH_ERR_LIBCRYPTO_ERROR;

	to->ecdsa_nid = from->ecdsa_nid;
	सचे ((ec_to = EC_कुञ्चिका_new_by_curve_name(from->ecdsa_nid)) == रिक्त)
		पटिनिवत्त SSH_ERR_ALLOC_FAIL;
	सचे (EC_कुञ्चिका_set_public_कुञ्चिका(ec_to,
	    EC_कुञ्चिका_get0_public_कुञ्चिका(ec_from)) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		गच्छ out;
	}
	EVP_PKEY_free(to->pkey);
	सचे ((to->pkey = EVP_PKEY_new()) == रिक्त) {
		ret = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	सचे (EVP_PKEY_set1_EC_कुञ्चिका(to->pkey, ec_to) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		गच्छ out;
	}
	ret = 0;
 out:
	EC_कुञ्चिका_free(ec_to);
	पटिनिवत्त ret;
}

स्थिर पूर्णाङ्क
ssh_ecdsa_deserialize_public(ध्रुव वर्ण *ktype, संरचना sshbuf *b,
    संरचना sshkey *कुञ्चिका)
{
	पूर्णाङ्क r;
	वर्ण *curve = रिक्त;
	EVP_PKEY *pkey = रिक्त;
	EC_कुञ्चिका *ec = रिक्त;

	सचे ((कुञ्चिका->ecdsa_nid = sshkey_ecdsa_nid_from_name(ktype)) == -1)
		पटिनिवत्त SSH_ERR_INVALID_ARGUMENT;
	सचे ((r = sshbuf_get_cstring(b, &curve, रिक्त)) != 0)
		गच्छ out;
	सचे (कुञ्चिका->ecdsa_nid != sshkey_curve_name_to_nid(curve)) {
		r = SSH_ERR_EC_CURVE_MISMATCH;
		गच्छ out;
	}
	सचे ((ec = EC_कुञ्चिका_new_by_curve_name(कुञ्चिका->ecdsa_nid)) == रिक्त) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		गच्छ out;
	}
	सचे ((r = sshbuf_get_eckey(b, ec)) != 0)
		गच्छ out;
	सचे (sshkey_ec_validate_public(EC_कुञ्चिका_get0_group(ec),
	    EC_कुञ्चिका_get0_public_कुञ्चिका(ec)) != 0) {
		r = SSH_ERR_कुञ्चिका_INVALID_EC_मानम्;
		गच्छ out;
	}
	सचे ((pkey = EVP_PKEY_new()) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	सचे (EVP_PKEY_set1_EC_कुञ्चिका(pkey, ec) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		गच्छ out;
	}
	EVP_PKEY_free(कुञ्चिका->pkey);
	कुञ्चिका->pkey = pkey;
	pkey = रिक्त;
	/* success */
	r = 0;
#ifdef DEBUG_PK
	sshkey_dump_ec_point(
	    EC_कुञ्चिका_get0_group(EVP_PKEY_get0_EC_कुञ्चिका(कुञ्चिका->pkey)),
	    EC_कुञ्चिका_get0_public_कुञ्चिका(EVP_PKEY_get0_EC_कुञ्चिका(कुञ्चिका->pkey)));
#endif
 out:
	EC_कुञ्चिका_free(ec);
	EVP_PKEY_free(pkey);
	मुक्त(curve);
	पटिनिवत्त r;
}

स्थिर पूर्णाङ्क
ssh_ecdsa_deserialize_private(ध्रुव वर्ण *ktype, संरचना sshbuf *b,
    संरचना sshkey *कुञ्चिका)
{
	पूर्णाङ्क r;
	BIGNUM *exponent = रिक्त;
	EC_कुञ्चिका *ec = रिक्त;

	सचे (!sshkey_is_cert(कुञ्चिका)) {
		सचे ((r = ssh_ecdsa_deserialize_public(ktype, b, कुञ्चिका)) != 0)
			पटिनिवत्त r;
	}
	सचे ((r = sshbuf_get_bignum2(b, &exponent)) != 0)
		गच्छ out;
	सचे ((ec = EVP_PKEY_get1_EC_कुञ्चिका(कुञ्चिका->pkey)) == रिक्त) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		गच्छ out;
	}
	सचे (EC_कुञ्चिका_set_private_कुञ्चिका(ec, exponent) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		गच्छ out;
	}
	सचे ((r = sshkey_ec_validate_private(ec)) != 0)
		गच्छ out;
	सचे (EVP_PKEY_set1_EC_कुञ्चिका(कुञ्चिका->pkey, ec) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		गच्छ out;
	}
	/* success */
	r = 0;
 out:
	BN_clear_free(exponent);
	EC_कुञ्चिका_free(ec);
	पटिनिवत्त r;
}

स्थिर पूर्णाङ्क
ssh_ecdsa_sign(संरचना sshkey *कुञ्चिका,
    u_char **sigp, size_t *lenp,
    ध्रुव u_char *data, size_t dlen,
    ध्रुव वर्ण *alg, ध्रुव वर्ण *sk_provider, ध्रुव वर्ण *sk_pin, u_int compat)
{
	ECDSA_SIG *esig = रिक्त;
	unsigned वर्ण *sigb = रिक्त;
	ध्रुव unsigned वर्ण *psig;
	ध्रुव BIGNUM *sig_r, *sig_s;
	पूर्णाङ्क hash_alg;
	size_t slen = 0;
	पूर्णाङ्क ret = SSH_ERR_INTERNAL_ERROR;

	सचे (lenp != रिक्त)
		*lenp = 0;
	सचे (sigp != रिक्त)
		*sigp = रिक्त;

	सचे (कुञ्चिका == रिक्त || कुञ्चिका->pkey == रिक्त ||
	    sshkey_type_plain(कुञ्चिका->type) != कुञ्चिका_ECDSA)
		पटिनिवत्त SSH_ERR_INVALID_ARGUMENT;

	सचे ((hash_alg = sshkey_ec_nid_to_hash_alg(कुञ्चिका->ecdsa_nid)) == -1)
		पटिनिवत्त SSH_ERR_INTERNAL_ERROR;

	सचे ((ret = sshkey_pkey_digest_sign(कुञ्चिका->pkey, hash_alg, &sigb, &slen,
	    data, dlen)) != 0)
		गच्छ out;

	psig = sigb;
	सचे ((esig = d2i_ECDSA_SIG(रिक्त, &psig, slen)) == रिक्त) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		गच्छ out;
	}
	ECDSA_SIG_get0(esig, &sig_r, &sig_s);

	सचे ((ret = ssh_ecdsa_encode_store_sig(कुञ्चिका, sig_r, sig_s,
	    sigp, lenp)) != 0)
		गच्छ out;
	/* success */
	ret = 0;
 out:
	freezero(sigb, slen);
	ECDSA_SIG_free(esig);
	पटिनिवत्त ret;
}

पूर्णाङ्क
ssh_ecdsa_encode_store_sig(ध्रुव संरचना sshkey *कुञ्चिका,
    ध्रुव BIGNUM *sig_r, ध्रुव BIGNUM *sig_s,
    u_char **sigp, size_t *lenp)
{
	संरचना sshbuf *b = रिक्त, *bb = रिक्त;
	पूर्णाङ्क ret;
	size_t len;

	सचे (lenp != रिक्त)
		*lenp = 0;
	सचे (sigp != रिक्त)
		*sigp = रिक्त;

	सचे ((bb = sshbuf_new()) == रिक्त || (b = sshbuf_new()) == रिक्त) {
		ret = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	सचे ((ret = sshbuf_put_bignum2(bb, sig_r)) != 0 ||
	    (ret = sshbuf_put_bignum2(bb, sig_s)) != 0)
		गच्छ out;
	सचे ((ret = sshbuf_put_cstring(b, sshkey_ssh_name_plain(कुञ्चिका))) != 0 ||
	    (ret = sshbuf_put_stringb(b, bb)) != 0)
		गच्छ out;
	len = sshbuf_len(b);
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
	sshbuf_free(bb);
	पटिनिवत्त ret;
}

स्थिर पूर्णाङ्क
ssh_ecdsa_verify(ध्रुव संरचना sshkey *कुञ्चिका,
    ध्रुव u_char *sig, size_t siglen,
    ध्रुव u_char *data, size_t dlen, ध्रुव वर्ण *alg, u_int compat,
    संरचना sshkey_sig_details **detailsp)
{
	ECDSA_SIG *esig = रिक्त;
	BIGNUM *sig_r = रिक्त, *sig_s = रिक्त;
	पूर्णाङ्क hash_alg, len = 0;
	पूर्णाङ्क ret = SSH_ERR_INTERNAL_ERROR;
	संरचना sshbuf *b = रिक्त, *sigbuf = रिक्त;
	वर्ण *ktype = रिक्त;
	unsigned वर्ण *sigb = रिक्त, *cp;

	सचे (कुञ्चिका == रिक्त || कुञ्चिका->pkey == रिक्त ||
	    sshkey_type_plain(कुञ्चिका->type) != कुञ्चिका_ECDSA ||
	    sig == रिक्त || siglen == 0)
		पटिनिवत्त SSH_ERR_INVALID_ARGUMENT;

	सचे ((hash_alg = sshkey_ec_nid_to_hash_alg(कुञ्चिका->ecdsa_nid)) == -1)
		पटिनिवत्त SSH_ERR_INTERNAL_ERROR;

	/* fetch signature */
	सचे ((b = sshbuf_from(sig, siglen)) == रिक्त)
		पटिनिवत्त SSH_ERR_ALLOC_FAIL;
	सचे (sshbuf_get_cstring(b, &ktype, रिक्त) != 0 ||
	    sshbuf_froms(b, &sigbuf) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		गच्छ out;
	}
	सचे (strcmp(sshkey_ssh_name_plain(कुञ्चिका), ktype) != 0) {
		ret = SSH_ERR_कुञ्चिका_TYPE_MISMATCH;
		गच्छ out;
	}
	सचे (sshbuf_len(b) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		गच्छ out;
	}

	/* parse signature */
	सचे (sshbuf_get_bignum2(sigbuf, &sig_r) != 0 ||
	    sshbuf_get_bignum2(sigbuf, &sig_s) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		गच्छ out;
	}
	सचे (sshbuf_len(sigbuf) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		गच्छ out;
	}

	सचे ((esig = ECDSA_SIG_new()) == रिक्त) {
		ret = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	सचे (!ECDSA_SIG_set0(esig, sig_r, sig_s)) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		गच्छ out;
	}
	sig_r = sig_s = रिक्त; /* transferred */

	सचे ((len = i2d_ECDSA_SIG(esig, रिक्त)) <= 0) {
		len = 0;
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		गच्छ out;
	}
	सचे ((sigb = calloc(1, len)) == रिक्त) {
		ret = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	cp = sigb; /* ASN1_item_i2d increments the pointer past the object */
	सचे (i2d_ECDSA_SIG(esig, &cp) != len) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		गच्छ out;
	}
	सचे ((ret = sshkey_pkey_digest_verify(कुञ्चिका->pkey, hash_alg,
	    data, dlen, sigb, len)) != 0)
		गच्छ out;
	/* success */
 out:
	freezero(sigb, len);
	sshbuf_free(sigbuf);
	sshbuf_free(b);
	ECDSA_SIG_free(esig);
	BN_clear_free(sig_r);
	BN_clear_free(sig_s);
	मुक्त(ktype);
	पटिनिवत्त ret;
}

/* NB. not static; used by ECDSA-SK */
ध्रुव संरचना sshkey_impl_funcs sshkey_ecdsa_funcs = {
	/* .size = */		ssh_ecdsa_size,
	/* .alloc = */		रिक्त,
	/* .cleanup = */	ssh_ecdsa_cleanup,
	/* .equal = */		ssh_ecdsa_equal,
	/* .ssh_serialize_public = */ ssh_ecdsa_serialize_public,
	/* .ssh_deserialize_public = */ ssh_ecdsa_deserialize_public,
	/* .ssh_serialize_private = */ ssh_ecdsa_serialize_private,
	/* .ssh_deserialize_private = */ ssh_ecdsa_deserialize_private,
	/* .generate = */	ssh_ecdsa_generate,
	/* .copy_public = */	ssh_ecdsa_copy_public,
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

#endif /* WITH_OPENSSL */
