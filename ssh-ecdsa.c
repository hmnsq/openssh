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

#जर defined(WITH_OPENSSL)
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

पूर्णांक
sshkey_ecdsa_fixup_group(EVP_PKEY *k)
{
	पूर्णांक nids[] = {
		NID_X9_62_prime256v1,
		NID_secp384r1,
		NID_secp521r1,
		-1
	};
	पूर्णांक nid = -1;
	u_int i;
	स्थिरांक EC_GROUP *g;
	EC_किल्ली *ec = रिक्त;
	EC_GROUP *eg = रिक्त;

	जर ((ec = EVP_PKEY_get1_EC_किल्ली(k)) == रिक्त ||
	    (g = EC_किल्ली_get0_group(ec)) == रिक्त)
		जा out;
	/*
	 * The group may be stored in a ASN.1 encoded private key in one of two
	 * ways: as a "named group", which is reconstituted by ASN.1 object ID
	 * or explicit group parameters encoded into the key blob. Only the
	 * "named group" case sets the group NID for us, but we can figure
	 * it out for the other case by comparing against all the groups that
	 * are supported.
	 */
	जर ((nid = EC_GROUP_get_curve_name(g)) > 0)
		जा out;
	nid = -1;
	साठी (i = 0; nids[i] != -1; i++) {
		जर ((eg = EC_GROUP_new_by_curve_name(nids[i])) == रिक्त)
			जा out;
		जर (EC_GROUP_cmp(g, eg, रिक्त) == 0)
			थांबा;
		EC_GROUP_free(eg);
		eg = रिक्त;
	}
	जर (nids[i] == -1)
		जा out;

	/* Use the group with the NID attached */
	EC_GROUP_set_asn1_flag(eg, OPENSSL_EC_NAMED_CURVE);
	जर (EC_किल्ली_set_group(ec, eg) != 1 ||
	    EVP_PKEY_set1_EC_किल्ली(k, ec) != 1)
		जा out;
	/* success */
	nid = nids[i];
 out:
	EC_किल्ली_free(ec);
	EC_GROUP_free(eg);
	परत nid;
}

स्थिर u_int
ssh_ecdsa_size(स्थिरांक संरचना sshkey *किल्ली)
{
	निवड (किल्ली->ecdsa_nid) {
	स्थिती NID_X9_62_prime256v1:
		परत 256;
	स्थिती NID_secp384r1:
		परत 384;
	स्थिती NID_secp521r1:
		परत 521;
	पूर्वनिर्धारित:
		परत 0;
	}
}

स्थिर शून्य
ssh_ecdsa_cleanup(संरचना sshkey *k)
{
	EVP_PKEY_free(k->pkey);
	k->pkey = रिक्त;
}

स्थिर पूर्णांक
ssh_ecdsa_equal(स्थिरांक संरचना sshkey *a, स्थिरांक संरचना sshkey *b)
{
	जर (a->pkey == रिक्त || b->pkey == रिक्त)
		परत 0;
	परत EVP_PKEY_cmp(a->pkey, b->pkey) == 1;
}

स्थिर पूर्णांक
ssh_ecdsa_serialize_public(स्थिरांक संरचना sshkey *किल्ली, संरचना sshbuf *b,
    गणना sshkey_serialize_rep opts)
{
	पूर्णांक r;

	जर (किल्ली->pkey == रिक्त)
		परत SSH_ERR_INVALID_ARGUMENT;
	जर ((r = sshbuf_put_cstring(b,
	    sshkey_curve_nid_to_name(किल्ली->ecdsa_nid))) != 0 ||
	    (r = sshbuf_put_ec_pkey(b, किल्ली->pkey)) != 0)
		परत r;

	परत 0;
}

स्थिर पूर्णांक
ssh_ecdsa_serialize_private(स्थिरांक संरचना sshkey *किल्ली, संरचना sshbuf *b,
    गणना sshkey_serialize_rep opts)
{
	पूर्णांक r;

	जर (!sshkey_is_cert(किल्ली)) {
		जर ((r = ssh_ecdsa_serialize_public(किल्ली, b, opts)) != 0)
			परत r;
	}
	जर ((r = sshbuf_put_bignum2(b,
	    EC_किल्ली_get0_private_किल्ली(EVP_PKEY_get0_EC_किल्ली(किल्ली->pkey)))) != 0)
		परत r;
	परत 0;
}

स्थिर पूर्णांक
ssh_ecdsa_generate(संरचना sshkey *k, पूर्णांक bits)
{
	EVP_PKEY *res = रिक्त;
	EVP_PKEY_CTX *ctx = रिक्त;
	पूर्णांक ret = SSH_ERR_INTERNAL_ERROR;

	जर ((k->ecdsa_nid = sshkey_ecdsa_bits_to_nid(bits)) == -1)
		परत SSH_ERR_किल्ली_LENGTH;

	जर ((ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, रिक्त)) == रिक्त)
		परत SSH_ERR_ALLOC_FAIL;

	जर (EVP_PKEY_keygen_init(ctx) <= 0 ||
	    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, k->ecdsa_nid) <= 0 ||
	    EVP_PKEY_keygen(ctx, &res) <= 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		जा out;
	}
	/* success */
	k->pkey = res;
	res = रिक्त;
	ret = 0;
 out:
	EVP_PKEY_free(res);
	EVP_PKEY_CTX_free(ctx);
	परत ret;
}

स्थिर पूर्णांक
ssh_ecdsa_copy_public(स्थिरांक संरचना sshkey *from, संरचना sshkey *to)
{
	स्थिरांक EC_किल्ली *ec_from;
	EC_किल्ली *ec_to = रिक्त;
	पूर्णांक ret = SSH_ERR_INTERNAL_ERROR;

	ec_from = EVP_PKEY_get0_EC_किल्ली(from->pkey);
	जर (ec_from == रिक्त)
		परत SSH_ERR_LIBCRYPTO_ERROR;

	to->ecdsa_nid = from->ecdsa_nid;
	जर ((ec_to = EC_किल्ली_new_by_curve_name(from->ecdsa_nid)) == रिक्त)
		परत SSH_ERR_ALLOC_FAIL;
	जर (EC_किल्ली_set_public_किल्ली(ec_to,
	    EC_किल्ली_get0_public_किल्ली(ec_from)) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		जा out;
	}
	EVP_PKEY_free(to->pkey);
	जर ((to->pkey = EVP_PKEY_new()) == रिक्त) {
		ret = SSH_ERR_ALLOC_FAIL;
		जा out;
	}
	जर (EVP_PKEY_set1_EC_किल्ली(to->pkey, ec_to) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		जा out;
	}
	ret = 0;
 out:
	EC_किल्ली_free(ec_to);
	परत ret;
}

स्थिर पूर्णांक
ssh_ecdsa_deserialize_public(स्थिरांक अक्षर *ktype, संरचना sshbuf *b,
    संरचना sshkey *किल्ली)
{
	पूर्णांक r;
	अक्षर *curve = रिक्त;
	EVP_PKEY *pkey = रिक्त;
	EC_किल्ली *ec = रिक्त;

	जर ((किल्ली->ecdsa_nid = sshkey_ecdsa_nid_from_name(ktype)) == -1)
		परत SSH_ERR_INVALID_ARGUMENT;
	जर ((r = sshbuf_get_cstring(b, &curve, रिक्त)) != 0)
		जा out;
	जर (किल्ली->ecdsa_nid != sshkey_curve_name_to_nid(curve)) {
		r = SSH_ERR_EC_CURVE_MISMATCH;
		जा out;
	}
	जर ((ec = EC_किल्ली_new_by_curve_name(किल्ली->ecdsa_nid)) == रिक्त) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		जा out;
	}
	जर ((r = sshbuf_get_eckey(b, ec)) != 0)
		जा out;
	जर (sshkey_ec_validate_public(EC_किल्ली_get0_group(ec),
	    EC_किल्ली_get0_public_किल्ली(ec)) != 0) {
		r = SSH_ERR_किल्ली_INVALID_EC_मूल्य;
		जा out;
	}
	जर ((pkey = EVP_PKEY_new()) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		जा out;
	}
	जर (EVP_PKEY_set1_EC_किल्ली(pkey, ec) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		जा out;
	}
	EVP_PKEY_free(किल्ली->pkey);
	किल्ली->pkey = pkey;
	pkey = रिक्त;
	/* success */
	r = 0;
#ifdef DEBUG_PK
	sshkey_dump_ec_point(
	    EC_किल्ली_get0_group(EVP_PKEY_get0_EC_किल्ली(किल्ली->pkey)),
	    EC_किल्ली_get0_public_किल्ली(EVP_PKEY_get0_EC_किल्ली(किल्ली->pkey)));
#endif
 out:
	EC_किल्ली_free(ec);
	EVP_PKEY_free(pkey);
	मुक्त(curve);
	परत r;
}

स्थिर पूर्णांक
ssh_ecdsa_deserialize_private(स्थिरांक अक्षर *ktype, संरचना sshbuf *b,
    संरचना sshkey *किल्ली)
{
	पूर्णांक r;
	BIGNUM *exponent = रिक्त;
	EC_किल्ली *ec = रिक्त;

	जर (!sshkey_is_cert(किल्ली)) {
		जर ((r = ssh_ecdsa_deserialize_public(ktype, b, किल्ली)) != 0)
			परत r;
	}
	जर ((r = sshbuf_get_bignum2(b, &exponent)) != 0)
		जा out;
	जर ((ec = EVP_PKEY_get1_EC_किल्ली(किल्ली->pkey)) == रिक्त) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		जा out;
	}
	जर (EC_किल्ली_set_private_किल्ली(ec, exponent) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		जा out;
	}
	जर ((r = sshkey_ec_validate_private(ec)) != 0)
		जा out;
	जर (EVP_PKEY_set1_EC_किल्ली(किल्ली->pkey, ec) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		जा out;
	}
	/* success */
	r = 0;
 out:
	BN_clear_free(exponent);
	EC_किल्ली_free(ec);
	परत r;
}

स्थिर पूर्णांक
ssh_ecdsa_sign(संरचना sshkey *किल्ली,
    u_char **sigp, माप_प्रकार *lenp,
    स्थिरांक u_char *data, माप_प्रकार dlen,
    स्थिरांक अक्षर *alg, स्थिरांक अक्षर *sk_provider, स्थिरांक अक्षर *sk_pin, u_int compat)
{
	ECDSA_SIG *esig = रिक्त;
	अचिन्हित अक्षर *sigb = रिक्त;
	स्थिरांक अचिन्हित अक्षर *psig;
	स्थिरांक BIGNUM *sig_r, *sig_s;
	पूर्णांक hash_alg;
	माप_प्रकार slen = 0;
	पूर्णांक ret = SSH_ERR_INTERNAL_ERROR;

	जर (lenp != रिक्त)
		*lenp = 0;
	जर (sigp != रिक्त)
		*sigp = रिक्त;

	जर (किल्ली == रिक्त || किल्ली->pkey == रिक्त ||
	    sshkey_type_plain(किल्ली->type) != किल्ली_ECDSA)
		परत SSH_ERR_INVALID_ARGUMENT;

	जर ((hash_alg = sshkey_ec_nid_to_hash_alg(किल्ली->ecdsa_nid)) == -1)
		परत SSH_ERR_INTERNAL_ERROR;

	जर ((ret = sshkey_pkey_digest_sign(किल्ली->pkey, hash_alg, &sigb, &slen,
	    data, dlen)) != 0)
		जा out;

	psig = sigb;
	जर ((esig = d2i_ECDSA_SIG(रिक्त, &psig, slen)) == रिक्त) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		जा out;
	}
	ECDSA_SIG_get0(esig, &sig_r, &sig_s);

	जर ((ret = ssh_ecdsa_encode_store_sig(किल्ली, sig_r, sig_s,
	    sigp, lenp)) != 0)
		जा out;
	/* success */
	ret = 0;
 out:
	freezero(sigb, slen);
	ECDSA_SIG_free(esig);
	परत ret;
}

पूर्णांक
ssh_ecdsa_encode_store_sig(स्थिरांक संरचना sshkey *किल्ली,
    स्थिरांक BIGNUM *sig_r, स्थिरांक BIGNUM *sig_s,
    u_char **sigp, माप_प्रकार *lenp)
{
	संरचना sshbuf *b = रिक्त, *bb = रिक्त;
	पूर्णांक ret;
	माप_प्रकार len;

	जर (lenp != रिक्त)
		*lenp = 0;
	जर (sigp != रिक्त)
		*sigp = रिक्त;

	जर ((bb = sshbuf_new()) == रिक्त || (b = sshbuf_new()) == रिक्त) {
		ret = SSH_ERR_ALLOC_FAIL;
		जा out;
	}
	जर ((ret = sshbuf_put_bignum2(bb, sig_r)) != 0 ||
	    (ret = sshbuf_put_bignum2(bb, sig_s)) != 0)
		जा out;
	जर ((ret = sshbuf_put_cstring(b, sshkey_ssh_name_plain(किल्ली))) != 0 ||
	    (ret = sshbuf_put_stringb(b, bb)) != 0)
		जा out;
	len = sshbuf_len(b);
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
	sshbuf_free(bb);
	परत ret;
}

स्थिर पूर्णांक
ssh_ecdsa_verify(स्थिरांक संरचना sshkey *किल्ली,
    स्थिरांक u_char *sig, माप_प्रकार siglen,
    स्थिरांक u_char *data, माप_प्रकार dlen, स्थिरांक अक्षर *alg, u_int compat,
    संरचना sshkey_sig_details **detailsp)
{
	ECDSA_SIG *esig = रिक्त;
	BIGNUM *sig_r = रिक्त, *sig_s = रिक्त;
	पूर्णांक hash_alg, len = 0;
	पूर्णांक ret = SSH_ERR_INTERNAL_ERROR;
	संरचना sshbuf *b = रिक्त, *sigbuf = रिक्त;
	अक्षर *ktype = रिक्त;
	अचिन्हित अक्षर *sigb = रिक्त, *cp;

	जर (किल्ली == रिक्त || किल्ली->pkey == रिक्त ||
	    sshkey_type_plain(किल्ली->type) != किल्ली_ECDSA ||
	    sig == रिक्त || siglen == 0)
		परत SSH_ERR_INVALID_ARGUMENT;

	जर ((hash_alg = sshkey_ec_nid_to_hash_alg(किल्ली->ecdsa_nid)) == -1)
		परत SSH_ERR_INTERNAL_ERROR;

	/* fetch signature */
	जर ((b = sshbuf_from(sig, siglen)) == रिक्त)
		परत SSH_ERR_ALLOC_FAIL;
	जर (sshbuf_get_cstring(b, &ktype, रिक्त) != 0 ||
	    sshbuf_froms(b, &sigbuf) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		जा out;
	}
	जर (म_भेद(sshkey_ssh_name_plain(किल्ली), ktype) != 0) {
		ret = SSH_ERR_किल्ली_TYPE_MISMATCH;
		जा out;
	}
	जर (sshbuf_len(b) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		जा out;
	}

	/* parse signature */
	जर (sshbuf_get_bignum2(sigbuf, &sig_r) != 0 ||
	    sshbuf_get_bignum2(sigbuf, &sig_s) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		जा out;
	}
	जर (sshbuf_len(sigbuf) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		जा out;
	}

	जर ((esig = ECDSA_SIG_new()) == रिक्त) {
		ret = SSH_ERR_ALLOC_FAIL;
		जा out;
	}
	जर (!ECDSA_SIG_set0(esig, sig_r, sig_s)) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		जा out;
	}
	sig_r = sig_s = रिक्त; /* transferred */

	जर ((len = i2d_ECDSA_SIG(esig, रिक्त)) <= 0) {
		len = 0;
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		जा out;
	}
	जर ((sigb = सुस्मृति(1, len)) == रिक्त) {
		ret = SSH_ERR_ALLOC_FAIL;
		जा out;
	}
	cp = sigb; /* ASN1_item_i2d increments the pointer past the object */
	जर (i2d_ECDSA_SIG(esig, &cp) != len) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		जा out;
	}
	जर ((ret = sshkey_pkey_digest_verify(किल्ली->pkey, hash_alg,
	    data, dlen, sigb, len)) != 0)
		जा out;
	/* success */
 out:
	freezero(sigb, len);
	sshbuf_free(sigbuf);
	sshbuf_free(b);
	ECDSA_SIG_free(esig);
	BN_clear_free(sig_r);
	BN_clear_free(sig_s);
	मुक्त(ktype);
	परत ret;
}

/* NB. not static; used by ECDSA-SK */
स्थिरांक संरचना sshkey_impl_funcs sshkey_ecdsa_funcs = {
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

स्थिरांक संरचना sshkey_impl sshkey_ecdsa_nistp256_impl = {
	/* .name = */		"ecdsa-sha2-nistp256",
	/* .shortname = */	"ECDSA",
	/* .sigalg = */		रिक्त,
	/* .type = */		किल्ली_ECDSA,
	/* .nid = */		NID_X9_62_prime256v1,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

स्थिरांक संरचना sshkey_impl sshkey_ecdsa_nistp256_cert_impl = {
	/* .name = */		"ecdsa-sha2-nistp256-cert-v01@openssh.com",
	/* .shortname = */	"ECDSA-CERT",
	/* .sigalg = */		रिक्त,
	/* .type = */		किल्ली_ECDSA_CERT,
	/* .nid = */		NID_X9_62_prime256v1,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

स्थिरांक संरचना sshkey_impl sshkey_ecdsa_nistp384_impl = {
	/* .name = */		"ecdsa-sha2-nistp384",
	/* .shortname = */	"ECDSA",
	/* .sigalg = */		रिक्त,
	/* .type = */		किल्ली_ECDSA,
	/* .nid = */		NID_secp384r1,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

स्थिरांक संरचना sshkey_impl sshkey_ecdsa_nistp384_cert_impl = {
	/* .name = */		"ecdsa-sha2-nistp384-cert-v01@openssh.com",
	/* .shortname = */	"ECDSA-CERT",
	/* .sigalg = */		रिक्त,
	/* .type = */		किल्ली_ECDSA_CERT,
	/* .nid = */		NID_secp384r1,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

स्थिरांक संरचना sshkey_impl sshkey_ecdsa_nistp521_impl = {
	/* .name = */		"ecdsa-sha2-nistp521",
	/* .shortname = */	"ECDSA",
	/* .sigalg = */		रिक्त,
	/* .type = */		किल्ली_ECDSA,
	/* .nid = */		NID_secp521r1,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

स्थिरांक संरचना sshkey_impl sshkey_ecdsa_nistp521_cert_impl = {
	/* .name = */		"ecdsa-sha2-nistp521-cert-v01@openssh.com",
	/* .shortname = */	"ECDSA-CERT",
	/* .sigalg = */		रिक्त,
	/* .type = */		किल्ली_ECDSA_CERT,
	/* .nid = */		NID_secp521r1,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

#endif /* WITH_OPENSSL */
