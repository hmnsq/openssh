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
	अचर EC_GROUP *g;
	EC_साँचो *ec = रिक्त;
	EC_GROUP *eg = रिक्त;

	यदि ((ec = EVP_PKEY_get1_EC_साँचो(k)) == रिक्त ||
	    (g = EC_साँचो_get0_group(ec)) == रिक्त)
		गच्छ out;
	/*
	 * The group may be stored in a ASN.1 encoded private key in one of two
	 * ways: as a "named group", which is reconstituted by ASN.1 object ID
	 * or explicit group parameters encoded into the key blob. Only the
	 * "named group" case sets the group NID for us, but we can figure
	 * it out for the other case by comparing against all the groups that
	 * are supported.
	 */
	यदि ((nid = EC_GROUP_get_curve_name(g)) > 0)
		गच्छ out;
	nid = -1;
	लागि (i = 0; nids[i] != -1; i++) {
		यदि ((eg = EC_GROUP_new_by_curve_name(nids[i])) == रिक्त)
			गच्छ out;
		यदि (EC_GROUP_cmp(g, eg, रिक्त) == 0)
			रोक;
		EC_GROUP_free(eg);
		eg = रिक्त;
	}
	यदि (nids[i] == -1)
		गच्छ out;

	/* Use the group with the NID attached */
	EC_GROUP_set_asn1_flag(eg, OPENSSL_EC_NAMED_CURVE);
	यदि (EC_साँचो_set_group(ec, eg) != 1 ||
	    EVP_PKEY_set1_EC_साँचो(k, ec) != 1)
		गच्छ out;
	/* success */
	nid = nids[i];
 out:
	EC_साँचो_free(ec);
	EC_GROUP_free(eg);
	फर्काऊ nid;
}

स्थिर u_int
ssh_ecdsa_size(अचर संरचना sshkey *साँचो)
{
	विकल्प (साँचो->ecdsa_nid) {
	पक्ष NID_X9_62_prime256v1:
		फर्काऊ 256;
	पक्ष NID_secp384r1:
		फर्काऊ 384;
	पक्ष NID_secp521r1:
		फर्काऊ 521;
	स्वभाव:
		फर्काऊ 0;
	}
}

स्थिर शून्य
ssh_ecdsa_cleanup(संरचना sshkey *k)
{
	EVP_PKEY_free(k->pkey);
	k->pkey = रिक्त;
}

स्थिर पूर्णाङ्क
ssh_ecdsa_equal(अचर संरचना sshkey *a, अचर संरचना sshkey *b)
{
	यदि (a->pkey == रिक्त || b->pkey == रिक्त)
		फर्काऊ 0;
	फर्काऊ EVP_PKEY_cmp(a->pkey, b->pkey) == 1;
}

स्थिर पूर्णाङ्क
ssh_ecdsa_serialize_public(अचर संरचना sshkey *साँचो, संरचना sshbuf *b,
    गणना sshkey_serialize_rep opts)
{
	पूर्णाङ्क r;

	यदि (साँचो->pkey == रिक्त)
		फर्काऊ SSH_ERR_INVALID_ARGUMENT;
	यदि ((r = sshbuf_put_cstring(b,
	    sshkey_curve_nid_to_name(साँचो->ecdsa_nid))) != 0 ||
	    (r = sshbuf_put_ec_pkey(b, साँचो->pkey)) != 0)
		फर्काऊ r;

	फर्काऊ 0;
}

स्थिर पूर्णाङ्क
ssh_ecdsa_serialize_private(अचर संरचना sshkey *साँचो, संरचना sshbuf *b,
    गणना sshkey_serialize_rep opts)
{
	पूर्णाङ्क r;

	यदि (!sshkey_is_cert(साँचो)) {
		यदि ((r = ssh_ecdsa_serialize_public(साँचो, b, opts)) != 0)
			फर्काऊ r;
	}
	यदि ((r = sshbuf_put_bignum2(b,
	    EC_साँचो_get0_private_साँचो(EVP_PKEY_get0_EC_साँचो(साँचो->pkey)))) != 0)
		फर्काऊ r;
	फर्काऊ 0;
}

स्थिर पूर्णाङ्क
ssh_ecdsa_generate(संरचना sshkey *k, पूर्णाङ्क bits)
{
	EVP_PKEY *res = रिक्त;
	EVP_PKEY_CTX *ctx = रिक्त;
	पूर्णाङ्क ret = SSH_ERR_INTERNAL_ERROR;

	यदि ((k->ecdsa_nid = sshkey_ecdsa_bits_to_nid(bits)) == -1)
		फर्काऊ SSH_ERR_साँचो_LENGTH;

	यदि ((ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, रिक्त)) == रिक्त)
		फर्काऊ SSH_ERR_ALLOC_FAIL;

	यदि (EVP_PKEY_keygen_init(ctx) <= 0 ||
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
	फर्काऊ ret;
}

स्थिर पूर्णाङ्क
ssh_ecdsa_copy_public(अचर संरचना sshkey *from, संरचना sshkey *to)
{
	अचर EC_साँचो *ec_from;
	EC_साँचो *ec_to = रिक्त;
	पूर्णाङ्क ret = SSH_ERR_INTERNAL_ERROR;

	ec_from = EVP_PKEY_get0_EC_साँचो(from->pkey);
	यदि (ec_from == रिक्त)
		फर्काऊ SSH_ERR_LIBCRYPTO_ERROR;

	to->ecdsa_nid = from->ecdsa_nid;
	यदि ((ec_to = EC_साँचो_new_by_curve_name(from->ecdsa_nid)) == रिक्त)
		फर्काऊ SSH_ERR_ALLOC_FAIL;
	यदि (EC_साँचो_set_public_साँचो(ec_to,
	    EC_साँचो_get0_public_साँचो(ec_from)) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		गच्छ out;
	}
	EVP_PKEY_free(to->pkey);
	यदि ((to->pkey = EVP_PKEY_new()) == रिक्त) {
		ret = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	यदि (EVP_PKEY_set1_EC_साँचो(to->pkey, ec_to) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		गच्छ out;
	}
	ret = 0;
 out:
	EC_साँचो_free(ec_to);
	फर्काऊ ret;
}

स्थिर पूर्णाङ्क
ssh_ecdsa_deserialize_public(अचर वर्ण *ktype, संरचना sshbuf *b,
    संरचना sshkey *साँचो)
{
	पूर्णाङ्क r;
	वर्ण *curve = रिक्त;
	EVP_PKEY *pkey = रिक्त;
	EC_साँचो *ec = रिक्त;

	यदि ((साँचो->ecdsa_nid = sshkey_ecdsa_nid_from_name(ktype)) == -1)
		फर्काऊ SSH_ERR_INVALID_ARGUMENT;
	यदि ((r = sshbuf_get_cstring(b, &curve, रिक्त)) != 0)
		गच्छ out;
	यदि (साँचो->ecdsa_nid != sshkey_curve_name_to_nid(curve)) {
		r = SSH_ERR_EC_CURVE_MISMATCH;
		गच्छ out;
	}
	यदि ((ec = EC_साँचो_new_by_curve_name(साँचो->ecdsa_nid)) == रिक्त) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		गच्छ out;
	}
	यदि ((r = sshbuf_get_eckey(b, ec)) != 0)
		गच्छ out;
	यदि (sshkey_ec_validate_public(EC_साँचो_get0_group(ec),
	    EC_साँचो_get0_public_साँचो(ec)) != 0) {
		r = SSH_ERR_साँचो_INVALID_EC_मान;
		गच्छ out;
	}
	यदि ((pkey = EVP_PKEY_new()) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	यदि (EVP_PKEY_set1_EC_साँचो(pkey, ec) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		गच्छ out;
	}
	EVP_PKEY_free(साँचो->pkey);
	साँचो->pkey = pkey;
	pkey = रिक्त;
	/* success */
	r = 0;
#ifdef DEBUG_PK
	sshkey_dump_ec_point(
	    EC_साँचो_get0_group(EVP_PKEY_get0_EC_साँचो(साँचो->pkey)),
	    EC_साँचो_get0_public_साँचो(EVP_PKEY_get0_EC_साँचो(साँचो->pkey)));
#endif
 out:
	EC_साँचो_free(ec);
	EVP_PKEY_free(pkey);
	मुक्त(curve);
	फर्काऊ r;
}

स्थिर पूर्णाङ्क
ssh_ecdsa_deserialize_private(अचर वर्ण *ktype, संरचना sshbuf *b,
    संरचना sshkey *साँचो)
{
	पूर्णाङ्क r;
	BIGNUM *exponent = रिक्त;
	EC_साँचो *ec = रिक्त;

	यदि (!sshkey_is_cert(साँचो)) {
		यदि ((r = ssh_ecdsa_deserialize_public(ktype, b, साँचो)) != 0)
			फर्काऊ r;
	}
	यदि ((r = sshbuf_get_bignum2(b, &exponent)) != 0)
		गच्छ out;
	यदि ((ec = EVP_PKEY_get1_EC_साँचो(साँचो->pkey)) == रिक्त) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		गच्छ out;
	}
	यदि (EC_साँचो_set_private_साँचो(ec, exponent) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		गच्छ out;
	}
	यदि ((r = sshkey_ec_validate_private(ec)) != 0)
		गच्छ out;
	यदि (EVP_PKEY_set1_EC_साँचो(साँचो->pkey, ec) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		गच्छ out;
	}
	/* success */
	r = 0;
 out:
	BN_clear_free(exponent);
	EC_साँचो_free(ec);
	फर्काऊ r;
}

स्थिर पूर्णाङ्क
ssh_ecdsa_sign(संरचना sshkey *साँचो,
    u_char **sigp, माप_प्रकार *lenp,
    अचर u_char *data, माप_प्रकार dlen,
    अचर वर्ण *alg, अचर वर्ण *sk_provider, अचर वर्ण *sk_pin, u_int compat)
{
	ECDSA_SIG *esig = रिक्त;
	अचिन्हित वर्ण *sigb = रिक्त;
	अचर अचिन्हित वर्ण *psig;
	अचर BIGNUM *sig_r, *sig_s;
	पूर्णाङ्क hash_alg;
	माप_प्रकार slen = 0;
	पूर्णाङ्क ret = SSH_ERR_INTERNAL_ERROR;

	यदि (lenp != रिक्त)
		*lenp = 0;
	यदि (sigp != रिक्त)
		*sigp = रिक्त;

	यदि (साँचो == रिक्त || साँचो->pkey == रिक्त ||
	    sshkey_type_plain(साँचो->type) != साँचो_ECDSA)
		फर्काऊ SSH_ERR_INVALID_ARGUMENT;

	यदि ((hash_alg = sshkey_ec_nid_to_hash_alg(साँचो->ecdsa_nid)) == -1)
		फर्काऊ SSH_ERR_INTERNAL_ERROR;

	यदि ((ret = sshkey_pkey_digest_sign(साँचो->pkey, hash_alg, &sigb, &slen,
	    data, dlen)) != 0)
		गच्छ out;

	psig = sigb;
	यदि ((esig = d2i_ECDSA_SIG(रिक्त, &psig, slen)) == रिक्त) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		गच्छ out;
	}
	ECDSA_SIG_get0(esig, &sig_r, &sig_s);

	यदि ((ret = ssh_ecdsa_encode_store_sig(साँचो, sig_r, sig_s,
	    sigp, lenp)) != 0)
		गच्छ out;
	/* success */
	ret = 0;
 out:
	freezero(sigb, slen);
	ECDSA_SIG_free(esig);
	फर्काऊ ret;
}

पूर्णाङ्क
ssh_ecdsa_encode_store_sig(अचर संरचना sshkey *साँचो,
    अचर BIGNUM *sig_r, अचर BIGNUM *sig_s,
    u_char **sigp, माप_प्रकार *lenp)
{
	संरचना sshbuf *b = रिक्त, *bb = रिक्त;
	पूर्णाङ्क ret;
	माप_प्रकार len;

	यदि (lenp != रिक्त)
		*lenp = 0;
	यदि (sigp != रिक्त)
		*sigp = रिक्त;

	यदि ((bb = sshbuf_new()) == रिक्त || (b = sshbuf_new()) == रिक्त) {
		ret = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	यदि ((ret = sshbuf_put_bignum2(bb, sig_r)) != 0 ||
	    (ret = sshbuf_put_bignum2(bb, sig_s)) != 0)
		गच्छ out;
	यदि ((ret = sshbuf_put_cstring(b, sshkey_ssh_name_plain(साँचो))) != 0 ||
	    (ret = sshbuf_put_stringb(b, bb)) != 0)
		गच्छ out;
	len = sshbuf_len(b);
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
	sshbuf_free(bb);
	फर्काऊ ret;
}

स्थिर पूर्णाङ्क
ssh_ecdsa_verify(अचर संरचना sshkey *साँचो,
    अचर u_char *sig, माप_प्रकार siglen,
    अचर u_char *data, माप_प्रकार dlen, अचर वर्ण *alg, u_int compat,
    संरचना sshkey_sig_details **detailsp)
{
	ECDSA_SIG *esig = रिक्त;
	BIGNUM *sig_r = रिक्त, *sig_s = रिक्त;
	पूर्णाङ्क hash_alg, len = 0;
	पूर्णाङ्क ret = SSH_ERR_INTERNAL_ERROR;
	संरचना sshbuf *b = रिक्त, *sigbuf = रिक्त;
	वर्ण *ktype = रिक्त;
	अचिन्हित वर्ण *sigb = रिक्त, *cp;

	यदि (साँचो == रिक्त || साँचो->pkey == रिक्त ||
	    sshkey_type_plain(साँचो->type) != साँचो_ECDSA ||
	    sig == रिक्त || siglen == 0)
		फर्काऊ SSH_ERR_INVALID_ARGUMENT;

	यदि ((hash_alg = sshkey_ec_nid_to_hash_alg(साँचो->ecdsa_nid)) == -1)
		फर्काऊ SSH_ERR_INTERNAL_ERROR;

	/* fetch signature */
	यदि ((b = sshbuf_from(sig, siglen)) == रिक्त)
		फर्काऊ SSH_ERR_ALLOC_FAIL;
	यदि (sshbuf_get_cstring(b, &ktype, रिक्त) != 0 ||
	    sshbuf_froms(b, &sigbuf) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		गच्छ out;
	}
	यदि (म_भेद(sshkey_ssh_name_plain(साँचो), ktype) != 0) {
		ret = SSH_ERR_साँचो_TYPE_MISMATCH;
		गच्छ out;
	}
	यदि (sshbuf_len(b) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		गच्छ out;
	}

	/* parse signature */
	यदि (sshbuf_get_bignum2(sigbuf, &sig_r) != 0 ||
	    sshbuf_get_bignum2(sigbuf, &sig_s) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		गच्छ out;
	}
	यदि (sshbuf_len(sigbuf) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		गच्छ out;
	}

	यदि ((esig = ECDSA_SIG_new()) == रिक्त) {
		ret = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	यदि (!ECDSA_SIG_set0(esig, sig_r, sig_s)) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		गच्छ out;
	}
	sig_r = sig_s = रिक्त; /* transferred */

	यदि ((len = i2d_ECDSA_SIG(esig, रिक्त)) <= 0) {
		len = 0;
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		गच्छ out;
	}
	यदि ((sigb = सुस्मृति(1, len)) == रिक्त) {
		ret = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	cp = sigb; /* ASN1_item_i2d increments the pointer past the object */
	यदि (i2d_ECDSA_SIG(esig, &cp) != len) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		गच्छ out;
	}
	यदि ((ret = sshkey_pkey_digest_verify(साँचो->pkey, hash_alg,
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
	फर्काऊ ret;
}

/* NB. not static; used by ECDSA-SK */
अचर संरचना sshkey_impl_funcs sshkey_ecdsa_funcs = {
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

अचर संरचना sshkey_impl sshkey_ecdsa_nistp256_impl = {
	/* .name = */		"ecdsa-sha2-nistp256",
	/* .shortname = */	"ECDSA",
	/* .sigalg = */		रिक्त,
	/* .type = */		साँचो_ECDSA,
	/* .nid = */		NID_X9_62_prime256v1,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

अचर संरचना sshkey_impl sshkey_ecdsa_nistp256_cert_impl = {
	/* .name = */		"ecdsa-sha2-nistp256-cert-v01@openssh.com",
	/* .shortname = */	"ECDSA-CERT",
	/* .sigalg = */		रिक्त,
	/* .type = */		साँचो_ECDSA_CERT,
	/* .nid = */		NID_X9_62_prime256v1,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

अचर संरचना sshkey_impl sshkey_ecdsa_nistp384_impl = {
	/* .name = */		"ecdsa-sha2-nistp384",
	/* .shortname = */	"ECDSA",
	/* .sigalg = */		रिक्त,
	/* .type = */		साँचो_ECDSA,
	/* .nid = */		NID_secp384r1,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

अचर संरचना sshkey_impl sshkey_ecdsa_nistp384_cert_impl = {
	/* .name = */		"ecdsa-sha2-nistp384-cert-v01@openssh.com",
	/* .shortname = */	"ECDSA-CERT",
	/* .sigalg = */		रिक्त,
	/* .type = */		साँचो_ECDSA_CERT,
	/* .nid = */		NID_secp384r1,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

अचर संरचना sshkey_impl sshkey_ecdsa_nistp521_impl = {
	/* .name = */		"ecdsa-sha2-nistp521",
	/* .shortname = */	"ECDSA",
	/* .sigalg = */		रिक्त,
	/* .type = */		साँचो_ECDSA,
	/* .nid = */		NID_secp521r1,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

अचर संरचना sshkey_impl sshkey_ecdsa_nistp521_cert_impl = {
	/* .name = */		"ecdsa-sha2-nistp521-cert-v01@openssh.com",
	/* .shortname = */	"ECDSA-CERT",
	/* .sigalg = */		रिक्त,
	/* .type = */		साँचो_ECDSA_CERT,
	/* .nid = */		NID_secp521r1,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

#endif /* WITH_OPENSSL */
