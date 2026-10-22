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

#شامل "includes.h"

#اگر defined(WITH_OPENSSL)
#شامل "openbsd-compat/openssl-compat.h"

#شامل <sys/types.h>

#شامل <openssl/bn.h>
#شامل <openssl/ec.h>
#شامل <openssl/ecdsa.h>
#شامل <openssl/evp.h>

#شامل <string.h>

#شامل "sshbuf.h"
#شامل "ssherr.h"
#define SSHKEY_INTERNAL
#شامل "sshkey.h"

صحیح
sshkey_ecdsa_fixup_group(EVP_PKEY *k)
{
	صحیح nids[] = {
		NID_X9_62_prime256v1,
		NID_secp384r1,
		NID_secp521r1,
		-1
	};
	صحیح nid = -1;
	u_int i;
	ثابت EC_GROUP *g;
	EC_کلید *ec = پوچ;
	EC_GROUP *eg = پوچ;

	اگر ((ec = EVP_PKEY_get1_EC_کلید(k)) == پوچ ||
	    (g = EC_کلید_get0_group(ec)) == پوچ)
		برو out;
	/*
	 * The group may be stored in a ASN.1 encoded private key in one of two
	 * ways: as a "named group", which is reconstituted by ASN.1 object ID
	 * or explicit group parameters encoded into the key blob. Only the
	 * "named group" case sets the group NID for us, but we can figure
	 * it out for the other case by comparing against all the groups that
	 * are supported.
	 */
	اگر ((nid = EC_GROUP_get_curve_name(g)) > 0)
		برو out;
	nid = -1;
	برای (i = 0; nids[i] != -1; i++) {
		اگر ((eg = EC_GROUP_new_by_curve_name(nids[i])) == پوچ)
			برو out;
		اگر (EC_GROUP_cmp(g, eg, پوچ) == 0)
			بشکن;
		EC_GROUP_free(eg);
		eg = پوچ;
	}
	اگر (nids[i] == -1)
		برو out;

	/* Use the group with the NID attached */
	EC_GROUP_set_asn1_flag(eg, OPENSSL_EC_NAMED_CURVE);
	اگر (EC_کلید_set_group(ec, eg) != 1 ||
	    EVP_PKEY_set1_EC_کلید(k, ec) != 1)
		برو out;
	/* success */
	nid = nids[i];
 out:
	EC_کلید_free(ec);
	EC_GROUP_free(eg);
	بازگشت nid;
}

ایستا u_int
ssh_ecdsa_size(ثابت ساختار sshkey *کلید)
{
	انتخاب (کلید->ecdsa_nid) {
	حالت NID_X9_62_prime256v1:
		بازگشت 256;
	حالت NID_secp384r1:
		بازگشت 384;
	حالت NID_secp521r1:
		بازگشت 521;
	پیشفرض:
		بازگشت 0;
	}
}

ایستا تهی
ssh_ecdsa_cleanup(ساختار sshkey *k)
{
	EVP_PKEY_free(k->pkey);
	k->pkey = پوچ;
}

ایستا صحیح
ssh_ecdsa_equal(ثابت ساختار sshkey *a, ثابت ساختار sshkey *b)
{
	اگر (a->pkey == پوچ || b->pkey == پوچ)
		بازگشت 0;
	بازگشت EVP_PKEY_cmp(a->pkey, b->pkey) == 1;
}

ایستا صحیح
ssh_ecdsa_serialize_public(ثابت ساختار sshkey *کلید, ساختار sshbuf *b,
    شمارش sshkey_serialize_rep opts)
{
	صحیح r;

	اگر (کلید->pkey == پوچ)
		بازگشت SSH_ERR_INVALID_ARGUMENT;
	اگر ((r = sshbuf_put_cstring(b,
	    sshkey_curve_nid_to_name(کلید->ecdsa_nid))) != 0 ||
	    (r = sshbuf_put_ec_pkey(b, کلید->pkey)) != 0)
		بازگشت r;

	بازگشت 0;
}

ایستا صحیح
ssh_ecdsa_serialize_private(ثابت ساختار sshkey *کلید, ساختار sshbuf *b,
    شمارش sshkey_serialize_rep opts)
{
	صحیح r;

	اگر (!sshkey_is_cert(کلید)) {
		اگر ((r = ssh_ecdsa_serialize_public(کلید, b, opts)) != 0)
			بازگشت r;
	}
	اگر ((r = sshbuf_put_bignum2(b,
	    EC_کلید_get0_private_کلید(EVP_PKEY_get0_EC_کلید(کلید->pkey)))) != 0)
		بازگشت r;
	بازگشت 0;
}

ایستا صحیح
ssh_ecdsa_generate(ساختار sshkey *k, صحیح bits)
{
	EVP_PKEY *res = پوچ;
	EVP_PKEY_CTX *ctx = پوچ;
	صحیح ret = SSH_ERR_INTERNAL_ERROR;

	اگر ((k->ecdsa_nid = sshkey_ecdsa_bits_to_nid(bits)) == -1)
		بازگشت SSH_ERR_کلید_LENGTH;

	اگر ((ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, پوچ)) == پوچ)
		بازگشت SSH_ERR_ALLOC_FAIL;

	اگر (EVP_PKEY_keygen_init(ctx) <= 0 ||
	    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, k->ecdsa_nid) <= 0 ||
	    EVP_PKEY_keygen(ctx, &res) <= 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		برو out;
	}
	/* success */
	k->pkey = res;
	res = پوچ;
	ret = 0;
 out:
	EVP_PKEY_free(res);
	EVP_PKEY_CTX_free(ctx);
	بازگشت ret;
}

ایستا صحیح
ssh_ecdsa_copy_public(ثابت ساختار sshkey *from, ساختار sshkey *to)
{
	ثابت EC_کلید *ec_from;
	EC_کلید *ec_to = پوچ;
	صحیح ret = SSH_ERR_INTERNAL_ERROR;

	ec_from = EVP_PKEY_get0_EC_کلید(from->pkey);
	اگر (ec_from == پوچ)
		بازگشت SSH_ERR_LIBCRYPTO_ERROR;

	to->ecdsa_nid = from->ecdsa_nid;
	اگر ((ec_to = EC_کلید_new_by_curve_name(from->ecdsa_nid)) == پوچ)
		بازگشت SSH_ERR_ALLOC_FAIL;
	اگر (EC_کلید_set_public_کلید(ec_to,
	    EC_کلید_get0_public_کلید(ec_from)) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		برو out;
	}
	EVP_PKEY_free(to->pkey);
	اگر ((to->pkey = EVP_PKEY_new()) == پوچ) {
		ret = SSH_ERR_ALLOC_FAIL;
		برو out;
	}
	اگر (EVP_PKEY_set1_EC_کلید(to->pkey, ec_to) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		برو out;
	}
	ret = 0;
 out:
	EC_کلید_free(ec_to);
	بازگشت ret;
}

ایستا صحیح
ssh_ecdsa_deserialize_public(ثابت نویسه *ktype, ساختار sshbuf *b,
    ساختار sshkey *کلید)
{
	صحیح r;
	نویسه *curve = پوچ;
	EVP_PKEY *pkey = پوچ;
	EC_کلید *ec = پوچ;

	اگر ((کلید->ecdsa_nid = sshkey_ecdsa_nid_from_name(ktype)) == -1)
		بازگشت SSH_ERR_INVALID_ARGUMENT;
	اگر ((r = sshbuf_get_cstring(b, &curve, پوچ)) != 0)
		برو out;
	اگر (کلید->ecdsa_nid != sshkey_curve_name_to_nid(curve)) {
		r = SSH_ERR_EC_CURVE_MISMATCH;
		برو out;
	}
	اگر ((ec = EC_کلید_new_by_curve_name(کلید->ecdsa_nid)) == پوچ) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		برو out;
	}
	اگر ((r = sshbuf_get_eckey(b, ec)) != 0)
		برو out;
	اگر (sshkey_ec_validate_public(EC_کلید_get0_group(ec),
	    EC_کلید_get0_public_کلید(ec)) != 0) {
		r = SSH_ERR_کلید_INVALID_EC_مقدار;
		برو out;
	}
	اگر ((pkey = EVP_PKEY_new()) == پوچ) {
		r = SSH_ERR_ALLOC_FAIL;
		برو out;
	}
	اگر (EVP_PKEY_set1_EC_کلید(pkey, ec) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		برو out;
	}
	EVP_PKEY_free(کلید->pkey);
	کلید->pkey = pkey;
	pkey = پوچ;
	/* success */
	r = 0;
#ifdef DEBUG_PK
	sshkey_dump_ec_point(
	    EC_کلید_get0_group(EVP_PKEY_get0_EC_کلید(کلید->pkey)),
	    EC_کلید_get0_public_کلید(EVP_PKEY_get0_EC_کلید(کلید->pkey)));
#endif
 out:
	EC_کلید_free(ec);
	EVP_PKEY_free(pkey);
	آزاد(curve);
	بازگشت r;
}

ایستا صحیح
ssh_ecdsa_deserialize_private(ثابت نویسه *ktype, ساختار sshbuf *b,
    ساختار sshkey *کلید)
{
	صحیح r;
	BIGNUM *exponent = پوچ;
	EC_کلید *ec = پوچ;

	اگر (!sshkey_is_cert(کلید)) {
		اگر ((r = ssh_ecdsa_deserialize_public(ktype, b, کلید)) != 0)
			بازگشت r;
	}
	اگر ((r = sshbuf_get_bignum2(b, &exponent)) != 0)
		برو out;
	اگر ((ec = EVP_PKEY_get1_EC_کلید(کلید->pkey)) == پوچ) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		برو out;
	}
	اگر (EC_کلید_set_private_کلید(ec, exponent) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		برو out;
	}
	اگر ((r = sshkey_ec_validate_private(ec)) != 0)
		برو out;
	اگر (EVP_PKEY_set1_EC_کلید(کلید->pkey, ec) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		برو out;
	}
	/* success */
	r = 0;
 out:
	BN_clear_free(exponent);
	EC_کلید_free(ec);
	بازگشت r;
}

ایستا صحیح
ssh_ecdsa_sign(ساختار sshkey *کلید,
    u_char **sigp, size_t *lenp,
    ثابت u_char *data, size_t dlen,
    ثابت نویسه *alg, ثابت نویسه *sk_provider, ثابت نویسه *sk_pin, u_int compat)
{
	ECDSA_SIG *esig = پوچ;
	unsigned نویسه *sigb = پوچ;
	ثابت unsigned نویسه *psig;
	ثابت BIGNUM *sig_r, *sig_s;
	صحیح hash_alg;
	size_t slen = 0;
	صحیح ret = SSH_ERR_INTERNAL_ERROR;

	اگر (lenp != پوچ)
		*lenp = 0;
	اگر (sigp != پوچ)
		*sigp = پوچ;

	اگر (کلید == پوچ || کلید->pkey == پوچ ||
	    sshkey_type_plain(کلید->type) != کلید_ECDSA)
		بازگشت SSH_ERR_INVALID_ARGUMENT;

	اگر ((hash_alg = sshkey_ec_nid_to_hash_alg(کلید->ecdsa_nid)) == -1)
		بازگشت SSH_ERR_INTERNAL_ERROR;

	اگر ((ret = sshkey_pkey_digest_sign(کلید->pkey, hash_alg, &sigb, &slen,
	    data, dlen)) != 0)
		برو out;

	psig = sigb;
	اگر ((esig = d2i_ECDSA_SIG(پوچ, &psig, slen)) == پوچ) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		برو out;
	}
	ECDSA_SIG_get0(esig, &sig_r, &sig_s);

	اگر ((ret = ssh_ecdsa_encode_store_sig(کلید, sig_r, sig_s,
	    sigp, lenp)) != 0)
		برو out;
	/* success */
	ret = 0;
 out:
	freezero(sigb, slen);
	ECDSA_SIG_free(esig);
	بازگشت ret;
}

صحیح
ssh_ecdsa_encode_store_sig(ثابت ساختار sshkey *کلید,
    ثابت BIGNUM *sig_r, ثابت BIGNUM *sig_s,
    u_char **sigp, size_t *lenp)
{
	ساختار sshbuf *b = پوچ, *bb = پوچ;
	صحیح ret;
	size_t len;

	اگر (lenp != پوچ)
		*lenp = 0;
	اگر (sigp != پوچ)
		*sigp = پوچ;

	اگر ((bb = sshbuf_new()) == پوچ || (b = sshbuf_new()) == پوچ) {
		ret = SSH_ERR_ALLOC_FAIL;
		برو out;
	}
	اگر ((ret = sshbuf_put_bignum2(bb, sig_r)) != 0 ||
	    (ret = sshbuf_put_bignum2(bb, sig_s)) != 0)
		برو out;
	اگر ((ret = sshbuf_put_cstring(b, sshkey_ssh_name_plain(کلید))) != 0 ||
	    (ret = sshbuf_put_stringb(b, bb)) != 0)
		برو out;
	len = sshbuf_len(b);
	اگر (sigp != پوچ) {
		اگر ((*sigp = malloc(len)) == پوچ) {
			ret = SSH_ERR_ALLOC_FAIL;
			برو out;
		}
		memcpy(*sigp, sshbuf_ptr(b), len);
	}
	اگر (lenp != پوچ)
		*lenp = len;
	ret = 0;
 out:
	sshbuf_free(b);
	sshbuf_free(bb);
	بازگشت ret;
}

ایستا صحیح
ssh_ecdsa_verify(ثابت ساختار sshkey *کلید,
    ثابت u_char *sig, size_t siglen,
    ثابت u_char *data, size_t dlen, ثابت نویسه *alg, u_int compat,
    ساختار sshkey_sig_details **detailsp)
{
	ECDSA_SIG *esig = پوچ;
	BIGNUM *sig_r = پوچ, *sig_s = پوچ;
	صحیح hash_alg, len = 0;
	صحیح ret = SSH_ERR_INTERNAL_ERROR;
	ساختار sshbuf *b = پوچ, *sigbuf = پوچ;
	نویسه *ktype = پوچ;
	unsigned نویسه *sigb = پوچ, *cp;

	اگر (کلید == پوچ || کلید->pkey == پوچ ||
	    sshkey_type_plain(کلید->type) != کلید_ECDSA ||
	    sig == پوچ || siglen == 0)
		بازگشت SSH_ERR_INVALID_ARGUMENT;

	اگر ((hash_alg = sshkey_ec_nid_to_hash_alg(کلید->ecdsa_nid)) == -1)
		بازگشت SSH_ERR_INTERNAL_ERROR;

	/* fetch signature */
	اگر ((b = sshbuf_from(sig, siglen)) == پوچ)
		بازگشت SSH_ERR_ALLOC_FAIL;
	اگر (sshbuf_get_cstring(b, &ktype, پوچ) != 0 ||
	    sshbuf_froms(b, &sigbuf) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		برو out;
	}
	اگر (strcmp(sshkey_ssh_name_plain(کلید), ktype) != 0) {
		ret = SSH_ERR_کلید_TYPE_MISMATCH;
		برو out;
	}
	اگر (sshbuf_len(b) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		برو out;
	}

	/* parse signature */
	اگر (sshbuf_get_bignum2(sigbuf, &sig_r) != 0 ||
	    sshbuf_get_bignum2(sigbuf, &sig_s) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		برو out;
	}
	اگر (sshbuf_len(sigbuf) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		برو out;
	}

	اگر ((esig = ECDSA_SIG_new()) == پوچ) {
		ret = SSH_ERR_ALLOC_FAIL;
		برو out;
	}
	اگر (!ECDSA_SIG_set0(esig, sig_r, sig_s)) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		برو out;
	}
	sig_r = sig_s = پوچ; /* transferred */

	اگر ((len = i2d_ECDSA_SIG(esig, پوچ)) <= 0) {
		len = 0;
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		برو out;
	}
	اگر ((sigb = calloc(1, len)) == پوچ) {
		ret = SSH_ERR_ALLOC_FAIL;
		برو out;
	}
	cp = sigb; /* ASN1_item_i2d increments the pointer past the object */
	اگر (i2d_ECDSA_SIG(esig, &cp) != len) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		برو out;
	}
	اگر ((ret = sshkey_pkey_digest_verify(کلید->pkey, hash_alg,
	    data, dlen, sigb, len)) != 0)
		برو out;
	/* success */
 out:
	freezero(sigb, len);
	sshbuf_free(sigbuf);
	sshbuf_free(b);
	ECDSA_SIG_free(esig);
	BN_clear_free(sig_r);
	BN_clear_free(sig_s);
	آزاد(ktype);
	بازگشت ret;
}

/* NB. not static; used by ECDSA-SK */
ثابت ساختار sshkey_impl_funcs sshkey_ecdsa_funcs = {
	/* .size = */		ssh_ecdsa_size,
	/* .alloc = */		پوچ,
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

ثابت ساختار sshkey_impl sshkey_ecdsa_nistp256_impl = {
	/* .name = */		"ecdsa-sha2-nistp256",
	/* .shortname = */	"ECDSA",
	/* .sigalg = */		پوچ,
	/* .type = */		کلید_ECDSA,
	/* .nid = */		NID_X9_62_prime256v1,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

ثابت ساختار sshkey_impl sshkey_ecdsa_nistp256_cert_impl = {
	/* .name = */		"ecdsa-sha2-nistp256-cert-v01@openssh.com",
	/* .shortname = */	"ECDSA-CERT",
	/* .sigalg = */		پوچ,
	/* .type = */		کلید_ECDSA_CERT,
	/* .nid = */		NID_X9_62_prime256v1,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

ثابت ساختار sshkey_impl sshkey_ecdsa_nistp384_impl = {
	/* .name = */		"ecdsa-sha2-nistp384",
	/* .shortname = */	"ECDSA",
	/* .sigalg = */		پوچ,
	/* .type = */		کلید_ECDSA,
	/* .nid = */		NID_secp384r1,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

ثابت ساختار sshkey_impl sshkey_ecdsa_nistp384_cert_impl = {
	/* .name = */		"ecdsa-sha2-nistp384-cert-v01@openssh.com",
	/* .shortname = */	"ECDSA-CERT",
	/* .sigalg = */		پوچ,
	/* .type = */		کلید_ECDSA_CERT,
	/* .nid = */		NID_secp384r1,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

ثابت ساختار sshkey_impl sshkey_ecdsa_nistp521_impl = {
	/* .name = */		"ecdsa-sha2-nistp521",
	/* .shortname = */	"ECDSA",
	/* .sigalg = */		پوچ,
	/* .type = */		کلید_ECDSA,
	/* .nid = */		NID_secp521r1,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

ثابت ساختار sshkey_impl sshkey_ecdsa_nistp521_cert_impl = {
	/* .name = */		"ecdsa-sha2-nistp521-cert-v01@openssh.com",
	/* .shortname = */	"ECDSA-CERT",
	/* .sigalg = */		پوچ,
	/* .type = */		کلید_ECDSA_CERT,
	/* .nid = */		NID_secp521r1,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

#endif /* WITH_OPENSSL */
