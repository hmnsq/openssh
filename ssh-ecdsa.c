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

#ضمن "includes.h"

#ܐܢ defined(WITH_OPENSSL)
#ضمن "openbsd-compat/openssl-compat.h"

#ضمن <sys/types.h>

#ضمن <openssl/bn.h>
#ضمن <openssl/ec.h>
#ضمن <openssl/ecdsa.h>
#ضمن <openssl/evp.h>

#ضمن <string.h>

#ضمن "sshbuf.h"
#ضمن "ssherr.h"
#define SSHKEY_INTERNAL
#ضمن "sshkey.h"

صحيح
sshkey_ecdsa_fixup_group(EVP_PKEY *k)
{
	صحيح nids[] = {
		NID_X9_62_prime256v1,
		NID_secp384r1,
		NID_secp521r1,
		-1
	};
	صحيح nid = -1;
	u_int i;
	ثابت EC_GROUP *g;
	EC_KEY *ec = عدم;
	EC_GROUP *eg = عدم;

	ܐܢ ((ec = EVP_PKEY_get1_EC_KEY(k)) == عدم ||
	    (g = EC_KEY_get0_group(ec)) == عدم)
		اذهب out;
	/*
	 * The group may be stored in a ASN.1 encoded private key in one of two
	 * ways: as a "named group", which is reconstituted by ASN.1 object ID
	 * or explicit group parameters encoded into the key blob. Only the
	 * "named group" case sets the group NID for us, but we can figure
	 * it out for the other case by comparing against all the groups that
	 * are supported.
	 */
	ܐܢ ((nid = EC_GROUP_get_curve_name(g)) > 0)
		اذهب out;
	nid = -1;
	لكل (i = 0; nids[i] != -1; i++) {
		ܐܢ ((eg = EC_GROUP_new_by_curve_name(nids[i])) == عدم)
			اذهب out;
		ܐܢ (EC_GROUP_cmp(g, eg, عدم) == 0)
			اكسر;
		EC_GROUP_free(eg);
		eg = عدم;
	}
	ܐܢ (nids[i] == -1)
		اذهب out;

	/* Use the group with the NID attached */
	EC_GROUP_set_asn1_flag(eg, OPENSSL_EC_NAMED_CURVE);
	ܐܢ (EC_KEY_set_group(ec, eg) != 1 ||
	    EVP_PKEY_set1_EC_KEY(k, ec) != 1)
		اذهب out;
	/* success */
	nid = nids[i];
 out:
	EC_KEY_free(ec);
	EC_GROUP_free(eg);
	ܦܢܐ nid;
}

ساكن u_int
ssh_ecdsa_size(ثابت بنية sshkey *key)
{
	بدل (key->ecdsa_nid) {
	حالة NID_X9_62_prime256v1:
		ܦܢܐ 256;
	حالة NID_secp384r1:
		ܦܢܐ 384;
	حالة NID_secp521r1:
		ܦܢܐ 521;
	افتراضي:
		ܦܢܐ 0;
	}
}

ساكن فراغ
ssh_ecdsa_cleanup(بنية sshkey *k)
{
	EVP_PKEY_free(k->pkey);
	k->pkey = عدم;
}

ساكن صحيح
ssh_ecdsa_equal(ثابت بنية sshkey *a, ثابت بنية sshkey *b)
{
	ܐܢ (a->pkey == عدم || b->pkey == عدم)
		ܦܢܐ 0;
	ܦܢܐ EVP_PKEY_cmp(a->pkey, b->pkey) == 1;
}

ساكن صحيح
ssh_ecdsa_serialize_public(ثابت بنية sshkey *key, بنية sshbuf *b,
    تعداد sshkey_serialize_rep opts)
{
	صحيح r;

	ܐܢ (key->pkey == عدم)
		ܦܢܐ SSH_ERR_INVALID_ARGUMENT;
	ܐܢ ((r = sshbuf_put_cstring(b,
	    sshkey_curve_nid_to_name(key->ecdsa_nid))) != 0 ||
	    (r = sshbuf_put_ec_pkey(b, key->pkey)) != 0)
		ܦܢܐ r;

	ܦܢܐ 0;
}

ساكن صحيح
ssh_ecdsa_serialize_private(ثابت بنية sshkey *key, بنية sshbuf *b,
    تعداد sshkey_serialize_rep opts)
{
	صحيح r;

	ܐܢ (!sshkey_is_cert(key)) {
		ܐܢ ((r = ssh_ecdsa_serialize_public(key, b, opts)) != 0)
			ܦܢܐ r;
	}
	ܐܢ ((r = sshbuf_put_bignum2(b,
	    EC_KEY_get0_private_key(EVP_PKEY_get0_EC_KEY(key->pkey)))) != 0)
		ܦܢܐ r;
	ܦܢܐ 0;
}

ساكن صحيح
ssh_ecdsa_generate(بنية sshkey *k, صحيح bits)
{
	EVP_PKEY *res = عدم;
	EVP_PKEY_CTX *ctx = عدم;
	صحيح ret = SSH_ERR_INTERNAL_ERROR;

	ܐܢ ((k->ecdsa_nid = sshkey_ecdsa_bits_to_nid(bits)) == -1)
		ܦܢܐ SSH_ERR_KEY_LENGTH;

	ܐܢ ((ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, عدم)) == عدم)
		ܦܢܐ SSH_ERR_ALLOC_FAIL;

	ܐܢ (EVP_PKEY_keygen_init(ctx) <= 0 ||
	    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, k->ecdsa_nid) <= 0 ||
	    EVP_PKEY_keygen(ctx, &res) <= 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		اذهب out;
	}
	/* success */
	k->pkey = res;
	res = عدم;
	ret = 0;
 out:
	EVP_PKEY_free(res);
	EVP_PKEY_CTX_free(ctx);
	ܦܢܐ ret;
}

ساكن صحيح
ssh_ecdsa_copy_public(ثابت بنية sshkey *from, بنية sshkey *to)
{
	ثابت EC_KEY *ec_from;
	EC_KEY *ec_to = عدم;
	صحيح ret = SSH_ERR_INTERNAL_ERROR;

	ec_from = EVP_PKEY_get0_EC_KEY(from->pkey);
	ܐܢ (ec_from == عدم)
		ܦܢܐ SSH_ERR_LIBCRYPTO_ERROR;

	to->ecdsa_nid = from->ecdsa_nid;
	ܐܢ ((ec_to = EC_KEY_new_by_curve_name(from->ecdsa_nid)) == عدم)
		ܦܢܐ SSH_ERR_ALLOC_FAIL;
	ܐܢ (EC_KEY_set_public_key(ec_to,
	    EC_KEY_get0_public_key(ec_from)) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		اذهب out;
	}
	EVP_PKEY_free(to->pkey);
	ܐܢ ((to->pkey = EVP_PKEY_new()) == عدم) {
		ret = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}
	ܐܢ (EVP_PKEY_set1_EC_KEY(to->pkey, ec_to) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		اذهب out;
	}
	ret = 0;
 out:
	EC_KEY_free(ec_to);
	ܦܢܐ ret;
}

ساكن صحيح
ssh_ecdsa_deserialize_public(ثابت حرف *ktype, بنية sshbuf *b,
    بنية sshkey *key)
{
	صحيح r;
	حرف *curve = عدم;
	EVP_PKEY *pkey = عدم;
	EC_KEY *ec = عدم;

	ܐܢ ((key->ecdsa_nid = sshkey_ecdsa_nid_from_name(ktype)) == -1)
		ܦܢܐ SSH_ERR_INVALID_ARGUMENT;
	ܐܢ ((r = sshbuf_get_cstring(b, &curve, عدم)) != 0)
		اذهب out;
	ܐܢ (key->ecdsa_nid != sshkey_curve_name_to_nid(curve)) {
		r = SSH_ERR_EC_CURVE_MISMATCH;
		اذهب out;
	}
	ܐܢ ((ec = EC_KEY_new_by_curve_name(key->ecdsa_nid)) == عدم) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		اذهب out;
	}
	ܐܢ ((r = sshbuf_get_eckey(b, ec)) != 0)
		اذهب out;
	ܐܢ (sshkey_ec_validate_public(EC_KEY_get0_group(ec),
	    EC_KEY_get0_public_key(ec)) != 0) {
		r = SSH_ERR_KEY_INVALID_EC_VALUE;
		اذهب out;
	}
	ܐܢ ((pkey = EVP_PKEY_new()) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}
	ܐܢ (EVP_PKEY_set1_EC_KEY(pkey, ec) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		اذهب out;
	}
	EVP_PKEY_free(key->pkey);
	key->pkey = pkey;
	pkey = عدم;
	/* success */
	r = 0;
#ifdef DEBUG_PK
	sshkey_dump_ec_point(
	    EC_KEY_get0_group(EVP_PKEY_get0_EC_KEY(key->pkey)),
	    EC_KEY_get0_public_key(EVP_PKEY_get0_EC_KEY(key->pkey)));
#endif
 out:
	EC_KEY_free(ec);
	EVP_PKEY_free(pkey);
	حرر(curve);
	ܦܢܐ r;
}

ساكن صحيح
ssh_ecdsa_deserialize_private(ثابت حرف *ktype, بنية sshbuf *b,
    بنية sshkey *key)
{
	صحيح r;
	BIGNUM *exponent = عدم;
	EC_KEY *ec = عدم;

	ܐܢ (!sshkey_is_cert(key)) {
		ܐܢ ((r = ssh_ecdsa_deserialize_public(ktype, b, key)) != 0)
			ܦܢܐ r;
	}
	ܐܢ ((r = sshbuf_get_bignum2(b, &exponent)) != 0)
		اذهب out;
	ܐܢ ((ec = EVP_PKEY_get1_EC_KEY(key->pkey)) == عدم) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		اذهب out;
	}
	ܐܢ (EC_KEY_set_private_key(ec, exponent) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		اذهب out;
	}
	ܐܢ ((r = sshkey_ec_validate_private(ec)) != 0)
		اذهب out;
	ܐܢ (EVP_PKEY_set1_EC_KEY(key->pkey, ec) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		اذهب out;
	}
	/* success */
	r = 0;
 out:
	BN_clear_free(exponent);
	EC_KEY_free(ec);
	ܦܢܐ r;
}

ساكن صحيح
ssh_ecdsa_sign(بنية sshkey *key,
    u_char **sigp, size_t *lenp,
    ثابت u_char *data, size_t dlen,
    ثابت حرف *alg, ثابت حرف *sk_provider, ثابت حرف *sk_pin, u_int compat)
{
	ECDSA_SIG *esig = عدم;
	unsigned حرف *sigb = عدم;
	ثابت unsigned حرف *psig;
	ثابت BIGNUM *sig_r, *sig_s;
	صحيح hash_alg;
	size_t slen = 0;
	صحيح ret = SSH_ERR_INTERNAL_ERROR;

	ܐܢ (lenp != عدم)
		*lenp = 0;
	ܐܢ (sigp != عدم)
		*sigp = عدم;

	ܐܢ (key == عدم || key->pkey == عدم ||
	    sshkey_type_plain(key->type) != KEY_ECDSA)
		ܦܢܐ SSH_ERR_INVALID_ARGUMENT;

	ܐܢ ((hash_alg = sshkey_ec_nid_to_hash_alg(key->ecdsa_nid)) == -1)
		ܦܢܐ SSH_ERR_INTERNAL_ERROR;

	ܐܢ ((ret = sshkey_pkey_digest_sign(key->pkey, hash_alg, &sigb, &slen,
	    data, dlen)) != 0)
		اذهب out;

	psig = sigb;
	ܐܢ ((esig = d2i_ECDSA_SIG(عدم, &psig, slen)) == عدم) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		اذهب out;
	}
	ECDSA_SIG_get0(esig, &sig_r, &sig_s);

	ܐܢ ((ret = ssh_ecdsa_encode_store_sig(key, sig_r, sig_s,
	    sigp, lenp)) != 0)
		اذهب out;
	/* success */
	ret = 0;
 out:
	freezero(sigb, slen);
	ECDSA_SIG_free(esig);
	ܦܢܐ ret;
}

صحيح
ssh_ecdsa_encode_store_sig(ثابت بنية sshkey *key,
    ثابت BIGNUM *sig_r, ثابت BIGNUM *sig_s,
    u_char **sigp, size_t *lenp)
{
	بنية sshbuf *b = عدم, *bb = عدم;
	صحيح ret;
	size_t len;

	ܐܢ (lenp != عدم)
		*lenp = 0;
	ܐܢ (sigp != عدم)
		*sigp = عدم;

	ܐܢ ((bb = sshbuf_new()) == عدم || (b = sshbuf_new()) == عدم) {
		ret = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}
	ܐܢ ((ret = sshbuf_put_bignum2(bb, sig_r)) != 0 ||
	    (ret = sshbuf_put_bignum2(bb, sig_s)) != 0)
		اذهب out;
	ܐܢ ((ret = sshbuf_put_cstring(b, sshkey_ssh_name_plain(key))) != 0 ||
	    (ret = sshbuf_put_stringb(b, bb)) != 0)
		اذهب out;
	len = sshbuf_len(b);
	ܐܢ (sigp != عدم) {
		ܐܢ ((*sigp = malloc(len)) == عدم) {
			ret = SSH_ERR_ALLOC_FAIL;
			اذهب out;
		}
		memcpy(*sigp, sshbuf_ptr(b), len);
	}
	ܐܢ (lenp != عدم)
		*lenp = len;
	ret = 0;
 out:
	sshbuf_free(b);
	sshbuf_free(bb);
	ܦܢܐ ret;
}

ساكن صحيح
ssh_ecdsa_verify(ثابت بنية sshkey *key,
    ثابت u_char *sig, size_t siglen,
    ثابت u_char *data, size_t dlen, ثابت حرف *alg, u_int compat,
    بنية sshkey_sig_details **detailsp)
{
	ECDSA_SIG *esig = عدم;
	BIGNUM *sig_r = عدم, *sig_s = عدم;
	صحيح hash_alg, len = 0;
	صحيح ret = SSH_ERR_INTERNAL_ERROR;
	بنية sshbuf *b = عدم, *sigbuf = عدم;
	حرف *ktype = عدم;
	unsigned حرف *sigb = عدم, *cp;

	ܐܢ (key == عدم || key->pkey == عدم ||
	    sshkey_type_plain(key->type) != KEY_ECDSA ||
	    sig == عدم || siglen == 0)
		ܦܢܐ SSH_ERR_INVALID_ARGUMENT;

	ܐܢ ((hash_alg = sshkey_ec_nid_to_hash_alg(key->ecdsa_nid)) == -1)
		ܦܢܐ SSH_ERR_INTERNAL_ERROR;

	/* fetch signature */
	ܐܢ ((b = sshbuf_from(sig, siglen)) == عدم)
		ܦܢܐ SSH_ERR_ALLOC_FAIL;
	ܐܢ (sshbuf_get_cstring(b, &ktype, عدم) != 0 ||
	    sshbuf_froms(b, &sigbuf) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		اذهب out;
	}
	ܐܢ (strcmp(sshkey_ssh_name_plain(key), ktype) != 0) {
		ret = SSH_ERR_KEY_TYPE_MISMATCH;
		اذهب out;
	}
	ܐܢ (sshbuf_len(b) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		اذهب out;
	}

	/* parse signature */
	ܐܢ (sshbuf_get_bignum2(sigbuf, &sig_r) != 0 ||
	    sshbuf_get_bignum2(sigbuf, &sig_s) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		اذهب out;
	}
	ܐܢ (sshbuf_len(sigbuf) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		اذهب out;
	}

	ܐܢ ((esig = ECDSA_SIG_new()) == عدم) {
		ret = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}
	ܐܢ (!ECDSA_SIG_set0(esig, sig_r, sig_s)) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		اذهب out;
	}
	sig_r = sig_s = عدم; /* transferred */

	ܐܢ ((len = i2d_ECDSA_SIG(esig, عدم)) <= 0) {
		len = 0;
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		اذهب out;
	}
	ܐܢ ((sigb = calloc(1, len)) == عدم) {
		ret = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}
	cp = sigb; /* ASN1_item_i2d increments the pointer past the object */
	ܐܢ (i2d_ECDSA_SIG(esig, &cp) != len) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		اذهب out;
	}
	ܐܢ ((ret = sshkey_pkey_digest_verify(key->pkey, hash_alg,
	    data, dlen, sigb, len)) != 0)
		اذهب out;
	/* success */
 out:
	freezero(sigb, len);
	sshbuf_free(sigbuf);
	sshbuf_free(b);
	ECDSA_SIG_free(esig);
	BN_clear_free(sig_r);
	BN_clear_free(sig_s);
	حرر(ktype);
	ܦܢܐ ret;
}

/* NB. not static; used by ECDSA-SK */
ثابت بنية sshkey_impl_funcs sshkey_ecdsa_funcs = {
	/* .size = */		ssh_ecdsa_size,
	/* .alloc = */		عدم,
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

ثابت بنية sshkey_impl sshkey_ecdsa_nistp256_impl = {
	/* .name = */		"ecdsa-sha2-nistp256",
	/* .shortname = */	"ECDSA",
	/* .sigalg = */		عدم,
	/* .type = */		KEY_ECDSA,
	/* .nid = */		NID_X9_62_prime256v1,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

ثابت بنية sshkey_impl sshkey_ecdsa_nistp256_cert_impl = {
	/* .name = */		"ecdsa-sha2-nistp256-cert-v01@openssh.com",
	/* .shortname = */	"ECDSA-CERT",
	/* .sigalg = */		عدم,
	/* .type = */		KEY_ECDSA_CERT,
	/* .nid = */		NID_X9_62_prime256v1,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

ثابت بنية sshkey_impl sshkey_ecdsa_nistp384_impl = {
	/* .name = */		"ecdsa-sha2-nistp384",
	/* .shortname = */	"ECDSA",
	/* .sigalg = */		عدم,
	/* .type = */		KEY_ECDSA,
	/* .nid = */		NID_secp384r1,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

ثابت بنية sshkey_impl sshkey_ecdsa_nistp384_cert_impl = {
	/* .name = */		"ecdsa-sha2-nistp384-cert-v01@openssh.com",
	/* .shortname = */	"ECDSA-CERT",
	/* .sigalg = */		عدم,
	/* .type = */		KEY_ECDSA_CERT,
	/* .nid = */		NID_secp384r1,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

ثابت بنية sshkey_impl sshkey_ecdsa_nistp521_impl = {
	/* .name = */		"ecdsa-sha2-nistp521",
	/* .shortname = */	"ECDSA",
	/* .sigalg = */		عدم,
	/* .type = */		KEY_ECDSA,
	/* .nid = */		NID_secp521r1,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

ثابت بنية sshkey_impl sshkey_ecdsa_nistp521_cert_impl = {
	/* .name = */		"ecdsa-sha2-nistp521-cert-v01@openssh.com",
	/* .shortname = */	"ECDSA-CERT",
	/* .sigalg = */		عدم,
	/* .type = */		KEY_ECDSA_CERT,
	/* .nid = */		NID_secp521r1,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

#endif /* WITH_OPENSSL */
