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

#অন্তর্ভাৱ "includes.h"

#যদি defined(WITH_OPENSSL)
#অন্তর্ভাৱ "openbsd-compat/openssl-compat.h"

#অন্তর্ভাৱ <sys/types.h>

#অন্তর্ভাৱ <openssl/bn.h>
#অন্তর্ভাৱ <openssl/ec.h>
#অন্তর্ভাৱ <openssl/ecdsa.h>
#অন্তর্ভাৱ <openssl/evp.h>

#অন্তর্ভাৱ <string.h>

#অন্তর্ভাৱ "sshbuf.h"
#অন্তর্ভাৱ "ssherr.h"
#define SSHKEY_INTERNAL
#অন্তর্ভাৱ "sshkey.h"

পূর্ণাঙ্ক
sshkey_ecdsa_fixup_group(EVP_PKEY *k)
{
	পূর্ণাঙ্ক nids[] = {
		NID_X9_62_prime256v1,
		NID_secp384r1,
		NID_secp521r1,
		-1
	};
	পূর্ণাঙ্ক nid = -1;
	u_int i;
	ধ্রুৱ EC_GROUP *g;
	EC_চাবি *ec = রিক্ত;
	EC_GROUP *eg = রিক্ত;

	যদি ((ec = EVP_PKEY_get1_EC_চাবি(k)) == রিক্ত ||
	    (g = EC_চাবি_get0_group(ec)) == রিক্ত)
		গচ্ছ out;
	/*
	 * The group may be stored in a ASN.1 encoded private key in one of two
	 * ways: as a "named group", which is reconstituted by ASN.1 object ID
	 * or explicit group parameters encoded into the key blob. Only the
	 * "named group" case sets the group NID for us, but we can figure
	 * it out for the other case by comparing against all the groups that
	 * are supported.
	 */
	যদি ((nid = EC_GROUP_get_curve_name(g)) > 0)
		গচ্ছ out;
	nid = -1;
	বাবে (i = 0; nids[i] != -1; i++) {
		যদি ((eg = EC_GROUP_new_by_curve_name(nids[i])) == রিক্ত)
			গচ্ছ out;
		যদি (EC_GROUP_cmp(g, eg, রিক্ত) == 0)
			ভঙ্গ;
		EC_GROUP_free(eg);
		eg = রিক্ত;
	}
	যদি (nids[i] == -1)
		গচ্ছ out;

	/* Use the group with the NID attached */
	EC_GROUP_set_asn1_flag(eg, OPENSSL_EC_NAMED_CURVE);
	যদি (EC_চাবি_set_group(ec, eg) != 1 ||
	    EVP_PKEY_set1_EC_চাবি(k, ec) != 1)
		গচ্ছ out;
	/* success */
	nid = nids[i];
 out:
	EC_চাবি_free(ec);
	EC_GROUP_free(eg);
	ঘূৰাই nid;
}

স্থির u_int
ssh_ecdsa_size(ধ্রুৱ সংরচনা sshkey *চাবি)
{
	ৱিকল্প (চাবি->ecdsa_nid) {
	পক্ষ NID_X9_62_prime256v1:
		ঘূৰাই 256;
	পক্ষ NID_secp384r1:
		ঘূৰাই 384;
	পক্ষ NID_secp521r1:
		ঘূৰাই 521;
	স্ৱভাৱ:
		ঘূৰাই 0;
	}
}

স্থির শূন্য
ssh_ecdsa_cleanup(সংরচনা sshkey *k)
{
	EVP_PKEY_free(k->pkey);
	k->pkey = রিক্ত;
}

স্থির পূর্ণাঙ্ক
ssh_ecdsa_equal(ধ্রুৱ সংরচনা sshkey *a, ধ্রুৱ সংরচনা sshkey *b)
{
	যদি (a->pkey == রিক্ত || b->pkey == রিক্ত)
		ঘূৰাই 0;
	ঘূৰাই EVP_PKEY_cmp(a->pkey, b->pkey) == 1;
}

স্থির পূর্ণাঙ্ক
ssh_ecdsa_serialize_public(ধ্রুৱ সংরচনা sshkey *চাবি, সংরচনা sshbuf *b,
    গণনা sshkey_serialize_rep opts)
{
	পূর্ণাঙ্ক r;

	যদি (চাবি->pkey == রিক্ত)
		ঘূৰাই SSH_ERR_INVALID_ARGUMENT;
	যদি ((r = sshbuf_put_cstring(b,
	    sshkey_curve_nid_to_name(চাবি->ecdsa_nid))) != 0 ||
	    (r = sshbuf_put_ec_pkey(b, চাবি->pkey)) != 0)
		ঘূৰাই r;

	ঘূৰাই 0;
}

স্থির পূর্ণাঙ্ক
ssh_ecdsa_serialize_private(ধ্রুৱ সংরচনা sshkey *চাবি, সংরচনা sshbuf *b,
    গণনা sshkey_serialize_rep opts)
{
	পূর্ণাঙ্ক r;

	যদি (!sshkey_is_cert(চাবি)) {
		যদি ((r = ssh_ecdsa_serialize_public(চাবি, b, opts)) != 0)
			ঘূৰাই r;
	}
	যদি ((r = sshbuf_put_bignum2(b,
	    EC_চাবি_get0_private_চাবি(EVP_PKEY_get0_EC_চাবি(চাবি->pkey)))) != 0)
		ঘূৰাই r;
	ঘূৰাই 0;
}

স্থির পূর্ণাঙ্ক
ssh_ecdsa_generate(সংরচনা sshkey *k, পূর্ণাঙ্ক bits)
{
	EVP_PKEY *res = রিক্ত;
	EVP_PKEY_CTX *ctx = রিক্ত;
	পূর্ণাঙ্ক ret = SSH_ERR_INTERNAL_ERROR;

	যদি ((k->ecdsa_nid = sshkey_ecdsa_bits_to_nid(bits)) == -1)
		ঘূৰাই SSH_ERR_চাবি_LENGTH;

	যদি ((ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, রিক্ত)) == রিক্ত)
		ঘূৰাই SSH_ERR_ALLOC_FAIL;

	যদি (EVP_PKEY_keygen_init(ctx) <= 0 ||
	    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, k->ecdsa_nid) <= 0 ||
	    EVP_PKEY_keygen(ctx, &res) <= 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		গচ্ছ out;
	}
	/* success */
	k->pkey = res;
	res = রিক্ত;
	ret = 0;
 out:
	EVP_PKEY_free(res);
	EVP_PKEY_CTX_free(ctx);
	ঘূৰাই ret;
}

স্থির পূর্ণাঙ্ক
ssh_ecdsa_copy_public(ধ্রুৱ সংরচনা sshkey *from, সংরচনা sshkey *to)
{
	ধ্রুৱ EC_চাবি *ec_from;
	EC_চাবি *ec_to = রিক্ত;
	পূর্ণাঙ্ক ret = SSH_ERR_INTERNAL_ERROR;

	ec_from = EVP_PKEY_get0_EC_চাবি(from->pkey);
	যদি (ec_from == রিক্ত)
		ঘূৰাই SSH_ERR_LIBCRYPTO_ERROR;

	to->ecdsa_nid = from->ecdsa_nid;
	যদি ((ec_to = EC_চাবি_new_by_curve_name(from->ecdsa_nid)) == রিক্ত)
		ঘূৰাই SSH_ERR_ALLOC_FAIL;
	যদি (EC_চাবি_set_public_চাবি(ec_to,
	    EC_চাবি_get0_public_চাবি(ec_from)) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		গচ্ছ out;
	}
	EVP_PKEY_free(to->pkey);
	যদি ((to->pkey = EVP_PKEY_new()) == রিক্ত) {
		ret = SSH_ERR_ALLOC_FAIL;
		গচ্ছ out;
	}
	যদি (EVP_PKEY_set1_EC_চাবি(to->pkey, ec_to) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		গচ্ছ out;
	}
	ret = 0;
 out:
	EC_চাবি_free(ec_to);
	ঘূৰাই ret;
}

স্থির পূর্ণাঙ্ক
ssh_ecdsa_deserialize_public(ধ্রুৱ ৱর্ণ *ktype, সংরচনা sshbuf *b,
    সংরচনা sshkey *চাবি)
{
	পূর্ণাঙ্ক r;
	ৱর্ণ *curve = রিক্ত;
	EVP_PKEY *pkey = রিক্ত;
	EC_চাবি *ec = রিক্ত;

	যদি ((চাবি->ecdsa_nid = sshkey_ecdsa_nid_from_name(ktype)) == -1)
		ঘূৰাই SSH_ERR_INVALID_ARGUMENT;
	যদি ((r = sshbuf_get_cstring(b, &curve, রিক্ত)) != 0)
		গচ্ছ out;
	যদি (চাবি->ecdsa_nid != sshkey_curve_name_to_nid(curve)) {
		r = SSH_ERR_EC_CURVE_MISMATCH;
		গচ্ছ out;
	}
	যদি ((ec = EC_চাবি_new_by_curve_name(চাবি->ecdsa_nid)) == রিক্ত) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		গচ্ছ out;
	}
	যদি ((r = sshbuf_get_eckey(b, ec)) != 0)
		গচ্ছ out;
	যদি (sshkey_ec_validate_public(EC_চাবি_get0_group(ec),
	    EC_চাবি_get0_public_চাবি(ec)) != 0) {
		r = SSH_ERR_চাবি_INVALID_EC_মান;
		গচ্ছ out;
	}
	যদি ((pkey = EVP_PKEY_new()) == রিক্ত) {
		r = SSH_ERR_ALLOC_FAIL;
		গচ্ছ out;
	}
	যদি (EVP_PKEY_set1_EC_চাবি(pkey, ec) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		গচ্ছ out;
	}
	EVP_PKEY_free(চাবি->pkey);
	চাবি->pkey = pkey;
	pkey = রিক্ত;
	/* success */
	r = 0;
#ifdef DEBUG_PK
	sshkey_dump_ec_point(
	    EC_চাবি_get0_group(EVP_PKEY_get0_EC_চাবি(চাবি->pkey)),
	    EC_চাবি_get0_public_চাবি(EVP_PKEY_get0_EC_চাবি(চাবি->pkey)));
#endif
 out:
	EC_চাবি_free(ec);
	EVP_PKEY_free(pkey);
	মুক্ত(curve);
	ঘূৰাই r;
}

স্থির পূর্ণাঙ্ক
ssh_ecdsa_deserialize_private(ধ্রুৱ ৱর্ণ *ktype, সংরচনা sshbuf *b,
    সংরচনা sshkey *চাবি)
{
	পূর্ণাঙ্ক r;
	BIGNUM *exponent = রিক্ত;
	EC_চাবি *ec = রিক্ত;

	যদি (!sshkey_is_cert(চাবি)) {
		যদি ((r = ssh_ecdsa_deserialize_public(ktype, b, চাবি)) != 0)
			ঘূৰাই r;
	}
	যদি ((r = sshbuf_get_bignum2(b, &exponent)) != 0)
		গচ্ছ out;
	যদি ((ec = EVP_PKEY_get1_EC_চাবি(চাবি->pkey)) == রিক্ত) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		গচ্ছ out;
	}
	যদি (EC_চাবি_set_private_চাবি(ec, exponent) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		গচ্ছ out;
	}
	যদি ((r = sshkey_ec_validate_private(ec)) != 0)
		গচ্ছ out;
	যদি (EVP_PKEY_set1_EC_চাবি(চাবি->pkey, ec) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		গচ্ছ out;
	}
	/* success */
	r = 0;
 out:
	BN_clear_free(exponent);
	EC_চাবি_free(ec);
	ঘূৰাই r;
}

স্থির পূর্ণাঙ্ক
ssh_ecdsa_sign(সংরচনা sshkey *চাবি,
    u_char **sigp, size_t *lenp,
    ধ্রুৱ u_char *data, size_t dlen,
    ধ্রুৱ ৱর্ণ *alg, ধ্রুৱ ৱর্ণ *sk_provider, ধ্রুৱ ৱর্ণ *sk_pin, u_int compat)
{
	ECDSA_SIG *esig = রিক্ত;
	unsigned ৱর্ণ *sigb = রিক্ত;
	ধ্রুৱ unsigned ৱর্ণ *psig;
	ধ্রুৱ BIGNUM *sig_r, *sig_s;
	পূর্ণাঙ্ক hash_alg;
	size_t slen = 0;
	পূর্ণাঙ্ক ret = SSH_ERR_INTERNAL_ERROR;

	যদি (lenp != রিক্ত)
		*lenp = 0;
	যদি (sigp != রিক্ত)
		*sigp = রিক্ত;

	যদি (চাবি == রিক্ত || চাবি->pkey == রিক্ত ||
	    sshkey_type_plain(চাবি->type) != চাবি_ECDSA)
		ঘূৰাই SSH_ERR_INVALID_ARGUMENT;

	যদি ((hash_alg = sshkey_ec_nid_to_hash_alg(চাবি->ecdsa_nid)) == -1)
		ঘূৰাই SSH_ERR_INTERNAL_ERROR;

	যদি ((ret = sshkey_pkey_digest_sign(চাবি->pkey, hash_alg, &sigb, &slen,
	    data, dlen)) != 0)
		গচ্ছ out;

	psig = sigb;
	যদি ((esig = d2i_ECDSA_SIG(রিক্ত, &psig, slen)) == রিক্ত) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		গচ্ছ out;
	}
	ECDSA_SIG_get0(esig, &sig_r, &sig_s);

	যদি ((ret = ssh_ecdsa_encode_store_sig(চাবি, sig_r, sig_s,
	    sigp, lenp)) != 0)
		গচ্ছ out;
	/* success */
	ret = 0;
 out:
	freezero(sigb, slen);
	ECDSA_SIG_free(esig);
	ঘূৰাই ret;
}

পূর্ণাঙ্ক
ssh_ecdsa_encode_store_sig(ধ্রুৱ সংরচনা sshkey *চাবি,
    ধ্রুৱ BIGNUM *sig_r, ধ্রুৱ BIGNUM *sig_s,
    u_char **sigp, size_t *lenp)
{
	সংরচনা sshbuf *b = রিক্ত, *bb = রিক্ত;
	পূর্ণাঙ্ক ret;
	size_t len;

	যদি (lenp != রিক্ত)
		*lenp = 0;
	যদি (sigp != রিক্ত)
		*sigp = রিক্ত;

	যদি ((bb = sshbuf_new()) == রিক্ত || (b = sshbuf_new()) == রিক্ত) {
		ret = SSH_ERR_ALLOC_FAIL;
		গচ্ছ out;
	}
	যদি ((ret = sshbuf_put_bignum2(bb, sig_r)) != 0 ||
	    (ret = sshbuf_put_bignum2(bb, sig_s)) != 0)
		গচ্ছ out;
	যদি ((ret = sshbuf_put_cstring(b, sshkey_ssh_name_plain(চাবি))) != 0 ||
	    (ret = sshbuf_put_stringb(b, bb)) != 0)
		গচ্ছ out;
	len = sshbuf_len(b);
	যদি (sigp != রিক্ত) {
		যদি ((*sigp = malloc(len)) == রিক্ত) {
			ret = SSH_ERR_ALLOC_FAIL;
			গচ্ছ out;
		}
		memcpy(*sigp, sshbuf_ptr(b), len);
	}
	যদি (lenp != রিক্ত)
		*lenp = len;
	ret = 0;
 out:
	sshbuf_free(b);
	sshbuf_free(bb);
	ঘূৰাই ret;
}

স্থির পূর্ণাঙ্ক
ssh_ecdsa_verify(ধ্রুৱ সংরচনা sshkey *চাবি,
    ধ্রুৱ u_char *sig, size_t siglen,
    ধ্রুৱ u_char *data, size_t dlen, ধ্রুৱ ৱর্ণ *alg, u_int compat,
    সংরচনা sshkey_sig_details **detailsp)
{
	ECDSA_SIG *esig = রিক্ত;
	BIGNUM *sig_r = রিক্ত, *sig_s = রিক্ত;
	পূর্ণাঙ্ক hash_alg, len = 0;
	পূর্ণাঙ্ক ret = SSH_ERR_INTERNAL_ERROR;
	সংরচনা sshbuf *b = রিক্ত, *sigbuf = রিক্ত;
	ৱর্ণ *ktype = রিক্ত;
	unsigned ৱর্ণ *sigb = রিক্ত, *cp;

	যদি (চাবি == রিক্ত || চাবি->pkey == রিক্ত ||
	    sshkey_type_plain(চাবি->type) != চাবি_ECDSA ||
	    sig == রিক্ত || siglen == 0)
		ঘূৰাই SSH_ERR_INVALID_ARGUMENT;

	যদি ((hash_alg = sshkey_ec_nid_to_hash_alg(চাবি->ecdsa_nid)) == -1)
		ঘূৰাই SSH_ERR_INTERNAL_ERROR;

	/* fetch signature */
	যদি ((b = sshbuf_from(sig, siglen)) == রিক্ত)
		ঘূৰাই SSH_ERR_ALLOC_FAIL;
	যদি (sshbuf_get_cstring(b, &ktype, রিক্ত) != 0 ||
	    sshbuf_froms(b, &sigbuf) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		গচ্ছ out;
	}
	যদি (strcmp(sshkey_ssh_name_plain(চাবি), ktype) != 0) {
		ret = SSH_ERR_চাবি_TYPE_MISMATCH;
		গচ্ছ out;
	}
	যদি (sshbuf_len(b) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		গচ্ছ out;
	}

	/* parse signature */
	যদি (sshbuf_get_bignum2(sigbuf, &sig_r) != 0 ||
	    sshbuf_get_bignum2(sigbuf, &sig_s) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		গচ্ছ out;
	}
	যদি (sshbuf_len(sigbuf) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		গচ্ছ out;
	}

	যদি ((esig = ECDSA_SIG_new()) == রিক্ত) {
		ret = SSH_ERR_ALLOC_FAIL;
		গচ্ছ out;
	}
	যদি (!ECDSA_SIG_set0(esig, sig_r, sig_s)) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		গচ্ছ out;
	}
	sig_r = sig_s = রিক্ত; /* transferred */

	যদি ((len = i2d_ECDSA_SIG(esig, রিক্ত)) <= 0) {
		len = 0;
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		গচ্ছ out;
	}
	যদি ((sigb = calloc(1, len)) == রিক্ত) {
		ret = SSH_ERR_ALLOC_FAIL;
		গচ্ছ out;
	}
	cp = sigb; /* ASN1_item_i2d increments the pointer past the object */
	যদি (i2d_ECDSA_SIG(esig, &cp) != len) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		গচ্ছ out;
	}
	যদি ((ret = sshkey_pkey_digest_verify(চাবি->pkey, hash_alg,
	    data, dlen, sigb, len)) != 0)
		গচ্ছ out;
	/* success */
 out:
	freezero(sigb, len);
	sshbuf_free(sigbuf);
	sshbuf_free(b);
	ECDSA_SIG_free(esig);
	BN_clear_free(sig_r);
	BN_clear_free(sig_s);
	মুক্ত(ktype);
	ঘূৰাই ret;
}

/* NB. not static; used by ECDSA-SK */
ধ্রুৱ সংরচনা sshkey_impl_funcs sshkey_ecdsa_funcs = {
	/* .size = */		ssh_ecdsa_size,
	/* .alloc = */		রিক্ত,
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

ধ্রুৱ সংরচনা sshkey_impl sshkey_ecdsa_nistp256_impl = {
	/* .name = */		"ecdsa-sha2-nistp256",
	/* .shortname = */	"ECDSA",
	/* .sigalg = */		রিক্ত,
	/* .type = */		চাবি_ECDSA,
	/* .nid = */		NID_X9_62_prime256v1,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

ধ্রুৱ সংরচনা sshkey_impl sshkey_ecdsa_nistp256_cert_impl = {
	/* .name = */		"ecdsa-sha2-nistp256-cert-v01@openssh.com",
	/* .shortname = */	"ECDSA-CERT",
	/* .sigalg = */		রিক্ত,
	/* .type = */		চাবি_ECDSA_CERT,
	/* .nid = */		NID_X9_62_prime256v1,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

ধ্রুৱ সংরচনা sshkey_impl sshkey_ecdsa_nistp384_impl = {
	/* .name = */		"ecdsa-sha2-nistp384",
	/* .shortname = */	"ECDSA",
	/* .sigalg = */		রিক্ত,
	/* .type = */		চাবি_ECDSA,
	/* .nid = */		NID_secp384r1,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

ধ্রুৱ সংরচনা sshkey_impl sshkey_ecdsa_nistp384_cert_impl = {
	/* .name = */		"ecdsa-sha2-nistp384-cert-v01@openssh.com",
	/* .shortname = */	"ECDSA-CERT",
	/* .sigalg = */		রিক্ত,
	/* .type = */		চাবি_ECDSA_CERT,
	/* .nid = */		NID_secp384r1,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

ধ্রুৱ সংরচনা sshkey_impl sshkey_ecdsa_nistp521_impl = {
	/* .name = */		"ecdsa-sha2-nistp521",
	/* .shortname = */	"ECDSA",
	/* .sigalg = */		রিক্ত,
	/* .type = */		চাবি_ECDSA,
	/* .nid = */		NID_secp521r1,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

ধ্রুৱ সংরচনা sshkey_impl sshkey_ecdsa_nistp521_cert_impl = {
	/* .name = */		"ecdsa-sha2-nistp521-cert-v01@openssh.com",
	/* .shortname = */	"ECDSA-CERT",
	/* .sigalg = */		রিক্ত,
	/* .type = */		চাবি_ECDSA_CERT,
	/* .nid = */		NID_secp521r1,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

#endif /* WITH_OPENSSL */
