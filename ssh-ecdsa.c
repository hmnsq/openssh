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

#অন্তর্ভাব "includes.h"

#যদি defined(WITH_OPENSSL)
#অন্তর্ভাব "openbsd-compat/openssl-compat.h"

#অন্তর্ভাব <sys/types.h>

#অন্তর্ভাব <openssl/bn.h>
#অন্তর্ভাব <openssl/ec.h>
#অন্তর্ভাব <openssl/ecdsa.h>
#অন্তর্ভাব <openssl/evp.h>

#অন্তর্ভাব <string.h>

#অন্তর্ভাব "sshbuf.h"
#অন্তর্ভাব "ssherr.h"
#define SSHKEY_INTERNAL
#অন্তর্ভাব "sshkey.h"

পূর্ণসংখ্যা
sshkey_ecdsa_fixup_group(EVP_PKEY *k)
{
	পূর্ণসংখ্যা nids[] = {
		NID_X9_62_prime256v1,
		NID_secp384r1,
		NID_secp521r1,
		-1
	};
	পূর্ণসংখ্যা nid = -1;
	u_int i;
	ধ্রুবক EC_GROUP *g;
	EC_চাবি *ec = ফাঁকা;
	EC_GROUP *eg = ফাঁকা;

	যদি ((ec = EVP_PKEY_get1_EC_চাবি(k)) == ফাঁকা ||
	    (g = EC_চাবি_get0_group(ec)) == ফাঁকা)
		যাও out;
	/*
	 * The group may be stored in a ASN.1 encoded private key in one of two
	 * ways: as a "named group", which is reconstituted by ASN.1 object ID
	 * or explicit group parameters encoded into the key blob. Only the
	 * "named group" case sets the group NID for us, but we can figure
	 * it out for the other case by comparing against all the groups that
	 * are supported.
	 */
	যদি ((nid = EC_GROUP_get_curve_name(g)) > 0)
		যাও out;
	nid = -1;
	জন্য (i = 0; nids[i] != -1; i++) {
		যদি ((eg = EC_GROUP_new_by_curve_name(nids[i])) == ফাঁকা)
			যাও out;
		যদি (EC_GROUP_cmp(g, eg, ফাঁকা) == 0)
			বিরতি;
		EC_GROUP_free(eg);
		eg = ফাঁকা;
	}
	যদি (nids[i] == -1)
		যাও out;

	/* Use the group with the NID attached */
	EC_GROUP_set_asn1_flag(eg, OPENSSL_EC_NAMED_CURVE);
	যদি (EC_চাবি_set_group(ec, eg) != 1 ||
	    EVP_PKEY_set1_EC_চাবি(k, ec) != 1)
		যাও out;
	/* success */
	nid = nids[i];
 out:
	EC_চাবি_free(ec);
	EC_GROUP_free(eg);
	ফেরত nid;
}

স্থির u_int
ssh_ecdsa_আকার(ধ্রুবক কাঠামো sshkey *চাবি)
{
	নির্বাচন (চাবি->ecdsa_nid) {
	ক্ষেত্র NID_X9_62_prime256v1:
		ফেরত 256;
	ক্ষেত্র NID_secp384r1:
		ফেরত 384;
	ক্ষেত্র NID_secp521r1:
		ফেরত 521;
	পূর্বনির্ধারিত:
		ফেরত 0;
	}
}

স্থির শূন্য
ssh_ecdsa_cleanup(কাঠামো sshkey *k)
{
	EVP_PKEY_free(k->pkey);
	k->pkey = ফাঁকা;
}

স্থির পূর্ণসংখ্যা
ssh_ecdsa_equal(ধ্রুবক কাঠামো sshkey *a, ধ্রুবক কাঠামো sshkey *b)
{
	যদি (a->pkey == ফাঁকা || b->pkey == ফাঁকা)
		ফেরত 0;
	ফেরত EVP_PKEY_cmp(a->pkey, b->pkey) == 1;
}

স্থির পূর্ণসংখ্যা
ssh_ecdsa_serialize_public(ধ্রুবক কাঠামো sshkey *চাবি, কাঠামো sshbuf *b,
    গণনা sshkey_serialize_rep opts)
{
	পূর্ণসংখ্যা r;

	যদি (চাবি->pkey == ফাঁকা)
		ফেরত SSH_ERR_INVALID_ARGUMENT;
	যদি ((r = sshbuf_put_cstring(b,
	    sshkey_curve_nid_to_name(চাবি->ecdsa_nid))) != 0 ||
	    (r = sshbuf_put_ec_pkey(b, চাবি->pkey)) != 0)
		ফেরত r;

	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
ssh_ecdsa_serialize_private(ধ্রুবক কাঠামো sshkey *চাবি, কাঠামো sshbuf *b,
    গণনা sshkey_serialize_rep opts)
{
	পূর্ণসংখ্যা r;

	যদি (!sshkey_is_cert(চাবি)) {
		যদি ((r = ssh_ecdsa_serialize_public(চাবি, b, opts)) != 0)
			ফেরত r;
	}
	যদি ((r = sshbuf_put_bignum2(b,
	    EC_চাবি_get0_private_চাবি(EVP_PKEY_get0_EC_চাবি(চাবি->pkey)))) != 0)
		ফেরত r;
	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
ssh_ecdsa_generate(কাঠামো sshkey *k, পূর্ণসংখ্যা bits)
{
	EVP_PKEY *res = ফাঁকা;
	EVP_PKEY_CTX *ctx = ফাঁকা;
	পূর্ণসংখ্যা ret = SSH_ERR_INTERNAL_ERROR;

	যদি ((k->ecdsa_nid = sshkey_ecdsa_bits_to_nid(bits)) == -1)
		ফেরত SSH_ERR_চাবি_দৈর্ঘ্য;

	যদি ((ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, ফাঁকা)) == ফাঁকা)
		ফেরত SSH_ERR_ALLOC_FAIL;

	যদি (EVP_PKEY_keygen_init(ctx) <= 0 ||
	    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, k->ecdsa_nid) <= 0 ||
	    EVP_PKEY_keygen(ctx, &res) <= 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		যাও out;
	}
	/* success */
	k->pkey = res;
	res = ফাঁকা;
	ret = 0;
 out:
	EVP_PKEY_free(res);
	EVP_PKEY_CTX_free(ctx);
	ফেরত ret;
}

স্থির পূর্ণসংখ্যা
ssh_ecdsa_copy_public(ধ্রুবক কাঠামো sshkey *from, কাঠামো sshkey *to)
{
	ধ্রুবক EC_চাবি *ec_from;
	EC_চাবি *ec_to = ফাঁকা;
	পূর্ণসংখ্যা ret = SSH_ERR_INTERNAL_ERROR;

	ec_from = EVP_PKEY_get0_EC_চাবি(from->pkey);
	যদি (ec_from == ফাঁকা)
		ফেরত SSH_ERR_LIBCRYPTO_ERROR;

	to->ecdsa_nid = from->ecdsa_nid;
	যদি ((ec_to = EC_চাবি_new_by_curve_name(from->ecdsa_nid)) == ফাঁকা)
		ফেরত SSH_ERR_ALLOC_FAIL;
	যদি (EC_চাবি_set_public_চাবি(ec_to,
	    EC_চাবি_get0_public_চাবি(ec_from)) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		যাও out;
	}
	EVP_PKEY_free(to->pkey);
	যদি ((to->pkey = EVP_PKEY_new()) == ফাঁকা) {
		ret = SSH_ERR_ALLOC_FAIL;
		যাও out;
	}
	যদি (EVP_PKEY_set1_EC_চাবি(to->pkey, ec_to) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		যাও out;
	}
	ret = 0;
 out:
	EC_চাবি_free(ec_to);
	ফেরত ret;
}

স্থির পূর্ণসংখ্যা
ssh_ecdsa_deserialize_public(ধ্রুবক অক্ষর *ktype, কাঠামো sshbuf *b,
    কাঠামো sshkey *চাবি)
{
	পূর্ণসংখ্যা r;
	অক্ষর *curve = ফাঁকা;
	EVP_PKEY *pkey = ফাঁকা;
	EC_চাবি *ec = ফাঁকা;

	যদি ((চাবি->ecdsa_nid = sshkey_ecdsa_nid_from_name(ktype)) == -1)
		ফেরত SSH_ERR_INVALID_ARGUMENT;
	যদি ((r = sshbuf_get_cstring(b, &curve, ফাঁকা)) != 0)
		যাও out;
	যদি (চাবি->ecdsa_nid != sshkey_curve_name_to_nid(curve)) {
		r = SSH_ERR_EC_CURVE_MISMATCH;
		যাও out;
	}
	যদি ((ec = EC_চাবি_new_by_curve_name(চাবি->ecdsa_nid)) == ফাঁকা) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		যাও out;
	}
	যদি ((r = sshbuf_get_eckey(b, ec)) != 0)
		যাও out;
	যদি (sshkey_ec_validate_public(EC_চাবি_get0_group(ec),
	    EC_চাবি_get0_public_চাবি(ec)) != 0) {
		r = SSH_ERR_চাবি_INVALID_EC_মান;
		যাও out;
	}
	যদি ((pkey = EVP_PKEY_new()) == ফাঁকা) {
		r = SSH_ERR_ALLOC_FAIL;
		যাও out;
	}
	যদি (EVP_PKEY_set1_EC_চাবি(pkey, ec) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		যাও out;
	}
	EVP_PKEY_free(চাবি->pkey);
	চাবি->pkey = pkey;
	pkey = ফাঁকা;
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
	ফেরত r;
}

স্থির পূর্ণসংখ্যা
ssh_ecdsa_deserialize_private(ধ্রুবক অক্ষর *ktype, কাঠামো sshbuf *b,
    কাঠামো sshkey *চাবি)
{
	পূর্ণসংখ্যা r;
	BIGNUM *exponent = ফাঁকা;
	EC_চাবি *ec = ফাঁকা;

	যদি (!sshkey_is_cert(চাবি)) {
		যদি ((r = ssh_ecdsa_deserialize_public(ktype, b, চাবি)) != 0)
			ফেরত r;
	}
	যদি ((r = sshbuf_get_bignum2(b, &exponent)) != 0)
		যাও out;
	যদি ((ec = EVP_PKEY_get1_EC_চাবি(চাবি->pkey)) == ফাঁকা) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		যাও out;
	}
	যদি (EC_চাবি_set_private_চাবি(ec, exponent) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		যাও out;
	}
	যদি ((r = sshkey_ec_validate_private(ec)) != 0)
		যাও out;
	যদি (EVP_PKEY_set1_EC_চাবি(চাবি->pkey, ec) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		যাও out;
	}
	/* success */
	r = 0;
 out:
	BN_clear_free(exponent);
	EC_চাবি_free(ec);
	ফেরত r;
}

স্থির পূর্ণসংখ্যা
ssh_ecdsa_sign(কাঠামো sshkey *চাবি,
    u_char **sigp, আকার_t *lenp,
    ধ্রুবক u_char *তথ্য, আকার_t dlen,
    ধ্রুবক অক্ষর *alg, ধ্রুবক অক্ষর *sk_provider, ধ্রুবক অক্ষর *sk_pin, u_int compat)
{
	ECDSA_SIG *esig = ফাঁকা;
	unsigned অক্ষর *sigb = ফাঁকা;
	ধ্রুবক unsigned অক্ষর *psig;
	ধ্রুবক BIGNUM *sig_r, *sig_s;
	পূর্ণসংখ্যা hash_alg;
	আকার_t slen = 0;
	পূর্ণসংখ্যা ret = SSH_ERR_INTERNAL_ERROR;

	যদি (lenp != ফাঁকা)
		*lenp = 0;
	যদি (sigp != ফাঁকা)
		*sigp = ফাঁকা;

	যদি (চাবি == ফাঁকা || চাবি->pkey == ফাঁকা ||
	    sshkey_type_plain(চাবি->type) != চাবি_ECDSA)
		ফেরত SSH_ERR_INVALID_ARGUMENT;

	যদি ((hash_alg = sshkey_ec_nid_to_hash_alg(চাবি->ecdsa_nid)) == -1)
		ফেরত SSH_ERR_INTERNAL_ERROR;

	যদি ((ret = sshkey_pkey_digest_sign(চাবি->pkey, hash_alg, &sigb, &slen,
	    তথ্য, dlen)) != 0)
		যাও out;

	psig = sigb;
	যদি ((esig = d2i_ECDSA_SIG(ফাঁকা, &psig, slen)) == ফাঁকা) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		যাও out;
	}
	ECDSA_SIG_get0(esig, &sig_r, &sig_s);

	যদি ((ret = ssh_ecdsa_encode_store_sig(চাবি, sig_r, sig_s,
	    sigp, lenp)) != 0)
		যাও out;
	/* success */
	ret = 0;
 out:
	freezero(sigb, slen);
	ECDSA_SIG_free(esig);
	ফেরত ret;
}

পূর্ণসংখ্যা
ssh_ecdsa_encode_store_sig(ধ্রুবক কাঠামো sshkey *চাবি,
    ধ্রুবক BIGNUM *sig_r, ধ্রুবক BIGNUM *sig_s,
    u_char **sigp, আকার_t *lenp)
{
	কাঠামো sshbuf *b = ফাঁকা, *bb = ফাঁকা;
	পূর্ণসংখ্যা ret;
	আকার_t len;

	যদি (lenp != ফাঁকা)
		*lenp = 0;
	যদি (sigp != ফাঁকা)
		*sigp = ফাঁকা;

	যদি ((bb = sshbuf_new()) == ফাঁকা || (b = sshbuf_new()) == ফাঁকা) {
		ret = SSH_ERR_ALLOC_FAIL;
		যাও out;
	}
	যদি ((ret = sshbuf_put_bignum2(bb, sig_r)) != 0 ||
	    (ret = sshbuf_put_bignum2(bb, sig_s)) != 0)
		যাও out;
	যদি ((ret = sshbuf_put_cstring(b, sshkey_ssh_name_plain(চাবি))) != 0 ||
	    (ret = sshbuf_put_stringb(b, bb)) != 0)
		যাও out;
	len = sshbuf_len(b);
	যদি (sigp != ফাঁকা) {
		যদি ((*sigp = malloc(len)) == ফাঁকা) {
			ret = SSH_ERR_ALLOC_FAIL;
			যাও out;
		}
		memcpy(*sigp, sshbuf_ptr(b), len);
	}
	যদি (lenp != ফাঁকা)
		*lenp = len;
	ret = 0;
 out:
	sshbuf_free(b);
	sshbuf_free(bb);
	ফেরত ret;
}

স্থির পূর্ণসংখ্যা
ssh_ecdsa_verify(ধ্রুবক কাঠামো sshkey *চাবি,
    ধ্রুবক u_char *sig, আকার_t siglen,
    ধ্রুবক u_char *তথ্য, আকার_t dlen, ধ্রুবক অক্ষর *alg, u_int compat,
    কাঠামো sshkey_sig_details **detailsp)
{
	ECDSA_SIG *esig = ফাঁকা;
	BIGNUM *sig_r = ফাঁকা, *sig_s = ফাঁকা;
	পূর্ণসংখ্যা hash_alg, len = 0;
	পূর্ণসংখ্যা ret = SSH_ERR_INTERNAL_ERROR;
	কাঠামো sshbuf *b = ফাঁকা, *sigbuf = ফাঁকা;
	অক্ষর *ktype = ফাঁকা;
	unsigned অক্ষর *sigb = ফাঁকা, *cp;

	যদি (চাবি == ফাঁকা || চাবি->pkey == ফাঁকা ||
	    sshkey_type_plain(চাবি->type) != চাবি_ECDSA ||
	    sig == ফাঁকা || siglen == 0)
		ফেরত SSH_ERR_INVALID_ARGUMENT;

	যদি ((hash_alg = sshkey_ec_nid_to_hash_alg(চাবি->ecdsa_nid)) == -1)
		ফেরত SSH_ERR_INTERNAL_ERROR;

	/* fetch signature */
	যদি ((b = sshbuf_from(sig, siglen)) == ফাঁকা)
		ফেরত SSH_ERR_ALLOC_FAIL;
	যদি (sshbuf_get_cstring(b, &ktype, ফাঁকা) != 0 ||
	    sshbuf_froms(b, &sigbuf) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		যাও out;
	}
	যদি (strcmp(sshkey_ssh_name_plain(চাবি), ktype) != 0) {
		ret = SSH_ERR_চাবি_TYPE_MISMATCH;
		যাও out;
	}
	যদি (sshbuf_len(b) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_তথ্য;
		যাও out;
	}

	/* parse signature */
	যদি (sshbuf_get_bignum2(sigbuf, &sig_r) != 0 ||
	    sshbuf_get_bignum2(sigbuf, &sig_s) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		যাও out;
	}
	যদি (sshbuf_len(sigbuf) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_তথ্য;
		যাও out;
	}

	যদি ((esig = ECDSA_SIG_new()) == ফাঁকা) {
		ret = SSH_ERR_ALLOC_FAIL;
		যাও out;
	}
	যদি (!ECDSA_SIG_set0(esig, sig_r, sig_s)) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		যাও out;
	}
	sig_r = sig_s = ফাঁকা; /* transferred */

	যদি ((len = i2d_ECDSA_SIG(esig, ফাঁকা)) <= 0) {
		len = 0;
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		যাও out;
	}
	যদি ((sigb = calloc(1, len)) == ফাঁকা) {
		ret = SSH_ERR_ALLOC_FAIL;
		যাও out;
	}
	cp = sigb; /* ASN1_item_i2d increments the pointer past the object */
	যদি (i2d_ECDSA_SIG(esig, &cp) != len) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		যাও out;
	}
	যদি ((ret = sshkey_pkey_digest_verify(চাবি->pkey, hash_alg,
	    তথ্য, dlen, sigb, len)) != 0)
		যাও out;
	/* success */
 out:
	freezero(sigb, len);
	sshbuf_free(sigbuf);
	sshbuf_free(b);
	ECDSA_SIG_free(esig);
	BN_clear_free(sig_r);
	BN_clear_free(sig_s);
	মুক্ত(ktype);
	ফেরত ret;
}

/* NB. not static; used by ECDSA-SK */
ধ্রুবক কাঠামো sshkey_impl_funcs sshkey_ecdsa_funcs = {
	/* .size = */		ssh_ecdsa_আকার,
	/* .alloc = */		ফাঁকা,
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

ধ্রুবক কাঠামো sshkey_impl sshkey_ecdsa_nistp256_impl = {
	/* .name = */		"ecdsa-sha2-nistp256",
	/* .shortname = */	"ECDSA",
	/* .sigalg = */		ফাঁকা,
	/* .type = */		চাবি_ECDSA,
	/* .nid = */		NID_X9_62_prime256v1,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

ধ্রুবক কাঠামো sshkey_impl sshkey_ecdsa_nistp256_cert_impl = {
	/* .name = */		"ecdsa-sha2-nistp256-cert-v01@openssh.com",
	/* .shortname = */	"ECDSA-CERT",
	/* .sigalg = */		ফাঁকা,
	/* .type = */		চাবি_ECDSA_CERT,
	/* .nid = */		NID_X9_62_prime256v1,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

ধ্রুবক কাঠামো sshkey_impl sshkey_ecdsa_nistp384_impl = {
	/* .name = */		"ecdsa-sha2-nistp384",
	/* .shortname = */	"ECDSA",
	/* .sigalg = */		ফাঁকা,
	/* .type = */		চাবি_ECDSA,
	/* .nid = */		NID_secp384r1,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

ধ্রুবক কাঠামো sshkey_impl sshkey_ecdsa_nistp384_cert_impl = {
	/* .name = */		"ecdsa-sha2-nistp384-cert-v01@openssh.com",
	/* .shortname = */	"ECDSA-CERT",
	/* .sigalg = */		ফাঁকা,
	/* .type = */		চাবি_ECDSA_CERT,
	/* .nid = */		NID_secp384r1,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

ধ্রুবক কাঠামো sshkey_impl sshkey_ecdsa_nistp521_impl = {
	/* .name = */		"ecdsa-sha2-nistp521",
	/* .shortname = */	"ECDSA",
	/* .sigalg = */		ফাঁকা,
	/* .type = */		চাবি_ECDSA,
	/* .nid = */		NID_secp521r1,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

ধ্রুবক কাঠামো sshkey_impl sshkey_ecdsa_nistp521_cert_impl = {
	/* .name = */		"ecdsa-sha2-nistp521-cert-v01@openssh.com",
	/* .shortname = */	"ECDSA-CERT",
	/* .sigalg = */		ফাঁকা,
	/* .type = */		চাবি_ECDSA_CERT,
	/* .nid = */		NID_secp521r1,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

#endif /* WITH_OPENSSL */
