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

#அந்தர்பாவ "includes.h"

#எனில் defined(WITH_OPENSSL)
#அந்தர்பாவ "openbsd-compat/openssl-compat.h"

#அந்தர்பாவ <sys/types.h>

#அந்தர்பாவ <openssl/bn.h>
#அந்தர்பாவ <openssl/ec.h>
#அந்தர்பாவ <openssl/ecdsa.h>
#அந்தர்பாவ <openssl/evp.h>

#அந்தர்பாவ <string.h>

#அந்தர்பாவ "sshbuf.h"
#அந்தர்பாவ "ssherr.h"
#define SSHKEY_INTERNAL
#அந்தர்பாவ "sshkey.h"

முழு
sshkey_ecdsa_fixup_group(EVP_PKEY *k)
{
	முழு nids[] = {
		NID_X9_62_prime256v1,
		NID_secp384r1,
		NID_secp521r1,
		-1
	};
	முழு nid = -1;
	u_int i;
	மாறிலி EC_GROUP *g;
	EC_சாவி *ec = வெற்று;
	EC_GROUP *eg = வெற்று;

	எனில் ((ec = EVP_PKEY_get1_EC_சாவி(k)) == வெற்று ||
	    (g = EC_சாவி_get0_group(ec)) == வெற்று)
		செல் out;
	/*
	 * The group may be stored in a ASN.1 encoded private key in one of two
	 * ways: as a "named group", which is reconstituted by ASN.1 object ID
	 * or explicit group parameters encoded into the key blob. Only the
	 * "named group" case sets the group NID for us, but we can figure
	 * it out for the other case by comparing against all the groups that
	 * are supported.
	 */
	எனில் ((nid = EC_GROUP_get_curve_name(g)) > 0)
		செல் out;
	nid = -1;
	க்கு (i = 0; nids[i] != -1; i++) {
		எனில் ((eg = EC_GROUP_new_by_curve_name(nids[i])) == வெற்று)
			செல் out;
		எனில் (EC_GROUP_cmp(g, eg, வெற்று) == 0)
			நிறுத்து;
		EC_GROUP_free(eg);
		eg = வெற்று;
	}
	எனில் (nids[i] == -1)
		செல் out;

	/* Use the group with the NID attached */
	EC_GROUP_set_asn1_flag(eg, OPENSSL_EC_NAMED_CURVE);
	எனில் (EC_சாவி_set_group(ec, eg) != 1 ||
	    EVP_PKEY_set1_EC_சாவி(k, ec) != 1)
		செல் out;
	/* success */
	nid = nids[i];
 out:
	EC_சாவி_free(ec);
	EC_GROUP_free(eg);
	திரும்பு nid;
}

நிலையான u_int
ssh_ecdsa_size(மாறிலி கட்டமைப்பு sshkey *சாவி)
{
	தேர்வு (சாவி->ecdsa_nid) {
	நிலை NID_X9_62_prime256v1:
		திரும்பு 256;
	நிலை NID_secp384r1:
		திரும்பு 384;
	நிலை NID_secp521r1:
		திரும்பு 521;
	இயல்பு:
		திரும்பு 0;
	}
}

நிலையான வெறுமை
ssh_ecdsa_cleanup(கட்டமைப்பு sshkey *k)
{
	EVP_PKEY_free(k->pkey);
	k->pkey = வெற்று;
}

நிலையான முழு
ssh_ecdsa_equal(மாறிலி கட்டமைப்பு sshkey *a, மாறிலி கட்டமைப்பு sshkey *b)
{
	எனில் (a->pkey == வெற்று || b->pkey == வெற்று)
		திரும்பு 0;
	திரும்பு EVP_PKEY_cmp(a->pkey, b->pkey) == 1;
}

நிலையான முழு
ssh_ecdsa_serialize_public(மாறிலி கட்டமைப்பு sshkey *சாவி, கட்டமைப்பு sshbuf *b,
    எண்ணிக்கை sshkey_serialize_rep opts)
{
	முழு r;

	எனில் (சாவி->pkey == வெற்று)
		திரும்பு SSH_ERR_INVALID_ARGUMENT;
	எனில் ((r = sshbuf_put_cstring(b,
	    sshkey_curve_nid_to_name(சாவி->ecdsa_nid))) != 0 ||
	    (r = sshbuf_put_ec_pkey(b, சாவி->pkey)) != 0)
		திரும்பு r;

	திரும்பு 0;
}

நிலையான முழு
ssh_ecdsa_serialize_private(மாறிலி கட்டமைப்பு sshkey *சாவி, கட்டமைப்பு sshbuf *b,
    எண்ணிக்கை sshkey_serialize_rep opts)
{
	முழு r;

	எனில் (!sshkey_is_cert(சாவி)) {
		எனில் ((r = ssh_ecdsa_serialize_public(சாவி, b, opts)) != 0)
			திரும்பு r;
	}
	எனில் ((r = sshbuf_put_bignum2(b,
	    EC_சாவி_get0_private_சாவி(EVP_PKEY_get0_EC_சாவி(சாவி->pkey)))) != 0)
		திரும்பு r;
	திரும்பு 0;
}

நிலையான முழு
ssh_ecdsa_generate(கட்டமைப்பு sshkey *k, முழு bits)
{
	EVP_PKEY *res = வெற்று;
	EVP_PKEY_CTX *ctx = வெற்று;
	முழு ret = SSH_ERR_INTERNAL_ERROR;

	எனில் ((k->ecdsa_nid = sshkey_ecdsa_bits_to_nid(bits)) == -1)
		திரும்பு SSH_ERR_சாவி_LENGTH;

	எனில் ((ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, வெற்று)) == வெற்று)
		திரும்பு SSH_ERR_ALLOC_FAIL;

	எனில் (EVP_PKEY_keygen_init(ctx) <= 0 ||
	    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, k->ecdsa_nid) <= 0 ||
	    EVP_PKEY_keygen(ctx, &res) <= 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		செல் out;
	}
	/* success */
	k->pkey = res;
	res = வெற்று;
	ret = 0;
 out:
	EVP_PKEY_free(res);
	EVP_PKEY_CTX_free(ctx);
	திரும்பு ret;
}

நிலையான முழு
ssh_ecdsa_copy_public(மாறிலி கட்டமைப்பு sshkey *from, கட்டமைப்பு sshkey *to)
{
	மாறிலி EC_சாவி *ec_from;
	EC_சாவி *ec_to = வெற்று;
	முழு ret = SSH_ERR_INTERNAL_ERROR;

	ec_from = EVP_PKEY_get0_EC_சாவி(from->pkey);
	எனில் (ec_from == வெற்று)
		திரும்பு SSH_ERR_LIBCRYPTO_ERROR;

	to->ecdsa_nid = from->ecdsa_nid;
	எனில் ((ec_to = EC_சாவி_new_by_curve_name(from->ecdsa_nid)) == வெற்று)
		திரும்பு SSH_ERR_ALLOC_FAIL;
	எனில் (EC_சாவி_set_public_சாவி(ec_to,
	    EC_சாவி_get0_public_சாவி(ec_from)) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		செல் out;
	}
	EVP_PKEY_free(to->pkey);
	எனில் ((to->pkey = EVP_PKEY_new()) == வெற்று) {
		ret = SSH_ERR_ALLOC_FAIL;
		செல் out;
	}
	எனில் (EVP_PKEY_set1_EC_சாவி(to->pkey, ec_to) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		செல் out;
	}
	ret = 0;
 out:
	EC_சாவி_free(ec_to);
	திரும்பு ret;
}

நிலையான முழு
ssh_ecdsa_deserialize_public(மாறிலி எழுத்து *ktype, கட்டமைப்பு sshbuf *b,
    கட்டமைப்பு sshkey *சாவி)
{
	முழு r;
	எழுத்து *curve = வெற்று;
	EVP_PKEY *pkey = வெற்று;
	EC_சாவி *ec = வெற்று;

	எனில் ((சாவி->ecdsa_nid = sshkey_ecdsa_nid_from_name(ktype)) == -1)
		திரும்பு SSH_ERR_INVALID_ARGUMENT;
	எனில் ((r = sshbuf_get_cstring(b, &curve, வெற்று)) != 0)
		செல் out;
	எனில் (சாவி->ecdsa_nid != sshkey_curve_name_to_nid(curve)) {
		r = SSH_ERR_EC_CURVE_MISMATCH;
		செல் out;
	}
	எனில் ((ec = EC_சாவி_new_by_curve_name(சாவி->ecdsa_nid)) == வெற்று) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		செல் out;
	}
	எனில் ((r = sshbuf_get_eckey(b, ec)) != 0)
		செல் out;
	எனில் (sshkey_ec_validate_public(EC_சாவி_get0_group(ec),
	    EC_சாவி_get0_public_சாவி(ec)) != 0) {
		r = SSH_ERR_சாவி_INVALID_EC_மதிப்பு;
		செல் out;
	}
	எனில் ((pkey = EVP_PKEY_new()) == வெற்று) {
		r = SSH_ERR_ALLOC_FAIL;
		செல் out;
	}
	எனில் (EVP_PKEY_set1_EC_சாவி(pkey, ec) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		செல் out;
	}
	EVP_PKEY_free(சாவி->pkey);
	சாவி->pkey = pkey;
	pkey = வெற்று;
	/* success */
	r = 0;
#ifdef DEBUG_PK
	sshkey_dump_ec_point(
	    EC_சாவி_get0_group(EVP_PKEY_get0_EC_சாவி(சாவி->pkey)),
	    EC_சாவி_get0_public_சாவி(EVP_PKEY_get0_EC_சாவி(சாவி->pkey)));
#endif
 out:
	EC_சாவி_free(ec);
	EVP_PKEY_free(pkey);
	விடுவி(curve);
	திரும்பு r;
}

நிலையான முழு
ssh_ecdsa_deserialize_private(மாறிலி எழுத்து *ktype, கட்டமைப்பு sshbuf *b,
    கட்டமைப்பு sshkey *சாவி)
{
	முழு r;
	BIGNUM *exponent = வெற்று;
	EC_சாவி *ec = வெற்று;

	எனில் (!sshkey_is_cert(சாவி)) {
		எனில் ((r = ssh_ecdsa_deserialize_public(ktype, b, சாவி)) != 0)
			திரும்பு r;
	}
	எனில் ((r = sshbuf_get_bignum2(b, &exponent)) != 0)
		செல் out;
	எனில் ((ec = EVP_PKEY_get1_EC_சாவி(சாவி->pkey)) == வெற்று) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		செல் out;
	}
	எனில் (EC_சாவி_set_private_சாவி(ec, exponent) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		செல் out;
	}
	எனில் ((r = sshkey_ec_validate_private(ec)) != 0)
		செல் out;
	எனில் (EVP_PKEY_set1_EC_சாவி(சாவி->pkey, ec) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		செல் out;
	}
	/* success */
	r = 0;
 out:
	BN_clear_free(exponent);
	EC_சாவி_free(ec);
	திரும்பு r;
}

நிலையான முழு
ssh_ecdsa_sign(கட்டமைப்பு sshkey *சாவி,
    u_char **sigp, size_t *lenp,
    மாறிலி u_char *data, size_t dlen,
    மாறிலி எழுத்து *alg, மாறிலி எழுத்து *sk_provider, மாறிலி எழுத்து *sk_pin, u_int compat)
{
	ECDSA_SIG *esig = வெற்று;
	unsigned எழுத்து *sigb = வெற்று;
	மாறிலி unsigned எழுத்து *psig;
	மாறிலி BIGNUM *sig_r, *sig_s;
	முழு hash_alg;
	size_t slen = 0;
	முழு ret = SSH_ERR_INTERNAL_ERROR;

	எனில் (lenp != வெற்று)
		*lenp = 0;
	எனில் (sigp != வெற்று)
		*sigp = வெற்று;

	எனில் (சாவி == வெற்று || சாவி->pkey == வெற்று ||
	    sshkey_type_plain(சாவி->type) != சாவி_ECDSA)
		திரும்பு SSH_ERR_INVALID_ARGUMENT;

	எனில் ((hash_alg = sshkey_ec_nid_to_hash_alg(சாவி->ecdsa_nid)) == -1)
		திரும்பு SSH_ERR_INTERNAL_ERROR;

	எனில் ((ret = sshkey_pkey_digest_sign(சாவி->pkey, hash_alg, &sigb, &slen,
	    data, dlen)) != 0)
		செல் out;

	psig = sigb;
	எனில் ((esig = d2i_ECDSA_SIG(வெற்று, &psig, slen)) == வெற்று) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		செல் out;
	}
	ECDSA_SIG_get0(esig, &sig_r, &sig_s);

	எனில் ((ret = ssh_ecdsa_encode_store_sig(சாவி, sig_r, sig_s,
	    sigp, lenp)) != 0)
		செல் out;
	/* success */
	ret = 0;
 out:
	freezero(sigb, slen);
	ECDSA_SIG_free(esig);
	திரும்பு ret;
}

முழு
ssh_ecdsa_encode_store_sig(மாறிலி கட்டமைப்பு sshkey *சாவி,
    மாறிலி BIGNUM *sig_r, மாறிலி BIGNUM *sig_s,
    u_char **sigp, size_t *lenp)
{
	கட்டமைப்பு sshbuf *b = வெற்று, *bb = வெற்று;
	முழு ret;
	size_t len;

	எனில் (lenp != வெற்று)
		*lenp = 0;
	எனில் (sigp != வெற்று)
		*sigp = வெற்று;

	எனில் ((bb = sshbuf_new()) == வெற்று || (b = sshbuf_new()) == வெற்று) {
		ret = SSH_ERR_ALLOC_FAIL;
		செல் out;
	}
	எனில் ((ret = sshbuf_put_bignum2(bb, sig_r)) != 0 ||
	    (ret = sshbuf_put_bignum2(bb, sig_s)) != 0)
		செல் out;
	எனில் ((ret = sshbuf_put_cstring(b, sshkey_ssh_name_plain(சாவி))) != 0 ||
	    (ret = sshbuf_put_stringb(b, bb)) != 0)
		செல் out;
	len = sshbuf_len(b);
	எனில் (sigp != வெற்று) {
		எனில் ((*sigp = malloc(len)) == வெற்று) {
			ret = SSH_ERR_ALLOC_FAIL;
			செல் out;
		}
		memcpy(*sigp, sshbuf_ptr(b), len);
	}
	எனில் (lenp != வெற்று)
		*lenp = len;
	ret = 0;
 out:
	sshbuf_free(b);
	sshbuf_free(bb);
	திரும்பு ret;
}

நிலையான முழு
ssh_ecdsa_verify(மாறிலி கட்டமைப்பு sshkey *சாவி,
    மாறிலி u_char *sig, size_t siglen,
    மாறிலி u_char *data, size_t dlen, மாறிலி எழுத்து *alg, u_int compat,
    கட்டமைப்பு sshkey_sig_details **detailsp)
{
	ECDSA_SIG *esig = வெற்று;
	BIGNUM *sig_r = வெற்று, *sig_s = வெற்று;
	முழு hash_alg, len = 0;
	முழு ret = SSH_ERR_INTERNAL_ERROR;
	கட்டமைப்பு sshbuf *b = வெற்று, *sigbuf = வெற்று;
	எழுத்து *ktype = வெற்று;
	unsigned எழுத்து *sigb = வெற்று, *cp;

	எனில் (சாவி == வெற்று || சாவி->pkey == வெற்று ||
	    sshkey_type_plain(சாவி->type) != சாவி_ECDSA ||
	    sig == வெற்று || siglen == 0)
		திரும்பு SSH_ERR_INVALID_ARGUMENT;

	எனில் ((hash_alg = sshkey_ec_nid_to_hash_alg(சாவி->ecdsa_nid)) == -1)
		திரும்பு SSH_ERR_INTERNAL_ERROR;

	/* fetch signature */
	எனில் ((b = sshbuf_from(sig, siglen)) == வெற்று)
		திரும்பு SSH_ERR_ALLOC_FAIL;
	எனில் (sshbuf_get_cstring(b, &ktype, வெற்று) != 0 ||
	    sshbuf_froms(b, &sigbuf) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		செல் out;
	}
	எனில் (strcmp(sshkey_ssh_name_plain(சாவி), ktype) != 0) {
		ret = SSH_ERR_சாவி_TYPE_MISMATCH;
		செல் out;
	}
	எனில் (sshbuf_len(b) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		செல் out;
	}

	/* parse signature */
	எனில் (sshbuf_get_bignum2(sigbuf, &sig_r) != 0 ||
	    sshbuf_get_bignum2(sigbuf, &sig_s) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		செல் out;
	}
	எனில் (sshbuf_len(sigbuf) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		செல் out;
	}

	எனில் ((esig = ECDSA_SIG_new()) == வெற்று) {
		ret = SSH_ERR_ALLOC_FAIL;
		செல் out;
	}
	எனில் (!ECDSA_SIG_set0(esig, sig_r, sig_s)) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		செல் out;
	}
	sig_r = sig_s = வெற்று; /* transferred */

	எனில் ((len = i2d_ECDSA_SIG(esig, வெற்று)) <= 0) {
		len = 0;
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		செல் out;
	}
	எனில் ((sigb = calloc(1, len)) == வெற்று) {
		ret = SSH_ERR_ALLOC_FAIL;
		செல் out;
	}
	cp = sigb; /* ASN1_item_i2d increments the pointer past the object */
	எனில் (i2d_ECDSA_SIG(esig, &cp) != len) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		செல் out;
	}
	எனில் ((ret = sshkey_pkey_digest_verify(சாவி->pkey, hash_alg,
	    data, dlen, sigb, len)) != 0)
		செல் out;
	/* success */
 out:
	freezero(sigb, len);
	sshbuf_free(sigbuf);
	sshbuf_free(b);
	ECDSA_SIG_free(esig);
	BN_clear_free(sig_r);
	BN_clear_free(sig_s);
	விடுவி(ktype);
	திரும்பு ret;
}

/* NB. not static; used by ECDSA-SK */
மாறிலி கட்டமைப்பு sshkey_impl_funcs sshkey_ecdsa_funcs = {
	/* .size = */		ssh_ecdsa_size,
	/* .alloc = */		வெற்று,
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

மாறிலி கட்டமைப்பு sshkey_impl sshkey_ecdsa_nistp256_impl = {
	/* .name = */		"ecdsa-sha2-nistp256",
	/* .shortname = */	"ECDSA",
	/* .sigalg = */		வெற்று,
	/* .type = */		சாவி_ECDSA,
	/* .nid = */		NID_X9_62_prime256v1,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

மாறிலி கட்டமைப்பு sshkey_impl sshkey_ecdsa_nistp256_cert_impl = {
	/* .name = */		"ecdsa-sha2-nistp256-cert-v01@openssh.com",
	/* .shortname = */	"ECDSA-CERT",
	/* .sigalg = */		வெற்று,
	/* .type = */		சாவி_ECDSA_CERT,
	/* .nid = */		NID_X9_62_prime256v1,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

மாறிலி கட்டமைப்பு sshkey_impl sshkey_ecdsa_nistp384_impl = {
	/* .name = */		"ecdsa-sha2-nistp384",
	/* .shortname = */	"ECDSA",
	/* .sigalg = */		வெற்று,
	/* .type = */		சாவி_ECDSA,
	/* .nid = */		NID_secp384r1,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

மாறிலி கட்டமைப்பு sshkey_impl sshkey_ecdsa_nistp384_cert_impl = {
	/* .name = */		"ecdsa-sha2-nistp384-cert-v01@openssh.com",
	/* .shortname = */	"ECDSA-CERT",
	/* .sigalg = */		வெற்று,
	/* .type = */		சாவி_ECDSA_CERT,
	/* .nid = */		NID_secp384r1,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

மாறிலி கட்டமைப்பு sshkey_impl sshkey_ecdsa_nistp521_impl = {
	/* .name = */		"ecdsa-sha2-nistp521",
	/* .shortname = */	"ECDSA",
	/* .sigalg = */		வெற்று,
	/* .type = */		சாவி_ECDSA,
	/* .nid = */		NID_secp521r1,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

மாறிலி கட்டமைப்பு sshkey_impl sshkey_ecdsa_nistp521_cert_impl = {
	/* .name = */		"ecdsa-sha2-nistp521-cert-v01@openssh.com",
	/* .shortname = */	"ECDSA-CERT",
	/* .sigalg = */		வெற்று,
	/* .type = */		சாவி_ECDSA_CERT,
	/* .nid = */		NID_secp521r1,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

#endif /* WITH_OPENSSL */
