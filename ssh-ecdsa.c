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

#અન્તર્ભાવ "includes.h"

#જો defined(WITH_OPENSSL)
#અન્તર્ભાવ "openbsd-compat/openssl-compat.h"

#અન્તર્ભાવ <sys/types.h>

#અન્તર્ભાવ <openssl/bn.h>
#અન્તર્ભાવ <openssl/ec.h>
#અન્તર્ભાવ <openssl/ecdsa.h>
#અન્તર્ભાવ <openssl/evp.h>

#અન્તર્ભાવ <string.h>

#અન્તર્ભાવ "sshbuf.h"
#અન્તર્ભાવ "ssherr.h"
#define SSHKEY_INTERNAL
#અન્તર્ભાવ "sshkey.h"

પૂર્ણાંક
sshkey_ecdsa_fixup_group(EVP_PKEY *k)
{
	પૂર્ણાંક nids[] = {
		NID_X9_62_prime256v1,
		NID_secp384r1,
		NID_secp521r1,
		-1
	};
	પૂર્ણાંક nid = -1;
	u_int i;
	અચલ EC_GROUP *g;
	EC_ચાવી *ec = ખાલી;
	EC_GROUP *eg = ખાલી;

	જો ((ec = EVP_PKEY_get1_EC_ચાવી(k)) == ખાલી ||
	    (g = EC_ચાવી_get0_group(ec)) == ખાલી)
		જાઓ out;
	/*
	 * The group may be stored in a ASN.1 encoded private key in one of two
	 * ways: as a "named group", which is reconstituted by ASN.1 object ID
	 * or explicit group parameters encoded into the key blob. Only the
	 * "named group" case sets the group NID for us, but we can figure
	 * it out for the other case by comparing against all the groups that
	 * are supported.
	 */
	જો ((nid = EC_GROUP_get_curve_name(g)) > 0)
		જાઓ out;
	nid = -1;
	માટે (i = 0; nids[i] != -1; i++) {
		જો ((eg = EC_GROUP_new_by_curve_name(nids[i])) == ખાલી)
			જાઓ out;
		જો (EC_GROUP_cmp(g, eg, ખાલી) == 0)
			તોડો;
		EC_GROUP_free(eg);
		eg = ખાલી;
	}
	જો (nids[i] == -1)
		જાઓ out;

	/* Use the group with the NID attached */
	EC_GROUP_set_asn1_flag(eg, OPENSSL_EC_NAMED_CURVE);
	જો (EC_ચાવી_set_group(ec, eg) != 1 ||
	    EVP_PKEY_set1_EC_ચાવી(k, ec) != 1)
		જાઓ out;
	/* success */
	nid = nids[i];
 out:
	EC_ચાવી_free(ec);
	EC_GROUP_free(eg);
	પાછા nid;
}

સ્થિર u_int
ssh_ecdsa_size(અચલ સંરચના sshkey *ચાવી)
{
	પસંદગી (ચાવી->ecdsa_nid) {
	સ્થિતિ NID_X9_62_prime256v1:
		પાછા 256;
	સ્થિતિ NID_secp384r1:
		પાછા 384;
	સ્થિતિ NID_secp521r1:
		પાછા 521;
	મૂળભૂત:
		પાછા 0;
	}
}

સ્થિર શૂન્ય
ssh_ecdsa_cleanup(સંરચના sshkey *k)
{
	EVP_PKEY_free(k->pkey);
	k->pkey = ખાલી;
}

સ્થિર પૂર્ણાંક
ssh_ecdsa_equal(અચલ સંરચના sshkey *a, અચલ સંરચના sshkey *b)
{
	જો (a->pkey == ખાલી || b->pkey == ખાલી)
		પાછા 0;
	પાછા EVP_PKEY_cmp(a->pkey, b->pkey) == 1;
}

સ્થિર પૂર્ણાંક
ssh_ecdsa_serialize_public(અચલ સંરચના sshkey *ચાવી, સંરચના sshbuf *b,
    ગણના sshkey_serialize_rep opts)
{
	પૂર્ણાંક r;

	જો (ચાવી->pkey == ખાલી)
		પાછા SSH_ERR_INVALID_ARGUMENT;
	જો ((r = sshbuf_put_cstring(b,
	    sshkey_curve_nid_to_name(ચાવી->ecdsa_nid))) != 0 ||
	    (r = sshbuf_put_ec_pkey(b, ચાવી->pkey)) != 0)
		પાછા r;

	પાછા 0;
}

સ્થિર પૂર્ણાંક
ssh_ecdsa_serialize_private(અચલ સંરચના sshkey *ચાવી, સંરચના sshbuf *b,
    ગણના sshkey_serialize_rep opts)
{
	પૂર્ણાંક r;

	જો (!sshkey_is_cert(ચાવી)) {
		જો ((r = ssh_ecdsa_serialize_public(ચાવી, b, opts)) != 0)
			પાછા r;
	}
	જો ((r = sshbuf_put_bignum2(b,
	    EC_ચાવી_get0_private_ચાવી(EVP_PKEY_get0_EC_ચાવી(ચાવી->pkey)))) != 0)
		પાછા r;
	પાછા 0;
}

સ્થિર પૂર્ણાંક
ssh_ecdsa_generate(સંરચના sshkey *k, પૂર્ણાંક bits)
{
	EVP_PKEY *res = ખાલી;
	EVP_PKEY_CTX *ctx = ખાલી;
	પૂર્ણાંક ret = SSH_ERR_INTERNAL_ERROR;

	જો ((k->ecdsa_nid = sshkey_ecdsa_bits_to_nid(bits)) == -1)
		પાછા SSH_ERR_ચાવી_LENGTH;

	જો ((ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, ખાલી)) == ખાલી)
		પાછા SSH_ERR_ALLOC_FAIL;

	જો (EVP_PKEY_keygen_init(ctx) <= 0 ||
	    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, k->ecdsa_nid) <= 0 ||
	    EVP_PKEY_keygen(ctx, &res) <= 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		જાઓ out;
	}
	/* success */
	k->pkey = res;
	res = ખાલી;
	ret = 0;
 out:
	EVP_PKEY_free(res);
	EVP_PKEY_CTX_free(ctx);
	પાછા ret;
}

સ્થિર પૂર્ણાંક
ssh_ecdsa_copy_public(અચલ સંરચના sshkey *from, સંરચના sshkey *to)
{
	અચલ EC_ચાવી *ec_from;
	EC_ચાવી *ec_to = ખાલી;
	પૂર્ણાંક ret = SSH_ERR_INTERNAL_ERROR;

	ec_from = EVP_PKEY_get0_EC_ચાવી(from->pkey);
	જો (ec_from == ખાલી)
		પાછા SSH_ERR_LIBCRYPTO_ERROR;

	to->ecdsa_nid = from->ecdsa_nid;
	જો ((ec_to = EC_ચાવી_new_by_curve_name(from->ecdsa_nid)) == ખાલી)
		પાછા SSH_ERR_ALLOC_FAIL;
	જો (EC_ચાવી_set_public_ચાવી(ec_to,
	    EC_ચાવી_get0_public_ચાવી(ec_from)) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		જાઓ out;
	}
	EVP_PKEY_free(to->pkey);
	જો ((to->pkey = EVP_PKEY_new()) == ખાલી) {
		ret = SSH_ERR_ALLOC_FAIL;
		જાઓ out;
	}
	જો (EVP_PKEY_set1_EC_ચાવી(to->pkey, ec_to) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		જાઓ out;
	}
	ret = 0;
 out:
	EC_ચાવી_free(ec_to);
	પાછા ret;
}

સ્થિર પૂર્ણાંક
ssh_ecdsa_deserialize_public(અચલ અક્ષર *ktype, સંરચના sshbuf *b,
    સંરચના sshkey *ચાવી)
{
	પૂર્ણાંક r;
	અક્ષર *curve = ખાલી;
	EVP_PKEY *pkey = ખાલી;
	EC_ચાવી *ec = ખાલી;

	જો ((ચાવી->ecdsa_nid = sshkey_ecdsa_nid_from_name(ktype)) == -1)
		પાછા SSH_ERR_INVALID_ARGUMENT;
	જો ((r = sshbuf_get_cstring(b, &curve, ખાલી)) != 0)
		જાઓ out;
	જો (ચાવી->ecdsa_nid != sshkey_curve_name_to_nid(curve)) {
		r = SSH_ERR_EC_CURVE_MISMATCH;
		જાઓ out;
	}
	જો ((ec = EC_ચાવી_new_by_curve_name(ચાવી->ecdsa_nid)) == ખાલી) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		જાઓ out;
	}
	જો ((r = sshbuf_get_eckey(b, ec)) != 0)
		જાઓ out;
	જો (sshkey_ec_validate_public(EC_ચાવી_get0_group(ec),
	    EC_ચાવી_get0_public_ચાવી(ec)) != 0) {
		r = SSH_ERR_ચાવી_INVALID_EC_કિંમત;
		જાઓ out;
	}
	જો ((pkey = EVP_PKEY_new()) == ખાલી) {
		r = SSH_ERR_ALLOC_FAIL;
		જાઓ out;
	}
	જો (EVP_PKEY_set1_EC_ચાવી(pkey, ec) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		જાઓ out;
	}
	EVP_PKEY_free(ચાવી->pkey);
	ચાવી->pkey = pkey;
	pkey = ખાલી;
	/* success */
	r = 0;
#ifdef DEBUG_PK
	sshkey_dump_ec_point(
	    EC_ચાવી_get0_group(EVP_PKEY_get0_EC_ચાવી(ચાવી->pkey)),
	    EC_ચાવી_get0_public_ચાવી(EVP_PKEY_get0_EC_ચાવી(ચાવી->pkey)));
#endif
 out:
	EC_ચાવી_free(ec);
	EVP_PKEY_free(pkey);
	મુક્ત(curve);
	પાછા r;
}

સ્થિર પૂર્ણાંક
ssh_ecdsa_deserialize_private(અચલ અક્ષર *ktype, સંરચના sshbuf *b,
    સંરચના sshkey *ચાવી)
{
	પૂર્ણાંક r;
	BIGNUM *exponent = ખાલી;
	EC_ચાવી *ec = ખાલી;

	જો (!sshkey_is_cert(ચાવી)) {
		જો ((r = ssh_ecdsa_deserialize_public(ktype, b, ચાવી)) != 0)
			પાછા r;
	}
	જો ((r = sshbuf_get_bignum2(b, &exponent)) != 0)
		જાઓ out;
	જો ((ec = EVP_PKEY_get1_EC_ચાવી(ચાવી->pkey)) == ખાલી) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		જાઓ out;
	}
	જો (EC_ચાવી_set_private_ચાવી(ec, exponent) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		જાઓ out;
	}
	જો ((r = sshkey_ec_validate_private(ec)) != 0)
		જાઓ out;
	જો (EVP_PKEY_set1_EC_ચાવી(ચાવી->pkey, ec) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		જાઓ out;
	}
	/* success */
	r = 0;
 out:
	BN_clear_free(exponent);
	EC_ચાવી_free(ec);
	પાછા r;
}

સ્થિર પૂર્ણાંક
ssh_ecdsa_sign(સંરચના sshkey *ચાવી,
    u_char **sigp, size_t *lenp,
    અચલ u_char *data, size_t dlen,
    અચલ અક્ષર *alg, અચલ અક્ષર *sk_provider, અચલ અક્ષર *sk_pin, u_int compat)
{
	ECDSA_SIG *esig = ખાલી;
	unsigned અક્ષર *sigb = ખાલી;
	અચલ unsigned અક્ષર *psig;
	અચલ BIGNUM *sig_r, *sig_s;
	પૂર્ણાંક hash_alg;
	size_t slen = 0;
	પૂર્ણાંક ret = SSH_ERR_INTERNAL_ERROR;

	જો (lenp != ખાલી)
		*lenp = 0;
	જો (sigp != ખાલી)
		*sigp = ખાલી;

	જો (ચાવી == ખાલી || ચાવી->pkey == ખાલી ||
	    sshkey_type_plain(ચાવી->type) != ચાવી_ECDSA)
		પાછા SSH_ERR_INVALID_ARGUMENT;

	જો ((hash_alg = sshkey_ec_nid_to_hash_alg(ચાવી->ecdsa_nid)) == -1)
		પાછા SSH_ERR_INTERNAL_ERROR;

	જો ((ret = sshkey_pkey_digest_sign(ચાવી->pkey, hash_alg, &sigb, &slen,
	    data, dlen)) != 0)
		જાઓ out;

	psig = sigb;
	જો ((esig = d2i_ECDSA_SIG(ખાલી, &psig, slen)) == ખાલી) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		જાઓ out;
	}
	ECDSA_SIG_get0(esig, &sig_r, &sig_s);

	જો ((ret = ssh_ecdsa_encode_store_sig(ચાવી, sig_r, sig_s,
	    sigp, lenp)) != 0)
		જાઓ out;
	/* success */
	ret = 0;
 out:
	freezero(sigb, slen);
	ECDSA_SIG_free(esig);
	પાછા ret;
}

પૂર્ણાંક
ssh_ecdsa_encode_store_sig(અચલ સંરચના sshkey *ચાવી,
    અચલ BIGNUM *sig_r, અચલ BIGNUM *sig_s,
    u_char **sigp, size_t *lenp)
{
	સંરચના sshbuf *b = ખાલી, *bb = ખાલી;
	પૂર્ણાંક ret;
	size_t len;

	જો (lenp != ખાલી)
		*lenp = 0;
	જો (sigp != ખાલી)
		*sigp = ખાલી;

	જો ((bb = sshbuf_new()) == ખાલી || (b = sshbuf_new()) == ખાલી) {
		ret = SSH_ERR_ALLOC_FAIL;
		જાઓ out;
	}
	જો ((ret = sshbuf_put_bignum2(bb, sig_r)) != 0 ||
	    (ret = sshbuf_put_bignum2(bb, sig_s)) != 0)
		જાઓ out;
	જો ((ret = sshbuf_put_cstring(b, sshkey_ssh_name_plain(ચાવી))) != 0 ||
	    (ret = sshbuf_put_stringb(b, bb)) != 0)
		જાઓ out;
	len = sshbuf_len(b);
	જો (sigp != ખાલી) {
		જો ((*sigp = malloc(len)) == ખાલી) {
			ret = SSH_ERR_ALLOC_FAIL;
			જાઓ out;
		}
		memcpy(*sigp, sshbuf_ptr(b), len);
	}
	જો (lenp != ખાલી)
		*lenp = len;
	ret = 0;
 out:
	sshbuf_free(b);
	sshbuf_free(bb);
	પાછા ret;
}

સ્થિર પૂર્ણાંક
ssh_ecdsa_verify(અચલ સંરચના sshkey *ચાવી,
    અચલ u_char *sig, size_t siglen,
    અચલ u_char *data, size_t dlen, અચલ અક્ષર *alg, u_int compat,
    સંરચના sshkey_sig_details **detailsp)
{
	ECDSA_SIG *esig = ખાલી;
	BIGNUM *sig_r = ખાલી, *sig_s = ખાલી;
	પૂર્ણાંક hash_alg, len = 0;
	પૂર્ણાંક ret = SSH_ERR_INTERNAL_ERROR;
	સંરચના sshbuf *b = ખાલી, *sigbuf = ખાલી;
	અક્ષર *ktype = ખાલી;
	unsigned અક્ષર *sigb = ખાલી, *cp;

	જો (ચાવી == ખાલી || ચાવી->pkey == ખાલી ||
	    sshkey_type_plain(ચાવી->type) != ચાવી_ECDSA ||
	    sig == ખાલી || siglen == 0)
		પાછા SSH_ERR_INVALID_ARGUMENT;

	જો ((hash_alg = sshkey_ec_nid_to_hash_alg(ચાવી->ecdsa_nid)) == -1)
		પાછા SSH_ERR_INTERNAL_ERROR;

	/* fetch signature */
	જો ((b = sshbuf_from(sig, siglen)) == ખાલી)
		પાછા SSH_ERR_ALLOC_FAIL;
	જો (sshbuf_get_cstring(b, &ktype, ખાલી) != 0 ||
	    sshbuf_froms(b, &sigbuf) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		જાઓ out;
	}
	જો (strcmp(sshkey_ssh_name_plain(ચાવી), ktype) != 0) {
		ret = SSH_ERR_ચાવી_TYPE_MISMATCH;
		જાઓ out;
	}
	જો (sshbuf_len(b) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		જાઓ out;
	}

	/* parse signature */
	જો (sshbuf_get_bignum2(sigbuf, &sig_r) != 0 ||
	    sshbuf_get_bignum2(sigbuf, &sig_s) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		જાઓ out;
	}
	જો (sshbuf_len(sigbuf) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		જાઓ out;
	}

	જો ((esig = ECDSA_SIG_new()) == ખાલી) {
		ret = SSH_ERR_ALLOC_FAIL;
		જાઓ out;
	}
	જો (!ECDSA_SIG_set0(esig, sig_r, sig_s)) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		જાઓ out;
	}
	sig_r = sig_s = ખાલી; /* transferred */

	જો ((len = i2d_ECDSA_SIG(esig, ખાલી)) <= 0) {
		len = 0;
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		જાઓ out;
	}
	જો ((sigb = calloc(1, len)) == ખાલી) {
		ret = SSH_ERR_ALLOC_FAIL;
		જાઓ out;
	}
	cp = sigb; /* ASN1_item_i2d increments the pointer past the object */
	જો (i2d_ECDSA_SIG(esig, &cp) != len) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		જાઓ out;
	}
	જો ((ret = sshkey_pkey_digest_verify(ચાવી->pkey, hash_alg,
	    data, dlen, sigb, len)) != 0)
		જાઓ out;
	/* success */
 out:
	freezero(sigb, len);
	sshbuf_free(sigbuf);
	sshbuf_free(b);
	ECDSA_SIG_free(esig);
	BN_clear_free(sig_r);
	BN_clear_free(sig_s);
	મુક્ત(ktype);
	પાછા ret;
}

/* NB. not static; used by ECDSA-SK */
અચલ સંરચના sshkey_impl_funcs sshkey_ecdsa_funcs = {
	/* .size = */		ssh_ecdsa_size,
	/* .alloc = */		ખાલી,
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

અચલ સંરચના sshkey_impl sshkey_ecdsa_nistp256_impl = {
	/* .name = */		"ecdsa-sha2-nistp256",
	/* .shortname = */	"ECDSA",
	/* .sigalg = */		ખાલી,
	/* .type = */		ચાવી_ECDSA,
	/* .nid = */		NID_X9_62_prime256v1,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

અચલ સંરચના sshkey_impl sshkey_ecdsa_nistp256_cert_impl = {
	/* .name = */		"ecdsa-sha2-nistp256-cert-v01@openssh.com",
	/* .shortname = */	"ECDSA-CERT",
	/* .sigalg = */		ખાલી,
	/* .type = */		ચાવી_ECDSA_CERT,
	/* .nid = */		NID_X9_62_prime256v1,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

અચલ સંરચના sshkey_impl sshkey_ecdsa_nistp384_impl = {
	/* .name = */		"ecdsa-sha2-nistp384",
	/* .shortname = */	"ECDSA",
	/* .sigalg = */		ખાલી,
	/* .type = */		ચાવી_ECDSA,
	/* .nid = */		NID_secp384r1,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

અચલ સંરચના sshkey_impl sshkey_ecdsa_nistp384_cert_impl = {
	/* .name = */		"ecdsa-sha2-nistp384-cert-v01@openssh.com",
	/* .shortname = */	"ECDSA-CERT",
	/* .sigalg = */		ખાલી,
	/* .type = */		ચાવી_ECDSA_CERT,
	/* .nid = */		NID_secp384r1,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

અચલ સંરચના sshkey_impl sshkey_ecdsa_nistp521_impl = {
	/* .name = */		"ecdsa-sha2-nistp521",
	/* .shortname = */	"ECDSA",
	/* .sigalg = */		ખાલી,
	/* .type = */		ચાવી_ECDSA,
	/* .nid = */		NID_secp521r1,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

અચલ સંરચના sshkey_impl sshkey_ecdsa_nistp521_cert_impl = {
	/* .name = */		"ecdsa-sha2-nistp521-cert-v01@openssh.com",
	/* .shortname = */	"ECDSA-CERT",
	/* .sigalg = */		ખાલી,
	/* .type = */		ચાવી_ECDSA_CERT,
	/* .nid = */		NID_secp521r1,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

#endif /* WITH_OPENSSL */
