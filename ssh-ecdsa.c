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

#അന്തര്ഭാവ "includes.h"

#എങ്കിൽ defined(WITH_OPENSSL)
#അന്തര്ഭാവ "openbsd-compat/openssl-compat.h"

#അന്തര്ഭാവ <sys/types.h>

#അന്തര്ഭാവ <openssl/bn.h>
#അന്തര്ഭാവ <openssl/ec.h>
#അന്തര്ഭാവ <openssl/ecdsa.h>
#അന്തര്ഭാവ <openssl/evp.h>

#അന്തര്ഭാവ <string.h>

#അന്തര്ഭാവ "sshbuf.h"
#അന്തര്ഭാവ "ssherr.h"
#define SSHKEY_INTERNAL
#അന്തര്ഭാവ "sshkey.h"

പൂർണ്ണസംഖ്യ
sshkey_ecdsa_fixup_group(EVP_PKEY *k)
{
	പൂർണ്ണസംഖ്യ nids[] = {
		NID_X9_62_prime256v1,
		NID_secp384r1,
		NID_secp521r1,
		-1
	};
	പൂർണ്ണസംഖ്യ nid = -1;
	u_int i;
	സ്ഥിരം EC_GROUP *g;
	EC_താക്കോൽ *ec = ശൂന്യ;
	EC_GROUP *eg = ശൂന്യ;

	എങ്കിൽ ((ec = EVP_PKEY_get1_EC_താക്കോൽ(k)) == ശൂന്യ ||
	    (g = EC_താക്കോൽ_get0_group(ec)) == ശൂന്യ)
		പോകുക out;
	/*
	 * The group may be stored in a ASN.1 encoded private key in one of two
	 * ways: as a "named group", which is reconstituted by ASN.1 object ID
	 * or explicit group parameters encoded into the key blob. Only the
	 * "named group" case sets the group NID for us, but we can figure
	 * it out for the other case by comparing against all the groups that
	 * are supported.
	 */
	എങ്കിൽ ((nid = EC_GROUP_get_curve_name(g)) > 0)
		പോകുക out;
	nid = -1;
	വേണ്ടി (i = 0; nids[i] != -1; i++) {
		എങ്കിൽ ((eg = EC_GROUP_new_by_curve_name(nids[i])) == ശൂന്യ)
			പോകുക out;
		എങ്കിൽ (EC_GROUP_cmp(g, eg, ശൂന്യ) == 0)
			നിർത്തുക;
		EC_GROUP_free(eg);
		eg = ശൂന്യ;
	}
	എങ്കിൽ (nids[i] == -1)
		പോകുക out;

	/* Use the group with the NID attached */
	EC_GROUP_set_asn1_flag(eg, OPENSSL_EC_NAMED_CURVE);
	എങ്കിൽ (EC_താക്കോൽ_set_group(ec, eg) != 1 ||
	    EVP_PKEY_set1_EC_താക്കോൽ(k, ec) != 1)
		പോകുക out;
	/* success */
	nid = nids[i];
 out:
	EC_താക്കോൽ_free(ec);
	EC_GROUP_free(eg);
	തിരികെ nid;
}

സ്ഥിതം u_int
ssh_ecdsa_size(സ്ഥിരം ഘടന sshkey *താക്കോൽ)
{
	തിരഞ്ഞെടുപ്പ് (താക്കോൽ->ecdsa_nid) {
	അവസ്ഥ NID_X9_62_prime256v1:
		തിരികെ 256;
	അവസ്ഥ NID_secp384r1:
		തിരികെ 384;
	അവസ്ഥ NID_secp521r1:
		തിരികെ 521;
	സ്ഥിരസ്ഥിതി:
		തിരികെ 0;
	}
}

സ്ഥിതം ശൂന്യം
ssh_ecdsa_cleanup(ഘടന sshkey *k)
{
	EVP_PKEY_free(k->pkey);
	k->pkey = ശൂന്യ;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
ssh_ecdsa_equal(സ്ഥിരം ഘടന sshkey *a, സ്ഥിരം ഘടന sshkey *b)
{
	എങ്കിൽ (a->pkey == ശൂന്യ || b->pkey == ശൂന്യ)
		തിരികെ 0;
	തിരികെ EVP_PKEY_cmp(a->pkey, b->pkey) == 1;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
ssh_ecdsa_serialize_public(സ്ഥിരം ഘടന sshkey *താക്കോൽ, ഘടന sshbuf *b,
    എണ്ണൽ sshkey_serialize_rep opts)
{
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ (താക്കോൽ->pkey == ശൂന്യ)
		തിരികെ SSH_ERR_INVALID_ARGUMENT;
	എങ്കിൽ ((r = sshbuf_put_cstring(b,
	    sshkey_curve_nid_to_name(താക്കോൽ->ecdsa_nid))) != 0 ||
	    (r = sshbuf_put_ec_pkey(b, താക്കോൽ->pkey)) != 0)
		തിരികെ r;

	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
ssh_ecdsa_serialize_private(സ്ഥിരം ഘടന sshkey *താക്കോൽ, ഘടന sshbuf *b,
    എണ്ണൽ sshkey_serialize_rep opts)
{
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ (!sshkey_is_cert(താക്കോൽ)) {
		എങ്കിൽ ((r = ssh_ecdsa_serialize_public(താക്കോൽ, b, opts)) != 0)
			തിരികെ r;
	}
	എങ്കിൽ ((r = sshbuf_put_bignum2(b,
	    EC_താക്കോൽ_get0_private_താക്കോൽ(EVP_PKEY_get0_EC_താക്കോൽ(താക്കോൽ->pkey)))) != 0)
		തിരികെ r;
	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
ssh_ecdsa_generate(ഘടന sshkey *k, പൂർണ്ണസംഖ്യ bits)
{
	EVP_PKEY *res = ശൂന്യ;
	EVP_PKEY_CTX *ctx = ശൂന്യ;
	പൂർണ്ണസംഖ്യ ret = SSH_ERR_INTERNAL_ERROR;

	എങ്കിൽ ((k->ecdsa_nid = sshkey_ecdsa_bits_to_nid(bits)) == -1)
		തിരികെ SSH_ERR_താക്കോൽ_LENGTH;

	എങ്കിൽ ((ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, ശൂന്യ)) == ശൂന്യ)
		തിരികെ SSH_ERR_ALLOC_FAIL;

	എങ്കിൽ (EVP_PKEY_keygen_init(ctx) <= 0 ||
	    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, k->ecdsa_nid) <= 0 ||
	    EVP_PKEY_keygen(ctx, &res) <= 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		പോകുക out;
	}
	/* success */
	k->pkey = res;
	res = ശൂന്യ;
	ret = 0;
 out:
	EVP_PKEY_free(res);
	EVP_PKEY_CTX_free(ctx);
	തിരികെ ret;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
ssh_ecdsa_copy_public(സ്ഥിരം ഘടന sshkey *from, ഘടന sshkey *to)
{
	സ്ഥിരം EC_താക്കോൽ *ec_from;
	EC_താക്കോൽ *ec_to = ശൂന്യ;
	പൂർണ്ണസംഖ്യ ret = SSH_ERR_INTERNAL_ERROR;

	ec_from = EVP_PKEY_get0_EC_താക്കോൽ(from->pkey);
	എങ്കിൽ (ec_from == ശൂന്യ)
		തിരികെ SSH_ERR_LIBCRYPTO_ERROR;

	to->ecdsa_nid = from->ecdsa_nid;
	എങ്കിൽ ((ec_to = EC_താക്കോൽ_new_by_curve_name(from->ecdsa_nid)) == ശൂന്യ)
		തിരികെ SSH_ERR_ALLOC_FAIL;
	എങ്കിൽ (EC_താക്കോൽ_set_public_താക്കോൽ(ec_to,
	    EC_താക്കോൽ_get0_public_താക്കോൽ(ec_from)) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		പോകുക out;
	}
	EVP_PKEY_free(to->pkey);
	എങ്കിൽ ((to->pkey = EVP_PKEY_new()) == ശൂന്യ) {
		ret = SSH_ERR_ALLOC_FAIL;
		പോകുക out;
	}
	എങ്കിൽ (EVP_PKEY_set1_EC_താക്കോൽ(to->pkey, ec_to) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		പോകുക out;
	}
	ret = 0;
 out:
	EC_താക്കോൽ_free(ec_to);
	തിരികെ ret;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
ssh_ecdsa_deserialize_public(സ്ഥിരം അക്ഷരം *ktype, ഘടന sshbuf *b,
    ഘടന sshkey *താക്കോൽ)
{
	പൂർണ്ണസംഖ്യ r;
	അക്ഷരം *curve = ശൂന്യ;
	EVP_PKEY *pkey = ശൂന്യ;
	EC_താക്കോൽ *ec = ശൂന്യ;

	എങ്കിൽ ((താക്കോൽ->ecdsa_nid = sshkey_ecdsa_nid_from_name(ktype)) == -1)
		തിരികെ SSH_ERR_INVALID_ARGUMENT;
	എങ്കിൽ ((r = sshbuf_get_cstring(b, &curve, ശൂന്യ)) != 0)
		പോകുക out;
	എങ്കിൽ (താക്കോൽ->ecdsa_nid != sshkey_curve_name_to_nid(curve)) {
		r = SSH_ERR_EC_CURVE_MISMATCH;
		പോകുക out;
	}
	എങ്കിൽ ((ec = EC_താക്കോൽ_new_by_curve_name(താക്കോൽ->ecdsa_nid)) == ശൂന്യ) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		പോകുക out;
	}
	എങ്കിൽ ((r = sshbuf_get_eckey(b, ec)) != 0)
		പോകുക out;
	എങ്കിൽ (sshkey_ec_validate_public(EC_താക്കോൽ_get0_group(ec),
	    EC_താക്കോൽ_get0_public_താക്കോൽ(ec)) != 0) {
		r = SSH_ERR_താക്കോൽ_INVALID_EC_മൂല്യം;
		പോകുക out;
	}
	എങ്കിൽ ((pkey = EVP_PKEY_new()) == ശൂന്യ) {
		r = SSH_ERR_ALLOC_FAIL;
		പോകുക out;
	}
	എങ്കിൽ (EVP_PKEY_set1_EC_താക്കോൽ(pkey, ec) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		പോകുക out;
	}
	EVP_PKEY_free(താക്കോൽ->pkey);
	താക്കോൽ->pkey = pkey;
	pkey = ശൂന്യ;
	/* success */
	r = 0;
#ifdef DEBUG_PK
	sshkey_dump_ec_point(
	    EC_താക്കോൽ_get0_group(EVP_PKEY_get0_EC_താക്കോൽ(താക്കോൽ->pkey)),
	    EC_താക്കോൽ_get0_public_താക്കോൽ(EVP_PKEY_get0_EC_താക്കോൽ(താക്കോൽ->pkey)));
#endif
 out:
	EC_താക്കോൽ_free(ec);
	EVP_PKEY_free(pkey);
	സ്വതന്ത്രം(curve);
	തിരികെ r;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
ssh_ecdsa_deserialize_private(സ്ഥിരം അക്ഷരം *ktype, ഘടന sshbuf *b,
    ഘടന sshkey *താക്കോൽ)
{
	പൂർണ്ണസംഖ്യ r;
	BIGNUM *exponent = ശൂന്യ;
	EC_താക്കോൽ *ec = ശൂന്യ;

	എങ്കിൽ (!sshkey_is_cert(താക്കോൽ)) {
		എങ്കിൽ ((r = ssh_ecdsa_deserialize_public(ktype, b, താക്കോൽ)) != 0)
			തിരികെ r;
	}
	എങ്കിൽ ((r = sshbuf_get_bignum2(b, &exponent)) != 0)
		പോകുക out;
	എങ്കിൽ ((ec = EVP_PKEY_get1_EC_താക്കോൽ(താക്കോൽ->pkey)) == ശൂന്യ) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		പോകുക out;
	}
	എങ്കിൽ (EC_താക്കോൽ_set_private_താക്കോൽ(ec, exponent) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		പോകുക out;
	}
	എങ്കിൽ ((r = sshkey_ec_validate_private(ec)) != 0)
		പോകുക out;
	എങ്കിൽ (EVP_PKEY_set1_EC_താക്കോൽ(താക്കോൽ->pkey, ec) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		പോകുക out;
	}
	/* success */
	r = 0;
 out:
	BN_clear_free(exponent);
	EC_താക്കോൽ_free(ec);
	തിരികെ r;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
ssh_ecdsa_sign(ഘടന sshkey *താക്കോൽ,
    u_char **sigp, size_t *lenp,
    സ്ഥിരം u_char *data, size_t dlen,
    സ്ഥിരം അക്ഷരം *alg, സ്ഥിരം അക്ഷരം *sk_provider, സ്ഥിരം അക്ഷരം *sk_pin, u_int compat)
{
	ECDSA_SIG *esig = ശൂന്യ;
	unsigned അക്ഷരം *sigb = ശൂന്യ;
	സ്ഥിരം unsigned അക്ഷരം *psig;
	സ്ഥിരം BIGNUM *sig_r, *sig_s;
	പൂർണ്ണസംഖ്യ hash_alg;
	size_t slen = 0;
	പൂർണ്ണസംഖ്യ ret = SSH_ERR_INTERNAL_ERROR;

	എങ്കിൽ (lenp != ശൂന്യ)
		*lenp = 0;
	എങ്കിൽ (sigp != ശൂന്യ)
		*sigp = ശൂന്യ;

	എങ്കിൽ (താക്കോൽ == ശൂന്യ || താക്കോൽ->pkey == ശൂന്യ ||
	    sshkey_type_plain(താക്കോൽ->type) != താക്കോൽ_ECDSA)
		തിരികെ SSH_ERR_INVALID_ARGUMENT;

	എങ്കിൽ ((hash_alg = sshkey_ec_nid_to_hash_alg(താക്കോൽ->ecdsa_nid)) == -1)
		തിരികെ SSH_ERR_INTERNAL_ERROR;

	എങ്കിൽ ((ret = sshkey_pkey_digest_sign(താക്കോൽ->pkey, hash_alg, &sigb, &slen,
	    data, dlen)) != 0)
		പോകുക out;

	psig = sigb;
	എങ്കിൽ ((esig = d2i_ECDSA_SIG(ശൂന്യ, &psig, slen)) == ശൂന്യ) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		പോകുക out;
	}
	ECDSA_SIG_get0(esig, &sig_r, &sig_s);

	എങ്കിൽ ((ret = ssh_ecdsa_encode_store_sig(താക്കോൽ, sig_r, sig_s,
	    sigp, lenp)) != 0)
		പോകുക out;
	/* success */
	ret = 0;
 out:
	freezero(sigb, slen);
	ECDSA_SIG_free(esig);
	തിരികെ ret;
}

പൂർണ്ണസംഖ്യ
ssh_ecdsa_encode_store_sig(സ്ഥിരം ഘടന sshkey *താക്കോൽ,
    സ്ഥിരം BIGNUM *sig_r, സ്ഥിരം BIGNUM *sig_s,
    u_char **sigp, size_t *lenp)
{
	ഘടന sshbuf *b = ശൂന്യ, *bb = ശൂന്യ;
	പൂർണ്ണസംഖ്യ ret;
	size_t len;

	എങ്കിൽ (lenp != ശൂന്യ)
		*lenp = 0;
	എങ്കിൽ (sigp != ശൂന്യ)
		*sigp = ശൂന്യ;

	എങ്കിൽ ((bb = sshbuf_new()) == ശൂന്യ || (b = sshbuf_new()) == ശൂന്യ) {
		ret = SSH_ERR_ALLOC_FAIL;
		പോകുക out;
	}
	എങ്കിൽ ((ret = sshbuf_put_bignum2(bb, sig_r)) != 0 ||
	    (ret = sshbuf_put_bignum2(bb, sig_s)) != 0)
		പോകുക out;
	എങ്കിൽ ((ret = sshbuf_put_cstring(b, sshkey_ssh_name_plain(താക്കോൽ))) != 0 ||
	    (ret = sshbuf_put_stringb(b, bb)) != 0)
		പോകുക out;
	len = sshbuf_len(b);
	എങ്കിൽ (sigp != ശൂന്യ) {
		എങ്കിൽ ((*sigp = malloc(len)) == ശൂന്യ) {
			ret = SSH_ERR_ALLOC_FAIL;
			പോകുക out;
		}
		memcpy(*sigp, sshbuf_ptr(b), len);
	}
	എങ്കിൽ (lenp != ശൂന്യ)
		*lenp = len;
	ret = 0;
 out:
	sshbuf_free(b);
	sshbuf_free(bb);
	തിരികെ ret;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
ssh_ecdsa_verify(സ്ഥിരം ഘടന sshkey *താക്കോൽ,
    സ്ഥിരം u_char *sig, size_t siglen,
    സ്ഥിരം u_char *data, size_t dlen, സ്ഥിരം അക്ഷരം *alg, u_int compat,
    ഘടന sshkey_sig_details **detailsp)
{
	ECDSA_SIG *esig = ശൂന്യ;
	BIGNUM *sig_r = ശൂന്യ, *sig_s = ശൂന്യ;
	പൂർണ്ണസംഖ്യ hash_alg, len = 0;
	പൂർണ്ണസംഖ്യ ret = SSH_ERR_INTERNAL_ERROR;
	ഘടന sshbuf *b = ശൂന്യ, *sigbuf = ശൂന്യ;
	അക്ഷരം *ktype = ശൂന്യ;
	unsigned അക്ഷരം *sigb = ശൂന്യ, *cp;

	എങ്കിൽ (താക്കോൽ == ശൂന്യ || താക്കോൽ->pkey == ശൂന്യ ||
	    sshkey_type_plain(താക്കോൽ->type) != താക്കോൽ_ECDSA ||
	    sig == ശൂന്യ || siglen == 0)
		തിരികെ SSH_ERR_INVALID_ARGUMENT;

	എങ്കിൽ ((hash_alg = sshkey_ec_nid_to_hash_alg(താക്കോൽ->ecdsa_nid)) == -1)
		തിരികെ SSH_ERR_INTERNAL_ERROR;

	/* fetch signature */
	എങ്കിൽ ((b = sshbuf_from(sig, siglen)) == ശൂന്യ)
		തിരികെ SSH_ERR_ALLOC_FAIL;
	എങ്കിൽ (sshbuf_get_cstring(b, &ktype, ശൂന്യ) != 0 ||
	    sshbuf_froms(b, &sigbuf) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		പോകുക out;
	}
	എങ്കിൽ (strcmp(sshkey_ssh_name_plain(താക്കോൽ), ktype) != 0) {
		ret = SSH_ERR_താക്കോൽ_TYPE_MISMATCH;
		പോകുക out;
	}
	എങ്കിൽ (sshbuf_len(b) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		പോകുക out;
	}

	/* parse signature */
	എങ്കിൽ (sshbuf_get_bignum2(sigbuf, &sig_r) != 0 ||
	    sshbuf_get_bignum2(sigbuf, &sig_s) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		പോകുക out;
	}
	എങ്കിൽ (sshbuf_len(sigbuf) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		പോകുക out;
	}

	എങ്കിൽ ((esig = ECDSA_SIG_new()) == ശൂന്യ) {
		ret = SSH_ERR_ALLOC_FAIL;
		പോകുക out;
	}
	എങ്കിൽ (!ECDSA_SIG_set0(esig, sig_r, sig_s)) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		പോകുക out;
	}
	sig_r = sig_s = ശൂന്യ; /* transferred */

	എങ്കിൽ ((len = i2d_ECDSA_SIG(esig, ശൂന്യ)) <= 0) {
		len = 0;
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		പോകുക out;
	}
	എങ്കിൽ ((sigb = calloc(1, len)) == ശൂന്യ) {
		ret = SSH_ERR_ALLOC_FAIL;
		പോകുക out;
	}
	cp = sigb; /* ASN1_item_i2d increments the pointer past the object */
	എങ്കിൽ (i2d_ECDSA_SIG(esig, &cp) != len) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		പോകുക out;
	}
	എങ്കിൽ ((ret = sshkey_pkey_digest_verify(താക്കോൽ->pkey, hash_alg,
	    data, dlen, sigb, len)) != 0)
		പോകുക out;
	/* success */
 out:
	freezero(sigb, len);
	sshbuf_free(sigbuf);
	sshbuf_free(b);
	ECDSA_SIG_free(esig);
	BN_clear_free(sig_r);
	BN_clear_free(sig_s);
	സ്വതന്ത്രം(ktype);
	തിരികെ ret;
}

/* NB. not static; used by ECDSA-SK */
സ്ഥിരം ഘടന sshkey_impl_funcs sshkey_ecdsa_funcs = {
	/* .size = */		ssh_ecdsa_size,
	/* .alloc = */		ശൂന്യ,
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

സ്ഥിരം ഘടന sshkey_impl sshkey_ecdsa_nistp256_impl = {
	/* .name = */		"ecdsa-sha2-nistp256",
	/* .shortname = */	"ECDSA",
	/* .sigalg = */		ശൂന്യ,
	/* .type = */		താക്കോൽ_ECDSA,
	/* .nid = */		NID_X9_62_prime256v1,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

സ്ഥിരം ഘടന sshkey_impl sshkey_ecdsa_nistp256_cert_impl = {
	/* .name = */		"ecdsa-sha2-nistp256-cert-v01@openssh.com",
	/* .shortname = */	"ECDSA-CERT",
	/* .sigalg = */		ശൂന്യ,
	/* .type = */		താക്കോൽ_ECDSA_CERT,
	/* .nid = */		NID_X9_62_prime256v1,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

സ്ഥിരം ഘടന sshkey_impl sshkey_ecdsa_nistp384_impl = {
	/* .name = */		"ecdsa-sha2-nistp384",
	/* .shortname = */	"ECDSA",
	/* .sigalg = */		ശൂന്യ,
	/* .type = */		താക്കോൽ_ECDSA,
	/* .nid = */		NID_secp384r1,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

സ്ഥിരം ഘടന sshkey_impl sshkey_ecdsa_nistp384_cert_impl = {
	/* .name = */		"ecdsa-sha2-nistp384-cert-v01@openssh.com",
	/* .shortname = */	"ECDSA-CERT",
	/* .sigalg = */		ശൂന്യ,
	/* .type = */		താക്കോൽ_ECDSA_CERT,
	/* .nid = */		NID_secp384r1,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

സ്ഥിരം ഘടന sshkey_impl sshkey_ecdsa_nistp521_impl = {
	/* .name = */		"ecdsa-sha2-nistp521",
	/* .shortname = */	"ECDSA",
	/* .sigalg = */		ശൂന്യ,
	/* .type = */		താക്കോൽ_ECDSA,
	/* .nid = */		NID_secp521r1,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

സ്ഥിരം ഘടന sshkey_impl sshkey_ecdsa_nistp521_cert_impl = {
	/* .name = */		"ecdsa-sha2-nistp521-cert-v01@openssh.com",
	/* .shortname = */	"ECDSA-CERT",
	/* .sigalg = */		ശൂന്യ,
	/* .type = */		താക്കോൽ_ECDSA_CERT,
	/* .nid = */		NID_secp521r1,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

#endif /* WITH_OPENSSL */
