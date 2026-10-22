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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਜੇ defined(WITH_OPENSSL)
#ਅਨ੍ਤਰ੍ਭਾਵ "openbsd-compat/openssl-compat.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/bn.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/ec.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/ecdsa.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/evp.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "sshbuf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssherr.h"
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHKEY_ਅੰਦਰੂਨੀ
#ਅਨ੍ਤਰ੍ਭਾਵ "sshkey.h"

ਪੂਰਨ
sshkey_ecdsa_fixup_ਸਮੂਹ(EVP_PKEY *k)
{
	ਪੂਰਨ nids[] = {
		NID_X9_62_prime256v1,
		NID_secp384r1,
		NID_secp521r1,
		-1
	};
	ਪੂਰਨ nid = -1;
	u_int i;
	ਅਚਲ EC_ਸਮੂਹ *g;
	EC_ਕੁੰਜੀ *ec = ਨਿਰਾ;
	EC_ਸਮੂਹ *eg = ਨਿਰਾ;

	ਜੇ ((ec = EVP_PKEY_get1_EC_ਕੁੰਜੀ(k)) == ਨਿਰਾ ||
	    (g = EC_ਕੁੰਜੀ_get0_ਸਮੂਹ(ec)) == ਨਿਰਾ)
		ਜਾਓ ਬਾਹਰਲਾ;
	/*
	 * The group may be stored in a ASN.1 encoded private key in one of two
	 * ways: as a "named group", which is reconstituted by ASN.1 object ID
	 * or explicit group parameters encoded into the key blob. Only the
	 * "named group" case sets the group NID for us, but we can figure
	 * it out for the other case by comparing against all the groups that
	 * are supported.
	 */
	ਜੇ ((nid = EC_ਸਮੂਹ_get_ਵਕਰ_name(g)) > 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	nid = -1;
	ਲਈ (i = 0; nids[i] != -1; i++) {
		ਜੇ ((eg = EC_ਸਮੂਹ_new_by_ਵਕਰ_name(nids[i])) == ਨਿਰਾ)
			ਜਾਓ ਬਾਹਰਲਾ;
		ਜੇ (EC_ਸਮੂਹ_cmp(g, eg, ਨਿਰਾ) == 0)
			ਰੋਕੋ;
		EC_ਸਮੂਹ_free(eg);
		eg = ਨਿਰਾ;
	}
	ਜੇ (nids[i] == -1)
		ਜਾਓ ਬਾਹਰਲਾ;

	/* Use the group with the NID attached */
	EC_ਸਮੂਹ_ਸੈੱਟ_asn1_flag(eg, OPENSSL_EC_NAMED_ਵਕਰ);
	ਜੇ (EC_ਕੁੰਜੀ_ਸੈੱਟ_ਸਮੂਹ(ec, eg) != 1 ||
	    EVP_PKEY_set1_EC_ਕੁੰਜੀ(k, ec) != 1)
		ਜਾਓ ਬਾਹਰਲਾ;
	/* success */
	nid = nids[i];
 ਬਾਹਰਲਾ:
	EC_ਕੁੰਜੀ_free(ec);
	EC_ਸਮੂਹ_free(eg);
	ਵਾਪਸ nid;
}

ਸਥਿਰ u_int
ssh_ecdsa_ਮਾਪ(ਅਚਲ ਬਣਤਰ sshkey *ਕੁੰਜੀ)
{
	ਚੋਣ (ਕੁੰਜੀ->ecdsa_nid) {
	ਹਾਲਤ NID_X9_62_prime256v1:
		ਵਾਪਸ 256;
	ਹਾਲਤ NID_secp384r1:
		ਵਾਪਸ 384;
	ਹਾਲਤ NID_secp521r1:
		ਵਾਪਸ 521;
	ਮੂਲ:
		ਵਾਪਸ 0;
	}
}

ਸਥਿਰ ਖਾਲੀ
ssh_ecdsa_cleanup(ਬਣਤਰ sshkey *k)
{
	EVP_PKEY_free(k->pkey);
	k->pkey = ਨਿਰਾ;
}

ਸਥਿਰ ਪੂਰਨ
ssh_ecdsa_equal(ਅਚਲ ਬਣਤਰ sshkey *a, ਅਚਲ ਬਣਤਰ sshkey *b)
{
	ਜੇ (a->pkey == ਨਿਰਾ || b->pkey == ਨਿਰਾ)
		ਵਾਪਸ 0;
	ਵਾਪਸ EVP_PKEY_cmp(a->pkey, b->pkey) == 1;
}

ਸਥਿਰ ਪੂਰਨ
ssh_ecdsa_serialize_ਜਨਤਕ(ਅਚਲ ਬਣਤਰ sshkey *ਕੁੰਜੀ, ਬਣਤਰ sshbuf *b,
    ਗਿਣਤੀ sshkey_serialize_rep opts)
{
	ਪੂਰਨ r;

	ਜੇ (ਕੁੰਜੀ->pkey == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_INVALID_ਦਲੀਲ;
	ਜੇ ((r = sshbuf_put_cstring(b,
	    sshkey_ਵਕਰ_nid_ਮੰਜ਼ਿਲ_name(ਕੁੰਜੀ->ecdsa_nid))) != 0 ||
	    (r = sshbuf_put_ec_pkey(b, ਕੁੰਜੀ->pkey)) != 0)
		ਵਾਪਸ r;

	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
ssh_ecdsa_serialize_ਨਿੱਜੀ(ਅਚਲ ਬਣਤਰ sshkey *ਕੁੰਜੀ, ਬਣਤਰ sshbuf *b,
    ਗਿਣਤੀ sshkey_serialize_rep opts)
{
	ਪੂਰਨ r;

	ਜੇ (!sshkey_is_cert(ਕੁੰਜੀ)) {
		ਜੇ ((r = ssh_ecdsa_serialize_ਜਨਤਕ(ਕੁੰਜੀ, b, opts)) != 0)
			ਵਾਪਸ r;
	}
	ਜੇ ((r = sshbuf_put_bignum2(b,
	    EC_ਕੁੰਜੀ_get0_ਨਿੱਜੀ_ਕੁੰਜੀ(EVP_PKEY_get0_EC_ਕੁੰਜੀ(ਕੁੰਜੀ->pkey)))) != 0)
		ਵਾਪਸ r;
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
ssh_ecdsa_generate(ਬਣਤਰ sshkey *k, ਪੂਰਨ ਬਿੱਟ)
{
	EVP_PKEY *res = ਨਿਰਾ;
	EVP_PKEY_CTX *ctx = ਨਿਰਾ;
	ਪੂਰਨ ret = SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;

	ਜੇ ((k->ecdsa_nid = sshkey_ecdsa_ਬਿੱਟ_ਮੰਜ਼ਿਲ_nid(ਬਿੱਟ)) == -1)
		ਵਾਪਸ SSH_ERR_ਕੁੰਜੀ_ਲੰਮਾਈ;

	ਜੇ ((ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, ਨਿਰਾ)) == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_ALLOC_FAIL;

	ਜੇ (EVP_PKEY_keygen_init(ctx) <= 0 ||
	    EVP_PKEY_CTX_ਸੈੱਟ_ec_paramgen_ਵਕਰ_nid(ctx, k->ecdsa_nid) <= 0 ||
	    EVP_PKEY_keygen(ctx, &res) <= 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	/* success */
	k->pkey = res;
	res = ਨਿਰਾ;
	ret = 0;
 ਬਾਹਰਲਾ:
	EVP_PKEY_free(res);
	EVP_PKEY_CTX_free(ctx);
	ਵਾਪਸ ret;
}

ਸਥਿਰ ਪੂਰਨ
ssh_ecdsa_copy_ਜਨਤਕ(ਅਚਲ ਬਣਤਰ sshkey *from, ਬਣਤਰ sshkey *ਮੰਜ਼ਿਲ)
{
	ਅਚਲ EC_ਕੁੰਜੀ *ec_from;
	EC_ਕੁੰਜੀ *ec_ਮੰਜ਼ਿਲ = ਨਿਰਾ;
	ਪੂਰਨ ret = SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;

	ec_from = EVP_PKEY_get0_EC_ਕੁੰਜੀ(from->pkey);
	ਜੇ (ec_from == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_LIBCRYPTO_ERROR;

	ਮੰਜ਼ਿਲ->ecdsa_nid = from->ecdsa_nid;
	ਜੇ ((ec_ਮੰਜ਼ਿਲ = EC_ਕੁੰਜੀ_new_by_ਵਕਰ_name(from->ecdsa_nid)) == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_ALLOC_FAIL;
	ਜੇ (EC_ਕੁੰਜੀ_ਸੈੱਟ_ਜਨਤਕ_ਕੁੰਜੀ(ec_ਮੰਜ਼ਿਲ,
	    EC_ਕੁੰਜੀ_get0_ਜਨਤਕ_ਕੁੰਜੀ(ec_from)) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	EVP_PKEY_free(ਮੰਜ਼ਿਲ->pkey);
	ਜੇ ((ਮੰਜ਼ਿਲ->pkey = EVP_PKEY_new()) == ਨਿਰਾ) {
		ret = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (EVP_PKEY_set1_EC_ਕੁੰਜੀ(ਮੰਜ਼ਿਲ->pkey, ec_ਮੰਜ਼ਿਲ) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ret = 0;
 ਬਾਹਰਲਾ:
	EC_ਕੁੰਜੀ_free(ec_ਮੰਜ਼ਿਲ);
	ਵਾਪਸ ret;
}

ਸਥਿਰ ਪੂਰਨ
ssh_ecdsa_deserialize_ਜਨਤਕ(ਅਚਲ ਅੱਖਰ *ktype, ਬਣਤਰ sshbuf *b,
    ਬਣਤਰ sshkey *ਕੁੰਜੀ)
{
	ਪੂਰਨ r;
	ਅੱਖਰ *ਵਕਰ = ਨਿਰਾ;
	EVP_PKEY *pkey = ਨਿਰਾ;
	EC_ਕੁੰਜੀ *ec = ਨਿਰਾ;

	ਜੇ ((ਕੁੰਜੀ->ecdsa_nid = sshkey_ecdsa_nid_from_name(ktype)) == -1)
		ਵਾਪਸ SSH_ERR_INVALID_ਦਲੀਲ;
	ਜੇ ((r = sshbuf_get_cstring(b, &ਵਕਰ, ਨਿਰਾ)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	ਜੇ (ਕੁੰਜੀ->ecdsa_nid != sshkey_ਵਕਰ_name_ਮੰਜ਼ਿਲ_nid(ਵਕਰ)) {
		r = SSH_ERR_EC_ਵਕਰ_MISMATCH;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((ec = EC_ਕੁੰਜੀ_new_by_ਵਕਰ_name(ਕੁੰਜੀ->ecdsa_nid)) == ਨਿਰਾ) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((r = sshbuf_get_eckey(b, ec)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	ਜੇ (sshkey_ec_validate_ਜਨਤਕ(EC_ਕੁੰਜੀ_get0_ਸਮੂਹ(ec),
	    EC_ਕੁੰਜੀ_get0_ਜਨਤਕ_ਕੁੰਜੀ(ec)) != 0) {
		r = SSH_ERR_ਕੁੰਜੀ_INVALID_EC_ਮੁੱਲ;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((pkey = EVP_PKEY_new()) == ਨਿਰਾ) {
		r = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (EVP_PKEY_set1_EC_ਕੁੰਜੀ(pkey, ec) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	EVP_PKEY_free(ਕੁੰਜੀ->pkey);
	ਕੁੰਜੀ->pkey = pkey;
	pkey = ਨਿਰਾ;
	/* success */
	r = 0;
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ DEBUG_PK
	sshkey_dump_ec_ਬਿੰਦੂ(
	    EC_ਕੁੰਜੀ_get0_ਸਮੂਹ(EVP_PKEY_get0_EC_ਕੁੰਜੀ(ਕੁੰਜੀ->pkey)),
	    EC_ਕੁੰਜੀ_get0_ਜਨਤਕ_ਕੁੰਜੀ(EVP_PKEY_get0_EC_ਕੁੰਜੀ(ਕੁੰਜੀ->pkey)));
#ਜੇ_ਅੰਤ
 ਬਾਹਰਲਾ:
	EC_ਕੁੰਜੀ_free(ec);
	EVP_PKEY_free(pkey);
	ਮੁਕਤ(ਵਕਰ);
	ਵਾਪਸ r;
}

ਸਥਿਰ ਪੂਰਨ
ssh_ecdsa_deserialize_ਨਿੱਜੀ(ਅਚਲ ਅੱਖਰ *ktype, ਬਣਤਰ sshbuf *b,
    ਬਣਤਰ sshkey *ਕੁੰਜੀ)
{
	ਪੂਰਨ r;
	BIGNUM *exponent = ਨਿਰਾ;
	EC_ਕੁੰਜੀ *ec = ਨਿਰਾ;

	ਜੇ (!sshkey_is_cert(ਕੁੰਜੀ)) {
		ਜੇ ((r = ssh_ecdsa_deserialize_ਜਨਤਕ(ktype, b, ਕੁੰਜੀ)) != 0)
			ਵਾਪਸ r;
	}
	ਜੇ ((r = sshbuf_get_bignum2(b, &exponent)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	ਜੇ ((ec = EVP_PKEY_get1_EC_ਕੁੰਜੀ(ਕੁੰਜੀ->pkey)) == ਨਿਰਾ) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (EC_ਕੁੰਜੀ_ਸੈੱਟ_ਨਿੱਜੀ_ਕੁੰਜੀ(ec, exponent) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((r = sshkey_ec_validate_ਨਿੱਜੀ(ec)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	ਜੇ (EVP_PKEY_set1_EC_ਕੁੰਜੀ(ਕੁੰਜੀ->pkey, ec) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	/* success */
	r = 0;
 ਬਾਹਰਲਾ:
	BN_clear_free(exponent);
	EC_ਕੁੰਜੀ_free(ec);
	ਵਾਪਸ r;
}

ਸਥਿਰ ਪੂਰਨ
ssh_ecdsa_sign(ਬਣਤਰ sshkey *ਕੁੰਜੀ,
    u_char **sigp, ਮਾਪ_t *lenp,
    ਅਚਲ u_char *ਅੰਕੜੇ, ਮਾਪ_t dlen,
    ਅਚਲ ਅੱਖਰ *alg, ਅਚਲ ਅੱਖਰ *sk_provider, ਅਚਲ ਅੱਖਰ *sk_pin, u_int compat)
{
	ECDSA_SIG *esig = ਨਿਰਾ;
	ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *sigb = ਨਿਰਾ;
	ਅਚਲ ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *psig;
	ਅਚਲ BIGNUM *sig_r, *sig_s;
	ਪੂਰਨ hash_alg;
	ਮਾਪ_t slen = 0;
	ਪੂਰਨ ret = SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;

	ਜੇ (lenp != ਨਿਰਾ)
		*lenp = 0;
	ਜੇ (sigp != ਨਿਰਾ)
		*sigp = ਨਿਰਾ;

	ਜੇ (ਕੁੰਜੀ == ਨਿਰਾ || ਕੁੰਜੀ->pkey == ਨਿਰਾ ||
	    sshkey_type_plain(ਕੁੰਜੀ->type) != ਕੁੰਜੀ_ECDSA)
		ਵਾਪਸ SSH_ERR_INVALID_ਦਲੀਲ;

	ਜੇ ((hash_alg = sshkey_ec_nid_ਮੰਜ਼ਿਲ_hash_alg(ਕੁੰਜੀ->ecdsa_nid)) == -1)
		ਵਾਪਸ SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;

	ਜੇ ((ret = sshkey_pkey_digest_sign(ਕੁੰਜੀ->pkey, hash_alg, &sigb, &slen,
	    ਅੰਕੜੇ, dlen)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;

	psig = sigb;
	ਜੇ ((esig = d2i_ECDSA_SIG(ਨਿਰਾ, &psig, slen)) == ਨਿਰਾ) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ECDSA_SIG_get0(esig, &sig_r, &sig_s);

	ਜੇ ((ret = ssh_ecdsa_encode_store_sig(ਕੁੰਜੀ, sig_r, sig_s,
	    sigp, lenp)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	/* success */
	ret = 0;
 ਬਾਹਰਲਾ:
	freezero(sigb, slen);
	ECDSA_SIG_free(esig);
	ਵਾਪਸ ret;
}

ਪੂਰਨ
ssh_ecdsa_encode_store_sig(ਅਚਲ ਬਣਤਰ sshkey *ਕੁੰਜੀ,
    ਅਚਲ BIGNUM *sig_r, ਅਚਲ BIGNUM *sig_s,
    u_char **sigp, ਮਾਪ_t *lenp)
{
	ਬਣਤਰ sshbuf *b = ਨਿਰਾ, *bb = ਨਿਰਾ;
	ਪੂਰਨ ret;
	ਮਾਪ_t len;

	ਜੇ (lenp != ਨਿਰਾ)
		*lenp = 0;
	ਜੇ (sigp != ਨਿਰਾ)
		*sigp = ਨਿਰਾ;

	ਜੇ ((bb = sshbuf_new()) == ਨਿਰਾ || (b = sshbuf_new()) == ਨਿਰਾ) {
		ret = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((ret = sshbuf_put_bignum2(bb, sig_r)) != 0 ||
	    (ret = sshbuf_put_bignum2(bb, sig_s)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	ਜੇ ((ret = sshbuf_put_cstring(b, sshkey_ssh_name_plain(ਕੁੰਜੀ))) != 0 ||
	    (ret = sshbuf_put_stringb(b, bb)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	len = sshbuf_len(b);
	ਜੇ (sigp != ਨਿਰਾ) {
		ਜੇ ((*sigp = ਸਮ੍ਰਿਤੀ_ਦਿਓ(len)) == ਨਿਰਾ) {
			ret = SSH_ERR_ALLOC_FAIL;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਸਮ੍ਰਿਤੀ_ਨਕਲ(*sigp, sshbuf_ptr(b), len);
	}
	ਜੇ (lenp != ਨਿਰਾ)
		*lenp = len;
	ret = 0;
 ਬਾਹਰਲਾ:
	sshbuf_free(b);
	sshbuf_free(bb);
	ਵਾਪਸ ret;
}

ਸਥਿਰ ਪੂਰਨ
ssh_ecdsa_verify(ਅਚਲ ਬਣਤਰ sshkey *ਕੁੰਜੀ,
    ਅਚਲ u_char *sig, ਮਾਪ_t siglen,
    ਅਚਲ u_char *ਅੰਕੜੇ, ਮਾਪ_t dlen, ਅਚਲ ਅੱਖਰ *alg, u_int compat,
    ਬਣਤਰ sshkey_sig_details **detailsp)
{
	ECDSA_SIG *esig = ਨਿਰਾ;
	BIGNUM *sig_r = ਨਿਰਾ, *sig_s = ਨਿਰਾ;
	ਪੂਰਨ hash_alg, len = 0;
	ਪੂਰਨ ret = SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
	ਬਣਤਰ sshbuf *b = ਨਿਰਾ, *sigbuf = ਨਿਰਾ;
	ਅੱਖਰ *ktype = ਨਿਰਾ;
	ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *sigb = ਨਿਰਾ, *cp;

	ਜੇ (ਕੁੰਜੀ == ਨਿਰਾ || ਕੁੰਜੀ->pkey == ਨਿਰਾ ||
	    sshkey_type_plain(ਕੁੰਜੀ->type) != ਕੁੰਜੀ_ECDSA ||
	    sig == ਨਿਰਾ || siglen == 0)
		ਵਾਪਸ SSH_ERR_INVALID_ਦਲੀਲ;

	ਜੇ ((hash_alg = sshkey_ec_nid_ਮੰਜ਼ਿਲ_hash_alg(ਕੁੰਜੀ->ecdsa_nid)) == -1)
		ਵਾਪਸ SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;

	/* fetch signature */
	ਜੇ ((b = sshbuf_from(sig, siglen)) == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_ALLOC_FAIL;
	ਜੇ (sshbuf_get_cstring(b, &ktype, ਨਿਰਾ) != 0 ||
	    sshbuf_froms(b, &sigbuf) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (strcmp(sshkey_ssh_name_plain(ਕੁੰਜੀ), ktype) != 0) {
		ret = SSH_ERR_ਕੁੰਜੀ_TYPE_MISMATCH;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (sshbuf_len(b) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_ਅੰਕੜੇ;
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	/* parse signature */
	ਜੇ (sshbuf_get_bignum2(sigbuf, &sig_r) != 0 ||
	    sshbuf_get_bignum2(sigbuf, &sig_s) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (sshbuf_len(sigbuf) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_ਅੰਕੜੇ;
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	ਜੇ ((esig = ECDSA_SIG_new()) == ਨਿਰਾ) {
		ret = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (!ECDSA_SIG_set0(esig, sig_r, sig_s)) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	sig_r = sig_s = ਨਿਰਾ; /* transferred */

	ਜੇ ((len = i2d_ECDSA_SIG(esig, ਨਿਰਾ)) <= 0) {
		len = 0;
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((sigb = ਸਿਫਰ_ਸਮ੍ਰਿਤੀ_ਦਿਓ(1, len)) == ਨਿਰਾ) {
		ret = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	cp = sigb; /* ASN1_item_i2d increments the pointer past the object */
	ਜੇ (i2d_ECDSA_SIG(esig, &cp) != len) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((ret = sshkey_pkey_digest_verify(ਕੁੰਜੀ->pkey, hash_alg,
	    ਅੰਕੜੇ, dlen, sigb, len)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	/* success */
 ਬਾਹਰਲਾ:
	freezero(sigb, len);
	sshbuf_free(sigbuf);
	sshbuf_free(b);
	ECDSA_SIG_free(esig);
	BN_clear_free(sig_r);
	BN_clear_free(sig_s);
	ਮੁਕਤ(ktype);
	ਵਾਪਸ ret;
}

/* NB. not static; used by ECDSA-SK */
ਅਚਲ ਬਣਤਰ sshkey_impl_funcs sshkey_ecdsa_funcs = {
	/* .size = */		ssh_ecdsa_ਮਾਪ,
	/* .alloc = */		ਨਿਰਾ,
	/* .cleanup = */	ssh_ecdsa_cleanup,
	/* .equal = */		ssh_ecdsa_equal,
	/* .ssh_serialize_public = */ ssh_ecdsa_serialize_ਜਨਤਕ,
	/* .ssh_deserialize_public = */ ssh_ecdsa_deserialize_ਜਨਤਕ,
	/* .ssh_serialize_private = */ ssh_ecdsa_serialize_ਨਿੱਜੀ,
	/* .ssh_deserialize_private = */ ssh_ecdsa_deserialize_ਨਿੱਜੀ,
	/* .generate = */	ssh_ecdsa_generate,
	/* .copy_public = */	ssh_ecdsa_copy_ਜਨਤਕ,
	/* .sign = */		ssh_ecdsa_sign,
	/* .verify = */		ssh_ecdsa_verify,
};

ਅਚਲ ਬਣਤਰ sshkey_impl sshkey_ecdsa_nistp256_impl = {
	/* .name = */		"ecdsa-sha2-nistp256",
	/* .shortname = */	"ECDSA",
	/* .sigalg = */		ਨਿਰਾ,
	/* .type = */		ਕੁੰਜੀ_ECDSA,
	/* .nid = */		NID_X9_62_prime256v1,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

ਅਚਲ ਬਣਤਰ sshkey_impl sshkey_ecdsa_nistp256_cert_impl = {
	/* .name = */		"ecdsa-sha2-nistp256-cert-v01@openssh.com",
	/* .shortname = */	"ECDSA-CERT",
	/* .sigalg = */		ਨਿਰਾ,
	/* .type = */		ਕੁੰਜੀ_ECDSA_CERT,
	/* .nid = */		NID_X9_62_prime256v1,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

ਅਚਲ ਬਣਤਰ sshkey_impl sshkey_ecdsa_nistp384_impl = {
	/* .name = */		"ecdsa-sha2-nistp384",
	/* .shortname = */	"ECDSA",
	/* .sigalg = */		ਨਿਰਾ,
	/* .type = */		ਕੁੰਜੀ_ECDSA,
	/* .nid = */		NID_secp384r1,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

ਅਚਲ ਬਣਤਰ sshkey_impl sshkey_ecdsa_nistp384_cert_impl = {
	/* .name = */		"ecdsa-sha2-nistp384-cert-v01@openssh.com",
	/* .shortname = */	"ECDSA-CERT",
	/* .sigalg = */		ਨਿਰਾ,
	/* .type = */		ਕੁੰਜੀ_ECDSA_CERT,
	/* .nid = */		NID_secp384r1,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

ਅਚਲ ਬਣਤਰ sshkey_impl sshkey_ecdsa_nistp521_impl = {
	/* .name = */		"ecdsa-sha2-nistp521",
	/* .shortname = */	"ECDSA",
	/* .sigalg = */		ਨਿਰਾ,
	/* .type = */		ਕੁੰਜੀ_ECDSA,
	/* .nid = */		NID_secp521r1,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

ਅਚਲ ਬਣਤਰ sshkey_impl sshkey_ecdsa_nistp521_cert_impl = {
	/* .name = */		"ecdsa-sha2-nistp521-cert-v01@openssh.com",
	/* .shortname = */	"ECDSA-CERT",
	/* .sigalg = */		ਨਿਰਾ,
	/* .type = */		ਕੁੰਜੀ_ECDSA_CERT,
	/* .nid = */		NID_secp521r1,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

#ਜੇ_ਅੰਤ /* WITH_OPENSSL */
