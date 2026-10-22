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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಯದಿ defined(WITH_OPENSSL)
#ಅನ್ತರ್ಭಾವ "openbsd-compat/openssl-compat.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>

#ಅನ್ತರ್ಭಾವ <openssl/bn.h>
#ಅನ್ತರ್ಭಾವ <openssl/ec.h>
#ಅನ್ತರ್ಭಾವ <openssl/ecdsa.h>
#ಅನ್ತರ್ಭಾವ <openssl/evp.h>

#ಅನ್ತರ್ಭಾವ <string.h>

#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "ssherr.h"
#define SSHKEY_INTERNAL
#ಅನ್ತರ್ಭಾವ "sshkey.h"

ಪೂರ್ಣಾಙ್ಕ
sshkey_ecdsa_fixup_group(EVP_PKEY *k)
{
	ಪೂರ್ಣಾಙ್ಕ nids[] = {
		NID_X9_62_prime256v1,
		NID_secp384r1,
		NID_secp521r1,
		-1
	};
	ಪೂರ್ಣಾಙ್ಕ nid = -1;
	u_int i;
	ಧ್ರುವ EC_GROUP *g;
	EC_ಕೀಲಿ *ec = ರಿಕ್ತ;
	EC_GROUP *eg = ರಿಕ್ತ;

	ಯದಿ ((ec = EVP_PKEY_get1_EC_ಕೀಲಿ(k)) == ರಿಕ್ತ ||
	    (g = EC_ಕೀಲಿ_get0_group(ec)) == ರಿಕ್ತ)
		ಗಚ್ಛ out;
	/*
	 * The group may be stored in a ASN.1 encoded private key in one of two
	 * ways: as a "named group", which is reconstituted by ASN.1 object ID
	 * or explicit group parameters encoded into the key blob. Only the
	 * "named group" case sets the group NID for us, but we can figure
	 * it out for the other case by comparing against all the groups that
	 * are supported.
	 */
	ಯದಿ ((nid = EC_GROUP_get_curve_name(g)) > 0)
		ಗಚ್ಛ out;
	nid = -1;
	ಪ್ರತಿ (i = 0; nids[i] != -1; i++) {
		ಯದಿ ((eg = EC_GROUP_new_by_curve_name(nids[i])) == ರಿಕ್ತ)
			ಗಚ್ಛ out;
		ಯದಿ (EC_GROUP_cmp(g, eg, ರಿಕ್ತ) == 0)
			ಭಙ್ಗ;
		EC_GROUP_free(eg);
		eg = ರಿಕ್ತ;
	}
	ಯದಿ (nids[i] == -1)
		ಗಚ್ಛ out;

	/* Use the group with the NID attached */
	EC_GROUP_set_asn1_flag(eg, OPENSSL_EC_NAMED_CURVE);
	ಯದಿ (EC_ಕೀಲಿ_set_group(ec, eg) != 1 ||
	    EVP_PKEY_set1_EC_ಕೀಲಿ(k, ec) != 1)
		ಗಚ್ಛ out;
	/* success */
	nid = nids[i];
 out:
	EC_ಕೀಲಿ_free(ec);
	EC_GROUP_free(eg);
	ಪ್ರತ್ಯಾಗಮ nid;
}

ಸ್ಥಿರ u_int
ssh_ecdsa_size(ಧ್ರುವ ಸಂರಚನಾ sshkey *ಕೀಲಿ)
{
	ವಿಕಲ್ಪ (ಕೀಲಿ->ecdsa_nid) {
	ಪಕ್ಷ NID_X9_62_prime256v1:
		ಪ್ರತ್ಯಾಗಮ 256;
	ಪಕ್ಷ NID_secp384r1:
		ಪ್ರತ್ಯಾಗಮ 384;
	ಪಕ್ಷ NID_secp521r1:
		ಪ್ರತ್ಯಾಗಮ 521;
	ಸ್ವಭಾವ:
		ಪ್ರತ್ಯಾಗಮ 0;
	}
}

ಸ್ಥಿರ ಶೂನ್ಯ
ssh_ecdsa_cleanup(ಸಂರಚನಾ sshkey *k)
{
	EVP_PKEY_free(k->pkey);
	k->pkey = ರಿಕ್ತ;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
ssh_ecdsa_equal(ಧ್ರುವ ಸಂರಚನಾ sshkey *a, ಧ್ರುವ ಸಂರಚನಾ sshkey *b)
{
	ಯದಿ (a->pkey == ರಿಕ್ತ || b->pkey == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಪ್ರತ್ಯಾಗಮ EVP_PKEY_cmp(a->pkey, b->pkey) == 1;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
ssh_ecdsa_serialize_public(ಧ್ರುವ ಸಂರಚನಾ sshkey *ಕೀಲಿ, ಸಂರಚನಾ sshbuf *b,
    ಗಣನಾ sshkey_serialize_rep opts)
{
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ (ಕೀಲಿ->pkey == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_ARGUMENT;
	ಯದಿ ((r = sshbuf_put_cstring(b,
	    sshkey_curve_nid_to_name(ಕೀಲಿ->ecdsa_nid))) != 0 ||
	    (r = sshbuf_put_ec_pkey(b, ಕೀಲಿ->pkey)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;

	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
ssh_ecdsa_serialize_private(ಧ್ರುವ ಸಂರಚನಾ sshkey *ಕೀಲಿ, ಸಂರಚನಾ sshbuf *b,
    ಗಣನಾ sshkey_serialize_rep opts)
{
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ (!sshkey_is_cert(ಕೀಲಿ)) {
		ಯದಿ ((r = ssh_ecdsa_serialize_public(ಕೀಲಿ, b, opts)) != 0)
			ಪ್ರತ್ಯಾಗಮ r;
	}
	ಯದಿ ((r = sshbuf_put_bignum2(b,
	    EC_ಕೀಲಿ_get0_private_ಕೀಲಿ(EVP_PKEY_get0_EC_ಕೀಲಿ(ಕೀಲಿ->pkey)))) != 0)
		ಪ್ರತ್ಯಾಗಮ r;
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
ssh_ecdsa_generate(ಸಂರಚನಾ sshkey *k, ಪೂರ್ಣಾಙ್ಕ bits)
{
	EVP_PKEY *res = ರಿಕ್ತ;
	EVP_PKEY_CTX *ctx = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ ret = SSH_ERR_INTERNAL_ERROR;

	ಯದಿ ((k->ecdsa_nid = sshkey_ecdsa_bits_to_nid(bits)) == -1)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ಕೀಲಿ_LENGTH;

	ಯದಿ ((ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, ರಿಕ್ತ)) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ALLOC_FAIL;

	ಯದಿ (EVP_PKEY_keygen_init(ctx) <= 0 ||
	    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, k->ecdsa_nid) <= 0 ||
	    EVP_PKEY_keygen(ctx, &res) <= 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		ಗಚ್ಛ out;
	}
	/* success */
	k->pkey = res;
	res = ರಿಕ್ತ;
	ret = 0;
 out:
	EVP_PKEY_free(res);
	EVP_PKEY_CTX_free(ctx);
	ಪ್ರತ್ಯಾಗಮ ret;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
ssh_ecdsa_copy_public(ಧ್ರುವ ಸಂರಚನಾ sshkey *from, ಸಂರಚನಾ sshkey *to)
{
	ಧ್ರುವ EC_ಕೀಲಿ *ec_from;
	EC_ಕೀಲಿ *ec_to = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ ret = SSH_ERR_INTERNAL_ERROR;

	ec_from = EVP_PKEY_get0_EC_ಕೀಲಿ(from->pkey);
	ಯದಿ (ec_from == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_LIBCRYPTO_ERROR;

	to->ecdsa_nid = from->ecdsa_nid;
	ಯದಿ ((ec_to = EC_ಕೀಲಿ_new_by_curve_name(from->ecdsa_nid)) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ALLOC_FAIL;
	ಯದಿ (EC_ಕೀಲಿ_set_public_ಕೀಲಿ(ec_to,
	    EC_ಕೀಲಿ_get0_public_ಕೀಲಿ(ec_from)) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		ಗಚ್ಛ out;
	}
	EVP_PKEY_free(to->pkey);
	ಯದಿ ((to->pkey = EVP_PKEY_new()) == ರಿಕ್ತ) {
		ret = SSH_ERR_ALLOC_FAIL;
		ಗಚ್ಛ out;
	}
	ಯದಿ (EVP_PKEY_set1_EC_ಕೀಲಿ(to->pkey, ec_to) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		ಗಚ್ಛ out;
	}
	ret = 0;
 out:
	EC_ಕೀಲಿ_free(ec_to);
	ಪ್ರತ್ಯಾಗಮ ret;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
ssh_ecdsa_deserialize_public(ಧ್ರುವ ವರ್ಣ *ktype, ಸಂರಚನಾ sshbuf *b,
    ಸಂರಚನಾ sshkey *ಕೀಲಿ)
{
	ಪೂರ್ಣಾಙ್ಕ r;
	ವರ್ಣ *curve = ರಿಕ್ತ;
	EVP_PKEY *pkey = ರಿಕ್ತ;
	EC_ಕೀಲಿ *ec = ರಿಕ್ತ;

	ಯದಿ ((ಕೀಲಿ->ecdsa_nid = sshkey_ecdsa_nid_from_name(ktype)) == -1)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_ARGUMENT;
	ಯದಿ ((r = sshbuf_get_cstring(b, &curve, ರಿಕ್ತ)) != 0)
		ಗಚ್ಛ out;
	ಯದಿ (ಕೀಲಿ->ecdsa_nid != sshkey_curve_name_to_nid(curve)) {
		r = SSH_ERR_EC_CURVE_MISMATCH;
		ಗಚ್ಛ out;
	}
	ಯದಿ ((ec = EC_ಕೀಲಿ_new_by_curve_name(ಕೀಲಿ->ecdsa_nid)) == ರಿಕ್ತ) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		ಗಚ್ಛ out;
	}
	ಯದಿ ((r = sshbuf_get_eckey(b, ec)) != 0)
		ಗಚ್ಛ out;
	ಯದಿ (sshkey_ec_validate_public(EC_ಕೀಲಿ_get0_group(ec),
	    EC_ಕೀಲಿ_get0_public_ಕೀಲಿ(ec)) != 0) {
		r = SSH_ERR_ಕೀಲಿ_INVALID_EC_ಮೌಲ್ಯ;
		ಗಚ್ಛ out;
	}
	ಯದಿ ((pkey = EVP_PKEY_new()) == ರಿಕ್ತ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಗಚ್ಛ out;
	}
	ಯದಿ (EVP_PKEY_set1_EC_ಕೀಲಿ(pkey, ec) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		ಗಚ್ಛ out;
	}
	EVP_PKEY_free(ಕೀಲಿ->pkey);
	ಕೀಲಿ->pkey = pkey;
	pkey = ರಿಕ್ತ;
	/* success */
	r = 0;
#ifdef DEBUG_PK
	sshkey_dump_ec_point(
	    EC_ಕೀಲಿ_get0_group(EVP_PKEY_get0_EC_ಕೀಲಿ(ಕೀಲಿ->pkey)),
	    EC_ಕೀಲಿ_get0_public_ಕೀಲಿ(EVP_PKEY_get0_EC_ಕೀಲಿ(ಕೀಲಿ->pkey)));
#endif
 out:
	EC_ಕೀಲಿ_free(ec);
	EVP_PKEY_free(pkey);
	ಮುಕ್ತ(curve);
	ಪ್ರತ್ಯಾಗಮ r;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
ssh_ecdsa_deserialize_private(ಧ್ರುವ ವರ್ಣ *ktype, ಸಂರಚನಾ sshbuf *b,
    ಸಂರಚನಾ sshkey *ಕೀಲಿ)
{
	ಪೂರ್ಣಾಙ್ಕ r;
	BIGNUM *exponent = ರಿಕ್ತ;
	EC_ಕೀಲಿ *ec = ರಿಕ್ತ;

	ಯದಿ (!sshkey_is_cert(ಕೀಲಿ)) {
		ಯದಿ ((r = ssh_ecdsa_deserialize_public(ktype, b, ಕೀಲಿ)) != 0)
			ಪ್ರತ್ಯಾಗಮ r;
	}
	ಯದಿ ((r = sshbuf_get_bignum2(b, &exponent)) != 0)
		ಗಚ್ಛ out;
	ಯದಿ ((ec = EVP_PKEY_get1_EC_ಕೀಲಿ(ಕೀಲಿ->pkey)) == ರಿಕ್ತ) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		ಗಚ್ಛ out;
	}
	ಯದಿ (EC_ಕೀಲಿ_set_private_ಕೀಲಿ(ec, exponent) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		ಗಚ್ಛ out;
	}
	ಯದಿ ((r = sshkey_ec_validate_private(ec)) != 0)
		ಗಚ್ಛ out;
	ಯದಿ (EVP_PKEY_set1_EC_ಕೀಲಿ(ಕೀಲಿ->pkey, ec) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		ಗಚ್ಛ out;
	}
	/* success */
	r = 0;
 out:
	BN_clear_free(exponent);
	EC_ಕೀಲಿ_free(ec);
	ಪ್ರತ್ಯಾಗಮ r;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
ssh_ecdsa_sign(ಸಂರಚನಾ sshkey *ಕೀಲಿ,
    u_char **sigp, size_t *lenp,
    ಧ್ರುವ u_char *data, size_t dlen,
    ಧ್ರುವ ವರ್ಣ *alg, ಧ್ರುವ ವರ್ಣ *sk_provider, ಧ್ರುವ ವರ್ಣ *sk_pin, u_int compat)
{
	ECDSA_SIG *esig = ರಿಕ್ತ;
	unsigned ವರ್ಣ *sigb = ರಿಕ್ತ;
	ಧ್ರುವ unsigned ವರ್ಣ *psig;
	ಧ್ರುವ BIGNUM *sig_r, *sig_s;
	ಪೂರ್ಣಾಙ್ಕ hash_alg;
	size_t slen = 0;
	ಪೂರ್ಣಾಙ್ಕ ret = SSH_ERR_INTERNAL_ERROR;

	ಯದಿ (lenp != ರಿಕ್ತ)
		*lenp = 0;
	ಯದಿ (sigp != ರಿಕ್ತ)
		*sigp = ರಿಕ್ತ;

	ಯದಿ (ಕೀಲಿ == ರಿಕ್ತ || ಕೀಲಿ->pkey == ರಿಕ್ತ ||
	    sshkey_type_plain(ಕೀಲಿ->type) != ಕೀಲಿ_ECDSA)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_ARGUMENT;

	ಯದಿ ((hash_alg = sshkey_ec_nid_to_hash_alg(ಕೀಲಿ->ecdsa_nid)) == -1)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INTERNAL_ERROR;

	ಯದಿ ((ret = sshkey_pkey_digest_sign(ಕೀಲಿ->pkey, hash_alg, &sigb, &slen,
	    data, dlen)) != 0)
		ಗಚ್ಛ out;

	psig = sigb;
	ಯದಿ ((esig = d2i_ECDSA_SIG(ರಿಕ್ತ, &psig, slen)) == ರಿಕ್ತ) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		ಗಚ್ಛ out;
	}
	ECDSA_SIG_get0(esig, &sig_r, &sig_s);

	ಯದಿ ((ret = ssh_ecdsa_encode_store_sig(ಕೀಲಿ, sig_r, sig_s,
	    sigp, lenp)) != 0)
		ಗಚ್ಛ out;
	/* success */
	ret = 0;
 out:
	freezero(sigb, slen);
	ECDSA_SIG_free(esig);
	ಪ್ರತ್ಯಾಗಮ ret;
}

ಪೂರ್ಣಾಙ್ಕ
ssh_ecdsa_encode_store_sig(ಧ್ರುವ ಸಂರಚನಾ sshkey *ಕೀಲಿ,
    ಧ್ರುವ BIGNUM *sig_r, ಧ್ರುವ BIGNUM *sig_s,
    u_char **sigp, size_t *lenp)
{
	ಸಂರಚನಾ sshbuf *b = ರಿಕ್ತ, *bb = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ ret;
	size_t len;

	ಯದಿ (lenp != ರಿಕ್ತ)
		*lenp = 0;
	ಯದಿ (sigp != ರಿಕ್ತ)
		*sigp = ರಿಕ್ತ;

	ಯದಿ ((bb = sshbuf_new()) == ರಿಕ್ತ || (b = sshbuf_new()) == ರಿಕ್ತ) {
		ret = SSH_ERR_ALLOC_FAIL;
		ಗಚ್ಛ out;
	}
	ಯದಿ ((ret = sshbuf_put_bignum2(bb, sig_r)) != 0 ||
	    (ret = sshbuf_put_bignum2(bb, sig_s)) != 0)
		ಗಚ್ಛ out;
	ಯದಿ ((ret = sshbuf_put_cstring(b, sshkey_ssh_name_plain(ಕೀಲಿ))) != 0 ||
	    (ret = sshbuf_put_stringb(b, bb)) != 0)
		ಗಚ್ಛ out;
	len = sshbuf_len(b);
	ಯದಿ (sigp != ರಿಕ್ತ) {
		ಯದಿ ((*sigp = malloc(len)) == ರಿಕ್ತ) {
			ret = SSH_ERR_ALLOC_FAIL;
			ಗಚ್ಛ out;
		}
		memcpy(*sigp, sshbuf_ptr(b), len);
	}
	ಯದಿ (lenp != ರಿಕ್ತ)
		*lenp = len;
	ret = 0;
 out:
	sshbuf_free(b);
	sshbuf_free(bb);
	ಪ್ರತ್ಯಾಗಮ ret;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
ssh_ecdsa_verify(ಧ್ರುವ ಸಂರಚನಾ sshkey *ಕೀಲಿ,
    ಧ್ರುವ u_char *sig, size_t siglen,
    ಧ್ರುವ u_char *data, size_t dlen, ಧ್ರುವ ವರ್ಣ *alg, u_int compat,
    ಸಂರಚನಾ sshkey_sig_details **detailsp)
{
	ECDSA_SIG *esig = ರಿಕ್ತ;
	BIGNUM *sig_r = ರಿಕ್ತ, *sig_s = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ hash_alg, len = 0;
	ಪೂರ್ಣಾಙ್ಕ ret = SSH_ERR_INTERNAL_ERROR;
	ಸಂರಚನಾ sshbuf *b = ರಿಕ್ತ, *sigbuf = ರಿಕ್ತ;
	ವರ್ಣ *ktype = ರಿಕ್ತ;
	unsigned ವರ್ಣ *sigb = ರಿಕ್ತ, *cp;

	ಯದಿ (ಕೀಲಿ == ರಿಕ್ತ || ಕೀಲಿ->pkey == ರಿಕ್ತ ||
	    sshkey_type_plain(ಕೀಲಿ->type) != ಕೀಲಿ_ECDSA ||
	    sig == ರಿಕ್ತ || siglen == 0)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_ARGUMENT;

	ಯದಿ ((hash_alg = sshkey_ec_nid_to_hash_alg(ಕೀಲಿ->ecdsa_nid)) == -1)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INTERNAL_ERROR;

	/* fetch signature */
	ಯದಿ ((b = sshbuf_from(sig, siglen)) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ALLOC_FAIL;
	ಯದಿ (sshbuf_get_cstring(b, &ktype, ರಿಕ್ತ) != 0 ||
	    sshbuf_froms(b, &sigbuf) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		ಗಚ್ಛ out;
	}
	ಯದಿ (strcmp(sshkey_ssh_name_plain(ಕೀಲಿ), ktype) != 0) {
		ret = SSH_ERR_ಕೀಲಿ_TYPE_MISMATCH;
		ಗಚ್ಛ out;
	}
	ಯದಿ (sshbuf_len(b) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		ಗಚ್ಛ out;
	}

	/* parse signature */
	ಯದಿ (sshbuf_get_bignum2(sigbuf, &sig_r) != 0 ||
	    sshbuf_get_bignum2(sigbuf, &sig_s) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		ಗಚ್ಛ out;
	}
	ಯದಿ (sshbuf_len(sigbuf) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		ಗಚ್ಛ out;
	}

	ಯದಿ ((esig = ECDSA_SIG_new()) == ರಿಕ್ತ) {
		ret = SSH_ERR_ALLOC_FAIL;
		ಗಚ್ಛ out;
	}
	ಯದಿ (!ECDSA_SIG_set0(esig, sig_r, sig_s)) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		ಗಚ್ಛ out;
	}
	sig_r = sig_s = ರಿಕ್ತ; /* transferred */

	ಯದಿ ((len = i2d_ECDSA_SIG(esig, ರಿಕ್ತ)) <= 0) {
		len = 0;
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		ಗಚ್ಛ out;
	}
	ಯದಿ ((sigb = calloc(1, len)) == ರಿಕ್ತ) {
		ret = SSH_ERR_ALLOC_FAIL;
		ಗಚ್ಛ out;
	}
	cp = sigb; /* ASN1_item_i2d increments the pointer past the object */
	ಯದಿ (i2d_ECDSA_SIG(esig, &cp) != len) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		ಗಚ್ಛ out;
	}
	ಯದಿ ((ret = sshkey_pkey_digest_verify(ಕೀಲಿ->pkey, hash_alg,
	    data, dlen, sigb, len)) != 0)
		ಗಚ್ಛ out;
	/* success */
 out:
	freezero(sigb, len);
	sshbuf_free(sigbuf);
	sshbuf_free(b);
	ECDSA_SIG_free(esig);
	BN_clear_free(sig_r);
	BN_clear_free(sig_s);
	ಮುಕ್ತ(ktype);
	ಪ್ರತ್ಯಾಗಮ ret;
}

/* NB. not static; used by ECDSA-SK */
ಧ್ರುವ ಸಂರಚನಾ sshkey_impl_funcs sshkey_ecdsa_funcs = {
	/* .size = */		ssh_ecdsa_size,
	/* .alloc = */		ರಿಕ್ತ,
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

ಧ್ರುವ ಸಂರಚನಾ sshkey_impl sshkey_ecdsa_nistp256_impl = {
	/* .name = */		"ecdsa-sha2-nistp256",
	/* .shortname = */	"ECDSA",
	/* .sigalg = */		ರಿಕ್ತ,
	/* .type = */		ಕೀಲಿ_ECDSA,
	/* .nid = */		NID_X9_62_prime256v1,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

ಧ್ರುವ ಸಂರಚನಾ sshkey_impl sshkey_ecdsa_nistp256_cert_impl = {
	/* .name = */		"ecdsa-sha2-nistp256-cert-v01@openssh.com",
	/* .shortname = */	"ECDSA-CERT",
	/* .sigalg = */		ರಿಕ್ತ,
	/* .type = */		ಕೀಲಿ_ECDSA_CERT,
	/* .nid = */		NID_X9_62_prime256v1,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

ಧ್ರುವ ಸಂರಚನಾ sshkey_impl sshkey_ecdsa_nistp384_impl = {
	/* .name = */		"ecdsa-sha2-nistp384",
	/* .shortname = */	"ECDSA",
	/* .sigalg = */		ರಿಕ್ತ,
	/* .type = */		ಕೀಲಿ_ECDSA,
	/* .nid = */		NID_secp384r1,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

ಧ್ರುವ ಸಂರಚನಾ sshkey_impl sshkey_ecdsa_nistp384_cert_impl = {
	/* .name = */		"ecdsa-sha2-nistp384-cert-v01@openssh.com",
	/* .shortname = */	"ECDSA-CERT",
	/* .sigalg = */		ರಿಕ್ತ,
	/* .type = */		ಕೀಲಿ_ECDSA_CERT,
	/* .nid = */		NID_secp384r1,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

ಧ್ರುವ ಸಂರಚನಾ sshkey_impl sshkey_ecdsa_nistp521_impl = {
	/* .name = */		"ecdsa-sha2-nistp521",
	/* .shortname = */	"ECDSA",
	/* .sigalg = */		ರಿಕ್ತ,
	/* .type = */		ಕೀಲಿ_ECDSA,
	/* .nid = */		NID_secp521r1,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

ಧ್ರುವ ಸಂರಚನಾ sshkey_impl sshkey_ecdsa_nistp521_cert_impl = {
	/* .name = */		"ecdsa-sha2-nistp521-cert-v01@openssh.com",
	/* .shortname = */	"ECDSA-CERT",
	/* .sigalg = */		ರಿಕ್ತ,
	/* .type = */		ಕೀಲಿ_ECDSA_CERT,
	/* .nid = */		NID_secp521r1,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

#endif /* WITH_OPENSSL */
