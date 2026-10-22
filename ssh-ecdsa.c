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

#ಆದರೆ defined(WITH_OPENSSL)
#ಅನ್ತರ್ಭಾವ "openbsd-compat/openssl-compat.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>

#ಅನ್ತರ್ಭಾವ <openssl/bn.h>
#ಅನ್ತರ್ಭಾವ <openssl/ec.h>
#ಅನ್ತರ್ಭಾವ <openssl/ecdsa.h>
#ಅನ್ತರ್ಭಾವ <openssl/evp.h>

#ಅನ್ತರ್ಭಾವ <string.h>

#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "ssherr.h"
#ವ್ಯಾಖ್ಯಾನಿಸು SSHKEY_ಆಂತರಿಕ
#ಅನ್ತರ್ಭಾವ "sshkey.h"

ಪೂರ್ಣಾಂಕ
sshkey_ecdsa_fixup_ಗುಂಪು(EVP_PKEY *k)
{
	ಪೂರ್ಣಾಂಕ nids[] = {
		NID_X9_62_prime256v1,
		NID_secp384r1,
		NID_secp521r1,
		-1
	};
	ಪೂರ್ಣಾಂಕ nid = -1;
	u_int i;
	ಸ್ಥಿರಾಂಕ EC_ಗುಂಪು *g;
	EC_ಕೀಲಿ *ec = ಖಾಲಿ;
	EC_ಗುಂಪು *eg = ಖಾಲಿ;

	ಆದರೆ ((ec = EVP_PKEY_get1_EC_ಕೀಲಿ(k)) == ಖಾಲಿ ||
	    (g = EC_ಕೀಲಿ_get0_ಗುಂಪು(ec)) == ಖಾಲಿ)
		ಹೋಗು ಹೊರಹೋಗು;
	/*
	 * The group may be stored in a ASN.1 encoded private key in one of two
	 * ways: as a "named group", which is reconstituted by ASN.1 object ID
	 * or explicit group parameters encoded into the key blob. Only the
	 * "named group" case sets the group NID for us, but we can figure
	 * it out for the other case by comparing against all the groups that
	 * are supported.
	 */
	ಆದರೆ ((nid = EC_ಗುಂಪು_get_ವಕ್ರ_name(g)) > 0)
		ಹೋಗು ಹೊರಹೋಗು;
	nid = -1;
	ಗಾಗಿ (i = 0; nids[i] != -1; i++) {
		ಆದರೆ ((eg = EC_ಗುಂಪು_new_by_ವಕ್ರ_name(nids[i])) == ಖಾಲಿ)
			ಹೋಗು ಹೊರಹೋಗು;
		ಆದರೆ (EC_ಗುಂಪು_cmp(g, eg, ಖಾಲಿ) == 0)
			ನಿಲ್ಲಿಸು;
		EC_ಗುಂಪು_free(eg);
		eg = ಖಾಲಿ;
	}
	ಆದರೆ (nids[i] == -1)
		ಹೋಗು ಹೊರಹೋಗು;

	/* Use the group with the NID attached */
	EC_ಗುಂಪು_ಗಣ_asn1_flag(eg, OPENSSL_EC_NAMED_ವಕ್ರ);
	ಆದರೆ (EC_ಕೀಲಿ_ಗಣ_ಗುಂಪು(ec, eg) != 1 ||
	    EVP_PKEY_set1_EC_ಕೀಲಿ(k, ec) != 1)
		ಹೋಗು ಹೊರಹೋಗು;
	/* success */
	nid = nids[i];
 ಹೊರಹೋಗು:
	EC_ಕೀಲಿ_free(ec);
	EC_ಗುಂಪು_free(eg);
	ಹಿಂತಿರುಗಿ nid;
}

ಸ್ಥಿರ u_int
ssh_ecdsa_ಗಾತ್ರ(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *ಕೀಲಿ)
{
	ಆಯ್ಕೆ (ಕೀಲಿ->ecdsa_nid) {
	ಸ್ಥಿತಿ NID_X9_62_prime256v1:
		ಹಿಂತಿರುಗಿ 256;
	ಸ್ಥಿತಿ NID_secp384r1:
		ಹಿಂತಿರುಗಿ 384;
	ಸ್ಥಿತಿ NID_secp521r1:
		ಹಿಂತಿರುಗಿ 521;
	ಪೂರ್ವನಿಯೋಜಿತ:
		ಹಿಂತಿರುಗಿ 0;
	}
}

ಸ್ಥಿರ ಶೂನ್ಯ
ssh_ecdsa_cleanup(ರಚನೆ sshkey *k)
{
	EVP_PKEY_free(k->pkey);
	k->pkey = ಖಾಲಿ;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ssh_ecdsa_equal(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *a, ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *b)
{
	ಆದರೆ (a->pkey == ಖಾಲಿ || b->pkey == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ 0;
	ಹಿಂತಿರುಗಿ EVP_PKEY_cmp(a->pkey, b->pkey) == 1;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ssh_ecdsa_serialize_ಬಹಿರಂಗ(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *ಕೀಲಿ, ರಚನೆ sshbuf *b,
    ಎಣಿಕೆ sshkey_serialize_rep opts)
{
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ (ಕೀಲಿ->pkey == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_ವಾದ;
	ಆದರೆ ((r = sshbuf_put_cstring(b,
	    sshkey_ವಕ್ರ_nid_ಗಮ್ಯ_name(ಕೀಲಿ->ecdsa_nid))) != 0 ||
	    (r = sshbuf_put_ec_pkey(b, ಕೀಲಿ->pkey)) != 0)
		ಹಿಂತಿರುಗಿ r;

	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ssh_ecdsa_serialize_ಖಾಸಗಿ(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *ಕೀಲಿ, ರಚನೆ sshbuf *b,
    ಎಣಿಕೆ sshkey_serialize_rep opts)
{
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ (!sshkey_is_cert(ಕೀಲಿ)) {
		ಆದರೆ ((r = ssh_ecdsa_serialize_ಬಹಿರಂಗ(ಕೀಲಿ, b, opts)) != 0)
			ಹಿಂತಿರುಗಿ r;
	}
	ಆದರೆ ((r = sshbuf_put_bignum2(b,
	    EC_ಕೀಲಿ_get0_ಖಾಸಗಿ_ಕೀಲಿ(EVP_PKEY_get0_EC_ಕೀಲಿ(ಕೀಲಿ->pkey)))) != 0)
		ಹಿಂತಿರುಗಿ r;
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ssh_ecdsa_generate(ರಚನೆ sshkey *k, ಪೂರ್ಣಾಂಕ ಬಿಟ್ಟುಗಳು)
{
	EVP_PKEY *res = ಖಾಲಿ;
	EVP_PKEY_CTX *ctx = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ ret = SSH_ERR_ಆಂತರಿಕ_ERROR;

	ಆದರೆ ((k->ecdsa_nid = sshkey_ecdsa_ಬಿಟ್ಟುಗಳು_ಗಮ್ಯ_nid(ಬಿಟ್ಟುಗಳು)) == -1)
		ಹಿಂತಿರುಗಿ SSH_ERR_ಕೀಲಿ_ಉದ್ದಳತೆ;

	ಆದರೆ ((ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, ಖಾಲಿ)) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_ALLOC_FAIL;

	ಆದರೆ (EVP_PKEY_keygen_init(ctx) <= 0 ||
	    EVP_PKEY_CTX_ಗಣ_ec_paramgen_ವಕ್ರ_nid(ctx, k->ecdsa_nid) <= 0 ||
	    EVP_PKEY_keygen(ctx, &res) <= 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	/* success */
	k->pkey = res;
	res = ಖಾಲಿ;
	ret = 0;
 ಹೊರಹೋಗು:
	EVP_PKEY_free(res);
	EVP_PKEY_CTX_free(ctx);
	ಹಿಂತಿರುಗಿ ret;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ssh_ecdsa_copy_ಬಹಿರಂಗ(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *from, ರಚನೆ sshkey *ಗಮ್ಯ)
{
	ಸ್ಥಿರಾಂಕ EC_ಕೀಲಿ *ec_from;
	EC_ಕೀಲಿ *ec_ಗಮ್ಯ = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ ret = SSH_ERR_ಆಂತರಿಕ_ERROR;

	ec_from = EVP_PKEY_get0_EC_ಕೀಲಿ(from->pkey);
	ಆದರೆ (ec_from == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_LIBCRYPTO_ERROR;

	ಗಮ್ಯ->ecdsa_nid = from->ecdsa_nid;
	ಆದರೆ ((ec_ಗಮ್ಯ = EC_ಕೀಲಿ_new_by_ವಕ್ರ_name(from->ecdsa_nid)) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_ALLOC_FAIL;
	ಆದರೆ (EC_ಕೀಲಿ_ಗಣ_ಬಹಿರಂಗ_ಕೀಲಿ(ec_ಗಮ್ಯ,
	    EC_ಕೀಲಿ_get0_ಬಹಿರಂಗ_ಕೀಲಿ(ec_from)) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	EVP_PKEY_free(ಗಮ್ಯ->pkey);
	ಆದರೆ ((ಗಮ್ಯ->pkey = EVP_PKEY_new()) == ಖಾಲಿ) {
		ret = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (EVP_PKEY_set1_EC_ಕೀಲಿ(ಗಮ್ಯ->pkey, ec_ಗಮ್ಯ) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ret = 0;
 ಹೊರಹೋಗು:
	EC_ಕೀಲಿ_free(ec_ಗಮ್ಯ);
	ಹಿಂತಿರುಗಿ ret;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ssh_ecdsa_deserialize_ಬಹಿರಂಗ(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ktype, ರಚನೆ sshbuf *b,
    ರಚನೆ sshkey *ಕೀಲಿ)
{
	ಪೂರ್ಣಾಂಕ r;
	ಅಕ್ಷರ *ವಕ್ರ = ಖಾಲಿ;
	EVP_PKEY *pkey = ಖಾಲಿ;
	EC_ಕೀಲಿ *ec = ಖಾಲಿ;

	ಆದರೆ ((ಕೀಲಿ->ecdsa_nid = sshkey_ecdsa_nid_from_name(ktype)) == -1)
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_ವಾದ;
	ಆದರೆ ((r = sshbuf_get_cstring(b, &ವಕ್ರ, ಖಾಲಿ)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	ಆದರೆ (ಕೀಲಿ->ecdsa_nid != sshkey_ವಕ್ರ_name_ಗಮ್ಯ_nid(ವಕ್ರ)) {
		r = SSH_ERR_EC_ವಕ್ರ_MISMATCH;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((ec = EC_ಕೀಲಿ_new_by_ವಕ್ರ_name(ಕೀಲಿ->ecdsa_nid)) == ಖಾಲಿ) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((r = sshbuf_get_eckey(b, ec)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	ಆದರೆ (sshkey_ec_validate_ಬಹಿರಂಗ(EC_ಕೀಲಿ_get0_ಗುಂಪು(ec),
	    EC_ಕೀಲಿ_get0_ಬಹಿರಂಗ_ಕೀಲಿ(ec)) != 0) {
		r = SSH_ERR_ಕೀಲಿ_INVALID_EC_ಮೌಲ್ಯ;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((pkey = EVP_PKEY_new()) == ಖಾಲಿ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (EVP_PKEY_set1_EC_ಕೀಲಿ(pkey, ec) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	EVP_PKEY_free(ಕೀಲಿ->pkey);
	ಕೀಲಿ->pkey = pkey;
	pkey = ಖಾಲಿ;
	/* success */
	r = 0;
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ DEBUG_PK
	sshkey_dump_ec_ಬಿಂದು(
	    EC_ಕೀಲಿ_get0_ಗುಂಪು(EVP_PKEY_get0_EC_ಕೀಲಿ(ಕೀಲಿ->pkey)),
	    EC_ಕೀಲಿ_get0_ಬಹಿರಂಗ_ಕೀಲಿ(EVP_PKEY_get0_EC_ಕೀಲಿ(ಕೀಲಿ->pkey)));
#ಆದರೆ_ಅಂತ್ಯ
 ಹೊರಹೋಗು:
	EC_ಕೀಲಿ_free(ec);
	EVP_PKEY_free(pkey);
	ಬಿಡುಗಡೆ(ವಕ್ರ);
	ಹಿಂತಿರುಗಿ r;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ssh_ecdsa_deserialize_ಖಾಸಗಿ(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ktype, ರಚನೆ sshbuf *b,
    ರಚನೆ sshkey *ಕೀಲಿ)
{
	ಪೂರ್ಣಾಂಕ r;
	BIGNUM *exponent = ಖಾಲಿ;
	EC_ಕೀಲಿ *ec = ಖಾಲಿ;

	ಆದರೆ (!sshkey_is_cert(ಕೀಲಿ)) {
		ಆದರೆ ((r = ssh_ecdsa_deserialize_ಬಹಿರಂಗ(ktype, b, ಕೀಲಿ)) != 0)
			ಹಿಂತಿರುಗಿ r;
	}
	ಆದರೆ ((r = sshbuf_get_bignum2(b, &exponent)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	ಆದರೆ ((ec = EVP_PKEY_get1_EC_ಕೀಲಿ(ಕೀಲಿ->pkey)) == ಖಾಲಿ) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (EC_ಕೀಲಿ_ಗಣ_ಖಾಸಗಿ_ಕೀಲಿ(ec, exponent) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((r = sshkey_ec_validate_ಖಾಸಗಿ(ec)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	ಆದರೆ (EVP_PKEY_set1_EC_ಕೀಲಿ(ಕೀಲಿ->pkey, ec) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	/* success */
	r = 0;
 ಹೊರಹೋಗು:
	BN_clear_free(exponent);
	EC_ಕೀಲಿ_free(ec);
	ಹಿಂತಿರುಗಿ r;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ssh_ecdsa_sign(ರಚನೆ sshkey *ಕೀಲಿ,
    u_char **sigp, ಗಾತ್ರ_t *lenp,
    ಸ್ಥಿರಾಂಕ u_char *ದತ್ತಾಂಶ, ಗಾತ್ರ_t dlen,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *alg, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *sk_provider, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *sk_pin, u_int compat)
{
	ECDSA_SIG *esig = ಖಾಲಿ;
	ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *sigb = ಖಾಲಿ;
	ಸ್ಥಿರಾಂಕ ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *psig;
	ಸ್ಥಿರಾಂಕ BIGNUM *sig_r, *sig_s;
	ಪೂರ್ಣಾಂಕ hash_alg;
	ಗಾತ್ರ_t slen = 0;
	ಪೂರ್ಣಾಂಕ ret = SSH_ERR_ಆಂತರಿಕ_ERROR;

	ಆದರೆ (lenp != ಖಾಲಿ)
		*lenp = 0;
	ಆದರೆ (sigp != ಖಾಲಿ)
		*sigp = ಖಾಲಿ;

	ಆದರೆ (ಕೀಲಿ == ಖಾಲಿ || ಕೀಲಿ->pkey == ಖಾಲಿ ||
	    sshkey_type_plain(ಕೀಲಿ->type) != ಕೀಲಿ_ECDSA)
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_ವಾದ;

	ಆದರೆ ((hash_alg = sshkey_ec_nid_ಗಮ್ಯ_hash_alg(ಕೀಲಿ->ecdsa_nid)) == -1)
		ಹಿಂತಿರುಗಿ SSH_ERR_ಆಂತರಿಕ_ERROR;

	ಆದರೆ ((ret = sshkey_pkey_digest_sign(ಕೀಲಿ->pkey, hash_alg, &sigb, &slen,
	    ದತ್ತಾಂಶ, dlen)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;

	psig = sigb;
	ಆದರೆ ((esig = d2i_ECDSA_SIG(ಖಾಲಿ, &psig, slen)) == ಖಾಲಿ) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ECDSA_SIG_get0(esig, &sig_r, &sig_s);

	ಆದರೆ ((ret = ssh_ecdsa_encode_store_sig(ಕೀಲಿ, sig_r, sig_s,
	    sigp, lenp)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	/* success */
	ret = 0;
 ಹೊರಹೋಗು:
	freezero(sigb, slen);
	ECDSA_SIG_free(esig);
	ಹಿಂತಿರುಗಿ ret;
}

ಪೂರ್ಣಾಂಕ
ssh_ecdsa_encode_store_sig(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *ಕೀಲಿ,
    ಸ್ಥಿರಾಂಕ BIGNUM *sig_r, ಸ್ಥಿರಾಂಕ BIGNUM *sig_s,
    u_char **sigp, ಗಾತ್ರ_t *lenp)
{
	ರಚನೆ sshbuf *b = ಖಾಲಿ, *bb = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ ret;
	ಗಾತ್ರ_t len;

	ಆದರೆ (lenp != ಖಾಲಿ)
		*lenp = 0;
	ಆದರೆ (sigp != ಖಾಲಿ)
		*sigp = ಖಾಲಿ;

	ಆದರೆ ((bb = sshbuf_new()) == ಖಾಲಿ || (b = sshbuf_new()) == ಖಾಲಿ) {
		ret = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((ret = sshbuf_put_bignum2(bb, sig_r)) != 0 ||
	    (ret = sshbuf_put_bignum2(bb, sig_s)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	ಆದರೆ ((ret = sshbuf_put_cstring(b, sshkey_ssh_name_plain(ಕೀಲಿ))) != 0 ||
	    (ret = sshbuf_put_stringb(b, bb)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	len = sshbuf_len(b);
	ಆದರೆ (sigp != ಖಾಲಿ) {
		ಆದರೆ ((*sigp = ಸ್ಮರಣೆ_ಕೊಡು(len)) == ಖಾಲಿ) {
			ret = SSH_ERR_ALLOC_FAIL;
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಸ್ಮರಣೆ_ನಕಲು(*sigp, sshbuf_ptr(b), len);
	}
	ಆದರೆ (lenp != ಖಾಲಿ)
		*lenp = len;
	ret = 0;
 ಹೊರಹೋಗು:
	sshbuf_free(b);
	sshbuf_free(bb);
	ಹಿಂತಿರುಗಿ ret;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ssh_ecdsa_verify(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *ಕೀಲಿ,
    ಸ್ಥಿರಾಂಕ u_char *sig, ಗಾತ್ರ_t siglen,
    ಸ್ಥಿರಾಂಕ u_char *ದತ್ತಾಂಶ, ಗಾತ್ರ_t dlen, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *alg, u_int compat,
    ರಚನೆ sshkey_sig_details **detailsp)
{
	ECDSA_SIG *esig = ಖಾಲಿ;
	BIGNUM *sig_r = ಖಾಲಿ, *sig_s = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ hash_alg, len = 0;
	ಪೂರ್ಣಾಂಕ ret = SSH_ERR_ಆಂತರಿಕ_ERROR;
	ರಚನೆ sshbuf *b = ಖಾಲಿ, *sigbuf = ಖಾಲಿ;
	ಅಕ್ಷರ *ktype = ಖಾಲಿ;
	ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *sigb = ಖಾಲಿ, *cp;

	ಆದರೆ (ಕೀಲಿ == ಖಾಲಿ || ಕೀಲಿ->pkey == ಖಾಲಿ ||
	    sshkey_type_plain(ಕೀಲಿ->type) != ಕೀಲಿ_ECDSA ||
	    sig == ಖಾಲಿ || siglen == 0)
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_ವಾದ;

	ಆದರೆ ((hash_alg = sshkey_ec_nid_ಗಮ್ಯ_hash_alg(ಕೀಲಿ->ecdsa_nid)) == -1)
		ಹಿಂತಿರುಗಿ SSH_ERR_ಆಂತರಿಕ_ERROR;

	/* fetch signature */
	ಆದರೆ ((b = sshbuf_from(sig, siglen)) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_ALLOC_FAIL;
	ಆದರೆ (sshbuf_get_cstring(b, &ktype, ಖಾಲಿ) != 0 ||
	    sshbuf_froms(b, &sigbuf) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (strcmp(sshkey_ssh_name_plain(ಕೀಲಿ), ktype) != 0) {
		ret = SSH_ERR_ಕೀಲಿ_TYPE_MISMATCH;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (sshbuf_len(b) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_ದತ್ತಾಂಶ;
		ಹೋಗು ಹೊರಹೋಗು;
	}

	/* parse signature */
	ಆದರೆ (sshbuf_get_bignum2(sigbuf, &sig_r) != 0 ||
	    sshbuf_get_bignum2(sigbuf, &sig_s) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (sshbuf_len(sigbuf) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_ದತ್ತಾಂಶ;
		ಹೋಗು ಹೊರಹೋಗು;
	}

	ಆದರೆ ((esig = ECDSA_SIG_new()) == ಖಾಲಿ) {
		ret = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (!ECDSA_SIG_set0(esig, sig_r, sig_s)) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	sig_r = sig_s = ಖಾಲಿ; /* transferred */

	ಆದರೆ ((len = i2d_ECDSA_SIG(esig, ಖಾಲಿ)) <= 0) {
		len = 0;
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((sigb = ಸೊನ್ನೆ_ಸ್ಮರಣೆ_ಕೊಡು(1, len)) == ಖಾಲಿ) {
		ret = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	cp = sigb; /* ASN1_item_i2d increments the pointer past the object */
	ಆದರೆ (i2d_ECDSA_SIG(esig, &cp) != len) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((ret = sshkey_pkey_digest_verify(ಕೀಲಿ->pkey, hash_alg,
	    ದತ್ತಾಂಶ, dlen, sigb, len)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	/* success */
 ಹೊರಹೋಗು:
	freezero(sigb, len);
	sshbuf_free(sigbuf);
	sshbuf_free(b);
	ECDSA_SIG_free(esig);
	BN_clear_free(sig_r);
	BN_clear_free(sig_s);
	ಬಿಡುಗಡೆ(ktype);
	ಹಿಂತಿರುಗಿ ret;
}

/* NB. not static; used by ECDSA-SK */
ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey_impl_funcs sshkey_ecdsa_funcs = {
	/* .size = */		ssh_ecdsa_ಗಾತ್ರ,
	/* .alloc = */		ಖಾಲಿ,
	/* .cleanup = */	ssh_ecdsa_cleanup,
	/* .equal = */		ssh_ecdsa_equal,
	/* .ssh_serialize_public = */ ssh_ecdsa_serialize_ಬಹಿರಂಗ,
	/* .ssh_deserialize_public = */ ssh_ecdsa_deserialize_ಬಹಿರಂಗ,
	/* .ssh_serialize_private = */ ssh_ecdsa_serialize_ಖಾಸಗಿ,
	/* .ssh_deserialize_private = */ ssh_ecdsa_deserialize_ಖಾಸಗಿ,
	/* .generate = */	ssh_ecdsa_generate,
	/* .copy_public = */	ssh_ecdsa_copy_ಬಹಿರಂಗ,
	/* .sign = */		ssh_ecdsa_sign,
	/* .verify = */		ssh_ecdsa_verify,
};

ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey_impl sshkey_ecdsa_nistp256_impl = {
	/* .name = */		"ecdsa-sha2-nistp256",
	/* .shortname = */	"ECDSA",
	/* .sigalg = */		ಖಾಲಿ,
	/* .type = */		ಕೀಲಿ_ECDSA,
	/* .nid = */		NID_X9_62_prime256v1,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey_impl sshkey_ecdsa_nistp256_cert_impl = {
	/* .name = */		"ecdsa-sha2-nistp256-cert-v01@openssh.com",
	/* .shortname = */	"ECDSA-CERT",
	/* .sigalg = */		ಖಾಲಿ,
	/* .type = */		ಕೀಲಿ_ECDSA_CERT,
	/* .nid = */		NID_X9_62_prime256v1,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey_impl sshkey_ecdsa_nistp384_impl = {
	/* .name = */		"ecdsa-sha2-nistp384",
	/* .shortname = */	"ECDSA",
	/* .sigalg = */		ಖಾಲಿ,
	/* .type = */		ಕೀಲಿ_ECDSA,
	/* .nid = */		NID_secp384r1,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey_impl sshkey_ecdsa_nistp384_cert_impl = {
	/* .name = */		"ecdsa-sha2-nistp384-cert-v01@openssh.com",
	/* .shortname = */	"ECDSA-CERT",
	/* .sigalg = */		ಖಾಲಿ,
	/* .type = */		ಕೀಲಿ_ECDSA_CERT,
	/* .nid = */		NID_secp384r1,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey_impl sshkey_ecdsa_nistp521_impl = {
	/* .name = */		"ecdsa-sha2-nistp521",
	/* .shortname = */	"ECDSA",
	/* .sigalg = */		ಖಾಲಿ,
	/* .type = */		ಕೀಲಿ_ECDSA,
	/* .nid = */		NID_secp521r1,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey_impl sshkey_ecdsa_nistp521_cert_impl = {
	/* .name = */		"ecdsa-sha2-nistp521-cert-v01@openssh.com",
	/* .shortname = */	"ECDSA-CERT",
	/* .sigalg = */		ಖಾಲಿ,
	/* .type = */		ಕೀಲಿ_ECDSA_CERT,
	/* .nid = */		NID_secp521r1,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

#ಆದರೆ_ಅಂತ್ಯ /* WITH_OPENSSL */
