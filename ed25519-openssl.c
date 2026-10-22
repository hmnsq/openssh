/* $OpenBSD: ed25519-openssl.c,v 1.4 2026/09/16 00:43:00 djm Exp $ */
/*
 * Copyright (c) 2025 OpenSSH
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * OpenSSL-based implementation of the Ed25519 crypto_sign API.
 * Alternative to the internal libsodium-based implementation in ed25519.c.
 */

#ಅನ್ತರ್ಭಾವ "includes.h"

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ OPENSSL_HAS_ED25519

#ಅನ್ತರ್ಭಾವ <sys/types.h>

#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <stdint.h>
#ಅನ್ತರ್ಭಾವ <limits.h>

#ಅನ್ತರ್ಭಾವ <openssl/evp.h>

#ಅನ್ತರ್ಭಾವ "crypto_api.h"
#ಅನ್ತರ್ಭಾವ "log.h"

#ಆದರೆ crypto_sign_ed25519_SECRETKEYBYTES <= crypto_sign_ed25519_PUBLICKEYBYTES
#ದೋಷ "crypto_sign_ed25519_SECRETKEYBYTES < crypto_sign_ed25519_PUBLICKEYBYTES"
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿಸು SSH_ED25519_RAW_SECRET_ಕೀಲಿ_LEN \
    (crypto_sign_ed25519_SECRETKEYBYTES - crypto_sign_ed25519_PUBLICKEYBYTES)

ಪೂರ್ಣಾಂಕ
crypto_sign_ed25519_keypair(ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *pk, ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *sk)
{
	EVP_PKEY_CTX *ctx = ಖಾಲಿ;
	EVP_PKEY *pkey = ಖಾಲಿ;
	ಗಾತ್ರ_t pklen, sklen;
	ಪೂರ್ಣಾಂಕ ret = -1;

	ಆದರೆ ((ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, ಖಾಲಿ)) == ಖಾಲಿ) {
		debug3_f("EVP_PKEY_CTX_new_id failed");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (EVP_PKEY_keygen_init(ctx) <= 0) {
		debug3_f("EVP_PKEY_keygen_init failed");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
		debug3_f("EVP_PKEY_keygen failed");
		ಹೋಗು ಹೊರಹೋಗು;
	}

	/* Extract public key */
	pklen = crypto_sign_ed25519_PUBLICKEYBYTES;
	ಆದರೆ (!EVP_PKEY_get_raw_ಬಹಿರಂಗ_ಕೀಲಿ(pkey, pk, &pklen)) {
		debug3_f("EVP_PKEY_get_raw_public_key failed");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (pklen != crypto_sign_ed25519_PUBLICKEYBYTES) {
		debug3_f("public key length mismatch: %zu", pklen);
		ಹೋಗು ಹೊರಹೋಗು;
	}

	sklen = SSH_ED25519_RAW_SECRET_ಕೀಲಿ_LEN;
	/* Extract private key (32 bytes seed) */
	ಆದರೆ (!EVP_PKEY_get_raw_ಖಾಸಗಿ_ಕೀಲಿ(pkey, sk, &sklen)) {
		debug3_f("EVP_PKEY_get_raw_private_key failed");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (sklen != SSH_ED25519_RAW_SECRET_ಕೀಲಿ_LEN) {
		debug3_f("private key length mismatch: %zu", sklen);
		ಹೋಗು ಹೊರಹೋಗು;
	}

	/* Append public key to secret key (SUPERCOP format compatibility) */
	ಸ್ಮರಣೆ_ನಕಲು(sk + sklen, pk, crypto_sign_ed25519_PUBLICKEYBYTES);

	ret = 0;
ಹೊರಹೋಗು:
	EVP_PKEY_free(pkey);
	EVP_PKEY_CTX_free(ctx);
	ಹಿಂತಿರುಗಿ ret;
}

ಪೂರ್ಣಾಂಕ
crypto_sign_ed25519_ಬೀಜ_keypair(ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *pk, ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *sk,
    ಸ್ಥಿರಾಂಕ ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *ಬೀಜ)
{
	EVP_PKEY *pkey = ಖಾಲಿ;
	ಗಾತ್ರ_t pklen;
	ಪೂರ್ಣಾಂಕ ret = -1;

	ಆದರೆ ((pkey = EVP_PKEY_new_raw_ಖಾಸಗಿ_ಕೀಲಿ(EVP_PKEY_ED25519, ಖಾಲಿ,
	    ಬೀಜ, SSH_ED25519_RAW_SECRET_ಕೀಲಿ_LEN)) == ಖಾಲಿ) {
		debug3_f("EVP_PKEY_new_raw_private_key failed");
		ಹೋಗು ಹೊರಹೋಗು;
	}

	/* Extract public key */
	pklen = crypto_sign_ed25519_PUBLICKEYBYTES;
	ಆದರೆ (!EVP_PKEY_get_raw_ಬಹಿರಂಗ_ಕೀಲಿ(pkey, pk, &pklen)) {
		debug3_f("EVP_PKEY_get_raw_public_key failed");
		ಹೋಗು ಹೊರಹೋಗು;
	}

	/* Build sk = seed || pk */
	ಸ್ಮರಣೆ_ನಕಲು(sk, ಬೀಜ, SSH_ED25519_RAW_SECRET_ಕೀಲಿ_LEN);
	ಸ್ಮರಣೆ_ನಕಲು(sk + SSH_ED25519_RAW_SECRET_ಕೀಲಿ_LEN, pk,
	    crypto_sign_ed25519_PUBLICKEYBYTES);

	ret = 0;
ಹೊರಹೋಗು:
	EVP_PKEY_free(pkey);
	ಹಿಂತಿರುಗಿ ret;
}

ಪೂರ್ಣಾಂಕ
crypto_sign_ed25519_detached(ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *sig, ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ *siglenp,
    ಸ್ಥಿರಾಂಕ ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *m, ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ mlen,
    ಸ್ಥಿರಾಂಕ ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *sk)
{
	EVP_PKEY *pkey = ಖಾಲಿ;
	EVP_MD_CTX *mdctx = ಖಾಲಿ;
	ಗಾತ್ರ_t siglen;
	ಪೂರ್ಣಾಂಕ ret = -1;

	/* Create EVP_PKEY from secret key (first 32 bytes are the seed) */
	ಆದರೆ ((pkey = EVP_PKEY_new_raw_ಖಾಸಗಿ_ಕೀಲಿ(EVP_PKEY_ED25519, ಖಾಲಿ,
	    sk, SSH_ED25519_RAW_SECRET_ಕೀಲಿ_LEN)) == ಖಾಲಿ) {
		debug3_f("EVP_PKEY_new_raw_private_key failed");
		ಹೋಗು ಹೊರಹೋಗು;
	}

	/* Sign the message */
	ಆದರೆ ((mdctx = EVP_MD_CTX_new()) == ಖಾಲಿ) {
		debug3_f("EVP_MD_CTX_new failed");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (EVP_DigestSignInit(mdctx, ಖಾಲಿ, ಖಾಲಿ, ಖಾಲಿ, pkey) != 1) {
		debug3_f("EVP_DigestSignInit failed");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	siglen = crypto_sign_ed25519_ಬೈಟುಗಳು;
	ಆದರೆ (EVP_DigestSign(mdctx, sig, &siglen, m, mlen) != 1) {
		debug3_f("EVP_DigestSign failed");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (siglen != crypto_sign_ed25519_ಬೈಟುಗಳು) {
		debug3_f("signature length mismatch: %zu", siglen);
		ಹೋಗು ಹೊರಹೋಗು;
	}

	ಆದರೆ (siglenp != ಖಾಲಿ)
		*siglenp = siglen;

	ret = 0;
ಹೊರಹೋಗು:
	EVP_MD_CTX_free(mdctx);
	EVP_PKEY_free(pkey);
	ಹಿಂತಿರುಗಿ ret;
}

ಪೂರ್ಣಾಂಕ
crypto_sign_ed25519_verify_detached(ಸ್ಥಿರಾಂಕ ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *sig,
    ಸ್ಥಿರಾಂಕ ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *m, ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ mlen,
    ಸ್ಥಿರಾಂಕ ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *pk)
{
	EVP_PKEY *pkey = ಖಾಲಿ;
	EVP_MD_CTX *mdctx = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ ret = -1;

	ಆದರೆ (mlen > SIZE_MAX) {
		debug3_f("message too long: %llu", mlen);
		ಹಿಂತಿರುಗಿ -1;
	}

	/* Create EVP_PKEY from public key */
	ಆದರೆ ((pkey = EVP_PKEY_new_raw_ಬಹಿರಂಗ_ಕೀಲಿ(EVP_PKEY_ED25519, ಖಾಲಿ,
	    pk, crypto_sign_ed25519_PUBLICKEYBYTES)) == ಖಾಲಿ) {
		debug3_f("EVP_PKEY_new_raw_public_key failed");
		ಹೋಗು ಹೊರಹೋಗು;
	}

	ಆದರೆ ((mdctx = EVP_MD_CTX_new()) == ಖಾಲಿ) {
		debug3_f("EVP_MD_CTX_new failed");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (EVP_DigestVerifyInit(mdctx, ಖಾಲಿ, ಖಾಲಿ, ಖಾಲಿ, pkey) <= 0) {
		debug3_f("EVP_DigestVerifyInit failed");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (EVP_DigestVerify(mdctx, sig, crypto_sign_ed25519_ಬೈಟುಗಳು,
	    m, (ಗಾತ್ರ_t)mlen) != 1) {
		debug3_f("EVP_DigestVerify failed");
		ಹೋಗು ಹೊರಹೋಗು;
	}

	ret = 0;
ಹೊರಹೋಗು:
	EVP_MD_CTX_free(mdctx);
	EVP_PKEY_free(pkey);
	ಹಿಂತಿರುಗಿ ret;
}

#ಆದರೆ_ಅಂತ್ಯ /* OPENSSL_HAS_ED25519 */
