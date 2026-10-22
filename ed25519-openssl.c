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

#ifdef OPENSSL_HAS_ED25519

#ಅನ್ತರ್ಭಾವ <sys/types.h>

#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <stdint.h>
#ಅನ್ತರ್ಭಾವ <limits.h>

#ಅನ್ತರ್ಭಾವ <openssl/evp.h>

#ಅನ್ತರ್ಭಾವ "crypto_api.h"
#ಅನ್ತರ್ಭಾವ "log.h"

#ಯದಿ crypto_sign_ed25519_SECRETKEYBYTES <= crypto_sign_ed25519_PUBLICKEYBYTES
#error "crypto_sign_ed25519_SECRETKEYBYTES < crypto_sign_ed25519_PUBLICKEYBYTES"
#endif

#define SSH_ED25519_RAW_SECRET_ಕೀಲಿ_LEN \
    (crypto_sign_ed25519_SECRETKEYBYTES - crypto_sign_ed25519_PUBLICKEYBYTES)

ಪೂರ್ಣಾಙ್ಕ
crypto_sign_ed25519_keypair(unsigned ವರ್ಣ *pk, unsigned ವರ್ಣ *sk)
{
	EVP_PKEY_CTX *ctx = ರಿಕ್ತ;
	EVP_PKEY *pkey = ರಿಕ್ತ;
	size_t pklen, sklen;
	ಪೂರ್ಣಾಙ್ಕ ret = -1;

	ಯದಿ ((ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, ರಿಕ್ತ)) == ರಿಕ್ತ) {
		debug3_f("EVP_PKEY_CTX_new_id failed");
		ಗಚ್ಛ out;
	}
	ಯದಿ (EVP_PKEY_keygen_init(ctx) <= 0) {
		debug3_f("EVP_PKEY_keygen_init failed");
		ಗಚ್ಛ out;
	}
	ಯದಿ (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
		debug3_f("EVP_PKEY_keygen failed");
		ಗಚ್ಛ out;
	}

	/* Extract public key */
	pklen = crypto_sign_ed25519_PUBLICKEYBYTES;
	ಯದಿ (!EVP_PKEY_get_raw_public_ಕೀಲಿ(pkey, pk, &pklen)) {
		debug3_f("EVP_PKEY_get_raw_public_key failed");
		ಗಚ್ಛ out;
	}
	ಯದಿ (pklen != crypto_sign_ed25519_PUBLICKEYBYTES) {
		debug3_f("public key length mismatch: %zu", pklen);
		ಗಚ್ಛ out;
	}

	sklen = SSH_ED25519_RAW_SECRET_ಕೀಲಿ_LEN;
	/* Extract private key (32 bytes seed) */
	ಯದಿ (!EVP_PKEY_get_raw_private_ಕೀಲಿ(pkey, sk, &sklen)) {
		debug3_f("EVP_PKEY_get_raw_private_key failed");
		ಗಚ್ಛ out;
	}
	ಯದಿ (sklen != SSH_ED25519_RAW_SECRET_ಕೀಲಿ_LEN) {
		debug3_f("private key length mismatch: %zu", sklen);
		ಗಚ್ಛ out;
	}

	/* Append public key to secret key (SUPERCOP format compatibility) */
	memcpy(sk + sklen, pk, crypto_sign_ed25519_PUBLICKEYBYTES);

	ret = 0;
out:
	EVP_PKEY_free(pkey);
	EVP_PKEY_CTX_free(ctx);
	ಪ್ರತ್ಯಾಗಮ ret;
}

ಪೂರ್ಣಾಙ್ಕ
crypto_sign_ed25519_seed_keypair(unsigned ವರ್ಣ *pk, unsigned ವರ್ಣ *sk,
    ಧ್ರುವ unsigned ವರ್ಣ *seed)
{
	EVP_PKEY *pkey = ರಿಕ್ತ;
	size_t pklen;
	ಪೂರ್ಣಾಙ್ಕ ret = -1;

	ಯದಿ ((pkey = EVP_PKEY_new_raw_private_ಕೀಲಿ(EVP_PKEY_ED25519, ರಿಕ್ತ,
	    seed, SSH_ED25519_RAW_SECRET_ಕೀಲಿ_LEN)) == ರಿಕ್ತ) {
		debug3_f("EVP_PKEY_new_raw_private_key failed");
		ಗಚ್ಛ out;
	}

	/* Extract public key */
	pklen = crypto_sign_ed25519_PUBLICKEYBYTES;
	ಯದಿ (!EVP_PKEY_get_raw_public_ಕೀಲಿ(pkey, pk, &pklen)) {
		debug3_f("EVP_PKEY_get_raw_public_key failed");
		ಗಚ್ಛ out;
	}

	/* Build sk = seed || pk */
	memcpy(sk, seed, SSH_ED25519_RAW_SECRET_ಕೀಲಿ_LEN);
	memcpy(sk + SSH_ED25519_RAW_SECRET_ಕೀಲಿ_LEN, pk,
	    crypto_sign_ed25519_PUBLICKEYBYTES);

	ret = 0;
out:
	EVP_PKEY_free(pkey);
	ಪ್ರತ್ಯಾಗಮ ret;
}

ಪೂರ್ಣಾಙ್ಕ
crypto_sign_ed25519_detached(unsigned ವರ್ಣ *sig, unsigned long long *siglenp,
    ಧ್ರುವ unsigned ವರ್ಣ *m, unsigned long long mlen,
    ಧ್ರುವ unsigned ವರ್ಣ *sk)
{
	EVP_PKEY *pkey = ರಿಕ್ತ;
	EVP_MD_CTX *mdctx = ರಿಕ್ತ;
	size_t siglen;
	ಪೂರ್ಣಾಙ್ಕ ret = -1;

	/* Create EVP_PKEY from secret key (first 32 bytes are the seed) */
	ಯದಿ ((pkey = EVP_PKEY_new_raw_private_ಕೀಲಿ(EVP_PKEY_ED25519, ರಿಕ್ತ,
	    sk, SSH_ED25519_RAW_SECRET_ಕೀಲಿ_LEN)) == ರಿಕ್ತ) {
		debug3_f("EVP_PKEY_new_raw_private_key failed");
		ಗಚ್ಛ out;
	}

	/* Sign the message */
	ಯದಿ ((mdctx = EVP_MD_CTX_new()) == ರಿಕ್ತ) {
		debug3_f("EVP_MD_CTX_new failed");
		ಗಚ್ಛ out;
	}
	ಯದಿ (EVP_DigestSignInit(mdctx, ರಿಕ್ತ, ರಿಕ್ತ, ರಿಕ್ತ, pkey) != 1) {
		debug3_f("EVP_DigestSignInit failed");
		ಗಚ್ಛ out;
	}
	siglen = crypto_sign_ed25519_BYTES;
	ಯದಿ (EVP_DigestSign(mdctx, sig, &siglen, m, mlen) != 1) {
		debug3_f("EVP_DigestSign failed");
		ಗಚ್ಛ out;
	}
	ಯದಿ (siglen != crypto_sign_ed25519_BYTES) {
		debug3_f("signature length mismatch: %zu", siglen);
		ಗಚ್ಛ out;
	}

	ಯದಿ (siglenp != ರಿಕ್ತ)
		*siglenp = siglen;

	ret = 0;
out:
	EVP_MD_CTX_free(mdctx);
	EVP_PKEY_free(pkey);
	ಪ್ರತ್ಯಾಗಮ ret;
}

ಪೂರ್ಣಾಙ್ಕ
crypto_sign_ed25519_verify_detached(ಧ್ರುವ unsigned ವರ್ಣ *sig,
    ಧ್ರುವ unsigned ವರ್ಣ *m, unsigned long long mlen,
    ಧ್ರುವ unsigned ವರ್ಣ *pk)
{
	EVP_PKEY *pkey = ರಿಕ್ತ;
	EVP_MD_CTX *mdctx = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ ret = -1;

	ಯದಿ (mlen > SIZE_MAX) {
		debug3_f("message too long: %llu", mlen);
		ಪ್ರತ್ಯಾಗಮ -1;
	}

	/* Create EVP_PKEY from public key */
	ಯದಿ ((pkey = EVP_PKEY_new_raw_public_ಕೀಲಿ(EVP_PKEY_ED25519, ರಿಕ್ತ,
	    pk, crypto_sign_ed25519_PUBLICKEYBYTES)) == ರಿಕ್ತ) {
		debug3_f("EVP_PKEY_new_raw_public_key failed");
		ಗಚ್ಛ out;
	}

	ಯದಿ ((mdctx = EVP_MD_CTX_new()) == ರಿಕ್ತ) {
		debug3_f("EVP_MD_CTX_new failed");
		ಗಚ್ಛ out;
	}
	ಯದಿ (EVP_DigestVerifyInit(mdctx, ರಿಕ್ತ, ರಿಕ್ತ, ರಿಕ್ತ, pkey) <= 0) {
		debug3_f("EVP_DigestVerifyInit failed");
		ಗಚ್ಛ out;
	}
	ಯದಿ (EVP_DigestVerify(mdctx, sig, crypto_sign_ed25519_BYTES,
	    m, (size_t)mlen) != 1) {
		debug3_f("EVP_DigestVerify failed");
		ಗಚ್ಛ out;
	}

	ret = 0;
out:
	EVP_MD_CTX_free(mdctx);
	EVP_PKEY_free(pkey);
	ಪ್ರತ್ಯಾಗಮ ret;
}

#endif /* OPENSSL_HAS_ED25519 */
