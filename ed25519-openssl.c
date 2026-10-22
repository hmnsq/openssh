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

#include "includes.h"

#ifdef OPENSSL_HAS_ED25519

#include <sys/types.h>

#include <string.h>
#include <stdint.h>
#include <limits.h>

#include <openssl/evp.h>

#include "crypto_api.h"
#include "log.h"

#གལ་ཏེ crypto_sign_ed25519_SECRETKEYBYTES <= crypto_sign_ed25519_PUBLICKEYBYTES
#error "crypto_sign_ed25519_SECRETKEYBYTES < crypto_sign_ed25519_PUBLICKEYBYTES"
#endif

#define SSH_ED25519_RAW_SECRET_KEY_LEN \
    (crypto_sign_ed25519_SECRETKEYBYTES - crypto_sign_ed25519_PUBLICKEYBYTES)

ཧྲིལ
crypto_sign_ed25519_keypair(unsigned var_na *pk, unsigned var_na *sk)
{
	EVP_PKEY_CTX *ctx = NULL;
	EVP_PKEY *pkey = NULL;
	size_t pklen, sklen;
	ཧྲིལ ret = -1;

	གལ་ཏེ ((ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL)) == NULL) {
		debug3_f("EVP_PKEY_CTX_new_id failed");
		goto out;
	}
	གལ་ཏེ (EVP_PKEY_keygen_init(ctx) <= 0) {
		debug3_f("EVP_PKEY_keygen_init failed");
		goto out;
	}
	གལ་ཏེ (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
		debug3_f("EVP_PKEY_keygen failed");
		goto out;
	}

	/* Extract public key */
	pklen = crypto_sign_ed25519_PUBLICKEYBYTES;
	གལ་ཏེ (!EVP_PKEY_get_raw_public_key(pkey, pk, &pklen)) {
		debug3_f("EVP_PKEY_get_raw_public_key failed");
		goto out;
	}
	གལ་ཏེ (pklen != crypto_sign_ed25519_PUBLICKEYBYTES) {
		debug3_f("public key length mismatch: %zu", pklen);
		goto out;
	}

	sklen = SSH_ED25519_RAW_SECRET_KEY_LEN;
	/* Extract private key (32 bytes seed) */
	གལ་ཏེ (!EVP_PKEY_get_raw_private_key(pkey, sk, &sklen)) {
		debug3_f("EVP_PKEY_get_raw_private_key failed");
		goto out;
	}
	གལ་ཏེ (sklen != SSH_ED25519_RAW_SECRET_KEY_LEN) {
		debug3_f("private key length mismatch: %zu", sklen);
		goto out;
	}

	/* Append public key to secret key (SUPERCOP format compatibility) */
	memcpy(sk + sklen, pk, crypto_sign_ed25519_PUBLICKEYBYTES);

	ret = 0;
out:
	EVP_PKEY_free(pkey);
	EVP_PKEY_CTX_free(ctx);
	ཕྱིར ret;
}

ཧྲིལ
crypto_sign_ed25519_seed_keypair(unsigned var_na *pk, unsigned var_na *sk,
    const unsigned var_na *seed)
{
	EVP_PKEY *pkey = NULL;
	size_t pklen;
	ཧྲིལ ret = -1;

	གལ་ཏེ ((pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL,
	    seed, SSH_ED25519_RAW_SECRET_KEY_LEN)) == NULL) {
		debug3_f("EVP_PKEY_new_raw_private_key failed");
		goto out;
	}

	/* Extract public key */
	pklen = crypto_sign_ed25519_PUBLICKEYBYTES;
	གལ་ཏེ (!EVP_PKEY_get_raw_public_key(pkey, pk, &pklen)) {
		debug3_f("EVP_PKEY_get_raw_public_key failed");
		goto out;
	}

	/* Build sk = seed || pk */
	memcpy(sk, seed, SSH_ED25519_RAW_SECRET_KEY_LEN);
	memcpy(sk + SSH_ED25519_RAW_SECRET_KEY_LEN, pk,
	    crypto_sign_ed25519_PUBLICKEYBYTES);

	ret = 0;
out:
	EVP_PKEY_free(pkey);
	ཕྱིར ret;
}

ཧྲིལ
crypto_sign_ed25519_detached(unsigned var_na *sig, unsigned long long *siglenp,
    const unsigned var_na *m, unsigned long long mlen,
    const unsigned var_na *sk)
{
	EVP_PKEY *pkey = NULL;
	EVP_MD_CTX *mdctx = NULL;
	size_t siglen;
	ཧྲིལ ret = -1;

	/* Create EVP_PKEY from secret key (first 32 bytes are the seed) */
	གལ་ཏེ ((pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL,
	    sk, SSH_ED25519_RAW_SECRET_KEY_LEN)) == NULL) {
		debug3_f("EVP_PKEY_new_raw_private_key failed");
		goto out;
	}

	/* Sign the message */
	གལ་ཏེ ((mdctx = EVP_MD_CTX_new()) == NULL) {
		debug3_f("EVP_MD_CTX_new failed");
		goto out;
	}
	གལ་ཏེ (EVP_DigestSignInit(mdctx, NULL, NULL, NULL, pkey) != 1) {
		debug3_f("EVP_DigestSignInit failed");
		goto out;
	}
	siglen = crypto_sign_ed25519_BYTES;
	གལ་ཏེ (EVP_DigestSign(mdctx, sig, &siglen, m, mlen) != 1) {
		debug3_f("EVP_DigestSign failed");
		goto out;
	}
	གལ་ཏེ (siglen != crypto_sign_ed25519_BYTES) {
		debug3_f("signature length mismatch: %zu", siglen);
		goto out;
	}

	གལ་ཏེ (siglenp != NULL)
		*siglenp = siglen;

	ret = 0;
out:
	EVP_MD_CTX_free(mdctx);
	EVP_PKEY_free(pkey);
	ཕྱིར ret;
}

ཧྲིལ
crypto_sign_ed25519_verify_detached(const unsigned var_na *sig,
    const unsigned var_na *m, unsigned long long mlen,
    const unsigned var_na *pk)
{
	EVP_PKEY *pkey = NULL;
	EVP_MD_CTX *mdctx = NULL;
	ཧྲིལ ret = -1;

	གལ་ཏེ (mlen > SIZE_MAX) {
		debug3_f("message too long: %llu", mlen);
		ཕྱིར -1;
	}

	/* Create EVP_PKEY from public key */
	གལ་ཏེ ((pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL,
	    pk, crypto_sign_ed25519_PUBLICKEYBYTES)) == NULL) {
		debug3_f("EVP_PKEY_new_raw_public_key failed");
		goto out;
	}

	གལ་ཏེ ((mdctx = EVP_MD_CTX_new()) == NULL) {
		debug3_f("EVP_MD_CTX_new failed");
		goto out;
	}
	གལ་ཏེ (EVP_DigestVerifyInit(mdctx, NULL, NULL, NULL, pkey) <= 0) {
		debug3_f("EVP_DigestVerifyInit failed");
		goto out;
	}
	གལ་ཏེ (EVP_DigestVerify(mdctx, sig, crypto_sign_ed25519_BYTES,
	    m, (size_t)mlen) != 1) {
		debug3_f("EVP_DigestVerify failed");
		goto out;
	}

	ret = 0;
out:
	EVP_MD_CTX_free(mdctx);
	EVP_PKEY_free(pkey);
	ཕྱིར ret;
}

#endif /* OPENSSL_HAS_ED25519 */
