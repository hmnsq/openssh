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

#அந்தர்பாவ "includes.h"

#ifdef OPENSSL_HAS_ED25519

#அந்தர்பாவ <sys/types.h>

#அந்தர்பாவ <string.h>
#அந்தர்பாவ <stdint.h>
#அந்தர்பாவ <limits.h>

#அந்தர்பாவ <openssl/evp.h>

#அந்தர்பாவ "crypto_api.h"
#அந்தர்பாவ "log.h"

#எனில் crypto_sign_ed25519_SECRETKEYBYTES <= crypto_sign_ed25519_PUBLICKEYBYTES
#error "crypto_sign_ed25519_SECRETKEYBYTES < crypto_sign_ed25519_PUBLICKEYBYTES"
#endif

#define SSH_ED25519_RAW_SECRET_சாவி_LEN \
    (crypto_sign_ed25519_SECRETKEYBYTES - crypto_sign_ed25519_PUBLICKEYBYTES)

முழு
crypto_sign_ed25519_keypair(unsigned எழுத்து *pk, unsigned எழுத்து *sk)
{
	EVP_PKEY_CTX *ctx = வெற்று;
	EVP_PKEY *pkey = வெற்று;
	size_t pklen, sklen;
	முழு ret = -1;

	எனில் ((ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, வெற்று)) == வெற்று) {
		debug3_f("EVP_PKEY_CTX_new_id failed");
		செல் out;
	}
	எனில் (EVP_PKEY_keygen_init(ctx) <= 0) {
		debug3_f("EVP_PKEY_keygen_init failed");
		செல் out;
	}
	எனில் (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
		debug3_f("EVP_PKEY_keygen failed");
		செல் out;
	}

	/* Extract public key */
	pklen = crypto_sign_ed25519_PUBLICKEYBYTES;
	எனில் (!EVP_PKEY_get_raw_public_சாவி(pkey, pk, &pklen)) {
		debug3_f("EVP_PKEY_get_raw_public_key failed");
		செல் out;
	}
	எனில் (pklen != crypto_sign_ed25519_PUBLICKEYBYTES) {
		debug3_f("public key length mismatch: %zu", pklen);
		செல் out;
	}

	sklen = SSH_ED25519_RAW_SECRET_சாவி_LEN;
	/* Extract private key (32 bytes seed) */
	எனில் (!EVP_PKEY_get_raw_private_சாவி(pkey, sk, &sklen)) {
		debug3_f("EVP_PKEY_get_raw_private_key failed");
		செல் out;
	}
	எனில் (sklen != SSH_ED25519_RAW_SECRET_சாவி_LEN) {
		debug3_f("private key length mismatch: %zu", sklen);
		செல் out;
	}

	/* Append public key to secret key (SUPERCOP format compatibility) */
	memcpy(sk + sklen, pk, crypto_sign_ed25519_PUBLICKEYBYTES);

	ret = 0;
out:
	EVP_PKEY_free(pkey);
	EVP_PKEY_CTX_free(ctx);
	திரும்பு ret;
}

முழு
crypto_sign_ed25519_seed_keypair(unsigned எழுத்து *pk, unsigned எழுத்து *sk,
    மாறிலி unsigned எழுத்து *seed)
{
	EVP_PKEY *pkey = வெற்று;
	size_t pklen;
	முழு ret = -1;

	எனில் ((pkey = EVP_PKEY_new_raw_private_சாவி(EVP_PKEY_ED25519, வெற்று,
	    seed, SSH_ED25519_RAW_SECRET_சாவி_LEN)) == வெற்று) {
		debug3_f("EVP_PKEY_new_raw_private_key failed");
		செல் out;
	}

	/* Extract public key */
	pklen = crypto_sign_ed25519_PUBLICKEYBYTES;
	எனில் (!EVP_PKEY_get_raw_public_சாவி(pkey, pk, &pklen)) {
		debug3_f("EVP_PKEY_get_raw_public_key failed");
		செல் out;
	}

	/* Build sk = seed || pk */
	memcpy(sk, seed, SSH_ED25519_RAW_SECRET_சாவி_LEN);
	memcpy(sk + SSH_ED25519_RAW_SECRET_சாவி_LEN, pk,
	    crypto_sign_ed25519_PUBLICKEYBYTES);

	ret = 0;
out:
	EVP_PKEY_free(pkey);
	திரும்பு ret;
}

முழு
crypto_sign_ed25519_detached(unsigned எழுத்து *sig, unsigned long long *siglenp,
    மாறிலி unsigned எழுத்து *m, unsigned long long mlen,
    மாறிலி unsigned எழுத்து *sk)
{
	EVP_PKEY *pkey = வெற்று;
	EVP_MD_CTX *mdctx = வெற்று;
	size_t siglen;
	முழு ret = -1;

	/* Create EVP_PKEY from secret key (first 32 bytes are the seed) */
	எனில் ((pkey = EVP_PKEY_new_raw_private_சாவி(EVP_PKEY_ED25519, வெற்று,
	    sk, SSH_ED25519_RAW_SECRET_சாவி_LEN)) == வெற்று) {
		debug3_f("EVP_PKEY_new_raw_private_key failed");
		செல் out;
	}

	/* Sign the message */
	எனில் ((mdctx = EVP_MD_CTX_new()) == வெற்று) {
		debug3_f("EVP_MD_CTX_new failed");
		செல் out;
	}
	எனில் (EVP_DigestSignInit(mdctx, வெற்று, வெற்று, வெற்று, pkey) != 1) {
		debug3_f("EVP_DigestSignInit failed");
		செல் out;
	}
	siglen = crypto_sign_ed25519_BYTES;
	எனில் (EVP_DigestSign(mdctx, sig, &siglen, m, mlen) != 1) {
		debug3_f("EVP_DigestSign failed");
		செல் out;
	}
	எனில் (siglen != crypto_sign_ed25519_BYTES) {
		debug3_f("signature length mismatch: %zu", siglen);
		செல் out;
	}

	எனில் (siglenp != வெற்று)
		*siglenp = siglen;

	ret = 0;
out:
	EVP_MD_CTX_free(mdctx);
	EVP_PKEY_free(pkey);
	திரும்பு ret;
}

முழு
crypto_sign_ed25519_verify_detached(மாறிலி unsigned எழுத்து *sig,
    மாறிலி unsigned எழுத்து *m, unsigned long long mlen,
    மாறிலி unsigned எழுத்து *pk)
{
	EVP_PKEY *pkey = வெற்று;
	EVP_MD_CTX *mdctx = வெற்று;
	முழு ret = -1;

	எனில் (mlen > SIZE_MAX) {
		debug3_f("message too long: %llu", mlen);
		திரும்பு -1;
	}

	/* Create EVP_PKEY from public key */
	எனில் ((pkey = EVP_PKEY_new_raw_public_சாவி(EVP_PKEY_ED25519, வெற்று,
	    pk, crypto_sign_ed25519_PUBLICKEYBYTES)) == வெற்று) {
		debug3_f("EVP_PKEY_new_raw_public_key failed");
		செல் out;
	}

	எனில் ((mdctx = EVP_MD_CTX_new()) == வெற்று) {
		debug3_f("EVP_MD_CTX_new failed");
		செல் out;
	}
	எனில் (EVP_DigestVerifyInit(mdctx, வெற்று, வெற்று, வெற்று, pkey) <= 0) {
		debug3_f("EVP_DigestVerifyInit failed");
		செல் out;
	}
	எனில் (EVP_DigestVerify(mdctx, sig, crypto_sign_ed25519_BYTES,
	    m, (size_t)mlen) != 1) {
		debug3_f("EVP_DigestVerify failed");
		செல் out;
	}

	ret = 0;
out:
	EVP_MD_CTX_free(mdctx);
	EVP_PKEY_free(pkey);
	திரும்பு ret;
}

#endif /* OPENSSL_HAS_ED25519 */
