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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ OPENSSL_HAS_ED25519

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdint.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <limits.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/evp.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "crypto_api.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"

#ਜੇ crypto_sign_ed25519_SECRETKEYBYTES <= crypto_sign_ed25519_PUBLICKEYBYTES
#ਗਲਤੀ "crypto_sign_ed25519_SECRETKEYBYTES < crypto_sign_ed25519_PUBLICKEYBYTES"
#ਜੇ_ਅੰਤ

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_ED25519_RAW_SECRET_ਕੁੰਜੀ_LEN \
    (crypto_sign_ed25519_SECRETKEYBYTES - crypto_sign_ed25519_PUBLICKEYBYTES)

ਪੂਰਨ
crypto_sign_ed25519_keypair(ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *pk, ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *sk)
{
	EVP_PKEY_CTX *ctx = ਨਿਰਾ;
	EVP_PKEY *pkey = ਨਿਰਾ;
	ਮਾਪ_t pklen, sklen;
	ਪੂਰਨ ret = -1;

	ਜੇ ((ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, ਨਿਰਾ)) == ਨਿਰਾ) {
		debug3_f("EVP_PKEY_CTX_new_id failed");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (EVP_PKEY_keygen_init(ctx) <= 0) {
		debug3_f("EVP_PKEY_keygen_init failed");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
		debug3_f("EVP_PKEY_keygen failed");
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	/* Extract public key */
	pklen = crypto_sign_ed25519_PUBLICKEYBYTES;
	ਜੇ (!EVP_PKEY_get_raw_ਜਨਤਕ_ਕੁੰਜੀ(pkey, pk, &pklen)) {
		debug3_f("EVP_PKEY_get_raw_public_key failed");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (pklen != crypto_sign_ed25519_PUBLICKEYBYTES) {
		debug3_f("public key length mismatch: %zu", pklen);
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	sklen = SSH_ED25519_RAW_SECRET_ਕੁੰਜੀ_LEN;
	/* Extract private key (32 bytes seed) */
	ਜੇ (!EVP_PKEY_get_raw_ਨਿੱਜੀ_ਕੁੰਜੀ(pkey, sk, &sklen)) {
		debug3_f("EVP_PKEY_get_raw_private_key failed");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (sklen != SSH_ED25519_RAW_SECRET_ਕੁੰਜੀ_LEN) {
		debug3_f("private key length mismatch: %zu", sklen);
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	/* Append public key to secret key (SUPERCOP format compatibility) */
	ਸਮ੍ਰਿਤੀ_ਨਕਲ(sk + sklen, pk, crypto_sign_ed25519_PUBLICKEYBYTES);

	ret = 0;
ਬਾਹਰਲਾ:
	EVP_PKEY_free(pkey);
	EVP_PKEY_CTX_free(ctx);
	ਵਾਪਸ ret;
}

ਪੂਰਨ
crypto_sign_ed25519_ਬੀਜ_keypair(ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *pk, ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *sk,
    ਅਚਲ ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *ਬੀਜ)
{
	EVP_PKEY *pkey = ਨਿਰਾ;
	ਮਾਪ_t pklen;
	ਪੂਰਨ ret = -1;

	ਜੇ ((pkey = EVP_PKEY_new_raw_ਨਿੱਜੀ_ਕੁੰਜੀ(EVP_PKEY_ED25519, ਨਿਰਾ,
	    ਬੀਜ, SSH_ED25519_RAW_SECRET_ਕੁੰਜੀ_LEN)) == ਨਿਰਾ) {
		debug3_f("EVP_PKEY_new_raw_private_key failed");
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	/* Extract public key */
	pklen = crypto_sign_ed25519_PUBLICKEYBYTES;
	ਜੇ (!EVP_PKEY_get_raw_ਜਨਤਕ_ਕੁੰਜੀ(pkey, pk, &pklen)) {
		debug3_f("EVP_PKEY_get_raw_public_key failed");
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	/* Build sk = seed || pk */
	ਸਮ੍ਰਿਤੀ_ਨਕਲ(sk, ਬੀਜ, SSH_ED25519_RAW_SECRET_ਕੁੰਜੀ_LEN);
	ਸਮ੍ਰਿਤੀ_ਨਕਲ(sk + SSH_ED25519_RAW_SECRET_ਕੁੰਜੀ_LEN, pk,
	    crypto_sign_ed25519_PUBLICKEYBYTES);

	ret = 0;
ਬਾਹਰਲਾ:
	EVP_PKEY_free(pkey);
	ਵਾਪਸ ret;
}

ਪੂਰਨ
crypto_sign_ed25519_detached(ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *sig, ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ *siglenp,
    ਅਚਲ ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *m, ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ mlen,
    ਅਚਲ ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *sk)
{
	EVP_PKEY *pkey = ਨਿਰਾ;
	EVP_MD_CTX *mdctx = ਨਿਰਾ;
	ਮਾਪ_t siglen;
	ਪੂਰਨ ret = -1;

	/* Create EVP_PKEY from secret key (first 32 bytes are the seed) */
	ਜੇ ((pkey = EVP_PKEY_new_raw_ਨਿੱਜੀ_ਕੁੰਜੀ(EVP_PKEY_ED25519, ਨਿਰਾ,
	    sk, SSH_ED25519_RAW_SECRET_ਕੁੰਜੀ_LEN)) == ਨਿਰਾ) {
		debug3_f("EVP_PKEY_new_raw_private_key failed");
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	/* Sign the message */
	ਜੇ ((mdctx = EVP_MD_CTX_new()) == ਨਿਰਾ) {
		debug3_f("EVP_MD_CTX_new failed");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (EVP_DigestSignInit(mdctx, ਨਿਰਾ, ਨਿਰਾ, ਨਿਰਾ, pkey) != 1) {
		debug3_f("EVP_DigestSignInit failed");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	siglen = crypto_sign_ed25519_ਬਾਈਟਾਂ;
	ਜੇ (EVP_DigestSign(mdctx, sig, &siglen, m, mlen) != 1) {
		debug3_f("EVP_DigestSign failed");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (siglen != crypto_sign_ed25519_ਬਾਈਟਾਂ) {
		debug3_f("signature length mismatch: %zu", siglen);
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	ਜੇ (siglenp != ਨਿਰਾ)
		*siglenp = siglen;

	ret = 0;
ਬਾਹਰਲਾ:
	EVP_MD_CTX_free(mdctx);
	EVP_PKEY_free(pkey);
	ਵਾਪਸ ret;
}

ਪੂਰਨ
crypto_sign_ed25519_verify_detached(ਅਚਲ ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *sig,
    ਅਚਲ ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *m, ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ mlen,
    ਅਚਲ ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *pk)
{
	EVP_PKEY *pkey = ਨਿਰਾ;
	EVP_MD_CTX *mdctx = ਨਿਰਾ;
	ਪੂਰਨ ret = -1;

	ਜੇ (mlen > SIZE_MAX) {
		debug3_f("message too long: %llu", mlen);
		ਵਾਪਸ -1;
	}

	/* Create EVP_PKEY from public key */
	ਜੇ ((pkey = EVP_PKEY_new_raw_ਜਨਤਕ_ਕੁੰਜੀ(EVP_PKEY_ED25519, ਨਿਰਾ,
	    pk, crypto_sign_ed25519_PUBLICKEYBYTES)) == ਨਿਰਾ) {
		debug3_f("EVP_PKEY_new_raw_public_key failed");
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	ਜੇ ((mdctx = EVP_MD_CTX_new()) == ਨਿਰਾ) {
		debug3_f("EVP_MD_CTX_new failed");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (EVP_DigestVerifyInit(mdctx, ਨਿਰਾ, ਨਿਰਾ, ਨਿਰਾ, pkey) <= 0) {
		debug3_f("EVP_DigestVerifyInit failed");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (EVP_DigestVerify(mdctx, sig, crypto_sign_ed25519_ਬਾਈਟਾਂ,
	    m, (ਮਾਪ_t)mlen) != 1) {
		debug3_f("EVP_DigestVerify failed");
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	ret = 0;
ਬਾਹਰਲਾ:
	EVP_MD_CTX_free(mdctx);
	EVP_PKEY_free(pkey);
	ਵਾਪਸ ret;
}

#ਜੇ_ਅੰਤ /* OPENSSL_HAS_ED25519 */
