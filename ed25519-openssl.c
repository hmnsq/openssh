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

#അന്തര്ഭാവ "includes.h"

#ifdef OPENSSL_HAS_ED25519

#അന്തര്ഭാവ <sys/types.h>

#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <stdint.h>
#അന്തര്ഭാവ <limits.h>

#അന്തര്ഭാവ <openssl/evp.h>

#അന്തര്ഭാവ "crypto_api.h"
#അന്തര്ഭാവ "log.h"

#എങ്കിൽ crypto_sign_ed25519_SECRETKEYBYTES <= crypto_sign_ed25519_PUBLICKEYBYTES
#error "crypto_sign_ed25519_SECRETKEYBYTES < crypto_sign_ed25519_PUBLICKEYBYTES"
#endif

#define SSH_ED25519_RAW_SECRET_താക്കോൽ_LEN \
    (crypto_sign_ed25519_SECRETKEYBYTES - crypto_sign_ed25519_PUBLICKEYBYTES)

പൂർണ്ണസംഖ്യ
crypto_sign_ed25519_keypair(unsigned അക്ഷരം *pk, unsigned അക്ഷരം *sk)
{
	EVP_PKEY_CTX *ctx = ശൂന്യ;
	EVP_PKEY *pkey = ശൂന്യ;
	size_t pklen, sklen;
	പൂർണ്ണസംഖ്യ ret = -1;

	എങ്കിൽ ((ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, ശൂന്യ)) == ശൂന്യ) {
		debug3_f("EVP_PKEY_CTX_new_id failed");
		പോകുക out;
	}
	എങ്കിൽ (EVP_PKEY_keygen_init(ctx) <= 0) {
		debug3_f("EVP_PKEY_keygen_init failed");
		പോകുക out;
	}
	എങ്കിൽ (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
		debug3_f("EVP_PKEY_keygen failed");
		പോകുക out;
	}

	/* Extract public key */
	pklen = crypto_sign_ed25519_PUBLICKEYBYTES;
	എങ്കിൽ (!EVP_PKEY_get_raw_public_താക്കോൽ(pkey, pk, &pklen)) {
		debug3_f("EVP_PKEY_get_raw_public_key failed");
		പോകുക out;
	}
	എങ്കിൽ (pklen != crypto_sign_ed25519_PUBLICKEYBYTES) {
		debug3_f("public key length mismatch: %zu", pklen);
		പോകുക out;
	}

	sklen = SSH_ED25519_RAW_SECRET_താക്കോൽ_LEN;
	/* Extract private key (32 bytes seed) */
	എങ്കിൽ (!EVP_PKEY_get_raw_private_താക്കോൽ(pkey, sk, &sklen)) {
		debug3_f("EVP_PKEY_get_raw_private_key failed");
		പോകുക out;
	}
	എങ്കിൽ (sklen != SSH_ED25519_RAW_SECRET_താക്കോൽ_LEN) {
		debug3_f("private key length mismatch: %zu", sklen);
		പോകുക out;
	}

	/* Append public key to secret key (SUPERCOP format compatibility) */
	memcpy(sk + sklen, pk, crypto_sign_ed25519_PUBLICKEYBYTES);

	ret = 0;
out:
	EVP_PKEY_free(pkey);
	EVP_PKEY_CTX_free(ctx);
	തിരികെ ret;
}

പൂർണ്ണസംഖ്യ
crypto_sign_ed25519_seed_keypair(unsigned അക്ഷരം *pk, unsigned അക്ഷരം *sk,
    സ്ഥിരം unsigned അക്ഷരം *seed)
{
	EVP_PKEY *pkey = ശൂന്യ;
	size_t pklen;
	പൂർണ്ണസംഖ്യ ret = -1;

	എങ്കിൽ ((pkey = EVP_PKEY_new_raw_private_താക്കോൽ(EVP_PKEY_ED25519, ശൂന്യ,
	    seed, SSH_ED25519_RAW_SECRET_താക്കോൽ_LEN)) == ശൂന്യ) {
		debug3_f("EVP_PKEY_new_raw_private_key failed");
		പോകുക out;
	}

	/* Extract public key */
	pklen = crypto_sign_ed25519_PUBLICKEYBYTES;
	എങ്കിൽ (!EVP_PKEY_get_raw_public_താക്കോൽ(pkey, pk, &pklen)) {
		debug3_f("EVP_PKEY_get_raw_public_key failed");
		പോകുക out;
	}

	/* Build sk = seed || pk */
	memcpy(sk, seed, SSH_ED25519_RAW_SECRET_താക്കോൽ_LEN);
	memcpy(sk + SSH_ED25519_RAW_SECRET_താക്കോൽ_LEN, pk,
	    crypto_sign_ed25519_PUBLICKEYBYTES);

	ret = 0;
out:
	EVP_PKEY_free(pkey);
	തിരികെ ret;
}

പൂർണ്ണസംഖ്യ
crypto_sign_ed25519_detached(unsigned അക്ഷരം *sig, unsigned long long *siglenp,
    സ്ഥിരം unsigned അക്ഷരം *m, unsigned long long mlen,
    സ്ഥിരം unsigned അക്ഷരം *sk)
{
	EVP_PKEY *pkey = ശൂന്യ;
	EVP_MD_CTX *mdctx = ശൂന്യ;
	size_t siglen;
	പൂർണ്ണസംഖ്യ ret = -1;

	/* Create EVP_PKEY from secret key (first 32 bytes are the seed) */
	എങ്കിൽ ((pkey = EVP_PKEY_new_raw_private_താക്കോൽ(EVP_PKEY_ED25519, ശൂന്യ,
	    sk, SSH_ED25519_RAW_SECRET_താക്കോൽ_LEN)) == ശൂന്യ) {
		debug3_f("EVP_PKEY_new_raw_private_key failed");
		പോകുക out;
	}

	/* Sign the message */
	എങ്കിൽ ((mdctx = EVP_MD_CTX_new()) == ശൂന്യ) {
		debug3_f("EVP_MD_CTX_new failed");
		പോകുക out;
	}
	എങ്കിൽ (EVP_DigestSignInit(mdctx, ശൂന്യ, ശൂന്യ, ശൂന്യ, pkey) != 1) {
		debug3_f("EVP_DigestSignInit failed");
		പോകുക out;
	}
	siglen = crypto_sign_ed25519_BYTES;
	എങ്കിൽ (EVP_DigestSign(mdctx, sig, &siglen, m, mlen) != 1) {
		debug3_f("EVP_DigestSign failed");
		പോകുക out;
	}
	എങ്കിൽ (siglen != crypto_sign_ed25519_BYTES) {
		debug3_f("signature length mismatch: %zu", siglen);
		പോകുക out;
	}

	എങ്കിൽ (siglenp != ശൂന്യ)
		*siglenp = siglen;

	ret = 0;
out:
	EVP_MD_CTX_free(mdctx);
	EVP_PKEY_free(pkey);
	തിരികെ ret;
}

പൂർണ്ണസംഖ്യ
crypto_sign_ed25519_verify_detached(സ്ഥിരം unsigned അക്ഷരം *sig,
    സ്ഥിരം unsigned അക്ഷരം *m, unsigned long long mlen,
    സ്ഥിരം unsigned അക്ഷരം *pk)
{
	EVP_PKEY *pkey = ശൂന്യ;
	EVP_MD_CTX *mdctx = ശൂന്യ;
	പൂർണ്ണസംഖ്യ ret = -1;

	എങ്കിൽ (mlen > SIZE_MAX) {
		debug3_f("message too long: %llu", mlen);
		തിരികെ -1;
	}

	/* Create EVP_PKEY from public key */
	എങ്കിൽ ((pkey = EVP_PKEY_new_raw_public_താക്കോൽ(EVP_PKEY_ED25519, ശൂന്യ,
	    pk, crypto_sign_ed25519_PUBLICKEYBYTES)) == ശൂന്യ) {
		debug3_f("EVP_PKEY_new_raw_public_key failed");
		പോകുക out;
	}

	എങ്കിൽ ((mdctx = EVP_MD_CTX_new()) == ശൂന്യ) {
		debug3_f("EVP_MD_CTX_new failed");
		പോകുക out;
	}
	എങ്കിൽ (EVP_DigestVerifyInit(mdctx, ശൂന്യ, ശൂന്യ, ശൂന്യ, pkey) <= 0) {
		debug3_f("EVP_DigestVerifyInit failed");
		പോകുക out;
	}
	എങ്കിൽ (EVP_DigestVerify(mdctx, sig, crypto_sign_ed25519_BYTES,
	    m, (size_t)mlen) != 1) {
		debug3_f("EVP_DigestVerify failed");
		പോകുക out;
	}

	ret = 0;
out:
	EVP_MD_CTX_free(mdctx);
	EVP_PKEY_free(pkey);
	തിരികെ ret;
}

#endif /* OPENSSL_HAS_ED25519 */
