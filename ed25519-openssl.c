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

#અન્તર્ભાવ "includes.h"

#ifdef OPENSSL_HAS_ED25519

#અન્તર્ભાવ <sys/types.h>

#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <stdint.h>
#અન્તર્ભાવ <limits.h>

#અન્તર્ભાવ <openssl/evp.h>

#અન્તર્ભાવ "crypto_api.h"
#અન્તર્ભાવ "log.h"

#જો crypto_sign_ed25519_SECRETKEYBYTES <= crypto_sign_ed25519_PUBLICKEYBYTES
#error "crypto_sign_ed25519_SECRETKEYBYTES < crypto_sign_ed25519_PUBLICKEYBYTES"
#endif

#define SSH_ED25519_RAW_SECRET_ચાવી_LEN \
    (crypto_sign_ed25519_SECRETKEYBYTES - crypto_sign_ed25519_PUBLICKEYBYTES)

પૂર્ણાંક
crypto_sign_ed25519_keypair(unsigned અક્ષર *pk, unsigned અક્ષર *sk)
{
	EVP_PKEY_CTX *ctx = ખાલી;
	EVP_PKEY *pkey = ખાલી;
	size_t pklen, sklen;
	પૂર્ણાંક ret = -1;

	જો ((ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, ખાલી)) == ખાલી) {
		debug3_f("EVP_PKEY_CTX_new_id failed");
		જાઓ out;
	}
	જો (EVP_PKEY_keygen_init(ctx) <= 0) {
		debug3_f("EVP_PKEY_keygen_init failed");
		જાઓ out;
	}
	જો (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
		debug3_f("EVP_PKEY_keygen failed");
		જાઓ out;
	}

	/* Extract public key */
	pklen = crypto_sign_ed25519_PUBLICKEYBYTES;
	જો (!EVP_PKEY_get_raw_public_ચાવી(pkey, pk, &pklen)) {
		debug3_f("EVP_PKEY_get_raw_public_key failed");
		જાઓ out;
	}
	જો (pklen != crypto_sign_ed25519_PUBLICKEYBYTES) {
		debug3_f("public key length mismatch: %zu", pklen);
		જાઓ out;
	}

	sklen = SSH_ED25519_RAW_SECRET_ચાવી_LEN;
	/* Extract private key (32 bytes seed) */
	જો (!EVP_PKEY_get_raw_private_ચાવી(pkey, sk, &sklen)) {
		debug3_f("EVP_PKEY_get_raw_private_key failed");
		જાઓ out;
	}
	જો (sklen != SSH_ED25519_RAW_SECRET_ચાવી_LEN) {
		debug3_f("private key length mismatch: %zu", sklen);
		જાઓ out;
	}

	/* Append public key to secret key (SUPERCOP format compatibility) */
	memcpy(sk + sklen, pk, crypto_sign_ed25519_PUBLICKEYBYTES);

	ret = 0;
out:
	EVP_PKEY_free(pkey);
	EVP_PKEY_CTX_free(ctx);
	પાછા ret;
}

પૂર્ણાંક
crypto_sign_ed25519_seed_keypair(unsigned અક્ષર *pk, unsigned અક્ષર *sk,
    અચલ unsigned અક્ષર *seed)
{
	EVP_PKEY *pkey = ખાલી;
	size_t pklen;
	પૂર્ણાંક ret = -1;

	જો ((pkey = EVP_PKEY_new_raw_private_ચાવી(EVP_PKEY_ED25519, ખાલી,
	    seed, SSH_ED25519_RAW_SECRET_ચાવી_LEN)) == ખાલી) {
		debug3_f("EVP_PKEY_new_raw_private_key failed");
		જાઓ out;
	}

	/* Extract public key */
	pklen = crypto_sign_ed25519_PUBLICKEYBYTES;
	જો (!EVP_PKEY_get_raw_public_ચાવી(pkey, pk, &pklen)) {
		debug3_f("EVP_PKEY_get_raw_public_key failed");
		જાઓ out;
	}

	/* Build sk = seed || pk */
	memcpy(sk, seed, SSH_ED25519_RAW_SECRET_ચાવી_LEN);
	memcpy(sk + SSH_ED25519_RAW_SECRET_ચાવી_LEN, pk,
	    crypto_sign_ed25519_PUBLICKEYBYTES);

	ret = 0;
out:
	EVP_PKEY_free(pkey);
	પાછા ret;
}

પૂર્ણાંક
crypto_sign_ed25519_detached(unsigned અક્ષર *sig, unsigned long long *siglenp,
    અચલ unsigned અક્ષર *m, unsigned long long mlen,
    અચલ unsigned અક્ષર *sk)
{
	EVP_PKEY *pkey = ખાલી;
	EVP_MD_CTX *mdctx = ખાલી;
	size_t siglen;
	પૂર્ણાંક ret = -1;

	/* Create EVP_PKEY from secret key (first 32 bytes are the seed) */
	જો ((pkey = EVP_PKEY_new_raw_private_ચાવી(EVP_PKEY_ED25519, ખાલી,
	    sk, SSH_ED25519_RAW_SECRET_ચાવી_LEN)) == ખાલી) {
		debug3_f("EVP_PKEY_new_raw_private_key failed");
		જાઓ out;
	}

	/* Sign the message */
	જો ((mdctx = EVP_MD_CTX_new()) == ખાલી) {
		debug3_f("EVP_MD_CTX_new failed");
		જાઓ out;
	}
	જો (EVP_DigestSignInit(mdctx, ખાલી, ખાલી, ખાલી, pkey) != 1) {
		debug3_f("EVP_DigestSignInit failed");
		જાઓ out;
	}
	siglen = crypto_sign_ed25519_BYTES;
	જો (EVP_DigestSign(mdctx, sig, &siglen, m, mlen) != 1) {
		debug3_f("EVP_DigestSign failed");
		જાઓ out;
	}
	જો (siglen != crypto_sign_ed25519_BYTES) {
		debug3_f("signature length mismatch: %zu", siglen);
		જાઓ out;
	}

	જો (siglenp != ખાલી)
		*siglenp = siglen;

	ret = 0;
out:
	EVP_MD_CTX_free(mdctx);
	EVP_PKEY_free(pkey);
	પાછા ret;
}

પૂર્ણાંક
crypto_sign_ed25519_verify_detached(અચલ unsigned અક્ષર *sig,
    અચલ unsigned અક્ષર *m, unsigned long long mlen,
    અચલ unsigned અક્ષર *pk)
{
	EVP_PKEY *pkey = ખાલી;
	EVP_MD_CTX *mdctx = ખાલી;
	પૂર્ણાંક ret = -1;

	જો (mlen > SIZE_MAX) {
		debug3_f("message too long: %llu", mlen);
		પાછા -1;
	}

	/* Create EVP_PKEY from public key */
	જો ((pkey = EVP_PKEY_new_raw_public_ચાવી(EVP_PKEY_ED25519, ખાલી,
	    pk, crypto_sign_ed25519_PUBLICKEYBYTES)) == ખાલી) {
		debug3_f("EVP_PKEY_new_raw_public_key failed");
		જાઓ out;
	}

	જો ((mdctx = EVP_MD_CTX_new()) == ખાલી) {
		debug3_f("EVP_MD_CTX_new failed");
		જાઓ out;
	}
	જો (EVP_DigestVerifyInit(mdctx, ખાલી, ખાલી, ખાલી, pkey) <= 0) {
		debug3_f("EVP_DigestVerifyInit failed");
		જાઓ out;
	}
	જો (EVP_DigestVerify(mdctx, sig, crypto_sign_ed25519_BYTES,
	    m, (size_t)mlen) != 1) {
		debug3_f("EVP_DigestVerify failed");
		જાઓ out;
	}

	ret = 0;
out:
	EVP_MD_CTX_free(mdctx);
	EVP_PKEY_free(pkey);
	પાછા ret;
}

#endif /* OPENSSL_HAS_ED25519 */
