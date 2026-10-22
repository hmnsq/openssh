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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ifdef OPENSSL_HAS_ED25519

#ଅନ୍ତର୍ଭାଵ <sys/types.h>

#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <stdint.h>
#ଅନ୍ତର୍ଭାଵ <limits.h>

#ଅନ୍ତର୍ଭାଵ <openssl/evp.h>

#ଅନ୍ତର୍ଭାଵ "crypto_api.h"
#ଅନ୍ତର୍ଭାଵ "log.h"

#ଯଦି crypto_sign_ed25519_SECRETKEYBYTES <= crypto_sign_ed25519_PUBLICKEYBYTES
#error "crypto_sign_ed25519_SECRETKEYBYTES < crypto_sign_ed25519_PUBLICKEYBYTES"
#endif

#define SSH_ED25519_RAW_SECRET_ଚାବି_LEN \
    (crypto_sign_ed25519_SECRETKEYBYTES - crypto_sign_ed25519_PUBLICKEYBYTES)

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
crypto_sign_ed25519_keypair(unsigned ଅକ୍ଷର *pk, unsigned ଅକ୍ଷର *sk)
{
	EVP_PKEY_CTX *ctx = ଖାଲି;
	EVP_PKEY *pkey = ଖାଲି;
	size_t pklen, sklen;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ret = -1;

	ଯଦି ((ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, ଖାଲି)) == ଖାଲି) {
		debug3_f("EVP_PKEY_CTX_new_id failed");
		ଯାଅ out;
	}
	ଯଦି (EVP_PKEY_keygen_init(ctx) <= 0) {
		debug3_f("EVP_PKEY_keygen_init failed");
		ଯାଅ out;
	}
	ଯଦି (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
		debug3_f("EVP_PKEY_keygen failed");
		ଯାଅ out;
	}

	/* Extract public key */
	pklen = crypto_sign_ed25519_PUBLICKEYBYTES;
	ଯଦି (!EVP_PKEY_get_raw_public_ଚାବି(pkey, pk, &pklen)) {
		debug3_f("EVP_PKEY_get_raw_public_key failed");
		ଯାଅ out;
	}
	ଯଦି (pklen != crypto_sign_ed25519_PUBLICKEYBYTES) {
		debug3_f("public key length mismatch: %zu", pklen);
		ଯାଅ out;
	}

	sklen = SSH_ED25519_RAW_SECRET_ଚାବି_LEN;
	/* Extract private key (32 bytes seed) */
	ଯଦି (!EVP_PKEY_get_raw_private_ଚାବି(pkey, sk, &sklen)) {
		debug3_f("EVP_PKEY_get_raw_private_key failed");
		ଯାଅ out;
	}
	ଯଦି (sklen != SSH_ED25519_RAW_SECRET_ଚାବି_LEN) {
		debug3_f("private key length mismatch: %zu", sklen);
		ଯାଅ out;
	}

	/* Append public key to secret key (SUPERCOP format compatibility) */
	memcpy(sk + sklen, pk, crypto_sign_ed25519_PUBLICKEYBYTES);

	ret = 0;
out:
	EVP_PKEY_free(pkey);
	EVP_PKEY_CTX_free(ctx);
	ଫେରନ୍ତୁ ret;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
crypto_sign_ed25519_seed_keypair(unsigned ଅକ୍ଷର *pk, unsigned ଅକ୍ଷର *sk,
    ଅଚଳ unsigned ଅକ୍ଷର *seed)
{
	EVP_PKEY *pkey = ଖାଲି;
	size_t pklen;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ret = -1;

	ଯଦି ((pkey = EVP_PKEY_new_raw_private_ଚାବି(EVP_PKEY_ED25519, ଖାଲି,
	    seed, SSH_ED25519_RAW_SECRET_ଚାବି_LEN)) == ଖାଲି) {
		debug3_f("EVP_PKEY_new_raw_private_key failed");
		ଯାଅ out;
	}

	/* Extract public key */
	pklen = crypto_sign_ed25519_PUBLICKEYBYTES;
	ଯଦି (!EVP_PKEY_get_raw_public_ଚାବି(pkey, pk, &pklen)) {
		debug3_f("EVP_PKEY_get_raw_public_key failed");
		ଯାଅ out;
	}

	/* Build sk = seed || pk */
	memcpy(sk, seed, SSH_ED25519_RAW_SECRET_ଚାବି_LEN);
	memcpy(sk + SSH_ED25519_RAW_SECRET_ଚାବି_LEN, pk,
	    crypto_sign_ed25519_PUBLICKEYBYTES);

	ret = 0;
out:
	EVP_PKEY_free(pkey);
	ଫେରନ୍ତୁ ret;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
crypto_sign_ed25519_detached(unsigned ଅକ୍ଷର *sig, unsigned long long *siglenp,
    ଅଚଳ unsigned ଅକ୍ଷର *m, unsigned long long mlen,
    ଅଚଳ unsigned ଅକ୍ଷର *sk)
{
	EVP_PKEY *pkey = ଖାଲି;
	EVP_MD_CTX *mdctx = ଖାଲି;
	size_t siglen;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ret = -1;

	/* Create EVP_PKEY from secret key (first 32 bytes are the seed) */
	ଯଦି ((pkey = EVP_PKEY_new_raw_private_ଚାବି(EVP_PKEY_ED25519, ଖାଲି,
	    sk, SSH_ED25519_RAW_SECRET_ଚାବି_LEN)) == ଖାଲି) {
		debug3_f("EVP_PKEY_new_raw_private_key failed");
		ଯାଅ out;
	}

	/* Sign the message */
	ଯଦି ((mdctx = EVP_MD_CTX_new()) == ଖାଲି) {
		debug3_f("EVP_MD_CTX_new failed");
		ଯାଅ out;
	}
	ଯଦି (EVP_DigestSignInit(mdctx, ଖାଲି, ଖାଲି, ଖାଲି, pkey) != 1) {
		debug3_f("EVP_DigestSignInit failed");
		ଯାଅ out;
	}
	siglen = crypto_sign_ed25519_BYTES;
	ଯଦି (EVP_DigestSign(mdctx, sig, &siglen, m, mlen) != 1) {
		debug3_f("EVP_DigestSign failed");
		ଯାଅ out;
	}
	ଯଦି (siglen != crypto_sign_ed25519_BYTES) {
		debug3_f("signature length mismatch: %zu", siglen);
		ଯାଅ out;
	}

	ଯଦି (siglenp != ଖାଲି)
		*siglenp = siglen;

	ret = 0;
out:
	EVP_MD_CTX_free(mdctx);
	EVP_PKEY_free(pkey);
	ଫେରନ୍ତୁ ret;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
crypto_sign_ed25519_verify_detached(ଅଚଳ unsigned ଅକ୍ଷର *sig,
    ଅଚଳ unsigned ଅକ୍ଷର *m, unsigned long long mlen,
    ଅଚଳ unsigned ଅକ୍ଷର *pk)
{
	EVP_PKEY *pkey = ଖାଲି;
	EVP_MD_CTX *mdctx = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ret = -1;

	ଯଦି (mlen > SIZE_MAX) {
		debug3_f("message too long: %llu", mlen);
		ଫେରନ୍ତୁ -1;
	}

	/* Create EVP_PKEY from public key */
	ଯଦି ((pkey = EVP_PKEY_new_raw_public_ଚାବି(EVP_PKEY_ED25519, ଖାଲି,
	    pk, crypto_sign_ed25519_PUBLICKEYBYTES)) == ଖାଲି) {
		debug3_f("EVP_PKEY_new_raw_public_key failed");
		ଯାଅ out;
	}

	ଯଦି ((mdctx = EVP_MD_CTX_new()) == ଖାଲି) {
		debug3_f("EVP_MD_CTX_new failed");
		ଯାଅ out;
	}
	ଯଦି (EVP_DigestVerifyInit(mdctx, ଖାଲି, ଖାଲି, ଖାଲି, pkey) <= 0) {
		debug3_f("EVP_DigestVerifyInit failed");
		ଯାଅ out;
	}
	ଯଦି (EVP_DigestVerify(mdctx, sig, crypto_sign_ed25519_BYTES,
	    m, (size_t)mlen) != 1) {
		debug3_f("EVP_DigestVerify failed");
		ଯାଅ out;
	}

	ret = 0;
out:
	EVP_MD_CTX_free(mdctx);
	EVP_PKEY_free(pkey);
	ଫେରନ୍ତୁ ret;
}

#endif /* OPENSSL_HAS_ED25519 */
