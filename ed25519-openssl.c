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

#অন্তর্ভাব "includes.h"

#ifdef OPENSSL_HAS_ED25519

#অন্তর্ভাব <sys/types.h>

#অন্তর্ভাব <string.h>
#অন্তর্ভাব <stdint.h>
#অন্তর্ভাব <limits.h>

#অন্তর্ভাব <openssl/evp.h>

#অন্তর্ভাব "crypto_api.h"
#অন্তর্ভাব "log.h"

#যদি crypto_sign_ed25519_SECRETKEYBYTES <= crypto_sign_ed25519_PUBLICKEYBYTES
#error "crypto_sign_ed25519_SECRETKEYBYTES < crypto_sign_ed25519_PUBLICKEYBYTES"
#endif

#define SSH_ED25519_RAW_SECRET_চাবি_LEN \
    (crypto_sign_ed25519_SECRETKEYBYTES - crypto_sign_ed25519_PUBLICKEYBYTES)

পূর্ণাঙ্ক
crypto_sign_ed25519_keypair(unsigned বর্ণ *pk, unsigned বর্ণ *sk)
{
	EVP_PKEY_CTX *ctx = রিক্ত;
	EVP_PKEY *pkey = রিক্ত;
	size_t pklen, sklen;
	পূর্ণাঙ্ক ret = -1;

	যদি ((ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, রিক্ত)) == রিক্ত) {
		debug3_f("EVP_PKEY_CTX_new_id failed");
		গচ্ছ out;
	}
	যদি (EVP_PKEY_keygen_init(ctx) <= 0) {
		debug3_f("EVP_PKEY_keygen_init failed");
		গচ্ছ out;
	}
	যদি (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
		debug3_f("EVP_PKEY_keygen failed");
		গচ্ছ out;
	}

	/* Extract public key */
	pklen = crypto_sign_ed25519_PUBLICKEYBYTES;
	যদি (!EVP_PKEY_get_raw_public_চাবি(pkey, pk, &pklen)) {
		debug3_f("EVP_PKEY_get_raw_public_key failed");
		গচ্ছ out;
	}
	যদি (pklen != crypto_sign_ed25519_PUBLICKEYBYTES) {
		debug3_f("public key length mismatch: %zu", pklen);
		গচ্ছ out;
	}

	sklen = SSH_ED25519_RAW_SECRET_চাবি_LEN;
	/* Extract private key (32 bytes seed) */
	যদি (!EVP_PKEY_get_raw_private_চাবি(pkey, sk, &sklen)) {
		debug3_f("EVP_PKEY_get_raw_private_key failed");
		গচ্ছ out;
	}
	যদি (sklen != SSH_ED25519_RAW_SECRET_চাবি_LEN) {
		debug3_f("private key length mismatch: %zu", sklen);
		গচ্ছ out;
	}

	/* Append public key to secret key (SUPERCOP format compatibility) */
	memcpy(sk + sklen, pk, crypto_sign_ed25519_PUBLICKEYBYTES);

	ret = 0;
out:
	EVP_PKEY_free(pkey);
	EVP_PKEY_CTX_free(ctx);
	প্রত্যাগম ret;
}

পূর্ণাঙ্ক
crypto_sign_ed25519_seed_keypair(unsigned বর্ণ *pk, unsigned বর্ণ *sk,
    ধ্রুব unsigned বর্ণ *seed)
{
	EVP_PKEY *pkey = রিক্ত;
	size_t pklen;
	পূর্ণাঙ্ক ret = -1;

	যদি ((pkey = EVP_PKEY_new_raw_private_চাবি(EVP_PKEY_ED25519, রিক্ত,
	    seed, SSH_ED25519_RAW_SECRET_চাবি_LEN)) == রিক্ত) {
		debug3_f("EVP_PKEY_new_raw_private_key failed");
		গচ্ছ out;
	}

	/* Extract public key */
	pklen = crypto_sign_ed25519_PUBLICKEYBYTES;
	যদি (!EVP_PKEY_get_raw_public_চাবি(pkey, pk, &pklen)) {
		debug3_f("EVP_PKEY_get_raw_public_key failed");
		গচ্ছ out;
	}

	/* Build sk = seed || pk */
	memcpy(sk, seed, SSH_ED25519_RAW_SECRET_চাবি_LEN);
	memcpy(sk + SSH_ED25519_RAW_SECRET_চাবি_LEN, pk,
	    crypto_sign_ed25519_PUBLICKEYBYTES);

	ret = 0;
out:
	EVP_PKEY_free(pkey);
	প্রত্যাগম ret;
}

পূর্ণাঙ্ক
crypto_sign_ed25519_detached(unsigned বর্ণ *sig, unsigned long long *siglenp,
    ধ্রুব unsigned বর্ণ *m, unsigned long long mlen,
    ধ্রুব unsigned বর্ণ *sk)
{
	EVP_PKEY *pkey = রিক্ত;
	EVP_MD_CTX *mdctx = রিক্ত;
	size_t siglen;
	পূর্ণাঙ্ক ret = -1;

	/* Create EVP_PKEY from secret key (first 32 bytes are the seed) */
	যদি ((pkey = EVP_PKEY_new_raw_private_চাবি(EVP_PKEY_ED25519, রিক্ত,
	    sk, SSH_ED25519_RAW_SECRET_চাবি_LEN)) == রিক্ত) {
		debug3_f("EVP_PKEY_new_raw_private_key failed");
		গচ্ছ out;
	}

	/* Sign the message */
	যদি ((mdctx = EVP_MD_CTX_new()) == রিক্ত) {
		debug3_f("EVP_MD_CTX_new failed");
		গচ্ছ out;
	}
	যদি (EVP_DigestSignInit(mdctx, রিক্ত, রিক্ত, রিক্ত, pkey) != 1) {
		debug3_f("EVP_DigestSignInit failed");
		গচ্ছ out;
	}
	siglen = crypto_sign_ed25519_BYTES;
	যদি (EVP_DigestSign(mdctx, sig, &siglen, m, mlen) != 1) {
		debug3_f("EVP_DigestSign failed");
		গচ্ছ out;
	}
	যদি (siglen != crypto_sign_ed25519_BYTES) {
		debug3_f("signature length mismatch: %zu", siglen);
		গচ্ছ out;
	}

	যদি (siglenp != রিক্ত)
		*siglenp = siglen;

	ret = 0;
out:
	EVP_MD_CTX_free(mdctx);
	EVP_PKEY_free(pkey);
	প্রত্যাগম ret;
}

পূর্ণাঙ্ক
crypto_sign_ed25519_verify_detached(ধ্রুব unsigned বর্ণ *sig,
    ধ্রুব unsigned বর্ণ *m, unsigned long long mlen,
    ধ্রুব unsigned বর্ণ *pk)
{
	EVP_PKEY *pkey = রিক্ত;
	EVP_MD_CTX *mdctx = রিক্ত;
	পূর্ণাঙ্ক ret = -1;

	যদি (mlen > SIZE_MAX) {
		debug3_f("message too long: %llu", mlen);
		প্রত্যাগম -1;
	}

	/* Create EVP_PKEY from public key */
	যদি ((pkey = EVP_PKEY_new_raw_public_চাবি(EVP_PKEY_ED25519, রিক্ত,
	    pk, crypto_sign_ed25519_PUBLICKEYBYTES)) == রিক্ত) {
		debug3_f("EVP_PKEY_new_raw_public_key failed");
		গচ্ছ out;
	}

	যদি ((mdctx = EVP_MD_CTX_new()) == রিক্ত) {
		debug3_f("EVP_MD_CTX_new failed");
		গচ্ছ out;
	}
	যদি (EVP_DigestVerifyInit(mdctx, রিক্ত, রিক্ত, রিক্ত, pkey) <= 0) {
		debug3_f("EVP_DigestVerifyInit failed");
		গচ্ছ out;
	}
	যদি (EVP_DigestVerify(mdctx, sig, crypto_sign_ed25519_BYTES,
	    m, (size_t)mlen) != 1) {
		debug3_f("EVP_DigestVerify failed");
		গচ্ছ out;
	}

	ret = 0;
out:
	EVP_MD_CTX_free(mdctx);
	EVP_PKEY_free(pkey);
	প্রত্যাগম ret;
}

#endif /* OPENSSL_HAS_ED25519 */
