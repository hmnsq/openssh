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

পূর্ণসংখ্যা
crypto_sign_ed25519_keypair(unsigned অক্ষর *pk, unsigned অক্ষর *sk)
{
	EVP_PKEY_CTX *ctx = ফাঁকা;
	EVP_PKEY *pkey = ফাঁকা;
	আকার_t pklen, sklen;
	পূর্ণসংখ্যা ret = -1;

	যদি ((ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, ফাঁকা)) == ফাঁকা) {
		debug3_f("EVP_PKEY_CTX_new_id failed");
		যাও out;
	}
	যদি (EVP_PKEY_keygen_init(ctx) <= 0) {
		debug3_f("EVP_PKEY_keygen_init failed");
		যাও out;
	}
	যদি (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
		debug3_f("EVP_PKEY_keygen failed");
		যাও out;
	}

	/* Extract public key */
	pklen = crypto_sign_ed25519_PUBLICKEYBYTES;
	যদি (!EVP_PKEY_get_raw_public_চাবি(pkey, pk, &pklen)) {
		debug3_f("EVP_PKEY_get_raw_public_key failed");
		যাও out;
	}
	যদি (pklen != crypto_sign_ed25519_PUBLICKEYBYTES) {
		debug3_f("public key length mismatch: %zu", pklen);
		যাও out;
	}

	sklen = SSH_ED25519_RAW_SECRET_চাবি_LEN;
	/* Extract private key (32 bytes seed) */
	যদি (!EVP_PKEY_get_raw_private_চাবি(pkey, sk, &sklen)) {
		debug3_f("EVP_PKEY_get_raw_private_key failed");
		যাও out;
	}
	যদি (sklen != SSH_ED25519_RAW_SECRET_চাবি_LEN) {
		debug3_f("private key length mismatch: %zu", sklen);
		যাও out;
	}

	/* Append public key to secret key (SUPERCOP format compatibility) */
	memcpy(sk + sklen, pk, crypto_sign_ed25519_PUBLICKEYBYTES);

	ret = 0;
out:
	EVP_PKEY_free(pkey);
	EVP_PKEY_CTX_free(ctx);
	ফেরত ret;
}

পূর্ণসংখ্যা
crypto_sign_ed25519_seed_keypair(unsigned অক্ষর *pk, unsigned অক্ষর *sk,
    ধ্রুবক unsigned অক্ষর *seed)
{
	EVP_PKEY *pkey = ফাঁকা;
	আকার_t pklen;
	পূর্ণসংখ্যা ret = -1;

	যদি ((pkey = EVP_PKEY_new_raw_private_চাবি(EVP_PKEY_ED25519, ফাঁকা,
	    seed, SSH_ED25519_RAW_SECRET_চাবি_LEN)) == ফাঁকা) {
		debug3_f("EVP_PKEY_new_raw_private_key failed");
		যাও out;
	}

	/* Extract public key */
	pklen = crypto_sign_ed25519_PUBLICKEYBYTES;
	যদি (!EVP_PKEY_get_raw_public_চাবি(pkey, pk, &pklen)) {
		debug3_f("EVP_PKEY_get_raw_public_key failed");
		যাও out;
	}

	/* Build sk = seed || pk */
	memcpy(sk, seed, SSH_ED25519_RAW_SECRET_চাবি_LEN);
	memcpy(sk + SSH_ED25519_RAW_SECRET_চাবি_LEN, pk,
	    crypto_sign_ed25519_PUBLICKEYBYTES);

	ret = 0;
out:
	EVP_PKEY_free(pkey);
	ফেরত ret;
}

পূর্ণসংখ্যা
crypto_sign_ed25519_detached(unsigned অক্ষর *sig, unsigned long long *siglenp,
    ধ্রুবক unsigned অক্ষর *m, unsigned long long mlen,
    ধ্রুবক unsigned অক্ষর *sk)
{
	EVP_PKEY *pkey = ফাঁকা;
	EVP_MD_CTX *mdctx = ফাঁকা;
	আকার_t siglen;
	পূর্ণসংখ্যা ret = -1;

	/* Create EVP_PKEY from secret key (first 32 bytes are the seed) */
	যদি ((pkey = EVP_PKEY_new_raw_private_চাবি(EVP_PKEY_ED25519, ফাঁকা,
	    sk, SSH_ED25519_RAW_SECRET_চাবি_LEN)) == ফাঁকা) {
		debug3_f("EVP_PKEY_new_raw_private_key failed");
		যাও out;
	}

	/* Sign the message */
	যদি ((mdctx = EVP_MD_CTX_new()) == ফাঁকা) {
		debug3_f("EVP_MD_CTX_new failed");
		যাও out;
	}
	যদি (EVP_DigestSignInit(mdctx, ফাঁকা, ফাঁকা, ফাঁকা, pkey) != 1) {
		debug3_f("EVP_DigestSignInit failed");
		যাও out;
	}
	siglen = crypto_sign_ed25519_BYTES;
	যদি (EVP_DigestSign(mdctx, sig, &siglen, m, mlen) != 1) {
		debug3_f("EVP_DigestSign failed");
		যাও out;
	}
	যদি (siglen != crypto_sign_ed25519_BYTES) {
		debug3_f("signature length mismatch: %zu", siglen);
		যাও out;
	}

	যদি (siglenp != ফাঁকা)
		*siglenp = siglen;

	ret = 0;
out:
	EVP_MD_CTX_free(mdctx);
	EVP_PKEY_free(pkey);
	ফেরত ret;
}

পূর্ণসংখ্যা
crypto_sign_ed25519_verify_detached(ধ্রুবক unsigned অক্ষর *sig,
    ধ্রুবক unsigned অক্ষর *m, unsigned long long mlen,
    ধ্রুবক unsigned অক্ষর *pk)
{
	EVP_PKEY *pkey = ফাঁকা;
	EVP_MD_CTX *mdctx = ফাঁকা;
	পূর্ণসংখ্যা ret = -1;

	যদি (mlen > SIZE_MAX) {
		debug3_f("message too long: %llu", mlen);
		ফেরত -1;
	}

	/* Create EVP_PKEY from public key */
	যদি ((pkey = EVP_PKEY_new_raw_public_চাবি(EVP_PKEY_ED25519, ফাঁকা,
	    pk, crypto_sign_ed25519_PUBLICKEYBYTES)) == ফাঁকা) {
		debug3_f("EVP_PKEY_new_raw_public_key failed");
		যাও out;
	}

	যদি ((mdctx = EVP_MD_CTX_new()) == ফাঁকা) {
		debug3_f("EVP_MD_CTX_new failed");
		যাও out;
	}
	যদি (EVP_DigestVerifyInit(mdctx, ফাঁকা, ফাঁকা, ফাঁকা, pkey) <= 0) {
		debug3_f("EVP_DigestVerifyInit failed");
		যাও out;
	}
	যদি (EVP_DigestVerify(mdctx, sig, crypto_sign_ed25519_BYTES,
	    m, (আকার_t)mlen) != 1) {
		debug3_f("EVP_DigestVerify failed");
		যাও out;
	}

	ret = 0;
out:
	EVP_MD_CTX_free(mdctx);
	EVP_PKEY_free(pkey);
	ফেরত ret;
}

#endif /* OPENSSL_HAS_ED25519 */
