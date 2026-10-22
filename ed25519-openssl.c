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

#شامل "includes.h"

#ifdef OPENSSL_HAS_ED25519

#شامل <sys/types.h>

#شامل <string.h>
#شامل <stdint.h>
#شامل <limits.h>

#شامل <openssl/evp.h>

#شامل "crypto_api.h"
#شامل "log.h"

#اگر crypto_sign_ed25519_SECRETKEYBYTES <= crypto_sign_ed25519_PUBLICKEYBYTES
#error "crypto_sign_ed25519_SECRETKEYBYTES < crypto_sign_ed25519_PUBLICKEYBYTES"
#endif

#define SSH_ED25519_RAW_SECRET_کلید_LEN \
    (crypto_sign_ed25519_SECRETKEYBYTES - crypto_sign_ed25519_PUBLICKEYBYTES)

صحیح
crypto_sign_ed25519_keypair(unsigned نویسه *pk, unsigned نویسه *sk)
{
	EVP_PKEY_CTX *ctx = پوچ;
	EVP_PKEY *pkey = پوچ;
	size_t pklen, sklen;
	صحیح ret = -1;

	اگر ((ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, پوچ)) == پوچ) {
		debug3_f("EVP_PKEY_CTX_new_id failed");
		برو out;
	}
	اگر (EVP_PKEY_keygen_init(ctx) <= 0) {
		debug3_f("EVP_PKEY_keygen_init failed");
		برو out;
	}
	اگر (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
		debug3_f("EVP_PKEY_keygen failed");
		برو out;
	}

	/* Extract public key */
	pklen = crypto_sign_ed25519_PUBLICKEYBYTES;
	اگر (!EVP_PKEY_get_raw_public_کلید(pkey, pk, &pklen)) {
		debug3_f("EVP_PKEY_get_raw_public_key failed");
		برو out;
	}
	اگر (pklen != crypto_sign_ed25519_PUBLICKEYBYTES) {
		debug3_f("public key length mismatch: %zu", pklen);
		برو out;
	}

	sklen = SSH_ED25519_RAW_SECRET_کلید_LEN;
	/* Extract private key (32 bytes seed) */
	اگر (!EVP_PKEY_get_raw_private_کلید(pkey, sk, &sklen)) {
		debug3_f("EVP_PKEY_get_raw_private_key failed");
		برو out;
	}
	اگر (sklen != SSH_ED25519_RAW_SECRET_کلید_LEN) {
		debug3_f("private key length mismatch: %zu", sklen);
		برو out;
	}

	/* Append public key to secret key (SUPERCOP format compatibility) */
	memcpy(sk + sklen, pk, crypto_sign_ed25519_PUBLICKEYBYTES);

	ret = 0;
out:
	EVP_PKEY_free(pkey);
	EVP_PKEY_CTX_free(ctx);
	بازگشت ret;
}

صحیح
crypto_sign_ed25519_seed_keypair(unsigned نویسه *pk, unsigned نویسه *sk,
    ثابت unsigned نویسه *seed)
{
	EVP_PKEY *pkey = پوچ;
	size_t pklen;
	صحیح ret = -1;

	اگر ((pkey = EVP_PKEY_new_raw_private_کلید(EVP_PKEY_ED25519, پوچ,
	    seed, SSH_ED25519_RAW_SECRET_کلید_LEN)) == پوچ) {
		debug3_f("EVP_PKEY_new_raw_private_key failed");
		برو out;
	}

	/* Extract public key */
	pklen = crypto_sign_ed25519_PUBLICKEYBYTES;
	اگر (!EVP_PKEY_get_raw_public_کلید(pkey, pk, &pklen)) {
		debug3_f("EVP_PKEY_get_raw_public_key failed");
		برو out;
	}

	/* Build sk = seed || pk */
	memcpy(sk, seed, SSH_ED25519_RAW_SECRET_کلید_LEN);
	memcpy(sk + SSH_ED25519_RAW_SECRET_کلید_LEN, pk,
	    crypto_sign_ed25519_PUBLICKEYBYTES);

	ret = 0;
out:
	EVP_PKEY_free(pkey);
	بازگشت ret;
}

صحیح
crypto_sign_ed25519_detached(unsigned نویسه *sig, unsigned long long *siglenp,
    ثابت unsigned نویسه *m, unsigned long long mlen,
    ثابت unsigned نویسه *sk)
{
	EVP_PKEY *pkey = پوچ;
	EVP_MD_CTX *mdctx = پوچ;
	size_t siglen;
	صحیح ret = -1;

	/* Create EVP_PKEY from secret key (first 32 bytes are the seed) */
	اگر ((pkey = EVP_PKEY_new_raw_private_کلید(EVP_PKEY_ED25519, پوچ,
	    sk, SSH_ED25519_RAW_SECRET_کلید_LEN)) == پوچ) {
		debug3_f("EVP_PKEY_new_raw_private_key failed");
		برو out;
	}

	/* Sign the message */
	اگر ((mdctx = EVP_MD_CTX_new()) == پوچ) {
		debug3_f("EVP_MD_CTX_new failed");
		برو out;
	}
	اگر (EVP_DigestSignInit(mdctx, پوچ, پوچ, پوچ, pkey) != 1) {
		debug3_f("EVP_DigestSignInit failed");
		برو out;
	}
	siglen = crypto_sign_ed25519_BYTES;
	اگر (EVP_DigestSign(mdctx, sig, &siglen, m, mlen) != 1) {
		debug3_f("EVP_DigestSign failed");
		برو out;
	}
	اگر (siglen != crypto_sign_ed25519_BYTES) {
		debug3_f("signature length mismatch: %zu", siglen);
		برو out;
	}

	اگر (siglenp != پوچ)
		*siglenp = siglen;

	ret = 0;
out:
	EVP_MD_CTX_free(mdctx);
	EVP_PKEY_free(pkey);
	بازگشت ret;
}

صحیح
crypto_sign_ed25519_verify_detached(ثابت unsigned نویسه *sig,
    ثابت unsigned نویسه *m, unsigned long long mlen,
    ثابت unsigned نویسه *pk)
{
	EVP_PKEY *pkey = پوچ;
	EVP_MD_CTX *mdctx = پوچ;
	صحیح ret = -1;

	اگر (mlen > SIZE_MAX) {
		debug3_f("message too long: %llu", mlen);
		بازگشت -1;
	}

	/* Create EVP_PKEY from public key */
	اگر ((pkey = EVP_PKEY_new_raw_public_کلید(EVP_PKEY_ED25519, پوچ,
	    pk, crypto_sign_ed25519_PUBLICKEYBYTES)) == پوچ) {
		debug3_f("EVP_PKEY_new_raw_public_key failed");
		برو out;
	}

	اگر ((mdctx = EVP_MD_CTX_new()) == پوچ) {
		debug3_f("EVP_MD_CTX_new failed");
		برو out;
	}
	اگر (EVP_DigestVerifyInit(mdctx, پوچ, پوچ, پوچ, pkey) <= 0) {
		debug3_f("EVP_DigestVerifyInit failed");
		برو out;
	}
	اگر (EVP_DigestVerify(mdctx, sig, crypto_sign_ed25519_BYTES,
	    m, (size_t)mlen) != 1) {
		debug3_f("EVP_DigestVerify failed");
		برو out;
	}

	ret = 0;
out:
	EVP_MD_CTX_free(mdctx);
	EVP_PKEY_free(pkey);
	بازگشت ret;
}

#endif /* OPENSSL_HAS_ED25519 */
