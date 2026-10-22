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

#اگر_تعریف_شدہ OPENSSL_HAS_ED25519

#شامل <sys/types.h>

#شامل <string.h>
#شامل <stdint.h>
#شامل <limits.h>

#شامل <openssl/evp.h>

#شامل "crypto_api.h"
#شامل "log.h"

#اگر crypto_sign_ed25519_SECRETKEYBYTES <= crypto_sign_ed25519_PUBLICKEYBYTES
#غلطی "crypto_sign_ed25519_SECRETKEYBYTES < crypto_sign_ed25519_PUBLICKEYBYTES"
#اگر_ختم

#تعریف_کرو SSH_ED25519_RAW_SECRET_کلید_LEN \
    (crypto_sign_ed25519_SECRETKEYBYTES - crypto_sign_ed25519_PUBLICKEYBYTES)

صحیح
crypto_sign_ed25519_keypair(غیرعلامتی حرف *pk, غیرعلامتی حرف *sk)
{
	EVP_PKEY_CTX *ctx = تہی;
	EVP_PKEY *pkey = تہی;
	سائز_t pklen, sklen;
	صحیح ret = -1;

	اگر ((ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, تہی)) == تہی) {
		debug3_f("EVP_PKEY_CTX_new_id failed");
		جاؤ برآمد;
	}
	اگر (EVP_PKEY_keygen_init(ctx) <= 0) {
		debug3_f("EVP_PKEY_keygen_init failed");
		جاؤ برآمد;
	}
	اگر (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
		debug3_f("EVP_PKEY_keygen failed");
		جاؤ برآمد;
	}

	/* Extract public key */
	pklen = crypto_sign_ed25519_PUBLICKEYBYTES;
	اگر (!EVP_PKEY_get_raw_عوامی_کلید(pkey, pk, &pklen)) {
		debug3_f("EVP_PKEY_get_raw_public_key failed");
		جاؤ برآمد;
	}
	اگر (pklen != crypto_sign_ed25519_PUBLICKEYBYTES) {
		debug3_f("public key length mismatch: %zu", pklen);
		جاؤ برآمد;
	}

	sklen = SSH_ED25519_RAW_SECRET_کلید_LEN;
	/* Extract private key (32 bytes seed) */
	اگر (!EVP_PKEY_get_raw_نجی_کلید(pkey, sk, &sklen)) {
		debug3_f("EVP_PKEY_get_raw_private_key failed");
		جاؤ برآمد;
	}
	اگر (sklen != SSH_ED25519_RAW_SECRET_کلید_LEN) {
		debug3_f("private key length mismatch: %zu", sklen);
		جاؤ برآمد;
	}

	/* Append public key to secret key (SUPERCOP format compatibility) */
	حافظہ_نقل(sk + sklen, pk, crypto_sign_ed25519_PUBLICKEYBYTES);

	ret = 0;
برآمد:
	EVP_PKEY_free(pkey);
	EVP_PKEY_CTX_free(ctx);
	واپس ret;
}

صحیح
crypto_sign_ed25519_بیج_keypair(غیرعلامتی حرف *pk, غیرعلامتی حرف *sk,
    ثابت غیرعلامتی حرف *بیج)
{
	EVP_PKEY *pkey = تہی;
	سائز_t pklen;
	صحیح ret = -1;

	اگر ((pkey = EVP_PKEY_new_raw_نجی_کلید(EVP_PKEY_ED25519, تہی,
	    بیج, SSH_ED25519_RAW_SECRET_کلید_LEN)) == تہی) {
		debug3_f("EVP_PKEY_new_raw_private_key failed");
		جاؤ برآمد;
	}

	/* Extract public key */
	pklen = crypto_sign_ed25519_PUBLICKEYBYTES;
	اگر (!EVP_PKEY_get_raw_عوامی_کلید(pkey, pk, &pklen)) {
		debug3_f("EVP_PKEY_get_raw_public_key failed");
		جاؤ برآمد;
	}

	/* Build sk = seed || pk */
	حافظہ_نقل(sk, بیج, SSH_ED25519_RAW_SECRET_کلید_LEN);
	حافظہ_نقل(sk + SSH_ED25519_RAW_SECRET_کلید_LEN, pk,
	    crypto_sign_ed25519_PUBLICKEYBYTES);

	ret = 0;
برآمد:
	EVP_PKEY_free(pkey);
	واپس ret;
}

صحیح
crypto_sign_ed25519_detached(غیرعلامتی حرف *sig, غیرعلامتی طویل طویل *siglenp,
    ثابت غیرعلامتی حرف *m, غیرعلامتی طویل طویل mlen,
    ثابت غیرعلامتی حرف *sk)
{
	EVP_PKEY *pkey = تہی;
	EVP_MD_CTX *mdctx = تہی;
	سائز_t siglen;
	صحیح ret = -1;

	/* Create EVP_PKEY from secret key (first 32 bytes are the seed) */
	اگر ((pkey = EVP_PKEY_new_raw_نجی_کلید(EVP_PKEY_ED25519, تہی,
	    sk, SSH_ED25519_RAW_SECRET_کلید_LEN)) == تہی) {
		debug3_f("EVP_PKEY_new_raw_private_key failed");
		جاؤ برآمد;
	}

	/* Sign the message */
	اگر ((mdctx = EVP_MD_CTX_new()) == تہی) {
		debug3_f("EVP_MD_CTX_new failed");
		جاؤ برآمد;
	}
	اگر (EVP_DigestSignInit(mdctx, تہی, تہی, تہی, pkey) != 1) {
		debug3_f("EVP_DigestSignInit failed");
		جاؤ برآمد;
	}
	siglen = crypto_sign_ed25519_بائٹیں;
	اگر (EVP_DigestSign(mdctx, sig, &siglen, m, mlen) != 1) {
		debug3_f("EVP_DigestSign failed");
		جاؤ برآمد;
	}
	اگر (siglen != crypto_sign_ed25519_بائٹیں) {
		debug3_f("signature length mismatch: %zu", siglen);
		جاؤ برآمد;
	}

	اگر (siglenp != تہی)
		*siglenp = siglen;

	ret = 0;
برآمد:
	EVP_MD_CTX_free(mdctx);
	EVP_PKEY_free(pkey);
	واپس ret;
}

صحیح
crypto_sign_ed25519_verify_detached(ثابت غیرعلامتی حرف *sig,
    ثابت غیرعلامتی حرف *m, غیرعلامتی طویل طویل mlen,
    ثابت غیرعلامتی حرف *pk)
{
	EVP_PKEY *pkey = تہی;
	EVP_MD_CTX *mdctx = تہی;
	صحیح ret = -1;

	اگر (mlen > SIZE_MAX) {
		debug3_f("message too long: %llu", mlen);
		واپس -1;
	}

	/* Create EVP_PKEY from public key */
	اگر ((pkey = EVP_PKEY_new_raw_عوامی_کلید(EVP_PKEY_ED25519, تہی,
	    pk, crypto_sign_ed25519_PUBLICKEYBYTES)) == تہی) {
		debug3_f("EVP_PKEY_new_raw_public_key failed");
		جاؤ برآمد;
	}

	اگر ((mdctx = EVP_MD_CTX_new()) == تہی) {
		debug3_f("EVP_MD_CTX_new failed");
		جاؤ برآمد;
	}
	اگر (EVP_DigestVerifyInit(mdctx, تہی, تہی, تہی, pkey) <= 0) {
		debug3_f("EVP_DigestVerifyInit failed");
		جاؤ برآمد;
	}
	اگر (EVP_DigestVerify(mdctx, sig, crypto_sign_ed25519_بائٹیں,
	    m, (سائز_t)mlen) != 1) {
		debug3_f("EVP_DigestVerify failed");
		جاؤ برآمد;
	}

	ret = 0;
برآمد:
	EVP_MD_CTX_free(mdctx);
	EVP_PKEY_free(pkey);
	واپس ret;
}

#اگر_ختم /* OPENSSL_HAS_ED25519 */
