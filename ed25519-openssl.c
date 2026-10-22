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

#ضمن "includes.h"

#جيڪڏهن_وصف_ٿيل OPENSSL_HAS_ED25519

#ضمن <sys/types.h>

#ضمن <string.h>
#ضمن <stdint.h>
#ضمن <limits.h>

#ضمن <openssl/evp.h>

#ضمن "crypto_api.h"
#ضمن "log.h"

#إذا crypto_sign_ed25519_SECRETKEYBYTES <= crypto_sign_ed25519_PUBLICKEYBYTES
#غلطي "crypto_sign_ed25519_SECRETKEYBYTES < crypto_sign_ed25519_PUBLICKEYBYTES"
#جيڪڏهن_پورو

#وصف_ڪريو SSH_ED25519_RAW_SECRET_ڪنجي_LEN \
    (crypto_sign_ed25519_SECRETKEYBYTES - crypto_sign_ed25519_PUBLICKEYBYTES)

صحيح
crypto_sign_ed25519_keypair(بنانشان حرف *pk, بنانشان حرف *sk)
{
	EVP_PKEY_CTX *ctx = عدم;
	EVP_PKEY *pkey = عدم;
	سائيز_t pklen, sklen;
	صحيح ret = -1;

	إذا ((ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, عدم)) == عدم) {
		debug3_f("EVP_PKEY_CTX_new_id failed");
		اذهب ٻاهريون;
	}
	إذا (EVP_PKEY_keygen_init(ctx) <= 0) {
		debug3_f("EVP_PKEY_keygen_init failed");
		اذهب ٻاهريون;
	}
	إذا (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
		debug3_f("EVP_PKEY_keygen failed");
		اذهب ٻاهريون;
	}

	/* Extract public key */
	pklen = crypto_sign_ed25519_PUBLICKEYBYTES;
	إذا (!EVP_PKEY_get_raw_عوامي_ڪنجي(pkey, pk, &pklen)) {
		debug3_f("EVP_PKEY_get_raw_public_key failed");
		اذهب ٻاهريون;
	}
	إذا (pklen != crypto_sign_ed25519_PUBLICKEYBYTES) {
		debug3_f("public key length mismatch: %zu", pklen);
		اذهب ٻاهريون;
	}

	sklen = SSH_ED25519_RAW_SECRET_ڪنجي_LEN;
	/* Extract private key (32 bytes seed) */
	إذا (!EVP_PKEY_get_raw_ذاتي_ڪنجي(pkey, sk, &sklen)) {
		debug3_f("EVP_PKEY_get_raw_private_key failed");
		اذهب ٻاهريون;
	}
	إذا (sklen != SSH_ED25519_RAW_SECRET_ڪنجي_LEN) {
		debug3_f("private key length mismatch: %zu", sklen);
		اذهب ٻاهريون;
	}

	/* Append public key to secret key (SUPERCOP format compatibility) */
	يادگيري_نقل(sk + sklen, pk, crypto_sign_ed25519_PUBLICKEYBYTES);

	ret = 0;
ٻاهريون:
	EVP_PKEY_free(pkey);
	EVP_PKEY_CTX_free(ctx);
	أرجع ret;
}

صحيح
crypto_sign_ed25519_ٻج_keypair(بنانشان حرف *pk, بنانشان حرف *sk,
    ثابت بنانشان حرف *ٻج)
{
	EVP_PKEY *pkey = عدم;
	سائيز_t pklen;
	صحيح ret = -1;

	إذا ((pkey = EVP_PKEY_new_raw_ذاتي_ڪنجي(EVP_PKEY_ED25519, عدم,
	    ٻج, SSH_ED25519_RAW_SECRET_ڪنجي_LEN)) == عدم) {
		debug3_f("EVP_PKEY_new_raw_private_key failed");
		اذهب ٻاهريون;
	}

	/* Extract public key */
	pklen = crypto_sign_ed25519_PUBLICKEYBYTES;
	إذا (!EVP_PKEY_get_raw_عوامي_ڪنجي(pkey, pk, &pklen)) {
		debug3_f("EVP_PKEY_get_raw_public_key failed");
		اذهب ٻاهريون;
	}

	/* Build sk = seed || pk */
	يادگيري_نقل(sk, ٻج, SSH_ED25519_RAW_SECRET_ڪنجي_LEN);
	يادگيري_نقل(sk + SSH_ED25519_RAW_SECRET_ڪنجي_LEN, pk,
	    crypto_sign_ed25519_PUBLICKEYBYTES);

	ret = 0;
ٻاهريون:
	EVP_PKEY_free(pkey);
	أرجع ret;
}

صحيح
crypto_sign_ed25519_detached(بنانشان حرف *sig, بنانشان ڊگهو ڊگهو *siglenp,
    ثابت بنانشان حرف *m, بنانشان ڊگهو ڊگهو mlen,
    ثابت بنانشان حرف *sk)
{
	EVP_PKEY *pkey = عدم;
	EVP_MD_CTX *mdctx = عدم;
	سائيز_t siglen;
	صحيح ret = -1;

	/* Create EVP_PKEY from secret key (first 32 bytes are the seed) */
	إذا ((pkey = EVP_PKEY_new_raw_ذاتي_ڪنجي(EVP_PKEY_ED25519, عدم,
	    sk, SSH_ED25519_RAW_SECRET_ڪنجي_LEN)) == عدم) {
		debug3_f("EVP_PKEY_new_raw_private_key failed");
		اذهب ٻاهريون;
	}

	/* Sign the message */
	إذا ((mdctx = EVP_MD_CTX_new()) == عدم) {
		debug3_f("EVP_MD_CTX_new failed");
		اذهب ٻاهريون;
	}
	إذا (EVP_DigestSignInit(mdctx, عدم, عدم, عدم, pkey) != 1) {
		debug3_f("EVP_DigestSignInit failed");
		اذهب ٻاهريون;
	}
	siglen = crypto_sign_ed25519_بائيٽون;
	إذا (EVP_DigestSign(mdctx, sig, &siglen, m, mlen) != 1) {
		debug3_f("EVP_DigestSign failed");
		اذهب ٻاهريون;
	}
	إذا (siglen != crypto_sign_ed25519_بائيٽون) {
		debug3_f("signature length mismatch: %zu", siglen);
		اذهب ٻاهريون;
	}

	إذا (siglenp != عدم)
		*siglenp = siglen;

	ret = 0;
ٻاهريون:
	EVP_MD_CTX_free(mdctx);
	EVP_PKEY_free(pkey);
	أرجع ret;
}

صحيح
crypto_sign_ed25519_verify_detached(ثابت بنانشان حرف *sig,
    ثابت بنانشان حرف *m, بنانشان ڊگهو ڊگهو mlen,
    ثابت بنانشان حرف *pk)
{
	EVP_PKEY *pkey = عدم;
	EVP_MD_CTX *mdctx = عدم;
	صحيح ret = -1;

	إذا (mlen > SIZE_MAX) {
		debug3_f("message too long: %llu", mlen);
		أرجع -1;
	}

	/* Create EVP_PKEY from public key */
	إذا ((pkey = EVP_PKEY_new_raw_عوامي_ڪنجي(EVP_PKEY_ED25519, عدم,
	    pk, crypto_sign_ed25519_PUBLICKEYBYTES)) == عدم) {
		debug3_f("EVP_PKEY_new_raw_public_key failed");
		اذهب ٻاهريون;
	}

	إذا ((mdctx = EVP_MD_CTX_new()) == عدم) {
		debug3_f("EVP_MD_CTX_new failed");
		اذهب ٻاهريون;
	}
	إذا (EVP_DigestVerifyInit(mdctx, عدم, عدم, عدم, pkey) <= 0) {
		debug3_f("EVP_DigestVerifyInit failed");
		اذهب ٻاهريون;
	}
	إذا (EVP_DigestVerify(mdctx, sig, crypto_sign_ed25519_بائيٽون,
	    m, (سائيز_t)mlen) != 1) {
		debug3_f("EVP_DigestVerify failed");
		اذهب ٻاهريون;
	}

	ret = 0;
ٻاهريون:
	EVP_MD_CTX_free(mdctx);
	EVP_PKEY_free(pkey);
	أرجع ret;
}

#جيڪڏهن_پورو /* OPENSSL_HAS_ED25519 */
