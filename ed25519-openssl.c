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

#అన్తర్భావ "includes.h"

#నిర్వచితమైతే OPENSSL_HAS_ED25519

#అన్తర్భావ <sys/types.h>

#అన్తర్భావ <string.h>
#అన్తర్భావ <stdint.h>
#అన్తర్భావ <limits.h>

#అన్తర్భావ <openssl/evp.h>

#అన్తర్భావ "crypto_api.h"
#అన్తర్భావ "log.h"

#ఒకవేళ crypto_sign_ed25519_SECRETKEYBYTES <= crypto_sign_ed25519_PUBLICKEYBYTES
#దోషం "crypto_sign_ed25519_SECRETKEYBYTES < crypto_sign_ed25519_PUBLICKEYBYTES"
#అయితే_ముగింపు

#నిర్వచించు SSH_ED25519_RAW_SECRET_కీలకం_LEN \
    (crypto_sign_ed25519_SECRETKEYBYTES - crypto_sign_ed25519_PUBLICKEYBYTES)

పూర్ణాంకం
crypto_sign_ed25519_keypair(గుర్తులేని అక్షరం *pk, గుర్తులేని అక్షరం *sk)
{
	EVP_PKEY_CTX *ctx = ఖాళీ;
	EVP_PKEY *pkey = ఖాళీ;
	కొలత_t pklen, sklen;
	పూర్ణాంకం ret = -1;

	ఒకవేళ ((ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, ఖాళీ)) == ఖాళీ) {
		debug3_f("EVP_PKEY_CTX_new_id failed");
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (EVP_PKEY_keygen_init(ctx) <= 0) {
		debug3_f("EVP_PKEY_keygen_init failed");
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
		debug3_f("EVP_PKEY_keygen failed");
		వెళ్ళు బహిర్గతం;
	}

	/* Extract public key */
	pklen = crypto_sign_ed25519_PUBLICKEYBYTES;
	ఒకవేళ (!EVP_PKEY_get_raw_ప్రజా_కీలకం(pkey, pk, &pklen)) {
		debug3_f("EVP_PKEY_get_raw_public_key failed");
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (pklen != crypto_sign_ed25519_PUBLICKEYBYTES) {
		debug3_f("public key length mismatch: %zu", pklen);
		వెళ్ళు బహిర్గతం;
	}

	sklen = SSH_ED25519_RAW_SECRET_కీలకం_LEN;
	/* Extract private key (32 bytes seed) */
	ఒకవేళ (!EVP_PKEY_get_raw_వ్యక్తిగత_కీలకం(pkey, sk, &sklen)) {
		debug3_f("EVP_PKEY_get_raw_private_key failed");
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (sklen != SSH_ED25519_RAW_SECRET_కీలకం_LEN) {
		debug3_f("private key length mismatch: %zu", sklen);
		వెళ్ళు బహిర్గతం;
	}

	/* Append public key to secret key (SUPERCOP format compatibility) */
	జ్ఞాపకం_నకలు(sk + sklen, pk, crypto_sign_ed25519_PUBLICKEYBYTES);

	ret = 0;
బహిర్గతం:
	EVP_PKEY_free(pkey);
	EVP_PKEY_CTX_free(ctx);
	తిరిగి ret;
}

పూర్ణాంకం
crypto_sign_ed25519_విత్తనం_keypair(గుర్తులేని అక్షరం *pk, గుర్తులేని అక్షరం *sk,
    స్థిరరాశి గుర్తులేని అక్షరం *విత్తనం)
{
	EVP_PKEY *pkey = ఖాళీ;
	కొలత_t pklen;
	పూర్ణాంకం ret = -1;

	ఒకవేళ ((pkey = EVP_PKEY_new_raw_వ్యక్తిగత_కీలకం(EVP_PKEY_ED25519, ఖాళీ,
	    విత్తనం, SSH_ED25519_RAW_SECRET_కీలకం_LEN)) == ఖాళీ) {
		debug3_f("EVP_PKEY_new_raw_private_key failed");
		వెళ్ళు బహిర్గతం;
	}

	/* Extract public key */
	pklen = crypto_sign_ed25519_PUBLICKEYBYTES;
	ఒకవేళ (!EVP_PKEY_get_raw_ప్రజా_కీలకం(pkey, pk, &pklen)) {
		debug3_f("EVP_PKEY_get_raw_public_key failed");
		వెళ్ళు బహిర్గతం;
	}

	/* Build sk = seed || pk */
	జ్ఞాపకం_నకలు(sk, విత్తనం, SSH_ED25519_RAW_SECRET_కీలకం_LEN);
	జ్ఞాపకం_నకలు(sk + SSH_ED25519_RAW_SECRET_కీలకం_LEN, pk,
	    crypto_sign_ed25519_PUBLICKEYBYTES);

	ret = 0;
బహిర్గతం:
	EVP_PKEY_free(pkey);
	తిరిగి ret;
}

పూర్ణాంకం
crypto_sign_ed25519_detached(గుర్తులేని అక్షరం *sig, గుర్తులేని దీర్ఘ దీర్ఘ *siglenp,
    స్థిరరాశి గుర్తులేని అక్షరం *m, గుర్తులేని దీర్ఘ దీర్ఘ mlen,
    స్థిరరాశి గుర్తులేని అక్షరం *sk)
{
	EVP_PKEY *pkey = ఖాళీ;
	EVP_MD_CTX *mdctx = ఖాళీ;
	కొలత_t siglen;
	పూర్ణాంకం ret = -1;

	/* Create EVP_PKEY from secret key (first 32 bytes are the seed) */
	ఒకవేళ ((pkey = EVP_PKEY_new_raw_వ్యక్తిగత_కీలకం(EVP_PKEY_ED25519, ఖాళీ,
	    sk, SSH_ED25519_RAW_SECRET_కీలకం_LEN)) == ఖాళీ) {
		debug3_f("EVP_PKEY_new_raw_private_key failed");
		వెళ్ళు బహిర్గతం;
	}

	/* Sign the message */
	ఒకవేళ ((mdctx = EVP_MD_CTX_new()) == ఖాళీ) {
		debug3_f("EVP_MD_CTX_new failed");
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (EVP_DigestSignInit(mdctx, ఖాళీ, ఖాళీ, ఖాళీ, pkey) != 1) {
		debug3_f("EVP_DigestSignInit failed");
		వెళ్ళు బహిర్గతం;
	}
	siglen = crypto_sign_ed25519_బైట్లు;
	ఒకవేళ (EVP_DigestSign(mdctx, sig, &siglen, m, mlen) != 1) {
		debug3_f("EVP_DigestSign failed");
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (siglen != crypto_sign_ed25519_బైట్లు) {
		debug3_f("signature length mismatch: %zu", siglen);
		వెళ్ళు బహిర్గతం;
	}

	ఒకవేళ (siglenp != ఖాళీ)
		*siglenp = siglen;

	ret = 0;
బహిర్గతం:
	EVP_MD_CTX_free(mdctx);
	EVP_PKEY_free(pkey);
	తిరిగి ret;
}

పూర్ణాంకం
crypto_sign_ed25519_verify_detached(స్థిరరాశి గుర్తులేని అక్షరం *sig,
    స్థిరరాశి గుర్తులేని అక్షరం *m, గుర్తులేని దీర్ఘ దీర్ఘ mlen,
    స్థిరరాశి గుర్తులేని అక్షరం *pk)
{
	EVP_PKEY *pkey = ఖాళీ;
	EVP_MD_CTX *mdctx = ఖాళీ;
	పూర్ణాంకం ret = -1;

	ఒకవేళ (mlen > SIZE_MAX) {
		debug3_f("message too long: %llu", mlen);
		తిరిగి -1;
	}

	/* Create EVP_PKEY from public key */
	ఒకవేళ ((pkey = EVP_PKEY_new_raw_ప్రజా_కీలకం(EVP_PKEY_ED25519, ఖాళీ,
	    pk, crypto_sign_ed25519_PUBLICKEYBYTES)) == ఖాళీ) {
		debug3_f("EVP_PKEY_new_raw_public_key failed");
		వెళ్ళు బహిర్గతం;
	}

	ఒకవేళ ((mdctx = EVP_MD_CTX_new()) == ఖాళీ) {
		debug3_f("EVP_MD_CTX_new failed");
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (EVP_DigestVerifyInit(mdctx, ఖాళీ, ఖాళీ, ఖాళీ, pkey) <= 0) {
		debug3_f("EVP_DigestVerifyInit failed");
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (EVP_DigestVerify(mdctx, sig, crypto_sign_ed25519_బైట్లు,
	    m, (కొలత_t)mlen) != 1) {
		debug3_f("EVP_DigestVerify failed");
		వెళ్ళు బహిర్గతం;
	}

	ret = 0;
బహిర్గతం:
	EVP_MD_CTX_free(mdctx);
	EVP_PKEY_free(pkey);
	తిరిగి ret;
}

#అయితే_ముగింపు /* OPENSSL_HAS_ED25519 */
