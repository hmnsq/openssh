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

#अन्तर्भाव "includes.h"

#ifdef OPENSSL_HAS_ED25519

#अन्तर्भाव <sys/types.h>

#अन्तर्भाव <string.h>
#अन्तर्भाव <stdint.h>
#अन्तर्भाव <limits.h>

#अन्तर्भाव <openssl/evp.h>

#अन्तर्भाव "crypto_api.h"
#अन्तर्भाव "log.h"

#यदि crypto_sign_ed25519_SECRETKEYBYTES <= crypto_sign_ed25519_PUBLICKEYBYTES
#error "crypto_sign_ed25519_SECRETKEYBYTES < crypto_sign_ed25519_PUBLICKEYBYTES"
#endif

#define SSH_ED25519_RAW_SECRET_कुंजी_LEN \
    (crypto_sign_ed25519_SECRETKEYBYTES - crypto_sign_ed25519_PUBLICKEYBYTES)

पूर्णाङ्क
crypto_sign_ed25519_keypair(अचिन्हित वर्ण *pk, अचिन्हित वर्ण *sk)
{
	EVP_PKEY_CTX *ctx = रिक्त;
	EVP_PKEY *pkey = रिक्त;
	माप_प्रकार pklen, sklen;
	पूर्णाङ्क ret = -1;

	यदि ((ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, रिक्त)) == रिक्त) {
		debug3_f("EVP_PKEY_CTX_new_id failed");
		गच्छ out;
	}
	यदि (EVP_PKEY_keygen_init(ctx) <= 0) {
		debug3_f("EVP_PKEY_keygen_init failed");
		गच्छ out;
	}
	यदि (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
		debug3_f("EVP_PKEY_keygen failed");
		गच्छ out;
	}

	/* Extract public key */
	pklen = crypto_sign_ed25519_PUBLICKEYBYTES;
	यदि (!EVP_PKEY_get_raw_public_कुंजी(pkey, pk, &pklen)) {
		debug3_f("EVP_PKEY_get_raw_public_key failed");
		गच्छ out;
	}
	यदि (pklen != crypto_sign_ed25519_PUBLICKEYBYTES) {
		debug3_f("public key length mismatch: %zu", pklen);
		गच्छ out;
	}

	sklen = SSH_ED25519_RAW_SECRET_कुंजी_LEN;
	/* Extract private key (32 bytes seed) */
	यदि (!EVP_PKEY_get_raw_private_कुंजी(pkey, sk, &sklen)) {
		debug3_f("EVP_PKEY_get_raw_private_key failed");
		गच्छ out;
	}
	यदि (sklen != SSH_ED25519_RAW_SECRET_कुंजी_LEN) {
		debug3_f("private key length mismatch: %zu", sklen);
		गच्छ out;
	}

	/* Append public key to secret key (SUPERCOP format compatibility) */
	स_नकल(sk + sklen, pk, crypto_sign_ed25519_PUBLICKEYBYTES);

	ret = 0;
out:
	EVP_PKEY_free(pkey);
	EVP_PKEY_CTX_free(ctx);
	प्रत्यागम ret;
}

पूर्णाङ्क
crypto_sign_ed25519_seed_keypair(अचिन्हित वर्ण *pk, अचिन्हित वर्ण *sk,
    ध्रुव अचिन्हित वर्ण *seed)
{
	EVP_PKEY *pkey = रिक्त;
	माप_प्रकार pklen;
	पूर्णाङ्क ret = -1;

	यदि ((pkey = EVP_PKEY_new_raw_private_कुंजी(EVP_PKEY_ED25519, रिक्त,
	    seed, SSH_ED25519_RAW_SECRET_कुंजी_LEN)) == रिक्त) {
		debug3_f("EVP_PKEY_new_raw_private_key failed");
		गच्छ out;
	}

	/* Extract public key */
	pklen = crypto_sign_ed25519_PUBLICKEYBYTES;
	यदि (!EVP_PKEY_get_raw_public_कुंजी(pkey, pk, &pklen)) {
		debug3_f("EVP_PKEY_get_raw_public_key failed");
		गच्छ out;
	}

	/* Build sk = seed || pk */
	स_नकल(sk, seed, SSH_ED25519_RAW_SECRET_कुंजी_LEN);
	स_नकल(sk + SSH_ED25519_RAW_SECRET_कुंजी_LEN, pk,
	    crypto_sign_ed25519_PUBLICKEYBYTES);

	ret = 0;
out:
	EVP_PKEY_free(pkey);
	प्रत्यागम ret;
}

पूर्णाङ्क
crypto_sign_ed25519_detached(अचिन्हित वर्ण *sig, अचिन्हित दीर्घ दीर्घ *siglenp,
    ध्रुव अचिन्हित वर्ण *m, अचिन्हित दीर्घ दीर्घ mlen,
    ध्रुव अचिन्हित वर्ण *sk)
{
	EVP_PKEY *pkey = रिक्त;
	EVP_MD_CTX *mdctx = रिक्त;
	माप_प्रकार siglen;
	पूर्णाङ्क ret = -1;

	/* Create EVP_PKEY from secret key (first 32 bytes are the seed) */
	यदि ((pkey = EVP_PKEY_new_raw_private_कुंजी(EVP_PKEY_ED25519, रिक्त,
	    sk, SSH_ED25519_RAW_SECRET_कुंजी_LEN)) == रिक्त) {
		debug3_f("EVP_PKEY_new_raw_private_key failed");
		गच्छ out;
	}

	/* Sign the message */
	यदि ((mdctx = EVP_MD_CTX_new()) == रिक्त) {
		debug3_f("EVP_MD_CTX_new failed");
		गच्छ out;
	}
	यदि (EVP_DigestSignInit(mdctx, रिक्त, रिक्त, रिक्त, pkey) != 1) {
		debug3_f("EVP_DigestSignInit failed");
		गच्छ out;
	}
	siglen = crypto_sign_ed25519_BYTES;
	यदि (EVP_DigestSign(mdctx, sig, &siglen, m, mlen) != 1) {
		debug3_f("EVP_DigestSign failed");
		गच्छ out;
	}
	यदि (siglen != crypto_sign_ed25519_BYTES) {
		debug3_f("signature length mismatch: %zu", siglen);
		गच्छ out;
	}

	यदि (siglenp != रिक्त)
		*siglenp = siglen;

	ret = 0;
out:
	EVP_MD_CTX_free(mdctx);
	EVP_PKEY_free(pkey);
	प्रत्यागम ret;
}

पूर्णाङ्क
crypto_sign_ed25519_verify_detached(ध्रुव अचिन्हित वर्ण *sig,
    ध्रुव अचिन्हित वर्ण *m, अचिन्हित दीर्घ दीर्घ mlen,
    ध्रुव अचिन्हित वर्ण *pk)
{
	EVP_PKEY *pkey = रिक्त;
	EVP_MD_CTX *mdctx = रिक्त;
	पूर्णाङ्क ret = -1;

	यदि (mlen > SIZE_MAX) {
		debug3_f("message too long: %llu", mlen);
		प्रत्यागम -1;
	}

	/* Create EVP_PKEY from public key */
	यदि ((pkey = EVP_PKEY_new_raw_public_कुंजी(EVP_PKEY_ED25519, रिक्त,
	    pk, crypto_sign_ed25519_PUBLICKEYBYTES)) == रिक्त) {
		debug3_f("EVP_PKEY_new_raw_public_key failed");
		गच्छ out;
	}

	यदि ((mdctx = EVP_MD_CTX_new()) == रिक्त) {
		debug3_f("EVP_MD_CTX_new failed");
		गच्छ out;
	}
	यदि (EVP_DigestVerifyInit(mdctx, रिक्त, रिक्त, रिक्त, pkey) <= 0) {
		debug3_f("EVP_DigestVerifyInit failed");
		गच्छ out;
	}
	यदि (EVP_DigestVerify(mdctx, sig, crypto_sign_ed25519_BYTES,
	    m, (माप_प्रकार)mlen) != 1) {
		debug3_f("EVP_DigestVerify failed");
		गच्छ out;
	}

	ret = 0;
out:
	EVP_MD_CTX_free(mdctx);
	EVP_PKEY_free(pkey);
	प्रत्यागम ret;
}

#endif /* OPENSSL_HAS_ED25519 */
