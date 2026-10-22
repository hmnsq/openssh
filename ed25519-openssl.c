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

#यदि_परिभाषितम् OPENSSL_HAS_ED25519

#अन्तर्भाव <sys/types.h>

#अन्तर्भाव <string.h>
#अन्तर्भाव <stdint.h>
#अन्तर्भाव <limits.h>

#अन्तर्भाव <openssl/evp.h>

#अन्तर्भाव "crypto_api.h"
#अन्तर्भाव "log.h"

#यदि crypto_sign_ed25519_SECRETKEYBYTES <= crypto_sign_ed25519_PUBLICKEYBYTES
#दोषः "crypto_sign_ed25519_SECRETKEYBYTES < crypto_sign_ed25519_PUBLICKEYBYTES"
#यदि_अन्तः

#परिभाषय SSH_ED25519_RAW_SECRET_कुञ्चिका_LEN \
    (crypto_sign_ed25519_SECRETKEYBYTES - crypto_sign_ed25519_PUBLICKEYBYTES)

पूर्णाङ्क
crypto_sign_ed25519_keypair(अचिह्नित वर्ण *pk, अचिह्नित वर्ण *sk)
{
	EVP_PKEY_CTX *ctx = रिक्त;
	EVP_PKEY *pkey = रिक्त;
	आकार_t pklen, sklen;
	पूर्णाङ्क ret = -1;

	यदि ((ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, रिक्त)) == रिक्त) {
		debug3_f("EVP_PKEY_CTX_new_id failed");
		गच्छ बहिर्गमनम्;
	}
	यदि (EVP_PKEY_keygen_init(ctx) <= 0) {
		debug3_f("EVP_PKEY_keygen_init failed");
		गच्छ बहिर्गमनम्;
	}
	यदि (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
		debug3_f("EVP_PKEY_keygen failed");
		गच्छ बहिर्गमनम्;
	}

	/* Extract public key */
	pklen = crypto_sign_ed25519_PUBLICKEYBYTES;
	यदि (!EVP_PKEY_get_raw_लौकिकम्_कुञ्चिका(pkey, pk, &pklen)) {
		debug3_f("EVP_PKEY_get_raw_public_key failed");
		गच्छ बहिर्गमनम्;
	}
	यदि (pklen != crypto_sign_ed25519_PUBLICKEYBYTES) {
		debug3_f("public key length mismatch: %zu", pklen);
		गच्छ बहिर्गमनम्;
	}

	sklen = SSH_ED25519_RAW_SECRET_कुञ्चिका_LEN;
	/* Extract private key (32 bytes seed) */
	यदि (!EVP_PKEY_get_raw_वैयक्तिकम्_कुञ्चिका(pkey, sk, &sklen)) {
		debug3_f("EVP_PKEY_get_raw_private_key failed");
		गच्छ बहिर्गमनम्;
	}
	यदि (sklen != SSH_ED25519_RAW_SECRET_कुञ्चिका_LEN) {
		debug3_f("private key length mismatch: %zu", sklen);
		गच्छ बहिर्गमनम्;
	}

	/* Append public key to secret key (SUPERCOP format compatibility) */
	स्मृतिं_प्रतिलिख(sk + sklen, pk, crypto_sign_ed25519_PUBLICKEYBYTES);

	ret = 0;
बहिर्गमनम्:
	EVP_PKEY_free(pkey);
	EVP_PKEY_CTX_free(ctx);
	प्रत्यागम ret;
}

पूर्णाङ्क
crypto_sign_ed25519_बीजम्_keypair(अचिह्नित वर्ण *pk, अचिह्नित वर्ण *sk,
    ध्रुव अचिह्नित वर्ण *बीजम्)
{
	EVP_PKEY *pkey = रिक्त;
	आकार_t pklen;
	पूर्णाङ्क ret = -1;

	यदि ((pkey = EVP_PKEY_new_raw_वैयक्तिकम्_कुञ्चिका(EVP_PKEY_ED25519, रिक्त,
	    बीजम्, SSH_ED25519_RAW_SECRET_कुञ्चिका_LEN)) == रिक्त) {
		debug3_f("EVP_PKEY_new_raw_private_key failed");
		गच्छ बहिर्गमनम्;
	}

	/* Extract public key */
	pklen = crypto_sign_ed25519_PUBLICKEYBYTES;
	यदि (!EVP_PKEY_get_raw_लौकिकम्_कुञ्चिका(pkey, pk, &pklen)) {
		debug3_f("EVP_PKEY_get_raw_public_key failed");
		गच्छ बहिर्गमनम्;
	}

	/* Build sk = seed || pk */
	स्मृतिं_प्रतिलिख(sk, बीजम्, SSH_ED25519_RAW_SECRET_कुञ्चिका_LEN);
	स्मृतिं_प्रतिलिख(sk + SSH_ED25519_RAW_SECRET_कुञ्चिका_LEN, pk,
	    crypto_sign_ed25519_PUBLICKEYBYTES);

	ret = 0;
बहिर्गमनम्:
	EVP_PKEY_free(pkey);
	प्रत्यागम ret;
}

पूर्णाङ्क
crypto_sign_ed25519_detached(अचिह्नित वर्ण *sig, अचिह्नित दीर्घ दीर्घ *siglenp,
    ध्रुव अचिह्नित वर्ण *m, अचिह्नित दीर्घ दीर्घ mlen,
    ध्रुव अचिह्नित वर्ण *sk)
{
	EVP_PKEY *pkey = रिक्त;
	EVP_MD_CTX *mdctx = रिक्त;
	आकार_t siglen;
	पूर्णाङ्क ret = -1;

	/* Create EVP_PKEY from secret key (first 32 bytes are the seed) */
	यदि ((pkey = EVP_PKEY_new_raw_वैयक्तिकम्_कुञ्चिका(EVP_PKEY_ED25519, रिक्त,
	    sk, SSH_ED25519_RAW_SECRET_कुञ्चिका_LEN)) == रिक्त) {
		debug3_f("EVP_PKEY_new_raw_private_key failed");
		गच्छ बहिर्गमनम्;
	}

	/* Sign the message */
	यदि ((mdctx = EVP_MD_CTX_new()) == रिक्त) {
		debug3_f("EVP_MD_CTX_new failed");
		गच्छ बहिर्गमनम्;
	}
	यदि (EVP_DigestSignInit(mdctx, रिक्त, रिक्त, रिक्त, pkey) != 1) {
		debug3_f("EVP_DigestSignInit failed");
		गच्छ बहिर्गमनम्;
	}
	siglen = crypto_sign_ed25519_अष्टकानि;
	यदि (EVP_DigestSign(mdctx, sig, &siglen, m, mlen) != 1) {
		debug3_f("EVP_DigestSign failed");
		गच्छ बहिर्गमनम्;
	}
	यदि (siglen != crypto_sign_ed25519_अष्टकानि) {
		debug3_f("signature length mismatch: %zu", siglen);
		गच्छ बहिर्गमनम्;
	}

	यदि (siglenp != रिक्त)
		*siglenp = siglen;

	ret = 0;
बहिर्गमनम्:
	EVP_MD_CTX_free(mdctx);
	EVP_PKEY_free(pkey);
	प्रत्यागम ret;
}

पूर्णाङ्क
crypto_sign_ed25519_verify_detached(ध्रुव अचिह्नित वर्ण *sig,
    ध्रुव अचिह्नित वर्ण *m, अचिह्नित दीर्घ दीर्घ mlen,
    ध्रुव अचिह्नित वर्ण *pk)
{
	EVP_PKEY *pkey = रिक्त;
	EVP_MD_CTX *mdctx = रिक्त;
	पूर्णाङ्क ret = -1;

	यदि (mlen > SIZE_MAX) {
		debug3_f("message too long: %llu", mlen);
		प्रत्यागम -1;
	}

	/* Create EVP_PKEY from public key */
	यदि ((pkey = EVP_PKEY_new_raw_लौकिकम्_कुञ्चिका(EVP_PKEY_ED25519, रिक्त,
	    pk, crypto_sign_ed25519_PUBLICKEYBYTES)) == रिक्त) {
		debug3_f("EVP_PKEY_new_raw_public_key failed");
		गच्छ बहिर्गमनम्;
	}

	यदि ((mdctx = EVP_MD_CTX_new()) == रिक्त) {
		debug3_f("EVP_MD_CTX_new failed");
		गच्छ बहिर्गमनम्;
	}
	यदि (EVP_DigestVerifyInit(mdctx, रिक्त, रिक्त, रिक्त, pkey) <= 0) {
		debug3_f("EVP_DigestVerifyInit failed");
		गच्छ बहिर्गमनम्;
	}
	यदि (EVP_DigestVerify(mdctx, sig, crypto_sign_ed25519_अष्टकानि,
	    m, (आकार_t)mlen) != 1) {
		debug3_f("EVP_DigestVerify failed");
		गच्छ बहिर्गमनम्;
	}

	ret = 0;
बहिर्गमनम्:
	EVP_MD_CTX_free(mdctx);
	EVP_PKEY_free(pkey);
	प्रत्यागम ret;
}

#यदि_अन्तः /* OPENSSL_HAS_ED25519 */
