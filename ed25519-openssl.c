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

#समावेश "includes.h"

#अगर_घोषित OPENSSL_HAS_ED25519

#समावेश <sys/types.h>

#समावेश <string.h>
#समावेश <stdint.h>
#समावेश <limits.h>

#समावेश <openssl/evp.h>

#समावेश "crypto_api.h"
#समावेश "log.h"

#अगर crypto_sign_ed25519_SECRETKEYBYTES <= crypto_sign_ed25519_PUBLICKEYBYTES
#त्रुटि "crypto_sign_ed25519_SECRETKEYBYTES < crypto_sign_ed25519_PUBLICKEYBYTES"
#पूर्ण_अगर

#घोषणा SSH_ED25519_RAW_SECRET_कुंजी_LEN \
    (crypto_sign_ed25519_SECRETKEYBYTES - crypto_sign_ed25519_PUBLICKEYBYTES)

पूर्णांक
crypto_sign_ed25519_keypair(अचिन्हित अक्षर *pk, अचिन्हित अक्षर *sk)
{
	EVP_PKEY_CTX *ctx = शून्य;
	EVP_PKEY *pkey = शून्य;
	माप_प्रकार pklen, sklen;
	पूर्णांक ret = -1;

	अगर ((ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, शून्य)) == शून्य) {
		debug3_f("EVP_PKEY_CTX_new_id failed");
		जाओ out;
	}
	अगर (EVP_PKEY_keygen_init(ctx) <= 0) {
		debug3_f("EVP_PKEY_keygen_init failed");
		जाओ out;
	}
	अगर (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
		debug3_f("EVP_PKEY_keygen failed");
		जाओ out;
	}

	/* Extract public key */
	pklen = crypto_sign_ed25519_PUBLICKEYBYTES;
	अगर (!EVP_PKEY_get_raw_public_कुंजी(pkey, pk, &pklen)) {
		debug3_f("EVP_PKEY_get_raw_public_key failed");
		जाओ out;
	}
	अगर (pklen != crypto_sign_ed25519_PUBLICKEYBYTES) {
		debug3_f("public key length mismatch: %zu", pklen);
		जाओ out;
	}

	sklen = SSH_ED25519_RAW_SECRET_कुंजी_LEN;
	/* Extract private key (32 bytes seed) */
	अगर (!EVP_PKEY_get_raw_private_कुंजी(pkey, sk, &sklen)) {
		debug3_f("EVP_PKEY_get_raw_private_key failed");
		जाओ out;
	}
	अगर (sklen != SSH_ED25519_RAW_SECRET_कुंजी_LEN) {
		debug3_f("private key length mismatch: %zu", sklen);
		जाओ out;
	}

	/* Append public key to secret key (SUPERCOP format compatibility) */
	स_नकल(sk + sklen, pk, crypto_sign_ed25519_PUBLICKEYBYTES);

	ret = 0;
out:
	EVP_PKEY_free(pkey);
	EVP_PKEY_CTX_free(ctx);
	वापस ret;
}

पूर्णांक
crypto_sign_ed25519_seed_keypair(अचिन्हित अक्षर *pk, अचिन्हित अक्षर *sk,
    स्थिर अचिन्हित अक्षर *seed)
{
	EVP_PKEY *pkey = शून्य;
	माप_प्रकार pklen;
	पूर्णांक ret = -1;

	अगर ((pkey = EVP_PKEY_new_raw_private_कुंजी(EVP_PKEY_ED25519, शून्य,
	    seed, SSH_ED25519_RAW_SECRET_कुंजी_LEN)) == शून्य) {
		debug3_f("EVP_PKEY_new_raw_private_key failed");
		जाओ out;
	}

	/* Extract public key */
	pklen = crypto_sign_ed25519_PUBLICKEYBYTES;
	अगर (!EVP_PKEY_get_raw_public_कुंजी(pkey, pk, &pklen)) {
		debug3_f("EVP_PKEY_get_raw_public_key failed");
		जाओ out;
	}

	/* Build sk = seed || pk */
	स_नकल(sk, seed, SSH_ED25519_RAW_SECRET_कुंजी_LEN);
	स_नकल(sk + SSH_ED25519_RAW_SECRET_कुंजी_LEN, pk,
	    crypto_sign_ed25519_PUBLICKEYBYTES);

	ret = 0;
out:
	EVP_PKEY_free(pkey);
	वापस ret;
}

पूर्णांक
crypto_sign_ed25519_detached(अचिन्हित अक्षर *sig, अचिन्हित दीर्घ दीर्घ *siglenp,
    स्थिर अचिन्हित अक्षर *m, अचिन्हित दीर्घ दीर्घ mlen,
    स्थिर अचिन्हित अक्षर *sk)
{
	EVP_PKEY *pkey = शून्य;
	EVP_MD_CTX *mdctx = शून्य;
	माप_प्रकार siglen;
	पूर्णांक ret = -1;

	/* Create EVP_PKEY from secret key (first 32 bytes are the seed) */
	अगर ((pkey = EVP_PKEY_new_raw_private_कुंजी(EVP_PKEY_ED25519, शून्य,
	    sk, SSH_ED25519_RAW_SECRET_कुंजी_LEN)) == शून्य) {
		debug3_f("EVP_PKEY_new_raw_private_key failed");
		जाओ out;
	}

	/* Sign the message */
	अगर ((mdctx = EVP_MD_CTX_new()) == शून्य) {
		debug3_f("EVP_MD_CTX_new failed");
		जाओ out;
	}
	अगर (EVP_DigestSignInit(mdctx, शून्य, शून्य, शून्य, pkey) != 1) {
		debug3_f("EVP_DigestSignInit failed");
		जाओ out;
	}
	siglen = crypto_sign_ed25519_BYTES;
	अगर (EVP_DigestSign(mdctx, sig, &siglen, m, mlen) != 1) {
		debug3_f("EVP_DigestSign failed");
		जाओ out;
	}
	अगर (siglen != crypto_sign_ed25519_BYTES) {
		debug3_f("signature length mismatch: %zu", siglen);
		जाओ out;
	}

	अगर (siglenp != शून्य)
		*siglenp = siglen;

	ret = 0;
out:
	EVP_MD_CTX_free(mdctx);
	EVP_PKEY_free(pkey);
	वापस ret;
}

पूर्णांक
crypto_sign_ed25519_verify_detached(स्थिर अचिन्हित अक्षर *sig,
    स्थिर अचिन्हित अक्षर *m, अचिन्हित दीर्घ दीर्घ mlen,
    स्थिर अचिन्हित अक्षर *pk)
{
	EVP_PKEY *pkey = शून्य;
	EVP_MD_CTX *mdctx = शून्य;
	पूर्णांक ret = -1;

	अगर (mlen > SIZE_MAX) {
		debug3_f("message too long: %llu", mlen);
		वापस -1;
	}

	/* Create EVP_PKEY from public key */
	अगर ((pkey = EVP_PKEY_new_raw_public_कुंजी(EVP_PKEY_ED25519, शून्य,
	    pk, crypto_sign_ed25519_PUBLICKEYBYTES)) == शून्य) {
		debug3_f("EVP_PKEY_new_raw_public_key failed");
		जाओ out;
	}

	अगर ((mdctx = EVP_MD_CTX_new()) == शून्य) {
		debug3_f("EVP_MD_CTX_new failed");
		जाओ out;
	}
	अगर (EVP_DigestVerifyInit(mdctx, शून्य, शून्य, शून्य, pkey) <= 0) {
		debug3_f("EVP_DigestVerifyInit failed");
		जाओ out;
	}
	अगर (EVP_DigestVerify(mdctx, sig, crypto_sign_ed25519_BYTES,
	    m, (माप_प्रकार)mlen) != 1) {
		debug3_f("EVP_DigestVerify failed");
		जाओ out;
	}

	ret = 0;
out:
	EVP_MD_CTX_free(mdctx);
	EVP_PKEY_free(pkey);
	वापस ret;
}

#पूर्ण_अगर /* OPENSSL_HAS_ED25519 */
