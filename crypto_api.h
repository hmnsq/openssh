/* $OpenBSD: crypto_api.h,v 1.13 2026/09/16 00:43:00 djm Exp $ */

/*
 * Assembled from generated headers and source files by Markus Friedl.
 * Placed in the public domain.
 */

#ifndef crypto_api_h
#define crypto_api_h

#अन्तर्भाव "includes.h"

#अन्तर्भाव <stdint.h>
#अन्तर्भाव <stdlib.h>

प्रकारव्याख्या int8_t crypto_int8;
प्रकारव्याख्या uint8_t crypto_uint8;
प्रकारव्याख्या int16_t crypto_int16;
प्रकारव्याख्या uint16_t crypto_uint16;
प्रकारव्याख्या int32_t crypto_int32;
प्रकारव्याख्या uint32_t crypto_uint32;
प्रकारव्याख्या int64_t crypto_int64;
प्रकारव्याख्या uint64_t crypto_uint64;

#define randombytes(buf, buf_len) arc4random_buf((buf), (buf_len))
#define small_random32() arc4random()

#define crypto_hash_sha512_BYTES 64U

#ifdef WITH_OPENSSL
#अन्तर्भाव <openssl/evp.h>
स्थिर ओळीत पूर्णांक
crypto_hash_sha512(अचिन्हित अक्षर *out, स्थिरांक अचिन्हित अक्षर *in,
    अचिन्हित दीर्घ दीर्घ inlen)
{

	जर (!EVP_Digest(in, inlen, out, रिक्त, EVP_sha512(), रिक्त))
		परत -1;
	परत 0;
}
#अन्यथा /* WITH_OPENSSL */
# ifdef HAVE_SHA2_H
#  include <sha2.h>
# endif
स्थिर ओळीत पूर्णांक
crypto_hash_sha512(अचिन्हित अक्षर *out, स्थिरांक अचिन्हित अक्षर *in,
    अचिन्हित दीर्घ दीर्घ inlen)
{

	SHA2_CTX ctx;

	SHA512Init(&ctx);
	SHA512Update(&ctx, in, inlen);
	SHA512Final(out, &ctx);
	परत 0;
}
#endif /* WITH_OPENSSL */

#define crypto_sign_ed25519_SECRETKEYBYTES 64U
#define crypto_sign_ed25519_PUBLICKEYBYTES 32U
#define crypto_sign_ed25519_SEEDBYTES 32U
#define crypto_sign_ed25519_BYTES 64U

पूर्णांक	crypto_sign_ed25519_detached(अचिन्हित अक्षर *, अचिन्हित दीर्घ दीर्घ *,
    स्थिरांक अचिन्हित अक्षर *, अचिन्हित दीर्घ दीर्घ, स्थिरांक अचिन्हित अक्षर *);
पूर्णांक	crypto_sign_ed25519_verify_detached(स्थिरांक अचिन्हित अक्षर *,
    स्थिरांक अचिन्हित अक्षर *, अचिन्हित दीर्घ दीर्घ, स्थिरांक अचिन्हित अक्षर *);
पूर्णांक	crypto_sign_ed25519_keypair(अचिन्हित अक्षर *, अचिन्हित अक्षर *);
पूर्णांक	crypto_sign_ed25519_seed_keypair(अचिन्हित अक्षर *, अचिन्हित अक्षर *,
    स्थिरांक अचिन्हित अक्षर *);

#define crypto_kem_sntrup761_PUBLICKEYBYTES 1158
#define crypto_kem_sntrup761_SECRETKEYBYTES 1763
#define crypto_kem_sntrup761_CIPHERTEXTBYTES 1039
#define crypto_kem_sntrup761_BYTES 32

पूर्णांक	crypto_kem_sntrup761_enc(अचिन्हित अक्षर *cstr, अचिन्हित अक्षर *k,
    स्थिरांक अचिन्हित अक्षर *pk);
पूर्णांक	crypto_kem_sntrup761_dec(अचिन्हित अक्षर *k,
    स्थिरांक अचिन्हित अक्षर *cstr, स्थिरांक अचिन्हित अक्षर *sk);
पूर्णांक	crypto_kem_sntrup761_keypair(अचिन्हित अक्षर *pk, अचिन्हित अक्षर *sk);

/* ML-KEM-768 */
#define crypto_kem_mlkem768_PUBLICKEYBYTES 1184
#define crypto_kem_mlkem768_SECRETKEYBYTES 2400
#define crypto_kem_mlkem768_CIPHERTEXTBYTES 1088
#define crypto_kem_mlkem768_BYTES 32
#define crypto_kem_mlkem768_ENCSEEDBYTES 32
#define crypto_kem_mlkem768_KEYPAIRSEEDBYTES 64

/* Aliases for MLKEM768 */
#define MLKEM768_PUBLICKEYBYTES crypto_kem_mlkem768_PUBLICKEYBYTES
#define MLKEM768_SECRETKEYBYTES crypto_kem_mlkem768_SECRETKEYBYTES
#define MLKEM768_CIPHERTEXTBYTES crypto_kem_mlkem768_CIPHERTEXTBYTES
#define MLKEM768_BYTES crypto_kem_mlkem768_BYTES

पूर्णांक crypto_kem_mlkem768_keypair(uint8_t pk[crypto_kem_mlkem768_PUBLICKEYBYTES],
    uint8_t sk[crypto_kem_mlkem768_SECRETKEYBYTES]);
पूर्णांक crypto_kem_mlkem768_enc(uint8_t ct[crypto_kem_mlkem768_CIPHERTEXTBYTES],
    uint8_t shared_secret[crypto_kem_mlkem768_BYTES],
    स्थिरांक uint8_t pk[crypto_kem_mlkem768_PUBLICKEYBYTES]);
पूर्णांक crypto_kem_mlkem768_dec(uint8_t shared_secret[crypto_kem_mlkem768_BYTES],
    स्थिरांक uint8_t ct[crypto_kem_mlkem768_CIPHERTEXTBYTES],
    स्थिरांक uint8_t sk[crypto_kem_mlkem768_SECRETKEYBYTES]);
पूर्णांक crypto_kem_mlkem768_keypair_seeded(uint8_t pk[crypto_kem_mlkem768_PUBLICKEYBYTES],
    uint8_t sk[crypto_kem_mlkem768_SECRETKEYBYTES], स्थिरांक uint8_t seed[64]);
पूर्णांक crypto_kem_mlkem768_enc_seeded(uint8_t ct[crypto_kem_mlkem768_CIPHERTEXTBYTES],
    uint8_t shared_secret[crypto_kem_mlkem768_BYTES],
    स्थिरांक uint8_t pk[crypto_kem_mlkem768_PUBLICKEYBYTES],
    स्थिरांक uint8_t seed[32]);

/* ML-DSA-44 */
#define MLDSA44_PUBLICKEYBYTES 1312
#define MLDSA44_SECRETKEYBYTES 2560
#define MLDSA44_SIGBYTES 2420
#define MLDSA44_SEEDBYTES 32

पूर्णांक crypto_sign_mldsa44_keypair(uint8_t pk[MLDSA44_PUBLICKEYBYTES],
    uint8_t sk[MLDSA44_SECRETKEYBYTES]);
पूर्णांक crypto_sign_mldsa44(uint8_t sig[MLDSA44_SIGBYTES],
    स्थिरांक uint8_t *संदेश, माप_प्रकार msglen,
    स्थिरांक uint8_t *ctx, माप_प्रकार ctxlen,
    स्थिरांक uint8_t sk[MLDSA44_SECRETKEYBYTES]);
पूर्णांक crypto_sign_mldsa44_verify(स्थिरांक uint8_t sig[MLDSA44_SIGBYTES],
    स्थिरांक uint8_t *संदेश, माप_प्रकार msglen,
    स्थिरांक uint8_t *ctx, माप_प्रकार ctxlen,
    स्थिरांक uint8_t pk[MLDSA44_PUBLICKEYBYTES]);
पूर्णांक crypto_sign_mldsa44_keypair_seeded(uint8_t pk[MLDSA44_PUBLICKEYBYTES],
    uint8_t sk[MLDSA44_SECRETKEYBYTES], स्थिरांक uint8_t seed[MLDSA44_SEEDBYTES]);
पूर्णांक crypto_sign_mldsa44_seeded(uint8_t sig[MLDSA44_SIGBYTES],
    स्थिरांक uint8_t *संदेश, माप_प्रकार msglen,
    स्थिरांक uint8_t *ctx, माप_प्रकार ctxlen,
    स्थिरांक uint8_t sk[MLDSA44_SECRETKEYBYTES],
    स्थिरांक uint8_t seed[MLDSA44_SEEDBYTES]);

/* ML-DSA-65 */
#define MLDSA65_PUBLICKEYBYTES 1952
#define MLDSA65_SECRETKEYBYTES 4032
#define MLDSA65_SIGBYTES 3309
#define MLDSA65_SEEDBYTES 32

#जर 0
पूर्णांक crypto_sign_mldsa65_keypair(uint8_t pk[MLDSA65_PUBLICKEYBYTES],
    uint8_t sk[MLDSA65_SECRETKEYBYTES]);
पूर्णांक crypto_sign_mldsa65(uint8_t sig[MLDSA65_SIGBYTES],
    स्थिरांक uint8_t *संदेश, माप_प्रकार msglen,
    स्थिरांक uint8_t *ctx, माप_प्रकार ctxlen,
    स्थिरांक uint8_t sk[MLDSA65_SECRETKEYBYTES]);
पूर्णांक crypto_sign_mldsa65_verify(स्थिरांक uint8_t sig[MLDSA65_SIGBYTES],
    स्थिरांक uint8_t *संदेश, माप_प्रकार msglen,
    स्थिरांक uint8_t *ctx, माप_प्रकार ctxlen,
    स्थिरांक uint8_t pk[MLDSA65_PUBLICKEYBYTES]);
पूर्णांक crypto_sign_mldsa65_keypair_seeded(uint8_t pk[MLDSA65_PUBLICKEYBYTES],
    uint8_t sk[MLDSA65_SECRETKEYBYTES], स्थिरांक uint8_t seed[MLDSA65_SEEDBYTES]);
पूर्णांक crypto_sign_mldsa65_seeded(uint8_t sig[MLDSA65_SIGBYTES],
    स्थिरांक uint8_t *संदेश, माप_प्रकार msglen,
    स्थिरांक uint8_t *ctx, माप_प्रकार ctxlen,
    स्थिरांक uint8_t sk[MLDSA65_SECRETKEYBYTES],
    स्थिरांक uint8_t seed[MLDSA65_SEEDBYTES]);
#endif

/* ML-DSA-87 */
#define MLDSA87_PUBLICKEYBYTES 2592
#define MLDSA87_SECRETKEYBYTES 4896
#define MLDSA87_SIGBYTES 4627
#define MLDSA87_SEEDBYTES 32

पूर्णांक crypto_sign_mldsa87_keypair(uint8_t pk[MLDSA87_PUBLICKEYBYTES],
    uint8_t sk[MLDSA87_SECRETKEYBYTES]);
पूर्णांक crypto_sign_mldsa87(uint8_t sig[MLDSA87_SIGBYTES],
    स्थिरांक uint8_t *संदेश, माप_प्रकार msglen,
    स्थिरांक uint8_t *ctx, माप_प्रकार ctxlen,
    स्थिरांक uint8_t sk[MLDSA87_SECRETKEYBYTES]);
पूर्णांक crypto_sign_mldsa87_verify(स्थिरांक uint8_t sig[MLDSA87_SIGBYTES],
    स्थिरांक uint8_t *संदेश, माप_प्रकार msglen,
    स्थिरांक uint8_t *ctx, माप_प्रकार ctxlen,
    स्थिरांक uint8_t pk[MLDSA87_PUBLICKEYBYTES]);
पूर्णांक crypto_sign_mldsa87_keypair_seeded(uint8_t pk[MLDSA87_PUBLICKEYBYTES],
    uint8_t sk[MLDSA87_SECRETKEYBYTES], स्थिरांक uint8_t seed[MLDSA87_SEEDBYTES]);
पूर्णांक crypto_sign_mldsa87_seeded(uint8_t sig[MLDSA87_SIGBYTES],
    स्थिरांक uint8_t *संदेश, माप_प्रकार msglen,
    स्थिरांक uint8_t *ctx, माप_प्रकार ctxlen,
    स्थिरांक uint8_t sk[MLDSA87_SECRETKEYBYTES],
    स्थिरांक uint8_t seed[MLDSA87_SEEDBYTES]);

/* MLDSA44-Ed25519-SHA512 */
#define MLDSA44_ED25519_PK_SZ (MLDSA44_PUBLICKEYBYTES + crypto_sign_ed25519_PUBLICKEYBYTES)
#define MLDSA44_ED25519_SK_SZ (MLDSA44_SEEDBYTES + crypto_sign_ed25519_SEEDBYTES)
#define MLDSA44_ED25519_SIG_SZ (MLDSA44_SIGBYTES + crypto_sign_ed25519_BYTES)

पूर्णांक crypto_sign_mldsa44_ed25519_keygen(uint8_t pk[MLDSA44_ED25519_PK_SZ],
    uint8_t sk[MLDSA44_ED25519_SK_SZ]);
पूर्णांक crypto_sign_mldsa44_ed25519_keygen_seeded(uint8_t pk[MLDSA44_ED25519_PK_SZ],
    uint8_t sk[MLDSA44_ED25519_SK_SZ],
    स्थिरांक uint8_t mldsa_seed[MLDSA44_SEEDBYTES],
    स्थिरांक uint8_t ed25519_seed[crypto_sign_ed25519_SEEDBYTES]);
पूर्णांक crypto_sign_mldsa44_ed25519_sign(uint8_t sig[MLDSA44_ED25519_SIG_SZ],
    स्थिरांक uint8_t *संदेश, माप_प्रकार msglen,
    स्थिरांक uint8_t *ctx, माप_प्रकार ctxlen,
    स्थिरांक uint8_t sk[MLDSA44_ED25519_SK_SZ]);
पूर्णांक crypto_sign_mldsa44_ed25519_verify(स्थिरांक uint8_t sig[MLDSA44_ED25519_SIG_SZ],
    स्थिरांक uint8_t *संदेश, माप_प्रकार msglen,
    स्थिरांक uint8_t *ctx, माप_प्रकार ctxlen,
    स्थिरांक uint8_t pk[MLDSA44_ED25519_PK_SZ]);

/* Utility */
शून्य sha3_256(uint8_t digest[32], स्थिरांक uint8_t *data, माप_प्रकार len);
शून्य sha3_512(uint8_t digest[64], स्थिरांक uint8_t *data, माप_प्रकार len);

#endif /* crypto_api_h */
