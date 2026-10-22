/* $OpenBSD: crypto_api.h,v 1.13 2026/09/16 00:43:00 djm Exp $ */

/*
 * Assembled from generated headers and source files by Markus Friedl.
 * Placed in the public domain.
 */

#अगर_अघोषित crypto_api_h
#घोषणा crypto_api_h

#समावेश "includes.h"

#समावेश <stdint.h>
#समावेश <stdlib.h>

प्रकार int8_t crypto_int8;
प्रकार uint8_t crypto_uint8;
प्रकार int16_t crypto_int16;
प्रकार uint16_t crypto_uint16;
प्रकार int32_t crypto_int32;
प्रकार uint32_t crypto_uint32;
प्रकार int64_t crypto_int64;
प्रकार uint64_t crypto_uint64;

#घोषणा randombytes(buf, buf_len) arc4random_buf((buf), (buf_len))
#घोषणा small_random32() arc4random()

#घोषणा crypto_hash_sha512_BYTES 64U

#अगर_घोषित WITH_OPENSSL
#समावेश <openssl/evp.h>
अटल अंतरभूत पूर्णांक
crypto_hash_sha512(अचिन्हित अक्षर *out, स्थिर अचिन्हित अक्षर *in,
    अचिन्हित दीर्घ दीर्घ inlen)
{

	अगर (!EVP_Digest(in, inlen, out, शून्य, EVP_sha512(), शून्य))
		वापस -1;
	वापस 0;
}
#अन्यथा /* WITH_OPENSSL */
# ifdef HAVE_SHA2_H
#  include <sha2.h>
# endif
अटल अंतरभूत पूर्णांक
crypto_hash_sha512(अचिन्हित अक्षर *out, स्थिर अचिन्हित अक्षर *in,
    अचिन्हित दीर्घ दीर्घ inlen)
{

	SHA2_CTX ctx;

	SHA512Init(&ctx);
	SHA512Update(&ctx, in, inlen);
	SHA512Final(out, &ctx);
	वापस 0;
}
#पूर्ण_अगर /* WITH_OPENSSL */

#घोषणा crypto_sign_ed25519_SECRETKEYBYTES 64U
#घोषणा crypto_sign_ed25519_PUBLICKEYBYTES 32U
#घोषणा crypto_sign_ed25519_SEEDBYTES 32U
#घोषणा crypto_sign_ed25519_BYTES 64U

पूर्णांक	crypto_sign_ed25519_detached(अचिन्हित अक्षर *, अचिन्हित दीर्घ दीर्घ *,
    स्थिर अचिन्हित अक्षर *, अचिन्हित दीर्घ दीर्घ, स्थिर अचिन्हित अक्षर *);
पूर्णांक	crypto_sign_ed25519_verify_detached(स्थिर अचिन्हित अक्षर *,
    स्थिर अचिन्हित अक्षर *, अचिन्हित दीर्घ दीर्घ, स्थिर अचिन्हित अक्षर *);
पूर्णांक	crypto_sign_ed25519_keypair(अचिन्हित अक्षर *, अचिन्हित अक्षर *);
पूर्णांक	crypto_sign_ed25519_seed_keypair(अचिन्हित अक्षर *, अचिन्हित अक्षर *,
    स्थिर अचिन्हित अक्षर *);

#घोषणा crypto_kem_sntrup761_PUBLICKEYBYTES 1158
#घोषणा crypto_kem_sntrup761_SECRETKEYBYTES 1763
#घोषणा crypto_kem_sntrup761_CIPHERTEXTBYTES 1039
#घोषणा crypto_kem_sntrup761_BYTES 32

पूर्णांक	crypto_kem_sntrup761_enc(अचिन्हित अक्षर *cstr, अचिन्हित अक्षर *k,
    स्थिर अचिन्हित अक्षर *pk);
पूर्णांक	crypto_kem_sntrup761_dec(अचिन्हित अक्षर *k,
    स्थिर अचिन्हित अक्षर *cstr, स्थिर अचिन्हित अक्षर *sk);
पूर्णांक	crypto_kem_sntrup761_keypair(अचिन्हित अक्षर *pk, अचिन्हित अक्षर *sk);

/* ML-KEM-768 */
#घोषणा crypto_kem_mlkem768_PUBLICKEYBYTES 1184
#घोषणा crypto_kem_mlkem768_SECRETKEYBYTES 2400
#घोषणा crypto_kem_mlkem768_CIPHERTEXTBYTES 1088
#घोषणा crypto_kem_mlkem768_BYTES 32
#घोषणा crypto_kem_mlkem768_ENCSEEDBYTES 32
#घोषणा crypto_kem_mlkem768_KEYPAIRSEEDBYTES 64

/* Aliases for MLKEM768 */
#घोषणा MLKEM768_PUBLICKEYBYTES crypto_kem_mlkem768_PUBLICKEYBYTES
#घोषणा MLKEM768_SECRETKEYBYTES crypto_kem_mlkem768_SECRETKEYBYTES
#घोषणा MLKEM768_CIPHERTEXTBYTES crypto_kem_mlkem768_CIPHERTEXTBYTES
#घोषणा MLKEM768_BYTES crypto_kem_mlkem768_BYTES

पूर्णांक crypto_kem_mlkem768_keypair(uint8_t pk[crypto_kem_mlkem768_PUBLICKEYBYTES],
    uint8_t sk[crypto_kem_mlkem768_SECRETKEYBYTES]);
पूर्णांक crypto_kem_mlkem768_enc(uint8_t ct[crypto_kem_mlkem768_CIPHERTEXTBYTES],
    uint8_t shared_secret[crypto_kem_mlkem768_BYTES],
    स्थिर uint8_t pk[crypto_kem_mlkem768_PUBLICKEYBYTES]);
पूर्णांक crypto_kem_mlkem768_dec(uint8_t shared_secret[crypto_kem_mlkem768_BYTES],
    स्थिर uint8_t ct[crypto_kem_mlkem768_CIPHERTEXTBYTES],
    स्थिर uint8_t sk[crypto_kem_mlkem768_SECRETKEYBYTES]);
पूर्णांक crypto_kem_mlkem768_keypair_seeded(uint8_t pk[crypto_kem_mlkem768_PUBLICKEYBYTES],
    uint8_t sk[crypto_kem_mlkem768_SECRETKEYBYTES], स्थिर uint8_t seed[64]);
पूर्णांक crypto_kem_mlkem768_enc_seeded(uint8_t ct[crypto_kem_mlkem768_CIPHERTEXTBYTES],
    uint8_t shared_secret[crypto_kem_mlkem768_BYTES],
    स्थिर uint8_t pk[crypto_kem_mlkem768_PUBLICKEYBYTES],
    स्थिर uint8_t seed[32]);

/* ML-DSA-44 */
#घोषणा MLDSA44_PUBLICKEYBYTES 1312
#घोषणा MLDSA44_SECRETKEYBYTES 2560
#घोषणा MLDSA44_SIGBYTES 2420
#घोषणा MLDSA44_SEEDBYTES 32

पूर्णांक crypto_sign_mldsa44_keypair(uint8_t pk[MLDSA44_PUBLICKEYBYTES],
    uint8_t sk[MLDSA44_SECRETKEYBYTES]);
पूर्णांक crypto_sign_mldsa44(uint8_t sig[MLDSA44_SIGBYTES],
    स्थिर uint8_t *संदेश, माप_प्रकार msglen,
    स्थिर uint8_t *ctx, माप_प्रकार ctxlen,
    स्थिर uint8_t sk[MLDSA44_SECRETKEYBYTES]);
पूर्णांक crypto_sign_mldsa44_verify(स्थिर uint8_t sig[MLDSA44_SIGBYTES],
    स्थिर uint8_t *संदेश, माप_प्रकार msglen,
    स्थिर uint8_t *ctx, माप_प्रकार ctxlen,
    स्थिर uint8_t pk[MLDSA44_PUBLICKEYBYTES]);
पूर्णांक crypto_sign_mldsa44_keypair_seeded(uint8_t pk[MLDSA44_PUBLICKEYBYTES],
    uint8_t sk[MLDSA44_SECRETKEYBYTES], स्थिर uint8_t seed[MLDSA44_SEEDBYTES]);
पूर्णांक crypto_sign_mldsa44_seeded(uint8_t sig[MLDSA44_SIGBYTES],
    स्थिर uint8_t *संदेश, माप_प्रकार msglen,
    स्थिर uint8_t *ctx, माप_प्रकार ctxlen,
    स्थिर uint8_t sk[MLDSA44_SECRETKEYBYTES],
    स्थिर uint8_t seed[MLDSA44_SEEDBYTES]);

/* ML-DSA-65 */
#घोषणा MLDSA65_PUBLICKEYBYTES 1952
#घोषणा MLDSA65_SECRETKEYBYTES 4032
#घोषणा MLDSA65_SIGBYTES 3309
#घोषणा MLDSA65_SEEDBYTES 32

#अगर 0
पूर्णांक crypto_sign_mldsa65_keypair(uint8_t pk[MLDSA65_PUBLICKEYBYTES],
    uint8_t sk[MLDSA65_SECRETKEYBYTES]);
पूर्णांक crypto_sign_mldsa65(uint8_t sig[MLDSA65_SIGBYTES],
    स्थिर uint8_t *संदेश, माप_प्रकार msglen,
    स्थिर uint8_t *ctx, माप_प्रकार ctxlen,
    स्थिर uint8_t sk[MLDSA65_SECRETKEYBYTES]);
पूर्णांक crypto_sign_mldsa65_verify(स्थिर uint8_t sig[MLDSA65_SIGBYTES],
    स्थिर uint8_t *संदेश, माप_प्रकार msglen,
    स्थिर uint8_t *ctx, माप_प्रकार ctxlen,
    स्थिर uint8_t pk[MLDSA65_PUBLICKEYBYTES]);
पूर्णांक crypto_sign_mldsa65_keypair_seeded(uint8_t pk[MLDSA65_PUBLICKEYBYTES],
    uint8_t sk[MLDSA65_SECRETKEYBYTES], स्थिर uint8_t seed[MLDSA65_SEEDBYTES]);
पूर्णांक crypto_sign_mldsa65_seeded(uint8_t sig[MLDSA65_SIGBYTES],
    स्थिर uint8_t *संदेश, माप_प्रकार msglen,
    स्थिर uint8_t *ctx, माप_प्रकार ctxlen,
    स्थिर uint8_t sk[MLDSA65_SECRETKEYBYTES],
    स्थिर uint8_t seed[MLDSA65_SEEDBYTES]);
#पूर्ण_अगर

/* ML-DSA-87 */
#घोषणा MLDSA87_PUBLICKEYBYTES 2592
#घोषणा MLDSA87_SECRETKEYBYTES 4896
#घोषणा MLDSA87_SIGBYTES 4627
#घोषणा MLDSA87_SEEDBYTES 32

पूर्णांक crypto_sign_mldsa87_keypair(uint8_t pk[MLDSA87_PUBLICKEYBYTES],
    uint8_t sk[MLDSA87_SECRETKEYBYTES]);
पूर्णांक crypto_sign_mldsa87(uint8_t sig[MLDSA87_SIGBYTES],
    स्थिर uint8_t *संदेश, माप_प्रकार msglen,
    स्थिर uint8_t *ctx, माप_प्रकार ctxlen,
    स्थिर uint8_t sk[MLDSA87_SECRETKEYBYTES]);
पूर्णांक crypto_sign_mldsa87_verify(स्थिर uint8_t sig[MLDSA87_SIGBYTES],
    स्थिर uint8_t *संदेश, माप_प्रकार msglen,
    स्थिर uint8_t *ctx, माप_प्रकार ctxlen,
    स्थिर uint8_t pk[MLDSA87_PUBLICKEYBYTES]);
पूर्णांक crypto_sign_mldsa87_keypair_seeded(uint8_t pk[MLDSA87_PUBLICKEYBYTES],
    uint8_t sk[MLDSA87_SECRETKEYBYTES], स्थिर uint8_t seed[MLDSA87_SEEDBYTES]);
पूर्णांक crypto_sign_mldsa87_seeded(uint8_t sig[MLDSA87_SIGBYTES],
    स्थिर uint8_t *संदेश, माप_प्रकार msglen,
    स्थिर uint8_t *ctx, माप_प्रकार ctxlen,
    स्थिर uint8_t sk[MLDSA87_SECRETKEYBYTES],
    स्थिर uint8_t seed[MLDSA87_SEEDBYTES]);

/* MLDSA44-Ed25519-SHA512 */
#घोषणा MLDSA44_ED25519_PK_SZ (MLDSA44_PUBLICKEYBYTES + crypto_sign_ed25519_PUBLICKEYBYTES)
#घोषणा MLDSA44_ED25519_SK_SZ (MLDSA44_SEEDBYTES + crypto_sign_ed25519_SEEDBYTES)
#घोषणा MLDSA44_ED25519_SIG_SZ (MLDSA44_SIGBYTES + crypto_sign_ed25519_BYTES)

पूर्णांक crypto_sign_mldsa44_ed25519_keygen(uint8_t pk[MLDSA44_ED25519_PK_SZ],
    uint8_t sk[MLDSA44_ED25519_SK_SZ]);
पूर्णांक crypto_sign_mldsa44_ed25519_keygen_seeded(uint8_t pk[MLDSA44_ED25519_PK_SZ],
    uint8_t sk[MLDSA44_ED25519_SK_SZ],
    स्थिर uint8_t mldsa_seed[MLDSA44_SEEDBYTES],
    स्थिर uint8_t ed25519_seed[crypto_sign_ed25519_SEEDBYTES]);
पूर्णांक crypto_sign_mldsa44_ed25519_sign(uint8_t sig[MLDSA44_ED25519_SIG_SZ],
    स्थिर uint8_t *संदेश, माप_प्रकार msglen,
    स्थिर uint8_t *ctx, माप_प्रकार ctxlen,
    स्थिर uint8_t sk[MLDSA44_ED25519_SK_SZ]);
पूर्णांक crypto_sign_mldsa44_ed25519_verify(स्थिर uint8_t sig[MLDSA44_ED25519_SIG_SZ],
    स्थिर uint8_t *संदेश, माप_प्रकार msglen,
    स्थिर uint8_t *ctx, माप_प्रकार ctxlen,
    स्थिर uint8_t pk[MLDSA44_ED25519_PK_SZ]);

/* Utility */
व्योम sha3_256(uint8_t digest[32], स्थिर uint8_t *तथ्य, माप_प्रकार len);
व्योम sha3_512(uint8_t digest[64], स्थिर uint8_t *तथ्य, माप_प्रकार len);

#पूर्ण_अगर /* crypto_api_h */
