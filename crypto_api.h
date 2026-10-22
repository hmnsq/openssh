/* $OpenBSD: crypto_api.h,v 1.13 2026/09/16 00:43:00 djm Exp $ */

/*
 * Assembled from generated headers and source files by Markus Friedl.
 * Placed in the public domain.
 */

#ifndef crypto_api_h
#define crypto_api_h

#شامل "includes.h"

#شامل <stdint.h>
#شامل <stdlib.h>

تعریفنوع int8_t crypto_int8;
تعریفنوع uint8_t crypto_uint8;
تعریفنوع int16_t crypto_int16;
تعریفنوع uint16_t crypto_uint16;
تعریفنوع int32_t crypto_int32;
تعریفنوع uint32_t crypto_uint32;
تعریفنوع int64_t crypto_int64;
تعریفنوع uint64_t crypto_uint64;

#define randombytes(buf, buf_len) arc4random_buf((buf), (buf_len))
#define small_random32() arc4random()

#define crypto_hash_sha512_BYTES 64U

#ifdef WITH_OPENSSL
#شامل <openssl/evp.h>
ایستا درونخطی صحیح
crypto_hash_sha512(unsigned نویسه *out, ثابت unsigned نویسه *in,
    unsigned long long inlen)
{

	اگر (!EVP_Digest(in, inlen, out, پوچ, EVP_sha512(), پوچ))
		بازگشت -1;
	بازگشت 0;
}
#وگرنه /* WITH_OPENSSL */
# ifdef HAVE_SHA2_H
#  include <sha2.h>
# endif
ایستا درونخطی صحیح
crypto_hash_sha512(unsigned نویسه *out, ثابت unsigned نویسه *in,
    unsigned long long inlen)
{

	SHA2_CTX ctx;

	SHA512Init(&ctx);
	SHA512Update(&ctx, in, inlen);
	SHA512Final(out, &ctx);
	بازگشت 0;
}
#endif /* WITH_OPENSSL */

#define crypto_sign_ed25519_SECRETKEYBYTES 64U
#define crypto_sign_ed25519_PUBLICKEYBYTES 32U
#define crypto_sign_ed25519_SEEDBYTES 32U
#define crypto_sign_ed25519_BYTES 64U

صحیح	crypto_sign_ed25519_detached(unsigned نویسه *, unsigned long long *,
    ثابت unsigned نویسه *, unsigned long long, ثابت unsigned نویسه *);
صحیح	crypto_sign_ed25519_verify_detached(ثابت unsigned نویسه *,
    ثابت unsigned نویسه *, unsigned long long, ثابت unsigned نویسه *);
صحیح	crypto_sign_ed25519_keypair(unsigned نویسه *, unsigned نویسه *);
صحیح	crypto_sign_ed25519_seed_keypair(unsigned نویسه *, unsigned نویسه *,
    ثابت unsigned نویسه *);

#define crypto_kem_sntrup761_PUBLICKEYBYTES 1158
#define crypto_kem_sntrup761_SECRETKEYBYTES 1763
#define crypto_kem_sntrup761_CIPHERTEXTBYTES 1039
#define crypto_kem_sntrup761_BYTES 32

صحیح	crypto_kem_sntrup761_enc(unsigned نویسه *cstr, unsigned نویسه *k,
    ثابت unsigned نویسه *pk);
صحیح	crypto_kem_sntrup761_dec(unsigned نویسه *k,
    ثابت unsigned نویسه *cstr, ثابت unsigned نویسه *sk);
صحیح	crypto_kem_sntrup761_keypair(unsigned نویسه *pk, unsigned نویسه *sk);

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

صحیح crypto_kem_mlkem768_keypair(uint8_t pk[crypto_kem_mlkem768_PUBLICKEYBYTES],
    uint8_t sk[crypto_kem_mlkem768_SECRETKEYBYTES]);
صحیح crypto_kem_mlkem768_enc(uint8_t ct[crypto_kem_mlkem768_CIPHERTEXTBYTES],
    uint8_t shared_secret[crypto_kem_mlkem768_BYTES],
    ثابت uint8_t pk[crypto_kem_mlkem768_PUBLICKEYBYTES]);
صحیح crypto_kem_mlkem768_dec(uint8_t shared_secret[crypto_kem_mlkem768_BYTES],
    ثابت uint8_t ct[crypto_kem_mlkem768_CIPHERTEXTBYTES],
    ثابت uint8_t sk[crypto_kem_mlkem768_SECRETKEYBYTES]);
صحیح crypto_kem_mlkem768_keypair_seeded(uint8_t pk[crypto_kem_mlkem768_PUBLICKEYBYTES],
    uint8_t sk[crypto_kem_mlkem768_SECRETKEYBYTES], ثابت uint8_t seed[64]);
صحیح crypto_kem_mlkem768_enc_seeded(uint8_t ct[crypto_kem_mlkem768_CIPHERTEXTBYTES],
    uint8_t shared_secret[crypto_kem_mlkem768_BYTES],
    ثابت uint8_t pk[crypto_kem_mlkem768_PUBLICKEYBYTES],
    ثابت uint8_t seed[32]);

/* ML-DSA-44 */
#define MLDSA44_PUBLICKEYBYTES 1312
#define MLDSA44_SECRETKEYBYTES 2560
#define MLDSA44_SIGBYTES 2420
#define MLDSA44_SEEDBYTES 32

صحیح crypto_sign_mldsa44_keypair(uint8_t pk[MLDSA44_PUBLICKEYBYTES],
    uint8_t sk[MLDSA44_SECRETKEYBYTES]);
صحیح crypto_sign_mldsa44(uint8_t sig[MLDSA44_SIGBYTES],
    ثابت uint8_t *پیام, size_t msglen,
    ثابت uint8_t *ctx, size_t ctxlen,
    ثابت uint8_t sk[MLDSA44_SECRETKEYBYTES]);
صحیح crypto_sign_mldsa44_verify(ثابت uint8_t sig[MLDSA44_SIGBYTES],
    ثابت uint8_t *پیام, size_t msglen,
    ثابت uint8_t *ctx, size_t ctxlen,
    ثابت uint8_t pk[MLDSA44_PUBLICKEYBYTES]);
صحیح crypto_sign_mldsa44_keypair_seeded(uint8_t pk[MLDSA44_PUBLICKEYBYTES],
    uint8_t sk[MLDSA44_SECRETKEYBYTES], ثابت uint8_t seed[MLDSA44_SEEDBYTES]);
صحیح crypto_sign_mldsa44_seeded(uint8_t sig[MLDSA44_SIGBYTES],
    ثابت uint8_t *پیام, size_t msglen,
    ثابت uint8_t *ctx, size_t ctxlen,
    ثابت uint8_t sk[MLDSA44_SECRETKEYBYTES],
    ثابت uint8_t seed[MLDSA44_SEEDBYTES]);

/* ML-DSA-65 */
#define MLDSA65_PUBLICKEYBYTES 1952
#define MLDSA65_SECRETKEYBYTES 4032
#define MLDSA65_SIGBYTES 3309
#define MLDSA65_SEEDBYTES 32

#اگر 0
صحیح crypto_sign_mldsa65_keypair(uint8_t pk[MLDSA65_PUBLICKEYBYTES],
    uint8_t sk[MLDSA65_SECRETKEYBYTES]);
صحیح crypto_sign_mldsa65(uint8_t sig[MLDSA65_SIGBYTES],
    ثابت uint8_t *پیام, size_t msglen,
    ثابت uint8_t *ctx, size_t ctxlen,
    ثابت uint8_t sk[MLDSA65_SECRETKEYBYTES]);
صحیح crypto_sign_mldsa65_verify(ثابت uint8_t sig[MLDSA65_SIGBYTES],
    ثابت uint8_t *پیام, size_t msglen,
    ثابت uint8_t *ctx, size_t ctxlen,
    ثابت uint8_t pk[MLDSA65_PUBLICKEYBYTES]);
صحیح crypto_sign_mldsa65_keypair_seeded(uint8_t pk[MLDSA65_PUBLICKEYBYTES],
    uint8_t sk[MLDSA65_SECRETKEYBYTES], ثابت uint8_t seed[MLDSA65_SEEDBYTES]);
صحیح crypto_sign_mldsa65_seeded(uint8_t sig[MLDSA65_SIGBYTES],
    ثابت uint8_t *پیام, size_t msglen,
    ثابت uint8_t *ctx, size_t ctxlen,
    ثابت uint8_t sk[MLDSA65_SECRETKEYBYTES],
    ثابت uint8_t seed[MLDSA65_SEEDBYTES]);
#endif

/* ML-DSA-87 */
#define MLDSA87_PUBLICKEYBYTES 2592
#define MLDSA87_SECRETKEYBYTES 4896
#define MLDSA87_SIGBYTES 4627
#define MLDSA87_SEEDBYTES 32

صحیح crypto_sign_mldsa87_keypair(uint8_t pk[MLDSA87_PUBLICKEYBYTES],
    uint8_t sk[MLDSA87_SECRETKEYBYTES]);
صحیح crypto_sign_mldsa87(uint8_t sig[MLDSA87_SIGBYTES],
    ثابت uint8_t *پیام, size_t msglen,
    ثابت uint8_t *ctx, size_t ctxlen,
    ثابت uint8_t sk[MLDSA87_SECRETKEYBYTES]);
صحیح crypto_sign_mldsa87_verify(ثابت uint8_t sig[MLDSA87_SIGBYTES],
    ثابت uint8_t *پیام, size_t msglen,
    ثابت uint8_t *ctx, size_t ctxlen,
    ثابت uint8_t pk[MLDSA87_PUBLICKEYBYTES]);
صحیح crypto_sign_mldsa87_keypair_seeded(uint8_t pk[MLDSA87_PUBLICKEYBYTES],
    uint8_t sk[MLDSA87_SECRETKEYBYTES], ثابت uint8_t seed[MLDSA87_SEEDBYTES]);
صحیح crypto_sign_mldsa87_seeded(uint8_t sig[MLDSA87_SIGBYTES],
    ثابت uint8_t *پیام, size_t msglen,
    ثابت uint8_t *ctx, size_t ctxlen,
    ثابت uint8_t sk[MLDSA87_SECRETKEYBYTES],
    ثابت uint8_t seed[MLDSA87_SEEDBYTES]);

/* MLDSA44-Ed25519-SHA512 */
#define MLDSA44_ED25519_PK_SZ (MLDSA44_PUBLICKEYBYTES + crypto_sign_ed25519_PUBLICKEYBYTES)
#define MLDSA44_ED25519_SK_SZ (MLDSA44_SEEDBYTES + crypto_sign_ed25519_SEEDBYTES)
#define MLDSA44_ED25519_SIG_SZ (MLDSA44_SIGBYTES + crypto_sign_ed25519_BYTES)

صحیح crypto_sign_mldsa44_ed25519_keygen(uint8_t pk[MLDSA44_ED25519_PK_SZ],
    uint8_t sk[MLDSA44_ED25519_SK_SZ]);
صحیح crypto_sign_mldsa44_ed25519_keygen_seeded(uint8_t pk[MLDSA44_ED25519_PK_SZ],
    uint8_t sk[MLDSA44_ED25519_SK_SZ],
    ثابت uint8_t mldsa_seed[MLDSA44_SEEDBYTES],
    ثابت uint8_t ed25519_seed[crypto_sign_ed25519_SEEDBYTES]);
صحیح crypto_sign_mldsa44_ed25519_sign(uint8_t sig[MLDSA44_ED25519_SIG_SZ],
    ثابت uint8_t *پیام, size_t msglen,
    ثابت uint8_t *ctx, size_t ctxlen,
    ثابت uint8_t sk[MLDSA44_ED25519_SK_SZ]);
صحیح crypto_sign_mldsa44_ed25519_verify(ثابت uint8_t sig[MLDSA44_ED25519_SIG_SZ],
    ثابت uint8_t *پیام, size_t msglen,
    ثابت uint8_t *ctx, size_t ctxlen,
    ثابت uint8_t pk[MLDSA44_ED25519_PK_SZ]);

/* Utility */
تهی sha3_256(uint8_t digest[32], ثابت uint8_t *data, size_t len);
تهی sha3_512(uint8_t digest[64], ثابت uint8_t *data, size_t len);

#endif /* crypto_api_h */
