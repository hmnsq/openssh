/* $OpenBSD: crypto_api.h,v 1.13 2026/09/16 00:43:00 djm Exp $ */

/*
 * Assembled from generated headers and source files by Markus Friedl.
 * Placed in the public domain.
 */

#ifndef crypto_api_h
#define crypto_api_h

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <stdint.h>
#অন্তর্ভাব <stdlib.h>

প্রকারনির্দেশ int8_t crypto_int8;
প্রকারনির্দেশ uint8_t crypto_uint8;
প্রকারনির্দেশ int16_t crypto_int16;
প্রকারনির্দেশ uint16_t crypto_uint16;
প্রকারনির্দেশ int32_t crypto_int32;
প্রকারনির্দেশ uint32_t crypto_uint32;
প্রকারনির্দেশ int64_t crypto_int64;
প্রকারনির্দেশ uint64_t crypto_uint64;

#define randombytes(buf, buf_len) arc4random_buf((buf), (buf_len))
#define small_random32() arc4random()

#define crypto_hash_sha512_BYTES 64U

#ifdef WITH_OPENSSL
#অন্তর্ভাব <openssl/evp.h>
স্থির অন্তঃস্থ পূর্ণাঙ্ক
crypto_hash_sha512(unsigned বর্ণ *out, ধ্রুব unsigned বর্ণ *in,
    unsigned long long inlen)
{

	যদি (!EVP_Digest(in, inlen, out, রিক্ত, EVP_sha512(), রিক্ত))
		প্রত্যাগম -1;
	প্রত্যাগম 0;
}
#অন্যথা /* WITH_OPENSSL */
# ifdef HAVE_SHA2_H
#  include <sha2.h>
# endif
স্থির অন্তঃস্থ পূর্ণাঙ্ক
crypto_hash_sha512(unsigned বর্ণ *out, ধ্রুব unsigned বর্ণ *in,
    unsigned long long inlen)
{

	SHA2_CTX ctx;

	SHA512Init(&ctx);
	SHA512Update(&ctx, in, inlen);
	SHA512Final(out, &ctx);
	প্রত্যাগম 0;
}
#endif /* WITH_OPENSSL */

#define crypto_sign_ed25519_SECRETKEYBYTES 64U
#define crypto_sign_ed25519_PUBLICKEYBYTES 32U
#define crypto_sign_ed25519_SEEDBYTES 32U
#define crypto_sign_ed25519_BYTES 64U

পূর্ণাঙ্ক	crypto_sign_ed25519_detached(unsigned বর্ণ *, unsigned long long *,
    ধ্রুব unsigned বর্ণ *, unsigned long long, ধ্রুব unsigned বর্ণ *);
পূর্ণাঙ্ক	crypto_sign_ed25519_verify_detached(ধ্রুব unsigned বর্ণ *,
    ধ্রুব unsigned বর্ণ *, unsigned long long, ধ্রুব unsigned বর্ণ *);
পূর্ণাঙ্ক	crypto_sign_ed25519_keypair(unsigned বর্ণ *, unsigned বর্ণ *);
পূর্ণাঙ্ক	crypto_sign_ed25519_seed_keypair(unsigned বর্ণ *, unsigned বর্ণ *,
    ধ্রুব unsigned বর্ণ *);

#define crypto_kem_sntrup761_PUBLICKEYBYTES 1158
#define crypto_kem_sntrup761_SECRETKEYBYTES 1763
#define crypto_kem_sntrup761_CIPHERTEXTBYTES 1039
#define crypto_kem_sntrup761_BYTES 32

পূর্ণাঙ্ক	crypto_kem_sntrup761_enc(unsigned বর্ণ *cstr, unsigned বর্ণ *k,
    ধ্রুব unsigned বর্ণ *pk);
পূর্ণাঙ্ক	crypto_kem_sntrup761_dec(unsigned বর্ণ *k,
    ধ্রুব unsigned বর্ণ *cstr, ধ্রুব unsigned বর্ণ *sk);
পূর্ণাঙ্ক	crypto_kem_sntrup761_keypair(unsigned বর্ণ *pk, unsigned বর্ণ *sk);

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

পূর্ণাঙ্ক crypto_kem_mlkem768_keypair(uint8_t pk[crypto_kem_mlkem768_PUBLICKEYBYTES],
    uint8_t sk[crypto_kem_mlkem768_SECRETKEYBYTES]);
পূর্ণাঙ্ক crypto_kem_mlkem768_enc(uint8_t ct[crypto_kem_mlkem768_CIPHERTEXTBYTES],
    uint8_t shared_secret[crypto_kem_mlkem768_BYTES],
    ধ্রুব uint8_t pk[crypto_kem_mlkem768_PUBLICKEYBYTES]);
পূর্ণাঙ্ক crypto_kem_mlkem768_dec(uint8_t shared_secret[crypto_kem_mlkem768_BYTES],
    ধ্রুব uint8_t ct[crypto_kem_mlkem768_CIPHERTEXTBYTES],
    ধ্রুব uint8_t sk[crypto_kem_mlkem768_SECRETKEYBYTES]);
পূর্ণাঙ্ক crypto_kem_mlkem768_keypair_seeded(uint8_t pk[crypto_kem_mlkem768_PUBLICKEYBYTES],
    uint8_t sk[crypto_kem_mlkem768_SECRETKEYBYTES], ধ্রুব uint8_t seed[64]);
পূর্ণাঙ্ক crypto_kem_mlkem768_enc_seeded(uint8_t ct[crypto_kem_mlkem768_CIPHERTEXTBYTES],
    uint8_t shared_secret[crypto_kem_mlkem768_BYTES],
    ধ্রুব uint8_t pk[crypto_kem_mlkem768_PUBLICKEYBYTES],
    ধ্রুব uint8_t seed[32]);

/* ML-DSA-44 */
#define MLDSA44_PUBLICKEYBYTES 1312
#define MLDSA44_SECRETKEYBYTES 2560
#define MLDSA44_SIGBYTES 2420
#define MLDSA44_SEEDBYTES 32

পূর্ণাঙ্ক crypto_sign_mldsa44_keypair(uint8_t pk[MLDSA44_PUBLICKEYBYTES],
    uint8_t sk[MLDSA44_SECRETKEYBYTES]);
পূর্ণাঙ্ক crypto_sign_mldsa44(uint8_t sig[MLDSA44_SIGBYTES],
    ধ্রুব uint8_t *বার্তা, size_t msglen,
    ধ্রুব uint8_t *ctx, size_t ctxlen,
    ধ্রুব uint8_t sk[MLDSA44_SECRETKEYBYTES]);
পূর্ণাঙ্ক crypto_sign_mldsa44_verify(ধ্রুব uint8_t sig[MLDSA44_SIGBYTES],
    ধ্রুব uint8_t *বার্তা, size_t msglen,
    ধ্রুব uint8_t *ctx, size_t ctxlen,
    ধ্রুব uint8_t pk[MLDSA44_PUBLICKEYBYTES]);
পূর্ণাঙ্ক crypto_sign_mldsa44_keypair_seeded(uint8_t pk[MLDSA44_PUBLICKEYBYTES],
    uint8_t sk[MLDSA44_SECRETKEYBYTES], ধ্রুব uint8_t seed[MLDSA44_SEEDBYTES]);
পূর্ণাঙ্ক crypto_sign_mldsa44_seeded(uint8_t sig[MLDSA44_SIGBYTES],
    ধ্রুব uint8_t *বার্তা, size_t msglen,
    ধ্রুব uint8_t *ctx, size_t ctxlen,
    ধ্রুব uint8_t sk[MLDSA44_SECRETKEYBYTES],
    ধ্রুব uint8_t seed[MLDSA44_SEEDBYTES]);

/* ML-DSA-65 */
#define MLDSA65_PUBLICKEYBYTES 1952
#define MLDSA65_SECRETKEYBYTES 4032
#define MLDSA65_SIGBYTES 3309
#define MLDSA65_SEEDBYTES 32

#যদি 0
পূর্ণাঙ্ক crypto_sign_mldsa65_keypair(uint8_t pk[MLDSA65_PUBLICKEYBYTES],
    uint8_t sk[MLDSA65_SECRETKEYBYTES]);
পূর্ণাঙ্ক crypto_sign_mldsa65(uint8_t sig[MLDSA65_SIGBYTES],
    ধ্রুব uint8_t *বার্তা, size_t msglen,
    ধ্রুব uint8_t *ctx, size_t ctxlen,
    ধ্রুব uint8_t sk[MLDSA65_SECRETKEYBYTES]);
পূর্ণাঙ্ক crypto_sign_mldsa65_verify(ধ্রুব uint8_t sig[MLDSA65_SIGBYTES],
    ধ্রুব uint8_t *বার্তা, size_t msglen,
    ধ্রুব uint8_t *ctx, size_t ctxlen,
    ধ্রুব uint8_t pk[MLDSA65_PUBLICKEYBYTES]);
পূর্ণাঙ্ক crypto_sign_mldsa65_keypair_seeded(uint8_t pk[MLDSA65_PUBLICKEYBYTES],
    uint8_t sk[MLDSA65_SECRETKEYBYTES], ধ্রুব uint8_t seed[MLDSA65_SEEDBYTES]);
পূর্ণাঙ্ক crypto_sign_mldsa65_seeded(uint8_t sig[MLDSA65_SIGBYTES],
    ধ্রুব uint8_t *বার্তা, size_t msglen,
    ধ্রুব uint8_t *ctx, size_t ctxlen,
    ধ্রুব uint8_t sk[MLDSA65_SECRETKEYBYTES],
    ধ্রুব uint8_t seed[MLDSA65_SEEDBYTES]);
#endif

/* ML-DSA-87 */
#define MLDSA87_PUBLICKEYBYTES 2592
#define MLDSA87_SECRETKEYBYTES 4896
#define MLDSA87_SIGBYTES 4627
#define MLDSA87_SEEDBYTES 32

পূর্ণাঙ্ক crypto_sign_mldsa87_keypair(uint8_t pk[MLDSA87_PUBLICKEYBYTES],
    uint8_t sk[MLDSA87_SECRETKEYBYTES]);
পূর্ণাঙ্ক crypto_sign_mldsa87(uint8_t sig[MLDSA87_SIGBYTES],
    ধ্রুব uint8_t *বার্তা, size_t msglen,
    ধ্রুব uint8_t *ctx, size_t ctxlen,
    ধ্রুব uint8_t sk[MLDSA87_SECRETKEYBYTES]);
পূর্ণাঙ্ক crypto_sign_mldsa87_verify(ধ্রুব uint8_t sig[MLDSA87_SIGBYTES],
    ধ্রুব uint8_t *বার্তা, size_t msglen,
    ধ্রুব uint8_t *ctx, size_t ctxlen,
    ধ্রুব uint8_t pk[MLDSA87_PUBLICKEYBYTES]);
পূর্ণাঙ্ক crypto_sign_mldsa87_keypair_seeded(uint8_t pk[MLDSA87_PUBLICKEYBYTES],
    uint8_t sk[MLDSA87_SECRETKEYBYTES], ধ্রুব uint8_t seed[MLDSA87_SEEDBYTES]);
পূর্ণাঙ্ক crypto_sign_mldsa87_seeded(uint8_t sig[MLDSA87_SIGBYTES],
    ধ্রুব uint8_t *বার্তা, size_t msglen,
    ধ্রুব uint8_t *ctx, size_t ctxlen,
    ধ্রুব uint8_t sk[MLDSA87_SECRETKEYBYTES],
    ধ্রুব uint8_t seed[MLDSA87_SEEDBYTES]);

/* MLDSA44-Ed25519-SHA512 */
#define MLDSA44_ED25519_PK_SZ (MLDSA44_PUBLICKEYBYTES + crypto_sign_ed25519_PUBLICKEYBYTES)
#define MLDSA44_ED25519_SK_SZ (MLDSA44_SEEDBYTES + crypto_sign_ed25519_SEEDBYTES)
#define MLDSA44_ED25519_SIG_SZ (MLDSA44_SIGBYTES + crypto_sign_ed25519_BYTES)

পূর্ণাঙ্ক crypto_sign_mldsa44_ed25519_keygen(uint8_t pk[MLDSA44_ED25519_PK_SZ],
    uint8_t sk[MLDSA44_ED25519_SK_SZ]);
পূর্ণাঙ্ক crypto_sign_mldsa44_ed25519_keygen_seeded(uint8_t pk[MLDSA44_ED25519_PK_SZ],
    uint8_t sk[MLDSA44_ED25519_SK_SZ],
    ধ্রুব uint8_t mldsa_seed[MLDSA44_SEEDBYTES],
    ধ্রুব uint8_t ed25519_seed[crypto_sign_ed25519_SEEDBYTES]);
পূর্ণাঙ্ক crypto_sign_mldsa44_ed25519_sign(uint8_t sig[MLDSA44_ED25519_SIG_SZ],
    ধ্রুব uint8_t *বার্তা, size_t msglen,
    ধ্রুব uint8_t *ctx, size_t ctxlen,
    ধ্রুব uint8_t sk[MLDSA44_ED25519_SK_SZ]);
পূর্ণাঙ্ক crypto_sign_mldsa44_ed25519_verify(ধ্রুব uint8_t sig[MLDSA44_ED25519_SIG_SZ],
    ধ্রুব uint8_t *বার্তা, size_t msglen,
    ধ্রুব uint8_t *ctx, size_t ctxlen,
    ধ্রুব uint8_t pk[MLDSA44_ED25519_PK_SZ]);

/* Utility */
শূন্য sha3_256(uint8_t digest[32], ধ্রুব uint8_t *data, size_t len);
শূন্য sha3_512(uint8_t digest[64], ধ্রুব uint8_t *data, size_t len);

#endif /* crypto_api_h */
