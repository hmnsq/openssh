/* $OpenBSD: crypto_api.h,v 1.13 2026/09/16 00:43:00 djm Exp $ */

/*
 * Assembled from generated headers and source files by Markus Friedl.
 * Placed in the public domain.
 */

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ crypto_api_h
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ crypto_api_h

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <stdint.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>

ਕਿਸਮਪਰਿਭਾਸ਼ਾ int8_t crypto_int8;
ਕਿਸਮਪਰਿਭਾਸ਼ਾ uint8_t crypto_uint8;
ਕਿਸਮਪਰਿਭਾਸ਼ਾ int16_t crypto_int16;
ਕਿਸਮਪਰਿਭਾਸ਼ਾ uint16_t crypto_uint16;
ਕਿਸਮਪਰਿਭਾਸ਼ਾ int32_t crypto_int32;
ਕਿਸਮਪਰਿਭਾਸ਼ਾ uint32_t crypto_uint32;
ਕਿਸਮਪਰਿਭਾਸ਼ਾ int64_t crypto_int64;
ਕਿਸਮਪਰਿਭਾਸ਼ਾ uint64_t crypto_uint64;

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ randombytes(buf, buf_len) arc4random_buf((buf), (buf_len))
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ small_random32() arc4random()

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ crypto_hash_sha512_ਬਾਈਟਾਂ 64U

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/evp.h>
ਸਥਿਰ ਸਤਰਅੰਦਰ ਪੂਰਨ
crypto_hash_sha512(ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *ਬਾਹਰਲਾ, ਅਚਲ ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *ਵਿੱਚ,
    ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ inlen)
{

	ਜੇ (!EVP_Digest(ਵਿੱਚ, inlen, ਬਾਹਰਲਾ, ਨਿਰਾ, EVP_sha512(), ਨਿਰਾ))
		ਵਾਪਸ -1;
	ਵਾਪਸ 0;
}
#ਨਹੀਂਤਾਂ /* WITH_OPENSSL */
# ifdef HAVE_SHA2_H
#  include <sha2.h>
# endif
ਸਥਿਰ ਸਤਰਅੰਦਰ ਪੂਰਨ
crypto_hash_sha512(ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *ਬਾਹਰਲਾ, ਅਚਲ ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *ਵਿੱਚ,
    ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ inlen)
{

	SHA2_CTX ctx;

	SHA512Init(&ctx);
	SHA512Update(&ctx, ਵਿੱਚ, inlen);
	SHA512Final(ਬਾਹਰਲਾ, &ctx);
	ਵਾਪਸ 0;
}
#ਜੇ_ਅੰਤ /* WITH_OPENSSL */

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ crypto_sign_ed25519_SECRETKEYBYTES 64U
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ crypto_sign_ed25519_PUBLICKEYBYTES 32U
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ crypto_sign_ed25519_SEEDBYTES 32U
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ crypto_sign_ed25519_ਬਾਈਟਾਂ 64U

ਪੂਰਨ	crypto_sign_ed25519_detached(ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *, ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ *,
    ਅਚਲ ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *, ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ, ਅਚਲ ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *);
ਪੂਰਨ	crypto_sign_ed25519_verify_detached(ਅਚਲ ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *,
    ਅਚਲ ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *, ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ, ਅਚਲ ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *);
ਪੂਰਨ	crypto_sign_ed25519_keypair(ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *, ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *);
ਪੂਰਨ	crypto_sign_ed25519_ਬੀਜ_keypair(ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *, ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *,
    ਅਚਲ ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *);

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ crypto_kem_sntrup761_PUBLICKEYBYTES 1158
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ crypto_kem_sntrup761_SECRETKEYBYTES 1763
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ crypto_kem_sntrup761_CIPHERTEXTBYTES 1039
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ crypto_kem_sntrup761_ਬਾਈਟਾਂ 32

ਪੂਰਨ	crypto_kem_sntrup761_enc(ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *cstr, ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *k,
    ਅਚਲ ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *pk);
ਪੂਰਨ	crypto_kem_sntrup761_dec(ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *k,
    ਅਚਲ ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *cstr, ਅਚਲ ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *sk);
ਪੂਰਨ	crypto_kem_sntrup761_keypair(ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *pk, ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *sk);

/* ML-KEM-768 */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ crypto_kem_mlkem768_PUBLICKEYBYTES 1184
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ crypto_kem_mlkem768_SECRETKEYBYTES 2400
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ crypto_kem_mlkem768_CIPHERTEXTBYTES 1088
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ crypto_kem_mlkem768_ਬਾਈਟਾਂ 32
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ crypto_kem_mlkem768_ENCSEEDBYTES 32
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ crypto_kem_mlkem768_KEYPAIRSEEDBYTES 64

/* Aliases for MLKEM768 */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ MLKEM768_PUBLICKEYBYTES crypto_kem_mlkem768_PUBLICKEYBYTES
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ MLKEM768_SECRETKEYBYTES crypto_kem_mlkem768_SECRETKEYBYTES
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ MLKEM768_CIPHERTEXTBYTES crypto_kem_mlkem768_CIPHERTEXTBYTES
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ MLKEM768_ਬਾਈਟਾਂ crypto_kem_mlkem768_ਬਾਈਟਾਂ

ਪੂਰਨ crypto_kem_mlkem768_keypair(uint8_t pk[crypto_kem_mlkem768_PUBLICKEYBYTES],
    uint8_t sk[crypto_kem_mlkem768_SECRETKEYBYTES]);
ਪੂਰਨ crypto_kem_mlkem768_enc(uint8_t ct[crypto_kem_mlkem768_CIPHERTEXTBYTES],
    uint8_t shared_secret[crypto_kem_mlkem768_ਬਾਈਟਾਂ],
    ਅਚਲ uint8_t pk[crypto_kem_mlkem768_PUBLICKEYBYTES]);
ਪੂਰਨ crypto_kem_mlkem768_dec(uint8_t shared_secret[crypto_kem_mlkem768_ਬਾਈਟਾਂ],
    ਅਚਲ uint8_t ct[crypto_kem_mlkem768_CIPHERTEXTBYTES],
    ਅਚਲ uint8_t sk[crypto_kem_mlkem768_SECRETKEYBYTES]);
ਪੂਰਨ crypto_kem_mlkem768_keypair_seeded(uint8_t pk[crypto_kem_mlkem768_PUBLICKEYBYTES],
    uint8_t sk[crypto_kem_mlkem768_SECRETKEYBYTES], ਅਚਲ uint8_t ਬੀਜ[64]);
ਪੂਰਨ crypto_kem_mlkem768_enc_seeded(uint8_t ct[crypto_kem_mlkem768_CIPHERTEXTBYTES],
    uint8_t shared_secret[crypto_kem_mlkem768_ਬਾਈਟਾਂ],
    ਅਚਲ uint8_t pk[crypto_kem_mlkem768_PUBLICKEYBYTES],
    ਅਚਲ uint8_t ਬੀਜ[32]);

/* ML-DSA-44 */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ MLDSA44_PUBLICKEYBYTES 1312
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ MLDSA44_SECRETKEYBYTES 2560
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ MLDSA44_SIGBYTES 2420
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ MLDSA44_SEEDBYTES 32

ਪੂਰਨ crypto_sign_mldsa44_keypair(uint8_t pk[MLDSA44_PUBLICKEYBYTES],
    uint8_t sk[MLDSA44_SECRETKEYBYTES]);
ਪੂਰਨ crypto_sign_mldsa44(uint8_t sig[MLDSA44_SIGBYTES],
    ਅਚਲ uint8_t *ਸੁਨੇਹਾ, ਮਾਪ_t msglen,
    ਅਚਲ uint8_t *ctx, ਮਾਪ_t ctxlen,
    ਅਚਲ uint8_t sk[MLDSA44_SECRETKEYBYTES]);
ਪੂਰਨ crypto_sign_mldsa44_verify(ਅਚਲ uint8_t sig[MLDSA44_SIGBYTES],
    ਅਚਲ uint8_t *ਸੁਨੇਹਾ, ਮਾਪ_t msglen,
    ਅਚਲ uint8_t *ctx, ਮਾਪ_t ctxlen,
    ਅਚਲ uint8_t pk[MLDSA44_PUBLICKEYBYTES]);
ਪੂਰਨ crypto_sign_mldsa44_keypair_seeded(uint8_t pk[MLDSA44_PUBLICKEYBYTES],
    uint8_t sk[MLDSA44_SECRETKEYBYTES], ਅਚਲ uint8_t ਬੀਜ[MLDSA44_SEEDBYTES]);
ਪੂਰਨ crypto_sign_mldsa44_seeded(uint8_t sig[MLDSA44_SIGBYTES],
    ਅਚਲ uint8_t *ਸੁਨੇਹਾ, ਮਾਪ_t msglen,
    ਅਚਲ uint8_t *ctx, ਮਾਪ_t ctxlen,
    ਅਚਲ uint8_t sk[MLDSA44_SECRETKEYBYTES],
    ਅਚਲ uint8_t ਬੀਜ[MLDSA44_SEEDBYTES]);

/* ML-DSA-65 */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ MLDSA65_PUBLICKEYBYTES 1952
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ MLDSA65_SECRETKEYBYTES 4032
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ MLDSA65_SIGBYTES 3309
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ MLDSA65_SEEDBYTES 32

#ਜੇ 0
ਪੂਰਨ crypto_sign_mldsa65_keypair(uint8_t pk[MLDSA65_PUBLICKEYBYTES],
    uint8_t sk[MLDSA65_SECRETKEYBYTES]);
ਪੂਰਨ crypto_sign_mldsa65(uint8_t sig[MLDSA65_SIGBYTES],
    ਅਚਲ uint8_t *ਸੁਨੇਹਾ, ਮਾਪ_t msglen,
    ਅਚਲ uint8_t *ctx, ਮਾਪ_t ctxlen,
    ਅਚਲ uint8_t sk[MLDSA65_SECRETKEYBYTES]);
ਪੂਰਨ crypto_sign_mldsa65_verify(ਅਚਲ uint8_t sig[MLDSA65_SIGBYTES],
    ਅਚਲ uint8_t *ਸੁਨੇਹਾ, ਮਾਪ_t msglen,
    ਅਚਲ uint8_t *ctx, ਮਾਪ_t ctxlen,
    ਅਚਲ uint8_t pk[MLDSA65_PUBLICKEYBYTES]);
ਪੂਰਨ crypto_sign_mldsa65_keypair_seeded(uint8_t pk[MLDSA65_PUBLICKEYBYTES],
    uint8_t sk[MLDSA65_SECRETKEYBYTES], ਅਚਲ uint8_t ਬੀਜ[MLDSA65_SEEDBYTES]);
ਪੂਰਨ crypto_sign_mldsa65_seeded(uint8_t sig[MLDSA65_SIGBYTES],
    ਅਚਲ uint8_t *ਸੁਨੇਹਾ, ਮਾਪ_t msglen,
    ਅਚਲ uint8_t *ctx, ਮਾਪ_t ctxlen,
    ਅਚਲ uint8_t sk[MLDSA65_SECRETKEYBYTES],
    ਅਚਲ uint8_t ਬੀਜ[MLDSA65_SEEDBYTES]);
#ਜੇ_ਅੰਤ

/* ML-DSA-87 */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ MLDSA87_PUBLICKEYBYTES 2592
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ MLDSA87_SECRETKEYBYTES 4896
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ MLDSA87_SIGBYTES 4627
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ MLDSA87_SEEDBYTES 32

ਪੂਰਨ crypto_sign_mldsa87_keypair(uint8_t pk[MLDSA87_PUBLICKEYBYTES],
    uint8_t sk[MLDSA87_SECRETKEYBYTES]);
ਪੂਰਨ crypto_sign_mldsa87(uint8_t sig[MLDSA87_SIGBYTES],
    ਅਚਲ uint8_t *ਸੁਨੇਹਾ, ਮਾਪ_t msglen,
    ਅਚਲ uint8_t *ctx, ਮਾਪ_t ctxlen,
    ਅਚਲ uint8_t sk[MLDSA87_SECRETKEYBYTES]);
ਪੂਰਨ crypto_sign_mldsa87_verify(ਅਚਲ uint8_t sig[MLDSA87_SIGBYTES],
    ਅਚਲ uint8_t *ਸੁਨੇਹਾ, ਮਾਪ_t msglen,
    ਅਚਲ uint8_t *ctx, ਮਾਪ_t ctxlen,
    ਅਚਲ uint8_t pk[MLDSA87_PUBLICKEYBYTES]);
ਪੂਰਨ crypto_sign_mldsa87_keypair_seeded(uint8_t pk[MLDSA87_PUBLICKEYBYTES],
    uint8_t sk[MLDSA87_SECRETKEYBYTES], ਅਚਲ uint8_t ਬੀਜ[MLDSA87_SEEDBYTES]);
ਪੂਰਨ crypto_sign_mldsa87_seeded(uint8_t sig[MLDSA87_SIGBYTES],
    ਅਚਲ uint8_t *ਸੁਨੇਹਾ, ਮਾਪ_t msglen,
    ਅਚਲ uint8_t *ctx, ਮਾਪ_t ctxlen,
    ਅਚਲ uint8_t sk[MLDSA87_SECRETKEYBYTES],
    ਅਚਲ uint8_t ਬੀਜ[MLDSA87_SEEDBYTES]);

/* MLDSA44-Ed25519-SHA512 */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ MLDSA44_ED25519_PK_SZ (MLDSA44_PUBLICKEYBYTES + crypto_sign_ed25519_PUBLICKEYBYTES)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ MLDSA44_ED25519_SK_SZ (MLDSA44_SEEDBYTES + crypto_sign_ed25519_SEEDBYTES)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ MLDSA44_ED25519_SIG_SZ (MLDSA44_SIGBYTES + crypto_sign_ed25519_ਬਾਈਟਾਂ)

ਪੂਰਨ crypto_sign_mldsa44_ed25519_keygen(uint8_t pk[MLDSA44_ED25519_PK_SZ],
    uint8_t sk[MLDSA44_ED25519_SK_SZ]);
ਪੂਰਨ crypto_sign_mldsa44_ed25519_keygen_seeded(uint8_t pk[MLDSA44_ED25519_PK_SZ],
    uint8_t sk[MLDSA44_ED25519_SK_SZ],
    ਅਚਲ uint8_t mldsa_ਬੀਜ[MLDSA44_SEEDBYTES],
    ਅਚਲ uint8_t ed25519_ਬੀਜ[crypto_sign_ed25519_SEEDBYTES]);
ਪੂਰਨ crypto_sign_mldsa44_ed25519_sign(uint8_t sig[MLDSA44_ED25519_SIG_SZ],
    ਅਚਲ uint8_t *ਸੁਨੇਹਾ, ਮਾਪ_t msglen,
    ਅਚਲ uint8_t *ctx, ਮਾਪ_t ctxlen,
    ਅਚਲ uint8_t sk[MLDSA44_ED25519_SK_SZ]);
ਪੂਰਨ crypto_sign_mldsa44_ed25519_verify(ਅਚਲ uint8_t sig[MLDSA44_ED25519_SIG_SZ],
    ਅਚਲ uint8_t *ਸੁਨੇਹਾ, ਮਾਪ_t msglen,
    ਅਚਲ uint8_t *ctx, ਮਾਪ_t ctxlen,
    ਅਚਲ uint8_t pk[MLDSA44_ED25519_PK_SZ]);

/* Utility */
ਖਾਲੀ sha3_256(uint8_t digest[32], ਅਚਲ uint8_t *ਅੰਕੜੇ, ਮਾਪ_t len);
ਖਾਲੀ sha3_512(uint8_t digest[64], ਅਚਲ uint8_t *ਅੰਕੜੇ, ਮਾਪ_t len);

#ਜੇ_ਅੰਤ /* crypto_api_h */
