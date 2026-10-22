/* $OpenBSD: crypto_api.h,v 1.13 2026/09/16 00:43:00 djm Exp $ */

/*
 * Assembled from generated headers and source files by Markus Friedl.
 * Placed in the public domain.
 */

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ crypto_api_h
#ವ್ಯಾಖ್ಯಾನಿಸು crypto_api_h

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <stdint.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ int8_t crypto_int8;
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ uint8_t crypto_uint8;
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ int16_t crypto_int16;
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ uint16_t crypto_uint16;
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ int32_t crypto_int32;
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ uint32_t crypto_uint32;
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ int64_t crypto_int64;
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ uint64_t crypto_uint64;

#ವ್ಯಾಖ್ಯಾನಿಸು randombytes(buf, buf_len) arc4random_buf((buf), (buf_len))
#ವ್ಯಾಖ್ಯಾನಿಸು small_random32() arc4random()

#ವ್ಯಾಖ್ಯಾನಿಸು crypto_hash_sha512_ಬೈಟುಗಳು 64U

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
#ಅನ್ತರ್ಭಾವ <openssl/evp.h>
ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಪೂರ್ಣಾಂಕ
crypto_hash_sha512(ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *ಹೊರಹೋಗು, ಸ್ಥಿರಾಂಕ ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *ಒಳ,
    ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ inlen)
{

	ಆದರೆ (!EVP_Digest(ಒಳ, inlen, ಹೊರಹೋಗು, ಖಾಲಿ, EVP_sha512(), ಖಾಲಿ))
		ಹಿಂತಿರುಗಿ -1;
	ಹಿಂತಿರುಗಿ 0;
}
#ಇಲ್ಲದಿದ್ದರೆ /* WITH_OPENSSL */
# ifdef HAVE_SHA2_H
#  include <sha2.h>
# endif
ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಪೂರ್ಣಾಂಕ
crypto_hash_sha512(ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *ಹೊರಹೋಗು, ಸ್ಥಿರಾಂಕ ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *ಒಳ,
    ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ inlen)
{

	SHA2_CTX ctx;

	SHA512Init(&ctx);
	SHA512Update(&ctx, ಒಳ, inlen);
	SHA512Final(ಹೊರಹೋಗು, &ctx);
	ಹಿಂತಿರುಗಿ 0;
}
#ಆದರೆ_ಅಂತ್ಯ /* WITH_OPENSSL */

#ವ್ಯಾಖ್ಯಾನಿಸು crypto_sign_ed25519_SECRETKEYBYTES 64U
#ವ್ಯಾಖ್ಯಾನಿಸು crypto_sign_ed25519_PUBLICKEYBYTES 32U
#ವ್ಯಾಖ್ಯಾನಿಸು crypto_sign_ed25519_SEEDBYTES 32U
#ವ್ಯಾಖ್ಯಾನಿಸು crypto_sign_ed25519_ಬೈಟುಗಳು 64U

ಪೂರ್ಣಾಂಕ	crypto_sign_ed25519_detached(ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *, ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ *,
    ಸ್ಥಿರಾಂಕ ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *, ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ, ಸ್ಥಿರಾಂಕ ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *);
ಪೂರ್ಣಾಂಕ	crypto_sign_ed25519_verify_detached(ಸ್ಥಿರಾಂಕ ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *,
    ಸ್ಥಿರಾಂಕ ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *, ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ, ಸ್ಥಿರಾಂಕ ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *);
ಪೂರ್ಣಾಂಕ	crypto_sign_ed25519_keypair(ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *, ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *);
ಪೂರ್ಣಾಂಕ	crypto_sign_ed25519_ಬೀಜ_keypair(ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *, ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *,
    ಸ್ಥಿರಾಂಕ ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *);

#ವ್ಯಾಖ್ಯಾನಿಸು crypto_kem_sntrup761_PUBLICKEYBYTES 1158
#ವ್ಯಾಖ್ಯಾನಿಸು crypto_kem_sntrup761_SECRETKEYBYTES 1763
#ವ್ಯಾಖ್ಯಾನಿಸು crypto_kem_sntrup761_CIPHERTEXTBYTES 1039
#ವ್ಯಾಖ್ಯಾನಿಸು crypto_kem_sntrup761_ಬೈಟುಗಳು 32

ಪೂರ್ಣಾಂಕ	crypto_kem_sntrup761_enc(ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *cstr, ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *k,
    ಸ್ಥಿರಾಂಕ ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *pk);
ಪೂರ್ಣಾಂಕ	crypto_kem_sntrup761_dec(ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *k,
    ಸ್ಥಿರಾಂಕ ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *cstr, ಸ್ಥಿರಾಂಕ ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *sk);
ಪೂರ್ಣಾಂಕ	crypto_kem_sntrup761_keypair(ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *pk, ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *sk);

/* ML-KEM-768 */
#ವ್ಯಾಖ್ಯಾನಿಸು crypto_kem_mlkem768_PUBLICKEYBYTES 1184
#ವ್ಯಾಖ್ಯಾನಿಸು crypto_kem_mlkem768_SECRETKEYBYTES 2400
#ವ್ಯಾಖ್ಯಾನಿಸು crypto_kem_mlkem768_CIPHERTEXTBYTES 1088
#ವ್ಯಾಖ್ಯಾನಿಸು crypto_kem_mlkem768_ಬೈಟುಗಳು 32
#ವ್ಯಾಖ್ಯಾನಿಸು crypto_kem_mlkem768_ENCSEEDBYTES 32
#ವ್ಯಾಖ್ಯಾನಿಸು crypto_kem_mlkem768_KEYPAIRSEEDBYTES 64

/* Aliases for MLKEM768 */
#ವ್ಯಾಖ್ಯಾನಿಸು MLKEM768_PUBLICKEYBYTES crypto_kem_mlkem768_PUBLICKEYBYTES
#ವ್ಯಾಖ್ಯಾನಿಸು MLKEM768_SECRETKEYBYTES crypto_kem_mlkem768_SECRETKEYBYTES
#ವ್ಯಾಖ್ಯಾನಿಸು MLKEM768_CIPHERTEXTBYTES crypto_kem_mlkem768_CIPHERTEXTBYTES
#ವ್ಯಾಖ್ಯಾನಿಸು MLKEM768_ಬೈಟುಗಳು crypto_kem_mlkem768_ಬೈಟುಗಳು

ಪೂರ್ಣಾಂಕ crypto_kem_mlkem768_keypair(uint8_t pk[crypto_kem_mlkem768_PUBLICKEYBYTES],
    uint8_t sk[crypto_kem_mlkem768_SECRETKEYBYTES]);
ಪೂರ್ಣಾಂಕ crypto_kem_mlkem768_enc(uint8_t ct[crypto_kem_mlkem768_CIPHERTEXTBYTES],
    uint8_t shared_secret[crypto_kem_mlkem768_ಬೈಟುಗಳು],
    ಸ್ಥಿರಾಂಕ uint8_t pk[crypto_kem_mlkem768_PUBLICKEYBYTES]);
ಪೂರ್ಣಾಂಕ crypto_kem_mlkem768_dec(uint8_t shared_secret[crypto_kem_mlkem768_ಬೈಟುಗಳು],
    ಸ್ಥಿರಾಂಕ uint8_t ct[crypto_kem_mlkem768_CIPHERTEXTBYTES],
    ಸ್ಥಿರಾಂಕ uint8_t sk[crypto_kem_mlkem768_SECRETKEYBYTES]);
ಪೂರ್ಣಾಂಕ crypto_kem_mlkem768_keypair_seeded(uint8_t pk[crypto_kem_mlkem768_PUBLICKEYBYTES],
    uint8_t sk[crypto_kem_mlkem768_SECRETKEYBYTES], ಸ್ಥಿರಾಂಕ uint8_t ಬೀಜ[64]);
ಪೂರ್ಣಾಂಕ crypto_kem_mlkem768_enc_seeded(uint8_t ct[crypto_kem_mlkem768_CIPHERTEXTBYTES],
    uint8_t shared_secret[crypto_kem_mlkem768_ಬೈಟುಗಳು],
    ಸ್ಥಿರಾಂಕ uint8_t pk[crypto_kem_mlkem768_PUBLICKEYBYTES],
    ಸ್ಥಿರಾಂಕ uint8_t ಬೀಜ[32]);

/* ML-DSA-44 */
#ವ್ಯಾಖ್ಯಾನಿಸು MLDSA44_PUBLICKEYBYTES 1312
#ವ್ಯಾಖ್ಯಾನಿಸು MLDSA44_SECRETKEYBYTES 2560
#ವ್ಯಾಖ್ಯಾನಿಸು MLDSA44_SIGBYTES 2420
#ವ್ಯಾಖ್ಯಾನಿಸು MLDSA44_SEEDBYTES 32

ಪೂರ್ಣಾಂಕ crypto_sign_mldsa44_keypair(uint8_t pk[MLDSA44_PUBLICKEYBYTES],
    uint8_t sk[MLDSA44_SECRETKEYBYTES]);
ಪೂರ್ಣಾಂಕ crypto_sign_mldsa44(uint8_t sig[MLDSA44_SIGBYTES],
    ಸ್ಥಿರಾಂಕ uint8_t *ಸಂದೇಶ, ಗಾತ್ರ_t msglen,
    ಸ್ಥಿರಾಂಕ uint8_t *ctx, ಗಾತ್ರ_t ctxlen,
    ಸ್ಥಿರಾಂಕ uint8_t sk[MLDSA44_SECRETKEYBYTES]);
ಪೂರ್ಣಾಂಕ crypto_sign_mldsa44_verify(ಸ್ಥಿರಾಂಕ uint8_t sig[MLDSA44_SIGBYTES],
    ಸ್ಥಿರಾಂಕ uint8_t *ಸಂದೇಶ, ಗಾತ್ರ_t msglen,
    ಸ್ಥಿರಾಂಕ uint8_t *ctx, ಗಾತ್ರ_t ctxlen,
    ಸ್ಥಿರಾಂಕ uint8_t pk[MLDSA44_PUBLICKEYBYTES]);
ಪೂರ್ಣಾಂಕ crypto_sign_mldsa44_keypair_seeded(uint8_t pk[MLDSA44_PUBLICKEYBYTES],
    uint8_t sk[MLDSA44_SECRETKEYBYTES], ಸ್ಥಿರಾಂಕ uint8_t ಬೀಜ[MLDSA44_SEEDBYTES]);
ಪೂರ್ಣಾಂಕ crypto_sign_mldsa44_seeded(uint8_t sig[MLDSA44_SIGBYTES],
    ಸ್ಥಿರಾಂಕ uint8_t *ಸಂದೇಶ, ಗಾತ್ರ_t msglen,
    ಸ್ಥಿರಾಂಕ uint8_t *ctx, ಗಾತ್ರ_t ctxlen,
    ಸ್ಥಿರಾಂಕ uint8_t sk[MLDSA44_SECRETKEYBYTES],
    ಸ್ಥಿರಾಂಕ uint8_t ಬೀಜ[MLDSA44_SEEDBYTES]);

/* ML-DSA-65 */
#ವ್ಯಾಖ್ಯಾನಿಸು MLDSA65_PUBLICKEYBYTES 1952
#ವ್ಯಾಖ್ಯಾನಿಸು MLDSA65_SECRETKEYBYTES 4032
#ವ್ಯಾಖ್ಯಾನಿಸು MLDSA65_SIGBYTES 3309
#ವ್ಯಾಖ್ಯಾನಿಸು MLDSA65_SEEDBYTES 32

#ಆದರೆ 0
ಪೂರ್ಣಾಂಕ crypto_sign_mldsa65_keypair(uint8_t pk[MLDSA65_PUBLICKEYBYTES],
    uint8_t sk[MLDSA65_SECRETKEYBYTES]);
ಪೂರ್ಣಾಂಕ crypto_sign_mldsa65(uint8_t sig[MLDSA65_SIGBYTES],
    ಸ್ಥಿರಾಂಕ uint8_t *ಸಂದೇಶ, ಗಾತ್ರ_t msglen,
    ಸ್ಥಿರಾಂಕ uint8_t *ctx, ಗಾತ್ರ_t ctxlen,
    ಸ್ಥಿರಾಂಕ uint8_t sk[MLDSA65_SECRETKEYBYTES]);
ಪೂರ್ಣಾಂಕ crypto_sign_mldsa65_verify(ಸ್ಥಿರಾಂಕ uint8_t sig[MLDSA65_SIGBYTES],
    ಸ್ಥಿರಾಂಕ uint8_t *ಸಂದೇಶ, ಗಾತ್ರ_t msglen,
    ಸ್ಥಿರಾಂಕ uint8_t *ctx, ಗಾತ್ರ_t ctxlen,
    ಸ್ಥಿರಾಂಕ uint8_t pk[MLDSA65_PUBLICKEYBYTES]);
ಪೂರ್ಣಾಂಕ crypto_sign_mldsa65_keypair_seeded(uint8_t pk[MLDSA65_PUBLICKEYBYTES],
    uint8_t sk[MLDSA65_SECRETKEYBYTES], ಸ್ಥಿರಾಂಕ uint8_t ಬೀಜ[MLDSA65_SEEDBYTES]);
ಪೂರ್ಣಾಂಕ crypto_sign_mldsa65_seeded(uint8_t sig[MLDSA65_SIGBYTES],
    ಸ್ಥಿರಾಂಕ uint8_t *ಸಂದೇಶ, ಗಾತ್ರ_t msglen,
    ಸ್ಥಿರಾಂಕ uint8_t *ctx, ಗಾತ್ರ_t ctxlen,
    ಸ್ಥಿರಾಂಕ uint8_t sk[MLDSA65_SECRETKEYBYTES],
    ಸ್ಥಿರಾಂಕ uint8_t ಬೀಜ[MLDSA65_SEEDBYTES]);
#ಆದರೆ_ಅಂತ್ಯ

/* ML-DSA-87 */
#ವ್ಯಾಖ್ಯಾನಿಸು MLDSA87_PUBLICKEYBYTES 2592
#ವ್ಯಾಖ್ಯಾನಿಸು MLDSA87_SECRETKEYBYTES 4896
#ವ್ಯಾಖ್ಯಾನಿಸು MLDSA87_SIGBYTES 4627
#ವ್ಯಾಖ್ಯಾನಿಸು MLDSA87_SEEDBYTES 32

ಪೂರ್ಣಾಂಕ crypto_sign_mldsa87_keypair(uint8_t pk[MLDSA87_PUBLICKEYBYTES],
    uint8_t sk[MLDSA87_SECRETKEYBYTES]);
ಪೂರ್ಣಾಂಕ crypto_sign_mldsa87(uint8_t sig[MLDSA87_SIGBYTES],
    ಸ್ಥಿರಾಂಕ uint8_t *ಸಂದೇಶ, ಗಾತ್ರ_t msglen,
    ಸ್ಥಿರಾಂಕ uint8_t *ctx, ಗಾತ್ರ_t ctxlen,
    ಸ್ಥಿರಾಂಕ uint8_t sk[MLDSA87_SECRETKEYBYTES]);
ಪೂರ್ಣಾಂಕ crypto_sign_mldsa87_verify(ಸ್ಥಿರಾಂಕ uint8_t sig[MLDSA87_SIGBYTES],
    ಸ್ಥಿರಾಂಕ uint8_t *ಸಂದೇಶ, ಗಾತ್ರ_t msglen,
    ಸ್ಥಿರಾಂಕ uint8_t *ctx, ಗಾತ್ರ_t ctxlen,
    ಸ್ಥಿರಾಂಕ uint8_t pk[MLDSA87_PUBLICKEYBYTES]);
ಪೂರ್ಣಾಂಕ crypto_sign_mldsa87_keypair_seeded(uint8_t pk[MLDSA87_PUBLICKEYBYTES],
    uint8_t sk[MLDSA87_SECRETKEYBYTES], ಸ್ಥಿರಾಂಕ uint8_t ಬೀಜ[MLDSA87_SEEDBYTES]);
ಪೂರ್ಣಾಂಕ crypto_sign_mldsa87_seeded(uint8_t sig[MLDSA87_SIGBYTES],
    ಸ್ಥಿರಾಂಕ uint8_t *ಸಂದೇಶ, ಗಾತ್ರ_t msglen,
    ಸ್ಥಿರಾಂಕ uint8_t *ctx, ಗಾತ್ರ_t ctxlen,
    ಸ್ಥಿರಾಂಕ uint8_t sk[MLDSA87_SECRETKEYBYTES],
    ಸ್ಥಿರಾಂಕ uint8_t ಬೀಜ[MLDSA87_SEEDBYTES]);

/* MLDSA44-Ed25519-SHA512 */
#ವ್ಯಾಖ್ಯಾನಿಸು MLDSA44_ED25519_PK_SZ (MLDSA44_PUBLICKEYBYTES + crypto_sign_ed25519_PUBLICKEYBYTES)
#ವ್ಯಾಖ್ಯಾನಿಸು MLDSA44_ED25519_SK_SZ (MLDSA44_SEEDBYTES + crypto_sign_ed25519_SEEDBYTES)
#ವ್ಯಾಖ್ಯಾನಿಸು MLDSA44_ED25519_SIG_SZ (MLDSA44_SIGBYTES + crypto_sign_ed25519_ಬೈಟುಗಳು)

ಪೂರ್ಣಾಂಕ crypto_sign_mldsa44_ed25519_keygen(uint8_t pk[MLDSA44_ED25519_PK_SZ],
    uint8_t sk[MLDSA44_ED25519_SK_SZ]);
ಪೂರ್ಣಾಂಕ crypto_sign_mldsa44_ed25519_keygen_seeded(uint8_t pk[MLDSA44_ED25519_PK_SZ],
    uint8_t sk[MLDSA44_ED25519_SK_SZ],
    ಸ್ಥಿರಾಂಕ uint8_t mldsa_ಬೀಜ[MLDSA44_SEEDBYTES],
    ಸ್ಥಿರಾಂಕ uint8_t ed25519_ಬೀಜ[crypto_sign_ed25519_SEEDBYTES]);
ಪೂರ್ಣಾಂಕ crypto_sign_mldsa44_ed25519_sign(uint8_t sig[MLDSA44_ED25519_SIG_SZ],
    ಸ್ಥಿರಾಂಕ uint8_t *ಸಂದೇಶ, ಗಾತ್ರ_t msglen,
    ಸ್ಥಿರಾಂಕ uint8_t *ctx, ಗಾತ್ರ_t ctxlen,
    ಸ್ಥಿರಾಂಕ uint8_t sk[MLDSA44_ED25519_SK_SZ]);
ಪೂರ್ಣಾಂಕ crypto_sign_mldsa44_ed25519_verify(ಸ್ಥಿರಾಂಕ uint8_t sig[MLDSA44_ED25519_SIG_SZ],
    ಸ್ಥಿರಾಂಕ uint8_t *ಸಂದೇಶ, ಗಾತ್ರ_t msglen,
    ಸ್ಥಿರಾಂಕ uint8_t *ctx, ಗಾತ್ರ_t ctxlen,
    ಸ್ಥಿರಾಂಕ uint8_t pk[MLDSA44_ED25519_PK_SZ]);

/* Utility */
ಶೂನ್ಯ sha3_256(uint8_t digest[32], ಸ್ಥಿರಾಂಕ uint8_t *ದತ್ತಾಂಶ, ಗಾತ್ರ_t len);
ಶೂನ್ಯ sha3_512(uint8_t digest[64], ಸ್ಥಿರಾಂಕ uint8_t *ದತ್ತಾಂಶ, ಗಾತ್ರ_t len);

#ಆದರೆ_ಅಂತ್ಯ /* crypto_api_h */
