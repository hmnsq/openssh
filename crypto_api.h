/* $OpenBSD: crypto_api.h,v 1.13 2026/09/16 00:43:00 djm Exp $ */

/*
 * Assembled from generated headers and source files by Markus Friedl.
 * Placed in the public domain.
 */

#ifndef crypto_api_h
#define crypto_api_h

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <stdint.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>

ಪ್ರಕಾರನಿರ್ದೇಶ int8_t crypto_int8;
ಪ್ರಕಾರನಿರ್ದೇಶ uint8_t crypto_uint8;
ಪ್ರಕಾರನಿರ್ದೇಶ int16_t crypto_int16;
ಪ್ರಕಾರನಿರ್ದೇಶ uint16_t crypto_uint16;
ಪ್ರಕಾರನಿರ್ದೇಶ int32_t crypto_int32;
ಪ್ರಕಾರನಿರ್ದೇಶ uint32_t crypto_uint32;
ಪ್ರಕಾರನಿರ್ದೇಶ int64_t crypto_int64;
ಪ್ರಕಾರನಿರ್ದೇಶ uint64_t crypto_uint64;

#define randombytes(buf, buf_len) arc4random_buf((buf), (buf_len))
#define small_random32() arc4random()

#define crypto_hash_sha512_BYTES 64U

#ifdef WITH_OPENSSL
#ಅನ್ತರ್ಭಾವ <openssl/evp.h>
ಸ್ಥಿರ ಅನ್ತಃಸ್ಥ ಪೂರ್ಣಾಙ್ಕ
crypto_hash_sha512(unsigned ವರ್ಣ *out, ಧ್ರುವ unsigned ವರ್ಣ *in,
    unsigned long long inlen)
{

	ಯದಿ (!EVP_Digest(in, inlen, out, ರಿಕ್ತ, EVP_sha512(), ರಿಕ್ತ))
		ಪ್ರತ್ಯಾಗಮ -1;
	ಪ್ರತ್ಯಾಗಮ 0;
}
#ಅನ್ಯಥಾ /* WITH_OPENSSL */
# ifdef HAVE_SHA2_H
#  include <sha2.h>
# endif
ಸ್ಥಿರ ಅನ್ತಃಸ್ಥ ಪೂರ್ಣಾಙ್ಕ
crypto_hash_sha512(unsigned ವರ್ಣ *out, ಧ್ರುವ unsigned ವರ್ಣ *in,
    unsigned long long inlen)
{

	SHA2_CTX ctx;

	SHA512Init(&ctx);
	SHA512Update(&ctx, in, inlen);
	SHA512Final(out, &ctx);
	ಪ್ರತ್ಯಾಗಮ 0;
}
#endif /* WITH_OPENSSL */

#define crypto_sign_ed25519_SECRETKEYBYTES 64U
#define crypto_sign_ed25519_PUBLICKEYBYTES 32U
#define crypto_sign_ed25519_SEEDBYTES 32U
#define crypto_sign_ed25519_BYTES 64U

ಪೂರ್ಣಾಙ್ಕ	crypto_sign_ed25519_detached(unsigned ವರ್ಣ *, unsigned long long *,
    ಧ್ರುವ unsigned ವರ್ಣ *, unsigned long long, ಧ್ರುವ unsigned ವರ್ಣ *);
ಪೂರ್ಣಾಙ್ಕ	crypto_sign_ed25519_verify_detached(ಧ್ರುವ unsigned ವರ್ಣ *,
    ಧ್ರುವ unsigned ವರ್ಣ *, unsigned long long, ಧ್ರುವ unsigned ವರ್ಣ *);
ಪೂರ್ಣಾಙ್ಕ	crypto_sign_ed25519_keypair(unsigned ವರ್ಣ *, unsigned ವರ್ಣ *);
ಪೂರ್ಣಾಙ್ಕ	crypto_sign_ed25519_seed_keypair(unsigned ವರ್ಣ *, unsigned ವರ್ಣ *,
    ಧ್ರುವ unsigned ವರ್ಣ *);

#define crypto_kem_sntrup761_PUBLICKEYBYTES 1158
#define crypto_kem_sntrup761_SECRETKEYBYTES 1763
#define crypto_kem_sntrup761_CIPHERTEXTBYTES 1039
#define crypto_kem_sntrup761_BYTES 32

ಪೂರ್ಣಾಙ್ಕ	crypto_kem_sntrup761_enc(unsigned ವರ್ಣ *cstr, unsigned ವರ್ಣ *k,
    ಧ್ರುವ unsigned ವರ್ಣ *pk);
ಪೂರ್ಣಾಙ್ಕ	crypto_kem_sntrup761_dec(unsigned ವರ್ಣ *k,
    ಧ್ರುವ unsigned ವರ್ಣ *cstr, ಧ್ರುವ unsigned ವರ್ಣ *sk);
ಪೂರ್ಣಾಙ್ಕ	crypto_kem_sntrup761_keypair(unsigned ವರ್ಣ *pk, unsigned ವರ್ಣ *sk);

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

ಪೂರ್ಣಾಙ್ಕ crypto_kem_mlkem768_keypair(uint8_t pk[crypto_kem_mlkem768_PUBLICKEYBYTES],
    uint8_t sk[crypto_kem_mlkem768_SECRETKEYBYTES]);
ಪೂರ್ಣಾಙ್ಕ crypto_kem_mlkem768_enc(uint8_t ct[crypto_kem_mlkem768_CIPHERTEXTBYTES],
    uint8_t shared_secret[crypto_kem_mlkem768_BYTES],
    ಧ್ರುವ uint8_t pk[crypto_kem_mlkem768_PUBLICKEYBYTES]);
ಪೂರ್ಣಾಙ್ಕ crypto_kem_mlkem768_dec(uint8_t shared_secret[crypto_kem_mlkem768_BYTES],
    ಧ್ರುವ uint8_t ct[crypto_kem_mlkem768_CIPHERTEXTBYTES],
    ಧ್ರುವ uint8_t sk[crypto_kem_mlkem768_SECRETKEYBYTES]);
ಪೂರ್ಣಾಙ್ಕ crypto_kem_mlkem768_keypair_seeded(uint8_t pk[crypto_kem_mlkem768_PUBLICKEYBYTES],
    uint8_t sk[crypto_kem_mlkem768_SECRETKEYBYTES], ಧ್ರುವ uint8_t seed[64]);
ಪೂರ್ಣಾಙ್ಕ crypto_kem_mlkem768_enc_seeded(uint8_t ct[crypto_kem_mlkem768_CIPHERTEXTBYTES],
    uint8_t shared_secret[crypto_kem_mlkem768_BYTES],
    ಧ್ರುವ uint8_t pk[crypto_kem_mlkem768_PUBLICKEYBYTES],
    ಧ್ರುವ uint8_t seed[32]);

/* ML-DSA-44 */
#define MLDSA44_PUBLICKEYBYTES 1312
#define MLDSA44_SECRETKEYBYTES 2560
#define MLDSA44_SIGBYTES 2420
#define MLDSA44_SEEDBYTES 32

ಪೂರ್ಣಾಙ್ಕ crypto_sign_mldsa44_keypair(uint8_t pk[MLDSA44_PUBLICKEYBYTES],
    uint8_t sk[MLDSA44_SECRETKEYBYTES]);
ಪೂರ್ಣಾಙ್ಕ crypto_sign_mldsa44(uint8_t sig[MLDSA44_SIGBYTES],
    ಧ್ರುವ uint8_t *ಸಂದೇಶ, size_t msglen,
    ಧ್ರುವ uint8_t *ctx, size_t ctxlen,
    ಧ್ರುವ uint8_t sk[MLDSA44_SECRETKEYBYTES]);
ಪೂರ್ಣಾಙ್ಕ crypto_sign_mldsa44_verify(ಧ್ರುವ uint8_t sig[MLDSA44_SIGBYTES],
    ಧ್ರುವ uint8_t *ಸಂದೇಶ, size_t msglen,
    ಧ್ರುವ uint8_t *ctx, size_t ctxlen,
    ಧ್ರುವ uint8_t pk[MLDSA44_PUBLICKEYBYTES]);
ಪೂರ್ಣಾಙ್ಕ crypto_sign_mldsa44_keypair_seeded(uint8_t pk[MLDSA44_PUBLICKEYBYTES],
    uint8_t sk[MLDSA44_SECRETKEYBYTES], ಧ್ರುವ uint8_t seed[MLDSA44_SEEDBYTES]);
ಪೂರ್ಣಾಙ್ಕ crypto_sign_mldsa44_seeded(uint8_t sig[MLDSA44_SIGBYTES],
    ಧ್ರುವ uint8_t *ಸಂದೇಶ, size_t msglen,
    ಧ್ರುವ uint8_t *ctx, size_t ctxlen,
    ಧ್ರುವ uint8_t sk[MLDSA44_SECRETKEYBYTES],
    ಧ್ರುವ uint8_t seed[MLDSA44_SEEDBYTES]);

/* ML-DSA-65 */
#define MLDSA65_PUBLICKEYBYTES 1952
#define MLDSA65_SECRETKEYBYTES 4032
#define MLDSA65_SIGBYTES 3309
#define MLDSA65_SEEDBYTES 32

#ಯದಿ 0
ಪೂರ್ಣಾಙ್ಕ crypto_sign_mldsa65_keypair(uint8_t pk[MLDSA65_PUBLICKEYBYTES],
    uint8_t sk[MLDSA65_SECRETKEYBYTES]);
ಪೂರ್ಣಾಙ್ಕ crypto_sign_mldsa65(uint8_t sig[MLDSA65_SIGBYTES],
    ಧ್ರುವ uint8_t *ಸಂದೇಶ, size_t msglen,
    ಧ್ರುವ uint8_t *ctx, size_t ctxlen,
    ಧ್ರುವ uint8_t sk[MLDSA65_SECRETKEYBYTES]);
ಪೂರ್ಣಾಙ್ಕ crypto_sign_mldsa65_verify(ಧ್ರುವ uint8_t sig[MLDSA65_SIGBYTES],
    ಧ್ರುವ uint8_t *ಸಂದೇಶ, size_t msglen,
    ಧ್ರುವ uint8_t *ctx, size_t ctxlen,
    ಧ್ರುವ uint8_t pk[MLDSA65_PUBLICKEYBYTES]);
ಪೂರ್ಣಾಙ್ಕ crypto_sign_mldsa65_keypair_seeded(uint8_t pk[MLDSA65_PUBLICKEYBYTES],
    uint8_t sk[MLDSA65_SECRETKEYBYTES], ಧ್ರುವ uint8_t seed[MLDSA65_SEEDBYTES]);
ಪೂರ್ಣಾಙ್ಕ crypto_sign_mldsa65_seeded(uint8_t sig[MLDSA65_SIGBYTES],
    ಧ್ರುವ uint8_t *ಸಂದೇಶ, size_t msglen,
    ಧ್ರುವ uint8_t *ctx, size_t ctxlen,
    ಧ್ರುವ uint8_t sk[MLDSA65_SECRETKEYBYTES],
    ಧ್ರುವ uint8_t seed[MLDSA65_SEEDBYTES]);
#endif

/* ML-DSA-87 */
#define MLDSA87_PUBLICKEYBYTES 2592
#define MLDSA87_SECRETKEYBYTES 4896
#define MLDSA87_SIGBYTES 4627
#define MLDSA87_SEEDBYTES 32

ಪೂರ್ಣಾಙ್ಕ crypto_sign_mldsa87_keypair(uint8_t pk[MLDSA87_PUBLICKEYBYTES],
    uint8_t sk[MLDSA87_SECRETKEYBYTES]);
ಪೂರ್ಣಾಙ್ಕ crypto_sign_mldsa87(uint8_t sig[MLDSA87_SIGBYTES],
    ಧ್ರುವ uint8_t *ಸಂದೇಶ, size_t msglen,
    ಧ್ರುವ uint8_t *ctx, size_t ctxlen,
    ಧ್ರುವ uint8_t sk[MLDSA87_SECRETKEYBYTES]);
ಪೂರ್ಣಾಙ್ಕ crypto_sign_mldsa87_verify(ಧ್ರುವ uint8_t sig[MLDSA87_SIGBYTES],
    ಧ್ರುವ uint8_t *ಸಂದೇಶ, size_t msglen,
    ಧ್ರುವ uint8_t *ctx, size_t ctxlen,
    ಧ್ರುವ uint8_t pk[MLDSA87_PUBLICKEYBYTES]);
ಪೂರ್ಣಾಙ್ಕ crypto_sign_mldsa87_keypair_seeded(uint8_t pk[MLDSA87_PUBLICKEYBYTES],
    uint8_t sk[MLDSA87_SECRETKEYBYTES], ಧ್ರುವ uint8_t seed[MLDSA87_SEEDBYTES]);
ಪೂರ್ಣಾಙ್ಕ crypto_sign_mldsa87_seeded(uint8_t sig[MLDSA87_SIGBYTES],
    ಧ್ರುವ uint8_t *ಸಂದೇಶ, size_t msglen,
    ಧ್ರುವ uint8_t *ctx, size_t ctxlen,
    ಧ್ರುವ uint8_t sk[MLDSA87_SECRETKEYBYTES],
    ಧ್ರುವ uint8_t seed[MLDSA87_SEEDBYTES]);

/* MLDSA44-Ed25519-SHA512 */
#define MLDSA44_ED25519_PK_SZ (MLDSA44_PUBLICKEYBYTES + crypto_sign_ed25519_PUBLICKEYBYTES)
#define MLDSA44_ED25519_SK_SZ (MLDSA44_SEEDBYTES + crypto_sign_ed25519_SEEDBYTES)
#define MLDSA44_ED25519_SIG_SZ (MLDSA44_SIGBYTES + crypto_sign_ed25519_BYTES)

ಪೂರ್ಣಾಙ್ಕ crypto_sign_mldsa44_ed25519_keygen(uint8_t pk[MLDSA44_ED25519_PK_SZ],
    uint8_t sk[MLDSA44_ED25519_SK_SZ]);
ಪೂರ್ಣಾಙ್ಕ crypto_sign_mldsa44_ed25519_keygen_seeded(uint8_t pk[MLDSA44_ED25519_PK_SZ],
    uint8_t sk[MLDSA44_ED25519_SK_SZ],
    ಧ್ರುವ uint8_t mldsa_seed[MLDSA44_SEEDBYTES],
    ಧ್ರುವ uint8_t ed25519_seed[crypto_sign_ed25519_SEEDBYTES]);
ಪೂರ್ಣಾಙ್ಕ crypto_sign_mldsa44_ed25519_sign(uint8_t sig[MLDSA44_ED25519_SIG_SZ],
    ಧ್ರುವ uint8_t *ಸಂದೇಶ, size_t msglen,
    ಧ್ರುವ uint8_t *ctx, size_t ctxlen,
    ಧ್ರುವ uint8_t sk[MLDSA44_ED25519_SK_SZ]);
ಪೂರ್ಣಾಙ್ಕ crypto_sign_mldsa44_ed25519_verify(ಧ್ರುವ uint8_t sig[MLDSA44_ED25519_SIG_SZ],
    ಧ್ರುವ uint8_t *ಸಂದೇಶ, size_t msglen,
    ಧ್ರುವ uint8_t *ctx, size_t ctxlen,
    ಧ್ರುವ uint8_t pk[MLDSA44_ED25519_PK_SZ]);

/* Utility */
ಶೂನ್ಯ sha3_256(uint8_t digest[32], ಧ್ರುವ uint8_t *data, size_t len);
ಶೂನ್ಯ sha3_512(uint8_t digest[64], ಧ್ರುವ uint8_t *data, size_t len);

#endif /* crypto_api_h */
