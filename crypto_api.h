/* $OpenBSD: crypto_api.h,v 1.13 2026/09/16 00:43:00 djm Exp $ */

/*
 * Assembled from generated headers and source files by Markus Friedl.
 * Placed in the public domain.
 */

#جيڪڏهن_وصف_نه_ٿيل crypto_api_h
#وصف_ڪريو crypto_api_h

#ضمن "includes.h"

#ضمن <stdint.h>
#ضمن <stdlib.h>

تعريفنوع int8_t crypto_int8;
تعريفنوع uint8_t crypto_uint8;
تعريفنوع int16_t crypto_int16;
تعريفنوع uint16_t crypto_uint16;
تعريفنوع int32_t crypto_int32;
تعريفنوع uint32_t crypto_uint32;
تعريفنوع int64_t crypto_int64;
تعريفنوع uint64_t crypto_uint64;

#وصف_ڪريو randombytes(buf, buf_len) arc4random_buf((buf), (buf_len))
#وصف_ڪريو small_random32() arc4random()

#وصف_ڪريو crypto_hash_sha512_بائيٽون 64U

#جيڪڏهن_وصف_ٿيل WITH_OPENSSL
#ضمن <openssl/evp.h>
ساكن مضمن صحيح
crypto_hash_sha512(بنانشان حرف *ٻاهريون, ثابت بنانشان حرف *اندريون,
    بنانشان ڊگهو ڊگهو inlen)
{

	إذا (!EVP_Digest(اندريون, inlen, ٻاهريون, عدم, EVP_sha512(), عدم))
		أرجع -1;
	أرجع 0;
}
#وإلا /* WITH_OPENSSL */
# ifdef HAVE_SHA2_H
#  include <sha2.h>
# endif
ساكن مضمن صحيح
crypto_hash_sha512(بنانشان حرف *ٻاهريون, ثابت بنانشان حرف *اندريون,
    بنانشان ڊگهو ڊگهو inlen)
{

	SHA2_CTX ctx;

	SHA512Init(&ctx);
	SHA512Update(&ctx, اندريون, inlen);
	SHA512Final(ٻاهريون, &ctx);
	أرجع 0;
}
#جيڪڏهن_پورو /* WITH_OPENSSL */

#وصف_ڪريو crypto_sign_ed25519_SECRETKEYBYTES 64U
#وصف_ڪريو crypto_sign_ed25519_PUBLICKEYBYTES 32U
#وصف_ڪريو crypto_sign_ed25519_SEEDBYTES 32U
#وصف_ڪريو crypto_sign_ed25519_بائيٽون 64U

صحيح	crypto_sign_ed25519_detached(بنانشان حرف *, بنانشان ڊگهو ڊگهو *,
    ثابت بنانشان حرف *, بنانشان ڊگهو ڊگهو, ثابت بنانشان حرف *);
صحيح	crypto_sign_ed25519_verify_detached(ثابت بنانشان حرف *,
    ثابت بنانشان حرف *, بنانشان ڊگهو ڊگهو, ثابت بنانشان حرف *);
صحيح	crypto_sign_ed25519_keypair(بنانشان حرف *, بنانشان حرف *);
صحيح	crypto_sign_ed25519_ٻج_keypair(بنانشان حرف *, بنانشان حرف *,
    ثابت بنانشان حرف *);

#وصف_ڪريو crypto_kem_sntrup761_PUBLICKEYBYTES 1158
#وصف_ڪريو crypto_kem_sntrup761_SECRETKEYBYTES 1763
#وصف_ڪريو crypto_kem_sntrup761_CIPHERTEXTBYTES 1039
#وصف_ڪريو crypto_kem_sntrup761_بائيٽون 32

صحيح	crypto_kem_sntrup761_enc(بنانشان حرف *cstr, بنانشان حرف *k,
    ثابت بنانشان حرف *pk);
صحيح	crypto_kem_sntrup761_dec(بنانشان حرف *k,
    ثابت بنانشان حرف *cstr, ثابت بنانشان حرف *sk);
صحيح	crypto_kem_sntrup761_keypair(بنانشان حرف *pk, بنانشان حرف *sk);

/* ML-KEM-768 */
#وصف_ڪريو crypto_kem_mlkem768_PUBLICKEYBYTES 1184
#وصف_ڪريو crypto_kem_mlkem768_SECRETKEYBYTES 2400
#وصف_ڪريو crypto_kem_mlkem768_CIPHERTEXTBYTES 1088
#وصف_ڪريو crypto_kem_mlkem768_بائيٽون 32
#وصف_ڪريو crypto_kem_mlkem768_ENCSEEDBYTES 32
#وصف_ڪريو crypto_kem_mlkem768_KEYPAIRSEEDBYTES 64

/* Aliases for MLKEM768 */
#وصف_ڪريو MLKEM768_PUBLICKEYBYTES crypto_kem_mlkem768_PUBLICKEYBYTES
#وصف_ڪريو MLKEM768_SECRETKEYBYTES crypto_kem_mlkem768_SECRETKEYBYTES
#وصف_ڪريو MLKEM768_CIPHERTEXTBYTES crypto_kem_mlkem768_CIPHERTEXTBYTES
#وصف_ڪريو MLKEM768_بائيٽون crypto_kem_mlkem768_بائيٽون

صحيح crypto_kem_mlkem768_keypair(uint8_t pk[crypto_kem_mlkem768_PUBLICKEYBYTES],
    uint8_t sk[crypto_kem_mlkem768_SECRETKEYBYTES]);
صحيح crypto_kem_mlkem768_enc(uint8_t ct[crypto_kem_mlkem768_CIPHERTEXTBYTES],
    uint8_t shared_secret[crypto_kem_mlkem768_بائيٽون],
    ثابت uint8_t pk[crypto_kem_mlkem768_PUBLICKEYBYTES]);
صحيح crypto_kem_mlkem768_dec(uint8_t shared_secret[crypto_kem_mlkem768_بائيٽون],
    ثابت uint8_t ct[crypto_kem_mlkem768_CIPHERTEXTBYTES],
    ثابت uint8_t sk[crypto_kem_mlkem768_SECRETKEYBYTES]);
صحيح crypto_kem_mlkem768_keypair_seeded(uint8_t pk[crypto_kem_mlkem768_PUBLICKEYBYTES],
    uint8_t sk[crypto_kem_mlkem768_SECRETKEYBYTES], ثابت uint8_t ٻج[64]);
صحيح crypto_kem_mlkem768_enc_seeded(uint8_t ct[crypto_kem_mlkem768_CIPHERTEXTBYTES],
    uint8_t shared_secret[crypto_kem_mlkem768_بائيٽون],
    ثابت uint8_t pk[crypto_kem_mlkem768_PUBLICKEYBYTES],
    ثابت uint8_t ٻج[32]);

/* ML-DSA-44 */
#وصف_ڪريو MLDSA44_PUBLICKEYBYTES 1312
#وصف_ڪريو MLDSA44_SECRETKEYBYTES 2560
#وصف_ڪريو MLDSA44_SIGBYTES 2420
#وصف_ڪريو MLDSA44_SEEDBYTES 32

صحيح crypto_sign_mldsa44_keypair(uint8_t pk[MLDSA44_PUBLICKEYBYTES],
    uint8_t sk[MLDSA44_SECRETKEYBYTES]);
صحيح crypto_sign_mldsa44(uint8_t sig[MLDSA44_SIGBYTES],
    ثابت uint8_t *نياپو, سائيز_t msglen,
    ثابت uint8_t *ctx, سائيز_t ctxlen,
    ثابت uint8_t sk[MLDSA44_SECRETKEYBYTES]);
صحيح crypto_sign_mldsa44_verify(ثابت uint8_t sig[MLDSA44_SIGBYTES],
    ثابت uint8_t *نياپو, سائيز_t msglen,
    ثابت uint8_t *ctx, سائيز_t ctxlen,
    ثابت uint8_t pk[MLDSA44_PUBLICKEYBYTES]);
صحيح crypto_sign_mldsa44_keypair_seeded(uint8_t pk[MLDSA44_PUBLICKEYBYTES],
    uint8_t sk[MLDSA44_SECRETKEYBYTES], ثابت uint8_t ٻج[MLDSA44_SEEDBYTES]);
صحيح crypto_sign_mldsa44_seeded(uint8_t sig[MLDSA44_SIGBYTES],
    ثابت uint8_t *نياپو, سائيز_t msglen,
    ثابت uint8_t *ctx, سائيز_t ctxlen,
    ثابت uint8_t sk[MLDSA44_SECRETKEYBYTES],
    ثابت uint8_t ٻج[MLDSA44_SEEDBYTES]);

/* ML-DSA-65 */
#وصف_ڪريو MLDSA65_PUBLICKEYBYTES 1952
#وصف_ڪريو MLDSA65_SECRETKEYBYTES 4032
#وصف_ڪريو MLDSA65_SIGBYTES 3309
#وصف_ڪريو MLDSA65_SEEDBYTES 32

#إذا 0
صحيح crypto_sign_mldsa65_keypair(uint8_t pk[MLDSA65_PUBLICKEYBYTES],
    uint8_t sk[MLDSA65_SECRETKEYBYTES]);
صحيح crypto_sign_mldsa65(uint8_t sig[MLDSA65_SIGBYTES],
    ثابت uint8_t *نياپو, سائيز_t msglen,
    ثابت uint8_t *ctx, سائيز_t ctxlen,
    ثابت uint8_t sk[MLDSA65_SECRETKEYBYTES]);
صحيح crypto_sign_mldsa65_verify(ثابت uint8_t sig[MLDSA65_SIGBYTES],
    ثابت uint8_t *نياپو, سائيز_t msglen,
    ثابت uint8_t *ctx, سائيز_t ctxlen,
    ثابت uint8_t pk[MLDSA65_PUBLICKEYBYTES]);
صحيح crypto_sign_mldsa65_keypair_seeded(uint8_t pk[MLDSA65_PUBLICKEYBYTES],
    uint8_t sk[MLDSA65_SECRETKEYBYTES], ثابت uint8_t ٻج[MLDSA65_SEEDBYTES]);
صحيح crypto_sign_mldsa65_seeded(uint8_t sig[MLDSA65_SIGBYTES],
    ثابت uint8_t *نياپو, سائيز_t msglen,
    ثابت uint8_t *ctx, سائيز_t ctxlen,
    ثابت uint8_t sk[MLDSA65_SECRETKEYBYTES],
    ثابت uint8_t ٻج[MLDSA65_SEEDBYTES]);
#جيڪڏهن_پورو

/* ML-DSA-87 */
#وصف_ڪريو MLDSA87_PUBLICKEYBYTES 2592
#وصف_ڪريو MLDSA87_SECRETKEYBYTES 4896
#وصف_ڪريو MLDSA87_SIGBYTES 4627
#وصف_ڪريو MLDSA87_SEEDBYTES 32

صحيح crypto_sign_mldsa87_keypair(uint8_t pk[MLDSA87_PUBLICKEYBYTES],
    uint8_t sk[MLDSA87_SECRETKEYBYTES]);
صحيح crypto_sign_mldsa87(uint8_t sig[MLDSA87_SIGBYTES],
    ثابت uint8_t *نياپو, سائيز_t msglen,
    ثابت uint8_t *ctx, سائيز_t ctxlen,
    ثابت uint8_t sk[MLDSA87_SECRETKEYBYTES]);
صحيح crypto_sign_mldsa87_verify(ثابت uint8_t sig[MLDSA87_SIGBYTES],
    ثابت uint8_t *نياپو, سائيز_t msglen,
    ثابت uint8_t *ctx, سائيز_t ctxlen,
    ثابت uint8_t pk[MLDSA87_PUBLICKEYBYTES]);
صحيح crypto_sign_mldsa87_keypair_seeded(uint8_t pk[MLDSA87_PUBLICKEYBYTES],
    uint8_t sk[MLDSA87_SECRETKEYBYTES], ثابت uint8_t ٻج[MLDSA87_SEEDBYTES]);
صحيح crypto_sign_mldsa87_seeded(uint8_t sig[MLDSA87_SIGBYTES],
    ثابت uint8_t *نياپو, سائيز_t msglen,
    ثابت uint8_t *ctx, سائيز_t ctxlen,
    ثابت uint8_t sk[MLDSA87_SECRETKEYBYTES],
    ثابت uint8_t ٻج[MLDSA87_SEEDBYTES]);

/* MLDSA44-Ed25519-SHA512 */
#وصف_ڪريو MLDSA44_ED25519_PK_SZ (MLDSA44_PUBLICKEYBYTES + crypto_sign_ed25519_PUBLICKEYBYTES)
#وصف_ڪريو MLDSA44_ED25519_SK_SZ (MLDSA44_SEEDBYTES + crypto_sign_ed25519_SEEDBYTES)
#وصف_ڪريو MLDSA44_ED25519_SIG_SZ (MLDSA44_SIGBYTES + crypto_sign_ed25519_بائيٽون)

صحيح crypto_sign_mldsa44_ed25519_keygen(uint8_t pk[MLDSA44_ED25519_PK_SZ],
    uint8_t sk[MLDSA44_ED25519_SK_SZ]);
صحيح crypto_sign_mldsa44_ed25519_keygen_seeded(uint8_t pk[MLDSA44_ED25519_PK_SZ],
    uint8_t sk[MLDSA44_ED25519_SK_SZ],
    ثابت uint8_t mldsa_ٻج[MLDSA44_SEEDBYTES],
    ثابت uint8_t ed25519_ٻج[crypto_sign_ed25519_SEEDBYTES]);
صحيح crypto_sign_mldsa44_ed25519_sign(uint8_t sig[MLDSA44_ED25519_SIG_SZ],
    ثابت uint8_t *نياپو, سائيز_t msglen,
    ثابت uint8_t *ctx, سائيز_t ctxlen,
    ثابت uint8_t sk[MLDSA44_ED25519_SK_SZ]);
صحيح crypto_sign_mldsa44_ed25519_verify(ثابت uint8_t sig[MLDSA44_ED25519_SIG_SZ],
    ثابت uint8_t *نياپو, سائيز_t msglen,
    ثابت uint8_t *ctx, سائيز_t ctxlen,
    ثابت uint8_t pk[MLDSA44_ED25519_PK_SZ]);

/* Utility */
فراغ sha3_256(uint8_t digest[32], ثابت uint8_t *معلومات, سائيز_t len);
فراغ sha3_512(uint8_t digest[64], ثابت uint8_t *معلومات, سائيز_t len);

#جيڪڏهن_پورو /* crypto_api_h */
