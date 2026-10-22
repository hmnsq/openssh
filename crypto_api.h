/* $OpenBSD: crypto_api.h,v 1.13 2026/09/16 00:43:00 djm Exp $ */

/*
 * Assembled from generated headers and source files by Markus Friedl.
 * Placed in the public domain.
 */

#جے_بنا_تعریف crypto_api_h
#تعریف_کرو crypto_api_h

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

#تعریف_کرو randombytes(buf, buf_len) arc4random_buf((buf), (buf_len))
#تعریف_کرو small_random32() arc4random()

#تعریف_کرو crypto_hash_sha512_بائٹاں 64U

#جے_تعریف_شدہ WITH_OPENSSL
#ضمن <openssl/evp.h>
ساكن مضمن صحيح
crypto_hash_sha512(بنانشانی حرف *باہرلا, ثابت بنانشانی حرف *وچ,
    بنانشانی لما لما inlen)
{

	إذا (!EVP_Digest(وچ, inlen, باہرلا, عدم, EVP_sha512(), عدم))
		أرجع -1;
	أرجع 0;
}
#وإلا /* WITH_OPENSSL */
# ifdef HAVE_SHA2_H
#  include <sha2.h>
# endif
ساكن مضمن صحيح
crypto_hash_sha512(بنانشانی حرف *باہرلا, ثابت بنانشانی حرف *وچ,
    بنانشانی لما لما inlen)
{

	SHA2_CTX ctx;

	SHA512Init(&ctx);
	SHA512Update(&ctx, وچ, inlen);
	SHA512Final(باہرلا, &ctx);
	أرجع 0;
}
#جے_انت /* WITH_OPENSSL */

#تعریف_کرو crypto_sign_ed25519_SECRETKEYBYTES 64U
#تعریف_کرو crypto_sign_ed25519_PUBLICKEYBYTES 32U
#تعریف_کرو crypto_sign_ed25519_SEEDBYTES 32U
#تعریف_کرو crypto_sign_ed25519_بائٹاں 64U

صحيح	crypto_sign_ed25519_detached(بنانشانی حرف *, بنانشانی لما لما *,
    ثابت بنانشانی حرف *, بنانشانی لما لما, ثابت بنانشانی حرف *);
صحيح	crypto_sign_ed25519_verify_detached(ثابت بنانشانی حرف *,
    ثابت بنانشانی حرف *, بنانشانی لما لما, ثابت بنانشانی حرف *);
صحيح	crypto_sign_ed25519_keypair(بنانشانی حرف *, بنانشانی حرف *);
صحيح	crypto_sign_ed25519_بیج_keypair(بنانشانی حرف *, بنانشانی حرف *,
    ثابت بنانشانی حرف *);

#تعریف_کرو crypto_kem_sntrup761_PUBLICKEYBYTES 1158
#تعریف_کرو crypto_kem_sntrup761_SECRETKEYBYTES 1763
#تعریف_کرو crypto_kem_sntrup761_CIPHERTEXTBYTES 1039
#تعریف_کرو crypto_kem_sntrup761_بائٹاں 32

صحيح	crypto_kem_sntrup761_enc(بنانشانی حرف *cstr, بنانشانی حرف *k,
    ثابت بنانشانی حرف *pk);
صحيح	crypto_kem_sntrup761_dec(بنانشانی حرف *k,
    ثابت بنانشانی حرف *cstr, ثابت بنانشانی حرف *sk);
صحيح	crypto_kem_sntrup761_keypair(بنانشانی حرف *pk, بنانشانی حرف *sk);

/* ML-KEM-768 */
#تعریف_کرو crypto_kem_mlkem768_PUBLICKEYBYTES 1184
#تعریف_کرو crypto_kem_mlkem768_SECRETKEYBYTES 2400
#تعریف_کرو crypto_kem_mlkem768_CIPHERTEXTBYTES 1088
#تعریف_کرو crypto_kem_mlkem768_بائٹاں 32
#تعریف_کرو crypto_kem_mlkem768_ENCSEEDBYTES 32
#تعریف_کرو crypto_kem_mlkem768_KEYPAIRSEEDBYTES 64

/* Aliases for MLKEM768 */
#تعریف_کرو MLKEM768_PUBLICKEYBYTES crypto_kem_mlkem768_PUBLICKEYBYTES
#تعریف_کرو MLKEM768_SECRETKEYBYTES crypto_kem_mlkem768_SECRETKEYBYTES
#تعریف_کرو MLKEM768_CIPHERTEXTBYTES crypto_kem_mlkem768_CIPHERTEXTBYTES
#تعریف_کرو MLKEM768_بائٹاں crypto_kem_mlkem768_بائٹاں

صحيح crypto_kem_mlkem768_keypair(uint8_t pk[crypto_kem_mlkem768_PUBLICKEYBYTES],
    uint8_t sk[crypto_kem_mlkem768_SECRETKEYBYTES]);
صحيح crypto_kem_mlkem768_enc(uint8_t ct[crypto_kem_mlkem768_CIPHERTEXTBYTES],
    uint8_t shared_secret[crypto_kem_mlkem768_بائٹاں],
    ثابت uint8_t pk[crypto_kem_mlkem768_PUBLICKEYBYTES]);
صحيح crypto_kem_mlkem768_dec(uint8_t shared_secret[crypto_kem_mlkem768_بائٹاں],
    ثابت uint8_t ct[crypto_kem_mlkem768_CIPHERTEXTBYTES],
    ثابت uint8_t sk[crypto_kem_mlkem768_SECRETKEYBYTES]);
صحيح crypto_kem_mlkem768_keypair_seeded(uint8_t pk[crypto_kem_mlkem768_PUBLICKEYBYTES],
    uint8_t sk[crypto_kem_mlkem768_SECRETKEYBYTES], ثابت uint8_t بیج[64]);
صحيح crypto_kem_mlkem768_enc_seeded(uint8_t ct[crypto_kem_mlkem768_CIPHERTEXTBYTES],
    uint8_t shared_secret[crypto_kem_mlkem768_بائٹاں],
    ثابت uint8_t pk[crypto_kem_mlkem768_PUBLICKEYBYTES],
    ثابت uint8_t بیج[32]);

/* ML-DSA-44 */
#تعریف_کرو MLDSA44_PUBLICKEYBYTES 1312
#تعریف_کرو MLDSA44_SECRETKEYBYTES 2560
#تعریف_کرو MLDSA44_SIGBYTES 2420
#تعریف_کرو MLDSA44_SEEDBYTES 32

صحيح crypto_sign_mldsa44_keypair(uint8_t pk[MLDSA44_PUBLICKEYBYTES],
    uint8_t sk[MLDSA44_SECRETKEYBYTES]);
صحيح crypto_sign_mldsa44(uint8_t sig[MLDSA44_SIGBYTES],
    ثابت uint8_t *پیغام, ناپ_t msglen,
    ثابت uint8_t *ctx, ناپ_t ctxlen,
    ثابت uint8_t sk[MLDSA44_SECRETKEYBYTES]);
صحيح crypto_sign_mldsa44_verify(ثابت uint8_t sig[MLDSA44_SIGBYTES],
    ثابت uint8_t *پیغام, ناپ_t msglen,
    ثابت uint8_t *ctx, ناپ_t ctxlen,
    ثابت uint8_t pk[MLDSA44_PUBLICKEYBYTES]);
صحيح crypto_sign_mldsa44_keypair_seeded(uint8_t pk[MLDSA44_PUBLICKEYBYTES],
    uint8_t sk[MLDSA44_SECRETKEYBYTES], ثابت uint8_t بیج[MLDSA44_SEEDBYTES]);
صحيح crypto_sign_mldsa44_seeded(uint8_t sig[MLDSA44_SIGBYTES],
    ثابت uint8_t *پیغام, ناپ_t msglen,
    ثابت uint8_t *ctx, ناپ_t ctxlen,
    ثابت uint8_t sk[MLDSA44_SECRETKEYBYTES],
    ثابت uint8_t بیج[MLDSA44_SEEDBYTES]);

/* ML-DSA-65 */
#تعریف_کرو MLDSA65_PUBLICKEYBYTES 1952
#تعریف_کرو MLDSA65_SECRETKEYBYTES 4032
#تعریف_کرو MLDSA65_SIGBYTES 3309
#تعریف_کرو MLDSA65_SEEDBYTES 32

#إذا 0
صحيح crypto_sign_mldsa65_keypair(uint8_t pk[MLDSA65_PUBLICKEYBYTES],
    uint8_t sk[MLDSA65_SECRETKEYBYTES]);
صحيح crypto_sign_mldsa65(uint8_t sig[MLDSA65_SIGBYTES],
    ثابت uint8_t *پیغام, ناپ_t msglen,
    ثابت uint8_t *ctx, ناپ_t ctxlen,
    ثابت uint8_t sk[MLDSA65_SECRETKEYBYTES]);
صحيح crypto_sign_mldsa65_verify(ثابت uint8_t sig[MLDSA65_SIGBYTES],
    ثابت uint8_t *پیغام, ناپ_t msglen,
    ثابت uint8_t *ctx, ناپ_t ctxlen,
    ثابت uint8_t pk[MLDSA65_PUBLICKEYBYTES]);
صحيح crypto_sign_mldsa65_keypair_seeded(uint8_t pk[MLDSA65_PUBLICKEYBYTES],
    uint8_t sk[MLDSA65_SECRETKEYBYTES], ثابت uint8_t بیج[MLDSA65_SEEDBYTES]);
صحيح crypto_sign_mldsa65_seeded(uint8_t sig[MLDSA65_SIGBYTES],
    ثابت uint8_t *پیغام, ناپ_t msglen,
    ثابت uint8_t *ctx, ناپ_t ctxlen,
    ثابت uint8_t sk[MLDSA65_SECRETKEYBYTES],
    ثابت uint8_t بیج[MLDSA65_SEEDBYTES]);
#جے_انت

/* ML-DSA-87 */
#تعریف_کرو MLDSA87_PUBLICKEYBYTES 2592
#تعریف_کرو MLDSA87_SECRETKEYBYTES 4896
#تعریف_کرو MLDSA87_SIGBYTES 4627
#تعریف_کرو MLDSA87_SEEDBYTES 32

صحيح crypto_sign_mldsa87_keypair(uint8_t pk[MLDSA87_PUBLICKEYBYTES],
    uint8_t sk[MLDSA87_SECRETKEYBYTES]);
صحيح crypto_sign_mldsa87(uint8_t sig[MLDSA87_SIGBYTES],
    ثابت uint8_t *پیغام, ناپ_t msglen,
    ثابت uint8_t *ctx, ناپ_t ctxlen,
    ثابت uint8_t sk[MLDSA87_SECRETKEYBYTES]);
صحيح crypto_sign_mldsa87_verify(ثابت uint8_t sig[MLDSA87_SIGBYTES],
    ثابت uint8_t *پیغام, ناپ_t msglen,
    ثابت uint8_t *ctx, ناپ_t ctxlen,
    ثابت uint8_t pk[MLDSA87_PUBLICKEYBYTES]);
صحيح crypto_sign_mldsa87_keypair_seeded(uint8_t pk[MLDSA87_PUBLICKEYBYTES],
    uint8_t sk[MLDSA87_SECRETKEYBYTES], ثابت uint8_t بیج[MLDSA87_SEEDBYTES]);
صحيح crypto_sign_mldsa87_seeded(uint8_t sig[MLDSA87_SIGBYTES],
    ثابت uint8_t *پیغام, ناپ_t msglen,
    ثابت uint8_t *ctx, ناپ_t ctxlen,
    ثابت uint8_t sk[MLDSA87_SECRETKEYBYTES],
    ثابت uint8_t بیج[MLDSA87_SEEDBYTES]);

/* MLDSA44-Ed25519-SHA512 */
#تعریف_کرو MLDSA44_ED25519_PK_SZ (MLDSA44_PUBLICKEYBYTES + crypto_sign_ed25519_PUBLICKEYBYTES)
#تعریف_کرو MLDSA44_ED25519_SK_SZ (MLDSA44_SEEDBYTES + crypto_sign_ed25519_SEEDBYTES)
#تعریف_کرو MLDSA44_ED25519_SIG_SZ (MLDSA44_SIGBYTES + crypto_sign_ed25519_بائٹاں)

صحيح crypto_sign_mldsa44_ed25519_keygen(uint8_t pk[MLDSA44_ED25519_PK_SZ],
    uint8_t sk[MLDSA44_ED25519_SK_SZ]);
صحيح crypto_sign_mldsa44_ed25519_keygen_seeded(uint8_t pk[MLDSA44_ED25519_PK_SZ],
    uint8_t sk[MLDSA44_ED25519_SK_SZ],
    ثابت uint8_t mldsa_بیج[MLDSA44_SEEDBYTES],
    ثابت uint8_t ed25519_بیج[crypto_sign_ed25519_SEEDBYTES]);
صحيح crypto_sign_mldsa44_ed25519_sign(uint8_t sig[MLDSA44_ED25519_SIG_SZ],
    ثابت uint8_t *پیغام, ناپ_t msglen,
    ثابت uint8_t *ctx, ناپ_t ctxlen,
    ثابت uint8_t sk[MLDSA44_ED25519_SK_SZ]);
صحيح crypto_sign_mldsa44_ed25519_verify(ثابت uint8_t sig[MLDSA44_ED25519_SIG_SZ],
    ثابت uint8_t *پیغام, ناپ_t msglen,
    ثابت uint8_t *ctx, ناپ_t ctxlen,
    ثابت uint8_t pk[MLDSA44_ED25519_PK_SZ]);

/* Utility */
فراغ sha3_256(uint8_t digest[32], ثابت uint8_t *انکڑے, ناپ_t len);
فراغ sha3_512(uint8_t digest[64], ثابت uint8_t *انکڑے, ناپ_t len);

#جے_انت /* crypto_api_h */
