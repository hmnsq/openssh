/* $OpenBSD: crypto_api.h,v 1.13 2026/09/16 00:43:00 djm Exp $ */

/*
 * Assembled from generated headers and source files by Markus Friedl.
 * Placed in the public domain.
 */

#اگر_غیر_تعریف_شدہ crypto_api_h
#تعریف_کرو crypto_api_h

#شامل "includes.h"

#شامل <stdint.h>
#شامل <stdlib.h>

قسمتعریف int8_t crypto_int8;
قسمتعریف uint8_t crypto_uint8;
قسمتعریف int16_t crypto_int16;
قسمتعریف uint16_t crypto_uint16;
قسمتعریف int32_t crypto_int32;
قسمتعریف uint32_t crypto_uint32;
قسمتعریف int64_t crypto_int64;
قسمتعریف uint64_t crypto_uint64;

#تعریف_کرو randombytes(buf, buf_len) arc4random_buf((buf), (buf_len))
#تعریف_کرو small_random32() arc4random()

#تعریف_کرو crypto_hash_sha512_بائٹیں 64U

#اگر_تعریف_شدہ WITH_OPENSSL
#شامل <openssl/evp.h>
ساکن اندرونی صحیح
crypto_hash_sha512(غیرعلامتی حرف *برآمد, ثابت غیرعلامتی حرف *اندر,
    غیرعلامتی طویل طویل inlen)
{

	اگر (!EVP_Digest(اندر, inlen, برآمد, تہی, EVP_sha512(), تہی))
		واپس -1;
	واپس 0;
}
#ورنہ /* WITH_OPENSSL */
# ifdef HAVE_SHA2_H
#  include <sha2.h>
# endif
ساکن اندرونی صحیح
crypto_hash_sha512(غیرعلامتی حرف *برآمد, ثابت غیرعلامتی حرف *اندر,
    غیرعلامتی طویل طویل inlen)
{

	SHA2_CTX ctx;

	SHA512Init(&ctx);
	SHA512Update(&ctx, اندر, inlen);
	SHA512Final(برآمد, &ctx);
	واپس 0;
}
#اگر_ختم /* WITH_OPENSSL */

#تعریف_کرو crypto_sign_ed25519_SECRETKEYBYTES 64U
#تعریف_کرو crypto_sign_ed25519_PUBLICKEYBYTES 32U
#تعریف_کرو crypto_sign_ed25519_SEEDBYTES 32U
#تعریف_کرو crypto_sign_ed25519_بائٹیں 64U

صحیح	crypto_sign_ed25519_detached(غیرعلامتی حرف *, غیرعلامتی طویل طویل *,
    ثابت غیرعلامتی حرف *, غیرعلامتی طویل طویل, ثابت غیرعلامتی حرف *);
صحیح	crypto_sign_ed25519_verify_detached(ثابت غیرعلامتی حرف *,
    ثابت غیرعلامتی حرف *, غیرعلامتی طویل طویل, ثابت غیرعلامتی حرف *);
صحیح	crypto_sign_ed25519_keypair(غیرعلامتی حرف *, غیرعلامتی حرف *);
صحیح	crypto_sign_ed25519_بیج_keypair(غیرعلامتی حرف *, غیرعلامتی حرف *,
    ثابت غیرعلامتی حرف *);

#تعریف_کرو crypto_kem_sntrup761_PUBLICKEYBYTES 1158
#تعریف_کرو crypto_kem_sntrup761_SECRETKEYBYTES 1763
#تعریف_کرو crypto_kem_sntrup761_CIPHERTEXTBYTES 1039
#تعریف_کرو crypto_kem_sntrup761_بائٹیں 32

صحیح	crypto_kem_sntrup761_enc(غیرعلامتی حرف *cstr, غیرعلامتی حرف *k,
    ثابت غیرعلامتی حرف *pk);
صحیح	crypto_kem_sntrup761_dec(غیرعلامتی حرف *k,
    ثابت غیرعلامتی حرف *cstr, ثابت غیرعلامتی حرف *sk);
صحیح	crypto_kem_sntrup761_keypair(غیرعلامتی حرف *pk, غیرعلامتی حرف *sk);

/* ML-KEM-768 */
#تعریف_کرو crypto_kem_mlkem768_PUBLICKEYBYTES 1184
#تعریف_کرو crypto_kem_mlkem768_SECRETKEYBYTES 2400
#تعریف_کرو crypto_kem_mlkem768_CIPHERTEXTBYTES 1088
#تعریف_کرو crypto_kem_mlkem768_بائٹیں 32
#تعریف_کرو crypto_kem_mlkem768_ENCSEEDBYTES 32
#تعریف_کرو crypto_kem_mlkem768_KEYPAIRSEEDBYTES 64

/* Aliases for MLKEM768 */
#تعریف_کرو MLKEM768_PUBLICKEYBYTES crypto_kem_mlkem768_PUBLICKEYBYTES
#تعریف_کرو MLKEM768_SECRETKEYBYTES crypto_kem_mlkem768_SECRETKEYBYTES
#تعریف_کرو MLKEM768_CIPHERTEXTBYTES crypto_kem_mlkem768_CIPHERTEXTBYTES
#تعریف_کرو MLKEM768_بائٹیں crypto_kem_mlkem768_بائٹیں

صحیح crypto_kem_mlkem768_keypair(uint8_t pk[crypto_kem_mlkem768_PUBLICKEYBYTES],
    uint8_t sk[crypto_kem_mlkem768_SECRETKEYBYTES]);
صحیح crypto_kem_mlkem768_enc(uint8_t ct[crypto_kem_mlkem768_CIPHERTEXTBYTES],
    uint8_t shared_secret[crypto_kem_mlkem768_بائٹیں],
    ثابت uint8_t pk[crypto_kem_mlkem768_PUBLICKEYBYTES]);
صحیح crypto_kem_mlkem768_dec(uint8_t shared_secret[crypto_kem_mlkem768_بائٹیں],
    ثابت uint8_t ct[crypto_kem_mlkem768_CIPHERTEXTBYTES],
    ثابت uint8_t sk[crypto_kem_mlkem768_SECRETKEYBYTES]);
صحیح crypto_kem_mlkem768_keypair_seeded(uint8_t pk[crypto_kem_mlkem768_PUBLICKEYBYTES],
    uint8_t sk[crypto_kem_mlkem768_SECRETKEYBYTES], ثابت uint8_t بیج[64]);
صحیح crypto_kem_mlkem768_enc_seeded(uint8_t ct[crypto_kem_mlkem768_CIPHERTEXTBYTES],
    uint8_t shared_secret[crypto_kem_mlkem768_بائٹیں],
    ثابت uint8_t pk[crypto_kem_mlkem768_PUBLICKEYBYTES],
    ثابت uint8_t بیج[32]);

/* ML-DSA-44 */
#تعریف_کرو MLDSA44_PUBLICKEYBYTES 1312
#تعریف_کرو MLDSA44_SECRETKEYBYTES 2560
#تعریف_کرو MLDSA44_SIGBYTES 2420
#تعریف_کرو MLDSA44_SEEDBYTES 32

صحیح crypto_sign_mldsa44_keypair(uint8_t pk[MLDSA44_PUBLICKEYBYTES],
    uint8_t sk[MLDSA44_SECRETKEYBYTES]);
صحیح crypto_sign_mldsa44(uint8_t sig[MLDSA44_SIGBYTES],
    ثابت uint8_t *پیغام, سائز_t msglen,
    ثابت uint8_t *ctx, سائز_t ctxlen,
    ثابت uint8_t sk[MLDSA44_SECRETKEYBYTES]);
صحیح crypto_sign_mldsa44_verify(ثابت uint8_t sig[MLDSA44_SIGBYTES],
    ثابت uint8_t *پیغام, سائز_t msglen,
    ثابت uint8_t *ctx, سائز_t ctxlen,
    ثابت uint8_t pk[MLDSA44_PUBLICKEYBYTES]);
صحیح crypto_sign_mldsa44_keypair_seeded(uint8_t pk[MLDSA44_PUBLICKEYBYTES],
    uint8_t sk[MLDSA44_SECRETKEYBYTES], ثابت uint8_t بیج[MLDSA44_SEEDBYTES]);
صحیح crypto_sign_mldsa44_seeded(uint8_t sig[MLDSA44_SIGBYTES],
    ثابت uint8_t *پیغام, سائز_t msglen,
    ثابت uint8_t *ctx, سائز_t ctxlen,
    ثابت uint8_t sk[MLDSA44_SECRETKEYBYTES],
    ثابت uint8_t بیج[MLDSA44_SEEDBYTES]);

/* ML-DSA-65 */
#تعریف_کرو MLDSA65_PUBLICKEYBYTES 1952
#تعریف_کرو MLDSA65_SECRETKEYBYTES 4032
#تعریف_کرو MLDSA65_SIGBYTES 3309
#تعریف_کرو MLDSA65_SEEDBYTES 32

#اگر 0
صحیح crypto_sign_mldsa65_keypair(uint8_t pk[MLDSA65_PUBLICKEYBYTES],
    uint8_t sk[MLDSA65_SECRETKEYBYTES]);
صحیح crypto_sign_mldsa65(uint8_t sig[MLDSA65_SIGBYTES],
    ثابت uint8_t *پیغام, سائز_t msglen,
    ثابت uint8_t *ctx, سائز_t ctxlen,
    ثابت uint8_t sk[MLDSA65_SECRETKEYBYTES]);
صحیح crypto_sign_mldsa65_verify(ثابت uint8_t sig[MLDSA65_SIGBYTES],
    ثابت uint8_t *پیغام, سائز_t msglen,
    ثابت uint8_t *ctx, سائز_t ctxlen,
    ثابت uint8_t pk[MLDSA65_PUBLICKEYBYTES]);
صحیح crypto_sign_mldsa65_keypair_seeded(uint8_t pk[MLDSA65_PUBLICKEYBYTES],
    uint8_t sk[MLDSA65_SECRETKEYBYTES], ثابت uint8_t بیج[MLDSA65_SEEDBYTES]);
صحیح crypto_sign_mldsa65_seeded(uint8_t sig[MLDSA65_SIGBYTES],
    ثابت uint8_t *پیغام, سائز_t msglen,
    ثابت uint8_t *ctx, سائز_t ctxlen,
    ثابت uint8_t sk[MLDSA65_SECRETKEYBYTES],
    ثابت uint8_t بیج[MLDSA65_SEEDBYTES]);
#اگر_ختم

/* ML-DSA-87 */
#تعریف_کرو MLDSA87_PUBLICKEYBYTES 2592
#تعریف_کرو MLDSA87_SECRETKEYBYTES 4896
#تعریف_کرو MLDSA87_SIGBYTES 4627
#تعریف_کرو MLDSA87_SEEDBYTES 32

صحیح crypto_sign_mldsa87_keypair(uint8_t pk[MLDSA87_PUBLICKEYBYTES],
    uint8_t sk[MLDSA87_SECRETKEYBYTES]);
صحیح crypto_sign_mldsa87(uint8_t sig[MLDSA87_SIGBYTES],
    ثابت uint8_t *پیغام, سائز_t msglen,
    ثابت uint8_t *ctx, سائز_t ctxlen,
    ثابت uint8_t sk[MLDSA87_SECRETKEYBYTES]);
صحیح crypto_sign_mldsa87_verify(ثابت uint8_t sig[MLDSA87_SIGBYTES],
    ثابت uint8_t *پیغام, سائز_t msglen,
    ثابت uint8_t *ctx, سائز_t ctxlen,
    ثابت uint8_t pk[MLDSA87_PUBLICKEYBYTES]);
صحیح crypto_sign_mldsa87_keypair_seeded(uint8_t pk[MLDSA87_PUBLICKEYBYTES],
    uint8_t sk[MLDSA87_SECRETKEYBYTES], ثابت uint8_t بیج[MLDSA87_SEEDBYTES]);
صحیح crypto_sign_mldsa87_seeded(uint8_t sig[MLDSA87_SIGBYTES],
    ثابت uint8_t *پیغام, سائز_t msglen,
    ثابت uint8_t *ctx, سائز_t ctxlen,
    ثابت uint8_t sk[MLDSA87_SECRETKEYBYTES],
    ثابت uint8_t بیج[MLDSA87_SEEDBYTES]);

/* MLDSA44-Ed25519-SHA512 */
#تعریف_کرو MLDSA44_ED25519_PK_SZ (MLDSA44_PUBLICKEYBYTES + crypto_sign_ed25519_PUBLICKEYBYTES)
#تعریف_کرو MLDSA44_ED25519_SK_SZ (MLDSA44_SEEDBYTES + crypto_sign_ed25519_SEEDBYTES)
#تعریف_کرو MLDSA44_ED25519_SIG_SZ (MLDSA44_SIGBYTES + crypto_sign_ed25519_بائٹیں)

صحیح crypto_sign_mldsa44_ed25519_keygen(uint8_t pk[MLDSA44_ED25519_PK_SZ],
    uint8_t sk[MLDSA44_ED25519_SK_SZ]);
صحیح crypto_sign_mldsa44_ed25519_keygen_seeded(uint8_t pk[MLDSA44_ED25519_PK_SZ],
    uint8_t sk[MLDSA44_ED25519_SK_SZ],
    ثابت uint8_t mldsa_بیج[MLDSA44_SEEDBYTES],
    ثابت uint8_t ed25519_بیج[crypto_sign_ed25519_SEEDBYTES]);
صحیح crypto_sign_mldsa44_ed25519_sign(uint8_t sig[MLDSA44_ED25519_SIG_SZ],
    ثابت uint8_t *پیغام, سائز_t msglen,
    ثابت uint8_t *ctx, سائز_t ctxlen,
    ثابت uint8_t sk[MLDSA44_ED25519_SK_SZ]);
صحیح crypto_sign_mldsa44_ed25519_verify(ثابت uint8_t sig[MLDSA44_ED25519_SIG_SZ],
    ثابت uint8_t *پیغام, سائز_t msglen,
    ثابت uint8_t *ctx, سائز_t ctxlen,
    ثابت uint8_t pk[MLDSA44_ED25519_PK_SZ]);

/* Utility */
خالی sha3_256(uint8_t digest[32], ثابت uint8_t *ڈیٹا, سائز_t len);
خالی sha3_512(uint8_t digest[64], ثابت uint8_t *ڈیٹا, سائز_t len);

#اگر_ختم /* crypto_api_h */
