/* $OpenBSD: crypto_api.h,v 1.13 2026/09/16 00:43:00 djm Exp $ */

/*
 * Assembled from generated headers and source files by Markus Friedl.
 * Placed in the public domain.
 */

#که_نه_تعریف_شوی crypto_api_h
#تعریف_کړه crypto_api_h

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

#تعریف_کړه randombytes(buf, buf_len) arc4random_buf((buf), (buf_len))
#تعریف_کړه small_random32() arc4random()

#تعریف_کړه crypto_hash_sha512_بایټونه 64U

#که_تعریف_شوی WITH_OPENSSL
#ضمن <openssl/evp.h>
ساكن مضمن صحيح
crypto_hash_sha512(بینښه حرف *بهر, ثابت بینښه حرف *دننه,
    بینښه اوږد اوږد inlen)
{

	إذا (!EVP_Digest(دننه, inlen, بهر, عدم, EVP_sha512(), عدم))
		أرجع -1;
	أرجع 0;
}
#وإلا /* WITH_OPENSSL */
# ifdef HAVE_SHA2_H
#  include <sha2.h>
# endif
ساكن مضمن صحيح
crypto_hash_sha512(بینښه حرف *بهر, ثابت بینښه حرف *دننه,
    بینښه اوږد اوږد inlen)
{

	SHA2_CTX ctx;

	SHA512Init(&ctx);
	SHA512Update(&ctx, دننه, inlen);
	SHA512Final(بهر, &ctx);
	أرجع 0;
}
#د_که_پای /* WITH_OPENSSL */

#تعریف_کړه crypto_sign_ed25519_SECRETKEYBYTES 64U
#تعریف_کړه crypto_sign_ed25519_PUBLICKEYBYTES 32U
#تعریف_کړه crypto_sign_ed25519_SEEDBYTES 32U
#تعریف_کړه crypto_sign_ed25519_بایټونه 64U

صحيح	crypto_sign_ed25519_detached(بینښه حرف *, بینښه اوږد اوږد *,
    ثابت بینښه حرف *, بینښه اوږد اوږد, ثابت بینښه حرف *);
صحيح	crypto_sign_ed25519_verify_detached(ثابت بینښه حرف *,
    ثابت بینښه حرف *, بینښه اوږد اوږد, ثابت بینښه حرف *);
صحيح	crypto_sign_ed25519_keypair(بینښه حرف *, بینښه حرف *);
صحيح	crypto_sign_ed25519_تخم_keypair(بینښه حرف *, بینښه حرف *,
    ثابت بینښه حرف *);

#تعریف_کړه crypto_kem_sntrup761_PUBLICKEYBYTES 1158
#تعریف_کړه crypto_kem_sntrup761_SECRETKEYBYTES 1763
#تعریف_کړه crypto_kem_sntrup761_CIPHERTEXTBYTES 1039
#تعریف_کړه crypto_kem_sntrup761_بایټونه 32

صحيح	crypto_kem_sntrup761_enc(بینښه حرف *cstr, بینښه حرف *k,
    ثابت بینښه حرف *pk);
صحيح	crypto_kem_sntrup761_dec(بینښه حرف *k,
    ثابت بینښه حرف *cstr, ثابت بینښه حرف *sk);
صحيح	crypto_kem_sntrup761_keypair(بینښه حرف *pk, بینښه حرف *sk);

/* ML-KEM-768 */
#تعریف_کړه crypto_kem_mlkem768_PUBLICKEYBYTES 1184
#تعریف_کړه crypto_kem_mlkem768_SECRETKEYBYTES 2400
#تعریف_کړه crypto_kem_mlkem768_CIPHERTEXTBYTES 1088
#تعریف_کړه crypto_kem_mlkem768_بایټونه 32
#تعریف_کړه crypto_kem_mlkem768_ENCSEEDBYTES 32
#تعریف_کړه crypto_kem_mlkem768_KEYPAIRSEEDBYTES 64

/* Aliases for MLKEM768 */
#تعریف_کړه MLKEM768_PUBLICKEYBYTES crypto_kem_mlkem768_PUBLICKEYBYTES
#تعریف_کړه MLKEM768_SECRETKEYBYTES crypto_kem_mlkem768_SECRETKEYBYTES
#تعریف_کړه MLKEM768_CIPHERTEXTBYTES crypto_kem_mlkem768_CIPHERTEXTBYTES
#تعریف_کړه MLKEM768_بایټونه crypto_kem_mlkem768_بایټونه

صحيح crypto_kem_mlkem768_keypair(uint8_t pk[crypto_kem_mlkem768_PUBLICKEYBYTES],
    uint8_t sk[crypto_kem_mlkem768_SECRETKEYBYTES]);
صحيح crypto_kem_mlkem768_enc(uint8_t ct[crypto_kem_mlkem768_CIPHERTEXTBYTES],
    uint8_t shared_secret[crypto_kem_mlkem768_بایټونه],
    ثابت uint8_t pk[crypto_kem_mlkem768_PUBLICKEYBYTES]);
صحيح crypto_kem_mlkem768_dec(uint8_t shared_secret[crypto_kem_mlkem768_بایټونه],
    ثابت uint8_t ct[crypto_kem_mlkem768_CIPHERTEXTBYTES],
    ثابت uint8_t sk[crypto_kem_mlkem768_SECRETKEYBYTES]);
صحيح crypto_kem_mlkem768_keypair_seeded(uint8_t pk[crypto_kem_mlkem768_PUBLICKEYBYTES],
    uint8_t sk[crypto_kem_mlkem768_SECRETKEYBYTES], ثابت uint8_t تخم[64]);
صحيح crypto_kem_mlkem768_enc_seeded(uint8_t ct[crypto_kem_mlkem768_CIPHERTEXTBYTES],
    uint8_t shared_secret[crypto_kem_mlkem768_بایټونه],
    ثابت uint8_t pk[crypto_kem_mlkem768_PUBLICKEYBYTES],
    ثابت uint8_t تخم[32]);

/* ML-DSA-44 */
#تعریف_کړه MLDSA44_PUBLICKEYBYTES 1312
#تعریف_کړه MLDSA44_SECRETKEYBYTES 2560
#تعریف_کړه MLDSA44_SIGBYTES 2420
#تعریف_کړه MLDSA44_SEEDBYTES 32

صحيح crypto_sign_mldsa44_keypair(uint8_t pk[MLDSA44_PUBLICKEYBYTES],
    uint8_t sk[MLDSA44_SECRETKEYBYTES]);
صحيح crypto_sign_mldsa44(uint8_t sig[MLDSA44_SIGBYTES],
    ثابت uint8_t *پیغام, اندازه_t msglen,
    ثابت uint8_t *ctx, اندازه_t ctxlen,
    ثابت uint8_t sk[MLDSA44_SECRETKEYBYTES]);
صحيح crypto_sign_mldsa44_verify(ثابت uint8_t sig[MLDSA44_SIGBYTES],
    ثابت uint8_t *پیغام, اندازه_t msglen,
    ثابت uint8_t *ctx, اندازه_t ctxlen,
    ثابت uint8_t pk[MLDSA44_PUBLICKEYBYTES]);
صحيح crypto_sign_mldsa44_keypair_seeded(uint8_t pk[MLDSA44_PUBLICKEYBYTES],
    uint8_t sk[MLDSA44_SECRETKEYBYTES], ثابت uint8_t تخم[MLDSA44_SEEDBYTES]);
صحيح crypto_sign_mldsa44_seeded(uint8_t sig[MLDSA44_SIGBYTES],
    ثابت uint8_t *پیغام, اندازه_t msglen,
    ثابت uint8_t *ctx, اندازه_t ctxlen,
    ثابت uint8_t sk[MLDSA44_SECRETKEYBYTES],
    ثابت uint8_t تخم[MLDSA44_SEEDBYTES]);

/* ML-DSA-65 */
#تعریف_کړه MLDSA65_PUBLICKEYBYTES 1952
#تعریف_کړه MLDSA65_SECRETKEYBYTES 4032
#تعریف_کړه MLDSA65_SIGBYTES 3309
#تعریف_کړه MLDSA65_SEEDBYTES 32

#إذا 0
صحيح crypto_sign_mldsa65_keypair(uint8_t pk[MLDSA65_PUBLICKEYBYTES],
    uint8_t sk[MLDSA65_SECRETKEYBYTES]);
صحيح crypto_sign_mldsa65(uint8_t sig[MLDSA65_SIGBYTES],
    ثابت uint8_t *پیغام, اندازه_t msglen,
    ثابت uint8_t *ctx, اندازه_t ctxlen,
    ثابت uint8_t sk[MLDSA65_SECRETKEYBYTES]);
صحيح crypto_sign_mldsa65_verify(ثابت uint8_t sig[MLDSA65_SIGBYTES],
    ثابت uint8_t *پیغام, اندازه_t msglen,
    ثابت uint8_t *ctx, اندازه_t ctxlen,
    ثابت uint8_t pk[MLDSA65_PUBLICKEYBYTES]);
صحيح crypto_sign_mldsa65_keypair_seeded(uint8_t pk[MLDSA65_PUBLICKEYBYTES],
    uint8_t sk[MLDSA65_SECRETKEYBYTES], ثابت uint8_t تخم[MLDSA65_SEEDBYTES]);
صحيح crypto_sign_mldsa65_seeded(uint8_t sig[MLDSA65_SIGBYTES],
    ثابت uint8_t *پیغام, اندازه_t msglen,
    ثابت uint8_t *ctx, اندازه_t ctxlen,
    ثابت uint8_t sk[MLDSA65_SECRETKEYBYTES],
    ثابت uint8_t تخم[MLDSA65_SEEDBYTES]);
#د_که_پای

/* ML-DSA-87 */
#تعریف_کړه MLDSA87_PUBLICKEYBYTES 2592
#تعریف_کړه MLDSA87_SECRETKEYBYTES 4896
#تعریف_کړه MLDSA87_SIGBYTES 4627
#تعریف_کړه MLDSA87_SEEDBYTES 32

صحيح crypto_sign_mldsa87_keypair(uint8_t pk[MLDSA87_PUBLICKEYBYTES],
    uint8_t sk[MLDSA87_SECRETKEYBYTES]);
صحيح crypto_sign_mldsa87(uint8_t sig[MLDSA87_SIGBYTES],
    ثابت uint8_t *پیغام, اندازه_t msglen,
    ثابت uint8_t *ctx, اندازه_t ctxlen,
    ثابت uint8_t sk[MLDSA87_SECRETKEYBYTES]);
صحيح crypto_sign_mldsa87_verify(ثابت uint8_t sig[MLDSA87_SIGBYTES],
    ثابت uint8_t *پیغام, اندازه_t msglen,
    ثابت uint8_t *ctx, اندازه_t ctxlen,
    ثابت uint8_t pk[MLDSA87_PUBLICKEYBYTES]);
صحيح crypto_sign_mldsa87_keypair_seeded(uint8_t pk[MLDSA87_PUBLICKEYBYTES],
    uint8_t sk[MLDSA87_SECRETKEYBYTES], ثابت uint8_t تخم[MLDSA87_SEEDBYTES]);
صحيح crypto_sign_mldsa87_seeded(uint8_t sig[MLDSA87_SIGBYTES],
    ثابت uint8_t *پیغام, اندازه_t msglen,
    ثابت uint8_t *ctx, اندازه_t ctxlen,
    ثابت uint8_t sk[MLDSA87_SECRETKEYBYTES],
    ثابت uint8_t تخم[MLDSA87_SEEDBYTES]);

/* MLDSA44-Ed25519-SHA512 */
#تعریف_کړه MLDSA44_ED25519_PK_SZ (MLDSA44_PUBLICKEYBYTES + crypto_sign_ed25519_PUBLICKEYBYTES)
#تعریف_کړه MLDSA44_ED25519_SK_SZ (MLDSA44_SEEDBYTES + crypto_sign_ed25519_SEEDBYTES)
#تعریف_کړه MLDSA44_ED25519_SIG_SZ (MLDSA44_SIGBYTES + crypto_sign_ed25519_بایټونه)

صحيح crypto_sign_mldsa44_ed25519_keygen(uint8_t pk[MLDSA44_ED25519_PK_SZ],
    uint8_t sk[MLDSA44_ED25519_SK_SZ]);
صحيح crypto_sign_mldsa44_ed25519_keygen_seeded(uint8_t pk[MLDSA44_ED25519_PK_SZ],
    uint8_t sk[MLDSA44_ED25519_SK_SZ],
    ثابت uint8_t mldsa_تخم[MLDSA44_SEEDBYTES],
    ثابت uint8_t ed25519_تخم[crypto_sign_ed25519_SEEDBYTES]);
صحيح crypto_sign_mldsa44_ed25519_sign(uint8_t sig[MLDSA44_ED25519_SIG_SZ],
    ثابت uint8_t *پیغام, اندازه_t msglen,
    ثابت uint8_t *ctx, اندازه_t ctxlen,
    ثابت uint8_t sk[MLDSA44_ED25519_SK_SZ]);
صحيح crypto_sign_mldsa44_ed25519_verify(ثابت uint8_t sig[MLDSA44_ED25519_SIG_SZ],
    ثابت uint8_t *پیغام, اندازه_t msglen,
    ثابت uint8_t *ctx, اندازه_t ctxlen,
    ثابت uint8_t pk[MLDSA44_ED25519_PK_SZ]);

/* Utility */
فراغ sha3_256(uint8_t digest[32], ثابت uint8_t *معلومات, اندازه_t len);
فراغ sha3_512(uint8_t digest[64], ثابت uint8_t *معلومات, اندازه_t len);

#د_که_پای /* crypto_api_h */
