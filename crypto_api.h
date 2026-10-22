/* $OpenBSD: crypto_api.h,v 1.13 2026/09/16 00:43:00 djm Exp $ */

/*
 * Assembled from generated headers and source files by Markus Friedl.
 * Placed in the public domain.
 */

#నిర్వచితం_కాకపోతే crypto_api_h
#నిర్వచించు crypto_api_h

#అన్తర్భావ "includes.h"

#అన్తర్భావ <stdint.h>
#అన్తర్భావ <stdlib.h>

రకనిర్వచనం int8_t crypto_int8;
రకనిర్వచనం uint8_t crypto_uint8;
రకనిర్వచనం int16_t crypto_int16;
రకనిర్వచనం uint16_t crypto_uint16;
రకనిర్వచనం int32_t crypto_int32;
రకనిర్వచనం uint32_t crypto_uint32;
రకనిర్వచనం int64_t crypto_int64;
రకనిర్వచనం uint64_t crypto_uint64;

#నిర్వచించు randombytes(buf, buf_len) arc4random_buf((buf), (buf_len))
#నిర్వచించు small_random32() arc4random()

#నిర్వచించు crypto_hash_sha512_బైట్లు 64U

#నిర్వచితమైతే WITH_OPENSSL
#అన్తర్భావ <openssl/evp.h>
స్థిర అంతఃవరుస పూర్ణాంకం
crypto_hash_sha512(గుర్తులేని అక్షరం *బహిర్గతం, స్థిరరాశి గుర్తులేని అక్షరం *లోపల,
    గుర్తులేని దీర్ఘ దీర్ఘ inlen)
{

	ఒకవేళ (!EVP_Digest(లోపల, inlen, బహిర్గతం, ఖాళీ, EVP_sha512(), ఖాళీ))
		తిరిగి -1;
	తిరిగి 0;
}
#లేకపోతే /* WITH_OPENSSL */
# ifdef HAVE_SHA2_H
#  include <sha2.h>
# endif
స్థిర అంతఃవరుస పూర్ణాంకం
crypto_hash_sha512(గుర్తులేని అక్షరం *బహిర్గతం, స్థిరరాశి గుర్తులేని అక్షరం *లోపల,
    గుర్తులేని దీర్ఘ దీర్ఘ inlen)
{

	SHA2_CTX ctx;

	SHA512Init(&ctx);
	SHA512Update(&ctx, లోపల, inlen);
	SHA512Final(బహిర్గతం, &ctx);
	తిరిగి 0;
}
#అయితే_ముగింపు /* WITH_OPENSSL */

#నిర్వచించు crypto_sign_ed25519_SECRETKEYBYTES 64U
#నిర్వచించు crypto_sign_ed25519_PUBLICKEYBYTES 32U
#నిర్వచించు crypto_sign_ed25519_SEEDBYTES 32U
#నిర్వచించు crypto_sign_ed25519_బైట్లు 64U

పూర్ణాంకం	crypto_sign_ed25519_detached(గుర్తులేని అక్షరం *, గుర్తులేని దీర్ఘ దీర్ఘ *,
    స్థిరరాశి గుర్తులేని అక్షరం *, గుర్తులేని దీర్ఘ దీర్ఘ, స్థిరరాశి గుర్తులేని అక్షరం *);
పూర్ణాంకం	crypto_sign_ed25519_verify_detached(స్థిరరాశి గుర్తులేని అక్షరం *,
    స్థిరరాశి గుర్తులేని అక్షరం *, గుర్తులేని దీర్ఘ దీర్ఘ, స్థిరరాశి గుర్తులేని అక్షరం *);
పూర్ణాంకం	crypto_sign_ed25519_keypair(గుర్తులేని అక్షరం *, గుర్తులేని అక్షరం *);
పూర్ణాంకం	crypto_sign_ed25519_విత్తనం_keypair(గుర్తులేని అక్షరం *, గుర్తులేని అక్షరం *,
    స్థిరరాశి గుర్తులేని అక్షరం *);

#నిర్వచించు crypto_kem_sntrup761_PUBLICKEYBYTES 1158
#నిర్వచించు crypto_kem_sntrup761_SECRETKEYBYTES 1763
#నిర్వచించు crypto_kem_sntrup761_CIPHERTEXTBYTES 1039
#నిర్వచించు crypto_kem_sntrup761_బైట్లు 32

పూర్ణాంకం	crypto_kem_sntrup761_enc(గుర్తులేని అక్షరం *cstr, గుర్తులేని అక్షరం *k,
    స్థిరరాశి గుర్తులేని అక్షరం *pk);
పూర్ణాంకం	crypto_kem_sntrup761_dec(గుర్తులేని అక్షరం *k,
    స్థిరరాశి గుర్తులేని అక్షరం *cstr, స్థిరరాశి గుర్తులేని అక్షరం *sk);
పూర్ణాంకం	crypto_kem_sntrup761_keypair(గుర్తులేని అక్షరం *pk, గుర్తులేని అక్షరం *sk);

/* ML-KEM-768 */
#నిర్వచించు crypto_kem_mlkem768_PUBLICKEYBYTES 1184
#నిర్వచించు crypto_kem_mlkem768_SECRETKEYBYTES 2400
#నిర్వచించు crypto_kem_mlkem768_CIPHERTEXTBYTES 1088
#నిర్వచించు crypto_kem_mlkem768_బైట్లు 32
#నిర్వచించు crypto_kem_mlkem768_ENCSEEDBYTES 32
#నిర్వచించు crypto_kem_mlkem768_KEYPAIRSEEDBYTES 64

/* Aliases for MLKEM768 */
#నిర్వచించు MLKEM768_PUBLICKEYBYTES crypto_kem_mlkem768_PUBLICKEYBYTES
#నిర్వచించు MLKEM768_SECRETKEYBYTES crypto_kem_mlkem768_SECRETKEYBYTES
#నిర్వచించు MLKEM768_CIPHERTEXTBYTES crypto_kem_mlkem768_CIPHERTEXTBYTES
#నిర్వచించు MLKEM768_బైట్లు crypto_kem_mlkem768_బైట్లు

పూర్ణాంకం crypto_kem_mlkem768_keypair(uint8_t pk[crypto_kem_mlkem768_PUBLICKEYBYTES],
    uint8_t sk[crypto_kem_mlkem768_SECRETKEYBYTES]);
పూర్ణాంకం crypto_kem_mlkem768_enc(uint8_t ct[crypto_kem_mlkem768_CIPHERTEXTBYTES],
    uint8_t shared_secret[crypto_kem_mlkem768_బైట్లు],
    స్థిరరాశి uint8_t pk[crypto_kem_mlkem768_PUBLICKEYBYTES]);
పూర్ణాంకం crypto_kem_mlkem768_dec(uint8_t shared_secret[crypto_kem_mlkem768_బైట్లు],
    స్థిరరాశి uint8_t ct[crypto_kem_mlkem768_CIPHERTEXTBYTES],
    స్థిరరాశి uint8_t sk[crypto_kem_mlkem768_SECRETKEYBYTES]);
పూర్ణాంకం crypto_kem_mlkem768_keypair_seeded(uint8_t pk[crypto_kem_mlkem768_PUBLICKEYBYTES],
    uint8_t sk[crypto_kem_mlkem768_SECRETKEYBYTES], స్థిరరాశి uint8_t విత్తనం[64]);
పూర్ణాంకం crypto_kem_mlkem768_enc_seeded(uint8_t ct[crypto_kem_mlkem768_CIPHERTEXTBYTES],
    uint8_t shared_secret[crypto_kem_mlkem768_బైట్లు],
    స్థిరరాశి uint8_t pk[crypto_kem_mlkem768_PUBLICKEYBYTES],
    స్థిరరాశి uint8_t విత్తనం[32]);

/* ML-DSA-44 */
#నిర్వచించు MLDSA44_PUBLICKEYBYTES 1312
#నిర్వచించు MLDSA44_SECRETKEYBYTES 2560
#నిర్వచించు MLDSA44_SIGBYTES 2420
#నిర్వచించు MLDSA44_SEEDBYTES 32

పూర్ణాంకం crypto_sign_mldsa44_keypair(uint8_t pk[MLDSA44_PUBLICKEYBYTES],
    uint8_t sk[MLDSA44_SECRETKEYBYTES]);
పూర్ణాంకం crypto_sign_mldsa44(uint8_t sig[MLDSA44_SIGBYTES],
    స్థిరరాశి uint8_t *సందేశం, కొలత_t msglen,
    స్థిరరాశి uint8_t *ctx, కొలత_t ctxlen,
    స్థిరరాశి uint8_t sk[MLDSA44_SECRETKEYBYTES]);
పూర్ణాంకం crypto_sign_mldsa44_verify(స్థిరరాశి uint8_t sig[MLDSA44_SIGBYTES],
    స్థిరరాశి uint8_t *సందేశం, కొలత_t msglen,
    స్థిరరాశి uint8_t *ctx, కొలత_t ctxlen,
    స్థిరరాశి uint8_t pk[MLDSA44_PUBLICKEYBYTES]);
పూర్ణాంకం crypto_sign_mldsa44_keypair_seeded(uint8_t pk[MLDSA44_PUBLICKEYBYTES],
    uint8_t sk[MLDSA44_SECRETKEYBYTES], స్థిరరాశి uint8_t విత్తనం[MLDSA44_SEEDBYTES]);
పూర్ణాంకం crypto_sign_mldsa44_seeded(uint8_t sig[MLDSA44_SIGBYTES],
    స్థిరరాశి uint8_t *సందేశం, కొలత_t msglen,
    స్థిరరాశి uint8_t *ctx, కొలత_t ctxlen,
    స్థిరరాశి uint8_t sk[MLDSA44_SECRETKEYBYTES],
    స్థిరరాశి uint8_t విత్తనం[MLDSA44_SEEDBYTES]);

/* ML-DSA-65 */
#నిర్వచించు MLDSA65_PUBLICKEYBYTES 1952
#నిర్వచించు MLDSA65_SECRETKEYBYTES 4032
#నిర్వచించు MLDSA65_SIGBYTES 3309
#నిర్వచించు MLDSA65_SEEDBYTES 32

#ఒకవేళ 0
పూర్ణాంకం crypto_sign_mldsa65_keypair(uint8_t pk[MLDSA65_PUBLICKEYBYTES],
    uint8_t sk[MLDSA65_SECRETKEYBYTES]);
పూర్ణాంకం crypto_sign_mldsa65(uint8_t sig[MLDSA65_SIGBYTES],
    స్థిరరాశి uint8_t *సందేశం, కొలత_t msglen,
    స్థిరరాశి uint8_t *ctx, కొలత_t ctxlen,
    స్థిరరాశి uint8_t sk[MLDSA65_SECRETKEYBYTES]);
పూర్ణాంకం crypto_sign_mldsa65_verify(స్థిరరాశి uint8_t sig[MLDSA65_SIGBYTES],
    స్థిరరాశి uint8_t *సందేశం, కొలత_t msglen,
    స్థిరరాశి uint8_t *ctx, కొలత_t ctxlen,
    స్థిరరాశి uint8_t pk[MLDSA65_PUBLICKEYBYTES]);
పూర్ణాంకం crypto_sign_mldsa65_keypair_seeded(uint8_t pk[MLDSA65_PUBLICKEYBYTES],
    uint8_t sk[MLDSA65_SECRETKEYBYTES], స్థిరరాశి uint8_t విత్తనం[MLDSA65_SEEDBYTES]);
పూర్ణాంకం crypto_sign_mldsa65_seeded(uint8_t sig[MLDSA65_SIGBYTES],
    స్థిరరాశి uint8_t *సందేశం, కొలత_t msglen,
    స్థిరరాశి uint8_t *ctx, కొలత_t ctxlen,
    స్థిరరాశి uint8_t sk[MLDSA65_SECRETKEYBYTES],
    స్థిరరాశి uint8_t విత్తనం[MLDSA65_SEEDBYTES]);
#అయితే_ముగింపు

/* ML-DSA-87 */
#నిర్వచించు MLDSA87_PUBLICKEYBYTES 2592
#నిర్వచించు MLDSA87_SECRETKEYBYTES 4896
#నిర్వచించు MLDSA87_SIGBYTES 4627
#నిర్వచించు MLDSA87_SEEDBYTES 32

పూర్ణాంకం crypto_sign_mldsa87_keypair(uint8_t pk[MLDSA87_PUBLICKEYBYTES],
    uint8_t sk[MLDSA87_SECRETKEYBYTES]);
పూర్ణాంకం crypto_sign_mldsa87(uint8_t sig[MLDSA87_SIGBYTES],
    స్థిరరాశి uint8_t *సందేశం, కొలత_t msglen,
    స్థిరరాశి uint8_t *ctx, కొలత_t ctxlen,
    స్థిరరాశి uint8_t sk[MLDSA87_SECRETKEYBYTES]);
పూర్ణాంకం crypto_sign_mldsa87_verify(స్థిరరాశి uint8_t sig[MLDSA87_SIGBYTES],
    స్థిరరాశి uint8_t *సందేశం, కొలత_t msglen,
    స్థిరరాశి uint8_t *ctx, కొలత_t ctxlen,
    స్థిరరాశి uint8_t pk[MLDSA87_PUBLICKEYBYTES]);
పూర్ణాంకం crypto_sign_mldsa87_keypair_seeded(uint8_t pk[MLDSA87_PUBLICKEYBYTES],
    uint8_t sk[MLDSA87_SECRETKEYBYTES], స్థిరరాశి uint8_t విత్తనం[MLDSA87_SEEDBYTES]);
పూర్ణాంకం crypto_sign_mldsa87_seeded(uint8_t sig[MLDSA87_SIGBYTES],
    స్థిరరాశి uint8_t *సందేశం, కొలత_t msglen,
    స్థిరరాశి uint8_t *ctx, కొలత_t ctxlen,
    స్థిరరాశి uint8_t sk[MLDSA87_SECRETKEYBYTES],
    స్థిరరాశి uint8_t విత్తనం[MLDSA87_SEEDBYTES]);

/* MLDSA44-Ed25519-SHA512 */
#నిర్వచించు MLDSA44_ED25519_PK_SZ (MLDSA44_PUBLICKEYBYTES + crypto_sign_ed25519_PUBLICKEYBYTES)
#నిర్వచించు MLDSA44_ED25519_SK_SZ (MLDSA44_SEEDBYTES + crypto_sign_ed25519_SEEDBYTES)
#నిర్వచించు MLDSA44_ED25519_SIG_SZ (MLDSA44_SIGBYTES + crypto_sign_ed25519_బైట్లు)

పూర్ణాంకం crypto_sign_mldsa44_ed25519_keygen(uint8_t pk[MLDSA44_ED25519_PK_SZ],
    uint8_t sk[MLDSA44_ED25519_SK_SZ]);
పూర్ణాంకం crypto_sign_mldsa44_ed25519_keygen_seeded(uint8_t pk[MLDSA44_ED25519_PK_SZ],
    uint8_t sk[MLDSA44_ED25519_SK_SZ],
    స్థిరరాశి uint8_t mldsa_విత్తనం[MLDSA44_SEEDBYTES],
    స్థిరరాశి uint8_t ed25519_విత్తనం[crypto_sign_ed25519_SEEDBYTES]);
పూర్ణాంకం crypto_sign_mldsa44_ed25519_sign(uint8_t sig[MLDSA44_ED25519_SIG_SZ],
    స్థిరరాశి uint8_t *సందేశం, కొలత_t msglen,
    స్థిరరాశి uint8_t *ctx, కొలత_t ctxlen,
    స్థిరరాశి uint8_t sk[MLDSA44_ED25519_SK_SZ]);
పూర్ణాంకం crypto_sign_mldsa44_ed25519_verify(స్థిరరాశి uint8_t sig[MLDSA44_ED25519_SIG_SZ],
    స్థిరరాశి uint8_t *సందేశం, కొలత_t msglen,
    స్థిరరాశి uint8_t *ctx, కొలత_t ctxlen,
    స్థిరరాశి uint8_t pk[MLDSA44_ED25519_PK_SZ]);

/* Utility */
శూన్య sha3_256(uint8_t digest[32], స్థిరరాశి uint8_t *దత్తాంశం, కొలత_t len);
శూన్య sha3_512(uint8_t digest[64], స్థిరరాశి uint8_t *దత్తాంశం, కొలత_t len);

#అయితే_ముగింపు /* crypto_api_h */
