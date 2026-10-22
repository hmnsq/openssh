/* $OpenBSD: crypto_api.h,v 1.13 2026/09/16 00:43:00 djm Exp $ */

/*
 * Assembled from generated headers and source files by Markus Friedl.
 * Placed in the public domain.
 */

#यदि_अपरिभाषितम् crypto_api_h
#परिभाषय crypto_api_h

#अन्तर्भाव "includes.h"

#अन्तर्भाव <stdint.h>
#अन्तर्भाव <stdlib.h>

प्रकारनिर्देश int8_t crypto_int8;
प्रकारनिर्देश uint8_t crypto_uint8;
प्रकारनिर्देश int16_t crypto_int16;
प्रकारनिर्देश uint16_t crypto_uint16;
प्रकारनिर्देश int32_t crypto_int32;
प्रकारनिर्देश uint32_t crypto_uint32;
प्रकारनिर्देश int64_t crypto_int64;
प्रकारनिर्देश uint64_t crypto_uint64;

#परिभाषय randombytes(buf, buf_len) arc4random_buf((buf), (buf_len))
#परिभाषय small_random32() arc4random()

#परिभाषय crypto_hash_sha512_अष्टकानि 64U

#यदि_परिभाषितम् WITH_OPENSSL
#अन्तर्भाव <openssl/evp.h>
स्थिर अन्तःस्थ पूर्णाङ्क
crypto_hash_sha512(अचिह्नित वर्ण *बहिर्गमनम्, ध्रुव अचिह्नित वर्ण *अन्तर्,
    अचिह्नित दीर्घ दीर्घ inlen)
{

	यदि (!EVP_Digest(अन्तर्, inlen, बहिर्गमनम्, रिक्त, EVP_sha512(), रिक्त))
		प्रत्यागम -1;
	प्रत्यागम 0;
}
#अन्यथा /* WITH_OPENSSL */
# ifdef HAVE_SHA2_H
#  include <sha2.h>
# endif
स्थिर अन्तःस्थ पूर्णाङ्क
crypto_hash_sha512(अचिह्नित वर्ण *बहिर्गमनम्, ध्रुव अचिह्नित वर्ण *अन्तर्,
    अचिह्नित दीर्घ दीर्घ inlen)
{

	SHA2_CTX ctx;

	SHA512Init(&ctx);
	SHA512Update(&ctx, अन्तर्, inlen);
	SHA512Final(बहिर्गमनम्, &ctx);
	प्रत्यागम 0;
}
#यदि_अन्तः /* WITH_OPENSSL */

#परिभाषय crypto_sign_ed25519_SECRETKEYBYTES 64U
#परिभाषय crypto_sign_ed25519_PUBLICKEYBYTES 32U
#परिभाषय crypto_sign_ed25519_SEEDBYTES 32U
#परिभाषय crypto_sign_ed25519_अष्टकानि 64U

पूर्णाङ्क	crypto_sign_ed25519_detached(अचिह्नित वर्ण *, अचिह्नित दीर्घ दीर्घ *,
    ध्रुव अचिह्नित वर्ण *, अचिह्नित दीर्घ दीर्घ, ध्रुव अचिह्नित वर्ण *);
पूर्णाङ्क	crypto_sign_ed25519_verify_detached(ध्रुव अचिह्नित वर्ण *,
    ध्रुव अचिह्नित वर्ण *, अचिह्नित दीर्घ दीर्घ, ध्रुव अचिह्नित वर्ण *);
पूर्णाङ्क	crypto_sign_ed25519_keypair(अचिह्नित वर्ण *, अचिह्नित वर्ण *);
पूर्णाङ्क	crypto_sign_ed25519_बीजम्_keypair(अचिह्नित वर्ण *, अचिह्नित वर्ण *,
    ध्रुव अचिह्नित वर्ण *);

#परिभाषय crypto_kem_sntrup761_PUBLICKEYBYTES 1158
#परिभाषय crypto_kem_sntrup761_SECRETKEYBYTES 1763
#परिभाषय crypto_kem_sntrup761_CIPHERTEXTBYTES 1039
#परिभाषय crypto_kem_sntrup761_अष्टकानि 32

पूर्णाङ्क	crypto_kem_sntrup761_enc(अचिह्नित वर्ण *cstr, अचिह्नित वर्ण *k,
    ध्रुव अचिह्नित वर्ण *pk);
पूर्णाङ्क	crypto_kem_sntrup761_dec(अचिह्नित वर्ण *k,
    ध्रुव अचिह्नित वर्ण *cstr, ध्रुव अचिह्नित वर्ण *sk);
पूर्णाङ्क	crypto_kem_sntrup761_keypair(अचिह्नित वर्ण *pk, अचिह्नित वर्ण *sk);

/* ML-KEM-768 */
#परिभाषय crypto_kem_mlkem768_PUBLICKEYBYTES 1184
#परिभाषय crypto_kem_mlkem768_SECRETKEYBYTES 2400
#परिभाषय crypto_kem_mlkem768_CIPHERTEXTBYTES 1088
#परिभाषय crypto_kem_mlkem768_अष्टकानि 32
#परिभाषय crypto_kem_mlkem768_ENCSEEDBYTES 32
#परिभाषय crypto_kem_mlkem768_KEYPAIRSEEDBYTES 64

/* Aliases for MLKEM768 */
#परिभाषय MLKEM768_PUBLICKEYBYTES crypto_kem_mlkem768_PUBLICKEYBYTES
#परिभाषय MLKEM768_SECRETKEYBYTES crypto_kem_mlkem768_SECRETKEYBYTES
#परिभाषय MLKEM768_CIPHERTEXTBYTES crypto_kem_mlkem768_CIPHERTEXTBYTES
#परिभाषय MLKEM768_अष्टकानि crypto_kem_mlkem768_अष्टकानि

पूर्णाङ्क crypto_kem_mlkem768_keypair(uint8_t pk[crypto_kem_mlkem768_PUBLICKEYBYTES],
    uint8_t sk[crypto_kem_mlkem768_SECRETKEYBYTES]);
पूर्णाङ्क crypto_kem_mlkem768_enc(uint8_t ct[crypto_kem_mlkem768_CIPHERTEXTBYTES],
    uint8_t shared_secret[crypto_kem_mlkem768_अष्टकानि],
    ध्रुव uint8_t pk[crypto_kem_mlkem768_PUBLICKEYBYTES]);
पूर्णाङ्क crypto_kem_mlkem768_dec(uint8_t shared_secret[crypto_kem_mlkem768_अष्टकानि],
    ध्रुव uint8_t ct[crypto_kem_mlkem768_CIPHERTEXTBYTES],
    ध्रुव uint8_t sk[crypto_kem_mlkem768_SECRETKEYBYTES]);
पूर्णाङ्क crypto_kem_mlkem768_keypair_seeded(uint8_t pk[crypto_kem_mlkem768_PUBLICKEYBYTES],
    uint8_t sk[crypto_kem_mlkem768_SECRETKEYBYTES], ध्रुव uint8_t बीजम्[64]);
पूर्णाङ्क crypto_kem_mlkem768_enc_seeded(uint8_t ct[crypto_kem_mlkem768_CIPHERTEXTBYTES],
    uint8_t shared_secret[crypto_kem_mlkem768_अष्टकानि],
    ध्रुव uint8_t pk[crypto_kem_mlkem768_PUBLICKEYBYTES],
    ध्रुव uint8_t बीजम्[32]);

/* ML-DSA-44 */
#परिभाषय MLDSA44_PUBLICKEYBYTES 1312
#परिभाषय MLDSA44_SECRETKEYBYTES 2560
#परिभाषय MLDSA44_SIGBYTES 2420
#परिभाषय MLDSA44_SEEDBYTES 32

पूर्णाङ्क crypto_sign_mldsa44_keypair(uint8_t pk[MLDSA44_PUBLICKEYBYTES],
    uint8_t sk[MLDSA44_SECRETKEYBYTES]);
पूर्णाङ्क crypto_sign_mldsa44(uint8_t sig[MLDSA44_SIGBYTES],
    ध्रुव uint8_t *सन्देशः, आकार_t msglen,
    ध्रुव uint8_t *ctx, आकार_t ctxlen,
    ध्रुव uint8_t sk[MLDSA44_SECRETKEYBYTES]);
पूर्णाङ्क crypto_sign_mldsa44_verify(ध्रुव uint8_t sig[MLDSA44_SIGBYTES],
    ध्रुव uint8_t *सन्देशः, आकार_t msglen,
    ध्रुव uint8_t *ctx, आकार_t ctxlen,
    ध्रुव uint8_t pk[MLDSA44_PUBLICKEYBYTES]);
पूर्णाङ्क crypto_sign_mldsa44_keypair_seeded(uint8_t pk[MLDSA44_PUBLICKEYBYTES],
    uint8_t sk[MLDSA44_SECRETKEYBYTES], ध्रुव uint8_t बीजम्[MLDSA44_SEEDBYTES]);
पूर्णाङ्क crypto_sign_mldsa44_seeded(uint8_t sig[MLDSA44_SIGBYTES],
    ध्रुव uint8_t *सन्देशः, आकार_t msglen,
    ध्रुव uint8_t *ctx, आकार_t ctxlen,
    ध्रुव uint8_t sk[MLDSA44_SECRETKEYBYTES],
    ध्रुव uint8_t बीजम्[MLDSA44_SEEDBYTES]);

/* ML-DSA-65 */
#परिभाषय MLDSA65_PUBLICKEYBYTES 1952
#परिभाषय MLDSA65_SECRETKEYBYTES 4032
#परिभाषय MLDSA65_SIGBYTES 3309
#परिभाषय MLDSA65_SEEDBYTES 32

#यदि 0
पूर्णाङ्क crypto_sign_mldsa65_keypair(uint8_t pk[MLDSA65_PUBLICKEYBYTES],
    uint8_t sk[MLDSA65_SECRETKEYBYTES]);
पूर्णाङ्क crypto_sign_mldsa65(uint8_t sig[MLDSA65_SIGBYTES],
    ध्रुव uint8_t *सन्देशः, आकार_t msglen,
    ध्रुव uint8_t *ctx, आकार_t ctxlen,
    ध्रुव uint8_t sk[MLDSA65_SECRETKEYBYTES]);
पूर्णाङ्क crypto_sign_mldsa65_verify(ध्रुव uint8_t sig[MLDSA65_SIGBYTES],
    ध्रुव uint8_t *सन्देशः, आकार_t msglen,
    ध्रुव uint8_t *ctx, आकार_t ctxlen,
    ध्रुव uint8_t pk[MLDSA65_PUBLICKEYBYTES]);
पूर्णाङ्क crypto_sign_mldsa65_keypair_seeded(uint8_t pk[MLDSA65_PUBLICKEYBYTES],
    uint8_t sk[MLDSA65_SECRETKEYBYTES], ध्रुव uint8_t बीजम्[MLDSA65_SEEDBYTES]);
पूर्णाङ्क crypto_sign_mldsa65_seeded(uint8_t sig[MLDSA65_SIGBYTES],
    ध्रुव uint8_t *सन्देशः, आकार_t msglen,
    ध्रुव uint8_t *ctx, आकार_t ctxlen,
    ध्रुव uint8_t sk[MLDSA65_SECRETKEYBYTES],
    ध्रुव uint8_t बीजम्[MLDSA65_SEEDBYTES]);
#यदि_अन्तः

/* ML-DSA-87 */
#परिभाषय MLDSA87_PUBLICKEYBYTES 2592
#परिभाषय MLDSA87_SECRETKEYBYTES 4896
#परिभाषय MLDSA87_SIGBYTES 4627
#परिभाषय MLDSA87_SEEDBYTES 32

पूर्णाङ्क crypto_sign_mldsa87_keypair(uint8_t pk[MLDSA87_PUBLICKEYBYTES],
    uint8_t sk[MLDSA87_SECRETKEYBYTES]);
पूर्णाङ्क crypto_sign_mldsa87(uint8_t sig[MLDSA87_SIGBYTES],
    ध्रुव uint8_t *सन्देशः, आकार_t msglen,
    ध्रुव uint8_t *ctx, आकार_t ctxlen,
    ध्रुव uint8_t sk[MLDSA87_SECRETKEYBYTES]);
पूर्णाङ्क crypto_sign_mldsa87_verify(ध्रुव uint8_t sig[MLDSA87_SIGBYTES],
    ध्रुव uint8_t *सन्देशः, आकार_t msglen,
    ध्रुव uint8_t *ctx, आकार_t ctxlen,
    ध्रुव uint8_t pk[MLDSA87_PUBLICKEYBYTES]);
पूर्णाङ्क crypto_sign_mldsa87_keypair_seeded(uint8_t pk[MLDSA87_PUBLICKEYBYTES],
    uint8_t sk[MLDSA87_SECRETKEYBYTES], ध्रुव uint8_t बीजम्[MLDSA87_SEEDBYTES]);
पूर्णाङ्क crypto_sign_mldsa87_seeded(uint8_t sig[MLDSA87_SIGBYTES],
    ध्रुव uint8_t *सन्देशः, आकार_t msglen,
    ध्रुव uint8_t *ctx, आकार_t ctxlen,
    ध्रुव uint8_t sk[MLDSA87_SECRETKEYBYTES],
    ध्रुव uint8_t बीजम्[MLDSA87_SEEDBYTES]);

/* MLDSA44-Ed25519-SHA512 */
#परिभाषय MLDSA44_ED25519_PK_SZ (MLDSA44_PUBLICKEYBYTES + crypto_sign_ed25519_PUBLICKEYBYTES)
#परिभाषय MLDSA44_ED25519_SK_SZ (MLDSA44_SEEDBYTES + crypto_sign_ed25519_SEEDBYTES)
#परिभाषय MLDSA44_ED25519_SIG_SZ (MLDSA44_SIGBYTES + crypto_sign_ed25519_अष्टकानि)

पूर्णाङ्क crypto_sign_mldsa44_ed25519_keygen(uint8_t pk[MLDSA44_ED25519_PK_SZ],
    uint8_t sk[MLDSA44_ED25519_SK_SZ]);
पूर्णाङ्क crypto_sign_mldsa44_ed25519_keygen_seeded(uint8_t pk[MLDSA44_ED25519_PK_SZ],
    uint8_t sk[MLDSA44_ED25519_SK_SZ],
    ध्रुव uint8_t mldsa_बीजम्[MLDSA44_SEEDBYTES],
    ध्रुव uint8_t ed25519_बीजम्[crypto_sign_ed25519_SEEDBYTES]);
पूर्णाङ्क crypto_sign_mldsa44_ed25519_sign(uint8_t sig[MLDSA44_ED25519_SIG_SZ],
    ध्रुव uint8_t *सन्देशः, आकार_t msglen,
    ध्रुव uint8_t *ctx, आकार_t ctxlen,
    ध्रुव uint8_t sk[MLDSA44_ED25519_SK_SZ]);
पूर्णाङ्क crypto_sign_mldsa44_ed25519_verify(ध्रुव uint8_t sig[MLDSA44_ED25519_SIG_SZ],
    ध्रुव uint8_t *सन्देशः, आकार_t msglen,
    ध्रुव uint8_t *ctx, आकार_t ctxlen,
    ध्रुव uint8_t pk[MLDSA44_ED25519_PK_SZ]);

/* Utility */
शून्य sha3_256(uint8_t digest[32], ध्रुव uint8_t *दत्त, आकार_t len);
शून्य sha3_512(uint8_t digest[64], ध्रुव uint8_t *दत्त, आकार_t len);

#यदि_अन्तः /* crypto_api_h */
