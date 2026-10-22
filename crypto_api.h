/* $OpenBSD: crypto_api.h,v 1.13 2026/09/16 00:43:00 djm Exp $ */

/*
 * Assembled from generated headers and source files by Markus Friedl.
 * Placed in the public domain.
 */

#ifndef crypto_api_h
#define crypto_api_h

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <stdint.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>

ପ୍ରକାରବ୍ୟାଖ୍ୟା int8_t crypto_int8;
ପ୍ରକାରବ୍ୟାଖ୍ୟା uint8_t crypto_uint8;
ପ୍ରକାରବ୍ୟାଖ୍ୟା int16_t crypto_int16;
ପ୍ରକାରବ୍ୟାଖ୍ୟା uint16_t crypto_uint16;
ପ୍ରକାରବ୍ୟାଖ୍ୟା int32_t crypto_int32;
ପ୍ରକାରବ୍ୟାଖ୍ୟା uint32_t crypto_uint32;
ପ୍ରକାରବ୍ୟାଖ୍ୟା int64_t crypto_int64;
ପ୍ରକାରବ୍ୟାଖ୍ୟା uint64_t crypto_uint64;

#define randombytes(buf, buf_len) arc4random_buf((buf), (buf_len))
#define small_random32() arc4random()

#define crypto_hash_sha512_BYTES 64U

#ifdef WITH_OPENSSL
#ଅନ୍ତର୍ଭାଵ <openssl/evp.h>
ସ୍ଥିର ଧାଡ଼ିଭିତରେ ପୂର୍ଣ୍ଣସଂଖ୍ୟା
crypto_hash_sha512(unsigned ଅକ୍ଷର *out, ଅଚଳ unsigned ଅକ୍ଷର *in,
    unsigned long long inlen)
{

	ଯଦି (!EVP_Digest(in, inlen, out, ଖାଲି, EVP_sha512(), ଖାଲି))
		ଫେରନ୍ତୁ -1;
	ଫେରନ୍ତୁ 0;
}
#ଅନ୍ୟଥା /* WITH_OPENSSL */
# ifdef HAVE_SHA2_H
#  include <sha2.h>
# endif
ସ୍ଥିର ଧାଡ଼ିଭିତରେ ପୂର୍ଣ୍ଣସଂଖ୍ୟା
crypto_hash_sha512(unsigned ଅକ୍ଷର *out, ଅଚଳ unsigned ଅକ୍ଷର *in,
    unsigned long long inlen)
{

	SHA2_CTX ctx;

	SHA512Init(&ctx);
	SHA512Update(&ctx, in, inlen);
	SHA512Final(out, &ctx);
	ଫେରନ୍ତୁ 0;
}
#endif /* WITH_OPENSSL */

#define crypto_sign_ed25519_SECRETKEYBYTES 64U
#define crypto_sign_ed25519_PUBLICKEYBYTES 32U
#define crypto_sign_ed25519_SEEDBYTES 32U
#define crypto_sign_ed25519_BYTES 64U

ପୂର୍ଣ୍ଣସଂଖ୍ୟା	crypto_sign_ed25519_detached(unsigned ଅକ୍ଷର *, unsigned long long *,
    ଅଚଳ unsigned ଅକ୍ଷର *, unsigned long long, ଅଚଳ unsigned ଅକ୍ଷର *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	crypto_sign_ed25519_verify_detached(ଅଚଳ unsigned ଅକ୍ଷର *,
    ଅଚଳ unsigned ଅକ୍ଷର *, unsigned long long, ଅଚଳ unsigned ଅକ୍ଷର *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	crypto_sign_ed25519_keypair(unsigned ଅକ୍ଷର *, unsigned ଅକ୍ଷର *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	crypto_sign_ed25519_seed_keypair(unsigned ଅକ୍ଷର *, unsigned ଅକ୍ଷର *,
    ଅଚଳ unsigned ଅକ୍ଷର *);

#define crypto_kem_sntrup761_PUBLICKEYBYTES 1158
#define crypto_kem_sntrup761_SECRETKEYBYTES 1763
#define crypto_kem_sntrup761_CIPHERTEXTBYTES 1039
#define crypto_kem_sntrup761_BYTES 32

ପୂର୍ଣ୍ଣସଂଖ୍ୟା	crypto_kem_sntrup761_enc(unsigned ଅକ୍ଷର *cstr, unsigned ଅକ୍ଷର *k,
    ଅଚଳ unsigned ଅକ୍ଷର *pk);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	crypto_kem_sntrup761_dec(unsigned ଅକ୍ଷର *k,
    ଅଚଳ unsigned ଅକ୍ଷର *cstr, ଅଚଳ unsigned ଅକ୍ଷର *sk);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	crypto_kem_sntrup761_keypair(unsigned ଅକ୍ଷର *pk, unsigned ଅକ୍ଷର *sk);

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

ପୂର୍ଣ୍ଣସଂଖ୍ୟା crypto_kem_mlkem768_keypair(uint8_t pk[crypto_kem_mlkem768_PUBLICKEYBYTES],
    uint8_t sk[crypto_kem_mlkem768_SECRETKEYBYTES]);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା crypto_kem_mlkem768_enc(uint8_t ct[crypto_kem_mlkem768_CIPHERTEXTBYTES],
    uint8_t shared_secret[crypto_kem_mlkem768_BYTES],
    ଅଚଳ uint8_t pk[crypto_kem_mlkem768_PUBLICKEYBYTES]);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା crypto_kem_mlkem768_dec(uint8_t shared_secret[crypto_kem_mlkem768_BYTES],
    ଅଚଳ uint8_t ct[crypto_kem_mlkem768_CIPHERTEXTBYTES],
    ଅଚଳ uint8_t sk[crypto_kem_mlkem768_SECRETKEYBYTES]);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା crypto_kem_mlkem768_keypair_seeded(uint8_t pk[crypto_kem_mlkem768_PUBLICKEYBYTES],
    uint8_t sk[crypto_kem_mlkem768_SECRETKEYBYTES], ଅଚଳ uint8_t seed[64]);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା crypto_kem_mlkem768_enc_seeded(uint8_t ct[crypto_kem_mlkem768_CIPHERTEXTBYTES],
    uint8_t shared_secret[crypto_kem_mlkem768_BYTES],
    ଅଚଳ uint8_t pk[crypto_kem_mlkem768_PUBLICKEYBYTES],
    ଅଚଳ uint8_t seed[32]);

/* ML-DSA-44 */
#define MLDSA44_PUBLICKEYBYTES 1312
#define MLDSA44_SECRETKEYBYTES 2560
#define MLDSA44_SIGBYTES 2420
#define MLDSA44_SEEDBYTES 32

ପୂର୍ଣ୍ଣସଂଖ୍ୟା crypto_sign_mldsa44_keypair(uint8_t pk[MLDSA44_PUBLICKEYBYTES],
    uint8_t sk[MLDSA44_SECRETKEYBYTES]);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା crypto_sign_mldsa44(uint8_t sig[MLDSA44_SIGBYTES],
    ଅଚଳ uint8_t *ସନ୍ଦେଶ, size_t msglen,
    ଅଚଳ uint8_t *ctx, size_t ctxlen,
    ଅଚଳ uint8_t sk[MLDSA44_SECRETKEYBYTES]);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା crypto_sign_mldsa44_verify(ଅଚଳ uint8_t sig[MLDSA44_SIGBYTES],
    ଅଚଳ uint8_t *ସନ୍ଦେଶ, size_t msglen,
    ଅଚଳ uint8_t *ctx, size_t ctxlen,
    ଅଚଳ uint8_t pk[MLDSA44_PUBLICKEYBYTES]);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା crypto_sign_mldsa44_keypair_seeded(uint8_t pk[MLDSA44_PUBLICKEYBYTES],
    uint8_t sk[MLDSA44_SECRETKEYBYTES], ଅଚଳ uint8_t seed[MLDSA44_SEEDBYTES]);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା crypto_sign_mldsa44_seeded(uint8_t sig[MLDSA44_SIGBYTES],
    ଅଚଳ uint8_t *ସନ୍ଦେଶ, size_t msglen,
    ଅଚଳ uint8_t *ctx, size_t ctxlen,
    ଅଚଳ uint8_t sk[MLDSA44_SECRETKEYBYTES],
    ଅଚଳ uint8_t seed[MLDSA44_SEEDBYTES]);

/* ML-DSA-65 */
#define MLDSA65_PUBLICKEYBYTES 1952
#define MLDSA65_SECRETKEYBYTES 4032
#define MLDSA65_SIGBYTES 3309
#define MLDSA65_SEEDBYTES 32

#ଯଦି 0
ପୂର୍ଣ୍ଣସଂଖ୍ୟା crypto_sign_mldsa65_keypair(uint8_t pk[MLDSA65_PUBLICKEYBYTES],
    uint8_t sk[MLDSA65_SECRETKEYBYTES]);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା crypto_sign_mldsa65(uint8_t sig[MLDSA65_SIGBYTES],
    ଅଚଳ uint8_t *ସନ୍ଦେଶ, size_t msglen,
    ଅଚଳ uint8_t *ctx, size_t ctxlen,
    ଅଚଳ uint8_t sk[MLDSA65_SECRETKEYBYTES]);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା crypto_sign_mldsa65_verify(ଅଚଳ uint8_t sig[MLDSA65_SIGBYTES],
    ଅଚଳ uint8_t *ସନ୍ଦେଶ, size_t msglen,
    ଅଚଳ uint8_t *ctx, size_t ctxlen,
    ଅଚଳ uint8_t pk[MLDSA65_PUBLICKEYBYTES]);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା crypto_sign_mldsa65_keypair_seeded(uint8_t pk[MLDSA65_PUBLICKEYBYTES],
    uint8_t sk[MLDSA65_SECRETKEYBYTES], ଅଚଳ uint8_t seed[MLDSA65_SEEDBYTES]);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା crypto_sign_mldsa65_seeded(uint8_t sig[MLDSA65_SIGBYTES],
    ଅଚଳ uint8_t *ସନ୍ଦେଶ, size_t msglen,
    ଅଚଳ uint8_t *ctx, size_t ctxlen,
    ଅଚଳ uint8_t sk[MLDSA65_SECRETKEYBYTES],
    ଅଚଳ uint8_t seed[MLDSA65_SEEDBYTES]);
#endif

/* ML-DSA-87 */
#define MLDSA87_PUBLICKEYBYTES 2592
#define MLDSA87_SECRETKEYBYTES 4896
#define MLDSA87_SIGBYTES 4627
#define MLDSA87_SEEDBYTES 32

ପୂର୍ଣ୍ଣସଂଖ୍ୟା crypto_sign_mldsa87_keypair(uint8_t pk[MLDSA87_PUBLICKEYBYTES],
    uint8_t sk[MLDSA87_SECRETKEYBYTES]);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା crypto_sign_mldsa87(uint8_t sig[MLDSA87_SIGBYTES],
    ଅଚଳ uint8_t *ସନ୍ଦେଶ, size_t msglen,
    ଅଚଳ uint8_t *ctx, size_t ctxlen,
    ଅଚଳ uint8_t sk[MLDSA87_SECRETKEYBYTES]);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା crypto_sign_mldsa87_verify(ଅଚଳ uint8_t sig[MLDSA87_SIGBYTES],
    ଅଚଳ uint8_t *ସନ୍ଦେଶ, size_t msglen,
    ଅଚଳ uint8_t *ctx, size_t ctxlen,
    ଅଚଳ uint8_t pk[MLDSA87_PUBLICKEYBYTES]);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା crypto_sign_mldsa87_keypair_seeded(uint8_t pk[MLDSA87_PUBLICKEYBYTES],
    uint8_t sk[MLDSA87_SECRETKEYBYTES], ଅଚଳ uint8_t seed[MLDSA87_SEEDBYTES]);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା crypto_sign_mldsa87_seeded(uint8_t sig[MLDSA87_SIGBYTES],
    ଅଚଳ uint8_t *ସନ୍ଦେଶ, size_t msglen,
    ଅଚଳ uint8_t *ctx, size_t ctxlen,
    ଅଚଳ uint8_t sk[MLDSA87_SECRETKEYBYTES],
    ଅଚଳ uint8_t seed[MLDSA87_SEEDBYTES]);

/* MLDSA44-Ed25519-SHA512 */
#define MLDSA44_ED25519_PK_SZ (MLDSA44_PUBLICKEYBYTES + crypto_sign_ed25519_PUBLICKEYBYTES)
#define MLDSA44_ED25519_SK_SZ (MLDSA44_SEEDBYTES + crypto_sign_ed25519_SEEDBYTES)
#define MLDSA44_ED25519_SIG_SZ (MLDSA44_SIGBYTES + crypto_sign_ed25519_BYTES)

ପୂର୍ଣ୍ଣସଂଖ୍ୟା crypto_sign_mldsa44_ed25519_keygen(uint8_t pk[MLDSA44_ED25519_PK_SZ],
    uint8_t sk[MLDSA44_ED25519_SK_SZ]);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା crypto_sign_mldsa44_ed25519_keygen_seeded(uint8_t pk[MLDSA44_ED25519_PK_SZ],
    uint8_t sk[MLDSA44_ED25519_SK_SZ],
    ଅଚଳ uint8_t mldsa_seed[MLDSA44_SEEDBYTES],
    ଅଚଳ uint8_t ed25519_seed[crypto_sign_ed25519_SEEDBYTES]);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା crypto_sign_mldsa44_ed25519_sign(uint8_t sig[MLDSA44_ED25519_SIG_SZ],
    ଅଚଳ uint8_t *ସନ୍ଦେଶ, size_t msglen,
    ଅଚଳ uint8_t *ctx, size_t ctxlen,
    ଅଚଳ uint8_t sk[MLDSA44_ED25519_SK_SZ]);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା crypto_sign_mldsa44_ed25519_verify(ଅଚଳ uint8_t sig[MLDSA44_ED25519_SIG_SZ],
    ଅଚଳ uint8_t *ସନ୍ଦେଶ, size_t msglen,
    ଅଚଳ uint8_t *ctx, size_t ctxlen,
    ଅଚଳ uint8_t pk[MLDSA44_ED25519_PK_SZ]);

/* Utility */
ଶୂନ୍ୟ sha3_256(uint8_t digest[32], ଅଚଳ uint8_t *data, size_t len);
ଶୂନ୍ୟ sha3_512(uint8_t digest[64], ଅଚଳ uint8_t *data, size_t len);

#endif /* crypto_api_h */
