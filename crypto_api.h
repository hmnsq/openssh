/* $OpenBSD: crypto_api.h,v 1.13 2026/09/16 00:43:00 djm Exp $ */

/*
 * Assembled from generated headers and source files by Markus Friedl.
 * Placed in the public domain.
 */

#ifndef crypto_api_h
#define crypto_api_h

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <stdint.h>
#അന്തര്ഭാവ <stdlib.h>

തരനിർവചനം int8_t crypto_int8;
തരനിർവചനം uint8_t crypto_uint8;
തരനിർവചനം int16_t crypto_int16;
തരനിർവചനം uint16_t crypto_uint16;
തരനിർവചനം int32_t crypto_int32;
തരനിർവചനം uint32_t crypto_uint32;
തരനിർവചനം int64_t crypto_int64;
തരനിർവചനം uint64_t crypto_uint64;

#define randombytes(buf, buf_len) arc4random_buf((buf), (buf_len))
#define small_random32() arc4random()

#define crypto_hash_sha512_BYTES 64U

#ifdef WITH_OPENSSL
#അന്തര്ഭാവ <openssl/evp.h>
സ്ഥിതം വരിയിൽ പൂർണ്ണസംഖ്യ
crypto_hash_sha512(unsigned അക്ഷരം *out, സ്ഥിരം unsigned അക്ഷരം *in,
    unsigned long long inlen)
{

	എങ്കിൽ (!EVP_Digest(in, inlen, out, ശൂന്യ, EVP_sha512(), ശൂന്യ))
		തിരികെ -1;
	തിരികെ 0;
}
#അല്ലെങ്കിൽ /* WITH_OPENSSL */
# ifdef HAVE_SHA2_H
#  include <sha2.h>
# endif
സ്ഥിതം വരിയിൽ പൂർണ്ണസംഖ്യ
crypto_hash_sha512(unsigned അക്ഷരം *out, സ്ഥിരം unsigned അക്ഷരം *in,
    unsigned long long inlen)
{

	SHA2_CTX ctx;

	SHA512Init(&ctx);
	SHA512Update(&ctx, in, inlen);
	SHA512Final(out, &ctx);
	തിരികെ 0;
}
#endif /* WITH_OPENSSL */

#define crypto_sign_ed25519_SECRETKEYBYTES 64U
#define crypto_sign_ed25519_PUBLICKEYBYTES 32U
#define crypto_sign_ed25519_SEEDBYTES 32U
#define crypto_sign_ed25519_BYTES 64U

പൂർണ്ണസംഖ്യ	crypto_sign_ed25519_detached(unsigned അക്ഷരം *, unsigned long long *,
    സ്ഥിരം unsigned അക്ഷരം *, unsigned long long, സ്ഥിരം unsigned അക്ഷരം *);
പൂർണ്ണസംഖ്യ	crypto_sign_ed25519_verify_detached(സ്ഥിരം unsigned അക്ഷരം *,
    സ്ഥിരം unsigned അക്ഷരം *, unsigned long long, സ്ഥിരം unsigned അക്ഷരം *);
പൂർണ്ണസംഖ്യ	crypto_sign_ed25519_keypair(unsigned അക്ഷരം *, unsigned അക്ഷരം *);
പൂർണ്ണസംഖ്യ	crypto_sign_ed25519_seed_keypair(unsigned അക്ഷരം *, unsigned അക്ഷരം *,
    സ്ഥിരം unsigned അക്ഷരം *);

#define crypto_kem_sntrup761_PUBLICKEYBYTES 1158
#define crypto_kem_sntrup761_SECRETKEYBYTES 1763
#define crypto_kem_sntrup761_CIPHERTEXTBYTES 1039
#define crypto_kem_sntrup761_BYTES 32

പൂർണ്ണസംഖ്യ	crypto_kem_sntrup761_enc(unsigned അക്ഷരം *cstr, unsigned അക്ഷരം *k,
    സ്ഥിരം unsigned അക്ഷരം *pk);
പൂർണ്ണസംഖ്യ	crypto_kem_sntrup761_dec(unsigned അക്ഷരം *k,
    സ്ഥിരം unsigned അക്ഷരം *cstr, സ്ഥിരം unsigned അക്ഷരം *sk);
പൂർണ്ണസംഖ്യ	crypto_kem_sntrup761_keypair(unsigned അക്ഷരം *pk, unsigned അക്ഷരം *sk);

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

പൂർണ്ണസംഖ്യ crypto_kem_mlkem768_keypair(uint8_t pk[crypto_kem_mlkem768_PUBLICKEYBYTES],
    uint8_t sk[crypto_kem_mlkem768_SECRETKEYBYTES]);
പൂർണ്ണസംഖ്യ crypto_kem_mlkem768_enc(uint8_t ct[crypto_kem_mlkem768_CIPHERTEXTBYTES],
    uint8_t shared_secret[crypto_kem_mlkem768_BYTES],
    സ്ഥിരം uint8_t pk[crypto_kem_mlkem768_PUBLICKEYBYTES]);
പൂർണ്ണസംഖ്യ crypto_kem_mlkem768_dec(uint8_t shared_secret[crypto_kem_mlkem768_BYTES],
    സ്ഥിരം uint8_t ct[crypto_kem_mlkem768_CIPHERTEXTBYTES],
    സ്ഥിരം uint8_t sk[crypto_kem_mlkem768_SECRETKEYBYTES]);
പൂർണ്ണസംഖ്യ crypto_kem_mlkem768_keypair_seeded(uint8_t pk[crypto_kem_mlkem768_PUBLICKEYBYTES],
    uint8_t sk[crypto_kem_mlkem768_SECRETKEYBYTES], സ്ഥിരം uint8_t seed[64]);
പൂർണ്ണസംഖ്യ crypto_kem_mlkem768_enc_seeded(uint8_t ct[crypto_kem_mlkem768_CIPHERTEXTBYTES],
    uint8_t shared_secret[crypto_kem_mlkem768_BYTES],
    സ്ഥിരം uint8_t pk[crypto_kem_mlkem768_PUBLICKEYBYTES],
    സ്ഥിരം uint8_t seed[32]);

/* ML-DSA-44 */
#define MLDSA44_PUBLICKEYBYTES 1312
#define MLDSA44_SECRETKEYBYTES 2560
#define MLDSA44_SIGBYTES 2420
#define MLDSA44_SEEDBYTES 32

പൂർണ്ണസംഖ്യ crypto_sign_mldsa44_keypair(uint8_t pk[MLDSA44_PUBLICKEYBYTES],
    uint8_t sk[MLDSA44_SECRETKEYBYTES]);
പൂർണ്ണസംഖ്യ crypto_sign_mldsa44(uint8_t sig[MLDSA44_SIGBYTES],
    സ്ഥിരം uint8_t *സന്ദേശം, size_t msglen,
    സ്ഥിരം uint8_t *ctx, size_t ctxlen,
    സ്ഥിരം uint8_t sk[MLDSA44_SECRETKEYBYTES]);
പൂർണ്ണസംഖ്യ crypto_sign_mldsa44_verify(സ്ഥിരം uint8_t sig[MLDSA44_SIGBYTES],
    സ്ഥിരം uint8_t *സന്ദേശം, size_t msglen,
    സ്ഥിരം uint8_t *ctx, size_t ctxlen,
    സ്ഥിരം uint8_t pk[MLDSA44_PUBLICKEYBYTES]);
പൂർണ്ണസംഖ്യ crypto_sign_mldsa44_keypair_seeded(uint8_t pk[MLDSA44_PUBLICKEYBYTES],
    uint8_t sk[MLDSA44_SECRETKEYBYTES], സ്ഥിരം uint8_t seed[MLDSA44_SEEDBYTES]);
പൂർണ്ണസംഖ്യ crypto_sign_mldsa44_seeded(uint8_t sig[MLDSA44_SIGBYTES],
    സ്ഥിരം uint8_t *സന്ദേശം, size_t msglen,
    സ്ഥിരം uint8_t *ctx, size_t ctxlen,
    സ്ഥിരം uint8_t sk[MLDSA44_SECRETKEYBYTES],
    സ്ഥിരം uint8_t seed[MLDSA44_SEEDBYTES]);

/* ML-DSA-65 */
#define MLDSA65_PUBLICKEYBYTES 1952
#define MLDSA65_SECRETKEYBYTES 4032
#define MLDSA65_SIGBYTES 3309
#define MLDSA65_SEEDBYTES 32

#എങ്കിൽ 0
പൂർണ്ണസംഖ്യ crypto_sign_mldsa65_keypair(uint8_t pk[MLDSA65_PUBLICKEYBYTES],
    uint8_t sk[MLDSA65_SECRETKEYBYTES]);
പൂർണ്ണസംഖ്യ crypto_sign_mldsa65(uint8_t sig[MLDSA65_SIGBYTES],
    സ്ഥിരം uint8_t *സന്ദേശം, size_t msglen,
    സ്ഥിരം uint8_t *ctx, size_t ctxlen,
    സ്ഥിരം uint8_t sk[MLDSA65_SECRETKEYBYTES]);
പൂർണ്ണസംഖ്യ crypto_sign_mldsa65_verify(സ്ഥിരം uint8_t sig[MLDSA65_SIGBYTES],
    സ്ഥിരം uint8_t *സന്ദേശം, size_t msglen,
    സ്ഥിരം uint8_t *ctx, size_t ctxlen,
    സ്ഥിരം uint8_t pk[MLDSA65_PUBLICKEYBYTES]);
പൂർണ്ണസംഖ്യ crypto_sign_mldsa65_keypair_seeded(uint8_t pk[MLDSA65_PUBLICKEYBYTES],
    uint8_t sk[MLDSA65_SECRETKEYBYTES], സ്ഥിരം uint8_t seed[MLDSA65_SEEDBYTES]);
പൂർണ്ണസംഖ്യ crypto_sign_mldsa65_seeded(uint8_t sig[MLDSA65_SIGBYTES],
    സ്ഥിരം uint8_t *സന്ദേശം, size_t msglen,
    സ്ഥിരം uint8_t *ctx, size_t ctxlen,
    സ്ഥിരം uint8_t sk[MLDSA65_SECRETKEYBYTES],
    സ്ഥിരം uint8_t seed[MLDSA65_SEEDBYTES]);
#endif

/* ML-DSA-87 */
#define MLDSA87_PUBLICKEYBYTES 2592
#define MLDSA87_SECRETKEYBYTES 4896
#define MLDSA87_SIGBYTES 4627
#define MLDSA87_SEEDBYTES 32

പൂർണ്ണസംഖ്യ crypto_sign_mldsa87_keypair(uint8_t pk[MLDSA87_PUBLICKEYBYTES],
    uint8_t sk[MLDSA87_SECRETKEYBYTES]);
പൂർണ്ണസംഖ്യ crypto_sign_mldsa87(uint8_t sig[MLDSA87_SIGBYTES],
    സ്ഥിരം uint8_t *സന്ദേശം, size_t msglen,
    സ്ഥിരം uint8_t *ctx, size_t ctxlen,
    സ്ഥിരം uint8_t sk[MLDSA87_SECRETKEYBYTES]);
പൂർണ്ണസംഖ്യ crypto_sign_mldsa87_verify(സ്ഥിരം uint8_t sig[MLDSA87_SIGBYTES],
    സ്ഥിരം uint8_t *സന്ദേശം, size_t msglen,
    സ്ഥിരം uint8_t *ctx, size_t ctxlen,
    സ്ഥിരം uint8_t pk[MLDSA87_PUBLICKEYBYTES]);
പൂർണ്ണസംഖ്യ crypto_sign_mldsa87_keypair_seeded(uint8_t pk[MLDSA87_PUBLICKEYBYTES],
    uint8_t sk[MLDSA87_SECRETKEYBYTES], സ്ഥിരം uint8_t seed[MLDSA87_SEEDBYTES]);
പൂർണ്ണസംഖ്യ crypto_sign_mldsa87_seeded(uint8_t sig[MLDSA87_SIGBYTES],
    സ്ഥിരം uint8_t *സന്ദേശം, size_t msglen,
    സ്ഥിരം uint8_t *ctx, size_t ctxlen,
    സ്ഥിരം uint8_t sk[MLDSA87_SECRETKEYBYTES],
    സ്ഥിരം uint8_t seed[MLDSA87_SEEDBYTES]);

/* MLDSA44-Ed25519-SHA512 */
#define MLDSA44_ED25519_PK_SZ (MLDSA44_PUBLICKEYBYTES + crypto_sign_ed25519_PUBLICKEYBYTES)
#define MLDSA44_ED25519_SK_SZ (MLDSA44_SEEDBYTES + crypto_sign_ed25519_SEEDBYTES)
#define MLDSA44_ED25519_SIG_SZ (MLDSA44_SIGBYTES + crypto_sign_ed25519_BYTES)

പൂർണ്ണസംഖ്യ crypto_sign_mldsa44_ed25519_keygen(uint8_t pk[MLDSA44_ED25519_PK_SZ],
    uint8_t sk[MLDSA44_ED25519_SK_SZ]);
പൂർണ്ണസംഖ്യ crypto_sign_mldsa44_ed25519_keygen_seeded(uint8_t pk[MLDSA44_ED25519_PK_SZ],
    uint8_t sk[MLDSA44_ED25519_SK_SZ],
    സ്ഥിരം uint8_t mldsa_seed[MLDSA44_SEEDBYTES],
    സ്ഥിരം uint8_t ed25519_seed[crypto_sign_ed25519_SEEDBYTES]);
പൂർണ്ണസംഖ്യ crypto_sign_mldsa44_ed25519_sign(uint8_t sig[MLDSA44_ED25519_SIG_SZ],
    സ്ഥിരം uint8_t *സന്ദേശം, size_t msglen,
    സ്ഥിരം uint8_t *ctx, size_t ctxlen,
    സ്ഥിരം uint8_t sk[MLDSA44_ED25519_SK_SZ]);
പൂർണ്ണസംഖ്യ crypto_sign_mldsa44_ed25519_verify(സ്ഥിരം uint8_t sig[MLDSA44_ED25519_SIG_SZ],
    സ്ഥിരം uint8_t *സന്ദേശം, size_t msglen,
    സ്ഥിരം uint8_t *ctx, size_t ctxlen,
    സ്ഥിരം uint8_t pk[MLDSA44_ED25519_PK_SZ]);

/* Utility */
ശൂന്യം sha3_256(uint8_t digest[32], സ്ഥിരം uint8_t *data, size_t len);
ശൂന്യം sha3_512(uint8_t digest[64], സ്ഥിരം uint8_t *data, size_t len);

#endif /* crypto_api_h */
