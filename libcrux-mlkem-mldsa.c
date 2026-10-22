/* $OpenBSD: libcrux-mlkem-mldsa.c,v 1.1 2026/06/14 03:59:34 djm Exp $ */
/*
 * Copyright (c) 2026 Damien Miller <djm@mindrot.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಯದಿ defined(USE_MLDSA) || defined(USE_MLKEM768X25519)

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <stdint.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <stdbool.h>
#ಅನ್ತರ್ಭಾವ <string.h>

#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "crypto_api.h"
#ಅನ್ತರ್ಭಾವ "libcrux_internal.h"

/* ML-KEM 768 */

ಪೂರ್ಣಾಙ್ಕ
crypto_kem_mlkem768_keypair(uint8_t pk[crypto_kem_mlkem768_PUBLICKEYBYTES],
    uint8_t sk[crypto_kem_mlkem768_SECRETKEYBYTES])
{
	uint8_t rnd[crypto_kem_mlkem768_KEYPAIRSEEDBYTES];
	ಪೂರ್ಣಾಙ್ಕ r;

	arc4random_buf(rnd, ಪರಿಮಾಣ(rnd));
	r = crypto_kem_mlkem768_keypair_seeded(pk, sk, rnd);
	explicit_bzero(rnd, ಪರಿಮಾಣ(rnd));
	ಪ್ರತ್ಯಾಗಮ r;
}

ಪೂರ್ಣಾಙ್ಕ
crypto_kem_mlkem768_keypair_seeded(uint8_t pk[crypto_kem_mlkem768_PUBLICKEYBYTES],
    uint8_t sk[crypto_kem_mlkem768_SECRETKEYBYTES],
    ಧ್ರುವ uint8_t seed[crypto_kem_mlkem768_KEYPAIRSEEDBYTES])
{
	libcrux_mlkem768_keypair keypair;
	libcrux_mlkem768_keypair_rnd rnd;

	memcpy(rnd.data, seed, ಪರಿಮಾಣ(rnd.data));
	keypair = libcrux_ml_kem_mlkem768_portable_generate_ಕೀಲಿ_pair(rnd);
	memcpy(pk, keypair.pk.data, crypto_kem_mlkem768_PUBLICKEYBYTES);
	memcpy(sk, keypair.sk.data, crypto_kem_mlkem768_SECRETKEYBYTES);

	explicit_bzero(&keypair, ಪರಿಮಾಣ(keypair));
	explicit_bzero(&rnd, ಪರಿಮಾಣ(rnd));
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಪೂರ್ಣಾಙ್ಕ
crypto_kem_mlkem768_enc(uint8_t ct[crypto_kem_mlkem768_CIPHERTEXTBYTES],
    uint8_t shared_secret[crypto_kem_mlkem768_BYTES],
    ಧ್ರುವ uint8_t pk[crypto_kem_mlkem768_PUBLICKEYBYTES])
{
	uint8_t rnd[crypto_kem_mlkem768_ENCSEEDBYTES];
	ಪೂರ್ಣಾಙ್ಕ r;

	arc4random_buf(rnd, ಪರಿಮಾಣ(rnd));
	r = crypto_kem_mlkem768_enc_seeded(ct, shared_secret, pk, rnd);
	explicit_bzero(rnd, ಪರಿಮಾಣ(rnd));
	ಪ್ರತ್ಯಾಗಮ r;
}

ಪೂರ್ಣಾಙ್ಕ
crypto_kem_mlkem768_enc_seeded(uint8_t ct[crypto_kem_mlkem768_CIPHERTEXTBYTES],
    uint8_t shared_secret[crypto_kem_mlkem768_BYTES],
    ಧ್ರುವ uint8_t pk[crypto_kem_mlkem768_PUBLICKEYBYTES],
    ಧ್ರುವ uint8_t seed[crypto_kem_mlkem768_ENCSEEDBYTES])
{
	libcrux_mlkem768_enc_result enc;
	libcrux_mlkem768_pk pk_internal;
	libcrux_mlkem768_enc_rnd rnd;

	memcpy(pk_internal.data, pk, crypto_kem_mlkem768_PUBLICKEYBYTES);
	ಯದಿ (!libcrux_ml_kem_mlkem768_portable_validate_public_ಕೀಲಿ(&pk_internal))
		ಪ್ರತ್ಯಾಗಮ -1;
	memcpy(rnd.data, seed, ಪರಿಮಾಣ(rnd.data));
	enc = libcrux_ml_kem_mlkem768_portable_encapsulate(&pk_internal, rnd);
	memcpy(ct, enc.fst.data, crypto_kem_mlkem768_CIPHERTEXTBYTES);
	memcpy(shared_secret, enc.snd.data, crypto_kem_mlkem768_BYTES);

	explicit_bzero(&enc, ಪರಿಮಾಣ(enc));
	explicit_bzero(&rnd, ಪರಿಮಾಣ(rnd));
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಪೂರ್ಣಾಙ್ಕ
crypto_kem_mlkem768_dec(uint8_t shared_secret[crypto_kem_mlkem768_BYTES],
    ಧ್ರುವ uint8_t ct[crypto_kem_mlkem768_CIPHERTEXTBYTES],
    ಧ್ರುವ uint8_t sk[crypto_kem_mlkem768_SECRETKEYBYTES])
{
	libcrux_mlkem768_sk sk_internal;
	libcrux_mlkem768_ciphertext ct_internal;
	libcrux_mlkem768_dec_result shared_secret_internal;

	memcpy(sk_internal.data, sk, crypto_kem_mlkem768_SECRETKEYBYTES);
	memcpy(ct_internal.data, ct, crypto_kem_mlkem768_CIPHERTEXTBYTES);
	shared_secret_internal = libcrux_ml_kem_mlkem768_portable_decapsulate(
	    &sk_internal, &ct_internal);
	memcpy(shared_secret, shared_secret_internal.data,
	    crypto_kem_mlkem768_BYTES);

	explicit_bzero(&sk_internal, ಪರಿಮಾಣ(sk_internal));
	explicit_bzero(&shared_secret_internal, ಪರಿಮಾಣ(shared_secret_internal));
	ಪ್ರತ್ಯಾಗಮ 0;
}

/* ML-DSA 44 */

ಪೂರ್ಣಾಙ್ಕ
crypto_sign_mldsa44_keypair(uint8_t pk[MLDSA44_PUBLICKEYBYTES],
    uint8_t sk[MLDSA44_SECRETKEYBYTES])
{
	uint8_t rnd[MLDSA44_SEEDBYTES];
	ಪೂರ್ಣಾಙ್ಕ r;

	arc4random_buf(rnd, ಪರಿಮಾಣ(rnd));
	r = crypto_sign_mldsa44_keypair_seeded(pk, sk, rnd);
	explicit_bzero(rnd, ಪರಿಮಾಣ(rnd));
	ಪ್ರತ್ಯಾಗಮ r;
}

ಪೂರ್ಣಾಙ್ಕ
crypto_sign_mldsa44_keypair_seeded(uint8_t pk[MLDSA44_PUBLICKEYBYTES],
    uint8_t sk[MLDSA44_SECRETKEYBYTES], ಧ್ರುವ uint8_t seed[MLDSA44_SEEDBYTES])
{
	libcrux_mldsa44_keypair_rnd rnd;
	libcrux_mldsa44_keypair keypair;

	memcpy(rnd.data, seed, ಪರಿಮಾಣ(rnd.data));
	keypair = libcrux_ml_dsa_ml_dsa_44_portable_generate_ಕೀಲಿ_pair(rnd);
	memcpy(pk, keypair.verification_ಕೀಲಿ.data, MLDSA44_PUBLICKEYBYTES);
	memcpy(sk, keypair.signing_ಕೀಲಿ.data, MLDSA44_SECRETKEYBYTES);

	explicit_bzero(&keypair, ಪರಿಮಾಣ(keypair));
	explicit_bzero(&rnd, ಪರಿಮಾಣ(rnd));
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಪೂರ್ಣಾಙ್ಕ
crypto_sign_mldsa44(uint8_t sig[MLDSA44_SIGBYTES],
    ಧ್ರುವ uint8_t *ಸಂದೇಶ, size_t msglen,
    ಧ್ರುವ uint8_t *ctx, size_t ctxlen,
    ಧ್ರುವ uint8_t sk[MLDSA44_SECRETKEYBYTES])
{
	uint8_t rnd[MLDSA44_SEEDBYTES];
	ಪೂರ್ಣಾಙ್ಕ r;

	arc4random_buf(rnd, ಪರಿಮಾಣ(rnd));
	r = crypto_sign_mldsa44_seeded(sig, ಸಂದೇಶ, msglen, ctx, ctxlen, sk, rnd);
	explicit_bzero(rnd, ಪರಿಮಾಣ(rnd));
	ಪ್ರತ್ಯಾಗಮ r;
}

ಪೂರ್ಣಾಙ್ಕ
crypto_sign_mldsa44_seeded(uint8_t sig[MLDSA44_SIGBYTES],
    ಧ್ರುವ uint8_t *ಸಂದೇಶ, size_t msglen,
    ಧ್ರುವ uint8_t *ctx, size_t ctxlen,
    ಧ್ರುವ uint8_t sk[MLDSA44_SECRETKEYBYTES],
    ಧ್ರುವ uint8_t seed[MLDSA44_SEEDBYTES])
{
	libcrux_mldsa44_sign_rnd rnd;
	libcrux_mldsa44_sk sk_internal;
	libcrux_mldsa44_message message = { ಸಂದೇಶ, msglen };
	libcrux_mldsa44_message context = { ctx, ctxlen };
	libcrux_mldsa44_sign_result res;
	ಪೂರ್ಣಾಙ್ಕ r = -1;

	memcpy(sk_internal.data, sk, MLDSA44_SECRETKEYBYTES);
	memcpy(rnd.data, seed, ಪರಿಮಾಣ(rnd.data));
	res = libcrux_ml_dsa_ml_dsa_44_portable_sign(&sk_internal,
	    message, context, rnd);
	ಯದಿ (res.tag == LIBCRUX_RESULT_OK) {
		memcpy(sig, res.val.case_Ok.data, MLDSA44_SIGBYTES);
		r = 0;
	}

	explicit_bzero(&sk_internal, ಪರಿಮಾಣ(sk_internal));
	explicit_bzero(&res, ಪರಿಮಾಣ(res));
	explicit_bzero(&rnd, ಪರಿಮಾಣ(rnd));
	ಪ್ರತ್ಯಾಗಮ r;
}

ಪೂರ್ಣಾಙ್ಕ
crypto_sign_mldsa44_verify(ಧ್ರುವ uint8_t sig[MLDSA44_SIGBYTES],
    ಧ್ರುವ uint8_t *ಸಂದೇಶ, size_t msglen,
    ಧ್ರುವ uint8_t *ctx, size_t ctxlen,
    ಧ್ರುವ uint8_t pk[MLDSA44_PUBLICKEYBYTES])
{
	libcrux_mldsa44_pk pk_internal;
	libcrux_mldsa44_signature sig_internal;
	libcrux_mldsa44_message message = { ಸಂದೇಶ, msglen };
	libcrux_mldsa44_message context = { ctx, ctxlen };
	libcrux_mldsa44_verify_result res;

	memcpy(pk_internal.data, pk, MLDSA44_PUBLICKEYBYTES);
	memcpy(sig_internal.data, sig, MLDSA44_SIGBYTES);
	res = libcrux_ml_dsa_ml_dsa_44_portable_verify(&pk_internal,
	    message, context, &sig_internal);

	ಪ್ರತ್ಯಾಗಮ (res.tag == LIBCRUX_RESULT_OK) ? 0 : -1;
}

/* ML-DSA 65 */

#ಯದಿ 0
ಪೂರ್ಣಾಙ್ಕ
crypto_sign_mldsa65_keypair(uint8_t pk[MLDSA65_PUBLICKEYBYTES],
    uint8_t sk[MLDSA65_SECRETKEYBYTES])
{
	uint8_t rnd[MLDSA65_SEEDBYTES];
	ಪೂರ್ಣಾಙ್ಕ r;

	arc4random_buf(rnd, ಪರಿಮಾಣ(rnd));
	r = crypto_sign_mldsa65_keypair_seeded(pk, sk, rnd);
	explicit_bzero(rnd, ಪರಿಮಾಣ(rnd));
	ಪ್ರತ್ಯಾಗಮ r;
}

ಪೂರ್ಣಾಙ್ಕ
crypto_sign_mldsa65_keypair_seeded(uint8_t pk[MLDSA65_PUBLICKEYBYTES],
    uint8_t sk[MLDSA65_SECRETKEYBYTES], ಧ್ರುವ uint8_t seed[MLDSA65_SEEDBYTES])
{
	libcrux_mldsa65_keypair_rnd rnd;
	libcrux_mldsa65_keypair keypair;

	memcpy(rnd.data, seed, ಪರಿಮಾಣ(rnd.data));
	keypair = libcrux_ml_dsa_ml_dsa_65_portable_generate_ಕೀಲಿ_pair(rnd);
	memcpy(pk, keypair.verification_ಕೀಲಿ.data, MLDSA65_PUBLICKEYBYTES);
	memcpy(sk, keypair.signing_ಕೀಲಿ.data, MLDSA65_SECRETKEYBYTES);

	explicit_bzero(&keypair, ಪರಿಮಾಣ(keypair));
	explicit_bzero(&rnd, ಪರಿಮಾಣ(rnd));
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಪೂರ್ಣಾಙ್ಕ
crypto_sign_mldsa65(uint8_t sig[MLDSA65_SIGBYTES],
    ಧ್ರುವ uint8_t *ಸಂದೇಶ, size_t msglen,
    ಧ್ರುವ uint8_t *ctx, size_t ctxlen,
    ಧ್ರುವ uint8_t sk[MLDSA65_SECRETKEYBYTES])
{
	uint8_t rnd[MLDSA65_SEEDBYTES];
	ಪೂರ್ಣಾಙ್ಕ r;

	arc4random_buf(rnd, ಪರಿಮಾಣ(rnd));
	r = crypto_sign_mldsa65_seeded(sig, ಸಂದೇಶ, msglen, ctx, ctxlen, sk, rnd);
	explicit_bzero(rnd, ಪರಿಮಾಣ(rnd));
	ಪ್ರತ್ಯಾಗಮ r;
}

ಪೂರ್ಣಾಙ್ಕ
crypto_sign_mldsa65_seeded(uint8_t sig[MLDSA65_SIGBYTES],
    ಧ್ರುವ uint8_t *ಸಂದೇಶ, size_t msglen,
    ಧ್ರುವ uint8_t *ctx, size_t ctxlen,
    ಧ್ರುವ uint8_t sk[MLDSA65_SECRETKEYBYTES],
    ಧ್ರುವ uint8_t seed[MLDSA65_SEEDBYTES])
{
	libcrux_mldsa65_sign_rnd rnd;
	libcrux_mldsa65_sk sk_internal;
	libcrux_mldsa65_message message = { ಸಂದೇಶ, msglen };
	libcrux_mldsa65_message context = { ctx, ctxlen };
	libcrux_mldsa65_sign_result res;
	ಪೂರ್ಣಾಙ್ಕ r = -1;

	memcpy(sk_internal.data, sk, MLDSA65_SECRETKEYBYTES);
	memcpy(rnd.data, seed, ಪರಿಮಾಣ(rnd.data));
	res = libcrux_ml_dsa_ml_dsa_65_portable_sign(&sk_internal,
	    message, context, rnd);
	ಯದಿ (res.tag == LIBCRUX_RESULT_OK) {
		memcpy(sig, res.val.case_Ok.data, MLDSA65_SIGBYTES);
		r = 0;
	}

	explicit_bzero(&sk_internal, ಪರಿಮಾಣ(sk_internal));
	explicit_bzero(&res, ಪರಿಮಾಣ(res));
	explicit_bzero(&rnd, ಪರಿಮಾಣ(rnd));
	ಪ್ರತ್ಯಾಗಮ r;
}

ಪೂರ್ಣಾಙ್ಕ
crypto_sign_mldsa65_verify(ಧ್ರುವ uint8_t sig[MLDSA65_SIGBYTES],
    ಧ್ರುವ uint8_t *ಸಂದೇಶ, size_t msglen,
    ಧ್ರುವ uint8_t *ctx, size_t ctxlen,
    ಧ್ರುವ uint8_t pk[MLDSA65_PUBLICKEYBYTES])
{
	libcrux_mldsa65_pk pk_internal;
	libcrux_mldsa65_signature sig_internal;
	libcrux_mldsa65_message message = { ಸಂದೇಶ, msglen };
	libcrux_mldsa65_message context = { ctx, ctxlen };
	libcrux_mldsa65_verify_result res;

	memcpy(pk_internal.data, pk, MLDSA65_PUBLICKEYBYTES);
	memcpy(sig_internal.data, sig, MLDSA65_SIGBYTES);
	res = libcrux_ml_dsa_ml_dsa_65_portable_verify(&pk_internal,
	    message, context, &sig_internal);

	ಪ್ರತ್ಯಾಗಮ (res.tag == LIBCRUX_RESULT_OK) ? 0 : -1;
}
#endif

/* ML-DSA 87 */

#ಯದಿ 0
ಪೂರ್ಣಾಙ್ಕ
crypto_sign_mldsa87_keypair(uint8_t pk[MLDSA87_PUBLICKEYBYTES],
    uint8_t sk[MLDSA87_SECRETKEYBYTES])
{
	uint8_t rnd[MLDSA87_SEEDBYTES];
	ಪೂರ್ಣಾಙ್ಕ r;

	arc4random_buf(rnd, ಪರಿಮಾಣ(rnd));
	r = crypto_sign_mldsa87_keypair_seeded(pk, sk, rnd);
	explicit_bzero(rnd, ಪರಿಮಾಣ(rnd));
	ಪ್ರತ್ಯಾಗಮ r;
}

ಪೂರ್ಣಾಙ್ಕ
crypto_sign_mldsa87_keypair_seeded(uint8_t pk[MLDSA87_PUBLICKEYBYTES],
    uint8_t sk[MLDSA87_SECRETKEYBYTES], ಧ್ರುವ uint8_t seed[MLDSA87_SEEDBYTES])
{
	libcrux_mldsa87_keypair_rnd rnd;
	libcrux_mldsa87_keypair keypair;

	memcpy(rnd.data, seed, ಪರಿಮಾಣ(rnd.data));
	keypair = libcrux_ml_dsa_ml_dsa_87_portable_generate_ಕೀಲಿ_pair(rnd);
	memcpy(pk, keypair.verification_ಕೀಲಿ.data, MLDSA87_PUBLICKEYBYTES);
	memcpy(sk, keypair.signing_ಕೀಲಿ.data, MLDSA87_SECRETKEYBYTES);

	explicit_bzero(&keypair, ಪರಿಮಾಣ(keypair));
	explicit_bzero(&rnd, ಪರಿಮಾಣ(rnd));
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಪೂರ್ಣಾಙ್ಕ
crypto_sign_mldsa87(uint8_t sig[MLDSA87_SIGBYTES],
    ಧ್ರುವ uint8_t *ಸಂದೇಶ, size_t msglen,
    ಧ್ರುವ uint8_t *ctx, size_t ctxlen,
    ಧ್ರುವ uint8_t sk[MLDSA87_SECRETKEYBYTES])
{
	uint8_t rnd[MLDSA87_SEEDBYTES];
	ಪೂರ್ಣಾಙ್ಕ r;

	arc4random_buf(rnd, ಪರಿಮಾಣ(rnd));
	r = crypto_sign_mldsa87_seeded(sig, ಸಂದೇಶ, msglen, ctx, ctxlen, sk, rnd);
	explicit_bzero(rnd, ಪರಿಮಾಣ(rnd));
	ಪ್ರತ್ಯಾಗಮ r;
}

ಪೂರ್ಣಾಙ್ಕ
crypto_sign_mldsa87_seeded(uint8_t sig[MLDSA87_SIGBYTES],
    ಧ್ರುವ uint8_t *ಸಂದೇಶ, size_t msglen,
    ಧ್ರುವ uint8_t *ctx, size_t ctxlen,
    ಧ್ರುವ uint8_t sk[MLDSA87_SECRETKEYBYTES],
    ಧ್ರುವ uint8_t seed[MLDSA87_SEEDBYTES])
{
	libcrux_mldsa87_sign_rnd rnd;
	libcrux_mldsa87_sk sk_internal;
	libcrux_mldsa87_message message = { ಸಂದೇಶ, msglen };
	libcrux_mldsa87_message context = { ctx, ctxlen };
	libcrux_mldsa87_sign_result res;
	ಪೂರ್ಣಾಙ್ಕ r = -1;

	memcpy(sk_internal.data, sk, MLDSA87_SECRETKEYBYTES);
	memcpy(rnd.data, seed, ಪರಿಮಾಣ(rnd.data));
	res = libcrux_ml_dsa_ml_dsa_87_portable_sign(&sk_internal,
	    message, context, rnd);
	ಯದಿ (res.tag == LIBCRUX_RESULT_OK) {
		memcpy(sig, res.val.case_Ok.data, MLDSA87_SIGBYTES);
		r = 0;
	}

	explicit_bzero(&sk_internal, ಪರಿಮಾಣ(sk_internal));
	explicit_bzero(&res, ಪರಿಮಾಣ(res));
	explicit_bzero(&rnd, ಪರಿಮಾಣ(rnd));
	ಪ್ರತ್ಯಾಗಮ r;
}

ಪೂರ್ಣಾಙ್ಕ
crypto_sign_mldsa87_verify(ಧ್ರುವ uint8_t sig[MLDSA87_SIGBYTES],
    ಧ್ರುವ uint8_t *ಸಂದೇಶ, size_t msglen,
    ಧ್ರುವ uint8_t *ctx, size_t ctxlen,
    ಧ್ರುವ uint8_t pk[MLDSA87_PUBLICKEYBYTES])
{
	libcrux_mldsa87_pk pk_internal;
	libcrux_mldsa87_signature sig_internal;
	libcrux_mldsa87_message message = { ಸಂದೇಶ, msglen };
	libcrux_mldsa87_message context = { ctx, ctxlen };
	libcrux_mldsa87_verify_result res;

	memcpy(pk_internal.data, pk, MLDSA87_PUBLICKEYBYTES);
	memcpy(sig_internal.data, sig, MLDSA87_SIGBYTES);
	res = libcrux_ml_dsa_ml_dsa_87_portable_verify(&pk_internal,
	    message, context, &sig_internal);

	ಪ್ರತ್ಯಾಗಮ (res.tag == LIBCRUX_RESULT_OK) ? 0 : -1;
}
#endif

ಶೂನ್ಯ
sha3_256(uint8_t digest[32], ಧ್ರುವ uint8_t *data, size_t len)
{
	Eurydice_borrow_slice_u8 ಒಳಹರಿವು = { data, len };
	Eurydice_mut_borrow_slice_u8 output = { digest, 32 };
	libcrux_sha3_portable_sha256(output, ಒಳಹರಿವು);
}

ಶೂನ್ಯ
sha3_512(uint8_t digest[64], ಧ್ರುವ uint8_t *data, size_t len)
{
	Eurydice_borrow_slice_u8 ಒಳಹರಿವು = { data, len };
	Eurydice_mut_borrow_slice_u8 output = { digest, 64 };
	libcrux_sha3_portable_sha512(output, ಒಳಹರಿವು);
}
#endif /* defined(USE_MLDSA) || defined(USE_MLKEM768X25519) */
