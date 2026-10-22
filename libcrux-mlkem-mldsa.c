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

#अन्तर्भाव "includes.h"

#यदि defined(USE_MLDSA) || defined(USE_MLKEM768X25519)

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <stdint.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <stdbool.h>
#अन्तर्भाव <string.h>

#अन्तर्भाव "log.h"
#अन्तर्भाव "crypto_api.h"
#अन्तर्भाव "libcrux_internal.h"

/* ML-KEM 768 */

पूर्णाङ्क
crypto_kem_mlkem768_keypair(uint8_t pk[crypto_kem_mlkem768_PUBLICKEYBYTES],
    uint8_t sk[crypto_kem_mlkem768_SECRETKEYBYTES])
{
	uint8_t rnd[crypto_kem_mlkem768_KEYPAIRSEEDBYTES];
	पूर्णाङ्क r;

	arc4random_buf(rnd, परिमाण(rnd));
	r = crypto_kem_mlkem768_keypair_seeded(pk, sk, rnd);
	explicit_bzero(rnd, परिमाण(rnd));
	प्रत्यागम r;
}

पूर्णाङ्क
crypto_kem_mlkem768_keypair_seeded(uint8_t pk[crypto_kem_mlkem768_PUBLICKEYBYTES],
    uint8_t sk[crypto_kem_mlkem768_SECRETKEYBYTES],
    ध्रुव uint8_t बीजम्[crypto_kem_mlkem768_KEYPAIRSEEDBYTES])
{
	libcrux_mlkem768_keypair keypair;
	libcrux_mlkem768_keypair_rnd rnd;

	स्मृतिं_प्रतिलिख(rnd.दत्त, बीजम्, परिमाण(rnd.दत्त));
	keypair = libcrux_ml_kem_mlkem768_portable_generate_कुञ्चिका_pair(rnd);
	स्मृतिं_प्रतिलिख(pk, keypair.pk.दत्त, crypto_kem_mlkem768_PUBLICKEYBYTES);
	स्मृतिं_प्रतिलिख(sk, keypair.sk.दत्त, crypto_kem_mlkem768_SECRETKEYBYTES);

	explicit_bzero(&keypair, परिमाण(keypair));
	explicit_bzero(&rnd, परिमाण(rnd));
	प्रत्यागम 0;
}

पूर्णाङ्क
crypto_kem_mlkem768_enc(uint8_t ct[crypto_kem_mlkem768_CIPHERTEXTBYTES],
    uint8_t shared_secret[crypto_kem_mlkem768_अष्टकानि],
    ध्रुव uint8_t pk[crypto_kem_mlkem768_PUBLICKEYBYTES])
{
	uint8_t rnd[crypto_kem_mlkem768_ENCSEEDBYTES];
	पूर्णाङ्क r;

	arc4random_buf(rnd, परिमाण(rnd));
	r = crypto_kem_mlkem768_enc_seeded(ct, shared_secret, pk, rnd);
	explicit_bzero(rnd, परिमाण(rnd));
	प्रत्यागम r;
}

पूर्णाङ्क
crypto_kem_mlkem768_enc_seeded(uint8_t ct[crypto_kem_mlkem768_CIPHERTEXTBYTES],
    uint8_t shared_secret[crypto_kem_mlkem768_अष्टकानि],
    ध्रुव uint8_t pk[crypto_kem_mlkem768_PUBLICKEYBYTES],
    ध्रुव uint8_t बीजम्[crypto_kem_mlkem768_ENCSEEDBYTES])
{
	libcrux_mlkem768_enc_परिणाम enc;
	libcrux_mlkem768_pk pk_आन्तरिकम्;
	libcrux_mlkem768_enc_rnd rnd;

	स्मृतिं_प्रतिलिख(pk_आन्तरिकम्.दत्त, pk, crypto_kem_mlkem768_PUBLICKEYBYTES);
	यदि (!libcrux_ml_kem_mlkem768_portable_validate_लौकिकम्_कुञ्चिका(&pk_आन्तरिकम्))
		प्रत्यागम -1;
	स्मृतिं_प्रतिलिख(rnd.दत्त, बीजम्, परिमाण(rnd.दत्त));
	enc = libcrux_ml_kem_mlkem768_portable_encapsulate(&pk_आन्तरिकम्, rnd);
	स्मृतिं_प्रतिलिख(ct, enc.fst.दत्त, crypto_kem_mlkem768_CIPHERTEXTBYTES);
	स्मृतिं_प्रतिलिख(shared_secret, enc.snd.दत्त, crypto_kem_mlkem768_अष्टकानि);

	explicit_bzero(&enc, परिमाण(enc));
	explicit_bzero(&rnd, परिमाण(rnd));
	प्रत्यागम 0;
}

पूर्णाङ्क
crypto_kem_mlkem768_dec(uint8_t shared_secret[crypto_kem_mlkem768_अष्टकानि],
    ध्रुव uint8_t ct[crypto_kem_mlkem768_CIPHERTEXTBYTES],
    ध्रुव uint8_t sk[crypto_kem_mlkem768_SECRETKEYBYTES])
{
	libcrux_mlkem768_sk sk_आन्तरिकम्;
	libcrux_mlkem768_ciphertext ct_आन्तरिकम्;
	libcrux_mlkem768_dec_परिणाम shared_secret_आन्तरिकम्;

	स्मृतिं_प्रतिलिख(sk_आन्तरिकम्.दत्त, sk, crypto_kem_mlkem768_SECRETKEYBYTES);
	स्मृतिं_प्रतिलिख(ct_आन्तरिकम्.दत्त, ct, crypto_kem_mlkem768_CIPHERTEXTBYTES);
	shared_secret_आन्तरिकम् = libcrux_ml_kem_mlkem768_portable_decapsulate(
	    &sk_आन्तरिकम्, &ct_आन्तरिकम्);
	स्मृतिं_प्रतिलिख(shared_secret, shared_secret_आन्तरिकम्.दत्त,
	    crypto_kem_mlkem768_अष्टकानि);

	explicit_bzero(&sk_आन्तरिकम्, परिमाण(sk_आन्तरिकम्));
	explicit_bzero(&shared_secret_आन्तरिकम्, परिमाण(shared_secret_आन्तरिकम्));
	प्रत्यागम 0;
}

/* ML-DSA 44 */

पूर्णाङ्क
crypto_sign_mldsa44_keypair(uint8_t pk[MLDSA44_PUBLICKEYBYTES],
    uint8_t sk[MLDSA44_SECRETKEYBYTES])
{
	uint8_t rnd[MLDSA44_SEEDBYTES];
	पूर्णाङ्क r;

	arc4random_buf(rnd, परिमाण(rnd));
	r = crypto_sign_mldsa44_keypair_seeded(pk, sk, rnd);
	explicit_bzero(rnd, परिमाण(rnd));
	प्रत्यागम r;
}

पूर्णाङ्क
crypto_sign_mldsa44_keypair_seeded(uint8_t pk[MLDSA44_PUBLICKEYBYTES],
    uint8_t sk[MLDSA44_SECRETKEYBYTES], ध्रुव uint8_t बीजम्[MLDSA44_SEEDBYTES])
{
	libcrux_mldsa44_keypair_rnd rnd;
	libcrux_mldsa44_keypair keypair;

	स्मृतिं_प्रतिलिख(rnd.दत्त, बीजम्, परिमाण(rnd.दत्त));
	keypair = libcrux_ml_dsa_ml_dsa_44_portable_generate_कुञ्चिका_pair(rnd);
	स्मृतिं_प्रतिलिख(pk, keypair.verification_कुञ्चिका.दत्त, MLDSA44_PUBLICKEYBYTES);
	स्मृतिं_प्रतिलिख(sk, keypair.signing_कुञ्चिका.दत्त, MLDSA44_SECRETKEYBYTES);

	explicit_bzero(&keypair, परिमाण(keypair));
	explicit_bzero(&rnd, परिमाण(rnd));
	प्रत्यागम 0;
}

पूर्णाङ्क
crypto_sign_mldsa44(uint8_t sig[MLDSA44_SIGBYTES],
    ध्रुव uint8_t *सन्देशः, आकार_t msglen,
    ध्रुव uint8_t *ctx, आकार_t ctxlen,
    ध्रुव uint8_t sk[MLDSA44_SECRETKEYBYTES])
{
	uint8_t rnd[MLDSA44_SEEDBYTES];
	पूर्णाङ्क r;

	arc4random_buf(rnd, परिमाण(rnd));
	r = crypto_sign_mldsa44_seeded(sig, सन्देशः, msglen, ctx, ctxlen, sk, rnd);
	explicit_bzero(rnd, परिमाण(rnd));
	प्रत्यागम r;
}

पूर्णाङ्क
crypto_sign_mldsa44_seeded(uint8_t sig[MLDSA44_SIGBYTES],
    ध्रुव uint8_t *सन्देशः, आकार_t msglen,
    ध्रुव uint8_t *ctx, आकार_t ctxlen,
    ध्रुव uint8_t sk[MLDSA44_SECRETKEYBYTES],
    ध्रुव uint8_t बीजम्[MLDSA44_SEEDBYTES])
{
	libcrux_mldsa44_sign_rnd rnd;
	libcrux_mldsa44_sk sk_आन्तरिकम्;
	libcrux_mldsa44_सन्देशः सन्देशः_2 = { सन्देशः, msglen };
	libcrux_mldsa44_सन्देशः context = { ctx, ctxlen };
	libcrux_mldsa44_sign_परिणाम res;
	पूर्णाङ्क r = -1;

	स्मृतिं_प्रतिलिख(sk_आन्तरिकम्.दत्त, sk, MLDSA44_SECRETKEYBYTES);
	स्मृतिं_प्रतिलिख(rnd.दत्त, बीजम्, परिमाण(rnd.दत्त));
	res = libcrux_ml_dsa_ml_dsa_44_portable_sign(&sk_आन्तरिकम्,
	    सन्देशः_2, context, rnd);
	यदि (res.चिह्नकम् == LIBCRUX_परिणाम_OK) {
		स्मृतिं_प्रतिलिख(sig, res.val.case_Ok.दत्त, MLDSA44_SIGBYTES);
		r = 0;
	}

	explicit_bzero(&sk_आन्तरिकम्, परिमाण(sk_आन्तरिकम्));
	explicit_bzero(&res, परिमाण(res));
	explicit_bzero(&rnd, परिमाण(rnd));
	प्रत्यागम r;
}

पूर्णाङ्क
crypto_sign_mldsa44_verify(ध्रुव uint8_t sig[MLDSA44_SIGBYTES],
    ध्रुव uint8_t *सन्देशः, आकार_t msglen,
    ध्रुव uint8_t *ctx, आकार_t ctxlen,
    ध्रुव uint8_t pk[MLDSA44_PUBLICKEYBYTES])
{
	libcrux_mldsa44_pk pk_आन्तरिकम्;
	libcrux_mldsa44_signature sig_आन्तरिकम्;
	libcrux_mldsa44_सन्देशः सन्देशः_2 = { सन्देशः, msglen };
	libcrux_mldsa44_सन्देशः context = { ctx, ctxlen };
	libcrux_mldsa44_verify_परिणाम res;

	स्मृतिं_प्रतिलिख(pk_आन्तरिकम्.दत्त, pk, MLDSA44_PUBLICKEYBYTES);
	स्मृतिं_प्रतिलिख(sig_आन्तरिकम्.दत्त, sig, MLDSA44_SIGBYTES);
	res = libcrux_ml_dsa_ml_dsa_44_portable_verify(&pk_आन्तरिकम्,
	    सन्देशः_2, context, &sig_आन्तरिकम्);

	प्रत्यागम (res.चिह्नकम् == LIBCRUX_परिणाम_OK) ? 0 : -1;
}

/* ML-DSA 65 */

#यदि 0
पूर्णाङ्क
crypto_sign_mldsa65_keypair(uint8_t pk[MLDSA65_PUBLICKEYBYTES],
    uint8_t sk[MLDSA65_SECRETKEYBYTES])
{
	uint8_t rnd[MLDSA65_SEEDBYTES];
	पूर्णाङ्क r;

	arc4random_buf(rnd, परिमाण(rnd));
	r = crypto_sign_mldsa65_keypair_seeded(pk, sk, rnd);
	explicit_bzero(rnd, परिमाण(rnd));
	प्रत्यागम r;
}

पूर्णाङ्क
crypto_sign_mldsa65_keypair_seeded(uint8_t pk[MLDSA65_PUBLICKEYBYTES],
    uint8_t sk[MLDSA65_SECRETKEYBYTES], ध्रुव uint8_t बीजम्[MLDSA65_SEEDBYTES])
{
	libcrux_mldsa65_keypair_rnd rnd;
	libcrux_mldsa65_keypair keypair;

	स्मृतिं_प्रतिलिख(rnd.दत्त, बीजम्, परिमाण(rnd.दत्त));
	keypair = libcrux_ml_dsa_ml_dsa_65_portable_generate_कुञ्चिका_pair(rnd);
	स्मृतिं_प्रतिलिख(pk, keypair.verification_कुञ्चिका.दत्त, MLDSA65_PUBLICKEYBYTES);
	स्मृतिं_प्रतिलिख(sk, keypair.signing_कुञ्चिका.दत्त, MLDSA65_SECRETKEYBYTES);

	explicit_bzero(&keypair, परिमाण(keypair));
	explicit_bzero(&rnd, परिमाण(rnd));
	प्रत्यागम 0;
}

पूर्णाङ्क
crypto_sign_mldsa65(uint8_t sig[MLDSA65_SIGBYTES],
    ध्रुव uint8_t *सन्देशः, आकार_t msglen,
    ध्रुव uint8_t *ctx, आकार_t ctxlen,
    ध्रुव uint8_t sk[MLDSA65_SECRETKEYBYTES])
{
	uint8_t rnd[MLDSA65_SEEDBYTES];
	पूर्णाङ्क r;

	arc4random_buf(rnd, परिमाण(rnd));
	r = crypto_sign_mldsa65_seeded(sig, सन्देशः, msglen, ctx, ctxlen, sk, rnd);
	explicit_bzero(rnd, परिमाण(rnd));
	प्रत्यागम r;
}

पूर्णाङ्क
crypto_sign_mldsa65_seeded(uint8_t sig[MLDSA65_SIGBYTES],
    ध्रुव uint8_t *सन्देशः, आकार_t msglen,
    ध्रुव uint8_t *ctx, आकार_t ctxlen,
    ध्रुव uint8_t sk[MLDSA65_SECRETKEYBYTES],
    ध्रुव uint8_t बीजम्[MLDSA65_SEEDBYTES])
{
	libcrux_mldsa65_sign_rnd rnd;
	libcrux_mldsa65_sk sk_आन्तरिकम्;
	libcrux_mldsa65_सन्देशः सन्देशः_2 = { सन्देशः, msglen };
	libcrux_mldsa65_सन्देशः context = { ctx, ctxlen };
	libcrux_mldsa65_sign_परिणाम res;
	पूर्णाङ्क r = -1;

	स्मृतिं_प्रतिलिख(sk_आन्तरिकम्.दत्त, sk, MLDSA65_SECRETKEYBYTES);
	स्मृतिं_प्रतिलिख(rnd.दत्त, बीजम्, परिमाण(rnd.दत्त));
	res = libcrux_ml_dsa_ml_dsa_65_portable_sign(&sk_आन्तरिकम्,
	    सन्देशः_2, context, rnd);
	यदि (res.चिह्नकम् == LIBCRUX_परिणाम_OK) {
		स्मृतिं_प्रतिलिख(sig, res.val.case_Ok.दत्त, MLDSA65_SIGBYTES);
		r = 0;
	}

	explicit_bzero(&sk_आन्तरिकम्, परिमाण(sk_आन्तरिकम्));
	explicit_bzero(&res, परिमाण(res));
	explicit_bzero(&rnd, परिमाण(rnd));
	प्रत्यागम r;
}

पूर्णाङ्क
crypto_sign_mldsa65_verify(ध्रुव uint8_t sig[MLDSA65_SIGBYTES],
    ध्रुव uint8_t *सन्देशः, आकार_t msglen,
    ध्रुव uint8_t *ctx, आकार_t ctxlen,
    ध्रुव uint8_t pk[MLDSA65_PUBLICKEYBYTES])
{
	libcrux_mldsa65_pk pk_आन्तरिकम्;
	libcrux_mldsa65_signature sig_आन्तरिकम्;
	libcrux_mldsa65_सन्देशः सन्देशः_2 = { सन्देशः, msglen };
	libcrux_mldsa65_सन्देशः context = { ctx, ctxlen };
	libcrux_mldsa65_verify_परिणाम res;

	स्मृतिं_प्रतिलिख(pk_आन्तरिकम्.दत्त, pk, MLDSA65_PUBLICKEYBYTES);
	स्मृतिं_प्रतिलिख(sig_आन्तरिकम्.दत्त, sig, MLDSA65_SIGBYTES);
	res = libcrux_ml_dsa_ml_dsa_65_portable_verify(&pk_आन्तरिकम्,
	    सन्देशः_2, context, &sig_आन्तरिकम्);

	प्रत्यागम (res.चिह्नकम् == LIBCRUX_परिणाम_OK) ? 0 : -1;
}
#यदि_अन्तः

/* ML-DSA 87 */

#यदि 0
पूर्णाङ्क
crypto_sign_mldsa87_keypair(uint8_t pk[MLDSA87_PUBLICKEYBYTES],
    uint8_t sk[MLDSA87_SECRETKEYBYTES])
{
	uint8_t rnd[MLDSA87_SEEDBYTES];
	पूर्णाङ्क r;

	arc4random_buf(rnd, परिमाण(rnd));
	r = crypto_sign_mldsa87_keypair_seeded(pk, sk, rnd);
	explicit_bzero(rnd, परिमाण(rnd));
	प्रत्यागम r;
}

पूर्णाङ्क
crypto_sign_mldsa87_keypair_seeded(uint8_t pk[MLDSA87_PUBLICKEYBYTES],
    uint8_t sk[MLDSA87_SECRETKEYBYTES], ध्रुव uint8_t बीजम्[MLDSA87_SEEDBYTES])
{
	libcrux_mldsa87_keypair_rnd rnd;
	libcrux_mldsa87_keypair keypair;

	स्मृतिं_प्रतिलिख(rnd.दत्त, बीजम्, परिमाण(rnd.दत्त));
	keypair = libcrux_ml_dsa_ml_dsa_87_portable_generate_कुञ्चिका_pair(rnd);
	स्मृतिं_प्रतिलिख(pk, keypair.verification_कुञ्चिका.दत्त, MLDSA87_PUBLICKEYBYTES);
	स्मृतिं_प्रतिलिख(sk, keypair.signing_कुञ्चिका.दत्त, MLDSA87_SECRETKEYBYTES);

	explicit_bzero(&keypair, परिमाण(keypair));
	explicit_bzero(&rnd, परिमाण(rnd));
	प्रत्यागम 0;
}

पूर्णाङ्क
crypto_sign_mldsa87(uint8_t sig[MLDSA87_SIGBYTES],
    ध्रुव uint8_t *सन्देशः, आकार_t msglen,
    ध्रुव uint8_t *ctx, आकार_t ctxlen,
    ध्रुव uint8_t sk[MLDSA87_SECRETKEYBYTES])
{
	uint8_t rnd[MLDSA87_SEEDBYTES];
	पूर्णाङ्क r;

	arc4random_buf(rnd, परिमाण(rnd));
	r = crypto_sign_mldsa87_seeded(sig, सन्देशः, msglen, ctx, ctxlen, sk, rnd);
	explicit_bzero(rnd, परिमाण(rnd));
	प्रत्यागम r;
}

पूर्णाङ्क
crypto_sign_mldsa87_seeded(uint8_t sig[MLDSA87_SIGBYTES],
    ध्रुव uint8_t *सन्देशः, आकार_t msglen,
    ध्रुव uint8_t *ctx, आकार_t ctxlen,
    ध्रुव uint8_t sk[MLDSA87_SECRETKEYBYTES],
    ध्रुव uint8_t बीजम्[MLDSA87_SEEDBYTES])
{
	libcrux_mldsa87_sign_rnd rnd;
	libcrux_mldsa87_sk sk_आन्तरिकम्;
	libcrux_mldsa87_सन्देशः सन्देशः_2 = { सन्देशः, msglen };
	libcrux_mldsa87_सन्देशः context = { ctx, ctxlen };
	libcrux_mldsa87_sign_परिणाम res;
	पूर्णाङ्क r = -1;

	स्मृतिं_प्रतिलिख(sk_आन्तरिकम्.दत्त, sk, MLDSA87_SECRETKEYBYTES);
	स्मृतिं_प्रतिलिख(rnd.दत्त, बीजम्, परिमाण(rnd.दत्त));
	res = libcrux_ml_dsa_ml_dsa_87_portable_sign(&sk_आन्तरिकम्,
	    सन्देशः_2, context, rnd);
	यदि (res.चिह्नकम् == LIBCRUX_परिणाम_OK) {
		स्मृतिं_प्रतिलिख(sig, res.val.case_Ok.दत्त, MLDSA87_SIGBYTES);
		r = 0;
	}

	explicit_bzero(&sk_आन्तरिकम्, परिमाण(sk_आन्तरिकम्));
	explicit_bzero(&res, परिमाण(res));
	explicit_bzero(&rnd, परिमाण(rnd));
	प्रत्यागम r;
}

पूर्णाङ्क
crypto_sign_mldsa87_verify(ध्रुव uint8_t sig[MLDSA87_SIGBYTES],
    ध्रुव uint8_t *सन्देशः, आकार_t msglen,
    ध्रुव uint8_t *ctx, आकार_t ctxlen,
    ध्रुव uint8_t pk[MLDSA87_PUBLICKEYBYTES])
{
	libcrux_mldsa87_pk pk_आन्तरिकम्;
	libcrux_mldsa87_signature sig_आन्तरिकम्;
	libcrux_mldsa87_सन्देशः सन्देशः_2 = { सन्देशः, msglen };
	libcrux_mldsa87_सन्देशः context = { ctx, ctxlen };
	libcrux_mldsa87_verify_परिणाम res;

	स्मृतिं_प्रतिलिख(pk_आन्तरिकम्.दत्त, pk, MLDSA87_PUBLICKEYBYTES);
	स्मृतिं_प्रतिलिख(sig_आन्तरिकम्.दत्त, sig, MLDSA87_SIGBYTES);
	res = libcrux_ml_dsa_ml_dsa_87_portable_verify(&pk_आन्तरिकम्,
	    सन्देशः_2, context, &sig_आन्तरिकम्);

	प्रत्यागम (res.चिह्नकम् == LIBCRUX_परिणाम_OK) ? 0 : -1;
}
#यदि_अन्तः

शून्य
sha3_256(uint8_t digest[32], ध्रुव uint8_t *दत्त, आकार_t len)
{
	Eurydice_borrow_खण्डिका_u8 निवेशः = { दत्त, len };
	Eurydice_mut_borrow_खण्डिका_u8 output = { digest, 32 };
	libcrux_sha3_portable_sha256(output, निवेशः);
}

शून्य
sha3_512(uint8_t digest[64], ध्रुव uint8_t *दत्त, आकार_t len)
{
	Eurydice_borrow_खण्डिका_u8 निवेशः = { दत्त, len };
	Eurydice_mut_borrow_खण्डिका_u8 output = { digest, 64 };
	libcrux_sha3_portable_sha512(output, निवेशः);
}
#यदि_अन्तः /* defined(USE_MLDSA) || defined(USE_MLKEM768X25519) */
