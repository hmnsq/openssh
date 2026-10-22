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

#అన్తర్భావ "includes.h"

#ఒకవేళ defined(USE_MLDSA) || defined(USE_MLKEM768X25519)

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <stdint.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <stdbool.h>
#అన్తర్భావ <string.h>

#అన్తర్భావ "log.h"
#అన్తర్భావ "crypto_api.h"
#అన్తర్భావ "libcrux_internal.h"

/* ML-KEM 768 */

పూర్ణాంకం
crypto_kem_mlkem768_keypair(uint8_t pk[crypto_kem_mlkem768_PUBLICKEYBYTES],
    uint8_t sk[crypto_kem_mlkem768_SECRETKEYBYTES])
{
	uint8_t rnd[crypto_kem_mlkem768_KEYPAIRSEEDBYTES];
	పూర్ణాంకం r;

	arc4random_buf(rnd, పరిమాణం(rnd));
	r = crypto_kem_mlkem768_keypair_seeded(pk, sk, rnd);
	explicit_bzero(rnd, పరిమాణం(rnd));
	తిరిగి r;
}

పూర్ణాంకం
crypto_kem_mlkem768_keypair_seeded(uint8_t pk[crypto_kem_mlkem768_PUBLICKEYBYTES],
    uint8_t sk[crypto_kem_mlkem768_SECRETKEYBYTES],
    స్థిరరాశి uint8_t విత్తనం[crypto_kem_mlkem768_KEYPAIRSEEDBYTES])
{
	libcrux_mlkem768_keypair keypair;
	libcrux_mlkem768_keypair_rnd rnd;

	జ్ఞాపకం_నకలు(rnd.దత్తాంశం, విత్తనం, పరిమాణం(rnd.దత్తాంశం));
	keypair = libcrux_ml_kem_mlkem768_portable_generate_కీలకం_pair(rnd);
	జ్ఞాపకం_నకలు(pk, keypair.pk.దత్తాంశం, crypto_kem_mlkem768_PUBLICKEYBYTES);
	జ్ఞాపకం_నకలు(sk, keypair.sk.దత్తాంశం, crypto_kem_mlkem768_SECRETKEYBYTES);

	explicit_bzero(&keypair, పరిమాణం(keypair));
	explicit_bzero(&rnd, పరిమాణం(rnd));
	తిరిగి 0;
}

పూర్ణాంకం
crypto_kem_mlkem768_enc(uint8_t ct[crypto_kem_mlkem768_CIPHERTEXTBYTES],
    uint8_t shared_secret[crypto_kem_mlkem768_బైట్లు],
    స్థిరరాశి uint8_t pk[crypto_kem_mlkem768_PUBLICKEYBYTES])
{
	uint8_t rnd[crypto_kem_mlkem768_ENCSEEDBYTES];
	పూర్ణాంకం r;

	arc4random_buf(rnd, పరిమాణం(rnd));
	r = crypto_kem_mlkem768_enc_seeded(ct, shared_secret, pk, rnd);
	explicit_bzero(rnd, పరిమాణం(rnd));
	తిరిగి r;
}

పూర్ణాంకం
crypto_kem_mlkem768_enc_seeded(uint8_t ct[crypto_kem_mlkem768_CIPHERTEXTBYTES],
    uint8_t shared_secret[crypto_kem_mlkem768_బైట్లు],
    స్థిరరాశి uint8_t pk[crypto_kem_mlkem768_PUBLICKEYBYTES],
    స్థిరరాశి uint8_t విత్తనం[crypto_kem_mlkem768_ENCSEEDBYTES])
{
	libcrux_mlkem768_enc_ఫలితం enc;
	libcrux_mlkem768_pk pk_అంతర్గత;
	libcrux_mlkem768_enc_rnd rnd;

	జ్ఞాపకం_నకలు(pk_అంతర్గత.దత్తాంశం, pk, crypto_kem_mlkem768_PUBLICKEYBYTES);
	ఒకవేళ (!libcrux_ml_kem_mlkem768_portable_validate_ప్రజా_కీలకం(&pk_అంతర్గత))
		తిరిగి -1;
	జ్ఞాపకం_నకలు(rnd.దత్తాంశం, విత్తనం, పరిమాణం(rnd.దత్తాంశం));
	enc = libcrux_ml_kem_mlkem768_portable_encapsulate(&pk_అంతర్గత, rnd);
	జ్ఞాపకం_నకలు(ct, enc.fst.దత్తాంశం, crypto_kem_mlkem768_CIPHERTEXTBYTES);
	జ్ఞాపకం_నకలు(shared_secret, enc.snd.దత్తాంశం, crypto_kem_mlkem768_బైట్లు);

	explicit_bzero(&enc, పరిమాణం(enc));
	explicit_bzero(&rnd, పరిమాణం(rnd));
	తిరిగి 0;
}

పూర్ణాంకం
crypto_kem_mlkem768_dec(uint8_t shared_secret[crypto_kem_mlkem768_బైట్లు],
    స్థిరరాశి uint8_t ct[crypto_kem_mlkem768_CIPHERTEXTBYTES],
    స్థిరరాశి uint8_t sk[crypto_kem_mlkem768_SECRETKEYBYTES])
{
	libcrux_mlkem768_sk sk_అంతర్గత;
	libcrux_mlkem768_ciphertext ct_అంతర్గత;
	libcrux_mlkem768_dec_ఫలితం shared_secret_అంతర్గత;

	జ్ఞాపకం_నకలు(sk_అంతర్గత.దత్తాంశం, sk, crypto_kem_mlkem768_SECRETKEYBYTES);
	జ్ఞాపకం_నకలు(ct_అంతర్గత.దత్తాంశం, ct, crypto_kem_mlkem768_CIPHERTEXTBYTES);
	shared_secret_అంతర్గత = libcrux_ml_kem_mlkem768_portable_decapsulate(
	    &sk_అంతర్గత, &ct_అంతర్గత);
	జ్ఞాపకం_నకలు(shared_secret, shared_secret_అంతర్గత.దత్తాంశం,
	    crypto_kem_mlkem768_బైట్లు);

	explicit_bzero(&sk_అంతర్గత, పరిమాణం(sk_అంతర్గత));
	explicit_bzero(&shared_secret_అంతర్గత, పరిమాణం(shared_secret_అంతర్గత));
	తిరిగి 0;
}

/* ML-DSA 44 */

పూర్ణాంకం
crypto_sign_mldsa44_keypair(uint8_t pk[MLDSA44_PUBLICKEYBYTES],
    uint8_t sk[MLDSA44_SECRETKEYBYTES])
{
	uint8_t rnd[MLDSA44_SEEDBYTES];
	పూర్ణాంకం r;

	arc4random_buf(rnd, పరిమాణం(rnd));
	r = crypto_sign_mldsa44_keypair_seeded(pk, sk, rnd);
	explicit_bzero(rnd, పరిమాణం(rnd));
	తిరిగి r;
}

పూర్ణాంకం
crypto_sign_mldsa44_keypair_seeded(uint8_t pk[MLDSA44_PUBLICKEYBYTES],
    uint8_t sk[MLDSA44_SECRETKEYBYTES], స్థిరరాశి uint8_t విత్తనం[MLDSA44_SEEDBYTES])
{
	libcrux_mldsa44_keypair_rnd rnd;
	libcrux_mldsa44_keypair keypair;

	జ్ఞాపకం_నకలు(rnd.దత్తాంశం, విత్తనం, పరిమాణం(rnd.దత్తాంశం));
	keypair = libcrux_ml_dsa_ml_dsa_44_portable_generate_కీలకం_pair(rnd);
	జ్ఞాపకం_నకలు(pk, keypair.verification_కీలకం.దత్తాంశం, MLDSA44_PUBLICKEYBYTES);
	జ్ఞాపకం_నకలు(sk, keypair.signing_కీలకం.దత్తాంశం, MLDSA44_SECRETKEYBYTES);

	explicit_bzero(&keypair, పరిమాణం(keypair));
	explicit_bzero(&rnd, పరిమాణం(rnd));
	తిరిగి 0;
}

పూర్ణాంకం
crypto_sign_mldsa44(uint8_t sig[MLDSA44_SIGBYTES],
    స్థిరరాశి uint8_t *సందేశం, కొలత_t msglen,
    స్థిరరాశి uint8_t *ctx, కొలత_t ctxlen,
    స్థిరరాశి uint8_t sk[MLDSA44_SECRETKEYBYTES])
{
	uint8_t rnd[MLDSA44_SEEDBYTES];
	పూర్ణాంకం r;

	arc4random_buf(rnd, పరిమాణం(rnd));
	r = crypto_sign_mldsa44_seeded(sig, సందేశం, msglen, ctx, ctxlen, sk, rnd);
	explicit_bzero(rnd, పరిమాణం(rnd));
	తిరిగి r;
}

పూర్ణాంకం
crypto_sign_mldsa44_seeded(uint8_t sig[MLDSA44_SIGBYTES],
    స్థిరరాశి uint8_t *సందేశం, కొలత_t msglen,
    స్థిరరాశి uint8_t *ctx, కొలత_t ctxlen,
    స్థిరరాశి uint8_t sk[MLDSA44_SECRETKEYBYTES],
    స్థిరరాశి uint8_t విత్తనం[MLDSA44_SEEDBYTES])
{
	libcrux_mldsa44_sign_rnd rnd;
	libcrux_mldsa44_sk sk_అంతర్గత;
	libcrux_mldsa44_సందేశం సందేశం_2 = { సందేశం, msglen };
	libcrux_mldsa44_సందేశం context = { ctx, ctxlen };
	libcrux_mldsa44_sign_ఫలితం res;
	పూర్ణాంకం r = -1;

	జ్ఞాపకం_నకలు(sk_అంతర్గత.దత్తాంశం, sk, MLDSA44_SECRETKEYBYTES);
	జ్ఞాపకం_నకలు(rnd.దత్తాంశం, విత్తనం, పరిమాణం(rnd.దత్తాంశం));
	res = libcrux_ml_dsa_ml_dsa_44_portable_sign(&sk_అంతర్గత,
	    సందేశం_2, context, rnd);
	ఒకవేళ (res.ట్యాగ్ == LIBCRUX_ఫలితం_OK) {
		జ్ఞాపకం_నకలు(sig, res.val.case_Ok.దత్తాంశం, MLDSA44_SIGBYTES);
		r = 0;
	}

	explicit_bzero(&sk_అంతర్గత, పరిమాణం(sk_అంతర్గత));
	explicit_bzero(&res, పరిమాణం(res));
	explicit_bzero(&rnd, పరిమాణం(rnd));
	తిరిగి r;
}

పూర్ణాంకం
crypto_sign_mldsa44_verify(స్థిరరాశి uint8_t sig[MLDSA44_SIGBYTES],
    స్థిరరాశి uint8_t *సందేశం, కొలత_t msglen,
    స్థిరరాశి uint8_t *ctx, కొలత_t ctxlen,
    స్థిరరాశి uint8_t pk[MLDSA44_PUBLICKEYBYTES])
{
	libcrux_mldsa44_pk pk_అంతర్గత;
	libcrux_mldsa44_signature sig_అంతర్గత;
	libcrux_mldsa44_సందేశం సందేశం_2 = { సందేశం, msglen };
	libcrux_mldsa44_సందేశం context = { ctx, ctxlen };
	libcrux_mldsa44_verify_ఫలితం res;

	జ్ఞాపకం_నకలు(pk_అంతర్గత.దత్తాంశం, pk, MLDSA44_PUBLICKEYBYTES);
	జ్ఞాపకం_నకలు(sig_అంతర్గత.దత్తాంశం, sig, MLDSA44_SIGBYTES);
	res = libcrux_ml_dsa_ml_dsa_44_portable_verify(&pk_అంతర్గత,
	    సందేశం_2, context, &sig_అంతర్గత);

	తిరిగి (res.ట్యాగ్ == LIBCRUX_ఫలితం_OK) ? 0 : -1;
}

/* ML-DSA 65 */

#ఒకవేళ 0
పూర్ణాంకం
crypto_sign_mldsa65_keypair(uint8_t pk[MLDSA65_PUBLICKEYBYTES],
    uint8_t sk[MLDSA65_SECRETKEYBYTES])
{
	uint8_t rnd[MLDSA65_SEEDBYTES];
	పూర్ణాంకం r;

	arc4random_buf(rnd, పరిమాణం(rnd));
	r = crypto_sign_mldsa65_keypair_seeded(pk, sk, rnd);
	explicit_bzero(rnd, పరిమాణం(rnd));
	తిరిగి r;
}

పూర్ణాంకం
crypto_sign_mldsa65_keypair_seeded(uint8_t pk[MLDSA65_PUBLICKEYBYTES],
    uint8_t sk[MLDSA65_SECRETKEYBYTES], స్థిరరాశి uint8_t విత్తనం[MLDSA65_SEEDBYTES])
{
	libcrux_mldsa65_keypair_rnd rnd;
	libcrux_mldsa65_keypair keypair;

	జ్ఞాపకం_నకలు(rnd.దత్తాంశం, విత్తనం, పరిమాణం(rnd.దత్తాంశం));
	keypair = libcrux_ml_dsa_ml_dsa_65_portable_generate_కీలకం_pair(rnd);
	జ్ఞాపకం_నకలు(pk, keypair.verification_కీలకం.దత్తాంశం, MLDSA65_PUBLICKEYBYTES);
	జ్ఞాపకం_నకలు(sk, keypair.signing_కీలకం.దత్తాంశం, MLDSA65_SECRETKEYBYTES);

	explicit_bzero(&keypair, పరిమాణం(keypair));
	explicit_bzero(&rnd, పరిమాణం(rnd));
	తిరిగి 0;
}

పూర్ణాంకం
crypto_sign_mldsa65(uint8_t sig[MLDSA65_SIGBYTES],
    స్థిరరాశి uint8_t *సందేశం, కొలత_t msglen,
    స్థిరరాశి uint8_t *ctx, కొలత_t ctxlen,
    స్థిరరాశి uint8_t sk[MLDSA65_SECRETKEYBYTES])
{
	uint8_t rnd[MLDSA65_SEEDBYTES];
	పూర్ణాంకం r;

	arc4random_buf(rnd, పరిమాణం(rnd));
	r = crypto_sign_mldsa65_seeded(sig, సందేశం, msglen, ctx, ctxlen, sk, rnd);
	explicit_bzero(rnd, పరిమాణం(rnd));
	తిరిగి r;
}

పూర్ణాంకం
crypto_sign_mldsa65_seeded(uint8_t sig[MLDSA65_SIGBYTES],
    స్థిరరాశి uint8_t *సందేశం, కొలత_t msglen,
    స్థిరరాశి uint8_t *ctx, కొలత_t ctxlen,
    స్థిరరాశి uint8_t sk[MLDSA65_SECRETKEYBYTES],
    స్థిరరాశి uint8_t విత్తనం[MLDSA65_SEEDBYTES])
{
	libcrux_mldsa65_sign_rnd rnd;
	libcrux_mldsa65_sk sk_అంతర్గత;
	libcrux_mldsa65_సందేశం సందేశం_2 = { సందేశం, msglen };
	libcrux_mldsa65_సందేశం context = { ctx, ctxlen };
	libcrux_mldsa65_sign_ఫలితం res;
	పూర్ణాంకం r = -1;

	జ్ఞాపకం_నకలు(sk_అంతర్గత.దత్తాంశం, sk, MLDSA65_SECRETKEYBYTES);
	జ్ఞాపకం_నకలు(rnd.దత్తాంశం, విత్తనం, పరిమాణం(rnd.దత్తాంశం));
	res = libcrux_ml_dsa_ml_dsa_65_portable_sign(&sk_అంతర్గత,
	    సందేశం_2, context, rnd);
	ఒకవేళ (res.ట్యాగ్ == LIBCRUX_ఫలితం_OK) {
		జ్ఞాపకం_నకలు(sig, res.val.case_Ok.దత్తాంశం, MLDSA65_SIGBYTES);
		r = 0;
	}

	explicit_bzero(&sk_అంతర్గత, పరిమాణం(sk_అంతర్గత));
	explicit_bzero(&res, పరిమాణం(res));
	explicit_bzero(&rnd, పరిమాణం(rnd));
	తిరిగి r;
}

పూర్ణాంకం
crypto_sign_mldsa65_verify(స్థిరరాశి uint8_t sig[MLDSA65_SIGBYTES],
    స్థిరరాశి uint8_t *సందేశం, కొలత_t msglen,
    స్థిరరాశి uint8_t *ctx, కొలత_t ctxlen,
    స్థిరరాశి uint8_t pk[MLDSA65_PUBLICKEYBYTES])
{
	libcrux_mldsa65_pk pk_అంతర్గత;
	libcrux_mldsa65_signature sig_అంతర్గత;
	libcrux_mldsa65_సందేశం సందేశం_2 = { సందేశం, msglen };
	libcrux_mldsa65_సందేశం context = { ctx, ctxlen };
	libcrux_mldsa65_verify_ఫలితం res;

	జ్ఞాపకం_నకలు(pk_అంతర్గత.దత్తాంశం, pk, MLDSA65_PUBLICKEYBYTES);
	జ్ఞాపకం_నకలు(sig_అంతర్గత.దత్తాంశం, sig, MLDSA65_SIGBYTES);
	res = libcrux_ml_dsa_ml_dsa_65_portable_verify(&pk_అంతర్గత,
	    సందేశం_2, context, &sig_అంతర్గత);

	తిరిగి (res.ట్యాగ్ == LIBCRUX_ఫలితం_OK) ? 0 : -1;
}
#అయితే_ముగింపు

/* ML-DSA 87 */

#ఒకవేళ 0
పూర్ణాంకం
crypto_sign_mldsa87_keypair(uint8_t pk[MLDSA87_PUBLICKEYBYTES],
    uint8_t sk[MLDSA87_SECRETKEYBYTES])
{
	uint8_t rnd[MLDSA87_SEEDBYTES];
	పూర్ణాంకం r;

	arc4random_buf(rnd, పరిమాణం(rnd));
	r = crypto_sign_mldsa87_keypair_seeded(pk, sk, rnd);
	explicit_bzero(rnd, పరిమాణం(rnd));
	తిరిగి r;
}

పూర్ణాంకం
crypto_sign_mldsa87_keypair_seeded(uint8_t pk[MLDSA87_PUBLICKEYBYTES],
    uint8_t sk[MLDSA87_SECRETKEYBYTES], స్థిరరాశి uint8_t విత్తనం[MLDSA87_SEEDBYTES])
{
	libcrux_mldsa87_keypair_rnd rnd;
	libcrux_mldsa87_keypair keypair;

	జ్ఞాపకం_నకలు(rnd.దత్తాంశం, విత్తనం, పరిమాణం(rnd.దత్తాంశం));
	keypair = libcrux_ml_dsa_ml_dsa_87_portable_generate_కీలకం_pair(rnd);
	జ్ఞాపకం_నకలు(pk, keypair.verification_కీలకం.దత్తాంశం, MLDSA87_PUBLICKEYBYTES);
	జ్ఞాపకం_నకలు(sk, keypair.signing_కీలకం.దత్తాంశం, MLDSA87_SECRETKEYBYTES);

	explicit_bzero(&keypair, పరిమాణం(keypair));
	explicit_bzero(&rnd, పరిమాణం(rnd));
	తిరిగి 0;
}

పూర్ణాంకం
crypto_sign_mldsa87(uint8_t sig[MLDSA87_SIGBYTES],
    స్థిరరాశి uint8_t *సందేశం, కొలత_t msglen,
    స్థిరరాశి uint8_t *ctx, కొలత_t ctxlen,
    స్థిరరాశి uint8_t sk[MLDSA87_SECRETKEYBYTES])
{
	uint8_t rnd[MLDSA87_SEEDBYTES];
	పూర్ణాంకం r;

	arc4random_buf(rnd, పరిమాణం(rnd));
	r = crypto_sign_mldsa87_seeded(sig, సందేశం, msglen, ctx, ctxlen, sk, rnd);
	explicit_bzero(rnd, పరిమాణం(rnd));
	తిరిగి r;
}

పూర్ణాంకం
crypto_sign_mldsa87_seeded(uint8_t sig[MLDSA87_SIGBYTES],
    స్థిరరాశి uint8_t *సందేశం, కొలత_t msglen,
    స్థిరరాశి uint8_t *ctx, కొలత_t ctxlen,
    స్థిరరాశి uint8_t sk[MLDSA87_SECRETKEYBYTES],
    స్థిరరాశి uint8_t విత్తనం[MLDSA87_SEEDBYTES])
{
	libcrux_mldsa87_sign_rnd rnd;
	libcrux_mldsa87_sk sk_అంతర్గత;
	libcrux_mldsa87_సందేశం సందేశం_2 = { సందేశం, msglen };
	libcrux_mldsa87_సందేశం context = { ctx, ctxlen };
	libcrux_mldsa87_sign_ఫలితం res;
	పూర్ణాంకం r = -1;

	జ్ఞాపకం_నకలు(sk_అంతర్గత.దత్తాంశం, sk, MLDSA87_SECRETKEYBYTES);
	జ్ఞాపకం_నకలు(rnd.దత్తాంశం, విత్తనం, పరిమాణం(rnd.దత్తాంశం));
	res = libcrux_ml_dsa_ml_dsa_87_portable_sign(&sk_అంతర్గత,
	    సందేశం_2, context, rnd);
	ఒకవేళ (res.ట్యాగ్ == LIBCRUX_ఫలితం_OK) {
		జ్ఞాపకం_నకలు(sig, res.val.case_Ok.దత్తాంశం, MLDSA87_SIGBYTES);
		r = 0;
	}

	explicit_bzero(&sk_అంతర్గత, పరిమాణం(sk_అంతర్గత));
	explicit_bzero(&res, పరిమాణం(res));
	explicit_bzero(&rnd, పరిమాణం(rnd));
	తిరిగి r;
}

పూర్ణాంకం
crypto_sign_mldsa87_verify(స్థిరరాశి uint8_t sig[MLDSA87_SIGBYTES],
    స్థిరరాశి uint8_t *సందేశం, కొలత_t msglen,
    స్థిరరాశి uint8_t *ctx, కొలత_t ctxlen,
    స్థిరరాశి uint8_t pk[MLDSA87_PUBLICKEYBYTES])
{
	libcrux_mldsa87_pk pk_అంతర్గత;
	libcrux_mldsa87_signature sig_అంతర్గత;
	libcrux_mldsa87_సందేశం సందేశం_2 = { సందేశం, msglen };
	libcrux_mldsa87_సందేశం context = { ctx, ctxlen };
	libcrux_mldsa87_verify_ఫలితం res;

	జ్ఞాపకం_నకలు(pk_అంతర్గత.దత్తాంశం, pk, MLDSA87_PUBLICKEYBYTES);
	జ్ఞాపకం_నకలు(sig_అంతర్గత.దత్తాంశం, sig, MLDSA87_SIGBYTES);
	res = libcrux_ml_dsa_ml_dsa_87_portable_verify(&pk_అంతర్గత,
	    సందేశం_2, context, &sig_అంతర్గత);

	తిరిగి (res.ట్యాగ్ == LIBCRUX_ఫలితం_OK) ? 0 : -1;
}
#అయితే_ముగింపు

శూన్య
sha3_256(uint8_t digest[32], స్థిరరాశి uint8_t *దత్తాంశం, కొలత_t len)
{
	Eurydice_borrow_ముక్క_u8 ఆదానం = { దత్తాంశం, len };
	Eurydice_mut_borrow_ముక్క_u8 output = { digest, 32 };
	libcrux_sha3_portable_sha256(output, ఆదానం);
}

శూన్య
sha3_512(uint8_t digest[64], స్థిరరాశి uint8_t *దత్తాంశం, కొలత_t len)
{
	Eurydice_borrow_ముక్క_u8 ఆదానం = { దత్తాంశం, len };
	Eurydice_mut_borrow_ముక్క_u8 output = { digest, 64 };
	libcrux_sha3_portable_sha512(output, ఆదానం);
}
#అయితే_ముగింపు /* defined(USE_MLDSA) || defined(USE_MLKEM768X25519) */
