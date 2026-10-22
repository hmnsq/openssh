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

#ضمن "includes.h"

#إذا defined(USE_MLDSA) || defined(USE_MLKEM768X25519)

#ضمن <sys/types.h>
#ضمن <stdint.h>
#ضمن <stdlib.h>
#ضمن <stdbool.h>
#ضمن <string.h>

#ضمن "log.h"
#ضمن "crypto_api.h"
#ضمن "libcrux_internal.h"

/* ML-KEM 768 */

صحيح
crypto_kem_mlkem768_keypair(uint8_t pk[crypto_kem_mlkem768_PUBLICKEYBYTES],
    uint8_t sk[crypto_kem_mlkem768_SECRETKEYBYTES])
{
	uint8_t rnd[crypto_kem_mlkem768_KEYPAIRSEEDBYTES];
	صحيح r;

	arc4random_buf(rnd, حجم(rnd));
	r = crypto_kem_mlkem768_keypair_seeded(pk, sk, rnd);
	explicit_bzero(rnd, حجم(rnd));
	أرجع r;
}

صحيح
crypto_kem_mlkem768_keypair_seeded(uint8_t pk[crypto_kem_mlkem768_PUBLICKEYBYTES],
    uint8_t sk[crypto_kem_mlkem768_SECRETKEYBYTES],
    ثابت uint8_t بیج[crypto_kem_mlkem768_KEYPAIRSEEDBYTES])
{
	libcrux_mlkem768_keypair keypair;
	libcrux_mlkem768_keypair_rnd rnd;

	حافظہ_نقل(rnd.انکڑے, بیج, حجم(rnd.انکڑے));
	keypair = libcrux_ml_kem_mlkem768_portable_generate_کلید_pair(rnd);
	حافظہ_نقل(pk, keypair.pk.انکڑے, crypto_kem_mlkem768_PUBLICKEYBYTES);
	حافظہ_نقل(sk, keypair.sk.انکڑے, crypto_kem_mlkem768_SECRETKEYBYTES);

	explicit_bzero(&keypair, حجم(keypair));
	explicit_bzero(&rnd, حجم(rnd));
	أرجع 0;
}

صحيح
crypto_kem_mlkem768_enc(uint8_t ct[crypto_kem_mlkem768_CIPHERTEXTBYTES],
    uint8_t shared_secret[crypto_kem_mlkem768_بائٹاں],
    ثابت uint8_t pk[crypto_kem_mlkem768_PUBLICKEYBYTES])
{
	uint8_t rnd[crypto_kem_mlkem768_ENCSEEDBYTES];
	صحيح r;

	arc4random_buf(rnd, حجم(rnd));
	r = crypto_kem_mlkem768_enc_seeded(ct, shared_secret, pk, rnd);
	explicit_bzero(rnd, حجم(rnd));
	أرجع r;
}

صحيح
crypto_kem_mlkem768_enc_seeded(uint8_t ct[crypto_kem_mlkem768_CIPHERTEXTBYTES],
    uint8_t shared_secret[crypto_kem_mlkem768_بائٹاں],
    ثابت uint8_t pk[crypto_kem_mlkem768_PUBLICKEYBYTES],
    ثابت uint8_t بیج[crypto_kem_mlkem768_ENCSEEDBYTES])
{
	libcrux_mlkem768_enc_نتیجہ enc;
	libcrux_mlkem768_pk pk_اندرونی;
	libcrux_mlkem768_enc_rnd rnd;

	حافظہ_نقل(pk_اندرونی.انکڑے, pk, crypto_kem_mlkem768_PUBLICKEYBYTES);
	إذا (!libcrux_ml_kem_mlkem768_portable_validate_عوامی_کلید(&pk_اندرونی))
		أرجع -1;
	حافظہ_نقل(rnd.انکڑے, بیج, حجم(rnd.انکڑے));
	enc = libcrux_ml_kem_mlkem768_portable_encapsulate(&pk_اندرونی, rnd);
	حافظہ_نقل(ct, enc.fst.انکڑے, crypto_kem_mlkem768_CIPHERTEXTBYTES);
	حافظہ_نقل(shared_secret, enc.snd.انکڑے, crypto_kem_mlkem768_بائٹاں);

	explicit_bzero(&enc, حجم(enc));
	explicit_bzero(&rnd, حجم(rnd));
	أرجع 0;
}

صحيح
crypto_kem_mlkem768_dec(uint8_t shared_secret[crypto_kem_mlkem768_بائٹاں],
    ثابت uint8_t ct[crypto_kem_mlkem768_CIPHERTEXTBYTES],
    ثابت uint8_t sk[crypto_kem_mlkem768_SECRETKEYBYTES])
{
	libcrux_mlkem768_sk sk_اندرونی;
	libcrux_mlkem768_ciphertext ct_اندرونی;
	libcrux_mlkem768_dec_نتیجہ shared_secret_اندرونی;

	حافظہ_نقل(sk_اندرونی.انکڑے, sk, crypto_kem_mlkem768_SECRETKEYBYTES);
	حافظہ_نقل(ct_اندرونی.انکڑے, ct, crypto_kem_mlkem768_CIPHERTEXTBYTES);
	shared_secret_اندرونی = libcrux_ml_kem_mlkem768_portable_decapsulate(
	    &sk_اندرونی, &ct_اندرونی);
	حافظہ_نقل(shared_secret, shared_secret_اندرونی.انکڑے,
	    crypto_kem_mlkem768_بائٹاں);

	explicit_bzero(&sk_اندرونی, حجم(sk_اندرونی));
	explicit_bzero(&shared_secret_اندرونی, حجم(shared_secret_اندرونی));
	أرجع 0;
}

/* ML-DSA 44 */

صحيح
crypto_sign_mldsa44_keypair(uint8_t pk[MLDSA44_PUBLICKEYBYTES],
    uint8_t sk[MLDSA44_SECRETKEYBYTES])
{
	uint8_t rnd[MLDSA44_SEEDBYTES];
	صحيح r;

	arc4random_buf(rnd, حجم(rnd));
	r = crypto_sign_mldsa44_keypair_seeded(pk, sk, rnd);
	explicit_bzero(rnd, حجم(rnd));
	أرجع r;
}

صحيح
crypto_sign_mldsa44_keypair_seeded(uint8_t pk[MLDSA44_PUBLICKEYBYTES],
    uint8_t sk[MLDSA44_SECRETKEYBYTES], ثابت uint8_t بیج[MLDSA44_SEEDBYTES])
{
	libcrux_mldsa44_keypair_rnd rnd;
	libcrux_mldsa44_keypair keypair;

	حافظہ_نقل(rnd.انکڑے, بیج, حجم(rnd.انکڑے));
	keypair = libcrux_ml_dsa_ml_dsa_44_portable_generate_کلید_pair(rnd);
	حافظہ_نقل(pk, keypair.verification_کلید.انکڑے, MLDSA44_PUBLICKEYBYTES);
	حافظہ_نقل(sk, keypair.signing_کلید.انکڑے, MLDSA44_SECRETKEYBYTES);

	explicit_bzero(&keypair, حجم(keypair));
	explicit_bzero(&rnd, حجم(rnd));
	أرجع 0;
}

صحيح
crypto_sign_mldsa44(uint8_t sig[MLDSA44_SIGBYTES],
    ثابت uint8_t *پیغام, ناپ_t msglen,
    ثابت uint8_t *ctx, ناپ_t ctxlen,
    ثابت uint8_t sk[MLDSA44_SECRETKEYBYTES])
{
	uint8_t rnd[MLDSA44_SEEDBYTES];
	صحيح r;

	arc4random_buf(rnd, حجم(rnd));
	r = crypto_sign_mldsa44_seeded(sig, پیغام, msglen, ctx, ctxlen, sk, rnd);
	explicit_bzero(rnd, حجم(rnd));
	أرجع r;
}

صحيح
crypto_sign_mldsa44_seeded(uint8_t sig[MLDSA44_SIGBYTES],
    ثابت uint8_t *پیغام, ناپ_t msglen,
    ثابت uint8_t *ctx, ناپ_t ctxlen,
    ثابت uint8_t sk[MLDSA44_SECRETKEYBYTES],
    ثابت uint8_t بیج[MLDSA44_SEEDBYTES])
{
	libcrux_mldsa44_sign_rnd rnd;
	libcrux_mldsa44_sk sk_اندرونی;
	libcrux_mldsa44_سنیہا سنیہا = { پیغام, msglen };
	libcrux_mldsa44_سنیہا context = { ctx, ctxlen };
	libcrux_mldsa44_sign_نتیجہ res;
	صحيح r = -1;

	حافظہ_نقل(sk_اندرونی.انکڑے, sk, MLDSA44_SECRETKEYBYTES);
	حافظہ_نقل(rnd.انکڑے, بیج, حجم(rnd.انکڑے));
	res = libcrux_ml_dsa_ml_dsa_44_portable_sign(&sk_اندرونی,
	    سنیہا, context, rnd);
	إذا (res.ٹیگ == LIBCRUX_نتیجہ_OK) {
		حافظہ_نقل(sig, res.val.case_Ok.انکڑے, MLDSA44_SIGBYTES);
		r = 0;
	}

	explicit_bzero(&sk_اندرونی, حجم(sk_اندرونی));
	explicit_bzero(&res, حجم(res));
	explicit_bzero(&rnd, حجم(rnd));
	أرجع r;
}

صحيح
crypto_sign_mldsa44_verify(ثابت uint8_t sig[MLDSA44_SIGBYTES],
    ثابت uint8_t *پیغام, ناپ_t msglen,
    ثابت uint8_t *ctx, ناپ_t ctxlen,
    ثابت uint8_t pk[MLDSA44_PUBLICKEYBYTES])
{
	libcrux_mldsa44_pk pk_اندرونی;
	libcrux_mldsa44_signature sig_اندرونی;
	libcrux_mldsa44_سنیہا سنیہا = { پیغام, msglen };
	libcrux_mldsa44_سنیہا context = { ctx, ctxlen };
	libcrux_mldsa44_verify_نتیجہ res;

	حافظہ_نقل(pk_اندرونی.انکڑے, pk, MLDSA44_PUBLICKEYBYTES);
	حافظہ_نقل(sig_اندرونی.انکڑے, sig, MLDSA44_SIGBYTES);
	res = libcrux_ml_dsa_ml_dsa_44_portable_verify(&pk_اندرونی,
	    سنیہا, context, &sig_اندرونی);

	أرجع (res.ٹیگ == LIBCRUX_نتیجہ_OK) ? 0 : -1;
}

/* ML-DSA 65 */

#إذا 0
صحيح
crypto_sign_mldsa65_keypair(uint8_t pk[MLDSA65_PUBLICKEYBYTES],
    uint8_t sk[MLDSA65_SECRETKEYBYTES])
{
	uint8_t rnd[MLDSA65_SEEDBYTES];
	صحيح r;

	arc4random_buf(rnd, حجم(rnd));
	r = crypto_sign_mldsa65_keypair_seeded(pk, sk, rnd);
	explicit_bzero(rnd, حجم(rnd));
	أرجع r;
}

صحيح
crypto_sign_mldsa65_keypair_seeded(uint8_t pk[MLDSA65_PUBLICKEYBYTES],
    uint8_t sk[MLDSA65_SECRETKEYBYTES], ثابت uint8_t بیج[MLDSA65_SEEDBYTES])
{
	libcrux_mldsa65_keypair_rnd rnd;
	libcrux_mldsa65_keypair keypair;

	حافظہ_نقل(rnd.انکڑے, بیج, حجم(rnd.انکڑے));
	keypair = libcrux_ml_dsa_ml_dsa_65_portable_generate_کلید_pair(rnd);
	حافظہ_نقل(pk, keypair.verification_کلید.انکڑے, MLDSA65_PUBLICKEYBYTES);
	حافظہ_نقل(sk, keypair.signing_کلید.انکڑے, MLDSA65_SECRETKEYBYTES);

	explicit_bzero(&keypair, حجم(keypair));
	explicit_bzero(&rnd, حجم(rnd));
	أرجع 0;
}

صحيح
crypto_sign_mldsa65(uint8_t sig[MLDSA65_SIGBYTES],
    ثابت uint8_t *پیغام, ناپ_t msglen,
    ثابت uint8_t *ctx, ناپ_t ctxlen,
    ثابت uint8_t sk[MLDSA65_SECRETKEYBYTES])
{
	uint8_t rnd[MLDSA65_SEEDBYTES];
	صحيح r;

	arc4random_buf(rnd, حجم(rnd));
	r = crypto_sign_mldsa65_seeded(sig, پیغام, msglen, ctx, ctxlen, sk, rnd);
	explicit_bzero(rnd, حجم(rnd));
	أرجع r;
}

صحيح
crypto_sign_mldsa65_seeded(uint8_t sig[MLDSA65_SIGBYTES],
    ثابت uint8_t *پیغام, ناپ_t msglen,
    ثابت uint8_t *ctx, ناپ_t ctxlen,
    ثابت uint8_t sk[MLDSA65_SECRETKEYBYTES],
    ثابت uint8_t بیج[MLDSA65_SEEDBYTES])
{
	libcrux_mldsa65_sign_rnd rnd;
	libcrux_mldsa65_sk sk_اندرونی;
	libcrux_mldsa65_سنیہا سنیہا = { پیغام, msglen };
	libcrux_mldsa65_سنیہا context = { ctx, ctxlen };
	libcrux_mldsa65_sign_نتیجہ res;
	صحيح r = -1;

	حافظہ_نقل(sk_اندرونی.انکڑے, sk, MLDSA65_SECRETKEYBYTES);
	حافظہ_نقل(rnd.انکڑے, بیج, حجم(rnd.انکڑے));
	res = libcrux_ml_dsa_ml_dsa_65_portable_sign(&sk_اندرونی,
	    سنیہا, context, rnd);
	إذا (res.ٹیگ == LIBCRUX_نتیجہ_OK) {
		حافظہ_نقل(sig, res.val.case_Ok.انکڑے, MLDSA65_SIGBYTES);
		r = 0;
	}

	explicit_bzero(&sk_اندرونی, حجم(sk_اندرونی));
	explicit_bzero(&res, حجم(res));
	explicit_bzero(&rnd, حجم(rnd));
	أرجع r;
}

صحيح
crypto_sign_mldsa65_verify(ثابت uint8_t sig[MLDSA65_SIGBYTES],
    ثابت uint8_t *پیغام, ناپ_t msglen,
    ثابت uint8_t *ctx, ناپ_t ctxlen,
    ثابت uint8_t pk[MLDSA65_PUBLICKEYBYTES])
{
	libcrux_mldsa65_pk pk_اندرونی;
	libcrux_mldsa65_signature sig_اندرونی;
	libcrux_mldsa65_سنیہا سنیہا = { پیغام, msglen };
	libcrux_mldsa65_سنیہا context = { ctx, ctxlen };
	libcrux_mldsa65_verify_نتیجہ res;

	حافظہ_نقل(pk_اندرونی.انکڑے, pk, MLDSA65_PUBLICKEYBYTES);
	حافظہ_نقل(sig_اندرونی.انکڑے, sig, MLDSA65_SIGBYTES);
	res = libcrux_ml_dsa_ml_dsa_65_portable_verify(&pk_اندرونی,
	    سنیہا, context, &sig_اندرونی);

	أرجع (res.ٹیگ == LIBCRUX_نتیجہ_OK) ? 0 : -1;
}
#جے_انت

/* ML-DSA 87 */

#إذا 0
صحيح
crypto_sign_mldsa87_keypair(uint8_t pk[MLDSA87_PUBLICKEYBYTES],
    uint8_t sk[MLDSA87_SECRETKEYBYTES])
{
	uint8_t rnd[MLDSA87_SEEDBYTES];
	صحيح r;

	arc4random_buf(rnd, حجم(rnd));
	r = crypto_sign_mldsa87_keypair_seeded(pk, sk, rnd);
	explicit_bzero(rnd, حجم(rnd));
	أرجع r;
}

صحيح
crypto_sign_mldsa87_keypair_seeded(uint8_t pk[MLDSA87_PUBLICKEYBYTES],
    uint8_t sk[MLDSA87_SECRETKEYBYTES], ثابت uint8_t بیج[MLDSA87_SEEDBYTES])
{
	libcrux_mldsa87_keypair_rnd rnd;
	libcrux_mldsa87_keypair keypair;

	حافظہ_نقل(rnd.انکڑے, بیج, حجم(rnd.انکڑے));
	keypair = libcrux_ml_dsa_ml_dsa_87_portable_generate_کلید_pair(rnd);
	حافظہ_نقل(pk, keypair.verification_کلید.انکڑے, MLDSA87_PUBLICKEYBYTES);
	حافظہ_نقل(sk, keypair.signing_کلید.انکڑے, MLDSA87_SECRETKEYBYTES);

	explicit_bzero(&keypair, حجم(keypair));
	explicit_bzero(&rnd, حجم(rnd));
	أرجع 0;
}

صحيح
crypto_sign_mldsa87(uint8_t sig[MLDSA87_SIGBYTES],
    ثابت uint8_t *پیغام, ناپ_t msglen,
    ثابت uint8_t *ctx, ناپ_t ctxlen,
    ثابت uint8_t sk[MLDSA87_SECRETKEYBYTES])
{
	uint8_t rnd[MLDSA87_SEEDBYTES];
	صحيح r;

	arc4random_buf(rnd, حجم(rnd));
	r = crypto_sign_mldsa87_seeded(sig, پیغام, msglen, ctx, ctxlen, sk, rnd);
	explicit_bzero(rnd, حجم(rnd));
	أرجع r;
}

صحيح
crypto_sign_mldsa87_seeded(uint8_t sig[MLDSA87_SIGBYTES],
    ثابت uint8_t *پیغام, ناپ_t msglen,
    ثابت uint8_t *ctx, ناپ_t ctxlen,
    ثابت uint8_t sk[MLDSA87_SECRETKEYBYTES],
    ثابت uint8_t بیج[MLDSA87_SEEDBYTES])
{
	libcrux_mldsa87_sign_rnd rnd;
	libcrux_mldsa87_sk sk_اندرونی;
	libcrux_mldsa87_سنیہا سنیہا = { پیغام, msglen };
	libcrux_mldsa87_سنیہا context = { ctx, ctxlen };
	libcrux_mldsa87_sign_نتیجہ res;
	صحيح r = -1;

	حافظہ_نقل(sk_اندرونی.انکڑے, sk, MLDSA87_SECRETKEYBYTES);
	حافظہ_نقل(rnd.انکڑے, بیج, حجم(rnd.انکڑے));
	res = libcrux_ml_dsa_ml_dsa_87_portable_sign(&sk_اندرونی,
	    سنیہا, context, rnd);
	إذا (res.ٹیگ == LIBCRUX_نتیجہ_OK) {
		حافظہ_نقل(sig, res.val.case_Ok.انکڑے, MLDSA87_SIGBYTES);
		r = 0;
	}

	explicit_bzero(&sk_اندرونی, حجم(sk_اندرونی));
	explicit_bzero(&res, حجم(res));
	explicit_bzero(&rnd, حجم(rnd));
	أرجع r;
}

صحيح
crypto_sign_mldsa87_verify(ثابت uint8_t sig[MLDSA87_SIGBYTES],
    ثابت uint8_t *پیغام, ناپ_t msglen,
    ثابت uint8_t *ctx, ناپ_t ctxlen,
    ثابت uint8_t pk[MLDSA87_PUBLICKEYBYTES])
{
	libcrux_mldsa87_pk pk_اندرونی;
	libcrux_mldsa87_signature sig_اندرونی;
	libcrux_mldsa87_سنیہا سنیہا = { پیغام, msglen };
	libcrux_mldsa87_سنیہا context = { ctx, ctxlen };
	libcrux_mldsa87_verify_نتیجہ res;

	حافظہ_نقل(pk_اندرونی.انکڑے, pk, MLDSA87_PUBLICKEYBYTES);
	حافظہ_نقل(sig_اندرونی.انکڑے, sig, MLDSA87_SIGBYTES);
	res = libcrux_ml_dsa_ml_dsa_87_portable_verify(&pk_اندرونی,
	    سنیہا, context, &sig_اندرونی);

	أرجع (res.ٹیگ == LIBCRUX_نتیجہ_OK) ? 0 : -1;
}
#جے_انت

فراغ
sha3_256(uint8_t digest[32], ثابت uint8_t *انکڑے, ناپ_t len)
{
	Eurydice_borrow_ٹکڑا_u8 داخلہ = { انکڑے, len };
	Eurydice_mut_borrow_ٹکڑا_u8 output = { digest, 32 };
	libcrux_sha3_portable_sha256(output, داخلہ);
}

فراغ
sha3_512(uint8_t digest[64], ثابت uint8_t *انکڑے, ناپ_t len)
{
	Eurydice_borrow_ٹکڑا_u8 داخلہ = { انکڑے, len };
	Eurydice_mut_borrow_ٹکڑا_u8 output = { digest, 64 };
	libcrux_sha3_portable_sha512(output, داخلہ);
}
#جے_انت /* defined(USE_MLDSA) || defined(USE_MLKEM768X25519) */
