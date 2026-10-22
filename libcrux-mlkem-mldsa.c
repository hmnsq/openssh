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
    ثابت uint8_t دانه[crypto_kem_mlkem768_KEYPAIRSEEDBYTES])
{
	libcrux_mlkem768_keypair keypair;
	libcrux_mlkem768_keypair_rnd rnd;

	کپی_حافظه(rnd.داده, دانه, حجم(rnd.داده));
	keypair = libcrux_ml_kem_mlkem768_portable_generate_کلید_pair(rnd);
	کپی_حافظه(pk, keypair.pk.داده, crypto_kem_mlkem768_PUBLICKEYBYTES);
	کپی_حافظه(sk, keypair.sk.داده, crypto_kem_mlkem768_SECRETKEYBYTES);

	explicit_bzero(&keypair, حجم(keypair));
	explicit_bzero(&rnd, حجم(rnd));
	أرجع 0;
}

صحيح
crypto_kem_mlkem768_enc(uint8_t ct[crypto_kem_mlkem768_CIPHERTEXTBYTES],
    uint8_t shared_secret[crypto_kem_mlkem768_بایتها],
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
    uint8_t shared_secret[crypto_kem_mlkem768_بایتها],
    ثابت uint8_t pk[crypto_kem_mlkem768_PUBLICKEYBYTES],
    ثابت uint8_t دانه[crypto_kem_mlkem768_ENCSEEDBYTES])
{
	libcrux_mlkem768_enc_نتیجه enc;
	libcrux_mlkem768_pk pk_داخلی;
	libcrux_mlkem768_enc_rnd rnd;

	کپی_حافظه(pk_داخلی.داده, pk, crypto_kem_mlkem768_PUBLICKEYBYTES);
	إذا (!libcrux_ml_kem_mlkem768_portable_validate_عمومی_کلید(&pk_داخلی))
		أرجع -1;
	کپی_حافظه(rnd.داده, دانه, حجم(rnd.داده));
	enc = libcrux_ml_kem_mlkem768_portable_encapsulate(&pk_داخلی, rnd);
	کپی_حافظه(ct, enc.fst.داده, crypto_kem_mlkem768_CIPHERTEXTBYTES);
	کپی_حافظه(shared_secret, enc.snd.داده, crypto_kem_mlkem768_بایتها);

	explicit_bzero(&enc, حجم(enc));
	explicit_bzero(&rnd, حجم(rnd));
	أرجع 0;
}

صحيح
crypto_kem_mlkem768_dec(uint8_t shared_secret[crypto_kem_mlkem768_بایتها],
    ثابت uint8_t ct[crypto_kem_mlkem768_CIPHERTEXTBYTES],
    ثابت uint8_t sk[crypto_kem_mlkem768_SECRETKEYBYTES])
{
	libcrux_mlkem768_sk sk_داخلی;
	libcrux_mlkem768_ciphertext ct_داخلی;
	libcrux_mlkem768_dec_نتیجه shared_secret_داخلی;

	کپی_حافظه(sk_داخلی.داده, sk, crypto_kem_mlkem768_SECRETKEYBYTES);
	کپی_حافظه(ct_داخلی.داده, ct, crypto_kem_mlkem768_CIPHERTEXTBYTES);
	shared_secret_داخلی = libcrux_ml_kem_mlkem768_portable_decapsulate(
	    &sk_داخلی, &ct_داخلی);
	کپی_حافظه(shared_secret, shared_secret_داخلی.داده,
	    crypto_kem_mlkem768_بایتها);

	explicit_bzero(&sk_داخلی, حجم(sk_داخلی));
	explicit_bzero(&shared_secret_داخلی, حجم(shared_secret_داخلی));
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
    uint8_t sk[MLDSA44_SECRETKEYBYTES], ثابت uint8_t دانه[MLDSA44_SEEDBYTES])
{
	libcrux_mldsa44_keypair_rnd rnd;
	libcrux_mldsa44_keypair keypair;

	کپی_حافظه(rnd.داده, دانه, حجم(rnd.داده));
	keypair = libcrux_ml_dsa_ml_dsa_44_portable_generate_کلید_pair(rnd);
	کپی_حافظه(pk, keypair.verification_کلید.داده, MLDSA44_PUBLICKEYBYTES);
	کپی_حافظه(sk, keypair.signing_کلید.داده, MLDSA44_SECRETKEYBYTES);

	explicit_bzero(&keypair, حجم(keypair));
	explicit_bzero(&rnd, حجم(rnd));
	أرجع 0;
}

صحيح
crypto_sign_mldsa44(uint8_t sig[MLDSA44_SIGBYTES],
    ثابت uint8_t *پیام, اندازه_t msglen,
    ثابت uint8_t *ctx, اندازه_t ctxlen,
    ثابت uint8_t sk[MLDSA44_SECRETKEYBYTES])
{
	uint8_t rnd[MLDSA44_SEEDBYTES];
	صحيح r;

	arc4random_buf(rnd, حجم(rnd));
	r = crypto_sign_mldsa44_seeded(sig, پیام, msglen, ctx, ctxlen, sk, rnd);
	explicit_bzero(rnd, حجم(rnd));
	أرجع r;
}

صحيح
crypto_sign_mldsa44_seeded(uint8_t sig[MLDSA44_SIGBYTES],
    ثابت uint8_t *پیام, اندازه_t msglen,
    ثابت uint8_t *ctx, اندازه_t ctxlen,
    ثابت uint8_t sk[MLDSA44_SECRETKEYBYTES],
    ثابت uint8_t دانه[MLDSA44_SEEDBYTES])
{
	libcrux_mldsa44_sign_rnd rnd;
	libcrux_mldsa44_sk sk_داخلی;
	libcrux_mldsa44_پیام پیام_2 = { پیام, msglen };
	libcrux_mldsa44_پیام context = { ctx, ctxlen };
	libcrux_mldsa44_sign_نتیجه res;
	صحيح r = -1;

	کپی_حافظه(sk_داخلی.داده, sk, MLDSA44_SECRETKEYBYTES);
	کپی_حافظه(rnd.داده, دانه, حجم(rnd.داده));
	res = libcrux_ml_dsa_ml_dsa_44_portable_sign(&sk_داخلی,
	    پیام_2, context, rnd);
	إذا (res.برچسب == LIBCRUX_نتیجه_OK) {
		کپی_حافظه(sig, res.val.case_Ok.داده, MLDSA44_SIGBYTES);
		r = 0;
	}

	explicit_bzero(&sk_داخلی, حجم(sk_داخلی));
	explicit_bzero(&res, حجم(res));
	explicit_bzero(&rnd, حجم(rnd));
	أرجع r;
}

صحيح
crypto_sign_mldsa44_verify(ثابت uint8_t sig[MLDSA44_SIGBYTES],
    ثابت uint8_t *پیام, اندازه_t msglen,
    ثابت uint8_t *ctx, اندازه_t ctxlen,
    ثابت uint8_t pk[MLDSA44_PUBLICKEYBYTES])
{
	libcrux_mldsa44_pk pk_داخلی;
	libcrux_mldsa44_signature sig_داخلی;
	libcrux_mldsa44_پیام پیام_2 = { پیام, msglen };
	libcrux_mldsa44_پیام context = { ctx, ctxlen };
	libcrux_mldsa44_verify_نتیجه res;

	کپی_حافظه(pk_داخلی.داده, pk, MLDSA44_PUBLICKEYBYTES);
	کپی_حافظه(sig_داخلی.داده, sig, MLDSA44_SIGBYTES);
	res = libcrux_ml_dsa_ml_dsa_44_portable_verify(&pk_داخلی,
	    پیام_2, context, &sig_داخلی);

	أرجع (res.برچسب == LIBCRUX_نتیجه_OK) ? 0 : -1;
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
    uint8_t sk[MLDSA65_SECRETKEYBYTES], ثابت uint8_t دانه[MLDSA65_SEEDBYTES])
{
	libcrux_mldsa65_keypair_rnd rnd;
	libcrux_mldsa65_keypair keypair;

	کپی_حافظه(rnd.داده, دانه, حجم(rnd.داده));
	keypair = libcrux_ml_dsa_ml_dsa_65_portable_generate_کلید_pair(rnd);
	کپی_حافظه(pk, keypair.verification_کلید.داده, MLDSA65_PUBLICKEYBYTES);
	کپی_حافظه(sk, keypair.signing_کلید.داده, MLDSA65_SECRETKEYBYTES);

	explicit_bzero(&keypair, حجم(keypair));
	explicit_bzero(&rnd, حجم(rnd));
	أرجع 0;
}

صحيح
crypto_sign_mldsa65(uint8_t sig[MLDSA65_SIGBYTES],
    ثابت uint8_t *پیام, اندازه_t msglen,
    ثابت uint8_t *ctx, اندازه_t ctxlen,
    ثابت uint8_t sk[MLDSA65_SECRETKEYBYTES])
{
	uint8_t rnd[MLDSA65_SEEDBYTES];
	صحيح r;

	arc4random_buf(rnd, حجم(rnd));
	r = crypto_sign_mldsa65_seeded(sig, پیام, msglen, ctx, ctxlen, sk, rnd);
	explicit_bzero(rnd, حجم(rnd));
	أرجع r;
}

صحيح
crypto_sign_mldsa65_seeded(uint8_t sig[MLDSA65_SIGBYTES],
    ثابت uint8_t *پیام, اندازه_t msglen,
    ثابت uint8_t *ctx, اندازه_t ctxlen,
    ثابت uint8_t sk[MLDSA65_SECRETKEYBYTES],
    ثابت uint8_t دانه[MLDSA65_SEEDBYTES])
{
	libcrux_mldsa65_sign_rnd rnd;
	libcrux_mldsa65_sk sk_داخلی;
	libcrux_mldsa65_پیام پیام_2 = { پیام, msglen };
	libcrux_mldsa65_پیام context = { ctx, ctxlen };
	libcrux_mldsa65_sign_نتیجه res;
	صحيح r = -1;

	کپی_حافظه(sk_داخلی.داده, sk, MLDSA65_SECRETKEYBYTES);
	کپی_حافظه(rnd.داده, دانه, حجم(rnd.داده));
	res = libcrux_ml_dsa_ml_dsa_65_portable_sign(&sk_داخلی,
	    پیام_2, context, rnd);
	إذا (res.برچسب == LIBCRUX_نتیجه_OK) {
		کپی_حافظه(sig, res.val.case_Ok.داده, MLDSA65_SIGBYTES);
		r = 0;
	}

	explicit_bzero(&sk_داخلی, حجم(sk_داخلی));
	explicit_bzero(&res, حجم(res));
	explicit_bzero(&rnd, حجم(rnd));
	أرجع r;
}

صحيح
crypto_sign_mldsa65_verify(ثابت uint8_t sig[MLDSA65_SIGBYTES],
    ثابت uint8_t *پیام, اندازه_t msglen,
    ثابت uint8_t *ctx, اندازه_t ctxlen,
    ثابت uint8_t pk[MLDSA65_PUBLICKEYBYTES])
{
	libcrux_mldsa65_pk pk_داخلی;
	libcrux_mldsa65_signature sig_داخلی;
	libcrux_mldsa65_پیام پیام_2 = { پیام, msglen };
	libcrux_mldsa65_پیام context = { ctx, ctxlen };
	libcrux_mldsa65_verify_نتیجه res;

	کپی_حافظه(pk_داخلی.داده, pk, MLDSA65_PUBLICKEYBYTES);
	کپی_حافظه(sig_داخلی.داده, sig, MLDSA65_SIGBYTES);
	res = libcrux_ml_dsa_ml_dsa_65_portable_verify(&pk_داخلی,
	    پیام_2, context, &sig_داخلی);

	أرجع (res.برچسب == LIBCRUX_نتیجه_OK) ? 0 : -1;
}
#پایان_اگر

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
    uint8_t sk[MLDSA87_SECRETKEYBYTES], ثابت uint8_t دانه[MLDSA87_SEEDBYTES])
{
	libcrux_mldsa87_keypair_rnd rnd;
	libcrux_mldsa87_keypair keypair;

	کپی_حافظه(rnd.داده, دانه, حجم(rnd.داده));
	keypair = libcrux_ml_dsa_ml_dsa_87_portable_generate_کلید_pair(rnd);
	کپی_حافظه(pk, keypair.verification_کلید.داده, MLDSA87_PUBLICKEYBYTES);
	کپی_حافظه(sk, keypair.signing_کلید.داده, MLDSA87_SECRETKEYBYTES);

	explicit_bzero(&keypair, حجم(keypair));
	explicit_bzero(&rnd, حجم(rnd));
	أرجع 0;
}

صحيح
crypto_sign_mldsa87(uint8_t sig[MLDSA87_SIGBYTES],
    ثابت uint8_t *پیام, اندازه_t msglen,
    ثابت uint8_t *ctx, اندازه_t ctxlen,
    ثابت uint8_t sk[MLDSA87_SECRETKEYBYTES])
{
	uint8_t rnd[MLDSA87_SEEDBYTES];
	صحيح r;

	arc4random_buf(rnd, حجم(rnd));
	r = crypto_sign_mldsa87_seeded(sig, پیام, msglen, ctx, ctxlen, sk, rnd);
	explicit_bzero(rnd, حجم(rnd));
	أرجع r;
}

صحيح
crypto_sign_mldsa87_seeded(uint8_t sig[MLDSA87_SIGBYTES],
    ثابت uint8_t *پیام, اندازه_t msglen,
    ثابت uint8_t *ctx, اندازه_t ctxlen,
    ثابت uint8_t sk[MLDSA87_SECRETKEYBYTES],
    ثابت uint8_t دانه[MLDSA87_SEEDBYTES])
{
	libcrux_mldsa87_sign_rnd rnd;
	libcrux_mldsa87_sk sk_داخلی;
	libcrux_mldsa87_پیام پیام_2 = { پیام, msglen };
	libcrux_mldsa87_پیام context = { ctx, ctxlen };
	libcrux_mldsa87_sign_نتیجه res;
	صحيح r = -1;

	کپی_حافظه(sk_داخلی.داده, sk, MLDSA87_SECRETKEYBYTES);
	کپی_حافظه(rnd.داده, دانه, حجم(rnd.داده));
	res = libcrux_ml_dsa_ml_dsa_87_portable_sign(&sk_داخلی,
	    پیام_2, context, rnd);
	إذا (res.برچسب == LIBCRUX_نتیجه_OK) {
		کپی_حافظه(sig, res.val.case_Ok.داده, MLDSA87_SIGBYTES);
		r = 0;
	}

	explicit_bzero(&sk_داخلی, حجم(sk_داخلی));
	explicit_bzero(&res, حجم(res));
	explicit_bzero(&rnd, حجم(rnd));
	أرجع r;
}

صحيح
crypto_sign_mldsa87_verify(ثابت uint8_t sig[MLDSA87_SIGBYTES],
    ثابت uint8_t *پیام, اندازه_t msglen,
    ثابت uint8_t *ctx, اندازه_t ctxlen,
    ثابت uint8_t pk[MLDSA87_PUBLICKEYBYTES])
{
	libcrux_mldsa87_pk pk_داخلی;
	libcrux_mldsa87_signature sig_داخلی;
	libcrux_mldsa87_پیام پیام_2 = { پیام, msglen };
	libcrux_mldsa87_پیام context = { ctx, ctxlen };
	libcrux_mldsa87_verify_نتیجه res;

	کپی_حافظه(pk_داخلی.داده, pk, MLDSA87_PUBLICKEYBYTES);
	کپی_حافظه(sig_داخلی.داده, sig, MLDSA87_SIGBYTES);
	res = libcrux_ml_dsa_ml_dsa_87_portable_verify(&pk_داخلی,
	    پیام_2, context, &sig_داخلی);

	أرجع (res.برچسب == LIBCRUX_نتیجه_OK) ? 0 : -1;
}
#پایان_اگر

فراغ
sha3_256(uint8_t digest[32], ثابت uint8_t *داده, اندازه_t len)
{
	Eurydice_borrow_برش_u8 درون_داد = { داده, len };
	Eurydice_mut_borrow_برش_u8 output = { digest, 32 };
	libcrux_sha3_portable_sha256(output, درون_داد);
}

فراغ
sha3_512(uint8_t digest[64], ثابت uint8_t *داده, اندازه_t len)
{
	Eurydice_borrow_برش_u8 درون_داد = { داده, len };
	Eurydice_mut_borrow_برش_u8 output = { digest, 64 };
	libcrux_sha3_portable_sha512(output, درون_داد);
}
#پایان_اگر /* defined(USE_MLDSA) || defined(USE_MLKEM768X25519) */
