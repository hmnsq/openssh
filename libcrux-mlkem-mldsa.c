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

#شامل "includes.h"

#اگر defined(USE_MLDSA) || defined(USE_MLKEM768X25519)

#شامل <sys/types.h>
#شامل <stdint.h>
#شامل <stdlib.h>
#شامل <stdbool.h>
#شامل <string.h>

#شامل "log.h"
#شامل "crypto_api.h"
#شامل "libcrux_internal.h"

/* ML-KEM 768 */

صحیح
crypto_kem_mlkem768_keypair(uint8_t pk[crypto_kem_mlkem768_PUBLICKEYBYTES],
    uint8_t sk[crypto_kem_mlkem768_SECRETKEYBYTES])
{
	uint8_t rnd[crypto_kem_mlkem768_KEYPAIRSEEDBYTES];
	صحیح r;

	arc4random_buf(rnd, حجم(rnd));
	r = crypto_kem_mlkem768_keypair_seeded(pk, sk, rnd);
	explicit_bzero(rnd, حجم(rnd));
	واپس r;
}

صحیح
crypto_kem_mlkem768_keypair_seeded(uint8_t pk[crypto_kem_mlkem768_PUBLICKEYBYTES],
    uint8_t sk[crypto_kem_mlkem768_SECRETKEYBYTES],
    ثابت uint8_t بیج[crypto_kem_mlkem768_KEYPAIRSEEDBYTES])
{
	libcrux_mlkem768_keypair keypair;
	libcrux_mlkem768_keypair_rnd rnd;

	حافظہ_نقل(rnd.ڈیٹا, بیج, حجم(rnd.ڈیٹا));
	keypair = libcrux_ml_kem_mlkem768_portable_generate_کلید_pair(rnd);
	حافظہ_نقل(pk, keypair.pk.ڈیٹا, crypto_kem_mlkem768_PUBLICKEYBYTES);
	حافظہ_نقل(sk, keypair.sk.ڈیٹا, crypto_kem_mlkem768_SECRETKEYBYTES);

	explicit_bzero(&keypair, حجم(keypair));
	explicit_bzero(&rnd, حجم(rnd));
	واپس 0;
}

صحیح
crypto_kem_mlkem768_enc(uint8_t ct[crypto_kem_mlkem768_CIPHERTEXTBYTES],
    uint8_t shared_secret[crypto_kem_mlkem768_بائٹیں],
    ثابت uint8_t pk[crypto_kem_mlkem768_PUBLICKEYBYTES])
{
	uint8_t rnd[crypto_kem_mlkem768_ENCSEEDBYTES];
	صحیح r;

	arc4random_buf(rnd, حجم(rnd));
	r = crypto_kem_mlkem768_enc_seeded(ct, shared_secret, pk, rnd);
	explicit_bzero(rnd, حجم(rnd));
	واپس r;
}

صحیح
crypto_kem_mlkem768_enc_seeded(uint8_t ct[crypto_kem_mlkem768_CIPHERTEXTBYTES],
    uint8_t shared_secret[crypto_kem_mlkem768_بائٹیں],
    ثابت uint8_t pk[crypto_kem_mlkem768_PUBLICKEYBYTES],
    ثابت uint8_t بیج[crypto_kem_mlkem768_ENCSEEDBYTES])
{
	libcrux_mlkem768_enc_نتیجہ enc;
	libcrux_mlkem768_pk pk_اندرونی;
	libcrux_mlkem768_enc_rnd rnd;

	حافظہ_نقل(pk_اندرونی.ڈیٹا, pk, crypto_kem_mlkem768_PUBLICKEYBYTES);
	اگر (!libcrux_ml_kem_mlkem768_portable_validate_عوامی_کلید(&pk_اندرونی))
		واپس -1;
	حافظہ_نقل(rnd.ڈیٹا, بیج, حجم(rnd.ڈیٹا));
	enc = libcrux_ml_kem_mlkem768_portable_encapsulate(&pk_اندرونی, rnd);
	حافظہ_نقل(ct, enc.fst.ڈیٹا, crypto_kem_mlkem768_CIPHERTEXTBYTES);
	حافظہ_نقل(shared_secret, enc.snd.ڈیٹا, crypto_kem_mlkem768_بائٹیں);

	explicit_bzero(&enc, حجم(enc));
	explicit_bzero(&rnd, حجم(rnd));
	واپس 0;
}

صحیح
crypto_kem_mlkem768_dec(uint8_t shared_secret[crypto_kem_mlkem768_بائٹیں],
    ثابت uint8_t ct[crypto_kem_mlkem768_CIPHERTEXTBYTES],
    ثابت uint8_t sk[crypto_kem_mlkem768_SECRETKEYBYTES])
{
	libcrux_mlkem768_sk sk_اندرونی;
	libcrux_mlkem768_ciphertext ct_اندرونی;
	libcrux_mlkem768_dec_نتیجہ shared_secret_اندرونی;

	حافظہ_نقل(sk_اندرونی.ڈیٹا, sk, crypto_kem_mlkem768_SECRETKEYBYTES);
	حافظہ_نقل(ct_اندرونی.ڈیٹا, ct, crypto_kem_mlkem768_CIPHERTEXTBYTES);
	shared_secret_اندرونی = libcrux_ml_kem_mlkem768_portable_decapsulate(
	    &sk_اندرونی, &ct_اندرونی);
	حافظہ_نقل(shared_secret, shared_secret_اندرونی.ڈیٹا,
	    crypto_kem_mlkem768_بائٹیں);

	explicit_bzero(&sk_اندرونی, حجم(sk_اندرونی));
	explicit_bzero(&shared_secret_اندرونی, حجم(shared_secret_اندرونی));
	واپس 0;
}

/* ML-DSA 44 */

صحیح
crypto_sign_mldsa44_keypair(uint8_t pk[MLDSA44_PUBLICKEYBYTES],
    uint8_t sk[MLDSA44_SECRETKEYBYTES])
{
	uint8_t rnd[MLDSA44_SEEDBYTES];
	صحیح r;

	arc4random_buf(rnd, حجم(rnd));
	r = crypto_sign_mldsa44_keypair_seeded(pk, sk, rnd);
	explicit_bzero(rnd, حجم(rnd));
	واپس r;
}

صحیح
crypto_sign_mldsa44_keypair_seeded(uint8_t pk[MLDSA44_PUBLICKEYBYTES],
    uint8_t sk[MLDSA44_SECRETKEYBYTES], ثابت uint8_t بیج[MLDSA44_SEEDBYTES])
{
	libcrux_mldsa44_keypair_rnd rnd;
	libcrux_mldsa44_keypair keypair;

	حافظہ_نقل(rnd.ڈیٹا, بیج, حجم(rnd.ڈیٹا));
	keypair = libcrux_ml_dsa_ml_dsa_44_portable_generate_کلید_pair(rnd);
	حافظہ_نقل(pk, keypair.verification_کلید.ڈیٹا, MLDSA44_PUBLICKEYBYTES);
	حافظہ_نقل(sk, keypair.signing_کلید.ڈیٹا, MLDSA44_SECRETKEYBYTES);

	explicit_bzero(&keypair, حجم(keypair));
	explicit_bzero(&rnd, حجم(rnd));
	واپس 0;
}

صحیح
crypto_sign_mldsa44(uint8_t sig[MLDSA44_SIGBYTES],
    ثابت uint8_t *پیغام, سائز_t msglen,
    ثابت uint8_t *ctx, سائز_t ctxlen,
    ثابت uint8_t sk[MLDSA44_SECRETKEYBYTES])
{
	uint8_t rnd[MLDSA44_SEEDBYTES];
	صحیح r;

	arc4random_buf(rnd, حجم(rnd));
	r = crypto_sign_mldsa44_seeded(sig, پیغام, msglen, ctx, ctxlen, sk, rnd);
	explicit_bzero(rnd, حجم(rnd));
	واپس r;
}

صحیح
crypto_sign_mldsa44_seeded(uint8_t sig[MLDSA44_SIGBYTES],
    ثابت uint8_t *پیغام, سائز_t msglen,
    ثابت uint8_t *ctx, سائز_t ctxlen,
    ثابت uint8_t sk[MLDSA44_SECRETKEYBYTES],
    ثابت uint8_t بیج[MLDSA44_SEEDBYTES])
{
	libcrux_mldsa44_sign_rnd rnd;
	libcrux_mldsa44_sk sk_اندرونی;
	libcrux_mldsa44_پیغام پیغام_2 = { پیغام, msglen };
	libcrux_mldsa44_پیغام context = { ctx, ctxlen };
	libcrux_mldsa44_sign_نتیجہ res;
	صحیح r = -1;

	حافظہ_نقل(sk_اندرونی.ڈیٹا, sk, MLDSA44_SECRETKEYBYTES);
	حافظہ_نقل(rnd.ڈیٹا, بیج, حجم(rnd.ڈیٹا));
	res = libcrux_ml_dsa_ml_dsa_44_portable_sign(&sk_اندرونی,
	    پیغام_2, context, rnd);
	اگر (res.لیبل == LIBCRUX_نتیجہ_OK) {
		حافظہ_نقل(sig, res.val.case_Ok.ڈیٹا, MLDSA44_SIGBYTES);
		r = 0;
	}

	explicit_bzero(&sk_اندرونی, حجم(sk_اندرونی));
	explicit_bzero(&res, حجم(res));
	explicit_bzero(&rnd, حجم(rnd));
	واپس r;
}

صحیح
crypto_sign_mldsa44_verify(ثابت uint8_t sig[MLDSA44_SIGBYTES],
    ثابت uint8_t *پیغام, سائز_t msglen,
    ثابت uint8_t *ctx, سائز_t ctxlen,
    ثابت uint8_t pk[MLDSA44_PUBLICKEYBYTES])
{
	libcrux_mldsa44_pk pk_اندرونی;
	libcrux_mldsa44_signature sig_اندرونی;
	libcrux_mldsa44_پیغام پیغام_2 = { پیغام, msglen };
	libcrux_mldsa44_پیغام context = { ctx, ctxlen };
	libcrux_mldsa44_verify_نتیجہ res;

	حافظہ_نقل(pk_اندرونی.ڈیٹا, pk, MLDSA44_PUBLICKEYBYTES);
	حافظہ_نقل(sig_اندرونی.ڈیٹا, sig, MLDSA44_SIGBYTES);
	res = libcrux_ml_dsa_ml_dsa_44_portable_verify(&pk_اندرونی,
	    پیغام_2, context, &sig_اندرونی);

	واپس (res.لیبل == LIBCRUX_نتیجہ_OK) ? 0 : -1;
}

/* ML-DSA 65 */

#اگر 0
صحیح
crypto_sign_mldsa65_keypair(uint8_t pk[MLDSA65_PUBLICKEYBYTES],
    uint8_t sk[MLDSA65_SECRETKEYBYTES])
{
	uint8_t rnd[MLDSA65_SEEDBYTES];
	صحیح r;

	arc4random_buf(rnd, حجم(rnd));
	r = crypto_sign_mldsa65_keypair_seeded(pk, sk, rnd);
	explicit_bzero(rnd, حجم(rnd));
	واپس r;
}

صحیح
crypto_sign_mldsa65_keypair_seeded(uint8_t pk[MLDSA65_PUBLICKEYBYTES],
    uint8_t sk[MLDSA65_SECRETKEYBYTES], ثابت uint8_t بیج[MLDSA65_SEEDBYTES])
{
	libcrux_mldsa65_keypair_rnd rnd;
	libcrux_mldsa65_keypair keypair;

	حافظہ_نقل(rnd.ڈیٹا, بیج, حجم(rnd.ڈیٹا));
	keypair = libcrux_ml_dsa_ml_dsa_65_portable_generate_کلید_pair(rnd);
	حافظہ_نقل(pk, keypair.verification_کلید.ڈیٹا, MLDSA65_PUBLICKEYBYTES);
	حافظہ_نقل(sk, keypair.signing_کلید.ڈیٹا, MLDSA65_SECRETKEYBYTES);

	explicit_bzero(&keypair, حجم(keypair));
	explicit_bzero(&rnd, حجم(rnd));
	واپس 0;
}

صحیح
crypto_sign_mldsa65(uint8_t sig[MLDSA65_SIGBYTES],
    ثابت uint8_t *پیغام, سائز_t msglen,
    ثابت uint8_t *ctx, سائز_t ctxlen,
    ثابت uint8_t sk[MLDSA65_SECRETKEYBYTES])
{
	uint8_t rnd[MLDSA65_SEEDBYTES];
	صحیح r;

	arc4random_buf(rnd, حجم(rnd));
	r = crypto_sign_mldsa65_seeded(sig, پیغام, msglen, ctx, ctxlen, sk, rnd);
	explicit_bzero(rnd, حجم(rnd));
	واپس r;
}

صحیح
crypto_sign_mldsa65_seeded(uint8_t sig[MLDSA65_SIGBYTES],
    ثابت uint8_t *پیغام, سائز_t msglen,
    ثابت uint8_t *ctx, سائز_t ctxlen,
    ثابت uint8_t sk[MLDSA65_SECRETKEYBYTES],
    ثابت uint8_t بیج[MLDSA65_SEEDBYTES])
{
	libcrux_mldsa65_sign_rnd rnd;
	libcrux_mldsa65_sk sk_اندرونی;
	libcrux_mldsa65_پیغام پیغام_2 = { پیغام, msglen };
	libcrux_mldsa65_پیغام context = { ctx, ctxlen };
	libcrux_mldsa65_sign_نتیجہ res;
	صحیح r = -1;

	حافظہ_نقل(sk_اندرونی.ڈیٹا, sk, MLDSA65_SECRETKEYBYTES);
	حافظہ_نقل(rnd.ڈیٹا, بیج, حجم(rnd.ڈیٹا));
	res = libcrux_ml_dsa_ml_dsa_65_portable_sign(&sk_اندرونی,
	    پیغام_2, context, rnd);
	اگر (res.لیبل == LIBCRUX_نتیجہ_OK) {
		حافظہ_نقل(sig, res.val.case_Ok.ڈیٹا, MLDSA65_SIGBYTES);
		r = 0;
	}

	explicit_bzero(&sk_اندرونی, حجم(sk_اندرونی));
	explicit_bzero(&res, حجم(res));
	explicit_bzero(&rnd, حجم(rnd));
	واپس r;
}

صحیح
crypto_sign_mldsa65_verify(ثابت uint8_t sig[MLDSA65_SIGBYTES],
    ثابت uint8_t *پیغام, سائز_t msglen,
    ثابت uint8_t *ctx, سائز_t ctxlen,
    ثابت uint8_t pk[MLDSA65_PUBLICKEYBYTES])
{
	libcrux_mldsa65_pk pk_اندرونی;
	libcrux_mldsa65_signature sig_اندرونی;
	libcrux_mldsa65_پیغام پیغام_2 = { پیغام, msglen };
	libcrux_mldsa65_پیغام context = { ctx, ctxlen };
	libcrux_mldsa65_verify_نتیجہ res;

	حافظہ_نقل(pk_اندرونی.ڈیٹا, pk, MLDSA65_PUBLICKEYBYTES);
	حافظہ_نقل(sig_اندرونی.ڈیٹا, sig, MLDSA65_SIGBYTES);
	res = libcrux_ml_dsa_ml_dsa_65_portable_verify(&pk_اندرونی,
	    پیغام_2, context, &sig_اندرونی);

	واپس (res.لیبل == LIBCRUX_نتیجہ_OK) ? 0 : -1;
}
#اگر_ختم

/* ML-DSA 87 */

#اگر 0
صحیح
crypto_sign_mldsa87_keypair(uint8_t pk[MLDSA87_PUBLICKEYBYTES],
    uint8_t sk[MLDSA87_SECRETKEYBYTES])
{
	uint8_t rnd[MLDSA87_SEEDBYTES];
	صحیح r;

	arc4random_buf(rnd, حجم(rnd));
	r = crypto_sign_mldsa87_keypair_seeded(pk, sk, rnd);
	explicit_bzero(rnd, حجم(rnd));
	واپس r;
}

صحیح
crypto_sign_mldsa87_keypair_seeded(uint8_t pk[MLDSA87_PUBLICKEYBYTES],
    uint8_t sk[MLDSA87_SECRETKEYBYTES], ثابت uint8_t بیج[MLDSA87_SEEDBYTES])
{
	libcrux_mldsa87_keypair_rnd rnd;
	libcrux_mldsa87_keypair keypair;

	حافظہ_نقل(rnd.ڈیٹا, بیج, حجم(rnd.ڈیٹا));
	keypair = libcrux_ml_dsa_ml_dsa_87_portable_generate_کلید_pair(rnd);
	حافظہ_نقل(pk, keypair.verification_کلید.ڈیٹا, MLDSA87_PUBLICKEYBYTES);
	حافظہ_نقل(sk, keypair.signing_کلید.ڈیٹا, MLDSA87_SECRETKEYBYTES);

	explicit_bzero(&keypair, حجم(keypair));
	explicit_bzero(&rnd, حجم(rnd));
	واپس 0;
}

صحیح
crypto_sign_mldsa87(uint8_t sig[MLDSA87_SIGBYTES],
    ثابت uint8_t *پیغام, سائز_t msglen,
    ثابت uint8_t *ctx, سائز_t ctxlen,
    ثابت uint8_t sk[MLDSA87_SECRETKEYBYTES])
{
	uint8_t rnd[MLDSA87_SEEDBYTES];
	صحیح r;

	arc4random_buf(rnd, حجم(rnd));
	r = crypto_sign_mldsa87_seeded(sig, پیغام, msglen, ctx, ctxlen, sk, rnd);
	explicit_bzero(rnd, حجم(rnd));
	واپس r;
}

صحیح
crypto_sign_mldsa87_seeded(uint8_t sig[MLDSA87_SIGBYTES],
    ثابت uint8_t *پیغام, سائز_t msglen,
    ثابت uint8_t *ctx, سائز_t ctxlen,
    ثابت uint8_t sk[MLDSA87_SECRETKEYBYTES],
    ثابت uint8_t بیج[MLDSA87_SEEDBYTES])
{
	libcrux_mldsa87_sign_rnd rnd;
	libcrux_mldsa87_sk sk_اندرونی;
	libcrux_mldsa87_پیغام پیغام_2 = { پیغام, msglen };
	libcrux_mldsa87_پیغام context = { ctx, ctxlen };
	libcrux_mldsa87_sign_نتیجہ res;
	صحیح r = -1;

	حافظہ_نقل(sk_اندرونی.ڈیٹا, sk, MLDSA87_SECRETKEYBYTES);
	حافظہ_نقل(rnd.ڈیٹا, بیج, حجم(rnd.ڈیٹا));
	res = libcrux_ml_dsa_ml_dsa_87_portable_sign(&sk_اندرونی,
	    پیغام_2, context, rnd);
	اگر (res.لیبل == LIBCRUX_نتیجہ_OK) {
		حافظہ_نقل(sig, res.val.case_Ok.ڈیٹا, MLDSA87_SIGBYTES);
		r = 0;
	}

	explicit_bzero(&sk_اندرونی, حجم(sk_اندرونی));
	explicit_bzero(&res, حجم(res));
	explicit_bzero(&rnd, حجم(rnd));
	واپس r;
}

صحیح
crypto_sign_mldsa87_verify(ثابت uint8_t sig[MLDSA87_SIGBYTES],
    ثابت uint8_t *پیغام, سائز_t msglen,
    ثابت uint8_t *ctx, سائز_t ctxlen,
    ثابت uint8_t pk[MLDSA87_PUBLICKEYBYTES])
{
	libcrux_mldsa87_pk pk_اندرونی;
	libcrux_mldsa87_signature sig_اندرونی;
	libcrux_mldsa87_پیغام پیغام_2 = { پیغام, msglen };
	libcrux_mldsa87_پیغام context = { ctx, ctxlen };
	libcrux_mldsa87_verify_نتیجہ res;

	حافظہ_نقل(pk_اندرونی.ڈیٹا, pk, MLDSA87_PUBLICKEYBYTES);
	حافظہ_نقل(sig_اندرونی.ڈیٹا, sig, MLDSA87_SIGBYTES);
	res = libcrux_ml_dsa_ml_dsa_87_portable_verify(&pk_اندرونی,
	    پیغام_2, context, &sig_اندرونی);

	واپس (res.لیبل == LIBCRUX_نتیجہ_OK) ? 0 : -1;
}
#اگر_ختم

خالی
sha3_256(uint8_t digest[32], ثابت uint8_t *ڈیٹا, سائز_t len)
{
	Eurydice_borrow_قاش_u8 داخلہ = { ڈیٹا, len };
	Eurydice_mut_borrow_قاش_u8 output = { digest, 32 };
	libcrux_sha3_portable_sha256(output, داخلہ);
}

خالی
sha3_512(uint8_t digest[64], ثابت uint8_t *ڈیٹا, سائز_t len)
{
	Eurydice_borrow_قاش_u8 داخلہ = { ڈیٹا, len };
	Eurydice_mut_borrow_قاش_u8 output = { digest, 64 };
	libcrux_sha3_portable_sha512(output, داخلہ);
}
#اگر_ختم /* defined(USE_MLDSA) || defined(USE_MLKEM768X25519) */
