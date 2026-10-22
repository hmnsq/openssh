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
    ثابت uint8_t تخم[crypto_kem_mlkem768_KEYPAIRSEEDBYTES])
{
	libcrux_mlkem768_keypair keypair;
	libcrux_mlkem768_keypair_rnd rnd;

	حافظه_نقل(rnd.معلومات, تخم, حجم(rnd.معلومات));
	keypair = libcrux_ml_kem_mlkem768_portable_generate_کلی_pair(rnd);
	حافظه_نقل(pk, keypair.pk.معلومات, crypto_kem_mlkem768_PUBLICKEYBYTES);
	حافظه_نقل(sk, keypair.sk.معلومات, crypto_kem_mlkem768_SECRETKEYBYTES);

	explicit_bzero(&keypair, حجم(keypair));
	explicit_bzero(&rnd, حجم(rnd));
	أرجع 0;
}

صحيح
crypto_kem_mlkem768_enc(uint8_t ct[crypto_kem_mlkem768_CIPHERTEXTBYTES],
    uint8_t shared_secret[crypto_kem_mlkem768_بایټونه],
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
    uint8_t shared_secret[crypto_kem_mlkem768_بایټونه],
    ثابت uint8_t pk[crypto_kem_mlkem768_PUBLICKEYBYTES],
    ثابت uint8_t تخم[crypto_kem_mlkem768_ENCSEEDBYTES])
{
	libcrux_mlkem768_enc_پایله enc;
	libcrux_mlkem768_pk pk_دننی;
	libcrux_mlkem768_enc_rnd rnd;

	حافظه_نقل(pk_دننی.معلومات, pk, crypto_kem_mlkem768_PUBLICKEYBYTES);
	إذا (!libcrux_ml_kem_mlkem768_portable_validate_عامه_کلی(&pk_دننی))
		أرجع -1;
	حافظه_نقل(rnd.معلومات, تخم, حجم(rnd.معلومات));
	enc = libcrux_ml_kem_mlkem768_portable_encapsulate(&pk_دننی, rnd);
	حافظه_نقل(ct, enc.fst.معلومات, crypto_kem_mlkem768_CIPHERTEXTBYTES);
	حافظه_نقل(shared_secret, enc.snd.معلومات, crypto_kem_mlkem768_بایټونه);

	explicit_bzero(&enc, حجم(enc));
	explicit_bzero(&rnd, حجم(rnd));
	أرجع 0;
}

صحيح
crypto_kem_mlkem768_dec(uint8_t shared_secret[crypto_kem_mlkem768_بایټونه],
    ثابت uint8_t ct[crypto_kem_mlkem768_CIPHERTEXTBYTES],
    ثابت uint8_t sk[crypto_kem_mlkem768_SECRETKEYBYTES])
{
	libcrux_mlkem768_sk sk_دننی;
	libcrux_mlkem768_ciphertext ct_دننی;
	libcrux_mlkem768_dec_پایله shared_secret_دننی;

	حافظه_نقل(sk_دننی.معلومات, sk, crypto_kem_mlkem768_SECRETKEYBYTES);
	حافظه_نقل(ct_دننی.معلومات, ct, crypto_kem_mlkem768_CIPHERTEXTBYTES);
	shared_secret_دننی = libcrux_ml_kem_mlkem768_portable_decapsulate(
	    &sk_دننی, &ct_دننی);
	حافظه_نقل(shared_secret, shared_secret_دننی.معلومات,
	    crypto_kem_mlkem768_بایټونه);

	explicit_bzero(&sk_دننی, حجم(sk_دننی));
	explicit_bzero(&shared_secret_دننی, حجم(shared_secret_دننی));
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
    uint8_t sk[MLDSA44_SECRETKEYBYTES], ثابت uint8_t تخم[MLDSA44_SEEDBYTES])
{
	libcrux_mldsa44_keypair_rnd rnd;
	libcrux_mldsa44_keypair keypair;

	حافظه_نقل(rnd.معلومات, تخم, حجم(rnd.معلومات));
	keypair = libcrux_ml_dsa_ml_dsa_44_portable_generate_کلی_pair(rnd);
	حافظه_نقل(pk, keypair.verification_کلی.معلومات, MLDSA44_PUBLICKEYBYTES);
	حافظه_نقل(sk, keypair.signing_کلی.معلومات, MLDSA44_SECRETKEYBYTES);

	explicit_bzero(&keypair, حجم(keypair));
	explicit_bzero(&rnd, حجم(rnd));
	أرجع 0;
}

صحيح
crypto_sign_mldsa44(uint8_t sig[MLDSA44_SIGBYTES],
    ثابت uint8_t *پیغام, اندازه_t msglen,
    ثابت uint8_t *ctx, اندازه_t ctxlen,
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
    ثابت uint8_t *پیغام, اندازه_t msglen,
    ثابت uint8_t *ctx, اندازه_t ctxlen,
    ثابت uint8_t sk[MLDSA44_SECRETKEYBYTES],
    ثابت uint8_t تخم[MLDSA44_SEEDBYTES])
{
	libcrux_mldsa44_sign_rnd rnd;
	libcrux_mldsa44_sk sk_دننی;
	libcrux_mldsa44_پیغام پیغام_2 = { پیغام, msglen };
	libcrux_mldsa44_پیغام context = { ctx, ctxlen };
	libcrux_mldsa44_sign_پایله res;
	صحيح r = -1;

	حافظه_نقل(sk_دننی.معلومات, sk, MLDSA44_SECRETKEYBYTES);
	حافظه_نقل(rnd.معلومات, تخم, حجم(rnd.معلومات));
	res = libcrux_ml_dsa_ml_dsa_44_portable_sign(&sk_دننی,
	    پیغام_2, context, rnd);
	إذا (res.نښان == LIBCRUX_پایله_OK) {
		حافظه_نقل(sig, res.val.case_Ok.معلومات, MLDSA44_SIGBYTES);
		r = 0;
	}

	explicit_bzero(&sk_دننی, حجم(sk_دننی));
	explicit_bzero(&res, حجم(res));
	explicit_bzero(&rnd, حجم(rnd));
	أرجع r;
}

صحيح
crypto_sign_mldsa44_verify(ثابت uint8_t sig[MLDSA44_SIGBYTES],
    ثابت uint8_t *پیغام, اندازه_t msglen,
    ثابت uint8_t *ctx, اندازه_t ctxlen,
    ثابت uint8_t pk[MLDSA44_PUBLICKEYBYTES])
{
	libcrux_mldsa44_pk pk_دننی;
	libcrux_mldsa44_signature sig_دننی;
	libcrux_mldsa44_پیغام پیغام_2 = { پیغام, msglen };
	libcrux_mldsa44_پیغام context = { ctx, ctxlen };
	libcrux_mldsa44_verify_پایله res;

	حافظه_نقل(pk_دننی.معلومات, pk, MLDSA44_PUBLICKEYBYTES);
	حافظه_نقل(sig_دننی.معلومات, sig, MLDSA44_SIGBYTES);
	res = libcrux_ml_dsa_ml_dsa_44_portable_verify(&pk_دننی,
	    پیغام_2, context, &sig_دننی);

	أرجع (res.نښان == LIBCRUX_پایله_OK) ? 0 : -1;
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
    uint8_t sk[MLDSA65_SECRETKEYBYTES], ثابت uint8_t تخم[MLDSA65_SEEDBYTES])
{
	libcrux_mldsa65_keypair_rnd rnd;
	libcrux_mldsa65_keypair keypair;

	حافظه_نقل(rnd.معلومات, تخم, حجم(rnd.معلومات));
	keypair = libcrux_ml_dsa_ml_dsa_65_portable_generate_کلی_pair(rnd);
	حافظه_نقل(pk, keypair.verification_کلی.معلومات, MLDSA65_PUBLICKEYBYTES);
	حافظه_نقل(sk, keypair.signing_کلی.معلومات, MLDSA65_SECRETKEYBYTES);

	explicit_bzero(&keypair, حجم(keypair));
	explicit_bzero(&rnd, حجم(rnd));
	أرجع 0;
}

صحيح
crypto_sign_mldsa65(uint8_t sig[MLDSA65_SIGBYTES],
    ثابت uint8_t *پیغام, اندازه_t msglen,
    ثابت uint8_t *ctx, اندازه_t ctxlen,
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
    ثابت uint8_t *پیغام, اندازه_t msglen,
    ثابت uint8_t *ctx, اندازه_t ctxlen,
    ثابت uint8_t sk[MLDSA65_SECRETKEYBYTES],
    ثابت uint8_t تخم[MLDSA65_SEEDBYTES])
{
	libcrux_mldsa65_sign_rnd rnd;
	libcrux_mldsa65_sk sk_دننی;
	libcrux_mldsa65_پیغام پیغام_2 = { پیغام, msglen };
	libcrux_mldsa65_پیغام context = { ctx, ctxlen };
	libcrux_mldsa65_sign_پایله res;
	صحيح r = -1;

	حافظه_نقل(sk_دننی.معلومات, sk, MLDSA65_SECRETKEYBYTES);
	حافظه_نقل(rnd.معلومات, تخم, حجم(rnd.معلومات));
	res = libcrux_ml_dsa_ml_dsa_65_portable_sign(&sk_دننی,
	    پیغام_2, context, rnd);
	إذا (res.نښان == LIBCRUX_پایله_OK) {
		حافظه_نقل(sig, res.val.case_Ok.معلومات, MLDSA65_SIGBYTES);
		r = 0;
	}

	explicit_bzero(&sk_دننی, حجم(sk_دننی));
	explicit_bzero(&res, حجم(res));
	explicit_bzero(&rnd, حجم(rnd));
	أرجع r;
}

صحيح
crypto_sign_mldsa65_verify(ثابت uint8_t sig[MLDSA65_SIGBYTES],
    ثابت uint8_t *پیغام, اندازه_t msglen,
    ثابت uint8_t *ctx, اندازه_t ctxlen,
    ثابت uint8_t pk[MLDSA65_PUBLICKEYBYTES])
{
	libcrux_mldsa65_pk pk_دننی;
	libcrux_mldsa65_signature sig_دننی;
	libcrux_mldsa65_پیغام پیغام_2 = { پیغام, msglen };
	libcrux_mldsa65_پیغام context = { ctx, ctxlen };
	libcrux_mldsa65_verify_پایله res;

	حافظه_نقل(pk_دننی.معلومات, pk, MLDSA65_PUBLICKEYBYTES);
	حافظه_نقل(sig_دننی.معلومات, sig, MLDSA65_SIGBYTES);
	res = libcrux_ml_dsa_ml_dsa_65_portable_verify(&pk_دننی,
	    پیغام_2, context, &sig_دننی);

	أرجع (res.نښان == LIBCRUX_پایله_OK) ? 0 : -1;
}
#د_که_پای

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
    uint8_t sk[MLDSA87_SECRETKEYBYTES], ثابت uint8_t تخم[MLDSA87_SEEDBYTES])
{
	libcrux_mldsa87_keypair_rnd rnd;
	libcrux_mldsa87_keypair keypair;

	حافظه_نقل(rnd.معلومات, تخم, حجم(rnd.معلومات));
	keypair = libcrux_ml_dsa_ml_dsa_87_portable_generate_کلی_pair(rnd);
	حافظه_نقل(pk, keypair.verification_کلی.معلومات, MLDSA87_PUBLICKEYBYTES);
	حافظه_نقل(sk, keypair.signing_کلی.معلومات, MLDSA87_SECRETKEYBYTES);

	explicit_bzero(&keypair, حجم(keypair));
	explicit_bzero(&rnd, حجم(rnd));
	أرجع 0;
}

صحيح
crypto_sign_mldsa87(uint8_t sig[MLDSA87_SIGBYTES],
    ثابت uint8_t *پیغام, اندازه_t msglen,
    ثابت uint8_t *ctx, اندازه_t ctxlen,
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
    ثابت uint8_t *پیغام, اندازه_t msglen,
    ثابت uint8_t *ctx, اندازه_t ctxlen,
    ثابت uint8_t sk[MLDSA87_SECRETKEYBYTES],
    ثابت uint8_t تخم[MLDSA87_SEEDBYTES])
{
	libcrux_mldsa87_sign_rnd rnd;
	libcrux_mldsa87_sk sk_دننی;
	libcrux_mldsa87_پیغام پیغام_2 = { پیغام, msglen };
	libcrux_mldsa87_پیغام context = { ctx, ctxlen };
	libcrux_mldsa87_sign_پایله res;
	صحيح r = -1;

	حافظه_نقل(sk_دننی.معلومات, sk, MLDSA87_SECRETKEYBYTES);
	حافظه_نقل(rnd.معلومات, تخم, حجم(rnd.معلومات));
	res = libcrux_ml_dsa_ml_dsa_87_portable_sign(&sk_دننی,
	    پیغام_2, context, rnd);
	إذا (res.نښان == LIBCRUX_پایله_OK) {
		حافظه_نقل(sig, res.val.case_Ok.معلومات, MLDSA87_SIGBYTES);
		r = 0;
	}

	explicit_bzero(&sk_دننی, حجم(sk_دننی));
	explicit_bzero(&res, حجم(res));
	explicit_bzero(&rnd, حجم(rnd));
	أرجع r;
}

صحيح
crypto_sign_mldsa87_verify(ثابت uint8_t sig[MLDSA87_SIGBYTES],
    ثابت uint8_t *پیغام, اندازه_t msglen,
    ثابت uint8_t *ctx, اندازه_t ctxlen,
    ثابت uint8_t pk[MLDSA87_PUBLICKEYBYTES])
{
	libcrux_mldsa87_pk pk_دننی;
	libcrux_mldsa87_signature sig_دننی;
	libcrux_mldsa87_پیغام پیغام_2 = { پیغام, msglen };
	libcrux_mldsa87_پیغام context = { ctx, ctxlen };
	libcrux_mldsa87_verify_پایله res;

	حافظه_نقل(pk_دننی.معلومات, pk, MLDSA87_PUBLICKEYBYTES);
	حافظه_نقل(sig_دننی.معلومات, sig, MLDSA87_SIGBYTES);
	res = libcrux_ml_dsa_ml_dsa_87_portable_verify(&pk_دننی,
	    پیغام_2, context, &sig_دننی);

	أرجع (res.نښان == LIBCRUX_پایله_OK) ? 0 : -1;
}
#د_که_پای

فراغ
sha3_256(uint8_t digest[32], ثابت uint8_t *معلومات, اندازه_t len)
{
	Eurydice_borrow_ټوټه_u8 ننوت = { معلومات, len };
	Eurydice_mut_borrow_ټوټه_u8 output = { digest, 32 };
	libcrux_sha3_portable_sha256(output, ننوت);
}

فراغ
sha3_512(uint8_t digest[64], ثابت uint8_t *معلومات, اندازه_t len)
{
	Eurydice_borrow_ټوټه_u8 ننوت = { معلومات, len };
	Eurydice_mut_borrow_ټوټه_u8 output = { digest, 64 };
	libcrux_sha3_portable_sha512(output, ننوت);
}
#د_که_پای /* defined(USE_MLDSA) || defined(USE_MLKEM768X25519) */
