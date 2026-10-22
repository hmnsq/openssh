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
    ثابت uint8_t ٻج[crypto_kem_mlkem768_KEYPAIRSEEDBYTES])
{
	libcrux_mlkem768_keypair keypair;
	libcrux_mlkem768_keypair_rnd rnd;

	يادگيري_نقل(rnd.معلومات, ٻج, حجم(rnd.معلومات));
	keypair = libcrux_ml_kem_mlkem768_portable_generate_ڪنجي_pair(rnd);
	يادگيري_نقل(pk, keypair.pk.معلومات, crypto_kem_mlkem768_PUBLICKEYBYTES);
	يادگيري_نقل(sk, keypair.sk.معلومات, crypto_kem_mlkem768_SECRETKEYBYTES);

	explicit_bzero(&keypair, حجم(keypair));
	explicit_bzero(&rnd, حجم(rnd));
	أرجع 0;
}

صحيح
crypto_kem_mlkem768_enc(uint8_t ct[crypto_kem_mlkem768_CIPHERTEXTBYTES],
    uint8_t shared_secret[crypto_kem_mlkem768_بائيٽون],
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
    uint8_t shared_secret[crypto_kem_mlkem768_بائيٽون],
    ثابت uint8_t pk[crypto_kem_mlkem768_PUBLICKEYBYTES],
    ثابت uint8_t ٻج[crypto_kem_mlkem768_ENCSEEDBYTES])
{
	libcrux_mlkem768_enc_نتيجو enc;
	libcrux_mlkem768_pk pk_اندروني;
	libcrux_mlkem768_enc_rnd rnd;

	يادگيري_نقل(pk_اندروني.معلومات, pk, crypto_kem_mlkem768_PUBLICKEYBYTES);
	إذا (!libcrux_ml_kem_mlkem768_portable_validate_عوامي_ڪنجي(&pk_اندروني))
		أرجع -1;
	يادگيري_نقل(rnd.معلومات, ٻج, حجم(rnd.معلومات));
	enc = libcrux_ml_kem_mlkem768_portable_encapsulate(&pk_اندروني, rnd);
	يادگيري_نقل(ct, enc.fst.معلومات, crypto_kem_mlkem768_CIPHERTEXTBYTES);
	يادگيري_نقل(shared_secret, enc.snd.معلومات, crypto_kem_mlkem768_بائيٽون);

	explicit_bzero(&enc, حجم(enc));
	explicit_bzero(&rnd, حجم(rnd));
	أرجع 0;
}

صحيح
crypto_kem_mlkem768_dec(uint8_t shared_secret[crypto_kem_mlkem768_بائيٽون],
    ثابت uint8_t ct[crypto_kem_mlkem768_CIPHERTEXTBYTES],
    ثابت uint8_t sk[crypto_kem_mlkem768_SECRETKEYBYTES])
{
	libcrux_mlkem768_sk sk_اندروني;
	libcrux_mlkem768_ciphertext ct_اندروني;
	libcrux_mlkem768_dec_نتيجو shared_secret_اندروني;

	يادگيري_نقل(sk_اندروني.معلومات, sk, crypto_kem_mlkem768_SECRETKEYBYTES);
	يادگيري_نقل(ct_اندروني.معلومات, ct, crypto_kem_mlkem768_CIPHERTEXTBYTES);
	shared_secret_اندروني = libcrux_ml_kem_mlkem768_portable_decapsulate(
	    &sk_اندروني, &ct_اندروني);
	يادگيري_نقل(shared_secret, shared_secret_اندروني.معلومات,
	    crypto_kem_mlkem768_بائيٽون);

	explicit_bzero(&sk_اندروني, حجم(sk_اندروني));
	explicit_bzero(&shared_secret_اندروني, حجم(shared_secret_اندروني));
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
    uint8_t sk[MLDSA44_SECRETKEYBYTES], ثابت uint8_t ٻج[MLDSA44_SEEDBYTES])
{
	libcrux_mldsa44_keypair_rnd rnd;
	libcrux_mldsa44_keypair keypair;

	يادگيري_نقل(rnd.معلومات, ٻج, حجم(rnd.معلومات));
	keypair = libcrux_ml_dsa_ml_dsa_44_portable_generate_ڪنجي_pair(rnd);
	يادگيري_نقل(pk, keypair.verification_ڪنجي.معلومات, MLDSA44_PUBLICKEYBYTES);
	يادگيري_نقل(sk, keypair.signing_ڪنجي.معلومات, MLDSA44_SECRETKEYBYTES);

	explicit_bzero(&keypair, حجم(keypair));
	explicit_bzero(&rnd, حجم(rnd));
	أرجع 0;
}

صحيح
crypto_sign_mldsa44(uint8_t sig[MLDSA44_SIGBYTES],
    ثابت uint8_t *نياپو, سائيز_t msglen,
    ثابت uint8_t *ctx, سائيز_t ctxlen,
    ثابت uint8_t sk[MLDSA44_SECRETKEYBYTES])
{
	uint8_t rnd[MLDSA44_SEEDBYTES];
	صحيح r;

	arc4random_buf(rnd, حجم(rnd));
	r = crypto_sign_mldsa44_seeded(sig, نياپو, msglen, ctx, ctxlen, sk, rnd);
	explicit_bzero(rnd, حجم(rnd));
	أرجع r;
}

صحيح
crypto_sign_mldsa44_seeded(uint8_t sig[MLDSA44_SIGBYTES],
    ثابت uint8_t *نياپو, سائيز_t msglen,
    ثابت uint8_t *ctx, سائيز_t ctxlen,
    ثابت uint8_t sk[MLDSA44_SECRETKEYBYTES],
    ثابت uint8_t ٻج[MLDSA44_SEEDBYTES])
{
	libcrux_mldsa44_sign_rnd rnd;
	libcrux_mldsa44_sk sk_اندروني;
	libcrux_mldsa44_پيغام پيغام = { نياپو, msglen };
	libcrux_mldsa44_پيغام context = { ctx, ctxlen };
	libcrux_mldsa44_sign_نتيجو res;
	صحيح r = -1;

	يادگيري_نقل(sk_اندروني.معلومات, sk, MLDSA44_SECRETKEYBYTES);
	يادگيري_نقل(rnd.معلومات, ٻج, حجم(rnd.معلومات));
	res = libcrux_ml_dsa_ml_dsa_44_portable_sign(&sk_اندروني,
	    پيغام, context, rnd);
	إذا (res.ٽيگ == LIBCRUX_نتيجو_OK) {
		يادگيري_نقل(sig, res.val.case_Ok.معلومات, MLDSA44_SIGBYTES);
		r = 0;
	}

	explicit_bzero(&sk_اندروني, حجم(sk_اندروني));
	explicit_bzero(&res, حجم(res));
	explicit_bzero(&rnd, حجم(rnd));
	أرجع r;
}

صحيح
crypto_sign_mldsa44_verify(ثابت uint8_t sig[MLDSA44_SIGBYTES],
    ثابت uint8_t *نياپو, سائيز_t msglen,
    ثابت uint8_t *ctx, سائيز_t ctxlen,
    ثابت uint8_t pk[MLDSA44_PUBLICKEYBYTES])
{
	libcrux_mldsa44_pk pk_اندروني;
	libcrux_mldsa44_signature sig_اندروني;
	libcrux_mldsa44_پيغام پيغام = { نياپو, msglen };
	libcrux_mldsa44_پيغام context = { ctx, ctxlen };
	libcrux_mldsa44_verify_نتيجو res;

	يادگيري_نقل(pk_اندروني.معلومات, pk, MLDSA44_PUBLICKEYBYTES);
	يادگيري_نقل(sig_اندروني.معلومات, sig, MLDSA44_SIGBYTES);
	res = libcrux_ml_dsa_ml_dsa_44_portable_verify(&pk_اندروني,
	    پيغام, context, &sig_اندروني);

	أرجع (res.ٽيگ == LIBCRUX_نتيجو_OK) ? 0 : -1;
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
    uint8_t sk[MLDSA65_SECRETKEYBYTES], ثابت uint8_t ٻج[MLDSA65_SEEDBYTES])
{
	libcrux_mldsa65_keypair_rnd rnd;
	libcrux_mldsa65_keypair keypair;

	يادگيري_نقل(rnd.معلومات, ٻج, حجم(rnd.معلومات));
	keypair = libcrux_ml_dsa_ml_dsa_65_portable_generate_ڪنجي_pair(rnd);
	يادگيري_نقل(pk, keypair.verification_ڪنجي.معلومات, MLDSA65_PUBLICKEYBYTES);
	يادگيري_نقل(sk, keypair.signing_ڪنجي.معلومات, MLDSA65_SECRETKEYBYTES);

	explicit_bzero(&keypair, حجم(keypair));
	explicit_bzero(&rnd, حجم(rnd));
	أرجع 0;
}

صحيح
crypto_sign_mldsa65(uint8_t sig[MLDSA65_SIGBYTES],
    ثابت uint8_t *نياپو, سائيز_t msglen,
    ثابت uint8_t *ctx, سائيز_t ctxlen,
    ثابت uint8_t sk[MLDSA65_SECRETKEYBYTES])
{
	uint8_t rnd[MLDSA65_SEEDBYTES];
	صحيح r;

	arc4random_buf(rnd, حجم(rnd));
	r = crypto_sign_mldsa65_seeded(sig, نياپو, msglen, ctx, ctxlen, sk, rnd);
	explicit_bzero(rnd, حجم(rnd));
	أرجع r;
}

صحيح
crypto_sign_mldsa65_seeded(uint8_t sig[MLDSA65_SIGBYTES],
    ثابت uint8_t *نياپو, سائيز_t msglen,
    ثابت uint8_t *ctx, سائيز_t ctxlen,
    ثابت uint8_t sk[MLDSA65_SECRETKEYBYTES],
    ثابت uint8_t ٻج[MLDSA65_SEEDBYTES])
{
	libcrux_mldsa65_sign_rnd rnd;
	libcrux_mldsa65_sk sk_اندروني;
	libcrux_mldsa65_پيغام پيغام = { نياپو, msglen };
	libcrux_mldsa65_پيغام context = { ctx, ctxlen };
	libcrux_mldsa65_sign_نتيجو res;
	صحيح r = -1;

	يادگيري_نقل(sk_اندروني.معلومات, sk, MLDSA65_SECRETKEYBYTES);
	يادگيري_نقل(rnd.معلومات, ٻج, حجم(rnd.معلومات));
	res = libcrux_ml_dsa_ml_dsa_65_portable_sign(&sk_اندروني,
	    پيغام, context, rnd);
	إذا (res.ٽيگ == LIBCRUX_نتيجو_OK) {
		يادگيري_نقل(sig, res.val.case_Ok.معلومات, MLDSA65_SIGBYTES);
		r = 0;
	}

	explicit_bzero(&sk_اندروني, حجم(sk_اندروني));
	explicit_bzero(&res, حجم(res));
	explicit_bzero(&rnd, حجم(rnd));
	أرجع r;
}

صحيح
crypto_sign_mldsa65_verify(ثابت uint8_t sig[MLDSA65_SIGBYTES],
    ثابت uint8_t *نياپو, سائيز_t msglen,
    ثابت uint8_t *ctx, سائيز_t ctxlen,
    ثابت uint8_t pk[MLDSA65_PUBLICKEYBYTES])
{
	libcrux_mldsa65_pk pk_اندروني;
	libcrux_mldsa65_signature sig_اندروني;
	libcrux_mldsa65_پيغام پيغام = { نياپو, msglen };
	libcrux_mldsa65_پيغام context = { ctx, ctxlen };
	libcrux_mldsa65_verify_نتيجو res;

	يادگيري_نقل(pk_اندروني.معلومات, pk, MLDSA65_PUBLICKEYBYTES);
	يادگيري_نقل(sig_اندروني.معلومات, sig, MLDSA65_SIGBYTES);
	res = libcrux_ml_dsa_ml_dsa_65_portable_verify(&pk_اندروني,
	    پيغام, context, &sig_اندروني);

	أرجع (res.ٽيگ == LIBCRUX_نتيجو_OK) ? 0 : -1;
}
#جيڪڏهن_پورو

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
    uint8_t sk[MLDSA87_SECRETKEYBYTES], ثابت uint8_t ٻج[MLDSA87_SEEDBYTES])
{
	libcrux_mldsa87_keypair_rnd rnd;
	libcrux_mldsa87_keypair keypair;

	يادگيري_نقل(rnd.معلومات, ٻج, حجم(rnd.معلومات));
	keypair = libcrux_ml_dsa_ml_dsa_87_portable_generate_ڪنجي_pair(rnd);
	يادگيري_نقل(pk, keypair.verification_ڪنجي.معلومات, MLDSA87_PUBLICKEYBYTES);
	يادگيري_نقل(sk, keypair.signing_ڪنجي.معلومات, MLDSA87_SECRETKEYBYTES);

	explicit_bzero(&keypair, حجم(keypair));
	explicit_bzero(&rnd, حجم(rnd));
	أرجع 0;
}

صحيح
crypto_sign_mldsa87(uint8_t sig[MLDSA87_SIGBYTES],
    ثابت uint8_t *نياپو, سائيز_t msglen,
    ثابت uint8_t *ctx, سائيز_t ctxlen,
    ثابت uint8_t sk[MLDSA87_SECRETKEYBYTES])
{
	uint8_t rnd[MLDSA87_SEEDBYTES];
	صحيح r;

	arc4random_buf(rnd, حجم(rnd));
	r = crypto_sign_mldsa87_seeded(sig, نياپو, msglen, ctx, ctxlen, sk, rnd);
	explicit_bzero(rnd, حجم(rnd));
	أرجع r;
}

صحيح
crypto_sign_mldsa87_seeded(uint8_t sig[MLDSA87_SIGBYTES],
    ثابت uint8_t *نياپو, سائيز_t msglen,
    ثابت uint8_t *ctx, سائيز_t ctxlen,
    ثابت uint8_t sk[MLDSA87_SECRETKEYBYTES],
    ثابت uint8_t ٻج[MLDSA87_SEEDBYTES])
{
	libcrux_mldsa87_sign_rnd rnd;
	libcrux_mldsa87_sk sk_اندروني;
	libcrux_mldsa87_پيغام پيغام = { نياپو, msglen };
	libcrux_mldsa87_پيغام context = { ctx, ctxlen };
	libcrux_mldsa87_sign_نتيجو res;
	صحيح r = -1;

	يادگيري_نقل(sk_اندروني.معلومات, sk, MLDSA87_SECRETKEYBYTES);
	يادگيري_نقل(rnd.معلومات, ٻج, حجم(rnd.معلومات));
	res = libcrux_ml_dsa_ml_dsa_87_portable_sign(&sk_اندروني,
	    پيغام, context, rnd);
	إذا (res.ٽيگ == LIBCRUX_نتيجو_OK) {
		يادگيري_نقل(sig, res.val.case_Ok.معلومات, MLDSA87_SIGBYTES);
		r = 0;
	}

	explicit_bzero(&sk_اندروني, حجم(sk_اندروني));
	explicit_bzero(&res, حجم(res));
	explicit_bzero(&rnd, حجم(rnd));
	أرجع r;
}

صحيح
crypto_sign_mldsa87_verify(ثابت uint8_t sig[MLDSA87_SIGBYTES],
    ثابت uint8_t *نياپو, سائيز_t msglen,
    ثابت uint8_t *ctx, سائيز_t ctxlen,
    ثابت uint8_t pk[MLDSA87_PUBLICKEYBYTES])
{
	libcrux_mldsa87_pk pk_اندروني;
	libcrux_mldsa87_signature sig_اندروني;
	libcrux_mldsa87_پيغام پيغام = { نياپو, msglen };
	libcrux_mldsa87_پيغام context = { ctx, ctxlen };
	libcrux_mldsa87_verify_نتيجو res;

	يادگيري_نقل(pk_اندروني.معلومات, pk, MLDSA87_PUBLICKEYBYTES);
	يادگيري_نقل(sig_اندروني.معلومات, sig, MLDSA87_SIGBYTES);
	res = libcrux_ml_dsa_ml_dsa_87_portable_verify(&pk_اندروني,
	    پيغام, context, &sig_اندروني);

	أرجع (res.ٽيگ == LIBCRUX_نتيجو_OK) ? 0 : -1;
}
#جيڪڏهن_پورو

فراغ
sha3_256(uint8_t digest[32], ثابت uint8_t *معلومات, سائيز_t len)
{
	Eurydice_borrow_ٽڪرو_u8 داخلا_2 = { معلومات, len };
	Eurydice_mut_borrow_ٽڪرو_u8 output = { digest, 32 };
	libcrux_sha3_portable_sha256(output, داخلا_2);
}

فراغ
sha3_512(uint8_t digest[64], ثابت uint8_t *معلومات, سائيز_t len)
{
	Eurydice_borrow_ٽڪرو_u8 داخلا_2 = { معلومات, len };
	Eurydice_mut_borrow_ٽڪرو_u8 output = { digest, 64 };
	libcrux_sha3_portable_sha512(output, داخلا_2);
}
#جيڪڏهن_پورو /* defined(USE_MLDSA) || defined(USE_MLKEM768X25519) */
