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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਜੇ defined(USE_MLDSA) || defined(USE_MLKEM768X25519)

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdint.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdbool.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "crypto_api.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "libcrux_internal.h"

/* ML-KEM 768 */

ਪੂਰਨ
crypto_kem_mlkem768_keypair(uint8_t pk[crypto_kem_mlkem768_PUBLICKEYBYTES],
    uint8_t sk[crypto_kem_mlkem768_SECRETKEYBYTES])
{
	uint8_t rnd[crypto_kem_mlkem768_KEYPAIRSEEDBYTES];
	ਪੂਰਨ r;

	arc4random_buf(rnd, ਆਕਾਰ(rnd));
	r = crypto_kem_mlkem768_keypair_seeded(pk, sk, rnd);
	explicit_bzero(rnd, ਆਕਾਰ(rnd));
	ਵਾਪਸ r;
}

ਪੂਰਨ
crypto_kem_mlkem768_keypair_seeded(uint8_t pk[crypto_kem_mlkem768_PUBLICKEYBYTES],
    uint8_t sk[crypto_kem_mlkem768_SECRETKEYBYTES],
    ਅਚਲ uint8_t ਬੀਜ[crypto_kem_mlkem768_KEYPAIRSEEDBYTES])
{
	libcrux_mlkem768_keypair keypair;
	libcrux_mlkem768_keypair_rnd rnd;

	ਸਮ੍ਰਿਤੀ_ਨਕਲ(rnd.ਅੰਕੜੇ, ਬੀਜ, ਆਕਾਰ(rnd.ਅੰਕੜੇ));
	keypair = libcrux_ml_kem_mlkem768_portable_generate_ਕੁੰਜੀ_pair(rnd);
	ਸਮ੍ਰਿਤੀ_ਨਕਲ(pk, keypair.pk.ਅੰਕੜੇ, crypto_kem_mlkem768_PUBLICKEYBYTES);
	ਸਮ੍ਰਿਤੀ_ਨਕਲ(sk, keypair.sk.ਅੰਕੜੇ, crypto_kem_mlkem768_SECRETKEYBYTES);

	explicit_bzero(&keypair, ਆਕਾਰ(keypair));
	explicit_bzero(&rnd, ਆਕਾਰ(rnd));
	ਵਾਪਸ 0;
}

ਪੂਰਨ
crypto_kem_mlkem768_enc(uint8_t ct[crypto_kem_mlkem768_CIPHERTEXTBYTES],
    uint8_t shared_secret[crypto_kem_mlkem768_ਬਾਈਟਾਂ],
    ਅਚਲ uint8_t pk[crypto_kem_mlkem768_PUBLICKEYBYTES])
{
	uint8_t rnd[crypto_kem_mlkem768_ENCSEEDBYTES];
	ਪੂਰਨ r;

	arc4random_buf(rnd, ਆਕਾਰ(rnd));
	r = crypto_kem_mlkem768_enc_seeded(ct, shared_secret, pk, rnd);
	explicit_bzero(rnd, ਆਕਾਰ(rnd));
	ਵਾਪਸ r;
}

ਪੂਰਨ
crypto_kem_mlkem768_enc_seeded(uint8_t ct[crypto_kem_mlkem768_CIPHERTEXTBYTES],
    uint8_t shared_secret[crypto_kem_mlkem768_ਬਾਈਟਾਂ],
    ਅਚਲ uint8_t pk[crypto_kem_mlkem768_PUBLICKEYBYTES],
    ਅਚਲ uint8_t ਬੀਜ[crypto_kem_mlkem768_ENCSEEDBYTES])
{
	libcrux_mlkem768_enc_ਨਤੀਜਾ enc;
	libcrux_mlkem768_pk pk_ਅੰਦਰੂਨੀ;
	libcrux_mlkem768_enc_rnd rnd;

	ਸਮ੍ਰਿਤੀ_ਨਕਲ(pk_ਅੰਦਰੂਨੀ.ਅੰਕੜੇ, pk, crypto_kem_mlkem768_PUBLICKEYBYTES);
	ਜੇ (!libcrux_ml_kem_mlkem768_portable_validate_ਜਨਤਕ_ਕੁੰਜੀ(&pk_ਅੰਦਰੂਨੀ))
		ਵਾਪਸ -1;
	ਸਮ੍ਰਿਤੀ_ਨਕਲ(rnd.ਅੰਕੜੇ, ਬੀਜ, ਆਕਾਰ(rnd.ਅੰਕੜੇ));
	enc = libcrux_ml_kem_mlkem768_portable_encapsulate(&pk_ਅੰਦਰੂਨੀ, rnd);
	ਸਮ੍ਰਿਤੀ_ਨਕਲ(ct, enc.fst.ਅੰਕੜੇ, crypto_kem_mlkem768_CIPHERTEXTBYTES);
	ਸਮ੍ਰਿਤੀ_ਨਕਲ(shared_secret, enc.snd.ਅੰਕੜੇ, crypto_kem_mlkem768_ਬਾਈਟਾਂ);

	explicit_bzero(&enc, ਆਕਾਰ(enc));
	explicit_bzero(&rnd, ਆਕਾਰ(rnd));
	ਵਾਪਸ 0;
}

ਪੂਰਨ
crypto_kem_mlkem768_dec(uint8_t shared_secret[crypto_kem_mlkem768_ਬਾਈਟਾਂ],
    ਅਚਲ uint8_t ct[crypto_kem_mlkem768_CIPHERTEXTBYTES],
    ਅਚਲ uint8_t sk[crypto_kem_mlkem768_SECRETKEYBYTES])
{
	libcrux_mlkem768_sk sk_ਅੰਦਰੂਨੀ;
	libcrux_mlkem768_ciphertext ct_ਅੰਦਰੂਨੀ;
	libcrux_mlkem768_dec_ਨਤੀਜਾ shared_secret_ਅੰਦਰੂਨੀ;

	ਸਮ੍ਰਿਤੀ_ਨਕਲ(sk_ਅੰਦਰੂਨੀ.ਅੰਕੜੇ, sk, crypto_kem_mlkem768_SECRETKEYBYTES);
	ਸਮ੍ਰਿਤੀ_ਨਕਲ(ct_ਅੰਦਰੂਨੀ.ਅੰਕੜੇ, ct, crypto_kem_mlkem768_CIPHERTEXTBYTES);
	shared_secret_ਅੰਦਰੂਨੀ = libcrux_ml_kem_mlkem768_portable_decapsulate(
	    &sk_ਅੰਦਰੂਨੀ, &ct_ਅੰਦਰੂਨੀ);
	ਸਮ੍ਰਿਤੀ_ਨਕਲ(shared_secret, shared_secret_ਅੰਦਰੂਨੀ.ਅੰਕੜੇ,
	    crypto_kem_mlkem768_ਬਾਈਟਾਂ);

	explicit_bzero(&sk_ਅੰਦਰੂਨੀ, ਆਕਾਰ(sk_ਅੰਦਰੂਨੀ));
	explicit_bzero(&shared_secret_ਅੰਦਰੂਨੀ, ਆਕਾਰ(shared_secret_ਅੰਦਰੂਨੀ));
	ਵਾਪਸ 0;
}

/* ML-DSA 44 */

ਪੂਰਨ
crypto_sign_mldsa44_keypair(uint8_t pk[MLDSA44_PUBLICKEYBYTES],
    uint8_t sk[MLDSA44_SECRETKEYBYTES])
{
	uint8_t rnd[MLDSA44_SEEDBYTES];
	ਪੂਰਨ r;

	arc4random_buf(rnd, ਆਕਾਰ(rnd));
	r = crypto_sign_mldsa44_keypair_seeded(pk, sk, rnd);
	explicit_bzero(rnd, ਆਕਾਰ(rnd));
	ਵਾਪਸ r;
}

ਪੂਰਨ
crypto_sign_mldsa44_keypair_seeded(uint8_t pk[MLDSA44_PUBLICKEYBYTES],
    uint8_t sk[MLDSA44_SECRETKEYBYTES], ਅਚਲ uint8_t ਬੀਜ[MLDSA44_SEEDBYTES])
{
	libcrux_mldsa44_keypair_rnd rnd;
	libcrux_mldsa44_keypair keypair;

	ਸਮ੍ਰਿਤੀ_ਨਕਲ(rnd.ਅੰਕੜੇ, ਬੀਜ, ਆਕਾਰ(rnd.ਅੰਕੜੇ));
	keypair = libcrux_ml_dsa_ml_dsa_44_portable_generate_ਕੁੰਜੀ_pair(rnd);
	ਸਮ੍ਰਿਤੀ_ਨਕਲ(pk, keypair.verification_ਕੁੰਜੀ.ਅੰਕੜੇ, MLDSA44_PUBLICKEYBYTES);
	ਸਮ੍ਰਿਤੀ_ਨਕਲ(sk, keypair.signing_ਕੁੰਜੀ.ਅੰਕੜੇ, MLDSA44_SECRETKEYBYTES);

	explicit_bzero(&keypair, ਆਕਾਰ(keypair));
	explicit_bzero(&rnd, ਆਕਾਰ(rnd));
	ਵਾਪਸ 0;
}

ਪੂਰਨ
crypto_sign_mldsa44(uint8_t sig[MLDSA44_SIGBYTES],
    ਅਚਲ uint8_t *ਸੁਨੇਹਾ, ਮਾਪ_t msglen,
    ਅਚਲ uint8_t *ctx, ਮਾਪ_t ctxlen,
    ਅਚਲ uint8_t sk[MLDSA44_SECRETKEYBYTES])
{
	uint8_t rnd[MLDSA44_SEEDBYTES];
	ਪੂਰਨ r;

	arc4random_buf(rnd, ਆਕਾਰ(rnd));
	r = crypto_sign_mldsa44_seeded(sig, ਸੁਨੇਹਾ, msglen, ctx, ctxlen, sk, rnd);
	explicit_bzero(rnd, ਆਕਾਰ(rnd));
	ਵਾਪਸ r;
}

ਪੂਰਨ
crypto_sign_mldsa44_seeded(uint8_t sig[MLDSA44_SIGBYTES],
    ਅਚਲ uint8_t *ਸੁਨੇਹਾ, ਮਾਪ_t msglen,
    ਅਚਲ uint8_t *ctx, ਮਾਪ_t ctxlen,
    ਅਚਲ uint8_t sk[MLDSA44_SECRETKEYBYTES],
    ਅਚਲ uint8_t ਬੀਜ[MLDSA44_SEEDBYTES])
{
	libcrux_mldsa44_sign_rnd rnd;
	libcrux_mldsa44_sk sk_ਅੰਦਰੂਨੀ;
	libcrux_mldsa44_ਸੁਨੇਹਾ ਸੁਨੇਹਾ_2 = { ਸੁਨੇਹਾ, msglen };
	libcrux_mldsa44_ਸੁਨੇਹਾ context = { ctx, ctxlen };
	libcrux_mldsa44_sign_ਨਤੀਜਾ res;
	ਪੂਰਨ r = -1;

	ਸਮ੍ਰਿਤੀ_ਨਕਲ(sk_ਅੰਦਰੂਨੀ.ਅੰਕੜੇ, sk, MLDSA44_SECRETKEYBYTES);
	ਸਮ੍ਰਿਤੀ_ਨਕਲ(rnd.ਅੰਕੜੇ, ਬੀਜ, ਆਕਾਰ(rnd.ਅੰਕੜੇ));
	res = libcrux_ml_dsa_ml_dsa_44_portable_sign(&sk_ਅੰਦਰੂਨੀ,
	    ਸੁਨੇਹਾ_2, context, rnd);
	ਜੇ (res.ਟੈਗ == LIBCRUX_ਨਤੀਜਾ_OK) {
		ਸਮ੍ਰਿਤੀ_ਨਕਲ(sig, res.val.case_Ok.ਅੰਕੜੇ, MLDSA44_SIGBYTES);
		r = 0;
	}

	explicit_bzero(&sk_ਅੰਦਰੂਨੀ, ਆਕਾਰ(sk_ਅੰਦਰੂਨੀ));
	explicit_bzero(&res, ਆਕਾਰ(res));
	explicit_bzero(&rnd, ਆਕਾਰ(rnd));
	ਵਾਪਸ r;
}

ਪੂਰਨ
crypto_sign_mldsa44_verify(ਅਚਲ uint8_t sig[MLDSA44_SIGBYTES],
    ਅਚਲ uint8_t *ਸੁਨੇਹਾ, ਮਾਪ_t msglen,
    ਅਚਲ uint8_t *ctx, ਮਾਪ_t ctxlen,
    ਅਚਲ uint8_t pk[MLDSA44_PUBLICKEYBYTES])
{
	libcrux_mldsa44_pk pk_ਅੰਦਰੂਨੀ;
	libcrux_mldsa44_signature sig_ਅੰਦਰੂਨੀ;
	libcrux_mldsa44_ਸੁਨੇਹਾ ਸੁਨੇਹਾ_2 = { ਸੁਨੇਹਾ, msglen };
	libcrux_mldsa44_ਸੁਨੇਹਾ context = { ctx, ctxlen };
	libcrux_mldsa44_verify_ਨਤੀਜਾ res;

	ਸਮ੍ਰਿਤੀ_ਨਕਲ(pk_ਅੰਦਰੂਨੀ.ਅੰਕੜੇ, pk, MLDSA44_PUBLICKEYBYTES);
	ਸਮ੍ਰਿਤੀ_ਨਕਲ(sig_ਅੰਦਰੂਨੀ.ਅੰਕੜੇ, sig, MLDSA44_SIGBYTES);
	res = libcrux_ml_dsa_ml_dsa_44_portable_verify(&pk_ਅੰਦਰੂਨੀ,
	    ਸੁਨੇਹਾ_2, context, &sig_ਅੰਦਰੂਨੀ);

	ਵਾਪਸ (res.ਟੈਗ == LIBCRUX_ਨਤੀਜਾ_OK) ? 0 : -1;
}

/* ML-DSA 65 */

#ਜੇ 0
ਪੂਰਨ
crypto_sign_mldsa65_keypair(uint8_t pk[MLDSA65_PUBLICKEYBYTES],
    uint8_t sk[MLDSA65_SECRETKEYBYTES])
{
	uint8_t rnd[MLDSA65_SEEDBYTES];
	ਪੂਰਨ r;

	arc4random_buf(rnd, ਆਕਾਰ(rnd));
	r = crypto_sign_mldsa65_keypair_seeded(pk, sk, rnd);
	explicit_bzero(rnd, ਆਕਾਰ(rnd));
	ਵਾਪਸ r;
}

ਪੂਰਨ
crypto_sign_mldsa65_keypair_seeded(uint8_t pk[MLDSA65_PUBLICKEYBYTES],
    uint8_t sk[MLDSA65_SECRETKEYBYTES], ਅਚਲ uint8_t ਬੀਜ[MLDSA65_SEEDBYTES])
{
	libcrux_mldsa65_keypair_rnd rnd;
	libcrux_mldsa65_keypair keypair;

	ਸਮ੍ਰਿਤੀ_ਨਕਲ(rnd.ਅੰਕੜੇ, ਬੀਜ, ਆਕਾਰ(rnd.ਅੰਕੜੇ));
	keypair = libcrux_ml_dsa_ml_dsa_65_portable_generate_ਕੁੰਜੀ_pair(rnd);
	ਸਮ੍ਰਿਤੀ_ਨਕਲ(pk, keypair.verification_ਕੁੰਜੀ.ਅੰਕੜੇ, MLDSA65_PUBLICKEYBYTES);
	ਸਮ੍ਰਿਤੀ_ਨਕਲ(sk, keypair.signing_ਕੁੰਜੀ.ਅੰਕੜੇ, MLDSA65_SECRETKEYBYTES);

	explicit_bzero(&keypair, ਆਕਾਰ(keypair));
	explicit_bzero(&rnd, ਆਕਾਰ(rnd));
	ਵਾਪਸ 0;
}

ਪੂਰਨ
crypto_sign_mldsa65(uint8_t sig[MLDSA65_SIGBYTES],
    ਅਚਲ uint8_t *ਸੁਨੇਹਾ, ਮਾਪ_t msglen,
    ਅਚਲ uint8_t *ctx, ਮਾਪ_t ctxlen,
    ਅਚਲ uint8_t sk[MLDSA65_SECRETKEYBYTES])
{
	uint8_t rnd[MLDSA65_SEEDBYTES];
	ਪੂਰਨ r;

	arc4random_buf(rnd, ਆਕਾਰ(rnd));
	r = crypto_sign_mldsa65_seeded(sig, ਸੁਨੇਹਾ, msglen, ctx, ctxlen, sk, rnd);
	explicit_bzero(rnd, ਆਕਾਰ(rnd));
	ਵਾਪਸ r;
}

ਪੂਰਨ
crypto_sign_mldsa65_seeded(uint8_t sig[MLDSA65_SIGBYTES],
    ਅਚਲ uint8_t *ਸੁਨੇਹਾ, ਮਾਪ_t msglen,
    ਅਚਲ uint8_t *ctx, ਮਾਪ_t ctxlen,
    ਅਚਲ uint8_t sk[MLDSA65_SECRETKEYBYTES],
    ਅਚਲ uint8_t ਬੀਜ[MLDSA65_SEEDBYTES])
{
	libcrux_mldsa65_sign_rnd rnd;
	libcrux_mldsa65_sk sk_ਅੰਦਰੂਨੀ;
	libcrux_mldsa65_ਸੁਨੇਹਾ ਸੁਨੇਹਾ_2 = { ਸੁਨੇਹਾ, msglen };
	libcrux_mldsa65_ਸੁਨੇਹਾ context = { ctx, ctxlen };
	libcrux_mldsa65_sign_ਨਤੀਜਾ res;
	ਪੂਰਨ r = -1;

	ਸਮ੍ਰਿਤੀ_ਨਕਲ(sk_ਅੰਦਰੂਨੀ.ਅੰਕੜੇ, sk, MLDSA65_SECRETKEYBYTES);
	ਸਮ੍ਰਿਤੀ_ਨਕਲ(rnd.ਅੰਕੜੇ, ਬੀਜ, ਆਕਾਰ(rnd.ਅੰਕੜੇ));
	res = libcrux_ml_dsa_ml_dsa_65_portable_sign(&sk_ਅੰਦਰੂਨੀ,
	    ਸੁਨੇਹਾ_2, context, rnd);
	ਜੇ (res.ਟੈਗ == LIBCRUX_ਨਤੀਜਾ_OK) {
		ਸਮ੍ਰਿਤੀ_ਨਕਲ(sig, res.val.case_Ok.ਅੰਕੜੇ, MLDSA65_SIGBYTES);
		r = 0;
	}

	explicit_bzero(&sk_ਅੰਦਰੂਨੀ, ਆਕਾਰ(sk_ਅੰਦਰੂਨੀ));
	explicit_bzero(&res, ਆਕਾਰ(res));
	explicit_bzero(&rnd, ਆਕਾਰ(rnd));
	ਵਾਪਸ r;
}

ਪੂਰਨ
crypto_sign_mldsa65_verify(ਅਚਲ uint8_t sig[MLDSA65_SIGBYTES],
    ਅਚਲ uint8_t *ਸੁਨੇਹਾ, ਮਾਪ_t msglen,
    ਅਚਲ uint8_t *ctx, ਮਾਪ_t ctxlen,
    ਅਚਲ uint8_t pk[MLDSA65_PUBLICKEYBYTES])
{
	libcrux_mldsa65_pk pk_ਅੰਦਰੂਨੀ;
	libcrux_mldsa65_signature sig_ਅੰਦਰੂਨੀ;
	libcrux_mldsa65_ਸੁਨੇਹਾ ਸੁਨੇਹਾ_2 = { ਸੁਨੇਹਾ, msglen };
	libcrux_mldsa65_ਸੁਨੇਹਾ context = { ctx, ctxlen };
	libcrux_mldsa65_verify_ਨਤੀਜਾ res;

	ਸਮ੍ਰਿਤੀ_ਨਕਲ(pk_ਅੰਦਰੂਨੀ.ਅੰਕੜੇ, pk, MLDSA65_PUBLICKEYBYTES);
	ਸਮ੍ਰਿਤੀ_ਨਕਲ(sig_ਅੰਦਰੂਨੀ.ਅੰਕੜੇ, sig, MLDSA65_SIGBYTES);
	res = libcrux_ml_dsa_ml_dsa_65_portable_verify(&pk_ਅੰਦਰੂਨੀ,
	    ਸੁਨੇਹਾ_2, context, &sig_ਅੰਦਰੂਨੀ);

	ਵਾਪਸ (res.ਟੈਗ == LIBCRUX_ਨਤੀਜਾ_OK) ? 0 : -1;
}
#ਜੇ_ਅੰਤ

/* ML-DSA 87 */

#ਜੇ 0
ਪੂਰਨ
crypto_sign_mldsa87_keypair(uint8_t pk[MLDSA87_PUBLICKEYBYTES],
    uint8_t sk[MLDSA87_SECRETKEYBYTES])
{
	uint8_t rnd[MLDSA87_SEEDBYTES];
	ਪੂਰਨ r;

	arc4random_buf(rnd, ਆਕਾਰ(rnd));
	r = crypto_sign_mldsa87_keypair_seeded(pk, sk, rnd);
	explicit_bzero(rnd, ਆਕਾਰ(rnd));
	ਵਾਪਸ r;
}

ਪੂਰਨ
crypto_sign_mldsa87_keypair_seeded(uint8_t pk[MLDSA87_PUBLICKEYBYTES],
    uint8_t sk[MLDSA87_SECRETKEYBYTES], ਅਚਲ uint8_t ਬੀਜ[MLDSA87_SEEDBYTES])
{
	libcrux_mldsa87_keypair_rnd rnd;
	libcrux_mldsa87_keypair keypair;

	ਸਮ੍ਰਿਤੀ_ਨਕਲ(rnd.ਅੰਕੜੇ, ਬੀਜ, ਆਕਾਰ(rnd.ਅੰਕੜੇ));
	keypair = libcrux_ml_dsa_ml_dsa_87_portable_generate_ਕੁੰਜੀ_pair(rnd);
	ਸਮ੍ਰਿਤੀ_ਨਕਲ(pk, keypair.verification_ਕੁੰਜੀ.ਅੰਕੜੇ, MLDSA87_PUBLICKEYBYTES);
	ਸਮ੍ਰਿਤੀ_ਨਕਲ(sk, keypair.signing_ਕੁੰਜੀ.ਅੰਕੜੇ, MLDSA87_SECRETKEYBYTES);

	explicit_bzero(&keypair, ਆਕਾਰ(keypair));
	explicit_bzero(&rnd, ਆਕਾਰ(rnd));
	ਵਾਪਸ 0;
}

ਪੂਰਨ
crypto_sign_mldsa87(uint8_t sig[MLDSA87_SIGBYTES],
    ਅਚਲ uint8_t *ਸੁਨੇਹਾ, ਮਾਪ_t msglen,
    ਅਚਲ uint8_t *ctx, ਮਾਪ_t ctxlen,
    ਅਚਲ uint8_t sk[MLDSA87_SECRETKEYBYTES])
{
	uint8_t rnd[MLDSA87_SEEDBYTES];
	ਪੂਰਨ r;

	arc4random_buf(rnd, ਆਕਾਰ(rnd));
	r = crypto_sign_mldsa87_seeded(sig, ਸੁਨੇਹਾ, msglen, ctx, ctxlen, sk, rnd);
	explicit_bzero(rnd, ਆਕਾਰ(rnd));
	ਵਾਪਸ r;
}

ਪੂਰਨ
crypto_sign_mldsa87_seeded(uint8_t sig[MLDSA87_SIGBYTES],
    ਅਚਲ uint8_t *ਸੁਨੇਹਾ, ਮਾਪ_t msglen,
    ਅਚਲ uint8_t *ctx, ਮਾਪ_t ctxlen,
    ਅਚਲ uint8_t sk[MLDSA87_SECRETKEYBYTES],
    ਅਚਲ uint8_t ਬੀਜ[MLDSA87_SEEDBYTES])
{
	libcrux_mldsa87_sign_rnd rnd;
	libcrux_mldsa87_sk sk_ਅੰਦਰੂਨੀ;
	libcrux_mldsa87_ਸੁਨੇਹਾ ਸੁਨੇਹਾ_2 = { ਸੁਨੇਹਾ, msglen };
	libcrux_mldsa87_ਸੁਨੇਹਾ context = { ctx, ctxlen };
	libcrux_mldsa87_sign_ਨਤੀਜਾ res;
	ਪੂਰਨ r = -1;

	ਸਮ੍ਰਿਤੀ_ਨਕਲ(sk_ਅੰਦਰੂਨੀ.ਅੰਕੜੇ, sk, MLDSA87_SECRETKEYBYTES);
	ਸਮ੍ਰਿਤੀ_ਨਕਲ(rnd.ਅੰਕੜੇ, ਬੀਜ, ਆਕਾਰ(rnd.ਅੰਕੜੇ));
	res = libcrux_ml_dsa_ml_dsa_87_portable_sign(&sk_ਅੰਦਰੂਨੀ,
	    ਸੁਨੇਹਾ_2, context, rnd);
	ਜੇ (res.ਟੈਗ == LIBCRUX_ਨਤੀਜਾ_OK) {
		ਸਮ੍ਰਿਤੀ_ਨਕਲ(sig, res.val.case_Ok.ਅੰਕੜੇ, MLDSA87_SIGBYTES);
		r = 0;
	}

	explicit_bzero(&sk_ਅੰਦਰੂਨੀ, ਆਕਾਰ(sk_ਅੰਦਰੂਨੀ));
	explicit_bzero(&res, ਆਕਾਰ(res));
	explicit_bzero(&rnd, ਆਕਾਰ(rnd));
	ਵਾਪਸ r;
}

ਪੂਰਨ
crypto_sign_mldsa87_verify(ਅਚਲ uint8_t sig[MLDSA87_SIGBYTES],
    ਅਚਲ uint8_t *ਸੁਨੇਹਾ, ਮਾਪ_t msglen,
    ਅਚਲ uint8_t *ctx, ਮਾਪ_t ctxlen,
    ਅਚਲ uint8_t pk[MLDSA87_PUBLICKEYBYTES])
{
	libcrux_mldsa87_pk pk_ਅੰਦਰੂਨੀ;
	libcrux_mldsa87_signature sig_ਅੰਦਰੂਨੀ;
	libcrux_mldsa87_ਸੁਨੇਹਾ ਸੁਨੇਹਾ_2 = { ਸੁਨੇਹਾ, msglen };
	libcrux_mldsa87_ਸੁਨੇਹਾ context = { ctx, ctxlen };
	libcrux_mldsa87_verify_ਨਤੀਜਾ res;

	ਸਮ੍ਰਿਤੀ_ਨਕਲ(pk_ਅੰਦਰੂਨੀ.ਅੰਕੜੇ, pk, MLDSA87_PUBLICKEYBYTES);
	ਸਮ੍ਰਿਤੀ_ਨਕਲ(sig_ਅੰਦਰੂਨੀ.ਅੰਕੜੇ, sig, MLDSA87_SIGBYTES);
	res = libcrux_ml_dsa_ml_dsa_87_portable_verify(&pk_ਅੰਦਰੂਨੀ,
	    ਸੁਨੇਹਾ_2, context, &sig_ਅੰਦਰੂਨੀ);

	ਵਾਪਸ (res.ਟੈਗ == LIBCRUX_ਨਤੀਜਾ_OK) ? 0 : -1;
}
#ਜੇ_ਅੰਤ

ਖਾਲੀ
sha3_256(uint8_t digest[32], ਅਚਲ uint8_t *ਅੰਕੜੇ, ਮਾਪ_t len)
{
	Eurydice_borrow_ਟੁਕੜਾ_u8 ਨਿਵੇਸ਼ = { ਅੰਕੜੇ, len };
	Eurydice_mut_borrow_ਟੁਕੜਾ_u8 output = { digest, 32 };
	libcrux_sha3_portable_sha256(output, ਨਿਵੇਸ਼);
}

ਖਾਲੀ
sha3_512(uint8_t digest[64], ਅਚਲ uint8_t *ਅੰਕੜੇ, ਮਾਪ_t len)
{
	Eurydice_borrow_ਟੁਕੜਾ_u8 ਨਿਵੇਸ਼ = { ਅੰਕੜੇ, len };
	Eurydice_mut_borrow_ਟੁਕੜਾ_u8 output = { digest, 64 };
	libcrux_sha3_portable_sha512(output, ਨਿਵੇਸ਼);
}
#ਜੇ_ਅੰਤ /* defined(USE_MLDSA) || defined(USE_MLKEM768X25519) */
