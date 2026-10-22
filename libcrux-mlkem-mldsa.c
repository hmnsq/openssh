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

#ಆದರೆ defined(USE_MLDSA) || defined(USE_MLKEM768X25519)

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <stdint.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <stdbool.h>
#ಅನ್ತರ್ಭಾವ <string.h>

#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "crypto_api.h"
#ಅನ್ತರ್ಭಾವ "libcrux_internal.h"

/* ML-KEM 768 */

ಪೂರ್ಣಾಂಕ
crypto_kem_mlkem768_keypair(uint8_t pk[crypto_kem_mlkem768_PUBLICKEYBYTES],
    uint8_t sk[crypto_kem_mlkem768_SECRETKEYBYTES])
{
	uint8_t rnd[crypto_kem_mlkem768_KEYPAIRSEEDBYTES];
	ಪೂರ್ಣಾಂಕ r;

	arc4random_buf(rnd, ಗಾತ್ರ(rnd));
	r = crypto_kem_mlkem768_keypair_seeded(pk, sk, rnd);
	explicit_bzero(rnd, ಗಾತ್ರ(rnd));
	ಹಿಂತಿರುಗಿ r;
}

ಪೂರ್ಣಾಂಕ
crypto_kem_mlkem768_keypair_seeded(uint8_t pk[crypto_kem_mlkem768_PUBLICKEYBYTES],
    uint8_t sk[crypto_kem_mlkem768_SECRETKEYBYTES],
    ಸ್ಥಿರಾಂಕ uint8_t ಬೀಜ[crypto_kem_mlkem768_KEYPAIRSEEDBYTES])
{
	libcrux_mlkem768_keypair keypair;
	libcrux_mlkem768_keypair_rnd rnd;

	ಸ್ಮರಣೆ_ನಕಲು(rnd.ದತ್ತಾಂಶ, ಬೀಜ, ಗಾತ್ರ(rnd.ದತ್ತಾಂಶ));
	keypair = libcrux_ml_kem_mlkem768_portable_generate_ಕೀಲಿ_pair(rnd);
	ಸ್ಮರಣೆ_ನಕಲು(pk, keypair.pk.ದತ್ತಾಂಶ, crypto_kem_mlkem768_PUBLICKEYBYTES);
	ಸ್ಮರಣೆ_ನಕಲು(sk, keypair.sk.ದತ್ತಾಂಶ, crypto_kem_mlkem768_SECRETKEYBYTES);

	explicit_bzero(&keypair, ಗಾತ್ರ(keypair));
	explicit_bzero(&rnd, ಗಾತ್ರ(rnd));
	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
crypto_kem_mlkem768_enc(uint8_t ct[crypto_kem_mlkem768_CIPHERTEXTBYTES],
    uint8_t shared_secret[crypto_kem_mlkem768_ಬೈಟುಗಳು],
    ಸ್ಥಿರಾಂಕ uint8_t pk[crypto_kem_mlkem768_PUBLICKEYBYTES])
{
	uint8_t rnd[crypto_kem_mlkem768_ENCSEEDBYTES];
	ಪೂರ್ಣಾಂಕ r;

	arc4random_buf(rnd, ಗಾತ್ರ(rnd));
	r = crypto_kem_mlkem768_enc_seeded(ct, shared_secret, pk, rnd);
	explicit_bzero(rnd, ಗಾತ್ರ(rnd));
	ಹಿಂತಿರುಗಿ r;
}

ಪೂರ್ಣಾಂಕ
crypto_kem_mlkem768_enc_seeded(uint8_t ct[crypto_kem_mlkem768_CIPHERTEXTBYTES],
    uint8_t shared_secret[crypto_kem_mlkem768_ಬೈಟುಗಳು],
    ಸ್ಥಿರಾಂಕ uint8_t pk[crypto_kem_mlkem768_PUBLICKEYBYTES],
    ಸ್ಥಿರಾಂಕ uint8_t ಬೀಜ[crypto_kem_mlkem768_ENCSEEDBYTES])
{
	libcrux_mlkem768_enc_ಫಲಿತಾಂಶ enc;
	libcrux_mlkem768_pk pk_ಆಂತರಿಕ;
	libcrux_mlkem768_enc_rnd rnd;

	ಸ್ಮರಣೆ_ನಕಲು(pk_ಆಂತರಿಕ.ದತ್ತಾಂಶ, pk, crypto_kem_mlkem768_PUBLICKEYBYTES);
	ಆದರೆ (!libcrux_ml_kem_mlkem768_portable_validate_ಬಹಿರಂಗ_ಕೀಲಿ(&pk_ಆಂತರಿಕ))
		ಹಿಂತಿರುಗಿ -1;
	ಸ್ಮರಣೆ_ನಕಲು(rnd.ದತ್ತಾಂಶ, ಬೀಜ, ಗಾತ್ರ(rnd.ದತ್ತಾಂಶ));
	enc = libcrux_ml_kem_mlkem768_portable_encapsulate(&pk_ಆಂತರಿಕ, rnd);
	ಸ್ಮರಣೆ_ನಕಲು(ct, enc.fst.ದತ್ತಾಂಶ, crypto_kem_mlkem768_CIPHERTEXTBYTES);
	ಸ್ಮರಣೆ_ನಕಲು(shared_secret, enc.snd.ದತ್ತಾಂಶ, crypto_kem_mlkem768_ಬೈಟುಗಳು);

	explicit_bzero(&enc, ಗಾತ್ರ(enc));
	explicit_bzero(&rnd, ಗಾತ್ರ(rnd));
	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
crypto_kem_mlkem768_dec(uint8_t shared_secret[crypto_kem_mlkem768_ಬೈಟುಗಳು],
    ಸ್ಥಿರಾಂಕ uint8_t ct[crypto_kem_mlkem768_CIPHERTEXTBYTES],
    ಸ್ಥಿರಾಂಕ uint8_t sk[crypto_kem_mlkem768_SECRETKEYBYTES])
{
	libcrux_mlkem768_sk sk_ಆಂತರಿಕ;
	libcrux_mlkem768_ciphertext ct_ಆಂತರಿಕ;
	libcrux_mlkem768_dec_ಫಲಿತಾಂಶ shared_secret_ಆಂತರಿಕ;

	ಸ್ಮರಣೆ_ನಕಲು(sk_ಆಂತರಿಕ.ದತ್ತಾಂಶ, sk, crypto_kem_mlkem768_SECRETKEYBYTES);
	ಸ್ಮರಣೆ_ನಕಲು(ct_ಆಂತರಿಕ.ದತ್ತಾಂಶ, ct, crypto_kem_mlkem768_CIPHERTEXTBYTES);
	shared_secret_ಆಂತರಿಕ = libcrux_ml_kem_mlkem768_portable_decapsulate(
	    &sk_ಆಂತರಿಕ, &ct_ಆಂತರಿಕ);
	ಸ್ಮರಣೆ_ನಕಲು(shared_secret, shared_secret_ಆಂತರಿಕ.ದತ್ತಾಂಶ,
	    crypto_kem_mlkem768_ಬೈಟುಗಳು);

	explicit_bzero(&sk_ಆಂತರಿಕ, ಗಾತ್ರ(sk_ಆಂತರಿಕ));
	explicit_bzero(&shared_secret_ಆಂತರಿಕ, ಗಾತ್ರ(shared_secret_ಆಂತರಿಕ));
	ಹಿಂತಿರುಗಿ 0;
}

/* ML-DSA 44 */

ಪೂರ್ಣಾಂಕ
crypto_sign_mldsa44_keypair(uint8_t pk[MLDSA44_PUBLICKEYBYTES],
    uint8_t sk[MLDSA44_SECRETKEYBYTES])
{
	uint8_t rnd[MLDSA44_SEEDBYTES];
	ಪೂರ್ಣಾಂಕ r;

	arc4random_buf(rnd, ಗಾತ್ರ(rnd));
	r = crypto_sign_mldsa44_keypair_seeded(pk, sk, rnd);
	explicit_bzero(rnd, ಗಾತ್ರ(rnd));
	ಹಿಂತಿರುಗಿ r;
}

ಪೂರ್ಣಾಂಕ
crypto_sign_mldsa44_keypair_seeded(uint8_t pk[MLDSA44_PUBLICKEYBYTES],
    uint8_t sk[MLDSA44_SECRETKEYBYTES], ಸ್ಥಿರಾಂಕ uint8_t ಬೀಜ[MLDSA44_SEEDBYTES])
{
	libcrux_mldsa44_keypair_rnd rnd;
	libcrux_mldsa44_keypair keypair;

	ಸ್ಮರಣೆ_ನಕಲು(rnd.ದತ್ತಾಂಶ, ಬೀಜ, ಗಾತ್ರ(rnd.ದತ್ತಾಂಶ));
	keypair = libcrux_ml_dsa_ml_dsa_44_portable_generate_ಕೀಲಿ_pair(rnd);
	ಸ್ಮರಣೆ_ನಕಲು(pk, keypair.verification_ಕೀಲಿ.ದತ್ತಾಂಶ, MLDSA44_PUBLICKEYBYTES);
	ಸ್ಮರಣೆ_ನಕಲು(sk, keypair.signing_ಕೀಲಿ.ದತ್ತಾಂಶ, MLDSA44_SECRETKEYBYTES);

	explicit_bzero(&keypair, ಗಾತ್ರ(keypair));
	explicit_bzero(&rnd, ಗಾತ್ರ(rnd));
	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
crypto_sign_mldsa44(uint8_t sig[MLDSA44_SIGBYTES],
    ಸ್ಥಿರಾಂಕ uint8_t *ಸಂದೇಶ, ಗಾತ್ರ_t msglen,
    ಸ್ಥಿರಾಂಕ uint8_t *ctx, ಗಾತ್ರ_t ctxlen,
    ಸ್ಥಿರಾಂಕ uint8_t sk[MLDSA44_SECRETKEYBYTES])
{
	uint8_t rnd[MLDSA44_SEEDBYTES];
	ಪೂರ್ಣಾಂಕ r;

	arc4random_buf(rnd, ಗಾತ್ರ(rnd));
	r = crypto_sign_mldsa44_seeded(sig, ಸಂದೇಶ, msglen, ctx, ctxlen, sk, rnd);
	explicit_bzero(rnd, ಗಾತ್ರ(rnd));
	ಹಿಂತಿರುಗಿ r;
}

ಪೂರ್ಣಾಂಕ
crypto_sign_mldsa44_seeded(uint8_t sig[MLDSA44_SIGBYTES],
    ಸ್ಥಿರಾಂಕ uint8_t *ಸಂದೇಶ, ಗಾತ್ರ_t msglen,
    ಸ್ಥಿರಾಂಕ uint8_t *ctx, ಗಾತ್ರ_t ctxlen,
    ಸ್ಥಿರಾಂಕ uint8_t sk[MLDSA44_SECRETKEYBYTES],
    ಸ್ಥಿರಾಂಕ uint8_t ಬೀಜ[MLDSA44_SEEDBYTES])
{
	libcrux_mldsa44_sign_rnd rnd;
	libcrux_mldsa44_sk sk_ಆಂತರಿಕ;
	libcrux_mldsa44_ಸಂದೇಶ ಸಂದೇಶ_2 = { ಸಂದೇಶ, msglen };
	libcrux_mldsa44_ಸಂದೇಶ context = { ctx, ctxlen };
	libcrux_mldsa44_sign_ಫಲಿತಾಂಶ res;
	ಪೂರ್ಣಾಂಕ r = -1;

	ಸ್ಮರಣೆ_ನಕಲು(sk_ಆಂತರಿಕ.ದತ್ತಾಂಶ, sk, MLDSA44_SECRETKEYBYTES);
	ಸ್ಮರಣೆ_ನಕಲು(rnd.ದತ್ತಾಂಶ, ಬೀಜ, ಗಾತ್ರ(rnd.ದತ್ತಾಂಶ));
	res = libcrux_ml_dsa_ml_dsa_44_portable_sign(&sk_ಆಂತರಿಕ,
	    ಸಂದೇಶ_2, context, rnd);
	ಆದರೆ (res.ಟ್ಯಾಗ್ == LIBCRUX_ಫಲಿತಾಂಶ_OK) {
		ಸ್ಮರಣೆ_ನಕಲು(sig, res.val.case_Ok.ದತ್ತಾಂಶ, MLDSA44_SIGBYTES);
		r = 0;
	}

	explicit_bzero(&sk_ಆಂತರಿಕ, ಗಾತ್ರ(sk_ಆಂತರಿಕ));
	explicit_bzero(&res, ಗಾತ್ರ(res));
	explicit_bzero(&rnd, ಗಾತ್ರ(rnd));
	ಹಿಂತಿರುಗಿ r;
}

ಪೂರ್ಣಾಂಕ
crypto_sign_mldsa44_verify(ಸ್ಥಿರಾಂಕ uint8_t sig[MLDSA44_SIGBYTES],
    ಸ್ಥಿರಾಂಕ uint8_t *ಸಂದೇಶ, ಗಾತ್ರ_t msglen,
    ಸ್ಥಿರಾಂಕ uint8_t *ctx, ಗಾತ್ರ_t ctxlen,
    ಸ್ಥಿರಾಂಕ uint8_t pk[MLDSA44_PUBLICKEYBYTES])
{
	libcrux_mldsa44_pk pk_ಆಂತರಿಕ;
	libcrux_mldsa44_signature sig_ಆಂತರಿಕ;
	libcrux_mldsa44_ಸಂದೇಶ ಸಂದೇಶ_2 = { ಸಂದೇಶ, msglen };
	libcrux_mldsa44_ಸಂದೇಶ context = { ctx, ctxlen };
	libcrux_mldsa44_verify_ಫಲಿತಾಂಶ res;

	ಸ್ಮರಣೆ_ನಕಲು(pk_ಆಂತರಿಕ.ದತ್ತಾಂಶ, pk, MLDSA44_PUBLICKEYBYTES);
	ಸ್ಮರಣೆ_ನಕಲು(sig_ಆಂತರಿಕ.ದತ್ತಾಂಶ, sig, MLDSA44_SIGBYTES);
	res = libcrux_ml_dsa_ml_dsa_44_portable_verify(&pk_ಆಂತರಿಕ,
	    ಸಂದೇಶ_2, context, &sig_ಆಂತರಿಕ);

	ಹಿಂತಿರುಗಿ (res.ಟ್ಯಾಗ್ == LIBCRUX_ಫಲಿತಾಂಶ_OK) ? 0 : -1;
}

/* ML-DSA 65 */

#ಆದರೆ 0
ಪೂರ್ಣಾಂಕ
crypto_sign_mldsa65_keypair(uint8_t pk[MLDSA65_PUBLICKEYBYTES],
    uint8_t sk[MLDSA65_SECRETKEYBYTES])
{
	uint8_t rnd[MLDSA65_SEEDBYTES];
	ಪೂರ್ಣಾಂಕ r;

	arc4random_buf(rnd, ಗಾತ್ರ(rnd));
	r = crypto_sign_mldsa65_keypair_seeded(pk, sk, rnd);
	explicit_bzero(rnd, ಗಾತ್ರ(rnd));
	ಹಿಂತಿರುಗಿ r;
}

ಪೂರ್ಣಾಂಕ
crypto_sign_mldsa65_keypair_seeded(uint8_t pk[MLDSA65_PUBLICKEYBYTES],
    uint8_t sk[MLDSA65_SECRETKEYBYTES], ಸ್ಥಿರಾಂಕ uint8_t ಬೀಜ[MLDSA65_SEEDBYTES])
{
	libcrux_mldsa65_keypair_rnd rnd;
	libcrux_mldsa65_keypair keypair;

	ಸ್ಮರಣೆ_ನಕಲು(rnd.ದತ್ತಾಂಶ, ಬೀಜ, ಗಾತ್ರ(rnd.ದತ್ತಾಂಶ));
	keypair = libcrux_ml_dsa_ml_dsa_65_portable_generate_ಕೀಲಿ_pair(rnd);
	ಸ್ಮರಣೆ_ನಕಲು(pk, keypair.verification_ಕೀಲಿ.ದತ್ತಾಂಶ, MLDSA65_PUBLICKEYBYTES);
	ಸ್ಮರಣೆ_ನಕಲು(sk, keypair.signing_ಕೀಲಿ.ದತ್ತಾಂಶ, MLDSA65_SECRETKEYBYTES);

	explicit_bzero(&keypair, ಗಾತ್ರ(keypair));
	explicit_bzero(&rnd, ಗಾತ್ರ(rnd));
	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
crypto_sign_mldsa65(uint8_t sig[MLDSA65_SIGBYTES],
    ಸ್ಥಿರಾಂಕ uint8_t *ಸಂದೇಶ, ಗಾತ್ರ_t msglen,
    ಸ್ಥಿರಾಂಕ uint8_t *ctx, ಗಾತ್ರ_t ctxlen,
    ಸ್ಥಿರಾಂಕ uint8_t sk[MLDSA65_SECRETKEYBYTES])
{
	uint8_t rnd[MLDSA65_SEEDBYTES];
	ಪೂರ್ಣಾಂಕ r;

	arc4random_buf(rnd, ಗಾತ್ರ(rnd));
	r = crypto_sign_mldsa65_seeded(sig, ಸಂದೇಶ, msglen, ctx, ctxlen, sk, rnd);
	explicit_bzero(rnd, ಗಾತ್ರ(rnd));
	ಹಿಂತಿರುಗಿ r;
}

ಪೂರ್ಣಾಂಕ
crypto_sign_mldsa65_seeded(uint8_t sig[MLDSA65_SIGBYTES],
    ಸ್ಥಿರಾಂಕ uint8_t *ಸಂದೇಶ, ಗಾತ್ರ_t msglen,
    ಸ್ಥಿರಾಂಕ uint8_t *ctx, ಗಾತ್ರ_t ctxlen,
    ಸ್ಥಿರಾಂಕ uint8_t sk[MLDSA65_SECRETKEYBYTES],
    ಸ್ಥಿರಾಂಕ uint8_t ಬೀಜ[MLDSA65_SEEDBYTES])
{
	libcrux_mldsa65_sign_rnd rnd;
	libcrux_mldsa65_sk sk_ಆಂತರಿಕ;
	libcrux_mldsa65_ಸಂದೇಶ ಸಂದೇಶ_2 = { ಸಂದೇಶ, msglen };
	libcrux_mldsa65_ಸಂದೇಶ context = { ctx, ctxlen };
	libcrux_mldsa65_sign_ಫಲಿತಾಂಶ res;
	ಪೂರ್ಣಾಂಕ r = -1;

	ಸ್ಮರಣೆ_ನಕಲು(sk_ಆಂತರಿಕ.ದತ್ತಾಂಶ, sk, MLDSA65_SECRETKEYBYTES);
	ಸ್ಮರಣೆ_ನಕಲು(rnd.ದತ್ತಾಂಶ, ಬೀಜ, ಗಾತ್ರ(rnd.ದತ್ತಾಂಶ));
	res = libcrux_ml_dsa_ml_dsa_65_portable_sign(&sk_ಆಂತರಿಕ,
	    ಸಂದೇಶ_2, context, rnd);
	ಆದರೆ (res.ಟ್ಯಾಗ್ == LIBCRUX_ಫಲಿತಾಂಶ_OK) {
		ಸ್ಮರಣೆ_ನಕಲು(sig, res.val.case_Ok.ದತ್ತಾಂಶ, MLDSA65_SIGBYTES);
		r = 0;
	}

	explicit_bzero(&sk_ಆಂತರಿಕ, ಗಾತ್ರ(sk_ಆಂತರಿಕ));
	explicit_bzero(&res, ಗಾತ್ರ(res));
	explicit_bzero(&rnd, ಗಾತ್ರ(rnd));
	ಹಿಂತಿರುಗಿ r;
}

ಪೂರ್ಣಾಂಕ
crypto_sign_mldsa65_verify(ಸ್ಥಿರಾಂಕ uint8_t sig[MLDSA65_SIGBYTES],
    ಸ್ಥಿರಾಂಕ uint8_t *ಸಂದೇಶ, ಗಾತ್ರ_t msglen,
    ಸ್ಥಿರಾಂಕ uint8_t *ctx, ಗಾತ್ರ_t ctxlen,
    ಸ್ಥಿರಾಂಕ uint8_t pk[MLDSA65_PUBLICKEYBYTES])
{
	libcrux_mldsa65_pk pk_ಆಂತರಿಕ;
	libcrux_mldsa65_signature sig_ಆಂತರಿಕ;
	libcrux_mldsa65_ಸಂದೇಶ ಸಂದೇಶ_2 = { ಸಂದೇಶ, msglen };
	libcrux_mldsa65_ಸಂದೇಶ context = { ctx, ctxlen };
	libcrux_mldsa65_verify_ಫಲಿತಾಂಶ res;

	ಸ್ಮರಣೆ_ನಕಲು(pk_ಆಂತರಿಕ.ದತ್ತಾಂಶ, pk, MLDSA65_PUBLICKEYBYTES);
	ಸ್ಮರಣೆ_ನಕಲು(sig_ಆಂತರಿಕ.ದತ್ತಾಂಶ, sig, MLDSA65_SIGBYTES);
	res = libcrux_ml_dsa_ml_dsa_65_portable_verify(&pk_ಆಂತರಿಕ,
	    ಸಂದೇಶ_2, context, &sig_ಆಂತರಿಕ);

	ಹಿಂತಿರುಗಿ (res.ಟ್ಯಾಗ್ == LIBCRUX_ಫಲಿತಾಂಶ_OK) ? 0 : -1;
}
#ಆದರೆ_ಅಂತ್ಯ

/* ML-DSA 87 */

#ಆದರೆ 0
ಪೂರ್ಣಾಂಕ
crypto_sign_mldsa87_keypair(uint8_t pk[MLDSA87_PUBLICKEYBYTES],
    uint8_t sk[MLDSA87_SECRETKEYBYTES])
{
	uint8_t rnd[MLDSA87_SEEDBYTES];
	ಪೂರ್ಣಾಂಕ r;

	arc4random_buf(rnd, ಗಾತ್ರ(rnd));
	r = crypto_sign_mldsa87_keypair_seeded(pk, sk, rnd);
	explicit_bzero(rnd, ಗಾತ್ರ(rnd));
	ಹಿಂತಿರುಗಿ r;
}

ಪೂರ್ಣಾಂಕ
crypto_sign_mldsa87_keypair_seeded(uint8_t pk[MLDSA87_PUBLICKEYBYTES],
    uint8_t sk[MLDSA87_SECRETKEYBYTES], ಸ್ಥಿರಾಂಕ uint8_t ಬೀಜ[MLDSA87_SEEDBYTES])
{
	libcrux_mldsa87_keypair_rnd rnd;
	libcrux_mldsa87_keypair keypair;

	ಸ್ಮರಣೆ_ನಕಲು(rnd.ದತ್ತಾಂಶ, ಬೀಜ, ಗಾತ್ರ(rnd.ದತ್ತಾಂಶ));
	keypair = libcrux_ml_dsa_ml_dsa_87_portable_generate_ಕೀಲಿ_pair(rnd);
	ಸ್ಮರಣೆ_ನಕಲು(pk, keypair.verification_ಕೀಲಿ.ದತ್ತಾಂಶ, MLDSA87_PUBLICKEYBYTES);
	ಸ್ಮರಣೆ_ನಕಲು(sk, keypair.signing_ಕೀಲಿ.ದತ್ತಾಂಶ, MLDSA87_SECRETKEYBYTES);

	explicit_bzero(&keypair, ಗಾತ್ರ(keypair));
	explicit_bzero(&rnd, ಗಾತ್ರ(rnd));
	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
crypto_sign_mldsa87(uint8_t sig[MLDSA87_SIGBYTES],
    ಸ್ಥಿರಾಂಕ uint8_t *ಸಂದೇಶ, ಗಾತ್ರ_t msglen,
    ಸ್ಥಿರಾಂಕ uint8_t *ctx, ಗಾತ್ರ_t ctxlen,
    ಸ್ಥಿರಾಂಕ uint8_t sk[MLDSA87_SECRETKEYBYTES])
{
	uint8_t rnd[MLDSA87_SEEDBYTES];
	ಪೂರ್ಣಾಂಕ r;

	arc4random_buf(rnd, ಗಾತ್ರ(rnd));
	r = crypto_sign_mldsa87_seeded(sig, ಸಂದೇಶ, msglen, ctx, ctxlen, sk, rnd);
	explicit_bzero(rnd, ಗಾತ್ರ(rnd));
	ಹಿಂತಿರುಗಿ r;
}

ಪೂರ್ಣಾಂಕ
crypto_sign_mldsa87_seeded(uint8_t sig[MLDSA87_SIGBYTES],
    ಸ್ಥಿರಾಂಕ uint8_t *ಸಂದೇಶ, ಗಾತ್ರ_t msglen,
    ಸ್ಥಿರಾಂಕ uint8_t *ctx, ಗಾತ್ರ_t ctxlen,
    ಸ್ಥಿರಾಂಕ uint8_t sk[MLDSA87_SECRETKEYBYTES],
    ಸ್ಥಿರಾಂಕ uint8_t ಬೀಜ[MLDSA87_SEEDBYTES])
{
	libcrux_mldsa87_sign_rnd rnd;
	libcrux_mldsa87_sk sk_ಆಂತರಿಕ;
	libcrux_mldsa87_ಸಂದೇಶ ಸಂದೇಶ_2 = { ಸಂದೇಶ, msglen };
	libcrux_mldsa87_ಸಂದೇಶ context = { ctx, ctxlen };
	libcrux_mldsa87_sign_ಫಲಿತಾಂಶ res;
	ಪೂರ್ಣಾಂಕ r = -1;

	ಸ್ಮರಣೆ_ನಕಲು(sk_ಆಂತರಿಕ.ದತ್ತಾಂಶ, sk, MLDSA87_SECRETKEYBYTES);
	ಸ್ಮರಣೆ_ನಕಲು(rnd.ದತ್ತಾಂಶ, ಬೀಜ, ಗಾತ್ರ(rnd.ದತ್ತಾಂಶ));
	res = libcrux_ml_dsa_ml_dsa_87_portable_sign(&sk_ಆಂತರಿಕ,
	    ಸಂದೇಶ_2, context, rnd);
	ಆದರೆ (res.ಟ್ಯಾಗ್ == LIBCRUX_ಫಲಿತಾಂಶ_OK) {
		ಸ್ಮರಣೆ_ನಕಲು(sig, res.val.case_Ok.ದತ್ತಾಂಶ, MLDSA87_SIGBYTES);
		r = 0;
	}

	explicit_bzero(&sk_ಆಂತರಿಕ, ಗಾತ್ರ(sk_ಆಂತರಿಕ));
	explicit_bzero(&res, ಗಾತ್ರ(res));
	explicit_bzero(&rnd, ಗಾತ್ರ(rnd));
	ಹಿಂತಿರುಗಿ r;
}

ಪೂರ್ಣಾಂಕ
crypto_sign_mldsa87_verify(ಸ್ಥಿರಾಂಕ uint8_t sig[MLDSA87_SIGBYTES],
    ಸ್ಥಿರಾಂಕ uint8_t *ಸಂದೇಶ, ಗಾತ್ರ_t msglen,
    ಸ್ಥಿರಾಂಕ uint8_t *ctx, ಗಾತ್ರ_t ctxlen,
    ಸ್ಥಿರಾಂಕ uint8_t pk[MLDSA87_PUBLICKEYBYTES])
{
	libcrux_mldsa87_pk pk_ಆಂತರಿಕ;
	libcrux_mldsa87_signature sig_ಆಂತರಿಕ;
	libcrux_mldsa87_ಸಂದೇಶ ಸಂದೇಶ_2 = { ಸಂದೇಶ, msglen };
	libcrux_mldsa87_ಸಂದೇಶ context = { ctx, ctxlen };
	libcrux_mldsa87_verify_ಫಲಿತಾಂಶ res;

	ಸ್ಮರಣೆ_ನಕಲು(pk_ಆಂತರಿಕ.ದತ್ತಾಂಶ, pk, MLDSA87_PUBLICKEYBYTES);
	ಸ್ಮರಣೆ_ನಕಲು(sig_ಆಂತರಿಕ.ದತ್ತಾಂಶ, sig, MLDSA87_SIGBYTES);
	res = libcrux_ml_dsa_ml_dsa_87_portable_verify(&pk_ಆಂತರಿಕ,
	    ಸಂದೇಶ_2, context, &sig_ಆಂತರಿಕ);

	ಹಿಂತಿರುಗಿ (res.ಟ್ಯಾಗ್ == LIBCRUX_ಫಲಿತಾಂಶ_OK) ? 0 : -1;
}
#ಆದರೆ_ಅಂತ್ಯ

ಶೂನ್ಯ
sha3_256(uint8_t digest[32], ಸ್ಥಿರಾಂಕ uint8_t *ದತ್ತಾಂಶ, ಗಾತ್ರ_t len)
{
	Eurydice_borrow_ತುಂಡು_u8 ಒಳಹರಿವು = { ದತ್ತಾಂಶ, len };
	Eurydice_mut_borrow_ತುಂಡು_u8 output = { digest, 32 };
	libcrux_sha3_portable_sha256(output, ಒಳಹರಿವು);
}

ಶೂನ್ಯ
sha3_512(uint8_t digest[64], ಸ್ಥಿರಾಂಕ uint8_t *ದತ್ತಾಂಶ, ಗಾತ್ರ_t len)
{
	Eurydice_borrow_ತುಂಡು_u8 ಒಳಹರಿವು = { ದತ್ತಾಂಶ, len };
	Eurydice_mut_borrow_ತುಂಡು_u8 output = { digest, 64 };
	libcrux_sha3_portable_sha512(output, ಒಳಹರಿವು);
}
#ಆದರೆ_ಅಂತ್ಯ /* defined(USE_MLDSA) || defined(USE_MLKEM768X25519) */
