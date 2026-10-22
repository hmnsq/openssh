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

#जर defined(USE_MLDSA) || defined(USE_MLKEM768X25519)

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <stdint.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <stdbool.h>
#अन्तर्भाव <string.h>

#अन्तर्भाव "log.h"
#अन्तर्भाव "crypto_api.h"
#अन्तर्भाव "libcrux_internal.h"

/* ML-KEM 768 */

पूर्णांक
crypto_kem_mlkem768_keypair(uint8_t pk[crypto_kem_mlkem768_PUBLICKEYBYTES],
    uint8_t sk[crypto_kem_mlkem768_SECRETKEYBYTES])
{
	uint8_t rnd[crypto_kem_mlkem768_KEYPAIRSEEDBYTES];
	पूर्णांक r;

	arc4random_buf(rnd, आकार(rnd));
	r = crypto_kem_mlkem768_keypair_seeded(pk, sk, rnd);
	explicit_bzero(rnd, आकार(rnd));
	परत r;
}

पूर्णांक
crypto_kem_mlkem768_keypair_seeded(uint8_t pk[crypto_kem_mlkem768_PUBLICKEYBYTES],
    uint8_t sk[crypto_kem_mlkem768_SECRETKEYBYTES],
    स्थिरांक uint8_t seed[crypto_kem_mlkem768_KEYPAIRSEEDBYTES])
{
	libcrux_mlkem768_keypair keypair;
	libcrux_mlkem768_keypair_rnd rnd;

	स_नकल(rnd.data, seed, आकार(rnd.data));
	keypair = libcrux_ml_kem_mlkem768_portable_generate_किल्ली_pair(rnd);
	स_नकल(pk, keypair.pk.data, crypto_kem_mlkem768_PUBLICKEYBYTES);
	स_नकल(sk, keypair.sk.data, crypto_kem_mlkem768_SECRETKEYBYTES);

	explicit_bzero(&keypair, आकार(keypair));
	explicit_bzero(&rnd, आकार(rnd));
	परत 0;
}

पूर्णांक
crypto_kem_mlkem768_enc(uint8_t ct[crypto_kem_mlkem768_CIPHERTEXTBYTES],
    uint8_t shared_secret[crypto_kem_mlkem768_BYTES],
    स्थिरांक uint8_t pk[crypto_kem_mlkem768_PUBLICKEYBYTES])
{
	uint8_t rnd[crypto_kem_mlkem768_ENCSEEDBYTES];
	पूर्णांक r;

	arc4random_buf(rnd, आकार(rnd));
	r = crypto_kem_mlkem768_enc_seeded(ct, shared_secret, pk, rnd);
	explicit_bzero(rnd, आकार(rnd));
	परत r;
}

पूर्णांक
crypto_kem_mlkem768_enc_seeded(uint8_t ct[crypto_kem_mlkem768_CIPHERTEXTBYTES],
    uint8_t shared_secret[crypto_kem_mlkem768_BYTES],
    स्थिरांक uint8_t pk[crypto_kem_mlkem768_PUBLICKEYBYTES],
    स्थिरांक uint8_t seed[crypto_kem_mlkem768_ENCSEEDBYTES])
{
	libcrux_mlkem768_enc_result enc;
	libcrux_mlkem768_pk pk_internal;
	libcrux_mlkem768_enc_rnd rnd;

	स_नकल(pk_internal.data, pk, crypto_kem_mlkem768_PUBLICKEYBYTES);
	जर (!libcrux_ml_kem_mlkem768_portable_validate_public_किल्ली(&pk_internal))
		परत -1;
	स_नकल(rnd.data, seed, आकार(rnd.data));
	enc = libcrux_ml_kem_mlkem768_portable_encapsulate(&pk_internal, rnd);
	स_नकल(ct, enc.fst.data, crypto_kem_mlkem768_CIPHERTEXTBYTES);
	स_नकल(shared_secret, enc.snd.data, crypto_kem_mlkem768_BYTES);

	explicit_bzero(&enc, आकार(enc));
	explicit_bzero(&rnd, आकार(rnd));
	परत 0;
}

पूर्णांक
crypto_kem_mlkem768_dec(uint8_t shared_secret[crypto_kem_mlkem768_BYTES],
    स्थिरांक uint8_t ct[crypto_kem_mlkem768_CIPHERTEXTBYTES],
    स्थिरांक uint8_t sk[crypto_kem_mlkem768_SECRETKEYBYTES])
{
	libcrux_mlkem768_sk sk_internal;
	libcrux_mlkem768_ciphertext ct_internal;
	libcrux_mlkem768_dec_result shared_secret_internal;

	स_नकल(sk_internal.data, sk, crypto_kem_mlkem768_SECRETKEYBYTES);
	स_नकल(ct_internal.data, ct, crypto_kem_mlkem768_CIPHERTEXTBYTES);
	shared_secret_internal = libcrux_ml_kem_mlkem768_portable_decapsulate(
	    &sk_internal, &ct_internal);
	स_नकल(shared_secret, shared_secret_internal.data,
	    crypto_kem_mlkem768_BYTES);

	explicit_bzero(&sk_internal, आकार(sk_internal));
	explicit_bzero(&shared_secret_internal, आकार(shared_secret_internal));
	परत 0;
}

/* ML-DSA 44 */

पूर्णांक
crypto_sign_mldsa44_keypair(uint8_t pk[MLDSA44_PUBLICKEYBYTES],
    uint8_t sk[MLDSA44_SECRETKEYBYTES])
{
	uint8_t rnd[MLDSA44_SEEDBYTES];
	पूर्णांक r;

	arc4random_buf(rnd, आकार(rnd));
	r = crypto_sign_mldsa44_keypair_seeded(pk, sk, rnd);
	explicit_bzero(rnd, आकार(rnd));
	परत r;
}

पूर्णांक
crypto_sign_mldsa44_keypair_seeded(uint8_t pk[MLDSA44_PUBLICKEYBYTES],
    uint8_t sk[MLDSA44_SECRETKEYBYTES], स्थिरांक uint8_t seed[MLDSA44_SEEDBYTES])
{
	libcrux_mldsa44_keypair_rnd rnd;
	libcrux_mldsa44_keypair keypair;

	स_नकल(rnd.data, seed, आकार(rnd.data));
	keypair = libcrux_ml_dsa_ml_dsa_44_portable_generate_किल्ली_pair(rnd);
	स_नकल(pk, keypair.verification_किल्ली.data, MLDSA44_PUBLICKEYBYTES);
	स_नकल(sk, keypair.signing_किल्ली.data, MLDSA44_SECRETKEYBYTES);

	explicit_bzero(&keypair, आकार(keypair));
	explicit_bzero(&rnd, आकार(rnd));
	परत 0;
}

पूर्णांक
crypto_sign_mldsa44(uint8_t sig[MLDSA44_SIGBYTES],
    स्थिरांक uint8_t *संदेश, माप_प्रकार msglen,
    स्थिरांक uint8_t *ctx, माप_प्रकार ctxlen,
    स्थिरांक uint8_t sk[MLDSA44_SECRETKEYBYTES])
{
	uint8_t rnd[MLDSA44_SEEDBYTES];
	पूर्णांक r;

	arc4random_buf(rnd, आकार(rnd));
	r = crypto_sign_mldsa44_seeded(sig, संदेश, msglen, ctx, ctxlen, sk, rnd);
	explicit_bzero(rnd, आकार(rnd));
	परत r;
}

पूर्णांक
crypto_sign_mldsa44_seeded(uint8_t sig[MLDSA44_SIGBYTES],
    स्थिरांक uint8_t *संदेश, माप_प्रकार msglen,
    स्थिरांक uint8_t *ctx, माप_प्रकार ctxlen,
    स्थिरांक uint8_t sk[MLDSA44_SECRETKEYBYTES],
    स्थिरांक uint8_t seed[MLDSA44_SEEDBYTES])
{
	libcrux_mldsa44_sign_rnd rnd;
	libcrux_mldsa44_sk sk_internal;
	libcrux_mldsa44_message message = { संदेश, msglen };
	libcrux_mldsa44_message context = { ctx, ctxlen };
	libcrux_mldsa44_sign_result res;
	पूर्णांक r = -1;

	स_नकल(sk_internal.data, sk, MLDSA44_SECRETKEYBYTES);
	स_नकल(rnd.data, seed, आकार(rnd.data));
	res = libcrux_ml_dsa_ml_dsa_44_portable_sign(&sk_internal,
	    message, context, rnd);
	जर (res.tag == LIBCRUX_RESULT_OK) {
		स_नकल(sig, res.val.case_Ok.data, MLDSA44_SIGBYTES);
		r = 0;
	}

	explicit_bzero(&sk_internal, आकार(sk_internal));
	explicit_bzero(&res, आकार(res));
	explicit_bzero(&rnd, आकार(rnd));
	परत r;
}

पूर्णांक
crypto_sign_mldsa44_verify(स्थिरांक uint8_t sig[MLDSA44_SIGBYTES],
    स्थिरांक uint8_t *संदेश, माप_प्रकार msglen,
    स्थिरांक uint8_t *ctx, माप_प्रकार ctxlen,
    स्थिरांक uint8_t pk[MLDSA44_PUBLICKEYBYTES])
{
	libcrux_mldsa44_pk pk_internal;
	libcrux_mldsa44_signature sig_internal;
	libcrux_mldsa44_message message = { संदेश, msglen };
	libcrux_mldsa44_message context = { ctx, ctxlen };
	libcrux_mldsa44_verify_result res;

	स_नकल(pk_internal.data, pk, MLDSA44_PUBLICKEYBYTES);
	स_नकल(sig_internal.data, sig, MLDSA44_SIGBYTES);
	res = libcrux_ml_dsa_ml_dsa_44_portable_verify(&pk_internal,
	    message, context, &sig_internal);

	परत (res.tag == LIBCRUX_RESULT_OK) ? 0 : -1;
}

/* ML-DSA 65 */

#जर 0
पूर्णांक
crypto_sign_mldsa65_keypair(uint8_t pk[MLDSA65_PUBLICKEYBYTES],
    uint8_t sk[MLDSA65_SECRETKEYBYTES])
{
	uint8_t rnd[MLDSA65_SEEDBYTES];
	पूर्णांक r;

	arc4random_buf(rnd, आकार(rnd));
	r = crypto_sign_mldsa65_keypair_seeded(pk, sk, rnd);
	explicit_bzero(rnd, आकार(rnd));
	परत r;
}

पूर्णांक
crypto_sign_mldsa65_keypair_seeded(uint8_t pk[MLDSA65_PUBLICKEYBYTES],
    uint8_t sk[MLDSA65_SECRETKEYBYTES], स्थिरांक uint8_t seed[MLDSA65_SEEDBYTES])
{
	libcrux_mldsa65_keypair_rnd rnd;
	libcrux_mldsa65_keypair keypair;

	स_नकल(rnd.data, seed, आकार(rnd.data));
	keypair = libcrux_ml_dsa_ml_dsa_65_portable_generate_किल्ली_pair(rnd);
	स_नकल(pk, keypair.verification_किल्ली.data, MLDSA65_PUBLICKEYBYTES);
	स_नकल(sk, keypair.signing_किल्ली.data, MLDSA65_SECRETKEYBYTES);

	explicit_bzero(&keypair, आकार(keypair));
	explicit_bzero(&rnd, आकार(rnd));
	परत 0;
}

पूर्णांक
crypto_sign_mldsa65(uint8_t sig[MLDSA65_SIGBYTES],
    स्थिरांक uint8_t *संदेश, माप_प्रकार msglen,
    स्थिरांक uint8_t *ctx, माप_प्रकार ctxlen,
    स्थिरांक uint8_t sk[MLDSA65_SECRETKEYBYTES])
{
	uint8_t rnd[MLDSA65_SEEDBYTES];
	पूर्णांक r;

	arc4random_buf(rnd, आकार(rnd));
	r = crypto_sign_mldsa65_seeded(sig, संदेश, msglen, ctx, ctxlen, sk, rnd);
	explicit_bzero(rnd, आकार(rnd));
	परत r;
}

पूर्णांक
crypto_sign_mldsa65_seeded(uint8_t sig[MLDSA65_SIGBYTES],
    स्थिरांक uint8_t *संदेश, माप_प्रकार msglen,
    स्थिरांक uint8_t *ctx, माप_प्रकार ctxlen,
    स्थिरांक uint8_t sk[MLDSA65_SECRETKEYBYTES],
    स्थिरांक uint8_t seed[MLDSA65_SEEDBYTES])
{
	libcrux_mldsa65_sign_rnd rnd;
	libcrux_mldsa65_sk sk_internal;
	libcrux_mldsa65_message message = { संदेश, msglen };
	libcrux_mldsa65_message context = { ctx, ctxlen };
	libcrux_mldsa65_sign_result res;
	पूर्णांक r = -1;

	स_नकल(sk_internal.data, sk, MLDSA65_SECRETKEYBYTES);
	स_नकल(rnd.data, seed, आकार(rnd.data));
	res = libcrux_ml_dsa_ml_dsa_65_portable_sign(&sk_internal,
	    message, context, rnd);
	जर (res.tag == LIBCRUX_RESULT_OK) {
		स_नकल(sig, res.val.case_Ok.data, MLDSA65_SIGBYTES);
		r = 0;
	}

	explicit_bzero(&sk_internal, आकार(sk_internal));
	explicit_bzero(&res, आकार(res));
	explicit_bzero(&rnd, आकार(rnd));
	परत r;
}

पूर्णांक
crypto_sign_mldsa65_verify(स्थिरांक uint8_t sig[MLDSA65_SIGBYTES],
    स्थिरांक uint8_t *संदेश, माप_प्रकार msglen,
    स्थिरांक uint8_t *ctx, माप_प्रकार ctxlen,
    स्थिरांक uint8_t pk[MLDSA65_PUBLICKEYBYTES])
{
	libcrux_mldsa65_pk pk_internal;
	libcrux_mldsa65_signature sig_internal;
	libcrux_mldsa65_message message = { संदेश, msglen };
	libcrux_mldsa65_message context = { ctx, ctxlen };
	libcrux_mldsa65_verify_result res;

	स_नकल(pk_internal.data, pk, MLDSA65_PUBLICKEYBYTES);
	स_नकल(sig_internal.data, sig, MLDSA65_SIGBYTES);
	res = libcrux_ml_dsa_ml_dsa_65_portable_verify(&pk_internal,
	    message, context, &sig_internal);

	परत (res.tag == LIBCRUX_RESULT_OK) ? 0 : -1;
}
#endif

/* ML-DSA 87 */

#जर 0
पूर्णांक
crypto_sign_mldsa87_keypair(uint8_t pk[MLDSA87_PUBLICKEYBYTES],
    uint8_t sk[MLDSA87_SECRETKEYBYTES])
{
	uint8_t rnd[MLDSA87_SEEDBYTES];
	पूर्णांक r;

	arc4random_buf(rnd, आकार(rnd));
	r = crypto_sign_mldsa87_keypair_seeded(pk, sk, rnd);
	explicit_bzero(rnd, आकार(rnd));
	परत r;
}

पूर्णांक
crypto_sign_mldsa87_keypair_seeded(uint8_t pk[MLDSA87_PUBLICKEYBYTES],
    uint8_t sk[MLDSA87_SECRETKEYBYTES], स्थिरांक uint8_t seed[MLDSA87_SEEDBYTES])
{
	libcrux_mldsa87_keypair_rnd rnd;
	libcrux_mldsa87_keypair keypair;

	स_नकल(rnd.data, seed, आकार(rnd.data));
	keypair = libcrux_ml_dsa_ml_dsa_87_portable_generate_किल्ली_pair(rnd);
	स_नकल(pk, keypair.verification_किल्ली.data, MLDSA87_PUBLICKEYBYTES);
	स_नकल(sk, keypair.signing_किल्ली.data, MLDSA87_SECRETKEYBYTES);

	explicit_bzero(&keypair, आकार(keypair));
	explicit_bzero(&rnd, आकार(rnd));
	परत 0;
}

पूर्णांक
crypto_sign_mldsa87(uint8_t sig[MLDSA87_SIGBYTES],
    स्थिरांक uint8_t *संदेश, माप_प्रकार msglen,
    स्थिरांक uint8_t *ctx, माप_प्रकार ctxlen,
    स्थिरांक uint8_t sk[MLDSA87_SECRETKEYBYTES])
{
	uint8_t rnd[MLDSA87_SEEDBYTES];
	पूर्णांक r;

	arc4random_buf(rnd, आकार(rnd));
	r = crypto_sign_mldsa87_seeded(sig, संदेश, msglen, ctx, ctxlen, sk, rnd);
	explicit_bzero(rnd, आकार(rnd));
	परत r;
}

पूर्णांक
crypto_sign_mldsa87_seeded(uint8_t sig[MLDSA87_SIGBYTES],
    स्थिरांक uint8_t *संदेश, माप_प्रकार msglen,
    स्थिरांक uint8_t *ctx, माप_प्रकार ctxlen,
    स्थिरांक uint8_t sk[MLDSA87_SECRETKEYBYTES],
    स्थिरांक uint8_t seed[MLDSA87_SEEDBYTES])
{
	libcrux_mldsa87_sign_rnd rnd;
	libcrux_mldsa87_sk sk_internal;
	libcrux_mldsa87_message message = { संदेश, msglen };
	libcrux_mldsa87_message context = { ctx, ctxlen };
	libcrux_mldsa87_sign_result res;
	पूर्णांक r = -1;

	स_नकल(sk_internal.data, sk, MLDSA87_SECRETKEYBYTES);
	स_नकल(rnd.data, seed, आकार(rnd.data));
	res = libcrux_ml_dsa_ml_dsa_87_portable_sign(&sk_internal,
	    message, context, rnd);
	जर (res.tag == LIBCRUX_RESULT_OK) {
		स_नकल(sig, res.val.case_Ok.data, MLDSA87_SIGBYTES);
		r = 0;
	}

	explicit_bzero(&sk_internal, आकार(sk_internal));
	explicit_bzero(&res, आकार(res));
	explicit_bzero(&rnd, आकार(rnd));
	परत r;
}

पूर्णांक
crypto_sign_mldsa87_verify(स्थिरांक uint8_t sig[MLDSA87_SIGBYTES],
    स्थिरांक uint8_t *संदेश, माप_प्रकार msglen,
    स्थिरांक uint8_t *ctx, माप_प्रकार ctxlen,
    स्थिरांक uint8_t pk[MLDSA87_PUBLICKEYBYTES])
{
	libcrux_mldsa87_pk pk_internal;
	libcrux_mldsa87_signature sig_internal;
	libcrux_mldsa87_message message = { संदेश, msglen };
	libcrux_mldsa87_message context = { ctx, ctxlen };
	libcrux_mldsa87_verify_result res;

	स_नकल(pk_internal.data, pk, MLDSA87_PUBLICKEYBYTES);
	स_नकल(sig_internal.data, sig, MLDSA87_SIGBYTES);
	res = libcrux_ml_dsa_ml_dsa_87_portable_verify(&pk_internal,
	    message, context, &sig_internal);

	परत (res.tag == LIBCRUX_RESULT_OK) ? 0 : -1;
}
#endif

शून्य
sha3_256(uint8_t digest[32], स्थिरांक uint8_t *data, माप_प्रकार len)
{
	Eurydice_borrow_slice_u8 आदान = { data, len };
	Eurydice_mut_borrow_slice_u8 output = { digest, 32 };
	libcrux_sha3_portable_sha256(output, आदान);
}

शून्य
sha3_512(uint8_t digest[64], स्थिरांक uint8_t *data, माप_प्रकार len)
{
	Eurydice_borrow_slice_u8 आदान = { data, len };
	Eurydice_mut_borrow_slice_u8 output = { digest, 64 };
	libcrux_sha3_portable_sha512(output, आदान);
}
#endif /* defined(USE_MLDSA) || defined(USE_MLKEM768X25519) */
