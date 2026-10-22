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

#অন্তর্ভাব "includes.h"

#যদি defined(USE_MLDSA) || defined(USE_MLKEM768X25519)

#অন্তর্ভাব <sys/types.h>
#অন্তর্ভাব <stdint.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <stdbool.h>
#অন্তর্ভাব <string.h>

#অন্তর্ভাব "log.h"
#অন্তর্ভাব "crypto_api.h"
#অন্তর্ভাব "libcrux_internal.h"

/* ML-KEM 768 */

পূর্ণসংখ্যা
crypto_kem_mlkem768_keypair(uint8_t pk[crypto_kem_mlkem768_PUBLICKEYBYTES],
    uint8_t sk[crypto_kem_mlkem768_SECRETKEYBYTES])
{
	uint8_t rnd[crypto_kem_mlkem768_KEYPAIRSEEDBYTES];
	পূর্ণসংখ্যা r;

	arc4random_buf(rnd, আকার(rnd));
	r = crypto_kem_mlkem768_keypair_seeded(pk, sk, rnd);
	explicit_bzero(rnd, আকার(rnd));
	ফেরত r;
}

পূর্ণসংখ্যা
crypto_kem_mlkem768_keypair_seeded(uint8_t pk[crypto_kem_mlkem768_PUBLICKEYBYTES],
    uint8_t sk[crypto_kem_mlkem768_SECRETKEYBYTES],
    ধ্রুবক uint8_t seed[crypto_kem_mlkem768_KEYPAIRSEEDBYTES])
{
	libcrux_mlkem768_keypair keypair;
	libcrux_mlkem768_keypair_rnd rnd;

	memcpy(rnd.তথ্য, seed, আকার(rnd.তথ্য));
	keypair = libcrux_ml_kem_mlkem768_portable_generate_চাবি_pair(rnd);
	memcpy(pk, keypair.pk.তথ্য, crypto_kem_mlkem768_PUBLICKEYBYTES);
	memcpy(sk, keypair.sk.তথ্য, crypto_kem_mlkem768_SECRETKEYBYTES);

	explicit_bzero(&keypair, আকার(keypair));
	explicit_bzero(&rnd, আকার(rnd));
	ফেরত 0;
}

পূর্ণসংখ্যা
crypto_kem_mlkem768_enc(uint8_t ct[crypto_kem_mlkem768_CIPHERTEXTBYTES],
    uint8_t shared_secret[crypto_kem_mlkem768_BYTES],
    ধ্রুবক uint8_t pk[crypto_kem_mlkem768_PUBLICKEYBYTES])
{
	uint8_t rnd[crypto_kem_mlkem768_ENCSEEDBYTES];
	পূর্ণসংখ্যা r;

	arc4random_buf(rnd, আকার(rnd));
	r = crypto_kem_mlkem768_enc_seeded(ct, shared_secret, pk, rnd);
	explicit_bzero(rnd, আকার(rnd));
	ফেরত r;
}

পূর্ণসংখ্যা
crypto_kem_mlkem768_enc_seeded(uint8_t ct[crypto_kem_mlkem768_CIPHERTEXTBYTES],
    uint8_t shared_secret[crypto_kem_mlkem768_BYTES],
    ধ্রুবক uint8_t pk[crypto_kem_mlkem768_PUBLICKEYBYTES],
    ধ্রুবক uint8_t seed[crypto_kem_mlkem768_ENCSEEDBYTES])
{
	libcrux_mlkem768_enc_ফলাফল enc;
	libcrux_mlkem768_pk pk_internal;
	libcrux_mlkem768_enc_rnd rnd;

	memcpy(pk_internal.তথ্য, pk, crypto_kem_mlkem768_PUBLICKEYBYTES);
	যদি (!libcrux_ml_kem_mlkem768_portable_validate_public_চাবি(&pk_internal))
		ফেরত -1;
	memcpy(rnd.তথ্য, seed, আকার(rnd.তথ্য));
	enc = libcrux_ml_kem_mlkem768_portable_encapsulate(&pk_internal, rnd);
	memcpy(ct, enc.fst.তথ্য, crypto_kem_mlkem768_CIPHERTEXTBYTES);
	memcpy(shared_secret, enc.snd.তথ্য, crypto_kem_mlkem768_BYTES);

	explicit_bzero(&enc, আকার(enc));
	explicit_bzero(&rnd, আকার(rnd));
	ফেরত 0;
}

পূর্ণসংখ্যা
crypto_kem_mlkem768_dec(uint8_t shared_secret[crypto_kem_mlkem768_BYTES],
    ধ্রুবক uint8_t ct[crypto_kem_mlkem768_CIPHERTEXTBYTES],
    ধ্রুবক uint8_t sk[crypto_kem_mlkem768_SECRETKEYBYTES])
{
	libcrux_mlkem768_sk sk_internal;
	libcrux_mlkem768_ciphertext ct_internal;
	libcrux_mlkem768_dec_ফলাফল shared_secret_internal;

	memcpy(sk_internal.তথ্য, sk, crypto_kem_mlkem768_SECRETKEYBYTES);
	memcpy(ct_internal.তথ্য, ct, crypto_kem_mlkem768_CIPHERTEXTBYTES);
	shared_secret_internal = libcrux_ml_kem_mlkem768_portable_decapsulate(
	    &sk_internal, &ct_internal);
	memcpy(shared_secret, shared_secret_internal.তথ্য,
	    crypto_kem_mlkem768_BYTES);

	explicit_bzero(&sk_internal, আকার(sk_internal));
	explicit_bzero(&shared_secret_internal, আকার(shared_secret_internal));
	ফেরত 0;
}

/* ML-DSA 44 */

পূর্ণসংখ্যা
crypto_sign_mldsa44_keypair(uint8_t pk[MLDSA44_PUBLICKEYBYTES],
    uint8_t sk[MLDSA44_SECRETKEYBYTES])
{
	uint8_t rnd[MLDSA44_SEEDBYTES];
	পূর্ণসংখ্যা r;

	arc4random_buf(rnd, আকার(rnd));
	r = crypto_sign_mldsa44_keypair_seeded(pk, sk, rnd);
	explicit_bzero(rnd, আকার(rnd));
	ফেরত r;
}

পূর্ণসংখ্যা
crypto_sign_mldsa44_keypair_seeded(uint8_t pk[MLDSA44_PUBLICKEYBYTES],
    uint8_t sk[MLDSA44_SECRETKEYBYTES], ধ্রুবক uint8_t seed[MLDSA44_SEEDBYTES])
{
	libcrux_mldsa44_keypair_rnd rnd;
	libcrux_mldsa44_keypair keypair;

	memcpy(rnd.তথ্য, seed, আকার(rnd.তথ্য));
	keypair = libcrux_ml_dsa_ml_dsa_44_portable_generate_চাবি_pair(rnd);
	memcpy(pk, keypair.verification_চাবি.তথ্য, MLDSA44_PUBLICKEYBYTES);
	memcpy(sk, keypair.signing_চাবি.তথ্য, MLDSA44_SECRETKEYBYTES);

	explicit_bzero(&keypair, আকার(keypair));
	explicit_bzero(&rnd, আকার(rnd));
	ফেরত 0;
}

পূর্ণসংখ্যা
crypto_sign_mldsa44(uint8_t sig[MLDSA44_SIGBYTES],
    ধ্রুবক uint8_t *বার্তা, আকার_t msglen,
    ধ্রুবক uint8_t *ctx, আকার_t ctxlen,
    ধ্রুবক uint8_t sk[MLDSA44_SECRETKEYBYTES])
{
	uint8_t rnd[MLDSA44_SEEDBYTES];
	পূর্ণসংখ্যা r;

	arc4random_buf(rnd, আকার(rnd));
	r = crypto_sign_mldsa44_seeded(sig, বার্তা, msglen, ctx, ctxlen, sk, rnd);
	explicit_bzero(rnd, আকার(rnd));
	ফেরত r;
}

পূর্ণসংখ্যা
crypto_sign_mldsa44_seeded(uint8_t sig[MLDSA44_SIGBYTES],
    ধ্রুবক uint8_t *বার্তা, আকার_t msglen,
    ধ্রুবক uint8_t *ctx, আকার_t ctxlen,
    ধ্রুবক uint8_t sk[MLDSA44_SECRETKEYBYTES],
    ধ্রুবক uint8_t seed[MLDSA44_SEEDBYTES])
{
	libcrux_mldsa44_sign_rnd rnd;
	libcrux_mldsa44_sk sk_internal;
	libcrux_mldsa44_message message = { বার্তা, msglen };
	libcrux_mldsa44_message context = { ctx, ctxlen };
	libcrux_mldsa44_sign_ফলাফল res;
	পূর্ণসংখ্যা r = -1;

	memcpy(sk_internal.তথ্য, sk, MLDSA44_SECRETKEYBYTES);
	memcpy(rnd.তথ্য, seed, আকার(rnd.তথ্য));
	res = libcrux_ml_dsa_ml_dsa_44_portable_sign(&sk_internal,
	    message, context, rnd);
	যদি (res.tag == LIBCRUX_ফলাফল_OK) {
		memcpy(sig, res.val.case_Ok.তথ্য, MLDSA44_SIGBYTES);
		r = 0;
	}

	explicit_bzero(&sk_internal, আকার(sk_internal));
	explicit_bzero(&res, আকার(res));
	explicit_bzero(&rnd, আকার(rnd));
	ফেরত r;
}

পূর্ণসংখ্যা
crypto_sign_mldsa44_verify(ধ্রুবক uint8_t sig[MLDSA44_SIGBYTES],
    ধ্রুবক uint8_t *বার্তা, আকার_t msglen,
    ধ্রুবক uint8_t *ctx, আকার_t ctxlen,
    ধ্রুবক uint8_t pk[MLDSA44_PUBLICKEYBYTES])
{
	libcrux_mldsa44_pk pk_internal;
	libcrux_mldsa44_signature sig_internal;
	libcrux_mldsa44_message message = { বার্তা, msglen };
	libcrux_mldsa44_message context = { ctx, ctxlen };
	libcrux_mldsa44_verify_ফলাফল res;

	memcpy(pk_internal.তথ্য, pk, MLDSA44_PUBLICKEYBYTES);
	memcpy(sig_internal.তথ্য, sig, MLDSA44_SIGBYTES);
	res = libcrux_ml_dsa_ml_dsa_44_portable_verify(&pk_internal,
	    message, context, &sig_internal);

	ফেরত (res.tag == LIBCRUX_ফলাফল_OK) ? 0 : -1;
}

/* ML-DSA 65 */

#যদি 0
পূর্ণসংখ্যা
crypto_sign_mldsa65_keypair(uint8_t pk[MLDSA65_PUBLICKEYBYTES],
    uint8_t sk[MLDSA65_SECRETKEYBYTES])
{
	uint8_t rnd[MLDSA65_SEEDBYTES];
	পূর্ণসংখ্যা r;

	arc4random_buf(rnd, আকার(rnd));
	r = crypto_sign_mldsa65_keypair_seeded(pk, sk, rnd);
	explicit_bzero(rnd, আকার(rnd));
	ফেরত r;
}

পূর্ণসংখ্যা
crypto_sign_mldsa65_keypair_seeded(uint8_t pk[MLDSA65_PUBLICKEYBYTES],
    uint8_t sk[MLDSA65_SECRETKEYBYTES], ধ্রুবক uint8_t seed[MLDSA65_SEEDBYTES])
{
	libcrux_mldsa65_keypair_rnd rnd;
	libcrux_mldsa65_keypair keypair;

	memcpy(rnd.তথ্য, seed, আকার(rnd.তথ্য));
	keypair = libcrux_ml_dsa_ml_dsa_65_portable_generate_চাবি_pair(rnd);
	memcpy(pk, keypair.verification_চাবি.তথ্য, MLDSA65_PUBLICKEYBYTES);
	memcpy(sk, keypair.signing_চাবি.তথ্য, MLDSA65_SECRETKEYBYTES);

	explicit_bzero(&keypair, আকার(keypair));
	explicit_bzero(&rnd, আকার(rnd));
	ফেরত 0;
}

পূর্ণসংখ্যা
crypto_sign_mldsa65(uint8_t sig[MLDSA65_SIGBYTES],
    ধ্রুবক uint8_t *বার্তা, আকার_t msglen,
    ধ্রুবক uint8_t *ctx, আকার_t ctxlen,
    ধ্রুবক uint8_t sk[MLDSA65_SECRETKEYBYTES])
{
	uint8_t rnd[MLDSA65_SEEDBYTES];
	পূর্ণসংখ্যা r;

	arc4random_buf(rnd, আকার(rnd));
	r = crypto_sign_mldsa65_seeded(sig, বার্তা, msglen, ctx, ctxlen, sk, rnd);
	explicit_bzero(rnd, আকার(rnd));
	ফেরত r;
}

পূর্ণসংখ্যা
crypto_sign_mldsa65_seeded(uint8_t sig[MLDSA65_SIGBYTES],
    ধ্রুবক uint8_t *বার্তা, আকার_t msglen,
    ধ্রুবক uint8_t *ctx, আকার_t ctxlen,
    ধ্রুবক uint8_t sk[MLDSA65_SECRETKEYBYTES],
    ধ্রুবক uint8_t seed[MLDSA65_SEEDBYTES])
{
	libcrux_mldsa65_sign_rnd rnd;
	libcrux_mldsa65_sk sk_internal;
	libcrux_mldsa65_message message = { বার্তা, msglen };
	libcrux_mldsa65_message context = { ctx, ctxlen };
	libcrux_mldsa65_sign_ফলাফল res;
	পূর্ণসংখ্যা r = -1;

	memcpy(sk_internal.তথ্য, sk, MLDSA65_SECRETKEYBYTES);
	memcpy(rnd.তথ্য, seed, আকার(rnd.তথ্য));
	res = libcrux_ml_dsa_ml_dsa_65_portable_sign(&sk_internal,
	    message, context, rnd);
	যদি (res.tag == LIBCRUX_ফলাফল_OK) {
		memcpy(sig, res.val.case_Ok.তথ্য, MLDSA65_SIGBYTES);
		r = 0;
	}

	explicit_bzero(&sk_internal, আকার(sk_internal));
	explicit_bzero(&res, আকার(res));
	explicit_bzero(&rnd, আকার(rnd));
	ফেরত r;
}

পূর্ণসংখ্যা
crypto_sign_mldsa65_verify(ধ্রুবক uint8_t sig[MLDSA65_SIGBYTES],
    ধ্রুবক uint8_t *বার্তা, আকার_t msglen,
    ধ্রুবক uint8_t *ctx, আকার_t ctxlen,
    ধ্রুবক uint8_t pk[MLDSA65_PUBLICKEYBYTES])
{
	libcrux_mldsa65_pk pk_internal;
	libcrux_mldsa65_signature sig_internal;
	libcrux_mldsa65_message message = { বার্তা, msglen };
	libcrux_mldsa65_message context = { ctx, ctxlen };
	libcrux_mldsa65_verify_ফলাফল res;

	memcpy(pk_internal.তথ্য, pk, MLDSA65_PUBLICKEYBYTES);
	memcpy(sig_internal.তথ্য, sig, MLDSA65_SIGBYTES);
	res = libcrux_ml_dsa_ml_dsa_65_portable_verify(&pk_internal,
	    message, context, &sig_internal);

	ফেরত (res.tag == LIBCRUX_ফলাফল_OK) ? 0 : -1;
}
#endif

/* ML-DSA 87 */

#যদি 0
পূর্ণসংখ্যা
crypto_sign_mldsa87_keypair(uint8_t pk[MLDSA87_PUBLICKEYBYTES],
    uint8_t sk[MLDSA87_SECRETKEYBYTES])
{
	uint8_t rnd[MLDSA87_SEEDBYTES];
	পূর্ণসংখ্যা r;

	arc4random_buf(rnd, আকার(rnd));
	r = crypto_sign_mldsa87_keypair_seeded(pk, sk, rnd);
	explicit_bzero(rnd, আকার(rnd));
	ফেরত r;
}

পূর্ণসংখ্যা
crypto_sign_mldsa87_keypair_seeded(uint8_t pk[MLDSA87_PUBLICKEYBYTES],
    uint8_t sk[MLDSA87_SECRETKEYBYTES], ধ্রুবক uint8_t seed[MLDSA87_SEEDBYTES])
{
	libcrux_mldsa87_keypair_rnd rnd;
	libcrux_mldsa87_keypair keypair;

	memcpy(rnd.তথ্য, seed, আকার(rnd.তথ্য));
	keypair = libcrux_ml_dsa_ml_dsa_87_portable_generate_চাবি_pair(rnd);
	memcpy(pk, keypair.verification_চাবি.তথ্য, MLDSA87_PUBLICKEYBYTES);
	memcpy(sk, keypair.signing_চাবি.তথ্য, MLDSA87_SECRETKEYBYTES);

	explicit_bzero(&keypair, আকার(keypair));
	explicit_bzero(&rnd, আকার(rnd));
	ফেরত 0;
}

পূর্ণসংখ্যা
crypto_sign_mldsa87(uint8_t sig[MLDSA87_SIGBYTES],
    ধ্রুবক uint8_t *বার্তা, আকার_t msglen,
    ধ্রুবক uint8_t *ctx, আকার_t ctxlen,
    ধ্রুবক uint8_t sk[MLDSA87_SECRETKEYBYTES])
{
	uint8_t rnd[MLDSA87_SEEDBYTES];
	পূর্ণসংখ্যা r;

	arc4random_buf(rnd, আকার(rnd));
	r = crypto_sign_mldsa87_seeded(sig, বার্তা, msglen, ctx, ctxlen, sk, rnd);
	explicit_bzero(rnd, আকার(rnd));
	ফেরত r;
}

পূর্ণসংখ্যা
crypto_sign_mldsa87_seeded(uint8_t sig[MLDSA87_SIGBYTES],
    ধ্রুবক uint8_t *বার্তা, আকার_t msglen,
    ধ্রুবক uint8_t *ctx, আকার_t ctxlen,
    ধ্রুবক uint8_t sk[MLDSA87_SECRETKEYBYTES],
    ধ্রুবক uint8_t seed[MLDSA87_SEEDBYTES])
{
	libcrux_mldsa87_sign_rnd rnd;
	libcrux_mldsa87_sk sk_internal;
	libcrux_mldsa87_message message = { বার্তা, msglen };
	libcrux_mldsa87_message context = { ctx, ctxlen };
	libcrux_mldsa87_sign_ফলাফল res;
	পূর্ণসংখ্যা r = -1;

	memcpy(sk_internal.তথ্য, sk, MLDSA87_SECRETKEYBYTES);
	memcpy(rnd.তথ্য, seed, আকার(rnd.তথ্য));
	res = libcrux_ml_dsa_ml_dsa_87_portable_sign(&sk_internal,
	    message, context, rnd);
	যদি (res.tag == LIBCRUX_ফলাফল_OK) {
		memcpy(sig, res.val.case_Ok.তথ্য, MLDSA87_SIGBYTES);
		r = 0;
	}

	explicit_bzero(&sk_internal, আকার(sk_internal));
	explicit_bzero(&res, আকার(res));
	explicit_bzero(&rnd, আকার(rnd));
	ফেরত r;
}

পূর্ণসংখ্যা
crypto_sign_mldsa87_verify(ধ্রুবক uint8_t sig[MLDSA87_SIGBYTES],
    ধ্রুবক uint8_t *বার্তা, আকার_t msglen,
    ধ্রুবক uint8_t *ctx, আকার_t ctxlen,
    ধ্রুবক uint8_t pk[MLDSA87_PUBLICKEYBYTES])
{
	libcrux_mldsa87_pk pk_internal;
	libcrux_mldsa87_signature sig_internal;
	libcrux_mldsa87_message message = { বার্তা, msglen };
	libcrux_mldsa87_message context = { ctx, ctxlen };
	libcrux_mldsa87_verify_ফলাফল res;

	memcpy(pk_internal.তথ্য, pk, MLDSA87_PUBLICKEYBYTES);
	memcpy(sig_internal.তথ্য, sig, MLDSA87_SIGBYTES);
	res = libcrux_ml_dsa_ml_dsa_87_portable_verify(&pk_internal,
	    message, context, &sig_internal);

	ফেরত (res.tag == LIBCRUX_ফলাফল_OK) ? 0 : -1;
}
#endif

শূন্য
sha3_256(uint8_t digest[32], ধ্রুবক uint8_t *তথ্য, আকার_t len)
{
	Eurydice_borrow_slice_u8 প্রবেশ = { তথ্য, len };
	Eurydice_mut_borrow_slice_u8 output = { digest, 32 };
	libcrux_sha3_portable_sha256(output, প্রবেশ);
}

শূন্য
sha3_512(uint8_t digest[64], ধ্রুবক uint8_t *তথ্য, আকার_t len)
{
	Eurydice_borrow_slice_u8 প্রবেশ = { তথ্য, len };
	Eurydice_mut_borrow_slice_u8 output = { digest, 64 };
	libcrux_sha3_portable_sha512(output, প্রবেশ);
}
#endif /* defined(USE_MLDSA) || defined(USE_MLKEM768X25519) */
