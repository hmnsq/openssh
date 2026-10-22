/* 	$OpenBSD: test_mldsa_eddsa.c,v 1.1 2026/06/14 04:08:06 djm Exp $ */
/*
 * Regress test for MLDSA44-Ed25519 composite signature
 *
 * Placed in the public domain
 */

#ಅನ್ತರ್ಭಾವ "includes.h"

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ USE_MLDSA

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stdint.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <ctype.h>
#ಅನ್ತರ್ಭಾವ <fcntl.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>

#ಅನ್ತರ್ಭಾವ "../test_helper/test_helper.h"
#ಅನ್ತರ್ಭಾವ "crypto_api.h"
#ಅನ್ತರ್ಭಾವ "ssherr.h"
#ಅನ್ತರ್ಭಾವ "sshkey.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "log.h"

/* in tests.c */
ರಚನೆ sshbuf *ತುಂಬು_ಪಠ್ಯ_file(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *name);
ಅಕ್ಷರ *get_json_string(ರಚನೆ sshbuf *content, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಕೀಲಿ, ಪೂರ್ಣಾಂಕ consume);

ಶೂನ್ಯ mldsa_eddsa_tests(ಶೂನ್ಯ);

/*
 * Simple JSON-ish parser for tvec.json.
 * Extracts the base64 value for a given key and decodes it into a new sshbuf.
 * Errors cause ASSERT_* failures.
 */
ಸ್ಥಿರ ರಚನೆ sshbuf *
get_json_b64(ರಚನೆ sshbuf *content, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಕೀಲಿ)
{
	ಅಕ್ಷರ *b64;
	ರಚನೆ sshbuf *ret;

	b64 = get_json_string(content, ಕೀಲಿ, 0);
	ASSERT_PTR_NE(ret = sshbuf_new(), ಖಾಲಿ);
	ASSERT_INT_EQ(sshbuf_b64tod(ret, b64), 0);
	ಬಿಡುಗಡೆ(b64);
	ಹಿಂತಿರುಗಿ ret;
}

ಸ್ಥಿರ ಶೂನ್ಯ
onerror(ಶೂನ್ಯ *fuzz)
{
	fprintf(stderr, "Failed during fuzz:\n");
	fuzz_dump((ರಚನೆ fuzz *)fuzz);
}

ಸ್ಥಿರ ಶೂನ್ಯ
sig_fuzz(ಸ್ಥಿರಾಂಕ uint8_t *m, ಗಾತ್ರ_t m_len, ಸ್ಥಿರಾಂಕ uint8_t *ctx, ಗಾತ್ರ_t ctx_len,
    ಸ್ಥಿರಾಂಕ uint8_t *pk, ಸ್ಥಿರಾಂಕ uint8_t *s)
{
	ರಚನೆ fuzz *fuzz;
	u_int fuzzers = FUZZ_1_ಬಿಟ್_FLIP | FUZZ_1_BYTE_FLIP;

	ಆದರೆ (test_is_fast())
		fuzzers &= ~FUZZ_1_ಬಿಟ್_FLIP;
	ಆದರೆ (test_is_slow())
		fuzzers |= FUZZ_2_BYTE_FLIP; /* FUZZ_2_BIT_FLIP much too slow */

	ASSERT_INT_EQ(crypto_sign_mldsa44_ed25519_verify(s, m, m_len,
	    ctx, ctx_len, pk), 0);
	fuzz = fuzz_begin(fuzzers, s, MLDSA44_ED25519_SIG_SZ);
	TEST_ONERROR(onerror, fuzz);
	ಗಾಗಿ(; !fuzz_ಮುಗಿದ(fuzz); fuzz_ಮುಂದಿನ(fuzz)) {
		/* Ensure 1-bit difference at least */
		ಆದರೆ (fuzz_matches_original(fuzz))
			ಮುಂದುವರಿ;
		ASSERT_INT_NE(crypto_sign_mldsa44_ed25519_verify(fuzz_ptr(fuzz),
		    m, m_len, ctx, ctx_len, pk), 0);
	}
	fuzz_cleanup(fuzz);
}


ಶೂನ್ಯ
mldsa_eddsa_tests(ಶೂನ್ಯ)
{
	uint8_t pk[MLDSA44_ED25519_PK_SZ];
	uint8_t sk[MLDSA44_ED25519_SK_SZ];
	uint8_t sig[MLDSA44_ED25519_SIG_SZ];
	ರಚನೆ sshbuf *b_m = ಖಾಲಿ, *b_ctx = ಖಾಲಿ, *b_pk = ಖಾಲಿ;
	ರಚನೆ sshbuf *b_sk = ಖಾಲಿ, *b_s = ಖಾಲಿ, *b_sWithContext = ಖಾಲಿ;
	ರಚನೆ sshbuf *json_buf = ಖಾಲಿ;
	ಸ್ಥಿರಾಂಕ uint8_t *tvec_m;
	ಗಾತ್ರ_t tvec_m_len;
	ಸ್ಥಿರಾಂಕ uint8_t *tvec_ctx;
	ಗಾತ್ರ_t tvec_ctx_len;
	ಸ್ಥಿರಾಂಕ uint8_t *tvec_pk;
	ಸ್ಥಿರಾಂಕ uint8_t *tvec_sk;
	ಸ್ಥಿರಾಂಕ uint8_t *tvec_s;
	ಸ್ಥಿರಾಂಕ uint8_t *tvec_sWithContext;

	TEST_ಆರಂಭ("MLDSA44-Ed25519-SHA512 load test vectors");
	json_buf = ತುಂಬು_ಪಠ್ಯ_file("draft-ietf-lamps-pq-composite-sigs.json");
	b_m = get_json_b64(json_buf, "m");
	b_ctx = get_json_b64(json_buf, "ctx");
	b_pk = get_json_b64(json_buf, "pk");
	b_sk = get_json_b64(json_buf, "sk");
	b_s = get_json_b64(json_buf, "s");
	b_sWithContext = get_json_b64(json_buf, "sWithContext");
	ASSERT_INT_EQ(sshbuf_len(b_pk), MLDSA44_ED25519_PK_SZ);
	ASSERT_INT_EQ(sshbuf_len(b_sk), MLDSA44_ED25519_SK_SZ);
	ASSERT_INT_EQ(sshbuf_len(b_s), MLDSA44_ED25519_SIG_SZ);
	ASSERT_INT_EQ(sshbuf_len(b_sWithContext), MLDSA44_ED25519_SIG_SZ);
	TEST_ಮುಗಿದ();

	tvec_m = sshbuf_ptr(b_m);
	tvec_m_len = sshbuf_len(b_m);
	tvec_ctx = sshbuf_ptr(b_ctx);
	tvec_ctx_len = sshbuf_len(b_ctx);
	tvec_pk = sshbuf_ptr(b_pk);
	tvec_sk = sshbuf_ptr(b_sk);
	tvec_s = sshbuf_ptr(b_s);
	tvec_sWithContext = sshbuf_ptr(b_sWithContext);

	TEST_ಆರಂಭ("MLDSA44-Ed25519-SHA512 raw self-consistency");
	ASSERT_INT_EQ(crypto_sign_mldsa44_ed25519_keygen(pk, sk), 0);
	ASSERT_INT_EQ(crypto_sign_mldsa44_ed25519_sign(sig,
	    tvec_m, tvec_m_len, tvec_ctx, tvec_ctx_len, sk), 0);
	ASSERT_INT_EQ(crypto_sign_mldsa44_ed25519_verify(sig,
	    tvec_m, tvec_m_len, tvec_ctx, tvec_ctx_len, pk), 0);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("MLDSA44-Ed25519-SHA512 raw KAT key expansion");
	uint8_t pk_expanded[MLDSA44_ED25519_PK_SZ];
	uint8_t sk_expanded[MLDSA44_ED25519_SK_SZ];

	/* Expansion: mldsa_seed (sk[0:32]) and ed25519_seed (sk[32:64]) */
	ASSERT_INT_EQ(crypto_sign_mldsa44_ed25519_keygen_seeded(pk_expanded,
	    sk_expanded, tvec_sk, tvec_sk + 32), 0);
	ASSERT_MEM_EQ(pk_expanded, tvec_pk, MLDSA44_ED25519_PK_SZ);
	/* sk_expanded should also match tvec_sk */
	ASSERT_MEM_EQ(sk_expanded, tvec_sk, MLDSA44_ED25519_SK_SZ);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("MLDSA44-Ed25519-SHA512 raw KAT verify (no context)");
	ASSERT_INT_EQ(crypto_sign_mldsa44_ed25519_verify(tvec_s, tvec_m,
	    tvec_m_len, ಖಾಲಿ, 0, tvec_pk), 0);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("MLDSA44-Ed25519-SHA512 raw KAT verify (with context)");
	ASSERT_INT_EQ(crypto_sign_mldsa44_ed25519_verify(tvec_sWithContext,
	    tvec_m, tvec_m_len, tvec_ctx, tvec_ctx_len, tvec_pk), 0);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("MLDSA44-Ed25519-SHA512 raw round-trip (no context)");
	ASSERT_INT_EQ(crypto_sign_mldsa44_ed25519_sign(sig, tvec_m, tvec_m_len,
	    ಖಾಲಿ, 0, tvec_sk), 0);
	ASSERT_INT_EQ(crypto_sign_mldsa44_ed25519_verify(sig,
	    tvec_m, tvec_m_len, ಖಾಲಿ, 0, tvec_pk), 0);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("MLDSA44-Ed25519-SHA512 raw round-trip (with context)");
	ASSERT_INT_EQ(crypto_sign_mldsa44_ed25519_sign(sig,
	    tvec_m, tvec_m_len, tvec_ctx, tvec_ctx_len, tvec_sk), 0);
	ASSERT_INT_EQ(crypto_sign_mldsa44_ed25519_verify(sig,
	    tvec_m, tvec_m_len, tvec_ctx, tvec_ctx_len, tvec_pk), 0);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("MLDSA44-Ed25519-SHA512 raw KAT verify (no context)");
	ASSERT_INT_EQ(crypto_sign_mldsa44_ed25519_verify(tvec_s, tvec_m,
	    tvec_m_len, ಖಾಲಿ, 0, tvec_pk), 0);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("MLDSA44-Ed25519-SHA512 fuzz raw verify (with context)");
	ASSERT_INT_EQ(crypto_sign_mldsa44_ed25519_verify(tvec_sWithContext,
	    tvec_m, tvec_m_len, tvec_ctx, tvec_ctx_len, tvec_pk), 0);
	sig_fuzz(tvec_m, tvec_m_len, ಖಾಲಿ, 0, tvec_pk, tvec_s);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("MLDSA44-Ed25519-SHA512 fuzz raw verify (with context)");
	ASSERT_INT_EQ(crypto_sign_mldsa44_ed25519_verify(tvec_sWithContext,
	    tvec_m, tvec_m_len, tvec_ctx, tvec_ctx_len, tvec_pk), 0);
	sig_fuzz(tvec_m, tvec_m_len, tvec_ctx, tvec_ctx_len,
	    tvec_pk, tvec_sWithContext);
	TEST_ಮುಗಿದ();

	sshbuf_free(json_buf);
	sshbuf_free(b_m);
	sshbuf_free(b_ctx);
	sshbuf_free(b_pk);
	sshbuf_free(b_sk);
	sshbuf_free(b_s);
	sshbuf_free(b_sWithContext);
}
#ಆದರೆ_ಅಂತ್ಯ /* USE_MLDSA */
