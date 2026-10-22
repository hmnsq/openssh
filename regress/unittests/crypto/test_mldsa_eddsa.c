/* 	$OpenBSD: test_mldsa_eddsa.c,v 1.1 2026/06/14 04:08:06 djm Exp $ */
/*
 * Regress test for MLDSA44-Ed25519 composite signature
 *
 * Placed in the public domain
 */

#ضمن "includes.h"

#ifdef USE_MLDSA

#ضمن <sys/types.h>
#ضمن <stdio.h>
#ضمن <stdint.h>
#ضمن <stdlib.h>
#ضمن <string.h>
#ضمن <ctype.h>
#ضمن <fcntl.h>
#ضمن <unistd.h>

#ضمن "../test_helper/test_helper.h"
#ضمن "crypto_api.h"
#ضمن "ssherr.h"
#ضمن "sshkey.h"
#ضمن "sshbuf.h"
#ضمن "log.h"

/* in tests.c */
بنية sshbuf *load_text_file(ثابت حرف *name);
حرف *get_json_string(بنية sshbuf *content, ثابت حرف *کلیل, صحيح consume);

فراغ mldsa_eddsa_tests(فراغ);

/*
 * Simple JSON-ish parser for tvec.json.
 * Extracts the base64 value for a given key and decodes it into a new sshbuf.
 * Errors cause ASSERT_* failures.
 */
ساكن بنية sshbuf *
get_json_b64(بنية sshbuf *content, ثابت حرف *کلیل)
{
	حرف *b64;
	بنية sshbuf *ret;

	b64 = get_json_string(content, کلیل, 0);
	ASSERT_PTR_NE(ret = sshbuf_new(), عدم);
	ASSERT_INT_EQ(sshbuf_b64tod(ret, b64), 0);
	حرر(b64);
	أرجع ret;
}

ساكن فراغ
onerror(فراغ *fuzz)
{
	fprintf(stderr, "Failed during fuzz:\n");
	fuzz_dump((بنية fuzz *)fuzz);
}

ساكن فراغ
sig_fuzz(ثابت uint8_t *m, size_t m_len, ثابت uint8_t *ctx, size_t ctx_len,
    ثابت uint8_t *pk, ثابت uint8_t *s)
{
	بنية fuzz *fuzz;
	u_int fuzzers = FUZZ_1_BIT_FLIP | FUZZ_1_BYTE_FLIP;

	إذا (test_is_fast())
		fuzzers &= ~FUZZ_1_BIT_FLIP;
	إذا (test_is_slow())
		fuzzers |= FUZZ_2_BYTE_FLIP; /* FUZZ_2_BIT_FLIP much too slow */

	ASSERT_INT_EQ(crypto_sign_mldsa44_ed25519_verify(s, m, m_len,
	    ctx, ctx_len, pk), 0);
	fuzz = fuzz_begin(fuzzers, s, MLDSA44_ED25519_SIG_SZ);
	TEST_ONERROR(onerror, fuzz);
	لكل(; !fuzz_done(fuzz); fuzz_next(fuzz)) {
		/* Ensure 1-bit difference at least */
		إذا (fuzz_matches_original(fuzz))
			استمر;
		ASSERT_INT_NE(crypto_sign_mldsa44_ed25519_verify(fuzz_ptr(fuzz),
		    m, m_len, ctx, ctx_len, pk), 0);
	}
	fuzz_cleanup(fuzz);
}


فراغ
mldsa_eddsa_tests(فراغ)
{
	uint8_t pk[MLDSA44_ED25519_PK_SZ];
	uint8_t sk[MLDSA44_ED25519_SK_SZ];
	uint8_t sig[MLDSA44_ED25519_SIG_SZ];
	بنية sshbuf *b_m = عدم, *b_ctx = عدم, *b_pk = عدم;
	بنية sshbuf *b_sk = عدم, *b_s = عدم, *b_sWithContext = عدم;
	بنية sshbuf *json_buf = عدم;
	ثابت uint8_t *tvec_m;
	size_t tvec_m_len;
	ثابت uint8_t *tvec_ctx;
	size_t tvec_ctx_len;
	ثابت uint8_t *tvec_pk;
	ثابت uint8_t *tvec_sk;
	ثابت uint8_t *tvec_s;
	ثابت uint8_t *tvec_sWithContext;

	TEST_START("MLDSA44-Ed25519-SHA512 load test vectors");
	json_buf = load_text_file("draft-ietf-lamps-pq-composite-sigs.json");
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
	TEST_DONE();

	tvec_m = sshbuf_ptr(b_m);
	tvec_m_len = sshbuf_len(b_m);
	tvec_ctx = sshbuf_ptr(b_ctx);
	tvec_ctx_len = sshbuf_len(b_ctx);
	tvec_pk = sshbuf_ptr(b_pk);
	tvec_sk = sshbuf_ptr(b_sk);
	tvec_s = sshbuf_ptr(b_s);
	tvec_sWithContext = sshbuf_ptr(b_sWithContext);

	TEST_START("MLDSA44-Ed25519-SHA512 raw self-consistency");
	ASSERT_INT_EQ(crypto_sign_mldsa44_ed25519_keygen(pk, sk), 0);
	ASSERT_INT_EQ(crypto_sign_mldsa44_ed25519_sign(sig,
	    tvec_m, tvec_m_len, tvec_ctx, tvec_ctx_len, sk), 0);
	ASSERT_INT_EQ(crypto_sign_mldsa44_ed25519_verify(sig,
	    tvec_m, tvec_m_len, tvec_ctx, tvec_ctx_len, pk), 0);
	TEST_DONE();

	TEST_START("MLDSA44-Ed25519-SHA512 raw KAT key expansion");
	uint8_t pk_expanded[MLDSA44_ED25519_PK_SZ];
	uint8_t sk_expanded[MLDSA44_ED25519_SK_SZ];

	/* Expansion: mldsa_seed (sk[0:32]) and ed25519_seed (sk[32:64]) */
	ASSERT_INT_EQ(crypto_sign_mldsa44_ed25519_keygen_seeded(pk_expanded,
	    sk_expanded, tvec_sk, tvec_sk + 32), 0);
	ASSERT_MEM_EQ(pk_expanded, tvec_pk, MLDSA44_ED25519_PK_SZ);
	/* sk_expanded should also match tvec_sk */
	ASSERT_MEM_EQ(sk_expanded, tvec_sk, MLDSA44_ED25519_SK_SZ);
	TEST_DONE();

	TEST_START("MLDSA44-Ed25519-SHA512 raw KAT verify (no context)");
	ASSERT_INT_EQ(crypto_sign_mldsa44_ed25519_verify(tvec_s, tvec_m,
	    tvec_m_len, عدم, 0, tvec_pk), 0);
	TEST_DONE();

	TEST_START("MLDSA44-Ed25519-SHA512 raw KAT verify (with context)");
	ASSERT_INT_EQ(crypto_sign_mldsa44_ed25519_verify(tvec_sWithContext,
	    tvec_m, tvec_m_len, tvec_ctx, tvec_ctx_len, tvec_pk), 0);
	TEST_DONE();

	TEST_START("MLDSA44-Ed25519-SHA512 raw round-trip (no context)");
	ASSERT_INT_EQ(crypto_sign_mldsa44_ed25519_sign(sig, tvec_m, tvec_m_len,
	    عدم, 0, tvec_sk), 0);
	ASSERT_INT_EQ(crypto_sign_mldsa44_ed25519_verify(sig,
	    tvec_m, tvec_m_len, عدم, 0, tvec_pk), 0);
	TEST_DONE();

	TEST_START("MLDSA44-Ed25519-SHA512 raw round-trip (with context)");
	ASSERT_INT_EQ(crypto_sign_mldsa44_ed25519_sign(sig,
	    tvec_m, tvec_m_len, tvec_ctx, tvec_ctx_len, tvec_sk), 0);
	ASSERT_INT_EQ(crypto_sign_mldsa44_ed25519_verify(sig,
	    tvec_m, tvec_m_len, tvec_ctx, tvec_ctx_len, tvec_pk), 0);
	TEST_DONE();

	TEST_START("MLDSA44-Ed25519-SHA512 raw KAT verify (no context)");
	ASSERT_INT_EQ(crypto_sign_mldsa44_ed25519_verify(tvec_s, tvec_m,
	    tvec_m_len, عدم, 0, tvec_pk), 0);
	TEST_DONE();

	TEST_START("MLDSA44-Ed25519-SHA512 fuzz raw verify (with context)");
	ASSERT_INT_EQ(crypto_sign_mldsa44_ed25519_verify(tvec_sWithContext,
	    tvec_m, tvec_m_len, tvec_ctx, tvec_ctx_len, tvec_pk), 0);
	sig_fuzz(tvec_m, tvec_m_len, عدم, 0, tvec_pk, tvec_s);
	TEST_DONE();

	TEST_START("MLDSA44-Ed25519-SHA512 fuzz raw verify (with context)");
	ASSERT_INT_EQ(crypto_sign_mldsa44_ed25519_verify(tvec_sWithContext,
	    tvec_m, tvec_m_len, tvec_ctx, tvec_ctx_len, tvec_pk), 0);
	sig_fuzz(tvec_m, tvec_m_len, tvec_ctx, tvec_ctx_len,
	    tvec_pk, tvec_sWithContext);
	TEST_DONE();

	sshbuf_free(json_buf);
	sshbuf_free(b_m);
	sshbuf_free(b_ctx);
	sshbuf_free(b_pk);
	sshbuf_free(b_sk);
	sshbuf_free(b_s);
	sshbuf_free(b_sWithContext);
}
#endif /* USE_MLDSA */
