/* 	$OpenBSD: test_mldsa_eddsa.c,v 1.1 2026/06/14 04:08:06 djm Exp $ */
/*
 * Regress test for MLDSA44-Ed25519 composite signature
 *
 * Placed in the public domain
 */

#అన్తర్భావ "includes.h"

#నిర్వచితమైతే USE_MLDSA

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <stdint.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <ctype.h>
#అన్తర్భావ <fcntl.h>
#అన్తర్భావ <unistd.h>

#అన్తర్భావ "../test_helper/test_helper.h"
#అన్తర్భావ "crypto_api.h"
#అన్తర్భావ "ssherr.h"
#అన్తర్భావ "sshkey.h"
#అన్తర్భావ "sshbuf.h"
#అన్తర్భావ "log.h"

/* in tests.c */
నిర్మాణం sshbuf *ఎక్కించు_పాఠ్యం_file(స్థిరరాశి అక్షరం *name);
అక్షరం *get_json_string(నిర్మాణం sshbuf *content, స్థిరరాశి అక్షరం *కీలకం, పూర్ణాంకం consume);

శూన్య mldsa_eddsa_tests(శూన్య);

/*
 * Simple JSON-ish parser for tvec.json.
 * Extracts the base64 value for a given key and decodes it into a new sshbuf.
 * Errors cause ASSERT_* failures.
 */
స్థిర నిర్మాణం sshbuf *
get_json_b64(నిర్మాణం sshbuf *content, స్థిరరాశి అక్షరం *కీలకం)
{
	అక్షరం *b64;
	నిర్మాణం sshbuf *ret;

	b64 = get_json_string(content, కీలకం, 0);
	ASSERT_PTR_NE(ret = sshbuf_new(), ఖాళీ);
	ASSERT_INT_EQ(sshbuf_b64tod(ret, b64), 0);
	విడుదల(b64);
	తిరిగి ret;
}

స్థిర శూన్య
onerror(శూన్య *fuzz)
{
	fprintf(stderr, "Failed during fuzz:\n");
	fuzz_dump((నిర్మాణం fuzz *)fuzz);
}

స్థిర శూన్య
sig_fuzz(స్థిరరాశి uint8_t *m, కొలత_t m_len, స్థిరరాశి uint8_t *ctx, కొలత_t ctx_len,
    స్థిరరాశి uint8_t *pk, స్థిరరాశి uint8_t *s)
{
	నిర్మాణం fuzz *fuzz;
	u_int fuzzers = FUZZ_1_బిట్టు_FLIP | FUZZ_1_BYTE_FLIP;

	ఒకవేళ (test_is_fast())
		fuzzers &= ~FUZZ_1_బిట్టు_FLIP;
	ఒకవేళ (test_is_slow())
		fuzzers |= FUZZ_2_BYTE_FLIP; /* FUZZ_2_BIT_FLIP much too slow */

	ASSERT_INT_EQ(crypto_sign_mldsa44_ed25519_verify(s, m, m_len,
	    ctx, ctx_len, pk), 0);
	fuzz = fuzz_begin(fuzzers, s, MLDSA44_ED25519_SIG_SZ);
	TEST_ONERROR(onerror, fuzz);
	కొరకు(; !fuzz_పూర్తి(fuzz); fuzz_తదుపరి(fuzz)) {
		/* Ensure 1-bit difference at least */
		ఒకవేళ (fuzz_matches_original(fuzz))
			కొనసాగు;
		ASSERT_INT_NE(crypto_sign_mldsa44_ed25519_verify(fuzz_ptr(fuzz),
		    m, m_len, ctx, ctx_len, pk), 0);
	}
	fuzz_cleanup(fuzz);
}


శూన్య
mldsa_eddsa_tests(శూన్య)
{
	uint8_t pk[MLDSA44_ED25519_PK_SZ];
	uint8_t sk[MLDSA44_ED25519_SK_SZ];
	uint8_t sig[MLDSA44_ED25519_SIG_SZ];
	నిర్మాణం sshbuf *b_m = ఖాళీ, *b_ctx = ఖాళీ, *b_pk = ఖాళీ;
	నిర్మాణం sshbuf *b_sk = ఖాళీ, *b_s = ఖాళీ, *b_sWithContext = ఖాళీ;
	నిర్మాణం sshbuf *json_buf = ఖాళీ;
	స్థిరరాశి uint8_t *tvec_m;
	కొలత_t tvec_m_len;
	స్థిరరాశి uint8_t *tvec_ctx;
	కొలత_t tvec_ctx_len;
	స్థిరరాశి uint8_t *tvec_pk;
	స్థిరరాశి uint8_t *tvec_sk;
	స్థిరరాశి uint8_t *tvec_s;
	స్థిరరాశి uint8_t *tvec_sWithContext;

	TEST_ప్రారంభం("MLDSA44-Ed25519-SHA512 load test vectors");
	json_buf = ఎక్కించు_పాఠ్యం_file("draft-ietf-lamps-pq-composite-sigs.json");
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
	TEST_పూర్తి();

	tvec_m = sshbuf_ptr(b_m);
	tvec_m_len = sshbuf_len(b_m);
	tvec_ctx = sshbuf_ptr(b_ctx);
	tvec_ctx_len = sshbuf_len(b_ctx);
	tvec_pk = sshbuf_ptr(b_pk);
	tvec_sk = sshbuf_ptr(b_sk);
	tvec_s = sshbuf_ptr(b_s);
	tvec_sWithContext = sshbuf_ptr(b_sWithContext);

	TEST_ప్రారంభం("MLDSA44-Ed25519-SHA512 raw self-consistency");
	ASSERT_INT_EQ(crypto_sign_mldsa44_ed25519_keygen(pk, sk), 0);
	ASSERT_INT_EQ(crypto_sign_mldsa44_ed25519_sign(sig,
	    tvec_m, tvec_m_len, tvec_ctx, tvec_ctx_len, sk), 0);
	ASSERT_INT_EQ(crypto_sign_mldsa44_ed25519_verify(sig,
	    tvec_m, tvec_m_len, tvec_ctx, tvec_ctx_len, pk), 0);
	TEST_పూర్తి();

	TEST_ప్రారంభం("MLDSA44-Ed25519-SHA512 raw KAT key expansion");
	uint8_t pk_expanded[MLDSA44_ED25519_PK_SZ];
	uint8_t sk_expanded[MLDSA44_ED25519_SK_SZ];

	/* Expansion: mldsa_seed (sk[0:32]) and ed25519_seed (sk[32:64]) */
	ASSERT_INT_EQ(crypto_sign_mldsa44_ed25519_keygen_seeded(pk_expanded,
	    sk_expanded, tvec_sk, tvec_sk + 32), 0);
	ASSERT_MEM_EQ(pk_expanded, tvec_pk, MLDSA44_ED25519_PK_SZ);
	/* sk_expanded should also match tvec_sk */
	ASSERT_MEM_EQ(sk_expanded, tvec_sk, MLDSA44_ED25519_SK_SZ);
	TEST_పూర్తి();

	TEST_ప్రారంభం("MLDSA44-Ed25519-SHA512 raw KAT verify (no context)");
	ASSERT_INT_EQ(crypto_sign_mldsa44_ed25519_verify(tvec_s, tvec_m,
	    tvec_m_len, ఖాళీ, 0, tvec_pk), 0);
	TEST_పూర్తి();

	TEST_ప్రారంభం("MLDSA44-Ed25519-SHA512 raw KAT verify (with context)");
	ASSERT_INT_EQ(crypto_sign_mldsa44_ed25519_verify(tvec_sWithContext,
	    tvec_m, tvec_m_len, tvec_ctx, tvec_ctx_len, tvec_pk), 0);
	TEST_పూర్తి();

	TEST_ప్రారంభం("MLDSA44-Ed25519-SHA512 raw round-trip (no context)");
	ASSERT_INT_EQ(crypto_sign_mldsa44_ed25519_sign(sig, tvec_m, tvec_m_len,
	    ఖాళీ, 0, tvec_sk), 0);
	ASSERT_INT_EQ(crypto_sign_mldsa44_ed25519_verify(sig,
	    tvec_m, tvec_m_len, ఖాళీ, 0, tvec_pk), 0);
	TEST_పూర్తి();

	TEST_ప్రారంభం("MLDSA44-Ed25519-SHA512 raw round-trip (with context)");
	ASSERT_INT_EQ(crypto_sign_mldsa44_ed25519_sign(sig,
	    tvec_m, tvec_m_len, tvec_ctx, tvec_ctx_len, tvec_sk), 0);
	ASSERT_INT_EQ(crypto_sign_mldsa44_ed25519_verify(sig,
	    tvec_m, tvec_m_len, tvec_ctx, tvec_ctx_len, tvec_pk), 0);
	TEST_పూర్తి();

	TEST_ప్రారంభం("MLDSA44-Ed25519-SHA512 raw KAT verify (no context)");
	ASSERT_INT_EQ(crypto_sign_mldsa44_ed25519_verify(tvec_s, tvec_m,
	    tvec_m_len, ఖాళీ, 0, tvec_pk), 0);
	TEST_పూర్తి();

	TEST_ప్రారంభం("MLDSA44-Ed25519-SHA512 fuzz raw verify (with context)");
	ASSERT_INT_EQ(crypto_sign_mldsa44_ed25519_verify(tvec_sWithContext,
	    tvec_m, tvec_m_len, tvec_ctx, tvec_ctx_len, tvec_pk), 0);
	sig_fuzz(tvec_m, tvec_m_len, ఖాళీ, 0, tvec_pk, tvec_s);
	TEST_పూర్తి();

	TEST_ప్రారంభం("MLDSA44-Ed25519-SHA512 fuzz raw verify (with context)");
	ASSERT_INT_EQ(crypto_sign_mldsa44_ed25519_verify(tvec_sWithContext,
	    tvec_m, tvec_m_len, tvec_ctx, tvec_ctx_len, tvec_pk), 0);
	sig_fuzz(tvec_m, tvec_m_len, tvec_ctx, tvec_ctx_len,
	    tvec_pk, tvec_sWithContext);
	TEST_పూర్తి();

	sshbuf_free(json_buf);
	sshbuf_free(b_m);
	sshbuf_free(b_ctx);
	sshbuf_free(b_pk);
	sshbuf_free(b_sk);
	sshbuf_free(b_s);
	sshbuf_free(b_sWithContext);
}
#అయితే_ముగింపు /* USE_MLDSA */
