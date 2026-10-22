/* 	$OpenBSD: test_mldsa_eddsa.c,v 1.1 2026/06/14 04:08:06 djm Exp $ */
/*
 * Regress test for MLDSA44-Ed25519 composite signature
 *
 * Placed in the public domain
 */

#شامل "includes.h"

#اگر_تعریف_شدہ USE_MLDSA

#شامل <sys/types.h>
#شامل <stdio.h>
#شامل <stdint.h>
#شامل <stdlib.h>
#شامل <string.h>
#شامل <ctype.h>
#شامل <fcntl.h>
#شامل <unistd.h>

#شامل "../test_helper/test_helper.h"
#شامل "crypto_api.h"
#شامل "ssherr.h"
#شامل "sshkey.h"
#شامل "sshbuf.h"
#شامل "log.h"

/* in tests.c */
ساخت sshbuf *بھرو_متن_file(ثابت حرف *name);
حرف *get_json_string(ساخت sshbuf *content, ثابت حرف *کلید, صحیح consume);

خالی mldsa_eddsa_tests(خالی);

/*
 * Simple JSON-ish parser for tvec.json.
 * Extracts the base64 value for a given key and decodes it into a new sshbuf.
 * Errors cause ASSERT_* failures.
 */
ساکن ساخت sshbuf *
get_json_b64(ساخت sshbuf *content, ثابت حرف *کلید)
{
	حرف *b64;
	ساخت sshbuf *ret;

	b64 = get_json_string(content, کلید, 0);
	ASSERT_PTR_NE(ret = sshbuf_new(), تہی);
	ASSERT_INT_EQ(sshbuf_b64tod(ret, b64), 0);
	آزاد(b64);
	واپس ret;
}

ساکن خالی
onerror(خالی *fuzz)
{
	fprintf(stderr, "Failed during fuzz:\n");
	fuzz_dump((ساخت fuzz *)fuzz);
}

ساکن خالی
sig_fuzz(ثابت uint8_t *m, سائز_t m_len, ثابت uint8_t *ctx, سائز_t ctx_len,
    ثابت uint8_t *pk, ثابت uint8_t *s)
{
	ساخت fuzz *fuzz;
	u_int fuzzers = FUZZ_1_ثنائی_ہندسہ_FLIP | FUZZ_1_BYTE_FLIP;

	اگر (test_is_fast())
		fuzzers &= ~FUZZ_1_ثنائی_ہندسہ_FLIP;
	اگر (test_is_slow())
		fuzzers |= FUZZ_2_BYTE_FLIP; /* FUZZ_2_BIT_FLIP much too slow */

	ASSERT_INT_EQ(crypto_sign_mldsa44_ed25519_verify(s, m, m_len,
	    ctx, ctx_len, pk), 0);
	fuzz = fuzz_begin(fuzzers, s, MLDSA44_ED25519_SIG_SZ);
	TEST_ONERROR(onerror, fuzz);
	برائے(; !fuzz_مکمل(fuzz); fuzz_اگلا(fuzz)) {
		/* Ensure 1-bit difference at least */
		اگر (fuzz_matches_original(fuzz))
			جاری;
		ASSERT_INT_NE(crypto_sign_mldsa44_ed25519_verify(fuzz_ptr(fuzz),
		    m, m_len, ctx, ctx_len, pk), 0);
	}
	fuzz_cleanup(fuzz);
}


خالی
mldsa_eddsa_tests(خالی)
{
	uint8_t pk[MLDSA44_ED25519_PK_SZ];
	uint8_t sk[MLDSA44_ED25519_SK_SZ];
	uint8_t sig[MLDSA44_ED25519_SIG_SZ];
	ساخت sshbuf *b_m = تہی, *b_ctx = تہی, *b_pk = تہی;
	ساخت sshbuf *b_sk = تہی, *b_s = تہی, *b_sWithContext = تہی;
	ساخت sshbuf *json_buf = تہی;
	ثابت uint8_t *tvec_m;
	سائز_t tvec_m_len;
	ثابت uint8_t *tvec_ctx;
	سائز_t tvec_ctx_len;
	ثابت uint8_t *tvec_pk;
	ثابت uint8_t *tvec_sk;
	ثابت uint8_t *tvec_s;
	ثابت uint8_t *tvec_sWithContext;

	TEST_آغاز("MLDSA44-Ed25519-SHA512 load test vectors");
	json_buf = بھرو_متن_file("draft-ietf-lamps-pq-composite-sigs.json");
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
	TEST_مکمل();

	tvec_m = sshbuf_ptr(b_m);
	tvec_m_len = sshbuf_len(b_m);
	tvec_ctx = sshbuf_ptr(b_ctx);
	tvec_ctx_len = sshbuf_len(b_ctx);
	tvec_pk = sshbuf_ptr(b_pk);
	tvec_sk = sshbuf_ptr(b_sk);
	tvec_s = sshbuf_ptr(b_s);
	tvec_sWithContext = sshbuf_ptr(b_sWithContext);

	TEST_آغاز("MLDSA44-Ed25519-SHA512 raw self-consistency");
	ASSERT_INT_EQ(crypto_sign_mldsa44_ed25519_keygen(pk, sk), 0);
	ASSERT_INT_EQ(crypto_sign_mldsa44_ed25519_sign(sig,
	    tvec_m, tvec_m_len, tvec_ctx, tvec_ctx_len, sk), 0);
	ASSERT_INT_EQ(crypto_sign_mldsa44_ed25519_verify(sig,
	    tvec_m, tvec_m_len, tvec_ctx, tvec_ctx_len, pk), 0);
	TEST_مکمل();

	TEST_آغاز("MLDSA44-Ed25519-SHA512 raw KAT key expansion");
	uint8_t pk_expanded[MLDSA44_ED25519_PK_SZ];
	uint8_t sk_expanded[MLDSA44_ED25519_SK_SZ];

	/* Expansion: mldsa_seed (sk[0:32]) and ed25519_seed (sk[32:64]) */
	ASSERT_INT_EQ(crypto_sign_mldsa44_ed25519_keygen_seeded(pk_expanded,
	    sk_expanded, tvec_sk, tvec_sk + 32), 0);
	ASSERT_MEM_EQ(pk_expanded, tvec_pk, MLDSA44_ED25519_PK_SZ);
	/* sk_expanded should also match tvec_sk */
	ASSERT_MEM_EQ(sk_expanded, tvec_sk, MLDSA44_ED25519_SK_SZ);
	TEST_مکمل();

	TEST_آغاز("MLDSA44-Ed25519-SHA512 raw KAT verify (no context)");
	ASSERT_INT_EQ(crypto_sign_mldsa44_ed25519_verify(tvec_s, tvec_m,
	    tvec_m_len, تہی, 0, tvec_pk), 0);
	TEST_مکمل();

	TEST_آغاز("MLDSA44-Ed25519-SHA512 raw KAT verify (with context)");
	ASSERT_INT_EQ(crypto_sign_mldsa44_ed25519_verify(tvec_sWithContext,
	    tvec_m, tvec_m_len, tvec_ctx, tvec_ctx_len, tvec_pk), 0);
	TEST_مکمل();

	TEST_آغاز("MLDSA44-Ed25519-SHA512 raw round-trip (no context)");
	ASSERT_INT_EQ(crypto_sign_mldsa44_ed25519_sign(sig, tvec_m, tvec_m_len,
	    تہی, 0, tvec_sk), 0);
	ASSERT_INT_EQ(crypto_sign_mldsa44_ed25519_verify(sig,
	    tvec_m, tvec_m_len, تہی, 0, tvec_pk), 0);
	TEST_مکمل();

	TEST_آغاز("MLDSA44-Ed25519-SHA512 raw round-trip (with context)");
	ASSERT_INT_EQ(crypto_sign_mldsa44_ed25519_sign(sig,
	    tvec_m, tvec_m_len, tvec_ctx, tvec_ctx_len, tvec_sk), 0);
	ASSERT_INT_EQ(crypto_sign_mldsa44_ed25519_verify(sig,
	    tvec_m, tvec_m_len, tvec_ctx, tvec_ctx_len, tvec_pk), 0);
	TEST_مکمل();

	TEST_آغاز("MLDSA44-Ed25519-SHA512 raw KAT verify (no context)");
	ASSERT_INT_EQ(crypto_sign_mldsa44_ed25519_verify(tvec_s, tvec_m,
	    tvec_m_len, تہی, 0, tvec_pk), 0);
	TEST_مکمل();

	TEST_آغاز("MLDSA44-Ed25519-SHA512 fuzz raw verify (with context)");
	ASSERT_INT_EQ(crypto_sign_mldsa44_ed25519_verify(tvec_sWithContext,
	    tvec_m, tvec_m_len, tvec_ctx, tvec_ctx_len, tvec_pk), 0);
	sig_fuzz(tvec_m, tvec_m_len, تہی, 0, tvec_pk, tvec_s);
	TEST_مکمل();

	TEST_آغاز("MLDSA44-Ed25519-SHA512 fuzz raw verify (with context)");
	ASSERT_INT_EQ(crypto_sign_mldsa44_ed25519_verify(tvec_sWithContext,
	    tvec_m, tvec_m_len, tvec_ctx, tvec_ctx_len, tvec_pk), 0);
	sig_fuzz(tvec_m, tvec_m_len, tvec_ctx, tvec_ctx_len,
	    tvec_pk, tvec_sWithContext);
	TEST_مکمل();

	sshbuf_free(json_buf);
	sshbuf_free(b_m);
	sshbuf_free(b_ctx);
	sshbuf_free(b_pk);
	sshbuf_free(b_sk);
	sshbuf_free(b_s);
	sshbuf_free(b_sWithContext);
}
#اگر_ختم /* USE_MLDSA */
