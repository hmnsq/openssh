/* 	$OpenBSD: test_mldsa_eddsa.c,v 1.1 2026/06/14 04:08:06 djm Exp $ */
/*
 * Regress test for MLDSA44-Ed25519 composite signature
 *
 * Placed in the public domain
 */

#അന്തര്ഭാവ "includes.h"

#ifdef USE_MLDSA

#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <stdint.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <ctype.h>
#അന്തര്ഭാവ <fcntl.h>
#അന്തര്ഭാവ <unistd.h>

#അന്തര്ഭാവ "../test_helper/test_helper.h"
#അന്തര്ഭാവ "crypto_api.h"
#അന്തര്ഭാവ "ssherr.h"
#അന്തര്ഭാവ "sshkey.h"
#അന്തര്ഭാവ "sshbuf.h"
#അന്തര്ഭാവ "log.h"

/* in tests.c */
ഘടന sshbuf *load_text_file(സ്ഥിരം അക്ഷരം *name);
അക്ഷരം *get_json_string(ഘടന sshbuf *content, സ്ഥിരം അക്ഷരം *താക്കോൽ, പൂർണ്ണസംഖ്യ consume);

ശൂന്യം mldsa_eddsa_tests(ശൂന്യം);

/*
 * Simple JSON-ish parser for tvec.json.
 * Extracts the base64 value for a given key and decodes it into a new sshbuf.
 * Errors cause ASSERT_* failures.
 */
സ്ഥിതം ഘടന sshbuf *
get_json_b64(ഘടന sshbuf *content, സ്ഥിരം അക്ഷരം *താക്കോൽ)
{
	അക്ഷരം *b64;
	ഘടന sshbuf *ret;

	b64 = get_json_string(content, താക്കോൽ, 0);
	ASSERT_PTR_NE(ret = sshbuf_new(), ശൂന്യ);
	ASSERT_INT_EQ(sshbuf_b64tod(ret, b64), 0);
	സ്വതന്ത്രം(b64);
	തിരികെ ret;
}

സ്ഥിതം ശൂന്യം
onerror(ശൂന്യം *fuzz)
{
	fprintf(stderr, "Failed during fuzz:\n");
	fuzz_dump((ഘടന fuzz *)fuzz);
}

സ്ഥിതം ശൂന്യം
sig_fuzz(സ്ഥിരം uint8_t *m, size_t m_len, സ്ഥിരം uint8_t *ctx, size_t ctx_len,
    സ്ഥിരം uint8_t *pk, സ്ഥിരം uint8_t *s)
{
	ഘടന fuzz *fuzz;
	u_int fuzzers = FUZZ_1_BIT_FLIP | FUZZ_1_BYTE_FLIP;

	എങ്കിൽ (test_is_fast())
		fuzzers &= ~FUZZ_1_BIT_FLIP;
	എങ്കിൽ (test_is_slow())
		fuzzers |= FUZZ_2_BYTE_FLIP; /* FUZZ_2_BIT_FLIP much too slow */

	ASSERT_INT_EQ(crypto_sign_mldsa44_ed25519_verify(s, m, m_len,
	    ctx, ctx_len, pk), 0);
	fuzz = fuzz_begin(fuzzers, s, MLDSA44_ED25519_SIG_SZ);
	TEST_ONERROR(onerror, fuzz);
	വേണ്ടി(; !fuzz_done(fuzz); fuzz_next(fuzz)) {
		/* Ensure 1-bit difference at least */
		എങ്കിൽ (fuzz_matches_original(fuzz))
			തുടരുക;
		ASSERT_INT_NE(crypto_sign_mldsa44_ed25519_verify(fuzz_ptr(fuzz),
		    m, m_len, ctx, ctx_len, pk), 0);
	}
	fuzz_cleanup(fuzz);
}


ശൂന്യം
mldsa_eddsa_tests(ശൂന്യം)
{
	uint8_t pk[MLDSA44_ED25519_PK_SZ];
	uint8_t sk[MLDSA44_ED25519_SK_SZ];
	uint8_t sig[MLDSA44_ED25519_SIG_SZ];
	ഘടന sshbuf *b_m = ശൂന്യ, *b_ctx = ശൂന്യ, *b_pk = ശൂന്യ;
	ഘടന sshbuf *b_sk = ശൂന്യ, *b_s = ശൂന്യ, *b_sWithContext = ശൂന്യ;
	ഘടന sshbuf *json_buf = ശൂന്യ;
	സ്ഥിരം uint8_t *tvec_m;
	size_t tvec_m_len;
	സ്ഥിരം uint8_t *tvec_ctx;
	size_t tvec_ctx_len;
	സ്ഥിരം uint8_t *tvec_pk;
	സ്ഥിരം uint8_t *tvec_sk;
	സ്ഥിരം uint8_t *tvec_s;
	സ്ഥിരം uint8_t *tvec_sWithContext;

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
	    tvec_m_len, ശൂന്യ, 0, tvec_pk), 0);
	TEST_DONE();

	TEST_START("MLDSA44-Ed25519-SHA512 raw KAT verify (with context)");
	ASSERT_INT_EQ(crypto_sign_mldsa44_ed25519_verify(tvec_sWithContext,
	    tvec_m, tvec_m_len, tvec_ctx, tvec_ctx_len, tvec_pk), 0);
	TEST_DONE();

	TEST_START("MLDSA44-Ed25519-SHA512 raw round-trip (no context)");
	ASSERT_INT_EQ(crypto_sign_mldsa44_ed25519_sign(sig, tvec_m, tvec_m_len,
	    ശൂന്യ, 0, tvec_sk), 0);
	ASSERT_INT_EQ(crypto_sign_mldsa44_ed25519_verify(sig,
	    tvec_m, tvec_m_len, ശൂന്യ, 0, tvec_pk), 0);
	TEST_DONE();

	TEST_START("MLDSA44-Ed25519-SHA512 raw round-trip (with context)");
	ASSERT_INT_EQ(crypto_sign_mldsa44_ed25519_sign(sig,
	    tvec_m, tvec_m_len, tvec_ctx, tvec_ctx_len, tvec_sk), 0);
	ASSERT_INT_EQ(crypto_sign_mldsa44_ed25519_verify(sig,
	    tvec_m, tvec_m_len, tvec_ctx, tvec_ctx_len, tvec_pk), 0);
	TEST_DONE();

	TEST_START("MLDSA44-Ed25519-SHA512 raw KAT verify (no context)");
	ASSERT_INT_EQ(crypto_sign_mldsa44_ed25519_verify(tvec_s, tvec_m,
	    tvec_m_len, ശൂന്യ, 0, tvec_pk), 0);
	TEST_DONE();

	TEST_START("MLDSA44-Ed25519-SHA512 fuzz raw verify (with context)");
	ASSERT_INT_EQ(crypto_sign_mldsa44_ed25519_verify(tvec_sWithContext,
	    tvec_m, tvec_m_len, tvec_ctx, tvec_ctx_len, tvec_pk), 0);
	sig_fuzz(tvec_m, tvec_m_len, ശൂന്യ, 0, tvec_pk, tvec_s);
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
