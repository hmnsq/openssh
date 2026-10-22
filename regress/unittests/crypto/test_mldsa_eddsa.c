/* 	$OpenBSD: test_mldsa_eddsa.c,v 1.1 2026/06/14 04:08:06 djm Exp $ */
/*
 * Regress test for MLDSA44-Ed25519 composite signature
 *
 * Placed in the public domain
 */

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ USE_MLDSA

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdint.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <ctype.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <fcntl.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "../test_helper/test_helper.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "crypto_api.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssherr.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshkey.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshbuf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"

/* in tests.c */
ਬਣਤਰ sshbuf *ਲੱਦੋ_ਪਾਠ_file(ਅਚਲ ਅੱਖਰ *name);
ਅੱਖਰ *get_json_string(ਬਣਤਰ sshbuf *content, ਅਚਲ ਅੱਖਰ *ਕੁੰਜੀ, ਪੂਰਨ consume);

ਖਾਲੀ mldsa_eddsa_tests(ਖਾਲੀ);

/*
 * Simple JSON-ish parser for tvec.json.
 * Extracts the base64 value for a given key and decodes it into a new sshbuf.
 * Errors cause ASSERT_* failures.
 */
ਸਥਿਰ ਬਣਤਰ sshbuf *
get_json_b64(ਬਣਤਰ sshbuf *content, ਅਚਲ ਅੱਖਰ *ਕੁੰਜੀ)
{
	ਅੱਖਰ *b64;
	ਬਣਤਰ sshbuf *ret;

	b64 = get_json_string(content, ਕੁੰਜੀ, 0);
	ASSERT_PTR_NE(ret = sshbuf_new(), ਨਿਰਾ);
	ASSERT_INT_EQ(sshbuf_b64tod(ret, b64), 0);
	ਮੁਕਤ(b64);
	ਵਾਪਸ ret;
}

ਸਥਿਰ ਖਾਲੀ
onerror(ਖਾਲੀ *fuzz)
{
	fprintf(stderr, "Failed during fuzz:\n");
	fuzz_dump((ਬਣਤਰ fuzz *)fuzz);
}

ਸਥਿਰ ਖਾਲੀ
sig_fuzz(ਅਚਲ uint8_t *m, ਮਾਪ_t m_len, ਅਚਲ uint8_t *ctx, ਮਾਪ_t ctx_len,
    ਅਚਲ uint8_t *pk, ਅਚਲ uint8_t *s)
{
	ਬਣਤਰ fuzz *fuzz;
	u_int fuzzers = FUZZ_1_ਦੋਆਧਾਰੀ_ਅੰਕ_FLIP | FUZZ_1_BYTE_FLIP;

	ਜੇ (test_is_fast())
		fuzzers &= ~FUZZ_1_ਦੋਆਧਾਰੀ_ਅੰਕ_FLIP;
	ਜੇ (test_is_slow())
		fuzzers |= FUZZ_2_BYTE_FLIP; /* FUZZ_2_BIT_FLIP much too slow */

	ASSERT_INT_EQ(crypto_sign_mldsa44_ed25519_verify(s, m, m_len,
	    ctx, ctx_len, pk), 0);
	fuzz = fuzz_begin(fuzzers, s, MLDSA44_ED25519_SIG_SZ);
	TEST_ONERROR(onerror, fuzz);
	ਲਈ(; !fuzz_ਪੂਰਾ(fuzz); fuzz_ਅਗਲਾ(fuzz)) {
		/* Ensure 1-bit difference at least */
		ਜੇ (fuzz_matches_original(fuzz))
			ਜਾਰੀ;
		ASSERT_INT_NE(crypto_sign_mldsa44_ed25519_verify(fuzz_ptr(fuzz),
		    m, m_len, ctx, ctx_len, pk), 0);
	}
	fuzz_cleanup(fuzz);
}


ਖਾਲੀ
mldsa_eddsa_tests(ਖਾਲੀ)
{
	uint8_t pk[MLDSA44_ED25519_PK_SZ];
	uint8_t sk[MLDSA44_ED25519_SK_SZ];
	uint8_t sig[MLDSA44_ED25519_SIG_SZ];
	ਬਣਤਰ sshbuf *b_m = ਨਿਰਾ, *b_ctx = ਨਿਰਾ, *b_pk = ਨਿਰਾ;
	ਬਣਤਰ sshbuf *b_sk = ਨਿਰਾ, *b_s = ਨਿਰਾ, *b_sWithContext = ਨਿਰਾ;
	ਬਣਤਰ sshbuf *json_buf = ਨਿਰਾ;
	ਅਚਲ uint8_t *tvec_m;
	ਮਾਪ_t tvec_m_len;
	ਅਚਲ uint8_t *tvec_ctx;
	ਮਾਪ_t tvec_ctx_len;
	ਅਚਲ uint8_t *tvec_pk;
	ਅਚਲ uint8_t *tvec_sk;
	ਅਚਲ uint8_t *tvec_s;
	ਅਚਲ uint8_t *tvec_sWithContext;

	TEST_ਸ਼ੁਰੂ("MLDSA44-Ed25519-SHA512 load test vectors");
	json_buf = ਲੱਦੋ_ਪਾਠ_file("draft-ietf-lamps-pq-composite-sigs.json");
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
	TEST_ਪੂਰਾ();

	tvec_m = sshbuf_ptr(b_m);
	tvec_m_len = sshbuf_len(b_m);
	tvec_ctx = sshbuf_ptr(b_ctx);
	tvec_ctx_len = sshbuf_len(b_ctx);
	tvec_pk = sshbuf_ptr(b_pk);
	tvec_sk = sshbuf_ptr(b_sk);
	tvec_s = sshbuf_ptr(b_s);
	tvec_sWithContext = sshbuf_ptr(b_sWithContext);

	TEST_ਸ਼ੁਰੂ("MLDSA44-Ed25519-SHA512 raw self-consistency");
	ASSERT_INT_EQ(crypto_sign_mldsa44_ed25519_keygen(pk, sk), 0);
	ASSERT_INT_EQ(crypto_sign_mldsa44_ed25519_sign(sig,
	    tvec_m, tvec_m_len, tvec_ctx, tvec_ctx_len, sk), 0);
	ASSERT_INT_EQ(crypto_sign_mldsa44_ed25519_verify(sig,
	    tvec_m, tvec_m_len, tvec_ctx, tvec_ctx_len, pk), 0);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("MLDSA44-Ed25519-SHA512 raw KAT key expansion");
	uint8_t pk_expanded[MLDSA44_ED25519_PK_SZ];
	uint8_t sk_expanded[MLDSA44_ED25519_SK_SZ];

	/* Expansion: mldsa_seed (sk[0:32]) and ed25519_seed (sk[32:64]) */
	ASSERT_INT_EQ(crypto_sign_mldsa44_ed25519_keygen_seeded(pk_expanded,
	    sk_expanded, tvec_sk, tvec_sk + 32), 0);
	ASSERT_MEM_EQ(pk_expanded, tvec_pk, MLDSA44_ED25519_PK_SZ);
	/* sk_expanded should also match tvec_sk */
	ASSERT_MEM_EQ(sk_expanded, tvec_sk, MLDSA44_ED25519_SK_SZ);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("MLDSA44-Ed25519-SHA512 raw KAT verify (no context)");
	ASSERT_INT_EQ(crypto_sign_mldsa44_ed25519_verify(tvec_s, tvec_m,
	    tvec_m_len, ਨਿਰਾ, 0, tvec_pk), 0);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("MLDSA44-Ed25519-SHA512 raw KAT verify (with context)");
	ASSERT_INT_EQ(crypto_sign_mldsa44_ed25519_verify(tvec_sWithContext,
	    tvec_m, tvec_m_len, tvec_ctx, tvec_ctx_len, tvec_pk), 0);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("MLDSA44-Ed25519-SHA512 raw round-trip (no context)");
	ASSERT_INT_EQ(crypto_sign_mldsa44_ed25519_sign(sig, tvec_m, tvec_m_len,
	    ਨਿਰਾ, 0, tvec_sk), 0);
	ASSERT_INT_EQ(crypto_sign_mldsa44_ed25519_verify(sig,
	    tvec_m, tvec_m_len, ਨਿਰਾ, 0, tvec_pk), 0);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("MLDSA44-Ed25519-SHA512 raw round-trip (with context)");
	ASSERT_INT_EQ(crypto_sign_mldsa44_ed25519_sign(sig,
	    tvec_m, tvec_m_len, tvec_ctx, tvec_ctx_len, tvec_sk), 0);
	ASSERT_INT_EQ(crypto_sign_mldsa44_ed25519_verify(sig,
	    tvec_m, tvec_m_len, tvec_ctx, tvec_ctx_len, tvec_pk), 0);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("MLDSA44-Ed25519-SHA512 raw KAT verify (no context)");
	ASSERT_INT_EQ(crypto_sign_mldsa44_ed25519_verify(tvec_s, tvec_m,
	    tvec_m_len, ਨਿਰਾ, 0, tvec_pk), 0);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("MLDSA44-Ed25519-SHA512 fuzz raw verify (with context)");
	ASSERT_INT_EQ(crypto_sign_mldsa44_ed25519_verify(tvec_sWithContext,
	    tvec_m, tvec_m_len, tvec_ctx, tvec_ctx_len, tvec_pk), 0);
	sig_fuzz(tvec_m, tvec_m_len, ਨਿਰਾ, 0, tvec_pk, tvec_s);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("MLDSA44-Ed25519-SHA512 fuzz raw verify (with context)");
	ASSERT_INT_EQ(crypto_sign_mldsa44_ed25519_verify(tvec_sWithContext,
	    tvec_m, tvec_m_len, tvec_ctx, tvec_ctx_len, tvec_pk), 0);
	sig_fuzz(tvec_m, tvec_m_len, tvec_ctx, tvec_ctx_len,
	    tvec_pk, tvec_sWithContext);
	TEST_ਪੂਰਾ();

	sshbuf_free(json_buf);
	sshbuf_free(b_m);
	sshbuf_free(b_ctx);
	sshbuf_free(b_pk);
	sshbuf_free(b_sk);
	sshbuf_free(b_s);
	sshbuf_free(b_sWithContext);
}
#ਜੇ_ਅੰਤ /* USE_MLDSA */
