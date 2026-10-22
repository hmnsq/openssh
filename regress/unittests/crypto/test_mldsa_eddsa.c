/* 	$OpenBSD: test_mldsa_eddsa.c,v 1.1 2026/06/14 04:08:06 djm Exp $ */
/*
 * Regress test for MLDSA44-Ed25519 composite signature
 *
 * Placed in the public domain
 */

#समावेश "includes.h"

#अगर_घोषित USE_MLDSA

#समावेश <sys/types.h>
#समावेश <stdio.h>
#समावेश <stdint.h>
#समावेश <stdlib.h>
#समावेश <string.h>
#समावेश <ctype.h>
#समावेश <fcntl.h>
#समावेश <unistd.h>

#समावेश "../test_helper/test_helper.h"
#समावेश "crypto_api.h"
#समावेश "ssherr.h"
#समावेश "sshkey.h"
#समावेश "sshbuf.h"
#समावेश "log.h"

/* in tests.c */
काष्ठा sshbuf *load_text_file(स्थिर अक्षर *name);
अक्षर *get_json_string(काष्ठा sshbuf *content, स्थिर अक्षर *कुंजी, पूर्णांक consume);

व्योम mldsa_eddsa_tests(व्योम);

/*
 * Simple JSON-ish parser for tvec.json.
 * Extracts the base64 value for a given key and decodes it into a new sshbuf.
 * Errors cause ASSERT_* failures.
 */
अटल काष्ठा sshbuf *
get_json_b64(काष्ठा sshbuf *content, स्थिर अक्षर *कुंजी)
{
	अक्षर *b64;
	काष्ठा sshbuf *ret;

	b64 = get_json_string(content, कुंजी, 0);
	ASSERT_PTR_NE(ret = sshbuf_new(), शून्य);
	ASSERT_INT_EQ(sshbuf_b64tod(ret, b64), 0);
	मुक्त(b64);
	वापस ret;
}

अटल व्योम
onerror(व्योम *fuzz)
{
	ख_लिखो(मानक_त्रुटि, "Failed during fuzz:\n");
	fuzz_dump((काष्ठा fuzz *)fuzz);
}

अटल व्योम
sig_fuzz(स्थिर uint8_t *m, माप_प्रकार m_len, स्थिर uint8_t *ctx, माप_प्रकार ctx_len,
    स्थिर uint8_t *pk, स्थिर uint8_t *s)
{
	काष्ठा fuzz *fuzz;
	u_int fuzzers = FUZZ_1_BIT_FLIP | FUZZ_1_BYTE_FLIP;

	अगर (test_is_fast())
		fuzzers &= ~FUZZ_1_BIT_FLIP;
	अगर (test_is_slow())
		fuzzers |= FUZZ_2_BYTE_FLIP; /* FUZZ_2_BIT_FLIP much too slow */

	ASSERT_INT_EQ(crypto_sign_mldsa44_ed25519_verify(s, m, m_len,
	    ctx, ctx_len, pk), 0);
	fuzz = fuzz_begin(fuzzers, s, MLDSA44_ED25519_SIG_SZ);
	TEST_ONERROR(onerror, fuzz);
	क्रम(; !fuzz_done(fuzz); fuzz_अग्र(fuzz)) {
		/* Ensure 1-bit difference at least */
		अगर (fuzz_matches_original(fuzz))
			जारी;
		ASSERT_INT_NE(crypto_sign_mldsa44_ed25519_verify(fuzz_ptr(fuzz),
		    m, m_len, ctx, ctx_len, pk), 0);
	}
	fuzz_cleanup(fuzz);
}


व्योम
mldsa_eddsa_tests(व्योम)
{
	uint8_t pk[MLDSA44_ED25519_PK_SZ];
	uint8_t sk[MLDSA44_ED25519_SK_SZ];
	uint8_t sig[MLDSA44_ED25519_SIG_SZ];
	काष्ठा sshbuf *b_m = शून्य, *b_ctx = शून्य, *b_pk = शून्य;
	काष्ठा sshbuf *b_sk = शून्य, *b_s = शून्य, *b_sWithContext = शून्य;
	काष्ठा sshbuf *json_buf = शून्य;
	स्थिर uint8_t *tvec_m;
	माप_प्रकार tvec_m_len;
	स्थिर uint8_t *tvec_ctx;
	माप_प्रकार tvec_ctx_len;
	स्थिर uint8_t *tvec_pk;
	स्थिर uint8_t *tvec_sk;
	स्थिर uint8_t *tvec_s;
	स्थिर uint8_t *tvec_sWithContext;

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
	    tvec_m_len, शून्य, 0, tvec_pk), 0);
	TEST_DONE();

	TEST_START("MLDSA44-Ed25519-SHA512 raw KAT verify (with context)");
	ASSERT_INT_EQ(crypto_sign_mldsa44_ed25519_verify(tvec_sWithContext,
	    tvec_m, tvec_m_len, tvec_ctx, tvec_ctx_len, tvec_pk), 0);
	TEST_DONE();

	TEST_START("MLDSA44-Ed25519-SHA512 raw round-trip (no context)");
	ASSERT_INT_EQ(crypto_sign_mldsa44_ed25519_sign(sig, tvec_m, tvec_m_len,
	    शून्य, 0, tvec_sk), 0);
	ASSERT_INT_EQ(crypto_sign_mldsa44_ed25519_verify(sig,
	    tvec_m, tvec_m_len, शून्य, 0, tvec_pk), 0);
	TEST_DONE();

	TEST_START("MLDSA44-Ed25519-SHA512 raw round-trip (with context)");
	ASSERT_INT_EQ(crypto_sign_mldsa44_ed25519_sign(sig,
	    tvec_m, tvec_m_len, tvec_ctx, tvec_ctx_len, tvec_sk), 0);
	ASSERT_INT_EQ(crypto_sign_mldsa44_ed25519_verify(sig,
	    tvec_m, tvec_m_len, tvec_ctx, tvec_ctx_len, tvec_pk), 0);
	TEST_DONE();

	TEST_START("MLDSA44-Ed25519-SHA512 raw KAT verify (no context)");
	ASSERT_INT_EQ(crypto_sign_mldsa44_ed25519_verify(tvec_s, tvec_m,
	    tvec_m_len, शून्य, 0, tvec_pk), 0);
	TEST_DONE();

	TEST_START("MLDSA44-Ed25519-SHA512 fuzz raw verify (with context)");
	ASSERT_INT_EQ(crypto_sign_mldsa44_ed25519_verify(tvec_sWithContext,
	    tvec_m, tvec_m_len, tvec_ctx, tvec_ctx_len, tvec_pk), 0);
	sig_fuzz(tvec_m, tvec_m_len, शून्य, 0, tvec_pk, tvec_s);
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
#पूर्ण_अगर /* USE_MLDSA */
