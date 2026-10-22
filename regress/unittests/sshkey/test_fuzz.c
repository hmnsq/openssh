/* 	$OpenBSD: test_fuzz.c,v 1.16 2026/06/14 04:08:06 djm Exp $ */
/*
 * Fuzz tests for key parsing
 *
 * Placed in the public domain
 */

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/stat.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <fcntl.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdint.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/bn.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/ec.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/rsa.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/objects.h>
#ਜੇ_ਅੰਤ

#ਅਨ੍ਤਰ੍ਭਾਵ "../test_helper/test_helper.h"

#ਅਨ੍ਤਰ੍ਭਾਵ "ssherr.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "authfile.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshkey.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshbuf.h"

#ਅਨ੍ਤਰ੍ਭਾਵ "common.h"

ਖਾਲੀ sshkey_fuzz_tests(ਖਾਲੀ);

ਸਥਿਰ ਖਾਲੀ
onerror(ਖਾਲੀ *fuzz)
{
	fprintf(stderr, "Failed during fuzz:\n");
	fuzz_dump((ਬਣਤਰ fuzz *)fuzz);
}

ਸਥਿਰ ਖਾਲੀ
ਜਨਤਕ_fuzz(ਬਣਤਰ sshkey *k)
{
	ਬਣਤਰ sshkey *k1;
	ਬਣਤਰ sshbuf *buf;
	ਬਣਤਰ fuzz *fuzz;
	u_int fuzzers = FUZZ_1_ਦੋਆਧਾਰੀ_ਅੰਕ_FLIP | FUZZ_1_BYTE_FLIP |
	    FUZZ_TRUNCATE_ਸ਼ੁਰੂ | FUZZ_TRUNCATE_ਸਿਰਾ;

	/* MLDSA44_ED25519 keys are large and slow to fuzz */
	ਜੇ (test_is_fast() || sshkey_type_plain(k->type) == ਕੁੰਜੀ_MLDSA44_ED25519)
		fuzzers &= ~FUZZ_1_ਦੋਆਧਾਰੀ_ਅੰਕ_FLIP;
	ਜੇ (test_is_slow())
		fuzzers |= FUZZ_2_ਦੋਆਧਾਰੀ_ਅੰਕ_FLIP | FUZZ_2_BYTE_FLIP;

	ASSERT_PTR_NE(buf = sshbuf_new(), ਨਿਰਾ);
	ASSERT_INT_EQ(sshkey_putb(k, buf), 0);
	fuzz = fuzz_begin(fuzzers, sshbuf_mutable_ptr(buf), sshbuf_len(buf));
	ASSERT_INT_EQ(sshkey_from_blob(sshbuf_ptr(buf), sshbuf_len(buf),
	    &k1), 0);
	sshkey_free(k1);
	sshbuf_free(buf);
	TEST_ONERROR(onerror, fuzz);
	ਲਈ(; !fuzz_ਪੂਰਾ(fuzz); fuzz_ਅਗਲਾ(fuzz)) {
		ਜੇ (sshkey_from_blob(fuzz_ptr(fuzz), fuzz_len(fuzz), &k1) == 0)
			sshkey_free(k1);
	}
	fuzz_cleanup(fuzz);
}

ਸਥਿਰ ਖਾਲੀ
sig_fuzz(ਬਣਤਰ sshkey *k, ਅਚਲ ਅੱਖਰ *sig_alg)
{
	ਬਣਤਰ fuzz *fuzz;
	u_char *sig, c[] = "some junk to be signed";
	ਮਾਪ_t l;
	u_int fuzzers = FUZZ_1_ਦੋਆਧਾਰੀ_ਅੰਕ_FLIP | FUZZ_1_BYTE_FLIP | FUZZ_2_BYTE_FLIP |
	    FUZZ_TRUNCATE_ਸ਼ੁਰੂ | FUZZ_TRUNCATE_ਸਿਰਾ;

	/* MLDSA44_ED25519 keys are large and slow to fuzz */
	ਜੇ (test_is_fast() || sshkey_type_plain(k->type) == ਕੁੰਜੀ_MLDSA44_ED25519)
		fuzzers &= ~FUZZ_2_BYTE_FLIP;
	ਜੇ (test_is_slow())
		fuzzers |= FUZZ_2_ਦੋਆਧਾਰੀ_ਅੰਕ_FLIP;

	ASSERT_INT_EQ(sshkey_sign(k, &sig, &l, c, ਆਕਾਰ(c),
	    sig_alg, ਨਿਰਾ, ਨਿਰਾ, 0), 0);
	ASSERT_ਮਾਪ_T_GT(l, 0);
	fuzz = fuzz_begin(fuzzers, sig, l);
	ASSERT_INT_EQ(sshkey_verify(k, sig, l, c, ਆਕਾਰ(c), ਨਿਰਾ, 0, ਨਿਰਾ), 0);
	ਮੁਕਤ(sig);
	TEST_ONERROR(onerror, fuzz);
	ਲਈ(; !fuzz_ਪੂਰਾ(fuzz); fuzz_ਅਗਲਾ(fuzz)) {
		/* Ensure 1-bit difference at least */
		ਜੇ (fuzz_matches_original(fuzz))
			ਜਾਰੀ;
		ASSERT_INT_NE(sshkey_verify(k, fuzz_ptr(fuzz), fuzz_len(fuzz),
		    c, ਆਕਾਰ(c), ਨਿਰਾ, 0, ਨਿਰਾ), 0);
	}
	fuzz_cleanup(fuzz);
}

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ਅੰਕ_FAST_BASE64_TESTS	1024

ਖਾਲੀ
sshkey_fuzz_tests(ਖਾਲੀ)
{
	ਬਣਤਰ sshkey *k1;
	ਬਣਤਰ sshbuf *buf, *fuzzed;
	ਬਣਤਰ fuzz *fuzz;
	ਪੂਰਨ r, i;

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
	TEST_ਸ਼ੁਰੂ("fuzz RSA private");
	buf = ਲੱਦੋ_file("rsa_1");
	fuzz = fuzz_begin(FUZZ_BASE64, sshbuf_mutable_ptr(buf),
	    sshbuf_len(buf));
	ASSERT_INT_EQ(sshkey_parse_ਨਿੱਜੀ_fileblob(buf, "", &k1, ਨਿਰਾ), 0);
	sshkey_free(k1);
	sshbuf_free(buf);
	ASSERT_PTR_NE(fuzzed = sshbuf_new(), ਨਿਰਾ);
	TEST_ONERROR(onerror, fuzz);
	ਲਈ(i = 0; !fuzz_ਪੂਰਾ(fuzz); i++, fuzz_ਅਗਲਾ(fuzz)) {
		r = sshbuf_put(fuzzed, fuzz_ptr(fuzz), fuzz_len(fuzz));
		ASSERT_INT_EQ(r, 0);
		ਜੇ (sshkey_parse_ਨਿੱਜੀ_fileblob(fuzzed, "", &k1, ਨਿਰਾ) == 0)
			sshkey_free(k1);
		sshbuf_reset(fuzzed);
		ਜੇ (test_is_fast() && i >= ਅੰਕ_FAST_BASE64_TESTS)
			ਰੋਕੋ;
	}
	sshbuf_free(fuzzed);
	fuzz_cleanup(fuzz);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("fuzz RSA new-format private");
	buf = ਲੱਦੋ_file("rsa_n");
	fuzz = fuzz_begin(FUZZ_BASE64, sshbuf_mutable_ptr(buf),
	    sshbuf_len(buf));
	ASSERT_INT_EQ(sshkey_parse_ਨਿੱਜੀ_fileblob(buf, "", &k1, ਨਿਰਾ), 0);
	sshkey_free(k1);
	sshbuf_free(buf);
	ASSERT_PTR_NE(fuzzed = sshbuf_new(), ਨਿਰਾ);
	TEST_ONERROR(onerror, fuzz);
	ਲਈ(i = 0; !fuzz_ਪੂਰਾ(fuzz); i++, fuzz_ਅਗਲਾ(fuzz)) {
		r = sshbuf_put(fuzzed, fuzz_ptr(fuzz), fuzz_len(fuzz));
		ASSERT_INT_EQ(r, 0);
		ਜੇ (sshkey_parse_ਨਿੱਜੀ_fileblob(fuzzed, "", &k1, ਨਿਰਾ) == 0)
			sshkey_free(k1);
		sshbuf_reset(fuzzed);
		ਜੇ (test_is_fast() && i >= ਅੰਕ_FAST_BASE64_TESTS)
			ਰੋਕੋ;
	}
	sshbuf_free(fuzzed);
	fuzz_cleanup(fuzz);
	TEST_ਪੂਰਾ();


	TEST_ਸ਼ੁਰੂ("fuzz ECDSA private");
	buf = ਲੱਦੋ_file("ecdsa_1");
	fuzz = fuzz_begin(FUZZ_BASE64, sshbuf_mutable_ptr(buf),
	    sshbuf_len(buf));
	ASSERT_INT_EQ(sshkey_parse_ਨਿੱਜੀ_fileblob(buf, "", &k1, ਨਿਰਾ), 0);
	sshkey_free(k1);
	sshbuf_free(buf);
	ASSERT_PTR_NE(fuzzed = sshbuf_new(), ਨਿਰਾ);
	TEST_ONERROR(onerror, fuzz);
	ਲਈ(i = 0; !fuzz_ਪੂਰਾ(fuzz); i++, fuzz_ਅਗਲਾ(fuzz)) {
		r = sshbuf_put(fuzzed, fuzz_ptr(fuzz), fuzz_len(fuzz));
		ASSERT_INT_EQ(r, 0);
		ਜੇ (sshkey_parse_ਨਿੱਜੀ_fileblob(fuzzed, "", &k1, ਨਿਰਾ) == 0)
			sshkey_free(k1);
		sshbuf_reset(fuzzed);
		ਜੇ (test_is_fast() && i >= ਅੰਕ_FAST_BASE64_TESTS)
			ਰੋਕੋ;
	}
	sshbuf_free(fuzzed);
	fuzz_cleanup(fuzz);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("fuzz ECDSA new-format private");
	buf = ਲੱਦੋ_file("ecdsa_n");
	fuzz = fuzz_begin(FUZZ_BASE64, sshbuf_mutable_ptr(buf),
	    sshbuf_len(buf));
	ASSERT_INT_EQ(sshkey_parse_ਨਿੱਜੀ_fileblob(buf, "", &k1, ਨਿਰਾ), 0);
	sshkey_free(k1);
	sshbuf_free(buf);
	ASSERT_PTR_NE(fuzzed = sshbuf_new(), ਨਿਰਾ);
	TEST_ONERROR(onerror, fuzz);
	ਲਈ(i = 0; !fuzz_ਪੂਰਾ(fuzz); i++, fuzz_ਅਗਲਾ(fuzz)) {
		r = sshbuf_put(fuzzed, fuzz_ptr(fuzz), fuzz_len(fuzz));
		ASSERT_INT_EQ(r, 0);
		ਜੇ (sshkey_parse_ਨਿੱਜੀ_fileblob(fuzzed, "", &k1, ਨਿਰਾ) == 0)
			sshkey_free(k1);
		sshbuf_reset(fuzzed);
		ਜੇ (test_is_fast() && i >= ਅੰਕ_FAST_BASE64_TESTS)
			ਰੋਕੋ;
	}
	sshbuf_free(fuzzed);
	fuzz_cleanup(fuzz);
	TEST_ਪੂਰਾ();
#ਜੇ_ਅੰਤ /* WITH_OPENSSL */

	TEST_ਸ਼ੁਰੂ("fuzz Ed25519 private");
	buf = ਲੱਦੋ_file("ed25519_1");
	fuzz = fuzz_begin(FUZZ_BASE64, sshbuf_mutable_ptr(buf),
	    sshbuf_len(buf));
	ASSERT_INT_EQ(sshkey_parse_ਨਿੱਜੀ_fileblob(buf, "", &k1, ਨਿਰਾ), 0);
	sshkey_free(k1);
	sshbuf_free(buf);
	ASSERT_PTR_NE(fuzzed = sshbuf_new(), ਨਿਰਾ);
	TEST_ONERROR(onerror, fuzz);
	ਲਈ(i = 0; !fuzz_ਪੂਰਾ(fuzz); i++, fuzz_ਅਗਲਾ(fuzz)) {
		r = sshbuf_put(fuzzed, fuzz_ptr(fuzz), fuzz_len(fuzz));
		ASSERT_INT_EQ(r, 0);
		ਜੇ (sshkey_parse_ਨਿੱਜੀ_fileblob(fuzzed, "", &k1, ਨਿਰਾ) == 0)
			sshkey_free(k1);
		sshbuf_reset(fuzzed);
		ਜੇ (test_is_fast() && i >= ਅੰਕ_FAST_BASE64_TESTS)
			ਰੋਕੋ;
	}
	sshbuf_free(fuzzed);
	fuzz_cleanup(fuzz);
	TEST_ਪੂਰਾ();

	/* MLDSA44-ED25519 are large and slow to fuzz */
	TEST_ਸ਼ੁਰੂ("fuzz MLDSA44-ED25519 private");
	buf = ਲੱਦੋ_file("mldsa44_ed25519_1");
	fuzz = fuzz_begin(FUZZ_BASE64, sshbuf_mutable_ptr(buf),
	    sshbuf_len(buf));
	ASSERT_INT_EQ(sshkey_parse_ਨਿੱਜੀ_fileblob(buf, "", &k1, ਨਿਰਾ), 0);
	sshkey_free(k1);
	sshbuf_free(buf);
	ASSERT_PTR_NE(fuzzed = sshbuf_new(), ਨਿਰਾ);
	TEST_ONERROR(onerror, fuzz);
	ਲਈ(i = 0; !fuzz_ਪੂਰਾ(fuzz); i++, fuzz_ਅਗਲਾ(fuzz)) {
		r = sshbuf_put(fuzzed, fuzz_ptr(fuzz), fuzz_len(fuzz));
		ASSERT_INT_EQ(r, 0);
		ਜੇ (sshkey_parse_ਨਿੱਜੀ_fileblob(fuzzed, "", &k1, ਨਿਰਾ) == 0)
			sshkey_free(k1);
		sshbuf_reset(fuzzed);
		ਜੇ (test_is_fast() && i >= ਅੰਕ_FAST_BASE64_TESTS)
			ਰੋਕੋ;
		/* MLDSA44_ED25519 keys are large and slow to fuzz */
		ਜੇ (!test_is_slow() || i >= ਅੰਕ_FAST_BASE64_TESTS)
			ਰੋਕੋ;
	}
	sshbuf_free(fuzzed);
	fuzz_cleanup(fuzz);
	TEST_ਪੂਰਾ();

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
	TEST_ਸ਼ੁਰੂ("fuzz RSA public");
	buf = ਲੱਦੋ_file("rsa_1");
	ASSERT_INT_EQ(sshkey_parse_ਨਿੱਜੀ_fileblob(buf, "", &k1, ਨਿਰਾ), 0);
	sshbuf_free(buf);
	ਜਨਤਕ_fuzz(k1);
	sshkey_free(k1);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("fuzz RSA cert");
	ASSERT_INT_EQ(sshkey_ਲੱਦੋ_cert(test_ਅੰਕੜੇ_file("rsa_1"), &k1), 0);
	ਜਨਤਕ_fuzz(k1);
	sshkey_free(k1);
	TEST_ਪੂਰਾ();


	TEST_ਸ਼ੁਰੂ("fuzz ECDSA public");
	buf = ਲੱਦੋ_file("ecdsa_1");
	ASSERT_INT_EQ(sshkey_parse_ਨਿੱਜੀ_fileblob(buf, "", &k1, ਨਿਰਾ), 0);
	sshbuf_free(buf);
	ਜਨਤਕ_fuzz(k1);
	sshkey_free(k1);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("fuzz ECDSA cert");
	ASSERT_INT_EQ(sshkey_ਲੱਦੋ_cert(test_ਅੰਕੜੇ_file("ecdsa_1"), &k1), 0);
	ਜਨਤਕ_fuzz(k1);
	sshkey_free(k1);
	TEST_ਪੂਰਾ();
#ਜੇ_ਅੰਤ /* WITH_OPENSSL */

	TEST_ਸ਼ੁਰੂ("fuzz Ed25519 public");
	buf = ਲੱਦੋ_file("ed25519_1");
	ASSERT_INT_EQ(sshkey_parse_ਨਿੱਜੀ_fileblob(buf, "", &k1, ਨਿਰਾ), 0);
	sshbuf_free(buf);
	ਜਨਤਕ_fuzz(k1);
	sshkey_free(k1);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("fuzz Ed25519 cert");
	ASSERT_INT_EQ(sshkey_ਲੱਦੋ_cert(test_ਅੰਕੜੇ_file("ed25519_1"), &k1), 0);
	ਜਨਤਕ_fuzz(k1);
	sshkey_free(k1);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("fuzz MLDSA44-ED25519 public");
	buf = ਲੱਦੋ_file("mldsa44_ed25519_1");
	ASSERT_INT_EQ(sshkey_parse_ਨਿੱਜੀ_fileblob(buf, "", &k1, ਨਿਰਾ), 0);
	sshbuf_free(buf);
	ਜਨਤਕ_fuzz(k1);
	sshkey_free(k1);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("fuzz MLDSA44-ED25519 cert");
	ASSERT_INT_EQ(sshkey_ਲੱਦੋ_cert(
	    test_ਅੰਕੜੇ_file("mldsa44_ed25519_1"), &k1), 0);
	ਜਨਤਕ_fuzz(k1);
	sshkey_free(k1);
	TEST_ਪੂਰਾ();

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
	TEST_ਸ਼ੁਰੂ("fuzz RSA sig");
	buf = ਲੱਦੋ_file("rsa_1");
	ASSERT_INT_EQ(sshkey_parse_ਨਿੱਜੀ_fileblob(buf, "", &k1, ਨਿਰਾ), 0);
	sshbuf_free(buf);
	sig_fuzz(k1, "ssh-rsa");
	sshkey_free(k1);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("fuzz RSA SHA256 sig");
	buf = ਲੱਦੋ_file("rsa_1");
	ASSERT_INT_EQ(sshkey_parse_ਨਿੱਜੀ_fileblob(buf, "", &k1, ਨਿਰਾ), 0);
	sshbuf_free(buf);
	sig_fuzz(k1, "rsa-sha2-256");
	sshkey_free(k1);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("fuzz RSA SHA512 sig");
	buf = ਲੱਦੋ_file("rsa_1");
	ASSERT_INT_EQ(sshkey_parse_ਨਿੱਜੀ_fileblob(buf, "", &k1, ਨਿਰਾ), 0);
	sshbuf_free(buf);
	sig_fuzz(k1, "rsa-sha2-512");
	sshkey_free(k1);
	TEST_ਪੂਰਾ();


	TEST_ਸ਼ੁਰੂ("fuzz ECDSA sig");
	buf = ਲੱਦੋ_file("ecdsa_1");
	ASSERT_INT_EQ(sshkey_parse_ਨਿੱਜੀ_fileblob(buf, "", &k1, ਨਿਰਾ), 0);
	sshbuf_free(buf);
	sig_fuzz(k1, ਨਿਰਾ);
	sshkey_free(k1);
	TEST_ਪੂਰਾ();
#ਜੇ_ਅੰਤ /* WITH_OPENSSL */

	TEST_ਸ਼ੁਰੂ("fuzz Ed25519 sig");
	buf = ਲੱਦੋ_file("ed25519_1");
	ASSERT_INT_EQ(sshkey_parse_ਨਿੱਜੀ_fileblob(buf, "", &k1, ਨਿਰਾ), 0);
	sshbuf_free(buf);
	sig_fuzz(k1, ਨਿਰਾ);
	sshkey_free(k1);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("fuzz MLDSA44-ED25519 sig");
	buf = ਲੱਦੋ_file("mldsa44_ed25519_1");
	ASSERT_INT_EQ(sshkey_parse_ਨਿੱਜੀ_fileblob(buf, "", &k1, ਨਿਰਾ), 0);
	sshbuf_free(buf);
	sig_fuzz(k1, ਨਿਰਾ);
	sshkey_free(k1);
	TEST_ਪੂਰਾ();

/* XXX fuzz decoded new-format blobs too */
/* XXX fuzz XMSS too */

}
