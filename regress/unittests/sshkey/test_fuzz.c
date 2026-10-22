/* 	$OpenBSD: test_fuzz.c,v 1.16 2026/06/14 04:08:06 djm Exp $ */
/*
 * Fuzz tests for key parsing
 *
 * Placed in the public domain
 */

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <sys/stat.h>
#അന്തര്ഭാവ <fcntl.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <stdint.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <unistd.h>

#ifdef WITH_OPENSSL
#അന്തര്ഭാവ <openssl/bn.h>
#അന്തര്ഭാവ <openssl/ec.h>
#അന്തര്ഭാവ <openssl/rsa.h>
#അന്തര്ഭാവ <openssl/objects.h>
#endif

#അന്തര്ഭാവ "../test_helper/test_helper.h"

#അന്തര്ഭാവ "ssherr.h"
#അന്തര്ഭാവ "authfile.h"
#അന്തര്ഭാവ "sshkey.h"
#അന്തര്ഭാവ "sshbuf.h"

#അന്തര്ഭാവ "common.h"

ശൂന്യം sshkey_fuzz_tests(ശൂന്യം);

സ്ഥിതം ശൂന്യം
onerror(ശൂന്യം *fuzz)
{
	fprintf(stderr, "Failed during fuzz:\n");
	fuzz_dump((ഘടന fuzz *)fuzz);
}

സ്ഥിതം ശൂന്യം
public_fuzz(ഘടന sshkey *k)
{
	ഘടന sshkey *k1;
	ഘടന sshbuf *buf;
	ഘടന fuzz *fuzz;
	u_int fuzzers = FUZZ_1_BIT_FLIP | FUZZ_1_BYTE_FLIP |
	    FUZZ_TRUNCATE_START | FUZZ_TRUNCATE_END;

	/* MLDSA44_ED25519 keys are large and slow to fuzz */
	എങ്കിൽ (test_is_fast() || sshkey_type_plain(k->type) == താക്കോൽ_MLDSA44_ED25519)
		fuzzers &= ~FUZZ_1_BIT_FLIP;
	എങ്കിൽ (test_is_slow())
		fuzzers |= FUZZ_2_BIT_FLIP | FUZZ_2_BYTE_FLIP;

	ASSERT_PTR_NE(buf = sshbuf_new(), ശൂന്യ);
	ASSERT_INT_EQ(sshkey_putb(k, buf), 0);
	fuzz = fuzz_begin(fuzzers, sshbuf_mutable_ptr(buf), sshbuf_len(buf));
	ASSERT_INT_EQ(sshkey_from_blob(sshbuf_ptr(buf), sshbuf_len(buf),
	    &k1), 0);
	sshkey_free(k1);
	sshbuf_free(buf);
	TEST_ONERROR(onerror, fuzz);
	വേണ്ടി(; !fuzz_done(fuzz); fuzz_next(fuzz)) {
		എങ്കിൽ (sshkey_from_blob(fuzz_ptr(fuzz), fuzz_len(fuzz), &k1) == 0)
			sshkey_free(k1);
	}
	fuzz_cleanup(fuzz);
}

സ്ഥിതം ശൂന്യം
sig_fuzz(ഘടന sshkey *k, സ്ഥിരം അക്ഷരം *sig_alg)
{
	ഘടന fuzz *fuzz;
	u_char *sig, c[] = "some junk to be signed";
	size_t l;
	u_int fuzzers = FUZZ_1_BIT_FLIP | FUZZ_1_BYTE_FLIP | FUZZ_2_BYTE_FLIP |
	    FUZZ_TRUNCATE_START | FUZZ_TRUNCATE_END;

	/* MLDSA44_ED25519 keys are large and slow to fuzz */
	എങ്കിൽ (test_is_fast() || sshkey_type_plain(k->type) == താക്കോൽ_MLDSA44_ED25519)
		fuzzers &= ~FUZZ_2_BYTE_FLIP;
	എങ്കിൽ (test_is_slow())
		fuzzers |= FUZZ_2_BIT_FLIP;

	ASSERT_INT_EQ(sshkey_sign(k, &sig, &l, c, വലുപ്പം(c),
	    sig_alg, ശൂന്യ, ശൂന്യ, 0), 0);
	ASSERT_SIZE_T_GT(l, 0);
	fuzz = fuzz_begin(fuzzers, sig, l);
	ASSERT_INT_EQ(sshkey_verify(k, sig, l, c, വലുപ്പം(c), ശൂന്യ, 0, ശൂന്യ), 0);
	സ്വതന്ത്രം(sig);
	TEST_ONERROR(onerror, fuzz);
	വേണ്ടി(; !fuzz_done(fuzz); fuzz_next(fuzz)) {
		/* Ensure 1-bit difference at least */
		എങ്കിൽ (fuzz_matches_original(fuzz))
			തുടരുക;
		ASSERT_INT_NE(sshkey_verify(k, fuzz_ptr(fuzz), fuzz_len(fuzz),
		    c, വലുപ്പം(c), ശൂന്യ, 0, ശൂന്യ), 0);
	}
	fuzz_cleanup(fuzz);
}

#define അക്കം_FAST_BASE64_TESTS	1024

ശൂന്യം
sshkey_fuzz_tests(ശൂന്യം)
{
	ഘടന sshkey *k1;
	ഘടന sshbuf *buf, *fuzzed;
	ഘടന fuzz *fuzz;
	പൂർണ്ണസംഖ്യ r, i;

#ifdef WITH_OPENSSL
	TEST_START("fuzz RSA private");
	buf = load_file("rsa_1");
	fuzz = fuzz_begin(FUZZ_BASE64, sshbuf_mutable_ptr(buf),
	    sshbuf_len(buf));
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, ശൂന്യ), 0);
	sshkey_free(k1);
	sshbuf_free(buf);
	ASSERT_PTR_NE(fuzzed = sshbuf_new(), ശൂന്യ);
	TEST_ONERROR(onerror, fuzz);
	വേണ്ടി(i = 0; !fuzz_done(fuzz); i++, fuzz_next(fuzz)) {
		r = sshbuf_put(fuzzed, fuzz_ptr(fuzz), fuzz_len(fuzz));
		ASSERT_INT_EQ(r, 0);
		എങ്കിൽ (sshkey_parse_private_fileblob(fuzzed, "", &k1, ശൂന്യ) == 0)
			sshkey_free(k1);
		sshbuf_reset(fuzzed);
		എങ്കിൽ (test_is_fast() && i >= അക്കം_FAST_BASE64_TESTS)
			നിർത്തുക;
	}
	sshbuf_free(fuzzed);
	fuzz_cleanup(fuzz);
	TEST_DONE();

	TEST_START("fuzz RSA new-format private");
	buf = load_file("rsa_n");
	fuzz = fuzz_begin(FUZZ_BASE64, sshbuf_mutable_ptr(buf),
	    sshbuf_len(buf));
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, ശൂന്യ), 0);
	sshkey_free(k1);
	sshbuf_free(buf);
	ASSERT_PTR_NE(fuzzed = sshbuf_new(), ശൂന്യ);
	TEST_ONERROR(onerror, fuzz);
	വേണ്ടി(i = 0; !fuzz_done(fuzz); i++, fuzz_next(fuzz)) {
		r = sshbuf_put(fuzzed, fuzz_ptr(fuzz), fuzz_len(fuzz));
		ASSERT_INT_EQ(r, 0);
		എങ്കിൽ (sshkey_parse_private_fileblob(fuzzed, "", &k1, ശൂന്യ) == 0)
			sshkey_free(k1);
		sshbuf_reset(fuzzed);
		എങ്കിൽ (test_is_fast() && i >= അക്കം_FAST_BASE64_TESTS)
			നിർത്തുക;
	}
	sshbuf_free(fuzzed);
	fuzz_cleanup(fuzz);
	TEST_DONE();


	TEST_START("fuzz ECDSA private");
	buf = load_file("ecdsa_1");
	fuzz = fuzz_begin(FUZZ_BASE64, sshbuf_mutable_ptr(buf),
	    sshbuf_len(buf));
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, ശൂന്യ), 0);
	sshkey_free(k1);
	sshbuf_free(buf);
	ASSERT_PTR_NE(fuzzed = sshbuf_new(), ശൂന്യ);
	TEST_ONERROR(onerror, fuzz);
	വേണ്ടി(i = 0; !fuzz_done(fuzz); i++, fuzz_next(fuzz)) {
		r = sshbuf_put(fuzzed, fuzz_ptr(fuzz), fuzz_len(fuzz));
		ASSERT_INT_EQ(r, 0);
		എങ്കിൽ (sshkey_parse_private_fileblob(fuzzed, "", &k1, ശൂന്യ) == 0)
			sshkey_free(k1);
		sshbuf_reset(fuzzed);
		എങ്കിൽ (test_is_fast() && i >= അക്കം_FAST_BASE64_TESTS)
			നിർത്തുക;
	}
	sshbuf_free(fuzzed);
	fuzz_cleanup(fuzz);
	TEST_DONE();

	TEST_START("fuzz ECDSA new-format private");
	buf = load_file("ecdsa_n");
	fuzz = fuzz_begin(FUZZ_BASE64, sshbuf_mutable_ptr(buf),
	    sshbuf_len(buf));
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, ശൂന്യ), 0);
	sshkey_free(k1);
	sshbuf_free(buf);
	ASSERT_PTR_NE(fuzzed = sshbuf_new(), ശൂന്യ);
	TEST_ONERROR(onerror, fuzz);
	വേണ്ടി(i = 0; !fuzz_done(fuzz); i++, fuzz_next(fuzz)) {
		r = sshbuf_put(fuzzed, fuzz_ptr(fuzz), fuzz_len(fuzz));
		ASSERT_INT_EQ(r, 0);
		എങ്കിൽ (sshkey_parse_private_fileblob(fuzzed, "", &k1, ശൂന്യ) == 0)
			sshkey_free(k1);
		sshbuf_reset(fuzzed);
		എങ്കിൽ (test_is_fast() && i >= അക്കം_FAST_BASE64_TESTS)
			നിർത്തുക;
	}
	sshbuf_free(fuzzed);
	fuzz_cleanup(fuzz);
	TEST_DONE();
#endif /* WITH_OPENSSL */

	TEST_START("fuzz Ed25519 private");
	buf = load_file("ed25519_1");
	fuzz = fuzz_begin(FUZZ_BASE64, sshbuf_mutable_ptr(buf),
	    sshbuf_len(buf));
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, ശൂന്യ), 0);
	sshkey_free(k1);
	sshbuf_free(buf);
	ASSERT_PTR_NE(fuzzed = sshbuf_new(), ശൂന്യ);
	TEST_ONERROR(onerror, fuzz);
	വേണ്ടി(i = 0; !fuzz_done(fuzz); i++, fuzz_next(fuzz)) {
		r = sshbuf_put(fuzzed, fuzz_ptr(fuzz), fuzz_len(fuzz));
		ASSERT_INT_EQ(r, 0);
		എങ്കിൽ (sshkey_parse_private_fileblob(fuzzed, "", &k1, ശൂന്യ) == 0)
			sshkey_free(k1);
		sshbuf_reset(fuzzed);
		എങ്കിൽ (test_is_fast() && i >= അക്കം_FAST_BASE64_TESTS)
			നിർത്തുക;
	}
	sshbuf_free(fuzzed);
	fuzz_cleanup(fuzz);
	TEST_DONE();

	/* MLDSA44-ED25519 are large and slow to fuzz */
	TEST_START("fuzz MLDSA44-ED25519 private");
	buf = load_file("mldsa44_ed25519_1");
	fuzz = fuzz_begin(FUZZ_BASE64, sshbuf_mutable_ptr(buf),
	    sshbuf_len(buf));
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, ശൂന്യ), 0);
	sshkey_free(k1);
	sshbuf_free(buf);
	ASSERT_PTR_NE(fuzzed = sshbuf_new(), ശൂന്യ);
	TEST_ONERROR(onerror, fuzz);
	വേണ്ടി(i = 0; !fuzz_done(fuzz); i++, fuzz_next(fuzz)) {
		r = sshbuf_put(fuzzed, fuzz_ptr(fuzz), fuzz_len(fuzz));
		ASSERT_INT_EQ(r, 0);
		എങ്കിൽ (sshkey_parse_private_fileblob(fuzzed, "", &k1, ശൂന്യ) == 0)
			sshkey_free(k1);
		sshbuf_reset(fuzzed);
		എങ്കിൽ (test_is_fast() && i >= അക്കം_FAST_BASE64_TESTS)
			നിർത്തുക;
		/* MLDSA44_ED25519 keys are large and slow to fuzz */
		എങ്കിൽ (!test_is_slow() || i >= അക്കം_FAST_BASE64_TESTS)
			നിർത്തുക;
	}
	sshbuf_free(fuzzed);
	fuzz_cleanup(fuzz);
	TEST_DONE();

#ifdef WITH_OPENSSL
	TEST_START("fuzz RSA public");
	buf = load_file("rsa_1");
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, ശൂന്യ), 0);
	sshbuf_free(buf);
	public_fuzz(k1);
	sshkey_free(k1);
	TEST_DONE();

	TEST_START("fuzz RSA cert");
	ASSERT_INT_EQ(sshkey_load_cert(test_data_file("rsa_1"), &k1), 0);
	public_fuzz(k1);
	sshkey_free(k1);
	TEST_DONE();


	TEST_START("fuzz ECDSA public");
	buf = load_file("ecdsa_1");
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, ശൂന്യ), 0);
	sshbuf_free(buf);
	public_fuzz(k1);
	sshkey_free(k1);
	TEST_DONE();

	TEST_START("fuzz ECDSA cert");
	ASSERT_INT_EQ(sshkey_load_cert(test_data_file("ecdsa_1"), &k1), 0);
	public_fuzz(k1);
	sshkey_free(k1);
	TEST_DONE();
#endif /* WITH_OPENSSL */

	TEST_START("fuzz Ed25519 public");
	buf = load_file("ed25519_1");
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, ശൂന്യ), 0);
	sshbuf_free(buf);
	public_fuzz(k1);
	sshkey_free(k1);
	TEST_DONE();

	TEST_START("fuzz Ed25519 cert");
	ASSERT_INT_EQ(sshkey_load_cert(test_data_file("ed25519_1"), &k1), 0);
	public_fuzz(k1);
	sshkey_free(k1);
	TEST_DONE();

	TEST_START("fuzz MLDSA44-ED25519 public");
	buf = load_file("mldsa44_ed25519_1");
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, ശൂന്യ), 0);
	sshbuf_free(buf);
	public_fuzz(k1);
	sshkey_free(k1);
	TEST_DONE();

	TEST_START("fuzz MLDSA44-ED25519 cert");
	ASSERT_INT_EQ(sshkey_load_cert(
	    test_data_file("mldsa44_ed25519_1"), &k1), 0);
	public_fuzz(k1);
	sshkey_free(k1);
	TEST_DONE();

#ifdef WITH_OPENSSL
	TEST_START("fuzz RSA sig");
	buf = load_file("rsa_1");
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, ശൂന്യ), 0);
	sshbuf_free(buf);
	sig_fuzz(k1, "ssh-rsa");
	sshkey_free(k1);
	TEST_DONE();

	TEST_START("fuzz RSA SHA256 sig");
	buf = load_file("rsa_1");
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, ശൂന്യ), 0);
	sshbuf_free(buf);
	sig_fuzz(k1, "rsa-sha2-256");
	sshkey_free(k1);
	TEST_DONE();

	TEST_START("fuzz RSA SHA512 sig");
	buf = load_file("rsa_1");
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, ശൂന്യ), 0);
	sshbuf_free(buf);
	sig_fuzz(k1, "rsa-sha2-512");
	sshkey_free(k1);
	TEST_DONE();


	TEST_START("fuzz ECDSA sig");
	buf = load_file("ecdsa_1");
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, ശൂന്യ), 0);
	sshbuf_free(buf);
	sig_fuzz(k1, ശൂന്യ);
	sshkey_free(k1);
	TEST_DONE();
#endif /* WITH_OPENSSL */

	TEST_START("fuzz Ed25519 sig");
	buf = load_file("ed25519_1");
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, ശൂന്യ), 0);
	sshbuf_free(buf);
	sig_fuzz(k1, ശൂന്യ);
	sshkey_free(k1);
	TEST_DONE();

	TEST_START("fuzz MLDSA44-ED25519 sig");
	buf = load_file("mldsa44_ed25519_1");
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, ശൂന്യ), 0);
	sshbuf_free(buf);
	sig_fuzz(k1, ശൂന്യ);
	sshkey_free(k1);
	TEST_DONE();

/* XXX fuzz decoded new-format blobs too */
/* XXX fuzz XMSS too */

}
