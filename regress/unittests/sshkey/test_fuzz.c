/* 	$OpenBSD: test_fuzz.c,v 1.16 2026/06/14 04:08:06 djm Exp $ */
/*
 * Fuzz tests for key parsing
 *
 * Placed in the public domain
 */

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <sys/types.h>
#ଅନ୍ତର୍ଭାଵ <sys/stat.h>
#ଅନ୍ତର୍ଭାଵ <fcntl.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <stdint.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <unistd.h>

#ifdef WITH_OPENSSL
#ଅନ୍ତର୍ଭାଵ <openssl/bn.h>
#ଅନ୍ତର୍ଭାଵ <openssl/ec.h>
#ଅନ୍ତର୍ଭାଵ <openssl/rsa.h>
#ଅନ୍ତର୍ଭାଵ <openssl/objects.h>
#endif

#ଅନ୍ତର୍ଭାଵ "../test_helper/test_helper.h"

#ଅନ୍ତର୍ଭାଵ "ssherr.h"
#ଅନ୍ତର୍ଭାଵ "authfile.h"
#ଅନ୍ତର୍ଭାଵ "sshkey.h"
#ଅନ୍ତର୍ଭାଵ "sshbuf.h"

#ଅନ୍ତର୍ଭାଵ "common.h"

ଶୂନ୍ୟ sshkey_fuzz_tests(ଶୂନ୍ୟ);

ସ୍ଥିର ଶୂନ୍ୟ
onerror(ଶୂନ୍ୟ *fuzz)
{
	fprintf(stderr, "Failed during fuzz:\n");
	fuzz_dump((ସଂରଚନା fuzz *)fuzz);
}

ସ୍ଥିର ଶୂନ୍ୟ
public_fuzz(ସଂରଚନା sshkey *k)
{
	ସଂରଚନା sshkey *k1;
	ସଂରଚନା sshbuf *buf;
	ସଂରଚନା fuzz *fuzz;
	u_int fuzzers = FUZZ_1_BIT_FLIP | FUZZ_1_BYTE_FLIP |
	    FUZZ_TRUNCATE_START | FUZZ_TRUNCATE_END;

	/* MLDSA44_ED25519 keys are large and slow to fuzz */
	ଯଦି (test_is_fast() || sshkey_type_plain(k->type) == ଚାବି_MLDSA44_ED25519)
		fuzzers &= ~FUZZ_1_BIT_FLIP;
	ଯଦି (test_is_slow())
		fuzzers |= FUZZ_2_BIT_FLIP | FUZZ_2_BYTE_FLIP;

	ASSERT_PTR_NE(buf = sshbuf_new(), ଖାଲି);
	ASSERT_INT_EQ(sshkey_putb(k, buf), 0);
	fuzz = fuzz_begin(fuzzers, sshbuf_mutable_ptr(buf), sshbuf_len(buf));
	ASSERT_INT_EQ(sshkey_from_blob(sshbuf_ptr(buf), sshbuf_len(buf),
	    &k1), 0);
	sshkey_free(k1);
	sshbuf_free(buf);
	TEST_ONERROR(onerror, fuzz);
	ପାଇଁ(; !fuzz_done(fuzz); fuzz_next(fuzz)) {
		ଯଦି (sshkey_from_blob(fuzz_ptr(fuzz), fuzz_len(fuzz), &k1) == 0)
			sshkey_free(k1);
	}
	fuzz_cleanup(fuzz);
}

ସ୍ଥିର ଶୂନ୍ୟ
sig_fuzz(ସଂରଚନା sshkey *k, ଅଚଳ ଅକ୍ଷର *sig_alg)
{
	ସଂରଚନା fuzz *fuzz;
	u_char *sig, c[] = "some junk to be signed";
	size_t l;
	u_int fuzzers = FUZZ_1_BIT_FLIP | FUZZ_1_BYTE_FLIP | FUZZ_2_BYTE_FLIP |
	    FUZZ_TRUNCATE_START | FUZZ_TRUNCATE_END;

	/* MLDSA44_ED25519 keys are large and slow to fuzz */
	ଯଦି (test_is_fast() || sshkey_type_plain(k->type) == ଚାବି_MLDSA44_ED25519)
		fuzzers &= ~FUZZ_2_BYTE_FLIP;
	ଯଦି (test_is_slow())
		fuzzers |= FUZZ_2_BIT_FLIP;

	ASSERT_INT_EQ(sshkey_sign(k, &sig, &l, c, ଆକାର(c),
	    sig_alg, ଖାଲି, ଖାଲି, 0), 0);
	ASSERT_SIZE_T_GT(l, 0);
	fuzz = fuzz_begin(fuzzers, sig, l);
	ASSERT_INT_EQ(sshkey_verify(k, sig, l, c, ଆକାର(c), ଖାଲି, 0, ଖାଲି), 0);
	ମୁକ୍ତ(sig);
	TEST_ONERROR(onerror, fuzz);
	ପାଇଁ(; !fuzz_done(fuzz); fuzz_next(fuzz)) {
		/* Ensure 1-bit difference at least */
		ଯଦି (fuzz_matches_original(fuzz))
			ଜାରି;
		ASSERT_INT_NE(sshkey_verify(k, fuzz_ptr(fuzz), fuzz_len(fuzz),
		    c, ଆକାର(c), ଖାଲି, 0, ଖାଲି), 0);
	}
	fuzz_cleanup(fuzz);
}

#define ଅଙ୍କ_FAST_BASE64_TESTS	1024

ଶୂନ୍ୟ
sshkey_fuzz_tests(ଶୂନ୍ୟ)
{
	ସଂରଚନା sshkey *k1;
	ସଂରଚନା sshbuf *buf, *fuzzed;
	ସଂରଚନା fuzz *fuzz;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, i;

#ifdef WITH_OPENSSL
	TEST_START("fuzz RSA private");
	buf = load_file("rsa_1");
	fuzz = fuzz_begin(FUZZ_BASE64, sshbuf_mutable_ptr(buf),
	    sshbuf_len(buf));
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, ଖାଲି), 0);
	sshkey_free(k1);
	sshbuf_free(buf);
	ASSERT_PTR_NE(fuzzed = sshbuf_new(), ଖାଲି);
	TEST_ONERROR(onerror, fuzz);
	ପାଇଁ(i = 0; !fuzz_done(fuzz); i++, fuzz_next(fuzz)) {
		r = sshbuf_put(fuzzed, fuzz_ptr(fuzz), fuzz_len(fuzz));
		ASSERT_INT_EQ(r, 0);
		ଯଦି (sshkey_parse_private_fileblob(fuzzed, "", &k1, ଖାଲି) == 0)
			sshkey_free(k1);
		sshbuf_reset(fuzzed);
		ଯଦି (test_is_fast() && i >= ଅଙ୍କ_FAST_BASE64_TESTS)
			ଭାଙ୍ଗ;
	}
	sshbuf_free(fuzzed);
	fuzz_cleanup(fuzz);
	TEST_DONE();

	TEST_START("fuzz RSA new-format private");
	buf = load_file("rsa_n");
	fuzz = fuzz_begin(FUZZ_BASE64, sshbuf_mutable_ptr(buf),
	    sshbuf_len(buf));
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, ଖାଲି), 0);
	sshkey_free(k1);
	sshbuf_free(buf);
	ASSERT_PTR_NE(fuzzed = sshbuf_new(), ଖାଲି);
	TEST_ONERROR(onerror, fuzz);
	ପାଇଁ(i = 0; !fuzz_done(fuzz); i++, fuzz_next(fuzz)) {
		r = sshbuf_put(fuzzed, fuzz_ptr(fuzz), fuzz_len(fuzz));
		ASSERT_INT_EQ(r, 0);
		ଯଦି (sshkey_parse_private_fileblob(fuzzed, "", &k1, ଖାଲି) == 0)
			sshkey_free(k1);
		sshbuf_reset(fuzzed);
		ଯଦି (test_is_fast() && i >= ଅଙ୍କ_FAST_BASE64_TESTS)
			ଭାଙ୍ଗ;
	}
	sshbuf_free(fuzzed);
	fuzz_cleanup(fuzz);
	TEST_DONE();


	TEST_START("fuzz ECDSA private");
	buf = load_file("ecdsa_1");
	fuzz = fuzz_begin(FUZZ_BASE64, sshbuf_mutable_ptr(buf),
	    sshbuf_len(buf));
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, ଖାଲି), 0);
	sshkey_free(k1);
	sshbuf_free(buf);
	ASSERT_PTR_NE(fuzzed = sshbuf_new(), ଖାଲି);
	TEST_ONERROR(onerror, fuzz);
	ପାଇଁ(i = 0; !fuzz_done(fuzz); i++, fuzz_next(fuzz)) {
		r = sshbuf_put(fuzzed, fuzz_ptr(fuzz), fuzz_len(fuzz));
		ASSERT_INT_EQ(r, 0);
		ଯଦି (sshkey_parse_private_fileblob(fuzzed, "", &k1, ଖାଲି) == 0)
			sshkey_free(k1);
		sshbuf_reset(fuzzed);
		ଯଦି (test_is_fast() && i >= ଅଙ୍କ_FAST_BASE64_TESTS)
			ଭାଙ୍ଗ;
	}
	sshbuf_free(fuzzed);
	fuzz_cleanup(fuzz);
	TEST_DONE();

	TEST_START("fuzz ECDSA new-format private");
	buf = load_file("ecdsa_n");
	fuzz = fuzz_begin(FUZZ_BASE64, sshbuf_mutable_ptr(buf),
	    sshbuf_len(buf));
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, ଖାଲି), 0);
	sshkey_free(k1);
	sshbuf_free(buf);
	ASSERT_PTR_NE(fuzzed = sshbuf_new(), ଖାଲି);
	TEST_ONERROR(onerror, fuzz);
	ପାଇଁ(i = 0; !fuzz_done(fuzz); i++, fuzz_next(fuzz)) {
		r = sshbuf_put(fuzzed, fuzz_ptr(fuzz), fuzz_len(fuzz));
		ASSERT_INT_EQ(r, 0);
		ଯଦି (sshkey_parse_private_fileblob(fuzzed, "", &k1, ଖାଲି) == 0)
			sshkey_free(k1);
		sshbuf_reset(fuzzed);
		ଯଦି (test_is_fast() && i >= ଅଙ୍କ_FAST_BASE64_TESTS)
			ଭାଙ୍ଗ;
	}
	sshbuf_free(fuzzed);
	fuzz_cleanup(fuzz);
	TEST_DONE();
#endif /* WITH_OPENSSL */

	TEST_START("fuzz Ed25519 private");
	buf = load_file("ed25519_1");
	fuzz = fuzz_begin(FUZZ_BASE64, sshbuf_mutable_ptr(buf),
	    sshbuf_len(buf));
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, ଖାଲି), 0);
	sshkey_free(k1);
	sshbuf_free(buf);
	ASSERT_PTR_NE(fuzzed = sshbuf_new(), ଖାଲି);
	TEST_ONERROR(onerror, fuzz);
	ପାଇଁ(i = 0; !fuzz_done(fuzz); i++, fuzz_next(fuzz)) {
		r = sshbuf_put(fuzzed, fuzz_ptr(fuzz), fuzz_len(fuzz));
		ASSERT_INT_EQ(r, 0);
		ଯଦି (sshkey_parse_private_fileblob(fuzzed, "", &k1, ଖାଲି) == 0)
			sshkey_free(k1);
		sshbuf_reset(fuzzed);
		ଯଦି (test_is_fast() && i >= ଅଙ୍କ_FAST_BASE64_TESTS)
			ଭାଙ୍ଗ;
	}
	sshbuf_free(fuzzed);
	fuzz_cleanup(fuzz);
	TEST_DONE();

	/* MLDSA44-ED25519 are large and slow to fuzz */
	TEST_START("fuzz MLDSA44-ED25519 private");
	buf = load_file("mldsa44_ed25519_1");
	fuzz = fuzz_begin(FUZZ_BASE64, sshbuf_mutable_ptr(buf),
	    sshbuf_len(buf));
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, ଖାଲି), 0);
	sshkey_free(k1);
	sshbuf_free(buf);
	ASSERT_PTR_NE(fuzzed = sshbuf_new(), ଖାଲି);
	TEST_ONERROR(onerror, fuzz);
	ପାଇଁ(i = 0; !fuzz_done(fuzz); i++, fuzz_next(fuzz)) {
		r = sshbuf_put(fuzzed, fuzz_ptr(fuzz), fuzz_len(fuzz));
		ASSERT_INT_EQ(r, 0);
		ଯଦି (sshkey_parse_private_fileblob(fuzzed, "", &k1, ଖାଲି) == 0)
			sshkey_free(k1);
		sshbuf_reset(fuzzed);
		ଯଦି (test_is_fast() && i >= ଅଙ୍କ_FAST_BASE64_TESTS)
			ଭାଙ୍ଗ;
		/* MLDSA44_ED25519 keys are large and slow to fuzz */
		ଯଦି (!test_is_slow() || i >= ଅଙ୍କ_FAST_BASE64_TESTS)
			ଭାଙ୍ଗ;
	}
	sshbuf_free(fuzzed);
	fuzz_cleanup(fuzz);
	TEST_DONE();

#ifdef WITH_OPENSSL
	TEST_START("fuzz RSA public");
	buf = load_file("rsa_1");
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, ଖାଲି), 0);
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
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, ଖାଲି), 0);
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
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, ଖାଲି), 0);
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
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, ଖାଲି), 0);
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
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, ଖାଲି), 0);
	sshbuf_free(buf);
	sig_fuzz(k1, "ssh-rsa");
	sshkey_free(k1);
	TEST_DONE();

	TEST_START("fuzz RSA SHA256 sig");
	buf = load_file("rsa_1");
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, ଖାଲି), 0);
	sshbuf_free(buf);
	sig_fuzz(k1, "rsa-sha2-256");
	sshkey_free(k1);
	TEST_DONE();

	TEST_START("fuzz RSA SHA512 sig");
	buf = load_file("rsa_1");
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, ଖାଲି), 0);
	sshbuf_free(buf);
	sig_fuzz(k1, "rsa-sha2-512");
	sshkey_free(k1);
	TEST_DONE();


	TEST_START("fuzz ECDSA sig");
	buf = load_file("ecdsa_1");
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, ଖାଲି), 0);
	sshbuf_free(buf);
	sig_fuzz(k1, ଖାଲି);
	sshkey_free(k1);
	TEST_DONE();
#endif /* WITH_OPENSSL */

	TEST_START("fuzz Ed25519 sig");
	buf = load_file("ed25519_1");
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, ଖାଲି), 0);
	sshbuf_free(buf);
	sig_fuzz(k1, ଖାଲି);
	sshkey_free(k1);
	TEST_DONE();

	TEST_START("fuzz MLDSA44-ED25519 sig");
	buf = load_file("mldsa44_ed25519_1");
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, ଖାଲି), 0);
	sshbuf_free(buf);
	sig_fuzz(k1, ଖାଲି);
	sshkey_free(k1);
	TEST_DONE();

/* XXX fuzz decoded new-format blobs too */
/* XXX fuzz XMSS too */

}
