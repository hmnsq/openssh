/* 	$OpenBSD: test_fuzz.c,v 1.16 2026/06/14 04:08:06 djm Exp $ */
/*
 * Fuzz tests for key parsing
 *
 * Placed in the public domain
 */

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <sys/types.h>
#অন্তর্ভাব <sys/stat.h>
#অন্তর্ভাব <fcntl.h>
#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <stdint.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <unistd.h>

#ifdef WITH_OPENSSL
#অন্তর্ভাব <openssl/bn.h>
#অন্তর্ভাব <openssl/ec.h>
#অন্তর্ভাব <openssl/rsa.h>
#অন্তর্ভাব <openssl/objects.h>
#endif

#অন্তর্ভাব "../test_helper/test_helper.h"

#অন্তর্ভাব "ssherr.h"
#অন্তর্ভাব "authfile.h"
#অন্তর্ভাব "sshkey.h"
#অন্তর্ভাব "sshbuf.h"

#অন্তর্ভাব "common.h"

শূন্য sshkey_fuzz_tests(শূন্য);

স্থির শূন্য
onerror(শূন্য *fuzz)
{
	fprintf(stderr, "Failed during fuzz:\n");
	fuzz_dump((কাঠামো fuzz *)fuzz);
}

স্থির শূন্য
public_fuzz(কাঠামো sshkey *k)
{
	কাঠামো sshkey *k1;
	কাঠামো sshbuf *buf;
	কাঠামো fuzz *fuzz;
	u_int fuzzers = FUZZ_1_BIT_FLIP | FUZZ_1_BYTE_FLIP |
	    FUZZ_TRUNCATE_START | FUZZ_TRUNCATE_END;

	/* MLDSA44_ED25519 keys are large and slow to fuzz */
	যদি (test_is_fast() || sshkey_type_plain(k->type) == চাবি_MLDSA44_ED25519)
		fuzzers &= ~FUZZ_1_BIT_FLIP;
	যদি (test_is_slow())
		fuzzers |= FUZZ_2_BIT_FLIP | FUZZ_2_BYTE_FLIP;

	ASSERT_PTR_NE(buf = sshbuf_new(), ফাঁকা);
	ASSERT_INT_EQ(sshkey_putb(k, buf), 0);
	fuzz = fuzz_begin(fuzzers, sshbuf_mutable_ptr(buf), sshbuf_len(buf));
	ASSERT_INT_EQ(sshkey_from_blob(sshbuf_ptr(buf), sshbuf_len(buf),
	    &k1), 0);
	sshkey_free(k1);
	sshbuf_free(buf);
	TEST_ONERROR(onerror, fuzz);
	জন্য(; !fuzz_done(fuzz); fuzz_পরবর্তী(fuzz)) {
		যদি (sshkey_from_blob(fuzz_ptr(fuzz), fuzz_len(fuzz), &k1) == 0)
			sshkey_free(k1);
	}
	fuzz_cleanup(fuzz);
}

স্থির শূন্য
sig_fuzz(কাঠামো sshkey *k, ধ্রুবক অক্ষর *sig_alg)
{
	কাঠামো fuzz *fuzz;
	u_char *sig, c[] = "some junk to be signed";
	আকার_t l;
	u_int fuzzers = FUZZ_1_BIT_FLIP | FUZZ_1_BYTE_FLIP | FUZZ_2_BYTE_FLIP |
	    FUZZ_TRUNCATE_START | FUZZ_TRUNCATE_END;

	/* MLDSA44_ED25519 keys are large and slow to fuzz */
	যদি (test_is_fast() || sshkey_type_plain(k->type) == চাবি_MLDSA44_ED25519)
		fuzzers &= ~FUZZ_2_BYTE_FLIP;
	যদি (test_is_slow())
		fuzzers |= FUZZ_2_BIT_FLIP;

	ASSERT_INT_EQ(sshkey_sign(k, &sig, &l, c, আকার(c),
	    sig_alg, ফাঁকা, ফাঁকা, 0), 0);
	ASSERT_আকার_T_GT(l, 0);
	fuzz = fuzz_begin(fuzzers, sig, l);
	ASSERT_INT_EQ(sshkey_verify(k, sig, l, c, আকার(c), ফাঁকা, 0, ফাঁকা), 0);
	মুক্ত(sig);
	TEST_ONERROR(onerror, fuzz);
	জন্য(; !fuzz_done(fuzz); fuzz_পরবর্তী(fuzz)) {
		/* Ensure 1-bit difference at least */
		যদি (fuzz_matches_original(fuzz))
			চালু;
		ASSERT_INT_NE(sshkey_verify(k, fuzz_ptr(fuzz), fuzz_len(fuzz),
		    c, আকার(c), ফাঁকা, 0, ফাঁকা), 0);
	}
	fuzz_cleanup(fuzz);
}

#define অঙ্ক_FAST_BASE64_TESTS	1024

শূন্য
sshkey_fuzz_tests(শূন্য)
{
	কাঠামো sshkey *k1;
	কাঠামো sshbuf *buf, *fuzzed;
	কাঠামো fuzz *fuzz;
	পূর্ণসংখ্যা r, i;

#ifdef WITH_OPENSSL
	TEST_START("fuzz RSA private");
	buf = load_file("rsa_1");
	fuzz = fuzz_begin(FUZZ_BASE64, sshbuf_mutable_ptr(buf),
	    sshbuf_len(buf));
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, ফাঁকা), 0);
	sshkey_free(k1);
	sshbuf_free(buf);
	ASSERT_PTR_NE(fuzzed = sshbuf_new(), ফাঁকা);
	TEST_ONERROR(onerror, fuzz);
	জন্য(i = 0; !fuzz_done(fuzz); i++, fuzz_পরবর্তী(fuzz)) {
		r = sshbuf_put(fuzzed, fuzz_ptr(fuzz), fuzz_len(fuzz));
		ASSERT_INT_EQ(r, 0);
		যদি (sshkey_parse_private_fileblob(fuzzed, "", &k1, ফাঁকা) == 0)
			sshkey_free(k1);
		sshbuf_reset(fuzzed);
		যদি (test_is_fast() && i >= অঙ্ক_FAST_BASE64_TESTS)
			বিরতি;
	}
	sshbuf_free(fuzzed);
	fuzz_cleanup(fuzz);
	TEST_DONE();

	TEST_START("fuzz RSA new-format private");
	buf = load_file("rsa_n");
	fuzz = fuzz_begin(FUZZ_BASE64, sshbuf_mutable_ptr(buf),
	    sshbuf_len(buf));
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, ফাঁকা), 0);
	sshkey_free(k1);
	sshbuf_free(buf);
	ASSERT_PTR_NE(fuzzed = sshbuf_new(), ফাঁকা);
	TEST_ONERROR(onerror, fuzz);
	জন্য(i = 0; !fuzz_done(fuzz); i++, fuzz_পরবর্তী(fuzz)) {
		r = sshbuf_put(fuzzed, fuzz_ptr(fuzz), fuzz_len(fuzz));
		ASSERT_INT_EQ(r, 0);
		যদি (sshkey_parse_private_fileblob(fuzzed, "", &k1, ফাঁকা) == 0)
			sshkey_free(k1);
		sshbuf_reset(fuzzed);
		যদি (test_is_fast() && i >= অঙ্ক_FAST_BASE64_TESTS)
			বিরতি;
	}
	sshbuf_free(fuzzed);
	fuzz_cleanup(fuzz);
	TEST_DONE();


	TEST_START("fuzz ECDSA private");
	buf = load_file("ecdsa_1");
	fuzz = fuzz_begin(FUZZ_BASE64, sshbuf_mutable_ptr(buf),
	    sshbuf_len(buf));
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, ফাঁকা), 0);
	sshkey_free(k1);
	sshbuf_free(buf);
	ASSERT_PTR_NE(fuzzed = sshbuf_new(), ফাঁকা);
	TEST_ONERROR(onerror, fuzz);
	জন্য(i = 0; !fuzz_done(fuzz); i++, fuzz_পরবর্তী(fuzz)) {
		r = sshbuf_put(fuzzed, fuzz_ptr(fuzz), fuzz_len(fuzz));
		ASSERT_INT_EQ(r, 0);
		যদি (sshkey_parse_private_fileblob(fuzzed, "", &k1, ফাঁকা) == 0)
			sshkey_free(k1);
		sshbuf_reset(fuzzed);
		যদি (test_is_fast() && i >= অঙ্ক_FAST_BASE64_TESTS)
			বিরতি;
	}
	sshbuf_free(fuzzed);
	fuzz_cleanup(fuzz);
	TEST_DONE();

	TEST_START("fuzz ECDSA new-format private");
	buf = load_file("ecdsa_n");
	fuzz = fuzz_begin(FUZZ_BASE64, sshbuf_mutable_ptr(buf),
	    sshbuf_len(buf));
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, ফাঁকা), 0);
	sshkey_free(k1);
	sshbuf_free(buf);
	ASSERT_PTR_NE(fuzzed = sshbuf_new(), ফাঁকা);
	TEST_ONERROR(onerror, fuzz);
	জন্য(i = 0; !fuzz_done(fuzz); i++, fuzz_পরবর্তী(fuzz)) {
		r = sshbuf_put(fuzzed, fuzz_ptr(fuzz), fuzz_len(fuzz));
		ASSERT_INT_EQ(r, 0);
		যদি (sshkey_parse_private_fileblob(fuzzed, "", &k1, ফাঁকা) == 0)
			sshkey_free(k1);
		sshbuf_reset(fuzzed);
		যদি (test_is_fast() && i >= অঙ্ক_FAST_BASE64_TESTS)
			বিরতি;
	}
	sshbuf_free(fuzzed);
	fuzz_cleanup(fuzz);
	TEST_DONE();
#endif /* WITH_OPENSSL */

	TEST_START("fuzz Ed25519 private");
	buf = load_file("ed25519_1");
	fuzz = fuzz_begin(FUZZ_BASE64, sshbuf_mutable_ptr(buf),
	    sshbuf_len(buf));
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, ফাঁকা), 0);
	sshkey_free(k1);
	sshbuf_free(buf);
	ASSERT_PTR_NE(fuzzed = sshbuf_new(), ফাঁকা);
	TEST_ONERROR(onerror, fuzz);
	জন্য(i = 0; !fuzz_done(fuzz); i++, fuzz_পরবর্তী(fuzz)) {
		r = sshbuf_put(fuzzed, fuzz_ptr(fuzz), fuzz_len(fuzz));
		ASSERT_INT_EQ(r, 0);
		যদি (sshkey_parse_private_fileblob(fuzzed, "", &k1, ফাঁকা) == 0)
			sshkey_free(k1);
		sshbuf_reset(fuzzed);
		যদি (test_is_fast() && i >= অঙ্ক_FAST_BASE64_TESTS)
			বিরতি;
	}
	sshbuf_free(fuzzed);
	fuzz_cleanup(fuzz);
	TEST_DONE();

	/* MLDSA44-ED25519 are large and slow to fuzz */
	TEST_START("fuzz MLDSA44-ED25519 private");
	buf = load_file("mldsa44_ed25519_1");
	fuzz = fuzz_begin(FUZZ_BASE64, sshbuf_mutable_ptr(buf),
	    sshbuf_len(buf));
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, ফাঁকা), 0);
	sshkey_free(k1);
	sshbuf_free(buf);
	ASSERT_PTR_NE(fuzzed = sshbuf_new(), ফাঁকা);
	TEST_ONERROR(onerror, fuzz);
	জন্য(i = 0; !fuzz_done(fuzz); i++, fuzz_পরবর্তী(fuzz)) {
		r = sshbuf_put(fuzzed, fuzz_ptr(fuzz), fuzz_len(fuzz));
		ASSERT_INT_EQ(r, 0);
		যদি (sshkey_parse_private_fileblob(fuzzed, "", &k1, ফাঁকা) == 0)
			sshkey_free(k1);
		sshbuf_reset(fuzzed);
		যদি (test_is_fast() && i >= অঙ্ক_FAST_BASE64_TESTS)
			বিরতি;
		/* MLDSA44_ED25519 keys are large and slow to fuzz */
		যদি (!test_is_slow() || i >= অঙ্ক_FAST_BASE64_TESTS)
			বিরতি;
	}
	sshbuf_free(fuzzed);
	fuzz_cleanup(fuzz);
	TEST_DONE();

#ifdef WITH_OPENSSL
	TEST_START("fuzz RSA public");
	buf = load_file("rsa_1");
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, ফাঁকা), 0);
	sshbuf_free(buf);
	public_fuzz(k1);
	sshkey_free(k1);
	TEST_DONE();

	TEST_START("fuzz RSA cert");
	ASSERT_INT_EQ(sshkey_load_cert(test_তথ্য_file("rsa_1"), &k1), 0);
	public_fuzz(k1);
	sshkey_free(k1);
	TEST_DONE();


	TEST_START("fuzz ECDSA public");
	buf = load_file("ecdsa_1");
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, ফাঁকা), 0);
	sshbuf_free(buf);
	public_fuzz(k1);
	sshkey_free(k1);
	TEST_DONE();

	TEST_START("fuzz ECDSA cert");
	ASSERT_INT_EQ(sshkey_load_cert(test_তথ্য_file("ecdsa_1"), &k1), 0);
	public_fuzz(k1);
	sshkey_free(k1);
	TEST_DONE();
#endif /* WITH_OPENSSL */

	TEST_START("fuzz Ed25519 public");
	buf = load_file("ed25519_1");
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, ফাঁকা), 0);
	sshbuf_free(buf);
	public_fuzz(k1);
	sshkey_free(k1);
	TEST_DONE();

	TEST_START("fuzz Ed25519 cert");
	ASSERT_INT_EQ(sshkey_load_cert(test_তথ্য_file("ed25519_1"), &k1), 0);
	public_fuzz(k1);
	sshkey_free(k1);
	TEST_DONE();

	TEST_START("fuzz MLDSA44-ED25519 public");
	buf = load_file("mldsa44_ed25519_1");
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, ফাঁকা), 0);
	sshbuf_free(buf);
	public_fuzz(k1);
	sshkey_free(k1);
	TEST_DONE();

	TEST_START("fuzz MLDSA44-ED25519 cert");
	ASSERT_INT_EQ(sshkey_load_cert(
	    test_তথ্য_file("mldsa44_ed25519_1"), &k1), 0);
	public_fuzz(k1);
	sshkey_free(k1);
	TEST_DONE();

#ifdef WITH_OPENSSL
	TEST_START("fuzz RSA sig");
	buf = load_file("rsa_1");
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, ফাঁকা), 0);
	sshbuf_free(buf);
	sig_fuzz(k1, "ssh-rsa");
	sshkey_free(k1);
	TEST_DONE();

	TEST_START("fuzz RSA SHA256 sig");
	buf = load_file("rsa_1");
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, ফাঁকা), 0);
	sshbuf_free(buf);
	sig_fuzz(k1, "rsa-sha2-256");
	sshkey_free(k1);
	TEST_DONE();

	TEST_START("fuzz RSA SHA512 sig");
	buf = load_file("rsa_1");
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, ফাঁকা), 0);
	sshbuf_free(buf);
	sig_fuzz(k1, "rsa-sha2-512");
	sshkey_free(k1);
	TEST_DONE();


	TEST_START("fuzz ECDSA sig");
	buf = load_file("ecdsa_1");
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, ফাঁকা), 0);
	sshbuf_free(buf);
	sig_fuzz(k1, ফাঁকা);
	sshkey_free(k1);
	TEST_DONE();
#endif /* WITH_OPENSSL */

	TEST_START("fuzz Ed25519 sig");
	buf = load_file("ed25519_1");
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, ফাঁকা), 0);
	sshbuf_free(buf);
	sig_fuzz(k1, ফাঁকা);
	sshkey_free(k1);
	TEST_DONE();

	TEST_START("fuzz MLDSA44-ED25519 sig");
	buf = load_file("mldsa44_ed25519_1");
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, ফাঁকা), 0);
	sshbuf_free(buf);
	sig_fuzz(k1, ফাঁকা);
	sshkey_free(k1);
	TEST_DONE();

/* XXX fuzz decoded new-format blobs too */
/* XXX fuzz XMSS too */

}
