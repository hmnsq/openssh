/* 	$OpenBSD: test_fuzz.c,v 1.16 2026/06/14 04:08:06 djm Exp $ */
/*
 * Fuzz tests for key parsing
 *
 * Placed in the public domain
 */

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <sys/stat.h>
#அந்தர்பாவ <fcntl.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <stdint.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <unistd.h>

#ifdef WITH_OPENSSL
#அந்தர்பாவ <openssl/bn.h>
#அந்தர்பாவ <openssl/ec.h>
#அந்தர்பாவ <openssl/rsa.h>
#அந்தர்பாவ <openssl/objects.h>
#endif

#அந்தர்பாவ "../test_helper/test_helper.h"

#அந்தர்பாவ "ssherr.h"
#அந்தர்பாவ "authfile.h"
#அந்தர்பாவ "sshkey.h"
#அந்தர்பாவ "sshbuf.h"

#அந்தர்பாவ "common.h"

வெறுமை sshkey_fuzz_tests(வெறுமை);

நிலையான வெறுமை
onerror(வெறுமை *fuzz)
{
	fprintf(stderr, "Failed during fuzz:\n");
	fuzz_dump((கட்டமைப்பு fuzz *)fuzz);
}

நிலையான வெறுமை
public_fuzz(கட்டமைப்பு sshkey *k)
{
	கட்டமைப்பு sshkey *k1;
	கட்டமைப்பு sshbuf *buf;
	கட்டமைப்பு fuzz *fuzz;
	u_int fuzzers = FUZZ_1_BIT_FLIP | FUZZ_1_BYTE_FLIP |
	    FUZZ_TRUNCATE_START | FUZZ_TRUNCATE_END;

	/* MLDSA44_ED25519 keys are large and slow to fuzz */
	எனில் (test_is_fast() || sshkey_type_plain(k->type) == சாவி_MLDSA44_ED25519)
		fuzzers &= ~FUZZ_1_BIT_FLIP;
	எனில் (test_is_slow())
		fuzzers |= FUZZ_2_BIT_FLIP | FUZZ_2_BYTE_FLIP;

	ASSERT_PTR_NE(buf = sshbuf_new(), வெற்று);
	ASSERT_INT_EQ(sshkey_putb(k, buf), 0);
	fuzz = fuzz_begin(fuzzers, sshbuf_mutable_ptr(buf), sshbuf_len(buf));
	ASSERT_INT_EQ(sshkey_from_blob(sshbuf_ptr(buf), sshbuf_len(buf),
	    &k1), 0);
	sshkey_free(k1);
	sshbuf_free(buf);
	TEST_ONERROR(onerror, fuzz);
	க்கு(; !fuzz_done(fuzz); fuzz_next(fuzz)) {
		எனில் (sshkey_from_blob(fuzz_ptr(fuzz), fuzz_len(fuzz), &k1) == 0)
			sshkey_free(k1);
	}
	fuzz_cleanup(fuzz);
}

நிலையான வெறுமை
sig_fuzz(கட்டமைப்பு sshkey *k, மாறிலி எழுத்து *sig_alg)
{
	கட்டமைப்பு fuzz *fuzz;
	u_char *sig, c[] = "some junk to be signed";
	size_t l;
	u_int fuzzers = FUZZ_1_BIT_FLIP | FUZZ_1_BYTE_FLIP | FUZZ_2_BYTE_FLIP |
	    FUZZ_TRUNCATE_START | FUZZ_TRUNCATE_END;

	/* MLDSA44_ED25519 keys are large and slow to fuzz */
	எனில் (test_is_fast() || sshkey_type_plain(k->type) == சாவி_MLDSA44_ED25519)
		fuzzers &= ~FUZZ_2_BYTE_FLIP;
	எனில் (test_is_slow())
		fuzzers |= FUZZ_2_BIT_FLIP;

	ASSERT_INT_EQ(sshkey_sign(k, &sig, &l, c, அளவு(c),
	    sig_alg, வெற்று, வெற்று, 0), 0);
	ASSERT_SIZE_T_GT(l, 0);
	fuzz = fuzz_begin(fuzzers, sig, l);
	ASSERT_INT_EQ(sshkey_verify(k, sig, l, c, அளவு(c), வெற்று, 0, வெற்று), 0);
	விடுவி(sig);
	TEST_ONERROR(onerror, fuzz);
	க்கு(; !fuzz_done(fuzz); fuzz_next(fuzz)) {
		/* Ensure 1-bit difference at least */
		எனில் (fuzz_matches_original(fuzz))
			தொடர்;
		ASSERT_INT_NE(sshkey_verify(k, fuzz_ptr(fuzz), fuzz_len(fuzz),
		    c, அளவு(c), வெற்று, 0, வெற்று), 0);
	}
	fuzz_cleanup(fuzz);
}

#define இலக்கம்_FAST_BASE64_TESTS	1024

வெறுமை
sshkey_fuzz_tests(வெறுமை)
{
	கட்டமைப்பு sshkey *k1;
	கட்டமைப்பு sshbuf *buf, *fuzzed;
	கட்டமைப்பு fuzz *fuzz;
	முழு r, i;

#ifdef WITH_OPENSSL
	TEST_START("fuzz RSA private");
	buf = load_file("rsa_1");
	fuzz = fuzz_begin(FUZZ_BASE64, sshbuf_mutable_ptr(buf),
	    sshbuf_len(buf));
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, வெற்று), 0);
	sshkey_free(k1);
	sshbuf_free(buf);
	ASSERT_PTR_NE(fuzzed = sshbuf_new(), வெற்று);
	TEST_ONERROR(onerror, fuzz);
	க்கு(i = 0; !fuzz_done(fuzz); i++, fuzz_next(fuzz)) {
		r = sshbuf_put(fuzzed, fuzz_ptr(fuzz), fuzz_len(fuzz));
		ASSERT_INT_EQ(r, 0);
		எனில் (sshkey_parse_private_fileblob(fuzzed, "", &k1, வெற்று) == 0)
			sshkey_free(k1);
		sshbuf_reset(fuzzed);
		எனில் (test_is_fast() && i >= இலக்கம்_FAST_BASE64_TESTS)
			நிறுத்து;
	}
	sshbuf_free(fuzzed);
	fuzz_cleanup(fuzz);
	TEST_DONE();

	TEST_START("fuzz RSA new-format private");
	buf = load_file("rsa_n");
	fuzz = fuzz_begin(FUZZ_BASE64, sshbuf_mutable_ptr(buf),
	    sshbuf_len(buf));
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, வெற்று), 0);
	sshkey_free(k1);
	sshbuf_free(buf);
	ASSERT_PTR_NE(fuzzed = sshbuf_new(), வெற்று);
	TEST_ONERROR(onerror, fuzz);
	க்கு(i = 0; !fuzz_done(fuzz); i++, fuzz_next(fuzz)) {
		r = sshbuf_put(fuzzed, fuzz_ptr(fuzz), fuzz_len(fuzz));
		ASSERT_INT_EQ(r, 0);
		எனில் (sshkey_parse_private_fileblob(fuzzed, "", &k1, வெற்று) == 0)
			sshkey_free(k1);
		sshbuf_reset(fuzzed);
		எனில் (test_is_fast() && i >= இலக்கம்_FAST_BASE64_TESTS)
			நிறுத்து;
	}
	sshbuf_free(fuzzed);
	fuzz_cleanup(fuzz);
	TEST_DONE();


	TEST_START("fuzz ECDSA private");
	buf = load_file("ecdsa_1");
	fuzz = fuzz_begin(FUZZ_BASE64, sshbuf_mutable_ptr(buf),
	    sshbuf_len(buf));
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, வெற்று), 0);
	sshkey_free(k1);
	sshbuf_free(buf);
	ASSERT_PTR_NE(fuzzed = sshbuf_new(), வெற்று);
	TEST_ONERROR(onerror, fuzz);
	க்கு(i = 0; !fuzz_done(fuzz); i++, fuzz_next(fuzz)) {
		r = sshbuf_put(fuzzed, fuzz_ptr(fuzz), fuzz_len(fuzz));
		ASSERT_INT_EQ(r, 0);
		எனில் (sshkey_parse_private_fileblob(fuzzed, "", &k1, வெற்று) == 0)
			sshkey_free(k1);
		sshbuf_reset(fuzzed);
		எனில் (test_is_fast() && i >= இலக்கம்_FAST_BASE64_TESTS)
			நிறுத்து;
	}
	sshbuf_free(fuzzed);
	fuzz_cleanup(fuzz);
	TEST_DONE();

	TEST_START("fuzz ECDSA new-format private");
	buf = load_file("ecdsa_n");
	fuzz = fuzz_begin(FUZZ_BASE64, sshbuf_mutable_ptr(buf),
	    sshbuf_len(buf));
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, வெற்று), 0);
	sshkey_free(k1);
	sshbuf_free(buf);
	ASSERT_PTR_NE(fuzzed = sshbuf_new(), வெற்று);
	TEST_ONERROR(onerror, fuzz);
	க்கு(i = 0; !fuzz_done(fuzz); i++, fuzz_next(fuzz)) {
		r = sshbuf_put(fuzzed, fuzz_ptr(fuzz), fuzz_len(fuzz));
		ASSERT_INT_EQ(r, 0);
		எனில் (sshkey_parse_private_fileblob(fuzzed, "", &k1, வெற்று) == 0)
			sshkey_free(k1);
		sshbuf_reset(fuzzed);
		எனில் (test_is_fast() && i >= இலக்கம்_FAST_BASE64_TESTS)
			நிறுத்து;
	}
	sshbuf_free(fuzzed);
	fuzz_cleanup(fuzz);
	TEST_DONE();
#endif /* WITH_OPENSSL */

	TEST_START("fuzz Ed25519 private");
	buf = load_file("ed25519_1");
	fuzz = fuzz_begin(FUZZ_BASE64, sshbuf_mutable_ptr(buf),
	    sshbuf_len(buf));
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, வெற்று), 0);
	sshkey_free(k1);
	sshbuf_free(buf);
	ASSERT_PTR_NE(fuzzed = sshbuf_new(), வெற்று);
	TEST_ONERROR(onerror, fuzz);
	க்கு(i = 0; !fuzz_done(fuzz); i++, fuzz_next(fuzz)) {
		r = sshbuf_put(fuzzed, fuzz_ptr(fuzz), fuzz_len(fuzz));
		ASSERT_INT_EQ(r, 0);
		எனில் (sshkey_parse_private_fileblob(fuzzed, "", &k1, வெற்று) == 0)
			sshkey_free(k1);
		sshbuf_reset(fuzzed);
		எனில் (test_is_fast() && i >= இலக்கம்_FAST_BASE64_TESTS)
			நிறுத்து;
	}
	sshbuf_free(fuzzed);
	fuzz_cleanup(fuzz);
	TEST_DONE();

	/* MLDSA44-ED25519 are large and slow to fuzz */
	TEST_START("fuzz MLDSA44-ED25519 private");
	buf = load_file("mldsa44_ed25519_1");
	fuzz = fuzz_begin(FUZZ_BASE64, sshbuf_mutable_ptr(buf),
	    sshbuf_len(buf));
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, வெற்று), 0);
	sshkey_free(k1);
	sshbuf_free(buf);
	ASSERT_PTR_NE(fuzzed = sshbuf_new(), வெற்று);
	TEST_ONERROR(onerror, fuzz);
	க்கு(i = 0; !fuzz_done(fuzz); i++, fuzz_next(fuzz)) {
		r = sshbuf_put(fuzzed, fuzz_ptr(fuzz), fuzz_len(fuzz));
		ASSERT_INT_EQ(r, 0);
		எனில் (sshkey_parse_private_fileblob(fuzzed, "", &k1, வெற்று) == 0)
			sshkey_free(k1);
		sshbuf_reset(fuzzed);
		எனில் (test_is_fast() && i >= இலக்கம்_FAST_BASE64_TESTS)
			நிறுத்து;
		/* MLDSA44_ED25519 keys are large and slow to fuzz */
		எனில் (!test_is_slow() || i >= இலக்கம்_FAST_BASE64_TESTS)
			நிறுத்து;
	}
	sshbuf_free(fuzzed);
	fuzz_cleanup(fuzz);
	TEST_DONE();

#ifdef WITH_OPENSSL
	TEST_START("fuzz RSA public");
	buf = load_file("rsa_1");
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, வெற்று), 0);
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
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, வெற்று), 0);
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
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, வெற்று), 0);
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
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, வெற்று), 0);
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
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, வெற்று), 0);
	sshbuf_free(buf);
	sig_fuzz(k1, "ssh-rsa");
	sshkey_free(k1);
	TEST_DONE();

	TEST_START("fuzz RSA SHA256 sig");
	buf = load_file("rsa_1");
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, வெற்று), 0);
	sshbuf_free(buf);
	sig_fuzz(k1, "rsa-sha2-256");
	sshkey_free(k1);
	TEST_DONE();

	TEST_START("fuzz RSA SHA512 sig");
	buf = load_file("rsa_1");
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, வெற்று), 0);
	sshbuf_free(buf);
	sig_fuzz(k1, "rsa-sha2-512");
	sshkey_free(k1);
	TEST_DONE();


	TEST_START("fuzz ECDSA sig");
	buf = load_file("ecdsa_1");
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, வெற்று), 0);
	sshbuf_free(buf);
	sig_fuzz(k1, வெற்று);
	sshkey_free(k1);
	TEST_DONE();
#endif /* WITH_OPENSSL */

	TEST_START("fuzz Ed25519 sig");
	buf = load_file("ed25519_1");
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, வெற்று), 0);
	sshbuf_free(buf);
	sig_fuzz(k1, வெற்று);
	sshkey_free(k1);
	TEST_DONE();

	TEST_START("fuzz MLDSA44-ED25519 sig");
	buf = load_file("mldsa44_ed25519_1");
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, வெற்று), 0);
	sshbuf_free(buf);
	sig_fuzz(k1, வெற்று);
	sshkey_free(k1);
	TEST_DONE();

/* XXX fuzz decoded new-format blobs too */
/* XXX fuzz XMSS too */

}
