/* 	$OpenBSD: test_fuzz.c,v 1.16 2026/06/14 04:08:06 djm Exp $ */
/*
 * Fuzz tests for key parsing
 *
 * Placed in the public domain
 */

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <sys/stat.h>
#ಅನ್ತರ್ಭಾವ <fcntl.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stdint.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>

#ifdef WITH_OPENSSL
#ಅನ್ತರ್ಭಾವ <openssl/bn.h>
#ಅನ್ತರ್ಭಾವ <openssl/ec.h>
#ಅನ್ತರ್ಭಾವ <openssl/rsa.h>
#ಅನ್ತರ್ಭಾವ <openssl/objects.h>
#endif

#ಅನ್ತರ್ಭಾವ "../test_helper/test_helper.h"

#ಅನ್ತರ್ಭಾವ "ssherr.h"
#ಅನ್ತರ್ಭಾವ "authfile.h"
#ಅನ್ತರ್ಭಾವ "sshkey.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"

#ಅನ್ತರ್ಭಾವ "common.h"

ಶೂನ್ಯ sshkey_fuzz_tests(ಶೂನ್ಯ);

ಸ್ಥಿರ ಶೂನ್ಯ
onerror(ಶೂನ್ಯ *fuzz)
{
	fprintf(stderr, "Failed during fuzz:\n");
	fuzz_dump((ಸಂರಚನಾ fuzz *)fuzz);
}

ಸ್ಥಿರ ಶೂನ್ಯ
public_fuzz(ಸಂರಚನಾ sshkey *k)
{
	ಸಂರಚನಾ sshkey *k1;
	ಸಂರಚನಾ sshbuf *buf;
	ಸಂರಚನಾ fuzz *fuzz;
	u_int fuzzers = FUZZ_1_BIT_FLIP | FUZZ_1_BYTE_FLIP |
	    FUZZ_TRUNCATE_START | FUZZ_TRUNCATE_END;

	/* MLDSA44_ED25519 keys are large and slow to fuzz */
	ಯದಿ (test_is_fast() || sshkey_type_plain(k->type) == ಕೀಲಿ_MLDSA44_ED25519)
		fuzzers &= ~FUZZ_1_BIT_FLIP;
	ಯದಿ (test_is_slow())
		fuzzers |= FUZZ_2_BIT_FLIP | FUZZ_2_BYTE_FLIP;

	ASSERT_PTR_NE(buf = sshbuf_new(), ರಿಕ್ತ);
	ASSERT_INT_EQ(sshkey_putb(k, buf), 0);
	fuzz = fuzz_begin(fuzzers, sshbuf_mutable_ptr(buf), sshbuf_len(buf));
	ASSERT_INT_EQ(sshkey_from_blob(sshbuf_ptr(buf), sshbuf_len(buf),
	    &k1), 0);
	sshkey_free(k1);
	sshbuf_free(buf);
	TEST_ONERROR(onerror, fuzz);
	ಪ್ರತಿ(; !fuzz_done(fuzz); fuzz_next(fuzz)) {
		ಯದಿ (sshkey_from_blob(fuzz_ptr(fuzz), fuzz_len(fuzz), &k1) == 0)
			sshkey_free(k1);
	}
	fuzz_cleanup(fuzz);
}

ಸ್ಥಿರ ಶೂನ್ಯ
sig_fuzz(ಸಂರಚನಾ sshkey *k, ಧ್ರುವ ವರ್ಣ *sig_alg)
{
	ಸಂರಚನಾ fuzz *fuzz;
	u_char *sig, c[] = "some junk to be signed";
	size_t l;
	u_int fuzzers = FUZZ_1_BIT_FLIP | FUZZ_1_BYTE_FLIP | FUZZ_2_BYTE_FLIP |
	    FUZZ_TRUNCATE_START | FUZZ_TRUNCATE_END;

	/* MLDSA44_ED25519 keys are large and slow to fuzz */
	ಯದಿ (test_is_fast() || sshkey_type_plain(k->type) == ಕೀಲಿ_MLDSA44_ED25519)
		fuzzers &= ~FUZZ_2_BYTE_FLIP;
	ಯದಿ (test_is_slow())
		fuzzers |= FUZZ_2_BIT_FLIP;

	ASSERT_INT_EQ(sshkey_sign(k, &sig, &l, c, ಪರಿಮಾಣ(c),
	    sig_alg, ರಿಕ್ತ, ರಿಕ್ತ, 0), 0);
	ASSERT_SIZE_T_GT(l, 0);
	fuzz = fuzz_begin(fuzzers, sig, l);
	ASSERT_INT_EQ(sshkey_verify(k, sig, l, c, ಪರಿಮಾಣ(c), ರಿಕ್ತ, 0, ರಿಕ್ತ), 0);
	ಮುಕ್ತ(sig);
	TEST_ONERROR(onerror, fuzz);
	ಪ್ರತಿ(; !fuzz_done(fuzz); fuzz_next(fuzz)) {
		/* Ensure 1-bit difference at least */
		ಯದಿ (fuzz_matches_original(fuzz))
			ಅನುವರ್ತ;
		ASSERT_INT_NE(sshkey_verify(k, fuzz_ptr(fuzz), fuzz_len(fuzz),
		    c, ಪರಿಮಾಣ(c), ರಿಕ್ತ, 0, ರಿಕ್ತ), 0);
	}
	fuzz_cleanup(fuzz);
}

#define ಅಂಕೆ_FAST_BASE64_TESTS	1024

ಶೂನ್ಯ
sshkey_fuzz_tests(ಶೂನ್ಯ)
{
	ಸಂರಚನಾ sshkey *k1;
	ಸಂರಚನಾ sshbuf *buf, *fuzzed;
	ಸಂರಚನಾ fuzz *fuzz;
	ಪೂರ್ಣಾಙ್ಕ r, i;

#ifdef WITH_OPENSSL
	TEST_START("fuzz RSA private");
	buf = load_file("rsa_1");
	fuzz = fuzz_begin(FUZZ_BASE64, sshbuf_mutable_ptr(buf),
	    sshbuf_len(buf));
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, ರಿಕ್ತ), 0);
	sshkey_free(k1);
	sshbuf_free(buf);
	ASSERT_PTR_NE(fuzzed = sshbuf_new(), ರಿಕ್ತ);
	TEST_ONERROR(onerror, fuzz);
	ಪ್ರತಿ(i = 0; !fuzz_done(fuzz); i++, fuzz_next(fuzz)) {
		r = sshbuf_put(fuzzed, fuzz_ptr(fuzz), fuzz_len(fuzz));
		ASSERT_INT_EQ(r, 0);
		ಯದಿ (sshkey_parse_private_fileblob(fuzzed, "", &k1, ರಿಕ್ತ) == 0)
			sshkey_free(k1);
		sshbuf_reset(fuzzed);
		ಯದಿ (test_is_fast() && i >= ಅಂಕೆ_FAST_BASE64_TESTS)
			ಭಙ್ಗ;
	}
	sshbuf_free(fuzzed);
	fuzz_cleanup(fuzz);
	TEST_DONE();

	TEST_START("fuzz RSA new-format private");
	buf = load_file("rsa_n");
	fuzz = fuzz_begin(FUZZ_BASE64, sshbuf_mutable_ptr(buf),
	    sshbuf_len(buf));
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, ರಿಕ್ತ), 0);
	sshkey_free(k1);
	sshbuf_free(buf);
	ASSERT_PTR_NE(fuzzed = sshbuf_new(), ರಿಕ್ತ);
	TEST_ONERROR(onerror, fuzz);
	ಪ್ರತಿ(i = 0; !fuzz_done(fuzz); i++, fuzz_next(fuzz)) {
		r = sshbuf_put(fuzzed, fuzz_ptr(fuzz), fuzz_len(fuzz));
		ASSERT_INT_EQ(r, 0);
		ಯದಿ (sshkey_parse_private_fileblob(fuzzed, "", &k1, ರಿಕ್ತ) == 0)
			sshkey_free(k1);
		sshbuf_reset(fuzzed);
		ಯದಿ (test_is_fast() && i >= ಅಂಕೆ_FAST_BASE64_TESTS)
			ಭಙ್ಗ;
	}
	sshbuf_free(fuzzed);
	fuzz_cleanup(fuzz);
	TEST_DONE();


	TEST_START("fuzz ECDSA private");
	buf = load_file("ecdsa_1");
	fuzz = fuzz_begin(FUZZ_BASE64, sshbuf_mutable_ptr(buf),
	    sshbuf_len(buf));
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, ರಿಕ್ತ), 0);
	sshkey_free(k1);
	sshbuf_free(buf);
	ASSERT_PTR_NE(fuzzed = sshbuf_new(), ರಿಕ್ತ);
	TEST_ONERROR(onerror, fuzz);
	ಪ್ರತಿ(i = 0; !fuzz_done(fuzz); i++, fuzz_next(fuzz)) {
		r = sshbuf_put(fuzzed, fuzz_ptr(fuzz), fuzz_len(fuzz));
		ASSERT_INT_EQ(r, 0);
		ಯದಿ (sshkey_parse_private_fileblob(fuzzed, "", &k1, ರಿಕ್ತ) == 0)
			sshkey_free(k1);
		sshbuf_reset(fuzzed);
		ಯದಿ (test_is_fast() && i >= ಅಂಕೆ_FAST_BASE64_TESTS)
			ಭಙ್ಗ;
	}
	sshbuf_free(fuzzed);
	fuzz_cleanup(fuzz);
	TEST_DONE();

	TEST_START("fuzz ECDSA new-format private");
	buf = load_file("ecdsa_n");
	fuzz = fuzz_begin(FUZZ_BASE64, sshbuf_mutable_ptr(buf),
	    sshbuf_len(buf));
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, ರಿಕ್ತ), 0);
	sshkey_free(k1);
	sshbuf_free(buf);
	ASSERT_PTR_NE(fuzzed = sshbuf_new(), ರಿಕ್ತ);
	TEST_ONERROR(onerror, fuzz);
	ಪ್ರತಿ(i = 0; !fuzz_done(fuzz); i++, fuzz_next(fuzz)) {
		r = sshbuf_put(fuzzed, fuzz_ptr(fuzz), fuzz_len(fuzz));
		ASSERT_INT_EQ(r, 0);
		ಯದಿ (sshkey_parse_private_fileblob(fuzzed, "", &k1, ರಿಕ್ತ) == 0)
			sshkey_free(k1);
		sshbuf_reset(fuzzed);
		ಯದಿ (test_is_fast() && i >= ಅಂಕೆ_FAST_BASE64_TESTS)
			ಭಙ್ಗ;
	}
	sshbuf_free(fuzzed);
	fuzz_cleanup(fuzz);
	TEST_DONE();
#endif /* WITH_OPENSSL */

	TEST_START("fuzz Ed25519 private");
	buf = load_file("ed25519_1");
	fuzz = fuzz_begin(FUZZ_BASE64, sshbuf_mutable_ptr(buf),
	    sshbuf_len(buf));
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, ರಿಕ್ತ), 0);
	sshkey_free(k1);
	sshbuf_free(buf);
	ASSERT_PTR_NE(fuzzed = sshbuf_new(), ರಿಕ್ತ);
	TEST_ONERROR(onerror, fuzz);
	ಪ್ರತಿ(i = 0; !fuzz_done(fuzz); i++, fuzz_next(fuzz)) {
		r = sshbuf_put(fuzzed, fuzz_ptr(fuzz), fuzz_len(fuzz));
		ASSERT_INT_EQ(r, 0);
		ಯದಿ (sshkey_parse_private_fileblob(fuzzed, "", &k1, ರಿಕ್ತ) == 0)
			sshkey_free(k1);
		sshbuf_reset(fuzzed);
		ಯದಿ (test_is_fast() && i >= ಅಂಕೆ_FAST_BASE64_TESTS)
			ಭಙ್ಗ;
	}
	sshbuf_free(fuzzed);
	fuzz_cleanup(fuzz);
	TEST_DONE();

	/* MLDSA44-ED25519 are large and slow to fuzz */
	TEST_START("fuzz MLDSA44-ED25519 private");
	buf = load_file("mldsa44_ed25519_1");
	fuzz = fuzz_begin(FUZZ_BASE64, sshbuf_mutable_ptr(buf),
	    sshbuf_len(buf));
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, ರಿಕ್ತ), 0);
	sshkey_free(k1);
	sshbuf_free(buf);
	ASSERT_PTR_NE(fuzzed = sshbuf_new(), ರಿಕ್ತ);
	TEST_ONERROR(onerror, fuzz);
	ಪ್ರತಿ(i = 0; !fuzz_done(fuzz); i++, fuzz_next(fuzz)) {
		r = sshbuf_put(fuzzed, fuzz_ptr(fuzz), fuzz_len(fuzz));
		ASSERT_INT_EQ(r, 0);
		ಯದಿ (sshkey_parse_private_fileblob(fuzzed, "", &k1, ರಿಕ್ತ) == 0)
			sshkey_free(k1);
		sshbuf_reset(fuzzed);
		ಯದಿ (test_is_fast() && i >= ಅಂಕೆ_FAST_BASE64_TESTS)
			ಭಙ್ಗ;
		/* MLDSA44_ED25519 keys are large and slow to fuzz */
		ಯದಿ (!test_is_slow() || i >= ಅಂಕೆ_FAST_BASE64_TESTS)
			ಭಙ್ಗ;
	}
	sshbuf_free(fuzzed);
	fuzz_cleanup(fuzz);
	TEST_DONE();

#ifdef WITH_OPENSSL
	TEST_START("fuzz RSA public");
	buf = load_file("rsa_1");
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, ರಿಕ್ತ), 0);
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
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, ರಿಕ್ತ), 0);
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
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, ರಿಕ್ತ), 0);
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
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, ರಿಕ್ತ), 0);
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
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, ರಿಕ್ತ), 0);
	sshbuf_free(buf);
	sig_fuzz(k1, "ssh-rsa");
	sshkey_free(k1);
	TEST_DONE();

	TEST_START("fuzz RSA SHA256 sig");
	buf = load_file("rsa_1");
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, ರಿಕ್ತ), 0);
	sshbuf_free(buf);
	sig_fuzz(k1, "rsa-sha2-256");
	sshkey_free(k1);
	TEST_DONE();

	TEST_START("fuzz RSA SHA512 sig");
	buf = load_file("rsa_1");
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, ರಿಕ್ತ), 0);
	sshbuf_free(buf);
	sig_fuzz(k1, "rsa-sha2-512");
	sshkey_free(k1);
	TEST_DONE();


	TEST_START("fuzz ECDSA sig");
	buf = load_file("ecdsa_1");
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, ರಿಕ್ತ), 0);
	sshbuf_free(buf);
	sig_fuzz(k1, ರಿಕ್ತ);
	sshkey_free(k1);
	TEST_DONE();
#endif /* WITH_OPENSSL */

	TEST_START("fuzz Ed25519 sig");
	buf = load_file("ed25519_1");
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, ರಿಕ್ತ), 0);
	sshbuf_free(buf);
	sig_fuzz(k1, ರಿಕ್ತ);
	sshkey_free(k1);
	TEST_DONE();

	TEST_START("fuzz MLDSA44-ED25519 sig");
	buf = load_file("mldsa44_ed25519_1");
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, ರಿಕ್ತ), 0);
	sshbuf_free(buf);
	sig_fuzz(k1, ರಿಕ್ತ);
	sshkey_free(k1);
	TEST_DONE();

/* XXX fuzz decoded new-format blobs too */
/* XXX fuzz XMSS too */

}
