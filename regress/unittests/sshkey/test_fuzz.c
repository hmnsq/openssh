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

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
#ಅನ್ತರ್ಭಾವ <openssl/bn.h>
#ಅನ್ತರ್ಭಾವ <openssl/ec.h>
#ಅನ್ತರ್ಭಾವ <openssl/rsa.h>
#ಅನ್ತರ್ಭಾವ <openssl/objects.h>
#ಆದರೆ_ಅಂತ್ಯ

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
	fuzz_dump((ರಚನೆ fuzz *)fuzz);
}

ಸ್ಥಿರ ಶೂನ್ಯ
ಬಹಿರಂಗ_fuzz(ರಚನೆ sshkey *k)
{
	ರಚನೆ sshkey *k1;
	ರಚನೆ sshbuf *buf;
	ರಚನೆ fuzz *fuzz;
	u_int fuzzers = FUZZ_1_ಬಿಟ್_FLIP | FUZZ_1_BYTE_FLIP |
	    FUZZ_TRUNCATE_ಆರಂಭ | FUZZ_TRUNCATE_ಕೊನೆ;

	/* MLDSA44_ED25519 keys are large and slow to fuzz */
	ಆದರೆ (test_is_fast() || sshkey_type_plain(k->type) == ಕೀಲಿ_MLDSA44_ED25519)
		fuzzers &= ~FUZZ_1_ಬಿಟ್_FLIP;
	ಆದರೆ (test_is_slow())
		fuzzers |= FUZZ_2_ಬಿಟ್_FLIP | FUZZ_2_BYTE_FLIP;

	ASSERT_PTR_NE(buf = sshbuf_new(), ಖಾಲಿ);
	ASSERT_INT_EQ(sshkey_putb(k, buf), 0);
	fuzz = fuzz_begin(fuzzers, sshbuf_mutable_ptr(buf), sshbuf_len(buf));
	ASSERT_INT_EQ(sshkey_from_blob(sshbuf_ptr(buf), sshbuf_len(buf),
	    &k1), 0);
	sshkey_free(k1);
	sshbuf_free(buf);
	TEST_ONERROR(onerror, fuzz);
	ಗಾಗಿ(; !fuzz_ಮುಗಿದ(fuzz); fuzz_ಮುಂದಿನ(fuzz)) {
		ಆದರೆ (sshkey_from_blob(fuzz_ptr(fuzz), fuzz_len(fuzz), &k1) == 0)
			sshkey_free(k1);
	}
	fuzz_cleanup(fuzz);
}

ಸ್ಥಿರ ಶೂನ್ಯ
sig_fuzz(ರಚನೆ sshkey *k, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *sig_alg)
{
	ರಚನೆ fuzz *fuzz;
	u_char *sig, c[] = "some junk to be signed";
	ಗಾತ್ರ_t l;
	u_int fuzzers = FUZZ_1_ಬಿಟ್_FLIP | FUZZ_1_BYTE_FLIP | FUZZ_2_BYTE_FLIP |
	    FUZZ_TRUNCATE_ಆರಂಭ | FUZZ_TRUNCATE_ಕೊನೆ;

	/* MLDSA44_ED25519 keys are large and slow to fuzz */
	ಆದರೆ (test_is_fast() || sshkey_type_plain(k->type) == ಕೀಲಿ_MLDSA44_ED25519)
		fuzzers &= ~FUZZ_2_BYTE_FLIP;
	ಆದರೆ (test_is_slow())
		fuzzers |= FUZZ_2_ಬಿಟ್_FLIP;

	ASSERT_INT_EQ(sshkey_sign(k, &sig, &l, c, ಗಾತ್ರ(c),
	    sig_alg, ಖಾಲಿ, ಖಾಲಿ, 0), 0);
	ASSERT_ಗಾತ್ರ_T_GT(l, 0);
	fuzz = fuzz_begin(fuzzers, sig, l);
	ASSERT_INT_EQ(sshkey_verify(k, sig, l, c, ಗಾತ್ರ(c), ಖಾಲಿ, 0, ಖಾಲಿ), 0);
	ಬಿಡುಗಡೆ(sig);
	TEST_ONERROR(onerror, fuzz);
	ಗಾಗಿ(; !fuzz_ಮುಗಿದ(fuzz); fuzz_ಮುಂದಿನ(fuzz)) {
		/* Ensure 1-bit difference at least */
		ಆದರೆ (fuzz_matches_original(fuzz))
			ಮುಂದುವರಿ;
		ASSERT_INT_NE(sshkey_verify(k, fuzz_ptr(fuzz), fuzz_len(fuzz),
		    c, ಗಾತ್ರ(c), ಖಾಲಿ, 0, ಖಾಲಿ), 0);
	}
	fuzz_cleanup(fuzz);
}

#ವ್ಯಾಖ್ಯಾನಿಸು ಅಂಕೆ_FAST_BASE64_TESTS	1024

ಶೂನ್ಯ
sshkey_fuzz_tests(ಶೂನ್ಯ)
{
	ರಚನೆ sshkey *k1;
	ರಚನೆ sshbuf *buf, *fuzzed;
	ರಚನೆ fuzz *fuzz;
	ಪೂರ್ಣಾಂಕ r, i;

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
	TEST_ಆರಂಭ("fuzz RSA private");
	buf = ತುಂಬು_file("rsa_1");
	fuzz = fuzz_begin(FUZZ_BASE64, sshbuf_mutable_ptr(buf),
	    sshbuf_len(buf));
	ASSERT_INT_EQ(sshkey_parse_ಖಾಸಗಿ_fileblob(buf, "", &k1, ಖಾಲಿ), 0);
	sshkey_free(k1);
	sshbuf_free(buf);
	ASSERT_PTR_NE(fuzzed = sshbuf_new(), ಖಾಲಿ);
	TEST_ONERROR(onerror, fuzz);
	ಗಾಗಿ(i = 0; !fuzz_ಮುಗಿದ(fuzz); i++, fuzz_ಮುಂದಿನ(fuzz)) {
		r = sshbuf_put(fuzzed, fuzz_ptr(fuzz), fuzz_len(fuzz));
		ASSERT_INT_EQ(r, 0);
		ಆದರೆ (sshkey_parse_ಖಾಸಗಿ_fileblob(fuzzed, "", &k1, ಖಾಲಿ) == 0)
			sshkey_free(k1);
		sshbuf_reset(fuzzed);
		ಆದರೆ (test_is_fast() && i >= ಅಂಕೆ_FAST_BASE64_TESTS)
			ನಿಲ್ಲಿಸು;
	}
	sshbuf_free(fuzzed);
	fuzz_cleanup(fuzz);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("fuzz RSA new-format private");
	buf = ತುಂಬು_file("rsa_n");
	fuzz = fuzz_begin(FUZZ_BASE64, sshbuf_mutable_ptr(buf),
	    sshbuf_len(buf));
	ASSERT_INT_EQ(sshkey_parse_ಖಾಸಗಿ_fileblob(buf, "", &k1, ಖಾಲಿ), 0);
	sshkey_free(k1);
	sshbuf_free(buf);
	ASSERT_PTR_NE(fuzzed = sshbuf_new(), ಖಾಲಿ);
	TEST_ONERROR(onerror, fuzz);
	ಗಾಗಿ(i = 0; !fuzz_ಮುಗಿದ(fuzz); i++, fuzz_ಮುಂದಿನ(fuzz)) {
		r = sshbuf_put(fuzzed, fuzz_ptr(fuzz), fuzz_len(fuzz));
		ASSERT_INT_EQ(r, 0);
		ಆದರೆ (sshkey_parse_ಖಾಸಗಿ_fileblob(fuzzed, "", &k1, ಖಾಲಿ) == 0)
			sshkey_free(k1);
		sshbuf_reset(fuzzed);
		ಆದರೆ (test_is_fast() && i >= ಅಂಕೆ_FAST_BASE64_TESTS)
			ನಿಲ್ಲಿಸು;
	}
	sshbuf_free(fuzzed);
	fuzz_cleanup(fuzz);
	TEST_ಮುಗಿದ();


	TEST_ಆರಂಭ("fuzz ECDSA private");
	buf = ತುಂಬು_file("ecdsa_1");
	fuzz = fuzz_begin(FUZZ_BASE64, sshbuf_mutable_ptr(buf),
	    sshbuf_len(buf));
	ASSERT_INT_EQ(sshkey_parse_ಖಾಸಗಿ_fileblob(buf, "", &k1, ಖಾಲಿ), 0);
	sshkey_free(k1);
	sshbuf_free(buf);
	ASSERT_PTR_NE(fuzzed = sshbuf_new(), ಖಾಲಿ);
	TEST_ONERROR(onerror, fuzz);
	ಗಾಗಿ(i = 0; !fuzz_ಮುಗಿದ(fuzz); i++, fuzz_ಮುಂದಿನ(fuzz)) {
		r = sshbuf_put(fuzzed, fuzz_ptr(fuzz), fuzz_len(fuzz));
		ASSERT_INT_EQ(r, 0);
		ಆದರೆ (sshkey_parse_ಖಾಸಗಿ_fileblob(fuzzed, "", &k1, ಖಾಲಿ) == 0)
			sshkey_free(k1);
		sshbuf_reset(fuzzed);
		ಆದರೆ (test_is_fast() && i >= ಅಂಕೆ_FAST_BASE64_TESTS)
			ನಿಲ್ಲಿಸು;
	}
	sshbuf_free(fuzzed);
	fuzz_cleanup(fuzz);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("fuzz ECDSA new-format private");
	buf = ತುಂಬು_file("ecdsa_n");
	fuzz = fuzz_begin(FUZZ_BASE64, sshbuf_mutable_ptr(buf),
	    sshbuf_len(buf));
	ASSERT_INT_EQ(sshkey_parse_ಖಾಸಗಿ_fileblob(buf, "", &k1, ಖಾಲಿ), 0);
	sshkey_free(k1);
	sshbuf_free(buf);
	ASSERT_PTR_NE(fuzzed = sshbuf_new(), ಖಾಲಿ);
	TEST_ONERROR(onerror, fuzz);
	ಗಾಗಿ(i = 0; !fuzz_ಮುಗಿದ(fuzz); i++, fuzz_ಮುಂದಿನ(fuzz)) {
		r = sshbuf_put(fuzzed, fuzz_ptr(fuzz), fuzz_len(fuzz));
		ASSERT_INT_EQ(r, 0);
		ಆದರೆ (sshkey_parse_ಖಾಸಗಿ_fileblob(fuzzed, "", &k1, ಖಾಲಿ) == 0)
			sshkey_free(k1);
		sshbuf_reset(fuzzed);
		ಆದರೆ (test_is_fast() && i >= ಅಂಕೆ_FAST_BASE64_TESTS)
			ನಿಲ್ಲಿಸು;
	}
	sshbuf_free(fuzzed);
	fuzz_cleanup(fuzz);
	TEST_ಮುಗಿದ();
#ಆದರೆ_ಅಂತ್ಯ /* WITH_OPENSSL */

	TEST_ಆರಂಭ("fuzz Ed25519 private");
	buf = ತುಂಬು_file("ed25519_1");
	fuzz = fuzz_begin(FUZZ_BASE64, sshbuf_mutable_ptr(buf),
	    sshbuf_len(buf));
	ASSERT_INT_EQ(sshkey_parse_ಖಾಸಗಿ_fileblob(buf, "", &k1, ಖಾಲಿ), 0);
	sshkey_free(k1);
	sshbuf_free(buf);
	ASSERT_PTR_NE(fuzzed = sshbuf_new(), ಖಾಲಿ);
	TEST_ONERROR(onerror, fuzz);
	ಗಾಗಿ(i = 0; !fuzz_ಮುಗಿದ(fuzz); i++, fuzz_ಮುಂದಿನ(fuzz)) {
		r = sshbuf_put(fuzzed, fuzz_ptr(fuzz), fuzz_len(fuzz));
		ASSERT_INT_EQ(r, 0);
		ಆದರೆ (sshkey_parse_ಖಾಸಗಿ_fileblob(fuzzed, "", &k1, ಖಾಲಿ) == 0)
			sshkey_free(k1);
		sshbuf_reset(fuzzed);
		ಆದರೆ (test_is_fast() && i >= ಅಂಕೆ_FAST_BASE64_TESTS)
			ನಿಲ್ಲಿಸು;
	}
	sshbuf_free(fuzzed);
	fuzz_cleanup(fuzz);
	TEST_ಮುಗಿದ();

	/* MLDSA44-ED25519 are large and slow to fuzz */
	TEST_ಆರಂಭ("fuzz MLDSA44-ED25519 private");
	buf = ತುಂಬು_file("mldsa44_ed25519_1");
	fuzz = fuzz_begin(FUZZ_BASE64, sshbuf_mutable_ptr(buf),
	    sshbuf_len(buf));
	ASSERT_INT_EQ(sshkey_parse_ಖಾಸಗಿ_fileblob(buf, "", &k1, ಖಾಲಿ), 0);
	sshkey_free(k1);
	sshbuf_free(buf);
	ASSERT_PTR_NE(fuzzed = sshbuf_new(), ಖಾಲಿ);
	TEST_ONERROR(onerror, fuzz);
	ಗಾಗಿ(i = 0; !fuzz_ಮುಗಿದ(fuzz); i++, fuzz_ಮುಂದಿನ(fuzz)) {
		r = sshbuf_put(fuzzed, fuzz_ptr(fuzz), fuzz_len(fuzz));
		ASSERT_INT_EQ(r, 0);
		ಆದರೆ (sshkey_parse_ಖಾಸಗಿ_fileblob(fuzzed, "", &k1, ಖಾಲಿ) == 0)
			sshkey_free(k1);
		sshbuf_reset(fuzzed);
		ಆದರೆ (test_is_fast() && i >= ಅಂಕೆ_FAST_BASE64_TESTS)
			ನಿಲ್ಲಿಸು;
		/* MLDSA44_ED25519 keys are large and slow to fuzz */
		ಆದರೆ (!test_is_slow() || i >= ಅಂಕೆ_FAST_BASE64_TESTS)
			ನಿಲ್ಲಿಸು;
	}
	sshbuf_free(fuzzed);
	fuzz_cleanup(fuzz);
	TEST_ಮುಗಿದ();

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
	TEST_ಆರಂಭ("fuzz RSA public");
	buf = ತುಂಬು_file("rsa_1");
	ASSERT_INT_EQ(sshkey_parse_ಖಾಸಗಿ_fileblob(buf, "", &k1, ಖಾಲಿ), 0);
	sshbuf_free(buf);
	ಬಹಿರಂಗ_fuzz(k1);
	sshkey_free(k1);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("fuzz RSA cert");
	ASSERT_INT_EQ(sshkey_ತುಂಬು_cert(test_ದತ್ತಾಂಶ_file("rsa_1"), &k1), 0);
	ಬಹಿರಂಗ_fuzz(k1);
	sshkey_free(k1);
	TEST_ಮುಗಿದ();


	TEST_ಆರಂಭ("fuzz ECDSA public");
	buf = ತುಂಬು_file("ecdsa_1");
	ASSERT_INT_EQ(sshkey_parse_ಖಾಸಗಿ_fileblob(buf, "", &k1, ಖಾಲಿ), 0);
	sshbuf_free(buf);
	ಬಹಿರಂಗ_fuzz(k1);
	sshkey_free(k1);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("fuzz ECDSA cert");
	ASSERT_INT_EQ(sshkey_ತುಂಬು_cert(test_ದತ್ತಾಂಶ_file("ecdsa_1"), &k1), 0);
	ಬಹಿರಂಗ_fuzz(k1);
	sshkey_free(k1);
	TEST_ಮುಗಿದ();
#ಆದರೆ_ಅಂತ್ಯ /* WITH_OPENSSL */

	TEST_ಆರಂಭ("fuzz Ed25519 public");
	buf = ತುಂಬು_file("ed25519_1");
	ASSERT_INT_EQ(sshkey_parse_ಖಾಸಗಿ_fileblob(buf, "", &k1, ಖಾಲಿ), 0);
	sshbuf_free(buf);
	ಬಹಿರಂಗ_fuzz(k1);
	sshkey_free(k1);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("fuzz Ed25519 cert");
	ASSERT_INT_EQ(sshkey_ತುಂಬು_cert(test_ದತ್ತಾಂಶ_file("ed25519_1"), &k1), 0);
	ಬಹಿರಂಗ_fuzz(k1);
	sshkey_free(k1);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("fuzz MLDSA44-ED25519 public");
	buf = ತುಂಬು_file("mldsa44_ed25519_1");
	ASSERT_INT_EQ(sshkey_parse_ಖಾಸಗಿ_fileblob(buf, "", &k1, ಖಾಲಿ), 0);
	sshbuf_free(buf);
	ಬಹಿರಂಗ_fuzz(k1);
	sshkey_free(k1);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("fuzz MLDSA44-ED25519 cert");
	ASSERT_INT_EQ(sshkey_ತುಂಬು_cert(
	    test_ದತ್ತಾಂಶ_file("mldsa44_ed25519_1"), &k1), 0);
	ಬಹಿರಂಗ_fuzz(k1);
	sshkey_free(k1);
	TEST_ಮುಗಿದ();

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
	TEST_ಆರಂಭ("fuzz RSA sig");
	buf = ತುಂಬು_file("rsa_1");
	ASSERT_INT_EQ(sshkey_parse_ಖಾಸಗಿ_fileblob(buf, "", &k1, ಖಾಲಿ), 0);
	sshbuf_free(buf);
	sig_fuzz(k1, "ssh-rsa");
	sshkey_free(k1);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("fuzz RSA SHA256 sig");
	buf = ತುಂಬು_file("rsa_1");
	ASSERT_INT_EQ(sshkey_parse_ಖಾಸಗಿ_fileblob(buf, "", &k1, ಖಾಲಿ), 0);
	sshbuf_free(buf);
	sig_fuzz(k1, "rsa-sha2-256");
	sshkey_free(k1);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("fuzz RSA SHA512 sig");
	buf = ತುಂಬು_file("rsa_1");
	ASSERT_INT_EQ(sshkey_parse_ಖಾಸಗಿ_fileblob(buf, "", &k1, ಖಾಲಿ), 0);
	sshbuf_free(buf);
	sig_fuzz(k1, "rsa-sha2-512");
	sshkey_free(k1);
	TEST_ಮುಗಿದ();


	TEST_ಆರಂಭ("fuzz ECDSA sig");
	buf = ತುಂಬು_file("ecdsa_1");
	ASSERT_INT_EQ(sshkey_parse_ಖಾಸಗಿ_fileblob(buf, "", &k1, ಖಾಲಿ), 0);
	sshbuf_free(buf);
	sig_fuzz(k1, ಖಾಲಿ);
	sshkey_free(k1);
	TEST_ಮುಗಿದ();
#ಆದರೆ_ಅಂತ್ಯ /* WITH_OPENSSL */

	TEST_ಆರಂಭ("fuzz Ed25519 sig");
	buf = ತುಂಬು_file("ed25519_1");
	ASSERT_INT_EQ(sshkey_parse_ಖಾಸಗಿ_fileblob(buf, "", &k1, ಖಾಲಿ), 0);
	sshbuf_free(buf);
	sig_fuzz(k1, ಖಾಲಿ);
	sshkey_free(k1);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("fuzz MLDSA44-ED25519 sig");
	buf = ತುಂಬು_file("mldsa44_ed25519_1");
	ASSERT_INT_EQ(sshkey_parse_ಖಾಸಗಿ_fileblob(buf, "", &k1, ಖಾಲಿ), 0);
	sshbuf_free(buf);
	sig_fuzz(k1, ಖಾಲಿ);
	sshkey_free(k1);
	TEST_ಮುಗಿದ();

/* XXX fuzz decoded new-format blobs too */
/* XXX fuzz XMSS too */

}
