/* 	$OpenBSD: test_fuzz.c,v 1.16 2026/06/14 04:08:06 djm Exp $ */
/*
 * Fuzz tests for key parsing
 *
 * Placed in the public domain
 */

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <sys/stat.h>
#अन्तर्भाव <fcntl.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <stdint.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <unistd.h>

#यदि_परिभाषितम् WITH_OPENSSL
#अन्तर्भाव <openssl/bn.h>
#अन्तर्भाव <openssl/ec.h>
#अन्तर्भाव <openssl/rsa.h>
#अन्तर्भाव <openssl/objects.h>
#यदि_अन्तः

#अन्तर्भाव "../test_helper/test_helper.h"

#अन्तर्भाव "ssherr.h"
#अन्तर्भाव "authfile.h"
#अन्तर्भाव "sshkey.h"
#अन्तर्भाव "sshbuf.h"

#अन्तर्भाव "common.h"

शून्य sshkey_fuzz_tests(शून्य);

स्थिर शून्य
onerror(शून्य *fuzz)
{
	fprintf(stderr, "Failed during fuzz:\n");
	fuzz_dump((संरचना fuzz *)fuzz);
}

स्थिर शून्य
लौकिकम्_fuzz(संरचना sshkey *k)
{
	संरचना sshkey *k1;
	संरचना sshbuf *buf;
	संरचना fuzz *fuzz;
	u_int fuzzers = FUZZ_1_BIT_FLIP | FUZZ_1_BYTE_FLIP |
	    FUZZ_TRUNCATE_START | FUZZ_TRUNCATE_अन्तः;

	/* MLDSA44_ED25519 keys are large and slow to fuzz */
	यदि (test_is_fast() || sshkey_type_plain(k->type) == कुञ्चिका_MLDSA44_ED25519)
		fuzzers &= ~FUZZ_1_BIT_FLIP;
	यदि (test_is_slow())
		fuzzers |= FUZZ_2_BIT_FLIP | FUZZ_2_BYTE_FLIP;

	ASSERT_PTR_NE(buf = sshbuf_new(), रिक्त);
	ASSERT_INT_EQ(sshkey_putb(k, buf), 0);
	fuzz = fuzz_begin(fuzzers, sshbuf_mutable_ptr(buf), sshbuf_len(buf));
	ASSERT_INT_EQ(sshkey_from_blob(sshbuf_ptr(buf), sshbuf_len(buf),
	    &k1), 0);
	sshkey_free(k1);
	sshbuf_free(buf);
	TEST_ONERROR(onerror, fuzz);
	प्रति(; !fuzz_समाप्तम्(fuzz); fuzz_अग्र(fuzz)) {
		यदि (sshkey_from_blob(fuzz_ptr(fuzz), fuzz_len(fuzz), &k1) == 0)
			sshkey_free(k1);
	}
	fuzz_cleanup(fuzz);
}

स्थिर शून्य
sig_fuzz(संरचना sshkey *k, ध्रुव वर्ण *sig_alg)
{
	संरचना fuzz *fuzz;
	u_char *sig, c[] = "some junk to be signed";
	आकार_t l;
	u_int fuzzers = FUZZ_1_BIT_FLIP | FUZZ_1_BYTE_FLIP | FUZZ_2_BYTE_FLIP |
	    FUZZ_TRUNCATE_START | FUZZ_TRUNCATE_अन्तः;

	/* MLDSA44_ED25519 keys are large and slow to fuzz */
	यदि (test_is_fast() || sshkey_type_plain(k->type) == कुञ्चिका_MLDSA44_ED25519)
		fuzzers &= ~FUZZ_2_BYTE_FLIP;
	यदि (test_is_slow())
		fuzzers |= FUZZ_2_BIT_FLIP;

	ASSERT_INT_EQ(sshkey_sign(k, &sig, &l, c, परिमाण(c),
	    sig_alg, रिक्त, रिक्त, 0), 0);
	ASSERT_आकार_T_GT(l, 0);
	fuzz = fuzz_begin(fuzzers, sig, l);
	ASSERT_INT_EQ(sshkey_verify(k, sig, l, c, परिमाण(c), रिक्त, 0, रिक्त), 0);
	मुक्त(sig);
	TEST_ONERROR(onerror, fuzz);
	प्रति(; !fuzz_समाप्तम्(fuzz); fuzz_अग्र(fuzz)) {
		/* Ensure 1-bit difference at least */
		यदि (fuzz_matches_original(fuzz))
			अनुवर्त;
		ASSERT_INT_NE(sshkey_verify(k, fuzz_ptr(fuzz), fuzz_len(fuzz),
		    c, परिमाण(c), रिक्त, 0, रिक्त), 0);
	}
	fuzz_cleanup(fuzz);
}

#परिभाषय अङ्कः_FAST_BASE64_TESTS	1024

शून्य
sshkey_fuzz_tests(शून्य)
{
	संरचना sshkey *k1;
	संरचना sshbuf *buf, *fuzzed;
	संरचना fuzz *fuzz;
	पूर्णाङ्क r, i;

#यदि_परिभाषितम् WITH_OPENSSL
	TEST_START("fuzz RSA private");
	buf = आरोपय_file("rsa_1");
	fuzz = fuzz_begin(FUZZ_BASE64, sshbuf_mutable_ptr(buf),
	    sshbuf_len(buf));
	ASSERT_INT_EQ(sshkey_parse_वैयक्तिकम्_fileblob(buf, "", &k1, रिक्त), 0);
	sshkey_free(k1);
	sshbuf_free(buf);
	ASSERT_PTR_NE(fuzzed = sshbuf_new(), रिक्त);
	TEST_ONERROR(onerror, fuzz);
	प्रति(i = 0; !fuzz_समाप्तम्(fuzz); i++, fuzz_अग्र(fuzz)) {
		r = sshbuf_put(fuzzed, fuzz_ptr(fuzz), fuzz_len(fuzz));
		ASSERT_INT_EQ(r, 0);
		यदि (sshkey_parse_वैयक्तिकम्_fileblob(fuzzed, "", &k1, रिक्त) == 0)
			sshkey_free(k1);
		sshbuf_reset(fuzzed);
		यदि (test_is_fast() && i >= अङ्कः_FAST_BASE64_TESTS)
			भङ्ग;
	}
	sshbuf_free(fuzzed);
	fuzz_cleanup(fuzz);
	TEST_समाप्तम्();

	TEST_START("fuzz RSA new-format private");
	buf = आरोपय_file("rsa_n");
	fuzz = fuzz_begin(FUZZ_BASE64, sshbuf_mutable_ptr(buf),
	    sshbuf_len(buf));
	ASSERT_INT_EQ(sshkey_parse_वैयक्तिकम्_fileblob(buf, "", &k1, रिक्त), 0);
	sshkey_free(k1);
	sshbuf_free(buf);
	ASSERT_PTR_NE(fuzzed = sshbuf_new(), रिक्त);
	TEST_ONERROR(onerror, fuzz);
	प्रति(i = 0; !fuzz_समाप्तम्(fuzz); i++, fuzz_अग्र(fuzz)) {
		r = sshbuf_put(fuzzed, fuzz_ptr(fuzz), fuzz_len(fuzz));
		ASSERT_INT_EQ(r, 0);
		यदि (sshkey_parse_वैयक्तिकम्_fileblob(fuzzed, "", &k1, रिक्त) == 0)
			sshkey_free(k1);
		sshbuf_reset(fuzzed);
		यदि (test_is_fast() && i >= अङ्कः_FAST_BASE64_TESTS)
			भङ्ग;
	}
	sshbuf_free(fuzzed);
	fuzz_cleanup(fuzz);
	TEST_समाप्तम्();


	TEST_START("fuzz ECDSA private");
	buf = आरोपय_file("ecdsa_1");
	fuzz = fuzz_begin(FUZZ_BASE64, sshbuf_mutable_ptr(buf),
	    sshbuf_len(buf));
	ASSERT_INT_EQ(sshkey_parse_वैयक्तिकम्_fileblob(buf, "", &k1, रिक्त), 0);
	sshkey_free(k1);
	sshbuf_free(buf);
	ASSERT_PTR_NE(fuzzed = sshbuf_new(), रिक्त);
	TEST_ONERROR(onerror, fuzz);
	प्रति(i = 0; !fuzz_समाप्तम्(fuzz); i++, fuzz_अग्र(fuzz)) {
		r = sshbuf_put(fuzzed, fuzz_ptr(fuzz), fuzz_len(fuzz));
		ASSERT_INT_EQ(r, 0);
		यदि (sshkey_parse_वैयक्तिकम्_fileblob(fuzzed, "", &k1, रिक्त) == 0)
			sshkey_free(k1);
		sshbuf_reset(fuzzed);
		यदि (test_is_fast() && i >= अङ्कः_FAST_BASE64_TESTS)
			भङ्ग;
	}
	sshbuf_free(fuzzed);
	fuzz_cleanup(fuzz);
	TEST_समाप्तम्();

	TEST_START("fuzz ECDSA new-format private");
	buf = आरोपय_file("ecdsa_n");
	fuzz = fuzz_begin(FUZZ_BASE64, sshbuf_mutable_ptr(buf),
	    sshbuf_len(buf));
	ASSERT_INT_EQ(sshkey_parse_वैयक्तिकम्_fileblob(buf, "", &k1, रिक्त), 0);
	sshkey_free(k1);
	sshbuf_free(buf);
	ASSERT_PTR_NE(fuzzed = sshbuf_new(), रिक्त);
	TEST_ONERROR(onerror, fuzz);
	प्रति(i = 0; !fuzz_समाप्तम्(fuzz); i++, fuzz_अग्र(fuzz)) {
		r = sshbuf_put(fuzzed, fuzz_ptr(fuzz), fuzz_len(fuzz));
		ASSERT_INT_EQ(r, 0);
		यदि (sshkey_parse_वैयक्तिकम्_fileblob(fuzzed, "", &k1, रिक्त) == 0)
			sshkey_free(k1);
		sshbuf_reset(fuzzed);
		यदि (test_is_fast() && i >= अङ्कः_FAST_BASE64_TESTS)
			भङ्ग;
	}
	sshbuf_free(fuzzed);
	fuzz_cleanup(fuzz);
	TEST_समाप्तम्();
#यदि_अन्तः /* WITH_OPENSSL */

	TEST_START("fuzz Ed25519 private");
	buf = आरोपय_file("ed25519_1");
	fuzz = fuzz_begin(FUZZ_BASE64, sshbuf_mutable_ptr(buf),
	    sshbuf_len(buf));
	ASSERT_INT_EQ(sshkey_parse_वैयक्तिकम्_fileblob(buf, "", &k1, रिक्त), 0);
	sshkey_free(k1);
	sshbuf_free(buf);
	ASSERT_PTR_NE(fuzzed = sshbuf_new(), रिक्त);
	TEST_ONERROR(onerror, fuzz);
	प्रति(i = 0; !fuzz_समाप्तम्(fuzz); i++, fuzz_अग्र(fuzz)) {
		r = sshbuf_put(fuzzed, fuzz_ptr(fuzz), fuzz_len(fuzz));
		ASSERT_INT_EQ(r, 0);
		यदि (sshkey_parse_वैयक्तिकम्_fileblob(fuzzed, "", &k1, रिक्त) == 0)
			sshkey_free(k1);
		sshbuf_reset(fuzzed);
		यदि (test_is_fast() && i >= अङ्कः_FAST_BASE64_TESTS)
			भङ्ग;
	}
	sshbuf_free(fuzzed);
	fuzz_cleanup(fuzz);
	TEST_समाप्तम्();

	/* MLDSA44-ED25519 are large and slow to fuzz */
	TEST_START("fuzz MLDSA44-ED25519 private");
	buf = आरोपय_file("mldsa44_ed25519_1");
	fuzz = fuzz_begin(FUZZ_BASE64, sshbuf_mutable_ptr(buf),
	    sshbuf_len(buf));
	ASSERT_INT_EQ(sshkey_parse_वैयक्तिकम्_fileblob(buf, "", &k1, रिक्त), 0);
	sshkey_free(k1);
	sshbuf_free(buf);
	ASSERT_PTR_NE(fuzzed = sshbuf_new(), रिक्त);
	TEST_ONERROR(onerror, fuzz);
	प्रति(i = 0; !fuzz_समाप्तम्(fuzz); i++, fuzz_अग्र(fuzz)) {
		r = sshbuf_put(fuzzed, fuzz_ptr(fuzz), fuzz_len(fuzz));
		ASSERT_INT_EQ(r, 0);
		यदि (sshkey_parse_वैयक्तिकम्_fileblob(fuzzed, "", &k1, रिक्त) == 0)
			sshkey_free(k1);
		sshbuf_reset(fuzzed);
		यदि (test_is_fast() && i >= अङ्कः_FAST_BASE64_TESTS)
			भङ्ग;
		/* MLDSA44_ED25519 keys are large and slow to fuzz */
		यदि (!test_is_slow() || i >= अङ्कः_FAST_BASE64_TESTS)
			भङ्ग;
	}
	sshbuf_free(fuzzed);
	fuzz_cleanup(fuzz);
	TEST_समाप्तम्();

#यदि_परिभाषितम् WITH_OPENSSL
	TEST_START("fuzz RSA public");
	buf = आरोपय_file("rsa_1");
	ASSERT_INT_EQ(sshkey_parse_वैयक्तिकम्_fileblob(buf, "", &k1, रिक्त), 0);
	sshbuf_free(buf);
	लौकिकम्_fuzz(k1);
	sshkey_free(k1);
	TEST_समाप्तम्();

	TEST_START("fuzz RSA cert");
	ASSERT_INT_EQ(sshkey_आरोपय_cert(test_दत्त_file("rsa_1"), &k1), 0);
	लौकिकम्_fuzz(k1);
	sshkey_free(k1);
	TEST_समाप्तम्();


	TEST_START("fuzz ECDSA public");
	buf = आरोपय_file("ecdsa_1");
	ASSERT_INT_EQ(sshkey_parse_वैयक्तिकम्_fileblob(buf, "", &k1, रिक्त), 0);
	sshbuf_free(buf);
	लौकिकम्_fuzz(k1);
	sshkey_free(k1);
	TEST_समाप्तम्();

	TEST_START("fuzz ECDSA cert");
	ASSERT_INT_EQ(sshkey_आरोपय_cert(test_दत्त_file("ecdsa_1"), &k1), 0);
	लौकिकम्_fuzz(k1);
	sshkey_free(k1);
	TEST_समाप्तम्();
#यदि_अन्तः /* WITH_OPENSSL */

	TEST_START("fuzz Ed25519 public");
	buf = आरोपय_file("ed25519_1");
	ASSERT_INT_EQ(sshkey_parse_वैयक्तिकम्_fileblob(buf, "", &k1, रिक्त), 0);
	sshbuf_free(buf);
	लौकिकम्_fuzz(k1);
	sshkey_free(k1);
	TEST_समाप्तम्();

	TEST_START("fuzz Ed25519 cert");
	ASSERT_INT_EQ(sshkey_आरोपय_cert(test_दत्त_file("ed25519_1"), &k1), 0);
	लौकिकम्_fuzz(k1);
	sshkey_free(k1);
	TEST_समाप्तम्();

	TEST_START("fuzz MLDSA44-ED25519 public");
	buf = आरोपय_file("mldsa44_ed25519_1");
	ASSERT_INT_EQ(sshkey_parse_वैयक्तिकम्_fileblob(buf, "", &k1, रिक्त), 0);
	sshbuf_free(buf);
	लौकिकम्_fuzz(k1);
	sshkey_free(k1);
	TEST_समाप्तम्();

	TEST_START("fuzz MLDSA44-ED25519 cert");
	ASSERT_INT_EQ(sshkey_आरोपय_cert(
	    test_दत्त_file("mldsa44_ed25519_1"), &k1), 0);
	लौकिकम्_fuzz(k1);
	sshkey_free(k1);
	TEST_समाप्तम्();

#यदि_परिभाषितम् WITH_OPENSSL
	TEST_START("fuzz RSA sig");
	buf = आरोपय_file("rsa_1");
	ASSERT_INT_EQ(sshkey_parse_वैयक्तिकम्_fileblob(buf, "", &k1, रिक्त), 0);
	sshbuf_free(buf);
	sig_fuzz(k1, "ssh-rsa");
	sshkey_free(k1);
	TEST_समाप्तम्();

	TEST_START("fuzz RSA SHA256 sig");
	buf = आरोपय_file("rsa_1");
	ASSERT_INT_EQ(sshkey_parse_वैयक्तिकम्_fileblob(buf, "", &k1, रिक्त), 0);
	sshbuf_free(buf);
	sig_fuzz(k1, "rsa-sha2-256");
	sshkey_free(k1);
	TEST_समाप्तम्();

	TEST_START("fuzz RSA SHA512 sig");
	buf = आरोपय_file("rsa_1");
	ASSERT_INT_EQ(sshkey_parse_वैयक्तिकम्_fileblob(buf, "", &k1, रिक्त), 0);
	sshbuf_free(buf);
	sig_fuzz(k1, "rsa-sha2-512");
	sshkey_free(k1);
	TEST_समाप्तम्();


	TEST_START("fuzz ECDSA sig");
	buf = आरोपय_file("ecdsa_1");
	ASSERT_INT_EQ(sshkey_parse_वैयक्तिकम्_fileblob(buf, "", &k1, रिक्त), 0);
	sshbuf_free(buf);
	sig_fuzz(k1, रिक्त);
	sshkey_free(k1);
	TEST_समाप्तम्();
#यदि_अन्तः /* WITH_OPENSSL */

	TEST_START("fuzz Ed25519 sig");
	buf = आरोपय_file("ed25519_1");
	ASSERT_INT_EQ(sshkey_parse_वैयक्तिकम्_fileblob(buf, "", &k1, रिक्त), 0);
	sshbuf_free(buf);
	sig_fuzz(k1, रिक्त);
	sshkey_free(k1);
	TEST_समाप्तम्();

	TEST_START("fuzz MLDSA44-ED25519 sig");
	buf = आरोपय_file("mldsa44_ed25519_1");
	ASSERT_INT_EQ(sshkey_parse_वैयक्तिकम्_fileblob(buf, "", &k1, रिक्त), 0);
	sshbuf_free(buf);
	sig_fuzz(k1, रिक्त);
	sshkey_free(k1);
	TEST_समाप्तम्();

/* XXX fuzz decoded new-format blobs too */
/* XXX fuzz XMSS too */

}
