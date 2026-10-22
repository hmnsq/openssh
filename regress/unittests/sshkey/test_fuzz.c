/* 	$OpenBSD: test_fuzz.c,v 1.16 2026/06/14 04:08:06 djm Exp $ */
/*
 * Fuzz tests for key parsing
 *
 * Placed in the public domain
 */

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <sys/stat.h>
#అన్తర్భావ <fcntl.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <stdint.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <unistd.h>

#నిర్వచితమైతే WITH_OPENSSL
#అన్తర్భావ <openssl/bn.h>
#అన్తర్భావ <openssl/ec.h>
#అన్తర్భావ <openssl/rsa.h>
#అన్తర్భావ <openssl/objects.h>
#అయితే_ముగింపు

#అన్తర్భావ "../test_helper/test_helper.h"

#అన్తర్భావ "ssherr.h"
#అన్తర్భావ "authfile.h"
#అన్తర్భావ "sshkey.h"
#అన్తర్భావ "sshbuf.h"

#అన్తర్భావ "common.h"

శూన్య sshkey_fuzz_tests(శూన్య);

స్థిర శూన్య
onerror(శూన్య *fuzz)
{
	fprintf(stderr, "Failed during fuzz:\n");
	fuzz_dump((నిర్మాణం fuzz *)fuzz);
}

స్థిర శూన్య
ప్రజా_fuzz(నిర్మాణం sshkey *k)
{
	నిర్మాణం sshkey *k1;
	నిర్మాణం sshbuf *buf;
	నిర్మాణం fuzz *fuzz;
	u_int fuzzers = FUZZ_1_బిట్టు_FLIP | FUZZ_1_BYTE_FLIP |
	    FUZZ_TRUNCATE_ప్రారంభం | FUZZ_TRUNCATE_చివర;

	/* MLDSA44_ED25519 keys are large and slow to fuzz */
	ఒకవేళ (test_is_fast() || sshkey_type_plain(k->type) == కీలకం_MLDSA44_ED25519)
		fuzzers &= ~FUZZ_1_బిట్టు_FLIP;
	ఒకవేళ (test_is_slow())
		fuzzers |= FUZZ_2_బిట్టు_FLIP | FUZZ_2_BYTE_FLIP;

	ASSERT_PTR_NE(buf = sshbuf_new(), ఖాళీ);
	ASSERT_INT_EQ(sshkey_putb(k, buf), 0);
	fuzz = fuzz_begin(fuzzers, sshbuf_mutable_ptr(buf), sshbuf_len(buf));
	ASSERT_INT_EQ(sshkey_from_blob(sshbuf_ptr(buf), sshbuf_len(buf),
	    &k1), 0);
	sshkey_free(k1);
	sshbuf_free(buf);
	TEST_ONERROR(onerror, fuzz);
	కొరకు(; !fuzz_పూర్తి(fuzz); fuzz_తదుపరి(fuzz)) {
		ఒకవేళ (sshkey_from_blob(fuzz_ptr(fuzz), fuzz_len(fuzz), &k1) == 0)
			sshkey_free(k1);
	}
	fuzz_cleanup(fuzz);
}

స్థిర శూన్య
sig_fuzz(నిర్మాణం sshkey *k, స్థిరరాశి అక్షరం *sig_alg)
{
	నిర్మాణం fuzz *fuzz;
	u_char *sig, c[] = "some junk to be signed";
	కొలత_t l;
	u_int fuzzers = FUZZ_1_బిట్టు_FLIP | FUZZ_1_BYTE_FLIP | FUZZ_2_BYTE_FLIP |
	    FUZZ_TRUNCATE_ప్రారంభం | FUZZ_TRUNCATE_చివర;

	/* MLDSA44_ED25519 keys are large and slow to fuzz */
	ఒకవేళ (test_is_fast() || sshkey_type_plain(k->type) == కీలకం_MLDSA44_ED25519)
		fuzzers &= ~FUZZ_2_BYTE_FLIP;
	ఒకవేళ (test_is_slow())
		fuzzers |= FUZZ_2_బిట్టు_FLIP;

	ASSERT_INT_EQ(sshkey_sign(k, &sig, &l, c, పరిమాణం(c),
	    sig_alg, ఖాళీ, ఖాళీ, 0), 0);
	ASSERT_కొలత_T_GT(l, 0);
	fuzz = fuzz_begin(fuzzers, sig, l);
	ASSERT_INT_EQ(sshkey_verify(k, sig, l, c, పరిమాణం(c), ఖాళీ, 0, ఖాళీ), 0);
	విడుదల(sig);
	TEST_ONERROR(onerror, fuzz);
	కొరకు(; !fuzz_పూర్తి(fuzz); fuzz_తదుపరి(fuzz)) {
		/* Ensure 1-bit difference at least */
		ఒకవేళ (fuzz_matches_original(fuzz))
			కొనసాగు;
		ASSERT_INT_NE(sshkey_verify(k, fuzz_ptr(fuzz), fuzz_len(fuzz),
		    c, పరిమాణం(c), ఖాళీ, 0, ఖాళీ), 0);
	}
	fuzz_cleanup(fuzz);
}

#నిర్వచించు అంకె_FAST_BASE64_TESTS	1024

శూన్య
sshkey_fuzz_tests(శూన్య)
{
	నిర్మాణం sshkey *k1;
	నిర్మాణం sshbuf *buf, *fuzzed;
	నిర్మాణం fuzz *fuzz;
	పూర్ణాంకం r, i;

#నిర్వచితమైతే WITH_OPENSSL
	TEST_ప్రారంభం("fuzz RSA private");
	buf = ఎక్కించు_file("rsa_1");
	fuzz = fuzz_begin(FUZZ_BASE64, sshbuf_mutable_ptr(buf),
	    sshbuf_len(buf));
	ASSERT_INT_EQ(sshkey_parse_వ్యక్తిగత_fileblob(buf, "", &k1, ఖాళీ), 0);
	sshkey_free(k1);
	sshbuf_free(buf);
	ASSERT_PTR_NE(fuzzed = sshbuf_new(), ఖాళీ);
	TEST_ONERROR(onerror, fuzz);
	కొరకు(i = 0; !fuzz_పూర్తి(fuzz); i++, fuzz_తదుపరి(fuzz)) {
		r = sshbuf_put(fuzzed, fuzz_ptr(fuzz), fuzz_len(fuzz));
		ASSERT_INT_EQ(r, 0);
		ఒకవేళ (sshkey_parse_వ్యక్తిగత_fileblob(fuzzed, "", &k1, ఖాళీ) == 0)
			sshkey_free(k1);
		sshbuf_reset(fuzzed);
		ఒకవేళ (test_is_fast() && i >= అంకె_FAST_BASE64_TESTS)
			ఆపు;
	}
	sshbuf_free(fuzzed);
	fuzz_cleanup(fuzz);
	TEST_పూర్తి();

	TEST_ప్రారంభం("fuzz RSA new-format private");
	buf = ఎక్కించు_file("rsa_n");
	fuzz = fuzz_begin(FUZZ_BASE64, sshbuf_mutable_ptr(buf),
	    sshbuf_len(buf));
	ASSERT_INT_EQ(sshkey_parse_వ్యక్తిగత_fileblob(buf, "", &k1, ఖాళీ), 0);
	sshkey_free(k1);
	sshbuf_free(buf);
	ASSERT_PTR_NE(fuzzed = sshbuf_new(), ఖాళీ);
	TEST_ONERROR(onerror, fuzz);
	కొరకు(i = 0; !fuzz_పూర్తి(fuzz); i++, fuzz_తదుపరి(fuzz)) {
		r = sshbuf_put(fuzzed, fuzz_ptr(fuzz), fuzz_len(fuzz));
		ASSERT_INT_EQ(r, 0);
		ఒకవేళ (sshkey_parse_వ్యక్తిగత_fileblob(fuzzed, "", &k1, ఖాళీ) == 0)
			sshkey_free(k1);
		sshbuf_reset(fuzzed);
		ఒకవేళ (test_is_fast() && i >= అంకె_FAST_BASE64_TESTS)
			ఆపు;
	}
	sshbuf_free(fuzzed);
	fuzz_cleanup(fuzz);
	TEST_పూర్తి();


	TEST_ప్రారంభం("fuzz ECDSA private");
	buf = ఎక్కించు_file("ecdsa_1");
	fuzz = fuzz_begin(FUZZ_BASE64, sshbuf_mutable_ptr(buf),
	    sshbuf_len(buf));
	ASSERT_INT_EQ(sshkey_parse_వ్యక్తిగత_fileblob(buf, "", &k1, ఖాళీ), 0);
	sshkey_free(k1);
	sshbuf_free(buf);
	ASSERT_PTR_NE(fuzzed = sshbuf_new(), ఖాళీ);
	TEST_ONERROR(onerror, fuzz);
	కొరకు(i = 0; !fuzz_పూర్తి(fuzz); i++, fuzz_తదుపరి(fuzz)) {
		r = sshbuf_put(fuzzed, fuzz_ptr(fuzz), fuzz_len(fuzz));
		ASSERT_INT_EQ(r, 0);
		ఒకవేళ (sshkey_parse_వ్యక్తిగత_fileblob(fuzzed, "", &k1, ఖాళీ) == 0)
			sshkey_free(k1);
		sshbuf_reset(fuzzed);
		ఒకవేళ (test_is_fast() && i >= అంకె_FAST_BASE64_TESTS)
			ఆపు;
	}
	sshbuf_free(fuzzed);
	fuzz_cleanup(fuzz);
	TEST_పూర్తి();

	TEST_ప్రారంభం("fuzz ECDSA new-format private");
	buf = ఎక్కించు_file("ecdsa_n");
	fuzz = fuzz_begin(FUZZ_BASE64, sshbuf_mutable_ptr(buf),
	    sshbuf_len(buf));
	ASSERT_INT_EQ(sshkey_parse_వ్యక్తిగత_fileblob(buf, "", &k1, ఖాళీ), 0);
	sshkey_free(k1);
	sshbuf_free(buf);
	ASSERT_PTR_NE(fuzzed = sshbuf_new(), ఖాళీ);
	TEST_ONERROR(onerror, fuzz);
	కొరకు(i = 0; !fuzz_పూర్తి(fuzz); i++, fuzz_తదుపరి(fuzz)) {
		r = sshbuf_put(fuzzed, fuzz_ptr(fuzz), fuzz_len(fuzz));
		ASSERT_INT_EQ(r, 0);
		ఒకవేళ (sshkey_parse_వ్యక్తిగత_fileblob(fuzzed, "", &k1, ఖాళీ) == 0)
			sshkey_free(k1);
		sshbuf_reset(fuzzed);
		ఒకవేళ (test_is_fast() && i >= అంకె_FAST_BASE64_TESTS)
			ఆపు;
	}
	sshbuf_free(fuzzed);
	fuzz_cleanup(fuzz);
	TEST_పూర్తి();
#అయితే_ముగింపు /* WITH_OPENSSL */

	TEST_ప్రారంభం("fuzz Ed25519 private");
	buf = ఎక్కించు_file("ed25519_1");
	fuzz = fuzz_begin(FUZZ_BASE64, sshbuf_mutable_ptr(buf),
	    sshbuf_len(buf));
	ASSERT_INT_EQ(sshkey_parse_వ్యక్తిగత_fileblob(buf, "", &k1, ఖాళీ), 0);
	sshkey_free(k1);
	sshbuf_free(buf);
	ASSERT_PTR_NE(fuzzed = sshbuf_new(), ఖాళీ);
	TEST_ONERROR(onerror, fuzz);
	కొరకు(i = 0; !fuzz_పూర్తి(fuzz); i++, fuzz_తదుపరి(fuzz)) {
		r = sshbuf_put(fuzzed, fuzz_ptr(fuzz), fuzz_len(fuzz));
		ASSERT_INT_EQ(r, 0);
		ఒకవేళ (sshkey_parse_వ్యక్తిగత_fileblob(fuzzed, "", &k1, ఖాళీ) == 0)
			sshkey_free(k1);
		sshbuf_reset(fuzzed);
		ఒకవేళ (test_is_fast() && i >= అంకె_FAST_BASE64_TESTS)
			ఆపు;
	}
	sshbuf_free(fuzzed);
	fuzz_cleanup(fuzz);
	TEST_పూర్తి();

	/* MLDSA44-ED25519 are large and slow to fuzz */
	TEST_ప్రారంభం("fuzz MLDSA44-ED25519 private");
	buf = ఎక్కించు_file("mldsa44_ed25519_1");
	fuzz = fuzz_begin(FUZZ_BASE64, sshbuf_mutable_ptr(buf),
	    sshbuf_len(buf));
	ASSERT_INT_EQ(sshkey_parse_వ్యక్తిగత_fileblob(buf, "", &k1, ఖాళీ), 0);
	sshkey_free(k1);
	sshbuf_free(buf);
	ASSERT_PTR_NE(fuzzed = sshbuf_new(), ఖాళీ);
	TEST_ONERROR(onerror, fuzz);
	కొరకు(i = 0; !fuzz_పూర్తి(fuzz); i++, fuzz_తదుపరి(fuzz)) {
		r = sshbuf_put(fuzzed, fuzz_ptr(fuzz), fuzz_len(fuzz));
		ASSERT_INT_EQ(r, 0);
		ఒకవేళ (sshkey_parse_వ్యక్తిగత_fileblob(fuzzed, "", &k1, ఖాళీ) == 0)
			sshkey_free(k1);
		sshbuf_reset(fuzzed);
		ఒకవేళ (test_is_fast() && i >= అంకె_FAST_BASE64_TESTS)
			ఆపు;
		/* MLDSA44_ED25519 keys are large and slow to fuzz */
		ఒకవేళ (!test_is_slow() || i >= అంకె_FAST_BASE64_TESTS)
			ఆపు;
	}
	sshbuf_free(fuzzed);
	fuzz_cleanup(fuzz);
	TEST_పూర్తి();

#నిర్వచితమైతే WITH_OPENSSL
	TEST_ప్రారంభం("fuzz RSA public");
	buf = ఎక్కించు_file("rsa_1");
	ASSERT_INT_EQ(sshkey_parse_వ్యక్తిగత_fileblob(buf, "", &k1, ఖాళీ), 0);
	sshbuf_free(buf);
	ప్రజా_fuzz(k1);
	sshkey_free(k1);
	TEST_పూర్తి();

	TEST_ప్రారంభం("fuzz RSA cert");
	ASSERT_INT_EQ(sshkey_ఎక్కించు_cert(test_దత్తాంశం_file("rsa_1"), &k1), 0);
	ప్రజా_fuzz(k1);
	sshkey_free(k1);
	TEST_పూర్తి();


	TEST_ప్రారంభం("fuzz ECDSA public");
	buf = ఎక్కించు_file("ecdsa_1");
	ASSERT_INT_EQ(sshkey_parse_వ్యక్తిగత_fileblob(buf, "", &k1, ఖాళీ), 0);
	sshbuf_free(buf);
	ప్రజా_fuzz(k1);
	sshkey_free(k1);
	TEST_పూర్తి();

	TEST_ప్రారంభం("fuzz ECDSA cert");
	ASSERT_INT_EQ(sshkey_ఎక్కించు_cert(test_దత్తాంశం_file("ecdsa_1"), &k1), 0);
	ప్రజా_fuzz(k1);
	sshkey_free(k1);
	TEST_పూర్తి();
#అయితే_ముగింపు /* WITH_OPENSSL */

	TEST_ప్రారంభం("fuzz Ed25519 public");
	buf = ఎక్కించు_file("ed25519_1");
	ASSERT_INT_EQ(sshkey_parse_వ్యక్తిగత_fileblob(buf, "", &k1, ఖాళీ), 0);
	sshbuf_free(buf);
	ప్రజా_fuzz(k1);
	sshkey_free(k1);
	TEST_పూర్తి();

	TEST_ప్రారంభం("fuzz Ed25519 cert");
	ASSERT_INT_EQ(sshkey_ఎక్కించు_cert(test_దత్తాంశం_file("ed25519_1"), &k1), 0);
	ప్రజా_fuzz(k1);
	sshkey_free(k1);
	TEST_పూర్తి();

	TEST_ప్రారంభం("fuzz MLDSA44-ED25519 public");
	buf = ఎక్కించు_file("mldsa44_ed25519_1");
	ASSERT_INT_EQ(sshkey_parse_వ్యక్తిగత_fileblob(buf, "", &k1, ఖాళీ), 0);
	sshbuf_free(buf);
	ప్రజా_fuzz(k1);
	sshkey_free(k1);
	TEST_పూర్తి();

	TEST_ప్రారంభం("fuzz MLDSA44-ED25519 cert");
	ASSERT_INT_EQ(sshkey_ఎక్కించు_cert(
	    test_దత్తాంశం_file("mldsa44_ed25519_1"), &k1), 0);
	ప్రజా_fuzz(k1);
	sshkey_free(k1);
	TEST_పూర్తి();

#నిర్వచితమైతే WITH_OPENSSL
	TEST_ప్రారంభం("fuzz RSA sig");
	buf = ఎక్కించు_file("rsa_1");
	ASSERT_INT_EQ(sshkey_parse_వ్యక్తిగత_fileblob(buf, "", &k1, ఖాళీ), 0);
	sshbuf_free(buf);
	sig_fuzz(k1, "ssh-rsa");
	sshkey_free(k1);
	TEST_పూర్తి();

	TEST_ప్రారంభం("fuzz RSA SHA256 sig");
	buf = ఎక్కించు_file("rsa_1");
	ASSERT_INT_EQ(sshkey_parse_వ్యక్తిగత_fileblob(buf, "", &k1, ఖాళీ), 0);
	sshbuf_free(buf);
	sig_fuzz(k1, "rsa-sha2-256");
	sshkey_free(k1);
	TEST_పూర్తి();

	TEST_ప్రారంభం("fuzz RSA SHA512 sig");
	buf = ఎక్కించు_file("rsa_1");
	ASSERT_INT_EQ(sshkey_parse_వ్యక్తిగత_fileblob(buf, "", &k1, ఖాళీ), 0);
	sshbuf_free(buf);
	sig_fuzz(k1, "rsa-sha2-512");
	sshkey_free(k1);
	TEST_పూర్తి();


	TEST_ప్రారంభం("fuzz ECDSA sig");
	buf = ఎక్కించు_file("ecdsa_1");
	ASSERT_INT_EQ(sshkey_parse_వ్యక్తిగత_fileblob(buf, "", &k1, ఖాళీ), 0);
	sshbuf_free(buf);
	sig_fuzz(k1, ఖాళీ);
	sshkey_free(k1);
	TEST_పూర్తి();
#అయితే_ముగింపు /* WITH_OPENSSL */

	TEST_ప్రారంభం("fuzz Ed25519 sig");
	buf = ఎక్కించు_file("ed25519_1");
	ASSERT_INT_EQ(sshkey_parse_వ్యక్తిగత_fileblob(buf, "", &k1, ఖాళీ), 0);
	sshbuf_free(buf);
	sig_fuzz(k1, ఖాళీ);
	sshkey_free(k1);
	TEST_పూర్తి();

	TEST_ప్రారంభం("fuzz MLDSA44-ED25519 sig");
	buf = ఎక్కించు_file("mldsa44_ed25519_1");
	ASSERT_INT_EQ(sshkey_parse_వ్యక్తిగత_fileblob(buf, "", &k1, ఖాళీ), 0);
	sshbuf_free(buf);
	sig_fuzz(k1, ఖాళీ);
	sshkey_free(k1);
	TEST_పూర్తి();

/* XXX fuzz decoded new-format blobs too */
/* XXX fuzz XMSS too */

}
