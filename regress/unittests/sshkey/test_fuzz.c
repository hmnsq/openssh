/* 	$OpenBSD: test_fuzz.c,v 1.16 2026/06/14 04:08:06 djm Exp $ */
/*
 * Fuzz tests for key parsing
 *
 * Placed in the public domain
 */

#شامل "includes.h"

#شامل <sys/types.h>
#شامل <sys/stat.h>
#شامل <fcntl.h>
#شامل <stdio.h>
#شامل <stdint.h>
#شامل <stdlib.h>
#شامل <string.h>
#شامل <unistd.h>

#اگر_تعریف_شدہ WITH_OPENSSL
#شامل <openssl/bn.h>
#شامل <openssl/ec.h>
#شامل <openssl/rsa.h>
#شامل <openssl/objects.h>
#اگر_ختم

#شامل "../test_helper/test_helper.h"

#شامل "ssherr.h"
#شامل "authfile.h"
#شامل "sshkey.h"
#شامل "sshbuf.h"

#شامل "common.h"

خالی sshkey_fuzz_tests(خالی);

ساکن خالی
onerror(خالی *fuzz)
{
	fprintf(stderr, "Failed during fuzz:\n");
	fuzz_dump((ساخت fuzz *)fuzz);
}

ساکن خالی
عوامی_fuzz(ساخت sshkey *k)
{
	ساخت sshkey *k1;
	ساخت sshbuf *buf;
	ساخت fuzz *fuzz;
	u_int fuzzers = FUZZ_1_ثنائی_ہندسہ_FLIP | FUZZ_1_BYTE_FLIP |
	    FUZZ_TRUNCATE_آغاز | FUZZ_TRUNCATE_انتہا;

	/* MLDSA44_ED25519 keys are large and slow to fuzz */
	اگر (test_is_fast() || sshkey_type_plain(k->type) == کلید_MLDSA44_ED25519)
		fuzzers &= ~FUZZ_1_ثنائی_ہندسہ_FLIP;
	اگر (test_is_slow())
		fuzzers |= FUZZ_2_ثنائی_ہندسہ_FLIP | FUZZ_2_BYTE_FLIP;

	ASSERT_PTR_NE(buf = sshbuf_new(), تہی);
	ASSERT_INT_EQ(sshkey_putb(k, buf), 0);
	fuzz = fuzz_begin(fuzzers, sshbuf_mutable_ptr(buf), sshbuf_len(buf));
	ASSERT_INT_EQ(sshkey_from_blob(sshbuf_ptr(buf), sshbuf_len(buf),
	    &k1), 0);
	sshkey_free(k1);
	sshbuf_free(buf);
	TEST_ONERROR(onerror, fuzz);
	برائے(; !fuzz_مکمل(fuzz); fuzz_اگلا(fuzz)) {
		اگر (sshkey_from_blob(fuzz_ptr(fuzz), fuzz_len(fuzz), &k1) == 0)
			sshkey_free(k1);
	}
	fuzz_cleanup(fuzz);
}

ساکن خالی
sig_fuzz(ساخت sshkey *k, ثابت حرف *sig_alg)
{
	ساخت fuzz *fuzz;
	u_char *sig, c[] = "some junk to be signed";
	سائز_t l;
	u_int fuzzers = FUZZ_1_ثنائی_ہندسہ_FLIP | FUZZ_1_BYTE_FLIP | FUZZ_2_BYTE_FLIP |
	    FUZZ_TRUNCATE_آغاز | FUZZ_TRUNCATE_انتہا;

	/* MLDSA44_ED25519 keys are large and slow to fuzz */
	اگر (test_is_fast() || sshkey_type_plain(k->type) == کلید_MLDSA44_ED25519)
		fuzzers &= ~FUZZ_2_BYTE_FLIP;
	اگر (test_is_slow())
		fuzzers |= FUZZ_2_ثنائی_ہندسہ_FLIP;

	ASSERT_INT_EQ(sshkey_sign(k, &sig, &l, c, حجم(c),
	    sig_alg, تہی, تہی, 0), 0);
	ASSERT_سائز_T_GT(l, 0);
	fuzz = fuzz_begin(fuzzers, sig, l);
	ASSERT_INT_EQ(sshkey_verify(k, sig, l, c, حجم(c), تہی, 0, تہی), 0);
	آزاد(sig);
	TEST_ONERROR(onerror, fuzz);
	برائے(; !fuzz_مکمل(fuzz); fuzz_اگلا(fuzz)) {
		/* Ensure 1-bit difference at least */
		اگر (fuzz_matches_original(fuzz))
			جاری;
		ASSERT_INT_NE(sshkey_verify(k, fuzz_ptr(fuzz), fuzz_len(fuzz),
		    c, حجم(c), تہی, 0, تہی), 0);
	}
	fuzz_cleanup(fuzz);
}

#تعریف_کرو عدد_FAST_BASE64_TESTS	1024

خالی
sshkey_fuzz_tests(خالی)
{
	ساخت sshkey *k1;
	ساخت sshbuf *buf, *fuzzed;
	ساخت fuzz *fuzz;
	صحیح r, i;

#اگر_تعریف_شدہ WITH_OPENSSL
	TEST_آغاز("fuzz RSA private");
	buf = بھرو_file("rsa_1");
	fuzz = fuzz_begin(FUZZ_BASE64, sshbuf_mutable_ptr(buf),
	    sshbuf_len(buf));
	ASSERT_INT_EQ(sshkey_parse_نجی_fileblob(buf, "", &k1, تہی), 0);
	sshkey_free(k1);
	sshbuf_free(buf);
	ASSERT_PTR_NE(fuzzed = sshbuf_new(), تہی);
	TEST_ONERROR(onerror, fuzz);
	برائے(i = 0; !fuzz_مکمل(fuzz); i++, fuzz_اگلا(fuzz)) {
		r = sshbuf_put(fuzzed, fuzz_ptr(fuzz), fuzz_len(fuzz));
		ASSERT_INT_EQ(r, 0);
		اگر (sshkey_parse_نجی_fileblob(fuzzed, "", &k1, تہی) == 0)
			sshkey_free(k1);
		sshbuf_reset(fuzzed);
		اگر (test_is_fast() && i >= عدد_FAST_BASE64_TESTS)
			توڑو;
	}
	sshbuf_free(fuzzed);
	fuzz_cleanup(fuzz);
	TEST_مکمل();

	TEST_آغاز("fuzz RSA new-format private");
	buf = بھرو_file("rsa_n");
	fuzz = fuzz_begin(FUZZ_BASE64, sshbuf_mutable_ptr(buf),
	    sshbuf_len(buf));
	ASSERT_INT_EQ(sshkey_parse_نجی_fileblob(buf, "", &k1, تہی), 0);
	sshkey_free(k1);
	sshbuf_free(buf);
	ASSERT_PTR_NE(fuzzed = sshbuf_new(), تہی);
	TEST_ONERROR(onerror, fuzz);
	برائے(i = 0; !fuzz_مکمل(fuzz); i++, fuzz_اگلا(fuzz)) {
		r = sshbuf_put(fuzzed, fuzz_ptr(fuzz), fuzz_len(fuzz));
		ASSERT_INT_EQ(r, 0);
		اگر (sshkey_parse_نجی_fileblob(fuzzed, "", &k1, تہی) == 0)
			sshkey_free(k1);
		sshbuf_reset(fuzzed);
		اگر (test_is_fast() && i >= عدد_FAST_BASE64_TESTS)
			توڑو;
	}
	sshbuf_free(fuzzed);
	fuzz_cleanup(fuzz);
	TEST_مکمل();


	TEST_آغاز("fuzz ECDSA private");
	buf = بھرو_file("ecdsa_1");
	fuzz = fuzz_begin(FUZZ_BASE64, sshbuf_mutable_ptr(buf),
	    sshbuf_len(buf));
	ASSERT_INT_EQ(sshkey_parse_نجی_fileblob(buf, "", &k1, تہی), 0);
	sshkey_free(k1);
	sshbuf_free(buf);
	ASSERT_PTR_NE(fuzzed = sshbuf_new(), تہی);
	TEST_ONERROR(onerror, fuzz);
	برائے(i = 0; !fuzz_مکمل(fuzz); i++, fuzz_اگلا(fuzz)) {
		r = sshbuf_put(fuzzed, fuzz_ptr(fuzz), fuzz_len(fuzz));
		ASSERT_INT_EQ(r, 0);
		اگر (sshkey_parse_نجی_fileblob(fuzzed, "", &k1, تہی) == 0)
			sshkey_free(k1);
		sshbuf_reset(fuzzed);
		اگر (test_is_fast() && i >= عدد_FAST_BASE64_TESTS)
			توڑو;
	}
	sshbuf_free(fuzzed);
	fuzz_cleanup(fuzz);
	TEST_مکمل();

	TEST_آغاز("fuzz ECDSA new-format private");
	buf = بھرو_file("ecdsa_n");
	fuzz = fuzz_begin(FUZZ_BASE64, sshbuf_mutable_ptr(buf),
	    sshbuf_len(buf));
	ASSERT_INT_EQ(sshkey_parse_نجی_fileblob(buf, "", &k1, تہی), 0);
	sshkey_free(k1);
	sshbuf_free(buf);
	ASSERT_PTR_NE(fuzzed = sshbuf_new(), تہی);
	TEST_ONERROR(onerror, fuzz);
	برائے(i = 0; !fuzz_مکمل(fuzz); i++, fuzz_اگلا(fuzz)) {
		r = sshbuf_put(fuzzed, fuzz_ptr(fuzz), fuzz_len(fuzz));
		ASSERT_INT_EQ(r, 0);
		اگر (sshkey_parse_نجی_fileblob(fuzzed, "", &k1, تہی) == 0)
			sshkey_free(k1);
		sshbuf_reset(fuzzed);
		اگر (test_is_fast() && i >= عدد_FAST_BASE64_TESTS)
			توڑو;
	}
	sshbuf_free(fuzzed);
	fuzz_cleanup(fuzz);
	TEST_مکمل();
#اگر_ختم /* WITH_OPENSSL */

	TEST_آغاز("fuzz Ed25519 private");
	buf = بھرو_file("ed25519_1");
	fuzz = fuzz_begin(FUZZ_BASE64, sshbuf_mutable_ptr(buf),
	    sshbuf_len(buf));
	ASSERT_INT_EQ(sshkey_parse_نجی_fileblob(buf, "", &k1, تہی), 0);
	sshkey_free(k1);
	sshbuf_free(buf);
	ASSERT_PTR_NE(fuzzed = sshbuf_new(), تہی);
	TEST_ONERROR(onerror, fuzz);
	برائے(i = 0; !fuzz_مکمل(fuzz); i++, fuzz_اگلا(fuzz)) {
		r = sshbuf_put(fuzzed, fuzz_ptr(fuzz), fuzz_len(fuzz));
		ASSERT_INT_EQ(r, 0);
		اگر (sshkey_parse_نجی_fileblob(fuzzed, "", &k1, تہی) == 0)
			sshkey_free(k1);
		sshbuf_reset(fuzzed);
		اگر (test_is_fast() && i >= عدد_FAST_BASE64_TESTS)
			توڑو;
	}
	sshbuf_free(fuzzed);
	fuzz_cleanup(fuzz);
	TEST_مکمل();

	/* MLDSA44-ED25519 are large and slow to fuzz */
	TEST_آغاز("fuzz MLDSA44-ED25519 private");
	buf = بھرو_file("mldsa44_ed25519_1");
	fuzz = fuzz_begin(FUZZ_BASE64, sshbuf_mutable_ptr(buf),
	    sshbuf_len(buf));
	ASSERT_INT_EQ(sshkey_parse_نجی_fileblob(buf, "", &k1, تہی), 0);
	sshkey_free(k1);
	sshbuf_free(buf);
	ASSERT_PTR_NE(fuzzed = sshbuf_new(), تہی);
	TEST_ONERROR(onerror, fuzz);
	برائے(i = 0; !fuzz_مکمل(fuzz); i++, fuzz_اگلا(fuzz)) {
		r = sshbuf_put(fuzzed, fuzz_ptr(fuzz), fuzz_len(fuzz));
		ASSERT_INT_EQ(r, 0);
		اگر (sshkey_parse_نجی_fileblob(fuzzed, "", &k1, تہی) == 0)
			sshkey_free(k1);
		sshbuf_reset(fuzzed);
		اگر (test_is_fast() && i >= عدد_FAST_BASE64_TESTS)
			توڑو;
		/* MLDSA44_ED25519 keys are large and slow to fuzz */
		اگر (!test_is_slow() || i >= عدد_FAST_BASE64_TESTS)
			توڑو;
	}
	sshbuf_free(fuzzed);
	fuzz_cleanup(fuzz);
	TEST_مکمل();

#اگر_تعریف_شدہ WITH_OPENSSL
	TEST_آغاز("fuzz RSA public");
	buf = بھرو_file("rsa_1");
	ASSERT_INT_EQ(sshkey_parse_نجی_fileblob(buf, "", &k1, تہی), 0);
	sshbuf_free(buf);
	عوامی_fuzz(k1);
	sshkey_free(k1);
	TEST_مکمل();

	TEST_آغاز("fuzz RSA cert");
	ASSERT_INT_EQ(sshkey_بھرو_cert(test_ڈیٹا_file("rsa_1"), &k1), 0);
	عوامی_fuzz(k1);
	sshkey_free(k1);
	TEST_مکمل();


	TEST_آغاز("fuzz ECDSA public");
	buf = بھرو_file("ecdsa_1");
	ASSERT_INT_EQ(sshkey_parse_نجی_fileblob(buf, "", &k1, تہی), 0);
	sshbuf_free(buf);
	عوامی_fuzz(k1);
	sshkey_free(k1);
	TEST_مکمل();

	TEST_آغاز("fuzz ECDSA cert");
	ASSERT_INT_EQ(sshkey_بھرو_cert(test_ڈیٹا_file("ecdsa_1"), &k1), 0);
	عوامی_fuzz(k1);
	sshkey_free(k1);
	TEST_مکمل();
#اگر_ختم /* WITH_OPENSSL */

	TEST_آغاز("fuzz Ed25519 public");
	buf = بھرو_file("ed25519_1");
	ASSERT_INT_EQ(sshkey_parse_نجی_fileblob(buf, "", &k1, تہی), 0);
	sshbuf_free(buf);
	عوامی_fuzz(k1);
	sshkey_free(k1);
	TEST_مکمل();

	TEST_آغاز("fuzz Ed25519 cert");
	ASSERT_INT_EQ(sshkey_بھرو_cert(test_ڈیٹا_file("ed25519_1"), &k1), 0);
	عوامی_fuzz(k1);
	sshkey_free(k1);
	TEST_مکمل();

	TEST_آغاز("fuzz MLDSA44-ED25519 public");
	buf = بھرو_file("mldsa44_ed25519_1");
	ASSERT_INT_EQ(sshkey_parse_نجی_fileblob(buf, "", &k1, تہی), 0);
	sshbuf_free(buf);
	عوامی_fuzz(k1);
	sshkey_free(k1);
	TEST_مکمل();

	TEST_آغاز("fuzz MLDSA44-ED25519 cert");
	ASSERT_INT_EQ(sshkey_بھرو_cert(
	    test_ڈیٹا_file("mldsa44_ed25519_1"), &k1), 0);
	عوامی_fuzz(k1);
	sshkey_free(k1);
	TEST_مکمل();

#اگر_تعریف_شدہ WITH_OPENSSL
	TEST_آغاز("fuzz RSA sig");
	buf = بھرو_file("rsa_1");
	ASSERT_INT_EQ(sshkey_parse_نجی_fileblob(buf, "", &k1, تہی), 0);
	sshbuf_free(buf);
	sig_fuzz(k1, "ssh-rsa");
	sshkey_free(k1);
	TEST_مکمل();

	TEST_آغاز("fuzz RSA SHA256 sig");
	buf = بھرو_file("rsa_1");
	ASSERT_INT_EQ(sshkey_parse_نجی_fileblob(buf, "", &k1, تہی), 0);
	sshbuf_free(buf);
	sig_fuzz(k1, "rsa-sha2-256");
	sshkey_free(k1);
	TEST_مکمل();

	TEST_آغاز("fuzz RSA SHA512 sig");
	buf = بھرو_file("rsa_1");
	ASSERT_INT_EQ(sshkey_parse_نجی_fileblob(buf, "", &k1, تہی), 0);
	sshbuf_free(buf);
	sig_fuzz(k1, "rsa-sha2-512");
	sshkey_free(k1);
	TEST_مکمل();


	TEST_آغاز("fuzz ECDSA sig");
	buf = بھرو_file("ecdsa_1");
	ASSERT_INT_EQ(sshkey_parse_نجی_fileblob(buf, "", &k1, تہی), 0);
	sshbuf_free(buf);
	sig_fuzz(k1, تہی);
	sshkey_free(k1);
	TEST_مکمل();
#اگر_ختم /* WITH_OPENSSL */

	TEST_آغاز("fuzz Ed25519 sig");
	buf = بھرو_file("ed25519_1");
	ASSERT_INT_EQ(sshkey_parse_نجی_fileblob(buf, "", &k1, تہی), 0);
	sshbuf_free(buf);
	sig_fuzz(k1, تہی);
	sshkey_free(k1);
	TEST_مکمل();

	TEST_آغاز("fuzz MLDSA44-ED25519 sig");
	buf = بھرو_file("mldsa44_ed25519_1");
	ASSERT_INT_EQ(sshkey_parse_نجی_fileblob(buf, "", &k1, تہی), 0);
	sshbuf_free(buf);
	sig_fuzz(k1, تہی);
	sshkey_free(k1);
	TEST_مکمل();

/* XXX fuzz decoded new-format blobs too */
/* XXX fuzz XMSS too */

}
