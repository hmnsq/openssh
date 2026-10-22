/* 	$OpenBSD: test_fuzz.c,v 1.16 2026/06/14 04:08:06 djm Exp $ */
/*
 * Fuzz tests for key parsing
 *
 * Placed in the public domain
 */

#समावेश "includes.h"

#समावेश <sys/types.h>
#समावेश <sys/stat.h>
#समावेश <fcntl.h>
#समावेश <stdio.h>
#समावेश <stdint.h>
#समावेश <stdlib.h>
#समावेश <string.h>
#समावेश <unistd.h>

#अगर_घोषित WITH_OPENSSL
#समावेश <openssl/bn.h>
#समावेश <openssl/ec.h>
#समावेश <openssl/rsa.h>
#समावेश <openssl/objects.h>
#पूर्ण_अगर

#समावेश "../test_helper/test_helper.h"

#समावेश "ssherr.h"
#समावेश "authfile.h"
#समावेश "sshkey.h"
#समावेश "sshbuf.h"

#समावेश "common.h"

व्योम sshkey_fuzz_tests(व्योम);

अटल व्योम
onerror(व्योम *fuzz)
{
	ख_लिखो(मानक_त्रुटि, "Failed during fuzz:\n");
	fuzz_dump((काष्ठा fuzz *)fuzz);
}

अटल व्योम
public_fuzz(काष्ठा sshkey *k)
{
	काष्ठा sshkey *k1;
	काष्ठा sshbuf *buf;
	काष्ठा fuzz *fuzz;
	u_int fuzzers = FUZZ_1_BIT_FLIP | FUZZ_1_BYTE_FLIP |
	    FUZZ_TRUNCATE_START | FUZZ_TRUNCATE_END;

	/* MLDSA44_ED25519 keys are large and slow to fuzz */
	अगर (test_is_fast() || sshkey_type_plain(k->type) == कुंजी_MLDSA44_ED25519)
		fuzzers &= ~FUZZ_1_BIT_FLIP;
	अगर (test_is_slow())
		fuzzers |= FUZZ_2_BIT_FLIP | FUZZ_2_BYTE_FLIP;

	ASSERT_PTR_NE(buf = sshbuf_new(), शून्य);
	ASSERT_INT_EQ(sshkey_putb(k, buf), 0);
	fuzz = fuzz_begin(fuzzers, sshbuf_mutable_ptr(buf), sshbuf_len(buf));
	ASSERT_INT_EQ(sshkey_from_blob(sshbuf_ptr(buf), sshbuf_len(buf),
	    &k1), 0);
	sshkey_free(k1);
	sshbuf_free(buf);
	TEST_ONERROR(onerror, fuzz);
	क्रम(; !fuzz_done(fuzz); fuzz_अग्र(fuzz)) {
		अगर (sshkey_from_blob(fuzz_ptr(fuzz), fuzz_len(fuzz), &k1) == 0)
			sshkey_free(k1);
	}
	fuzz_cleanup(fuzz);
}

अटल व्योम
sig_fuzz(काष्ठा sshkey *k, स्थिर अक्षर *sig_alg)
{
	काष्ठा fuzz *fuzz;
	u_char *sig, c[] = "some junk to be signed";
	माप_प्रकार l;
	u_int fuzzers = FUZZ_1_BIT_FLIP | FUZZ_1_BYTE_FLIP | FUZZ_2_BYTE_FLIP |
	    FUZZ_TRUNCATE_START | FUZZ_TRUNCATE_END;

	/* MLDSA44_ED25519 keys are large and slow to fuzz */
	अगर (test_is_fast() || sshkey_type_plain(k->type) == कुंजी_MLDSA44_ED25519)
		fuzzers &= ~FUZZ_2_BYTE_FLIP;
	अगर (test_is_slow())
		fuzzers |= FUZZ_2_BIT_FLIP;

	ASSERT_INT_EQ(sshkey_sign(k, &sig, &l, c, माप(c),
	    sig_alg, शून्य, शून्य, 0), 0);
	ASSERT_आकार_T_GT(l, 0);
	fuzz = fuzz_begin(fuzzers, sig, l);
	ASSERT_INT_EQ(sshkey_verify(k, sig, l, c, माप(c), शून्य, 0, शून्य), 0);
	मुक्त(sig);
	TEST_ONERROR(onerror, fuzz);
	क्रम(; !fuzz_done(fuzz); fuzz_अग्र(fuzz)) {
		/* Ensure 1-bit difference at least */
		अगर (fuzz_matches_original(fuzz))
			जारी;
		ASSERT_INT_NE(sshkey_verify(k, fuzz_ptr(fuzz), fuzz_len(fuzz),
		    c, माप(c), शून्य, 0, शून्य), 0);
	}
	fuzz_cleanup(fuzz);
}

#घोषणा अंक_FAST_BASE64_TESTS	1024

व्योम
sshkey_fuzz_tests(व्योम)
{
	काष्ठा sshkey *k1;
	काष्ठा sshbuf *buf, *fuzzed;
	काष्ठा fuzz *fuzz;
	पूर्णांक r, i;

#अगर_घोषित WITH_OPENSSL
	TEST_START("fuzz RSA private");
	buf = load_file("rsa_1");
	fuzz = fuzz_begin(FUZZ_BASE64, sshbuf_mutable_ptr(buf),
	    sshbuf_len(buf));
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, शून्य), 0);
	sshkey_free(k1);
	sshbuf_free(buf);
	ASSERT_PTR_NE(fuzzed = sshbuf_new(), शून्य);
	TEST_ONERROR(onerror, fuzz);
	क्रम(i = 0; !fuzz_done(fuzz); i++, fuzz_अग्र(fuzz)) {
		r = sshbuf_put(fuzzed, fuzz_ptr(fuzz), fuzz_len(fuzz));
		ASSERT_INT_EQ(r, 0);
		अगर (sshkey_parse_private_fileblob(fuzzed, "", &k1, शून्य) == 0)
			sshkey_free(k1);
		sshbuf_reset(fuzzed);
		अगर (test_is_fast() && i >= अंक_FAST_BASE64_TESTS)
			अवरोध;
	}
	sshbuf_free(fuzzed);
	fuzz_cleanup(fuzz);
	TEST_DONE();

	TEST_START("fuzz RSA new-format private");
	buf = load_file("rsa_n");
	fuzz = fuzz_begin(FUZZ_BASE64, sshbuf_mutable_ptr(buf),
	    sshbuf_len(buf));
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, शून्य), 0);
	sshkey_free(k1);
	sshbuf_free(buf);
	ASSERT_PTR_NE(fuzzed = sshbuf_new(), शून्य);
	TEST_ONERROR(onerror, fuzz);
	क्रम(i = 0; !fuzz_done(fuzz); i++, fuzz_अग्र(fuzz)) {
		r = sshbuf_put(fuzzed, fuzz_ptr(fuzz), fuzz_len(fuzz));
		ASSERT_INT_EQ(r, 0);
		अगर (sshkey_parse_private_fileblob(fuzzed, "", &k1, शून्य) == 0)
			sshkey_free(k1);
		sshbuf_reset(fuzzed);
		अगर (test_is_fast() && i >= अंक_FAST_BASE64_TESTS)
			अवरोध;
	}
	sshbuf_free(fuzzed);
	fuzz_cleanup(fuzz);
	TEST_DONE();


	TEST_START("fuzz ECDSA private");
	buf = load_file("ecdsa_1");
	fuzz = fuzz_begin(FUZZ_BASE64, sshbuf_mutable_ptr(buf),
	    sshbuf_len(buf));
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, शून्य), 0);
	sshkey_free(k1);
	sshbuf_free(buf);
	ASSERT_PTR_NE(fuzzed = sshbuf_new(), शून्य);
	TEST_ONERROR(onerror, fuzz);
	क्रम(i = 0; !fuzz_done(fuzz); i++, fuzz_अग्र(fuzz)) {
		r = sshbuf_put(fuzzed, fuzz_ptr(fuzz), fuzz_len(fuzz));
		ASSERT_INT_EQ(r, 0);
		अगर (sshkey_parse_private_fileblob(fuzzed, "", &k1, शून्य) == 0)
			sshkey_free(k1);
		sshbuf_reset(fuzzed);
		अगर (test_is_fast() && i >= अंक_FAST_BASE64_TESTS)
			अवरोध;
	}
	sshbuf_free(fuzzed);
	fuzz_cleanup(fuzz);
	TEST_DONE();

	TEST_START("fuzz ECDSA new-format private");
	buf = load_file("ecdsa_n");
	fuzz = fuzz_begin(FUZZ_BASE64, sshbuf_mutable_ptr(buf),
	    sshbuf_len(buf));
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, शून्य), 0);
	sshkey_free(k1);
	sshbuf_free(buf);
	ASSERT_PTR_NE(fuzzed = sshbuf_new(), शून्य);
	TEST_ONERROR(onerror, fuzz);
	क्रम(i = 0; !fuzz_done(fuzz); i++, fuzz_अग्र(fuzz)) {
		r = sshbuf_put(fuzzed, fuzz_ptr(fuzz), fuzz_len(fuzz));
		ASSERT_INT_EQ(r, 0);
		अगर (sshkey_parse_private_fileblob(fuzzed, "", &k1, शून्य) == 0)
			sshkey_free(k1);
		sshbuf_reset(fuzzed);
		अगर (test_is_fast() && i >= अंक_FAST_BASE64_TESTS)
			अवरोध;
	}
	sshbuf_free(fuzzed);
	fuzz_cleanup(fuzz);
	TEST_DONE();
#पूर्ण_अगर /* WITH_OPENSSL */

	TEST_START("fuzz Ed25519 private");
	buf = load_file("ed25519_1");
	fuzz = fuzz_begin(FUZZ_BASE64, sshbuf_mutable_ptr(buf),
	    sshbuf_len(buf));
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, शून्य), 0);
	sshkey_free(k1);
	sshbuf_free(buf);
	ASSERT_PTR_NE(fuzzed = sshbuf_new(), शून्य);
	TEST_ONERROR(onerror, fuzz);
	क्रम(i = 0; !fuzz_done(fuzz); i++, fuzz_अग्र(fuzz)) {
		r = sshbuf_put(fuzzed, fuzz_ptr(fuzz), fuzz_len(fuzz));
		ASSERT_INT_EQ(r, 0);
		अगर (sshkey_parse_private_fileblob(fuzzed, "", &k1, शून्य) == 0)
			sshkey_free(k1);
		sshbuf_reset(fuzzed);
		अगर (test_is_fast() && i >= अंक_FAST_BASE64_TESTS)
			अवरोध;
	}
	sshbuf_free(fuzzed);
	fuzz_cleanup(fuzz);
	TEST_DONE();

	/* MLDSA44-ED25519 are large and slow to fuzz */
	TEST_START("fuzz MLDSA44-ED25519 private");
	buf = load_file("mldsa44_ed25519_1");
	fuzz = fuzz_begin(FUZZ_BASE64, sshbuf_mutable_ptr(buf),
	    sshbuf_len(buf));
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, शून्य), 0);
	sshkey_free(k1);
	sshbuf_free(buf);
	ASSERT_PTR_NE(fuzzed = sshbuf_new(), शून्य);
	TEST_ONERROR(onerror, fuzz);
	क्रम(i = 0; !fuzz_done(fuzz); i++, fuzz_अग्र(fuzz)) {
		r = sshbuf_put(fuzzed, fuzz_ptr(fuzz), fuzz_len(fuzz));
		ASSERT_INT_EQ(r, 0);
		अगर (sshkey_parse_private_fileblob(fuzzed, "", &k1, शून्य) == 0)
			sshkey_free(k1);
		sshbuf_reset(fuzzed);
		अगर (test_is_fast() && i >= अंक_FAST_BASE64_TESTS)
			अवरोध;
		/* MLDSA44_ED25519 keys are large and slow to fuzz */
		अगर (!test_is_slow() || i >= अंक_FAST_BASE64_TESTS)
			अवरोध;
	}
	sshbuf_free(fuzzed);
	fuzz_cleanup(fuzz);
	TEST_DONE();

#अगर_घोषित WITH_OPENSSL
	TEST_START("fuzz RSA public");
	buf = load_file("rsa_1");
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, शून्य), 0);
	sshbuf_free(buf);
	public_fuzz(k1);
	sshkey_free(k1);
	TEST_DONE();

	TEST_START("fuzz RSA cert");
	ASSERT_INT_EQ(sshkey_load_cert(test_तथ्य_file("rsa_1"), &k1), 0);
	public_fuzz(k1);
	sshkey_free(k1);
	TEST_DONE();


	TEST_START("fuzz ECDSA public");
	buf = load_file("ecdsa_1");
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, शून्य), 0);
	sshbuf_free(buf);
	public_fuzz(k1);
	sshkey_free(k1);
	TEST_DONE();

	TEST_START("fuzz ECDSA cert");
	ASSERT_INT_EQ(sshkey_load_cert(test_तथ्य_file("ecdsa_1"), &k1), 0);
	public_fuzz(k1);
	sshkey_free(k1);
	TEST_DONE();
#पूर्ण_अगर /* WITH_OPENSSL */

	TEST_START("fuzz Ed25519 public");
	buf = load_file("ed25519_1");
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, शून्य), 0);
	sshbuf_free(buf);
	public_fuzz(k1);
	sshkey_free(k1);
	TEST_DONE();

	TEST_START("fuzz Ed25519 cert");
	ASSERT_INT_EQ(sshkey_load_cert(test_तथ्य_file("ed25519_1"), &k1), 0);
	public_fuzz(k1);
	sshkey_free(k1);
	TEST_DONE();

	TEST_START("fuzz MLDSA44-ED25519 public");
	buf = load_file("mldsa44_ed25519_1");
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, शून्य), 0);
	sshbuf_free(buf);
	public_fuzz(k1);
	sshkey_free(k1);
	TEST_DONE();

	TEST_START("fuzz MLDSA44-ED25519 cert");
	ASSERT_INT_EQ(sshkey_load_cert(
	    test_तथ्य_file("mldsa44_ed25519_1"), &k1), 0);
	public_fuzz(k1);
	sshkey_free(k1);
	TEST_DONE();

#अगर_घोषित WITH_OPENSSL
	TEST_START("fuzz RSA sig");
	buf = load_file("rsa_1");
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, शून्य), 0);
	sshbuf_free(buf);
	sig_fuzz(k1, "ssh-rsa");
	sshkey_free(k1);
	TEST_DONE();

	TEST_START("fuzz RSA SHA256 sig");
	buf = load_file("rsa_1");
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, शून्य), 0);
	sshbuf_free(buf);
	sig_fuzz(k1, "rsa-sha2-256");
	sshkey_free(k1);
	TEST_DONE();

	TEST_START("fuzz RSA SHA512 sig");
	buf = load_file("rsa_1");
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, शून्य), 0);
	sshbuf_free(buf);
	sig_fuzz(k1, "rsa-sha2-512");
	sshkey_free(k1);
	TEST_DONE();


	TEST_START("fuzz ECDSA sig");
	buf = load_file("ecdsa_1");
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, शून्य), 0);
	sshbuf_free(buf);
	sig_fuzz(k1, शून्य);
	sshkey_free(k1);
	TEST_DONE();
#पूर्ण_अगर /* WITH_OPENSSL */

	TEST_START("fuzz Ed25519 sig");
	buf = load_file("ed25519_1");
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, शून्य), 0);
	sshbuf_free(buf);
	sig_fuzz(k1, शून्य);
	sshkey_free(k1);
	TEST_DONE();

	TEST_START("fuzz MLDSA44-ED25519 sig");
	buf = load_file("mldsa44_ed25519_1");
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, शून्य), 0);
	sshbuf_free(buf);
	sig_fuzz(k1, शून्य);
	sshkey_free(k1);
	TEST_DONE();

/* XXX fuzz decoded new-format blobs too */
/* XXX fuzz XMSS too */

}
