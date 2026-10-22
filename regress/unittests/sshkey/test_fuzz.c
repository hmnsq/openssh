/* 	$OpenBSD: test_fuzz.c,v 1.16 2026/06/14 04:08:06 djm Exp $ */
/*
 * Fuzz tests for key parsing
 *
 * Placed in the public domain
 */

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <sys/stat.h>
#અન્તર્ભાવ <fcntl.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <stdint.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <unistd.h>

#ifdef WITH_OPENSSL
#અન્તર્ભાવ <openssl/bn.h>
#અન્તર્ભાવ <openssl/ec.h>
#અન્તર્ભાવ <openssl/rsa.h>
#અન્તર્ભાવ <openssl/objects.h>
#endif

#અન્તર્ભાવ "../test_helper/test_helper.h"

#અન્તર્ભાવ "ssherr.h"
#અન્તર્ભાવ "authfile.h"
#અન્તર્ભાવ "sshkey.h"
#અન્તર્ભાવ "sshbuf.h"

#અન્તર્ભાવ "common.h"

શૂન્ય sshkey_fuzz_tests(શૂન્ય);

સ્થિર શૂન્ય
onerror(શૂન્ય *fuzz)
{
	fprintf(stderr, "Failed during fuzz:\n");
	fuzz_dump((સંરચના fuzz *)fuzz);
}

સ્થિર શૂન્ય
public_fuzz(સંરચના sshkey *k)
{
	સંરચના sshkey *k1;
	સંરચના sshbuf *buf;
	સંરચના fuzz *fuzz;
	u_int fuzzers = FUZZ_1_BIT_FLIP | FUZZ_1_BYTE_FLIP |
	    FUZZ_TRUNCATE_START | FUZZ_TRUNCATE_END;

	/* MLDSA44_ED25519 keys are large and slow to fuzz */
	જો (test_is_fast() || sshkey_type_plain(k->type) == ચાવી_MLDSA44_ED25519)
		fuzzers &= ~FUZZ_1_BIT_FLIP;
	જો (test_is_slow())
		fuzzers |= FUZZ_2_BIT_FLIP | FUZZ_2_BYTE_FLIP;

	ASSERT_PTR_NE(buf = sshbuf_new(), ખાલી);
	ASSERT_INT_EQ(sshkey_putb(k, buf), 0);
	fuzz = fuzz_begin(fuzzers, sshbuf_mutable_ptr(buf), sshbuf_len(buf));
	ASSERT_INT_EQ(sshkey_from_blob(sshbuf_ptr(buf), sshbuf_len(buf),
	    &k1), 0);
	sshkey_free(k1);
	sshbuf_free(buf);
	TEST_ONERROR(onerror, fuzz);
	માટે(; !fuzz_done(fuzz); fuzz_next(fuzz)) {
		જો (sshkey_from_blob(fuzz_ptr(fuzz), fuzz_len(fuzz), &k1) == 0)
			sshkey_free(k1);
	}
	fuzz_cleanup(fuzz);
}

સ્થિર શૂન્ય
sig_fuzz(સંરચના sshkey *k, અચલ અક્ષર *sig_alg)
{
	સંરચના fuzz *fuzz;
	u_char *sig, c[] = "some junk to be signed";
	size_t l;
	u_int fuzzers = FUZZ_1_BIT_FLIP | FUZZ_1_BYTE_FLIP | FUZZ_2_BYTE_FLIP |
	    FUZZ_TRUNCATE_START | FUZZ_TRUNCATE_END;

	/* MLDSA44_ED25519 keys are large and slow to fuzz */
	જો (test_is_fast() || sshkey_type_plain(k->type) == ચાવી_MLDSA44_ED25519)
		fuzzers &= ~FUZZ_2_BYTE_FLIP;
	જો (test_is_slow())
		fuzzers |= FUZZ_2_BIT_FLIP;

	ASSERT_INT_EQ(sshkey_sign(k, &sig, &l, c, કદ(c),
	    sig_alg, ખાલી, ખાલી, 0), 0);
	ASSERT_SIZE_T_GT(l, 0);
	fuzz = fuzz_begin(fuzzers, sig, l);
	ASSERT_INT_EQ(sshkey_verify(k, sig, l, c, કદ(c), ખાલી, 0, ખાલી), 0);
	મુક્ત(sig);
	TEST_ONERROR(onerror, fuzz);
	માટે(; !fuzz_done(fuzz); fuzz_next(fuzz)) {
		/* Ensure 1-bit difference at least */
		જો (fuzz_matches_original(fuzz))
			ચાલુ;
		ASSERT_INT_NE(sshkey_verify(k, fuzz_ptr(fuzz), fuzz_len(fuzz),
		    c, કદ(c), ખાલી, 0, ખાલી), 0);
	}
	fuzz_cleanup(fuzz);
}

#define અંક_FAST_BASE64_TESTS	1024

શૂન્ય
sshkey_fuzz_tests(શૂન્ય)
{
	સંરચના sshkey *k1;
	સંરચના sshbuf *buf, *fuzzed;
	સંરચના fuzz *fuzz;
	પૂર્ણાંક r, i;

#ifdef WITH_OPENSSL
	TEST_START("fuzz RSA private");
	buf = load_file("rsa_1");
	fuzz = fuzz_begin(FUZZ_BASE64, sshbuf_mutable_ptr(buf),
	    sshbuf_len(buf));
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, ખાલી), 0);
	sshkey_free(k1);
	sshbuf_free(buf);
	ASSERT_PTR_NE(fuzzed = sshbuf_new(), ખાલી);
	TEST_ONERROR(onerror, fuzz);
	માટે(i = 0; !fuzz_done(fuzz); i++, fuzz_next(fuzz)) {
		r = sshbuf_put(fuzzed, fuzz_ptr(fuzz), fuzz_len(fuzz));
		ASSERT_INT_EQ(r, 0);
		જો (sshkey_parse_private_fileblob(fuzzed, "", &k1, ખાલી) == 0)
			sshkey_free(k1);
		sshbuf_reset(fuzzed);
		જો (test_is_fast() && i >= અંક_FAST_BASE64_TESTS)
			તોડો;
	}
	sshbuf_free(fuzzed);
	fuzz_cleanup(fuzz);
	TEST_DONE();

	TEST_START("fuzz RSA new-format private");
	buf = load_file("rsa_n");
	fuzz = fuzz_begin(FUZZ_BASE64, sshbuf_mutable_ptr(buf),
	    sshbuf_len(buf));
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, ખાલી), 0);
	sshkey_free(k1);
	sshbuf_free(buf);
	ASSERT_PTR_NE(fuzzed = sshbuf_new(), ખાલી);
	TEST_ONERROR(onerror, fuzz);
	માટે(i = 0; !fuzz_done(fuzz); i++, fuzz_next(fuzz)) {
		r = sshbuf_put(fuzzed, fuzz_ptr(fuzz), fuzz_len(fuzz));
		ASSERT_INT_EQ(r, 0);
		જો (sshkey_parse_private_fileblob(fuzzed, "", &k1, ખાલી) == 0)
			sshkey_free(k1);
		sshbuf_reset(fuzzed);
		જો (test_is_fast() && i >= અંક_FAST_BASE64_TESTS)
			તોડો;
	}
	sshbuf_free(fuzzed);
	fuzz_cleanup(fuzz);
	TEST_DONE();


	TEST_START("fuzz ECDSA private");
	buf = load_file("ecdsa_1");
	fuzz = fuzz_begin(FUZZ_BASE64, sshbuf_mutable_ptr(buf),
	    sshbuf_len(buf));
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, ખાલી), 0);
	sshkey_free(k1);
	sshbuf_free(buf);
	ASSERT_PTR_NE(fuzzed = sshbuf_new(), ખાલી);
	TEST_ONERROR(onerror, fuzz);
	માટે(i = 0; !fuzz_done(fuzz); i++, fuzz_next(fuzz)) {
		r = sshbuf_put(fuzzed, fuzz_ptr(fuzz), fuzz_len(fuzz));
		ASSERT_INT_EQ(r, 0);
		જો (sshkey_parse_private_fileblob(fuzzed, "", &k1, ખાલી) == 0)
			sshkey_free(k1);
		sshbuf_reset(fuzzed);
		જો (test_is_fast() && i >= અંક_FAST_BASE64_TESTS)
			તોડો;
	}
	sshbuf_free(fuzzed);
	fuzz_cleanup(fuzz);
	TEST_DONE();

	TEST_START("fuzz ECDSA new-format private");
	buf = load_file("ecdsa_n");
	fuzz = fuzz_begin(FUZZ_BASE64, sshbuf_mutable_ptr(buf),
	    sshbuf_len(buf));
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, ખાલી), 0);
	sshkey_free(k1);
	sshbuf_free(buf);
	ASSERT_PTR_NE(fuzzed = sshbuf_new(), ખાલી);
	TEST_ONERROR(onerror, fuzz);
	માટે(i = 0; !fuzz_done(fuzz); i++, fuzz_next(fuzz)) {
		r = sshbuf_put(fuzzed, fuzz_ptr(fuzz), fuzz_len(fuzz));
		ASSERT_INT_EQ(r, 0);
		જો (sshkey_parse_private_fileblob(fuzzed, "", &k1, ખાલી) == 0)
			sshkey_free(k1);
		sshbuf_reset(fuzzed);
		જો (test_is_fast() && i >= અંક_FAST_BASE64_TESTS)
			તોડો;
	}
	sshbuf_free(fuzzed);
	fuzz_cleanup(fuzz);
	TEST_DONE();
#endif /* WITH_OPENSSL */

	TEST_START("fuzz Ed25519 private");
	buf = load_file("ed25519_1");
	fuzz = fuzz_begin(FUZZ_BASE64, sshbuf_mutable_ptr(buf),
	    sshbuf_len(buf));
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, ખાલી), 0);
	sshkey_free(k1);
	sshbuf_free(buf);
	ASSERT_PTR_NE(fuzzed = sshbuf_new(), ખાલી);
	TEST_ONERROR(onerror, fuzz);
	માટે(i = 0; !fuzz_done(fuzz); i++, fuzz_next(fuzz)) {
		r = sshbuf_put(fuzzed, fuzz_ptr(fuzz), fuzz_len(fuzz));
		ASSERT_INT_EQ(r, 0);
		જો (sshkey_parse_private_fileblob(fuzzed, "", &k1, ખાલી) == 0)
			sshkey_free(k1);
		sshbuf_reset(fuzzed);
		જો (test_is_fast() && i >= અંક_FAST_BASE64_TESTS)
			તોડો;
	}
	sshbuf_free(fuzzed);
	fuzz_cleanup(fuzz);
	TEST_DONE();

	/* MLDSA44-ED25519 are large and slow to fuzz */
	TEST_START("fuzz MLDSA44-ED25519 private");
	buf = load_file("mldsa44_ed25519_1");
	fuzz = fuzz_begin(FUZZ_BASE64, sshbuf_mutable_ptr(buf),
	    sshbuf_len(buf));
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, ખાલી), 0);
	sshkey_free(k1);
	sshbuf_free(buf);
	ASSERT_PTR_NE(fuzzed = sshbuf_new(), ખાલી);
	TEST_ONERROR(onerror, fuzz);
	માટે(i = 0; !fuzz_done(fuzz); i++, fuzz_next(fuzz)) {
		r = sshbuf_put(fuzzed, fuzz_ptr(fuzz), fuzz_len(fuzz));
		ASSERT_INT_EQ(r, 0);
		જો (sshkey_parse_private_fileblob(fuzzed, "", &k1, ખાલી) == 0)
			sshkey_free(k1);
		sshbuf_reset(fuzzed);
		જો (test_is_fast() && i >= અંક_FAST_BASE64_TESTS)
			તોડો;
		/* MLDSA44_ED25519 keys are large and slow to fuzz */
		જો (!test_is_slow() || i >= અંક_FAST_BASE64_TESTS)
			તોડો;
	}
	sshbuf_free(fuzzed);
	fuzz_cleanup(fuzz);
	TEST_DONE();

#ifdef WITH_OPENSSL
	TEST_START("fuzz RSA public");
	buf = load_file("rsa_1");
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, ખાલી), 0);
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
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, ખાલી), 0);
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
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, ખાલી), 0);
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
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, ખાલી), 0);
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
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, ખાલી), 0);
	sshbuf_free(buf);
	sig_fuzz(k1, "ssh-rsa");
	sshkey_free(k1);
	TEST_DONE();

	TEST_START("fuzz RSA SHA256 sig");
	buf = load_file("rsa_1");
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, ખાલી), 0);
	sshbuf_free(buf);
	sig_fuzz(k1, "rsa-sha2-256");
	sshkey_free(k1);
	TEST_DONE();

	TEST_START("fuzz RSA SHA512 sig");
	buf = load_file("rsa_1");
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, ખાલી), 0);
	sshbuf_free(buf);
	sig_fuzz(k1, "rsa-sha2-512");
	sshkey_free(k1);
	TEST_DONE();


	TEST_START("fuzz ECDSA sig");
	buf = load_file("ecdsa_1");
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, ખાલી), 0);
	sshbuf_free(buf);
	sig_fuzz(k1, ખાલી);
	sshkey_free(k1);
	TEST_DONE();
#endif /* WITH_OPENSSL */

	TEST_START("fuzz Ed25519 sig");
	buf = load_file("ed25519_1");
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, ખાલી), 0);
	sshbuf_free(buf);
	sig_fuzz(k1, ખાલી);
	sshkey_free(k1);
	TEST_DONE();

	TEST_START("fuzz MLDSA44-ED25519 sig");
	buf = load_file("mldsa44_ed25519_1");
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, ખાલી), 0);
	sshbuf_free(buf);
	sig_fuzz(k1, ખાલી);
	sshkey_free(k1);
	TEST_DONE();

/* XXX fuzz decoded new-format blobs too */
/* XXX fuzz XMSS too */

}
