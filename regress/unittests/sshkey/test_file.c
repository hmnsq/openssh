/* 	$OpenBSD: test_file.c,v 1.14 2026/06/14 04:08:06 djm Exp $ */
/*
 * Regress test for sshkey.h key management API
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
#पूर्ण_अगर /* WITH_OPENSSL */

#समावेश "../test_helper/test_helper.h"

#समावेश "ssherr.h"
#समावेश "authfile.h"
#समावेश "sshkey.h"
#समावेश "sshbuf.h"
#समावेश "digest.h"

#समावेश "common.h"

व्योम sshkey_file_tests(व्योम);

व्योम
sshkey_file_tests(व्योम)
{
	काष्ठा sshkey *k1, *k2;
	काष्ठा sshbuf *buf, *pw;
#अगर_घोषित WITH_OPENSSL
	BIGNUM *a, *b, *c;
#पूर्ण_अगर
	अक्षर *cp;

	TEST_START("load passphrase");
	pw = load_text_file("pw");
	TEST_DONE();


#अगर_घोषित WITH_OPENSSL
	TEST_START("parse RSA from private");
	buf = load_file("rsa_1");
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, शून्य), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k1, शून्य);
	a = load_bignum("rsa_1.param.n");
	b = load_bignum("rsa_1.param.p");
	c = load_bignum("rsa_1.param.q");
	ASSERT_BIGNUM_EQ(rsa_n(k1), a);
	ASSERT_BIGNUM_EQ(rsa_p(k1), b);
	ASSERT_BIGNUM_EQ(rsa_q(k1), c);
	BN_free(a);
	BN_free(b);
	BN_free(c);
	TEST_DONE();

	TEST_START("parse RSA from private w/ passphrase");
	buf = load_file("rsa_1_pw");
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf,
	    (स्थिर अक्षर *)sshbuf_ptr(pw), &k2, शून्य), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k2, शून्य);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_DONE();

	TEST_START("parse RSA from new-format");
	buf = load_file("rsa_n");
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k2, शून्य), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k2, शून्य);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_DONE();

	TEST_START("parse RSA from new-format w/ passphrase");
	buf = load_file("rsa_n_pw");
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf,
	    (स्थिर अक्षर *)sshbuf_ptr(pw), &k2, शून्य), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k2, शून्य);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_DONE();

	TEST_START("load RSA from public");
	ASSERT_INT_EQ(sshkey_load_public(test_तथ्य_file("rsa_1.pub"), &k2,
	    शून्य), 0);
	ASSERT_PTR_NE(k2, शून्य);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_DONE();

	TEST_START("load RSA cert with SHA1 signature");
	ASSERT_INT_EQ(sshkey_load_cert(test_तथ्य_file("rsa_1_sha1"), &k2), 0);
	ASSERT_PTR_NE(k2, शून्य);
	ASSERT_INT_EQ(k2->type, कुंजी_RSA_CERT);
	ASSERT_INT_EQ(sshkey_equal_public(k1, k2), 1);
	ASSERT_STRING_EQ(k2->cert->signature_type, "ssh-rsa");
	sshkey_free(k2);
	TEST_DONE();

	TEST_START("load RSA cert with SHA512 signature");
	ASSERT_INT_EQ(sshkey_load_cert(test_तथ्य_file("rsa_1_sha512"), &k2), 0);
	ASSERT_PTR_NE(k2, शून्य);
	ASSERT_INT_EQ(k2->type, कुंजी_RSA_CERT);
	ASSERT_INT_EQ(sshkey_equal_public(k1, k2), 1);
	ASSERT_STRING_EQ(k2->cert->signature_type, "rsa-sha2-512");
	sshkey_free(k2);
	TEST_DONE();

	TEST_START("load RSA cert");
	ASSERT_INT_EQ(sshkey_load_cert(test_तथ्य_file("rsa_1"), &k2), 0);
	ASSERT_PTR_NE(k2, शून्य);
	ASSERT_INT_EQ(k2->type, कुंजी_RSA_CERT);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 0);
	ASSERT_INT_EQ(sshkey_equal_public(k1, k2), 1);
	TEST_DONE();

	TEST_START("RSA key hex fingerprint");
	buf = load_text_file("rsa_1.fp");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, शून्य);
	ASSERT_STRING_EQ(cp, (स्थिर अक्षर *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	मुक्त(cp);
	TEST_DONE();

	TEST_START("RSA cert hex fingerprint");
	buf = load_text_file("rsa_1-cert.fp");
	cp = sshkey_fingerprint(k2, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, शून्य);
	ASSERT_STRING_EQ(cp, (स्थिर अक्षर *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	मुक्त(cp);
	sshkey_free(k2);
	TEST_DONE();

	TEST_START("RSA key bubblebabble fingerprint");
	buf = load_text_file("rsa_1.fp.bb");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA1, SSH_FP_BUBBLEBABBLE);
	ASSERT_PTR_NE(cp, शून्य);
	ASSERT_STRING_EQ(cp, (स्थिर अक्षर *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	मुक्त(cp);
	TEST_DONE();

	sshkey_free(k1);


	TEST_START("parse ECDSA from private");
	buf = load_file("ecdsa_1");
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, शून्य), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k1, शून्य);
	buf = load_text_file("ecdsa_1.param.curve");
	ASSERT_STRING_EQ((स्थिर अक्षर *)sshbuf_ptr(buf),
	    OBJ_nid2sn(k1->ecdsa_nid));
	sshbuf_free(buf);
#अगर_अघोषित OPENSSL_IS_BORINGSSL /* lacks EC_POINT_point2bn() */
	a = load_bignum("ecdsa_1.param.priv");
	b = load_bignum("ecdsa_1.param.pub");
	c = EC_POINT_point2bn(EC_कुंजी_get0_group(EVP_PKEY_get0_EC_कुंजी(k1->pkey)),
	    EC_कुंजी_get0_public_कुंजी(EVP_PKEY_get0_EC_कुंजी(k1->pkey)),
	    POINT_CONVERSION_UNCOMPRESSED, शून्य, शून्य);
	ASSERT_PTR_NE(c, शून्य);
	ASSERT_BIGNUM_EQ(
	    EC_कुंजी_get0_private_कुंजी(EVP_PKEY_get0_EC_कुंजी(k1->pkey)), a);
	ASSERT_BIGNUM_EQ(b, c);
	BN_free(a);
	BN_free(b);
	BN_free(c);
#पूर्ण_अगर /* OPENSSL_IS_BORINGSSL */
	TEST_DONE();

	TEST_START("parse ECDSA from private w/ passphrase");
	buf = load_file("ecdsa_1_pw");
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf,
	    (स्थिर अक्षर *)sshbuf_ptr(pw), &k2, शून्य), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k2, शून्य);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_DONE();

	TEST_START("parse ECDSA from new-format");
	buf = load_file("ecdsa_n");
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k2, शून्य), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k2, शून्य);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_DONE();

	TEST_START("parse ECDSA from new-format w/ passphrase");
	buf = load_file("ecdsa_n_pw");
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf,
	    (स्थिर अक्षर *)sshbuf_ptr(pw), &k2, शून्य), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k2, शून्य);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_DONE();

	TEST_START("load ECDSA from public");
	ASSERT_INT_EQ(sshkey_load_public(test_तथ्य_file("ecdsa_1.pub"), &k2,
	    शून्य), 0);
	ASSERT_PTR_NE(k2, शून्य);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_DONE();

	TEST_START("load ECDSA cert");
	ASSERT_INT_EQ(sshkey_load_cert(test_तथ्य_file("ecdsa_1"), &k2), 0);
	ASSERT_PTR_NE(k2, शून्य);
	ASSERT_INT_EQ(k2->type, कुंजी_ECDSA_CERT);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 0);
	ASSERT_INT_EQ(sshkey_equal_public(k1, k2), 1);
	TEST_DONE();

	TEST_START("ECDSA key hex fingerprint");
	buf = load_text_file("ecdsa_1.fp");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, शून्य);
	ASSERT_STRING_EQ(cp, (स्थिर अक्षर *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	मुक्त(cp);
	TEST_DONE();

	TEST_START("ECDSA cert hex fingerprint");
	buf = load_text_file("ecdsa_1-cert.fp");
	cp = sshkey_fingerprint(k2, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, शून्य);
	ASSERT_STRING_EQ(cp, (स्थिर अक्षर *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	मुक्त(cp);
	sshkey_free(k2);
	TEST_DONE();

	TEST_START("ECDSA key bubblebabble fingerprint");
	buf = load_text_file("ecdsa_1.fp.bb");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA1, SSH_FP_BUBBLEBABBLE);
	ASSERT_PTR_NE(cp, शून्य);
	ASSERT_STRING_EQ(cp, (स्थिर अक्षर *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	मुक्त(cp);
	TEST_DONE();

	sshkey_free(k1);
#पूर्ण_अगर /* WITH_OPENSSL */

	TEST_START("parse Ed25519 from private");
	buf = load_file("ed25519_1");
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, शून्य), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k1, शून्य);
	ASSERT_INT_EQ(k1->type, कुंजी_ED25519);
	/* XXX check key contents */
	TEST_DONE();

	TEST_START("parse Ed25519 from private w/ passphrase");
	buf = load_file("ed25519_1_pw");
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf,
	    (स्थिर अक्षर *)sshbuf_ptr(pw), &k2, शून्य), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k2, शून्य);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_DONE();

	TEST_START("load Ed25519 from public");
	ASSERT_INT_EQ(sshkey_load_public(test_तथ्य_file("ed25519_1.pub"), &k2,
	    शून्य), 0);
	ASSERT_PTR_NE(k2, शून्य);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_DONE();

	TEST_START("load Ed25519 cert");
	ASSERT_INT_EQ(sshkey_load_cert(test_तथ्य_file("ed25519_1"), &k2), 0);
	ASSERT_PTR_NE(k2, शून्य);
	ASSERT_INT_EQ(k2->type, कुंजी_ED25519_CERT);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 0);
	ASSERT_INT_EQ(sshkey_equal_public(k1, k2), 1);
	TEST_DONE();

	TEST_START("Ed25519 key hex fingerprint");
	buf = load_text_file("ed25519_1.fp");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, शून्य);
	ASSERT_STRING_EQ(cp, (स्थिर अक्षर *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	मुक्त(cp);
	TEST_DONE();

	TEST_START("Ed25519 cert hex fingerprint");
	buf = load_text_file("ed25519_1-cert.fp");
	cp = sshkey_fingerprint(k2, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, शून्य);
	ASSERT_STRING_EQ(cp, (स्थिर अक्षर *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	मुक्त(cp);
	sshkey_free(k2);
	TEST_DONE();

	TEST_START("Ed25519 key bubblebabble fingerprint");
	buf = load_text_file("ed25519_1.fp.bb");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA1, SSH_FP_BUBBLEBABBLE);
	ASSERT_PTR_NE(cp, शून्य);
	ASSERT_STRING_EQ(cp, (स्थिर अक्षर *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	मुक्त(cp);
	TEST_DONE();

	sshkey_free(k1);

	TEST_START("parse MLDSA44-ED25519 from private");
	buf = load_file("mldsa44_ed25519_1");
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, शून्य), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k1, शून्य);
	ASSERT_INT_EQ(k1->type, कुंजी_MLDSA44_ED25519);
	TEST_DONE();

	TEST_START("parse MLDSA44-ED25519 from private w/ passphrase");
	buf = load_file("mldsa44_ed25519_1_pw");
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf,
	    (स्थिर अक्षर *)sshbuf_ptr(pw), &k2, शून्य), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k2, शून्य);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_DONE();

	TEST_START("load MLDSA44-ED25519 from public");
	ASSERT_INT_EQ(sshkey_load_public(
	    test_तथ्य_file("mldsa44_ed25519_1.pub"), &k2, शून्य), 0);
	ASSERT_PTR_NE(k2, शून्य);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_DONE();

	TEST_START("load MLDSA44-ED25519 cert");
	ASSERT_INT_EQ(sshkey_load_cert(
	    test_तथ्य_file("mldsa44_ed25519_1"), &k2), 0);
	ASSERT_PTR_NE(k2, शून्य);
	ASSERT_INT_EQ(k2->type, कुंजी_MLDSA44_ED25519_CERT);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 0);
	ASSERT_INT_EQ(sshkey_equal_public(k1, k2), 1);
	TEST_DONE();

	TEST_START("MLDSA44-ED25519 key hex fingerprint");
	buf = load_text_file("mldsa44_ed25519_1.fp");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, शून्य);
	ASSERT_STRING_EQ(cp, (स्थिर अक्षर *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	मुक्त(cp);
	TEST_DONE();

	TEST_START("MLDSA44-ED25519 cert hex fingerprint");
	buf = load_text_file("mldsa44_ed25519_1-cert.fp");
	cp = sshkey_fingerprint(k2, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, शून्य);
	ASSERT_STRING_EQ(cp, (स्थिर अक्षर *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	मुक्त(cp);
	sshkey_free(k2);
	TEST_DONE();

	TEST_START("MLDSA44-ED25519 key bubblebabble fingerprint");
	buf = load_text_file("mldsa44_ed25519_1.fp.bb");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA1, SSH_FP_BUBBLEBABBLE);
	ASSERT_PTR_NE(cp, शून्य);
	ASSERT_STRING_EQ(cp, (स्थिर अक्षर *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	मुक्त(cp);
	TEST_DONE();

	sshkey_free(k1);

#अगर_घोषित ENABLE_SK
#अगर defined(WITH_OPENSSL)
	TEST_START("parse ECDSA-SK from private");
	buf = load_file("ecdsa_sk1");
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, शून्य), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k1, शून्य);
	ASSERT_INT_EQ(k1->type, कुंजी_ECDSA_SK);
	TEST_DONE();

	TEST_START("parse ECDSA-SK from private w/ passphrase");
	buf = load_file("ecdsa_sk1_pw");
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf,
	    (स्थिर अक्षर *)sshbuf_ptr(pw), &k2, शून्य), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k2, शून्य);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_DONE();

	TEST_START("load ECDSA-SK from public");
	ASSERT_INT_EQ(sshkey_load_public(test_तथ्य_file("ecdsa_sk1.pub"), &k2,
	    शून्य), 0);
	ASSERT_PTR_NE(k2, शून्य);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_DONE();

	TEST_START("load ECDSA-SK cert");
	ASSERT_INT_EQ(sshkey_load_cert(test_तथ्य_file("ecdsa_sk1"), &k2), 0);
	ASSERT_PTR_NE(k2, शून्य);
	ASSERT_INT_EQ(k2->type, कुंजी_ECDSA_SK_CERT);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 0);
	ASSERT_INT_EQ(sshkey_equal_public(k1, k2), 1);
	TEST_DONE();

	TEST_START("ECDSA-SK key hex fingerprint");
	buf = load_text_file("ecdsa_sk1.fp");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, शून्य);
	ASSERT_STRING_EQ(cp, (स्थिर अक्षर *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	मुक्त(cp);
	TEST_DONE();

	TEST_START("ECDSA-SK cert hex fingerprint");
	buf = load_text_file("ecdsa_sk1-cert.fp");
	cp = sshkey_fingerprint(k2, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, शून्य);
	ASSERT_STRING_EQ(cp, (स्थिर अक्षर *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	मुक्त(cp);
	sshkey_free(k2);
	TEST_DONE();

	TEST_START("ECDSA-SK key bubblebabble fingerprint");
	buf = load_text_file("ecdsa_sk1.fp.bb");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA1, SSH_FP_BUBBLEBABBLE);
	ASSERT_PTR_NE(cp, शून्य);
	ASSERT_STRING_EQ(cp, (स्थिर अक्षर *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	मुक्त(cp);
	TEST_DONE();

	sshkey_free(k1);
#पूर्ण_अगर

	TEST_START("parse Ed25519-SK from private");
	buf = load_file("ed25519_sk1");
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, शून्य), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k1, शून्य);
	ASSERT_INT_EQ(k1->type, कुंजी_ED25519_SK);
	/* XXX check key contents */
	TEST_DONE();

	TEST_START("parse Ed25519-SK from private w/ passphrase");
	buf = load_file("ed25519_sk1_pw");
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf,
	    (स्थिर अक्षर *)sshbuf_ptr(pw), &k2, शून्य), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k2, शून्य);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_DONE();

	TEST_START("load Ed25519-SK from public");
	ASSERT_INT_EQ(sshkey_load_public(test_तथ्य_file("ed25519_sk1.pub"),
	    &k2, शून्य), 0);
	ASSERT_PTR_NE(k2, शून्य);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_DONE();

	TEST_START("load Ed25519-SK cert");
	ASSERT_INT_EQ(sshkey_load_cert(test_तथ्य_file("ed25519_sk1"), &k2), 0);
	ASSERT_PTR_NE(k2, शून्य);
	ASSERT_INT_EQ(k2->type, कुंजी_ED25519_SK_CERT);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 0);
	ASSERT_INT_EQ(sshkey_equal_public(k1, k2), 1);
	TEST_DONE();

	TEST_START("Ed25519-SK key hex fingerprint");
	buf = load_text_file("ed25519_sk1.fp");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, शून्य);
	ASSERT_STRING_EQ(cp, (स्थिर अक्षर *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	मुक्त(cp);
	TEST_DONE();

	TEST_START("Ed25519-SK cert hex fingerprint");
	buf = load_text_file("ed25519_sk1-cert.fp");
	cp = sshkey_fingerprint(k2, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, शून्य);
	ASSERT_STRING_EQ(cp, (स्थिर अक्षर *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	मुक्त(cp);
	sshkey_free(k2);
	TEST_DONE();

	TEST_START("Ed25519-SK key bubblebabble fingerprint");
	buf = load_text_file("ed25519_sk1.fp.bb");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA1, SSH_FP_BUBBLEBABBLE);
	ASSERT_PTR_NE(cp, शून्य);
	ASSERT_STRING_EQ(cp, (स्थिर अक्षर *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	मुक्त(cp);
	TEST_DONE();

	sshkey_free(k1);
#पूर्ण_अगर /* ENABLE_SK */

	sshbuf_free(pw);

}
