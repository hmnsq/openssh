/* 	$OpenBSD: test_file.c,v 1.14 2026/06/14 04:08:06 djm Exp $ */
/*
 * Regress test for sshkey.h key management API
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
#यदि_अन्तः /* WITH_OPENSSL */

#अन्तर्भाव "../test_helper/test_helper.h"

#अन्तर्भाव "ssherr.h"
#अन्तर्भाव "authfile.h"
#अन्तर्भाव "sshkey.h"
#अन्तर्भाव "sshbuf.h"
#अन्तर्भाव "digest.h"

#अन्तर्भाव "common.h"

शून्य sshkey_file_tests(शून्य);

शून्य
sshkey_file_tests(शून्य)
{
	संरचना sshkey *k1, *k2;
	संरचना sshbuf *buf, *pw;
#यदि_परिभाषितम् WITH_OPENSSL
	BIGNUM *a, *b, *c;
#यदि_अन्तः
	वर्ण *cp;

	TEST_START("load passphrase");
	pw = आरोपय_text_file("pw");
	TEST_समाप्तम्();


#यदि_परिभाषितम् WITH_OPENSSL
	TEST_START("parse RSA from private");
	buf = आरोपय_file("rsa_1");
	ASSERT_INT_EQ(sshkey_parse_वैयक्तिकम्_fileblob(buf, "", &k1, रिक्त), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k1, रिक्त);
	a = आरोपय_bignum("rsa_1.param.n");
	b = आरोपय_bignum("rsa_1.param.p");
	c = आरोपय_bignum("rsa_1.param.q");
	ASSERT_BIGNUM_EQ(rsa_n(k1), a);
	ASSERT_BIGNUM_EQ(rsa_p(k1), b);
	ASSERT_BIGNUM_EQ(rsa_q(k1), c);
	BN_free(a);
	BN_free(b);
	BN_free(c);
	TEST_समाप्तम्();

	TEST_START("parse RSA from private w/ passphrase");
	buf = आरोपय_file("rsa_1_pw");
	ASSERT_INT_EQ(sshkey_parse_वैयक्तिकम्_fileblob(buf,
	    (ध्रुव वर्ण *)sshbuf_ptr(pw), &k2, रिक्त), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k2, रिक्त);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_समाप्तम्();

	TEST_START("parse RSA from new-format");
	buf = आरोपय_file("rsa_n");
	ASSERT_INT_EQ(sshkey_parse_वैयक्तिकम्_fileblob(buf, "", &k2, रिक्त), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k2, रिक्त);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_समाप्तम्();

	TEST_START("parse RSA from new-format w/ passphrase");
	buf = आरोपय_file("rsa_n_pw");
	ASSERT_INT_EQ(sshkey_parse_वैयक्तिकम्_fileblob(buf,
	    (ध्रुव वर्ण *)sshbuf_ptr(pw), &k2, रिक्त), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k2, रिक्त);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_समाप्तम्();

	TEST_START("load RSA from public");
	ASSERT_INT_EQ(sshkey_आरोपय_लौकिकम्(test_दत्त_file("rsa_1.pub"), &k2,
	    रिक्त), 0);
	ASSERT_PTR_NE(k2, रिक्त);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_समाप्तम्();

	TEST_START("load RSA cert with SHA1 signature");
	ASSERT_INT_EQ(sshkey_आरोपय_cert(test_दत्त_file("rsa_1_sha1"), &k2), 0);
	ASSERT_PTR_NE(k2, रिक्त);
	ASSERT_INT_EQ(k2->type, कुञ्चिका_RSA_CERT);
	ASSERT_INT_EQ(sshkey_equal_लौकिकम्(k1, k2), 1);
	ASSERT_STRING_EQ(k2->cert->signature_type, "ssh-rsa");
	sshkey_free(k2);
	TEST_समाप्तम्();

	TEST_START("load RSA cert with SHA512 signature");
	ASSERT_INT_EQ(sshkey_आरोपय_cert(test_दत्त_file("rsa_1_sha512"), &k2), 0);
	ASSERT_PTR_NE(k2, रिक्त);
	ASSERT_INT_EQ(k2->type, कुञ्चिका_RSA_CERT);
	ASSERT_INT_EQ(sshkey_equal_लौकिकम्(k1, k2), 1);
	ASSERT_STRING_EQ(k2->cert->signature_type, "rsa-sha2-512");
	sshkey_free(k2);
	TEST_समाप्तम्();

	TEST_START("load RSA cert");
	ASSERT_INT_EQ(sshkey_आरोपय_cert(test_दत्त_file("rsa_1"), &k2), 0);
	ASSERT_PTR_NE(k2, रिक्त);
	ASSERT_INT_EQ(k2->type, कुञ्चिका_RSA_CERT);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 0);
	ASSERT_INT_EQ(sshkey_equal_लौकिकम्(k1, k2), 1);
	TEST_समाप्तम्();

	TEST_START("RSA key hex fingerprint");
	buf = आरोपय_text_file("rsa_1.fp");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, रिक्त);
	ASSERT_STRING_EQ(cp, (ध्रुव वर्ण *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	मुक्त(cp);
	TEST_समाप्तम्();

	TEST_START("RSA cert hex fingerprint");
	buf = आरोपय_text_file("rsa_1-cert.fp");
	cp = sshkey_fingerprint(k2, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, रिक्त);
	ASSERT_STRING_EQ(cp, (ध्रुव वर्ण *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	मुक्त(cp);
	sshkey_free(k2);
	TEST_समाप्तम्();

	TEST_START("RSA key bubblebabble fingerprint");
	buf = आरोपय_text_file("rsa_1.fp.bb");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA1, SSH_FP_BUBBLEBABBLE);
	ASSERT_PTR_NE(cp, रिक्त);
	ASSERT_STRING_EQ(cp, (ध्रुव वर्ण *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	मुक्त(cp);
	TEST_समाप्तम्();

	sshkey_free(k1);


	TEST_START("parse ECDSA from private");
	buf = आरोपय_file("ecdsa_1");
	ASSERT_INT_EQ(sshkey_parse_वैयक्तिकम्_fileblob(buf, "", &k1, रिक्त), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k1, रिक्त);
	buf = आरोपय_text_file("ecdsa_1.param.curve");
	ASSERT_STRING_EQ((ध्रुव वर्ण *)sshbuf_ptr(buf),
	    OBJ_nid2sn(k1->ecdsa_nid));
	sshbuf_free(buf);
#यदि_अपरिभाषितम् OPENSSL_IS_BORINGSSL /* lacks EC_POINT_point2bn() */
	a = आरोपय_bignum("ecdsa_1.param.priv");
	b = आरोपय_bignum("ecdsa_1.param.pub");
	c = EC_POINT_point2bn(EC_कुञ्चिका_get0_गणः(EVP_PKEY_get0_EC_कुञ्चिका(k1->pkey)),
	    EC_कुञ्चिका_get0_लौकिकम्_कुञ्चिका(EVP_PKEY_get0_EC_कुञ्चिका(k1->pkey)),
	    POINT_CONVERSION_UNCOMPRESSED, रिक्त, रिक्त);
	ASSERT_PTR_NE(c, रिक्त);
	ASSERT_BIGNUM_EQ(
	    EC_कुञ्चिका_get0_वैयक्तिकम्_कुञ्चिका(EVP_PKEY_get0_EC_कुञ्चिका(k1->pkey)), a);
	ASSERT_BIGNUM_EQ(b, c);
	BN_free(a);
	BN_free(b);
	BN_free(c);
#यदि_अन्तः /* OPENSSL_IS_BORINGSSL */
	TEST_समाप्तम्();

	TEST_START("parse ECDSA from private w/ passphrase");
	buf = आरोपय_file("ecdsa_1_pw");
	ASSERT_INT_EQ(sshkey_parse_वैयक्तिकम्_fileblob(buf,
	    (ध्रुव वर्ण *)sshbuf_ptr(pw), &k2, रिक्त), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k2, रिक्त);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_समाप्तम्();

	TEST_START("parse ECDSA from new-format");
	buf = आरोपय_file("ecdsa_n");
	ASSERT_INT_EQ(sshkey_parse_वैयक्तिकम्_fileblob(buf, "", &k2, रिक्त), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k2, रिक्त);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_समाप्तम्();

	TEST_START("parse ECDSA from new-format w/ passphrase");
	buf = आरोपय_file("ecdsa_n_pw");
	ASSERT_INT_EQ(sshkey_parse_वैयक्तिकम्_fileblob(buf,
	    (ध्रुव वर्ण *)sshbuf_ptr(pw), &k2, रिक्त), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k2, रिक्त);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_समाप्तम्();

	TEST_START("load ECDSA from public");
	ASSERT_INT_EQ(sshkey_आरोपय_लौकिकम्(test_दत्त_file("ecdsa_1.pub"), &k2,
	    रिक्त), 0);
	ASSERT_PTR_NE(k2, रिक्त);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_समाप्तम्();

	TEST_START("load ECDSA cert");
	ASSERT_INT_EQ(sshkey_आरोपय_cert(test_दत्त_file("ecdsa_1"), &k2), 0);
	ASSERT_PTR_NE(k2, रिक्त);
	ASSERT_INT_EQ(k2->type, कुञ्चिका_ECDSA_CERT);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 0);
	ASSERT_INT_EQ(sshkey_equal_लौकिकम्(k1, k2), 1);
	TEST_समाप्तम्();

	TEST_START("ECDSA key hex fingerprint");
	buf = आरोपय_text_file("ecdsa_1.fp");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, रिक्त);
	ASSERT_STRING_EQ(cp, (ध्रुव वर्ण *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	मुक्त(cp);
	TEST_समाप्तम्();

	TEST_START("ECDSA cert hex fingerprint");
	buf = आरोपय_text_file("ecdsa_1-cert.fp");
	cp = sshkey_fingerprint(k2, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, रिक्त);
	ASSERT_STRING_EQ(cp, (ध्रुव वर्ण *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	मुक्त(cp);
	sshkey_free(k2);
	TEST_समाप्तम्();

	TEST_START("ECDSA key bubblebabble fingerprint");
	buf = आरोपय_text_file("ecdsa_1.fp.bb");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA1, SSH_FP_BUBBLEBABBLE);
	ASSERT_PTR_NE(cp, रिक्त);
	ASSERT_STRING_EQ(cp, (ध्रुव वर्ण *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	मुक्त(cp);
	TEST_समाप्तम्();

	sshkey_free(k1);
#यदि_अन्तः /* WITH_OPENSSL */

	TEST_START("parse Ed25519 from private");
	buf = आरोपय_file("ed25519_1");
	ASSERT_INT_EQ(sshkey_parse_वैयक्तिकम्_fileblob(buf, "", &k1, रिक्त), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k1, रिक्त);
	ASSERT_INT_EQ(k1->type, कुञ्चिका_ED25519);
	/* XXX check key contents */
	TEST_समाप्तम्();

	TEST_START("parse Ed25519 from private w/ passphrase");
	buf = आरोपय_file("ed25519_1_pw");
	ASSERT_INT_EQ(sshkey_parse_वैयक्तिकम्_fileblob(buf,
	    (ध्रुव वर्ण *)sshbuf_ptr(pw), &k2, रिक्त), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k2, रिक्त);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_समाप्तम्();

	TEST_START("load Ed25519 from public");
	ASSERT_INT_EQ(sshkey_आरोपय_लौकिकम्(test_दत्त_file("ed25519_1.pub"), &k2,
	    रिक्त), 0);
	ASSERT_PTR_NE(k2, रिक्त);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_समाप्तम्();

	TEST_START("load Ed25519 cert");
	ASSERT_INT_EQ(sshkey_आरोपय_cert(test_दत्त_file("ed25519_1"), &k2), 0);
	ASSERT_PTR_NE(k2, रिक्त);
	ASSERT_INT_EQ(k2->type, कुञ्चिका_ED25519_CERT);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 0);
	ASSERT_INT_EQ(sshkey_equal_लौकिकम्(k1, k2), 1);
	TEST_समाप्तम्();

	TEST_START("Ed25519 key hex fingerprint");
	buf = आरोपय_text_file("ed25519_1.fp");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, रिक्त);
	ASSERT_STRING_EQ(cp, (ध्रुव वर्ण *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	मुक्त(cp);
	TEST_समाप्तम्();

	TEST_START("Ed25519 cert hex fingerprint");
	buf = आरोपय_text_file("ed25519_1-cert.fp");
	cp = sshkey_fingerprint(k2, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, रिक्त);
	ASSERT_STRING_EQ(cp, (ध्रुव वर्ण *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	मुक्त(cp);
	sshkey_free(k2);
	TEST_समाप्तम्();

	TEST_START("Ed25519 key bubblebabble fingerprint");
	buf = आरोपय_text_file("ed25519_1.fp.bb");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA1, SSH_FP_BUBBLEBABBLE);
	ASSERT_PTR_NE(cp, रिक्त);
	ASSERT_STRING_EQ(cp, (ध्रुव वर्ण *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	मुक्त(cp);
	TEST_समाप्तम्();

	sshkey_free(k1);

	TEST_START("parse MLDSA44-ED25519 from private");
	buf = आरोपय_file("mldsa44_ed25519_1");
	ASSERT_INT_EQ(sshkey_parse_वैयक्तिकम्_fileblob(buf, "", &k1, रिक्त), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k1, रिक्त);
	ASSERT_INT_EQ(k1->type, कुञ्चिका_MLDSA44_ED25519);
	TEST_समाप्तम्();

	TEST_START("parse MLDSA44-ED25519 from private w/ passphrase");
	buf = आरोपय_file("mldsa44_ed25519_1_pw");
	ASSERT_INT_EQ(sshkey_parse_वैयक्तिकम्_fileblob(buf,
	    (ध्रुव वर्ण *)sshbuf_ptr(pw), &k2, रिक्त), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k2, रिक्त);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_समाप्तम्();

	TEST_START("load MLDSA44-ED25519 from public");
	ASSERT_INT_EQ(sshkey_आरोपय_लौकिकम्(
	    test_दत्त_file("mldsa44_ed25519_1.pub"), &k2, रिक्त), 0);
	ASSERT_PTR_NE(k2, रिक्त);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_समाप्तम्();

	TEST_START("load MLDSA44-ED25519 cert");
	ASSERT_INT_EQ(sshkey_आरोपय_cert(
	    test_दत्त_file("mldsa44_ed25519_1"), &k2), 0);
	ASSERT_PTR_NE(k2, रिक्त);
	ASSERT_INT_EQ(k2->type, कुञ्चिका_MLDSA44_ED25519_CERT);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 0);
	ASSERT_INT_EQ(sshkey_equal_लौकिकम्(k1, k2), 1);
	TEST_समाप्तम्();

	TEST_START("MLDSA44-ED25519 key hex fingerprint");
	buf = आरोपय_text_file("mldsa44_ed25519_1.fp");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, रिक्त);
	ASSERT_STRING_EQ(cp, (ध्रुव वर्ण *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	मुक्त(cp);
	TEST_समाप्तम्();

	TEST_START("MLDSA44-ED25519 cert hex fingerprint");
	buf = आरोपय_text_file("mldsa44_ed25519_1-cert.fp");
	cp = sshkey_fingerprint(k2, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, रिक्त);
	ASSERT_STRING_EQ(cp, (ध्रुव वर्ण *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	मुक्त(cp);
	sshkey_free(k2);
	TEST_समाप्तम्();

	TEST_START("MLDSA44-ED25519 key bubblebabble fingerprint");
	buf = आरोपय_text_file("mldsa44_ed25519_1.fp.bb");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA1, SSH_FP_BUBBLEBABBLE);
	ASSERT_PTR_NE(cp, रिक्त);
	ASSERT_STRING_EQ(cp, (ध्रुव वर्ण *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	मुक्त(cp);
	TEST_समाप्तम्();

	sshkey_free(k1);

#यदि_परिभाषितम् ENABLE_SK
#यदि defined(WITH_OPENSSL)
	TEST_START("parse ECDSA-SK from private");
	buf = आरोपय_file("ecdsa_sk1");
	ASSERT_INT_EQ(sshkey_parse_वैयक्तिकम्_fileblob(buf, "", &k1, रिक्त), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k1, रिक्त);
	ASSERT_INT_EQ(k1->type, कुञ्चिका_ECDSA_SK);
	TEST_समाप्तम्();

	TEST_START("parse ECDSA-SK from private w/ passphrase");
	buf = आरोपय_file("ecdsa_sk1_pw");
	ASSERT_INT_EQ(sshkey_parse_वैयक्तिकम्_fileblob(buf,
	    (ध्रुव वर्ण *)sshbuf_ptr(pw), &k2, रिक्त), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k2, रिक्त);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_समाप्तम्();

	TEST_START("load ECDSA-SK from public");
	ASSERT_INT_EQ(sshkey_आरोपय_लौकिकम्(test_दत्त_file("ecdsa_sk1.pub"), &k2,
	    रिक्त), 0);
	ASSERT_PTR_NE(k2, रिक्त);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_समाप्तम्();

	TEST_START("load ECDSA-SK cert");
	ASSERT_INT_EQ(sshkey_आरोपय_cert(test_दत्त_file("ecdsa_sk1"), &k2), 0);
	ASSERT_PTR_NE(k2, रिक्त);
	ASSERT_INT_EQ(k2->type, कुञ्चिका_ECDSA_SK_CERT);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 0);
	ASSERT_INT_EQ(sshkey_equal_लौकिकम्(k1, k2), 1);
	TEST_समाप्तम्();

	TEST_START("ECDSA-SK key hex fingerprint");
	buf = आरोपय_text_file("ecdsa_sk1.fp");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, रिक्त);
	ASSERT_STRING_EQ(cp, (ध्रुव वर्ण *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	मुक्त(cp);
	TEST_समाप्तम्();

	TEST_START("ECDSA-SK cert hex fingerprint");
	buf = आरोपय_text_file("ecdsa_sk1-cert.fp");
	cp = sshkey_fingerprint(k2, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, रिक्त);
	ASSERT_STRING_EQ(cp, (ध्रुव वर्ण *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	मुक्त(cp);
	sshkey_free(k2);
	TEST_समाप्तम्();

	TEST_START("ECDSA-SK key bubblebabble fingerprint");
	buf = आरोपय_text_file("ecdsa_sk1.fp.bb");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA1, SSH_FP_BUBBLEBABBLE);
	ASSERT_PTR_NE(cp, रिक्त);
	ASSERT_STRING_EQ(cp, (ध्रुव वर्ण *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	मुक्त(cp);
	TEST_समाप्तम्();

	sshkey_free(k1);
#यदि_अन्तः

	TEST_START("parse Ed25519-SK from private");
	buf = आरोपय_file("ed25519_sk1");
	ASSERT_INT_EQ(sshkey_parse_वैयक्तिकम्_fileblob(buf, "", &k1, रिक्त), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k1, रिक्त);
	ASSERT_INT_EQ(k1->type, कुञ्चिका_ED25519_SK);
	/* XXX check key contents */
	TEST_समाप्तम्();

	TEST_START("parse Ed25519-SK from private w/ passphrase");
	buf = आरोपय_file("ed25519_sk1_pw");
	ASSERT_INT_EQ(sshkey_parse_वैयक्तिकम्_fileblob(buf,
	    (ध्रुव वर्ण *)sshbuf_ptr(pw), &k2, रिक्त), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k2, रिक्त);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_समाप्तम्();

	TEST_START("load Ed25519-SK from public");
	ASSERT_INT_EQ(sshkey_आरोपय_लौकिकम्(test_दत्त_file("ed25519_sk1.pub"),
	    &k2, रिक्त), 0);
	ASSERT_PTR_NE(k2, रिक्त);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_समाप्तम्();

	TEST_START("load Ed25519-SK cert");
	ASSERT_INT_EQ(sshkey_आरोपय_cert(test_दत्त_file("ed25519_sk1"), &k2), 0);
	ASSERT_PTR_NE(k2, रिक्त);
	ASSERT_INT_EQ(k2->type, कुञ्चिका_ED25519_SK_CERT);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 0);
	ASSERT_INT_EQ(sshkey_equal_लौकिकम्(k1, k2), 1);
	TEST_समाप्तम्();

	TEST_START("Ed25519-SK key hex fingerprint");
	buf = आरोपय_text_file("ed25519_sk1.fp");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, रिक्त);
	ASSERT_STRING_EQ(cp, (ध्रुव वर्ण *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	मुक्त(cp);
	TEST_समाप्तम्();

	TEST_START("Ed25519-SK cert hex fingerprint");
	buf = आरोपय_text_file("ed25519_sk1-cert.fp");
	cp = sshkey_fingerprint(k2, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, रिक्त);
	ASSERT_STRING_EQ(cp, (ध्रुव वर्ण *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	मुक्त(cp);
	sshkey_free(k2);
	TEST_समाप्तम्();

	TEST_START("Ed25519-SK key bubblebabble fingerprint");
	buf = आरोपय_text_file("ed25519_sk1.fp.bb");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA1, SSH_FP_BUBBLEBABBLE);
	ASSERT_PTR_NE(cp, रिक्त);
	ASSERT_STRING_EQ(cp, (ध्रुव वर्ण *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	मुक्त(cp);
	TEST_समाप्तम्();

	sshkey_free(k1);
#यदि_अन्तः /* ENABLE_SK */

	sshbuf_free(pw);

}
