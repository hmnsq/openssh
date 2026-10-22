/* 	$OpenBSD: test_file.c,v 1.14 2026/06/14 04:08:06 djm Exp $ */
/*
 * Regress test for sshkey.h key management API
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
#اگر_ختم /* WITH_OPENSSL */

#شامل "../test_helper/test_helper.h"

#شامل "ssherr.h"
#شامل "authfile.h"
#شامل "sshkey.h"
#شامل "sshbuf.h"
#شامل "digest.h"

#شامل "common.h"

خالی sshkey_file_tests(خالی);

خالی
sshkey_file_tests(خالی)
{
	ساخت sshkey *k1, *k2;
	ساخت sshbuf *buf, *pw;
#اگر_تعریف_شدہ WITH_OPENSSL
	BIGNUM *a, *b, *c;
#اگر_ختم
	حرف *cp;

	TEST_آغاز("load passphrase");
	pw = بھرو_متن_file("pw");
	TEST_مکمل();


#اگر_تعریف_شدہ WITH_OPENSSL
	TEST_آغاز("parse RSA from private");
	buf = بھرو_file("rsa_1");
	ASSERT_INT_EQ(sshkey_parse_نجی_fileblob(buf, "", &k1, تہی), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k1, تہی);
	a = بھرو_bignum("rsa_1.param.n");
	b = بھرو_bignum("rsa_1.param.p");
	c = بھرو_bignum("rsa_1.param.q");
	ASSERT_BIGNUM_EQ(rsa_n(k1), a);
	ASSERT_BIGNUM_EQ(rsa_p(k1), b);
	ASSERT_BIGNUM_EQ(rsa_q(k1), c);
	BN_free(a);
	BN_free(b);
	BN_free(c);
	TEST_مکمل();

	TEST_آغاز("parse RSA from private w/ passphrase");
	buf = بھرو_file("rsa_1_pw");
	ASSERT_INT_EQ(sshkey_parse_نجی_fileblob(buf,
	    (ثابت حرف *)sshbuf_ptr(pw), &k2, تہی), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k2, تہی);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_مکمل();

	TEST_آغاز("parse RSA from new-format");
	buf = بھرو_file("rsa_n");
	ASSERT_INT_EQ(sshkey_parse_نجی_fileblob(buf, "", &k2, تہی), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k2, تہی);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_مکمل();

	TEST_آغاز("parse RSA from new-format w/ passphrase");
	buf = بھرو_file("rsa_n_pw");
	ASSERT_INT_EQ(sshkey_parse_نجی_fileblob(buf,
	    (ثابت حرف *)sshbuf_ptr(pw), &k2, تہی), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k2, تہی);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_مکمل();

	TEST_آغاز("load RSA from public");
	ASSERT_INT_EQ(sshkey_بھرو_عوامی(test_ڈیٹا_file("rsa_1.pub"), &k2,
	    تہی), 0);
	ASSERT_PTR_NE(k2, تہی);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_مکمل();

	TEST_آغاز("load RSA cert with SHA1 signature");
	ASSERT_INT_EQ(sshkey_بھرو_cert(test_ڈیٹا_file("rsa_1_sha1"), &k2), 0);
	ASSERT_PTR_NE(k2, تہی);
	ASSERT_INT_EQ(k2->type, کلید_RSA_CERT);
	ASSERT_INT_EQ(sshkey_equal_عوامی(k1, k2), 1);
	ASSERT_STRING_EQ(k2->cert->signature_type, "ssh-rsa");
	sshkey_free(k2);
	TEST_مکمل();

	TEST_آغاز("load RSA cert with SHA512 signature");
	ASSERT_INT_EQ(sshkey_بھرو_cert(test_ڈیٹا_file("rsa_1_sha512"), &k2), 0);
	ASSERT_PTR_NE(k2, تہی);
	ASSERT_INT_EQ(k2->type, کلید_RSA_CERT);
	ASSERT_INT_EQ(sshkey_equal_عوامی(k1, k2), 1);
	ASSERT_STRING_EQ(k2->cert->signature_type, "rsa-sha2-512");
	sshkey_free(k2);
	TEST_مکمل();

	TEST_آغاز("load RSA cert");
	ASSERT_INT_EQ(sshkey_بھرو_cert(test_ڈیٹا_file("rsa_1"), &k2), 0);
	ASSERT_PTR_NE(k2, تہی);
	ASSERT_INT_EQ(k2->type, کلید_RSA_CERT);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 0);
	ASSERT_INT_EQ(sshkey_equal_عوامی(k1, k2), 1);
	TEST_مکمل();

	TEST_آغاز("RSA key hex fingerprint");
	buf = بھرو_متن_file("rsa_1.fp");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, تہی);
	ASSERT_STRING_EQ(cp, (ثابت حرف *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	آزاد(cp);
	TEST_مکمل();

	TEST_آغاز("RSA cert hex fingerprint");
	buf = بھرو_متن_file("rsa_1-cert.fp");
	cp = sshkey_fingerprint(k2, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, تہی);
	ASSERT_STRING_EQ(cp, (ثابت حرف *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	آزاد(cp);
	sshkey_free(k2);
	TEST_مکمل();

	TEST_آغاز("RSA key bubblebabble fingerprint");
	buf = بھرو_متن_file("rsa_1.fp.bb");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA1, SSH_FP_BUBBLEBABBLE);
	ASSERT_PTR_NE(cp, تہی);
	ASSERT_STRING_EQ(cp, (ثابت حرف *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	آزاد(cp);
	TEST_مکمل();

	sshkey_free(k1);


	TEST_آغاز("parse ECDSA from private");
	buf = بھرو_file("ecdsa_1");
	ASSERT_INT_EQ(sshkey_parse_نجی_fileblob(buf, "", &k1, تہی), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k1, تہی);
	buf = بھرو_متن_file("ecdsa_1.param.curve");
	ASSERT_STRING_EQ((ثابت حرف *)sshbuf_ptr(buf),
	    OBJ_nid2sn(k1->ecdsa_nid));
	sshbuf_free(buf);
#اگر_غیر_تعریف_شدہ OPENSSL_IS_BORINGSSL /* lacks EC_POINT_point2bn() */
	a = بھرو_bignum("ecdsa_1.param.priv");
	b = بھرو_bignum("ecdsa_1.param.pub");
	c = EC_نقطہ_point2bn(EC_کلید_get0_گروہ(EVP_PKEY_get0_EC_کلید(k1->pkey)),
	    EC_کلید_get0_عوامی_کلید(EVP_PKEY_get0_EC_کلید(k1->pkey)),
	    نقطہ_CONVERSION_UNCOMPRESSED, تہی, تہی);
	ASSERT_PTR_NE(c, تہی);
	ASSERT_BIGNUM_EQ(
	    EC_کلید_get0_نجی_کلید(EVP_PKEY_get0_EC_کلید(k1->pkey)), a);
	ASSERT_BIGNUM_EQ(b, c);
	BN_free(a);
	BN_free(b);
	BN_free(c);
#اگر_ختم /* OPENSSL_IS_BORINGSSL */
	TEST_مکمل();

	TEST_آغاز("parse ECDSA from private w/ passphrase");
	buf = بھرو_file("ecdsa_1_pw");
	ASSERT_INT_EQ(sshkey_parse_نجی_fileblob(buf,
	    (ثابت حرف *)sshbuf_ptr(pw), &k2, تہی), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k2, تہی);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_مکمل();

	TEST_آغاز("parse ECDSA from new-format");
	buf = بھرو_file("ecdsa_n");
	ASSERT_INT_EQ(sshkey_parse_نجی_fileblob(buf, "", &k2, تہی), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k2, تہی);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_مکمل();

	TEST_آغاز("parse ECDSA from new-format w/ passphrase");
	buf = بھرو_file("ecdsa_n_pw");
	ASSERT_INT_EQ(sshkey_parse_نجی_fileblob(buf,
	    (ثابت حرف *)sshbuf_ptr(pw), &k2, تہی), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k2, تہی);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_مکمل();

	TEST_آغاز("load ECDSA from public");
	ASSERT_INT_EQ(sshkey_بھرو_عوامی(test_ڈیٹا_file("ecdsa_1.pub"), &k2,
	    تہی), 0);
	ASSERT_PTR_NE(k2, تہی);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_مکمل();

	TEST_آغاز("load ECDSA cert");
	ASSERT_INT_EQ(sshkey_بھرو_cert(test_ڈیٹا_file("ecdsa_1"), &k2), 0);
	ASSERT_PTR_NE(k2, تہی);
	ASSERT_INT_EQ(k2->type, کلید_ECDSA_CERT);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 0);
	ASSERT_INT_EQ(sshkey_equal_عوامی(k1, k2), 1);
	TEST_مکمل();

	TEST_آغاز("ECDSA key hex fingerprint");
	buf = بھرو_متن_file("ecdsa_1.fp");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, تہی);
	ASSERT_STRING_EQ(cp, (ثابت حرف *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	آزاد(cp);
	TEST_مکمل();

	TEST_آغاز("ECDSA cert hex fingerprint");
	buf = بھرو_متن_file("ecdsa_1-cert.fp");
	cp = sshkey_fingerprint(k2, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, تہی);
	ASSERT_STRING_EQ(cp, (ثابت حرف *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	آزاد(cp);
	sshkey_free(k2);
	TEST_مکمل();

	TEST_آغاز("ECDSA key bubblebabble fingerprint");
	buf = بھرو_متن_file("ecdsa_1.fp.bb");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA1, SSH_FP_BUBBLEBABBLE);
	ASSERT_PTR_NE(cp, تہی);
	ASSERT_STRING_EQ(cp, (ثابت حرف *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	آزاد(cp);
	TEST_مکمل();

	sshkey_free(k1);
#اگر_ختم /* WITH_OPENSSL */

	TEST_آغاز("parse Ed25519 from private");
	buf = بھرو_file("ed25519_1");
	ASSERT_INT_EQ(sshkey_parse_نجی_fileblob(buf, "", &k1, تہی), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k1, تہی);
	ASSERT_INT_EQ(k1->type, کلید_ED25519);
	/* XXX check key contents */
	TEST_مکمل();

	TEST_آغاز("parse Ed25519 from private w/ passphrase");
	buf = بھرو_file("ed25519_1_pw");
	ASSERT_INT_EQ(sshkey_parse_نجی_fileblob(buf,
	    (ثابت حرف *)sshbuf_ptr(pw), &k2, تہی), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k2, تہی);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_مکمل();

	TEST_آغاز("load Ed25519 from public");
	ASSERT_INT_EQ(sshkey_بھرو_عوامی(test_ڈیٹا_file("ed25519_1.pub"), &k2,
	    تہی), 0);
	ASSERT_PTR_NE(k2, تہی);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_مکمل();

	TEST_آغاز("load Ed25519 cert");
	ASSERT_INT_EQ(sshkey_بھرو_cert(test_ڈیٹا_file("ed25519_1"), &k2), 0);
	ASSERT_PTR_NE(k2, تہی);
	ASSERT_INT_EQ(k2->type, کلید_ED25519_CERT);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 0);
	ASSERT_INT_EQ(sshkey_equal_عوامی(k1, k2), 1);
	TEST_مکمل();

	TEST_آغاز("Ed25519 key hex fingerprint");
	buf = بھرو_متن_file("ed25519_1.fp");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, تہی);
	ASSERT_STRING_EQ(cp, (ثابت حرف *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	آزاد(cp);
	TEST_مکمل();

	TEST_آغاز("Ed25519 cert hex fingerprint");
	buf = بھرو_متن_file("ed25519_1-cert.fp");
	cp = sshkey_fingerprint(k2, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, تہی);
	ASSERT_STRING_EQ(cp, (ثابت حرف *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	آزاد(cp);
	sshkey_free(k2);
	TEST_مکمل();

	TEST_آغاز("Ed25519 key bubblebabble fingerprint");
	buf = بھرو_متن_file("ed25519_1.fp.bb");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA1, SSH_FP_BUBBLEBABBLE);
	ASSERT_PTR_NE(cp, تہی);
	ASSERT_STRING_EQ(cp, (ثابت حرف *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	آزاد(cp);
	TEST_مکمل();

	sshkey_free(k1);

	TEST_آغاز("parse MLDSA44-ED25519 from private");
	buf = بھرو_file("mldsa44_ed25519_1");
	ASSERT_INT_EQ(sshkey_parse_نجی_fileblob(buf, "", &k1, تہی), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k1, تہی);
	ASSERT_INT_EQ(k1->type, کلید_MLDSA44_ED25519);
	TEST_مکمل();

	TEST_آغاز("parse MLDSA44-ED25519 from private w/ passphrase");
	buf = بھرو_file("mldsa44_ed25519_1_pw");
	ASSERT_INT_EQ(sshkey_parse_نجی_fileblob(buf,
	    (ثابت حرف *)sshbuf_ptr(pw), &k2, تہی), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k2, تہی);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_مکمل();

	TEST_آغاز("load MLDSA44-ED25519 from public");
	ASSERT_INT_EQ(sshkey_بھرو_عوامی(
	    test_ڈیٹا_file("mldsa44_ed25519_1.pub"), &k2, تہی), 0);
	ASSERT_PTR_NE(k2, تہی);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_مکمل();

	TEST_آغاز("load MLDSA44-ED25519 cert");
	ASSERT_INT_EQ(sshkey_بھرو_cert(
	    test_ڈیٹا_file("mldsa44_ed25519_1"), &k2), 0);
	ASSERT_PTR_NE(k2, تہی);
	ASSERT_INT_EQ(k2->type, کلید_MLDSA44_ED25519_CERT);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 0);
	ASSERT_INT_EQ(sshkey_equal_عوامی(k1, k2), 1);
	TEST_مکمل();

	TEST_آغاز("MLDSA44-ED25519 key hex fingerprint");
	buf = بھرو_متن_file("mldsa44_ed25519_1.fp");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, تہی);
	ASSERT_STRING_EQ(cp, (ثابت حرف *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	آزاد(cp);
	TEST_مکمل();

	TEST_آغاز("MLDSA44-ED25519 cert hex fingerprint");
	buf = بھرو_متن_file("mldsa44_ed25519_1-cert.fp");
	cp = sshkey_fingerprint(k2, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, تہی);
	ASSERT_STRING_EQ(cp, (ثابت حرف *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	آزاد(cp);
	sshkey_free(k2);
	TEST_مکمل();

	TEST_آغاز("MLDSA44-ED25519 key bubblebabble fingerprint");
	buf = بھرو_متن_file("mldsa44_ed25519_1.fp.bb");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA1, SSH_FP_BUBBLEBABBLE);
	ASSERT_PTR_NE(cp, تہی);
	ASSERT_STRING_EQ(cp, (ثابت حرف *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	آزاد(cp);
	TEST_مکمل();

	sshkey_free(k1);

#اگر_تعریف_شدہ ENABLE_SK
#اگر defined(WITH_OPENSSL)
	TEST_آغاز("parse ECDSA-SK from private");
	buf = بھرو_file("ecdsa_sk1");
	ASSERT_INT_EQ(sshkey_parse_نجی_fileblob(buf, "", &k1, تہی), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k1, تہی);
	ASSERT_INT_EQ(k1->type, کلید_ECDSA_SK);
	TEST_مکمل();

	TEST_آغاز("parse ECDSA-SK from private w/ passphrase");
	buf = بھرو_file("ecdsa_sk1_pw");
	ASSERT_INT_EQ(sshkey_parse_نجی_fileblob(buf,
	    (ثابت حرف *)sshbuf_ptr(pw), &k2, تہی), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k2, تہی);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_مکمل();

	TEST_آغاز("load ECDSA-SK from public");
	ASSERT_INT_EQ(sshkey_بھرو_عوامی(test_ڈیٹا_file("ecdsa_sk1.pub"), &k2,
	    تہی), 0);
	ASSERT_PTR_NE(k2, تہی);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_مکمل();

	TEST_آغاز("load ECDSA-SK cert");
	ASSERT_INT_EQ(sshkey_بھرو_cert(test_ڈیٹا_file("ecdsa_sk1"), &k2), 0);
	ASSERT_PTR_NE(k2, تہی);
	ASSERT_INT_EQ(k2->type, کلید_ECDSA_SK_CERT);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 0);
	ASSERT_INT_EQ(sshkey_equal_عوامی(k1, k2), 1);
	TEST_مکمل();

	TEST_آغاز("ECDSA-SK key hex fingerprint");
	buf = بھرو_متن_file("ecdsa_sk1.fp");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, تہی);
	ASSERT_STRING_EQ(cp, (ثابت حرف *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	آزاد(cp);
	TEST_مکمل();

	TEST_آغاز("ECDSA-SK cert hex fingerprint");
	buf = بھرو_متن_file("ecdsa_sk1-cert.fp");
	cp = sshkey_fingerprint(k2, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, تہی);
	ASSERT_STRING_EQ(cp, (ثابت حرف *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	آزاد(cp);
	sshkey_free(k2);
	TEST_مکمل();

	TEST_آغاز("ECDSA-SK key bubblebabble fingerprint");
	buf = بھرو_متن_file("ecdsa_sk1.fp.bb");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA1, SSH_FP_BUBBLEBABBLE);
	ASSERT_PTR_NE(cp, تہی);
	ASSERT_STRING_EQ(cp, (ثابت حرف *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	آزاد(cp);
	TEST_مکمل();

	sshkey_free(k1);
#اگر_ختم

	TEST_آغاز("parse Ed25519-SK from private");
	buf = بھرو_file("ed25519_sk1");
	ASSERT_INT_EQ(sshkey_parse_نجی_fileblob(buf, "", &k1, تہی), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k1, تہی);
	ASSERT_INT_EQ(k1->type, کلید_ED25519_SK);
	/* XXX check key contents */
	TEST_مکمل();

	TEST_آغاز("parse Ed25519-SK from private w/ passphrase");
	buf = بھرو_file("ed25519_sk1_pw");
	ASSERT_INT_EQ(sshkey_parse_نجی_fileblob(buf,
	    (ثابت حرف *)sshbuf_ptr(pw), &k2, تہی), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k2, تہی);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_مکمل();

	TEST_آغاز("load Ed25519-SK from public");
	ASSERT_INT_EQ(sshkey_بھرو_عوامی(test_ڈیٹا_file("ed25519_sk1.pub"),
	    &k2, تہی), 0);
	ASSERT_PTR_NE(k2, تہی);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_مکمل();

	TEST_آغاز("load Ed25519-SK cert");
	ASSERT_INT_EQ(sshkey_بھرو_cert(test_ڈیٹا_file("ed25519_sk1"), &k2), 0);
	ASSERT_PTR_NE(k2, تہی);
	ASSERT_INT_EQ(k2->type, کلید_ED25519_SK_CERT);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 0);
	ASSERT_INT_EQ(sshkey_equal_عوامی(k1, k2), 1);
	TEST_مکمل();

	TEST_آغاز("Ed25519-SK key hex fingerprint");
	buf = بھرو_متن_file("ed25519_sk1.fp");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, تہی);
	ASSERT_STRING_EQ(cp, (ثابت حرف *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	آزاد(cp);
	TEST_مکمل();

	TEST_آغاز("Ed25519-SK cert hex fingerprint");
	buf = بھرو_متن_file("ed25519_sk1-cert.fp");
	cp = sshkey_fingerprint(k2, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, تہی);
	ASSERT_STRING_EQ(cp, (ثابت حرف *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	آزاد(cp);
	sshkey_free(k2);
	TEST_مکمل();

	TEST_آغاز("Ed25519-SK key bubblebabble fingerprint");
	buf = بھرو_متن_file("ed25519_sk1.fp.bb");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA1, SSH_FP_BUBBLEBABBLE);
	ASSERT_PTR_NE(cp, تہی);
	ASSERT_STRING_EQ(cp, (ثابت حرف *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	آزاد(cp);
	TEST_مکمل();

	sshkey_free(k1);
#اگر_ختم /* ENABLE_SK */

	sshbuf_free(pw);

}
