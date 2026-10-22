/* 	$OpenBSD: test_file.c,v 1.14 2026/06/14 04:08:06 djm Exp $ */
/*
 * Regress test for sshkey.h key management API
 *
 * Placed in the public domain
 */

#ضمن "includes.h"

#ضمن <sys/types.h>
#ضمن <sys/stat.h>
#ضمن <fcntl.h>
#ضمن <stdio.h>
#ضمن <stdint.h>
#ضمن <stdlib.h>
#ضمن <string.h>
#ضمن <unistd.h>

#جے_تعریف_شدہ WITH_OPENSSL
#ضمن <openssl/bn.h>
#ضمن <openssl/ec.h>
#ضمن <openssl/rsa.h>
#ضمن <openssl/objects.h>
#جے_انت /* WITH_OPENSSL */

#ضمن "../test_helper/test_helper.h"

#ضمن "ssherr.h"
#ضمن "authfile.h"
#ضمن "sshkey.h"
#ضمن "sshbuf.h"
#ضمن "digest.h"

#ضمن "common.h"

فراغ sshkey_file_tests(فراغ);

فراغ
sshkey_file_tests(فراغ)
{
	بنية sshkey *k1, *k2;
	بنية sshbuf *buf, *pw;
#جے_تعریف_شدہ WITH_OPENSSL
	BIGNUM *a, *b, *c;
#جے_انت
	حرف *cp;

	TEST_شروع("load passphrase");
	pw = لدو_متن_file("pw");
	TEST_پورا();


#جے_تعریف_شدہ WITH_OPENSSL
	TEST_شروع("parse RSA from private");
	buf = لدو_file("rsa_1");
	ASSERT_INT_EQ(sshkey_parse_نجی_fileblob(buf, "", &k1, عدم), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k1, عدم);
	a = لدو_bignum("rsa_1.param.n");
	b = لدو_bignum("rsa_1.param.p");
	c = لدو_bignum("rsa_1.param.q");
	ASSERT_BIGNUM_EQ(rsa_n(k1), a);
	ASSERT_BIGNUM_EQ(rsa_p(k1), b);
	ASSERT_BIGNUM_EQ(rsa_q(k1), c);
	BN_free(a);
	BN_free(b);
	BN_free(c);
	TEST_پورا();

	TEST_شروع("parse RSA from private w/ passphrase");
	buf = لدو_file("rsa_1_pw");
	ASSERT_INT_EQ(sshkey_parse_نجی_fileblob(buf,
	    (ثابت حرف *)sshbuf_ptr(pw), &k2, عدم), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k2, عدم);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_پورا();

	TEST_شروع("parse RSA from new-format");
	buf = لدو_file("rsa_n");
	ASSERT_INT_EQ(sshkey_parse_نجی_fileblob(buf, "", &k2, عدم), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k2, عدم);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_پورا();

	TEST_شروع("parse RSA from new-format w/ passphrase");
	buf = لدو_file("rsa_n_pw");
	ASSERT_INT_EQ(sshkey_parse_نجی_fileblob(buf,
	    (ثابت حرف *)sshbuf_ptr(pw), &k2, عدم), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k2, عدم);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_پورا();

	TEST_شروع("load RSA from public");
	ASSERT_INT_EQ(sshkey_لدو_عوامی(test_انکڑے_file("rsa_1.pub"), &k2,
	    عدم), 0);
	ASSERT_PTR_NE(k2, عدم);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_پورا();

	TEST_شروع("load RSA cert with SHA1 signature");
	ASSERT_INT_EQ(sshkey_لدو_cert(test_انکڑے_file("rsa_1_sha1"), &k2), 0);
	ASSERT_PTR_NE(k2, عدم);
	ASSERT_INT_EQ(k2->type, کلید_RSA_CERT);
	ASSERT_INT_EQ(sshkey_equal_عوامی(k1, k2), 1);
	ASSERT_STRING_EQ(k2->cert->signature_type, "ssh-rsa");
	sshkey_free(k2);
	TEST_پورا();

	TEST_شروع("load RSA cert with SHA512 signature");
	ASSERT_INT_EQ(sshkey_لدو_cert(test_انکڑے_file("rsa_1_sha512"), &k2), 0);
	ASSERT_PTR_NE(k2, عدم);
	ASSERT_INT_EQ(k2->type, کلید_RSA_CERT);
	ASSERT_INT_EQ(sshkey_equal_عوامی(k1, k2), 1);
	ASSERT_STRING_EQ(k2->cert->signature_type, "rsa-sha2-512");
	sshkey_free(k2);
	TEST_پورا();

	TEST_شروع("load RSA cert");
	ASSERT_INT_EQ(sshkey_لدو_cert(test_انکڑے_file("rsa_1"), &k2), 0);
	ASSERT_PTR_NE(k2, عدم);
	ASSERT_INT_EQ(k2->type, کلید_RSA_CERT);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 0);
	ASSERT_INT_EQ(sshkey_equal_عوامی(k1, k2), 1);
	TEST_پورا();

	TEST_شروع("RSA key hex fingerprint");
	buf = لدو_متن_file("rsa_1.fp");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, عدم);
	ASSERT_STRING_EQ(cp, (ثابت حرف *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	حرر(cp);
	TEST_پورا();

	TEST_شروع("RSA cert hex fingerprint");
	buf = لدو_متن_file("rsa_1-cert.fp");
	cp = sshkey_fingerprint(k2, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, عدم);
	ASSERT_STRING_EQ(cp, (ثابت حرف *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	حرر(cp);
	sshkey_free(k2);
	TEST_پورا();

	TEST_شروع("RSA key bubblebabble fingerprint");
	buf = لدو_متن_file("rsa_1.fp.bb");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA1, SSH_FP_BUBBLEBABBLE);
	ASSERT_PTR_NE(cp, عدم);
	ASSERT_STRING_EQ(cp, (ثابت حرف *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	حرر(cp);
	TEST_پورا();

	sshkey_free(k1);


	TEST_شروع("parse ECDSA from private");
	buf = لدو_file("ecdsa_1");
	ASSERT_INT_EQ(sshkey_parse_نجی_fileblob(buf, "", &k1, عدم), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k1, عدم);
	buf = لدو_متن_file("ecdsa_1.param.curve");
	ASSERT_STRING_EQ((ثابت حرف *)sshbuf_ptr(buf),
	    OBJ_nid2sn(k1->ecdsa_nid));
	sshbuf_free(buf);
#جے_بنا_تعریف OPENSSL_IS_BORINGSSL /* lacks EC_POINT_point2bn() */
	a = لدو_bignum("ecdsa_1.param.priv");
	b = لدو_bignum("ecdsa_1.param.pub");
	c = EC_نقطہ_point2bn(EC_کلید_get0_گروہ(EVP_PKEY_get0_EC_کلید(k1->pkey)),
	    EC_کلید_get0_عوامی_کلید(EVP_PKEY_get0_EC_کلید(k1->pkey)),
	    نقطہ_CONVERSION_UNCOMPRESSED, عدم, عدم);
	ASSERT_PTR_NE(c, عدم);
	ASSERT_BIGNUM_EQ(
	    EC_کلید_get0_نجی_کلید(EVP_PKEY_get0_EC_کلید(k1->pkey)), a);
	ASSERT_BIGNUM_EQ(b, c);
	BN_free(a);
	BN_free(b);
	BN_free(c);
#جے_انت /* OPENSSL_IS_BORINGSSL */
	TEST_پورا();

	TEST_شروع("parse ECDSA from private w/ passphrase");
	buf = لدو_file("ecdsa_1_pw");
	ASSERT_INT_EQ(sshkey_parse_نجی_fileblob(buf,
	    (ثابت حرف *)sshbuf_ptr(pw), &k2, عدم), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k2, عدم);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_پورا();

	TEST_شروع("parse ECDSA from new-format");
	buf = لدو_file("ecdsa_n");
	ASSERT_INT_EQ(sshkey_parse_نجی_fileblob(buf, "", &k2, عدم), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k2, عدم);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_پورا();

	TEST_شروع("parse ECDSA from new-format w/ passphrase");
	buf = لدو_file("ecdsa_n_pw");
	ASSERT_INT_EQ(sshkey_parse_نجی_fileblob(buf,
	    (ثابت حرف *)sshbuf_ptr(pw), &k2, عدم), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k2, عدم);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_پورا();

	TEST_شروع("load ECDSA from public");
	ASSERT_INT_EQ(sshkey_لدو_عوامی(test_انکڑے_file("ecdsa_1.pub"), &k2,
	    عدم), 0);
	ASSERT_PTR_NE(k2, عدم);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_پورا();

	TEST_شروع("load ECDSA cert");
	ASSERT_INT_EQ(sshkey_لدو_cert(test_انکڑے_file("ecdsa_1"), &k2), 0);
	ASSERT_PTR_NE(k2, عدم);
	ASSERT_INT_EQ(k2->type, کلید_ECDSA_CERT);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 0);
	ASSERT_INT_EQ(sshkey_equal_عوامی(k1, k2), 1);
	TEST_پورا();

	TEST_شروع("ECDSA key hex fingerprint");
	buf = لدو_متن_file("ecdsa_1.fp");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, عدم);
	ASSERT_STRING_EQ(cp, (ثابت حرف *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	حرر(cp);
	TEST_پورا();

	TEST_شروع("ECDSA cert hex fingerprint");
	buf = لدو_متن_file("ecdsa_1-cert.fp");
	cp = sshkey_fingerprint(k2, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, عدم);
	ASSERT_STRING_EQ(cp, (ثابت حرف *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	حرر(cp);
	sshkey_free(k2);
	TEST_پورا();

	TEST_شروع("ECDSA key bubblebabble fingerprint");
	buf = لدو_متن_file("ecdsa_1.fp.bb");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA1, SSH_FP_BUBBLEBABBLE);
	ASSERT_PTR_NE(cp, عدم);
	ASSERT_STRING_EQ(cp, (ثابت حرف *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	حرر(cp);
	TEST_پورا();

	sshkey_free(k1);
#جے_انت /* WITH_OPENSSL */

	TEST_شروع("parse Ed25519 from private");
	buf = لدو_file("ed25519_1");
	ASSERT_INT_EQ(sshkey_parse_نجی_fileblob(buf, "", &k1, عدم), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k1, عدم);
	ASSERT_INT_EQ(k1->type, کلید_ED25519);
	/* XXX check key contents */
	TEST_پورا();

	TEST_شروع("parse Ed25519 from private w/ passphrase");
	buf = لدو_file("ed25519_1_pw");
	ASSERT_INT_EQ(sshkey_parse_نجی_fileblob(buf,
	    (ثابت حرف *)sshbuf_ptr(pw), &k2, عدم), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k2, عدم);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_پورا();

	TEST_شروع("load Ed25519 from public");
	ASSERT_INT_EQ(sshkey_لدو_عوامی(test_انکڑے_file("ed25519_1.pub"), &k2,
	    عدم), 0);
	ASSERT_PTR_NE(k2, عدم);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_پورا();

	TEST_شروع("load Ed25519 cert");
	ASSERT_INT_EQ(sshkey_لدو_cert(test_انکڑے_file("ed25519_1"), &k2), 0);
	ASSERT_PTR_NE(k2, عدم);
	ASSERT_INT_EQ(k2->type, کلید_ED25519_CERT);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 0);
	ASSERT_INT_EQ(sshkey_equal_عوامی(k1, k2), 1);
	TEST_پورا();

	TEST_شروع("Ed25519 key hex fingerprint");
	buf = لدو_متن_file("ed25519_1.fp");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, عدم);
	ASSERT_STRING_EQ(cp, (ثابت حرف *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	حرر(cp);
	TEST_پورا();

	TEST_شروع("Ed25519 cert hex fingerprint");
	buf = لدو_متن_file("ed25519_1-cert.fp");
	cp = sshkey_fingerprint(k2, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, عدم);
	ASSERT_STRING_EQ(cp, (ثابت حرف *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	حرر(cp);
	sshkey_free(k2);
	TEST_پورا();

	TEST_شروع("Ed25519 key bubblebabble fingerprint");
	buf = لدو_متن_file("ed25519_1.fp.bb");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA1, SSH_FP_BUBBLEBABBLE);
	ASSERT_PTR_NE(cp, عدم);
	ASSERT_STRING_EQ(cp, (ثابت حرف *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	حرر(cp);
	TEST_پورا();

	sshkey_free(k1);

	TEST_شروع("parse MLDSA44-ED25519 from private");
	buf = لدو_file("mldsa44_ed25519_1");
	ASSERT_INT_EQ(sshkey_parse_نجی_fileblob(buf, "", &k1, عدم), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k1, عدم);
	ASSERT_INT_EQ(k1->type, کلید_MLDSA44_ED25519);
	TEST_پورا();

	TEST_شروع("parse MLDSA44-ED25519 from private w/ passphrase");
	buf = لدو_file("mldsa44_ed25519_1_pw");
	ASSERT_INT_EQ(sshkey_parse_نجی_fileblob(buf,
	    (ثابت حرف *)sshbuf_ptr(pw), &k2, عدم), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k2, عدم);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_پورا();

	TEST_شروع("load MLDSA44-ED25519 from public");
	ASSERT_INT_EQ(sshkey_لدو_عوامی(
	    test_انکڑے_file("mldsa44_ed25519_1.pub"), &k2, عدم), 0);
	ASSERT_PTR_NE(k2, عدم);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_پورا();

	TEST_شروع("load MLDSA44-ED25519 cert");
	ASSERT_INT_EQ(sshkey_لدو_cert(
	    test_انکڑے_file("mldsa44_ed25519_1"), &k2), 0);
	ASSERT_PTR_NE(k2, عدم);
	ASSERT_INT_EQ(k2->type, کلید_MLDSA44_ED25519_CERT);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 0);
	ASSERT_INT_EQ(sshkey_equal_عوامی(k1, k2), 1);
	TEST_پورا();

	TEST_شروع("MLDSA44-ED25519 key hex fingerprint");
	buf = لدو_متن_file("mldsa44_ed25519_1.fp");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, عدم);
	ASSERT_STRING_EQ(cp, (ثابت حرف *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	حرر(cp);
	TEST_پورا();

	TEST_شروع("MLDSA44-ED25519 cert hex fingerprint");
	buf = لدو_متن_file("mldsa44_ed25519_1-cert.fp");
	cp = sshkey_fingerprint(k2, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, عدم);
	ASSERT_STRING_EQ(cp, (ثابت حرف *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	حرر(cp);
	sshkey_free(k2);
	TEST_پورا();

	TEST_شروع("MLDSA44-ED25519 key bubblebabble fingerprint");
	buf = لدو_متن_file("mldsa44_ed25519_1.fp.bb");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA1, SSH_FP_BUBBLEBABBLE);
	ASSERT_PTR_NE(cp, عدم);
	ASSERT_STRING_EQ(cp, (ثابت حرف *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	حرر(cp);
	TEST_پورا();

	sshkey_free(k1);

#جے_تعریف_شدہ ENABLE_SK
#إذا defined(WITH_OPENSSL)
	TEST_شروع("parse ECDSA-SK from private");
	buf = لدو_file("ecdsa_sk1");
	ASSERT_INT_EQ(sshkey_parse_نجی_fileblob(buf, "", &k1, عدم), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k1, عدم);
	ASSERT_INT_EQ(k1->type, کلید_ECDSA_SK);
	TEST_پورا();

	TEST_شروع("parse ECDSA-SK from private w/ passphrase");
	buf = لدو_file("ecdsa_sk1_pw");
	ASSERT_INT_EQ(sshkey_parse_نجی_fileblob(buf,
	    (ثابت حرف *)sshbuf_ptr(pw), &k2, عدم), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k2, عدم);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_پورا();

	TEST_شروع("load ECDSA-SK from public");
	ASSERT_INT_EQ(sshkey_لدو_عوامی(test_انکڑے_file("ecdsa_sk1.pub"), &k2,
	    عدم), 0);
	ASSERT_PTR_NE(k2, عدم);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_پورا();

	TEST_شروع("load ECDSA-SK cert");
	ASSERT_INT_EQ(sshkey_لدو_cert(test_انکڑے_file("ecdsa_sk1"), &k2), 0);
	ASSERT_PTR_NE(k2, عدم);
	ASSERT_INT_EQ(k2->type, کلید_ECDSA_SK_CERT);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 0);
	ASSERT_INT_EQ(sshkey_equal_عوامی(k1, k2), 1);
	TEST_پورا();

	TEST_شروع("ECDSA-SK key hex fingerprint");
	buf = لدو_متن_file("ecdsa_sk1.fp");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, عدم);
	ASSERT_STRING_EQ(cp, (ثابت حرف *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	حرر(cp);
	TEST_پورا();

	TEST_شروع("ECDSA-SK cert hex fingerprint");
	buf = لدو_متن_file("ecdsa_sk1-cert.fp");
	cp = sshkey_fingerprint(k2, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, عدم);
	ASSERT_STRING_EQ(cp, (ثابت حرف *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	حرر(cp);
	sshkey_free(k2);
	TEST_پورا();

	TEST_شروع("ECDSA-SK key bubblebabble fingerprint");
	buf = لدو_متن_file("ecdsa_sk1.fp.bb");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA1, SSH_FP_BUBBLEBABBLE);
	ASSERT_PTR_NE(cp, عدم);
	ASSERT_STRING_EQ(cp, (ثابت حرف *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	حرر(cp);
	TEST_پورا();

	sshkey_free(k1);
#جے_انت

	TEST_شروع("parse Ed25519-SK from private");
	buf = لدو_file("ed25519_sk1");
	ASSERT_INT_EQ(sshkey_parse_نجی_fileblob(buf, "", &k1, عدم), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k1, عدم);
	ASSERT_INT_EQ(k1->type, کلید_ED25519_SK);
	/* XXX check key contents */
	TEST_پورا();

	TEST_شروع("parse Ed25519-SK from private w/ passphrase");
	buf = لدو_file("ed25519_sk1_pw");
	ASSERT_INT_EQ(sshkey_parse_نجی_fileblob(buf,
	    (ثابت حرف *)sshbuf_ptr(pw), &k2, عدم), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k2, عدم);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_پورا();

	TEST_شروع("load Ed25519-SK from public");
	ASSERT_INT_EQ(sshkey_لدو_عوامی(test_انکڑے_file("ed25519_sk1.pub"),
	    &k2, عدم), 0);
	ASSERT_PTR_NE(k2, عدم);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_پورا();

	TEST_شروع("load Ed25519-SK cert");
	ASSERT_INT_EQ(sshkey_لدو_cert(test_انکڑے_file("ed25519_sk1"), &k2), 0);
	ASSERT_PTR_NE(k2, عدم);
	ASSERT_INT_EQ(k2->type, کلید_ED25519_SK_CERT);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 0);
	ASSERT_INT_EQ(sshkey_equal_عوامی(k1, k2), 1);
	TEST_پورا();

	TEST_شروع("Ed25519-SK key hex fingerprint");
	buf = لدو_متن_file("ed25519_sk1.fp");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, عدم);
	ASSERT_STRING_EQ(cp, (ثابت حرف *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	حرر(cp);
	TEST_پورا();

	TEST_شروع("Ed25519-SK cert hex fingerprint");
	buf = لدو_متن_file("ed25519_sk1-cert.fp");
	cp = sshkey_fingerprint(k2, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, عدم);
	ASSERT_STRING_EQ(cp, (ثابت حرف *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	حرر(cp);
	sshkey_free(k2);
	TEST_پورا();

	TEST_شروع("Ed25519-SK key bubblebabble fingerprint");
	buf = لدو_متن_file("ed25519_sk1.fp.bb");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA1, SSH_FP_BUBBLEBABBLE);
	ASSERT_PTR_NE(cp, عدم);
	ASSERT_STRING_EQ(cp, (ثابت حرف *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	حرر(cp);
	TEST_پورا();

	sshkey_free(k1);
#جے_انت /* ENABLE_SK */

	sshbuf_free(pw);

}
