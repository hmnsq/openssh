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

#جيڪڏهن_وصف_ٿيل WITH_OPENSSL
#ضمن <openssl/bn.h>
#ضمن <openssl/ec.h>
#ضمن <openssl/rsa.h>
#ضمن <openssl/objects.h>
#جيڪڏهن_پورو /* WITH_OPENSSL */

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
#جيڪڏهن_وصف_ٿيل WITH_OPENSSL
	BIGNUM *a, *b, *c;
#جيڪڏهن_پورو
	حرف *cp;

	TEST_شروعات("load passphrase");
	pw = ڀريو_متن_file("pw");
	TEST_پورو();


#جيڪڏهن_وصف_ٿيل WITH_OPENSSL
	TEST_شروعات("parse RSA from private");
	buf = ڀريو_file("rsa_1");
	ASSERT_INT_EQ(sshkey_parse_ذاتي_fileblob(buf, "", &k1, عدم), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k1, عدم);
	a = ڀريو_bignum("rsa_1.param.n");
	b = ڀريو_bignum("rsa_1.param.p");
	c = ڀريو_bignum("rsa_1.param.q");
	ASSERT_BIGNUM_EQ(rsa_n(k1), a);
	ASSERT_BIGNUM_EQ(rsa_p(k1), b);
	ASSERT_BIGNUM_EQ(rsa_q(k1), c);
	BN_free(a);
	BN_free(b);
	BN_free(c);
	TEST_پورو();

	TEST_شروعات("parse RSA from private w/ passphrase");
	buf = ڀريو_file("rsa_1_pw");
	ASSERT_INT_EQ(sshkey_parse_ذاتي_fileblob(buf,
	    (ثابت حرف *)sshbuf_ptr(pw), &k2, عدم), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k2, عدم);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_پورو();

	TEST_شروعات("parse RSA from new-format");
	buf = ڀريو_file("rsa_n");
	ASSERT_INT_EQ(sshkey_parse_ذاتي_fileblob(buf, "", &k2, عدم), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k2, عدم);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_پورو();

	TEST_شروعات("parse RSA from new-format w/ passphrase");
	buf = ڀريو_file("rsa_n_pw");
	ASSERT_INT_EQ(sshkey_parse_ذاتي_fileblob(buf,
	    (ثابت حرف *)sshbuf_ptr(pw), &k2, عدم), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k2, عدم);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_پورو();

	TEST_شروعات("load RSA from public");
	ASSERT_INT_EQ(sshkey_ڀريو_عوامي(test_معلومات_file("rsa_1.pub"), &k2,
	    عدم), 0);
	ASSERT_PTR_NE(k2, عدم);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_پورو();

	TEST_شروعات("load RSA cert with SHA1 signature");
	ASSERT_INT_EQ(sshkey_ڀريو_cert(test_معلومات_file("rsa_1_sha1"), &k2), 0);
	ASSERT_PTR_NE(k2, عدم);
	ASSERT_INT_EQ(k2->type, ڪنجي_RSA_CERT);
	ASSERT_INT_EQ(sshkey_equal_عوامي(k1, k2), 1);
	ASSERT_STRING_EQ(k2->cert->signature_type, "ssh-rsa");
	sshkey_free(k2);
	TEST_پورو();

	TEST_شروعات("load RSA cert with SHA512 signature");
	ASSERT_INT_EQ(sshkey_ڀريو_cert(test_معلومات_file("rsa_1_sha512"), &k2), 0);
	ASSERT_PTR_NE(k2, عدم);
	ASSERT_INT_EQ(k2->type, ڪنجي_RSA_CERT);
	ASSERT_INT_EQ(sshkey_equal_عوامي(k1, k2), 1);
	ASSERT_STRING_EQ(k2->cert->signature_type, "rsa-sha2-512");
	sshkey_free(k2);
	TEST_پورو();

	TEST_شروعات("load RSA cert");
	ASSERT_INT_EQ(sshkey_ڀريو_cert(test_معلومات_file("rsa_1"), &k2), 0);
	ASSERT_PTR_NE(k2, عدم);
	ASSERT_INT_EQ(k2->type, ڪنجي_RSA_CERT);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 0);
	ASSERT_INT_EQ(sshkey_equal_عوامي(k1, k2), 1);
	TEST_پورو();

	TEST_شروعات("RSA key hex fingerprint");
	buf = ڀريو_متن_file("rsa_1.fp");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, عدم);
	ASSERT_STRING_EQ(cp, (ثابت حرف *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	حرر(cp);
	TEST_پورو();

	TEST_شروعات("RSA cert hex fingerprint");
	buf = ڀريو_متن_file("rsa_1-cert.fp");
	cp = sshkey_fingerprint(k2, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, عدم);
	ASSERT_STRING_EQ(cp, (ثابت حرف *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	حرر(cp);
	sshkey_free(k2);
	TEST_پورو();

	TEST_شروعات("RSA key bubblebabble fingerprint");
	buf = ڀريو_متن_file("rsa_1.fp.bb");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA1, SSH_FP_BUBBLEBABBLE);
	ASSERT_PTR_NE(cp, عدم);
	ASSERT_STRING_EQ(cp, (ثابت حرف *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	حرر(cp);
	TEST_پورو();

	sshkey_free(k1);


	TEST_شروعات("parse ECDSA from private");
	buf = ڀريو_file("ecdsa_1");
	ASSERT_INT_EQ(sshkey_parse_ذاتي_fileblob(buf, "", &k1, عدم), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k1, عدم);
	buf = ڀريو_متن_file("ecdsa_1.param.curve");
	ASSERT_STRING_EQ((ثابت حرف *)sshbuf_ptr(buf),
	    OBJ_nid2sn(k1->ecdsa_nid));
	sshbuf_free(buf);
#جيڪڏهن_وصف_نه_ٿيل OPENSSL_IS_BORINGSSL /* lacks EC_POINT_point2bn() */
	a = ڀريو_bignum("ecdsa_1.param.priv");
	b = ڀريو_bignum("ecdsa_1.param.pub");
	c = EC_نقطو_point2bn(EC_ڪنجي_get0_گروهه(EVP_PKEY_get0_EC_ڪنجي(k1->pkey)),
	    EC_ڪنجي_get0_عوامي_ڪنجي(EVP_PKEY_get0_EC_ڪنجي(k1->pkey)),
	    نقطو_CONVERSION_UNCOMPRESSED, عدم, عدم);
	ASSERT_PTR_NE(c, عدم);
	ASSERT_BIGNUM_EQ(
	    EC_ڪنجي_get0_ذاتي_ڪنجي(EVP_PKEY_get0_EC_ڪنجي(k1->pkey)), a);
	ASSERT_BIGNUM_EQ(b, c);
	BN_free(a);
	BN_free(b);
	BN_free(c);
#جيڪڏهن_پورو /* OPENSSL_IS_BORINGSSL */
	TEST_پورو();

	TEST_شروعات("parse ECDSA from private w/ passphrase");
	buf = ڀريو_file("ecdsa_1_pw");
	ASSERT_INT_EQ(sshkey_parse_ذاتي_fileblob(buf,
	    (ثابت حرف *)sshbuf_ptr(pw), &k2, عدم), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k2, عدم);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_پورو();

	TEST_شروعات("parse ECDSA from new-format");
	buf = ڀريو_file("ecdsa_n");
	ASSERT_INT_EQ(sshkey_parse_ذاتي_fileblob(buf, "", &k2, عدم), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k2, عدم);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_پورو();

	TEST_شروعات("parse ECDSA from new-format w/ passphrase");
	buf = ڀريو_file("ecdsa_n_pw");
	ASSERT_INT_EQ(sshkey_parse_ذاتي_fileblob(buf,
	    (ثابت حرف *)sshbuf_ptr(pw), &k2, عدم), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k2, عدم);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_پورو();

	TEST_شروعات("load ECDSA from public");
	ASSERT_INT_EQ(sshkey_ڀريو_عوامي(test_معلومات_file("ecdsa_1.pub"), &k2,
	    عدم), 0);
	ASSERT_PTR_NE(k2, عدم);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_پورو();

	TEST_شروعات("load ECDSA cert");
	ASSERT_INT_EQ(sshkey_ڀريو_cert(test_معلومات_file("ecdsa_1"), &k2), 0);
	ASSERT_PTR_NE(k2, عدم);
	ASSERT_INT_EQ(k2->type, ڪنجي_ECDSA_CERT);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 0);
	ASSERT_INT_EQ(sshkey_equal_عوامي(k1, k2), 1);
	TEST_پورو();

	TEST_شروعات("ECDSA key hex fingerprint");
	buf = ڀريو_متن_file("ecdsa_1.fp");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, عدم);
	ASSERT_STRING_EQ(cp, (ثابت حرف *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	حرر(cp);
	TEST_پورو();

	TEST_شروعات("ECDSA cert hex fingerprint");
	buf = ڀريو_متن_file("ecdsa_1-cert.fp");
	cp = sshkey_fingerprint(k2, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, عدم);
	ASSERT_STRING_EQ(cp, (ثابت حرف *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	حرر(cp);
	sshkey_free(k2);
	TEST_پورو();

	TEST_شروعات("ECDSA key bubblebabble fingerprint");
	buf = ڀريو_متن_file("ecdsa_1.fp.bb");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA1, SSH_FP_BUBBLEBABBLE);
	ASSERT_PTR_NE(cp, عدم);
	ASSERT_STRING_EQ(cp, (ثابت حرف *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	حرر(cp);
	TEST_پورو();

	sshkey_free(k1);
#جيڪڏهن_پورو /* WITH_OPENSSL */

	TEST_شروعات("parse Ed25519 from private");
	buf = ڀريو_file("ed25519_1");
	ASSERT_INT_EQ(sshkey_parse_ذاتي_fileblob(buf, "", &k1, عدم), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k1, عدم);
	ASSERT_INT_EQ(k1->type, ڪنجي_ED25519);
	/* XXX check key contents */
	TEST_پورو();

	TEST_شروعات("parse Ed25519 from private w/ passphrase");
	buf = ڀريو_file("ed25519_1_pw");
	ASSERT_INT_EQ(sshkey_parse_ذاتي_fileblob(buf,
	    (ثابت حرف *)sshbuf_ptr(pw), &k2, عدم), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k2, عدم);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_پورو();

	TEST_شروعات("load Ed25519 from public");
	ASSERT_INT_EQ(sshkey_ڀريو_عوامي(test_معلومات_file("ed25519_1.pub"), &k2,
	    عدم), 0);
	ASSERT_PTR_NE(k2, عدم);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_پورو();

	TEST_شروعات("load Ed25519 cert");
	ASSERT_INT_EQ(sshkey_ڀريو_cert(test_معلومات_file("ed25519_1"), &k2), 0);
	ASSERT_PTR_NE(k2, عدم);
	ASSERT_INT_EQ(k2->type, ڪنجي_ED25519_CERT);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 0);
	ASSERT_INT_EQ(sshkey_equal_عوامي(k1, k2), 1);
	TEST_پورو();

	TEST_شروعات("Ed25519 key hex fingerprint");
	buf = ڀريو_متن_file("ed25519_1.fp");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, عدم);
	ASSERT_STRING_EQ(cp, (ثابت حرف *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	حرر(cp);
	TEST_پورو();

	TEST_شروعات("Ed25519 cert hex fingerprint");
	buf = ڀريو_متن_file("ed25519_1-cert.fp");
	cp = sshkey_fingerprint(k2, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, عدم);
	ASSERT_STRING_EQ(cp, (ثابت حرف *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	حرر(cp);
	sshkey_free(k2);
	TEST_پورو();

	TEST_شروعات("Ed25519 key bubblebabble fingerprint");
	buf = ڀريو_متن_file("ed25519_1.fp.bb");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA1, SSH_FP_BUBBLEBABBLE);
	ASSERT_PTR_NE(cp, عدم);
	ASSERT_STRING_EQ(cp, (ثابت حرف *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	حرر(cp);
	TEST_پورو();

	sshkey_free(k1);

	TEST_شروعات("parse MLDSA44-ED25519 from private");
	buf = ڀريو_file("mldsa44_ed25519_1");
	ASSERT_INT_EQ(sshkey_parse_ذاتي_fileblob(buf, "", &k1, عدم), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k1, عدم);
	ASSERT_INT_EQ(k1->type, ڪنجي_MLDSA44_ED25519);
	TEST_پورو();

	TEST_شروعات("parse MLDSA44-ED25519 from private w/ passphrase");
	buf = ڀريو_file("mldsa44_ed25519_1_pw");
	ASSERT_INT_EQ(sshkey_parse_ذاتي_fileblob(buf,
	    (ثابت حرف *)sshbuf_ptr(pw), &k2, عدم), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k2, عدم);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_پورو();

	TEST_شروعات("load MLDSA44-ED25519 from public");
	ASSERT_INT_EQ(sshkey_ڀريو_عوامي(
	    test_معلومات_file("mldsa44_ed25519_1.pub"), &k2, عدم), 0);
	ASSERT_PTR_NE(k2, عدم);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_پورو();

	TEST_شروعات("load MLDSA44-ED25519 cert");
	ASSERT_INT_EQ(sshkey_ڀريو_cert(
	    test_معلومات_file("mldsa44_ed25519_1"), &k2), 0);
	ASSERT_PTR_NE(k2, عدم);
	ASSERT_INT_EQ(k2->type, ڪنجي_MLDSA44_ED25519_CERT);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 0);
	ASSERT_INT_EQ(sshkey_equal_عوامي(k1, k2), 1);
	TEST_پورو();

	TEST_شروعات("MLDSA44-ED25519 key hex fingerprint");
	buf = ڀريو_متن_file("mldsa44_ed25519_1.fp");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, عدم);
	ASSERT_STRING_EQ(cp, (ثابت حرف *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	حرر(cp);
	TEST_پورو();

	TEST_شروعات("MLDSA44-ED25519 cert hex fingerprint");
	buf = ڀريو_متن_file("mldsa44_ed25519_1-cert.fp");
	cp = sshkey_fingerprint(k2, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, عدم);
	ASSERT_STRING_EQ(cp, (ثابت حرف *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	حرر(cp);
	sshkey_free(k2);
	TEST_پورو();

	TEST_شروعات("MLDSA44-ED25519 key bubblebabble fingerprint");
	buf = ڀريو_متن_file("mldsa44_ed25519_1.fp.bb");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA1, SSH_FP_BUBBLEBABBLE);
	ASSERT_PTR_NE(cp, عدم);
	ASSERT_STRING_EQ(cp, (ثابت حرف *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	حرر(cp);
	TEST_پورو();

	sshkey_free(k1);

#جيڪڏهن_وصف_ٿيل ENABLE_SK
#إذا defined(WITH_OPENSSL)
	TEST_شروعات("parse ECDSA-SK from private");
	buf = ڀريو_file("ecdsa_sk1");
	ASSERT_INT_EQ(sshkey_parse_ذاتي_fileblob(buf, "", &k1, عدم), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k1, عدم);
	ASSERT_INT_EQ(k1->type, ڪنجي_ECDSA_SK);
	TEST_پورو();

	TEST_شروعات("parse ECDSA-SK from private w/ passphrase");
	buf = ڀريو_file("ecdsa_sk1_pw");
	ASSERT_INT_EQ(sshkey_parse_ذاتي_fileblob(buf,
	    (ثابت حرف *)sshbuf_ptr(pw), &k2, عدم), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k2, عدم);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_پورو();

	TEST_شروعات("load ECDSA-SK from public");
	ASSERT_INT_EQ(sshkey_ڀريو_عوامي(test_معلومات_file("ecdsa_sk1.pub"), &k2,
	    عدم), 0);
	ASSERT_PTR_NE(k2, عدم);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_پورو();

	TEST_شروعات("load ECDSA-SK cert");
	ASSERT_INT_EQ(sshkey_ڀريو_cert(test_معلومات_file("ecdsa_sk1"), &k2), 0);
	ASSERT_PTR_NE(k2, عدم);
	ASSERT_INT_EQ(k2->type, ڪنجي_ECDSA_SK_CERT);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 0);
	ASSERT_INT_EQ(sshkey_equal_عوامي(k1, k2), 1);
	TEST_پورو();

	TEST_شروعات("ECDSA-SK key hex fingerprint");
	buf = ڀريو_متن_file("ecdsa_sk1.fp");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, عدم);
	ASSERT_STRING_EQ(cp, (ثابت حرف *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	حرر(cp);
	TEST_پورو();

	TEST_شروعات("ECDSA-SK cert hex fingerprint");
	buf = ڀريو_متن_file("ecdsa_sk1-cert.fp");
	cp = sshkey_fingerprint(k2, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, عدم);
	ASSERT_STRING_EQ(cp, (ثابت حرف *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	حرر(cp);
	sshkey_free(k2);
	TEST_پورو();

	TEST_شروعات("ECDSA-SK key bubblebabble fingerprint");
	buf = ڀريو_متن_file("ecdsa_sk1.fp.bb");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA1, SSH_FP_BUBBLEBABBLE);
	ASSERT_PTR_NE(cp, عدم);
	ASSERT_STRING_EQ(cp, (ثابت حرف *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	حرر(cp);
	TEST_پورو();

	sshkey_free(k1);
#جيڪڏهن_پورو

	TEST_شروعات("parse Ed25519-SK from private");
	buf = ڀريو_file("ed25519_sk1");
	ASSERT_INT_EQ(sshkey_parse_ذاتي_fileblob(buf, "", &k1, عدم), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k1, عدم);
	ASSERT_INT_EQ(k1->type, ڪنجي_ED25519_SK);
	/* XXX check key contents */
	TEST_پورو();

	TEST_شروعات("parse Ed25519-SK from private w/ passphrase");
	buf = ڀريو_file("ed25519_sk1_pw");
	ASSERT_INT_EQ(sshkey_parse_ذاتي_fileblob(buf,
	    (ثابت حرف *)sshbuf_ptr(pw), &k2, عدم), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k2, عدم);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_پورو();

	TEST_شروعات("load Ed25519-SK from public");
	ASSERT_INT_EQ(sshkey_ڀريو_عوامي(test_معلومات_file("ed25519_sk1.pub"),
	    &k2, عدم), 0);
	ASSERT_PTR_NE(k2, عدم);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_پورو();

	TEST_شروعات("load Ed25519-SK cert");
	ASSERT_INT_EQ(sshkey_ڀريو_cert(test_معلومات_file("ed25519_sk1"), &k2), 0);
	ASSERT_PTR_NE(k2, عدم);
	ASSERT_INT_EQ(k2->type, ڪنجي_ED25519_SK_CERT);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 0);
	ASSERT_INT_EQ(sshkey_equal_عوامي(k1, k2), 1);
	TEST_پورو();

	TEST_شروعات("Ed25519-SK key hex fingerprint");
	buf = ڀريو_متن_file("ed25519_sk1.fp");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, عدم);
	ASSERT_STRING_EQ(cp, (ثابت حرف *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	حرر(cp);
	TEST_پورو();

	TEST_شروعات("Ed25519-SK cert hex fingerprint");
	buf = ڀريو_متن_file("ed25519_sk1-cert.fp");
	cp = sshkey_fingerprint(k2, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, عدم);
	ASSERT_STRING_EQ(cp, (ثابت حرف *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	حرر(cp);
	sshkey_free(k2);
	TEST_پورو();

	TEST_شروعات("Ed25519-SK key bubblebabble fingerprint");
	buf = ڀريو_متن_file("ed25519_sk1.fp.bb");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA1, SSH_FP_BUBBLEBABBLE);
	ASSERT_PTR_NE(cp, عدم);
	ASSERT_STRING_EQ(cp, (ثابت حرف *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	حرر(cp);
	TEST_پورو();

	sshkey_free(k1);
#جيڪڏهن_پورو /* ENABLE_SK */

	sshbuf_free(pw);

}
