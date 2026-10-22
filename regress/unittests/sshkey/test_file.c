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

#که_تعریف_شوی WITH_OPENSSL
#ضمن <openssl/bn.h>
#ضمن <openssl/ec.h>
#ضمن <openssl/rsa.h>
#ضمن <openssl/objects.h>
#د_که_پای /* WITH_OPENSSL */

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
#که_تعریف_شوی WITH_OPENSSL
	BIGNUM *a, *b, *c;
#د_که_پای
	حرف *cp;

	TEST_پیل("load passphrase");
	pw = بارول_متن_file("pw");
	TEST_بشپړ();


#که_تعریف_شوی WITH_OPENSSL
	TEST_پیل("parse RSA from private");
	buf = بارول_file("rsa_1");
	ASSERT_INT_EQ(sshkey_parse_شخصي_fileblob(buf, "", &k1, عدم), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k1, عدم);
	a = بارول_bignum("rsa_1.param.n");
	b = بارول_bignum("rsa_1.param.p");
	c = بارول_bignum("rsa_1.param.q");
	ASSERT_BIGNUM_EQ(rsa_n(k1), a);
	ASSERT_BIGNUM_EQ(rsa_p(k1), b);
	ASSERT_BIGNUM_EQ(rsa_q(k1), c);
	BN_free(a);
	BN_free(b);
	BN_free(c);
	TEST_بشپړ();

	TEST_پیل("parse RSA from private w/ passphrase");
	buf = بارول_file("rsa_1_pw");
	ASSERT_INT_EQ(sshkey_parse_شخصي_fileblob(buf,
	    (ثابت حرف *)sshbuf_ptr(pw), &k2, عدم), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k2, عدم);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_بشپړ();

	TEST_پیل("parse RSA from new-format");
	buf = بارول_file("rsa_n");
	ASSERT_INT_EQ(sshkey_parse_شخصي_fileblob(buf, "", &k2, عدم), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k2, عدم);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_بشپړ();

	TEST_پیل("parse RSA from new-format w/ passphrase");
	buf = بارول_file("rsa_n_pw");
	ASSERT_INT_EQ(sshkey_parse_شخصي_fileblob(buf,
	    (ثابت حرف *)sshbuf_ptr(pw), &k2, عدم), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k2, عدم);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_بشپړ();

	TEST_پیل("load RSA from public");
	ASSERT_INT_EQ(sshkey_بارول_عامه(test_معلومات_file("rsa_1.pub"), &k2,
	    عدم), 0);
	ASSERT_PTR_NE(k2, عدم);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_بشپړ();

	TEST_پیل("load RSA cert with SHA1 signature");
	ASSERT_INT_EQ(sshkey_بارول_cert(test_معلومات_file("rsa_1_sha1"), &k2), 0);
	ASSERT_PTR_NE(k2, عدم);
	ASSERT_INT_EQ(k2->type, کلی_RSA_CERT);
	ASSERT_INT_EQ(sshkey_equal_عامه(k1, k2), 1);
	ASSERT_STRING_EQ(k2->cert->signature_type, "ssh-rsa");
	sshkey_free(k2);
	TEST_بشپړ();

	TEST_پیل("load RSA cert with SHA512 signature");
	ASSERT_INT_EQ(sshkey_بارول_cert(test_معلومات_file("rsa_1_sha512"), &k2), 0);
	ASSERT_PTR_NE(k2, عدم);
	ASSERT_INT_EQ(k2->type, کلی_RSA_CERT);
	ASSERT_INT_EQ(sshkey_equal_عامه(k1, k2), 1);
	ASSERT_STRING_EQ(k2->cert->signature_type, "rsa-sha2-512");
	sshkey_free(k2);
	TEST_بشپړ();

	TEST_پیل("load RSA cert");
	ASSERT_INT_EQ(sshkey_بارول_cert(test_معلومات_file("rsa_1"), &k2), 0);
	ASSERT_PTR_NE(k2, عدم);
	ASSERT_INT_EQ(k2->type, کلی_RSA_CERT);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 0);
	ASSERT_INT_EQ(sshkey_equal_عامه(k1, k2), 1);
	TEST_بشپړ();

	TEST_پیل("RSA key hex fingerprint");
	buf = بارول_متن_file("rsa_1.fp");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, عدم);
	ASSERT_STRING_EQ(cp, (ثابت حرف *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	حرر(cp);
	TEST_بشپړ();

	TEST_پیل("RSA cert hex fingerprint");
	buf = بارول_متن_file("rsa_1-cert.fp");
	cp = sshkey_fingerprint(k2, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, عدم);
	ASSERT_STRING_EQ(cp, (ثابت حرف *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	حرر(cp);
	sshkey_free(k2);
	TEST_بشپړ();

	TEST_پیل("RSA key bubblebabble fingerprint");
	buf = بارول_متن_file("rsa_1.fp.bb");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA1, SSH_FP_BUBBLEBABBLE);
	ASSERT_PTR_NE(cp, عدم);
	ASSERT_STRING_EQ(cp, (ثابت حرف *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	حرر(cp);
	TEST_بشپړ();

	sshkey_free(k1);


	TEST_پیل("parse ECDSA from private");
	buf = بارول_file("ecdsa_1");
	ASSERT_INT_EQ(sshkey_parse_شخصي_fileblob(buf, "", &k1, عدم), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k1, عدم);
	buf = بارول_متن_file("ecdsa_1.param.curve");
	ASSERT_STRING_EQ((ثابت حرف *)sshbuf_ptr(buf),
	    OBJ_nid2sn(k1->ecdsa_nid));
	sshbuf_free(buf);
#که_نه_تعریف_شوی OPENSSL_IS_BORINGSSL /* lacks EC_POINT_point2bn() */
	a = بارول_bignum("ecdsa_1.param.priv");
	b = بارول_bignum("ecdsa_1.param.pub");
	c = EC_ټکی_point2bn(EC_کلی_get0_ډله(EVP_PKEY_get0_EC_کلی(k1->pkey)),
	    EC_کلی_get0_عامه_کلی(EVP_PKEY_get0_EC_کلی(k1->pkey)),
	    ټکی_CONVERSION_UNCOMPRESSED, عدم, عدم);
	ASSERT_PTR_NE(c, عدم);
	ASSERT_BIGNUM_EQ(
	    EC_کلی_get0_شخصي_کلی(EVP_PKEY_get0_EC_کلی(k1->pkey)), a);
	ASSERT_BIGNUM_EQ(b, c);
	BN_free(a);
	BN_free(b);
	BN_free(c);
#د_که_پای /* OPENSSL_IS_BORINGSSL */
	TEST_بشپړ();

	TEST_پیل("parse ECDSA from private w/ passphrase");
	buf = بارول_file("ecdsa_1_pw");
	ASSERT_INT_EQ(sshkey_parse_شخصي_fileblob(buf,
	    (ثابت حرف *)sshbuf_ptr(pw), &k2, عدم), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k2, عدم);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_بشپړ();

	TEST_پیل("parse ECDSA from new-format");
	buf = بارول_file("ecdsa_n");
	ASSERT_INT_EQ(sshkey_parse_شخصي_fileblob(buf, "", &k2, عدم), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k2, عدم);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_بشپړ();

	TEST_پیل("parse ECDSA from new-format w/ passphrase");
	buf = بارول_file("ecdsa_n_pw");
	ASSERT_INT_EQ(sshkey_parse_شخصي_fileblob(buf,
	    (ثابت حرف *)sshbuf_ptr(pw), &k2, عدم), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k2, عدم);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_بشپړ();

	TEST_پیل("load ECDSA from public");
	ASSERT_INT_EQ(sshkey_بارول_عامه(test_معلومات_file("ecdsa_1.pub"), &k2,
	    عدم), 0);
	ASSERT_PTR_NE(k2, عدم);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_بشپړ();

	TEST_پیل("load ECDSA cert");
	ASSERT_INT_EQ(sshkey_بارول_cert(test_معلومات_file("ecdsa_1"), &k2), 0);
	ASSERT_PTR_NE(k2, عدم);
	ASSERT_INT_EQ(k2->type, کلی_ECDSA_CERT);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 0);
	ASSERT_INT_EQ(sshkey_equal_عامه(k1, k2), 1);
	TEST_بشپړ();

	TEST_پیل("ECDSA key hex fingerprint");
	buf = بارول_متن_file("ecdsa_1.fp");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, عدم);
	ASSERT_STRING_EQ(cp, (ثابت حرف *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	حرر(cp);
	TEST_بشپړ();

	TEST_پیل("ECDSA cert hex fingerprint");
	buf = بارول_متن_file("ecdsa_1-cert.fp");
	cp = sshkey_fingerprint(k2, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, عدم);
	ASSERT_STRING_EQ(cp, (ثابت حرف *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	حرر(cp);
	sshkey_free(k2);
	TEST_بشپړ();

	TEST_پیل("ECDSA key bubblebabble fingerprint");
	buf = بارول_متن_file("ecdsa_1.fp.bb");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA1, SSH_FP_BUBBLEBABBLE);
	ASSERT_PTR_NE(cp, عدم);
	ASSERT_STRING_EQ(cp, (ثابت حرف *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	حرر(cp);
	TEST_بشپړ();

	sshkey_free(k1);
#د_که_پای /* WITH_OPENSSL */

	TEST_پیل("parse Ed25519 from private");
	buf = بارول_file("ed25519_1");
	ASSERT_INT_EQ(sshkey_parse_شخصي_fileblob(buf, "", &k1, عدم), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k1, عدم);
	ASSERT_INT_EQ(k1->type, کلی_ED25519);
	/* XXX check key contents */
	TEST_بشپړ();

	TEST_پیل("parse Ed25519 from private w/ passphrase");
	buf = بارول_file("ed25519_1_pw");
	ASSERT_INT_EQ(sshkey_parse_شخصي_fileblob(buf,
	    (ثابت حرف *)sshbuf_ptr(pw), &k2, عدم), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k2, عدم);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_بشپړ();

	TEST_پیل("load Ed25519 from public");
	ASSERT_INT_EQ(sshkey_بارول_عامه(test_معلومات_file("ed25519_1.pub"), &k2,
	    عدم), 0);
	ASSERT_PTR_NE(k2, عدم);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_بشپړ();

	TEST_پیل("load Ed25519 cert");
	ASSERT_INT_EQ(sshkey_بارول_cert(test_معلومات_file("ed25519_1"), &k2), 0);
	ASSERT_PTR_NE(k2, عدم);
	ASSERT_INT_EQ(k2->type, کلی_ED25519_CERT);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 0);
	ASSERT_INT_EQ(sshkey_equal_عامه(k1, k2), 1);
	TEST_بشپړ();

	TEST_پیل("Ed25519 key hex fingerprint");
	buf = بارول_متن_file("ed25519_1.fp");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, عدم);
	ASSERT_STRING_EQ(cp, (ثابت حرف *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	حرر(cp);
	TEST_بشپړ();

	TEST_پیل("Ed25519 cert hex fingerprint");
	buf = بارول_متن_file("ed25519_1-cert.fp");
	cp = sshkey_fingerprint(k2, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, عدم);
	ASSERT_STRING_EQ(cp, (ثابت حرف *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	حرر(cp);
	sshkey_free(k2);
	TEST_بشپړ();

	TEST_پیل("Ed25519 key bubblebabble fingerprint");
	buf = بارول_متن_file("ed25519_1.fp.bb");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA1, SSH_FP_BUBBLEBABBLE);
	ASSERT_PTR_NE(cp, عدم);
	ASSERT_STRING_EQ(cp, (ثابت حرف *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	حرر(cp);
	TEST_بشپړ();

	sshkey_free(k1);

	TEST_پیل("parse MLDSA44-ED25519 from private");
	buf = بارول_file("mldsa44_ed25519_1");
	ASSERT_INT_EQ(sshkey_parse_شخصي_fileblob(buf, "", &k1, عدم), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k1, عدم);
	ASSERT_INT_EQ(k1->type, کلی_MLDSA44_ED25519);
	TEST_بشپړ();

	TEST_پیل("parse MLDSA44-ED25519 from private w/ passphrase");
	buf = بارول_file("mldsa44_ed25519_1_pw");
	ASSERT_INT_EQ(sshkey_parse_شخصي_fileblob(buf,
	    (ثابت حرف *)sshbuf_ptr(pw), &k2, عدم), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k2, عدم);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_بشپړ();

	TEST_پیل("load MLDSA44-ED25519 from public");
	ASSERT_INT_EQ(sshkey_بارول_عامه(
	    test_معلومات_file("mldsa44_ed25519_1.pub"), &k2, عدم), 0);
	ASSERT_PTR_NE(k2, عدم);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_بشپړ();

	TEST_پیل("load MLDSA44-ED25519 cert");
	ASSERT_INT_EQ(sshkey_بارول_cert(
	    test_معلومات_file("mldsa44_ed25519_1"), &k2), 0);
	ASSERT_PTR_NE(k2, عدم);
	ASSERT_INT_EQ(k2->type, کلی_MLDSA44_ED25519_CERT);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 0);
	ASSERT_INT_EQ(sshkey_equal_عامه(k1, k2), 1);
	TEST_بشپړ();

	TEST_پیل("MLDSA44-ED25519 key hex fingerprint");
	buf = بارول_متن_file("mldsa44_ed25519_1.fp");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, عدم);
	ASSERT_STRING_EQ(cp, (ثابت حرف *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	حرر(cp);
	TEST_بشپړ();

	TEST_پیل("MLDSA44-ED25519 cert hex fingerprint");
	buf = بارول_متن_file("mldsa44_ed25519_1-cert.fp");
	cp = sshkey_fingerprint(k2, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, عدم);
	ASSERT_STRING_EQ(cp, (ثابت حرف *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	حرر(cp);
	sshkey_free(k2);
	TEST_بشپړ();

	TEST_پیل("MLDSA44-ED25519 key bubblebabble fingerprint");
	buf = بارول_متن_file("mldsa44_ed25519_1.fp.bb");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA1, SSH_FP_BUBBLEBABBLE);
	ASSERT_PTR_NE(cp, عدم);
	ASSERT_STRING_EQ(cp, (ثابت حرف *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	حرر(cp);
	TEST_بشپړ();

	sshkey_free(k1);

#که_تعریف_شوی ENABLE_SK
#إذا defined(WITH_OPENSSL)
	TEST_پیل("parse ECDSA-SK from private");
	buf = بارول_file("ecdsa_sk1");
	ASSERT_INT_EQ(sshkey_parse_شخصي_fileblob(buf, "", &k1, عدم), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k1, عدم);
	ASSERT_INT_EQ(k1->type, کلی_ECDSA_SK);
	TEST_بشپړ();

	TEST_پیل("parse ECDSA-SK from private w/ passphrase");
	buf = بارول_file("ecdsa_sk1_pw");
	ASSERT_INT_EQ(sshkey_parse_شخصي_fileblob(buf,
	    (ثابت حرف *)sshbuf_ptr(pw), &k2, عدم), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k2, عدم);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_بشپړ();

	TEST_پیل("load ECDSA-SK from public");
	ASSERT_INT_EQ(sshkey_بارول_عامه(test_معلومات_file("ecdsa_sk1.pub"), &k2,
	    عدم), 0);
	ASSERT_PTR_NE(k2, عدم);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_بشپړ();

	TEST_پیل("load ECDSA-SK cert");
	ASSERT_INT_EQ(sshkey_بارول_cert(test_معلومات_file("ecdsa_sk1"), &k2), 0);
	ASSERT_PTR_NE(k2, عدم);
	ASSERT_INT_EQ(k2->type, کلی_ECDSA_SK_CERT);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 0);
	ASSERT_INT_EQ(sshkey_equal_عامه(k1, k2), 1);
	TEST_بشپړ();

	TEST_پیل("ECDSA-SK key hex fingerprint");
	buf = بارول_متن_file("ecdsa_sk1.fp");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, عدم);
	ASSERT_STRING_EQ(cp, (ثابت حرف *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	حرر(cp);
	TEST_بشپړ();

	TEST_پیل("ECDSA-SK cert hex fingerprint");
	buf = بارول_متن_file("ecdsa_sk1-cert.fp");
	cp = sshkey_fingerprint(k2, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, عدم);
	ASSERT_STRING_EQ(cp, (ثابت حرف *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	حرر(cp);
	sshkey_free(k2);
	TEST_بشپړ();

	TEST_پیل("ECDSA-SK key bubblebabble fingerprint");
	buf = بارول_متن_file("ecdsa_sk1.fp.bb");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA1, SSH_FP_BUBBLEBABBLE);
	ASSERT_PTR_NE(cp, عدم);
	ASSERT_STRING_EQ(cp, (ثابت حرف *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	حرر(cp);
	TEST_بشپړ();

	sshkey_free(k1);
#د_که_پای

	TEST_پیل("parse Ed25519-SK from private");
	buf = بارول_file("ed25519_sk1");
	ASSERT_INT_EQ(sshkey_parse_شخصي_fileblob(buf, "", &k1, عدم), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k1, عدم);
	ASSERT_INT_EQ(k1->type, کلی_ED25519_SK);
	/* XXX check key contents */
	TEST_بشپړ();

	TEST_پیل("parse Ed25519-SK from private w/ passphrase");
	buf = بارول_file("ed25519_sk1_pw");
	ASSERT_INT_EQ(sshkey_parse_شخصي_fileblob(buf,
	    (ثابت حرف *)sshbuf_ptr(pw), &k2, عدم), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k2, عدم);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_بشپړ();

	TEST_پیل("load Ed25519-SK from public");
	ASSERT_INT_EQ(sshkey_بارول_عامه(test_معلومات_file("ed25519_sk1.pub"),
	    &k2, عدم), 0);
	ASSERT_PTR_NE(k2, عدم);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_بشپړ();

	TEST_پیل("load Ed25519-SK cert");
	ASSERT_INT_EQ(sshkey_بارول_cert(test_معلومات_file("ed25519_sk1"), &k2), 0);
	ASSERT_PTR_NE(k2, عدم);
	ASSERT_INT_EQ(k2->type, کلی_ED25519_SK_CERT);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 0);
	ASSERT_INT_EQ(sshkey_equal_عامه(k1, k2), 1);
	TEST_بشپړ();

	TEST_پیل("Ed25519-SK key hex fingerprint");
	buf = بارول_متن_file("ed25519_sk1.fp");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, عدم);
	ASSERT_STRING_EQ(cp, (ثابت حرف *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	حرر(cp);
	TEST_بشپړ();

	TEST_پیل("Ed25519-SK cert hex fingerprint");
	buf = بارول_متن_file("ed25519_sk1-cert.fp");
	cp = sshkey_fingerprint(k2, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, عدم);
	ASSERT_STRING_EQ(cp, (ثابت حرف *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	حرر(cp);
	sshkey_free(k2);
	TEST_بشپړ();

	TEST_پیل("Ed25519-SK key bubblebabble fingerprint");
	buf = بارول_متن_file("ed25519_sk1.fp.bb");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA1, SSH_FP_BUBBLEBABBLE);
	ASSERT_PTR_NE(cp, عدم);
	ASSERT_STRING_EQ(cp, (ثابت حرف *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	حرر(cp);
	TEST_بشپړ();

	sshkey_free(k1);
#د_که_پای /* ENABLE_SK */

	sshbuf_free(pw);

}
