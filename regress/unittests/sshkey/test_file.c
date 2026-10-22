/* 	$OpenBSD: test_file.c,v 1.14 2026/06/14 04:08:06 djm Exp $ */
/*
 * Regress test for sshkey.h key management API
 *
 * Placed in the public domain
 */

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/stat.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <fcntl.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdint.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/bn.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/ec.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/rsa.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/objects.h>
#ਜੇ_ਅੰਤ /* WITH_OPENSSL */

#ਅਨ੍ਤਰ੍ਭਾਵ "../test_helper/test_helper.h"

#ਅਨ੍ਤਰ੍ਭਾਵ "ssherr.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "authfile.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshkey.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshbuf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "digest.h"

#ਅਨ੍ਤਰ੍ਭਾਵ "common.h"

ਖਾਲੀ sshkey_file_tests(ਖਾਲੀ);

ਖਾਲੀ
sshkey_file_tests(ਖਾਲੀ)
{
	ਬਣਤਰ sshkey *k1, *k2;
	ਬਣਤਰ sshbuf *buf, *pw;
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
	BIGNUM *a, *b, *c;
#ਜੇ_ਅੰਤ
	ਅੱਖਰ *cp;

	TEST_ਸ਼ੁਰੂ("load passphrase");
	pw = ਲੱਦੋ_ਪਾਠ_file("pw");
	TEST_ਪੂਰਾ();


#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
	TEST_ਸ਼ੁਰੂ("parse RSA from private");
	buf = ਲੱਦੋ_file("rsa_1");
	ASSERT_INT_EQ(sshkey_parse_ਨਿੱਜੀ_fileblob(buf, "", &k1, ਨਿਰਾ), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k1, ਨਿਰਾ);
	a = ਲੱਦੋ_bignum("rsa_1.param.n");
	b = ਲੱਦੋ_bignum("rsa_1.param.p");
	c = ਲੱਦੋ_bignum("rsa_1.param.q");
	ASSERT_BIGNUM_EQ(rsa_n(k1), a);
	ASSERT_BIGNUM_EQ(rsa_p(k1), b);
	ASSERT_BIGNUM_EQ(rsa_q(k1), c);
	BN_free(a);
	BN_free(b);
	BN_free(c);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("parse RSA from private w/ passphrase");
	buf = ਲੱਦੋ_file("rsa_1_pw");
	ASSERT_INT_EQ(sshkey_parse_ਨਿੱਜੀ_fileblob(buf,
	    (ਅਚਲ ਅੱਖਰ *)sshbuf_ptr(pw), &k2, ਨਿਰਾ), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k2, ਨਿਰਾ);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("parse RSA from new-format");
	buf = ਲੱਦੋ_file("rsa_n");
	ASSERT_INT_EQ(sshkey_parse_ਨਿੱਜੀ_fileblob(buf, "", &k2, ਨਿਰਾ), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k2, ਨਿਰਾ);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("parse RSA from new-format w/ passphrase");
	buf = ਲੱਦੋ_file("rsa_n_pw");
	ASSERT_INT_EQ(sshkey_parse_ਨਿੱਜੀ_fileblob(buf,
	    (ਅਚਲ ਅੱਖਰ *)sshbuf_ptr(pw), &k2, ਨਿਰਾ), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k2, ਨਿਰਾ);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("load RSA from public");
	ASSERT_INT_EQ(sshkey_ਲੱਦੋ_ਜਨਤਕ(test_ਅੰਕੜੇ_file("rsa_1.pub"), &k2,
	    ਨਿਰਾ), 0);
	ASSERT_PTR_NE(k2, ਨਿਰਾ);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("load RSA cert with SHA1 signature");
	ASSERT_INT_EQ(sshkey_ਲੱਦੋ_cert(test_ਅੰਕੜੇ_file("rsa_1_sha1"), &k2), 0);
	ASSERT_PTR_NE(k2, ਨਿਰਾ);
	ASSERT_INT_EQ(k2->type, ਕੁੰਜੀ_RSA_CERT);
	ASSERT_INT_EQ(sshkey_equal_ਜਨਤਕ(k1, k2), 1);
	ASSERT_STRING_EQ(k2->cert->signature_type, "ssh-rsa");
	sshkey_free(k2);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("load RSA cert with SHA512 signature");
	ASSERT_INT_EQ(sshkey_ਲੱਦੋ_cert(test_ਅੰਕੜੇ_file("rsa_1_sha512"), &k2), 0);
	ASSERT_PTR_NE(k2, ਨਿਰਾ);
	ASSERT_INT_EQ(k2->type, ਕੁੰਜੀ_RSA_CERT);
	ASSERT_INT_EQ(sshkey_equal_ਜਨਤਕ(k1, k2), 1);
	ASSERT_STRING_EQ(k2->cert->signature_type, "rsa-sha2-512");
	sshkey_free(k2);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("load RSA cert");
	ASSERT_INT_EQ(sshkey_ਲੱਦੋ_cert(test_ਅੰਕੜੇ_file("rsa_1"), &k2), 0);
	ASSERT_PTR_NE(k2, ਨਿਰਾ);
	ASSERT_INT_EQ(k2->type, ਕੁੰਜੀ_RSA_CERT);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 0);
	ASSERT_INT_EQ(sshkey_equal_ਜਨਤਕ(k1, k2), 1);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("RSA key hex fingerprint");
	buf = ਲੱਦੋ_ਪਾਠ_file("rsa_1.fp");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, ਨਿਰਾ);
	ASSERT_STRING_EQ(cp, (ਅਚਲ ਅੱਖਰ *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	ਮੁਕਤ(cp);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("RSA cert hex fingerprint");
	buf = ਲੱਦੋ_ਪਾਠ_file("rsa_1-cert.fp");
	cp = sshkey_fingerprint(k2, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, ਨਿਰਾ);
	ASSERT_STRING_EQ(cp, (ਅਚਲ ਅੱਖਰ *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	ਮੁਕਤ(cp);
	sshkey_free(k2);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("RSA key bubblebabble fingerprint");
	buf = ਲੱਦੋ_ਪਾਠ_file("rsa_1.fp.bb");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA1, SSH_FP_BUBBLEBABBLE);
	ASSERT_PTR_NE(cp, ਨਿਰਾ);
	ASSERT_STRING_EQ(cp, (ਅਚਲ ਅੱਖਰ *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	ਮੁਕਤ(cp);
	TEST_ਪੂਰਾ();

	sshkey_free(k1);


	TEST_ਸ਼ੁਰੂ("parse ECDSA from private");
	buf = ਲੱਦੋ_file("ecdsa_1");
	ASSERT_INT_EQ(sshkey_parse_ਨਿੱਜੀ_fileblob(buf, "", &k1, ਨਿਰਾ), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k1, ਨਿਰਾ);
	buf = ਲੱਦੋ_ਪਾਠ_file("ecdsa_1.param.curve");
	ASSERT_STRING_EQ((ਅਚਲ ਅੱਖਰ *)sshbuf_ptr(buf),
	    OBJ_nid2sn(k1->ecdsa_nid));
	sshbuf_free(buf);
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ OPENSSL_IS_BORINGSSL /* lacks EC_POINT_point2bn() */
	a = ਲੱਦੋ_bignum("ecdsa_1.param.priv");
	b = ਲੱਦੋ_bignum("ecdsa_1.param.pub");
	c = EC_ਬਿੰਦੂ_point2bn(EC_ਕੁੰਜੀ_get0_ਸਮੂਹ(EVP_PKEY_get0_EC_ਕੁੰਜੀ(k1->pkey)),
	    EC_ਕੁੰਜੀ_get0_ਜਨਤਕ_ਕੁੰਜੀ(EVP_PKEY_get0_EC_ਕੁੰਜੀ(k1->pkey)),
	    ਬਿੰਦੂ_CONVERSION_UNCOMPRESSED, ਨਿਰਾ, ਨਿਰਾ);
	ASSERT_PTR_NE(c, ਨਿਰਾ);
	ASSERT_BIGNUM_EQ(
	    EC_ਕੁੰਜੀ_get0_ਨਿੱਜੀ_ਕੁੰਜੀ(EVP_PKEY_get0_EC_ਕੁੰਜੀ(k1->pkey)), a);
	ASSERT_BIGNUM_EQ(b, c);
	BN_free(a);
	BN_free(b);
	BN_free(c);
#ਜੇ_ਅੰਤ /* OPENSSL_IS_BORINGSSL */
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("parse ECDSA from private w/ passphrase");
	buf = ਲੱਦੋ_file("ecdsa_1_pw");
	ASSERT_INT_EQ(sshkey_parse_ਨਿੱਜੀ_fileblob(buf,
	    (ਅਚਲ ਅੱਖਰ *)sshbuf_ptr(pw), &k2, ਨਿਰਾ), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k2, ਨਿਰਾ);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("parse ECDSA from new-format");
	buf = ਲੱਦੋ_file("ecdsa_n");
	ASSERT_INT_EQ(sshkey_parse_ਨਿੱਜੀ_fileblob(buf, "", &k2, ਨਿਰਾ), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k2, ਨਿਰਾ);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("parse ECDSA from new-format w/ passphrase");
	buf = ਲੱਦੋ_file("ecdsa_n_pw");
	ASSERT_INT_EQ(sshkey_parse_ਨਿੱਜੀ_fileblob(buf,
	    (ਅਚਲ ਅੱਖਰ *)sshbuf_ptr(pw), &k2, ਨਿਰਾ), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k2, ਨਿਰਾ);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("load ECDSA from public");
	ASSERT_INT_EQ(sshkey_ਲੱਦੋ_ਜਨਤਕ(test_ਅੰਕੜੇ_file("ecdsa_1.pub"), &k2,
	    ਨਿਰਾ), 0);
	ASSERT_PTR_NE(k2, ਨਿਰਾ);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("load ECDSA cert");
	ASSERT_INT_EQ(sshkey_ਲੱਦੋ_cert(test_ਅੰਕੜੇ_file("ecdsa_1"), &k2), 0);
	ASSERT_PTR_NE(k2, ਨਿਰਾ);
	ASSERT_INT_EQ(k2->type, ਕੁੰਜੀ_ECDSA_CERT);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 0);
	ASSERT_INT_EQ(sshkey_equal_ਜਨਤਕ(k1, k2), 1);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("ECDSA key hex fingerprint");
	buf = ਲੱਦੋ_ਪਾਠ_file("ecdsa_1.fp");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, ਨਿਰਾ);
	ASSERT_STRING_EQ(cp, (ਅਚਲ ਅੱਖਰ *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	ਮੁਕਤ(cp);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("ECDSA cert hex fingerprint");
	buf = ਲੱਦੋ_ਪਾਠ_file("ecdsa_1-cert.fp");
	cp = sshkey_fingerprint(k2, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, ਨਿਰਾ);
	ASSERT_STRING_EQ(cp, (ਅਚਲ ਅੱਖਰ *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	ਮੁਕਤ(cp);
	sshkey_free(k2);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("ECDSA key bubblebabble fingerprint");
	buf = ਲੱਦੋ_ਪਾਠ_file("ecdsa_1.fp.bb");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA1, SSH_FP_BUBBLEBABBLE);
	ASSERT_PTR_NE(cp, ਨਿਰਾ);
	ASSERT_STRING_EQ(cp, (ਅਚਲ ਅੱਖਰ *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	ਮੁਕਤ(cp);
	TEST_ਪੂਰਾ();

	sshkey_free(k1);
#ਜੇ_ਅੰਤ /* WITH_OPENSSL */

	TEST_ਸ਼ੁਰੂ("parse Ed25519 from private");
	buf = ਲੱਦੋ_file("ed25519_1");
	ASSERT_INT_EQ(sshkey_parse_ਨਿੱਜੀ_fileblob(buf, "", &k1, ਨਿਰਾ), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k1, ਨਿਰਾ);
	ASSERT_INT_EQ(k1->type, ਕੁੰਜੀ_ED25519);
	/* XXX check key contents */
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("parse Ed25519 from private w/ passphrase");
	buf = ਲੱਦੋ_file("ed25519_1_pw");
	ASSERT_INT_EQ(sshkey_parse_ਨਿੱਜੀ_fileblob(buf,
	    (ਅਚਲ ਅੱਖਰ *)sshbuf_ptr(pw), &k2, ਨਿਰਾ), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k2, ਨਿਰਾ);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("load Ed25519 from public");
	ASSERT_INT_EQ(sshkey_ਲੱਦੋ_ਜਨਤਕ(test_ਅੰਕੜੇ_file("ed25519_1.pub"), &k2,
	    ਨਿਰਾ), 0);
	ASSERT_PTR_NE(k2, ਨਿਰਾ);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("load Ed25519 cert");
	ASSERT_INT_EQ(sshkey_ਲੱਦੋ_cert(test_ਅੰਕੜੇ_file("ed25519_1"), &k2), 0);
	ASSERT_PTR_NE(k2, ਨਿਰਾ);
	ASSERT_INT_EQ(k2->type, ਕੁੰਜੀ_ED25519_CERT);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 0);
	ASSERT_INT_EQ(sshkey_equal_ਜਨਤਕ(k1, k2), 1);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("Ed25519 key hex fingerprint");
	buf = ਲੱਦੋ_ਪਾਠ_file("ed25519_1.fp");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, ਨਿਰਾ);
	ASSERT_STRING_EQ(cp, (ਅਚਲ ਅੱਖਰ *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	ਮੁਕਤ(cp);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("Ed25519 cert hex fingerprint");
	buf = ਲੱਦੋ_ਪਾਠ_file("ed25519_1-cert.fp");
	cp = sshkey_fingerprint(k2, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, ਨਿਰਾ);
	ASSERT_STRING_EQ(cp, (ਅਚਲ ਅੱਖਰ *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	ਮੁਕਤ(cp);
	sshkey_free(k2);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("Ed25519 key bubblebabble fingerprint");
	buf = ਲੱਦੋ_ਪਾਠ_file("ed25519_1.fp.bb");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA1, SSH_FP_BUBBLEBABBLE);
	ASSERT_PTR_NE(cp, ਨਿਰਾ);
	ASSERT_STRING_EQ(cp, (ਅਚਲ ਅੱਖਰ *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	ਮੁਕਤ(cp);
	TEST_ਪੂਰਾ();

	sshkey_free(k1);

	TEST_ਸ਼ੁਰੂ("parse MLDSA44-ED25519 from private");
	buf = ਲੱਦੋ_file("mldsa44_ed25519_1");
	ASSERT_INT_EQ(sshkey_parse_ਨਿੱਜੀ_fileblob(buf, "", &k1, ਨਿਰਾ), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k1, ਨਿਰਾ);
	ASSERT_INT_EQ(k1->type, ਕੁੰਜੀ_MLDSA44_ED25519);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("parse MLDSA44-ED25519 from private w/ passphrase");
	buf = ਲੱਦੋ_file("mldsa44_ed25519_1_pw");
	ASSERT_INT_EQ(sshkey_parse_ਨਿੱਜੀ_fileblob(buf,
	    (ਅਚਲ ਅੱਖਰ *)sshbuf_ptr(pw), &k2, ਨਿਰਾ), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k2, ਨਿਰਾ);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("load MLDSA44-ED25519 from public");
	ASSERT_INT_EQ(sshkey_ਲੱਦੋ_ਜਨਤਕ(
	    test_ਅੰਕੜੇ_file("mldsa44_ed25519_1.pub"), &k2, ਨਿਰਾ), 0);
	ASSERT_PTR_NE(k2, ਨਿਰਾ);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("load MLDSA44-ED25519 cert");
	ASSERT_INT_EQ(sshkey_ਲੱਦੋ_cert(
	    test_ਅੰਕੜੇ_file("mldsa44_ed25519_1"), &k2), 0);
	ASSERT_PTR_NE(k2, ਨਿਰਾ);
	ASSERT_INT_EQ(k2->type, ਕੁੰਜੀ_MLDSA44_ED25519_CERT);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 0);
	ASSERT_INT_EQ(sshkey_equal_ਜਨਤਕ(k1, k2), 1);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("MLDSA44-ED25519 key hex fingerprint");
	buf = ਲੱਦੋ_ਪਾਠ_file("mldsa44_ed25519_1.fp");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, ਨਿਰਾ);
	ASSERT_STRING_EQ(cp, (ਅਚਲ ਅੱਖਰ *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	ਮੁਕਤ(cp);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("MLDSA44-ED25519 cert hex fingerprint");
	buf = ਲੱਦੋ_ਪਾਠ_file("mldsa44_ed25519_1-cert.fp");
	cp = sshkey_fingerprint(k2, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, ਨਿਰਾ);
	ASSERT_STRING_EQ(cp, (ਅਚਲ ਅੱਖਰ *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	ਮੁਕਤ(cp);
	sshkey_free(k2);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("MLDSA44-ED25519 key bubblebabble fingerprint");
	buf = ਲੱਦੋ_ਪਾਠ_file("mldsa44_ed25519_1.fp.bb");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA1, SSH_FP_BUBBLEBABBLE);
	ASSERT_PTR_NE(cp, ਨਿਰਾ);
	ASSERT_STRING_EQ(cp, (ਅਚਲ ਅੱਖਰ *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	ਮੁਕਤ(cp);
	TEST_ਪੂਰਾ();

	sshkey_free(k1);

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ ENABLE_SK
#ਜੇ defined(WITH_OPENSSL)
	TEST_ਸ਼ੁਰੂ("parse ECDSA-SK from private");
	buf = ਲੱਦੋ_file("ecdsa_sk1");
	ASSERT_INT_EQ(sshkey_parse_ਨਿੱਜੀ_fileblob(buf, "", &k1, ਨਿਰਾ), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k1, ਨਿਰਾ);
	ASSERT_INT_EQ(k1->type, ਕੁੰਜੀ_ECDSA_SK);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("parse ECDSA-SK from private w/ passphrase");
	buf = ਲੱਦੋ_file("ecdsa_sk1_pw");
	ASSERT_INT_EQ(sshkey_parse_ਨਿੱਜੀ_fileblob(buf,
	    (ਅਚਲ ਅੱਖਰ *)sshbuf_ptr(pw), &k2, ਨਿਰਾ), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k2, ਨਿਰਾ);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("load ECDSA-SK from public");
	ASSERT_INT_EQ(sshkey_ਲੱਦੋ_ਜਨਤਕ(test_ਅੰਕੜੇ_file("ecdsa_sk1.pub"), &k2,
	    ਨਿਰਾ), 0);
	ASSERT_PTR_NE(k2, ਨਿਰਾ);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("load ECDSA-SK cert");
	ASSERT_INT_EQ(sshkey_ਲੱਦੋ_cert(test_ਅੰਕੜੇ_file("ecdsa_sk1"), &k2), 0);
	ASSERT_PTR_NE(k2, ਨਿਰਾ);
	ASSERT_INT_EQ(k2->type, ਕੁੰਜੀ_ECDSA_SK_CERT);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 0);
	ASSERT_INT_EQ(sshkey_equal_ਜਨਤਕ(k1, k2), 1);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("ECDSA-SK key hex fingerprint");
	buf = ਲੱਦੋ_ਪਾਠ_file("ecdsa_sk1.fp");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, ਨਿਰਾ);
	ASSERT_STRING_EQ(cp, (ਅਚਲ ਅੱਖਰ *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	ਮੁਕਤ(cp);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("ECDSA-SK cert hex fingerprint");
	buf = ਲੱਦੋ_ਪਾਠ_file("ecdsa_sk1-cert.fp");
	cp = sshkey_fingerprint(k2, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, ਨਿਰਾ);
	ASSERT_STRING_EQ(cp, (ਅਚਲ ਅੱਖਰ *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	ਮੁਕਤ(cp);
	sshkey_free(k2);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("ECDSA-SK key bubblebabble fingerprint");
	buf = ਲੱਦੋ_ਪਾਠ_file("ecdsa_sk1.fp.bb");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA1, SSH_FP_BUBBLEBABBLE);
	ASSERT_PTR_NE(cp, ਨਿਰਾ);
	ASSERT_STRING_EQ(cp, (ਅਚਲ ਅੱਖਰ *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	ਮੁਕਤ(cp);
	TEST_ਪੂਰਾ();

	sshkey_free(k1);
#ਜੇ_ਅੰਤ

	TEST_ਸ਼ੁਰੂ("parse Ed25519-SK from private");
	buf = ਲੱਦੋ_file("ed25519_sk1");
	ASSERT_INT_EQ(sshkey_parse_ਨਿੱਜੀ_fileblob(buf, "", &k1, ਨਿਰਾ), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k1, ਨਿਰਾ);
	ASSERT_INT_EQ(k1->type, ਕੁੰਜੀ_ED25519_SK);
	/* XXX check key contents */
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("parse Ed25519-SK from private w/ passphrase");
	buf = ਲੱਦੋ_file("ed25519_sk1_pw");
	ASSERT_INT_EQ(sshkey_parse_ਨਿੱਜੀ_fileblob(buf,
	    (ਅਚਲ ਅੱਖਰ *)sshbuf_ptr(pw), &k2, ਨਿਰਾ), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k2, ਨਿਰਾ);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("load Ed25519-SK from public");
	ASSERT_INT_EQ(sshkey_ਲੱਦੋ_ਜਨਤਕ(test_ਅੰਕੜੇ_file("ed25519_sk1.pub"),
	    &k2, ਨਿਰਾ), 0);
	ASSERT_PTR_NE(k2, ਨਿਰਾ);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("load Ed25519-SK cert");
	ASSERT_INT_EQ(sshkey_ਲੱਦੋ_cert(test_ਅੰਕੜੇ_file("ed25519_sk1"), &k2), 0);
	ASSERT_PTR_NE(k2, ਨਿਰਾ);
	ASSERT_INT_EQ(k2->type, ਕੁੰਜੀ_ED25519_SK_CERT);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 0);
	ASSERT_INT_EQ(sshkey_equal_ਜਨਤਕ(k1, k2), 1);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("Ed25519-SK key hex fingerprint");
	buf = ਲੱਦੋ_ਪਾਠ_file("ed25519_sk1.fp");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, ਨਿਰਾ);
	ASSERT_STRING_EQ(cp, (ਅਚਲ ਅੱਖਰ *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	ਮੁਕਤ(cp);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("Ed25519-SK cert hex fingerprint");
	buf = ਲੱਦੋ_ਪਾਠ_file("ed25519_sk1-cert.fp");
	cp = sshkey_fingerprint(k2, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, ਨਿਰਾ);
	ASSERT_STRING_EQ(cp, (ਅਚਲ ਅੱਖਰ *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	ਮੁਕਤ(cp);
	sshkey_free(k2);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("Ed25519-SK key bubblebabble fingerprint");
	buf = ਲੱਦੋ_ਪਾਠ_file("ed25519_sk1.fp.bb");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA1, SSH_FP_BUBBLEBABBLE);
	ASSERT_PTR_NE(cp, ਨਿਰਾ);
	ASSERT_STRING_EQ(cp, (ਅਚਲ ਅੱਖਰ *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	ਮੁਕਤ(cp);
	TEST_ਪੂਰਾ();

	sshkey_free(k1);
#ਜੇ_ਅੰਤ /* ENABLE_SK */

	sshbuf_free(pw);

}
