/* 	$OpenBSD: test_file.c,v 1.14 2026/06/14 04:08:06 djm Exp $ */
/*
 * Regress test for sshkey.h key management API
 *
 * Placed in the public domain
 */

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <sys/stat.h>
#ಅನ್ತರ್ಭಾವ <fcntl.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stdint.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
#ಅನ್ತರ್ಭಾವ <openssl/bn.h>
#ಅನ್ತರ್ಭಾವ <openssl/ec.h>
#ಅನ್ತರ್ಭಾವ <openssl/rsa.h>
#ಅನ್ತರ್ಭಾವ <openssl/objects.h>
#ಆದರೆ_ಅಂತ್ಯ /* WITH_OPENSSL */

#ಅನ್ತರ್ಭಾವ "../test_helper/test_helper.h"

#ಅನ್ತರ್ಭಾವ "ssherr.h"
#ಅನ್ತರ್ಭಾವ "authfile.h"
#ಅನ್ತರ್ಭಾವ "sshkey.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "digest.h"

#ಅನ್ತರ್ಭಾವ "common.h"

ಶೂನ್ಯ sshkey_file_tests(ಶೂನ್ಯ);

ಶೂನ್ಯ
sshkey_file_tests(ಶೂನ್ಯ)
{
	ರಚನೆ sshkey *k1, *k2;
	ರಚನೆ sshbuf *buf, *pw;
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
	BIGNUM *a, *b, *c;
#ಆದರೆ_ಅಂತ್ಯ
	ಅಕ್ಷರ *cp;

	TEST_ಆರಂಭ("load passphrase");
	pw = ತುಂಬು_ಪಠ್ಯ_file("pw");
	TEST_ಮುಗಿದ();


#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
	TEST_ಆರಂಭ("parse RSA from private");
	buf = ತುಂಬು_file("rsa_1");
	ASSERT_INT_EQ(sshkey_parse_ಖಾಸಗಿ_fileblob(buf, "", &k1, ಖಾಲಿ), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k1, ಖಾಲಿ);
	a = ತುಂಬು_bignum("rsa_1.param.n");
	b = ತುಂಬು_bignum("rsa_1.param.p");
	c = ತುಂಬು_bignum("rsa_1.param.q");
	ASSERT_BIGNUM_EQ(rsa_n(k1), a);
	ASSERT_BIGNUM_EQ(rsa_p(k1), b);
	ASSERT_BIGNUM_EQ(rsa_q(k1), c);
	BN_free(a);
	BN_free(b);
	BN_free(c);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("parse RSA from private w/ passphrase");
	buf = ತುಂಬು_file("rsa_1_pw");
	ASSERT_INT_EQ(sshkey_parse_ಖಾಸಗಿ_fileblob(buf,
	    (ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *)sshbuf_ptr(pw), &k2, ಖಾಲಿ), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k2, ಖಾಲಿ);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("parse RSA from new-format");
	buf = ತುಂಬು_file("rsa_n");
	ASSERT_INT_EQ(sshkey_parse_ಖಾಸಗಿ_fileblob(buf, "", &k2, ಖಾಲಿ), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k2, ಖಾಲಿ);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("parse RSA from new-format w/ passphrase");
	buf = ತುಂಬು_file("rsa_n_pw");
	ASSERT_INT_EQ(sshkey_parse_ಖಾಸಗಿ_fileblob(buf,
	    (ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *)sshbuf_ptr(pw), &k2, ಖಾಲಿ), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k2, ಖಾಲಿ);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("load RSA from public");
	ASSERT_INT_EQ(sshkey_ತುಂಬು_ಬಹಿರಂಗ(test_ದತ್ತಾಂಶ_file("rsa_1.pub"), &k2,
	    ಖಾಲಿ), 0);
	ASSERT_PTR_NE(k2, ಖಾಲಿ);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("load RSA cert with SHA1 signature");
	ASSERT_INT_EQ(sshkey_ತುಂಬು_cert(test_ದತ್ತಾಂಶ_file("rsa_1_sha1"), &k2), 0);
	ASSERT_PTR_NE(k2, ಖಾಲಿ);
	ASSERT_INT_EQ(k2->type, ಕೀಲಿ_RSA_CERT);
	ASSERT_INT_EQ(sshkey_equal_ಬಹಿರಂಗ(k1, k2), 1);
	ASSERT_STRING_EQ(k2->cert->signature_type, "ssh-rsa");
	sshkey_free(k2);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("load RSA cert with SHA512 signature");
	ASSERT_INT_EQ(sshkey_ತುಂಬು_cert(test_ದತ್ತಾಂಶ_file("rsa_1_sha512"), &k2), 0);
	ASSERT_PTR_NE(k2, ಖಾಲಿ);
	ASSERT_INT_EQ(k2->type, ಕೀಲಿ_RSA_CERT);
	ASSERT_INT_EQ(sshkey_equal_ಬಹಿರಂಗ(k1, k2), 1);
	ASSERT_STRING_EQ(k2->cert->signature_type, "rsa-sha2-512");
	sshkey_free(k2);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("load RSA cert");
	ASSERT_INT_EQ(sshkey_ತುಂಬು_cert(test_ದತ್ತಾಂಶ_file("rsa_1"), &k2), 0);
	ASSERT_PTR_NE(k2, ಖಾಲಿ);
	ASSERT_INT_EQ(k2->type, ಕೀಲಿ_RSA_CERT);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 0);
	ASSERT_INT_EQ(sshkey_equal_ಬಹಿರಂಗ(k1, k2), 1);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("RSA key hex fingerprint");
	buf = ತುಂಬು_ಪಠ್ಯ_file("rsa_1.fp");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, ಖಾಲಿ);
	ASSERT_STRING_EQ(cp, (ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	ಬಿಡುಗಡೆ(cp);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("RSA cert hex fingerprint");
	buf = ತುಂಬು_ಪಠ್ಯ_file("rsa_1-cert.fp");
	cp = sshkey_fingerprint(k2, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, ಖಾಲಿ);
	ASSERT_STRING_EQ(cp, (ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	ಬಿಡುಗಡೆ(cp);
	sshkey_free(k2);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("RSA key bubblebabble fingerprint");
	buf = ತುಂಬು_ಪಠ್ಯ_file("rsa_1.fp.bb");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA1, SSH_FP_BUBBLEBABBLE);
	ASSERT_PTR_NE(cp, ಖಾಲಿ);
	ASSERT_STRING_EQ(cp, (ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	ಬಿಡುಗಡೆ(cp);
	TEST_ಮುಗಿದ();

	sshkey_free(k1);


	TEST_ಆರಂಭ("parse ECDSA from private");
	buf = ತುಂಬು_file("ecdsa_1");
	ASSERT_INT_EQ(sshkey_parse_ಖಾಸಗಿ_fileblob(buf, "", &k1, ಖಾಲಿ), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k1, ಖಾಲಿ);
	buf = ತುಂಬು_ಪಠ್ಯ_file("ecdsa_1.param.curve");
	ASSERT_STRING_EQ((ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *)sshbuf_ptr(buf),
	    OBJ_nid2sn(k1->ecdsa_nid));
	sshbuf_free(buf);
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ OPENSSL_IS_BORINGSSL /* lacks EC_POINT_point2bn() */
	a = ತುಂಬು_bignum("ecdsa_1.param.priv");
	b = ತುಂಬು_bignum("ecdsa_1.param.pub");
	c = EC_ಬಿಂದು_point2bn(EC_ಕೀಲಿ_get0_ಗುಂಪು(EVP_PKEY_get0_EC_ಕೀಲಿ(k1->pkey)),
	    EC_ಕೀಲಿ_get0_ಬಹಿರಂಗ_ಕೀಲಿ(EVP_PKEY_get0_EC_ಕೀಲಿ(k1->pkey)),
	    ಬಿಂದು_CONVERSION_UNCOMPRESSED, ಖಾಲಿ, ಖಾಲಿ);
	ASSERT_PTR_NE(c, ಖಾಲಿ);
	ASSERT_BIGNUM_EQ(
	    EC_ಕೀಲಿ_get0_ಖಾಸಗಿ_ಕೀಲಿ(EVP_PKEY_get0_EC_ಕೀಲಿ(k1->pkey)), a);
	ASSERT_BIGNUM_EQ(b, c);
	BN_free(a);
	BN_free(b);
	BN_free(c);
#ಆದರೆ_ಅಂತ್ಯ /* OPENSSL_IS_BORINGSSL */
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("parse ECDSA from private w/ passphrase");
	buf = ತುಂಬು_file("ecdsa_1_pw");
	ASSERT_INT_EQ(sshkey_parse_ಖಾಸಗಿ_fileblob(buf,
	    (ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *)sshbuf_ptr(pw), &k2, ಖಾಲಿ), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k2, ಖಾಲಿ);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("parse ECDSA from new-format");
	buf = ತುಂಬು_file("ecdsa_n");
	ASSERT_INT_EQ(sshkey_parse_ಖಾಸಗಿ_fileblob(buf, "", &k2, ಖಾಲಿ), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k2, ಖಾಲಿ);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("parse ECDSA from new-format w/ passphrase");
	buf = ತುಂಬು_file("ecdsa_n_pw");
	ASSERT_INT_EQ(sshkey_parse_ಖಾಸಗಿ_fileblob(buf,
	    (ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *)sshbuf_ptr(pw), &k2, ಖಾಲಿ), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k2, ಖಾಲಿ);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("load ECDSA from public");
	ASSERT_INT_EQ(sshkey_ತುಂಬು_ಬಹಿರಂಗ(test_ದತ್ತಾಂಶ_file("ecdsa_1.pub"), &k2,
	    ಖಾಲಿ), 0);
	ASSERT_PTR_NE(k2, ಖಾಲಿ);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("load ECDSA cert");
	ASSERT_INT_EQ(sshkey_ತುಂಬು_cert(test_ದತ್ತಾಂಶ_file("ecdsa_1"), &k2), 0);
	ASSERT_PTR_NE(k2, ಖಾಲಿ);
	ASSERT_INT_EQ(k2->type, ಕೀಲಿ_ECDSA_CERT);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 0);
	ASSERT_INT_EQ(sshkey_equal_ಬಹಿರಂಗ(k1, k2), 1);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("ECDSA key hex fingerprint");
	buf = ತುಂಬು_ಪಠ್ಯ_file("ecdsa_1.fp");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, ಖಾಲಿ);
	ASSERT_STRING_EQ(cp, (ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	ಬಿಡುಗಡೆ(cp);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("ECDSA cert hex fingerprint");
	buf = ತುಂಬು_ಪಠ್ಯ_file("ecdsa_1-cert.fp");
	cp = sshkey_fingerprint(k2, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, ಖಾಲಿ);
	ASSERT_STRING_EQ(cp, (ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	ಬಿಡುಗಡೆ(cp);
	sshkey_free(k2);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("ECDSA key bubblebabble fingerprint");
	buf = ತುಂಬು_ಪಠ್ಯ_file("ecdsa_1.fp.bb");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA1, SSH_FP_BUBBLEBABBLE);
	ASSERT_PTR_NE(cp, ಖಾಲಿ);
	ASSERT_STRING_EQ(cp, (ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	ಬಿಡುಗಡೆ(cp);
	TEST_ಮುಗಿದ();

	sshkey_free(k1);
#ಆದರೆ_ಅಂತ್ಯ /* WITH_OPENSSL */

	TEST_ಆರಂಭ("parse Ed25519 from private");
	buf = ತುಂಬು_file("ed25519_1");
	ASSERT_INT_EQ(sshkey_parse_ಖಾಸಗಿ_fileblob(buf, "", &k1, ಖಾಲಿ), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k1, ಖಾಲಿ);
	ASSERT_INT_EQ(k1->type, ಕೀಲಿ_ED25519);
	/* XXX check key contents */
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("parse Ed25519 from private w/ passphrase");
	buf = ತುಂಬು_file("ed25519_1_pw");
	ASSERT_INT_EQ(sshkey_parse_ಖಾಸಗಿ_fileblob(buf,
	    (ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *)sshbuf_ptr(pw), &k2, ಖಾಲಿ), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k2, ಖಾಲಿ);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("load Ed25519 from public");
	ASSERT_INT_EQ(sshkey_ತುಂಬು_ಬಹಿರಂಗ(test_ದತ್ತಾಂಶ_file("ed25519_1.pub"), &k2,
	    ಖಾಲಿ), 0);
	ASSERT_PTR_NE(k2, ಖಾಲಿ);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("load Ed25519 cert");
	ASSERT_INT_EQ(sshkey_ತುಂಬು_cert(test_ದತ್ತಾಂಶ_file("ed25519_1"), &k2), 0);
	ASSERT_PTR_NE(k2, ಖಾಲಿ);
	ASSERT_INT_EQ(k2->type, ಕೀಲಿ_ED25519_CERT);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 0);
	ASSERT_INT_EQ(sshkey_equal_ಬಹಿರಂಗ(k1, k2), 1);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("Ed25519 key hex fingerprint");
	buf = ತುಂಬು_ಪಠ್ಯ_file("ed25519_1.fp");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, ಖಾಲಿ);
	ASSERT_STRING_EQ(cp, (ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	ಬಿಡುಗಡೆ(cp);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("Ed25519 cert hex fingerprint");
	buf = ತುಂಬು_ಪಠ್ಯ_file("ed25519_1-cert.fp");
	cp = sshkey_fingerprint(k2, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, ಖಾಲಿ);
	ASSERT_STRING_EQ(cp, (ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	ಬಿಡುಗಡೆ(cp);
	sshkey_free(k2);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("Ed25519 key bubblebabble fingerprint");
	buf = ತುಂಬು_ಪಠ್ಯ_file("ed25519_1.fp.bb");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA1, SSH_FP_BUBBLEBABBLE);
	ASSERT_PTR_NE(cp, ಖಾಲಿ);
	ASSERT_STRING_EQ(cp, (ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	ಬಿಡುಗಡೆ(cp);
	TEST_ಮುಗಿದ();

	sshkey_free(k1);

	TEST_ಆರಂಭ("parse MLDSA44-ED25519 from private");
	buf = ತುಂಬು_file("mldsa44_ed25519_1");
	ASSERT_INT_EQ(sshkey_parse_ಖಾಸಗಿ_fileblob(buf, "", &k1, ಖಾಲಿ), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k1, ಖಾಲಿ);
	ASSERT_INT_EQ(k1->type, ಕೀಲಿ_MLDSA44_ED25519);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("parse MLDSA44-ED25519 from private w/ passphrase");
	buf = ತುಂಬು_file("mldsa44_ed25519_1_pw");
	ASSERT_INT_EQ(sshkey_parse_ಖಾಸಗಿ_fileblob(buf,
	    (ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *)sshbuf_ptr(pw), &k2, ಖಾಲಿ), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k2, ಖಾಲಿ);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("load MLDSA44-ED25519 from public");
	ASSERT_INT_EQ(sshkey_ತುಂಬು_ಬಹಿರಂಗ(
	    test_ದತ್ತಾಂಶ_file("mldsa44_ed25519_1.pub"), &k2, ಖಾಲಿ), 0);
	ASSERT_PTR_NE(k2, ಖಾಲಿ);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("load MLDSA44-ED25519 cert");
	ASSERT_INT_EQ(sshkey_ತುಂಬು_cert(
	    test_ದತ್ತಾಂಶ_file("mldsa44_ed25519_1"), &k2), 0);
	ASSERT_PTR_NE(k2, ಖಾಲಿ);
	ASSERT_INT_EQ(k2->type, ಕೀಲಿ_MLDSA44_ED25519_CERT);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 0);
	ASSERT_INT_EQ(sshkey_equal_ಬಹಿರಂಗ(k1, k2), 1);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("MLDSA44-ED25519 key hex fingerprint");
	buf = ತುಂಬು_ಪಠ್ಯ_file("mldsa44_ed25519_1.fp");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, ಖಾಲಿ);
	ASSERT_STRING_EQ(cp, (ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	ಬಿಡುಗಡೆ(cp);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("MLDSA44-ED25519 cert hex fingerprint");
	buf = ತುಂಬು_ಪಠ್ಯ_file("mldsa44_ed25519_1-cert.fp");
	cp = sshkey_fingerprint(k2, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, ಖಾಲಿ);
	ASSERT_STRING_EQ(cp, (ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	ಬಿಡುಗಡೆ(cp);
	sshkey_free(k2);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("MLDSA44-ED25519 key bubblebabble fingerprint");
	buf = ತುಂಬು_ಪಠ್ಯ_file("mldsa44_ed25519_1.fp.bb");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA1, SSH_FP_BUBBLEBABBLE);
	ASSERT_PTR_NE(cp, ಖಾಲಿ);
	ASSERT_STRING_EQ(cp, (ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	ಬಿಡುಗಡೆ(cp);
	TEST_ಮುಗಿದ();

	sshkey_free(k1);

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ ENABLE_SK
#ಆದರೆ defined(WITH_OPENSSL)
	TEST_ಆರಂಭ("parse ECDSA-SK from private");
	buf = ತುಂಬು_file("ecdsa_sk1");
	ASSERT_INT_EQ(sshkey_parse_ಖಾಸಗಿ_fileblob(buf, "", &k1, ಖಾಲಿ), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k1, ಖಾಲಿ);
	ASSERT_INT_EQ(k1->type, ಕೀಲಿ_ECDSA_SK);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("parse ECDSA-SK from private w/ passphrase");
	buf = ತುಂಬು_file("ecdsa_sk1_pw");
	ASSERT_INT_EQ(sshkey_parse_ಖಾಸಗಿ_fileblob(buf,
	    (ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *)sshbuf_ptr(pw), &k2, ಖಾಲಿ), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k2, ಖಾಲಿ);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("load ECDSA-SK from public");
	ASSERT_INT_EQ(sshkey_ತುಂಬು_ಬಹಿರಂಗ(test_ದತ್ತಾಂಶ_file("ecdsa_sk1.pub"), &k2,
	    ಖಾಲಿ), 0);
	ASSERT_PTR_NE(k2, ಖಾಲಿ);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("load ECDSA-SK cert");
	ASSERT_INT_EQ(sshkey_ತುಂಬು_cert(test_ದತ್ತಾಂಶ_file("ecdsa_sk1"), &k2), 0);
	ASSERT_PTR_NE(k2, ಖಾಲಿ);
	ASSERT_INT_EQ(k2->type, ಕೀಲಿ_ECDSA_SK_CERT);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 0);
	ASSERT_INT_EQ(sshkey_equal_ಬಹಿರಂಗ(k1, k2), 1);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("ECDSA-SK key hex fingerprint");
	buf = ತುಂಬು_ಪಠ್ಯ_file("ecdsa_sk1.fp");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, ಖಾಲಿ);
	ASSERT_STRING_EQ(cp, (ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	ಬಿಡುಗಡೆ(cp);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("ECDSA-SK cert hex fingerprint");
	buf = ತುಂಬು_ಪಠ್ಯ_file("ecdsa_sk1-cert.fp");
	cp = sshkey_fingerprint(k2, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, ಖಾಲಿ);
	ASSERT_STRING_EQ(cp, (ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	ಬಿಡುಗಡೆ(cp);
	sshkey_free(k2);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("ECDSA-SK key bubblebabble fingerprint");
	buf = ತುಂಬು_ಪಠ್ಯ_file("ecdsa_sk1.fp.bb");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA1, SSH_FP_BUBBLEBABBLE);
	ASSERT_PTR_NE(cp, ಖಾಲಿ);
	ASSERT_STRING_EQ(cp, (ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	ಬಿಡುಗಡೆ(cp);
	TEST_ಮುಗಿದ();

	sshkey_free(k1);
#ಆದರೆ_ಅಂತ್ಯ

	TEST_ಆರಂಭ("parse Ed25519-SK from private");
	buf = ತುಂಬು_file("ed25519_sk1");
	ASSERT_INT_EQ(sshkey_parse_ಖಾಸಗಿ_fileblob(buf, "", &k1, ಖಾಲಿ), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k1, ಖಾಲಿ);
	ASSERT_INT_EQ(k1->type, ಕೀಲಿ_ED25519_SK);
	/* XXX check key contents */
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("parse Ed25519-SK from private w/ passphrase");
	buf = ತುಂಬು_file("ed25519_sk1_pw");
	ASSERT_INT_EQ(sshkey_parse_ಖಾಸಗಿ_fileblob(buf,
	    (ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *)sshbuf_ptr(pw), &k2, ಖಾಲಿ), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k2, ಖಾಲಿ);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("load Ed25519-SK from public");
	ASSERT_INT_EQ(sshkey_ತುಂಬು_ಬಹಿರಂಗ(test_ದತ್ತಾಂಶ_file("ed25519_sk1.pub"),
	    &k2, ಖಾಲಿ), 0);
	ASSERT_PTR_NE(k2, ಖಾಲಿ);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("load Ed25519-SK cert");
	ASSERT_INT_EQ(sshkey_ತುಂಬು_cert(test_ದತ್ತಾಂಶ_file("ed25519_sk1"), &k2), 0);
	ASSERT_PTR_NE(k2, ಖಾಲಿ);
	ASSERT_INT_EQ(k2->type, ಕೀಲಿ_ED25519_SK_CERT);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 0);
	ASSERT_INT_EQ(sshkey_equal_ಬಹಿರಂಗ(k1, k2), 1);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("Ed25519-SK key hex fingerprint");
	buf = ತುಂಬು_ಪಠ್ಯ_file("ed25519_sk1.fp");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, ಖಾಲಿ);
	ASSERT_STRING_EQ(cp, (ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	ಬಿಡುಗಡೆ(cp);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("Ed25519-SK cert hex fingerprint");
	buf = ತುಂಬು_ಪಠ್ಯ_file("ed25519_sk1-cert.fp");
	cp = sshkey_fingerprint(k2, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, ಖಾಲಿ);
	ASSERT_STRING_EQ(cp, (ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	ಬಿಡುಗಡೆ(cp);
	sshkey_free(k2);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("Ed25519-SK key bubblebabble fingerprint");
	buf = ತುಂಬು_ಪಠ್ಯ_file("ed25519_sk1.fp.bb");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA1, SSH_FP_BUBBLEBABBLE);
	ASSERT_PTR_NE(cp, ಖಾಲಿ);
	ASSERT_STRING_EQ(cp, (ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	ಬಿಡುಗಡೆ(cp);
	TEST_ಮುಗಿದ();

	sshkey_free(k1);
#ಆದರೆ_ಅಂತ್ಯ /* ENABLE_SK */

	sshbuf_free(pw);

}
