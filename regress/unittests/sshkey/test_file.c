/* 	$OpenBSD: test_file.c,v 1.14 2026/06/14 04:08:06 djm Exp $ */
/*
 * Regress test for sshkey.h key management API
 *
 * Placed in the public domain
 */

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <sys/stat.h>
#அந்தர்பாவ <fcntl.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <stdint.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <unistd.h>

#ifdef WITH_OPENSSL
#அந்தர்பாவ <openssl/bn.h>
#அந்தர்பாவ <openssl/ec.h>
#அந்தர்பாவ <openssl/rsa.h>
#அந்தர்பாவ <openssl/objects.h>
#endif /* WITH_OPENSSL */

#அந்தர்பாவ "../test_helper/test_helper.h"

#அந்தர்பாவ "ssherr.h"
#அந்தர்பாவ "authfile.h"
#அந்தர்பாவ "sshkey.h"
#அந்தர்பாவ "sshbuf.h"
#அந்தர்பாவ "digest.h"

#அந்தர்பாவ "common.h"

வெறுமை sshkey_file_tests(வெறுமை);

வெறுமை
sshkey_file_tests(வெறுமை)
{
	கட்டமைப்பு sshkey *k1, *k2;
	கட்டமைப்பு sshbuf *buf, *pw;
#ifdef WITH_OPENSSL
	BIGNUM *a, *b, *c;
#endif
	எழுத்து *cp;

	TEST_START("load passphrase");
	pw = load_text_file("pw");
	TEST_DONE();


#ifdef WITH_OPENSSL
	TEST_START("parse RSA from private");
	buf = load_file("rsa_1");
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, வெற்று), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k1, வெற்று);
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
	    (மாறிலி எழுத்து *)sshbuf_ptr(pw), &k2, வெற்று), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k2, வெற்று);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_DONE();

	TEST_START("parse RSA from new-format");
	buf = load_file("rsa_n");
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k2, வெற்று), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k2, வெற்று);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_DONE();

	TEST_START("parse RSA from new-format w/ passphrase");
	buf = load_file("rsa_n_pw");
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf,
	    (மாறிலி எழுத்து *)sshbuf_ptr(pw), &k2, வெற்று), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k2, வெற்று);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_DONE();

	TEST_START("load RSA from public");
	ASSERT_INT_EQ(sshkey_load_public(test_data_file("rsa_1.pub"), &k2,
	    வெற்று), 0);
	ASSERT_PTR_NE(k2, வெற்று);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_DONE();

	TEST_START("load RSA cert with SHA1 signature");
	ASSERT_INT_EQ(sshkey_load_cert(test_data_file("rsa_1_sha1"), &k2), 0);
	ASSERT_PTR_NE(k2, வெற்று);
	ASSERT_INT_EQ(k2->type, சாவி_RSA_CERT);
	ASSERT_INT_EQ(sshkey_equal_public(k1, k2), 1);
	ASSERT_STRING_EQ(k2->cert->signature_type, "ssh-rsa");
	sshkey_free(k2);
	TEST_DONE();

	TEST_START("load RSA cert with SHA512 signature");
	ASSERT_INT_EQ(sshkey_load_cert(test_data_file("rsa_1_sha512"), &k2), 0);
	ASSERT_PTR_NE(k2, வெற்று);
	ASSERT_INT_EQ(k2->type, சாவி_RSA_CERT);
	ASSERT_INT_EQ(sshkey_equal_public(k1, k2), 1);
	ASSERT_STRING_EQ(k2->cert->signature_type, "rsa-sha2-512");
	sshkey_free(k2);
	TEST_DONE();

	TEST_START("load RSA cert");
	ASSERT_INT_EQ(sshkey_load_cert(test_data_file("rsa_1"), &k2), 0);
	ASSERT_PTR_NE(k2, வெற்று);
	ASSERT_INT_EQ(k2->type, சாவி_RSA_CERT);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 0);
	ASSERT_INT_EQ(sshkey_equal_public(k1, k2), 1);
	TEST_DONE();

	TEST_START("RSA key hex fingerprint");
	buf = load_text_file("rsa_1.fp");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, வெற்று);
	ASSERT_STRING_EQ(cp, (மாறிலி எழுத்து *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	விடுவி(cp);
	TEST_DONE();

	TEST_START("RSA cert hex fingerprint");
	buf = load_text_file("rsa_1-cert.fp");
	cp = sshkey_fingerprint(k2, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, வெற்று);
	ASSERT_STRING_EQ(cp, (மாறிலி எழுத்து *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	விடுவி(cp);
	sshkey_free(k2);
	TEST_DONE();

	TEST_START("RSA key bubblebabble fingerprint");
	buf = load_text_file("rsa_1.fp.bb");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA1, SSH_FP_BUBBLEBABBLE);
	ASSERT_PTR_NE(cp, வெற்று);
	ASSERT_STRING_EQ(cp, (மாறிலி எழுத்து *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	விடுவி(cp);
	TEST_DONE();

	sshkey_free(k1);


	TEST_START("parse ECDSA from private");
	buf = load_file("ecdsa_1");
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, வெற்று), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k1, வெற்று);
	buf = load_text_file("ecdsa_1.param.curve");
	ASSERT_STRING_EQ((மாறிலி எழுத்து *)sshbuf_ptr(buf),
	    OBJ_nid2sn(k1->ecdsa_nid));
	sshbuf_free(buf);
#ifndef OPENSSL_IS_BORINGSSL /* lacks EC_POINT_point2bn() */
	a = load_bignum("ecdsa_1.param.priv");
	b = load_bignum("ecdsa_1.param.pub");
	c = EC_POINT_point2bn(EC_சாவி_get0_group(EVP_PKEY_get0_EC_சாவி(k1->pkey)),
	    EC_சாவி_get0_public_சாவி(EVP_PKEY_get0_EC_சாவி(k1->pkey)),
	    POINT_CONVERSION_UNCOMPRESSED, வெற்று, வெற்று);
	ASSERT_PTR_NE(c, வெற்று);
	ASSERT_BIGNUM_EQ(
	    EC_சாவி_get0_private_சாவி(EVP_PKEY_get0_EC_சாவி(k1->pkey)), a);
	ASSERT_BIGNUM_EQ(b, c);
	BN_free(a);
	BN_free(b);
	BN_free(c);
#endif /* OPENSSL_IS_BORINGSSL */
	TEST_DONE();

	TEST_START("parse ECDSA from private w/ passphrase");
	buf = load_file("ecdsa_1_pw");
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf,
	    (மாறிலி எழுத்து *)sshbuf_ptr(pw), &k2, வெற்று), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k2, வெற்று);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_DONE();

	TEST_START("parse ECDSA from new-format");
	buf = load_file("ecdsa_n");
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k2, வெற்று), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k2, வெற்று);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_DONE();

	TEST_START("parse ECDSA from new-format w/ passphrase");
	buf = load_file("ecdsa_n_pw");
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf,
	    (மாறிலி எழுத்து *)sshbuf_ptr(pw), &k2, வெற்று), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k2, வெற்று);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_DONE();

	TEST_START("load ECDSA from public");
	ASSERT_INT_EQ(sshkey_load_public(test_data_file("ecdsa_1.pub"), &k2,
	    வெற்று), 0);
	ASSERT_PTR_NE(k2, வெற்று);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_DONE();

	TEST_START("load ECDSA cert");
	ASSERT_INT_EQ(sshkey_load_cert(test_data_file("ecdsa_1"), &k2), 0);
	ASSERT_PTR_NE(k2, வெற்று);
	ASSERT_INT_EQ(k2->type, சாவி_ECDSA_CERT);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 0);
	ASSERT_INT_EQ(sshkey_equal_public(k1, k2), 1);
	TEST_DONE();

	TEST_START("ECDSA key hex fingerprint");
	buf = load_text_file("ecdsa_1.fp");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, வெற்று);
	ASSERT_STRING_EQ(cp, (மாறிலி எழுத்து *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	விடுவி(cp);
	TEST_DONE();

	TEST_START("ECDSA cert hex fingerprint");
	buf = load_text_file("ecdsa_1-cert.fp");
	cp = sshkey_fingerprint(k2, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, வெற்று);
	ASSERT_STRING_EQ(cp, (மாறிலி எழுத்து *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	விடுவி(cp);
	sshkey_free(k2);
	TEST_DONE();

	TEST_START("ECDSA key bubblebabble fingerprint");
	buf = load_text_file("ecdsa_1.fp.bb");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA1, SSH_FP_BUBBLEBABBLE);
	ASSERT_PTR_NE(cp, வெற்று);
	ASSERT_STRING_EQ(cp, (மாறிலி எழுத்து *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	விடுவி(cp);
	TEST_DONE();

	sshkey_free(k1);
#endif /* WITH_OPENSSL */

	TEST_START("parse Ed25519 from private");
	buf = load_file("ed25519_1");
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, வெற்று), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k1, வெற்று);
	ASSERT_INT_EQ(k1->type, சாவி_ED25519);
	/* XXX check key contents */
	TEST_DONE();

	TEST_START("parse Ed25519 from private w/ passphrase");
	buf = load_file("ed25519_1_pw");
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf,
	    (மாறிலி எழுத்து *)sshbuf_ptr(pw), &k2, வெற்று), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k2, வெற்று);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_DONE();

	TEST_START("load Ed25519 from public");
	ASSERT_INT_EQ(sshkey_load_public(test_data_file("ed25519_1.pub"), &k2,
	    வெற்று), 0);
	ASSERT_PTR_NE(k2, வெற்று);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_DONE();

	TEST_START("load Ed25519 cert");
	ASSERT_INT_EQ(sshkey_load_cert(test_data_file("ed25519_1"), &k2), 0);
	ASSERT_PTR_NE(k2, வெற்று);
	ASSERT_INT_EQ(k2->type, சாவி_ED25519_CERT);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 0);
	ASSERT_INT_EQ(sshkey_equal_public(k1, k2), 1);
	TEST_DONE();

	TEST_START("Ed25519 key hex fingerprint");
	buf = load_text_file("ed25519_1.fp");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, வெற்று);
	ASSERT_STRING_EQ(cp, (மாறிலி எழுத்து *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	விடுவி(cp);
	TEST_DONE();

	TEST_START("Ed25519 cert hex fingerprint");
	buf = load_text_file("ed25519_1-cert.fp");
	cp = sshkey_fingerprint(k2, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, வெற்று);
	ASSERT_STRING_EQ(cp, (மாறிலி எழுத்து *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	விடுவி(cp);
	sshkey_free(k2);
	TEST_DONE();

	TEST_START("Ed25519 key bubblebabble fingerprint");
	buf = load_text_file("ed25519_1.fp.bb");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA1, SSH_FP_BUBBLEBABBLE);
	ASSERT_PTR_NE(cp, வெற்று);
	ASSERT_STRING_EQ(cp, (மாறிலி எழுத்து *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	விடுவி(cp);
	TEST_DONE();

	sshkey_free(k1);

	TEST_START("parse MLDSA44-ED25519 from private");
	buf = load_file("mldsa44_ed25519_1");
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, வெற்று), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k1, வெற்று);
	ASSERT_INT_EQ(k1->type, சாவி_MLDSA44_ED25519);
	TEST_DONE();

	TEST_START("parse MLDSA44-ED25519 from private w/ passphrase");
	buf = load_file("mldsa44_ed25519_1_pw");
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf,
	    (மாறிலி எழுத்து *)sshbuf_ptr(pw), &k2, வெற்று), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k2, வெற்று);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_DONE();

	TEST_START("load MLDSA44-ED25519 from public");
	ASSERT_INT_EQ(sshkey_load_public(
	    test_data_file("mldsa44_ed25519_1.pub"), &k2, வெற்று), 0);
	ASSERT_PTR_NE(k2, வெற்று);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_DONE();

	TEST_START("load MLDSA44-ED25519 cert");
	ASSERT_INT_EQ(sshkey_load_cert(
	    test_data_file("mldsa44_ed25519_1"), &k2), 0);
	ASSERT_PTR_NE(k2, வெற்று);
	ASSERT_INT_EQ(k2->type, சாவி_MLDSA44_ED25519_CERT);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 0);
	ASSERT_INT_EQ(sshkey_equal_public(k1, k2), 1);
	TEST_DONE();

	TEST_START("MLDSA44-ED25519 key hex fingerprint");
	buf = load_text_file("mldsa44_ed25519_1.fp");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, வெற்று);
	ASSERT_STRING_EQ(cp, (மாறிலி எழுத்து *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	விடுவி(cp);
	TEST_DONE();

	TEST_START("MLDSA44-ED25519 cert hex fingerprint");
	buf = load_text_file("mldsa44_ed25519_1-cert.fp");
	cp = sshkey_fingerprint(k2, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, வெற்று);
	ASSERT_STRING_EQ(cp, (மாறிலி எழுத்து *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	விடுவி(cp);
	sshkey_free(k2);
	TEST_DONE();

	TEST_START("MLDSA44-ED25519 key bubblebabble fingerprint");
	buf = load_text_file("mldsa44_ed25519_1.fp.bb");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA1, SSH_FP_BUBBLEBABBLE);
	ASSERT_PTR_NE(cp, வெற்று);
	ASSERT_STRING_EQ(cp, (மாறிலி எழுத்து *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	விடுவி(cp);
	TEST_DONE();

	sshkey_free(k1);

#ifdef ENABLE_SK
#எனில் defined(WITH_OPENSSL)
	TEST_START("parse ECDSA-SK from private");
	buf = load_file("ecdsa_sk1");
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, வெற்று), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k1, வெற்று);
	ASSERT_INT_EQ(k1->type, சாவி_ECDSA_SK);
	TEST_DONE();

	TEST_START("parse ECDSA-SK from private w/ passphrase");
	buf = load_file("ecdsa_sk1_pw");
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf,
	    (மாறிலி எழுத்து *)sshbuf_ptr(pw), &k2, வெற்று), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k2, வெற்று);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_DONE();

	TEST_START("load ECDSA-SK from public");
	ASSERT_INT_EQ(sshkey_load_public(test_data_file("ecdsa_sk1.pub"), &k2,
	    வெற்று), 0);
	ASSERT_PTR_NE(k2, வெற்று);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_DONE();

	TEST_START("load ECDSA-SK cert");
	ASSERT_INT_EQ(sshkey_load_cert(test_data_file("ecdsa_sk1"), &k2), 0);
	ASSERT_PTR_NE(k2, வெற்று);
	ASSERT_INT_EQ(k2->type, சாவி_ECDSA_SK_CERT);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 0);
	ASSERT_INT_EQ(sshkey_equal_public(k1, k2), 1);
	TEST_DONE();

	TEST_START("ECDSA-SK key hex fingerprint");
	buf = load_text_file("ecdsa_sk1.fp");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, வெற்று);
	ASSERT_STRING_EQ(cp, (மாறிலி எழுத்து *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	விடுவி(cp);
	TEST_DONE();

	TEST_START("ECDSA-SK cert hex fingerprint");
	buf = load_text_file("ecdsa_sk1-cert.fp");
	cp = sshkey_fingerprint(k2, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, வெற்று);
	ASSERT_STRING_EQ(cp, (மாறிலி எழுத்து *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	விடுவி(cp);
	sshkey_free(k2);
	TEST_DONE();

	TEST_START("ECDSA-SK key bubblebabble fingerprint");
	buf = load_text_file("ecdsa_sk1.fp.bb");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA1, SSH_FP_BUBBLEBABBLE);
	ASSERT_PTR_NE(cp, வெற்று);
	ASSERT_STRING_EQ(cp, (மாறிலி எழுத்து *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	விடுவி(cp);
	TEST_DONE();

	sshkey_free(k1);
#endif

	TEST_START("parse Ed25519-SK from private");
	buf = load_file("ed25519_sk1");
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, வெற்று), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k1, வெற்று);
	ASSERT_INT_EQ(k1->type, சாவி_ED25519_SK);
	/* XXX check key contents */
	TEST_DONE();

	TEST_START("parse Ed25519-SK from private w/ passphrase");
	buf = load_file("ed25519_sk1_pw");
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf,
	    (மாறிலி எழுத்து *)sshbuf_ptr(pw), &k2, வெற்று), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k2, வெற்று);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_DONE();

	TEST_START("load Ed25519-SK from public");
	ASSERT_INT_EQ(sshkey_load_public(test_data_file("ed25519_sk1.pub"),
	    &k2, வெற்று), 0);
	ASSERT_PTR_NE(k2, வெற்று);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_DONE();

	TEST_START("load Ed25519-SK cert");
	ASSERT_INT_EQ(sshkey_load_cert(test_data_file("ed25519_sk1"), &k2), 0);
	ASSERT_PTR_NE(k2, வெற்று);
	ASSERT_INT_EQ(k2->type, சாவி_ED25519_SK_CERT);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 0);
	ASSERT_INT_EQ(sshkey_equal_public(k1, k2), 1);
	TEST_DONE();

	TEST_START("Ed25519-SK key hex fingerprint");
	buf = load_text_file("ed25519_sk1.fp");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, வெற்று);
	ASSERT_STRING_EQ(cp, (மாறிலி எழுத்து *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	விடுவி(cp);
	TEST_DONE();

	TEST_START("Ed25519-SK cert hex fingerprint");
	buf = load_text_file("ed25519_sk1-cert.fp");
	cp = sshkey_fingerprint(k2, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, வெற்று);
	ASSERT_STRING_EQ(cp, (மாறிலி எழுத்து *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	விடுவி(cp);
	sshkey_free(k2);
	TEST_DONE();

	TEST_START("Ed25519-SK key bubblebabble fingerprint");
	buf = load_text_file("ed25519_sk1.fp.bb");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA1, SSH_FP_BUBBLEBABBLE);
	ASSERT_PTR_NE(cp, வெற்று);
	ASSERT_STRING_EQ(cp, (மாறிலி எழுத்து *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	விடுவி(cp);
	TEST_DONE();

	sshkey_free(k1);
#endif /* ENABLE_SK */

	sshbuf_free(pw);

}
