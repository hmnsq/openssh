/* 	$OpenBSD: test_file.c,v 1.14 2026/06/14 04:08:06 djm Exp $ */
/*
 * Regress test for sshkey.h key management API
 *
 * Placed in the public domain
 */

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <sys/stat.h>
#అన్తర్భావ <fcntl.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <stdint.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <unistd.h>

#నిర్వచితమైతే WITH_OPENSSL
#అన్తర్భావ <openssl/bn.h>
#అన్తర్భావ <openssl/ec.h>
#అన్తర్భావ <openssl/rsa.h>
#అన్తర్భావ <openssl/objects.h>
#అయితే_ముగింపు /* WITH_OPENSSL */

#అన్తర్భావ "../test_helper/test_helper.h"

#అన్తర్భావ "ssherr.h"
#అన్తర్భావ "authfile.h"
#అన్తర్భావ "sshkey.h"
#అన్తర్భావ "sshbuf.h"
#అన్తర్భావ "digest.h"

#అన్తర్భావ "common.h"

శూన్య sshkey_file_tests(శూన్య);

శూన్య
sshkey_file_tests(శూన్య)
{
	నిర్మాణం sshkey *k1, *k2;
	నిర్మాణం sshbuf *buf, *pw;
#నిర్వచితమైతే WITH_OPENSSL
	BIGNUM *a, *b, *c;
#అయితే_ముగింపు
	అక్షరం *cp;

	TEST_ప్రారంభం("load passphrase");
	pw = ఎక్కించు_పాఠ్యం_file("pw");
	TEST_పూర్తి();


#నిర్వచితమైతే WITH_OPENSSL
	TEST_ప్రారంభం("parse RSA from private");
	buf = ఎక్కించు_file("rsa_1");
	ASSERT_INT_EQ(sshkey_parse_వ్యక్తిగత_fileblob(buf, "", &k1, ఖాళీ), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k1, ఖాళీ);
	a = ఎక్కించు_bignum("rsa_1.param.n");
	b = ఎక్కించు_bignum("rsa_1.param.p");
	c = ఎక్కించు_bignum("rsa_1.param.q");
	ASSERT_BIGNUM_EQ(rsa_n(k1), a);
	ASSERT_BIGNUM_EQ(rsa_p(k1), b);
	ASSERT_BIGNUM_EQ(rsa_q(k1), c);
	BN_free(a);
	BN_free(b);
	BN_free(c);
	TEST_పూర్తి();

	TEST_ప్రారంభం("parse RSA from private w/ passphrase");
	buf = ఎక్కించు_file("rsa_1_pw");
	ASSERT_INT_EQ(sshkey_parse_వ్యక్తిగత_fileblob(buf,
	    (స్థిరరాశి అక్షరం *)sshbuf_ptr(pw), &k2, ఖాళీ), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k2, ఖాళీ);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_పూర్తి();

	TEST_ప్రారంభం("parse RSA from new-format");
	buf = ఎక్కించు_file("rsa_n");
	ASSERT_INT_EQ(sshkey_parse_వ్యక్తిగత_fileblob(buf, "", &k2, ఖాళీ), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k2, ఖాళీ);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_పూర్తి();

	TEST_ప్రారంభం("parse RSA from new-format w/ passphrase");
	buf = ఎక్కించు_file("rsa_n_pw");
	ASSERT_INT_EQ(sshkey_parse_వ్యక్తిగత_fileblob(buf,
	    (స్థిరరాశి అక్షరం *)sshbuf_ptr(pw), &k2, ఖాళీ), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k2, ఖాళీ);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_పూర్తి();

	TEST_ప్రారంభం("load RSA from public");
	ASSERT_INT_EQ(sshkey_ఎక్కించు_ప్రజా(test_దత్తాంశం_file("rsa_1.pub"), &k2,
	    ఖాళీ), 0);
	ASSERT_PTR_NE(k2, ఖాళీ);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_పూర్తి();

	TEST_ప్రారంభం("load RSA cert with SHA1 signature");
	ASSERT_INT_EQ(sshkey_ఎక్కించు_cert(test_దత్తాంశం_file("rsa_1_sha1"), &k2), 0);
	ASSERT_PTR_NE(k2, ఖాళీ);
	ASSERT_INT_EQ(k2->type, కీలకం_RSA_CERT);
	ASSERT_INT_EQ(sshkey_equal_ప్రజా(k1, k2), 1);
	ASSERT_STRING_EQ(k2->cert->signature_type, "ssh-rsa");
	sshkey_free(k2);
	TEST_పూర్తి();

	TEST_ప్రారంభం("load RSA cert with SHA512 signature");
	ASSERT_INT_EQ(sshkey_ఎక్కించు_cert(test_దత్తాంశం_file("rsa_1_sha512"), &k2), 0);
	ASSERT_PTR_NE(k2, ఖాళీ);
	ASSERT_INT_EQ(k2->type, కీలకం_RSA_CERT);
	ASSERT_INT_EQ(sshkey_equal_ప్రజా(k1, k2), 1);
	ASSERT_STRING_EQ(k2->cert->signature_type, "rsa-sha2-512");
	sshkey_free(k2);
	TEST_పూర్తి();

	TEST_ప్రారంభం("load RSA cert");
	ASSERT_INT_EQ(sshkey_ఎక్కించు_cert(test_దత్తాంశం_file("rsa_1"), &k2), 0);
	ASSERT_PTR_NE(k2, ఖాళీ);
	ASSERT_INT_EQ(k2->type, కీలకం_RSA_CERT);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 0);
	ASSERT_INT_EQ(sshkey_equal_ప్రజా(k1, k2), 1);
	TEST_పూర్తి();

	TEST_ప్రారంభం("RSA key hex fingerprint");
	buf = ఎక్కించు_పాఠ్యం_file("rsa_1.fp");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, ఖాళీ);
	ASSERT_STRING_EQ(cp, (స్థిరరాశి అక్షరం *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	విడుదల(cp);
	TEST_పూర్తి();

	TEST_ప్రారంభం("RSA cert hex fingerprint");
	buf = ఎక్కించు_పాఠ్యం_file("rsa_1-cert.fp");
	cp = sshkey_fingerprint(k2, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, ఖాళీ);
	ASSERT_STRING_EQ(cp, (స్థిరరాశి అక్షరం *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	విడుదల(cp);
	sshkey_free(k2);
	TEST_పూర్తి();

	TEST_ప్రారంభం("RSA key bubblebabble fingerprint");
	buf = ఎక్కించు_పాఠ్యం_file("rsa_1.fp.bb");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA1, SSH_FP_BUBBLEBABBLE);
	ASSERT_PTR_NE(cp, ఖాళీ);
	ASSERT_STRING_EQ(cp, (స్థిరరాశి అక్షరం *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	విడుదల(cp);
	TEST_పూర్తి();

	sshkey_free(k1);


	TEST_ప్రారంభం("parse ECDSA from private");
	buf = ఎక్కించు_file("ecdsa_1");
	ASSERT_INT_EQ(sshkey_parse_వ్యక్తిగత_fileblob(buf, "", &k1, ఖాళీ), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k1, ఖాళీ);
	buf = ఎక్కించు_పాఠ్యం_file("ecdsa_1.param.curve");
	ASSERT_STRING_EQ((స్థిరరాశి అక్షరం *)sshbuf_ptr(buf),
	    OBJ_nid2sn(k1->ecdsa_nid));
	sshbuf_free(buf);
#నిర్వచితం_కాకపోతే OPENSSL_IS_BORINGSSL /* lacks EC_POINT_point2bn() */
	a = ఎక్కించు_bignum("ecdsa_1.param.priv");
	b = ఎక్కించు_bignum("ecdsa_1.param.pub");
	c = EC_బిందువు_point2bn(EC_కీలకం_get0_సమూహం(EVP_PKEY_get0_EC_కీలకం(k1->pkey)),
	    EC_కీలకం_get0_ప్రజా_కీలకం(EVP_PKEY_get0_EC_కీలకం(k1->pkey)),
	    బిందువు_CONVERSION_UNCOMPRESSED, ఖాళీ, ఖాళీ);
	ASSERT_PTR_NE(c, ఖాళీ);
	ASSERT_BIGNUM_EQ(
	    EC_కీలకం_get0_వ్యక్తిగత_కీలకం(EVP_PKEY_get0_EC_కీలకం(k1->pkey)), a);
	ASSERT_BIGNUM_EQ(b, c);
	BN_free(a);
	BN_free(b);
	BN_free(c);
#అయితే_ముగింపు /* OPENSSL_IS_BORINGSSL */
	TEST_పూర్తి();

	TEST_ప్రారంభం("parse ECDSA from private w/ passphrase");
	buf = ఎక్కించు_file("ecdsa_1_pw");
	ASSERT_INT_EQ(sshkey_parse_వ్యక్తిగత_fileblob(buf,
	    (స్థిరరాశి అక్షరం *)sshbuf_ptr(pw), &k2, ఖాళీ), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k2, ఖాళీ);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_పూర్తి();

	TEST_ప్రారంభం("parse ECDSA from new-format");
	buf = ఎక్కించు_file("ecdsa_n");
	ASSERT_INT_EQ(sshkey_parse_వ్యక్తిగత_fileblob(buf, "", &k2, ఖాళీ), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k2, ఖాళీ);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_పూర్తి();

	TEST_ప్రారంభం("parse ECDSA from new-format w/ passphrase");
	buf = ఎక్కించు_file("ecdsa_n_pw");
	ASSERT_INT_EQ(sshkey_parse_వ్యక్తిగత_fileblob(buf,
	    (స్థిరరాశి అక్షరం *)sshbuf_ptr(pw), &k2, ఖాళీ), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k2, ఖాళీ);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_పూర్తి();

	TEST_ప్రారంభం("load ECDSA from public");
	ASSERT_INT_EQ(sshkey_ఎక్కించు_ప్రజా(test_దత్తాంశం_file("ecdsa_1.pub"), &k2,
	    ఖాళీ), 0);
	ASSERT_PTR_NE(k2, ఖాళీ);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_పూర్తి();

	TEST_ప్రారంభం("load ECDSA cert");
	ASSERT_INT_EQ(sshkey_ఎక్కించు_cert(test_దత్తాంశం_file("ecdsa_1"), &k2), 0);
	ASSERT_PTR_NE(k2, ఖాళీ);
	ASSERT_INT_EQ(k2->type, కీలకం_ECDSA_CERT);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 0);
	ASSERT_INT_EQ(sshkey_equal_ప్రజా(k1, k2), 1);
	TEST_పూర్తి();

	TEST_ప్రారంభం("ECDSA key hex fingerprint");
	buf = ఎక్కించు_పాఠ్యం_file("ecdsa_1.fp");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, ఖాళీ);
	ASSERT_STRING_EQ(cp, (స్థిరరాశి అక్షరం *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	విడుదల(cp);
	TEST_పూర్తి();

	TEST_ప్రారంభం("ECDSA cert hex fingerprint");
	buf = ఎక్కించు_పాఠ్యం_file("ecdsa_1-cert.fp");
	cp = sshkey_fingerprint(k2, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, ఖాళీ);
	ASSERT_STRING_EQ(cp, (స్థిరరాశి అక్షరం *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	విడుదల(cp);
	sshkey_free(k2);
	TEST_పూర్తి();

	TEST_ప్రారంభం("ECDSA key bubblebabble fingerprint");
	buf = ఎక్కించు_పాఠ్యం_file("ecdsa_1.fp.bb");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA1, SSH_FP_BUBBLEBABBLE);
	ASSERT_PTR_NE(cp, ఖాళీ);
	ASSERT_STRING_EQ(cp, (స్థిరరాశి అక్షరం *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	విడుదల(cp);
	TEST_పూర్తి();

	sshkey_free(k1);
#అయితే_ముగింపు /* WITH_OPENSSL */

	TEST_ప్రారంభం("parse Ed25519 from private");
	buf = ఎక్కించు_file("ed25519_1");
	ASSERT_INT_EQ(sshkey_parse_వ్యక్తిగత_fileblob(buf, "", &k1, ఖాళీ), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k1, ఖాళీ);
	ASSERT_INT_EQ(k1->type, కీలకం_ED25519);
	/* XXX check key contents */
	TEST_పూర్తి();

	TEST_ప్రారంభం("parse Ed25519 from private w/ passphrase");
	buf = ఎక్కించు_file("ed25519_1_pw");
	ASSERT_INT_EQ(sshkey_parse_వ్యక్తిగత_fileblob(buf,
	    (స్థిరరాశి అక్షరం *)sshbuf_ptr(pw), &k2, ఖాళీ), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k2, ఖాళీ);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_పూర్తి();

	TEST_ప్రారంభం("load Ed25519 from public");
	ASSERT_INT_EQ(sshkey_ఎక్కించు_ప్రజా(test_దత్తాంశం_file("ed25519_1.pub"), &k2,
	    ఖాళీ), 0);
	ASSERT_PTR_NE(k2, ఖాళీ);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_పూర్తి();

	TEST_ప్రారంభం("load Ed25519 cert");
	ASSERT_INT_EQ(sshkey_ఎక్కించు_cert(test_దత్తాంశం_file("ed25519_1"), &k2), 0);
	ASSERT_PTR_NE(k2, ఖాళీ);
	ASSERT_INT_EQ(k2->type, కీలకం_ED25519_CERT);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 0);
	ASSERT_INT_EQ(sshkey_equal_ప్రజా(k1, k2), 1);
	TEST_పూర్తి();

	TEST_ప్రారంభం("Ed25519 key hex fingerprint");
	buf = ఎక్కించు_పాఠ్యం_file("ed25519_1.fp");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, ఖాళీ);
	ASSERT_STRING_EQ(cp, (స్థిరరాశి అక్షరం *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	విడుదల(cp);
	TEST_పూర్తి();

	TEST_ప్రారంభం("Ed25519 cert hex fingerprint");
	buf = ఎక్కించు_పాఠ్యం_file("ed25519_1-cert.fp");
	cp = sshkey_fingerprint(k2, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, ఖాళీ);
	ASSERT_STRING_EQ(cp, (స్థిరరాశి అక్షరం *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	విడుదల(cp);
	sshkey_free(k2);
	TEST_పూర్తి();

	TEST_ప్రారంభం("Ed25519 key bubblebabble fingerprint");
	buf = ఎక్కించు_పాఠ్యం_file("ed25519_1.fp.bb");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA1, SSH_FP_BUBBLEBABBLE);
	ASSERT_PTR_NE(cp, ఖాళీ);
	ASSERT_STRING_EQ(cp, (స్థిరరాశి అక్షరం *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	విడుదల(cp);
	TEST_పూర్తి();

	sshkey_free(k1);

	TEST_ప్రారంభం("parse MLDSA44-ED25519 from private");
	buf = ఎక్కించు_file("mldsa44_ed25519_1");
	ASSERT_INT_EQ(sshkey_parse_వ్యక్తిగత_fileblob(buf, "", &k1, ఖాళీ), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k1, ఖాళీ);
	ASSERT_INT_EQ(k1->type, కీలకం_MLDSA44_ED25519);
	TEST_పూర్తి();

	TEST_ప్రారంభం("parse MLDSA44-ED25519 from private w/ passphrase");
	buf = ఎక్కించు_file("mldsa44_ed25519_1_pw");
	ASSERT_INT_EQ(sshkey_parse_వ్యక్తిగత_fileblob(buf,
	    (స్థిరరాశి అక్షరం *)sshbuf_ptr(pw), &k2, ఖాళీ), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k2, ఖాళీ);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_పూర్తి();

	TEST_ప్రారంభం("load MLDSA44-ED25519 from public");
	ASSERT_INT_EQ(sshkey_ఎక్కించు_ప్రజా(
	    test_దత్తాంశం_file("mldsa44_ed25519_1.pub"), &k2, ఖాళీ), 0);
	ASSERT_PTR_NE(k2, ఖాళీ);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_పూర్తి();

	TEST_ప్రారంభం("load MLDSA44-ED25519 cert");
	ASSERT_INT_EQ(sshkey_ఎక్కించు_cert(
	    test_దత్తాంశం_file("mldsa44_ed25519_1"), &k2), 0);
	ASSERT_PTR_NE(k2, ఖాళీ);
	ASSERT_INT_EQ(k2->type, కీలకం_MLDSA44_ED25519_CERT);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 0);
	ASSERT_INT_EQ(sshkey_equal_ప్రజా(k1, k2), 1);
	TEST_పూర్తి();

	TEST_ప్రారంభం("MLDSA44-ED25519 key hex fingerprint");
	buf = ఎక్కించు_పాఠ్యం_file("mldsa44_ed25519_1.fp");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, ఖాళీ);
	ASSERT_STRING_EQ(cp, (స్థిరరాశి అక్షరం *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	విడుదల(cp);
	TEST_పూర్తి();

	TEST_ప్రారంభం("MLDSA44-ED25519 cert hex fingerprint");
	buf = ఎక్కించు_పాఠ్యం_file("mldsa44_ed25519_1-cert.fp");
	cp = sshkey_fingerprint(k2, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, ఖాళీ);
	ASSERT_STRING_EQ(cp, (స్థిరరాశి అక్షరం *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	విడుదల(cp);
	sshkey_free(k2);
	TEST_పూర్తి();

	TEST_ప్రారంభం("MLDSA44-ED25519 key bubblebabble fingerprint");
	buf = ఎక్కించు_పాఠ్యం_file("mldsa44_ed25519_1.fp.bb");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA1, SSH_FP_BUBBLEBABBLE);
	ASSERT_PTR_NE(cp, ఖాళీ);
	ASSERT_STRING_EQ(cp, (స్థిరరాశి అక్షరం *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	విడుదల(cp);
	TEST_పూర్తి();

	sshkey_free(k1);

#నిర్వచితమైతే ENABLE_SK
#ఒకవేళ defined(WITH_OPENSSL)
	TEST_ప్రారంభం("parse ECDSA-SK from private");
	buf = ఎక్కించు_file("ecdsa_sk1");
	ASSERT_INT_EQ(sshkey_parse_వ్యక్తిగత_fileblob(buf, "", &k1, ఖాళీ), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k1, ఖాళీ);
	ASSERT_INT_EQ(k1->type, కీలకం_ECDSA_SK);
	TEST_పూర్తి();

	TEST_ప్రారంభం("parse ECDSA-SK from private w/ passphrase");
	buf = ఎక్కించు_file("ecdsa_sk1_pw");
	ASSERT_INT_EQ(sshkey_parse_వ్యక్తిగత_fileblob(buf,
	    (స్థిరరాశి అక్షరం *)sshbuf_ptr(pw), &k2, ఖాళీ), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k2, ఖాళీ);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_పూర్తి();

	TEST_ప్రారంభం("load ECDSA-SK from public");
	ASSERT_INT_EQ(sshkey_ఎక్కించు_ప్రజా(test_దత్తాంశం_file("ecdsa_sk1.pub"), &k2,
	    ఖాళీ), 0);
	ASSERT_PTR_NE(k2, ఖాళీ);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_పూర్తి();

	TEST_ప్రారంభం("load ECDSA-SK cert");
	ASSERT_INT_EQ(sshkey_ఎక్కించు_cert(test_దత్తాంశం_file("ecdsa_sk1"), &k2), 0);
	ASSERT_PTR_NE(k2, ఖాళీ);
	ASSERT_INT_EQ(k2->type, కీలకం_ECDSA_SK_CERT);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 0);
	ASSERT_INT_EQ(sshkey_equal_ప్రజా(k1, k2), 1);
	TEST_పూర్తి();

	TEST_ప్రారంభం("ECDSA-SK key hex fingerprint");
	buf = ఎక్కించు_పాఠ్యం_file("ecdsa_sk1.fp");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, ఖాళీ);
	ASSERT_STRING_EQ(cp, (స్థిరరాశి అక్షరం *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	విడుదల(cp);
	TEST_పూర్తి();

	TEST_ప్రారంభం("ECDSA-SK cert hex fingerprint");
	buf = ఎక్కించు_పాఠ్యం_file("ecdsa_sk1-cert.fp");
	cp = sshkey_fingerprint(k2, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, ఖాళీ);
	ASSERT_STRING_EQ(cp, (స్థిరరాశి అక్షరం *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	విడుదల(cp);
	sshkey_free(k2);
	TEST_పూర్తి();

	TEST_ప్రారంభం("ECDSA-SK key bubblebabble fingerprint");
	buf = ఎక్కించు_పాఠ్యం_file("ecdsa_sk1.fp.bb");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA1, SSH_FP_BUBBLEBABBLE);
	ASSERT_PTR_NE(cp, ఖాళీ);
	ASSERT_STRING_EQ(cp, (స్థిరరాశి అక్షరం *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	విడుదల(cp);
	TEST_పూర్తి();

	sshkey_free(k1);
#అయితే_ముగింపు

	TEST_ప్రారంభం("parse Ed25519-SK from private");
	buf = ఎక్కించు_file("ed25519_sk1");
	ASSERT_INT_EQ(sshkey_parse_వ్యక్తిగత_fileblob(buf, "", &k1, ఖాళీ), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k1, ఖాళీ);
	ASSERT_INT_EQ(k1->type, కీలకం_ED25519_SK);
	/* XXX check key contents */
	TEST_పూర్తి();

	TEST_ప్రారంభం("parse Ed25519-SK from private w/ passphrase");
	buf = ఎక్కించు_file("ed25519_sk1_pw");
	ASSERT_INT_EQ(sshkey_parse_వ్యక్తిగత_fileblob(buf,
	    (స్థిరరాశి అక్షరం *)sshbuf_ptr(pw), &k2, ఖాళీ), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k2, ఖాళీ);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_పూర్తి();

	TEST_ప్రారంభం("load Ed25519-SK from public");
	ASSERT_INT_EQ(sshkey_ఎక్కించు_ప్రజా(test_దత్తాంశం_file("ed25519_sk1.pub"),
	    &k2, ఖాళీ), 0);
	ASSERT_PTR_NE(k2, ఖాళీ);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_పూర్తి();

	TEST_ప్రారంభం("load Ed25519-SK cert");
	ASSERT_INT_EQ(sshkey_ఎక్కించు_cert(test_దత్తాంశం_file("ed25519_sk1"), &k2), 0);
	ASSERT_PTR_NE(k2, ఖాళీ);
	ASSERT_INT_EQ(k2->type, కీలకం_ED25519_SK_CERT);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 0);
	ASSERT_INT_EQ(sshkey_equal_ప్రజా(k1, k2), 1);
	TEST_పూర్తి();

	TEST_ప్రారంభం("Ed25519-SK key hex fingerprint");
	buf = ఎక్కించు_పాఠ్యం_file("ed25519_sk1.fp");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, ఖాళీ);
	ASSERT_STRING_EQ(cp, (స్థిరరాశి అక్షరం *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	విడుదల(cp);
	TEST_పూర్తి();

	TEST_ప్రారంభం("Ed25519-SK cert hex fingerprint");
	buf = ఎక్కించు_పాఠ్యం_file("ed25519_sk1-cert.fp");
	cp = sshkey_fingerprint(k2, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, ఖాళీ);
	ASSERT_STRING_EQ(cp, (స్థిరరాశి అక్షరం *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	విడుదల(cp);
	sshkey_free(k2);
	TEST_పూర్తి();

	TEST_ప్రారంభం("Ed25519-SK key bubblebabble fingerprint");
	buf = ఎక్కించు_పాఠ్యం_file("ed25519_sk1.fp.bb");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA1, SSH_FP_BUBBLEBABBLE);
	ASSERT_PTR_NE(cp, ఖాళీ);
	ASSERT_STRING_EQ(cp, (స్థిరరాశి అక్షరం *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	విడుదల(cp);
	TEST_పూర్తి();

	sshkey_free(k1);
#అయితే_ముగింపు /* ENABLE_SK */

	sshbuf_free(pw);

}
