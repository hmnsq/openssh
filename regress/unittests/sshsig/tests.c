/* 	$OpenBSD: tests.c,v 1.8 2026/06/29 07:46:22 djm Exp $ */
/*
 * Regress test for sshbuf.h buffer API
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
#अन्तर्भाव <openssl/err.h>
#अन्तर्भाव <openssl/evp.h>
#अन्तर्भाव <openssl/crypto.h>
#यदि_अन्तः

#अन्तर्भाव "ssherr.h"
#अन्तर्भाव "authfile.h"
#अन्तर्भाव "sshkey.h"
#अन्तर्भाव "sshbuf.h"
#अन्तर्भाव "sshsig.h"
#अन्तर्भाव "log.h"

#अन्तर्भाव "../test_helper/test_helper.h"

स्थिर संरचना sshbuf *
आरोपय_file(ध्रुव वर्ण *name)
{
	संरचना sshbuf *ret = रिक्त;

	ASSERT_INT_EQ(sshbuf_आरोपय_file(test_दत्त_file(name), &ret), 0);
	ASSERT_PTR_NE(ret, रिक्त);
	प्रत्यागम ret;
}

स्थिर संरचना sshkey *
आरोपय_कुञ्चिका(ध्रुव वर्ण *name)
{
	संरचना sshkey *ret = रिक्त;
	ASSERT_INT_EQ(sshkey_आरोपय_लौकिकम्(test_दत्त_file(name), &ret, रिक्त), 0);
	ASSERT_PTR_NE(ret, रिक्त);
	प्रत्यागम ret;
}

स्थिर शून्य
check_sig(ध्रुव वर्ण *keyname, ध्रुव वर्ण *signame, ध्रुव संरचना sshbuf *सन्देशः,
    ध्रुव वर्ण *namespace)
{
	संरचना sshkey *k, *sign_कुञ्चिका;
	संरचना sshbuf *sig, *rawsig;
	संरचना sshkey_sig_details *sig_details;

	k = आरोपय_कुञ्चिका(keyname);
	sig = आरोपय_file(signame);
	sign_कुञ्चिका = रिक्त;
	sig_details = रिक्त;
	rawsig = रिक्त;
	ASSERT_INT_EQ(sshsig_dearmor(sig, &rawsig), 0);
	ASSERT_INT_EQ(sshsig_verifyb(rawsig, सन्देशः, namespace,
	    &sign_कुञ्चिका, &sig_details), 0);
	ASSERT_INT_EQ(sshkey_equal(k, sign_कुञ्चिका), 1);
	sshkey_free(k);
	sshkey_free(sign_कुञ्चिका);
	sshkey_sig_details_free(sig_details);
	sshbuf_free(sig);
	sshbuf_free(rawsig);
}

शून्य
tests(शून्य)
{
	संरचना sshbuf *सन्देशः;
	वर्ण *namespace;

#यदि 0
        log_init("test_sshsig", SYSLOG_LEVEL_DEBUG3, SYSLOG_FACILITY_AUTH, 1);
#यदि_अन्तः

#यदि_परिभाषितम् WITH_OPENSSL
	Open_SSL_सङ्कलय_all_algorithms();
	OPENSSL_init_crypto(OPENSSL_INIT_आरोपय_CRYPTO_वाक्यानि, रिक्त);
#यदि_अन्तः

	TEST_START("load data");
	सन्देशः = आरोपय_file("namespace");
	namespace = sshbuf_dup_string(सन्देशः);
	ASSERT_PTR_NE(namespace, रिक्त);
	sshbuf_free(सन्देशः);
	सन्देशः = आरोपय_file("signed-data");
	TEST_समाप्तम्();

#यदि_परिभाषितम् WITH_OPENSSL
	TEST_START("check RSA signature");
	check_sig("rsa.pub", "rsa.sig", सन्देशः, namespace);
	TEST_समाप्तम्();


	TEST_START("check ECDSA signature");
	check_sig("ecdsa.pub", "ecdsa.sig", सन्देशः, namespace);
	TEST_समाप्तम्();
#यदि_अन्तः

	TEST_START("check ED25519 signature");
	check_sig("ed25519.pub", "ed25519.sig", सन्देशः, namespace);
	TEST_समाप्तम्();

	TEST_START("check MLDSA44-ED25519 signature");
	check_sig("mldsa44-ed25519.pub", "mldsa44-ed25519.sig", सन्देशः, namespace);
	TEST_समाप्तम्();

#यदि_परिभाषितम् ENABLE_SK
#यदि defined(WITH_OPENSSL)
	TEST_START("check ECDSA-SK signature");
	check_sig("ecdsa_sk.pub", "ecdsa_sk.sig", सन्देशः, namespace);
	TEST_समाप्तम्();
#यदि_अन्तः

	TEST_START("check ED25519-SK signature");
	check_sig("ed25519_sk.pub", "ed25519_sk.sig", सन्देशः, namespace);
	TEST_समाप्तम्();

#यदि defined(WITH_OPENSSL)
	TEST_START("check ECDSA-SK webauthn signature");
	check_sig("ecdsa_sk_webauthn.pub", "ecdsa_sk_webauthn.sig",
	    सन्देशः, namespace);
	TEST_समाप्तम्();
#यदि_अन्तः
#यदि_अन्तः /* ENABLE_SK */

	sshbuf_free(सन्देशः);
	मुक्त(namespace);
}

शून्य
benchmarks(शून्य)
{
	प्रारूप_लिख("no benchmarks\n");
}
