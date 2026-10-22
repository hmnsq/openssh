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

#ifdef WITH_OPENSSL
#अन्तर्भाव <openssl/err.h>
#अन्तर्भाव <openssl/evp.h>
#अन्तर्भाव <openssl/crypto.h>
#endif

#अन्तर्भाव "ssherr.h"
#अन्तर्भाव "authfile.h"
#अन्तर्भाव "sshkey.h"
#अन्तर्भाव "sshbuf.h"
#अन्तर्भाव "sshsig.h"
#अन्तर्भाव "log.h"

#अन्तर्भाव "../test_helper/test_helper.h"

स्थिर संरचना sshbuf *
load_file(स्थिरांक अक्षर *name)
{
	संरचना sshbuf *ret = रिक्त;

	ASSERT_INT_EQ(sshbuf_load_file(test_data_file(name), &ret), 0);
	ASSERT_PTR_NE(ret, रिक्त);
	परत ret;
}

स्थिर संरचना sshkey *
load_किल्ली(स्थिरांक अक्षर *name)
{
	संरचना sshkey *ret = रिक्त;
	ASSERT_INT_EQ(sshkey_load_public(test_data_file(name), &ret, रिक्त), 0);
	ASSERT_PTR_NE(ret, रिक्त);
	परत ret;
}

स्थिर शून्य
check_sig(स्थिरांक अक्षर *keyname, स्थिरांक अक्षर *signame, स्थिरांक संरचना sshbuf *संदेश,
    स्थिरांक अक्षर *namespace)
{
	संरचना sshkey *k, *sign_किल्ली;
	संरचना sshbuf *sig, *rawsig;
	संरचना sshkey_sig_details *sig_details;

	k = load_किल्ली(keyname);
	sig = load_file(signame);
	sign_किल्ली = रिक्त;
	sig_details = रिक्त;
	rawsig = रिक्त;
	ASSERT_INT_EQ(sshsig_dearmor(sig, &rawsig), 0);
	ASSERT_INT_EQ(sshsig_verifyb(rawsig, संदेश, namespace,
	    &sign_किल्ली, &sig_details), 0);
	ASSERT_INT_EQ(sshkey_equal(k, sign_किल्ली), 1);
	sshkey_free(k);
	sshkey_free(sign_किल्ली);
	sshkey_sig_details_free(sig_details);
	sshbuf_free(sig);
	sshbuf_free(rawsig);
}

शून्य
tests(शून्य)
{
	संरचना sshbuf *संदेश;
	अक्षर *namespace;

#जर 0
        log_init("test_sshsig", SYSLOG_LEVEL_DEBUG3, SYSLOG_FACILITY_AUTH, 1);
#endif

#ifdef WITH_OPENSSL
	OpenSSL_add_all_algorithms();
	OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, रिक्त);
#endif

	TEST_START("load data");
	संदेश = load_file("namespace");
	namespace = sshbuf_dup_string(संदेश);
	ASSERT_PTR_NE(namespace, रिक्त);
	sshbuf_free(संदेश);
	संदेश = load_file("signed-data");
	TEST_DONE();

#ifdef WITH_OPENSSL
	TEST_START("check RSA signature");
	check_sig("rsa.pub", "rsa.sig", संदेश, namespace);
	TEST_DONE();


	TEST_START("check ECDSA signature");
	check_sig("ecdsa.pub", "ecdsa.sig", संदेश, namespace);
	TEST_DONE();
#endif

	TEST_START("check ED25519 signature");
	check_sig("ed25519.pub", "ed25519.sig", संदेश, namespace);
	TEST_DONE();

	TEST_START("check MLDSA44-ED25519 signature");
	check_sig("mldsa44-ed25519.pub", "mldsa44-ed25519.sig", संदेश, namespace);
	TEST_DONE();

#ifdef ENABLE_SK
#जर defined(WITH_OPENSSL)
	TEST_START("check ECDSA-SK signature");
	check_sig("ecdsa_sk.pub", "ecdsa_sk.sig", संदेश, namespace);
	TEST_DONE();
#endif

	TEST_START("check ED25519-SK signature");
	check_sig("ed25519_sk.pub", "ed25519_sk.sig", संदेश, namespace);
	TEST_DONE();

#जर defined(WITH_OPENSSL)
	TEST_START("check ECDSA-SK webauthn signature");
	check_sig("ecdsa_sk_webauthn.pub", "ecdsa_sk_webauthn.sig",
	    संदेश, namespace);
	TEST_DONE();
#endif
#endif /* ENABLE_SK */

	sshbuf_free(संदेश);
	मुक्त(namespace);
}

शून्य
benchmarks(शून्य)
{
	म_लिखो("no benchmarks\n");
}
