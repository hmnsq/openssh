/* 	$OpenBSD: tests.c,v 1.8 2026/06/29 07:46:22 djm Exp $ */
/*
 * Regress test for sshbuf.h buffer API
 *
 * Placed in the public domain
 */

#समावेश "includes.h"

#समावेश <sys/types.h>
#समावेश <sys/stat.h>
#समावेश <fcntl.h>
#समावेश <stdio.h>
#समावेश <stdint.h>
#समावेश <stdlib.h>
#समावेश <string.h>
#समावेश <unistd.h>

#अगर_घोषित WITH_OPENSSL
#समावेश <openssl/err.h>
#समावेश <openssl/evp.h>
#समावेश <openssl/crypto.h>
#पूर्ण_अगर

#समावेश "ssherr.h"
#समावेश "authfile.h"
#समावेश "sshkey.h"
#समावेश "sshbuf.h"
#समावेश "sshsig.h"
#समावेश "log.h"

#समावेश "../test_helper/test_helper.h"

अटल काष्ठा sshbuf *
load_file(स्थिर अक्षर *name)
{
	काष्ठा sshbuf *ret = शून्य;

	ASSERT_INT_EQ(sshbuf_load_file(test_तथ्य_file(name), &ret), 0);
	ASSERT_PTR_NE(ret, शून्य);
	वापस ret;
}

अटल काष्ठा sshkey *
load_कुंजी(स्थिर अक्षर *name)
{
	काष्ठा sshkey *ret = शून्य;
	ASSERT_INT_EQ(sshkey_load_public(test_तथ्य_file(name), &ret, शून्य), 0);
	ASSERT_PTR_NE(ret, शून्य);
	वापस ret;
}

अटल व्योम
check_sig(स्थिर अक्षर *keyname, स्थिर अक्षर *signame, स्थिर काष्ठा sshbuf *संदेश,
    स्थिर अक्षर *namespace)
{
	काष्ठा sshkey *k, *sign_कुंजी;
	काष्ठा sshbuf *sig, *rawsig;
	काष्ठा sshkey_sig_details *sig_details;

	k = load_कुंजी(keyname);
	sig = load_file(signame);
	sign_कुंजी = शून्य;
	sig_details = शून्य;
	rawsig = शून्य;
	ASSERT_INT_EQ(sshsig_dearmor(sig, &rawsig), 0);
	ASSERT_INT_EQ(sshsig_verifyb(rawsig, संदेश, namespace,
	    &sign_कुंजी, &sig_details), 0);
	ASSERT_INT_EQ(sshkey_equal(k, sign_कुंजी), 1);
	sshkey_free(k);
	sshkey_free(sign_कुंजी);
	sshkey_sig_details_free(sig_details);
	sshbuf_free(sig);
	sshbuf_free(rawsig);
}

व्योम
tests(व्योम)
{
	काष्ठा sshbuf *संदेश;
	अक्षर *namespace;

#अगर 0
        log_init("test_sshsig", SYSLOG_LEVEL_DEBUG3, SYSLOG_FACILITY_AUTH, 1);
#पूर्ण_अगर

#अगर_घोषित WITH_OPENSSL
	OpenSSL_add_all_algorithms();
	OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, शून्य);
#पूर्ण_अगर

	TEST_START("load data");
	संदेश = load_file("namespace");
	namespace = sshbuf_dup_string(संदेश);
	ASSERT_PTR_NE(namespace, शून्य);
	sshbuf_free(संदेश);
	संदेश = load_file("signed-data");
	TEST_DONE();

#अगर_घोषित WITH_OPENSSL
	TEST_START("check RSA signature");
	check_sig("rsa.pub", "rsa.sig", संदेश, namespace);
	TEST_DONE();


	TEST_START("check ECDSA signature");
	check_sig("ecdsa.pub", "ecdsa.sig", संदेश, namespace);
	TEST_DONE();
#पूर्ण_अगर

	TEST_START("check ED25519 signature");
	check_sig("ed25519.pub", "ed25519.sig", संदेश, namespace);
	TEST_DONE();

	TEST_START("check MLDSA44-ED25519 signature");
	check_sig("mldsa44-ed25519.pub", "mldsa44-ed25519.sig", संदेश, namespace);
	TEST_DONE();

#अगर_घोषित ENABLE_SK
#अगर defined(WITH_OPENSSL)
	TEST_START("check ECDSA-SK signature");
	check_sig("ecdsa_sk.pub", "ecdsa_sk.sig", संदेश, namespace);
	TEST_DONE();
#पूर्ण_अगर

	TEST_START("check ED25519-SK signature");
	check_sig("ed25519_sk.pub", "ed25519_sk.sig", संदेश, namespace);
	TEST_DONE();

#अगर defined(WITH_OPENSSL)
	TEST_START("check ECDSA-SK webauthn signature");
	check_sig("ecdsa_sk_webauthn.pub", "ecdsa_sk_webauthn.sig",
	    संदेश, namespace);
	TEST_DONE();
#पूर्ण_अगर
#पूर्ण_अगर /* ENABLE_SK */

	sshbuf_free(संदेश);
	मुक्त(namespace);
}

व्योम
benchmarks(व्योम)
{
	म_लिखो("no benchmarks\n");
}
