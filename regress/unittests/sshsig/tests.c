/* 	$OpenBSD: tests.c,v 1.8 2026/06/29 07:46:22 djm Exp $ */
/*
 * Regress test for sshbuf.h buffer API
 *
 * Placed in the public domain
 */

#شامل "includes.h"

#شامل <sys/types.h>
#شامل <sys/stat.h>
#شامل <fcntl.h>
#شامل <stdio.h>
#شامل <stdint.h>
#شامل <stdlib.h>
#شامل <string.h>
#شامل <unistd.h>

#ifdef WITH_OPENSSL
#شامل <openssl/err.h>
#شامل <openssl/evp.h>
#شامل <openssl/crypto.h>
#endif

#شامل "ssherr.h"
#شامل "authfile.h"
#شامل "sshkey.h"
#شامل "sshbuf.h"
#شامل "sshsig.h"
#شامل "log.h"

#شامل "../test_helper/test_helper.h"

ایستا ساختار sshbuf *
load_file(ثابت نویسه *name)
{
	ساختار sshbuf *ret = پوچ;

	ASSERT_INT_EQ(sshbuf_load_file(test_data_file(name), &ret), 0);
	ASSERT_PTR_NE(ret, پوچ);
	بازگشت ret;
}

ایستا ساختار sshkey *
load_کلید(ثابت نویسه *name)
{
	ساختار sshkey *ret = پوچ;
	ASSERT_INT_EQ(sshkey_load_public(test_data_file(name), &ret, پوچ), 0);
	ASSERT_PTR_NE(ret, پوچ);
	بازگشت ret;
}

ایستا تهی
check_sig(ثابت نویسه *keyname, ثابت نویسه *signame, ثابت ساختار sshbuf *پیام,
    ثابت نویسه *namespace)
{
	ساختار sshkey *k, *sign_کلید;
	ساختار sshbuf *sig, *rawsig;
	ساختار sshkey_sig_details *sig_details;

	k = load_کلید(keyname);
	sig = load_file(signame);
	sign_کلید = پوچ;
	sig_details = پوچ;
	rawsig = پوچ;
	ASSERT_INT_EQ(sshsig_dearmor(sig, &rawsig), 0);
	ASSERT_INT_EQ(sshsig_verifyb(rawsig, پیام, namespace,
	    &sign_کلید, &sig_details), 0);
	ASSERT_INT_EQ(sshkey_equal(k, sign_کلید), 1);
	sshkey_free(k);
	sshkey_free(sign_کلید);
	sshkey_sig_details_free(sig_details);
	sshbuf_free(sig);
	sshbuf_free(rawsig);
}

تهی
tests(تهی)
{
	ساختار sshbuf *پیام;
	نویسه *namespace;

#اگر 0
        log_init("test_sshsig", SYSLOG_LEVEL_DEBUG3, SYSLOG_FACILITY_AUTH, 1);
#endif

#ifdef WITH_OPENSSL
	OpenSSL_add_all_algorithms();
	OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, پوچ);
#endif

	TEST_START("load data");
	پیام = load_file("namespace");
	namespace = sshbuf_dup_string(پیام);
	ASSERT_PTR_NE(namespace, پوچ);
	sshbuf_free(پیام);
	پیام = load_file("signed-data");
	TEST_DONE();

#ifdef WITH_OPENSSL
	TEST_START("check RSA signature");
	check_sig("rsa.pub", "rsa.sig", پیام, namespace);
	TEST_DONE();


	TEST_START("check ECDSA signature");
	check_sig("ecdsa.pub", "ecdsa.sig", پیام, namespace);
	TEST_DONE();
#endif

	TEST_START("check ED25519 signature");
	check_sig("ed25519.pub", "ed25519.sig", پیام, namespace);
	TEST_DONE();

	TEST_START("check MLDSA44-ED25519 signature");
	check_sig("mldsa44-ed25519.pub", "mldsa44-ed25519.sig", پیام, namespace);
	TEST_DONE();

#ifdef ENABLE_SK
#اگر defined(WITH_OPENSSL)
	TEST_START("check ECDSA-SK signature");
	check_sig("ecdsa_sk.pub", "ecdsa_sk.sig", پیام, namespace);
	TEST_DONE();
#endif

	TEST_START("check ED25519-SK signature");
	check_sig("ed25519_sk.pub", "ed25519_sk.sig", پیام, namespace);
	TEST_DONE();

#اگر defined(WITH_OPENSSL)
	TEST_START("check ECDSA-SK webauthn signature");
	check_sig("ecdsa_sk_webauthn.pub", "ecdsa_sk_webauthn.sig",
	    پیام, namespace);
	TEST_DONE();
#endif
#endif /* ENABLE_SK */

	sshbuf_free(پیام);
	آزاد(namespace);
}

تهی
benchmarks(تهی)
{
	printf("no benchmarks\n");
}
