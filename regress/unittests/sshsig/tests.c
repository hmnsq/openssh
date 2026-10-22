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

#اگر_تعریف_شدہ WITH_OPENSSL
#شامل <openssl/err.h>
#شامل <openssl/evp.h>
#شامل <openssl/crypto.h>
#اگر_ختم

#شامل "ssherr.h"
#شامل "authfile.h"
#شامل "sshkey.h"
#شامل "sshbuf.h"
#شامل "sshsig.h"
#شامل "log.h"

#شامل "../test_helper/test_helper.h"

ساکن ساخت sshbuf *
بھرو_file(ثابت حرف *name)
{
	ساخت sshbuf *ret = تہی;

	ASSERT_INT_EQ(sshbuf_بھرو_file(test_ڈیٹا_file(name), &ret), 0);
	ASSERT_PTR_NE(ret, تہی);
	واپس ret;
}

ساکن ساخت sshkey *
بھرو_کلید(ثابت حرف *name)
{
	ساخت sshkey *ret = تہی;
	ASSERT_INT_EQ(sshkey_بھرو_عوامی(test_ڈیٹا_file(name), &ret, تہی), 0);
	ASSERT_PTR_NE(ret, تہی);
	واپس ret;
}

ساکن خالی
check_sig(ثابت حرف *keyname, ثابت حرف *signame, ثابت ساخت sshbuf *پیغام,
    ثابت حرف *namespace)
{
	ساخت sshkey *k, *sign_کلید;
	ساخت sshbuf *sig, *rawsig;
	ساخت sshkey_sig_details *sig_details;

	k = بھرو_کلید(keyname);
	sig = بھرو_file(signame);
	sign_کلید = تہی;
	sig_details = تہی;
	rawsig = تہی;
	ASSERT_INT_EQ(sshsig_dearmor(sig, &rawsig), 0);
	ASSERT_INT_EQ(sshsig_verifyb(rawsig, پیغام, namespace,
	    &sign_کلید, &sig_details), 0);
	ASSERT_INT_EQ(sshkey_equal(k, sign_کلید), 1);
	sshkey_free(k);
	sshkey_free(sign_کلید);
	sshkey_sig_details_free(sig_details);
	sshbuf_free(sig);
	sshbuf_free(rawsig);
}

خالی
tests(خالی)
{
	ساخت sshbuf *پیغام;
	حرف *namespace;

#اگر 0
        log_init("test_sshsig", SYSLOG_LEVEL_DEBUG3, SYSLOG_FACILITY_AUTH, 1);
#اگر_ختم

#اگر_تعریف_شدہ WITH_OPENSSL
	Open_SSL_جوڑو_all_algorithms();
	OPENSSL_init_crypto(OPENSSL_INIT_بھرو_CRYPTO_لڑیاں, تہی);
#اگر_ختم

	TEST_آغاز("load data");
	پیغام = بھرو_file("namespace");
	namespace = sshbuf_dup_string(پیغام);
	ASSERT_PTR_NE(namespace, تہی);
	sshbuf_free(پیغام);
	پیغام = بھرو_file("signed-data");
	TEST_مکمل();

#اگر_تعریف_شدہ WITH_OPENSSL
	TEST_آغاز("check RSA signature");
	check_sig("rsa.pub", "rsa.sig", پیغام, namespace);
	TEST_مکمل();


	TEST_آغاز("check ECDSA signature");
	check_sig("ecdsa.pub", "ecdsa.sig", پیغام, namespace);
	TEST_مکمل();
#اگر_ختم

	TEST_آغاز("check ED25519 signature");
	check_sig("ed25519.pub", "ed25519.sig", پیغام, namespace);
	TEST_مکمل();

	TEST_آغاز("check MLDSA44-ED25519 signature");
	check_sig("mldsa44-ed25519.pub", "mldsa44-ed25519.sig", پیغام, namespace);
	TEST_مکمل();

#اگر_تعریف_شدہ ENABLE_SK
#اگر defined(WITH_OPENSSL)
	TEST_آغاز("check ECDSA-SK signature");
	check_sig("ecdsa_sk.pub", "ecdsa_sk.sig", پیغام, namespace);
	TEST_مکمل();
#اگر_ختم

	TEST_آغاز("check ED25519-SK signature");
	check_sig("ed25519_sk.pub", "ed25519_sk.sig", پیغام, namespace);
	TEST_مکمل();

#اگر defined(WITH_OPENSSL)
	TEST_آغاز("check ECDSA-SK webauthn signature");
	check_sig("ecdsa_sk_webauthn.pub", "ecdsa_sk_webauthn.sig",
	    پیغام, namespace);
	TEST_مکمل();
#اگر_ختم
#اگر_ختم /* ENABLE_SK */

	sshbuf_free(پیغام);
	آزاد(namespace);
}

خالی
benchmarks(خالی)
{
	لکھو("no benchmarks\n");
}
