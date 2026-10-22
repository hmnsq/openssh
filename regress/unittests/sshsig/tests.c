/* 	$OpenBSD: tests.c,v 1.8 2026/06/29 07:46:22 djm Exp $ */
/*
 * Regress test for sshbuf.h buffer API
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

#جے_تعریف_شدہ WITH_OPENSSL
#ضمن <openssl/err.h>
#ضمن <openssl/evp.h>
#ضمن <openssl/crypto.h>
#جے_انت

#ضمن "ssherr.h"
#ضمن "authfile.h"
#ضمن "sshkey.h"
#ضمن "sshbuf.h"
#ضمن "sshsig.h"
#ضمن "log.h"

#ضمن "../test_helper/test_helper.h"

ساكن بنية sshbuf *
لدو_file(ثابت حرف *name)
{
	بنية sshbuf *ret = عدم;

	ASSERT_INT_EQ(sshbuf_لدو_file(test_انکڑے_file(name), &ret), 0);
	ASSERT_PTR_NE(ret, عدم);
	أرجع ret;
}

ساكن بنية sshkey *
لدو_کلید(ثابت حرف *name)
{
	بنية sshkey *ret = عدم;
	ASSERT_INT_EQ(sshkey_لدو_عوامی(test_انکڑے_file(name), &ret, عدم), 0);
	ASSERT_PTR_NE(ret, عدم);
	أرجع ret;
}

ساكن فراغ
check_sig(ثابت حرف *keyname, ثابت حرف *signame, ثابت بنية sshbuf *پیغام,
    ثابت حرف *namespace)
{
	بنية sshkey *k, *sign_کلید;
	بنية sshbuf *sig, *rawsig;
	بنية sshkey_sig_details *sig_details;

	k = لدو_کلید(keyname);
	sig = لدو_file(signame);
	sign_کلید = عدم;
	sig_details = عدم;
	rawsig = عدم;
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

فراغ
tests(فراغ)
{
	بنية sshbuf *پیغام;
	حرف *namespace;

#إذا 0
        log_init("test_sshsig", SYSLOG_LEVEL_DEBUG3, SYSLOG_FACILITY_AUTH, 1);
#جے_انت

#جے_تعریف_شدہ WITH_OPENSSL
	Open_SSL_جوڑو_all_algorithms();
	OPENSSL_init_crypto(OPENSSL_INIT_لدو_CRYPTO_لڑیاں, عدم);
#جے_انت

	TEST_شروع("load data");
	پیغام = لدو_file("namespace");
	namespace = sshbuf_dup_string(پیغام);
	ASSERT_PTR_NE(namespace, عدم);
	sshbuf_free(پیغام);
	پیغام = لدو_file("signed-data");
	TEST_پورا();

#جے_تعریف_شدہ WITH_OPENSSL
	TEST_شروع("check RSA signature");
	check_sig("rsa.pub", "rsa.sig", پیغام, namespace);
	TEST_پورا();


	TEST_شروع("check ECDSA signature");
	check_sig("ecdsa.pub", "ecdsa.sig", پیغام, namespace);
	TEST_پورا();
#جے_انت

	TEST_شروع("check ED25519 signature");
	check_sig("ed25519.pub", "ed25519.sig", پیغام, namespace);
	TEST_پورا();

	TEST_شروع("check MLDSA44-ED25519 signature");
	check_sig("mldsa44-ed25519.pub", "mldsa44-ed25519.sig", پیغام, namespace);
	TEST_پورا();

#جے_تعریف_شدہ ENABLE_SK
#إذا defined(WITH_OPENSSL)
	TEST_شروع("check ECDSA-SK signature");
	check_sig("ecdsa_sk.pub", "ecdsa_sk.sig", پیغام, namespace);
	TEST_پورا();
#جے_انت

	TEST_شروع("check ED25519-SK signature");
	check_sig("ed25519_sk.pub", "ed25519_sk.sig", پیغام, namespace);
	TEST_پورا();

#إذا defined(WITH_OPENSSL)
	TEST_شروع("check ECDSA-SK webauthn signature");
	check_sig("ecdsa_sk_webauthn.pub", "ecdsa_sk_webauthn.sig",
	    پیغام, namespace);
	TEST_پورا();
#جے_انت
#جے_انت /* ENABLE_SK */

	sshbuf_free(پیغام);
	حرر(namespace);
}

فراغ
benchmarks(فراغ)
{
	لکھو("no benchmarks\n");
}
