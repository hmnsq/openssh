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

#که_تعریف_شوی WITH_OPENSSL
#ضمن <openssl/err.h>
#ضمن <openssl/evp.h>
#ضمن <openssl/crypto.h>
#د_که_پای

#ضمن "ssherr.h"
#ضمن "authfile.h"
#ضمن "sshkey.h"
#ضمن "sshbuf.h"
#ضمن "sshsig.h"
#ضمن "log.h"

#ضمن "../test_helper/test_helper.h"

ساكن بنية sshbuf *
بارول_file(ثابت حرف *name)
{
	بنية sshbuf *ret = عدم;

	ASSERT_INT_EQ(sshbuf_بارول_file(test_معلومات_file(name), &ret), 0);
	ASSERT_PTR_NE(ret, عدم);
	أرجع ret;
}

ساكن بنية sshkey *
بارول_کلی(ثابت حرف *name)
{
	بنية sshkey *ret = عدم;
	ASSERT_INT_EQ(sshkey_بارول_عامه(test_معلومات_file(name), &ret, عدم), 0);
	ASSERT_PTR_NE(ret, عدم);
	أرجع ret;
}

ساكن فراغ
check_sig(ثابت حرف *keyname, ثابت حرف *signame, ثابت بنية sshbuf *پیغام,
    ثابت حرف *namespace)
{
	بنية sshkey *k, *sign_کلی;
	بنية sshbuf *sig, *rawsig;
	بنية sshkey_sig_details *sig_details;

	k = بارول_کلی(keyname);
	sig = بارول_file(signame);
	sign_کلی = عدم;
	sig_details = عدم;
	rawsig = عدم;
	ASSERT_INT_EQ(sshsig_dearmor(sig, &rawsig), 0);
	ASSERT_INT_EQ(sshsig_verifyb(rawsig, پیغام, namespace,
	    &sign_کلی, &sig_details), 0);
	ASSERT_INT_EQ(sshkey_equal(k, sign_کلی), 1);
	sshkey_free(k);
	sshkey_free(sign_کلی);
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
#د_که_پای

#که_تعریف_شوی WITH_OPENSSL
	Open_SSL_جمع_کړه_all_algorithms();
	OPENSSL_init_crypto(OPENSSL_INIT_بارول_CRYPTO_مزي_ګانې, عدم);
#د_که_پای

	TEST_پیل("load data");
	پیغام = بارول_file("namespace");
	namespace = sshbuf_dup_string(پیغام);
	ASSERT_PTR_NE(namespace, عدم);
	sshbuf_free(پیغام);
	پیغام = بارول_file("signed-data");
	TEST_بشپړ();

#که_تعریف_شوی WITH_OPENSSL
	TEST_پیل("check RSA signature");
	check_sig("rsa.pub", "rsa.sig", پیغام, namespace);
	TEST_بشپړ();


	TEST_پیل("check ECDSA signature");
	check_sig("ecdsa.pub", "ecdsa.sig", پیغام, namespace);
	TEST_بشپړ();
#د_که_پای

	TEST_پیل("check ED25519 signature");
	check_sig("ed25519.pub", "ed25519.sig", پیغام, namespace);
	TEST_بشپړ();

	TEST_پیل("check MLDSA44-ED25519 signature");
	check_sig("mldsa44-ed25519.pub", "mldsa44-ed25519.sig", پیغام, namespace);
	TEST_بشپړ();

#که_تعریف_شوی ENABLE_SK
#إذا defined(WITH_OPENSSL)
	TEST_پیل("check ECDSA-SK signature");
	check_sig("ecdsa_sk.pub", "ecdsa_sk.sig", پیغام, namespace);
	TEST_بشپړ();
#د_که_پای

	TEST_پیل("check ED25519-SK signature");
	check_sig("ed25519_sk.pub", "ed25519_sk.sig", پیغام, namespace);
	TEST_بشپړ();

#إذا defined(WITH_OPENSSL)
	TEST_پیل("check ECDSA-SK webauthn signature");
	check_sig("ecdsa_sk_webauthn.pub", "ecdsa_sk_webauthn.sig",
	    پیغام, namespace);
	TEST_بشپړ();
#د_که_پای
#د_که_پای /* ENABLE_SK */

	sshbuf_free(پیغام);
	حرر(namespace);
}

فراغ
benchmarks(فراغ)
{
	چاپ_کړه("no benchmarks\n");
}
