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

#ifdef WITH_OPENSSL
#ضمن <openssl/err.h>
#ضمن <openssl/evp.h>
#ضمن <openssl/crypto.h>
#endif

#ضمن "ssherr.h"
#ضمن "authfile.h"
#ضمن "sshkey.h"
#ضمن "sshbuf.h"
#ضمن "sshsig.h"
#ضمن "log.h"

#ضمن "../test_helper/test_helper.h"

ساكن بنية sshbuf *
load_file(ثابت حرف *name)
{
	بنية sshbuf *ret = عدم;

	ASSERT_INT_EQ(sshbuf_load_file(test_data_file(name), &ret), 0);
	ASSERT_PTR_NE(ret, عدم);
	أرجع ret;
}

ساكن بنية sshkey *
load_کلید(ثابت حرف *name)
{
	بنية sshkey *ret = عدم;
	ASSERT_INT_EQ(sshkey_load_public(test_data_file(name), &ret, عدم), 0);
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

	k = load_کلید(keyname);
	sig = load_file(signame);
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
#endif

#ifdef WITH_OPENSSL
	OpenSSL_add_all_algorithms();
	OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, عدم);
#endif

	TEST_START("load data");
	پیغام = load_file("namespace");
	namespace = sshbuf_dup_string(پیغام);
	ASSERT_PTR_NE(namespace, عدم);
	sshbuf_free(پیغام);
	پیغام = load_file("signed-data");
	TEST_DONE();

#ifdef WITH_OPENSSL
	TEST_START("check RSA signature");
	check_sig("rsa.pub", "rsa.sig", پیغام, namespace);
	TEST_DONE();


	TEST_START("check ECDSA signature");
	check_sig("ecdsa.pub", "ecdsa.sig", پیغام, namespace);
	TEST_DONE();
#endif

	TEST_START("check ED25519 signature");
	check_sig("ed25519.pub", "ed25519.sig", پیغام, namespace);
	TEST_DONE();

	TEST_START("check MLDSA44-ED25519 signature");
	check_sig("mldsa44-ed25519.pub", "mldsa44-ed25519.sig", پیغام, namespace);
	TEST_DONE();

#ifdef ENABLE_SK
#إذا defined(WITH_OPENSSL)
	TEST_START("check ECDSA-SK signature");
	check_sig("ecdsa_sk.pub", "ecdsa_sk.sig", پیغام, namespace);
	TEST_DONE();
#endif

	TEST_START("check ED25519-SK signature");
	check_sig("ed25519_sk.pub", "ed25519_sk.sig", پیغام, namespace);
	TEST_DONE();

#إذا defined(WITH_OPENSSL)
	TEST_START("check ECDSA-SK webauthn signature");
	check_sig("ecdsa_sk_webauthn.pub", "ecdsa_sk_webauthn.sig",
	    پیغام, namespace);
	TEST_DONE();
#endif
#endif /* ENABLE_SK */

	sshbuf_free(پیغام);
	حرر(namespace);
}

فراغ
benchmarks(فراغ)
{
	printf("no benchmarks\n");
}
