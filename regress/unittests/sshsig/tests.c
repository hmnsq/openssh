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

#جيڪڏهن_وصف_ٿيل WITH_OPENSSL
#ضمن <openssl/err.h>
#ضمن <openssl/evp.h>
#ضمن <openssl/crypto.h>
#جيڪڏهن_پورو

#ضمن "ssherr.h"
#ضمن "authfile.h"
#ضمن "sshkey.h"
#ضمن "sshbuf.h"
#ضمن "sshsig.h"
#ضمن "log.h"

#ضمن "../test_helper/test_helper.h"

ساكن بنية sshbuf *
ڀريو_file(ثابت حرف *name)
{
	بنية sshbuf *ret = عدم;

	ASSERT_INT_EQ(sshbuf_ڀريو_file(test_معلومات_file(name), &ret), 0);
	ASSERT_PTR_NE(ret, عدم);
	أرجع ret;
}

ساكن بنية sshkey *
ڀريو_ڪنجي(ثابت حرف *name)
{
	بنية sshkey *ret = عدم;
	ASSERT_INT_EQ(sshkey_ڀريو_عوامي(test_معلومات_file(name), &ret, عدم), 0);
	ASSERT_PTR_NE(ret, عدم);
	أرجع ret;
}

ساكن فراغ
check_sig(ثابت حرف *keyname, ثابت حرف *signame, ثابت بنية sshbuf *نياپو,
    ثابت حرف *namespace)
{
	بنية sshkey *k, *sign_ڪنجي;
	بنية sshbuf *sig, *rawsig;
	بنية sshkey_sig_details *sig_details;

	k = ڀريو_ڪنجي(keyname);
	sig = ڀريو_file(signame);
	sign_ڪنجي = عدم;
	sig_details = عدم;
	rawsig = عدم;
	ASSERT_INT_EQ(sshsig_dearmor(sig, &rawsig), 0);
	ASSERT_INT_EQ(sshsig_verifyb(rawsig, نياپو, namespace,
	    &sign_ڪنجي, &sig_details), 0);
	ASSERT_INT_EQ(sshkey_equal(k, sign_ڪنجي), 1);
	sshkey_free(k);
	sshkey_free(sign_ڪنجي);
	sshkey_sig_details_free(sig_details);
	sshbuf_free(sig);
	sshbuf_free(rawsig);
}

فراغ
tests(فراغ)
{
	بنية sshbuf *نياپو;
	حرف *namespace;

#إذا 0
        log_init("test_sshsig", SYSLOG_LEVEL_DEBUG3, SYSLOG_FACILITY_AUTH, 1);
#جيڪڏهن_پورو

#جيڪڏهن_وصف_ٿيل WITH_OPENSSL
	Open_SSL_جوڙيو_all_algorithms();
	OPENSSL_init_crypto(OPENSSL_INIT_ڀريو_CRYPTO_لڙيون, عدم);
#جيڪڏهن_پورو

	TEST_شروعات("load data");
	نياپو = ڀريو_file("namespace");
	namespace = sshbuf_dup_string(نياپو);
	ASSERT_PTR_NE(namespace, عدم);
	sshbuf_free(نياپو);
	نياپو = ڀريو_file("signed-data");
	TEST_پورو();

#جيڪڏهن_وصف_ٿيل WITH_OPENSSL
	TEST_شروعات("check RSA signature");
	check_sig("rsa.pub", "rsa.sig", نياپو, namespace);
	TEST_پورو();


	TEST_شروعات("check ECDSA signature");
	check_sig("ecdsa.pub", "ecdsa.sig", نياپو, namespace);
	TEST_پورو();
#جيڪڏهن_پورو

	TEST_شروعات("check ED25519 signature");
	check_sig("ed25519.pub", "ed25519.sig", نياپو, namespace);
	TEST_پورو();

	TEST_شروعات("check MLDSA44-ED25519 signature");
	check_sig("mldsa44-ed25519.pub", "mldsa44-ed25519.sig", نياپو, namespace);
	TEST_پورو();

#جيڪڏهن_وصف_ٿيل ENABLE_SK
#إذا defined(WITH_OPENSSL)
	TEST_شروعات("check ECDSA-SK signature");
	check_sig("ecdsa_sk.pub", "ecdsa_sk.sig", نياپو, namespace);
	TEST_پورو();
#جيڪڏهن_پورو

	TEST_شروعات("check ED25519-SK signature");
	check_sig("ed25519_sk.pub", "ed25519_sk.sig", نياپو, namespace);
	TEST_پورو();

#إذا defined(WITH_OPENSSL)
	TEST_شروعات("check ECDSA-SK webauthn signature");
	check_sig("ecdsa_sk_webauthn.pub", "ecdsa_sk_webauthn.sig",
	    نياپو, namespace);
	TEST_پورو();
#جيڪڏهن_پورو
#جيڪڏهن_پورو /* ENABLE_SK */

	sshbuf_free(نياپو);
	حرر(namespace);
}

فراغ
benchmarks(فراغ)
{
	لکو("no benchmarks\n");
}
