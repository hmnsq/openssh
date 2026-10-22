/* 	$OpenBSD: tests.c,v 1.8 2026/06/29 07:46:22 djm Exp $ */
/*
 * Regress test for sshbuf.h buffer API
 *
 * Placed in the public domain
 */

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <sys/stat.h>
#ಅನ್ತರ್ಭಾವ <fcntl.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stdint.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>

#ifdef WITH_OPENSSL
#ಅನ್ತರ್ಭಾವ <openssl/err.h>
#ಅನ್ತರ್ಭಾವ <openssl/evp.h>
#ಅನ್ತರ್ಭಾವ <openssl/crypto.h>
#endif

#ಅನ್ತರ್ಭಾವ "ssherr.h"
#ಅನ್ತರ್ಭಾವ "authfile.h"
#ಅನ್ತರ್ಭಾವ "sshkey.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "sshsig.h"
#ಅನ್ತರ್ಭಾವ "log.h"

#ಅನ್ತರ್ಭಾವ "../test_helper/test_helper.h"

ಸ್ಥಿರ ಸಂರಚನಾ sshbuf *
load_file(ಧ್ರುವ ವರ್ಣ *name)
{
	ಸಂರಚನಾ sshbuf *ret = ರಿಕ್ತ;

	ASSERT_INT_EQ(sshbuf_load_file(test_data_file(name), &ret), 0);
	ASSERT_PTR_NE(ret, ರಿಕ್ತ);
	ಪ್ರತ್ಯಾಗಮ ret;
}

ಸ್ಥಿರ ಸಂರಚನಾ sshkey *
load_ಕೀಲಿ(ಧ್ರುವ ವರ್ಣ *name)
{
	ಸಂರಚನಾ sshkey *ret = ರಿಕ್ತ;
	ASSERT_INT_EQ(sshkey_load_public(test_data_file(name), &ret, ರಿಕ್ತ), 0);
	ASSERT_PTR_NE(ret, ರಿಕ್ತ);
	ಪ್ರತ್ಯಾಗಮ ret;
}

ಸ್ಥಿರ ಶೂನ್ಯ
check_sig(ಧ್ರುವ ವರ್ಣ *keyname, ಧ್ರುವ ವರ್ಣ *signame, ಧ್ರುವ ಸಂರಚನಾ sshbuf *ಸಂದೇಶ,
    ಧ್ರುವ ವರ್ಣ *namespace)
{
	ಸಂರಚನಾ sshkey *k, *sign_ಕೀಲಿ;
	ಸಂರಚನಾ sshbuf *sig, *rawsig;
	ಸಂರಚನಾ sshkey_sig_details *sig_details;

	k = load_ಕೀಲಿ(keyname);
	sig = load_file(signame);
	sign_ಕೀಲಿ = ರಿಕ್ತ;
	sig_details = ರಿಕ್ತ;
	rawsig = ರಿಕ್ತ;
	ASSERT_INT_EQ(sshsig_dearmor(sig, &rawsig), 0);
	ASSERT_INT_EQ(sshsig_verifyb(rawsig, ಸಂದೇಶ, namespace,
	    &sign_ಕೀಲಿ, &sig_details), 0);
	ASSERT_INT_EQ(sshkey_equal(k, sign_ಕೀಲಿ), 1);
	sshkey_free(k);
	sshkey_free(sign_ಕೀಲಿ);
	sshkey_sig_details_free(sig_details);
	sshbuf_free(sig);
	sshbuf_free(rawsig);
}

ಶೂನ್ಯ
tests(ಶೂನ್ಯ)
{
	ಸಂರಚನಾ sshbuf *ಸಂದೇಶ;
	ವರ್ಣ *namespace;

#ಯದಿ 0
        log_init("test_sshsig", SYSLOG_LEVEL_DEBUG3, SYSLOG_FACILITY_AUTH, 1);
#endif

#ifdef WITH_OPENSSL
	OpenSSL_add_all_algorithms();
	OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, ರಿಕ್ತ);
#endif

	TEST_START("load data");
	ಸಂದೇಶ = load_file("namespace");
	namespace = sshbuf_dup_string(ಸಂದೇಶ);
	ASSERT_PTR_NE(namespace, ರಿಕ್ತ);
	sshbuf_free(ಸಂದೇಶ);
	ಸಂದೇಶ = load_file("signed-data");
	TEST_DONE();

#ifdef WITH_OPENSSL
	TEST_START("check RSA signature");
	check_sig("rsa.pub", "rsa.sig", ಸಂದೇಶ, namespace);
	TEST_DONE();


	TEST_START("check ECDSA signature");
	check_sig("ecdsa.pub", "ecdsa.sig", ಸಂದೇಶ, namespace);
	TEST_DONE();
#endif

	TEST_START("check ED25519 signature");
	check_sig("ed25519.pub", "ed25519.sig", ಸಂದೇಶ, namespace);
	TEST_DONE();

	TEST_START("check MLDSA44-ED25519 signature");
	check_sig("mldsa44-ed25519.pub", "mldsa44-ed25519.sig", ಸಂದೇಶ, namespace);
	TEST_DONE();

#ifdef ENABLE_SK
#ಯದಿ defined(WITH_OPENSSL)
	TEST_START("check ECDSA-SK signature");
	check_sig("ecdsa_sk.pub", "ecdsa_sk.sig", ಸಂದೇಶ, namespace);
	TEST_DONE();
#endif

	TEST_START("check ED25519-SK signature");
	check_sig("ed25519_sk.pub", "ed25519_sk.sig", ಸಂದೇಶ, namespace);
	TEST_DONE();

#ಯದಿ defined(WITH_OPENSSL)
	TEST_START("check ECDSA-SK webauthn signature");
	check_sig("ecdsa_sk_webauthn.pub", "ecdsa_sk_webauthn.sig",
	    ಸಂದೇಶ, namespace);
	TEST_DONE();
#endif
#endif /* ENABLE_SK */

	sshbuf_free(ಸಂದೇಶ);
	ಮುಕ್ತ(namespace);
}

ಶೂನ್ಯ
benchmarks(ಶೂನ್ಯ)
{
	printf("no benchmarks\n");
}
