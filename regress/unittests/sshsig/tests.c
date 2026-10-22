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

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
#ಅನ್ತರ್ಭಾವ <openssl/err.h>
#ಅನ್ತರ್ಭಾವ <openssl/evp.h>
#ಅನ್ತರ್ಭಾವ <openssl/crypto.h>
#ಆದರೆ_ಅಂತ್ಯ

#ಅನ್ತರ್ಭಾವ "ssherr.h"
#ಅನ್ತರ್ಭಾವ "authfile.h"
#ಅನ್ತರ್ಭಾವ "sshkey.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "sshsig.h"
#ಅನ್ತರ್ಭಾವ "log.h"

#ಅನ್ತರ್ಭಾವ "../test_helper/test_helper.h"

ಸ್ಥಿರ ರಚನೆ sshbuf *
ತುಂಬು_file(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *name)
{
	ರಚನೆ sshbuf *ret = ಖಾಲಿ;

	ASSERT_INT_EQ(sshbuf_ತುಂಬು_file(test_ದತ್ತಾಂಶ_file(name), &ret), 0);
	ASSERT_PTR_NE(ret, ಖಾಲಿ);
	ಹಿಂತಿರುಗಿ ret;
}

ಸ್ಥಿರ ರಚನೆ sshkey *
ತುಂಬು_ಕೀಲಿ(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *name)
{
	ರಚನೆ sshkey *ret = ಖಾಲಿ;
	ASSERT_INT_EQ(sshkey_ತುಂಬು_ಬಹಿರಂಗ(test_ದತ್ತಾಂಶ_file(name), &ret, ಖಾಲಿ), 0);
	ASSERT_PTR_NE(ret, ಖಾಲಿ);
	ಹಿಂತಿರುಗಿ ret;
}

ಸ್ಥಿರ ಶೂನ್ಯ
check_sig(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *keyname, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *signame, ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *ಸಂದೇಶ,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *namespace)
{
	ರಚನೆ sshkey *k, *sign_ಕೀಲಿ;
	ರಚನೆ sshbuf *sig, *rawsig;
	ರಚನೆ sshkey_sig_details *sig_details;

	k = ತುಂಬು_ಕೀಲಿ(keyname);
	sig = ತುಂಬು_file(signame);
	sign_ಕೀಲಿ = ಖಾಲಿ;
	sig_details = ಖಾಲಿ;
	rawsig = ಖಾಲಿ;
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
	ರಚನೆ sshbuf *ಸಂದೇಶ;
	ಅಕ್ಷರ *namespace;

#ಆದರೆ 0
        log_init("test_sshsig", SYSLOG_LEVEL_DEBUG3, SYSLOG_FACILITY_AUTH, 1);
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
	Open_SSL_ಕೂಡಿಸು_all_algorithms();
	OPENSSL_init_crypto(OPENSSL_INIT_ತುಂಬು_CRYPTO_ಅಕ್ಷರಸರಣಿಗಳು, ಖಾಲಿ);
#ಆದರೆ_ಅಂತ್ಯ

	TEST_ಆರಂಭ("load data");
	ಸಂದೇಶ = ತುಂಬು_file("namespace");
	namespace = sshbuf_dup_string(ಸಂದೇಶ);
	ASSERT_PTR_NE(namespace, ಖಾಲಿ);
	sshbuf_free(ಸಂದೇಶ);
	ಸಂದೇಶ = ತುಂಬು_file("signed-data");
	TEST_ಮುಗಿದ();

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
	TEST_ಆರಂಭ("check RSA signature");
	check_sig("rsa.pub", "rsa.sig", ಸಂದೇಶ, namespace);
	TEST_ಮುಗಿದ();


	TEST_ಆರಂಭ("check ECDSA signature");
	check_sig("ecdsa.pub", "ecdsa.sig", ಸಂದೇಶ, namespace);
	TEST_ಮುಗಿದ();
#ಆದರೆ_ಅಂತ್ಯ

	TEST_ಆರಂಭ("check ED25519 signature");
	check_sig("ed25519.pub", "ed25519.sig", ಸಂದೇಶ, namespace);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("check MLDSA44-ED25519 signature");
	check_sig("mldsa44-ed25519.pub", "mldsa44-ed25519.sig", ಸಂದೇಶ, namespace);
	TEST_ಮುಗಿದ();

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ ENABLE_SK
#ಆದರೆ defined(WITH_OPENSSL)
	TEST_ಆರಂಭ("check ECDSA-SK signature");
	check_sig("ecdsa_sk.pub", "ecdsa_sk.sig", ಸಂದೇಶ, namespace);
	TEST_ಮುಗಿದ();
#ಆದರೆ_ಅಂತ್ಯ

	TEST_ಆರಂಭ("check ED25519-SK signature");
	check_sig("ed25519_sk.pub", "ed25519_sk.sig", ಸಂದೇಶ, namespace);
	TEST_ಮುಗಿದ();

#ಆದರೆ defined(WITH_OPENSSL)
	TEST_ಆರಂಭ("check ECDSA-SK webauthn signature");
	check_sig("ecdsa_sk_webauthn.pub", "ecdsa_sk_webauthn.sig",
	    ಸಂದೇಶ, namespace);
	TEST_ಮುಗಿದ();
#ಆದರೆ_ಅಂತ್ಯ
#ಆದರೆ_ಅಂತ್ಯ /* ENABLE_SK */

	sshbuf_free(ಸಂದೇಶ);
	ಬಿಡುಗಡೆ(namespace);
}

ಶೂನ್ಯ
benchmarks(ಶೂನ್ಯ)
{
	ಬರೆ("no benchmarks\n");
}
