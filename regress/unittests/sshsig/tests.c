/* 	$OpenBSD: tests.c,v 1.8 2026/06/29 07:46:22 djm Exp $ */
/*
 * Regress test for sshbuf.h buffer API
 *
 * Placed in the public domain
 */

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/stat.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <fcntl.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdint.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/err.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/evp.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/crypto.h>
#ਜੇ_ਅੰਤ

#ਅਨ੍ਤਰ੍ਭਾਵ "ssherr.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "authfile.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshkey.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshbuf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshsig.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"

#ਅਨ੍ਤਰ੍ਭਾਵ "../test_helper/test_helper.h"

ਸਥਿਰ ਬਣਤਰ sshbuf *
ਲੱਦੋ_file(ਅਚਲ ਅੱਖਰ *name)
{
	ਬਣਤਰ sshbuf *ret = ਨਿਰਾ;

	ASSERT_INT_EQ(sshbuf_ਲੱਦੋ_file(test_ਅੰਕੜੇ_file(name), &ret), 0);
	ASSERT_PTR_NE(ret, ਨਿਰਾ);
	ਵਾਪਸ ret;
}

ਸਥਿਰ ਬਣਤਰ sshkey *
ਲੱਦੋ_ਕੁੰਜੀ(ਅਚਲ ਅੱਖਰ *name)
{
	ਬਣਤਰ sshkey *ret = ਨਿਰਾ;
	ASSERT_INT_EQ(sshkey_ਲੱਦੋ_ਜਨਤਕ(test_ਅੰਕੜੇ_file(name), &ret, ਨਿਰਾ), 0);
	ASSERT_PTR_NE(ret, ਨਿਰਾ);
	ਵਾਪਸ ret;
}

ਸਥਿਰ ਖਾਲੀ
check_sig(ਅਚਲ ਅੱਖਰ *keyname, ਅਚਲ ਅੱਖਰ *signame, ਅਚਲ ਬਣਤਰ sshbuf *ਸੁਨੇਹਾ,
    ਅਚਲ ਅੱਖਰ *namespace)
{
	ਬਣਤਰ sshkey *k, *sign_ਕੁੰਜੀ;
	ਬਣਤਰ sshbuf *sig, *rawsig;
	ਬਣਤਰ sshkey_sig_details *sig_details;

	k = ਲੱਦੋ_ਕੁੰਜੀ(keyname);
	sig = ਲੱਦੋ_file(signame);
	sign_ਕੁੰਜੀ = ਨਿਰਾ;
	sig_details = ਨਿਰਾ;
	rawsig = ਨਿਰਾ;
	ASSERT_INT_EQ(sshsig_dearmor(sig, &rawsig), 0);
	ASSERT_INT_EQ(sshsig_verifyb(rawsig, ਸੁਨੇਹਾ, namespace,
	    &sign_ਕੁੰਜੀ, &sig_details), 0);
	ASSERT_INT_EQ(sshkey_equal(k, sign_ਕੁੰਜੀ), 1);
	sshkey_free(k);
	sshkey_free(sign_ਕੁੰਜੀ);
	sshkey_sig_details_free(sig_details);
	sshbuf_free(sig);
	sshbuf_free(rawsig);
}

ਖਾਲੀ
tests(ਖਾਲੀ)
{
	ਬਣਤਰ sshbuf *ਸੁਨੇਹਾ;
	ਅੱਖਰ *namespace;

#ਜੇ 0
        log_init("test_sshsig", SYSLOG_LEVEL_DEBUG3, SYSLOG_FACILITY_AUTH, 1);
#ਜੇ_ਅੰਤ

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
	Open_SSL_ਜੋੜੋ_all_algorithms();
	OPENSSL_init_crypto(OPENSSL_INIT_ਲੱਦੋ_CRYPTO_ਲੜੀਆਂ, ਨਿਰਾ);
#ਜੇ_ਅੰਤ

	TEST_ਸ਼ੁਰੂ("load data");
	ਸੁਨੇਹਾ = ਲੱਦੋ_file("namespace");
	namespace = sshbuf_dup_string(ਸੁਨੇਹਾ);
	ASSERT_PTR_NE(namespace, ਨਿਰਾ);
	sshbuf_free(ਸੁਨੇਹਾ);
	ਸੁਨੇਹਾ = ਲੱਦੋ_file("signed-data");
	TEST_ਪੂਰਾ();

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
	TEST_ਸ਼ੁਰੂ("check RSA signature");
	check_sig("rsa.pub", "rsa.sig", ਸੁਨੇਹਾ, namespace);
	TEST_ਪੂਰਾ();


	TEST_ਸ਼ੁਰੂ("check ECDSA signature");
	check_sig("ecdsa.pub", "ecdsa.sig", ਸੁਨੇਹਾ, namespace);
	TEST_ਪੂਰਾ();
#ਜੇ_ਅੰਤ

	TEST_ਸ਼ੁਰੂ("check ED25519 signature");
	check_sig("ed25519.pub", "ed25519.sig", ਸੁਨੇਹਾ, namespace);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("check MLDSA44-ED25519 signature");
	check_sig("mldsa44-ed25519.pub", "mldsa44-ed25519.sig", ਸੁਨੇਹਾ, namespace);
	TEST_ਪੂਰਾ();

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ ENABLE_SK
#ਜੇ defined(WITH_OPENSSL)
	TEST_ਸ਼ੁਰੂ("check ECDSA-SK signature");
	check_sig("ecdsa_sk.pub", "ecdsa_sk.sig", ਸੁਨੇਹਾ, namespace);
	TEST_ਪੂਰਾ();
#ਜੇ_ਅੰਤ

	TEST_ਸ਼ੁਰੂ("check ED25519-SK signature");
	check_sig("ed25519_sk.pub", "ed25519_sk.sig", ਸੁਨੇਹਾ, namespace);
	TEST_ਪੂਰਾ();

#ਜੇ defined(WITH_OPENSSL)
	TEST_ਸ਼ੁਰੂ("check ECDSA-SK webauthn signature");
	check_sig("ecdsa_sk_webauthn.pub", "ecdsa_sk_webauthn.sig",
	    ਸੁਨੇਹਾ, namespace);
	TEST_ਪੂਰਾ();
#ਜੇ_ਅੰਤ
#ਜੇ_ਅੰਤ /* ENABLE_SK */

	sshbuf_free(ਸੁਨੇਹਾ);
	ਮੁਕਤ(namespace);
}

ਖਾਲੀ
benchmarks(ਖਾਲੀ)
{
	ਲਿਖੋ("no benchmarks\n");
}
