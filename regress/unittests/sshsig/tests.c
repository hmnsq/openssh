/* 	$OpenBSD: tests.c,v 1.8 2026/06/29 07:46:22 djm Exp $ */
/*
 * Regress test for sshbuf.h buffer API
 *
 * Placed in the public domain
 */

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <sys/types.h>
#ଅନ୍ତର୍ଭାଵ <sys/stat.h>
#ଅନ୍ତର୍ଭାଵ <fcntl.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <stdint.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <unistd.h>

#ifdef WITH_OPENSSL
#ଅନ୍ତର୍ଭାଵ <openssl/err.h>
#ଅନ୍ତର୍ଭାଵ <openssl/evp.h>
#ଅନ୍ତର୍ଭାଵ <openssl/crypto.h>
#endif

#ଅନ୍ତର୍ଭାଵ "ssherr.h"
#ଅନ୍ତର୍ଭାଵ "authfile.h"
#ଅନ୍ତର୍ଭାଵ "sshkey.h"
#ଅନ୍ତର୍ଭାଵ "sshbuf.h"
#ଅନ୍ତର୍ଭାଵ "sshsig.h"
#ଅନ୍ତର୍ଭାଵ "log.h"

#ଅନ୍ତର୍ଭାଵ "../test_helper/test_helper.h"

ସ୍ଥିର ସଂରଚନା sshbuf *
load_file(ଅଚଳ ଅକ୍ଷର *name)
{
	ସଂରଚନା sshbuf *ret = ଖାଲି;

	ASSERT_INT_EQ(sshbuf_load_file(test_data_file(name), &ret), 0);
	ASSERT_PTR_NE(ret, ଖାଲି);
	ଫେରନ୍ତୁ ret;
}

ସ୍ଥିର ସଂରଚନା sshkey *
load_ଚାବି(ଅଚଳ ଅକ୍ଷର *name)
{
	ସଂରଚନା sshkey *ret = ଖାଲି;
	ASSERT_INT_EQ(sshkey_load_public(test_data_file(name), &ret, ଖାଲି), 0);
	ASSERT_PTR_NE(ret, ଖାଲି);
	ଫେରନ୍ତୁ ret;
}

ସ୍ଥିର ଶୂନ୍ୟ
check_sig(ଅଚଳ ଅକ୍ଷର *keyname, ଅଚଳ ଅକ୍ଷର *signame, ଅଚଳ ସଂରଚନା sshbuf *ସନ୍ଦେଶ,
    ଅଚଳ ଅକ୍ଷର *namespace)
{
	ସଂରଚନା sshkey *k, *sign_ଚାବି;
	ସଂରଚନା sshbuf *sig, *rawsig;
	ସଂରଚନା sshkey_sig_details *sig_details;

	k = load_ଚାବି(keyname);
	sig = load_file(signame);
	sign_ଚାବି = ଖାଲି;
	sig_details = ଖାଲି;
	rawsig = ଖାଲି;
	ASSERT_INT_EQ(sshsig_dearmor(sig, &rawsig), 0);
	ASSERT_INT_EQ(sshsig_verifyb(rawsig, ସନ୍ଦେଶ, namespace,
	    &sign_ଚାବି, &sig_details), 0);
	ASSERT_INT_EQ(sshkey_equal(k, sign_ଚାବି), 1);
	sshkey_free(k);
	sshkey_free(sign_ଚାବି);
	sshkey_sig_details_free(sig_details);
	sshbuf_free(sig);
	sshbuf_free(rawsig);
}

ଶୂନ୍ୟ
tests(ଶୂନ୍ୟ)
{
	ସଂରଚନା sshbuf *ସନ୍ଦେଶ;
	ଅକ୍ଷର *namespace;

#ଯଦି 0
        log_init("test_sshsig", SYSLOG_LEVEL_DEBUG3, SYSLOG_FACILITY_AUTH, 1);
#endif

#ifdef WITH_OPENSSL
	OpenSSL_add_all_algorithms();
	OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, ଖାଲି);
#endif

	TEST_START("load data");
	ସନ୍ଦେଶ = load_file("namespace");
	namespace = sshbuf_dup_string(ସନ୍ଦେଶ);
	ASSERT_PTR_NE(namespace, ଖାଲି);
	sshbuf_free(ସନ୍ଦେଶ);
	ସନ୍ଦେଶ = load_file("signed-data");
	TEST_DONE();

#ifdef WITH_OPENSSL
	TEST_START("check RSA signature");
	check_sig("rsa.pub", "rsa.sig", ସନ୍ଦେଶ, namespace);
	TEST_DONE();


	TEST_START("check ECDSA signature");
	check_sig("ecdsa.pub", "ecdsa.sig", ସନ୍ଦେଶ, namespace);
	TEST_DONE();
#endif

	TEST_START("check ED25519 signature");
	check_sig("ed25519.pub", "ed25519.sig", ସନ୍ଦେଶ, namespace);
	TEST_DONE();

	TEST_START("check MLDSA44-ED25519 signature");
	check_sig("mldsa44-ed25519.pub", "mldsa44-ed25519.sig", ସନ୍ଦେଶ, namespace);
	TEST_DONE();

#ifdef ENABLE_SK
#ଯଦି defined(WITH_OPENSSL)
	TEST_START("check ECDSA-SK signature");
	check_sig("ecdsa_sk.pub", "ecdsa_sk.sig", ସନ୍ଦେଶ, namespace);
	TEST_DONE();
#endif

	TEST_START("check ED25519-SK signature");
	check_sig("ed25519_sk.pub", "ed25519_sk.sig", ସନ୍ଦେଶ, namespace);
	TEST_DONE();

#ଯଦି defined(WITH_OPENSSL)
	TEST_START("check ECDSA-SK webauthn signature");
	check_sig("ecdsa_sk_webauthn.pub", "ecdsa_sk_webauthn.sig",
	    ସନ୍ଦେଶ, namespace);
	TEST_DONE();
#endif
#endif /* ENABLE_SK */

	sshbuf_free(ସନ୍ଦେଶ);
	ମୁକ୍ତ(namespace);
}

ଶୂନ୍ୟ
benchmarks(ଶୂନ୍ୟ)
{
	printf("no benchmarks\n");
}
