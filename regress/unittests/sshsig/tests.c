/* 	$OpenBSD: tests.c,v 1.8 2026/06/29 07:46:22 djm Exp $ */
/*
 * Regress test for sshbuf.h buffer API
 *
 * Placed in the public domain
 */

#অন্তর্ভাৱ "includes.h"

#অন্তর্ভাৱ <sys/types.h>
#অন্তর্ভাৱ <sys/stat.h>
#অন্তর্ভাৱ <fcntl.h>
#অন্তর্ভাৱ <stdio.h>
#অন্তর্ভাৱ <stdint.h>
#অন্তর্ভাৱ <stdlib.h>
#অন্তর্ভাৱ <string.h>
#অন্তর্ভাৱ <unistd.h>

#ifdef WITH_OPENSSL
#অন্তর্ভাৱ <openssl/err.h>
#অন্তর্ভাৱ <openssl/evp.h>
#অন্তর্ভাৱ <openssl/crypto.h>
#endif

#অন্তর্ভাৱ "ssherr.h"
#অন্তর্ভাৱ "authfile.h"
#অন্তর্ভাৱ "sshkey.h"
#অন্তর্ভাৱ "sshbuf.h"
#অন্তর্ভাৱ "sshsig.h"
#অন্তর্ভাৱ "log.h"

#অন্তর্ভাৱ "../test_helper/test_helper.h"

স্থির সংরচনা sshbuf *
load_file(ধ্রুৱ ৱর্ণ *name)
{
	সংরচনা sshbuf *ret = রিক্ত;

	ASSERT_INT_EQ(sshbuf_load_file(test_data_file(name), &ret), 0);
	ASSERT_PTR_NE(ret, রিক্ত);
	ঘূৰাই ret;
}

স্থির সংরচনা sshkey *
load_চাবি(ধ্রুৱ ৱর্ণ *name)
{
	সংরচনা sshkey *ret = রিক্ত;
	ASSERT_INT_EQ(sshkey_load_public(test_data_file(name), &ret, রিক্ত), 0);
	ASSERT_PTR_NE(ret, রিক্ত);
	ঘূৰাই ret;
}

স্থির শূন্য
check_sig(ধ্রুৱ ৱর্ণ *keyname, ধ্রুৱ ৱর্ণ *signame, ধ্রুৱ সংরচনা sshbuf *বাৰ্তা,
    ধ্রুৱ ৱর্ণ *namespace)
{
	সংরচনা sshkey *k, *sign_চাবি;
	সংরচনা sshbuf *sig, *rawsig;
	সংরচনা sshkey_sig_details *sig_details;

	k = load_চাবি(keyname);
	sig = load_file(signame);
	sign_চাবি = রিক্ত;
	sig_details = রিক্ত;
	rawsig = রিক্ত;
	ASSERT_INT_EQ(sshsig_dearmor(sig, &rawsig), 0);
	ASSERT_INT_EQ(sshsig_verifyb(rawsig, বাৰ্তা, namespace,
	    &sign_চাবি, &sig_details), 0);
	ASSERT_INT_EQ(sshkey_equal(k, sign_চাবি), 1);
	sshkey_free(k);
	sshkey_free(sign_চাবি);
	sshkey_sig_details_free(sig_details);
	sshbuf_free(sig);
	sshbuf_free(rawsig);
}

শূন্য
tests(শূন্য)
{
	সংরচনা sshbuf *বাৰ্তা;
	ৱর্ণ *namespace;

#যদি 0
        log_init("test_sshsig", SYSLOG_LEVEL_DEBUG3, SYSLOG_FACILITY_AUTH, 1);
#endif

#ifdef WITH_OPENSSL
	OpenSSL_add_all_algorithms();
	OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, রিক্ত);
#endif

	TEST_START("load data");
	বাৰ্তা = load_file("namespace");
	namespace = sshbuf_dup_string(বাৰ্তা);
	ASSERT_PTR_NE(namespace, রিক্ত);
	sshbuf_free(বাৰ্তা);
	বাৰ্তা = load_file("signed-data");
	TEST_DONE();

#ifdef WITH_OPENSSL
	TEST_START("check RSA signature");
	check_sig("rsa.pub", "rsa.sig", বাৰ্তা, namespace);
	TEST_DONE();


	TEST_START("check ECDSA signature");
	check_sig("ecdsa.pub", "ecdsa.sig", বাৰ্তা, namespace);
	TEST_DONE();
#endif

	TEST_START("check ED25519 signature");
	check_sig("ed25519.pub", "ed25519.sig", বাৰ্তা, namespace);
	TEST_DONE();

	TEST_START("check MLDSA44-ED25519 signature");
	check_sig("mldsa44-ed25519.pub", "mldsa44-ed25519.sig", বাৰ্তা, namespace);
	TEST_DONE();

#ifdef ENABLE_SK
#যদি defined(WITH_OPENSSL)
	TEST_START("check ECDSA-SK signature");
	check_sig("ecdsa_sk.pub", "ecdsa_sk.sig", বাৰ্তা, namespace);
	TEST_DONE();
#endif

	TEST_START("check ED25519-SK signature");
	check_sig("ed25519_sk.pub", "ed25519_sk.sig", বাৰ্তা, namespace);
	TEST_DONE();

#যদি defined(WITH_OPENSSL)
	TEST_START("check ECDSA-SK webauthn signature");
	check_sig("ecdsa_sk_webauthn.pub", "ecdsa_sk_webauthn.sig",
	    বাৰ্তা, namespace);
	TEST_DONE();
#endif
#endif /* ENABLE_SK */

	sshbuf_free(বাৰ্তা);
	মুক্ত(namespace);
}

শূন্য
benchmarks(শূন্য)
{
	printf("no benchmarks\n");
}
