/* 	$OpenBSD: tests.c,v 1.8 2026/06/29 07:46:22 djm Exp $ */
/*
 * Regress test for sshbuf.h buffer API
 *
 * Placed in the public domain
 */

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <sys/stat.h>
#அந்தர்பாவ <fcntl.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <stdint.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <unistd.h>

#ifdef WITH_OPENSSL
#அந்தர்பாவ <openssl/err.h>
#அந்தர்பாவ <openssl/evp.h>
#அந்தர்பாவ <openssl/crypto.h>
#endif

#அந்தர்பாவ "ssherr.h"
#அந்தர்பாவ "authfile.h"
#அந்தர்பாவ "sshkey.h"
#அந்தர்பாவ "sshbuf.h"
#அந்தர்பாவ "sshsig.h"
#அந்தர்பாவ "log.h"

#அந்தர்பாவ "../test_helper/test_helper.h"

நிலையான கட்டமைப்பு sshbuf *
load_file(மாறிலி எழுத்து *name)
{
	கட்டமைப்பு sshbuf *ret = வெற்று;

	ASSERT_INT_EQ(sshbuf_load_file(test_data_file(name), &ret), 0);
	ASSERT_PTR_NE(ret, வெற்று);
	திரும்பு ret;
}

நிலையான கட்டமைப்பு sshkey *
load_சாவி(மாறிலி எழுத்து *name)
{
	கட்டமைப்பு sshkey *ret = வெற்று;
	ASSERT_INT_EQ(sshkey_load_public(test_data_file(name), &ret, வெற்று), 0);
	ASSERT_PTR_NE(ret, வெற்று);
	திரும்பு ret;
}

நிலையான வெறுமை
check_sig(மாறிலி எழுத்து *keyname, மாறிலி எழுத்து *signame, மாறிலி கட்டமைப்பு sshbuf *செய்தி,
    மாறிலி எழுத்து *namespace)
{
	கட்டமைப்பு sshkey *k, *sign_சாவி;
	கட்டமைப்பு sshbuf *sig, *rawsig;
	கட்டமைப்பு sshkey_sig_details *sig_details;

	k = load_சாவி(keyname);
	sig = load_file(signame);
	sign_சாவி = வெற்று;
	sig_details = வெற்று;
	rawsig = வெற்று;
	ASSERT_INT_EQ(sshsig_dearmor(sig, &rawsig), 0);
	ASSERT_INT_EQ(sshsig_verifyb(rawsig, செய்தி, namespace,
	    &sign_சாவி, &sig_details), 0);
	ASSERT_INT_EQ(sshkey_equal(k, sign_சாவி), 1);
	sshkey_free(k);
	sshkey_free(sign_சாவி);
	sshkey_sig_details_free(sig_details);
	sshbuf_free(sig);
	sshbuf_free(rawsig);
}

வெறுமை
tests(வெறுமை)
{
	கட்டமைப்பு sshbuf *செய்தி;
	எழுத்து *namespace;

#எனில் 0
        log_init("test_sshsig", SYSLOG_LEVEL_DEBUG3, SYSLOG_FACILITY_AUTH, 1);
#endif

#ifdef WITH_OPENSSL
	OpenSSL_add_all_algorithms();
	OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, வெற்று);
#endif

	TEST_START("load data");
	செய்தி = load_file("namespace");
	namespace = sshbuf_dup_string(செய்தி);
	ASSERT_PTR_NE(namespace, வெற்று);
	sshbuf_free(செய்தி);
	செய்தி = load_file("signed-data");
	TEST_DONE();

#ifdef WITH_OPENSSL
	TEST_START("check RSA signature");
	check_sig("rsa.pub", "rsa.sig", செய்தி, namespace);
	TEST_DONE();


	TEST_START("check ECDSA signature");
	check_sig("ecdsa.pub", "ecdsa.sig", செய்தி, namespace);
	TEST_DONE();
#endif

	TEST_START("check ED25519 signature");
	check_sig("ed25519.pub", "ed25519.sig", செய்தி, namespace);
	TEST_DONE();

	TEST_START("check MLDSA44-ED25519 signature");
	check_sig("mldsa44-ed25519.pub", "mldsa44-ed25519.sig", செய்தி, namespace);
	TEST_DONE();

#ifdef ENABLE_SK
#எனில் defined(WITH_OPENSSL)
	TEST_START("check ECDSA-SK signature");
	check_sig("ecdsa_sk.pub", "ecdsa_sk.sig", செய்தி, namespace);
	TEST_DONE();
#endif

	TEST_START("check ED25519-SK signature");
	check_sig("ed25519_sk.pub", "ed25519_sk.sig", செய்தி, namespace);
	TEST_DONE();

#எனில் defined(WITH_OPENSSL)
	TEST_START("check ECDSA-SK webauthn signature");
	check_sig("ecdsa_sk_webauthn.pub", "ecdsa_sk_webauthn.sig",
	    செய்தி, namespace);
	TEST_DONE();
#endif
#endif /* ENABLE_SK */

	sshbuf_free(செய்தி);
	விடுவி(namespace);
}

வெறுமை
benchmarks(வெறுமை)
{
	printf("no benchmarks\n");
}
