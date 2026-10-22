/* 	$OpenBSD: tests.c,v 1.8 2026/06/29 07:46:22 djm Exp $ */
/*
 * Regress test for sshbuf.h buffer API
 *
 * Placed in the public domain
 */

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <sys/stat.h>
#അന്തര്ഭാവ <fcntl.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <stdint.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <unistd.h>

#ifdef WITH_OPENSSL
#അന്തര്ഭാവ <openssl/err.h>
#അന്തര്ഭാവ <openssl/evp.h>
#അന്തര്ഭാവ <openssl/crypto.h>
#endif

#അന്തര്ഭാവ "ssherr.h"
#അന്തര്ഭാവ "authfile.h"
#അന്തര്ഭാവ "sshkey.h"
#അന്തര്ഭാവ "sshbuf.h"
#അന്തര്ഭാവ "sshsig.h"
#അന്തര്ഭാവ "log.h"

#അന്തര്ഭാവ "../test_helper/test_helper.h"

സ്ഥിതം ഘടന sshbuf *
load_file(സ്ഥിരം അക്ഷരം *name)
{
	ഘടന sshbuf *ret = ശൂന്യ;

	ASSERT_INT_EQ(sshbuf_load_file(test_data_file(name), &ret), 0);
	ASSERT_PTR_NE(ret, ശൂന്യ);
	തിരികെ ret;
}

സ്ഥിതം ഘടന sshkey *
load_താക്കോൽ(സ്ഥിരം അക്ഷരം *name)
{
	ഘടന sshkey *ret = ശൂന്യ;
	ASSERT_INT_EQ(sshkey_load_public(test_data_file(name), &ret, ശൂന്യ), 0);
	ASSERT_PTR_NE(ret, ശൂന്യ);
	തിരികെ ret;
}

സ്ഥിതം ശൂന്യം
check_sig(സ്ഥിരം അക്ഷരം *keyname, സ്ഥിരം അക്ഷരം *signame, സ്ഥിരം ഘടന sshbuf *സന്ദേശം,
    സ്ഥിരം അക്ഷരം *namespace)
{
	ഘടന sshkey *k, *sign_താക്കോൽ;
	ഘടന sshbuf *sig, *rawsig;
	ഘടന sshkey_sig_details *sig_details;

	k = load_താക്കോൽ(keyname);
	sig = load_file(signame);
	sign_താക്കോൽ = ശൂന്യ;
	sig_details = ശൂന്യ;
	rawsig = ശൂന്യ;
	ASSERT_INT_EQ(sshsig_dearmor(sig, &rawsig), 0);
	ASSERT_INT_EQ(sshsig_verifyb(rawsig, സന്ദേശം, namespace,
	    &sign_താക്കോൽ, &sig_details), 0);
	ASSERT_INT_EQ(sshkey_equal(k, sign_താക്കോൽ), 1);
	sshkey_free(k);
	sshkey_free(sign_താക്കോൽ);
	sshkey_sig_details_free(sig_details);
	sshbuf_free(sig);
	sshbuf_free(rawsig);
}

ശൂന്യം
tests(ശൂന്യം)
{
	ഘടന sshbuf *സന്ദേശം;
	അക്ഷരം *namespace;

#എങ്കിൽ 0
        log_init("test_sshsig", SYSLOG_LEVEL_DEBUG3, SYSLOG_FACILITY_AUTH, 1);
#endif

#ifdef WITH_OPENSSL
	OpenSSL_add_all_algorithms();
	OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, ശൂന്യ);
#endif

	TEST_START("load data");
	സന്ദേശം = load_file("namespace");
	namespace = sshbuf_dup_string(സന്ദേശം);
	ASSERT_PTR_NE(namespace, ശൂന്യ);
	sshbuf_free(സന്ദേശം);
	സന്ദേശം = load_file("signed-data");
	TEST_DONE();

#ifdef WITH_OPENSSL
	TEST_START("check RSA signature");
	check_sig("rsa.pub", "rsa.sig", സന്ദേശം, namespace);
	TEST_DONE();


	TEST_START("check ECDSA signature");
	check_sig("ecdsa.pub", "ecdsa.sig", സന്ദേശം, namespace);
	TEST_DONE();
#endif

	TEST_START("check ED25519 signature");
	check_sig("ed25519.pub", "ed25519.sig", സന്ദേശം, namespace);
	TEST_DONE();

	TEST_START("check MLDSA44-ED25519 signature");
	check_sig("mldsa44-ed25519.pub", "mldsa44-ed25519.sig", സന്ദേശം, namespace);
	TEST_DONE();

#ifdef ENABLE_SK
#എങ്കിൽ defined(WITH_OPENSSL)
	TEST_START("check ECDSA-SK signature");
	check_sig("ecdsa_sk.pub", "ecdsa_sk.sig", സന്ദേശം, namespace);
	TEST_DONE();
#endif

	TEST_START("check ED25519-SK signature");
	check_sig("ed25519_sk.pub", "ed25519_sk.sig", സന്ദേശം, namespace);
	TEST_DONE();

#എങ്കിൽ defined(WITH_OPENSSL)
	TEST_START("check ECDSA-SK webauthn signature");
	check_sig("ecdsa_sk_webauthn.pub", "ecdsa_sk_webauthn.sig",
	    സന്ദേശം, namespace);
	TEST_DONE();
#endif
#endif /* ENABLE_SK */

	sshbuf_free(സന്ദേശം);
	സ്വതന്ത്രം(namespace);
}

ശൂന്യം
benchmarks(ശൂന്യം)
{
	printf("no benchmarks\n");
}
