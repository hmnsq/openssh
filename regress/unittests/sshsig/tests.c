/* 	$OpenBSD: tests.c,v 1.8 2026/06/29 07:46:22 djm Exp $ */
/*
 * Regress test for sshbuf.h buffer API
 *
 * Placed in the public domain
 */

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <sys/stat.h>
#અન્તર્ભાવ <fcntl.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <stdint.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <unistd.h>

#ifdef WITH_OPENSSL
#અન્તર્ભાવ <openssl/err.h>
#અન્તર્ભાવ <openssl/evp.h>
#અન્તર્ભાવ <openssl/crypto.h>
#endif

#અન્તર્ભાવ "ssherr.h"
#અન્તર્ભાવ "authfile.h"
#અન્તર્ભાવ "sshkey.h"
#અન્તર્ભાવ "sshbuf.h"
#અન્તર્ભાવ "sshsig.h"
#અન્તર્ભાવ "log.h"

#અન્તર્ભાવ "../test_helper/test_helper.h"

સ્થિર સંરચના sshbuf *
load_file(અચલ અક્ષર *name)
{
	સંરચના sshbuf *ret = ખાલી;

	ASSERT_INT_EQ(sshbuf_load_file(test_data_file(name), &ret), 0);
	ASSERT_PTR_NE(ret, ખાલી);
	પાછા ret;
}

સ્થિર સંરચના sshkey *
load_ચાવી(અચલ અક્ષર *name)
{
	સંરચના sshkey *ret = ખાલી;
	ASSERT_INT_EQ(sshkey_load_public(test_data_file(name), &ret, ખાલી), 0);
	ASSERT_PTR_NE(ret, ખાલી);
	પાછા ret;
}

સ્થિર શૂન્ય
check_sig(અચલ અક્ષર *keyname, અચલ અક્ષર *signame, અચલ સંરચના sshbuf *સંદેશ,
    અચલ અક્ષર *namespace)
{
	સંરચના sshkey *k, *sign_ચાવી;
	સંરચના sshbuf *sig, *rawsig;
	સંરચના sshkey_sig_details *sig_details;

	k = load_ચાવી(keyname);
	sig = load_file(signame);
	sign_ચાવી = ખાલી;
	sig_details = ખાલી;
	rawsig = ખાલી;
	ASSERT_INT_EQ(sshsig_dearmor(sig, &rawsig), 0);
	ASSERT_INT_EQ(sshsig_verifyb(rawsig, સંદેશ, namespace,
	    &sign_ચાવી, &sig_details), 0);
	ASSERT_INT_EQ(sshkey_equal(k, sign_ચાવી), 1);
	sshkey_free(k);
	sshkey_free(sign_ચાવી);
	sshkey_sig_details_free(sig_details);
	sshbuf_free(sig);
	sshbuf_free(rawsig);
}

શૂન્ય
tests(શૂન્ય)
{
	સંરચના sshbuf *સંદેશ;
	અક્ષર *namespace;

#જો 0
        log_init("test_sshsig", SYSLOG_LEVEL_DEBUG3, SYSLOG_FACILITY_AUTH, 1);
#endif

#ifdef WITH_OPENSSL
	OpenSSL_add_all_algorithms();
	OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, ખાલી);
#endif

	TEST_START("load data");
	સંદેશ = load_file("namespace");
	namespace = sshbuf_dup_string(સંદેશ);
	ASSERT_PTR_NE(namespace, ખાલી);
	sshbuf_free(સંદેશ);
	સંદેશ = load_file("signed-data");
	TEST_DONE();

#ifdef WITH_OPENSSL
	TEST_START("check RSA signature");
	check_sig("rsa.pub", "rsa.sig", સંદેશ, namespace);
	TEST_DONE();


	TEST_START("check ECDSA signature");
	check_sig("ecdsa.pub", "ecdsa.sig", સંદેશ, namespace);
	TEST_DONE();
#endif

	TEST_START("check ED25519 signature");
	check_sig("ed25519.pub", "ed25519.sig", સંદેશ, namespace);
	TEST_DONE();

	TEST_START("check MLDSA44-ED25519 signature");
	check_sig("mldsa44-ed25519.pub", "mldsa44-ed25519.sig", સંદેશ, namespace);
	TEST_DONE();

#ifdef ENABLE_SK
#જો defined(WITH_OPENSSL)
	TEST_START("check ECDSA-SK signature");
	check_sig("ecdsa_sk.pub", "ecdsa_sk.sig", સંદેશ, namespace);
	TEST_DONE();
#endif

	TEST_START("check ED25519-SK signature");
	check_sig("ed25519_sk.pub", "ed25519_sk.sig", સંદેશ, namespace);
	TEST_DONE();

#જો defined(WITH_OPENSSL)
	TEST_START("check ECDSA-SK webauthn signature");
	check_sig("ecdsa_sk_webauthn.pub", "ecdsa_sk_webauthn.sig",
	    સંદેશ, namespace);
	TEST_DONE();
#endif
#endif /* ENABLE_SK */

	sshbuf_free(સંદેશ);
	મુક્ત(namespace);
}

શૂન્ય
benchmarks(શૂન્ય)
{
	printf("no benchmarks\n");
}
