/* 	$OpenBSD: tests.c,v 1.8 2026/06/29 07:46:22 djm Exp $ */
/*
 * Regress test for sshbuf.h buffer API
 *
 * Placed in the public domain
 */

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <sys/stat.h>
#అన్తర్భావ <fcntl.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <stdint.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <unistd.h>

#నిర్వచితమైతే WITH_OPENSSL
#అన్తర్భావ <openssl/err.h>
#అన్తర్భావ <openssl/evp.h>
#అన్తర్భావ <openssl/crypto.h>
#అయితే_ముగింపు

#అన్తర్భావ "ssherr.h"
#అన్తర్భావ "authfile.h"
#అన్తర్భావ "sshkey.h"
#అన్తర్భావ "sshbuf.h"
#అన్తర్భావ "sshsig.h"
#అన్తర్భావ "log.h"

#అన్తర్భావ "../test_helper/test_helper.h"

స్థిర నిర్మాణం sshbuf *
ఎక్కించు_file(స్థిరరాశి అక్షరం *name)
{
	నిర్మాణం sshbuf *ret = ఖాళీ;

	ASSERT_INT_EQ(sshbuf_ఎక్కించు_file(test_దత్తాంశం_file(name), &ret), 0);
	ASSERT_PTR_NE(ret, ఖాళీ);
	తిరిగి ret;
}

స్థిర నిర్మాణం sshkey *
ఎక్కించు_కీలకం(స్థిరరాశి అక్షరం *name)
{
	నిర్మాణం sshkey *ret = ఖాళీ;
	ASSERT_INT_EQ(sshkey_ఎక్కించు_ప్రజా(test_దత్తాంశం_file(name), &ret, ఖాళీ), 0);
	ASSERT_PTR_NE(ret, ఖాళీ);
	తిరిగి ret;
}

స్థిర శూన్య
check_sig(స్థిరరాశి అక్షరం *keyname, స్థిరరాశి అక్షరం *signame, స్థిరరాశి నిర్మాణం sshbuf *సందేశం,
    స్థిరరాశి అక్షరం *namespace)
{
	నిర్మాణం sshkey *k, *sign_కీలకం;
	నిర్మాణం sshbuf *sig, *rawsig;
	నిర్మాణం sshkey_sig_details *sig_details;

	k = ఎక్కించు_కీలకం(keyname);
	sig = ఎక్కించు_file(signame);
	sign_కీలకం = ఖాళీ;
	sig_details = ఖాళీ;
	rawsig = ఖాళీ;
	ASSERT_INT_EQ(sshsig_dearmor(sig, &rawsig), 0);
	ASSERT_INT_EQ(sshsig_verifyb(rawsig, సందేశం, namespace,
	    &sign_కీలకం, &sig_details), 0);
	ASSERT_INT_EQ(sshkey_equal(k, sign_కీలకం), 1);
	sshkey_free(k);
	sshkey_free(sign_కీలకం);
	sshkey_sig_details_free(sig_details);
	sshbuf_free(sig);
	sshbuf_free(rawsig);
}

శూన్య
tests(శూన్య)
{
	నిర్మాణం sshbuf *సందేశం;
	అక్షరం *namespace;

#ఒకవేళ 0
        log_init("test_sshsig", SYSLOG_LEVEL_DEBUG3, SYSLOG_FACILITY_AUTH, 1);
#అయితే_ముగింపు

#నిర్వచితమైతే WITH_OPENSSL
	Open_SSL_కూడు_all_algorithms();
	OPENSSL_init_crypto(OPENSSL_INIT_ఎక్కించు_CRYPTO_అక్షరశ్రేణులు, ఖాళీ);
#అయితే_ముగింపు

	TEST_ప్రారంభం("load data");
	సందేశం = ఎక్కించు_file("namespace");
	namespace = sshbuf_dup_string(సందేశం);
	ASSERT_PTR_NE(namespace, ఖాళీ);
	sshbuf_free(సందేశం);
	సందేశం = ఎక్కించు_file("signed-data");
	TEST_పూర్తి();

#నిర్వచితమైతే WITH_OPENSSL
	TEST_ప్రారంభం("check RSA signature");
	check_sig("rsa.pub", "rsa.sig", సందేశం, namespace);
	TEST_పూర్తి();


	TEST_ప్రారంభం("check ECDSA signature");
	check_sig("ecdsa.pub", "ecdsa.sig", సందేశం, namespace);
	TEST_పూర్తి();
#అయితే_ముగింపు

	TEST_ప్రారంభం("check ED25519 signature");
	check_sig("ed25519.pub", "ed25519.sig", సందేశం, namespace);
	TEST_పూర్తి();

	TEST_ప్రారంభం("check MLDSA44-ED25519 signature");
	check_sig("mldsa44-ed25519.pub", "mldsa44-ed25519.sig", సందేశం, namespace);
	TEST_పూర్తి();

#నిర్వచితమైతే ENABLE_SK
#ఒకవేళ defined(WITH_OPENSSL)
	TEST_ప్రారంభం("check ECDSA-SK signature");
	check_sig("ecdsa_sk.pub", "ecdsa_sk.sig", సందేశం, namespace);
	TEST_పూర్తి();
#అయితే_ముగింపు

	TEST_ప్రారంభం("check ED25519-SK signature");
	check_sig("ed25519_sk.pub", "ed25519_sk.sig", సందేశం, namespace);
	TEST_పూర్తి();

#ఒకవేళ defined(WITH_OPENSSL)
	TEST_ప్రారంభం("check ECDSA-SK webauthn signature");
	check_sig("ecdsa_sk_webauthn.pub", "ecdsa_sk_webauthn.sig",
	    సందేశం, namespace);
	TEST_పూర్తి();
#అయితే_ముగింపు
#అయితే_ముగింపు /* ENABLE_SK */

	sshbuf_free(సందేశం);
	విడుదల(namespace);
}

శూన్య
benchmarks(శూన్య)
{
	రాయి("no benchmarks\n");
}
