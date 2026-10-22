/* 	$OpenBSD: test_sshkey.c,v 1.34 2026/06/14 04:08:06 djm Exp $ */
/*
 * Regress test for sshkey.h key management API
 *
 * Placed in the public domain
 */

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <stdint.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <string.h>

#నిర్వచితమైతే WITH_OPENSSL
#అన్తర్భావ <openssl/bn.h>
#అన్తర్భావ <openssl/ec.h>
#అన్తర్భావ <openssl/rsa.h>
#అయితే_ముగింపు

#అన్తర్భావ "../test_helper/test_helper.h"

#అన్తర్భావ "ssherr.h"
#అన్తర్భావ "sshbuf.h"
#నిర్వచించు SSHBUF_అంతర్గత 1	/* access internals for testing */
#అన్తర్భావ "sshkey.h"

#అన్తర్భావ "authfile.h"
#అన్తర్భావ "common.h"
#అన్తర్భావ "ssh2.h"

శూన్య sshkey_tests(శూన్య);
శూన్య sshkey_benchmarks(శూన్య);

స్థిర శూన్య
put_opt(నిర్మాణం sshbuf *b, స్థిరరాశి అక్షరం *name, స్థిరరాశి అక్షరం *విలువ)
{
	నిర్మాణం sshbuf *sect;

	sect = sshbuf_new();
	ASSERT_PTR_NE(sect, ఖాళీ);
	ASSERT_INT_EQ(sshbuf_put_cstring(b, name), 0);
	ఒకవేళ (విలువ != ఖాళీ)
		ASSERT_INT_EQ(sshbuf_put_cstring(sect, విలువ), 0);
	ASSERT_INT_EQ(sshbuf_put_stringb(b, sect), 0);
	sshbuf_free(sect);
}

#నిర్వచితమైతే WITH_OPENSSL
స్థిర శూన్య
build_cert(నిర్మాణం sshbuf *b, నిర్మాణం sshkey *k, స్థిరరాశి అక్షరం *type,
    నిర్మాణం sshkey *sign_కీలకం, నిర్మాణం sshkey *ca_కీలకం,
    స్థిరరాశి అక్షరం *sig_alg)
{
	నిర్మాణం sshbuf *ca_buf, *pk, *principals, *critopts, *exts;
	u_char *sigblob;
	కొలత_t siglen;

	ca_buf = sshbuf_new();
	ASSERT_PTR_NE(ca_buf, ఖాళీ);
	ASSERT_INT_EQ(sshkey_putb(ca_కీలకం, ca_buf), 0);

	/*
	 * Get the public key serialisation by rendering the key and skipping
	 * the type string. This is a bit of a hack :/
	 */
	pk = sshbuf_new();
	ASSERT_PTR_NE(pk, ఖాళీ);
	ASSERT_INT_EQ(sshkey_putb_plain(k, pk), 0);
	ASSERT_INT_EQ(sshbuf_skip_string(pk), 0);

	principals = sshbuf_new();
	ASSERT_PTR_NE(principals, ఖాళీ);
	ASSERT_INT_EQ(sshbuf_put_cstring(principals, "gsamsa"), 0);
	ASSERT_INT_EQ(sshbuf_put_cstring(principals, "gregor"), 0);

	critopts = sshbuf_new();
	ASSERT_PTR_NE(critopts, ఖాళీ);
	put_opt(critopts, "force-command", "/usr/local/bin/nethack");
	put_opt(critopts, "source-address", "192.168.0.0/24,127.0.0.1,::1");

	exts = sshbuf_new();
	ASSERT_PTR_NE(exts, ఖాళీ);
	put_opt(critopts, "permit-X11-forwarding", ఖాళీ);

	ASSERT_INT_EQ(sshbuf_put_cstring(b, type), 0);
	ASSERT_INT_EQ(sshbuf_put_cstring(b, "noncenoncenonce!"), 0); /* nonce */
	ASSERT_INT_EQ(sshbuf_putb(b, pk), 0); /* public key serialisation */
	ASSERT_INT_EQ(sshbuf_put_u64(b, 1234), 0); /* serial */
	ASSERT_INT_EQ(sshbuf_put_u32(b, SSH2_CERT_TYPE_USER), 0); /* type */
	ASSERT_INT_EQ(sshbuf_put_cstring(b, "gregor"), 0); /* key ID */
	ASSERT_INT_EQ(sshbuf_put_stringb(b, principals), 0); /* principals */
	ASSERT_INT_EQ(sshbuf_put_u64(b, 0), 0); /*ప్రారంభం*/
	ASSERT_INT_EQ(sshbuf_put_u64(b, 0xffffffffffffffffULL), 0); /*చివర*/
	ASSERT_INT_EQ(sshbuf_put_stringb(b, critopts), 0); /* options */
	ASSERT_INT_EQ(sshbuf_put_stringb(b, exts), 0); /* extensions */
	ASSERT_INT_EQ(sshbuf_put_string(b, ఖాళీ, 0), 0); /* reserved */
	ASSERT_INT_EQ(sshbuf_put_stringb(b, ca_buf), 0); /* signature key */
	ASSERT_INT_EQ(sshkey_sign(sign_కీలకం, &sigblob, &siglen,
	    sshbuf_ptr(b), sshbuf_len(b), sig_alg, ఖాళీ, ఖాళీ, 0), 0);
	ASSERT_INT_EQ(sshbuf_put_string(b, sigblob, siglen), 0); /* signature */

	విడుదల(sigblob);
	sshbuf_free(ca_buf);
	sshbuf_free(exts);
	sshbuf_free(critopts);
	sshbuf_free(principals);
	sshbuf_free(pk);
}
#అయితే_ముగింపు /* WITH_OPENSSL */

స్థిర శూన్య
signature_test(నిర్మాణం sshkey *k, నిర్మాణం sshkey *bad, స్థిరరాశి అక్షరం *sig_alg,
    స్థిరరాశి u_char *d, కొలత_t l)
{
	కొలత_t len;
	u_char *sig;

	ASSERT_INT_EQ(sshkey_sign(k, &sig, &len, d, l, sig_alg,
	    ఖాళీ, ఖాళీ, 0), 0);
	ASSERT_కొలత_T_GT(len, 8);
	ASSERT_PTR_NE(sig, ఖాళీ);
	ASSERT_INT_EQ(sshkey_verify(k, sig, len, d, l, ఖాళీ, 0, ఖాళీ), 0);
	ASSERT_INT_NE(sshkey_verify(bad, sig, len, d, l, ఖాళీ, 0, ఖాళీ), 0);
	/* Fuzz test is more comprehensive, this is just a smoke test */
	sig[len - 5] ^= 0x10;
	ASSERT_INT_NE(sshkey_verify(k, sig, len, d, l, ఖాళీ, 0, ఖాళీ), 0);
	విడుదల(sig);
}

స్థిర శూన్య
signature_bench(స్థిరరాశి అక్షరం *name, పూర్ణాంకం ktype, పూర్ణాంకం బిట్లు, స్థిరరాశి అక్షరం *sig_alg,
    స్థిరరాశి u_char *d, కొలత_t l)
{
	నిర్మాణం sshkey *k;
	కొలత_t len;
	u_char *sig;
	అక్షరం testname[256];

	snprintf(testname, పరిమాణం(testname), "sign %s", name);
	TEST_ప్రారంభం(testname);
	ASSERT_INT_EQ(sshkey_generate(ktype, బిట్లు, &k), 0);
	ASSERT_PTR_NE(k, ఖాళీ);

	BENCH_ప్రారంభం(testname);
	ASSERT_INT_EQ(sshkey_sign(k, &sig, &len, d, l, sig_alg,
	    ఖాళీ, ఖాళీ, 0), 0);
	విడుదల(sig);
	BENCH_ముగింపు("sign");

	sshkey_free(k);
	TEST_పూర్తి();
}

స్థిర శూన్య
verify_bench(స్థిరరాశి అక్షరం *name, పూర్ణాంకం ktype, పూర్ణాంకం బిట్లు, స్థిరరాశి అక్షరం *sig_alg,
    స్థిరరాశి u_char *d, కొలత_t l)
{
	నిర్మాణం sshkey *k;
	కొలత_t len;
	u_char *sig;
	అక్షరం testname[256];

	snprintf(testname, పరిమాణం(testname), "verify %s", name);
	TEST_ప్రారంభం(testname);
	ASSERT_INT_EQ(sshkey_generate(ktype, బిట్లు, &k), 0);
	ASSERT_PTR_NE(k, ఖాళీ);

	ASSERT_INT_EQ(sshkey_sign(k, &sig, &len, d, l, sig_alg,
	    ఖాళీ, ఖాళీ, 0), 0);
	BENCH_ప్రారంభం(testname);
	ASSERT_INT_EQ(sshkey_verify(k, sig, len, d, l, ఖాళీ, 0, ఖాళీ), 0);
	BENCH_ముగింపు("verify");

	విడుదల(sig);
	sshkey_free(k);
	TEST_పూర్తి();
}

స్థిర శూన్య
banana(u_char *s, కొలత_t l)
{
	కొలత_t o;
	స్థిరరాశి u_char the_banana[] = { 'b', 'a', 'n', 'a', 'n', 'a' };

	కొరకు (o = 0; o < l; o += పరిమాణం(the_banana)) {
		ఒకవేళ (l - o < పరిమాణం(the_banana)) {
			జ్ఞాపకం_నకలు(s + o, "nanananana", l - o);
			ఆపు;
		}
		జ్ఞాపకం_నకలు(s + o, the_banana, పరిమాణం(the_banana));
	}
}

స్థిర శూన్య
signature_tests(నిర్మాణం sshkey *k, నిర్మాణం sshkey *bad, స్థిరరాశి అక్షరం *sig_alg)
{
	u_char i, buf[2049];
	కొలత_t lens[] = {
		1, 2, 7, 8, 9, 15, 16, 17, 31, 32, 33, 127, 128, 129,
		255, 256, 257, 1023, 1024, 1025, 2047, 2048, 2049
	};

	కొరకు (i = 0; i < (పరిమాణం(lens)/పరిమాణం(lens[0])); i++) {
		test_subtest_info("%s key, banana length %zu",
		    sshkey_type(k), lens[i]);
		banana(buf, lens[i]);
		signature_test(k, bad, sig_alg, buf, lens[i]);
	}
}

స్థిర శూన్య
signature_benchmark(స్థిరరాశి అక్షరం *name, పూర్ణాంకం ktype, పూర్ణాంకం బిట్లు,
    స్థిరరాశి అక్షరం *sig_alg, పూర్ణాంకం bench_verify)
{
	u_char buf[256];

	banana(buf, పరిమాణం(buf));
	ఒకవేళ (bench_verify)
		verify_bench(name, ktype, బిట్లు, sig_alg, buf, పరిమాణం(buf));
	లేకపోతే
		signature_bench(name, ktype, బిట్లు, sig_alg, buf, పరిమాణం(buf));
}

స్థిర నిర్మాణం sshkey *
get_వ్యక్తిగత(స్థిరరాశి అక్షరం *n)
{
	నిర్మాణం sshbuf *b;
	నిర్మాణం sshkey *ret;

	b = ఎక్కించు_file(n);
	ASSERT_INT_EQ(sshkey_parse_వ్యక్తిగత_fileblob(b, "", &ret, ఖాళీ), 0);
	sshbuf_free(b);
	తిరిగి ret;
}

శూన్య
sshkey_tests(శూన్య)
{
	నిర్మాణం sshkey *k1 = ఖాళీ, *k2 = ఖాళీ, *k3 = ఖాళీ, *k4 = ఖాళీ;
	నిర్మాణం sshkey *kr = ఖాళీ, *kd = ఖాళీ, *ke = ఖాళీ, *kf = ఖాళీ;
	నిర్మాణం sshbuf *b = ఖాళీ;

	TEST_ప్రారంభం("new invalid");
	k1 = sshkey_new(-42);
	ASSERT_PTR_EQ(k1, ఖాళీ);
	TEST_పూర్తి();

	TEST_ప్రారంభం("new/free KEY_UNSPEC");
	k1 = sshkey_new(కీలకం_UNSPEC);
	ASSERT_PTR_NE(k1, ఖాళీ);
	sshkey_free(k1);
	k1 = ఖాళీ;
	TEST_పూర్తి();

#నిర్వచితమైతే WITH_OPENSSL
	TEST_ప్రారంభం("new/free KEY_RSA");
	k1 = sshkey_new(కీలకం_RSA);
	ASSERT_PTR_NE(k1, ఖాళీ);
	ASSERT_PTR_NE(k1->pkey, ఖాళీ);
	sshkey_free(k1);
	k1 = ఖాళీ;
	TEST_పూర్తి();

	TEST_ప్రారంభం("new/free KEY_ECDSA");
	k1 = sshkey_new(కీలకం_ECDSA);
	ASSERT_PTR_NE(k1, ఖాళీ);
	ASSERT_PTR_EQ(k1->pkey, ఖాళీ);  /* Can't allocate without NID */
	sshkey_free(k1);
	k1 = ఖాళీ;
	TEST_పూర్తి();
#అయితే_ముగింపు /* WITH_OPENSSL */

	TEST_ప్రారంభం("new/free KEY_ED25519");
	k1 = sshkey_new(కీలకం_ED25519);
	ASSERT_PTR_NE(k1, ఖాళీ);
	/* These should be blank until key loaded or generated */
	ASSERT_PTR_EQ(k1->ed25519_sk, ఖాళీ);
	ASSERT_PTR_EQ(k1->ed25519_pk, ఖాళీ);
	sshkey_free(k1);
	k1 = ఖాళీ;
	TEST_పూర్తి();

	TEST_ప్రారంభం("new/free KEY_MLDSA44_ED25519");
	k1 = sshkey_new(కీలకం_MLDSA44_ED25519);
	ASSERT_PTR_NE(k1, ఖాళీ);
	ASSERT_PTR_EQ(k1->mldsa_ed25519_sk, ఖాళీ);
	ASSERT_PTR_EQ(k1->mldsa_ed25519_pk, ఖాళీ);
	sshkey_free(k1);
	k1 = ఖాళీ;
	TEST_పూర్తి();

#నిర్వచితమైతే WITH_OPENSSL
	TEST_ప్రారంభం("generate KEY_RSA too small modulus");
	ASSERT_INT_EQ(sshkey_generate(కీలకం_RSA, 128, &k1),
	    SSH_ERR_కీలకం_నిడివి);
	ASSERT_PTR_EQ(k1, ఖాళీ);
	TEST_పూర్తి();

	TEST_ప్రారంభం("generate KEY_RSA too large modulus");
	ASSERT_INT_EQ(sshkey_generate(కీలకం_RSA, 1 << 20, &k1),
	    SSH_ERR_కీలకం_నిడివి);
	ASSERT_PTR_EQ(k1, ఖాళీ);
	TEST_పూర్తి();


	TEST_ప్రారంభం("generate KEY_ECDSA wrong bits");
	ASSERT_INT_EQ(sshkey_generate(కీలకం_ECDSA, 42, &k1),
	    SSH_ERR_కీలకం_నిడివి);
	ASSERT_PTR_EQ(k1, ఖాళీ);
	sshkey_free(k1);
	k1 = ఖాళీ;
	TEST_పూర్తి();

	TEST_ప్రారంభం("generate KEY_RSA");
	ASSERT_INT_EQ(sshkey_generate(కీలకం_RSA, 767, &kr),
	    SSH_ERR_కీలకం_నిడివి);
	ASSERT_INT_EQ(sshkey_generate(కీలకం_RSA, 1024, &kr), 0);
	ASSERT_PTR_NE(kr, ఖాళీ);
	ASSERT_PTR_NE(EVP_PKEY_get0_RSA(kr->pkey), ఖాళీ);
	ASSERT_PTR_NE(rsa_n(kr), ఖాళీ);
	ASSERT_PTR_NE(rsa_e(kr), ఖాళీ);
	ASSERT_PTR_NE(rsa_p(kr), ఖాళీ);
	ASSERT_INT_EQ(BN_అంకె_బిట్లు(rsa_n(kr)), 1024);
	TEST_పూర్తి();


	TEST_ప్రారంభం("generate KEY_ECDSA");
	ASSERT_INT_EQ(sshkey_generate(కీలకం_ECDSA, 256, &ke), 0);
	ASSERT_PTR_NE(ke, ఖాళీ);
	ASSERT_PTR_NE(EVP_PKEY_get0_EC_కీలకం(ke->pkey), ఖాళీ);
	ASSERT_PTR_NE(EC_కీలకం_get0_ప్రజా_కీలకం(EVP_PKEY_get0_EC_కీలకం(ke->pkey)),
	    ఖాళీ);
	ASSERT_PTR_NE(EC_కీలకం_get0_వ్యక్తిగత_కీలకం(EVP_PKEY_get0_EC_కీలకం(ke->pkey)),
	    ఖాళీ);
	TEST_పూర్తి();
#అయితే_ముగింపు /* WITH_OPENSSL */

	TEST_ప్రారంభం("generate KEY_ED25519");
	ASSERT_INT_EQ(sshkey_generate(కీలకం_ED25519, 256, &kf), 0);
	ASSERT_PTR_NE(kf, ఖాళీ);
	ASSERT_INT_EQ(kf->type, కీలకం_ED25519);
	ASSERT_PTR_NE(kf->ed25519_pk, ఖాళీ);
	ASSERT_PTR_NE(kf->ed25519_sk, ఖాళీ);
	TEST_పూర్తి();

	TEST_ప్రారంభం("generate KEY_MLDSA44_ED25519");
	ASSERT_INT_EQ(sshkey_generate(కీలకం_MLDSA44_ED25519, 256, &k1), 0);
	ASSERT_PTR_NE(k1, ఖాళీ);
	ASSERT_INT_EQ(k1->type, కీలకం_MLDSA44_ED25519);
	ASSERT_PTR_NE(k1->mldsa_ed25519_pk, ఖాళీ);
	ASSERT_PTR_NE(k1->mldsa_ed25519_sk, ఖాళీ);
	sshkey_free(k1);
	k1 = ఖాళీ;
	TEST_పూర్తి();

#నిర్వచితమైతే WITH_OPENSSL
	TEST_ప్రారంభం("demote KEY_RSA");
	ASSERT_INT_EQ(sshkey_from_వ్యక్తిగత(kr, &k1), 0);
	ASSERT_PTR_NE(k1, ఖాళీ);
	ASSERT_PTR_NE(kr, k1);
	ASSERT_INT_EQ(k1->type, కీలకం_RSA);
	ASSERT_PTR_NE(EVP_PKEY_get0_RSA(k1->pkey), ఖాళీ);
	ASSERT_PTR_NE(rsa_n(k1), ఖాళీ);
	ASSERT_PTR_NE(rsa_e(k1), ఖాళీ);
	ASSERT_PTR_EQ(rsa_p(k1), ఖాళీ);
	TEST_పూర్తి();

	TEST_ప్రారంభం("equal KEY_RSA/demoted KEY_RSA");
	ASSERT_INT_EQ(sshkey_equal(kr, k1), 1);
	sshkey_free(k1);
	k1 = ఖాళీ;
	TEST_పూర్తి();


	TEST_ప్రారంభం("demote KEY_ECDSA");
	ASSERT_INT_EQ(sshkey_from_వ్యక్తిగత(ke, &k1), 0);
	ASSERT_PTR_NE(k1, ఖాళీ);
	ASSERT_PTR_NE(ke, k1);
	ASSERT_INT_EQ(k1->type, కీలకం_ECDSA);
	ASSERT_PTR_NE(EVP_PKEY_get0_EC_కీలకం(k1->pkey), ఖాళీ);
	ASSERT_INT_EQ(k1->ecdsa_nid, ke->ecdsa_nid);
	ASSERT_PTR_NE(EC_కీలకం_get0_ప్రజా_కీలకం(EVP_PKEY_get0_EC_కీలకం(ke->pkey)),
	   ఖాళీ);
	ASSERT_PTR_EQ(EC_కీలకం_get0_వ్యక్తిగత_కీలకం(EVP_PKEY_get0_EC_కీలకం(k1->pkey)),
	   ఖాళీ);
	TEST_పూర్తి();

	TEST_ప్రారంభం("equal KEY_ECDSA/demoted KEY_ECDSA");
	ASSERT_INT_EQ(sshkey_equal(ke, k1), 1);
	sshkey_free(k1);
	k1 = ఖాళీ;
	TEST_పూర్తి();
#అయితే_ముగింపు /* WITH_OPENSSL */

	TEST_ప్రారంభం("demote KEY_ED25519");
	ASSERT_INT_EQ(sshkey_from_వ్యక్తిగత(kf, &k1), 0);
	ASSERT_PTR_NE(k1, ఖాళీ);
	ASSERT_PTR_NE(kf, k1);
	ASSERT_INT_EQ(k1->type, కీలకం_ED25519);
	ASSERT_PTR_NE(k1->ed25519_pk, ఖాళీ);
	ASSERT_PTR_EQ(k1->ed25519_sk, ఖాళీ);
	TEST_పూర్తి();

	TEST_ప్రారంభం("equal KEY_ED25519/demoted KEY_ED25519");
	ASSERT_INT_EQ(sshkey_equal(kf, k1), 1);
	sshkey_free(k1);
	k1 = ఖాళీ;
	TEST_పూర్తి();

	TEST_ప్రారంభం("demote KEY_MLDSA44_ED25519");
	ASSERT_INT_EQ(sshkey_generate(కీలకం_MLDSA44_ED25519, 256, &k2), 0);
	ASSERT_INT_EQ(sshkey_from_వ్యక్తిగత(k2, &k1), 0);
	ASSERT_PTR_NE(k1, ఖాళీ);
	ASSERT_PTR_NE(k2, k1);
	ASSERT_INT_EQ(k1->type, కీలకం_MLDSA44_ED25519);
	ASSERT_PTR_NE(k1->mldsa_ed25519_pk, ఖాళీ);
	ASSERT_PTR_EQ(k1->mldsa_ed25519_sk, ఖాళీ);
	TEST_పూర్తి();

	TEST_ప్రారంభం("equal KEY_MLDSA44_ED25519/demoted KEY_MLDSA44_ED25519");
	ASSERT_INT_EQ(sshkey_equal(k2, k1), 1);
	sshkey_free(k1);
	sshkey_free(k2);
	k1 = k2 = ఖాళీ;
	TEST_పూర్తి();

#నిర్వచితమైతే WITH_OPENSSL
	TEST_ప్రారంభం("equal mismatched key types");
	ASSERT_INT_EQ(sshkey_equal(kd, kr), 0);
	ASSERT_INT_EQ(sshkey_equal(kd, ke), 0);
	ASSERT_INT_EQ(sshkey_equal(kr, ke), 0);
	ASSERT_INT_EQ(sshkey_equal(ke, kf), 0);
	ASSERT_INT_EQ(sshkey_equal(kd, kf), 0);
	TEST_పూర్తి();

	TEST_ప్రారంభం("equal different keys");
	ASSERT_INT_EQ(sshkey_generate(కీలకం_RSA, 1024, &k1), 0);
	ASSERT_INT_EQ(sshkey_equal(kr, k1), 0);
	sshkey_free(k1);
	k1 = ఖాళీ;
	ASSERT_INT_EQ(sshkey_generate(కీలకం_ECDSA, 256, &k1), 0);
	ASSERT_INT_EQ(sshkey_equal(ke, k1), 0);
	sshkey_free(k1);
	k1 = ఖాళీ;
	ASSERT_INT_EQ(sshkey_generate(కీలకం_ED25519, 256, &k1), 0);
	ASSERT_INT_EQ(sshkey_equal(kf, k1), 0);
	sshkey_free(k1);
	k1 = ఖాళీ;
	ASSERT_INT_EQ(sshkey_generate(కీలకం_MLDSA44_ED25519, 256, &k1), 0);
	ASSERT_INT_EQ(sshkey_generate(కీలకం_MLDSA44_ED25519, 256, &k2), 0);
	ASSERT_INT_EQ(sshkey_equal(k2, k1), 0);
	sshkey_free(k1);
	sshkey_free(k2);
	k1 = k2 = ఖాళీ;
	TEST_పూర్తి();
#అయితే_ముగింపు /* WITH_OPENSSL */

	sshkey_free(kr);
	sshkey_free(kd);
	sshkey_free(ke);
	sshkey_free(kf);
	kr = kd = ke = kf = ఖాళీ;

	TEST_ప్రారంభం("certify key");
	ASSERT_INT_EQ(sshkey_ఎక్కించు_ప్రజా(test_దత్తాంశం_file("ed25519_1.pub"),
	    &k1, ఖాళీ), 0);
	k2 = get_వ్యక్తిగత("ed25519_2");
	ASSERT_INT_EQ(sshkey_గమ్యం_certified(k1), 0);
	ASSERT_PTR_NE(k1->cert, ఖాళీ);
	k1->cert->type = SSH2_CERT_TYPE_USER;
	k1->cert->serial = 1234;
	k1->cert->కీలకం_id = strdup("estragon");
	ASSERT_PTR_NE(k1->cert->కీలకం_id, ఖాళీ);
	k1->cert->principals = సున్నా_జ్ఞాపకం_ఇవ్వు(4, పరిమాణం(*k1->cert->principals));
	ASSERT_PTR_NE(k1->cert->principals, ఖాళీ);
	k1->cert->principals[0] = strdup("estragon");
	k1->cert->principals[1] = strdup("vladimir");
	k1->cert->principals[2] = strdup("pozzo");
	k1->cert->principals[3] = strdup("lucky");
	ASSERT_PTR_NE(k1->cert->principals[0], ఖాళీ);
	ASSERT_PTR_NE(k1->cert->principals[1], ఖాళీ);
	ASSERT_PTR_NE(k1->cert->principals[2], ఖాళీ);
	ASSERT_PTR_NE(k1->cert->principals[3], ఖాళీ);
	k1->cert->nprincipals = 4;
	k1->cert->valid_after = 0;
	k1->cert->valid_before = (uint64_t)-1;
	sshbuf_free(k1->cert->critical);
	k1->cert->critical = sshbuf_new();
	ASSERT_PTR_NE(k1->cert->critical, ఖాళీ);
	sshbuf_free(k1->cert->extensions);
	k1->cert->extensions = sshbuf_new();
	ASSERT_PTR_NE(k1->cert->extensions, ఖాళీ);
	put_opt(k1->cert->critical, "force-command", "/usr/bin/true");
	put_opt(k1->cert->critical, "source-address", "127.0.0.1");
	put_opt(k1->cert->extensions, "permit-X11-forwarding", ఖాళీ);
	put_opt(k1->cert->extensions, "permit-agent-forwarding", ఖాళీ);
	ASSERT_INT_EQ(sshkey_from_వ్యక్తిగత(k2, &k1->cert->signature_కీలకం), 0);
	ASSERT_INT_EQ(sshkey_certify(k1, k2, ఖాళీ, ఖాళీ, ఖాళీ), 0);
	b = sshbuf_new();
	ASSERT_PTR_NE(b, ఖాళీ);
	ASSERT_INT_EQ(sshkey_putb(k1, b), 0);
	ASSERT_INT_EQ(sshkey_from_blob(sshbuf_ptr(b), sshbuf_len(b), &k3), 0);

	sshkey_free(k1);
	sshkey_free(k2);
	sshkey_free(k3);
	k1 = k2 = k3 = ఖాళీ;
	sshbuf_reset(b);
	TEST_పూర్తి();

	TEST_ప్రారంభం("certify key MLDSA44-ED25519");
	ASSERT_INT_EQ(sshkey_ఎక్కించు_ప్రజా(
	    test_దత్తాంశం_file("mldsa44_ed25519_1.pub"), &k1, ఖాళీ), 0);
	k2 = get_వ్యక్తిగత("mldsa44_ed25519_2");
	ASSERT_INT_EQ(sshkey_గమ్యం_certified(k1), 0);
	ASSERT_PTR_NE(k1->cert, ఖాళీ);
	k1->cert->type = SSH2_CERT_TYPE_USER;
	k1->cert->serial = 1234;
	k1->cert->కీలకం_id = strdup("estragon");
	ASSERT_PTR_NE(k1->cert->కీలకం_id, ఖాళీ);
	k1->cert->principals = సున్నా_జ్ఞాపకం_ఇవ్వు(4, పరిమాణం(*k1->cert->principals));
	ASSERT_PTR_NE(k1->cert->principals, ఖాళీ);
	k1->cert->principals[0] = strdup("estragon");
	k1->cert->principals[1] = strdup("vladimir");
	k1->cert->principals[2] = strdup("pozzo");
	k1->cert->principals[3] = strdup("lucky");
	ASSERT_PTR_NE(k1->cert->principals[0], ఖాళీ);
	ASSERT_PTR_NE(k1->cert->principals[1], ఖాళీ);
	ASSERT_PTR_NE(k1->cert->principals[2], ఖాళీ);
	ASSERT_PTR_NE(k1->cert->principals[3], ఖాళీ);
	k1->cert->nprincipals = 4;
	k1->cert->valid_after = 0;
	k1->cert->valid_before = (uint64_t)-1;
	sshbuf_free(k1->cert->critical);
	k1->cert->critical = sshbuf_new();
	ASSERT_PTR_NE(k1->cert->critical, ఖాళీ);
	sshbuf_free(k1->cert->extensions);
	k1->cert->extensions = sshbuf_new();
	ASSERT_PTR_NE(k1->cert->extensions, ఖాళీ);
	put_opt(k1->cert->critical, "force-command", "/usr/bin/true");
	put_opt(k1->cert->critical, "source-address", "127.0.0.1");
	put_opt(k1->cert->extensions, "permit-X11-forwarding", ఖాళీ);
	put_opt(k1->cert->extensions, "permit-agent-forwarding", ఖాళీ);
	ASSERT_INT_EQ(sshkey_from_వ్యక్తిగత(k2, &k1->cert->signature_కీలకం), 0);
	ASSERT_INT_EQ(sshkey_certify(k1, k2, ఖాళీ, ఖాళీ, ఖాళీ), 0);
	b = sshbuf_new();
	ASSERT_PTR_NE(b, ఖాళీ);
	ASSERT_INT_EQ(sshkey_putb(k1, b), 0);
	ASSERT_INT_EQ(sshkey_from_blob(sshbuf_ptr(b), sshbuf_len(b), &k3), 0);
	sshkey_free(k1);
	sshkey_free(k2);
	sshkey_free(k3);
	k1 = k2 = k3 = ఖాళీ;
	sshbuf_reset(b);
	TEST_పూర్తి();

#నిర్వచితమైతే WITH_OPENSSL
	TEST_ప్రారంభం("sign and verify RSA");
	k1 = get_వ్యక్తిగత("rsa_1");
	ASSERT_INT_EQ(sshkey_ఎక్కించు_ప్రజా(test_దత్తాంశం_file("rsa_2.pub"), &k2,
	    ఖాళీ), 0);
	signature_tests(k1, k2, "ssh-rsa");
	sshkey_free(k1);
	sshkey_free(k2);
	k1 = k2 = ఖాళీ;
	TEST_పూర్తి();

	TEST_ప్రారంభం("sign and verify RSA-SHA256");
	k1 = get_వ్యక్తిగత("rsa_1");
	ASSERT_INT_EQ(sshkey_ఎక్కించు_ప్రజా(test_దత్తాంశం_file("rsa_2.pub"), &k2,
	    ఖాళీ), 0);
	signature_tests(k1, k2, "rsa-sha2-256");
	sshkey_free(k1);
	sshkey_free(k2);
	k1 = k2 = ఖాళీ;
	TEST_పూర్తి();

	TEST_ప్రారంభం("sign and verify RSA-SHA512");
	k1 = get_వ్యక్తిగత("rsa_1");
	ASSERT_INT_EQ(sshkey_ఎక్కించు_ప్రజా(test_దత్తాంశం_file("rsa_2.pub"), &k2,
	    ఖాళీ), 0);
	signature_tests(k1, k2, "rsa-sha2-512");
	sshkey_free(k1);
	sshkey_free(k2);
	k1 = k2 = ఖాళీ;
	TEST_పూర్తి();


	TEST_ప్రారంభం("sign and verify ECDSA");
	k1 = get_వ్యక్తిగత("ecdsa_1");
	ASSERT_INT_EQ(sshkey_ఎక్కించు_ప్రజా(test_దత్తాంశం_file("ecdsa_2.pub"), &k2,
	    ఖాళీ), 0);
	signature_tests(k1, k2, ఖాళీ);
	sshkey_free(k1);
	sshkey_free(k2);
	k1 = k2 = ఖాళీ;
	TEST_పూర్తి();
#అయితే_ముగింపు /* WITH_OPENSSL */

	TEST_ప్రారంభం("sign and verify ED25519");
	k1 = get_వ్యక్తిగత("ed25519_1");
	ASSERT_INT_EQ(sshkey_ఎక్కించు_ప్రజా(test_దత్తాంశం_file("ed25519_2.pub"), &k2,
	    ఖాళీ), 0);
	signature_tests(k1, k2, ఖాళీ);
	sshkey_free(k1);
	sshkey_free(k2);
	k1 = k2 = ఖాళీ;
	TEST_పూర్తి();

	TEST_ప్రారంభం("sign and verify MLDSA44-ED25519");
	k1 = get_వ్యక్తిగత("mldsa44_ed25519_1");
	ASSERT_INT_EQ(sshkey_ఎక్కించు_ప్రజా(
	    test_దత్తాంశం_file("mldsa44_ed25519_2.pub"), &k2, ఖాళీ), 0);
	signature_tests(k1, k2, ఖాళీ);
	sshkey_free(k1);
	sshkey_free(k2);
	k1 = k2 = ఖాళీ;
	TEST_పూర్తి();

#నిర్వచితమైతే WITH_OPENSSL
	TEST_ప్రారంభం("nested certificate");
	ASSERT_INT_EQ(sshkey_ఎక్కించు_cert(test_దత్తాంశం_file("rsa_1"), &k1), 0);
	ASSERT_INT_EQ(sshkey_ఎక్కించు_ప్రజా(test_దత్తాంశం_file("rsa_1.pub"), &k2,
	    ఖాళీ), 0);
	k3 = get_వ్యక్తిగత("rsa_1");
	build_cert(b, k2, "ssh-rsa-cert-v01@openssh.com", k3, k1, ఖాళీ);
	ASSERT_INT_EQ(sshkey_from_blob(sshbuf_ptr(b), sshbuf_len(b), &k4),
	    SSH_ERR_కీలకం_CERT_INVALID_SIGN_కీలకం);
	ASSERT_PTR_EQ(k4, ఖాళీ);
	sshkey_free(k1);
	sshkey_free(k2);
	sshkey_free(k3);
	k1 = k2 = k3 = ఖాళీ;
	sshbuf_free(b);
	TEST_పూర్తి();
#అయితే_ముగింపు /* WITH_OPENSSL */
}

శూన్య
sshkey_benchmarks(శూన్య)
{
	నిర్మాణం sshkey *k = ఖాళీ;

#నిర్వచితమైతే WITH_OPENSSL
	BENCH_ప్రారంభం("generate RSA-1024");
	TEST_ప్రారంభం("generate KEY_RSA");
	ASSERT_INT_EQ(sshkey_generate(కీలకం_RSA, 1024, &k), 0);
	ASSERT_PTR_NE(k, ఖాళీ);
	sshkey_free(k);
	k = ఖాళీ;
	TEST_పూర్తి();
	BENCH_ముగింపు("keys");

	BENCH_ప్రారంభం("generate RSA-2048");
	TEST_ప్రారంభం("generate KEY_RSA");
	ASSERT_INT_EQ(sshkey_generate(కీలకం_RSA, 2048, &k), 0);
	ASSERT_PTR_NE(k, ఖాళీ);
	sshkey_free(k);
	k = ఖాళీ;
	TEST_పూర్తి();
	BENCH_ముగింపు("keys");

	BENCH_ప్రారంభం("generate ECDSA-256");
	TEST_ప్రారంభం("generate KEY_ECDSA");
	ASSERT_INT_EQ(sshkey_generate(కీలకం_ECDSA, 256, &k), 0);
	ASSERT_PTR_NE(k, ఖాళీ);
	sshkey_free(k);
	k = ఖాళీ;
	TEST_పూర్తి();
	BENCH_ముగింపు("keys");

	BENCH_ప్రారంభం("generate ECDSA-384");
	TEST_ప్రారంభం("generate KEY_ECDSA");
	ASSERT_INT_EQ(sshkey_generate(కీలకం_ECDSA, 384, &k), 0);
	ASSERT_PTR_NE(k, ఖాళీ);
	sshkey_free(k);
	k = ఖాళీ;
	TEST_పూర్తి();
	BENCH_ముగింపు("keys");

	BENCH_ప్రారంభం("generate ECDSA-521");
	TEST_ప్రారంభం("generate KEY_ECDSA");
	ASSERT_INT_EQ(sshkey_generate(కీలకం_ECDSA, 521, &k), 0);
	ASSERT_PTR_NE(k, ఖాళీ);
	sshkey_free(k);
	k = ఖాళీ;
	TEST_పూర్తి();
	BENCH_ముగింపు("keys");
#అయితే_ముగింపు /* WITH_OPENSSL */

	BENCH_ప్రారంభం("generate ED25519");
	TEST_ప్రారంభం("generate KEY_ED25519");
	ASSERT_INT_EQ(sshkey_generate(కీలకం_ED25519, 256, &k), 0);
	ASSERT_PTR_NE(k, ఖాళీ);
	sshkey_free(k);
	k = ఖాళీ;
	TEST_పూర్తి();
	BENCH_ముగింపు("keys");

	BENCH_ప్రారంభం("generate MLDSA44-ED25519");
	TEST_ప్రారంభం("generate KEY_MLDSA44_ED25519");
	ASSERT_INT_EQ(sshkey_generate(కీలకం_MLDSA44_ED25519, 256, &k), 0);
	ASSERT_PTR_NE(k, ఖాళీ);
	sshkey_free(k);
	k = ఖాళీ;
	TEST_పూర్తి();
	BENCH_ముగింపు("keys");

#నిర్వచితమైతే WITH_OPENSSL
	/* sign */
	signature_benchmark("RSA-1024/SHA1", కీలకం_RSA, 1024, "ssh-rsa", 0);
	signature_benchmark("RSA-1024/SHA256", కీలకం_RSA, 1024, "rsa-sha2-256", 0);
	signature_benchmark("RSA-1024/SHA512", కీలకం_RSA, 1024, "rsa-sha2-512", 0);
	signature_benchmark("RSA-2048/SHA1", కీలకం_RSA, 2048, "ssh-rsa", 0);
	signature_benchmark("RSA-2048/SHA256", కీలకం_RSA, 2048, "rsa-sha2-256", 0);
	signature_benchmark("RSA-2048/SHA512", కీలకం_RSA, 2048, "rsa-sha2-512", 0);
	signature_benchmark("ECDSA-256", కీలకం_ECDSA, 256, ఖాళీ, 0);
	signature_benchmark("ECDSA-384", కీలకం_ECDSA, 384, ఖాళీ, 0);
	signature_benchmark("ECDSA-521", కీలకం_ECDSA, 521, ఖాళీ, 0);
	signature_benchmark("ED25519", కీలకం_ED25519, 0, ఖాళీ, 0);
	signature_benchmark("MLDSA44-ED25519", కీలకం_MLDSA44_ED25519, 0, ఖాళీ, 0);

	/* verify */
	signature_benchmark("RSA-1024/SHA1", కీలకం_RSA, 1024, "ssh-rsa", 1);
	signature_benchmark("RSA-1024/SHA256", కీలకం_RSA, 1024, "rsa-sha2-256", 1);
	signature_benchmark("RSA-1024/SHA512", కీలకం_RSA, 1024, "rsa-sha2-512", 1);
	signature_benchmark("RSA-2048/SHA1", కీలకం_RSA, 2048, "ssh-rsa", 1);
	signature_benchmark("RSA-2048/SHA256", కీలకం_RSA, 2048, "rsa-sha2-256", 1);
	signature_benchmark("RSA-2048/SHA512", కీలకం_RSA, 2048, "rsa-sha2-512", 1);
	signature_benchmark("ECDSA-256", కీలకం_ECDSA, 256, ఖాళీ, 1);
	signature_benchmark("ECDSA-384", కీలకం_ECDSA, 384, ఖాళీ, 1);
	signature_benchmark("ECDSA-521", కీలకం_ECDSA, 521, ఖాళీ, 1);
#అయితే_ముగింపు /* WITH_OPENSSL */
	signature_benchmark("ED25519", కీలకం_ED25519, 0, ఖాళీ, 1);
	signature_benchmark("MLDSA44-ED25519", కీలకం_MLDSA44_ED25519, 0, ఖాళీ, 1);
}
