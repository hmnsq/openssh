/* 	$OpenBSD: test_sshkey.c,v 1.34 2026/06/14 04:08:06 djm Exp $ */
/*
 * Regress test for sshkey.h key management API
 *
 * Placed in the public domain
 */

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <sys/types.h>
#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <stdint.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <string.h>

#ifdef WITH_OPENSSL
#অন্তর্ভাব <openssl/bn.h>
#অন্তর্ভাব <openssl/ec.h>
#অন্তর্ভাব <openssl/rsa.h>
#endif

#অন্তর্ভাব "../test_helper/test_helper.h"

#অন্তর্ভাব "ssherr.h"
#অন্তর্ভাব "sshbuf.h"
#define SSHBUF_INTERNAL 1	/* access internals for testing */
#অন্তর্ভাব "sshkey.h"

#অন্তর্ভাব "authfile.h"
#অন্তর্ভাব "common.h"
#অন্তর্ভাব "ssh2.h"

শূন্য sshkey_tests(শূন্য);
শূন্য sshkey_benchmarks(শূন্য);

স্থির শূন্য
put_opt(কাঠামো sshbuf *b, ধ্রুবক অক্ষর *name, ধ্রুবক অক্ষর *মান)
{
	কাঠামো sshbuf *sect;

	sect = sshbuf_new();
	ASSERT_PTR_NE(sect, ফাঁকা);
	ASSERT_INT_EQ(sshbuf_put_cstring(b, name), 0);
	যদি (মান != ফাঁকা)
		ASSERT_INT_EQ(sshbuf_put_cstring(sect, মান), 0);
	ASSERT_INT_EQ(sshbuf_put_stringb(b, sect), 0);
	sshbuf_free(sect);
}

#ifdef WITH_OPENSSL
স্থির শূন্য
build_cert(কাঠামো sshbuf *b, কাঠামো sshkey *k, ধ্রুবক অক্ষর *type,
    কাঠামো sshkey *sign_চাবি, কাঠামো sshkey *ca_চাবি,
    ধ্রুবক অক্ষর *sig_alg)
{
	কাঠামো sshbuf *ca_buf, *pk, *principals, *critopts, *exts;
	u_char *sigblob;
	আকার_t siglen;

	ca_buf = sshbuf_new();
	ASSERT_PTR_NE(ca_buf, ফাঁকা);
	ASSERT_INT_EQ(sshkey_putb(ca_চাবি, ca_buf), 0);

	/*
	 * Get the public key serialisation by rendering the key and skipping
	 * the type string. This is a bit of a hack :/
	 */
	pk = sshbuf_new();
	ASSERT_PTR_NE(pk, ফাঁকা);
	ASSERT_INT_EQ(sshkey_putb_plain(k, pk), 0);
	ASSERT_INT_EQ(sshbuf_skip_string(pk), 0);

	principals = sshbuf_new();
	ASSERT_PTR_NE(principals, ফাঁকা);
	ASSERT_INT_EQ(sshbuf_put_cstring(principals, "gsamsa"), 0);
	ASSERT_INT_EQ(sshbuf_put_cstring(principals, "gregor"), 0);

	critopts = sshbuf_new();
	ASSERT_PTR_NE(critopts, ফাঁকা);
	put_opt(critopts, "force-command", "/usr/local/bin/nethack");
	put_opt(critopts, "source-address", "192.168.0.0/24,127.0.0.1,::1");

	exts = sshbuf_new();
	ASSERT_PTR_NE(exts, ফাঁকা);
	put_opt(critopts, "permit-X11-forwarding", ফাঁকা);

	ASSERT_INT_EQ(sshbuf_put_cstring(b, type), 0);
	ASSERT_INT_EQ(sshbuf_put_cstring(b, "noncenoncenonce!"), 0); /* nonce */
	ASSERT_INT_EQ(sshbuf_putb(b, pk), 0); /* public key serialisation */
	ASSERT_INT_EQ(sshbuf_put_u64(b, 1234), 0); /* serial */
	ASSERT_INT_EQ(sshbuf_put_u32(b, SSH2_CERT_TYPE_USER), 0); /* type */
	ASSERT_INT_EQ(sshbuf_put_cstring(b, "gregor"), 0); /* key ID */
	ASSERT_INT_EQ(sshbuf_put_stringb(b, principals), 0); /* principals */
	ASSERT_INT_EQ(sshbuf_put_u64(b, 0), 0); /* start */
	ASSERT_INT_EQ(sshbuf_put_u64(b, 0xffffffffffffffffULL), 0); /* end */
	ASSERT_INT_EQ(sshbuf_put_stringb(b, critopts), 0); /* options */
	ASSERT_INT_EQ(sshbuf_put_stringb(b, exts), 0); /* extensions */
	ASSERT_INT_EQ(sshbuf_put_string(b, ফাঁকা, 0), 0); /* reserved */
	ASSERT_INT_EQ(sshbuf_put_stringb(b, ca_buf), 0); /* signature key */
	ASSERT_INT_EQ(sshkey_sign(sign_চাবি, &sigblob, &siglen,
	    sshbuf_ptr(b), sshbuf_len(b), sig_alg, ফাঁকা, ফাঁকা, 0), 0);
	ASSERT_INT_EQ(sshbuf_put_string(b, sigblob, siglen), 0); /* signature */

	মুক্ত(sigblob);
	sshbuf_free(ca_buf);
	sshbuf_free(exts);
	sshbuf_free(critopts);
	sshbuf_free(principals);
	sshbuf_free(pk);
}
#endif /* WITH_OPENSSL */

স্থির শূন্য
signature_test(কাঠামো sshkey *k, কাঠামো sshkey *bad, ধ্রুবক অক্ষর *sig_alg,
    ধ্রুবক u_char *d, আকার_t l)
{
	আকার_t len;
	u_char *sig;

	ASSERT_INT_EQ(sshkey_sign(k, &sig, &len, d, l, sig_alg,
	    ফাঁকা, ফাঁকা, 0), 0);
	ASSERT_আকার_T_GT(len, 8);
	ASSERT_PTR_NE(sig, ফাঁকা);
	ASSERT_INT_EQ(sshkey_verify(k, sig, len, d, l, ফাঁকা, 0, ফাঁকা), 0);
	ASSERT_INT_NE(sshkey_verify(bad, sig, len, d, l, ফাঁকা, 0, ফাঁকা), 0);
	/* Fuzz test is more comprehensive, this is just a smoke test */
	sig[len - 5] ^= 0x10;
	ASSERT_INT_NE(sshkey_verify(k, sig, len, d, l, ফাঁকা, 0, ফাঁকা), 0);
	মুক্ত(sig);
}

স্থির শূন্য
signature_bench(ধ্রুবক অক্ষর *name, পূর্ণসংখ্যা ktype, পূর্ণসংখ্যা bits, ধ্রুবক অক্ষর *sig_alg,
    ধ্রুবক u_char *d, আকার_t l)
{
	কাঠামো sshkey *k;
	আকার_t len;
	u_char *sig;
	অক্ষর testname[256];

	snprintf(testname, আকার(testname), "sign %s", name);
	TEST_START(testname);
	ASSERT_INT_EQ(sshkey_generate(ktype, bits, &k), 0);
	ASSERT_PTR_NE(k, ফাঁকা);

	BENCH_START(testname);
	ASSERT_INT_EQ(sshkey_sign(k, &sig, &len, d, l, sig_alg,
	    ফাঁকা, ফাঁকা, 0), 0);
	মুক্ত(sig);
	BENCH_FINISH("sign");

	sshkey_free(k);
	TEST_DONE();
}

স্থির শূন্য
verify_bench(ধ্রুবক অক্ষর *name, পূর্ণসংখ্যা ktype, পূর্ণসংখ্যা bits, ধ্রুবক অক্ষর *sig_alg,
    ধ্রুবক u_char *d, আকার_t l)
{
	কাঠামো sshkey *k;
	আকার_t len;
	u_char *sig;
	অক্ষর testname[256];

	snprintf(testname, আকার(testname), "verify %s", name);
	TEST_START(testname);
	ASSERT_INT_EQ(sshkey_generate(ktype, bits, &k), 0);
	ASSERT_PTR_NE(k, ফাঁকা);

	ASSERT_INT_EQ(sshkey_sign(k, &sig, &len, d, l, sig_alg,
	    ফাঁকা, ফাঁকা, 0), 0);
	BENCH_START(testname);
	ASSERT_INT_EQ(sshkey_verify(k, sig, len, d, l, ফাঁকা, 0, ফাঁকা), 0);
	BENCH_FINISH("verify");

	মুক্ত(sig);
	sshkey_free(k);
	TEST_DONE();
}

স্থির শূন্য
banana(u_char *s, আকার_t l)
{
	আকার_t o;
	ধ্রুবক u_char the_banana[] = { 'b', 'a', 'n', 'a', 'n', 'a' };

	জন্য (o = 0; o < l; o += আকার(the_banana)) {
		যদি (l - o < আকার(the_banana)) {
			memcpy(s + o, "nanananana", l - o);
			বিরতি;
		}
		memcpy(s + o, the_banana, আকার(the_banana));
	}
}

স্থির শূন্য
signature_tests(কাঠামো sshkey *k, কাঠামো sshkey *bad, ধ্রুবক অক্ষর *sig_alg)
{
	u_char i, buf[2049];
	আকার_t lens[] = {
		1, 2, 7, 8, 9, 15, 16, 17, 31, 32, 33, 127, 128, 129,
		255, 256, 257, 1023, 1024, 1025, 2047, 2048, 2049
	};

	জন্য (i = 0; i < (আকার(lens)/আকার(lens[0])); i++) {
		test_subtest_info("%s key, banana length %zu",
		    sshkey_type(k), lens[i]);
		banana(buf, lens[i]);
		signature_test(k, bad, sig_alg, buf, lens[i]);
	}
}

স্থির শূন্য
signature_benchmark(ধ্রুবক অক্ষর *name, পূর্ণসংখ্যা ktype, পূর্ণসংখ্যা bits,
    ধ্রুবক অক্ষর *sig_alg, পূর্ণসংখ্যা bench_verify)
{
	u_char buf[256];

	banana(buf, আকার(buf));
	যদি (bench_verify)
		verify_bench(name, ktype, bits, sig_alg, buf, আকার(buf));
	অন্যথা
		signature_bench(name, ktype, bits, sig_alg, buf, আকার(buf));
}

স্থির কাঠামো sshkey *
get_private(ধ্রুবক অক্ষর *n)
{
	কাঠামো sshbuf *b;
	কাঠামো sshkey *ret;

	b = load_file(n);
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(b, "", &ret, ফাঁকা), 0);
	sshbuf_free(b);
	ফেরত ret;
}

শূন্য
sshkey_tests(শূন্য)
{
	কাঠামো sshkey *k1 = ফাঁকা, *k2 = ফাঁকা, *k3 = ফাঁকা, *k4 = ফাঁকা;
	কাঠামো sshkey *kr = ফাঁকা, *kd = ফাঁকা, *ke = ফাঁকা, *kf = ফাঁকা;
	কাঠামো sshbuf *b = ফাঁকা;

	TEST_START("new invalid");
	k1 = sshkey_new(-42);
	ASSERT_PTR_EQ(k1, ফাঁকা);
	TEST_DONE();

	TEST_START("new/free KEY_UNSPEC");
	k1 = sshkey_new(চাবি_UNSPEC);
	ASSERT_PTR_NE(k1, ফাঁকা);
	sshkey_free(k1);
	k1 = ফাঁকা;
	TEST_DONE();

#ifdef WITH_OPENSSL
	TEST_START("new/free KEY_RSA");
	k1 = sshkey_new(চাবি_RSA);
	ASSERT_PTR_NE(k1, ফাঁকা);
	ASSERT_PTR_NE(k1->pkey, ফাঁকা);
	sshkey_free(k1);
	k1 = ফাঁকা;
	TEST_DONE();

	TEST_START("new/free KEY_ECDSA");
	k1 = sshkey_new(চাবি_ECDSA);
	ASSERT_PTR_NE(k1, ফাঁকা);
	ASSERT_PTR_EQ(k1->pkey, ফাঁকা);  /* Can't allocate without NID */
	sshkey_free(k1);
	k1 = ফাঁকা;
	TEST_DONE();
#endif /* WITH_OPENSSL */

	TEST_START("new/free KEY_ED25519");
	k1 = sshkey_new(চাবি_ED25519);
	ASSERT_PTR_NE(k1, ফাঁকা);
	/* These should be blank until key loaded or generated */
	ASSERT_PTR_EQ(k1->ed25519_sk, ফাঁকা);
	ASSERT_PTR_EQ(k1->ed25519_pk, ফাঁকা);
	sshkey_free(k1);
	k1 = ফাঁকা;
	TEST_DONE();

	TEST_START("new/free KEY_MLDSA44_ED25519");
	k1 = sshkey_new(চাবি_MLDSA44_ED25519);
	ASSERT_PTR_NE(k1, ফাঁকা);
	ASSERT_PTR_EQ(k1->mldsa_ed25519_sk, ফাঁকা);
	ASSERT_PTR_EQ(k1->mldsa_ed25519_pk, ফাঁকা);
	sshkey_free(k1);
	k1 = ফাঁকা;
	TEST_DONE();

#ifdef WITH_OPENSSL
	TEST_START("generate KEY_RSA too small modulus");
	ASSERT_INT_EQ(sshkey_generate(চাবি_RSA, 128, &k1),
	    SSH_ERR_চাবি_দৈর্ঘ্য);
	ASSERT_PTR_EQ(k1, ফাঁকা);
	TEST_DONE();

	TEST_START("generate KEY_RSA too large modulus");
	ASSERT_INT_EQ(sshkey_generate(চাবি_RSA, 1 << 20, &k1),
	    SSH_ERR_চাবি_দৈর্ঘ্য);
	ASSERT_PTR_EQ(k1, ফাঁকা);
	TEST_DONE();


	TEST_START("generate KEY_ECDSA wrong bits");
	ASSERT_INT_EQ(sshkey_generate(চাবি_ECDSA, 42, &k1),
	    SSH_ERR_চাবি_দৈর্ঘ্য);
	ASSERT_PTR_EQ(k1, ফাঁকা);
	sshkey_free(k1);
	k1 = ফাঁকা;
	TEST_DONE();

	TEST_START("generate KEY_RSA");
	ASSERT_INT_EQ(sshkey_generate(চাবি_RSA, 767, &kr),
	    SSH_ERR_চাবি_দৈর্ঘ্য);
	ASSERT_INT_EQ(sshkey_generate(চাবি_RSA, 1024, &kr), 0);
	ASSERT_PTR_NE(kr, ফাঁকা);
	ASSERT_PTR_NE(EVP_PKEY_get0_RSA(kr->pkey), ফাঁকা);
	ASSERT_PTR_NE(rsa_n(kr), ফাঁকা);
	ASSERT_PTR_NE(rsa_e(kr), ফাঁকা);
	ASSERT_PTR_NE(rsa_p(kr), ফাঁকা);
	ASSERT_INT_EQ(BN_অঙ্ক_bits(rsa_n(kr)), 1024);
	TEST_DONE();


	TEST_START("generate KEY_ECDSA");
	ASSERT_INT_EQ(sshkey_generate(চাবি_ECDSA, 256, &ke), 0);
	ASSERT_PTR_NE(ke, ফাঁকা);
	ASSERT_PTR_NE(EVP_PKEY_get0_EC_চাবি(ke->pkey), ফাঁকা);
	ASSERT_PTR_NE(EC_চাবি_get0_public_চাবি(EVP_PKEY_get0_EC_চাবি(ke->pkey)),
	    ফাঁকা);
	ASSERT_PTR_NE(EC_চাবি_get0_private_চাবি(EVP_PKEY_get0_EC_চাবি(ke->pkey)),
	    ফাঁকা);
	TEST_DONE();
#endif /* WITH_OPENSSL */

	TEST_START("generate KEY_ED25519");
	ASSERT_INT_EQ(sshkey_generate(চাবি_ED25519, 256, &kf), 0);
	ASSERT_PTR_NE(kf, ফাঁকা);
	ASSERT_INT_EQ(kf->type, চাবি_ED25519);
	ASSERT_PTR_NE(kf->ed25519_pk, ফাঁকা);
	ASSERT_PTR_NE(kf->ed25519_sk, ফাঁকা);
	TEST_DONE();

	TEST_START("generate KEY_MLDSA44_ED25519");
	ASSERT_INT_EQ(sshkey_generate(চাবি_MLDSA44_ED25519, 256, &k1), 0);
	ASSERT_PTR_NE(k1, ফাঁকা);
	ASSERT_INT_EQ(k1->type, চাবি_MLDSA44_ED25519);
	ASSERT_PTR_NE(k1->mldsa_ed25519_pk, ফাঁকা);
	ASSERT_PTR_NE(k1->mldsa_ed25519_sk, ফাঁকা);
	sshkey_free(k1);
	k1 = ফাঁকা;
	TEST_DONE();

#ifdef WITH_OPENSSL
	TEST_START("demote KEY_RSA");
	ASSERT_INT_EQ(sshkey_from_private(kr, &k1), 0);
	ASSERT_PTR_NE(k1, ফাঁকা);
	ASSERT_PTR_NE(kr, k1);
	ASSERT_INT_EQ(k1->type, চাবি_RSA);
	ASSERT_PTR_NE(EVP_PKEY_get0_RSA(k1->pkey), ফাঁকা);
	ASSERT_PTR_NE(rsa_n(k1), ফাঁকা);
	ASSERT_PTR_NE(rsa_e(k1), ফাঁকা);
	ASSERT_PTR_EQ(rsa_p(k1), ফাঁকা);
	TEST_DONE();

	TEST_START("equal KEY_RSA/demoted KEY_RSA");
	ASSERT_INT_EQ(sshkey_equal(kr, k1), 1);
	sshkey_free(k1);
	k1 = ফাঁকা;
	TEST_DONE();


	TEST_START("demote KEY_ECDSA");
	ASSERT_INT_EQ(sshkey_from_private(ke, &k1), 0);
	ASSERT_PTR_NE(k1, ফাঁকা);
	ASSERT_PTR_NE(ke, k1);
	ASSERT_INT_EQ(k1->type, চাবি_ECDSA);
	ASSERT_PTR_NE(EVP_PKEY_get0_EC_চাবি(k1->pkey), ফাঁকা);
	ASSERT_INT_EQ(k1->ecdsa_nid, ke->ecdsa_nid);
	ASSERT_PTR_NE(EC_চাবি_get0_public_চাবি(EVP_PKEY_get0_EC_চাবি(ke->pkey)),
	   ফাঁকা);
	ASSERT_PTR_EQ(EC_চাবি_get0_private_চাবি(EVP_PKEY_get0_EC_চাবি(k1->pkey)),
	   ফাঁকা);
	TEST_DONE();

	TEST_START("equal KEY_ECDSA/demoted KEY_ECDSA");
	ASSERT_INT_EQ(sshkey_equal(ke, k1), 1);
	sshkey_free(k1);
	k1 = ফাঁকা;
	TEST_DONE();
#endif /* WITH_OPENSSL */

	TEST_START("demote KEY_ED25519");
	ASSERT_INT_EQ(sshkey_from_private(kf, &k1), 0);
	ASSERT_PTR_NE(k1, ফাঁকা);
	ASSERT_PTR_NE(kf, k1);
	ASSERT_INT_EQ(k1->type, চাবি_ED25519);
	ASSERT_PTR_NE(k1->ed25519_pk, ফাঁকা);
	ASSERT_PTR_EQ(k1->ed25519_sk, ফাঁকা);
	TEST_DONE();

	TEST_START("equal KEY_ED25519/demoted KEY_ED25519");
	ASSERT_INT_EQ(sshkey_equal(kf, k1), 1);
	sshkey_free(k1);
	k1 = ফাঁকা;
	TEST_DONE();

	TEST_START("demote KEY_MLDSA44_ED25519");
	ASSERT_INT_EQ(sshkey_generate(চাবি_MLDSA44_ED25519, 256, &k2), 0);
	ASSERT_INT_EQ(sshkey_from_private(k2, &k1), 0);
	ASSERT_PTR_NE(k1, ফাঁকা);
	ASSERT_PTR_NE(k2, k1);
	ASSERT_INT_EQ(k1->type, চাবি_MLDSA44_ED25519);
	ASSERT_PTR_NE(k1->mldsa_ed25519_pk, ফাঁকা);
	ASSERT_PTR_EQ(k1->mldsa_ed25519_sk, ফাঁকা);
	TEST_DONE();

	TEST_START("equal KEY_MLDSA44_ED25519/demoted KEY_MLDSA44_ED25519");
	ASSERT_INT_EQ(sshkey_equal(k2, k1), 1);
	sshkey_free(k1);
	sshkey_free(k2);
	k1 = k2 = ফাঁকা;
	TEST_DONE();

#ifdef WITH_OPENSSL
	TEST_START("equal mismatched key types");
	ASSERT_INT_EQ(sshkey_equal(kd, kr), 0);
	ASSERT_INT_EQ(sshkey_equal(kd, ke), 0);
	ASSERT_INT_EQ(sshkey_equal(kr, ke), 0);
	ASSERT_INT_EQ(sshkey_equal(ke, kf), 0);
	ASSERT_INT_EQ(sshkey_equal(kd, kf), 0);
	TEST_DONE();

	TEST_START("equal different keys");
	ASSERT_INT_EQ(sshkey_generate(চাবি_RSA, 1024, &k1), 0);
	ASSERT_INT_EQ(sshkey_equal(kr, k1), 0);
	sshkey_free(k1);
	k1 = ফাঁকা;
	ASSERT_INT_EQ(sshkey_generate(চাবি_ECDSA, 256, &k1), 0);
	ASSERT_INT_EQ(sshkey_equal(ke, k1), 0);
	sshkey_free(k1);
	k1 = ফাঁকা;
	ASSERT_INT_EQ(sshkey_generate(চাবি_ED25519, 256, &k1), 0);
	ASSERT_INT_EQ(sshkey_equal(kf, k1), 0);
	sshkey_free(k1);
	k1 = ফাঁকা;
	ASSERT_INT_EQ(sshkey_generate(চাবি_MLDSA44_ED25519, 256, &k1), 0);
	ASSERT_INT_EQ(sshkey_generate(চাবি_MLDSA44_ED25519, 256, &k2), 0);
	ASSERT_INT_EQ(sshkey_equal(k2, k1), 0);
	sshkey_free(k1);
	sshkey_free(k2);
	k1 = k2 = ফাঁকা;
	TEST_DONE();
#endif /* WITH_OPENSSL */

	sshkey_free(kr);
	sshkey_free(kd);
	sshkey_free(ke);
	sshkey_free(kf);
	kr = kd = ke = kf = ফাঁকা;

	TEST_START("certify key");
	ASSERT_INT_EQ(sshkey_load_public(test_তথ্য_file("ed25519_1.pub"),
	    &k1, ফাঁকা), 0);
	k2 = get_private("ed25519_2");
	ASSERT_INT_EQ(sshkey_to_certified(k1), 0);
	ASSERT_PTR_NE(k1->cert, ফাঁকা);
	k1->cert->type = SSH2_CERT_TYPE_USER;
	k1->cert->serial = 1234;
	k1->cert->চাবি_id = strdup("estragon");
	ASSERT_PTR_NE(k1->cert->চাবি_id, ফাঁকা);
	k1->cert->principals = calloc(4, আকার(*k1->cert->principals));
	ASSERT_PTR_NE(k1->cert->principals, ফাঁকা);
	k1->cert->principals[0] = strdup("estragon");
	k1->cert->principals[1] = strdup("vladimir");
	k1->cert->principals[2] = strdup("pozzo");
	k1->cert->principals[3] = strdup("lucky");
	ASSERT_PTR_NE(k1->cert->principals[0], ফাঁকা);
	ASSERT_PTR_NE(k1->cert->principals[1], ফাঁকা);
	ASSERT_PTR_NE(k1->cert->principals[2], ফাঁকা);
	ASSERT_PTR_NE(k1->cert->principals[3], ফাঁকা);
	k1->cert->nprincipals = 4;
	k1->cert->valid_after = 0;
	k1->cert->valid_before = (uint64_t)-1;
	sshbuf_free(k1->cert->critical);
	k1->cert->critical = sshbuf_new();
	ASSERT_PTR_NE(k1->cert->critical, ফাঁকা);
	sshbuf_free(k1->cert->extensions);
	k1->cert->extensions = sshbuf_new();
	ASSERT_PTR_NE(k1->cert->extensions, ফাঁকা);
	put_opt(k1->cert->critical, "force-command", "/usr/bin/true");
	put_opt(k1->cert->critical, "source-address", "127.0.0.1");
	put_opt(k1->cert->extensions, "permit-X11-forwarding", ফাঁকা);
	put_opt(k1->cert->extensions, "permit-agent-forwarding", ফাঁকা);
	ASSERT_INT_EQ(sshkey_from_private(k2, &k1->cert->signature_চাবি), 0);
	ASSERT_INT_EQ(sshkey_certify(k1, k2, ফাঁকা, ফাঁকা, ফাঁকা), 0);
	b = sshbuf_new();
	ASSERT_PTR_NE(b, ফাঁকা);
	ASSERT_INT_EQ(sshkey_putb(k1, b), 0);
	ASSERT_INT_EQ(sshkey_from_blob(sshbuf_ptr(b), sshbuf_len(b), &k3), 0);

	sshkey_free(k1);
	sshkey_free(k2);
	sshkey_free(k3);
	k1 = k2 = k3 = ফাঁকা;
	sshbuf_reset(b);
	TEST_DONE();

	TEST_START("certify key MLDSA44-ED25519");
	ASSERT_INT_EQ(sshkey_load_public(
	    test_তথ্য_file("mldsa44_ed25519_1.pub"), &k1, ফাঁকা), 0);
	k2 = get_private("mldsa44_ed25519_2");
	ASSERT_INT_EQ(sshkey_to_certified(k1), 0);
	ASSERT_PTR_NE(k1->cert, ফাঁকা);
	k1->cert->type = SSH2_CERT_TYPE_USER;
	k1->cert->serial = 1234;
	k1->cert->চাবি_id = strdup("estragon");
	ASSERT_PTR_NE(k1->cert->চাবি_id, ফাঁকা);
	k1->cert->principals = calloc(4, আকার(*k1->cert->principals));
	ASSERT_PTR_NE(k1->cert->principals, ফাঁকা);
	k1->cert->principals[0] = strdup("estragon");
	k1->cert->principals[1] = strdup("vladimir");
	k1->cert->principals[2] = strdup("pozzo");
	k1->cert->principals[3] = strdup("lucky");
	ASSERT_PTR_NE(k1->cert->principals[0], ফাঁকা);
	ASSERT_PTR_NE(k1->cert->principals[1], ফাঁকা);
	ASSERT_PTR_NE(k1->cert->principals[2], ফাঁকা);
	ASSERT_PTR_NE(k1->cert->principals[3], ফাঁকা);
	k1->cert->nprincipals = 4;
	k1->cert->valid_after = 0;
	k1->cert->valid_before = (uint64_t)-1;
	sshbuf_free(k1->cert->critical);
	k1->cert->critical = sshbuf_new();
	ASSERT_PTR_NE(k1->cert->critical, ফাঁকা);
	sshbuf_free(k1->cert->extensions);
	k1->cert->extensions = sshbuf_new();
	ASSERT_PTR_NE(k1->cert->extensions, ফাঁকা);
	put_opt(k1->cert->critical, "force-command", "/usr/bin/true");
	put_opt(k1->cert->critical, "source-address", "127.0.0.1");
	put_opt(k1->cert->extensions, "permit-X11-forwarding", ফাঁকা);
	put_opt(k1->cert->extensions, "permit-agent-forwarding", ফাঁকা);
	ASSERT_INT_EQ(sshkey_from_private(k2, &k1->cert->signature_চাবি), 0);
	ASSERT_INT_EQ(sshkey_certify(k1, k2, ফাঁকা, ফাঁকা, ফাঁকা), 0);
	b = sshbuf_new();
	ASSERT_PTR_NE(b, ফাঁকা);
	ASSERT_INT_EQ(sshkey_putb(k1, b), 0);
	ASSERT_INT_EQ(sshkey_from_blob(sshbuf_ptr(b), sshbuf_len(b), &k3), 0);
	sshkey_free(k1);
	sshkey_free(k2);
	sshkey_free(k3);
	k1 = k2 = k3 = ফাঁকা;
	sshbuf_reset(b);
	TEST_DONE();

#ifdef WITH_OPENSSL
	TEST_START("sign and verify RSA");
	k1 = get_private("rsa_1");
	ASSERT_INT_EQ(sshkey_load_public(test_তথ্য_file("rsa_2.pub"), &k2,
	    ফাঁকা), 0);
	signature_tests(k1, k2, "ssh-rsa");
	sshkey_free(k1);
	sshkey_free(k2);
	k1 = k2 = ফাঁকা;
	TEST_DONE();

	TEST_START("sign and verify RSA-SHA256");
	k1 = get_private("rsa_1");
	ASSERT_INT_EQ(sshkey_load_public(test_তথ্য_file("rsa_2.pub"), &k2,
	    ফাঁকা), 0);
	signature_tests(k1, k2, "rsa-sha2-256");
	sshkey_free(k1);
	sshkey_free(k2);
	k1 = k2 = ফাঁকা;
	TEST_DONE();

	TEST_START("sign and verify RSA-SHA512");
	k1 = get_private("rsa_1");
	ASSERT_INT_EQ(sshkey_load_public(test_তথ্য_file("rsa_2.pub"), &k2,
	    ফাঁকা), 0);
	signature_tests(k1, k2, "rsa-sha2-512");
	sshkey_free(k1);
	sshkey_free(k2);
	k1 = k2 = ফাঁকা;
	TEST_DONE();


	TEST_START("sign and verify ECDSA");
	k1 = get_private("ecdsa_1");
	ASSERT_INT_EQ(sshkey_load_public(test_তথ্য_file("ecdsa_2.pub"), &k2,
	    ফাঁকা), 0);
	signature_tests(k1, k2, ফাঁকা);
	sshkey_free(k1);
	sshkey_free(k2);
	k1 = k2 = ফাঁকা;
	TEST_DONE();
#endif /* WITH_OPENSSL */

	TEST_START("sign and verify ED25519");
	k1 = get_private("ed25519_1");
	ASSERT_INT_EQ(sshkey_load_public(test_তথ্য_file("ed25519_2.pub"), &k2,
	    ফাঁকা), 0);
	signature_tests(k1, k2, ফাঁকা);
	sshkey_free(k1);
	sshkey_free(k2);
	k1 = k2 = ফাঁকা;
	TEST_DONE();

	TEST_START("sign and verify MLDSA44-ED25519");
	k1 = get_private("mldsa44_ed25519_1");
	ASSERT_INT_EQ(sshkey_load_public(
	    test_তথ্য_file("mldsa44_ed25519_2.pub"), &k2, ফাঁকা), 0);
	signature_tests(k1, k2, ফাঁকা);
	sshkey_free(k1);
	sshkey_free(k2);
	k1 = k2 = ফাঁকা;
	TEST_DONE();

#ifdef WITH_OPENSSL
	TEST_START("nested certificate");
	ASSERT_INT_EQ(sshkey_load_cert(test_তথ্য_file("rsa_1"), &k1), 0);
	ASSERT_INT_EQ(sshkey_load_public(test_তথ্য_file("rsa_1.pub"), &k2,
	    ফাঁকা), 0);
	k3 = get_private("rsa_1");
	build_cert(b, k2, "ssh-rsa-cert-v01@openssh.com", k3, k1, ফাঁকা);
	ASSERT_INT_EQ(sshkey_from_blob(sshbuf_ptr(b), sshbuf_len(b), &k4),
	    SSH_ERR_চাবি_CERT_INVALID_SIGN_চাবি);
	ASSERT_PTR_EQ(k4, ফাঁকা);
	sshkey_free(k1);
	sshkey_free(k2);
	sshkey_free(k3);
	k1 = k2 = k3 = ফাঁকা;
	sshbuf_free(b);
	TEST_DONE();
#endif /* WITH_OPENSSL */
}

শূন্য
sshkey_benchmarks(শূন্য)
{
	কাঠামো sshkey *k = ফাঁকা;

#ifdef WITH_OPENSSL
	BENCH_START("generate RSA-1024");
	TEST_START("generate KEY_RSA");
	ASSERT_INT_EQ(sshkey_generate(চাবি_RSA, 1024, &k), 0);
	ASSERT_PTR_NE(k, ফাঁকা);
	sshkey_free(k);
	k = ফাঁকা;
	TEST_DONE();
	BENCH_FINISH("keys");

	BENCH_START("generate RSA-2048");
	TEST_START("generate KEY_RSA");
	ASSERT_INT_EQ(sshkey_generate(চাবি_RSA, 2048, &k), 0);
	ASSERT_PTR_NE(k, ফাঁকা);
	sshkey_free(k);
	k = ফাঁকা;
	TEST_DONE();
	BENCH_FINISH("keys");

	BENCH_START("generate ECDSA-256");
	TEST_START("generate KEY_ECDSA");
	ASSERT_INT_EQ(sshkey_generate(চাবি_ECDSA, 256, &k), 0);
	ASSERT_PTR_NE(k, ফাঁকা);
	sshkey_free(k);
	k = ফাঁকা;
	TEST_DONE();
	BENCH_FINISH("keys");

	BENCH_START("generate ECDSA-384");
	TEST_START("generate KEY_ECDSA");
	ASSERT_INT_EQ(sshkey_generate(চাবি_ECDSA, 384, &k), 0);
	ASSERT_PTR_NE(k, ফাঁকা);
	sshkey_free(k);
	k = ফাঁকা;
	TEST_DONE();
	BENCH_FINISH("keys");

	BENCH_START("generate ECDSA-521");
	TEST_START("generate KEY_ECDSA");
	ASSERT_INT_EQ(sshkey_generate(চাবি_ECDSA, 521, &k), 0);
	ASSERT_PTR_NE(k, ফাঁকা);
	sshkey_free(k);
	k = ফাঁকা;
	TEST_DONE();
	BENCH_FINISH("keys");
#endif /* WITH_OPENSSL */

	BENCH_START("generate ED25519");
	TEST_START("generate KEY_ED25519");
	ASSERT_INT_EQ(sshkey_generate(চাবি_ED25519, 256, &k), 0);
	ASSERT_PTR_NE(k, ফাঁকা);
	sshkey_free(k);
	k = ফাঁকা;
	TEST_DONE();
	BENCH_FINISH("keys");

	BENCH_START("generate MLDSA44-ED25519");
	TEST_START("generate KEY_MLDSA44_ED25519");
	ASSERT_INT_EQ(sshkey_generate(চাবি_MLDSA44_ED25519, 256, &k), 0);
	ASSERT_PTR_NE(k, ফাঁকা);
	sshkey_free(k);
	k = ফাঁকা;
	TEST_DONE();
	BENCH_FINISH("keys");

#ifdef WITH_OPENSSL
	/* sign */
	signature_benchmark("RSA-1024/SHA1", চাবি_RSA, 1024, "ssh-rsa", 0);
	signature_benchmark("RSA-1024/SHA256", চাবি_RSA, 1024, "rsa-sha2-256", 0);
	signature_benchmark("RSA-1024/SHA512", চাবি_RSA, 1024, "rsa-sha2-512", 0);
	signature_benchmark("RSA-2048/SHA1", চাবি_RSA, 2048, "ssh-rsa", 0);
	signature_benchmark("RSA-2048/SHA256", চাবি_RSA, 2048, "rsa-sha2-256", 0);
	signature_benchmark("RSA-2048/SHA512", চাবি_RSA, 2048, "rsa-sha2-512", 0);
	signature_benchmark("ECDSA-256", চাবি_ECDSA, 256, ফাঁকা, 0);
	signature_benchmark("ECDSA-384", চাবি_ECDSA, 384, ফাঁকা, 0);
	signature_benchmark("ECDSA-521", চাবি_ECDSA, 521, ফাঁকা, 0);
	signature_benchmark("ED25519", চাবি_ED25519, 0, ফাঁকা, 0);
	signature_benchmark("MLDSA44-ED25519", চাবি_MLDSA44_ED25519, 0, ফাঁকা, 0);

	/* verify */
	signature_benchmark("RSA-1024/SHA1", চাবি_RSA, 1024, "ssh-rsa", 1);
	signature_benchmark("RSA-1024/SHA256", চাবি_RSA, 1024, "rsa-sha2-256", 1);
	signature_benchmark("RSA-1024/SHA512", চাবি_RSA, 1024, "rsa-sha2-512", 1);
	signature_benchmark("RSA-2048/SHA1", চাবি_RSA, 2048, "ssh-rsa", 1);
	signature_benchmark("RSA-2048/SHA256", চাবি_RSA, 2048, "rsa-sha2-256", 1);
	signature_benchmark("RSA-2048/SHA512", চাবি_RSA, 2048, "rsa-sha2-512", 1);
	signature_benchmark("ECDSA-256", চাবি_ECDSA, 256, ফাঁকা, 1);
	signature_benchmark("ECDSA-384", চাবি_ECDSA, 384, ফাঁকা, 1);
	signature_benchmark("ECDSA-521", চাবি_ECDSA, 521, ফাঁকা, 1);
#endif /* WITH_OPENSSL */
	signature_benchmark("ED25519", চাবি_ED25519, 0, ফাঁকা, 1);
	signature_benchmark("MLDSA44-ED25519", চাবি_MLDSA44_ED25519, 0, ফাঁকা, 1);
}
