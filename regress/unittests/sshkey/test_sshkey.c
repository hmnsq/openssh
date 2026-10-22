/* 	$OpenBSD: test_sshkey.c,v 1.34 2026/06/14 04:08:06 djm Exp $ */
/*
 * Regress test for sshkey.h key management API
 *
 * Placed in the public domain
 */

#شامل "includes.h"

#شامل <sys/types.h>
#شامل <stdio.h>
#شامل <stdint.h>
#شامل <stdlib.h>
#شامل <string.h>

#ifdef WITH_OPENSSL
#شامل <openssl/bn.h>
#شامل <openssl/ec.h>
#شامل <openssl/rsa.h>
#endif

#شامل "../test_helper/test_helper.h"

#شامل "ssherr.h"
#شامل "sshbuf.h"
#define SSHBUF_INTERNAL 1	/* access internals for testing */
#شامل "sshkey.h"

#شامل "authfile.h"
#شامل "common.h"
#شامل "ssh2.h"

تهی sshkey_tests(تهی);
تهی sshkey_benchmarks(تهی);

ایستا تهی
put_opt(ساختار sshbuf *b, ثابت نویسه *name, ثابت نویسه *مقدار)
{
	ساختار sshbuf *sect;

	sect = sshbuf_new();
	ASSERT_PTR_NE(sect, پوچ);
	ASSERT_INT_EQ(sshbuf_put_cstring(b, name), 0);
	اگر (مقدار != پوچ)
		ASSERT_INT_EQ(sshbuf_put_cstring(sect, مقدار), 0);
	ASSERT_INT_EQ(sshbuf_put_stringb(b, sect), 0);
	sshbuf_free(sect);
}

#ifdef WITH_OPENSSL
ایستا تهی
build_cert(ساختار sshbuf *b, ساختار sshkey *k, ثابت نویسه *type,
    ساختار sshkey *sign_کلید, ساختار sshkey *ca_کلید,
    ثابت نویسه *sig_alg)
{
	ساختار sshbuf *ca_buf, *pk, *principals, *critopts, *exts;
	u_char *sigblob;
	size_t siglen;

	ca_buf = sshbuf_new();
	ASSERT_PTR_NE(ca_buf, پوچ);
	ASSERT_INT_EQ(sshkey_putb(ca_کلید, ca_buf), 0);

	/*
	 * Get the public key serialisation by rendering the key and skipping
	 * the type string. This is a bit of a hack :/
	 */
	pk = sshbuf_new();
	ASSERT_PTR_NE(pk, پوچ);
	ASSERT_INT_EQ(sshkey_putb_plain(k, pk), 0);
	ASSERT_INT_EQ(sshbuf_skip_string(pk), 0);

	principals = sshbuf_new();
	ASSERT_PTR_NE(principals, پوچ);
	ASSERT_INT_EQ(sshbuf_put_cstring(principals, "gsamsa"), 0);
	ASSERT_INT_EQ(sshbuf_put_cstring(principals, "gregor"), 0);

	critopts = sshbuf_new();
	ASSERT_PTR_NE(critopts, پوچ);
	put_opt(critopts, "force-command", "/usr/local/bin/nethack");
	put_opt(critopts, "source-address", "192.168.0.0/24,127.0.0.1,::1");

	exts = sshbuf_new();
	ASSERT_PTR_NE(exts, پوچ);
	put_opt(critopts, "permit-X11-forwarding", پوچ);

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
	ASSERT_INT_EQ(sshbuf_put_string(b, پوچ, 0), 0); /* reserved */
	ASSERT_INT_EQ(sshbuf_put_stringb(b, ca_buf), 0); /* signature key */
	ASSERT_INT_EQ(sshkey_sign(sign_کلید, &sigblob, &siglen,
	    sshbuf_ptr(b), sshbuf_len(b), sig_alg, پوچ, پوچ, 0), 0);
	ASSERT_INT_EQ(sshbuf_put_string(b, sigblob, siglen), 0); /* signature */

	آزاد(sigblob);
	sshbuf_free(ca_buf);
	sshbuf_free(exts);
	sshbuf_free(critopts);
	sshbuf_free(principals);
	sshbuf_free(pk);
}
#endif /* WITH_OPENSSL */

ایستا تهی
signature_test(ساختار sshkey *k, ساختار sshkey *bad, ثابت نویسه *sig_alg,
    ثابت u_char *d, size_t l)
{
	size_t len;
	u_char *sig;

	ASSERT_INT_EQ(sshkey_sign(k, &sig, &len, d, l, sig_alg,
	    پوچ, پوچ, 0), 0);
	ASSERT_SIZE_T_GT(len, 8);
	ASSERT_PTR_NE(sig, پوچ);
	ASSERT_INT_EQ(sshkey_verify(k, sig, len, d, l, پوچ, 0, پوچ), 0);
	ASSERT_INT_NE(sshkey_verify(bad, sig, len, d, l, پوچ, 0, پوچ), 0);
	/* Fuzz test is more comprehensive, this is just a smoke test */
	sig[len - 5] ^= 0x10;
	ASSERT_INT_NE(sshkey_verify(k, sig, len, d, l, پوچ, 0, پوچ), 0);
	آزاد(sig);
}

ایستا تهی
signature_bench(ثابت نویسه *name, صحیح ktype, صحیح bits, ثابت نویسه *sig_alg,
    ثابت u_char *d, size_t l)
{
	ساختار sshkey *k;
	size_t len;
	u_char *sig;
	نویسه testname[256];

	snprintf(testname, اندازه(testname), "sign %s", name);
	TEST_START(testname);
	ASSERT_INT_EQ(sshkey_generate(ktype, bits, &k), 0);
	ASSERT_PTR_NE(k, پوچ);

	BENCH_START(testname);
	ASSERT_INT_EQ(sshkey_sign(k, &sig, &len, d, l, sig_alg,
	    پوچ, پوچ, 0), 0);
	آزاد(sig);
	BENCH_FINISH("sign");

	sshkey_free(k);
	TEST_DONE();
}

ایستا تهی
verify_bench(ثابت نویسه *name, صحیح ktype, صحیح bits, ثابت نویسه *sig_alg,
    ثابت u_char *d, size_t l)
{
	ساختار sshkey *k;
	size_t len;
	u_char *sig;
	نویسه testname[256];

	snprintf(testname, اندازه(testname), "verify %s", name);
	TEST_START(testname);
	ASSERT_INT_EQ(sshkey_generate(ktype, bits, &k), 0);
	ASSERT_PTR_NE(k, پوچ);

	ASSERT_INT_EQ(sshkey_sign(k, &sig, &len, d, l, sig_alg,
	    پوچ, پوچ, 0), 0);
	BENCH_START(testname);
	ASSERT_INT_EQ(sshkey_verify(k, sig, len, d, l, پوچ, 0, پوچ), 0);
	BENCH_FINISH("verify");

	آزاد(sig);
	sshkey_free(k);
	TEST_DONE();
}

ایستا تهی
banana(u_char *s, size_t l)
{
	size_t o;
	ثابت u_char the_banana[] = { 'b', 'a', 'n', 'a', 'n', 'a' };

	برای (o = 0; o < l; o += اندازه(the_banana)) {
		اگر (l - o < اندازه(the_banana)) {
			memcpy(s + o, "nanananana", l - o);
			بشکن;
		}
		memcpy(s + o, the_banana, اندازه(the_banana));
	}
}

ایستا تهی
signature_tests(ساختار sshkey *k, ساختار sshkey *bad, ثابت نویسه *sig_alg)
{
	u_char i, buf[2049];
	size_t lens[] = {
		1, 2, 7, 8, 9, 15, 16, 17, 31, 32, 33, 127, 128, 129,
		255, 256, 257, 1023, 1024, 1025, 2047, 2048, 2049
	};

	برای (i = 0; i < (اندازه(lens)/اندازه(lens[0])); i++) {
		test_subtest_info("%s key, banana length %zu",
		    sshkey_type(k), lens[i]);
		banana(buf, lens[i]);
		signature_test(k, bad, sig_alg, buf, lens[i]);
	}
}

ایستا تهی
signature_benchmark(ثابت نویسه *name, صحیح ktype, صحیح bits,
    ثابت نویسه *sig_alg, صحیح bench_verify)
{
	u_char buf[256];

	banana(buf, اندازه(buf));
	اگر (bench_verify)
		verify_bench(name, ktype, bits, sig_alg, buf, اندازه(buf));
	وگرنه
		signature_bench(name, ktype, bits, sig_alg, buf, اندازه(buf));
}

ایستا ساختار sshkey *
get_private(ثابت نویسه *n)
{
	ساختار sshbuf *b;
	ساختار sshkey *ret;

	b = load_file(n);
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(b, "", &ret, پوچ), 0);
	sshbuf_free(b);
	بازگشت ret;
}

تهی
sshkey_tests(تهی)
{
	ساختار sshkey *k1 = پوچ, *k2 = پوچ, *k3 = پوچ, *k4 = پوچ;
	ساختار sshkey *kr = پوچ, *kd = پوچ, *ke = پوچ, *kf = پوچ;
	ساختار sshbuf *b = پوچ;

	TEST_START("new invalid");
	k1 = sshkey_new(-42);
	ASSERT_PTR_EQ(k1, پوچ);
	TEST_DONE();

	TEST_START("new/free KEY_UNSPEC");
	k1 = sshkey_new(کلید_UNSPEC);
	ASSERT_PTR_NE(k1, پوچ);
	sshkey_free(k1);
	k1 = پوچ;
	TEST_DONE();

#ifdef WITH_OPENSSL
	TEST_START("new/free KEY_RSA");
	k1 = sshkey_new(کلید_RSA);
	ASSERT_PTR_NE(k1, پوچ);
	ASSERT_PTR_NE(k1->pkey, پوچ);
	sshkey_free(k1);
	k1 = پوچ;
	TEST_DONE();

	TEST_START("new/free KEY_ECDSA");
	k1 = sshkey_new(کلید_ECDSA);
	ASSERT_PTR_NE(k1, پوچ);
	ASSERT_PTR_EQ(k1->pkey, پوچ);  /* Can't allocate without NID */
	sshkey_free(k1);
	k1 = پوچ;
	TEST_DONE();
#endif /* WITH_OPENSSL */

	TEST_START("new/free KEY_ED25519");
	k1 = sshkey_new(کلید_ED25519);
	ASSERT_PTR_NE(k1, پوچ);
	/* These should be blank until key loaded or generated */
	ASSERT_PTR_EQ(k1->ed25519_sk, پوچ);
	ASSERT_PTR_EQ(k1->ed25519_pk, پوچ);
	sshkey_free(k1);
	k1 = پوچ;
	TEST_DONE();

	TEST_START("new/free KEY_MLDSA44_ED25519");
	k1 = sshkey_new(کلید_MLDSA44_ED25519);
	ASSERT_PTR_NE(k1, پوچ);
	ASSERT_PTR_EQ(k1->mldsa_ed25519_sk, پوچ);
	ASSERT_PTR_EQ(k1->mldsa_ed25519_pk, پوچ);
	sshkey_free(k1);
	k1 = پوچ;
	TEST_DONE();

#ifdef WITH_OPENSSL
	TEST_START("generate KEY_RSA too small modulus");
	ASSERT_INT_EQ(sshkey_generate(کلید_RSA, 128, &k1),
	    SSH_ERR_کلید_LENGTH);
	ASSERT_PTR_EQ(k1, پوچ);
	TEST_DONE();

	TEST_START("generate KEY_RSA too large modulus");
	ASSERT_INT_EQ(sshkey_generate(کلید_RSA, 1 << 20, &k1),
	    SSH_ERR_کلید_LENGTH);
	ASSERT_PTR_EQ(k1, پوچ);
	TEST_DONE();


	TEST_START("generate KEY_ECDSA wrong bits");
	ASSERT_INT_EQ(sshkey_generate(کلید_ECDSA, 42, &k1),
	    SSH_ERR_کلید_LENGTH);
	ASSERT_PTR_EQ(k1, پوچ);
	sshkey_free(k1);
	k1 = پوچ;
	TEST_DONE();

	TEST_START("generate KEY_RSA");
	ASSERT_INT_EQ(sshkey_generate(کلید_RSA, 767, &kr),
	    SSH_ERR_کلید_LENGTH);
	ASSERT_INT_EQ(sshkey_generate(کلید_RSA, 1024, &kr), 0);
	ASSERT_PTR_NE(kr, پوچ);
	ASSERT_PTR_NE(EVP_PKEY_get0_RSA(kr->pkey), پوچ);
	ASSERT_PTR_NE(rsa_n(kr), پوچ);
	ASSERT_PTR_NE(rsa_e(kr), پوچ);
	ASSERT_PTR_NE(rsa_p(kr), پوچ);
	ASSERT_INT_EQ(BN_رقم_bits(rsa_n(kr)), 1024);
	TEST_DONE();


	TEST_START("generate KEY_ECDSA");
	ASSERT_INT_EQ(sshkey_generate(کلید_ECDSA, 256, &ke), 0);
	ASSERT_PTR_NE(ke, پوچ);
	ASSERT_PTR_NE(EVP_PKEY_get0_EC_کلید(ke->pkey), پوچ);
	ASSERT_PTR_NE(EC_کلید_get0_public_کلید(EVP_PKEY_get0_EC_کلید(ke->pkey)),
	    پوچ);
	ASSERT_PTR_NE(EC_کلید_get0_private_کلید(EVP_PKEY_get0_EC_کلید(ke->pkey)),
	    پوچ);
	TEST_DONE();
#endif /* WITH_OPENSSL */

	TEST_START("generate KEY_ED25519");
	ASSERT_INT_EQ(sshkey_generate(کلید_ED25519, 256, &kf), 0);
	ASSERT_PTR_NE(kf, پوچ);
	ASSERT_INT_EQ(kf->type, کلید_ED25519);
	ASSERT_PTR_NE(kf->ed25519_pk, پوچ);
	ASSERT_PTR_NE(kf->ed25519_sk, پوچ);
	TEST_DONE();

	TEST_START("generate KEY_MLDSA44_ED25519");
	ASSERT_INT_EQ(sshkey_generate(کلید_MLDSA44_ED25519, 256, &k1), 0);
	ASSERT_PTR_NE(k1, پوچ);
	ASSERT_INT_EQ(k1->type, کلید_MLDSA44_ED25519);
	ASSERT_PTR_NE(k1->mldsa_ed25519_pk, پوچ);
	ASSERT_PTR_NE(k1->mldsa_ed25519_sk, پوچ);
	sshkey_free(k1);
	k1 = پوچ;
	TEST_DONE();

#ifdef WITH_OPENSSL
	TEST_START("demote KEY_RSA");
	ASSERT_INT_EQ(sshkey_from_private(kr, &k1), 0);
	ASSERT_PTR_NE(k1, پوچ);
	ASSERT_PTR_NE(kr, k1);
	ASSERT_INT_EQ(k1->type, کلید_RSA);
	ASSERT_PTR_NE(EVP_PKEY_get0_RSA(k1->pkey), پوچ);
	ASSERT_PTR_NE(rsa_n(k1), پوچ);
	ASSERT_PTR_NE(rsa_e(k1), پوچ);
	ASSERT_PTR_EQ(rsa_p(k1), پوچ);
	TEST_DONE();

	TEST_START("equal KEY_RSA/demoted KEY_RSA");
	ASSERT_INT_EQ(sshkey_equal(kr, k1), 1);
	sshkey_free(k1);
	k1 = پوچ;
	TEST_DONE();


	TEST_START("demote KEY_ECDSA");
	ASSERT_INT_EQ(sshkey_from_private(ke, &k1), 0);
	ASSERT_PTR_NE(k1, پوچ);
	ASSERT_PTR_NE(ke, k1);
	ASSERT_INT_EQ(k1->type, کلید_ECDSA);
	ASSERT_PTR_NE(EVP_PKEY_get0_EC_کلید(k1->pkey), پوچ);
	ASSERT_INT_EQ(k1->ecdsa_nid, ke->ecdsa_nid);
	ASSERT_PTR_NE(EC_کلید_get0_public_کلید(EVP_PKEY_get0_EC_کلید(ke->pkey)),
	   پوچ);
	ASSERT_PTR_EQ(EC_کلید_get0_private_کلید(EVP_PKEY_get0_EC_کلید(k1->pkey)),
	   پوچ);
	TEST_DONE();

	TEST_START("equal KEY_ECDSA/demoted KEY_ECDSA");
	ASSERT_INT_EQ(sshkey_equal(ke, k1), 1);
	sshkey_free(k1);
	k1 = پوچ;
	TEST_DONE();
#endif /* WITH_OPENSSL */

	TEST_START("demote KEY_ED25519");
	ASSERT_INT_EQ(sshkey_from_private(kf, &k1), 0);
	ASSERT_PTR_NE(k1, پوچ);
	ASSERT_PTR_NE(kf, k1);
	ASSERT_INT_EQ(k1->type, کلید_ED25519);
	ASSERT_PTR_NE(k1->ed25519_pk, پوچ);
	ASSERT_PTR_EQ(k1->ed25519_sk, پوچ);
	TEST_DONE();

	TEST_START("equal KEY_ED25519/demoted KEY_ED25519");
	ASSERT_INT_EQ(sshkey_equal(kf, k1), 1);
	sshkey_free(k1);
	k1 = پوچ;
	TEST_DONE();

	TEST_START("demote KEY_MLDSA44_ED25519");
	ASSERT_INT_EQ(sshkey_generate(کلید_MLDSA44_ED25519, 256, &k2), 0);
	ASSERT_INT_EQ(sshkey_from_private(k2, &k1), 0);
	ASSERT_PTR_NE(k1, پوچ);
	ASSERT_PTR_NE(k2, k1);
	ASSERT_INT_EQ(k1->type, کلید_MLDSA44_ED25519);
	ASSERT_PTR_NE(k1->mldsa_ed25519_pk, پوچ);
	ASSERT_PTR_EQ(k1->mldsa_ed25519_sk, پوچ);
	TEST_DONE();

	TEST_START("equal KEY_MLDSA44_ED25519/demoted KEY_MLDSA44_ED25519");
	ASSERT_INT_EQ(sshkey_equal(k2, k1), 1);
	sshkey_free(k1);
	sshkey_free(k2);
	k1 = k2 = پوچ;
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
	ASSERT_INT_EQ(sshkey_generate(کلید_RSA, 1024, &k1), 0);
	ASSERT_INT_EQ(sshkey_equal(kr, k1), 0);
	sshkey_free(k1);
	k1 = پوچ;
	ASSERT_INT_EQ(sshkey_generate(کلید_ECDSA, 256, &k1), 0);
	ASSERT_INT_EQ(sshkey_equal(ke, k1), 0);
	sshkey_free(k1);
	k1 = پوچ;
	ASSERT_INT_EQ(sshkey_generate(کلید_ED25519, 256, &k1), 0);
	ASSERT_INT_EQ(sshkey_equal(kf, k1), 0);
	sshkey_free(k1);
	k1 = پوچ;
	ASSERT_INT_EQ(sshkey_generate(کلید_MLDSA44_ED25519, 256, &k1), 0);
	ASSERT_INT_EQ(sshkey_generate(کلید_MLDSA44_ED25519, 256, &k2), 0);
	ASSERT_INT_EQ(sshkey_equal(k2, k1), 0);
	sshkey_free(k1);
	sshkey_free(k2);
	k1 = k2 = پوچ;
	TEST_DONE();
#endif /* WITH_OPENSSL */

	sshkey_free(kr);
	sshkey_free(kd);
	sshkey_free(ke);
	sshkey_free(kf);
	kr = kd = ke = kf = پوچ;

	TEST_START("certify key");
	ASSERT_INT_EQ(sshkey_load_public(test_data_file("ed25519_1.pub"),
	    &k1, پوچ), 0);
	k2 = get_private("ed25519_2");
	ASSERT_INT_EQ(sshkey_to_certified(k1), 0);
	ASSERT_PTR_NE(k1->cert, پوچ);
	k1->cert->type = SSH2_CERT_TYPE_USER;
	k1->cert->serial = 1234;
	k1->cert->کلید_id = strdup("estragon");
	ASSERT_PTR_NE(k1->cert->کلید_id, پوچ);
	k1->cert->principals = calloc(4, اندازه(*k1->cert->principals));
	ASSERT_PTR_NE(k1->cert->principals, پوچ);
	k1->cert->principals[0] = strdup("estragon");
	k1->cert->principals[1] = strdup("vladimir");
	k1->cert->principals[2] = strdup("pozzo");
	k1->cert->principals[3] = strdup("lucky");
	ASSERT_PTR_NE(k1->cert->principals[0], پوچ);
	ASSERT_PTR_NE(k1->cert->principals[1], پوچ);
	ASSERT_PTR_NE(k1->cert->principals[2], پوچ);
	ASSERT_PTR_NE(k1->cert->principals[3], پوچ);
	k1->cert->nprincipals = 4;
	k1->cert->valid_after = 0;
	k1->cert->valid_before = (uint64_t)-1;
	sshbuf_free(k1->cert->critical);
	k1->cert->critical = sshbuf_new();
	ASSERT_PTR_NE(k1->cert->critical, پوچ);
	sshbuf_free(k1->cert->extensions);
	k1->cert->extensions = sshbuf_new();
	ASSERT_PTR_NE(k1->cert->extensions, پوچ);
	put_opt(k1->cert->critical, "force-command", "/usr/bin/true");
	put_opt(k1->cert->critical, "source-address", "127.0.0.1");
	put_opt(k1->cert->extensions, "permit-X11-forwarding", پوچ);
	put_opt(k1->cert->extensions, "permit-agent-forwarding", پوچ);
	ASSERT_INT_EQ(sshkey_from_private(k2, &k1->cert->signature_کلید), 0);
	ASSERT_INT_EQ(sshkey_certify(k1, k2, پوچ, پوچ, پوچ), 0);
	b = sshbuf_new();
	ASSERT_PTR_NE(b, پوچ);
	ASSERT_INT_EQ(sshkey_putb(k1, b), 0);
	ASSERT_INT_EQ(sshkey_from_blob(sshbuf_ptr(b), sshbuf_len(b), &k3), 0);

	sshkey_free(k1);
	sshkey_free(k2);
	sshkey_free(k3);
	k1 = k2 = k3 = پوچ;
	sshbuf_reset(b);
	TEST_DONE();

	TEST_START("certify key MLDSA44-ED25519");
	ASSERT_INT_EQ(sshkey_load_public(
	    test_data_file("mldsa44_ed25519_1.pub"), &k1, پوچ), 0);
	k2 = get_private("mldsa44_ed25519_2");
	ASSERT_INT_EQ(sshkey_to_certified(k1), 0);
	ASSERT_PTR_NE(k1->cert, پوچ);
	k1->cert->type = SSH2_CERT_TYPE_USER;
	k1->cert->serial = 1234;
	k1->cert->کلید_id = strdup("estragon");
	ASSERT_PTR_NE(k1->cert->کلید_id, پوچ);
	k1->cert->principals = calloc(4, اندازه(*k1->cert->principals));
	ASSERT_PTR_NE(k1->cert->principals, پوچ);
	k1->cert->principals[0] = strdup("estragon");
	k1->cert->principals[1] = strdup("vladimir");
	k1->cert->principals[2] = strdup("pozzo");
	k1->cert->principals[3] = strdup("lucky");
	ASSERT_PTR_NE(k1->cert->principals[0], پوچ);
	ASSERT_PTR_NE(k1->cert->principals[1], پوچ);
	ASSERT_PTR_NE(k1->cert->principals[2], پوچ);
	ASSERT_PTR_NE(k1->cert->principals[3], پوچ);
	k1->cert->nprincipals = 4;
	k1->cert->valid_after = 0;
	k1->cert->valid_before = (uint64_t)-1;
	sshbuf_free(k1->cert->critical);
	k1->cert->critical = sshbuf_new();
	ASSERT_PTR_NE(k1->cert->critical, پوچ);
	sshbuf_free(k1->cert->extensions);
	k1->cert->extensions = sshbuf_new();
	ASSERT_PTR_NE(k1->cert->extensions, پوچ);
	put_opt(k1->cert->critical, "force-command", "/usr/bin/true");
	put_opt(k1->cert->critical, "source-address", "127.0.0.1");
	put_opt(k1->cert->extensions, "permit-X11-forwarding", پوچ);
	put_opt(k1->cert->extensions, "permit-agent-forwarding", پوچ);
	ASSERT_INT_EQ(sshkey_from_private(k2, &k1->cert->signature_کلید), 0);
	ASSERT_INT_EQ(sshkey_certify(k1, k2, پوچ, پوچ, پوچ), 0);
	b = sshbuf_new();
	ASSERT_PTR_NE(b, پوچ);
	ASSERT_INT_EQ(sshkey_putb(k1, b), 0);
	ASSERT_INT_EQ(sshkey_from_blob(sshbuf_ptr(b), sshbuf_len(b), &k3), 0);
	sshkey_free(k1);
	sshkey_free(k2);
	sshkey_free(k3);
	k1 = k2 = k3 = پوچ;
	sshbuf_reset(b);
	TEST_DONE();

#ifdef WITH_OPENSSL
	TEST_START("sign and verify RSA");
	k1 = get_private("rsa_1");
	ASSERT_INT_EQ(sshkey_load_public(test_data_file("rsa_2.pub"), &k2,
	    پوچ), 0);
	signature_tests(k1, k2, "ssh-rsa");
	sshkey_free(k1);
	sshkey_free(k2);
	k1 = k2 = پوچ;
	TEST_DONE();

	TEST_START("sign and verify RSA-SHA256");
	k1 = get_private("rsa_1");
	ASSERT_INT_EQ(sshkey_load_public(test_data_file("rsa_2.pub"), &k2,
	    پوچ), 0);
	signature_tests(k1, k2, "rsa-sha2-256");
	sshkey_free(k1);
	sshkey_free(k2);
	k1 = k2 = پوچ;
	TEST_DONE();

	TEST_START("sign and verify RSA-SHA512");
	k1 = get_private("rsa_1");
	ASSERT_INT_EQ(sshkey_load_public(test_data_file("rsa_2.pub"), &k2,
	    پوچ), 0);
	signature_tests(k1, k2, "rsa-sha2-512");
	sshkey_free(k1);
	sshkey_free(k2);
	k1 = k2 = پوچ;
	TEST_DONE();


	TEST_START("sign and verify ECDSA");
	k1 = get_private("ecdsa_1");
	ASSERT_INT_EQ(sshkey_load_public(test_data_file("ecdsa_2.pub"), &k2,
	    پوچ), 0);
	signature_tests(k1, k2, پوچ);
	sshkey_free(k1);
	sshkey_free(k2);
	k1 = k2 = پوچ;
	TEST_DONE();
#endif /* WITH_OPENSSL */

	TEST_START("sign and verify ED25519");
	k1 = get_private("ed25519_1");
	ASSERT_INT_EQ(sshkey_load_public(test_data_file("ed25519_2.pub"), &k2,
	    پوچ), 0);
	signature_tests(k1, k2, پوچ);
	sshkey_free(k1);
	sshkey_free(k2);
	k1 = k2 = پوچ;
	TEST_DONE();

	TEST_START("sign and verify MLDSA44-ED25519");
	k1 = get_private("mldsa44_ed25519_1");
	ASSERT_INT_EQ(sshkey_load_public(
	    test_data_file("mldsa44_ed25519_2.pub"), &k2, پوچ), 0);
	signature_tests(k1, k2, پوچ);
	sshkey_free(k1);
	sshkey_free(k2);
	k1 = k2 = پوچ;
	TEST_DONE();

#ifdef WITH_OPENSSL
	TEST_START("nested certificate");
	ASSERT_INT_EQ(sshkey_load_cert(test_data_file("rsa_1"), &k1), 0);
	ASSERT_INT_EQ(sshkey_load_public(test_data_file("rsa_1.pub"), &k2,
	    پوچ), 0);
	k3 = get_private("rsa_1");
	build_cert(b, k2, "ssh-rsa-cert-v01@openssh.com", k3, k1, پوچ);
	ASSERT_INT_EQ(sshkey_from_blob(sshbuf_ptr(b), sshbuf_len(b), &k4),
	    SSH_ERR_کلید_CERT_INVALID_SIGN_کلید);
	ASSERT_PTR_EQ(k4, پوچ);
	sshkey_free(k1);
	sshkey_free(k2);
	sshkey_free(k3);
	k1 = k2 = k3 = پوچ;
	sshbuf_free(b);
	TEST_DONE();
#endif /* WITH_OPENSSL */
}

تهی
sshkey_benchmarks(تهی)
{
	ساختار sshkey *k = پوچ;

#ifdef WITH_OPENSSL
	BENCH_START("generate RSA-1024");
	TEST_START("generate KEY_RSA");
	ASSERT_INT_EQ(sshkey_generate(کلید_RSA, 1024, &k), 0);
	ASSERT_PTR_NE(k, پوچ);
	sshkey_free(k);
	k = پوچ;
	TEST_DONE();
	BENCH_FINISH("keys");

	BENCH_START("generate RSA-2048");
	TEST_START("generate KEY_RSA");
	ASSERT_INT_EQ(sshkey_generate(کلید_RSA, 2048, &k), 0);
	ASSERT_PTR_NE(k, پوچ);
	sshkey_free(k);
	k = پوچ;
	TEST_DONE();
	BENCH_FINISH("keys");

	BENCH_START("generate ECDSA-256");
	TEST_START("generate KEY_ECDSA");
	ASSERT_INT_EQ(sshkey_generate(کلید_ECDSA, 256, &k), 0);
	ASSERT_PTR_NE(k, پوچ);
	sshkey_free(k);
	k = پوچ;
	TEST_DONE();
	BENCH_FINISH("keys");

	BENCH_START("generate ECDSA-384");
	TEST_START("generate KEY_ECDSA");
	ASSERT_INT_EQ(sshkey_generate(کلید_ECDSA, 384, &k), 0);
	ASSERT_PTR_NE(k, پوچ);
	sshkey_free(k);
	k = پوچ;
	TEST_DONE();
	BENCH_FINISH("keys");

	BENCH_START("generate ECDSA-521");
	TEST_START("generate KEY_ECDSA");
	ASSERT_INT_EQ(sshkey_generate(کلید_ECDSA, 521, &k), 0);
	ASSERT_PTR_NE(k, پوچ);
	sshkey_free(k);
	k = پوچ;
	TEST_DONE();
	BENCH_FINISH("keys");
#endif /* WITH_OPENSSL */

	BENCH_START("generate ED25519");
	TEST_START("generate KEY_ED25519");
	ASSERT_INT_EQ(sshkey_generate(کلید_ED25519, 256, &k), 0);
	ASSERT_PTR_NE(k, پوچ);
	sshkey_free(k);
	k = پوچ;
	TEST_DONE();
	BENCH_FINISH("keys");

	BENCH_START("generate MLDSA44-ED25519");
	TEST_START("generate KEY_MLDSA44_ED25519");
	ASSERT_INT_EQ(sshkey_generate(کلید_MLDSA44_ED25519, 256, &k), 0);
	ASSERT_PTR_NE(k, پوچ);
	sshkey_free(k);
	k = پوچ;
	TEST_DONE();
	BENCH_FINISH("keys");

#ifdef WITH_OPENSSL
	/* sign */
	signature_benchmark("RSA-1024/SHA1", کلید_RSA, 1024, "ssh-rsa", 0);
	signature_benchmark("RSA-1024/SHA256", کلید_RSA, 1024, "rsa-sha2-256", 0);
	signature_benchmark("RSA-1024/SHA512", کلید_RSA, 1024, "rsa-sha2-512", 0);
	signature_benchmark("RSA-2048/SHA1", کلید_RSA, 2048, "ssh-rsa", 0);
	signature_benchmark("RSA-2048/SHA256", کلید_RSA, 2048, "rsa-sha2-256", 0);
	signature_benchmark("RSA-2048/SHA512", کلید_RSA, 2048, "rsa-sha2-512", 0);
	signature_benchmark("ECDSA-256", کلید_ECDSA, 256, پوچ, 0);
	signature_benchmark("ECDSA-384", کلید_ECDSA, 384, پوچ, 0);
	signature_benchmark("ECDSA-521", کلید_ECDSA, 521, پوچ, 0);
	signature_benchmark("ED25519", کلید_ED25519, 0, پوچ, 0);
	signature_benchmark("MLDSA44-ED25519", کلید_MLDSA44_ED25519, 0, پوچ, 0);

	/* verify */
	signature_benchmark("RSA-1024/SHA1", کلید_RSA, 1024, "ssh-rsa", 1);
	signature_benchmark("RSA-1024/SHA256", کلید_RSA, 1024, "rsa-sha2-256", 1);
	signature_benchmark("RSA-1024/SHA512", کلید_RSA, 1024, "rsa-sha2-512", 1);
	signature_benchmark("RSA-2048/SHA1", کلید_RSA, 2048, "ssh-rsa", 1);
	signature_benchmark("RSA-2048/SHA256", کلید_RSA, 2048, "rsa-sha2-256", 1);
	signature_benchmark("RSA-2048/SHA512", کلید_RSA, 2048, "rsa-sha2-512", 1);
	signature_benchmark("ECDSA-256", کلید_ECDSA, 256, پوچ, 1);
	signature_benchmark("ECDSA-384", کلید_ECDSA, 384, پوچ, 1);
	signature_benchmark("ECDSA-521", کلید_ECDSA, 521, پوچ, 1);
#endif /* WITH_OPENSSL */
	signature_benchmark("ED25519", کلید_ED25519, 0, پوچ, 1);
	signature_benchmark("MLDSA44-ED25519", کلید_MLDSA44_ED25519, 0, پوچ, 1);
}
