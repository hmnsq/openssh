/* 	$OpenBSD: test_sshkey.c,v 1.34 2026/06/14 04:08:06 djm Exp $ */
/*
 * Regress test for sshkey.h key management API
 *
 * Placed in the public domain
 */

#समावेश "includes.h"

#समावेश <sys/types.h>
#समावेश <stdio.h>
#समावेश <stdint.h>
#समावेश <stdlib.h>
#समावेश <string.h>

#अगर_घोषित WITH_OPENSSL
#समावेश <openssl/bn.h>
#समावेश <openssl/ec.h>
#समावेश <openssl/rsa.h>
#पूर्ण_अगर

#समावेश "../test_helper/test_helper.h"

#समावेश "ssherr.h"
#समावेश "sshbuf.h"
#घोषणा SSHBUF_INTERNAL 1	/* access internals for testing */
#समावेश "sshkey.h"

#समावेश "authfile.h"
#समावेश "common.h"
#समावेश "ssh2.h"

व्योम sshkey_tests(व्योम);
व्योम sshkey_benchmarks(व्योम);

अटल व्योम
put_opt(काष्ठा sshbuf *b, स्थिर अक्षर *name, स्थिर अक्षर *मूल्य)
{
	काष्ठा sshbuf *sect;

	sect = sshbuf_new();
	ASSERT_PTR_NE(sect, शून्य);
	ASSERT_INT_EQ(sshbuf_put_cstring(b, name), 0);
	अगर (मूल्य != शून्य)
		ASSERT_INT_EQ(sshbuf_put_cstring(sect, मूल्य), 0);
	ASSERT_INT_EQ(sshbuf_put_stringb(b, sect), 0);
	sshbuf_free(sect);
}

#अगर_घोषित WITH_OPENSSL
अटल व्योम
build_cert(काष्ठा sshbuf *b, काष्ठा sshkey *k, स्थिर अक्षर *type,
    काष्ठा sshkey *sign_कुंजी, काष्ठा sshkey *ca_कुंजी,
    स्थिर अक्षर *sig_alg)
{
	काष्ठा sshbuf *ca_buf, *pk, *principals, *critopts, *exts;
	u_char *sigblob;
	माप_प्रकार siglen;

	ca_buf = sshbuf_new();
	ASSERT_PTR_NE(ca_buf, शून्य);
	ASSERT_INT_EQ(sshkey_putb(ca_कुंजी, ca_buf), 0);

	/*
	 * Get the public key serialisation by rendering the key and skipping
	 * the type string. This is a bit of a hack :/
	 */
	pk = sshbuf_new();
	ASSERT_PTR_NE(pk, शून्य);
	ASSERT_INT_EQ(sshkey_putb_plain(k, pk), 0);
	ASSERT_INT_EQ(sshbuf_skip_string(pk), 0);

	principals = sshbuf_new();
	ASSERT_PTR_NE(principals, शून्य);
	ASSERT_INT_EQ(sshbuf_put_cstring(principals, "gsamsa"), 0);
	ASSERT_INT_EQ(sshbuf_put_cstring(principals, "gregor"), 0);

	critopts = sshbuf_new();
	ASSERT_PTR_NE(critopts, शून्य);
	put_opt(critopts, "force-command", "/usr/local/bin/nethack");
	put_opt(critopts, "source-address", "192.168.0.0/24,127.0.0.1,::1");

	exts = sshbuf_new();
	ASSERT_PTR_NE(exts, शून्य);
	put_opt(critopts, "permit-X11-forwarding", शून्य);

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
	ASSERT_INT_EQ(sshbuf_put_string(b, शून्य, 0), 0); /* reserved */
	ASSERT_INT_EQ(sshbuf_put_stringb(b, ca_buf), 0); /* signature key */
	ASSERT_INT_EQ(sshkey_sign(sign_कुंजी, &sigblob, &siglen,
	    sshbuf_ptr(b), sshbuf_len(b), sig_alg, शून्य, शून्य, 0), 0);
	ASSERT_INT_EQ(sshbuf_put_string(b, sigblob, siglen), 0); /* signature */

	मुक्त(sigblob);
	sshbuf_free(ca_buf);
	sshbuf_free(exts);
	sshbuf_free(critopts);
	sshbuf_free(principals);
	sshbuf_free(pk);
}
#पूर्ण_अगर /* WITH_OPENSSL */

अटल व्योम
signature_test(काष्ठा sshkey *k, काष्ठा sshkey *bad, स्थिर अक्षर *sig_alg,
    स्थिर u_char *d, माप_प्रकार l)
{
	माप_प्रकार len;
	u_char *sig;

	ASSERT_INT_EQ(sshkey_sign(k, &sig, &len, d, l, sig_alg,
	    शून्य, शून्य, 0), 0);
	ASSERT_आकार_T_GT(len, 8);
	ASSERT_PTR_NE(sig, शून्य);
	ASSERT_INT_EQ(sshkey_verify(k, sig, len, d, l, शून्य, 0, शून्य), 0);
	ASSERT_INT_NE(sshkey_verify(bad, sig, len, d, l, शून्य, 0, शून्य), 0);
	/* Fuzz test is more comprehensive, this is just a smoke test */
	sig[len - 5] ^= 0x10;
	ASSERT_INT_NE(sshkey_verify(k, sig, len, d, l, शून्य, 0, शून्य), 0);
	मुक्त(sig);
}

अटल व्योम
signature_bench(स्थिर अक्षर *name, पूर्णांक ktype, पूर्णांक bits, स्थिर अक्षर *sig_alg,
    स्थिर u_char *d, माप_प्रकार l)
{
	काष्ठा sshkey *k;
	माप_प्रकार len;
	u_char *sig;
	अक्षर testname[256];

	snprintf(testname, माप(testname), "sign %s", name);
	TEST_START(testname);
	ASSERT_INT_EQ(sshkey_generate(ktype, bits, &k), 0);
	ASSERT_PTR_NE(k, शून्य);

	BENCH_START(testname);
	ASSERT_INT_EQ(sshkey_sign(k, &sig, &len, d, l, sig_alg,
	    शून्य, शून्य, 0), 0);
	मुक्त(sig);
	BENCH_FINISH("sign");

	sshkey_free(k);
	TEST_DONE();
}

अटल व्योम
verify_bench(स्थिर अक्षर *name, पूर्णांक ktype, पूर्णांक bits, स्थिर अक्षर *sig_alg,
    स्थिर u_char *d, माप_प्रकार l)
{
	काष्ठा sshkey *k;
	माप_प्रकार len;
	u_char *sig;
	अक्षर testname[256];

	snprintf(testname, माप(testname), "verify %s", name);
	TEST_START(testname);
	ASSERT_INT_EQ(sshkey_generate(ktype, bits, &k), 0);
	ASSERT_PTR_NE(k, शून्य);

	ASSERT_INT_EQ(sshkey_sign(k, &sig, &len, d, l, sig_alg,
	    शून्य, शून्य, 0), 0);
	BENCH_START(testname);
	ASSERT_INT_EQ(sshkey_verify(k, sig, len, d, l, शून्य, 0, शून्य), 0);
	BENCH_FINISH("verify");

	मुक्त(sig);
	sshkey_free(k);
	TEST_DONE();
}

अटल व्योम
banana(u_char *s, माप_प्रकार l)
{
	माप_प्रकार o;
	स्थिर u_char the_banana[] = { 'b', 'a', 'n', 'a', 'n', 'a' };

	क्रम (o = 0; o < l; o += माप(the_banana)) {
		अगर (l - o < माप(the_banana)) {
			स_नकल(s + o, "nanananana", l - o);
			अवरोध;
		}
		स_नकल(s + o, the_banana, माप(the_banana));
	}
}

अटल व्योम
signature_tests(काष्ठा sshkey *k, काष्ठा sshkey *bad, स्थिर अक्षर *sig_alg)
{
	u_char i, buf[2049];
	माप_प्रकार lens[] = {
		1, 2, 7, 8, 9, 15, 16, 17, 31, 32, 33, 127, 128, 129,
		255, 256, 257, 1023, 1024, 1025, 2047, 2048, 2049
	};

	क्रम (i = 0; i < (माप(lens)/माप(lens[0])); i++) {
		test_subtest_info("%s key, banana length %zu",
		    sshkey_type(k), lens[i]);
		banana(buf, lens[i]);
		signature_test(k, bad, sig_alg, buf, lens[i]);
	}
}

अटल व्योम
signature_benchmark(स्थिर अक्षर *name, पूर्णांक ktype, पूर्णांक bits,
    स्थिर अक्षर *sig_alg, पूर्णांक bench_verify)
{
	u_char buf[256];

	banana(buf, माप(buf));
	अगर (bench_verify)
		verify_bench(name, ktype, bits, sig_alg, buf, माप(buf));
	अन्यथा
		signature_bench(name, ktype, bits, sig_alg, buf, माप(buf));
}

अटल काष्ठा sshkey *
get_private(स्थिर अक्षर *n)
{
	काष्ठा sshbuf *b;
	काष्ठा sshkey *ret;

	b = load_file(n);
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(b, "", &ret, शून्य), 0);
	sshbuf_free(b);
	वापस ret;
}

व्योम
sshkey_tests(व्योम)
{
	काष्ठा sshkey *k1 = शून्य, *k2 = शून्य, *k3 = शून्य, *k4 = शून्य;
	काष्ठा sshkey *kr = शून्य, *kd = शून्य, *ke = शून्य, *kf = शून्य;
	काष्ठा sshbuf *b = शून्य;

	TEST_START("new invalid");
	k1 = sshkey_new(-42);
	ASSERT_PTR_EQ(k1, शून्य);
	TEST_DONE();

	TEST_START("new/free KEY_UNSPEC");
	k1 = sshkey_new(कुंजी_UNSPEC);
	ASSERT_PTR_NE(k1, शून्य);
	sshkey_free(k1);
	k1 = शून्य;
	TEST_DONE();

#अगर_घोषित WITH_OPENSSL
	TEST_START("new/free KEY_RSA");
	k1 = sshkey_new(कुंजी_RSA);
	ASSERT_PTR_NE(k1, शून्य);
	ASSERT_PTR_NE(k1->pkey, शून्य);
	sshkey_free(k1);
	k1 = शून्य;
	TEST_DONE();

	TEST_START("new/free KEY_ECDSA");
	k1 = sshkey_new(कुंजी_ECDSA);
	ASSERT_PTR_NE(k1, शून्य);
	ASSERT_PTR_EQ(k1->pkey, शून्य);  /* Can't allocate without NID */
	sshkey_free(k1);
	k1 = शून्य;
	TEST_DONE();
#पूर्ण_अगर /* WITH_OPENSSL */

	TEST_START("new/free KEY_ED25519");
	k1 = sshkey_new(कुंजी_ED25519);
	ASSERT_PTR_NE(k1, शून्य);
	/* These should be blank until key loaded or generated */
	ASSERT_PTR_EQ(k1->ed25519_sk, शून्य);
	ASSERT_PTR_EQ(k1->ed25519_pk, शून्य);
	sshkey_free(k1);
	k1 = शून्य;
	TEST_DONE();

	TEST_START("new/free KEY_MLDSA44_ED25519");
	k1 = sshkey_new(कुंजी_MLDSA44_ED25519);
	ASSERT_PTR_NE(k1, शून्य);
	ASSERT_PTR_EQ(k1->mldsa_ed25519_sk, शून्य);
	ASSERT_PTR_EQ(k1->mldsa_ed25519_pk, शून्य);
	sshkey_free(k1);
	k1 = शून्य;
	TEST_DONE();

#अगर_घोषित WITH_OPENSSL
	TEST_START("generate KEY_RSA too small modulus");
	ASSERT_INT_EQ(sshkey_generate(कुंजी_RSA, 128, &k1),
	    SSH_ERR_कुंजी_लंबाई);
	ASSERT_PTR_EQ(k1, शून्य);
	TEST_DONE();

	TEST_START("generate KEY_RSA too large modulus");
	ASSERT_INT_EQ(sshkey_generate(कुंजी_RSA, 1 << 20, &k1),
	    SSH_ERR_कुंजी_लंबाई);
	ASSERT_PTR_EQ(k1, शून्य);
	TEST_DONE();


	TEST_START("generate KEY_ECDSA wrong bits");
	ASSERT_INT_EQ(sshkey_generate(कुंजी_ECDSA, 42, &k1),
	    SSH_ERR_कुंजी_लंबाई);
	ASSERT_PTR_EQ(k1, शून्य);
	sshkey_free(k1);
	k1 = शून्य;
	TEST_DONE();

	TEST_START("generate KEY_RSA");
	ASSERT_INT_EQ(sshkey_generate(कुंजी_RSA, 767, &kr),
	    SSH_ERR_कुंजी_लंबाई);
	ASSERT_INT_EQ(sshkey_generate(कुंजी_RSA, 1024, &kr), 0);
	ASSERT_PTR_NE(kr, शून्य);
	ASSERT_PTR_NE(EVP_PKEY_get0_RSA(kr->pkey), शून्य);
	ASSERT_PTR_NE(rsa_n(kr), शून्य);
	ASSERT_PTR_NE(rsa_e(kr), शून्य);
	ASSERT_PTR_NE(rsa_p(kr), शून्य);
	ASSERT_INT_EQ(BN_अंक_bits(rsa_n(kr)), 1024);
	TEST_DONE();


	TEST_START("generate KEY_ECDSA");
	ASSERT_INT_EQ(sshkey_generate(कुंजी_ECDSA, 256, &ke), 0);
	ASSERT_PTR_NE(ke, शून्य);
	ASSERT_PTR_NE(EVP_PKEY_get0_EC_कुंजी(ke->pkey), शून्य);
	ASSERT_PTR_NE(EC_कुंजी_get0_public_कुंजी(EVP_PKEY_get0_EC_कुंजी(ke->pkey)),
	    शून्य);
	ASSERT_PTR_NE(EC_कुंजी_get0_private_कुंजी(EVP_PKEY_get0_EC_कुंजी(ke->pkey)),
	    शून्य);
	TEST_DONE();
#पूर्ण_अगर /* WITH_OPENSSL */

	TEST_START("generate KEY_ED25519");
	ASSERT_INT_EQ(sshkey_generate(कुंजी_ED25519, 256, &kf), 0);
	ASSERT_PTR_NE(kf, शून्य);
	ASSERT_INT_EQ(kf->type, कुंजी_ED25519);
	ASSERT_PTR_NE(kf->ed25519_pk, शून्य);
	ASSERT_PTR_NE(kf->ed25519_sk, शून्य);
	TEST_DONE();

	TEST_START("generate KEY_MLDSA44_ED25519");
	ASSERT_INT_EQ(sshkey_generate(कुंजी_MLDSA44_ED25519, 256, &k1), 0);
	ASSERT_PTR_NE(k1, शून्य);
	ASSERT_INT_EQ(k1->type, कुंजी_MLDSA44_ED25519);
	ASSERT_PTR_NE(k1->mldsa_ed25519_pk, शून्य);
	ASSERT_PTR_NE(k1->mldsa_ed25519_sk, शून्य);
	sshkey_free(k1);
	k1 = शून्य;
	TEST_DONE();

#अगर_घोषित WITH_OPENSSL
	TEST_START("demote KEY_RSA");
	ASSERT_INT_EQ(sshkey_from_private(kr, &k1), 0);
	ASSERT_PTR_NE(k1, शून्य);
	ASSERT_PTR_NE(kr, k1);
	ASSERT_INT_EQ(k1->type, कुंजी_RSA);
	ASSERT_PTR_NE(EVP_PKEY_get0_RSA(k1->pkey), शून्य);
	ASSERT_PTR_NE(rsa_n(k1), शून्य);
	ASSERT_PTR_NE(rsa_e(k1), शून्य);
	ASSERT_PTR_EQ(rsa_p(k1), शून्य);
	TEST_DONE();

	TEST_START("equal KEY_RSA/demoted KEY_RSA");
	ASSERT_INT_EQ(sshkey_equal(kr, k1), 1);
	sshkey_free(k1);
	k1 = शून्य;
	TEST_DONE();


	TEST_START("demote KEY_ECDSA");
	ASSERT_INT_EQ(sshkey_from_private(ke, &k1), 0);
	ASSERT_PTR_NE(k1, शून्य);
	ASSERT_PTR_NE(ke, k1);
	ASSERT_INT_EQ(k1->type, कुंजी_ECDSA);
	ASSERT_PTR_NE(EVP_PKEY_get0_EC_कुंजी(k1->pkey), शून्य);
	ASSERT_INT_EQ(k1->ecdsa_nid, ke->ecdsa_nid);
	ASSERT_PTR_NE(EC_कुंजी_get0_public_कुंजी(EVP_PKEY_get0_EC_कुंजी(ke->pkey)),
	   शून्य);
	ASSERT_PTR_EQ(EC_कुंजी_get0_private_कुंजी(EVP_PKEY_get0_EC_कुंजी(k1->pkey)),
	   शून्य);
	TEST_DONE();

	TEST_START("equal KEY_ECDSA/demoted KEY_ECDSA");
	ASSERT_INT_EQ(sshkey_equal(ke, k1), 1);
	sshkey_free(k1);
	k1 = शून्य;
	TEST_DONE();
#पूर्ण_अगर /* WITH_OPENSSL */

	TEST_START("demote KEY_ED25519");
	ASSERT_INT_EQ(sshkey_from_private(kf, &k1), 0);
	ASSERT_PTR_NE(k1, शून्य);
	ASSERT_PTR_NE(kf, k1);
	ASSERT_INT_EQ(k1->type, कुंजी_ED25519);
	ASSERT_PTR_NE(k1->ed25519_pk, शून्य);
	ASSERT_PTR_EQ(k1->ed25519_sk, शून्य);
	TEST_DONE();

	TEST_START("equal KEY_ED25519/demoted KEY_ED25519");
	ASSERT_INT_EQ(sshkey_equal(kf, k1), 1);
	sshkey_free(k1);
	k1 = शून्य;
	TEST_DONE();

	TEST_START("demote KEY_MLDSA44_ED25519");
	ASSERT_INT_EQ(sshkey_generate(कुंजी_MLDSA44_ED25519, 256, &k2), 0);
	ASSERT_INT_EQ(sshkey_from_private(k2, &k1), 0);
	ASSERT_PTR_NE(k1, शून्य);
	ASSERT_PTR_NE(k2, k1);
	ASSERT_INT_EQ(k1->type, कुंजी_MLDSA44_ED25519);
	ASSERT_PTR_NE(k1->mldsa_ed25519_pk, शून्य);
	ASSERT_PTR_EQ(k1->mldsa_ed25519_sk, शून्य);
	TEST_DONE();

	TEST_START("equal KEY_MLDSA44_ED25519/demoted KEY_MLDSA44_ED25519");
	ASSERT_INT_EQ(sshkey_equal(k2, k1), 1);
	sshkey_free(k1);
	sshkey_free(k2);
	k1 = k2 = शून्य;
	TEST_DONE();

#अगर_घोषित WITH_OPENSSL
	TEST_START("equal mismatched key types");
	ASSERT_INT_EQ(sshkey_equal(kd, kr), 0);
	ASSERT_INT_EQ(sshkey_equal(kd, ke), 0);
	ASSERT_INT_EQ(sshkey_equal(kr, ke), 0);
	ASSERT_INT_EQ(sshkey_equal(ke, kf), 0);
	ASSERT_INT_EQ(sshkey_equal(kd, kf), 0);
	TEST_DONE();

	TEST_START("equal different keys");
	ASSERT_INT_EQ(sshkey_generate(कुंजी_RSA, 1024, &k1), 0);
	ASSERT_INT_EQ(sshkey_equal(kr, k1), 0);
	sshkey_free(k1);
	k1 = शून्य;
	ASSERT_INT_EQ(sshkey_generate(कुंजी_ECDSA, 256, &k1), 0);
	ASSERT_INT_EQ(sshkey_equal(ke, k1), 0);
	sshkey_free(k1);
	k1 = शून्य;
	ASSERT_INT_EQ(sshkey_generate(कुंजी_ED25519, 256, &k1), 0);
	ASSERT_INT_EQ(sshkey_equal(kf, k1), 0);
	sshkey_free(k1);
	k1 = शून्य;
	ASSERT_INT_EQ(sshkey_generate(कुंजी_MLDSA44_ED25519, 256, &k1), 0);
	ASSERT_INT_EQ(sshkey_generate(कुंजी_MLDSA44_ED25519, 256, &k2), 0);
	ASSERT_INT_EQ(sshkey_equal(k2, k1), 0);
	sshkey_free(k1);
	sshkey_free(k2);
	k1 = k2 = शून्य;
	TEST_DONE();
#पूर्ण_अगर /* WITH_OPENSSL */

	sshkey_free(kr);
	sshkey_free(kd);
	sshkey_free(ke);
	sshkey_free(kf);
	kr = kd = ke = kf = शून्य;

	TEST_START("certify key");
	ASSERT_INT_EQ(sshkey_load_public(test_तथ्य_file("ed25519_1.pub"),
	    &k1, शून्य), 0);
	k2 = get_private("ed25519_2");
	ASSERT_INT_EQ(sshkey_to_certified(k1), 0);
	ASSERT_PTR_NE(k1->cert, शून्य);
	k1->cert->type = SSH2_CERT_TYPE_USER;
	k1->cert->serial = 1234;
	k1->cert->कुंजी_id = strdup("estragon");
	ASSERT_PTR_NE(k1->cert->कुंजी_id, शून्य);
	k1->cert->principals = सुस्मृति(4, माप(*k1->cert->principals));
	ASSERT_PTR_NE(k1->cert->principals, शून्य);
	k1->cert->principals[0] = strdup("estragon");
	k1->cert->principals[1] = strdup("vladimir");
	k1->cert->principals[2] = strdup("pozzo");
	k1->cert->principals[3] = strdup("lucky");
	ASSERT_PTR_NE(k1->cert->principals[0], शून्य);
	ASSERT_PTR_NE(k1->cert->principals[1], शून्य);
	ASSERT_PTR_NE(k1->cert->principals[2], शून्य);
	ASSERT_PTR_NE(k1->cert->principals[3], शून्य);
	k1->cert->nprincipals = 4;
	k1->cert->valid_after = 0;
	k1->cert->valid_before = (uint64_t)-1;
	sshbuf_free(k1->cert->critical);
	k1->cert->critical = sshbuf_new();
	ASSERT_PTR_NE(k1->cert->critical, शून्य);
	sshbuf_free(k1->cert->extensions);
	k1->cert->extensions = sshbuf_new();
	ASSERT_PTR_NE(k1->cert->extensions, शून्य);
	put_opt(k1->cert->critical, "force-command", "/usr/bin/true");
	put_opt(k1->cert->critical, "source-address", "127.0.0.1");
	put_opt(k1->cert->extensions, "permit-X11-forwarding", शून्य);
	put_opt(k1->cert->extensions, "permit-agent-forwarding", शून्य);
	ASSERT_INT_EQ(sshkey_from_private(k2, &k1->cert->signature_कुंजी), 0);
	ASSERT_INT_EQ(sshkey_certify(k1, k2, शून्य, शून्य, शून्य), 0);
	b = sshbuf_new();
	ASSERT_PTR_NE(b, शून्य);
	ASSERT_INT_EQ(sshkey_putb(k1, b), 0);
	ASSERT_INT_EQ(sshkey_from_blob(sshbuf_ptr(b), sshbuf_len(b), &k3), 0);

	sshkey_free(k1);
	sshkey_free(k2);
	sshkey_free(k3);
	k1 = k2 = k3 = शून्य;
	sshbuf_reset(b);
	TEST_DONE();

	TEST_START("certify key MLDSA44-ED25519");
	ASSERT_INT_EQ(sshkey_load_public(
	    test_तथ्य_file("mldsa44_ed25519_1.pub"), &k1, शून्य), 0);
	k2 = get_private("mldsa44_ed25519_2");
	ASSERT_INT_EQ(sshkey_to_certified(k1), 0);
	ASSERT_PTR_NE(k1->cert, शून्य);
	k1->cert->type = SSH2_CERT_TYPE_USER;
	k1->cert->serial = 1234;
	k1->cert->कुंजी_id = strdup("estragon");
	ASSERT_PTR_NE(k1->cert->कुंजी_id, शून्य);
	k1->cert->principals = सुस्मृति(4, माप(*k1->cert->principals));
	ASSERT_PTR_NE(k1->cert->principals, शून्य);
	k1->cert->principals[0] = strdup("estragon");
	k1->cert->principals[1] = strdup("vladimir");
	k1->cert->principals[2] = strdup("pozzo");
	k1->cert->principals[3] = strdup("lucky");
	ASSERT_PTR_NE(k1->cert->principals[0], शून्य);
	ASSERT_PTR_NE(k1->cert->principals[1], शून्य);
	ASSERT_PTR_NE(k1->cert->principals[2], शून्य);
	ASSERT_PTR_NE(k1->cert->principals[3], शून्य);
	k1->cert->nprincipals = 4;
	k1->cert->valid_after = 0;
	k1->cert->valid_before = (uint64_t)-1;
	sshbuf_free(k1->cert->critical);
	k1->cert->critical = sshbuf_new();
	ASSERT_PTR_NE(k1->cert->critical, शून्य);
	sshbuf_free(k1->cert->extensions);
	k1->cert->extensions = sshbuf_new();
	ASSERT_PTR_NE(k1->cert->extensions, शून्य);
	put_opt(k1->cert->critical, "force-command", "/usr/bin/true");
	put_opt(k1->cert->critical, "source-address", "127.0.0.1");
	put_opt(k1->cert->extensions, "permit-X11-forwarding", शून्य);
	put_opt(k1->cert->extensions, "permit-agent-forwarding", शून्य);
	ASSERT_INT_EQ(sshkey_from_private(k2, &k1->cert->signature_कुंजी), 0);
	ASSERT_INT_EQ(sshkey_certify(k1, k2, शून्य, शून्य, शून्य), 0);
	b = sshbuf_new();
	ASSERT_PTR_NE(b, शून्य);
	ASSERT_INT_EQ(sshkey_putb(k1, b), 0);
	ASSERT_INT_EQ(sshkey_from_blob(sshbuf_ptr(b), sshbuf_len(b), &k3), 0);
	sshkey_free(k1);
	sshkey_free(k2);
	sshkey_free(k3);
	k1 = k2 = k3 = शून्य;
	sshbuf_reset(b);
	TEST_DONE();

#अगर_घोषित WITH_OPENSSL
	TEST_START("sign and verify RSA");
	k1 = get_private("rsa_1");
	ASSERT_INT_EQ(sshkey_load_public(test_तथ्य_file("rsa_2.pub"), &k2,
	    शून्य), 0);
	signature_tests(k1, k2, "ssh-rsa");
	sshkey_free(k1);
	sshkey_free(k2);
	k1 = k2 = शून्य;
	TEST_DONE();

	TEST_START("sign and verify RSA-SHA256");
	k1 = get_private("rsa_1");
	ASSERT_INT_EQ(sshkey_load_public(test_तथ्य_file("rsa_2.pub"), &k2,
	    शून्य), 0);
	signature_tests(k1, k2, "rsa-sha2-256");
	sshkey_free(k1);
	sshkey_free(k2);
	k1 = k2 = शून्य;
	TEST_DONE();

	TEST_START("sign and verify RSA-SHA512");
	k1 = get_private("rsa_1");
	ASSERT_INT_EQ(sshkey_load_public(test_तथ्य_file("rsa_2.pub"), &k2,
	    शून्य), 0);
	signature_tests(k1, k2, "rsa-sha2-512");
	sshkey_free(k1);
	sshkey_free(k2);
	k1 = k2 = शून्य;
	TEST_DONE();


	TEST_START("sign and verify ECDSA");
	k1 = get_private("ecdsa_1");
	ASSERT_INT_EQ(sshkey_load_public(test_तथ्य_file("ecdsa_2.pub"), &k2,
	    शून्य), 0);
	signature_tests(k1, k2, शून्य);
	sshkey_free(k1);
	sshkey_free(k2);
	k1 = k2 = शून्य;
	TEST_DONE();
#पूर्ण_अगर /* WITH_OPENSSL */

	TEST_START("sign and verify ED25519");
	k1 = get_private("ed25519_1");
	ASSERT_INT_EQ(sshkey_load_public(test_तथ्य_file("ed25519_2.pub"), &k2,
	    शून्य), 0);
	signature_tests(k1, k2, शून्य);
	sshkey_free(k1);
	sshkey_free(k2);
	k1 = k2 = शून्य;
	TEST_DONE();

	TEST_START("sign and verify MLDSA44-ED25519");
	k1 = get_private("mldsa44_ed25519_1");
	ASSERT_INT_EQ(sshkey_load_public(
	    test_तथ्य_file("mldsa44_ed25519_2.pub"), &k2, शून्य), 0);
	signature_tests(k1, k2, शून्य);
	sshkey_free(k1);
	sshkey_free(k2);
	k1 = k2 = शून्य;
	TEST_DONE();

#अगर_घोषित WITH_OPENSSL
	TEST_START("nested certificate");
	ASSERT_INT_EQ(sshkey_load_cert(test_तथ्य_file("rsa_1"), &k1), 0);
	ASSERT_INT_EQ(sshkey_load_public(test_तथ्य_file("rsa_1.pub"), &k2,
	    शून्य), 0);
	k3 = get_private("rsa_1");
	build_cert(b, k2, "ssh-rsa-cert-v01@openssh.com", k3, k1, शून्य);
	ASSERT_INT_EQ(sshkey_from_blob(sshbuf_ptr(b), sshbuf_len(b), &k4),
	    SSH_ERR_कुंजी_CERT_INVALID_SIGN_कुंजी);
	ASSERT_PTR_EQ(k4, शून्य);
	sshkey_free(k1);
	sshkey_free(k2);
	sshkey_free(k3);
	k1 = k2 = k3 = शून्य;
	sshbuf_free(b);
	TEST_DONE();
#पूर्ण_अगर /* WITH_OPENSSL */
}

व्योम
sshkey_benchmarks(व्योम)
{
	काष्ठा sshkey *k = शून्य;

#अगर_घोषित WITH_OPENSSL
	BENCH_START("generate RSA-1024");
	TEST_START("generate KEY_RSA");
	ASSERT_INT_EQ(sshkey_generate(कुंजी_RSA, 1024, &k), 0);
	ASSERT_PTR_NE(k, शून्य);
	sshkey_free(k);
	k = शून्य;
	TEST_DONE();
	BENCH_FINISH("keys");

	BENCH_START("generate RSA-2048");
	TEST_START("generate KEY_RSA");
	ASSERT_INT_EQ(sshkey_generate(कुंजी_RSA, 2048, &k), 0);
	ASSERT_PTR_NE(k, शून्य);
	sshkey_free(k);
	k = शून्य;
	TEST_DONE();
	BENCH_FINISH("keys");

	BENCH_START("generate ECDSA-256");
	TEST_START("generate KEY_ECDSA");
	ASSERT_INT_EQ(sshkey_generate(कुंजी_ECDSA, 256, &k), 0);
	ASSERT_PTR_NE(k, शून्य);
	sshkey_free(k);
	k = शून्य;
	TEST_DONE();
	BENCH_FINISH("keys");

	BENCH_START("generate ECDSA-384");
	TEST_START("generate KEY_ECDSA");
	ASSERT_INT_EQ(sshkey_generate(कुंजी_ECDSA, 384, &k), 0);
	ASSERT_PTR_NE(k, शून्य);
	sshkey_free(k);
	k = शून्य;
	TEST_DONE();
	BENCH_FINISH("keys");

	BENCH_START("generate ECDSA-521");
	TEST_START("generate KEY_ECDSA");
	ASSERT_INT_EQ(sshkey_generate(कुंजी_ECDSA, 521, &k), 0);
	ASSERT_PTR_NE(k, शून्य);
	sshkey_free(k);
	k = शून्य;
	TEST_DONE();
	BENCH_FINISH("keys");
#पूर्ण_अगर /* WITH_OPENSSL */

	BENCH_START("generate ED25519");
	TEST_START("generate KEY_ED25519");
	ASSERT_INT_EQ(sshkey_generate(कुंजी_ED25519, 256, &k), 0);
	ASSERT_PTR_NE(k, शून्य);
	sshkey_free(k);
	k = शून्य;
	TEST_DONE();
	BENCH_FINISH("keys");

	BENCH_START("generate MLDSA44-ED25519");
	TEST_START("generate KEY_MLDSA44_ED25519");
	ASSERT_INT_EQ(sshkey_generate(कुंजी_MLDSA44_ED25519, 256, &k), 0);
	ASSERT_PTR_NE(k, शून्य);
	sshkey_free(k);
	k = शून्य;
	TEST_DONE();
	BENCH_FINISH("keys");

#अगर_घोषित WITH_OPENSSL
	/* sign */
	signature_benchmark("RSA-1024/SHA1", कुंजी_RSA, 1024, "ssh-rsa", 0);
	signature_benchmark("RSA-1024/SHA256", कुंजी_RSA, 1024, "rsa-sha2-256", 0);
	signature_benchmark("RSA-1024/SHA512", कुंजी_RSA, 1024, "rsa-sha2-512", 0);
	signature_benchmark("RSA-2048/SHA1", कुंजी_RSA, 2048, "ssh-rsa", 0);
	signature_benchmark("RSA-2048/SHA256", कुंजी_RSA, 2048, "rsa-sha2-256", 0);
	signature_benchmark("RSA-2048/SHA512", कुंजी_RSA, 2048, "rsa-sha2-512", 0);
	signature_benchmark("ECDSA-256", कुंजी_ECDSA, 256, शून्य, 0);
	signature_benchmark("ECDSA-384", कुंजी_ECDSA, 384, शून्य, 0);
	signature_benchmark("ECDSA-521", कुंजी_ECDSA, 521, शून्य, 0);
	signature_benchmark("ED25519", कुंजी_ED25519, 0, शून्य, 0);
	signature_benchmark("MLDSA44-ED25519", कुंजी_MLDSA44_ED25519, 0, शून्य, 0);

	/* verify */
	signature_benchmark("RSA-1024/SHA1", कुंजी_RSA, 1024, "ssh-rsa", 1);
	signature_benchmark("RSA-1024/SHA256", कुंजी_RSA, 1024, "rsa-sha2-256", 1);
	signature_benchmark("RSA-1024/SHA512", कुंजी_RSA, 1024, "rsa-sha2-512", 1);
	signature_benchmark("RSA-2048/SHA1", कुंजी_RSA, 2048, "ssh-rsa", 1);
	signature_benchmark("RSA-2048/SHA256", कुंजी_RSA, 2048, "rsa-sha2-256", 1);
	signature_benchmark("RSA-2048/SHA512", कुंजी_RSA, 2048, "rsa-sha2-512", 1);
	signature_benchmark("ECDSA-256", कुंजी_ECDSA, 256, शून्य, 1);
	signature_benchmark("ECDSA-384", कुंजी_ECDSA, 384, शून्य, 1);
	signature_benchmark("ECDSA-521", कुंजी_ECDSA, 521, शून्य, 1);
#पूर्ण_अगर /* WITH_OPENSSL */
	signature_benchmark("ED25519", कुंजी_ED25519, 0, शून्य, 1);
	signature_benchmark("MLDSA44-ED25519", कुंजी_MLDSA44_ED25519, 0, शून्य, 1);
}
