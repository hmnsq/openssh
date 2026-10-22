/* 	$OpenBSD: test_sshkey.c,v 1.34 2026/06/14 04:08:06 djm Exp $ */
/*
 * Regress test for sshkey.h key management API
 *
 * Placed in the public domain
 */

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <stdint.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>

#ifdef WITH_OPENSSL
#अन्तर्भाव <openssl/bn.h>
#अन्तर्भाव <openssl/ec.h>
#अन्तर्भाव <openssl/rsa.h>
#endif

#अन्तर्भाव "../test_helper/test_helper.h"

#अन्तर्भाव "ssherr.h"
#अन्तर्भाव "sshbuf.h"
#define SSHBUF_INTERNAL 1	/* access internals for testing */
#अन्तर्भाव "sshkey.h"

#अन्तर्भाव "authfile.h"
#अन्तर्भाव "common.h"
#अन्तर्भाव "ssh2.h"

शून्य sshkey_tests(शून्य);
शून्य sshkey_benchmarks(शून्य);

स्थिर शून्य
put_opt(संरचना sshbuf *b, अचर वर्ण *name, अचर वर्ण *मान)
{
	संरचना sshbuf *sect;

	sect = sshbuf_new();
	ASSERT_PTR_NE(sect, रिक्त);
	ASSERT_INT_EQ(sshbuf_put_cstring(b, name), 0);
	यदि (मान != रिक्त)
		ASSERT_INT_EQ(sshbuf_put_cstring(sect, मान), 0);
	ASSERT_INT_EQ(sshbuf_put_stringb(b, sect), 0);
	sshbuf_free(sect);
}

#ifdef WITH_OPENSSL
स्थिर शून्य
build_cert(संरचना sshbuf *b, संरचना sshkey *k, अचर वर्ण *type,
    संरचना sshkey *sign_साँचो, संरचना sshkey *ca_साँचो,
    अचर वर्ण *sig_alg)
{
	संरचना sshbuf *ca_buf, *pk, *principals, *critopts, *exts;
	u_char *sigblob;
	माप_प्रकार siglen;

	ca_buf = sshbuf_new();
	ASSERT_PTR_NE(ca_buf, रिक्त);
	ASSERT_INT_EQ(sshkey_putb(ca_साँचो, ca_buf), 0);

	/*
	 * Get the public key serialisation by rendering the key and skipping
	 * the type string. This is a bit of a hack :/
	 */
	pk = sshbuf_new();
	ASSERT_PTR_NE(pk, रिक्त);
	ASSERT_INT_EQ(sshkey_putb_plain(k, pk), 0);
	ASSERT_INT_EQ(sshbuf_skip_string(pk), 0);

	principals = sshbuf_new();
	ASSERT_PTR_NE(principals, रिक्त);
	ASSERT_INT_EQ(sshbuf_put_cstring(principals, "gsamsa"), 0);
	ASSERT_INT_EQ(sshbuf_put_cstring(principals, "gregor"), 0);

	critopts = sshbuf_new();
	ASSERT_PTR_NE(critopts, रिक्त);
	put_opt(critopts, "force-command", "/usr/local/bin/nethack");
	put_opt(critopts, "source-address", "192.168.0.0/24,127.0.0.1,::1");

	exts = sshbuf_new();
	ASSERT_PTR_NE(exts, रिक्त);
	put_opt(critopts, "permit-X11-forwarding", रिक्त);

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
	ASSERT_INT_EQ(sshbuf_put_string(b, रिक्त, 0), 0); /* reserved */
	ASSERT_INT_EQ(sshbuf_put_stringb(b, ca_buf), 0); /* signature key */
	ASSERT_INT_EQ(sshkey_sign(sign_साँचो, &sigblob, &siglen,
	    sshbuf_ptr(b), sshbuf_len(b), sig_alg, रिक्त, रिक्त, 0), 0);
	ASSERT_INT_EQ(sshbuf_put_string(b, sigblob, siglen), 0); /* signature */

	मुक्त(sigblob);
	sshbuf_free(ca_buf);
	sshbuf_free(exts);
	sshbuf_free(critopts);
	sshbuf_free(principals);
	sshbuf_free(pk);
}
#endif /* WITH_OPENSSL */

स्थिर शून्य
signature_test(संरचना sshkey *k, संरचना sshkey *bad, अचर वर्ण *sig_alg,
    अचर u_char *d, माप_प्रकार l)
{
	माप_प्रकार len;
	u_char *sig;

	ASSERT_INT_EQ(sshkey_sign(k, &sig, &len, d, l, sig_alg,
	    रिक्त, रिक्त, 0), 0);
	ASSERT_SIZE_T_GT(len, 8);
	ASSERT_PTR_NE(sig, रिक्त);
	ASSERT_INT_EQ(sshkey_verify(k, sig, len, d, l, रिक्त, 0, रिक्त), 0);
	ASSERT_INT_NE(sshkey_verify(bad, sig, len, d, l, रिक्त, 0, रिक्त), 0);
	/* Fuzz test is more comprehensive, this is just a smoke test */
	sig[len - 5] ^= 0x10;
	ASSERT_INT_NE(sshkey_verify(k, sig, len, d, l, रिक्त, 0, रिक्त), 0);
	मुक्त(sig);
}

स्थिर शून्य
signature_bench(अचर वर्ण *name, पूर्णाङ्क ktype, पूर्णाङ्क bits, अचर वर्ण *sig_alg,
    अचर u_char *d, माप_प्रकार l)
{
	संरचना sshkey *k;
	माप_प्रकार len;
	u_char *sig;
	वर्ण testname[256];

	snprintf(testname, परिमाण(testname), "sign %s", name);
	TEST_START(testname);
	ASSERT_INT_EQ(sshkey_generate(ktype, bits, &k), 0);
	ASSERT_PTR_NE(k, रिक्त);

	BENCH_START(testname);
	ASSERT_INT_EQ(sshkey_sign(k, &sig, &len, d, l, sig_alg,
	    रिक्त, रिक्त, 0), 0);
	मुक्त(sig);
	BENCH_FINISH("sign");

	sshkey_free(k);
	TEST_DONE();
}

स्थिर शून्य
verify_bench(अचर वर्ण *name, पूर्णाङ्क ktype, पूर्णाङ्क bits, अचर वर्ण *sig_alg,
    अचर u_char *d, माप_प्रकार l)
{
	संरचना sshkey *k;
	माप_प्रकार len;
	u_char *sig;
	वर्ण testname[256];

	snprintf(testname, परिमाण(testname), "verify %s", name);
	TEST_START(testname);
	ASSERT_INT_EQ(sshkey_generate(ktype, bits, &k), 0);
	ASSERT_PTR_NE(k, रिक्त);

	ASSERT_INT_EQ(sshkey_sign(k, &sig, &len, d, l, sig_alg,
	    रिक्त, रिक्त, 0), 0);
	BENCH_START(testname);
	ASSERT_INT_EQ(sshkey_verify(k, sig, len, d, l, रिक्त, 0, रिक्त), 0);
	BENCH_FINISH("verify");

	मुक्त(sig);
	sshkey_free(k);
	TEST_DONE();
}

स्थिर शून्य
banana(u_char *s, माप_प्रकार l)
{
	माप_प्रकार o;
	अचर u_char the_banana[] = { 'b', 'a', 'n', 'a', 'n', 'a' };

	लागि (o = 0; o < l; o += परिमाण(the_banana)) {
		यदि (l - o < परिमाण(the_banana)) {
			स_नकल(s + o, "nanananana", l - o);
			रोक;
		}
		स_नकल(s + o, the_banana, परिमाण(the_banana));
	}
}

स्थिर शून्य
signature_tests(संरचना sshkey *k, संरचना sshkey *bad, अचर वर्ण *sig_alg)
{
	u_char i, buf[2049];
	माप_प्रकार lens[] = {
		1, 2, 7, 8, 9, 15, 16, 17, 31, 32, 33, 127, 128, 129,
		255, 256, 257, 1023, 1024, 1025, 2047, 2048, 2049
	};

	लागि (i = 0; i < (परिमाण(lens)/परिमाण(lens[0])); i++) {
		test_subtest_info("%s key, banana length %zu",
		    sshkey_type(k), lens[i]);
		banana(buf, lens[i]);
		signature_test(k, bad, sig_alg, buf, lens[i]);
	}
}

स्थिर शून्य
signature_benchmark(अचर वर्ण *name, पूर्णाङ्क ktype, पूर्णाङ्क bits,
    अचर वर्ण *sig_alg, पूर्णाङ्क bench_verify)
{
	u_char buf[256];

	banana(buf, परिमाण(buf));
	यदि (bench_verify)
		verify_bench(name, ktype, bits, sig_alg, buf, परिमाण(buf));
	अन्यथा
		signature_bench(name, ktype, bits, sig_alg, buf, परिमाण(buf));
}

स्थिर संरचना sshkey *
get_private(अचर वर्ण *n)
{
	संरचना sshbuf *b;
	संरचना sshkey *ret;

	b = load_file(n);
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(b, "", &ret, रिक्त), 0);
	sshbuf_free(b);
	फर्काऊ ret;
}

शून्य
sshkey_tests(शून्य)
{
	संरचना sshkey *k1 = रिक्त, *k2 = रिक्त, *k3 = रिक्त, *k4 = रिक्त;
	संरचना sshkey *kr = रिक्त, *kd = रिक्त, *ke = रिक्त, *kf = रिक्त;
	संरचना sshbuf *b = रिक्त;

	TEST_START("new invalid");
	k1 = sshkey_new(-42);
	ASSERT_PTR_EQ(k1, रिक्त);
	TEST_DONE();

	TEST_START("new/free KEY_UNSPEC");
	k1 = sshkey_new(साँचो_UNSPEC);
	ASSERT_PTR_NE(k1, रिक्त);
	sshkey_free(k1);
	k1 = रिक्त;
	TEST_DONE();

#ifdef WITH_OPENSSL
	TEST_START("new/free KEY_RSA");
	k1 = sshkey_new(साँचो_RSA);
	ASSERT_PTR_NE(k1, रिक्त);
	ASSERT_PTR_NE(k1->pkey, रिक्त);
	sshkey_free(k1);
	k1 = रिक्त;
	TEST_DONE();

	TEST_START("new/free KEY_ECDSA");
	k1 = sshkey_new(साँचो_ECDSA);
	ASSERT_PTR_NE(k1, रिक्त);
	ASSERT_PTR_EQ(k1->pkey, रिक्त);  /* Can't allocate without NID */
	sshkey_free(k1);
	k1 = रिक्त;
	TEST_DONE();
#endif /* WITH_OPENSSL */

	TEST_START("new/free KEY_ED25519");
	k1 = sshkey_new(साँचो_ED25519);
	ASSERT_PTR_NE(k1, रिक्त);
	/* These should be blank until key loaded or generated */
	ASSERT_PTR_EQ(k1->ed25519_sk, रिक्त);
	ASSERT_PTR_EQ(k1->ed25519_pk, रिक्त);
	sshkey_free(k1);
	k1 = रिक्त;
	TEST_DONE();

	TEST_START("new/free KEY_MLDSA44_ED25519");
	k1 = sshkey_new(साँचो_MLDSA44_ED25519);
	ASSERT_PTR_NE(k1, रिक्त);
	ASSERT_PTR_EQ(k1->mldsa_ed25519_sk, रिक्त);
	ASSERT_PTR_EQ(k1->mldsa_ed25519_pk, रिक्त);
	sshkey_free(k1);
	k1 = रिक्त;
	TEST_DONE();

#ifdef WITH_OPENSSL
	TEST_START("generate KEY_RSA too small modulus");
	ASSERT_INT_EQ(sshkey_generate(साँचो_RSA, 128, &k1),
	    SSH_ERR_साँचो_LENGTH);
	ASSERT_PTR_EQ(k1, रिक्त);
	TEST_DONE();

	TEST_START("generate KEY_RSA too large modulus");
	ASSERT_INT_EQ(sshkey_generate(साँचो_RSA, 1 << 20, &k1),
	    SSH_ERR_साँचो_LENGTH);
	ASSERT_PTR_EQ(k1, रिक्त);
	TEST_DONE();


	TEST_START("generate KEY_ECDSA wrong bits");
	ASSERT_INT_EQ(sshkey_generate(साँचो_ECDSA, 42, &k1),
	    SSH_ERR_साँचो_LENGTH);
	ASSERT_PTR_EQ(k1, रिक्त);
	sshkey_free(k1);
	k1 = रिक्त;
	TEST_DONE();

	TEST_START("generate KEY_RSA");
	ASSERT_INT_EQ(sshkey_generate(साँचो_RSA, 767, &kr),
	    SSH_ERR_साँचो_LENGTH);
	ASSERT_INT_EQ(sshkey_generate(साँचो_RSA, 1024, &kr), 0);
	ASSERT_PTR_NE(kr, रिक्त);
	ASSERT_PTR_NE(EVP_PKEY_get0_RSA(kr->pkey), रिक्त);
	ASSERT_PTR_NE(rsa_n(kr), रिक्त);
	ASSERT_PTR_NE(rsa_e(kr), रिक्त);
	ASSERT_PTR_NE(rsa_p(kr), रिक्त);
	ASSERT_INT_EQ(BN_अङ्क_bits(rsa_n(kr)), 1024);
	TEST_DONE();


	TEST_START("generate KEY_ECDSA");
	ASSERT_INT_EQ(sshkey_generate(साँचो_ECDSA, 256, &ke), 0);
	ASSERT_PTR_NE(ke, रिक्त);
	ASSERT_PTR_NE(EVP_PKEY_get0_EC_साँचो(ke->pkey), रिक्त);
	ASSERT_PTR_NE(EC_साँचो_get0_public_साँचो(EVP_PKEY_get0_EC_साँचो(ke->pkey)),
	    रिक्त);
	ASSERT_PTR_NE(EC_साँचो_get0_private_साँचो(EVP_PKEY_get0_EC_साँचो(ke->pkey)),
	    रिक्त);
	TEST_DONE();
#endif /* WITH_OPENSSL */

	TEST_START("generate KEY_ED25519");
	ASSERT_INT_EQ(sshkey_generate(साँचो_ED25519, 256, &kf), 0);
	ASSERT_PTR_NE(kf, रिक्त);
	ASSERT_INT_EQ(kf->type, साँचो_ED25519);
	ASSERT_PTR_NE(kf->ed25519_pk, रिक्त);
	ASSERT_PTR_NE(kf->ed25519_sk, रिक्त);
	TEST_DONE();

	TEST_START("generate KEY_MLDSA44_ED25519");
	ASSERT_INT_EQ(sshkey_generate(साँचो_MLDSA44_ED25519, 256, &k1), 0);
	ASSERT_PTR_NE(k1, रिक्त);
	ASSERT_INT_EQ(k1->type, साँचो_MLDSA44_ED25519);
	ASSERT_PTR_NE(k1->mldsa_ed25519_pk, रिक्त);
	ASSERT_PTR_NE(k1->mldsa_ed25519_sk, रिक्त);
	sshkey_free(k1);
	k1 = रिक्त;
	TEST_DONE();

#ifdef WITH_OPENSSL
	TEST_START("demote KEY_RSA");
	ASSERT_INT_EQ(sshkey_from_private(kr, &k1), 0);
	ASSERT_PTR_NE(k1, रिक्त);
	ASSERT_PTR_NE(kr, k1);
	ASSERT_INT_EQ(k1->type, साँचो_RSA);
	ASSERT_PTR_NE(EVP_PKEY_get0_RSA(k1->pkey), रिक्त);
	ASSERT_PTR_NE(rsa_n(k1), रिक्त);
	ASSERT_PTR_NE(rsa_e(k1), रिक्त);
	ASSERT_PTR_EQ(rsa_p(k1), रिक्त);
	TEST_DONE();

	TEST_START("equal KEY_RSA/demoted KEY_RSA");
	ASSERT_INT_EQ(sshkey_equal(kr, k1), 1);
	sshkey_free(k1);
	k1 = रिक्त;
	TEST_DONE();


	TEST_START("demote KEY_ECDSA");
	ASSERT_INT_EQ(sshkey_from_private(ke, &k1), 0);
	ASSERT_PTR_NE(k1, रिक्त);
	ASSERT_PTR_NE(ke, k1);
	ASSERT_INT_EQ(k1->type, साँचो_ECDSA);
	ASSERT_PTR_NE(EVP_PKEY_get0_EC_साँचो(k1->pkey), रिक्त);
	ASSERT_INT_EQ(k1->ecdsa_nid, ke->ecdsa_nid);
	ASSERT_PTR_NE(EC_साँचो_get0_public_साँचो(EVP_PKEY_get0_EC_साँचो(ke->pkey)),
	   रिक्त);
	ASSERT_PTR_EQ(EC_साँचो_get0_private_साँचो(EVP_PKEY_get0_EC_साँचो(k1->pkey)),
	   रिक्त);
	TEST_DONE();

	TEST_START("equal KEY_ECDSA/demoted KEY_ECDSA");
	ASSERT_INT_EQ(sshkey_equal(ke, k1), 1);
	sshkey_free(k1);
	k1 = रिक्त;
	TEST_DONE();
#endif /* WITH_OPENSSL */

	TEST_START("demote KEY_ED25519");
	ASSERT_INT_EQ(sshkey_from_private(kf, &k1), 0);
	ASSERT_PTR_NE(k1, रिक्त);
	ASSERT_PTR_NE(kf, k1);
	ASSERT_INT_EQ(k1->type, साँचो_ED25519);
	ASSERT_PTR_NE(k1->ed25519_pk, रिक्त);
	ASSERT_PTR_EQ(k1->ed25519_sk, रिक्त);
	TEST_DONE();

	TEST_START("equal KEY_ED25519/demoted KEY_ED25519");
	ASSERT_INT_EQ(sshkey_equal(kf, k1), 1);
	sshkey_free(k1);
	k1 = रिक्त;
	TEST_DONE();

	TEST_START("demote KEY_MLDSA44_ED25519");
	ASSERT_INT_EQ(sshkey_generate(साँचो_MLDSA44_ED25519, 256, &k2), 0);
	ASSERT_INT_EQ(sshkey_from_private(k2, &k1), 0);
	ASSERT_PTR_NE(k1, रिक्त);
	ASSERT_PTR_NE(k2, k1);
	ASSERT_INT_EQ(k1->type, साँचो_MLDSA44_ED25519);
	ASSERT_PTR_NE(k1->mldsa_ed25519_pk, रिक्त);
	ASSERT_PTR_EQ(k1->mldsa_ed25519_sk, रिक्त);
	TEST_DONE();

	TEST_START("equal KEY_MLDSA44_ED25519/demoted KEY_MLDSA44_ED25519");
	ASSERT_INT_EQ(sshkey_equal(k2, k1), 1);
	sshkey_free(k1);
	sshkey_free(k2);
	k1 = k2 = रिक्त;
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
	ASSERT_INT_EQ(sshkey_generate(साँचो_RSA, 1024, &k1), 0);
	ASSERT_INT_EQ(sshkey_equal(kr, k1), 0);
	sshkey_free(k1);
	k1 = रिक्त;
	ASSERT_INT_EQ(sshkey_generate(साँचो_ECDSA, 256, &k1), 0);
	ASSERT_INT_EQ(sshkey_equal(ke, k1), 0);
	sshkey_free(k1);
	k1 = रिक्त;
	ASSERT_INT_EQ(sshkey_generate(साँचो_ED25519, 256, &k1), 0);
	ASSERT_INT_EQ(sshkey_equal(kf, k1), 0);
	sshkey_free(k1);
	k1 = रिक्त;
	ASSERT_INT_EQ(sshkey_generate(साँचो_MLDSA44_ED25519, 256, &k1), 0);
	ASSERT_INT_EQ(sshkey_generate(साँचो_MLDSA44_ED25519, 256, &k2), 0);
	ASSERT_INT_EQ(sshkey_equal(k2, k1), 0);
	sshkey_free(k1);
	sshkey_free(k2);
	k1 = k2 = रिक्त;
	TEST_DONE();
#endif /* WITH_OPENSSL */

	sshkey_free(kr);
	sshkey_free(kd);
	sshkey_free(ke);
	sshkey_free(kf);
	kr = kd = ke = kf = रिक्त;

	TEST_START("certify key");
	ASSERT_INT_EQ(sshkey_load_public(test_data_file("ed25519_1.pub"),
	    &k1, रिक्त), 0);
	k2 = get_private("ed25519_2");
	ASSERT_INT_EQ(sshkey_to_certified(k1), 0);
	ASSERT_PTR_NE(k1->cert, रिक्त);
	k1->cert->type = SSH2_CERT_TYPE_USER;
	k1->cert->serial = 1234;
	k1->cert->साँचो_id = strdup("estragon");
	ASSERT_PTR_NE(k1->cert->साँचो_id, रिक्त);
	k1->cert->principals = सुस्मृति(4, परिमाण(*k1->cert->principals));
	ASSERT_PTR_NE(k1->cert->principals, रिक्त);
	k1->cert->principals[0] = strdup("estragon");
	k1->cert->principals[1] = strdup("vladimir");
	k1->cert->principals[2] = strdup("pozzo");
	k1->cert->principals[3] = strdup("lucky");
	ASSERT_PTR_NE(k1->cert->principals[0], रिक्त);
	ASSERT_PTR_NE(k1->cert->principals[1], रिक्त);
	ASSERT_PTR_NE(k1->cert->principals[2], रिक्त);
	ASSERT_PTR_NE(k1->cert->principals[3], रिक्त);
	k1->cert->nprincipals = 4;
	k1->cert->valid_after = 0;
	k1->cert->valid_before = (uint64_t)-1;
	sshbuf_free(k1->cert->critical);
	k1->cert->critical = sshbuf_new();
	ASSERT_PTR_NE(k1->cert->critical, रिक्त);
	sshbuf_free(k1->cert->extensions);
	k1->cert->extensions = sshbuf_new();
	ASSERT_PTR_NE(k1->cert->extensions, रिक्त);
	put_opt(k1->cert->critical, "force-command", "/usr/bin/true");
	put_opt(k1->cert->critical, "source-address", "127.0.0.1");
	put_opt(k1->cert->extensions, "permit-X11-forwarding", रिक्त);
	put_opt(k1->cert->extensions, "permit-agent-forwarding", रिक्त);
	ASSERT_INT_EQ(sshkey_from_private(k2, &k1->cert->signature_साँचो), 0);
	ASSERT_INT_EQ(sshkey_certify(k1, k2, रिक्त, रिक्त, रिक्त), 0);
	b = sshbuf_new();
	ASSERT_PTR_NE(b, रिक्त);
	ASSERT_INT_EQ(sshkey_putb(k1, b), 0);
	ASSERT_INT_EQ(sshkey_from_blob(sshbuf_ptr(b), sshbuf_len(b), &k3), 0);

	sshkey_free(k1);
	sshkey_free(k2);
	sshkey_free(k3);
	k1 = k2 = k3 = रिक्त;
	sshbuf_reset(b);
	TEST_DONE();

	TEST_START("certify key MLDSA44-ED25519");
	ASSERT_INT_EQ(sshkey_load_public(
	    test_data_file("mldsa44_ed25519_1.pub"), &k1, रिक्त), 0);
	k2 = get_private("mldsa44_ed25519_2");
	ASSERT_INT_EQ(sshkey_to_certified(k1), 0);
	ASSERT_PTR_NE(k1->cert, रिक्त);
	k1->cert->type = SSH2_CERT_TYPE_USER;
	k1->cert->serial = 1234;
	k1->cert->साँचो_id = strdup("estragon");
	ASSERT_PTR_NE(k1->cert->साँचो_id, रिक्त);
	k1->cert->principals = सुस्मृति(4, परिमाण(*k1->cert->principals));
	ASSERT_PTR_NE(k1->cert->principals, रिक्त);
	k1->cert->principals[0] = strdup("estragon");
	k1->cert->principals[1] = strdup("vladimir");
	k1->cert->principals[2] = strdup("pozzo");
	k1->cert->principals[3] = strdup("lucky");
	ASSERT_PTR_NE(k1->cert->principals[0], रिक्त);
	ASSERT_PTR_NE(k1->cert->principals[1], रिक्त);
	ASSERT_PTR_NE(k1->cert->principals[2], रिक्त);
	ASSERT_PTR_NE(k1->cert->principals[3], रिक्त);
	k1->cert->nprincipals = 4;
	k1->cert->valid_after = 0;
	k1->cert->valid_before = (uint64_t)-1;
	sshbuf_free(k1->cert->critical);
	k1->cert->critical = sshbuf_new();
	ASSERT_PTR_NE(k1->cert->critical, रिक्त);
	sshbuf_free(k1->cert->extensions);
	k1->cert->extensions = sshbuf_new();
	ASSERT_PTR_NE(k1->cert->extensions, रिक्त);
	put_opt(k1->cert->critical, "force-command", "/usr/bin/true");
	put_opt(k1->cert->critical, "source-address", "127.0.0.1");
	put_opt(k1->cert->extensions, "permit-X11-forwarding", रिक्त);
	put_opt(k1->cert->extensions, "permit-agent-forwarding", रिक्त);
	ASSERT_INT_EQ(sshkey_from_private(k2, &k1->cert->signature_साँचो), 0);
	ASSERT_INT_EQ(sshkey_certify(k1, k2, रिक्त, रिक्त, रिक्त), 0);
	b = sshbuf_new();
	ASSERT_PTR_NE(b, रिक्त);
	ASSERT_INT_EQ(sshkey_putb(k1, b), 0);
	ASSERT_INT_EQ(sshkey_from_blob(sshbuf_ptr(b), sshbuf_len(b), &k3), 0);
	sshkey_free(k1);
	sshkey_free(k2);
	sshkey_free(k3);
	k1 = k2 = k3 = रिक्त;
	sshbuf_reset(b);
	TEST_DONE();

#ifdef WITH_OPENSSL
	TEST_START("sign and verify RSA");
	k1 = get_private("rsa_1");
	ASSERT_INT_EQ(sshkey_load_public(test_data_file("rsa_2.pub"), &k2,
	    रिक्त), 0);
	signature_tests(k1, k2, "ssh-rsa");
	sshkey_free(k1);
	sshkey_free(k2);
	k1 = k2 = रिक्त;
	TEST_DONE();

	TEST_START("sign and verify RSA-SHA256");
	k1 = get_private("rsa_1");
	ASSERT_INT_EQ(sshkey_load_public(test_data_file("rsa_2.pub"), &k2,
	    रिक्त), 0);
	signature_tests(k1, k2, "rsa-sha2-256");
	sshkey_free(k1);
	sshkey_free(k2);
	k1 = k2 = रिक्त;
	TEST_DONE();

	TEST_START("sign and verify RSA-SHA512");
	k1 = get_private("rsa_1");
	ASSERT_INT_EQ(sshkey_load_public(test_data_file("rsa_2.pub"), &k2,
	    रिक्त), 0);
	signature_tests(k1, k2, "rsa-sha2-512");
	sshkey_free(k1);
	sshkey_free(k2);
	k1 = k2 = रिक्त;
	TEST_DONE();


	TEST_START("sign and verify ECDSA");
	k1 = get_private("ecdsa_1");
	ASSERT_INT_EQ(sshkey_load_public(test_data_file("ecdsa_2.pub"), &k2,
	    रिक्त), 0);
	signature_tests(k1, k2, रिक्त);
	sshkey_free(k1);
	sshkey_free(k2);
	k1 = k2 = रिक्त;
	TEST_DONE();
#endif /* WITH_OPENSSL */

	TEST_START("sign and verify ED25519");
	k1 = get_private("ed25519_1");
	ASSERT_INT_EQ(sshkey_load_public(test_data_file("ed25519_2.pub"), &k2,
	    रिक्त), 0);
	signature_tests(k1, k2, रिक्त);
	sshkey_free(k1);
	sshkey_free(k2);
	k1 = k2 = रिक्त;
	TEST_DONE();

	TEST_START("sign and verify MLDSA44-ED25519");
	k1 = get_private("mldsa44_ed25519_1");
	ASSERT_INT_EQ(sshkey_load_public(
	    test_data_file("mldsa44_ed25519_2.pub"), &k2, रिक्त), 0);
	signature_tests(k1, k2, रिक्त);
	sshkey_free(k1);
	sshkey_free(k2);
	k1 = k2 = रिक्त;
	TEST_DONE();

#ifdef WITH_OPENSSL
	TEST_START("nested certificate");
	ASSERT_INT_EQ(sshkey_load_cert(test_data_file("rsa_1"), &k1), 0);
	ASSERT_INT_EQ(sshkey_load_public(test_data_file("rsa_1.pub"), &k2,
	    रिक्त), 0);
	k3 = get_private("rsa_1");
	build_cert(b, k2, "ssh-rsa-cert-v01@openssh.com", k3, k1, रिक्त);
	ASSERT_INT_EQ(sshkey_from_blob(sshbuf_ptr(b), sshbuf_len(b), &k4),
	    SSH_ERR_साँचो_CERT_INVALID_SIGN_साँचो);
	ASSERT_PTR_EQ(k4, रिक्त);
	sshkey_free(k1);
	sshkey_free(k2);
	sshkey_free(k3);
	k1 = k2 = k3 = रिक्त;
	sshbuf_free(b);
	TEST_DONE();
#endif /* WITH_OPENSSL */
}

शून्य
sshkey_benchmarks(शून्य)
{
	संरचना sshkey *k = रिक्त;

#ifdef WITH_OPENSSL
	BENCH_START("generate RSA-1024");
	TEST_START("generate KEY_RSA");
	ASSERT_INT_EQ(sshkey_generate(साँचो_RSA, 1024, &k), 0);
	ASSERT_PTR_NE(k, रिक्त);
	sshkey_free(k);
	k = रिक्त;
	TEST_DONE();
	BENCH_FINISH("keys");

	BENCH_START("generate RSA-2048");
	TEST_START("generate KEY_RSA");
	ASSERT_INT_EQ(sshkey_generate(साँचो_RSA, 2048, &k), 0);
	ASSERT_PTR_NE(k, रिक्त);
	sshkey_free(k);
	k = रिक्त;
	TEST_DONE();
	BENCH_FINISH("keys");

	BENCH_START("generate ECDSA-256");
	TEST_START("generate KEY_ECDSA");
	ASSERT_INT_EQ(sshkey_generate(साँचो_ECDSA, 256, &k), 0);
	ASSERT_PTR_NE(k, रिक्त);
	sshkey_free(k);
	k = रिक्त;
	TEST_DONE();
	BENCH_FINISH("keys");

	BENCH_START("generate ECDSA-384");
	TEST_START("generate KEY_ECDSA");
	ASSERT_INT_EQ(sshkey_generate(साँचो_ECDSA, 384, &k), 0);
	ASSERT_PTR_NE(k, रिक्त);
	sshkey_free(k);
	k = रिक्त;
	TEST_DONE();
	BENCH_FINISH("keys");

	BENCH_START("generate ECDSA-521");
	TEST_START("generate KEY_ECDSA");
	ASSERT_INT_EQ(sshkey_generate(साँचो_ECDSA, 521, &k), 0);
	ASSERT_PTR_NE(k, रिक्त);
	sshkey_free(k);
	k = रिक्त;
	TEST_DONE();
	BENCH_FINISH("keys");
#endif /* WITH_OPENSSL */

	BENCH_START("generate ED25519");
	TEST_START("generate KEY_ED25519");
	ASSERT_INT_EQ(sshkey_generate(साँचो_ED25519, 256, &k), 0);
	ASSERT_PTR_NE(k, रिक्त);
	sshkey_free(k);
	k = रिक्त;
	TEST_DONE();
	BENCH_FINISH("keys");

	BENCH_START("generate MLDSA44-ED25519");
	TEST_START("generate KEY_MLDSA44_ED25519");
	ASSERT_INT_EQ(sshkey_generate(साँचो_MLDSA44_ED25519, 256, &k), 0);
	ASSERT_PTR_NE(k, रिक्त);
	sshkey_free(k);
	k = रिक्त;
	TEST_DONE();
	BENCH_FINISH("keys");

#ifdef WITH_OPENSSL
	/* sign */
	signature_benchmark("RSA-1024/SHA1", साँचो_RSA, 1024, "ssh-rsa", 0);
	signature_benchmark("RSA-1024/SHA256", साँचो_RSA, 1024, "rsa-sha2-256", 0);
	signature_benchmark("RSA-1024/SHA512", साँचो_RSA, 1024, "rsa-sha2-512", 0);
	signature_benchmark("RSA-2048/SHA1", साँचो_RSA, 2048, "ssh-rsa", 0);
	signature_benchmark("RSA-2048/SHA256", साँचो_RSA, 2048, "rsa-sha2-256", 0);
	signature_benchmark("RSA-2048/SHA512", साँचो_RSA, 2048, "rsa-sha2-512", 0);
	signature_benchmark("ECDSA-256", साँचो_ECDSA, 256, रिक्त, 0);
	signature_benchmark("ECDSA-384", साँचो_ECDSA, 384, रिक्त, 0);
	signature_benchmark("ECDSA-521", साँचो_ECDSA, 521, रिक्त, 0);
	signature_benchmark("ED25519", साँचो_ED25519, 0, रिक्त, 0);
	signature_benchmark("MLDSA44-ED25519", साँचो_MLDSA44_ED25519, 0, रिक्त, 0);

	/* verify */
	signature_benchmark("RSA-1024/SHA1", साँचो_RSA, 1024, "ssh-rsa", 1);
	signature_benchmark("RSA-1024/SHA256", साँचो_RSA, 1024, "rsa-sha2-256", 1);
	signature_benchmark("RSA-1024/SHA512", साँचो_RSA, 1024, "rsa-sha2-512", 1);
	signature_benchmark("RSA-2048/SHA1", साँचो_RSA, 2048, "ssh-rsa", 1);
	signature_benchmark("RSA-2048/SHA256", साँचो_RSA, 2048, "rsa-sha2-256", 1);
	signature_benchmark("RSA-2048/SHA512", साँचो_RSA, 2048, "rsa-sha2-512", 1);
	signature_benchmark("ECDSA-256", साँचो_ECDSA, 256, रिक्त, 1);
	signature_benchmark("ECDSA-384", साँचो_ECDSA, 384, रिक्त, 1);
	signature_benchmark("ECDSA-521", साँचो_ECDSA, 521, रिक्त, 1);
#endif /* WITH_OPENSSL */
	signature_benchmark("ED25519", साँचो_ED25519, 0, रिक्त, 1);
	signature_benchmark("MLDSA44-ED25519", साँचो_MLDSA44_ED25519, 0, रिक्त, 1);
}
