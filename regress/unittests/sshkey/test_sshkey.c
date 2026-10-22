/* 	$OpenBSD: test_sshkey.c,v 1.34 2026/06/14 04:08:06 djm Exp $ */
/*
 * Regress test for sshkey.h key management API
 *
 * Placed in the public domain
 */

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <stdint.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <string.h>

#ifdef WITH_OPENSSL
#அந்தர்பாவ <openssl/bn.h>
#அந்தர்பாவ <openssl/ec.h>
#அந்தர்பாவ <openssl/rsa.h>
#endif

#அந்தர்பாவ "../test_helper/test_helper.h"

#அந்தர்பாவ "ssherr.h"
#அந்தர்பாவ "sshbuf.h"
#define SSHBUF_INTERNAL 1	/* access internals for testing */
#அந்தர்பாவ "sshkey.h"

#அந்தர்பாவ "authfile.h"
#அந்தர்பாவ "common.h"
#அந்தர்பாவ "ssh2.h"

வெறுமை sshkey_tests(வெறுமை);
வெறுமை sshkey_benchmarks(வெறுமை);

நிலையான வெறுமை
put_opt(கட்டமைப்பு sshbuf *b, மாறிலி எழுத்து *name, மாறிலி எழுத்து *மதிப்பு)
{
	கட்டமைப்பு sshbuf *sect;

	sect = sshbuf_new();
	ASSERT_PTR_NE(sect, வெற்று);
	ASSERT_INT_EQ(sshbuf_put_cstring(b, name), 0);
	எனில் (மதிப்பு != வெற்று)
		ASSERT_INT_EQ(sshbuf_put_cstring(sect, மதிப்பு), 0);
	ASSERT_INT_EQ(sshbuf_put_stringb(b, sect), 0);
	sshbuf_free(sect);
}

#ifdef WITH_OPENSSL
நிலையான வெறுமை
build_cert(கட்டமைப்பு sshbuf *b, கட்டமைப்பு sshkey *k, மாறிலி எழுத்து *type,
    கட்டமைப்பு sshkey *sign_சாவி, கட்டமைப்பு sshkey *ca_சாவி,
    மாறிலி எழுத்து *sig_alg)
{
	கட்டமைப்பு sshbuf *ca_buf, *pk, *principals, *critopts, *exts;
	u_char *sigblob;
	size_t siglen;

	ca_buf = sshbuf_new();
	ASSERT_PTR_NE(ca_buf, வெற்று);
	ASSERT_INT_EQ(sshkey_putb(ca_சாவி, ca_buf), 0);

	/*
	 * Get the public key serialisation by rendering the key and skipping
	 * the type string. This is a bit of a hack :/
	 */
	pk = sshbuf_new();
	ASSERT_PTR_NE(pk, வெற்று);
	ASSERT_INT_EQ(sshkey_putb_plain(k, pk), 0);
	ASSERT_INT_EQ(sshbuf_skip_string(pk), 0);

	principals = sshbuf_new();
	ASSERT_PTR_NE(principals, வெற்று);
	ASSERT_INT_EQ(sshbuf_put_cstring(principals, "gsamsa"), 0);
	ASSERT_INT_EQ(sshbuf_put_cstring(principals, "gregor"), 0);

	critopts = sshbuf_new();
	ASSERT_PTR_NE(critopts, வெற்று);
	put_opt(critopts, "force-command", "/usr/local/bin/nethack");
	put_opt(critopts, "source-address", "192.168.0.0/24,127.0.0.1,::1");

	exts = sshbuf_new();
	ASSERT_PTR_NE(exts, வெற்று);
	put_opt(critopts, "permit-X11-forwarding", வெற்று);

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
	ASSERT_INT_EQ(sshbuf_put_string(b, வெற்று, 0), 0); /* reserved */
	ASSERT_INT_EQ(sshbuf_put_stringb(b, ca_buf), 0); /* signature key */
	ASSERT_INT_EQ(sshkey_sign(sign_சாவி, &sigblob, &siglen,
	    sshbuf_ptr(b), sshbuf_len(b), sig_alg, வெற்று, வெற்று, 0), 0);
	ASSERT_INT_EQ(sshbuf_put_string(b, sigblob, siglen), 0); /* signature */

	விடுவி(sigblob);
	sshbuf_free(ca_buf);
	sshbuf_free(exts);
	sshbuf_free(critopts);
	sshbuf_free(principals);
	sshbuf_free(pk);
}
#endif /* WITH_OPENSSL */

நிலையான வெறுமை
signature_test(கட்டமைப்பு sshkey *k, கட்டமைப்பு sshkey *bad, மாறிலி எழுத்து *sig_alg,
    மாறிலி u_char *d, size_t l)
{
	size_t len;
	u_char *sig;

	ASSERT_INT_EQ(sshkey_sign(k, &sig, &len, d, l, sig_alg,
	    வெற்று, வெற்று, 0), 0);
	ASSERT_SIZE_T_GT(len, 8);
	ASSERT_PTR_NE(sig, வெற்று);
	ASSERT_INT_EQ(sshkey_verify(k, sig, len, d, l, வெற்று, 0, வெற்று), 0);
	ASSERT_INT_NE(sshkey_verify(bad, sig, len, d, l, வெற்று, 0, வெற்று), 0);
	/* Fuzz test is more comprehensive, this is just a smoke test */
	sig[len - 5] ^= 0x10;
	ASSERT_INT_NE(sshkey_verify(k, sig, len, d, l, வெற்று, 0, வெற்று), 0);
	விடுவி(sig);
}

நிலையான வெறுமை
signature_bench(மாறிலி எழுத்து *name, முழு ktype, முழு bits, மாறிலி எழுத்து *sig_alg,
    மாறிலி u_char *d, size_t l)
{
	கட்டமைப்பு sshkey *k;
	size_t len;
	u_char *sig;
	எழுத்து testname[256];

	snprintf(testname, அளவு(testname), "sign %s", name);
	TEST_START(testname);
	ASSERT_INT_EQ(sshkey_generate(ktype, bits, &k), 0);
	ASSERT_PTR_NE(k, வெற்று);

	BENCH_START(testname);
	ASSERT_INT_EQ(sshkey_sign(k, &sig, &len, d, l, sig_alg,
	    வெற்று, வெற்று, 0), 0);
	விடுவி(sig);
	BENCH_FINISH("sign");

	sshkey_free(k);
	TEST_DONE();
}

நிலையான வெறுமை
verify_bench(மாறிலி எழுத்து *name, முழு ktype, முழு bits, மாறிலி எழுத்து *sig_alg,
    மாறிலி u_char *d, size_t l)
{
	கட்டமைப்பு sshkey *k;
	size_t len;
	u_char *sig;
	எழுத்து testname[256];

	snprintf(testname, அளவு(testname), "verify %s", name);
	TEST_START(testname);
	ASSERT_INT_EQ(sshkey_generate(ktype, bits, &k), 0);
	ASSERT_PTR_NE(k, வெற்று);

	ASSERT_INT_EQ(sshkey_sign(k, &sig, &len, d, l, sig_alg,
	    வெற்று, வெற்று, 0), 0);
	BENCH_START(testname);
	ASSERT_INT_EQ(sshkey_verify(k, sig, len, d, l, வெற்று, 0, வெற்று), 0);
	BENCH_FINISH("verify");

	விடுவி(sig);
	sshkey_free(k);
	TEST_DONE();
}

நிலையான வெறுமை
banana(u_char *s, size_t l)
{
	size_t o;
	மாறிலி u_char the_banana[] = { 'b', 'a', 'n', 'a', 'n', 'a' };

	க்கு (o = 0; o < l; o += அளவு(the_banana)) {
		எனில் (l - o < அளவு(the_banana)) {
			memcpy(s + o, "nanananana", l - o);
			நிறுத்து;
		}
		memcpy(s + o, the_banana, அளவு(the_banana));
	}
}

நிலையான வெறுமை
signature_tests(கட்டமைப்பு sshkey *k, கட்டமைப்பு sshkey *bad, மாறிலி எழுத்து *sig_alg)
{
	u_char i, buf[2049];
	size_t lens[] = {
		1, 2, 7, 8, 9, 15, 16, 17, 31, 32, 33, 127, 128, 129,
		255, 256, 257, 1023, 1024, 1025, 2047, 2048, 2049
	};

	க்கு (i = 0; i < (அளவு(lens)/அளவு(lens[0])); i++) {
		test_subtest_info("%s key, banana length %zu",
		    sshkey_type(k), lens[i]);
		banana(buf, lens[i]);
		signature_test(k, bad, sig_alg, buf, lens[i]);
	}
}

நிலையான வெறுமை
signature_benchmark(மாறிலி எழுத்து *name, முழு ktype, முழு bits,
    மாறிலி எழுத்து *sig_alg, முழு bench_verify)
{
	u_char buf[256];

	banana(buf, அளவு(buf));
	எனில் (bench_verify)
		verify_bench(name, ktype, bits, sig_alg, buf, அளவு(buf));
	இல்லையெனில்
		signature_bench(name, ktype, bits, sig_alg, buf, அளவு(buf));
}

நிலையான கட்டமைப்பு sshkey *
get_private(மாறிலி எழுத்து *n)
{
	கட்டமைப்பு sshbuf *b;
	கட்டமைப்பு sshkey *ret;

	b = load_file(n);
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(b, "", &ret, வெற்று), 0);
	sshbuf_free(b);
	திரும்பு ret;
}

வெறுமை
sshkey_tests(வெறுமை)
{
	கட்டமைப்பு sshkey *k1 = வெற்று, *k2 = வெற்று, *k3 = வெற்று, *k4 = வெற்று;
	கட்டமைப்பு sshkey *kr = வெற்று, *kd = வெற்று, *ke = வெற்று, *kf = வெற்று;
	கட்டமைப்பு sshbuf *b = வெற்று;

	TEST_START("new invalid");
	k1 = sshkey_new(-42);
	ASSERT_PTR_EQ(k1, வெற்று);
	TEST_DONE();

	TEST_START("new/free KEY_UNSPEC");
	k1 = sshkey_new(சாவி_UNSPEC);
	ASSERT_PTR_NE(k1, வெற்று);
	sshkey_free(k1);
	k1 = வெற்று;
	TEST_DONE();

#ifdef WITH_OPENSSL
	TEST_START("new/free KEY_RSA");
	k1 = sshkey_new(சாவி_RSA);
	ASSERT_PTR_NE(k1, வெற்று);
	ASSERT_PTR_NE(k1->pkey, வெற்று);
	sshkey_free(k1);
	k1 = வெற்று;
	TEST_DONE();

	TEST_START("new/free KEY_ECDSA");
	k1 = sshkey_new(சாவி_ECDSA);
	ASSERT_PTR_NE(k1, வெற்று);
	ASSERT_PTR_EQ(k1->pkey, வெற்று);  /* Can't allocate without NID */
	sshkey_free(k1);
	k1 = வெற்று;
	TEST_DONE();
#endif /* WITH_OPENSSL */

	TEST_START("new/free KEY_ED25519");
	k1 = sshkey_new(சாவி_ED25519);
	ASSERT_PTR_NE(k1, வெற்று);
	/* These should be blank until key loaded or generated */
	ASSERT_PTR_EQ(k1->ed25519_sk, வெற்று);
	ASSERT_PTR_EQ(k1->ed25519_pk, வெற்று);
	sshkey_free(k1);
	k1 = வெற்று;
	TEST_DONE();

	TEST_START("new/free KEY_MLDSA44_ED25519");
	k1 = sshkey_new(சாவி_MLDSA44_ED25519);
	ASSERT_PTR_NE(k1, வெற்று);
	ASSERT_PTR_EQ(k1->mldsa_ed25519_sk, வெற்று);
	ASSERT_PTR_EQ(k1->mldsa_ed25519_pk, வெற்று);
	sshkey_free(k1);
	k1 = வெற்று;
	TEST_DONE();

#ifdef WITH_OPENSSL
	TEST_START("generate KEY_RSA too small modulus");
	ASSERT_INT_EQ(sshkey_generate(சாவி_RSA, 128, &k1),
	    SSH_ERR_சாவி_LENGTH);
	ASSERT_PTR_EQ(k1, வெற்று);
	TEST_DONE();

	TEST_START("generate KEY_RSA too large modulus");
	ASSERT_INT_EQ(sshkey_generate(சாவி_RSA, 1 << 20, &k1),
	    SSH_ERR_சாவி_LENGTH);
	ASSERT_PTR_EQ(k1, வெற்று);
	TEST_DONE();


	TEST_START("generate KEY_ECDSA wrong bits");
	ASSERT_INT_EQ(sshkey_generate(சாவி_ECDSA, 42, &k1),
	    SSH_ERR_சாவி_LENGTH);
	ASSERT_PTR_EQ(k1, வெற்று);
	sshkey_free(k1);
	k1 = வெற்று;
	TEST_DONE();

	TEST_START("generate KEY_RSA");
	ASSERT_INT_EQ(sshkey_generate(சாவி_RSA, 767, &kr),
	    SSH_ERR_சாவி_LENGTH);
	ASSERT_INT_EQ(sshkey_generate(சாவி_RSA, 1024, &kr), 0);
	ASSERT_PTR_NE(kr, வெற்று);
	ASSERT_PTR_NE(EVP_PKEY_get0_RSA(kr->pkey), வெற்று);
	ASSERT_PTR_NE(rsa_n(kr), வெற்று);
	ASSERT_PTR_NE(rsa_e(kr), வெற்று);
	ASSERT_PTR_NE(rsa_p(kr), வெற்று);
	ASSERT_INT_EQ(BN_இலக்கம்_bits(rsa_n(kr)), 1024);
	TEST_DONE();


	TEST_START("generate KEY_ECDSA");
	ASSERT_INT_EQ(sshkey_generate(சாவி_ECDSA, 256, &ke), 0);
	ASSERT_PTR_NE(ke, வெற்று);
	ASSERT_PTR_NE(EVP_PKEY_get0_EC_சாவி(ke->pkey), வெற்று);
	ASSERT_PTR_NE(EC_சாவி_get0_public_சாவி(EVP_PKEY_get0_EC_சாவி(ke->pkey)),
	    வெற்று);
	ASSERT_PTR_NE(EC_சாவி_get0_private_சாவி(EVP_PKEY_get0_EC_சாவி(ke->pkey)),
	    வெற்று);
	TEST_DONE();
#endif /* WITH_OPENSSL */

	TEST_START("generate KEY_ED25519");
	ASSERT_INT_EQ(sshkey_generate(சாவி_ED25519, 256, &kf), 0);
	ASSERT_PTR_NE(kf, வெற்று);
	ASSERT_INT_EQ(kf->type, சாவி_ED25519);
	ASSERT_PTR_NE(kf->ed25519_pk, வெற்று);
	ASSERT_PTR_NE(kf->ed25519_sk, வெற்று);
	TEST_DONE();

	TEST_START("generate KEY_MLDSA44_ED25519");
	ASSERT_INT_EQ(sshkey_generate(சாவி_MLDSA44_ED25519, 256, &k1), 0);
	ASSERT_PTR_NE(k1, வெற்று);
	ASSERT_INT_EQ(k1->type, சாவி_MLDSA44_ED25519);
	ASSERT_PTR_NE(k1->mldsa_ed25519_pk, வெற்று);
	ASSERT_PTR_NE(k1->mldsa_ed25519_sk, வெற்று);
	sshkey_free(k1);
	k1 = வெற்று;
	TEST_DONE();

#ifdef WITH_OPENSSL
	TEST_START("demote KEY_RSA");
	ASSERT_INT_EQ(sshkey_from_private(kr, &k1), 0);
	ASSERT_PTR_NE(k1, வெற்று);
	ASSERT_PTR_NE(kr, k1);
	ASSERT_INT_EQ(k1->type, சாவி_RSA);
	ASSERT_PTR_NE(EVP_PKEY_get0_RSA(k1->pkey), வெற்று);
	ASSERT_PTR_NE(rsa_n(k1), வெற்று);
	ASSERT_PTR_NE(rsa_e(k1), வெற்று);
	ASSERT_PTR_EQ(rsa_p(k1), வெற்று);
	TEST_DONE();

	TEST_START("equal KEY_RSA/demoted KEY_RSA");
	ASSERT_INT_EQ(sshkey_equal(kr, k1), 1);
	sshkey_free(k1);
	k1 = வெற்று;
	TEST_DONE();


	TEST_START("demote KEY_ECDSA");
	ASSERT_INT_EQ(sshkey_from_private(ke, &k1), 0);
	ASSERT_PTR_NE(k1, வெற்று);
	ASSERT_PTR_NE(ke, k1);
	ASSERT_INT_EQ(k1->type, சாவி_ECDSA);
	ASSERT_PTR_NE(EVP_PKEY_get0_EC_சாவி(k1->pkey), வெற்று);
	ASSERT_INT_EQ(k1->ecdsa_nid, ke->ecdsa_nid);
	ASSERT_PTR_NE(EC_சாவி_get0_public_சாவி(EVP_PKEY_get0_EC_சாவி(ke->pkey)),
	   வெற்று);
	ASSERT_PTR_EQ(EC_சாவி_get0_private_சாவி(EVP_PKEY_get0_EC_சாவி(k1->pkey)),
	   வெற்று);
	TEST_DONE();

	TEST_START("equal KEY_ECDSA/demoted KEY_ECDSA");
	ASSERT_INT_EQ(sshkey_equal(ke, k1), 1);
	sshkey_free(k1);
	k1 = வெற்று;
	TEST_DONE();
#endif /* WITH_OPENSSL */

	TEST_START("demote KEY_ED25519");
	ASSERT_INT_EQ(sshkey_from_private(kf, &k1), 0);
	ASSERT_PTR_NE(k1, வெற்று);
	ASSERT_PTR_NE(kf, k1);
	ASSERT_INT_EQ(k1->type, சாவி_ED25519);
	ASSERT_PTR_NE(k1->ed25519_pk, வெற்று);
	ASSERT_PTR_EQ(k1->ed25519_sk, வெற்று);
	TEST_DONE();

	TEST_START("equal KEY_ED25519/demoted KEY_ED25519");
	ASSERT_INT_EQ(sshkey_equal(kf, k1), 1);
	sshkey_free(k1);
	k1 = வெற்று;
	TEST_DONE();

	TEST_START("demote KEY_MLDSA44_ED25519");
	ASSERT_INT_EQ(sshkey_generate(சாவி_MLDSA44_ED25519, 256, &k2), 0);
	ASSERT_INT_EQ(sshkey_from_private(k2, &k1), 0);
	ASSERT_PTR_NE(k1, வெற்று);
	ASSERT_PTR_NE(k2, k1);
	ASSERT_INT_EQ(k1->type, சாவி_MLDSA44_ED25519);
	ASSERT_PTR_NE(k1->mldsa_ed25519_pk, வெற்று);
	ASSERT_PTR_EQ(k1->mldsa_ed25519_sk, வெற்று);
	TEST_DONE();

	TEST_START("equal KEY_MLDSA44_ED25519/demoted KEY_MLDSA44_ED25519");
	ASSERT_INT_EQ(sshkey_equal(k2, k1), 1);
	sshkey_free(k1);
	sshkey_free(k2);
	k1 = k2 = வெற்று;
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
	ASSERT_INT_EQ(sshkey_generate(சாவி_RSA, 1024, &k1), 0);
	ASSERT_INT_EQ(sshkey_equal(kr, k1), 0);
	sshkey_free(k1);
	k1 = வெற்று;
	ASSERT_INT_EQ(sshkey_generate(சாவி_ECDSA, 256, &k1), 0);
	ASSERT_INT_EQ(sshkey_equal(ke, k1), 0);
	sshkey_free(k1);
	k1 = வெற்று;
	ASSERT_INT_EQ(sshkey_generate(சாவி_ED25519, 256, &k1), 0);
	ASSERT_INT_EQ(sshkey_equal(kf, k1), 0);
	sshkey_free(k1);
	k1 = வெற்று;
	ASSERT_INT_EQ(sshkey_generate(சாவி_MLDSA44_ED25519, 256, &k1), 0);
	ASSERT_INT_EQ(sshkey_generate(சாவி_MLDSA44_ED25519, 256, &k2), 0);
	ASSERT_INT_EQ(sshkey_equal(k2, k1), 0);
	sshkey_free(k1);
	sshkey_free(k2);
	k1 = k2 = வெற்று;
	TEST_DONE();
#endif /* WITH_OPENSSL */

	sshkey_free(kr);
	sshkey_free(kd);
	sshkey_free(ke);
	sshkey_free(kf);
	kr = kd = ke = kf = வெற்று;

	TEST_START("certify key");
	ASSERT_INT_EQ(sshkey_load_public(test_data_file("ed25519_1.pub"),
	    &k1, வெற்று), 0);
	k2 = get_private("ed25519_2");
	ASSERT_INT_EQ(sshkey_to_certified(k1), 0);
	ASSERT_PTR_NE(k1->cert, வெற்று);
	k1->cert->type = SSH2_CERT_TYPE_USER;
	k1->cert->serial = 1234;
	k1->cert->சாவி_id = strdup("estragon");
	ASSERT_PTR_NE(k1->cert->சாவி_id, வெற்று);
	k1->cert->principals = calloc(4, அளவு(*k1->cert->principals));
	ASSERT_PTR_NE(k1->cert->principals, வெற்று);
	k1->cert->principals[0] = strdup("estragon");
	k1->cert->principals[1] = strdup("vladimir");
	k1->cert->principals[2] = strdup("pozzo");
	k1->cert->principals[3] = strdup("lucky");
	ASSERT_PTR_NE(k1->cert->principals[0], வெற்று);
	ASSERT_PTR_NE(k1->cert->principals[1], வெற்று);
	ASSERT_PTR_NE(k1->cert->principals[2], வெற்று);
	ASSERT_PTR_NE(k1->cert->principals[3], வெற்று);
	k1->cert->nprincipals = 4;
	k1->cert->valid_after = 0;
	k1->cert->valid_before = (uint64_t)-1;
	sshbuf_free(k1->cert->critical);
	k1->cert->critical = sshbuf_new();
	ASSERT_PTR_NE(k1->cert->critical, வெற்று);
	sshbuf_free(k1->cert->extensions);
	k1->cert->extensions = sshbuf_new();
	ASSERT_PTR_NE(k1->cert->extensions, வெற்று);
	put_opt(k1->cert->critical, "force-command", "/usr/bin/true");
	put_opt(k1->cert->critical, "source-address", "127.0.0.1");
	put_opt(k1->cert->extensions, "permit-X11-forwarding", வெற்று);
	put_opt(k1->cert->extensions, "permit-agent-forwarding", வெற்று);
	ASSERT_INT_EQ(sshkey_from_private(k2, &k1->cert->signature_சாவி), 0);
	ASSERT_INT_EQ(sshkey_certify(k1, k2, வெற்று, வெற்று, வெற்று), 0);
	b = sshbuf_new();
	ASSERT_PTR_NE(b, வெற்று);
	ASSERT_INT_EQ(sshkey_putb(k1, b), 0);
	ASSERT_INT_EQ(sshkey_from_blob(sshbuf_ptr(b), sshbuf_len(b), &k3), 0);

	sshkey_free(k1);
	sshkey_free(k2);
	sshkey_free(k3);
	k1 = k2 = k3 = வெற்று;
	sshbuf_reset(b);
	TEST_DONE();

	TEST_START("certify key MLDSA44-ED25519");
	ASSERT_INT_EQ(sshkey_load_public(
	    test_data_file("mldsa44_ed25519_1.pub"), &k1, வெற்று), 0);
	k2 = get_private("mldsa44_ed25519_2");
	ASSERT_INT_EQ(sshkey_to_certified(k1), 0);
	ASSERT_PTR_NE(k1->cert, வெற்று);
	k1->cert->type = SSH2_CERT_TYPE_USER;
	k1->cert->serial = 1234;
	k1->cert->சாவி_id = strdup("estragon");
	ASSERT_PTR_NE(k1->cert->சாவி_id, வெற்று);
	k1->cert->principals = calloc(4, அளவு(*k1->cert->principals));
	ASSERT_PTR_NE(k1->cert->principals, வெற்று);
	k1->cert->principals[0] = strdup("estragon");
	k1->cert->principals[1] = strdup("vladimir");
	k1->cert->principals[2] = strdup("pozzo");
	k1->cert->principals[3] = strdup("lucky");
	ASSERT_PTR_NE(k1->cert->principals[0], வெற்று);
	ASSERT_PTR_NE(k1->cert->principals[1], வெற்று);
	ASSERT_PTR_NE(k1->cert->principals[2], வெற்று);
	ASSERT_PTR_NE(k1->cert->principals[3], வெற்று);
	k1->cert->nprincipals = 4;
	k1->cert->valid_after = 0;
	k1->cert->valid_before = (uint64_t)-1;
	sshbuf_free(k1->cert->critical);
	k1->cert->critical = sshbuf_new();
	ASSERT_PTR_NE(k1->cert->critical, வெற்று);
	sshbuf_free(k1->cert->extensions);
	k1->cert->extensions = sshbuf_new();
	ASSERT_PTR_NE(k1->cert->extensions, வெற்று);
	put_opt(k1->cert->critical, "force-command", "/usr/bin/true");
	put_opt(k1->cert->critical, "source-address", "127.0.0.1");
	put_opt(k1->cert->extensions, "permit-X11-forwarding", வெற்று);
	put_opt(k1->cert->extensions, "permit-agent-forwarding", வெற்று);
	ASSERT_INT_EQ(sshkey_from_private(k2, &k1->cert->signature_சாவி), 0);
	ASSERT_INT_EQ(sshkey_certify(k1, k2, வெற்று, வெற்று, வெற்று), 0);
	b = sshbuf_new();
	ASSERT_PTR_NE(b, வெற்று);
	ASSERT_INT_EQ(sshkey_putb(k1, b), 0);
	ASSERT_INT_EQ(sshkey_from_blob(sshbuf_ptr(b), sshbuf_len(b), &k3), 0);
	sshkey_free(k1);
	sshkey_free(k2);
	sshkey_free(k3);
	k1 = k2 = k3 = வெற்று;
	sshbuf_reset(b);
	TEST_DONE();

#ifdef WITH_OPENSSL
	TEST_START("sign and verify RSA");
	k1 = get_private("rsa_1");
	ASSERT_INT_EQ(sshkey_load_public(test_data_file("rsa_2.pub"), &k2,
	    வெற்று), 0);
	signature_tests(k1, k2, "ssh-rsa");
	sshkey_free(k1);
	sshkey_free(k2);
	k1 = k2 = வெற்று;
	TEST_DONE();

	TEST_START("sign and verify RSA-SHA256");
	k1 = get_private("rsa_1");
	ASSERT_INT_EQ(sshkey_load_public(test_data_file("rsa_2.pub"), &k2,
	    வெற்று), 0);
	signature_tests(k1, k2, "rsa-sha2-256");
	sshkey_free(k1);
	sshkey_free(k2);
	k1 = k2 = வெற்று;
	TEST_DONE();

	TEST_START("sign and verify RSA-SHA512");
	k1 = get_private("rsa_1");
	ASSERT_INT_EQ(sshkey_load_public(test_data_file("rsa_2.pub"), &k2,
	    வெற்று), 0);
	signature_tests(k1, k2, "rsa-sha2-512");
	sshkey_free(k1);
	sshkey_free(k2);
	k1 = k2 = வெற்று;
	TEST_DONE();


	TEST_START("sign and verify ECDSA");
	k1 = get_private("ecdsa_1");
	ASSERT_INT_EQ(sshkey_load_public(test_data_file("ecdsa_2.pub"), &k2,
	    வெற்று), 0);
	signature_tests(k1, k2, வெற்று);
	sshkey_free(k1);
	sshkey_free(k2);
	k1 = k2 = வெற்று;
	TEST_DONE();
#endif /* WITH_OPENSSL */

	TEST_START("sign and verify ED25519");
	k1 = get_private("ed25519_1");
	ASSERT_INT_EQ(sshkey_load_public(test_data_file("ed25519_2.pub"), &k2,
	    வெற்று), 0);
	signature_tests(k1, k2, வெற்று);
	sshkey_free(k1);
	sshkey_free(k2);
	k1 = k2 = வெற்று;
	TEST_DONE();

	TEST_START("sign and verify MLDSA44-ED25519");
	k1 = get_private("mldsa44_ed25519_1");
	ASSERT_INT_EQ(sshkey_load_public(
	    test_data_file("mldsa44_ed25519_2.pub"), &k2, வெற்று), 0);
	signature_tests(k1, k2, வெற்று);
	sshkey_free(k1);
	sshkey_free(k2);
	k1 = k2 = வெற்று;
	TEST_DONE();

#ifdef WITH_OPENSSL
	TEST_START("nested certificate");
	ASSERT_INT_EQ(sshkey_load_cert(test_data_file("rsa_1"), &k1), 0);
	ASSERT_INT_EQ(sshkey_load_public(test_data_file("rsa_1.pub"), &k2,
	    வெற்று), 0);
	k3 = get_private("rsa_1");
	build_cert(b, k2, "ssh-rsa-cert-v01@openssh.com", k3, k1, வெற்று);
	ASSERT_INT_EQ(sshkey_from_blob(sshbuf_ptr(b), sshbuf_len(b), &k4),
	    SSH_ERR_சாவி_CERT_INVALID_SIGN_சாவி);
	ASSERT_PTR_EQ(k4, வெற்று);
	sshkey_free(k1);
	sshkey_free(k2);
	sshkey_free(k3);
	k1 = k2 = k3 = வெற்று;
	sshbuf_free(b);
	TEST_DONE();
#endif /* WITH_OPENSSL */
}

வெறுமை
sshkey_benchmarks(வெறுமை)
{
	கட்டமைப்பு sshkey *k = வெற்று;

#ifdef WITH_OPENSSL
	BENCH_START("generate RSA-1024");
	TEST_START("generate KEY_RSA");
	ASSERT_INT_EQ(sshkey_generate(சாவி_RSA, 1024, &k), 0);
	ASSERT_PTR_NE(k, வெற்று);
	sshkey_free(k);
	k = வெற்று;
	TEST_DONE();
	BENCH_FINISH("keys");

	BENCH_START("generate RSA-2048");
	TEST_START("generate KEY_RSA");
	ASSERT_INT_EQ(sshkey_generate(சாவி_RSA, 2048, &k), 0);
	ASSERT_PTR_NE(k, வெற்று);
	sshkey_free(k);
	k = வெற்று;
	TEST_DONE();
	BENCH_FINISH("keys");

	BENCH_START("generate ECDSA-256");
	TEST_START("generate KEY_ECDSA");
	ASSERT_INT_EQ(sshkey_generate(சாவி_ECDSA, 256, &k), 0);
	ASSERT_PTR_NE(k, வெற்று);
	sshkey_free(k);
	k = வெற்று;
	TEST_DONE();
	BENCH_FINISH("keys");

	BENCH_START("generate ECDSA-384");
	TEST_START("generate KEY_ECDSA");
	ASSERT_INT_EQ(sshkey_generate(சாவி_ECDSA, 384, &k), 0);
	ASSERT_PTR_NE(k, வெற்று);
	sshkey_free(k);
	k = வெற்று;
	TEST_DONE();
	BENCH_FINISH("keys");

	BENCH_START("generate ECDSA-521");
	TEST_START("generate KEY_ECDSA");
	ASSERT_INT_EQ(sshkey_generate(சாவி_ECDSA, 521, &k), 0);
	ASSERT_PTR_NE(k, வெற்று);
	sshkey_free(k);
	k = வெற்று;
	TEST_DONE();
	BENCH_FINISH("keys");
#endif /* WITH_OPENSSL */

	BENCH_START("generate ED25519");
	TEST_START("generate KEY_ED25519");
	ASSERT_INT_EQ(sshkey_generate(சாவி_ED25519, 256, &k), 0);
	ASSERT_PTR_NE(k, வெற்று);
	sshkey_free(k);
	k = வெற்று;
	TEST_DONE();
	BENCH_FINISH("keys");

	BENCH_START("generate MLDSA44-ED25519");
	TEST_START("generate KEY_MLDSA44_ED25519");
	ASSERT_INT_EQ(sshkey_generate(சாவி_MLDSA44_ED25519, 256, &k), 0);
	ASSERT_PTR_NE(k, வெற்று);
	sshkey_free(k);
	k = வெற்று;
	TEST_DONE();
	BENCH_FINISH("keys");

#ifdef WITH_OPENSSL
	/* sign */
	signature_benchmark("RSA-1024/SHA1", சாவி_RSA, 1024, "ssh-rsa", 0);
	signature_benchmark("RSA-1024/SHA256", சாவி_RSA, 1024, "rsa-sha2-256", 0);
	signature_benchmark("RSA-1024/SHA512", சாவி_RSA, 1024, "rsa-sha2-512", 0);
	signature_benchmark("RSA-2048/SHA1", சாவி_RSA, 2048, "ssh-rsa", 0);
	signature_benchmark("RSA-2048/SHA256", சாவி_RSA, 2048, "rsa-sha2-256", 0);
	signature_benchmark("RSA-2048/SHA512", சாவி_RSA, 2048, "rsa-sha2-512", 0);
	signature_benchmark("ECDSA-256", சாவி_ECDSA, 256, வெற்று, 0);
	signature_benchmark("ECDSA-384", சாவி_ECDSA, 384, வெற்று, 0);
	signature_benchmark("ECDSA-521", சாவி_ECDSA, 521, வெற்று, 0);
	signature_benchmark("ED25519", சாவி_ED25519, 0, வெற்று, 0);
	signature_benchmark("MLDSA44-ED25519", சாவி_MLDSA44_ED25519, 0, வெற்று, 0);

	/* verify */
	signature_benchmark("RSA-1024/SHA1", சாவி_RSA, 1024, "ssh-rsa", 1);
	signature_benchmark("RSA-1024/SHA256", சாவி_RSA, 1024, "rsa-sha2-256", 1);
	signature_benchmark("RSA-1024/SHA512", சாவி_RSA, 1024, "rsa-sha2-512", 1);
	signature_benchmark("RSA-2048/SHA1", சாவி_RSA, 2048, "ssh-rsa", 1);
	signature_benchmark("RSA-2048/SHA256", சாவி_RSA, 2048, "rsa-sha2-256", 1);
	signature_benchmark("RSA-2048/SHA512", சாவி_RSA, 2048, "rsa-sha2-512", 1);
	signature_benchmark("ECDSA-256", சாவி_ECDSA, 256, வெற்று, 1);
	signature_benchmark("ECDSA-384", சாவி_ECDSA, 384, வெற்று, 1);
	signature_benchmark("ECDSA-521", சாவி_ECDSA, 521, வெற்று, 1);
#endif /* WITH_OPENSSL */
	signature_benchmark("ED25519", சாவி_ED25519, 0, வெற்று, 1);
	signature_benchmark("MLDSA44-ED25519", சாவி_MLDSA44_ED25519, 0, வெற்று, 1);
}
