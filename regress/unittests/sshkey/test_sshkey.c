/* 	$OpenBSD: test_sshkey.c,v 1.34 2026/06/14 04:08:06 djm Exp $ */
/*
 * Regress test for sshkey.h key management API
 *
 * Placed in the public domain
 */

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <stdint.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <string.h>

#ifdef WITH_OPENSSL
#અન્તર્ભાવ <openssl/bn.h>
#અન્તર્ભાવ <openssl/ec.h>
#અન્તર્ભાવ <openssl/rsa.h>
#endif

#અન્તર્ભાવ "../test_helper/test_helper.h"

#અન્તર્ભાવ "ssherr.h"
#અન્તર્ભાવ "sshbuf.h"
#define SSHBUF_INTERNAL 1	/* access internals for testing */
#અન્તર્ભાવ "sshkey.h"

#અન્તર્ભાવ "authfile.h"
#અન્તર્ભાવ "common.h"
#અન્તર્ભાવ "ssh2.h"

શૂન્ય sshkey_tests(શૂન્ય);
શૂન્ય sshkey_benchmarks(શૂન્ય);

સ્થિર શૂન્ય
put_opt(સંરચના sshbuf *b, અચલ અક્ષર *name, અચલ અક્ષર *કિંમત)
{
	સંરચના sshbuf *sect;

	sect = sshbuf_new();
	ASSERT_PTR_NE(sect, ખાલી);
	ASSERT_INT_EQ(sshbuf_put_cstring(b, name), 0);
	જો (કિંમત != ખાલી)
		ASSERT_INT_EQ(sshbuf_put_cstring(sect, કિંમત), 0);
	ASSERT_INT_EQ(sshbuf_put_stringb(b, sect), 0);
	sshbuf_free(sect);
}

#ifdef WITH_OPENSSL
સ્થિર શૂન્ય
build_cert(સંરચના sshbuf *b, સંરચના sshkey *k, અચલ અક્ષર *type,
    સંરચના sshkey *sign_ચાવી, સંરચના sshkey *ca_ચાવી,
    અચલ અક્ષર *sig_alg)
{
	સંરચના sshbuf *ca_buf, *pk, *principals, *critopts, *exts;
	u_char *sigblob;
	size_t siglen;

	ca_buf = sshbuf_new();
	ASSERT_PTR_NE(ca_buf, ખાલી);
	ASSERT_INT_EQ(sshkey_putb(ca_ચાવી, ca_buf), 0);

	/*
	 * Get the public key serialisation by rendering the key and skipping
	 * the type string. This is a bit of a hack :/
	 */
	pk = sshbuf_new();
	ASSERT_PTR_NE(pk, ખાલી);
	ASSERT_INT_EQ(sshkey_putb_plain(k, pk), 0);
	ASSERT_INT_EQ(sshbuf_skip_string(pk), 0);

	principals = sshbuf_new();
	ASSERT_PTR_NE(principals, ખાલી);
	ASSERT_INT_EQ(sshbuf_put_cstring(principals, "gsamsa"), 0);
	ASSERT_INT_EQ(sshbuf_put_cstring(principals, "gregor"), 0);

	critopts = sshbuf_new();
	ASSERT_PTR_NE(critopts, ખાલી);
	put_opt(critopts, "force-command", "/usr/local/bin/nethack");
	put_opt(critopts, "source-address", "192.168.0.0/24,127.0.0.1,::1");

	exts = sshbuf_new();
	ASSERT_PTR_NE(exts, ખાલી);
	put_opt(critopts, "permit-X11-forwarding", ખાલી);

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
	ASSERT_INT_EQ(sshbuf_put_string(b, ખાલી, 0), 0); /* reserved */
	ASSERT_INT_EQ(sshbuf_put_stringb(b, ca_buf), 0); /* signature key */
	ASSERT_INT_EQ(sshkey_sign(sign_ચાવી, &sigblob, &siglen,
	    sshbuf_ptr(b), sshbuf_len(b), sig_alg, ખાલી, ખાલી, 0), 0);
	ASSERT_INT_EQ(sshbuf_put_string(b, sigblob, siglen), 0); /* signature */

	મુક્ત(sigblob);
	sshbuf_free(ca_buf);
	sshbuf_free(exts);
	sshbuf_free(critopts);
	sshbuf_free(principals);
	sshbuf_free(pk);
}
#endif /* WITH_OPENSSL */

સ્થિર શૂન્ય
signature_test(સંરચના sshkey *k, સંરચના sshkey *bad, અચલ અક્ષર *sig_alg,
    અચલ u_char *d, size_t l)
{
	size_t len;
	u_char *sig;

	ASSERT_INT_EQ(sshkey_sign(k, &sig, &len, d, l, sig_alg,
	    ખાલી, ખાલી, 0), 0);
	ASSERT_SIZE_T_GT(len, 8);
	ASSERT_PTR_NE(sig, ખાલી);
	ASSERT_INT_EQ(sshkey_verify(k, sig, len, d, l, ખાલી, 0, ખાલી), 0);
	ASSERT_INT_NE(sshkey_verify(bad, sig, len, d, l, ખાલી, 0, ખાલી), 0);
	/* Fuzz test is more comprehensive, this is just a smoke test */
	sig[len - 5] ^= 0x10;
	ASSERT_INT_NE(sshkey_verify(k, sig, len, d, l, ખાલી, 0, ખાલી), 0);
	મુક્ત(sig);
}

સ્થિર શૂન્ય
signature_bench(અચલ અક્ષર *name, પૂર્ણાંક ktype, પૂર્ણાંક bits, અચલ અક્ષર *sig_alg,
    અચલ u_char *d, size_t l)
{
	સંરચના sshkey *k;
	size_t len;
	u_char *sig;
	અક્ષર testname[256];

	snprintf(testname, કદ(testname), "sign %s", name);
	TEST_START(testname);
	ASSERT_INT_EQ(sshkey_generate(ktype, bits, &k), 0);
	ASSERT_PTR_NE(k, ખાલી);

	BENCH_START(testname);
	ASSERT_INT_EQ(sshkey_sign(k, &sig, &len, d, l, sig_alg,
	    ખાલી, ખાલી, 0), 0);
	મુક્ત(sig);
	BENCH_FINISH("sign");

	sshkey_free(k);
	TEST_DONE();
}

સ્થિર શૂન્ય
verify_bench(અચલ અક્ષર *name, પૂર્ણાંક ktype, પૂર્ણાંક bits, અચલ અક્ષર *sig_alg,
    અચલ u_char *d, size_t l)
{
	સંરચના sshkey *k;
	size_t len;
	u_char *sig;
	અક્ષર testname[256];

	snprintf(testname, કદ(testname), "verify %s", name);
	TEST_START(testname);
	ASSERT_INT_EQ(sshkey_generate(ktype, bits, &k), 0);
	ASSERT_PTR_NE(k, ખાલી);

	ASSERT_INT_EQ(sshkey_sign(k, &sig, &len, d, l, sig_alg,
	    ખાલી, ખાલી, 0), 0);
	BENCH_START(testname);
	ASSERT_INT_EQ(sshkey_verify(k, sig, len, d, l, ખાલી, 0, ખાલી), 0);
	BENCH_FINISH("verify");

	મુક્ત(sig);
	sshkey_free(k);
	TEST_DONE();
}

સ્થિર શૂન્ય
banana(u_char *s, size_t l)
{
	size_t o;
	અચલ u_char the_banana[] = { 'b', 'a', 'n', 'a', 'n', 'a' };

	માટે (o = 0; o < l; o += કદ(the_banana)) {
		જો (l - o < કદ(the_banana)) {
			memcpy(s + o, "nanananana", l - o);
			તોડો;
		}
		memcpy(s + o, the_banana, કદ(the_banana));
	}
}

સ્થિર શૂન્ય
signature_tests(સંરચના sshkey *k, સંરચના sshkey *bad, અચલ અક્ષર *sig_alg)
{
	u_char i, buf[2049];
	size_t lens[] = {
		1, 2, 7, 8, 9, 15, 16, 17, 31, 32, 33, 127, 128, 129,
		255, 256, 257, 1023, 1024, 1025, 2047, 2048, 2049
	};

	માટે (i = 0; i < (કદ(lens)/કદ(lens[0])); i++) {
		test_subtest_info("%s key, banana length %zu",
		    sshkey_type(k), lens[i]);
		banana(buf, lens[i]);
		signature_test(k, bad, sig_alg, buf, lens[i]);
	}
}

સ્થિર શૂન્ય
signature_benchmark(અચલ અક્ષર *name, પૂર્ણાંક ktype, પૂર્ણાંક bits,
    અચલ અક્ષર *sig_alg, પૂર્ણાંક bench_verify)
{
	u_char buf[256];

	banana(buf, કદ(buf));
	જો (bench_verify)
		verify_bench(name, ktype, bits, sig_alg, buf, કદ(buf));
	નહીંતર
		signature_bench(name, ktype, bits, sig_alg, buf, કદ(buf));
}

સ્થિર સંરચના sshkey *
get_private(અચલ અક્ષર *n)
{
	સંરચના sshbuf *b;
	સંરચના sshkey *ret;

	b = load_file(n);
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(b, "", &ret, ખાલી), 0);
	sshbuf_free(b);
	પાછા ret;
}

શૂન્ય
sshkey_tests(શૂન્ય)
{
	સંરચના sshkey *k1 = ખાલી, *k2 = ખાલી, *k3 = ખાલી, *k4 = ખાલી;
	સંરચના sshkey *kr = ખાલી, *kd = ખાલી, *ke = ખાલી, *kf = ખાલી;
	સંરચના sshbuf *b = ખાલી;

	TEST_START("new invalid");
	k1 = sshkey_new(-42);
	ASSERT_PTR_EQ(k1, ખાલી);
	TEST_DONE();

	TEST_START("new/free KEY_UNSPEC");
	k1 = sshkey_new(ચાવી_UNSPEC);
	ASSERT_PTR_NE(k1, ખાલી);
	sshkey_free(k1);
	k1 = ખાલી;
	TEST_DONE();

#ifdef WITH_OPENSSL
	TEST_START("new/free KEY_RSA");
	k1 = sshkey_new(ચાવી_RSA);
	ASSERT_PTR_NE(k1, ખાલી);
	ASSERT_PTR_NE(k1->pkey, ખાલી);
	sshkey_free(k1);
	k1 = ખાલી;
	TEST_DONE();

	TEST_START("new/free KEY_ECDSA");
	k1 = sshkey_new(ચાવી_ECDSA);
	ASSERT_PTR_NE(k1, ખાલી);
	ASSERT_PTR_EQ(k1->pkey, ખાલી);  /* Can't allocate without NID */
	sshkey_free(k1);
	k1 = ખાલી;
	TEST_DONE();
#endif /* WITH_OPENSSL */

	TEST_START("new/free KEY_ED25519");
	k1 = sshkey_new(ચાવી_ED25519);
	ASSERT_PTR_NE(k1, ખાલી);
	/* These should be blank until key loaded or generated */
	ASSERT_PTR_EQ(k1->ed25519_sk, ખાલી);
	ASSERT_PTR_EQ(k1->ed25519_pk, ખાલી);
	sshkey_free(k1);
	k1 = ખાલી;
	TEST_DONE();

	TEST_START("new/free KEY_MLDSA44_ED25519");
	k1 = sshkey_new(ચાવી_MLDSA44_ED25519);
	ASSERT_PTR_NE(k1, ખાલી);
	ASSERT_PTR_EQ(k1->mldsa_ed25519_sk, ખાલી);
	ASSERT_PTR_EQ(k1->mldsa_ed25519_pk, ખાલી);
	sshkey_free(k1);
	k1 = ખાલી;
	TEST_DONE();

#ifdef WITH_OPENSSL
	TEST_START("generate KEY_RSA too small modulus");
	ASSERT_INT_EQ(sshkey_generate(ચાવી_RSA, 128, &k1),
	    SSH_ERR_ચાવી_LENGTH);
	ASSERT_PTR_EQ(k1, ખાલી);
	TEST_DONE();

	TEST_START("generate KEY_RSA too large modulus");
	ASSERT_INT_EQ(sshkey_generate(ચાવી_RSA, 1 << 20, &k1),
	    SSH_ERR_ચાવી_LENGTH);
	ASSERT_PTR_EQ(k1, ખાલી);
	TEST_DONE();


	TEST_START("generate KEY_ECDSA wrong bits");
	ASSERT_INT_EQ(sshkey_generate(ચાવી_ECDSA, 42, &k1),
	    SSH_ERR_ચાવી_LENGTH);
	ASSERT_PTR_EQ(k1, ખાલી);
	sshkey_free(k1);
	k1 = ખાલી;
	TEST_DONE();

	TEST_START("generate KEY_RSA");
	ASSERT_INT_EQ(sshkey_generate(ચાવી_RSA, 767, &kr),
	    SSH_ERR_ચાવી_LENGTH);
	ASSERT_INT_EQ(sshkey_generate(ચાવી_RSA, 1024, &kr), 0);
	ASSERT_PTR_NE(kr, ખાલી);
	ASSERT_PTR_NE(EVP_PKEY_get0_RSA(kr->pkey), ખાલી);
	ASSERT_PTR_NE(rsa_n(kr), ખાલી);
	ASSERT_PTR_NE(rsa_e(kr), ખાલી);
	ASSERT_PTR_NE(rsa_p(kr), ખાલી);
	ASSERT_INT_EQ(BN_અંક_bits(rsa_n(kr)), 1024);
	TEST_DONE();


	TEST_START("generate KEY_ECDSA");
	ASSERT_INT_EQ(sshkey_generate(ચાવી_ECDSA, 256, &ke), 0);
	ASSERT_PTR_NE(ke, ખાલી);
	ASSERT_PTR_NE(EVP_PKEY_get0_EC_ચાવી(ke->pkey), ખાલી);
	ASSERT_PTR_NE(EC_ચાવી_get0_public_ચાવી(EVP_PKEY_get0_EC_ચાવી(ke->pkey)),
	    ખાલી);
	ASSERT_PTR_NE(EC_ચાવી_get0_private_ચાવી(EVP_PKEY_get0_EC_ચાવી(ke->pkey)),
	    ખાલી);
	TEST_DONE();
#endif /* WITH_OPENSSL */

	TEST_START("generate KEY_ED25519");
	ASSERT_INT_EQ(sshkey_generate(ચાવી_ED25519, 256, &kf), 0);
	ASSERT_PTR_NE(kf, ખાલી);
	ASSERT_INT_EQ(kf->type, ચાવી_ED25519);
	ASSERT_PTR_NE(kf->ed25519_pk, ખાલી);
	ASSERT_PTR_NE(kf->ed25519_sk, ખાલી);
	TEST_DONE();

	TEST_START("generate KEY_MLDSA44_ED25519");
	ASSERT_INT_EQ(sshkey_generate(ચાવી_MLDSA44_ED25519, 256, &k1), 0);
	ASSERT_PTR_NE(k1, ખાલી);
	ASSERT_INT_EQ(k1->type, ચાવી_MLDSA44_ED25519);
	ASSERT_PTR_NE(k1->mldsa_ed25519_pk, ખાલી);
	ASSERT_PTR_NE(k1->mldsa_ed25519_sk, ખાલી);
	sshkey_free(k1);
	k1 = ખાલી;
	TEST_DONE();

#ifdef WITH_OPENSSL
	TEST_START("demote KEY_RSA");
	ASSERT_INT_EQ(sshkey_from_private(kr, &k1), 0);
	ASSERT_PTR_NE(k1, ખાલી);
	ASSERT_PTR_NE(kr, k1);
	ASSERT_INT_EQ(k1->type, ચાવી_RSA);
	ASSERT_PTR_NE(EVP_PKEY_get0_RSA(k1->pkey), ખાલી);
	ASSERT_PTR_NE(rsa_n(k1), ખાલી);
	ASSERT_PTR_NE(rsa_e(k1), ખાલી);
	ASSERT_PTR_EQ(rsa_p(k1), ખાલી);
	TEST_DONE();

	TEST_START("equal KEY_RSA/demoted KEY_RSA");
	ASSERT_INT_EQ(sshkey_equal(kr, k1), 1);
	sshkey_free(k1);
	k1 = ખાલી;
	TEST_DONE();


	TEST_START("demote KEY_ECDSA");
	ASSERT_INT_EQ(sshkey_from_private(ke, &k1), 0);
	ASSERT_PTR_NE(k1, ખાલી);
	ASSERT_PTR_NE(ke, k1);
	ASSERT_INT_EQ(k1->type, ચાવી_ECDSA);
	ASSERT_PTR_NE(EVP_PKEY_get0_EC_ચાવી(k1->pkey), ખાલી);
	ASSERT_INT_EQ(k1->ecdsa_nid, ke->ecdsa_nid);
	ASSERT_PTR_NE(EC_ચાવી_get0_public_ચાવી(EVP_PKEY_get0_EC_ચાવી(ke->pkey)),
	   ખાલી);
	ASSERT_PTR_EQ(EC_ચાવી_get0_private_ચાવી(EVP_PKEY_get0_EC_ચાવી(k1->pkey)),
	   ખાલી);
	TEST_DONE();

	TEST_START("equal KEY_ECDSA/demoted KEY_ECDSA");
	ASSERT_INT_EQ(sshkey_equal(ke, k1), 1);
	sshkey_free(k1);
	k1 = ખાલી;
	TEST_DONE();
#endif /* WITH_OPENSSL */

	TEST_START("demote KEY_ED25519");
	ASSERT_INT_EQ(sshkey_from_private(kf, &k1), 0);
	ASSERT_PTR_NE(k1, ખાલી);
	ASSERT_PTR_NE(kf, k1);
	ASSERT_INT_EQ(k1->type, ચાવી_ED25519);
	ASSERT_PTR_NE(k1->ed25519_pk, ખાલી);
	ASSERT_PTR_EQ(k1->ed25519_sk, ખાલી);
	TEST_DONE();

	TEST_START("equal KEY_ED25519/demoted KEY_ED25519");
	ASSERT_INT_EQ(sshkey_equal(kf, k1), 1);
	sshkey_free(k1);
	k1 = ખાલી;
	TEST_DONE();

	TEST_START("demote KEY_MLDSA44_ED25519");
	ASSERT_INT_EQ(sshkey_generate(ચાવી_MLDSA44_ED25519, 256, &k2), 0);
	ASSERT_INT_EQ(sshkey_from_private(k2, &k1), 0);
	ASSERT_PTR_NE(k1, ખાલી);
	ASSERT_PTR_NE(k2, k1);
	ASSERT_INT_EQ(k1->type, ચાવી_MLDSA44_ED25519);
	ASSERT_PTR_NE(k1->mldsa_ed25519_pk, ખાલી);
	ASSERT_PTR_EQ(k1->mldsa_ed25519_sk, ખાલી);
	TEST_DONE();

	TEST_START("equal KEY_MLDSA44_ED25519/demoted KEY_MLDSA44_ED25519");
	ASSERT_INT_EQ(sshkey_equal(k2, k1), 1);
	sshkey_free(k1);
	sshkey_free(k2);
	k1 = k2 = ખાલી;
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
	ASSERT_INT_EQ(sshkey_generate(ચાવી_RSA, 1024, &k1), 0);
	ASSERT_INT_EQ(sshkey_equal(kr, k1), 0);
	sshkey_free(k1);
	k1 = ખાલી;
	ASSERT_INT_EQ(sshkey_generate(ચાવી_ECDSA, 256, &k1), 0);
	ASSERT_INT_EQ(sshkey_equal(ke, k1), 0);
	sshkey_free(k1);
	k1 = ખાલી;
	ASSERT_INT_EQ(sshkey_generate(ચાવી_ED25519, 256, &k1), 0);
	ASSERT_INT_EQ(sshkey_equal(kf, k1), 0);
	sshkey_free(k1);
	k1 = ખાલી;
	ASSERT_INT_EQ(sshkey_generate(ચાવી_MLDSA44_ED25519, 256, &k1), 0);
	ASSERT_INT_EQ(sshkey_generate(ચાવી_MLDSA44_ED25519, 256, &k2), 0);
	ASSERT_INT_EQ(sshkey_equal(k2, k1), 0);
	sshkey_free(k1);
	sshkey_free(k2);
	k1 = k2 = ખાલી;
	TEST_DONE();
#endif /* WITH_OPENSSL */

	sshkey_free(kr);
	sshkey_free(kd);
	sshkey_free(ke);
	sshkey_free(kf);
	kr = kd = ke = kf = ખાલી;

	TEST_START("certify key");
	ASSERT_INT_EQ(sshkey_load_public(test_data_file("ed25519_1.pub"),
	    &k1, ખાલી), 0);
	k2 = get_private("ed25519_2");
	ASSERT_INT_EQ(sshkey_to_certified(k1), 0);
	ASSERT_PTR_NE(k1->cert, ખાલી);
	k1->cert->type = SSH2_CERT_TYPE_USER;
	k1->cert->serial = 1234;
	k1->cert->ચાવી_id = strdup("estragon");
	ASSERT_PTR_NE(k1->cert->ચાવી_id, ખાલી);
	k1->cert->principals = calloc(4, કદ(*k1->cert->principals));
	ASSERT_PTR_NE(k1->cert->principals, ખાલી);
	k1->cert->principals[0] = strdup("estragon");
	k1->cert->principals[1] = strdup("vladimir");
	k1->cert->principals[2] = strdup("pozzo");
	k1->cert->principals[3] = strdup("lucky");
	ASSERT_PTR_NE(k1->cert->principals[0], ખાલી);
	ASSERT_PTR_NE(k1->cert->principals[1], ખાલી);
	ASSERT_PTR_NE(k1->cert->principals[2], ખાલી);
	ASSERT_PTR_NE(k1->cert->principals[3], ખાલી);
	k1->cert->nprincipals = 4;
	k1->cert->valid_after = 0;
	k1->cert->valid_before = (uint64_t)-1;
	sshbuf_free(k1->cert->critical);
	k1->cert->critical = sshbuf_new();
	ASSERT_PTR_NE(k1->cert->critical, ખાલી);
	sshbuf_free(k1->cert->extensions);
	k1->cert->extensions = sshbuf_new();
	ASSERT_PTR_NE(k1->cert->extensions, ખાલી);
	put_opt(k1->cert->critical, "force-command", "/usr/bin/true");
	put_opt(k1->cert->critical, "source-address", "127.0.0.1");
	put_opt(k1->cert->extensions, "permit-X11-forwarding", ખાલી);
	put_opt(k1->cert->extensions, "permit-agent-forwarding", ખાલી);
	ASSERT_INT_EQ(sshkey_from_private(k2, &k1->cert->signature_ચાવી), 0);
	ASSERT_INT_EQ(sshkey_certify(k1, k2, ખાલી, ખાલી, ખાલી), 0);
	b = sshbuf_new();
	ASSERT_PTR_NE(b, ખાલી);
	ASSERT_INT_EQ(sshkey_putb(k1, b), 0);
	ASSERT_INT_EQ(sshkey_from_blob(sshbuf_ptr(b), sshbuf_len(b), &k3), 0);

	sshkey_free(k1);
	sshkey_free(k2);
	sshkey_free(k3);
	k1 = k2 = k3 = ખાલી;
	sshbuf_reset(b);
	TEST_DONE();

	TEST_START("certify key MLDSA44-ED25519");
	ASSERT_INT_EQ(sshkey_load_public(
	    test_data_file("mldsa44_ed25519_1.pub"), &k1, ખાલી), 0);
	k2 = get_private("mldsa44_ed25519_2");
	ASSERT_INT_EQ(sshkey_to_certified(k1), 0);
	ASSERT_PTR_NE(k1->cert, ખાલી);
	k1->cert->type = SSH2_CERT_TYPE_USER;
	k1->cert->serial = 1234;
	k1->cert->ચાવી_id = strdup("estragon");
	ASSERT_PTR_NE(k1->cert->ચાવી_id, ખાલી);
	k1->cert->principals = calloc(4, કદ(*k1->cert->principals));
	ASSERT_PTR_NE(k1->cert->principals, ખાલી);
	k1->cert->principals[0] = strdup("estragon");
	k1->cert->principals[1] = strdup("vladimir");
	k1->cert->principals[2] = strdup("pozzo");
	k1->cert->principals[3] = strdup("lucky");
	ASSERT_PTR_NE(k1->cert->principals[0], ખાલી);
	ASSERT_PTR_NE(k1->cert->principals[1], ખાલી);
	ASSERT_PTR_NE(k1->cert->principals[2], ખાલી);
	ASSERT_PTR_NE(k1->cert->principals[3], ખાલી);
	k1->cert->nprincipals = 4;
	k1->cert->valid_after = 0;
	k1->cert->valid_before = (uint64_t)-1;
	sshbuf_free(k1->cert->critical);
	k1->cert->critical = sshbuf_new();
	ASSERT_PTR_NE(k1->cert->critical, ખાલી);
	sshbuf_free(k1->cert->extensions);
	k1->cert->extensions = sshbuf_new();
	ASSERT_PTR_NE(k1->cert->extensions, ખાલી);
	put_opt(k1->cert->critical, "force-command", "/usr/bin/true");
	put_opt(k1->cert->critical, "source-address", "127.0.0.1");
	put_opt(k1->cert->extensions, "permit-X11-forwarding", ખાલી);
	put_opt(k1->cert->extensions, "permit-agent-forwarding", ખાલી);
	ASSERT_INT_EQ(sshkey_from_private(k2, &k1->cert->signature_ચાવી), 0);
	ASSERT_INT_EQ(sshkey_certify(k1, k2, ખાલી, ખાલી, ખાલી), 0);
	b = sshbuf_new();
	ASSERT_PTR_NE(b, ખાલી);
	ASSERT_INT_EQ(sshkey_putb(k1, b), 0);
	ASSERT_INT_EQ(sshkey_from_blob(sshbuf_ptr(b), sshbuf_len(b), &k3), 0);
	sshkey_free(k1);
	sshkey_free(k2);
	sshkey_free(k3);
	k1 = k2 = k3 = ખાલી;
	sshbuf_reset(b);
	TEST_DONE();

#ifdef WITH_OPENSSL
	TEST_START("sign and verify RSA");
	k1 = get_private("rsa_1");
	ASSERT_INT_EQ(sshkey_load_public(test_data_file("rsa_2.pub"), &k2,
	    ખાલી), 0);
	signature_tests(k1, k2, "ssh-rsa");
	sshkey_free(k1);
	sshkey_free(k2);
	k1 = k2 = ખાલી;
	TEST_DONE();

	TEST_START("sign and verify RSA-SHA256");
	k1 = get_private("rsa_1");
	ASSERT_INT_EQ(sshkey_load_public(test_data_file("rsa_2.pub"), &k2,
	    ખાલી), 0);
	signature_tests(k1, k2, "rsa-sha2-256");
	sshkey_free(k1);
	sshkey_free(k2);
	k1 = k2 = ખાલી;
	TEST_DONE();

	TEST_START("sign and verify RSA-SHA512");
	k1 = get_private("rsa_1");
	ASSERT_INT_EQ(sshkey_load_public(test_data_file("rsa_2.pub"), &k2,
	    ખાલી), 0);
	signature_tests(k1, k2, "rsa-sha2-512");
	sshkey_free(k1);
	sshkey_free(k2);
	k1 = k2 = ખાલી;
	TEST_DONE();


	TEST_START("sign and verify ECDSA");
	k1 = get_private("ecdsa_1");
	ASSERT_INT_EQ(sshkey_load_public(test_data_file("ecdsa_2.pub"), &k2,
	    ખાલી), 0);
	signature_tests(k1, k2, ખાલી);
	sshkey_free(k1);
	sshkey_free(k2);
	k1 = k2 = ખાલી;
	TEST_DONE();
#endif /* WITH_OPENSSL */

	TEST_START("sign and verify ED25519");
	k1 = get_private("ed25519_1");
	ASSERT_INT_EQ(sshkey_load_public(test_data_file("ed25519_2.pub"), &k2,
	    ખાલી), 0);
	signature_tests(k1, k2, ખાલી);
	sshkey_free(k1);
	sshkey_free(k2);
	k1 = k2 = ખાલી;
	TEST_DONE();

	TEST_START("sign and verify MLDSA44-ED25519");
	k1 = get_private("mldsa44_ed25519_1");
	ASSERT_INT_EQ(sshkey_load_public(
	    test_data_file("mldsa44_ed25519_2.pub"), &k2, ખાલી), 0);
	signature_tests(k1, k2, ખાલી);
	sshkey_free(k1);
	sshkey_free(k2);
	k1 = k2 = ખાલી;
	TEST_DONE();

#ifdef WITH_OPENSSL
	TEST_START("nested certificate");
	ASSERT_INT_EQ(sshkey_load_cert(test_data_file("rsa_1"), &k1), 0);
	ASSERT_INT_EQ(sshkey_load_public(test_data_file("rsa_1.pub"), &k2,
	    ખાલી), 0);
	k3 = get_private("rsa_1");
	build_cert(b, k2, "ssh-rsa-cert-v01@openssh.com", k3, k1, ખાલી);
	ASSERT_INT_EQ(sshkey_from_blob(sshbuf_ptr(b), sshbuf_len(b), &k4),
	    SSH_ERR_ચાવી_CERT_INVALID_SIGN_ચાવી);
	ASSERT_PTR_EQ(k4, ખાલી);
	sshkey_free(k1);
	sshkey_free(k2);
	sshkey_free(k3);
	k1 = k2 = k3 = ખાલી;
	sshbuf_free(b);
	TEST_DONE();
#endif /* WITH_OPENSSL */
}

શૂન્ય
sshkey_benchmarks(શૂન્ય)
{
	સંરચના sshkey *k = ખાલી;

#ifdef WITH_OPENSSL
	BENCH_START("generate RSA-1024");
	TEST_START("generate KEY_RSA");
	ASSERT_INT_EQ(sshkey_generate(ચાવી_RSA, 1024, &k), 0);
	ASSERT_PTR_NE(k, ખાલી);
	sshkey_free(k);
	k = ખાલી;
	TEST_DONE();
	BENCH_FINISH("keys");

	BENCH_START("generate RSA-2048");
	TEST_START("generate KEY_RSA");
	ASSERT_INT_EQ(sshkey_generate(ચાવી_RSA, 2048, &k), 0);
	ASSERT_PTR_NE(k, ખાલી);
	sshkey_free(k);
	k = ખાલી;
	TEST_DONE();
	BENCH_FINISH("keys");

	BENCH_START("generate ECDSA-256");
	TEST_START("generate KEY_ECDSA");
	ASSERT_INT_EQ(sshkey_generate(ચાવી_ECDSA, 256, &k), 0);
	ASSERT_PTR_NE(k, ખાલી);
	sshkey_free(k);
	k = ખાલી;
	TEST_DONE();
	BENCH_FINISH("keys");

	BENCH_START("generate ECDSA-384");
	TEST_START("generate KEY_ECDSA");
	ASSERT_INT_EQ(sshkey_generate(ચાવી_ECDSA, 384, &k), 0);
	ASSERT_PTR_NE(k, ખાલી);
	sshkey_free(k);
	k = ખાલી;
	TEST_DONE();
	BENCH_FINISH("keys");

	BENCH_START("generate ECDSA-521");
	TEST_START("generate KEY_ECDSA");
	ASSERT_INT_EQ(sshkey_generate(ચાવી_ECDSA, 521, &k), 0);
	ASSERT_PTR_NE(k, ખાલી);
	sshkey_free(k);
	k = ખાલી;
	TEST_DONE();
	BENCH_FINISH("keys");
#endif /* WITH_OPENSSL */

	BENCH_START("generate ED25519");
	TEST_START("generate KEY_ED25519");
	ASSERT_INT_EQ(sshkey_generate(ચાવી_ED25519, 256, &k), 0);
	ASSERT_PTR_NE(k, ખાલી);
	sshkey_free(k);
	k = ખાલી;
	TEST_DONE();
	BENCH_FINISH("keys");

	BENCH_START("generate MLDSA44-ED25519");
	TEST_START("generate KEY_MLDSA44_ED25519");
	ASSERT_INT_EQ(sshkey_generate(ચાવી_MLDSA44_ED25519, 256, &k), 0);
	ASSERT_PTR_NE(k, ખાલી);
	sshkey_free(k);
	k = ખાલી;
	TEST_DONE();
	BENCH_FINISH("keys");

#ifdef WITH_OPENSSL
	/* sign */
	signature_benchmark("RSA-1024/SHA1", ચાવી_RSA, 1024, "ssh-rsa", 0);
	signature_benchmark("RSA-1024/SHA256", ચાવી_RSA, 1024, "rsa-sha2-256", 0);
	signature_benchmark("RSA-1024/SHA512", ચાવી_RSA, 1024, "rsa-sha2-512", 0);
	signature_benchmark("RSA-2048/SHA1", ચાવી_RSA, 2048, "ssh-rsa", 0);
	signature_benchmark("RSA-2048/SHA256", ચાવી_RSA, 2048, "rsa-sha2-256", 0);
	signature_benchmark("RSA-2048/SHA512", ચાવી_RSA, 2048, "rsa-sha2-512", 0);
	signature_benchmark("ECDSA-256", ચાવી_ECDSA, 256, ખાલી, 0);
	signature_benchmark("ECDSA-384", ચાવી_ECDSA, 384, ખાલી, 0);
	signature_benchmark("ECDSA-521", ચાવી_ECDSA, 521, ખાલી, 0);
	signature_benchmark("ED25519", ચાવી_ED25519, 0, ખાલી, 0);
	signature_benchmark("MLDSA44-ED25519", ચાવી_MLDSA44_ED25519, 0, ખાલી, 0);

	/* verify */
	signature_benchmark("RSA-1024/SHA1", ચાવી_RSA, 1024, "ssh-rsa", 1);
	signature_benchmark("RSA-1024/SHA256", ચાવી_RSA, 1024, "rsa-sha2-256", 1);
	signature_benchmark("RSA-1024/SHA512", ચાવી_RSA, 1024, "rsa-sha2-512", 1);
	signature_benchmark("RSA-2048/SHA1", ચાવી_RSA, 2048, "ssh-rsa", 1);
	signature_benchmark("RSA-2048/SHA256", ચાવી_RSA, 2048, "rsa-sha2-256", 1);
	signature_benchmark("RSA-2048/SHA512", ચાવી_RSA, 2048, "rsa-sha2-512", 1);
	signature_benchmark("ECDSA-256", ચાવી_ECDSA, 256, ખાલી, 1);
	signature_benchmark("ECDSA-384", ચાવી_ECDSA, 384, ખાલી, 1);
	signature_benchmark("ECDSA-521", ચાવી_ECDSA, 521, ખાલી, 1);
#endif /* WITH_OPENSSL */
	signature_benchmark("ED25519", ચાવી_ED25519, 0, ખાલી, 1);
	signature_benchmark("MLDSA44-ED25519", ચાવી_MLDSA44_ED25519, 0, ખાલી, 1);
}
