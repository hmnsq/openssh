/* 	$OpenBSD: test_sshkey.c,v 1.34 2026/06/14 04:08:06 djm Exp $ */
/*
 * Regress test for sshkey.h key management API
 *
 * Placed in the public domain
 */

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stdint.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
#ಅನ್ತರ್ಭಾವ <openssl/bn.h>
#ಅನ್ತರ್ಭಾವ <openssl/ec.h>
#ಅನ್ತರ್ಭಾವ <openssl/rsa.h>
#ಆದರೆ_ಅಂತ್ಯ

#ಅನ್ತರ್ಭಾವ "../test_helper/test_helper.h"

#ಅನ್ತರ್ಭಾವ "ssherr.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ವ್ಯಾಖ್ಯಾನಿಸು SSHBUF_ಆಂತರಿಕ 1	/* access internals for testing */
#ಅನ್ತರ್ಭಾವ "sshkey.h"

#ಅನ್ತರ್ಭಾವ "authfile.h"
#ಅನ್ತರ್ಭಾವ "common.h"
#ಅನ್ತರ್ಭಾವ "ssh2.h"

ಶೂನ್ಯ sshkey_tests(ಶೂನ್ಯ);
ಶೂನ್ಯ sshkey_benchmarks(ಶೂನ್ಯ);

ಸ್ಥಿರ ಶೂನ್ಯ
put_opt(ರಚನೆ sshbuf *b, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *name, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮೌಲ್ಯ)
{
	ರಚನೆ sshbuf *sect;

	sect = sshbuf_new();
	ASSERT_PTR_NE(sect, ಖಾಲಿ);
	ASSERT_INT_EQ(sshbuf_put_cstring(b, name), 0);
	ಆದರೆ (ಮೌಲ್ಯ != ಖಾಲಿ)
		ASSERT_INT_EQ(sshbuf_put_cstring(sect, ಮೌಲ್ಯ), 0);
	ASSERT_INT_EQ(sshbuf_put_stringb(b, sect), 0);
	sshbuf_free(sect);
}

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
ಸ್ಥಿರ ಶೂನ್ಯ
build_cert(ರಚನೆ sshbuf *b, ರಚನೆ sshkey *k, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *type,
    ರಚನೆ sshkey *sign_ಕೀಲಿ, ರಚನೆ sshkey *ca_ಕೀಲಿ,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *sig_alg)
{
	ರಚನೆ sshbuf *ca_buf, *pk, *principals, *critopts, *exts;
	u_char *sigblob;
	ಗಾತ್ರ_t siglen;

	ca_buf = sshbuf_new();
	ASSERT_PTR_NE(ca_buf, ಖಾಲಿ);
	ASSERT_INT_EQ(sshkey_putb(ca_ಕೀಲಿ, ca_buf), 0);

	/*
	 * Get the public key serialisation by rendering the key and skipping
	 * the type string. This is a bit of a hack :/
	 */
	pk = sshbuf_new();
	ASSERT_PTR_NE(pk, ಖಾಲಿ);
	ASSERT_INT_EQ(sshkey_putb_plain(k, pk), 0);
	ASSERT_INT_EQ(sshbuf_skip_string(pk), 0);

	principals = sshbuf_new();
	ASSERT_PTR_NE(principals, ಖಾಲಿ);
	ASSERT_INT_EQ(sshbuf_put_cstring(principals, "gsamsa"), 0);
	ASSERT_INT_EQ(sshbuf_put_cstring(principals, "gregor"), 0);

	critopts = sshbuf_new();
	ASSERT_PTR_NE(critopts, ಖಾಲಿ);
	put_opt(critopts, "force-command", "/usr/local/bin/nethack");
	put_opt(critopts, "source-address", "192.168.0.0/24,127.0.0.1,::1");

	exts = sshbuf_new();
	ASSERT_PTR_NE(exts, ಖಾಲಿ);
	put_opt(critopts, "permit-X11-forwarding", ಖಾಲಿ);

	ASSERT_INT_EQ(sshbuf_put_cstring(b, type), 0);
	ASSERT_INT_EQ(sshbuf_put_cstring(b, "noncenoncenonce!"), 0); /* nonce */
	ASSERT_INT_EQ(sshbuf_putb(b, pk), 0); /* public key serialisation */
	ASSERT_INT_EQ(sshbuf_put_u64(b, 1234), 0); /* serial */
	ASSERT_INT_EQ(sshbuf_put_u32(b, SSH2_CERT_TYPE_USER), 0); /* type */
	ASSERT_INT_EQ(sshbuf_put_cstring(b, "gregor"), 0); /* key ID */
	ASSERT_INT_EQ(sshbuf_put_stringb(b, principals), 0); /* principals */
	ASSERT_INT_EQ(sshbuf_put_u64(b, 0), 0); /*ಆರಂಭ*/
	ASSERT_INT_EQ(sshbuf_put_u64(b, 0xffffffffffffffffULL), 0); /*ಕೊನೆ*/
	ASSERT_INT_EQ(sshbuf_put_stringb(b, critopts), 0); /* options */
	ASSERT_INT_EQ(sshbuf_put_stringb(b, exts), 0); /* extensions */
	ASSERT_INT_EQ(sshbuf_put_string(b, ಖಾಲಿ, 0), 0); /* reserved */
	ASSERT_INT_EQ(sshbuf_put_stringb(b, ca_buf), 0); /* signature key */
	ASSERT_INT_EQ(sshkey_sign(sign_ಕೀಲಿ, &sigblob, &siglen,
	    sshbuf_ptr(b), sshbuf_len(b), sig_alg, ಖಾಲಿ, ಖಾಲಿ, 0), 0);
	ASSERT_INT_EQ(sshbuf_put_string(b, sigblob, siglen), 0); /* signature */

	ಬಿಡುಗಡೆ(sigblob);
	sshbuf_free(ca_buf);
	sshbuf_free(exts);
	sshbuf_free(critopts);
	sshbuf_free(principals);
	sshbuf_free(pk);
}
#ಆದರೆ_ಅಂತ್ಯ /* WITH_OPENSSL */

ಸ್ಥಿರ ಶೂನ್ಯ
signature_test(ರಚನೆ sshkey *k, ರಚನೆ sshkey *bad, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *sig_alg,
    ಸ್ಥಿರಾಂಕ u_char *d, ಗಾತ್ರ_t l)
{
	ಗಾತ್ರ_t len;
	u_char *sig;

	ASSERT_INT_EQ(sshkey_sign(k, &sig, &len, d, l, sig_alg,
	    ಖಾಲಿ, ಖಾಲಿ, 0), 0);
	ASSERT_ಗಾತ್ರ_T_GT(len, 8);
	ASSERT_PTR_NE(sig, ಖಾಲಿ);
	ASSERT_INT_EQ(sshkey_verify(k, sig, len, d, l, ಖಾಲಿ, 0, ಖಾಲಿ), 0);
	ASSERT_INT_NE(sshkey_verify(bad, sig, len, d, l, ಖಾಲಿ, 0, ಖಾಲಿ), 0);
	/* Fuzz test is more comprehensive, this is just a smoke test */
	sig[len - 5] ^= 0x10;
	ASSERT_INT_NE(sshkey_verify(k, sig, len, d, l, ಖಾಲಿ, 0, ಖಾಲಿ), 0);
	ಬಿಡುಗಡೆ(sig);
}

ಸ್ಥಿರ ಶೂನ್ಯ
signature_bench(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *name, ಪೂರ್ಣಾಂಕ ktype, ಪೂರ್ಣಾಂಕ ಬಿಟ್ಟುಗಳು, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *sig_alg,
    ಸ್ಥಿರಾಂಕ u_char *d, ಗಾತ್ರ_t l)
{
	ರಚನೆ sshkey *k;
	ಗಾತ್ರ_t len;
	u_char *sig;
	ಅಕ್ಷರ testname[256];

	snprintf(testname, ಗಾತ್ರ(testname), "sign %s", name);
	TEST_ಆರಂಭ(testname);
	ASSERT_INT_EQ(sshkey_generate(ktype, ಬಿಟ್ಟುಗಳು, &k), 0);
	ASSERT_PTR_NE(k, ಖಾಲಿ);

	BENCH_ಆರಂಭ(testname);
	ASSERT_INT_EQ(sshkey_sign(k, &sig, &len, d, l, sig_alg,
	    ಖಾಲಿ, ಖಾಲಿ, 0), 0);
	ಬಿಡುಗಡೆ(sig);
	BENCH_ಮುಕ್ತಾಯ("sign");

	sshkey_free(k);
	TEST_ಮುಗಿದ();
}

ಸ್ಥಿರ ಶೂನ್ಯ
verify_bench(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *name, ಪೂರ್ಣಾಂಕ ktype, ಪೂರ್ಣಾಂಕ ಬಿಟ್ಟುಗಳು, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *sig_alg,
    ಸ್ಥಿರಾಂಕ u_char *d, ಗಾತ್ರ_t l)
{
	ರಚನೆ sshkey *k;
	ಗಾತ್ರ_t len;
	u_char *sig;
	ಅಕ್ಷರ testname[256];

	snprintf(testname, ಗಾತ್ರ(testname), "verify %s", name);
	TEST_ಆರಂಭ(testname);
	ASSERT_INT_EQ(sshkey_generate(ktype, ಬಿಟ್ಟುಗಳು, &k), 0);
	ASSERT_PTR_NE(k, ಖಾಲಿ);

	ASSERT_INT_EQ(sshkey_sign(k, &sig, &len, d, l, sig_alg,
	    ಖಾಲಿ, ಖಾಲಿ, 0), 0);
	BENCH_ಆರಂಭ(testname);
	ASSERT_INT_EQ(sshkey_verify(k, sig, len, d, l, ಖಾಲಿ, 0, ಖಾಲಿ), 0);
	BENCH_ಮುಕ್ತಾಯ("verify");

	ಬಿಡುಗಡೆ(sig);
	sshkey_free(k);
	TEST_ಮುಗಿದ();
}

ಸ್ಥಿರ ಶೂನ್ಯ
banana(u_char *s, ಗಾತ್ರ_t l)
{
	ಗಾತ್ರ_t o;
	ಸ್ಥಿರಾಂಕ u_char the_banana[] = { 'b', 'a', 'n', 'a', 'n', 'a' };

	ಗಾಗಿ (o = 0; o < l; o += ಗಾತ್ರ(the_banana)) {
		ಆದರೆ (l - o < ಗಾತ್ರ(the_banana)) {
			ಸ್ಮರಣೆ_ನಕಲು(s + o, "nanananana", l - o);
			ನಿಲ್ಲಿಸು;
		}
		ಸ್ಮರಣೆ_ನಕಲು(s + o, the_banana, ಗಾತ್ರ(the_banana));
	}
}

ಸ್ಥಿರ ಶೂನ್ಯ
signature_tests(ರಚನೆ sshkey *k, ರಚನೆ sshkey *bad, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *sig_alg)
{
	u_char i, buf[2049];
	ಗಾತ್ರ_t lens[] = {
		1, 2, 7, 8, 9, 15, 16, 17, 31, 32, 33, 127, 128, 129,
		255, 256, 257, 1023, 1024, 1025, 2047, 2048, 2049
	};

	ಗಾಗಿ (i = 0; i < (ಗಾತ್ರ(lens)/ಗಾತ್ರ(lens[0])); i++) {
		test_subtest_info("%s key, banana length %zu",
		    sshkey_type(k), lens[i]);
		banana(buf, lens[i]);
		signature_test(k, bad, sig_alg, buf, lens[i]);
	}
}

ಸ್ಥಿರ ಶೂನ್ಯ
signature_benchmark(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *name, ಪೂರ್ಣಾಂಕ ktype, ಪೂರ್ಣಾಂಕ ಬಿಟ್ಟುಗಳು,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *sig_alg, ಪೂರ್ಣಾಂಕ bench_verify)
{
	u_char buf[256];

	banana(buf, ಗಾತ್ರ(buf));
	ಆದರೆ (bench_verify)
		verify_bench(name, ktype, ಬಿಟ್ಟುಗಳು, sig_alg, buf, ಗಾತ್ರ(buf));
	ಇಲ್ಲದಿದ್ದರೆ
		signature_bench(name, ktype, ಬಿಟ್ಟುಗಳು, sig_alg, buf, ಗಾತ್ರ(buf));
}

ಸ್ಥಿರ ರಚನೆ sshkey *
get_ಖಾಸಗಿ(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *n)
{
	ರಚನೆ sshbuf *b;
	ರಚನೆ sshkey *ret;

	b = ತುಂಬು_file(n);
	ASSERT_INT_EQ(sshkey_parse_ಖಾಸಗಿ_fileblob(b, "", &ret, ಖಾಲಿ), 0);
	sshbuf_free(b);
	ಹಿಂತಿರುಗಿ ret;
}

ಶೂನ್ಯ
sshkey_tests(ಶೂನ್ಯ)
{
	ರಚನೆ sshkey *k1 = ಖಾಲಿ, *k2 = ಖಾಲಿ, *k3 = ಖಾಲಿ, *k4 = ಖಾಲಿ;
	ರಚನೆ sshkey *kr = ಖಾಲಿ, *kd = ಖಾಲಿ, *ke = ಖಾಲಿ, *kf = ಖಾಲಿ;
	ರಚನೆ sshbuf *b = ಖಾಲಿ;

	TEST_ಆರಂಭ("new invalid");
	k1 = sshkey_new(-42);
	ASSERT_PTR_EQ(k1, ಖಾಲಿ);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("new/free KEY_UNSPEC");
	k1 = sshkey_new(ಕೀಲಿ_UNSPEC);
	ASSERT_PTR_NE(k1, ಖಾಲಿ);
	sshkey_free(k1);
	k1 = ಖಾಲಿ;
	TEST_ಮುಗಿದ();

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
	TEST_ಆರಂಭ("new/free KEY_RSA");
	k1 = sshkey_new(ಕೀಲಿ_RSA);
	ASSERT_PTR_NE(k1, ಖಾಲಿ);
	ASSERT_PTR_NE(k1->pkey, ಖಾಲಿ);
	sshkey_free(k1);
	k1 = ಖಾಲಿ;
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("new/free KEY_ECDSA");
	k1 = sshkey_new(ಕೀಲಿ_ECDSA);
	ASSERT_PTR_NE(k1, ಖಾಲಿ);
	ASSERT_PTR_EQ(k1->pkey, ಖಾಲಿ);  /* Can't allocate without NID */
	sshkey_free(k1);
	k1 = ಖಾಲಿ;
	TEST_ಮುಗಿದ();
#ಆದರೆ_ಅಂತ್ಯ /* WITH_OPENSSL */

	TEST_ಆರಂಭ("new/free KEY_ED25519");
	k1 = sshkey_new(ಕೀಲಿ_ED25519);
	ASSERT_PTR_NE(k1, ಖಾಲಿ);
	/* These should be blank until key loaded or generated */
	ASSERT_PTR_EQ(k1->ed25519_sk, ಖಾಲಿ);
	ASSERT_PTR_EQ(k1->ed25519_pk, ಖಾಲಿ);
	sshkey_free(k1);
	k1 = ಖಾಲಿ;
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("new/free KEY_MLDSA44_ED25519");
	k1 = sshkey_new(ಕೀಲಿ_MLDSA44_ED25519);
	ASSERT_PTR_NE(k1, ಖಾಲಿ);
	ASSERT_PTR_EQ(k1->mldsa_ed25519_sk, ಖಾಲಿ);
	ASSERT_PTR_EQ(k1->mldsa_ed25519_pk, ಖಾಲಿ);
	sshkey_free(k1);
	k1 = ಖಾಲಿ;
	TEST_ಮುಗಿದ();

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
	TEST_ಆರಂಭ("generate KEY_RSA too small modulus");
	ASSERT_INT_EQ(sshkey_generate(ಕೀಲಿ_RSA, 128, &k1),
	    SSH_ERR_ಕೀಲಿ_ಉದ್ದಳತೆ);
	ASSERT_PTR_EQ(k1, ಖಾಲಿ);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("generate KEY_RSA too large modulus");
	ASSERT_INT_EQ(sshkey_generate(ಕೀಲಿ_RSA, 1 << 20, &k1),
	    SSH_ERR_ಕೀಲಿ_ಉದ್ದಳತೆ);
	ASSERT_PTR_EQ(k1, ಖಾಲಿ);
	TEST_ಮುಗಿದ();


	TEST_ಆರಂಭ("generate KEY_ECDSA wrong bits");
	ASSERT_INT_EQ(sshkey_generate(ಕೀಲಿ_ECDSA, 42, &k1),
	    SSH_ERR_ಕೀಲಿ_ಉದ್ದಳತೆ);
	ASSERT_PTR_EQ(k1, ಖಾಲಿ);
	sshkey_free(k1);
	k1 = ಖಾಲಿ;
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("generate KEY_RSA");
	ASSERT_INT_EQ(sshkey_generate(ಕೀಲಿ_RSA, 767, &kr),
	    SSH_ERR_ಕೀಲಿ_ಉದ್ದಳತೆ);
	ASSERT_INT_EQ(sshkey_generate(ಕೀಲಿ_RSA, 1024, &kr), 0);
	ASSERT_PTR_NE(kr, ಖಾಲಿ);
	ASSERT_PTR_NE(EVP_PKEY_get0_RSA(kr->pkey), ಖಾಲಿ);
	ASSERT_PTR_NE(rsa_n(kr), ಖಾಲಿ);
	ASSERT_PTR_NE(rsa_e(kr), ಖಾಲಿ);
	ASSERT_PTR_NE(rsa_p(kr), ಖಾಲಿ);
	ASSERT_INT_EQ(BN_ಅಂಕೆ_ಬಿಟ್ಟುಗಳು(rsa_n(kr)), 1024);
	TEST_ಮುಗಿದ();


	TEST_ಆರಂಭ("generate KEY_ECDSA");
	ASSERT_INT_EQ(sshkey_generate(ಕೀಲಿ_ECDSA, 256, &ke), 0);
	ASSERT_PTR_NE(ke, ಖಾಲಿ);
	ASSERT_PTR_NE(EVP_PKEY_get0_EC_ಕೀಲಿ(ke->pkey), ಖಾಲಿ);
	ASSERT_PTR_NE(EC_ಕೀಲಿ_get0_ಬಹಿರಂಗ_ಕೀಲಿ(EVP_PKEY_get0_EC_ಕೀಲಿ(ke->pkey)),
	    ಖಾಲಿ);
	ASSERT_PTR_NE(EC_ಕೀಲಿ_get0_ಖಾಸಗಿ_ಕೀಲಿ(EVP_PKEY_get0_EC_ಕೀಲಿ(ke->pkey)),
	    ಖಾಲಿ);
	TEST_ಮುಗಿದ();
#ಆದರೆ_ಅಂತ್ಯ /* WITH_OPENSSL */

	TEST_ಆರಂಭ("generate KEY_ED25519");
	ASSERT_INT_EQ(sshkey_generate(ಕೀಲಿ_ED25519, 256, &kf), 0);
	ASSERT_PTR_NE(kf, ಖಾಲಿ);
	ASSERT_INT_EQ(kf->type, ಕೀಲಿ_ED25519);
	ASSERT_PTR_NE(kf->ed25519_pk, ಖಾಲಿ);
	ASSERT_PTR_NE(kf->ed25519_sk, ಖಾಲಿ);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("generate KEY_MLDSA44_ED25519");
	ASSERT_INT_EQ(sshkey_generate(ಕೀಲಿ_MLDSA44_ED25519, 256, &k1), 0);
	ASSERT_PTR_NE(k1, ಖಾಲಿ);
	ASSERT_INT_EQ(k1->type, ಕೀಲಿ_MLDSA44_ED25519);
	ASSERT_PTR_NE(k1->mldsa_ed25519_pk, ಖಾಲಿ);
	ASSERT_PTR_NE(k1->mldsa_ed25519_sk, ಖಾಲಿ);
	sshkey_free(k1);
	k1 = ಖಾಲಿ;
	TEST_ಮುಗಿದ();

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
	TEST_ಆರಂಭ("demote KEY_RSA");
	ASSERT_INT_EQ(sshkey_from_ಖಾಸಗಿ(kr, &k1), 0);
	ASSERT_PTR_NE(k1, ಖಾಲಿ);
	ASSERT_PTR_NE(kr, k1);
	ASSERT_INT_EQ(k1->type, ಕೀಲಿ_RSA);
	ASSERT_PTR_NE(EVP_PKEY_get0_RSA(k1->pkey), ಖಾಲಿ);
	ASSERT_PTR_NE(rsa_n(k1), ಖಾಲಿ);
	ASSERT_PTR_NE(rsa_e(k1), ಖಾಲಿ);
	ASSERT_PTR_EQ(rsa_p(k1), ಖಾಲಿ);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("equal KEY_RSA/demoted KEY_RSA");
	ASSERT_INT_EQ(sshkey_equal(kr, k1), 1);
	sshkey_free(k1);
	k1 = ಖಾಲಿ;
	TEST_ಮುಗಿದ();


	TEST_ಆರಂಭ("demote KEY_ECDSA");
	ASSERT_INT_EQ(sshkey_from_ಖಾಸಗಿ(ke, &k1), 0);
	ASSERT_PTR_NE(k1, ಖಾಲಿ);
	ASSERT_PTR_NE(ke, k1);
	ASSERT_INT_EQ(k1->type, ಕೀಲಿ_ECDSA);
	ASSERT_PTR_NE(EVP_PKEY_get0_EC_ಕೀಲಿ(k1->pkey), ಖಾಲಿ);
	ASSERT_INT_EQ(k1->ecdsa_nid, ke->ecdsa_nid);
	ASSERT_PTR_NE(EC_ಕೀಲಿ_get0_ಬಹಿರಂಗ_ಕೀಲಿ(EVP_PKEY_get0_EC_ಕೀಲಿ(ke->pkey)),
	   ಖಾಲಿ);
	ASSERT_PTR_EQ(EC_ಕೀಲಿ_get0_ಖಾಸಗಿ_ಕೀಲಿ(EVP_PKEY_get0_EC_ಕೀಲಿ(k1->pkey)),
	   ಖಾಲಿ);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("equal KEY_ECDSA/demoted KEY_ECDSA");
	ASSERT_INT_EQ(sshkey_equal(ke, k1), 1);
	sshkey_free(k1);
	k1 = ಖಾಲಿ;
	TEST_ಮುಗಿದ();
#ಆದರೆ_ಅಂತ್ಯ /* WITH_OPENSSL */

	TEST_ಆರಂಭ("demote KEY_ED25519");
	ASSERT_INT_EQ(sshkey_from_ಖಾಸಗಿ(kf, &k1), 0);
	ASSERT_PTR_NE(k1, ಖಾಲಿ);
	ASSERT_PTR_NE(kf, k1);
	ASSERT_INT_EQ(k1->type, ಕೀಲಿ_ED25519);
	ASSERT_PTR_NE(k1->ed25519_pk, ಖಾಲಿ);
	ASSERT_PTR_EQ(k1->ed25519_sk, ಖಾಲಿ);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("equal KEY_ED25519/demoted KEY_ED25519");
	ASSERT_INT_EQ(sshkey_equal(kf, k1), 1);
	sshkey_free(k1);
	k1 = ಖಾಲಿ;
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("demote KEY_MLDSA44_ED25519");
	ASSERT_INT_EQ(sshkey_generate(ಕೀಲಿ_MLDSA44_ED25519, 256, &k2), 0);
	ASSERT_INT_EQ(sshkey_from_ಖಾಸಗಿ(k2, &k1), 0);
	ASSERT_PTR_NE(k1, ಖಾಲಿ);
	ASSERT_PTR_NE(k2, k1);
	ASSERT_INT_EQ(k1->type, ಕೀಲಿ_MLDSA44_ED25519);
	ASSERT_PTR_NE(k1->mldsa_ed25519_pk, ಖಾಲಿ);
	ASSERT_PTR_EQ(k1->mldsa_ed25519_sk, ಖಾಲಿ);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("equal KEY_MLDSA44_ED25519/demoted KEY_MLDSA44_ED25519");
	ASSERT_INT_EQ(sshkey_equal(k2, k1), 1);
	sshkey_free(k1);
	sshkey_free(k2);
	k1 = k2 = ಖಾಲಿ;
	TEST_ಮುಗಿದ();

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
	TEST_ಆರಂಭ("equal mismatched key types");
	ASSERT_INT_EQ(sshkey_equal(kd, kr), 0);
	ASSERT_INT_EQ(sshkey_equal(kd, ke), 0);
	ASSERT_INT_EQ(sshkey_equal(kr, ke), 0);
	ASSERT_INT_EQ(sshkey_equal(ke, kf), 0);
	ASSERT_INT_EQ(sshkey_equal(kd, kf), 0);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("equal different keys");
	ASSERT_INT_EQ(sshkey_generate(ಕೀಲಿ_RSA, 1024, &k1), 0);
	ASSERT_INT_EQ(sshkey_equal(kr, k1), 0);
	sshkey_free(k1);
	k1 = ಖಾಲಿ;
	ASSERT_INT_EQ(sshkey_generate(ಕೀಲಿ_ECDSA, 256, &k1), 0);
	ASSERT_INT_EQ(sshkey_equal(ke, k1), 0);
	sshkey_free(k1);
	k1 = ಖಾಲಿ;
	ASSERT_INT_EQ(sshkey_generate(ಕೀಲಿ_ED25519, 256, &k1), 0);
	ASSERT_INT_EQ(sshkey_equal(kf, k1), 0);
	sshkey_free(k1);
	k1 = ಖಾಲಿ;
	ASSERT_INT_EQ(sshkey_generate(ಕೀಲಿ_MLDSA44_ED25519, 256, &k1), 0);
	ASSERT_INT_EQ(sshkey_generate(ಕೀಲಿ_MLDSA44_ED25519, 256, &k2), 0);
	ASSERT_INT_EQ(sshkey_equal(k2, k1), 0);
	sshkey_free(k1);
	sshkey_free(k2);
	k1 = k2 = ಖಾಲಿ;
	TEST_ಮುಗಿದ();
#ಆದರೆ_ಅಂತ್ಯ /* WITH_OPENSSL */

	sshkey_free(kr);
	sshkey_free(kd);
	sshkey_free(ke);
	sshkey_free(kf);
	kr = kd = ke = kf = ಖಾಲಿ;

	TEST_ಆರಂಭ("certify key");
	ASSERT_INT_EQ(sshkey_ತುಂಬು_ಬಹಿರಂಗ(test_ದತ್ತಾಂಶ_file("ed25519_1.pub"),
	    &k1, ಖಾಲಿ), 0);
	k2 = get_ಖಾಸಗಿ("ed25519_2");
	ASSERT_INT_EQ(sshkey_ಗಮ್ಯ_certified(k1), 0);
	ASSERT_PTR_NE(k1->cert, ಖಾಲಿ);
	k1->cert->type = SSH2_CERT_TYPE_USER;
	k1->cert->serial = 1234;
	k1->cert->ಕೀಲಿ_id = strdup("estragon");
	ASSERT_PTR_NE(k1->cert->ಕೀಲಿ_id, ಖಾಲಿ);
	k1->cert->principals = ಸೊನ್ನೆ_ಸ್ಮರಣೆ_ಕೊಡು(4, ಗಾತ್ರ(*k1->cert->principals));
	ASSERT_PTR_NE(k1->cert->principals, ಖಾಲಿ);
	k1->cert->principals[0] = strdup("estragon");
	k1->cert->principals[1] = strdup("vladimir");
	k1->cert->principals[2] = strdup("pozzo");
	k1->cert->principals[3] = strdup("lucky");
	ASSERT_PTR_NE(k1->cert->principals[0], ಖಾಲಿ);
	ASSERT_PTR_NE(k1->cert->principals[1], ಖಾಲಿ);
	ASSERT_PTR_NE(k1->cert->principals[2], ಖಾಲಿ);
	ASSERT_PTR_NE(k1->cert->principals[3], ಖಾಲಿ);
	k1->cert->nprincipals = 4;
	k1->cert->valid_after = 0;
	k1->cert->valid_before = (uint64_t)-1;
	sshbuf_free(k1->cert->critical);
	k1->cert->critical = sshbuf_new();
	ASSERT_PTR_NE(k1->cert->critical, ಖಾಲಿ);
	sshbuf_free(k1->cert->extensions);
	k1->cert->extensions = sshbuf_new();
	ASSERT_PTR_NE(k1->cert->extensions, ಖಾಲಿ);
	put_opt(k1->cert->critical, "force-command", "/usr/bin/true");
	put_opt(k1->cert->critical, "source-address", "127.0.0.1");
	put_opt(k1->cert->extensions, "permit-X11-forwarding", ಖಾಲಿ);
	put_opt(k1->cert->extensions, "permit-agent-forwarding", ಖಾಲಿ);
	ASSERT_INT_EQ(sshkey_from_ಖಾಸಗಿ(k2, &k1->cert->signature_ಕೀಲಿ), 0);
	ASSERT_INT_EQ(sshkey_certify(k1, k2, ಖಾಲಿ, ಖಾಲಿ, ಖಾಲಿ), 0);
	b = sshbuf_new();
	ASSERT_PTR_NE(b, ಖಾಲಿ);
	ASSERT_INT_EQ(sshkey_putb(k1, b), 0);
	ASSERT_INT_EQ(sshkey_from_blob(sshbuf_ptr(b), sshbuf_len(b), &k3), 0);

	sshkey_free(k1);
	sshkey_free(k2);
	sshkey_free(k3);
	k1 = k2 = k3 = ಖಾಲಿ;
	sshbuf_reset(b);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("certify key MLDSA44-ED25519");
	ASSERT_INT_EQ(sshkey_ತುಂಬು_ಬಹಿರಂಗ(
	    test_ದತ್ತಾಂಶ_file("mldsa44_ed25519_1.pub"), &k1, ಖಾಲಿ), 0);
	k2 = get_ಖಾಸಗಿ("mldsa44_ed25519_2");
	ASSERT_INT_EQ(sshkey_ಗಮ್ಯ_certified(k1), 0);
	ASSERT_PTR_NE(k1->cert, ಖಾಲಿ);
	k1->cert->type = SSH2_CERT_TYPE_USER;
	k1->cert->serial = 1234;
	k1->cert->ಕೀಲಿ_id = strdup("estragon");
	ASSERT_PTR_NE(k1->cert->ಕೀಲಿ_id, ಖಾಲಿ);
	k1->cert->principals = ಸೊನ್ನೆ_ಸ್ಮರಣೆ_ಕೊಡು(4, ಗಾತ್ರ(*k1->cert->principals));
	ASSERT_PTR_NE(k1->cert->principals, ಖಾಲಿ);
	k1->cert->principals[0] = strdup("estragon");
	k1->cert->principals[1] = strdup("vladimir");
	k1->cert->principals[2] = strdup("pozzo");
	k1->cert->principals[3] = strdup("lucky");
	ASSERT_PTR_NE(k1->cert->principals[0], ಖಾಲಿ);
	ASSERT_PTR_NE(k1->cert->principals[1], ಖಾಲಿ);
	ASSERT_PTR_NE(k1->cert->principals[2], ಖಾಲಿ);
	ASSERT_PTR_NE(k1->cert->principals[3], ಖಾಲಿ);
	k1->cert->nprincipals = 4;
	k1->cert->valid_after = 0;
	k1->cert->valid_before = (uint64_t)-1;
	sshbuf_free(k1->cert->critical);
	k1->cert->critical = sshbuf_new();
	ASSERT_PTR_NE(k1->cert->critical, ಖಾಲಿ);
	sshbuf_free(k1->cert->extensions);
	k1->cert->extensions = sshbuf_new();
	ASSERT_PTR_NE(k1->cert->extensions, ಖಾಲಿ);
	put_opt(k1->cert->critical, "force-command", "/usr/bin/true");
	put_opt(k1->cert->critical, "source-address", "127.0.0.1");
	put_opt(k1->cert->extensions, "permit-X11-forwarding", ಖಾಲಿ);
	put_opt(k1->cert->extensions, "permit-agent-forwarding", ಖಾಲಿ);
	ASSERT_INT_EQ(sshkey_from_ಖಾಸಗಿ(k2, &k1->cert->signature_ಕೀಲಿ), 0);
	ASSERT_INT_EQ(sshkey_certify(k1, k2, ಖಾಲಿ, ಖಾಲಿ, ಖಾಲಿ), 0);
	b = sshbuf_new();
	ASSERT_PTR_NE(b, ಖಾಲಿ);
	ASSERT_INT_EQ(sshkey_putb(k1, b), 0);
	ASSERT_INT_EQ(sshkey_from_blob(sshbuf_ptr(b), sshbuf_len(b), &k3), 0);
	sshkey_free(k1);
	sshkey_free(k2);
	sshkey_free(k3);
	k1 = k2 = k3 = ಖಾಲಿ;
	sshbuf_reset(b);
	TEST_ಮುಗಿದ();

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
	TEST_ಆರಂಭ("sign and verify RSA");
	k1 = get_ಖಾಸಗಿ("rsa_1");
	ASSERT_INT_EQ(sshkey_ತುಂಬು_ಬಹಿರಂಗ(test_ದತ್ತಾಂಶ_file("rsa_2.pub"), &k2,
	    ಖಾಲಿ), 0);
	signature_tests(k1, k2, "ssh-rsa");
	sshkey_free(k1);
	sshkey_free(k2);
	k1 = k2 = ಖಾಲಿ;
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("sign and verify RSA-SHA256");
	k1 = get_ಖಾಸಗಿ("rsa_1");
	ASSERT_INT_EQ(sshkey_ತುಂಬು_ಬಹಿರಂಗ(test_ದತ್ತಾಂಶ_file("rsa_2.pub"), &k2,
	    ಖಾಲಿ), 0);
	signature_tests(k1, k2, "rsa-sha2-256");
	sshkey_free(k1);
	sshkey_free(k2);
	k1 = k2 = ಖಾಲಿ;
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("sign and verify RSA-SHA512");
	k1 = get_ಖಾಸಗಿ("rsa_1");
	ASSERT_INT_EQ(sshkey_ತುಂಬು_ಬಹಿರಂಗ(test_ದತ್ತಾಂಶ_file("rsa_2.pub"), &k2,
	    ಖಾಲಿ), 0);
	signature_tests(k1, k2, "rsa-sha2-512");
	sshkey_free(k1);
	sshkey_free(k2);
	k1 = k2 = ಖಾಲಿ;
	TEST_ಮುಗಿದ();


	TEST_ಆರಂಭ("sign and verify ECDSA");
	k1 = get_ಖಾಸಗಿ("ecdsa_1");
	ASSERT_INT_EQ(sshkey_ತುಂಬು_ಬಹಿರಂಗ(test_ದತ್ತಾಂಶ_file("ecdsa_2.pub"), &k2,
	    ಖಾಲಿ), 0);
	signature_tests(k1, k2, ಖಾಲಿ);
	sshkey_free(k1);
	sshkey_free(k2);
	k1 = k2 = ಖಾಲಿ;
	TEST_ಮುಗಿದ();
#ಆದರೆ_ಅಂತ್ಯ /* WITH_OPENSSL */

	TEST_ಆರಂಭ("sign and verify ED25519");
	k1 = get_ಖಾಸಗಿ("ed25519_1");
	ASSERT_INT_EQ(sshkey_ತುಂಬು_ಬಹಿರಂಗ(test_ದತ್ತಾಂಶ_file("ed25519_2.pub"), &k2,
	    ಖಾಲಿ), 0);
	signature_tests(k1, k2, ಖಾಲಿ);
	sshkey_free(k1);
	sshkey_free(k2);
	k1 = k2 = ಖಾಲಿ;
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("sign and verify MLDSA44-ED25519");
	k1 = get_ಖಾಸಗಿ("mldsa44_ed25519_1");
	ASSERT_INT_EQ(sshkey_ತುಂಬು_ಬಹಿರಂಗ(
	    test_ದತ್ತಾಂಶ_file("mldsa44_ed25519_2.pub"), &k2, ಖಾಲಿ), 0);
	signature_tests(k1, k2, ಖಾಲಿ);
	sshkey_free(k1);
	sshkey_free(k2);
	k1 = k2 = ಖಾಲಿ;
	TEST_ಮುಗಿದ();

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
	TEST_ಆರಂಭ("nested certificate");
	ASSERT_INT_EQ(sshkey_ತುಂಬು_cert(test_ದತ್ತಾಂಶ_file("rsa_1"), &k1), 0);
	ASSERT_INT_EQ(sshkey_ತುಂಬು_ಬಹಿರಂಗ(test_ದತ್ತಾಂಶ_file("rsa_1.pub"), &k2,
	    ಖಾಲಿ), 0);
	k3 = get_ಖಾಸಗಿ("rsa_1");
	build_cert(b, k2, "ssh-rsa-cert-v01@openssh.com", k3, k1, ಖಾಲಿ);
	ASSERT_INT_EQ(sshkey_from_blob(sshbuf_ptr(b), sshbuf_len(b), &k4),
	    SSH_ERR_ಕೀಲಿ_CERT_INVALID_SIGN_ಕೀಲಿ);
	ASSERT_PTR_EQ(k4, ಖಾಲಿ);
	sshkey_free(k1);
	sshkey_free(k2);
	sshkey_free(k3);
	k1 = k2 = k3 = ಖಾಲಿ;
	sshbuf_free(b);
	TEST_ಮುಗಿದ();
#ಆದರೆ_ಅಂತ್ಯ /* WITH_OPENSSL */
}

ಶೂನ್ಯ
sshkey_benchmarks(ಶೂನ್ಯ)
{
	ರಚನೆ sshkey *k = ಖಾಲಿ;

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
	BENCH_ಆರಂಭ("generate RSA-1024");
	TEST_ಆರಂಭ("generate KEY_RSA");
	ASSERT_INT_EQ(sshkey_generate(ಕೀಲಿ_RSA, 1024, &k), 0);
	ASSERT_PTR_NE(k, ಖಾಲಿ);
	sshkey_free(k);
	k = ಖಾಲಿ;
	TEST_ಮುಗಿದ();
	BENCH_ಮುಕ್ತಾಯ("keys");

	BENCH_ಆರಂಭ("generate RSA-2048");
	TEST_ಆರಂಭ("generate KEY_RSA");
	ASSERT_INT_EQ(sshkey_generate(ಕೀಲಿ_RSA, 2048, &k), 0);
	ASSERT_PTR_NE(k, ಖಾಲಿ);
	sshkey_free(k);
	k = ಖಾಲಿ;
	TEST_ಮುಗಿದ();
	BENCH_ಮುಕ್ತಾಯ("keys");

	BENCH_ಆರಂಭ("generate ECDSA-256");
	TEST_ಆರಂಭ("generate KEY_ECDSA");
	ASSERT_INT_EQ(sshkey_generate(ಕೀಲಿ_ECDSA, 256, &k), 0);
	ASSERT_PTR_NE(k, ಖಾಲಿ);
	sshkey_free(k);
	k = ಖಾಲಿ;
	TEST_ಮುಗಿದ();
	BENCH_ಮುಕ್ತಾಯ("keys");

	BENCH_ಆರಂಭ("generate ECDSA-384");
	TEST_ಆರಂಭ("generate KEY_ECDSA");
	ASSERT_INT_EQ(sshkey_generate(ಕೀಲಿ_ECDSA, 384, &k), 0);
	ASSERT_PTR_NE(k, ಖಾಲಿ);
	sshkey_free(k);
	k = ಖಾಲಿ;
	TEST_ಮುಗಿದ();
	BENCH_ಮುಕ್ತಾಯ("keys");

	BENCH_ಆರಂಭ("generate ECDSA-521");
	TEST_ಆರಂಭ("generate KEY_ECDSA");
	ASSERT_INT_EQ(sshkey_generate(ಕೀಲಿ_ECDSA, 521, &k), 0);
	ASSERT_PTR_NE(k, ಖಾಲಿ);
	sshkey_free(k);
	k = ಖಾಲಿ;
	TEST_ಮುಗಿದ();
	BENCH_ಮುಕ್ತಾಯ("keys");
#ಆದರೆ_ಅಂತ್ಯ /* WITH_OPENSSL */

	BENCH_ಆರಂಭ("generate ED25519");
	TEST_ಆರಂಭ("generate KEY_ED25519");
	ASSERT_INT_EQ(sshkey_generate(ಕೀಲಿ_ED25519, 256, &k), 0);
	ASSERT_PTR_NE(k, ಖಾಲಿ);
	sshkey_free(k);
	k = ಖಾಲಿ;
	TEST_ಮುಗಿದ();
	BENCH_ಮುಕ್ತಾಯ("keys");

	BENCH_ಆರಂಭ("generate MLDSA44-ED25519");
	TEST_ಆರಂಭ("generate KEY_MLDSA44_ED25519");
	ASSERT_INT_EQ(sshkey_generate(ಕೀಲಿ_MLDSA44_ED25519, 256, &k), 0);
	ASSERT_PTR_NE(k, ಖಾಲಿ);
	sshkey_free(k);
	k = ಖಾಲಿ;
	TEST_ಮುಗಿದ();
	BENCH_ಮುಕ್ತಾಯ("keys");

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
	/* sign */
	signature_benchmark("RSA-1024/SHA1", ಕೀಲಿ_RSA, 1024, "ssh-rsa", 0);
	signature_benchmark("RSA-1024/SHA256", ಕೀಲಿ_RSA, 1024, "rsa-sha2-256", 0);
	signature_benchmark("RSA-1024/SHA512", ಕೀಲಿ_RSA, 1024, "rsa-sha2-512", 0);
	signature_benchmark("RSA-2048/SHA1", ಕೀಲಿ_RSA, 2048, "ssh-rsa", 0);
	signature_benchmark("RSA-2048/SHA256", ಕೀಲಿ_RSA, 2048, "rsa-sha2-256", 0);
	signature_benchmark("RSA-2048/SHA512", ಕೀಲಿ_RSA, 2048, "rsa-sha2-512", 0);
	signature_benchmark("ECDSA-256", ಕೀಲಿ_ECDSA, 256, ಖಾಲಿ, 0);
	signature_benchmark("ECDSA-384", ಕೀಲಿ_ECDSA, 384, ಖಾಲಿ, 0);
	signature_benchmark("ECDSA-521", ಕೀಲಿ_ECDSA, 521, ಖಾಲಿ, 0);
	signature_benchmark("ED25519", ಕೀಲಿ_ED25519, 0, ಖಾಲಿ, 0);
	signature_benchmark("MLDSA44-ED25519", ಕೀಲಿ_MLDSA44_ED25519, 0, ಖಾಲಿ, 0);

	/* verify */
	signature_benchmark("RSA-1024/SHA1", ಕೀಲಿ_RSA, 1024, "ssh-rsa", 1);
	signature_benchmark("RSA-1024/SHA256", ಕೀಲಿ_RSA, 1024, "rsa-sha2-256", 1);
	signature_benchmark("RSA-1024/SHA512", ಕೀಲಿ_RSA, 1024, "rsa-sha2-512", 1);
	signature_benchmark("RSA-2048/SHA1", ಕೀಲಿ_RSA, 2048, "ssh-rsa", 1);
	signature_benchmark("RSA-2048/SHA256", ಕೀಲಿ_RSA, 2048, "rsa-sha2-256", 1);
	signature_benchmark("RSA-2048/SHA512", ಕೀಲಿ_RSA, 2048, "rsa-sha2-512", 1);
	signature_benchmark("ECDSA-256", ಕೀಲಿ_ECDSA, 256, ಖಾಲಿ, 1);
	signature_benchmark("ECDSA-384", ಕೀಲಿ_ECDSA, 384, ಖಾಲಿ, 1);
	signature_benchmark("ECDSA-521", ಕೀಲಿ_ECDSA, 521, ಖಾಲಿ, 1);
#ಆದರೆ_ಅಂತ್ಯ /* WITH_OPENSSL */
	signature_benchmark("ED25519", ಕೀಲಿ_ED25519, 0, ಖಾಲಿ, 1);
	signature_benchmark("MLDSA44-ED25519", ಕೀಲಿ_MLDSA44_ED25519, 0, ಖಾಲಿ, 1);
}
