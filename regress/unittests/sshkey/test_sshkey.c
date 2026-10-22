/* 	$OpenBSD: test_sshkey.c,v 1.34 2026/06/14 04:08:06 djm Exp $ */
/*
 * Regress test for sshkey.h key management API
 *
 * Placed in the public domain
 */

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdint.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/bn.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/ec.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/rsa.h>
#ਜੇ_ਅੰਤ

#ਅਨ੍ਤਰ੍ਭਾਵ "../test_helper/test_helper.h"

#ਅਨ੍ਤਰ੍ਭਾਵ "ssherr.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshbuf.h"
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHBUF_ਅੰਦਰੂਨੀ 1	/* access internals for testing */
#ਅਨ੍ਤਰ੍ਭਾਵ "sshkey.h"

#ਅਨ੍ਤਰ੍ਭਾਵ "authfile.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "common.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssh2.h"

ਖਾਲੀ sshkey_tests(ਖਾਲੀ);
ਖਾਲੀ sshkey_benchmarks(ਖਾਲੀ);

ਸਥਿਰ ਖਾਲੀ
put_opt(ਬਣਤਰ sshbuf *b, ਅਚਲ ਅੱਖਰ *name, ਅਚਲ ਅੱਖਰ *ਮੁੱਲ)
{
	ਬਣਤਰ sshbuf *sect;

	sect = sshbuf_new();
	ASSERT_PTR_NE(sect, ਨਿਰਾ);
	ASSERT_INT_EQ(sshbuf_put_cstring(b, name), 0);
	ਜੇ (ਮੁੱਲ != ਨਿਰਾ)
		ASSERT_INT_EQ(sshbuf_put_cstring(sect, ਮੁੱਲ), 0);
	ASSERT_INT_EQ(sshbuf_put_stringb(b, sect), 0);
	sshbuf_free(sect);
}

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
ਸਥਿਰ ਖਾਲੀ
build_cert(ਬਣਤਰ sshbuf *b, ਬਣਤਰ sshkey *k, ਅਚਲ ਅੱਖਰ *type,
    ਬਣਤਰ sshkey *sign_ਕੁੰਜੀ, ਬਣਤਰ sshkey *ca_ਕੁੰਜੀ,
    ਅਚਲ ਅੱਖਰ *sig_alg)
{
	ਬਣਤਰ sshbuf *ca_buf, *pk, *principals, *critopts, *exts;
	u_char *sigblob;
	ਮਾਪ_t siglen;

	ca_buf = sshbuf_new();
	ASSERT_PTR_NE(ca_buf, ਨਿਰਾ);
	ASSERT_INT_EQ(sshkey_putb(ca_ਕੁੰਜੀ, ca_buf), 0);

	/*
	 * Get the public key serialisation by rendering the key and skipping
	 * the type string. This is a bit of a hack :/
	 */
	pk = sshbuf_new();
	ASSERT_PTR_NE(pk, ਨਿਰਾ);
	ASSERT_INT_EQ(sshkey_putb_plain(k, pk), 0);
	ASSERT_INT_EQ(sshbuf_skip_string(pk), 0);

	principals = sshbuf_new();
	ASSERT_PTR_NE(principals, ਨਿਰਾ);
	ASSERT_INT_EQ(sshbuf_put_cstring(principals, "gsamsa"), 0);
	ASSERT_INT_EQ(sshbuf_put_cstring(principals, "gregor"), 0);

	critopts = sshbuf_new();
	ASSERT_PTR_NE(critopts, ਨਿਰਾ);
	put_opt(critopts, "force-command", "/usr/local/bin/nethack");
	put_opt(critopts, "source-address", "192.168.0.0/24,127.0.0.1,::1");

	exts = sshbuf_new();
	ASSERT_PTR_NE(exts, ਨਿਰਾ);
	put_opt(critopts, "permit-X11-forwarding", ਨਿਰਾ);

	ASSERT_INT_EQ(sshbuf_put_cstring(b, type), 0);
	ASSERT_INT_EQ(sshbuf_put_cstring(b, "noncenoncenonce!"), 0); /* nonce */
	ASSERT_INT_EQ(sshbuf_putb(b, pk), 0); /* public key serialisation */
	ASSERT_INT_EQ(sshbuf_put_u64(b, 1234), 0); /* serial */
	ASSERT_INT_EQ(sshbuf_put_u32(b, SSH2_CERT_TYPE_USER), 0); /* type */
	ASSERT_INT_EQ(sshbuf_put_cstring(b, "gregor"), 0); /* key ID */
	ASSERT_INT_EQ(sshbuf_put_stringb(b, principals), 0); /* principals */
	ASSERT_INT_EQ(sshbuf_put_u64(b, 0), 0); /*ਸ਼ੁਰੂ*/
	ASSERT_INT_EQ(sshbuf_put_u64(b, 0xffffffffffffffffULL), 0); /*ਸਿਰਾ*/
	ASSERT_INT_EQ(sshbuf_put_stringb(b, critopts), 0); /* options */
	ASSERT_INT_EQ(sshbuf_put_stringb(b, exts), 0); /* extensions */
	ASSERT_INT_EQ(sshbuf_put_string(b, ਨਿਰਾ, 0), 0); /* reserved */
	ASSERT_INT_EQ(sshbuf_put_stringb(b, ca_buf), 0); /* signature key */
	ASSERT_INT_EQ(sshkey_sign(sign_ਕੁੰਜੀ, &sigblob, &siglen,
	    sshbuf_ptr(b), sshbuf_len(b), sig_alg, ਨਿਰਾ, ਨਿਰਾ, 0), 0);
	ASSERT_INT_EQ(sshbuf_put_string(b, sigblob, siglen), 0); /* signature */

	ਮੁਕਤ(sigblob);
	sshbuf_free(ca_buf);
	sshbuf_free(exts);
	sshbuf_free(critopts);
	sshbuf_free(principals);
	sshbuf_free(pk);
}
#ਜੇ_ਅੰਤ /* WITH_OPENSSL */

ਸਥਿਰ ਖਾਲੀ
signature_test(ਬਣਤਰ sshkey *k, ਬਣਤਰ sshkey *bad, ਅਚਲ ਅੱਖਰ *sig_alg,
    ਅਚਲ u_char *d, ਮਾਪ_t l)
{
	ਮਾਪ_t len;
	u_char *sig;

	ASSERT_INT_EQ(sshkey_sign(k, &sig, &len, d, l, sig_alg,
	    ਨਿਰਾ, ਨਿਰਾ, 0), 0);
	ASSERT_ਮਾਪ_T_GT(len, 8);
	ASSERT_PTR_NE(sig, ਨਿਰਾ);
	ASSERT_INT_EQ(sshkey_verify(k, sig, len, d, l, ਨਿਰਾ, 0, ਨਿਰਾ), 0);
	ASSERT_INT_NE(sshkey_verify(bad, sig, len, d, l, ਨਿਰਾ, 0, ਨਿਰਾ), 0);
	/* Fuzz test is more comprehensive, this is just a smoke test */
	sig[len - 5] ^= 0x10;
	ASSERT_INT_NE(sshkey_verify(k, sig, len, d, l, ਨਿਰਾ, 0, ਨਿਰਾ), 0);
	ਮੁਕਤ(sig);
}

ਸਥਿਰ ਖਾਲੀ
signature_bench(ਅਚਲ ਅੱਖਰ *name, ਪੂਰਨ ktype, ਪੂਰਨ ਬਿੱਟ, ਅਚਲ ਅੱਖਰ *sig_alg,
    ਅਚਲ u_char *d, ਮਾਪ_t l)
{
	ਬਣਤਰ sshkey *k;
	ਮਾਪ_t len;
	u_char *sig;
	ਅੱਖਰ testname[256];

	snprintf(testname, ਆਕਾਰ(testname), "sign %s", name);
	TEST_ਸ਼ੁਰੂ(testname);
	ASSERT_INT_EQ(sshkey_generate(ktype, ਬਿੱਟ, &k), 0);
	ASSERT_PTR_NE(k, ਨਿਰਾ);

	BENCH_ਸ਼ੁਰੂ(testname);
	ASSERT_INT_EQ(sshkey_sign(k, &sig, &len, d, l, sig_alg,
	    ਨਿਰਾ, ਨਿਰਾ, 0), 0);
	ਮੁਕਤ(sig);
	BENCH_ਅੰਤ("sign");

	sshkey_free(k);
	TEST_ਪੂਰਾ();
}

ਸਥਿਰ ਖਾਲੀ
verify_bench(ਅਚਲ ਅੱਖਰ *name, ਪੂਰਨ ktype, ਪੂਰਨ ਬਿੱਟ, ਅਚਲ ਅੱਖਰ *sig_alg,
    ਅਚਲ u_char *d, ਮਾਪ_t l)
{
	ਬਣਤਰ sshkey *k;
	ਮਾਪ_t len;
	u_char *sig;
	ਅੱਖਰ testname[256];

	snprintf(testname, ਆਕਾਰ(testname), "verify %s", name);
	TEST_ਸ਼ੁਰੂ(testname);
	ASSERT_INT_EQ(sshkey_generate(ktype, ਬਿੱਟ, &k), 0);
	ASSERT_PTR_NE(k, ਨਿਰਾ);

	ASSERT_INT_EQ(sshkey_sign(k, &sig, &len, d, l, sig_alg,
	    ਨਿਰਾ, ਨਿਰਾ, 0), 0);
	BENCH_ਸ਼ੁਰੂ(testname);
	ASSERT_INT_EQ(sshkey_verify(k, sig, len, d, l, ਨਿਰਾ, 0, ਨਿਰਾ), 0);
	BENCH_ਅੰਤ("verify");

	ਮੁਕਤ(sig);
	sshkey_free(k);
	TEST_ਪੂਰਾ();
}

ਸਥਿਰ ਖਾਲੀ
banana(u_char *s, ਮਾਪ_t l)
{
	ਮਾਪ_t o;
	ਅਚਲ u_char the_banana[] = { 'b', 'a', 'n', 'a', 'n', 'a' };

	ਲਈ (o = 0; o < l; o += ਆਕਾਰ(the_banana)) {
		ਜੇ (l - o < ਆਕਾਰ(the_banana)) {
			ਸਮ੍ਰਿਤੀ_ਨਕਲ(s + o, "nanananana", l - o);
			ਰੋਕੋ;
		}
		ਸਮ੍ਰਿਤੀ_ਨਕਲ(s + o, the_banana, ਆਕਾਰ(the_banana));
	}
}

ਸਥਿਰ ਖਾਲੀ
signature_tests(ਬਣਤਰ sshkey *k, ਬਣਤਰ sshkey *bad, ਅਚਲ ਅੱਖਰ *sig_alg)
{
	u_char i, buf[2049];
	ਮਾਪ_t lens[] = {
		1, 2, 7, 8, 9, 15, 16, 17, 31, 32, 33, 127, 128, 129,
		255, 256, 257, 1023, 1024, 1025, 2047, 2048, 2049
	};

	ਲਈ (i = 0; i < (ਆਕਾਰ(lens)/ਆਕਾਰ(lens[0])); i++) {
		test_subtest_info("%s key, banana length %zu",
		    sshkey_type(k), lens[i]);
		banana(buf, lens[i]);
		signature_test(k, bad, sig_alg, buf, lens[i]);
	}
}

ਸਥਿਰ ਖਾਲੀ
signature_benchmark(ਅਚਲ ਅੱਖਰ *name, ਪੂਰਨ ktype, ਪੂਰਨ ਬਿੱਟ,
    ਅਚਲ ਅੱਖਰ *sig_alg, ਪੂਰਨ bench_verify)
{
	u_char buf[256];

	banana(buf, ਆਕਾਰ(buf));
	ਜੇ (bench_verify)
		verify_bench(name, ktype, ਬਿੱਟ, sig_alg, buf, ਆਕਾਰ(buf));
	ਨਹੀਂਤਾਂ
		signature_bench(name, ktype, ਬਿੱਟ, sig_alg, buf, ਆਕਾਰ(buf));
}

ਸਥਿਰ ਬਣਤਰ sshkey *
get_ਨਿੱਜੀ(ਅਚਲ ਅੱਖਰ *n)
{
	ਬਣਤਰ sshbuf *b;
	ਬਣਤਰ sshkey *ret;

	b = ਲੱਦੋ_file(n);
	ASSERT_INT_EQ(sshkey_parse_ਨਿੱਜੀ_fileblob(b, "", &ret, ਨਿਰਾ), 0);
	sshbuf_free(b);
	ਵਾਪਸ ret;
}

ਖਾਲੀ
sshkey_tests(ਖਾਲੀ)
{
	ਬਣਤਰ sshkey *k1 = ਨਿਰਾ, *k2 = ਨਿਰਾ, *k3 = ਨਿਰਾ, *k4 = ਨਿਰਾ;
	ਬਣਤਰ sshkey *kr = ਨਿਰਾ, *kd = ਨਿਰਾ, *ke = ਨਿਰਾ, *kf = ਨਿਰਾ;
	ਬਣਤਰ sshbuf *b = ਨਿਰਾ;

	TEST_ਸ਼ੁਰੂ("new invalid");
	k1 = sshkey_new(-42);
	ASSERT_PTR_EQ(k1, ਨਿਰਾ);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("new/free KEY_UNSPEC");
	k1 = sshkey_new(ਕੁੰਜੀ_UNSPEC);
	ASSERT_PTR_NE(k1, ਨਿਰਾ);
	sshkey_free(k1);
	k1 = ਨਿਰਾ;
	TEST_ਪੂਰਾ();

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
	TEST_ਸ਼ੁਰੂ("new/free KEY_RSA");
	k1 = sshkey_new(ਕੁੰਜੀ_RSA);
	ASSERT_PTR_NE(k1, ਨਿਰਾ);
	ASSERT_PTR_NE(k1->pkey, ਨਿਰਾ);
	sshkey_free(k1);
	k1 = ਨਿਰਾ;
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("new/free KEY_ECDSA");
	k1 = sshkey_new(ਕੁੰਜੀ_ECDSA);
	ASSERT_PTR_NE(k1, ਨਿਰਾ);
	ASSERT_PTR_EQ(k1->pkey, ਨਿਰਾ);  /* Can't allocate without NID */
	sshkey_free(k1);
	k1 = ਨਿਰਾ;
	TEST_ਪੂਰਾ();
#ਜੇ_ਅੰਤ /* WITH_OPENSSL */

	TEST_ਸ਼ੁਰੂ("new/free KEY_ED25519");
	k1 = sshkey_new(ਕੁੰਜੀ_ED25519);
	ASSERT_PTR_NE(k1, ਨਿਰਾ);
	/* These should be blank until key loaded or generated */
	ASSERT_PTR_EQ(k1->ed25519_sk, ਨਿਰਾ);
	ASSERT_PTR_EQ(k1->ed25519_pk, ਨਿਰਾ);
	sshkey_free(k1);
	k1 = ਨਿਰਾ;
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("new/free KEY_MLDSA44_ED25519");
	k1 = sshkey_new(ਕੁੰਜੀ_MLDSA44_ED25519);
	ASSERT_PTR_NE(k1, ਨਿਰਾ);
	ASSERT_PTR_EQ(k1->mldsa_ed25519_sk, ਨਿਰਾ);
	ASSERT_PTR_EQ(k1->mldsa_ed25519_pk, ਨਿਰਾ);
	sshkey_free(k1);
	k1 = ਨਿਰਾ;
	TEST_ਪੂਰਾ();

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
	TEST_ਸ਼ੁਰੂ("generate KEY_RSA too small modulus");
	ASSERT_INT_EQ(sshkey_generate(ਕੁੰਜੀ_RSA, 128, &k1),
	    SSH_ERR_ਕੁੰਜੀ_ਲੰਮਾਈ);
	ASSERT_PTR_EQ(k1, ਨਿਰਾ);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("generate KEY_RSA too large modulus");
	ASSERT_INT_EQ(sshkey_generate(ਕੁੰਜੀ_RSA, 1 << 20, &k1),
	    SSH_ERR_ਕੁੰਜੀ_ਲੰਮਾਈ);
	ASSERT_PTR_EQ(k1, ਨਿਰਾ);
	TEST_ਪੂਰਾ();


	TEST_ਸ਼ੁਰੂ("generate KEY_ECDSA wrong bits");
	ASSERT_INT_EQ(sshkey_generate(ਕੁੰਜੀ_ECDSA, 42, &k1),
	    SSH_ERR_ਕੁੰਜੀ_ਲੰਮਾਈ);
	ASSERT_PTR_EQ(k1, ਨਿਰਾ);
	sshkey_free(k1);
	k1 = ਨਿਰਾ;
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("generate KEY_RSA");
	ASSERT_INT_EQ(sshkey_generate(ਕੁੰਜੀ_RSA, 767, &kr),
	    SSH_ERR_ਕੁੰਜੀ_ਲੰਮਾਈ);
	ASSERT_INT_EQ(sshkey_generate(ਕੁੰਜੀ_RSA, 1024, &kr), 0);
	ASSERT_PTR_NE(kr, ਨਿਰਾ);
	ASSERT_PTR_NE(EVP_PKEY_get0_RSA(kr->pkey), ਨਿਰਾ);
	ASSERT_PTR_NE(rsa_n(kr), ਨਿਰਾ);
	ASSERT_PTR_NE(rsa_e(kr), ਨਿਰਾ);
	ASSERT_PTR_NE(rsa_p(kr), ਨਿਰਾ);
	ASSERT_INT_EQ(BN_ਅੰਕ_ਬਿੱਟ(rsa_n(kr)), 1024);
	TEST_ਪੂਰਾ();


	TEST_ਸ਼ੁਰੂ("generate KEY_ECDSA");
	ASSERT_INT_EQ(sshkey_generate(ਕੁੰਜੀ_ECDSA, 256, &ke), 0);
	ASSERT_PTR_NE(ke, ਨਿਰਾ);
	ASSERT_PTR_NE(EVP_PKEY_get0_EC_ਕੁੰਜੀ(ke->pkey), ਨਿਰਾ);
	ASSERT_PTR_NE(EC_ਕੁੰਜੀ_get0_ਜਨਤਕ_ਕੁੰਜੀ(EVP_PKEY_get0_EC_ਕੁੰਜੀ(ke->pkey)),
	    ਨਿਰਾ);
	ASSERT_PTR_NE(EC_ਕੁੰਜੀ_get0_ਨਿੱਜੀ_ਕੁੰਜੀ(EVP_PKEY_get0_EC_ਕੁੰਜੀ(ke->pkey)),
	    ਨਿਰਾ);
	TEST_ਪੂਰਾ();
#ਜੇ_ਅੰਤ /* WITH_OPENSSL */

	TEST_ਸ਼ੁਰੂ("generate KEY_ED25519");
	ASSERT_INT_EQ(sshkey_generate(ਕੁੰਜੀ_ED25519, 256, &kf), 0);
	ASSERT_PTR_NE(kf, ਨਿਰਾ);
	ASSERT_INT_EQ(kf->type, ਕੁੰਜੀ_ED25519);
	ASSERT_PTR_NE(kf->ed25519_pk, ਨਿਰਾ);
	ASSERT_PTR_NE(kf->ed25519_sk, ਨਿਰਾ);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("generate KEY_MLDSA44_ED25519");
	ASSERT_INT_EQ(sshkey_generate(ਕੁੰਜੀ_MLDSA44_ED25519, 256, &k1), 0);
	ASSERT_PTR_NE(k1, ਨਿਰਾ);
	ASSERT_INT_EQ(k1->type, ਕੁੰਜੀ_MLDSA44_ED25519);
	ASSERT_PTR_NE(k1->mldsa_ed25519_pk, ਨਿਰਾ);
	ASSERT_PTR_NE(k1->mldsa_ed25519_sk, ਨਿਰਾ);
	sshkey_free(k1);
	k1 = ਨਿਰਾ;
	TEST_ਪੂਰਾ();

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
	TEST_ਸ਼ੁਰੂ("demote KEY_RSA");
	ASSERT_INT_EQ(sshkey_from_ਨਿੱਜੀ(kr, &k1), 0);
	ASSERT_PTR_NE(k1, ਨਿਰਾ);
	ASSERT_PTR_NE(kr, k1);
	ASSERT_INT_EQ(k1->type, ਕੁੰਜੀ_RSA);
	ASSERT_PTR_NE(EVP_PKEY_get0_RSA(k1->pkey), ਨਿਰਾ);
	ASSERT_PTR_NE(rsa_n(k1), ਨਿਰਾ);
	ASSERT_PTR_NE(rsa_e(k1), ਨਿਰਾ);
	ASSERT_PTR_EQ(rsa_p(k1), ਨਿਰਾ);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("equal KEY_RSA/demoted KEY_RSA");
	ASSERT_INT_EQ(sshkey_equal(kr, k1), 1);
	sshkey_free(k1);
	k1 = ਨਿਰਾ;
	TEST_ਪੂਰਾ();


	TEST_ਸ਼ੁਰੂ("demote KEY_ECDSA");
	ASSERT_INT_EQ(sshkey_from_ਨਿੱਜੀ(ke, &k1), 0);
	ASSERT_PTR_NE(k1, ਨਿਰਾ);
	ASSERT_PTR_NE(ke, k1);
	ASSERT_INT_EQ(k1->type, ਕੁੰਜੀ_ECDSA);
	ASSERT_PTR_NE(EVP_PKEY_get0_EC_ਕੁੰਜੀ(k1->pkey), ਨਿਰਾ);
	ASSERT_INT_EQ(k1->ecdsa_nid, ke->ecdsa_nid);
	ASSERT_PTR_NE(EC_ਕੁੰਜੀ_get0_ਜਨਤਕ_ਕੁੰਜੀ(EVP_PKEY_get0_EC_ਕੁੰਜੀ(ke->pkey)),
	   ਨਿਰਾ);
	ASSERT_PTR_EQ(EC_ਕੁੰਜੀ_get0_ਨਿੱਜੀ_ਕੁੰਜੀ(EVP_PKEY_get0_EC_ਕੁੰਜੀ(k1->pkey)),
	   ਨਿਰਾ);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("equal KEY_ECDSA/demoted KEY_ECDSA");
	ASSERT_INT_EQ(sshkey_equal(ke, k1), 1);
	sshkey_free(k1);
	k1 = ਨਿਰਾ;
	TEST_ਪੂਰਾ();
#ਜੇ_ਅੰਤ /* WITH_OPENSSL */

	TEST_ਸ਼ੁਰੂ("demote KEY_ED25519");
	ASSERT_INT_EQ(sshkey_from_ਨਿੱਜੀ(kf, &k1), 0);
	ASSERT_PTR_NE(k1, ਨਿਰਾ);
	ASSERT_PTR_NE(kf, k1);
	ASSERT_INT_EQ(k1->type, ਕੁੰਜੀ_ED25519);
	ASSERT_PTR_NE(k1->ed25519_pk, ਨਿਰਾ);
	ASSERT_PTR_EQ(k1->ed25519_sk, ਨਿਰਾ);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("equal KEY_ED25519/demoted KEY_ED25519");
	ASSERT_INT_EQ(sshkey_equal(kf, k1), 1);
	sshkey_free(k1);
	k1 = ਨਿਰਾ;
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("demote KEY_MLDSA44_ED25519");
	ASSERT_INT_EQ(sshkey_generate(ਕੁੰਜੀ_MLDSA44_ED25519, 256, &k2), 0);
	ASSERT_INT_EQ(sshkey_from_ਨਿੱਜੀ(k2, &k1), 0);
	ASSERT_PTR_NE(k1, ਨਿਰਾ);
	ASSERT_PTR_NE(k2, k1);
	ASSERT_INT_EQ(k1->type, ਕੁੰਜੀ_MLDSA44_ED25519);
	ASSERT_PTR_NE(k1->mldsa_ed25519_pk, ਨਿਰਾ);
	ASSERT_PTR_EQ(k1->mldsa_ed25519_sk, ਨਿਰਾ);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("equal KEY_MLDSA44_ED25519/demoted KEY_MLDSA44_ED25519");
	ASSERT_INT_EQ(sshkey_equal(k2, k1), 1);
	sshkey_free(k1);
	sshkey_free(k2);
	k1 = k2 = ਨਿਰਾ;
	TEST_ਪੂਰਾ();

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
	TEST_ਸ਼ੁਰੂ("equal mismatched key types");
	ASSERT_INT_EQ(sshkey_equal(kd, kr), 0);
	ASSERT_INT_EQ(sshkey_equal(kd, ke), 0);
	ASSERT_INT_EQ(sshkey_equal(kr, ke), 0);
	ASSERT_INT_EQ(sshkey_equal(ke, kf), 0);
	ASSERT_INT_EQ(sshkey_equal(kd, kf), 0);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("equal different keys");
	ASSERT_INT_EQ(sshkey_generate(ਕੁੰਜੀ_RSA, 1024, &k1), 0);
	ASSERT_INT_EQ(sshkey_equal(kr, k1), 0);
	sshkey_free(k1);
	k1 = ਨਿਰਾ;
	ASSERT_INT_EQ(sshkey_generate(ਕੁੰਜੀ_ECDSA, 256, &k1), 0);
	ASSERT_INT_EQ(sshkey_equal(ke, k1), 0);
	sshkey_free(k1);
	k1 = ਨਿਰਾ;
	ASSERT_INT_EQ(sshkey_generate(ਕੁੰਜੀ_ED25519, 256, &k1), 0);
	ASSERT_INT_EQ(sshkey_equal(kf, k1), 0);
	sshkey_free(k1);
	k1 = ਨਿਰਾ;
	ASSERT_INT_EQ(sshkey_generate(ਕੁੰਜੀ_MLDSA44_ED25519, 256, &k1), 0);
	ASSERT_INT_EQ(sshkey_generate(ਕੁੰਜੀ_MLDSA44_ED25519, 256, &k2), 0);
	ASSERT_INT_EQ(sshkey_equal(k2, k1), 0);
	sshkey_free(k1);
	sshkey_free(k2);
	k1 = k2 = ਨਿਰਾ;
	TEST_ਪੂਰਾ();
#ਜੇ_ਅੰਤ /* WITH_OPENSSL */

	sshkey_free(kr);
	sshkey_free(kd);
	sshkey_free(ke);
	sshkey_free(kf);
	kr = kd = ke = kf = ਨਿਰਾ;

	TEST_ਸ਼ੁਰੂ("certify key");
	ASSERT_INT_EQ(sshkey_ਲੱਦੋ_ਜਨਤਕ(test_ਅੰਕੜੇ_file("ed25519_1.pub"),
	    &k1, ਨਿਰਾ), 0);
	k2 = get_ਨਿੱਜੀ("ed25519_2");
	ASSERT_INT_EQ(sshkey_ਮੰਜ਼ਿਲ_certified(k1), 0);
	ASSERT_PTR_NE(k1->cert, ਨਿਰਾ);
	k1->cert->type = SSH2_CERT_TYPE_USER;
	k1->cert->serial = 1234;
	k1->cert->ਕੁੰਜੀ_id = strdup("estragon");
	ASSERT_PTR_NE(k1->cert->ਕੁੰਜੀ_id, ਨਿਰਾ);
	k1->cert->principals = ਸਿਫਰ_ਸਮ੍ਰਿਤੀ_ਦਿਓ(4, ਆਕਾਰ(*k1->cert->principals));
	ASSERT_PTR_NE(k1->cert->principals, ਨਿਰਾ);
	k1->cert->principals[0] = strdup("estragon");
	k1->cert->principals[1] = strdup("vladimir");
	k1->cert->principals[2] = strdup("pozzo");
	k1->cert->principals[3] = strdup("lucky");
	ASSERT_PTR_NE(k1->cert->principals[0], ਨਿਰਾ);
	ASSERT_PTR_NE(k1->cert->principals[1], ਨਿਰਾ);
	ASSERT_PTR_NE(k1->cert->principals[2], ਨਿਰਾ);
	ASSERT_PTR_NE(k1->cert->principals[3], ਨਿਰਾ);
	k1->cert->nprincipals = 4;
	k1->cert->valid_after = 0;
	k1->cert->valid_before = (uint64_t)-1;
	sshbuf_free(k1->cert->critical);
	k1->cert->critical = sshbuf_new();
	ASSERT_PTR_NE(k1->cert->critical, ਨਿਰਾ);
	sshbuf_free(k1->cert->extensions);
	k1->cert->extensions = sshbuf_new();
	ASSERT_PTR_NE(k1->cert->extensions, ਨਿਰਾ);
	put_opt(k1->cert->critical, "force-command", "/usr/bin/true");
	put_opt(k1->cert->critical, "source-address", "127.0.0.1");
	put_opt(k1->cert->extensions, "permit-X11-forwarding", ਨਿਰਾ);
	put_opt(k1->cert->extensions, "permit-agent-forwarding", ਨਿਰਾ);
	ASSERT_INT_EQ(sshkey_from_ਨਿੱਜੀ(k2, &k1->cert->signature_ਕੁੰਜੀ), 0);
	ASSERT_INT_EQ(sshkey_certify(k1, k2, ਨਿਰਾ, ਨਿਰਾ, ਨਿਰਾ), 0);
	b = sshbuf_new();
	ASSERT_PTR_NE(b, ਨਿਰਾ);
	ASSERT_INT_EQ(sshkey_putb(k1, b), 0);
	ASSERT_INT_EQ(sshkey_from_blob(sshbuf_ptr(b), sshbuf_len(b), &k3), 0);

	sshkey_free(k1);
	sshkey_free(k2);
	sshkey_free(k3);
	k1 = k2 = k3 = ਨਿਰਾ;
	sshbuf_reset(b);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("certify key MLDSA44-ED25519");
	ASSERT_INT_EQ(sshkey_ਲੱਦੋ_ਜਨਤਕ(
	    test_ਅੰਕੜੇ_file("mldsa44_ed25519_1.pub"), &k1, ਨਿਰਾ), 0);
	k2 = get_ਨਿੱਜੀ("mldsa44_ed25519_2");
	ASSERT_INT_EQ(sshkey_ਮੰਜ਼ਿਲ_certified(k1), 0);
	ASSERT_PTR_NE(k1->cert, ਨਿਰਾ);
	k1->cert->type = SSH2_CERT_TYPE_USER;
	k1->cert->serial = 1234;
	k1->cert->ਕੁੰਜੀ_id = strdup("estragon");
	ASSERT_PTR_NE(k1->cert->ਕੁੰਜੀ_id, ਨਿਰਾ);
	k1->cert->principals = ਸਿਫਰ_ਸਮ੍ਰਿਤੀ_ਦਿਓ(4, ਆਕਾਰ(*k1->cert->principals));
	ASSERT_PTR_NE(k1->cert->principals, ਨਿਰਾ);
	k1->cert->principals[0] = strdup("estragon");
	k1->cert->principals[1] = strdup("vladimir");
	k1->cert->principals[2] = strdup("pozzo");
	k1->cert->principals[3] = strdup("lucky");
	ASSERT_PTR_NE(k1->cert->principals[0], ਨਿਰਾ);
	ASSERT_PTR_NE(k1->cert->principals[1], ਨਿਰਾ);
	ASSERT_PTR_NE(k1->cert->principals[2], ਨਿਰਾ);
	ASSERT_PTR_NE(k1->cert->principals[3], ਨਿਰਾ);
	k1->cert->nprincipals = 4;
	k1->cert->valid_after = 0;
	k1->cert->valid_before = (uint64_t)-1;
	sshbuf_free(k1->cert->critical);
	k1->cert->critical = sshbuf_new();
	ASSERT_PTR_NE(k1->cert->critical, ਨਿਰਾ);
	sshbuf_free(k1->cert->extensions);
	k1->cert->extensions = sshbuf_new();
	ASSERT_PTR_NE(k1->cert->extensions, ਨਿਰਾ);
	put_opt(k1->cert->critical, "force-command", "/usr/bin/true");
	put_opt(k1->cert->critical, "source-address", "127.0.0.1");
	put_opt(k1->cert->extensions, "permit-X11-forwarding", ਨਿਰਾ);
	put_opt(k1->cert->extensions, "permit-agent-forwarding", ਨਿਰਾ);
	ASSERT_INT_EQ(sshkey_from_ਨਿੱਜੀ(k2, &k1->cert->signature_ਕੁੰਜੀ), 0);
	ASSERT_INT_EQ(sshkey_certify(k1, k2, ਨਿਰਾ, ਨਿਰਾ, ਨਿਰਾ), 0);
	b = sshbuf_new();
	ASSERT_PTR_NE(b, ਨਿਰਾ);
	ASSERT_INT_EQ(sshkey_putb(k1, b), 0);
	ASSERT_INT_EQ(sshkey_from_blob(sshbuf_ptr(b), sshbuf_len(b), &k3), 0);
	sshkey_free(k1);
	sshkey_free(k2);
	sshkey_free(k3);
	k1 = k2 = k3 = ਨਿਰਾ;
	sshbuf_reset(b);
	TEST_ਪੂਰਾ();

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
	TEST_ਸ਼ੁਰੂ("sign and verify RSA");
	k1 = get_ਨਿੱਜੀ("rsa_1");
	ASSERT_INT_EQ(sshkey_ਲੱਦੋ_ਜਨਤਕ(test_ਅੰਕੜੇ_file("rsa_2.pub"), &k2,
	    ਨਿਰਾ), 0);
	signature_tests(k1, k2, "ssh-rsa");
	sshkey_free(k1);
	sshkey_free(k2);
	k1 = k2 = ਨਿਰਾ;
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("sign and verify RSA-SHA256");
	k1 = get_ਨਿੱਜੀ("rsa_1");
	ASSERT_INT_EQ(sshkey_ਲੱਦੋ_ਜਨਤਕ(test_ਅੰਕੜੇ_file("rsa_2.pub"), &k2,
	    ਨਿਰਾ), 0);
	signature_tests(k1, k2, "rsa-sha2-256");
	sshkey_free(k1);
	sshkey_free(k2);
	k1 = k2 = ਨਿਰਾ;
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("sign and verify RSA-SHA512");
	k1 = get_ਨਿੱਜੀ("rsa_1");
	ASSERT_INT_EQ(sshkey_ਲੱਦੋ_ਜਨਤਕ(test_ਅੰਕੜੇ_file("rsa_2.pub"), &k2,
	    ਨਿਰਾ), 0);
	signature_tests(k1, k2, "rsa-sha2-512");
	sshkey_free(k1);
	sshkey_free(k2);
	k1 = k2 = ਨਿਰਾ;
	TEST_ਪੂਰਾ();


	TEST_ਸ਼ੁਰੂ("sign and verify ECDSA");
	k1 = get_ਨਿੱਜੀ("ecdsa_1");
	ASSERT_INT_EQ(sshkey_ਲੱਦੋ_ਜਨਤਕ(test_ਅੰਕੜੇ_file("ecdsa_2.pub"), &k2,
	    ਨਿਰਾ), 0);
	signature_tests(k1, k2, ਨਿਰਾ);
	sshkey_free(k1);
	sshkey_free(k2);
	k1 = k2 = ਨਿਰਾ;
	TEST_ਪੂਰਾ();
#ਜੇ_ਅੰਤ /* WITH_OPENSSL */

	TEST_ਸ਼ੁਰੂ("sign and verify ED25519");
	k1 = get_ਨਿੱਜੀ("ed25519_1");
	ASSERT_INT_EQ(sshkey_ਲੱਦੋ_ਜਨਤਕ(test_ਅੰਕੜੇ_file("ed25519_2.pub"), &k2,
	    ਨਿਰਾ), 0);
	signature_tests(k1, k2, ਨਿਰਾ);
	sshkey_free(k1);
	sshkey_free(k2);
	k1 = k2 = ਨਿਰਾ;
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("sign and verify MLDSA44-ED25519");
	k1 = get_ਨਿੱਜੀ("mldsa44_ed25519_1");
	ASSERT_INT_EQ(sshkey_ਲੱਦੋ_ਜਨਤਕ(
	    test_ਅੰਕੜੇ_file("mldsa44_ed25519_2.pub"), &k2, ਨਿਰਾ), 0);
	signature_tests(k1, k2, ਨਿਰਾ);
	sshkey_free(k1);
	sshkey_free(k2);
	k1 = k2 = ਨਿਰਾ;
	TEST_ਪੂਰਾ();

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
	TEST_ਸ਼ੁਰੂ("nested certificate");
	ASSERT_INT_EQ(sshkey_ਲੱਦੋ_cert(test_ਅੰਕੜੇ_file("rsa_1"), &k1), 0);
	ASSERT_INT_EQ(sshkey_ਲੱਦੋ_ਜਨਤਕ(test_ਅੰਕੜੇ_file("rsa_1.pub"), &k2,
	    ਨਿਰਾ), 0);
	k3 = get_ਨਿੱਜੀ("rsa_1");
	build_cert(b, k2, "ssh-rsa-cert-v01@openssh.com", k3, k1, ਨਿਰਾ);
	ASSERT_INT_EQ(sshkey_from_blob(sshbuf_ptr(b), sshbuf_len(b), &k4),
	    SSH_ERR_ਕੁੰਜੀ_CERT_INVALID_SIGN_ਕੁੰਜੀ);
	ASSERT_PTR_EQ(k4, ਨਿਰਾ);
	sshkey_free(k1);
	sshkey_free(k2);
	sshkey_free(k3);
	k1 = k2 = k3 = ਨਿਰਾ;
	sshbuf_free(b);
	TEST_ਪੂਰਾ();
#ਜੇ_ਅੰਤ /* WITH_OPENSSL */
}

ਖਾਲੀ
sshkey_benchmarks(ਖਾਲੀ)
{
	ਬਣਤਰ sshkey *k = ਨਿਰਾ;

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
	BENCH_ਸ਼ੁਰੂ("generate RSA-1024");
	TEST_ਸ਼ੁਰੂ("generate KEY_RSA");
	ASSERT_INT_EQ(sshkey_generate(ਕੁੰਜੀ_RSA, 1024, &k), 0);
	ASSERT_PTR_NE(k, ਨਿਰਾ);
	sshkey_free(k);
	k = ਨਿਰਾ;
	TEST_ਪੂਰਾ();
	BENCH_ਅੰਤ("keys");

	BENCH_ਸ਼ੁਰੂ("generate RSA-2048");
	TEST_ਸ਼ੁਰੂ("generate KEY_RSA");
	ASSERT_INT_EQ(sshkey_generate(ਕੁੰਜੀ_RSA, 2048, &k), 0);
	ASSERT_PTR_NE(k, ਨਿਰਾ);
	sshkey_free(k);
	k = ਨਿਰਾ;
	TEST_ਪੂਰਾ();
	BENCH_ਅੰਤ("keys");

	BENCH_ਸ਼ੁਰੂ("generate ECDSA-256");
	TEST_ਸ਼ੁਰੂ("generate KEY_ECDSA");
	ASSERT_INT_EQ(sshkey_generate(ਕੁੰਜੀ_ECDSA, 256, &k), 0);
	ASSERT_PTR_NE(k, ਨਿਰਾ);
	sshkey_free(k);
	k = ਨਿਰਾ;
	TEST_ਪੂਰਾ();
	BENCH_ਅੰਤ("keys");

	BENCH_ਸ਼ੁਰੂ("generate ECDSA-384");
	TEST_ਸ਼ੁਰੂ("generate KEY_ECDSA");
	ASSERT_INT_EQ(sshkey_generate(ਕੁੰਜੀ_ECDSA, 384, &k), 0);
	ASSERT_PTR_NE(k, ਨਿਰਾ);
	sshkey_free(k);
	k = ਨਿਰਾ;
	TEST_ਪੂਰਾ();
	BENCH_ਅੰਤ("keys");

	BENCH_ਸ਼ੁਰੂ("generate ECDSA-521");
	TEST_ਸ਼ੁਰੂ("generate KEY_ECDSA");
	ASSERT_INT_EQ(sshkey_generate(ਕੁੰਜੀ_ECDSA, 521, &k), 0);
	ASSERT_PTR_NE(k, ਨਿਰਾ);
	sshkey_free(k);
	k = ਨਿਰਾ;
	TEST_ਪੂਰਾ();
	BENCH_ਅੰਤ("keys");
#ਜੇ_ਅੰਤ /* WITH_OPENSSL */

	BENCH_ਸ਼ੁਰੂ("generate ED25519");
	TEST_ਸ਼ੁਰੂ("generate KEY_ED25519");
	ASSERT_INT_EQ(sshkey_generate(ਕੁੰਜੀ_ED25519, 256, &k), 0);
	ASSERT_PTR_NE(k, ਨਿਰਾ);
	sshkey_free(k);
	k = ਨਿਰਾ;
	TEST_ਪੂਰਾ();
	BENCH_ਅੰਤ("keys");

	BENCH_ਸ਼ੁਰੂ("generate MLDSA44-ED25519");
	TEST_ਸ਼ੁਰੂ("generate KEY_MLDSA44_ED25519");
	ASSERT_INT_EQ(sshkey_generate(ਕੁੰਜੀ_MLDSA44_ED25519, 256, &k), 0);
	ASSERT_PTR_NE(k, ਨਿਰਾ);
	sshkey_free(k);
	k = ਨਿਰਾ;
	TEST_ਪੂਰਾ();
	BENCH_ਅੰਤ("keys");

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
	/* sign */
	signature_benchmark("RSA-1024/SHA1", ਕੁੰਜੀ_RSA, 1024, "ssh-rsa", 0);
	signature_benchmark("RSA-1024/SHA256", ਕੁੰਜੀ_RSA, 1024, "rsa-sha2-256", 0);
	signature_benchmark("RSA-1024/SHA512", ਕੁੰਜੀ_RSA, 1024, "rsa-sha2-512", 0);
	signature_benchmark("RSA-2048/SHA1", ਕੁੰਜੀ_RSA, 2048, "ssh-rsa", 0);
	signature_benchmark("RSA-2048/SHA256", ਕੁੰਜੀ_RSA, 2048, "rsa-sha2-256", 0);
	signature_benchmark("RSA-2048/SHA512", ਕੁੰਜੀ_RSA, 2048, "rsa-sha2-512", 0);
	signature_benchmark("ECDSA-256", ਕੁੰਜੀ_ECDSA, 256, ਨਿਰਾ, 0);
	signature_benchmark("ECDSA-384", ਕੁੰਜੀ_ECDSA, 384, ਨਿਰਾ, 0);
	signature_benchmark("ECDSA-521", ਕੁੰਜੀ_ECDSA, 521, ਨਿਰਾ, 0);
	signature_benchmark("ED25519", ਕੁੰਜੀ_ED25519, 0, ਨਿਰਾ, 0);
	signature_benchmark("MLDSA44-ED25519", ਕੁੰਜੀ_MLDSA44_ED25519, 0, ਨਿਰਾ, 0);

	/* verify */
	signature_benchmark("RSA-1024/SHA1", ਕੁੰਜੀ_RSA, 1024, "ssh-rsa", 1);
	signature_benchmark("RSA-1024/SHA256", ਕੁੰਜੀ_RSA, 1024, "rsa-sha2-256", 1);
	signature_benchmark("RSA-1024/SHA512", ਕੁੰਜੀ_RSA, 1024, "rsa-sha2-512", 1);
	signature_benchmark("RSA-2048/SHA1", ਕੁੰਜੀ_RSA, 2048, "ssh-rsa", 1);
	signature_benchmark("RSA-2048/SHA256", ਕੁੰਜੀ_RSA, 2048, "rsa-sha2-256", 1);
	signature_benchmark("RSA-2048/SHA512", ਕੁੰਜੀ_RSA, 2048, "rsa-sha2-512", 1);
	signature_benchmark("ECDSA-256", ਕੁੰਜੀ_ECDSA, 256, ਨਿਰਾ, 1);
	signature_benchmark("ECDSA-384", ਕੁੰਜੀ_ECDSA, 384, ਨਿਰਾ, 1);
	signature_benchmark("ECDSA-521", ਕੁੰਜੀ_ECDSA, 521, ਨਿਰਾ, 1);
#ਜੇ_ਅੰਤ /* WITH_OPENSSL */
	signature_benchmark("ED25519", ਕੁੰਜੀ_ED25519, 0, ਨਿਰਾ, 1);
	signature_benchmark("MLDSA44-ED25519", ਕੁੰਜੀ_MLDSA44_ED25519, 0, ਨਿਰਾ, 1);
}
