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

#اگر_تعریف_شدہ WITH_OPENSSL
#شامل <openssl/bn.h>
#شامل <openssl/ec.h>
#شامل <openssl/rsa.h>
#اگر_ختم

#شامل "../test_helper/test_helper.h"

#شامل "ssherr.h"
#شامل "sshbuf.h"
#تعریف_کرو SSHBUF_اندرونی 1	/* access internals for testing */
#شامل "sshkey.h"

#شامل "authfile.h"
#شامل "common.h"
#شامل "ssh2.h"

خالی sshkey_tests(خالی);
خالی sshkey_benchmarks(خالی);

ساکن خالی
put_opt(ساخت sshbuf *b, ثابت حرف *name, ثابت حرف *قدر)
{
	ساخت sshbuf *sect;

	sect = sshbuf_new();
	ASSERT_PTR_NE(sect, تہی);
	ASSERT_INT_EQ(sshbuf_put_cstring(b, name), 0);
	اگر (قدر != تہی)
		ASSERT_INT_EQ(sshbuf_put_cstring(sect, قدر), 0);
	ASSERT_INT_EQ(sshbuf_put_stringb(b, sect), 0);
	sshbuf_free(sect);
}

#اگر_تعریف_شدہ WITH_OPENSSL
ساکن خالی
build_cert(ساخت sshbuf *b, ساخت sshkey *k, ثابت حرف *type,
    ساخت sshkey *sign_کلید, ساخت sshkey *ca_کلید,
    ثابت حرف *sig_alg)
{
	ساخت sshbuf *ca_buf, *pk, *principals, *critopts, *exts;
	u_char *sigblob;
	سائز_t siglen;

	ca_buf = sshbuf_new();
	ASSERT_PTR_NE(ca_buf, تہی);
	ASSERT_INT_EQ(sshkey_putb(ca_کلید, ca_buf), 0);

	/*
	 * Get the public key serialisation by rendering the key and skipping
	 * the type string. This is a bit of a hack :/
	 */
	pk = sshbuf_new();
	ASSERT_PTR_NE(pk, تہی);
	ASSERT_INT_EQ(sshkey_putb_plain(k, pk), 0);
	ASSERT_INT_EQ(sshbuf_skip_string(pk), 0);

	principals = sshbuf_new();
	ASSERT_PTR_NE(principals, تہی);
	ASSERT_INT_EQ(sshbuf_put_cstring(principals, "gsamsa"), 0);
	ASSERT_INT_EQ(sshbuf_put_cstring(principals, "gregor"), 0);

	critopts = sshbuf_new();
	ASSERT_PTR_NE(critopts, تہی);
	put_opt(critopts, "force-command", "/usr/local/bin/nethack");
	put_opt(critopts, "source-address", "192.168.0.0/24,127.0.0.1,::1");

	exts = sshbuf_new();
	ASSERT_PTR_NE(exts, تہی);
	put_opt(critopts, "permit-X11-forwarding", تہی);

	ASSERT_INT_EQ(sshbuf_put_cstring(b, type), 0);
	ASSERT_INT_EQ(sshbuf_put_cstring(b, "noncenoncenonce!"), 0); /* nonce */
	ASSERT_INT_EQ(sshbuf_putb(b, pk), 0); /* public key serialisation */
	ASSERT_INT_EQ(sshbuf_put_u64(b, 1234), 0); /* serial */
	ASSERT_INT_EQ(sshbuf_put_u32(b, SSH2_CERT_TYPE_USER), 0); /* type */
	ASSERT_INT_EQ(sshbuf_put_cstring(b, "gregor"), 0); /* key ID */
	ASSERT_INT_EQ(sshbuf_put_stringb(b, principals), 0); /* principals */
	ASSERT_INT_EQ(sshbuf_put_u64(b, 0), 0); /*آغاز*/
	ASSERT_INT_EQ(sshbuf_put_u64(b, 0xffffffffffffffffULL), 0); /*انتہا*/
	ASSERT_INT_EQ(sshbuf_put_stringb(b, critopts), 0); /* options */
	ASSERT_INT_EQ(sshbuf_put_stringb(b, exts), 0); /* extensions */
	ASSERT_INT_EQ(sshbuf_put_string(b, تہی, 0), 0); /* reserved */
	ASSERT_INT_EQ(sshbuf_put_stringb(b, ca_buf), 0); /* signature key */
	ASSERT_INT_EQ(sshkey_sign(sign_کلید, &sigblob, &siglen,
	    sshbuf_ptr(b), sshbuf_len(b), sig_alg, تہی, تہی, 0), 0);
	ASSERT_INT_EQ(sshbuf_put_string(b, sigblob, siglen), 0); /* signature */

	آزاد(sigblob);
	sshbuf_free(ca_buf);
	sshbuf_free(exts);
	sshbuf_free(critopts);
	sshbuf_free(principals);
	sshbuf_free(pk);
}
#اگر_ختم /* WITH_OPENSSL */

ساکن خالی
signature_test(ساخت sshkey *k, ساخت sshkey *bad, ثابت حرف *sig_alg,
    ثابت u_char *d, سائز_t l)
{
	سائز_t len;
	u_char *sig;

	ASSERT_INT_EQ(sshkey_sign(k, &sig, &len, d, l, sig_alg,
	    تہی, تہی, 0), 0);
	ASSERT_سائز_T_GT(len, 8);
	ASSERT_PTR_NE(sig, تہی);
	ASSERT_INT_EQ(sshkey_verify(k, sig, len, d, l, تہی, 0, تہی), 0);
	ASSERT_INT_NE(sshkey_verify(bad, sig, len, d, l, تہی, 0, تہی), 0);
	/* Fuzz test is more comprehensive, this is just a smoke test */
	sig[len - 5] ^= 0x10;
	ASSERT_INT_NE(sshkey_verify(k, sig, len, d, l, تہی, 0, تہی), 0);
	آزاد(sig);
}

ساکن خالی
signature_bench(ثابت حرف *name, صحیح ktype, صحیح بٹ, ثابت حرف *sig_alg,
    ثابت u_char *d, سائز_t l)
{
	ساخت sshkey *k;
	سائز_t len;
	u_char *sig;
	حرف testname[256];

	snprintf(testname, حجم(testname), "sign %s", name);
	TEST_آغاز(testname);
	ASSERT_INT_EQ(sshkey_generate(ktype, بٹ, &k), 0);
	ASSERT_PTR_NE(k, تہی);

	BENCH_آغاز(testname);
	ASSERT_INT_EQ(sshkey_sign(k, &sig, &len, d, l, sig_alg,
	    تہی, تہی, 0), 0);
	آزاد(sig);
	BENCH_اختتام("sign");

	sshkey_free(k);
	TEST_مکمل();
}

ساکن خالی
verify_bench(ثابت حرف *name, صحیح ktype, صحیح بٹ, ثابت حرف *sig_alg,
    ثابت u_char *d, سائز_t l)
{
	ساخت sshkey *k;
	سائز_t len;
	u_char *sig;
	حرف testname[256];

	snprintf(testname, حجم(testname), "verify %s", name);
	TEST_آغاز(testname);
	ASSERT_INT_EQ(sshkey_generate(ktype, بٹ, &k), 0);
	ASSERT_PTR_NE(k, تہی);

	ASSERT_INT_EQ(sshkey_sign(k, &sig, &len, d, l, sig_alg,
	    تہی, تہی, 0), 0);
	BENCH_آغاز(testname);
	ASSERT_INT_EQ(sshkey_verify(k, sig, len, d, l, تہی, 0, تہی), 0);
	BENCH_اختتام("verify");

	آزاد(sig);
	sshkey_free(k);
	TEST_مکمل();
}

ساکن خالی
banana(u_char *s, سائز_t l)
{
	سائز_t o;
	ثابت u_char the_banana[] = { 'b', 'a', 'n', 'a', 'n', 'a' };

	برائے (o = 0; o < l; o += حجم(the_banana)) {
		اگر (l - o < حجم(the_banana)) {
			حافظہ_نقل(s + o, "nanananana", l - o);
			توڑو;
		}
		حافظہ_نقل(s + o, the_banana, حجم(the_banana));
	}
}

ساکن خالی
signature_tests(ساخت sshkey *k, ساخت sshkey *bad, ثابت حرف *sig_alg)
{
	u_char i, buf[2049];
	سائز_t lens[] = {
		1, 2, 7, 8, 9, 15, 16, 17, 31, 32, 33, 127, 128, 129,
		255, 256, 257, 1023, 1024, 1025, 2047, 2048, 2049
	};

	برائے (i = 0; i < (حجم(lens)/حجم(lens[0])); i++) {
		test_subtest_info("%s key, banana length %zu",
		    sshkey_type(k), lens[i]);
		banana(buf, lens[i]);
		signature_test(k, bad, sig_alg, buf, lens[i]);
	}
}

ساکن خالی
signature_benchmark(ثابت حرف *name, صحیح ktype, صحیح بٹ,
    ثابت حرف *sig_alg, صحیح bench_verify)
{
	u_char buf[256];

	banana(buf, حجم(buf));
	اگر (bench_verify)
		verify_bench(name, ktype, بٹ, sig_alg, buf, حجم(buf));
	ورنہ
		signature_bench(name, ktype, بٹ, sig_alg, buf, حجم(buf));
}

ساکن ساخت sshkey *
get_نجی(ثابت حرف *n)
{
	ساخت sshbuf *b;
	ساخت sshkey *ret;

	b = بھرو_file(n);
	ASSERT_INT_EQ(sshkey_parse_نجی_fileblob(b, "", &ret, تہی), 0);
	sshbuf_free(b);
	واپس ret;
}

خالی
sshkey_tests(خالی)
{
	ساخت sshkey *k1 = تہی, *k2 = تہی, *k3 = تہی, *k4 = تہی;
	ساخت sshkey *kr = تہی, *kd = تہی, *ke = تہی, *kf = تہی;
	ساخت sshbuf *b = تہی;

	TEST_آغاز("new invalid");
	k1 = sshkey_new(-42);
	ASSERT_PTR_EQ(k1, تہی);
	TEST_مکمل();

	TEST_آغاز("new/free KEY_UNSPEC");
	k1 = sshkey_new(کلید_UNSPEC);
	ASSERT_PTR_NE(k1, تہی);
	sshkey_free(k1);
	k1 = تہی;
	TEST_مکمل();

#اگر_تعریف_شدہ WITH_OPENSSL
	TEST_آغاز("new/free KEY_RSA");
	k1 = sshkey_new(کلید_RSA);
	ASSERT_PTR_NE(k1, تہی);
	ASSERT_PTR_NE(k1->pkey, تہی);
	sshkey_free(k1);
	k1 = تہی;
	TEST_مکمل();

	TEST_آغاز("new/free KEY_ECDSA");
	k1 = sshkey_new(کلید_ECDSA);
	ASSERT_PTR_NE(k1, تہی);
	ASSERT_PTR_EQ(k1->pkey, تہی);  /* Can't allocate without NID */
	sshkey_free(k1);
	k1 = تہی;
	TEST_مکمل();
#اگر_ختم /* WITH_OPENSSL */

	TEST_آغاز("new/free KEY_ED25519");
	k1 = sshkey_new(کلید_ED25519);
	ASSERT_PTR_NE(k1, تہی);
	/* These should be blank until key loaded or generated */
	ASSERT_PTR_EQ(k1->ed25519_sk, تہی);
	ASSERT_PTR_EQ(k1->ed25519_pk, تہی);
	sshkey_free(k1);
	k1 = تہی;
	TEST_مکمل();

	TEST_آغاز("new/free KEY_MLDSA44_ED25519");
	k1 = sshkey_new(کلید_MLDSA44_ED25519);
	ASSERT_PTR_NE(k1, تہی);
	ASSERT_PTR_EQ(k1->mldsa_ed25519_sk, تہی);
	ASSERT_PTR_EQ(k1->mldsa_ed25519_pk, تہی);
	sshkey_free(k1);
	k1 = تہی;
	TEST_مکمل();

#اگر_تعریف_شدہ WITH_OPENSSL
	TEST_آغاز("generate KEY_RSA too small modulus");
	ASSERT_INT_EQ(sshkey_generate(کلید_RSA, 128, &k1),
	    SSH_ERR_کلید_لمبائی);
	ASSERT_PTR_EQ(k1, تہی);
	TEST_مکمل();

	TEST_آغاز("generate KEY_RSA too large modulus");
	ASSERT_INT_EQ(sshkey_generate(کلید_RSA, 1 << 20, &k1),
	    SSH_ERR_کلید_لمبائی);
	ASSERT_PTR_EQ(k1, تہی);
	TEST_مکمل();


	TEST_آغاز("generate KEY_ECDSA wrong bits");
	ASSERT_INT_EQ(sshkey_generate(کلید_ECDSA, 42, &k1),
	    SSH_ERR_کلید_لمبائی);
	ASSERT_PTR_EQ(k1, تہی);
	sshkey_free(k1);
	k1 = تہی;
	TEST_مکمل();

	TEST_آغاز("generate KEY_RSA");
	ASSERT_INT_EQ(sshkey_generate(کلید_RSA, 767, &kr),
	    SSH_ERR_کلید_لمبائی);
	ASSERT_INT_EQ(sshkey_generate(کلید_RSA, 1024, &kr), 0);
	ASSERT_PTR_NE(kr, تہی);
	ASSERT_PTR_NE(EVP_PKEY_get0_RSA(kr->pkey), تہی);
	ASSERT_PTR_NE(rsa_n(kr), تہی);
	ASSERT_PTR_NE(rsa_e(kr), تہی);
	ASSERT_PTR_NE(rsa_p(kr), تہی);
	ASSERT_INT_EQ(BN_عدد_بٹ(rsa_n(kr)), 1024);
	TEST_مکمل();


	TEST_آغاز("generate KEY_ECDSA");
	ASSERT_INT_EQ(sshkey_generate(کلید_ECDSA, 256, &ke), 0);
	ASSERT_PTR_NE(ke, تہی);
	ASSERT_PTR_NE(EVP_PKEY_get0_EC_کلید(ke->pkey), تہی);
	ASSERT_PTR_NE(EC_کلید_get0_عوامی_کلید(EVP_PKEY_get0_EC_کلید(ke->pkey)),
	    تہی);
	ASSERT_PTR_NE(EC_کلید_get0_نجی_کلید(EVP_PKEY_get0_EC_کلید(ke->pkey)),
	    تہی);
	TEST_مکمل();
#اگر_ختم /* WITH_OPENSSL */

	TEST_آغاز("generate KEY_ED25519");
	ASSERT_INT_EQ(sshkey_generate(کلید_ED25519, 256, &kf), 0);
	ASSERT_PTR_NE(kf, تہی);
	ASSERT_INT_EQ(kf->type, کلید_ED25519);
	ASSERT_PTR_NE(kf->ed25519_pk, تہی);
	ASSERT_PTR_NE(kf->ed25519_sk, تہی);
	TEST_مکمل();

	TEST_آغاز("generate KEY_MLDSA44_ED25519");
	ASSERT_INT_EQ(sshkey_generate(کلید_MLDSA44_ED25519, 256, &k1), 0);
	ASSERT_PTR_NE(k1, تہی);
	ASSERT_INT_EQ(k1->type, کلید_MLDSA44_ED25519);
	ASSERT_PTR_NE(k1->mldsa_ed25519_pk, تہی);
	ASSERT_PTR_NE(k1->mldsa_ed25519_sk, تہی);
	sshkey_free(k1);
	k1 = تہی;
	TEST_مکمل();

#اگر_تعریف_شدہ WITH_OPENSSL
	TEST_آغاز("demote KEY_RSA");
	ASSERT_INT_EQ(sshkey_from_نجی(kr, &k1), 0);
	ASSERT_PTR_NE(k1, تہی);
	ASSERT_PTR_NE(kr, k1);
	ASSERT_INT_EQ(k1->type, کلید_RSA);
	ASSERT_PTR_NE(EVP_PKEY_get0_RSA(k1->pkey), تہی);
	ASSERT_PTR_NE(rsa_n(k1), تہی);
	ASSERT_PTR_NE(rsa_e(k1), تہی);
	ASSERT_PTR_EQ(rsa_p(k1), تہی);
	TEST_مکمل();

	TEST_آغاز("equal KEY_RSA/demoted KEY_RSA");
	ASSERT_INT_EQ(sshkey_equal(kr, k1), 1);
	sshkey_free(k1);
	k1 = تہی;
	TEST_مکمل();


	TEST_آغاز("demote KEY_ECDSA");
	ASSERT_INT_EQ(sshkey_from_نجی(ke, &k1), 0);
	ASSERT_PTR_NE(k1, تہی);
	ASSERT_PTR_NE(ke, k1);
	ASSERT_INT_EQ(k1->type, کلید_ECDSA);
	ASSERT_PTR_NE(EVP_PKEY_get0_EC_کلید(k1->pkey), تہی);
	ASSERT_INT_EQ(k1->ecdsa_nid, ke->ecdsa_nid);
	ASSERT_PTR_NE(EC_کلید_get0_عوامی_کلید(EVP_PKEY_get0_EC_کلید(ke->pkey)),
	   تہی);
	ASSERT_PTR_EQ(EC_کلید_get0_نجی_کلید(EVP_PKEY_get0_EC_کلید(k1->pkey)),
	   تہی);
	TEST_مکمل();

	TEST_آغاز("equal KEY_ECDSA/demoted KEY_ECDSA");
	ASSERT_INT_EQ(sshkey_equal(ke, k1), 1);
	sshkey_free(k1);
	k1 = تہی;
	TEST_مکمل();
#اگر_ختم /* WITH_OPENSSL */

	TEST_آغاز("demote KEY_ED25519");
	ASSERT_INT_EQ(sshkey_from_نجی(kf, &k1), 0);
	ASSERT_PTR_NE(k1, تہی);
	ASSERT_PTR_NE(kf, k1);
	ASSERT_INT_EQ(k1->type, کلید_ED25519);
	ASSERT_PTR_NE(k1->ed25519_pk, تہی);
	ASSERT_PTR_EQ(k1->ed25519_sk, تہی);
	TEST_مکمل();

	TEST_آغاز("equal KEY_ED25519/demoted KEY_ED25519");
	ASSERT_INT_EQ(sshkey_equal(kf, k1), 1);
	sshkey_free(k1);
	k1 = تہی;
	TEST_مکمل();

	TEST_آغاز("demote KEY_MLDSA44_ED25519");
	ASSERT_INT_EQ(sshkey_generate(کلید_MLDSA44_ED25519, 256, &k2), 0);
	ASSERT_INT_EQ(sshkey_from_نجی(k2, &k1), 0);
	ASSERT_PTR_NE(k1, تہی);
	ASSERT_PTR_NE(k2, k1);
	ASSERT_INT_EQ(k1->type, کلید_MLDSA44_ED25519);
	ASSERT_PTR_NE(k1->mldsa_ed25519_pk, تہی);
	ASSERT_PTR_EQ(k1->mldsa_ed25519_sk, تہی);
	TEST_مکمل();

	TEST_آغاز("equal KEY_MLDSA44_ED25519/demoted KEY_MLDSA44_ED25519");
	ASSERT_INT_EQ(sshkey_equal(k2, k1), 1);
	sshkey_free(k1);
	sshkey_free(k2);
	k1 = k2 = تہی;
	TEST_مکمل();

#اگر_تعریف_شدہ WITH_OPENSSL
	TEST_آغاز("equal mismatched key types");
	ASSERT_INT_EQ(sshkey_equal(kd, kr), 0);
	ASSERT_INT_EQ(sshkey_equal(kd, ke), 0);
	ASSERT_INT_EQ(sshkey_equal(kr, ke), 0);
	ASSERT_INT_EQ(sshkey_equal(ke, kf), 0);
	ASSERT_INT_EQ(sshkey_equal(kd, kf), 0);
	TEST_مکمل();

	TEST_آغاز("equal different keys");
	ASSERT_INT_EQ(sshkey_generate(کلید_RSA, 1024, &k1), 0);
	ASSERT_INT_EQ(sshkey_equal(kr, k1), 0);
	sshkey_free(k1);
	k1 = تہی;
	ASSERT_INT_EQ(sshkey_generate(کلید_ECDSA, 256, &k1), 0);
	ASSERT_INT_EQ(sshkey_equal(ke, k1), 0);
	sshkey_free(k1);
	k1 = تہی;
	ASSERT_INT_EQ(sshkey_generate(کلید_ED25519, 256, &k1), 0);
	ASSERT_INT_EQ(sshkey_equal(kf, k1), 0);
	sshkey_free(k1);
	k1 = تہی;
	ASSERT_INT_EQ(sshkey_generate(کلید_MLDSA44_ED25519, 256, &k1), 0);
	ASSERT_INT_EQ(sshkey_generate(کلید_MLDSA44_ED25519, 256, &k2), 0);
	ASSERT_INT_EQ(sshkey_equal(k2, k1), 0);
	sshkey_free(k1);
	sshkey_free(k2);
	k1 = k2 = تہی;
	TEST_مکمل();
#اگر_ختم /* WITH_OPENSSL */

	sshkey_free(kr);
	sshkey_free(kd);
	sshkey_free(ke);
	sshkey_free(kf);
	kr = kd = ke = kf = تہی;

	TEST_آغاز("certify key");
	ASSERT_INT_EQ(sshkey_بھرو_عوامی(test_ڈیٹا_file("ed25519_1.pub"),
	    &k1, تہی), 0);
	k2 = get_نجی("ed25519_2");
	ASSERT_INT_EQ(sshkey_مقصد_certified(k1), 0);
	ASSERT_PTR_NE(k1->cert, تہی);
	k1->cert->type = SSH2_CERT_TYPE_USER;
	k1->cert->serial = 1234;
	k1->cert->کلید_id = strdup("estragon");
	ASSERT_PTR_NE(k1->cert->کلید_id, تہی);
	k1->cert->principals = صفر_حافظہ_دو(4, حجم(*k1->cert->principals));
	ASSERT_PTR_NE(k1->cert->principals, تہی);
	k1->cert->principals[0] = strdup("estragon");
	k1->cert->principals[1] = strdup("vladimir");
	k1->cert->principals[2] = strdup("pozzo");
	k1->cert->principals[3] = strdup("lucky");
	ASSERT_PTR_NE(k1->cert->principals[0], تہی);
	ASSERT_PTR_NE(k1->cert->principals[1], تہی);
	ASSERT_PTR_NE(k1->cert->principals[2], تہی);
	ASSERT_PTR_NE(k1->cert->principals[3], تہی);
	k1->cert->nprincipals = 4;
	k1->cert->valid_after = 0;
	k1->cert->valid_before = (uint64_t)-1;
	sshbuf_free(k1->cert->critical);
	k1->cert->critical = sshbuf_new();
	ASSERT_PTR_NE(k1->cert->critical, تہی);
	sshbuf_free(k1->cert->extensions);
	k1->cert->extensions = sshbuf_new();
	ASSERT_PTR_NE(k1->cert->extensions, تہی);
	put_opt(k1->cert->critical, "force-command", "/usr/bin/true");
	put_opt(k1->cert->critical, "source-address", "127.0.0.1");
	put_opt(k1->cert->extensions, "permit-X11-forwarding", تہی);
	put_opt(k1->cert->extensions, "permit-agent-forwarding", تہی);
	ASSERT_INT_EQ(sshkey_from_نجی(k2, &k1->cert->signature_کلید), 0);
	ASSERT_INT_EQ(sshkey_certify(k1, k2, تہی, تہی, تہی), 0);
	b = sshbuf_new();
	ASSERT_PTR_NE(b, تہی);
	ASSERT_INT_EQ(sshkey_putb(k1, b), 0);
	ASSERT_INT_EQ(sshkey_from_blob(sshbuf_ptr(b), sshbuf_len(b), &k3), 0);

	sshkey_free(k1);
	sshkey_free(k2);
	sshkey_free(k3);
	k1 = k2 = k3 = تہی;
	sshbuf_reset(b);
	TEST_مکمل();

	TEST_آغاز("certify key MLDSA44-ED25519");
	ASSERT_INT_EQ(sshkey_بھرو_عوامی(
	    test_ڈیٹا_file("mldsa44_ed25519_1.pub"), &k1, تہی), 0);
	k2 = get_نجی("mldsa44_ed25519_2");
	ASSERT_INT_EQ(sshkey_مقصد_certified(k1), 0);
	ASSERT_PTR_NE(k1->cert, تہی);
	k1->cert->type = SSH2_CERT_TYPE_USER;
	k1->cert->serial = 1234;
	k1->cert->کلید_id = strdup("estragon");
	ASSERT_PTR_NE(k1->cert->کلید_id, تہی);
	k1->cert->principals = صفر_حافظہ_دو(4, حجم(*k1->cert->principals));
	ASSERT_PTR_NE(k1->cert->principals, تہی);
	k1->cert->principals[0] = strdup("estragon");
	k1->cert->principals[1] = strdup("vladimir");
	k1->cert->principals[2] = strdup("pozzo");
	k1->cert->principals[3] = strdup("lucky");
	ASSERT_PTR_NE(k1->cert->principals[0], تہی);
	ASSERT_PTR_NE(k1->cert->principals[1], تہی);
	ASSERT_PTR_NE(k1->cert->principals[2], تہی);
	ASSERT_PTR_NE(k1->cert->principals[3], تہی);
	k1->cert->nprincipals = 4;
	k1->cert->valid_after = 0;
	k1->cert->valid_before = (uint64_t)-1;
	sshbuf_free(k1->cert->critical);
	k1->cert->critical = sshbuf_new();
	ASSERT_PTR_NE(k1->cert->critical, تہی);
	sshbuf_free(k1->cert->extensions);
	k1->cert->extensions = sshbuf_new();
	ASSERT_PTR_NE(k1->cert->extensions, تہی);
	put_opt(k1->cert->critical, "force-command", "/usr/bin/true");
	put_opt(k1->cert->critical, "source-address", "127.0.0.1");
	put_opt(k1->cert->extensions, "permit-X11-forwarding", تہی);
	put_opt(k1->cert->extensions, "permit-agent-forwarding", تہی);
	ASSERT_INT_EQ(sshkey_from_نجی(k2, &k1->cert->signature_کلید), 0);
	ASSERT_INT_EQ(sshkey_certify(k1, k2, تہی, تہی, تہی), 0);
	b = sshbuf_new();
	ASSERT_PTR_NE(b, تہی);
	ASSERT_INT_EQ(sshkey_putb(k1, b), 0);
	ASSERT_INT_EQ(sshkey_from_blob(sshbuf_ptr(b), sshbuf_len(b), &k3), 0);
	sshkey_free(k1);
	sshkey_free(k2);
	sshkey_free(k3);
	k1 = k2 = k3 = تہی;
	sshbuf_reset(b);
	TEST_مکمل();

#اگر_تعریف_شدہ WITH_OPENSSL
	TEST_آغاز("sign and verify RSA");
	k1 = get_نجی("rsa_1");
	ASSERT_INT_EQ(sshkey_بھرو_عوامی(test_ڈیٹا_file("rsa_2.pub"), &k2,
	    تہی), 0);
	signature_tests(k1, k2, "ssh-rsa");
	sshkey_free(k1);
	sshkey_free(k2);
	k1 = k2 = تہی;
	TEST_مکمل();

	TEST_آغاز("sign and verify RSA-SHA256");
	k1 = get_نجی("rsa_1");
	ASSERT_INT_EQ(sshkey_بھرو_عوامی(test_ڈیٹا_file("rsa_2.pub"), &k2,
	    تہی), 0);
	signature_tests(k1, k2, "rsa-sha2-256");
	sshkey_free(k1);
	sshkey_free(k2);
	k1 = k2 = تہی;
	TEST_مکمل();

	TEST_آغاز("sign and verify RSA-SHA512");
	k1 = get_نجی("rsa_1");
	ASSERT_INT_EQ(sshkey_بھرو_عوامی(test_ڈیٹا_file("rsa_2.pub"), &k2,
	    تہی), 0);
	signature_tests(k1, k2, "rsa-sha2-512");
	sshkey_free(k1);
	sshkey_free(k2);
	k1 = k2 = تہی;
	TEST_مکمل();


	TEST_آغاز("sign and verify ECDSA");
	k1 = get_نجی("ecdsa_1");
	ASSERT_INT_EQ(sshkey_بھرو_عوامی(test_ڈیٹا_file("ecdsa_2.pub"), &k2,
	    تہی), 0);
	signature_tests(k1, k2, تہی);
	sshkey_free(k1);
	sshkey_free(k2);
	k1 = k2 = تہی;
	TEST_مکمل();
#اگر_ختم /* WITH_OPENSSL */

	TEST_آغاز("sign and verify ED25519");
	k1 = get_نجی("ed25519_1");
	ASSERT_INT_EQ(sshkey_بھرو_عوامی(test_ڈیٹا_file("ed25519_2.pub"), &k2,
	    تہی), 0);
	signature_tests(k1, k2, تہی);
	sshkey_free(k1);
	sshkey_free(k2);
	k1 = k2 = تہی;
	TEST_مکمل();

	TEST_آغاز("sign and verify MLDSA44-ED25519");
	k1 = get_نجی("mldsa44_ed25519_1");
	ASSERT_INT_EQ(sshkey_بھرو_عوامی(
	    test_ڈیٹا_file("mldsa44_ed25519_2.pub"), &k2, تہی), 0);
	signature_tests(k1, k2, تہی);
	sshkey_free(k1);
	sshkey_free(k2);
	k1 = k2 = تہی;
	TEST_مکمل();

#اگر_تعریف_شدہ WITH_OPENSSL
	TEST_آغاز("nested certificate");
	ASSERT_INT_EQ(sshkey_بھرو_cert(test_ڈیٹا_file("rsa_1"), &k1), 0);
	ASSERT_INT_EQ(sshkey_بھرو_عوامی(test_ڈیٹا_file("rsa_1.pub"), &k2,
	    تہی), 0);
	k3 = get_نجی("rsa_1");
	build_cert(b, k2, "ssh-rsa-cert-v01@openssh.com", k3, k1, تہی);
	ASSERT_INT_EQ(sshkey_from_blob(sshbuf_ptr(b), sshbuf_len(b), &k4),
	    SSH_ERR_کلید_CERT_INVALID_SIGN_کلید);
	ASSERT_PTR_EQ(k4, تہی);
	sshkey_free(k1);
	sshkey_free(k2);
	sshkey_free(k3);
	k1 = k2 = k3 = تہی;
	sshbuf_free(b);
	TEST_مکمل();
#اگر_ختم /* WITH_OPENSSL */
}

خالی
sshkey_benchmarks(خالی)
{
	ساخت sshkey *k = تہی;

#اگر_تعریف_شدہ WITH_OPENSSL
	BENCH_آغاز("generate RSA-1024");
	TEST_آغاز("generate KEY_RSA");
	ASSERT_INT_EQ(sshkey_generate(کلید_RSA, 1024, &k), 0);
	ASSERT_PTR_NE(k, تہی);
	sshkey_free(k);
	k = تہی;
	TEST_مکمل();
	BENCH_اختتام("keys");

	BENCH_آغاز("generate RSA-2048");
	TEST_آغاز("generate KEY_RSA");
	ASSERT_INT_EQ(sshkey_generate(کلید_RSA, 2048, &k), 0);
	ASSERT_PTR_NE(k, تہی);
	sshkey_free(k);
	k = تہی;
	TEST_مکمل();
	BENCH_اختتام("keys");

	BENCH_آغاز("generate ECDSA-256");
	TEST_آغاز("generate KEY_ECDSA");
	ASSERT_INT_EQ(sshkey_generate(کلید_ECDSA, 256, &k), 0);
	ASSERT_PTR_NE(k, تہی);
	sshkey_free(k);
	k = تہی;
	TEST_مکمل();
	BENCH_اختتام("keys");

	BENCH_آغاز("generate ECDSA-384");
	TEST_آغاز("generate KEY_ECDSA");
	ASSERT_INT_EQ(sshkey_generate(کلید_ECDSA, 384, &k), 0);
	ASSERT_PTR_NE(k, تہی);
	sshkey_free(k);
	k = تہی;
	TEST_مکمل();
	BENCH_اختتام("keys");

	BENCH_آغاز("generate ECDSA-521");
	TEST_آغاز("generate KEY_ECDSA");
	ASSERT_INT_EQ(sshkey_generate(کلید_ECDSA, 521, &k), 0);
	ASSERT_PTR_NE(k, تہی);
	sshkey_free(k);
	k = تہی;
	TEST_مکمل();
	BENCH_اختتام("keys");
#اگر_ختم /* WITH_OPENSSL */

	BENCH_آغاز("generate ED25519");
	TEST_آغاز("generate KEY_ED25519");
	ASSERT_INT_EQ(sshkey_generate(کلید_ED25519, 256, &k), 0);
	ASSERT_PTR_NE(k, تہی);
	sshkey_free(k);
	k = تہی;
	TEST_مکمل();
	BENCH_اختتام("keys");

	BENCH_آغاز("generate MLDSA44-ED25519");
	TEST_آغاز("generate KEY_MLDSA44_ED25519");
	ASSERT_INT_EQ(sshkey_generate(کلید_MLDSA44_ED25519, 256, &k), 0);
	ASSERT_PTR_NE(k, تہی);
	sshkey_free(k);
	k = تہی;
	TEST_مکمل();
	BENCH_اختتام("keys");

#اگر_تعریف_شدہ WITH_OPENSSL
	/* sign */
	signature_benchmark("RSA-1024/SHA1", کلید_RSA, 1024, "ssh-rsa", 0);
	signature_benchmark("RSA-1024/SHA256", کلید_RSA, 1024, "rsa-sha2-256", 0);
	signature_benchmark("RSA-1024/SHA512", کلید_RSA, 1024, "rsa-sha2-512", 0);
	signature_benchmark("RSA-2048/SHA1", کلید_RSA, 2048, "ssh-rsa", 0);
	signature_benchmark("RSA-2048/SHA256", کلید_RSA, 2048, "rsa-sha2-256", 0);
	signature_benchmark("RSA-2048/SHA512", کلید_RSA, 2048, "rsa-sha2-512", 0);
	signature_benchmark("ECDSA-256", کلید_ECDSA, 256, تہی, 0);
	signature_benchmark("ECDSA-384", کلید_ECDSA, 384, تہی, 0);
	signature_benchmark("ECDSA-521", کلید_ECDSA, 521, تہی, 0);
	signature_benchmark("ED25519", کلید_ED25519, 0, تہی, 0);
	signature_benchmark("MLDSA44-ED25519", کلید_MLDSA44_ED25519, 0, تہی, 0);

	/* verify */
	signature_benchmark("RSA-1024/SHA1", کلید_RSA, 1024, "ssh-rsa", 1);
	signature_benchmark("RSA-1024/SHA256", کلید_RSA, 1024, "rsa-sha2-256", 1);
	signature_benchmark("RSA-1024/SHA512", کلید_RSA, 1024, "rsa-sha2-512", 1);
	signature_benchmark("RSA-2048/SHA1", کلید_RSA, 2048, "ssh-rsa", 1);
	signature_benchmark("RSA-2048/SHA256", کلید_RSA, 2048, "rsa-sha2-256", 1);
	signature_benchmark("RSA-2048/SHA512", کلید_RSA, 2048, "rsa-sha2-512", 1);
	signature_benchmark("ECDSA-256", کلید_ECDSA, 256, تہی, 1);
	signature_benchmark("ECDSA-384", کلید_ECDSA, 384, تہی, 1);
	signature_benchmark("ECDSA-521", کلید_ECDSA, 521, تہی, 1);
#اگر_ختم /* WITH_OPENSSL */
	signature_benchmark("ED25519", کلید_ED25519, 0, تہی, 1);
	signature_benchmark("MLDSA44-ED25519", کلید_MLDSA44_ED25519, 0, تہی, 1);
}
