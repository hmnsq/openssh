/* 	$OpenBSD: test_sshkey.c,v 1.34 2026/06/14 04:08:06 djm Exp $ */
/*
 * Regress test for sshkey.h key management API
 *
 * Placed in the public domain
 */

#ضمن "includes.h"

#ضمن <sys/types.h>
#ضمن <stdio.h>
#ضمن <stdint.h>
#ضمن <stdlib.h>
#ضمن <string.h>

#جيڪڏهن_وصف_ٿيل WITH_OPENSSL
#ضمن <openssl/bn.h>
#ضمن <openssl/ec.h>
#ضمن <openssl/rsa.h>
#جيڪڏهن_پورو

#ضمن "../test_helper/test_helper.h"

#ضمن "ssherr.h"
#ضمن "sshbuf.h"
#وصف_ڪريو SSHBUF_اندروني 1	/* access internals for testing */
#ضمن "sshkey.h"

#ضمن "authfile.h"
#ضمن "common.h"
#ضمن "ssh2.h"

فراغ sshkey_tests(فراغ);
فراغ sshkey_benchmarks(فراغ);

ساكن فراغ
put_opt(بنية sshbuf *b, ثابت حرف *name, ثابت حرف *قدر)
{
	بنية sshbuf *sect;

	sect = sshbuf_new();
	ASSERT_PTR_NE(sect, عدم);
	ASSERT_INT_EQ(sshbuf_put_cstring(b, name), 0);
	إذا (قدر != عدم)
		ASSERT_INT_EQ(sshbuf_put_cstring(sect, قدر), 0);
	ASSERT_INT_EQ(sshbuf_put_stringb(b, sect), 0);
	sshbuf_free(sect);
}

#جيڪڏهن_وصف_ٿيل WITH_OPENSSL
ساكن فراغ
build_cert(بنية sshbuf *b, بنية sshkey *k, ثابت حرف *type,
    بنية sshkey *sign_ڪنجي, بنية sshkey *ca_ڪنجي,
    ثابت حرف *sig_alg)
{
	بنية sshbuf *ca_buf, *pk, *principals, *critopts, *exts;
	u_char *sigblob;
	سائيز_t siglen;

	ca_buf = sshbuf_new();
	ASSERT_PTR_NE(ca_buf, عدم);
	ASSERT_INT_EQ(sshkey_putb(ca_ڪنجي, ca_buf), 0);

	/*
	 * Get the public key serialisation by rendering the key and skipping
	 * the type string. This is a bit of a hack :/
	 */
	pk = sshbuf_new();
	ASSERT_PTR_NE(pk, عدم);
	ASSERT_INT_EQ(sshkey_putb_plain(k, pk), 0);
	ASSERT_INT_EQ(sshbuf_skip_string(pk), 0);

	principals = sshbuf_new();
	ASSERT_PTR_NE(principals, عدم);
	ASSERT_INT_EQ(sshbuf_put_cstring(principals, "gsamsa"), 0);
	ASSERT_INT_EQ(sshbuf_put_cstring(principals, "gregor"), 0);

	critopts = sshbuf_new();
	ASSERT_PTR_NE(critopts, عدم);
	put_opt(critopts, "force-command", "/usr/local/bin/nethack");
	put_opt(critopts, "source-address", "192.168.0.0/24,127.0.0.1,::1");

	exts = sshbuf_new();
	ASSERT_PTR_NE(exts, عدم);
	put_opt(critopts, "permit-X11-forwarding", عدم);

	ASSERT_INT_EQ(sshbuf_put_cstring(b, type), 0);
	ASSERT_INT_EQ(sshbuf_put_cstring(b, "noncenoncenonce!"), 0); /* nonce */
	ASSERT_INT_EQ(sshbuf_putb(b, pk), 0); /* public key serialisation */
	ASSERT_INT_EQ(sshbuf_put_u64(b, 1234), 0); /* serial */
	ASSERT_INT_EQ(sshbuf_put_u32(b, SSH2_CERT_TYPE_USER), 0); /* type */
	ASSERT_INT_EQ(sshbuf_put_cstring(b, "gregor"), 0); /* key ID */
	ASSERT_INT_EQ(sshbuf_put_stringb(b, principals), 0); /* principals */
	ASSERT_INT_EQ(sshbuf_put_u64(b, 0), 0); /*شروعات*/
	ASSERT_INT_EQ(sshbuf_put_u64(b, 0xffffffffffffffffULL), 0); /*پڇاڙي*/
	ASSERT_INT_EQ(sshbuf_put_stringb(b, critopts), 0); /* options */
	ASSERT_INT_EQ(sshbuf_put_stringb(b, exts), 0); /* extensions */
	ASSERT_INT_EQ(sshbuf_put_string(b, عدم, 0), 0); /* reserved */
	ASSERT_INT_EQ(sshbuf_put_stringb(b, ca_buf), 0); /* signature key */
	ASSERT_INT_EQ(sshkey_sign(sign_ڪنجي, &sigblob, &siglen,
	    sshbuf_ptr(b), sshbuf_len(b), sig_alg, عدم, عدم, 0), 0);
	ASSERT_INT_EQ(sshbuf_put_string(b, sigblob, siglen), 0); /* signature */

	حرر(sigblob);
	sshbuf_free(ca_buf);
	sshbuf_free(exts);
	sshbuf_free(critopts);
	sshbuf_free(principals);
	sshbuf_free(pk);
}
#جيڪڏهن_پورو /* WITH_OPENSSL */

ساكن فراغ
signature_test(بنية sshkey *k, بنية sshkey *bad, ثابت حرف *sig_alg,
    ثابت u_char *d, سائيز_t l)
{
	سائيز_t len;
	u_char *sig;

	ASSERT_INT_EQ(sshkey_sign(k, &sig, &len, d, l, sig_alg,
	    عدم, عدم, 0), 0);
	ASSERT_سائيز_T_GT(len, 8);
	ASSERT_PTR_NE(sig, عدم);
	ASSERT_INT_EQ(sshkey_verify(k, sig, len, d, l, عدم, 0, عدم), 0);
	ASSERT_INT_NE(sshkey_verify(bad, sig, len, d, l, عدم, 0, عدم), 0);
	/* Fuzz test is more comprehensive, this is just a smoke test */
	sig[len - 5] ^= 0x10;
	ASSERT_INT_NE(sshkey_verify(k, sig, len, d, l, عدم, 0, عدم), 0);
	حرر(sig);
}

ساكن فراغ
signature_bench(ثابت حرف *name, صحيح ktype, صحيح بٽ, ثابت حرف *sig_alg,
    ثابت u_char *d, سائيز_t l)
{
	بنية sshkey *k;
	سائيز_t len;
	u_char *sig;
	حرف testname[256];

	snprintf(testname, حجم(testname), "sign %s", name);
	TEST_شروعات(testname);
	ASSERT_INT_EQ(sshkey_generate(ktype, بٽ, &k), 0);
	ASSERT_PTR_NE(k, عدم);

	BENCH_شروعات(testname);
	ASSERT_INT_EQ(sshkey_sign(k, &sig, &len, d, l, sig_alg,
	    عدم, عدم, 0), 0);
	حرر(sig);
	BENCH_پڄاڻي("sign");

	sshkey_free(k);
	TEST_پورو();
}

ساكن فراغ
verify_bench(ثابت حرف *name, صحيح ktype, صحيح بٽ, ثابت حرف *sig_alg,
    ثابت u_char *d, سائيز_t l)
{
	بنية sshkey *k;
	سائيز_t len;
	u_char *sig;
	حرف testname[256];

	snprintf(testname, حجم(testname), "verify %s", name);
	TEST_شروعات(testname);
	ASSERT_INT_EQ(sshkey_generate(ktype, بٽ, &k), 0);
	ASSERT_PTR_NE(k, عدم);

	ASSERT_INT_EQ(sshkey_sign(k, &sig, &len, d, l, sig_alg,
	    عدم, عدم, 0), 0);
	BENCH_شروعات(testname);
	ASSERT_INT_EQ(sshkey_verify(k, sig, len, d, l, عدم, 0, عدم), 0);
	BENCH_پڄاڻي("verify");

	حرر(sig);
	sshkey_free(k);
	TEST_پورو();
}

ساكن فراغ
banana(u_char *s, سائيز_t l)
{
	سائيز_t o;
	ثابت u_char the_banana[] = { 'b', 'a', 'n', 'a', 'n', 'a' };

	لكل (o = 0; o < l; o += حجم(the_banana)) {
		إذا (l - o < حجم(the_banana)) {
			يادگيري_نقل(s + o, "nanananana", l - o);
			اكسر;
		}
		يادگيري_نقل(s + o, the_banana, حجم(the_banana));
	}
}

ساكن فراغ
signature_tests(بنية sshkey *k, بنية sshkey *bad, ثابت حرف *sig_alg)
{
	u_char i, buf[2049];
	سائيز_t lens[] = {
		1, 2, 7, 8, 9, 15, 16, 17, 31, 32, 33, 127, 128, 129,
		255, 256, 257, 1023, 1024, 1025, 2047, 2048, 2049
	};

	لكل (i = 0; i < (حجم(lens)/حجم(lens[0])); i++) {
		test_subtest_info("%s key, banana length %zu",
		    sshkey_type(k), lens[i]);
		banana(buf, lens[i]);
		signature_test(k, bad, sig_alg, buf, lens[i]);
	}
}

ساكن فراغ
signature_benchmark(ثابت حرف *name, صحيح ktype, صحيح بٽ,
    ثابت حرف *sig_alg, صحيح bench_verify)
{
	u_char buf[256];

	banana(buf, حجم(buf));
	إذا (bench_verify)
		verify_bench(name, ktype, بٽ, sig_alg, buf, حجم(buf));
	وإلا
		signature_bench(name, ktype, بٽ, sig_alg, buf, حجم(buf));
}

ساكن بنية sshkey *
get_ذاتي(ثابت حرف *n)
{
	بنية sshbuf *b;
	بنية sshkey *ret;

	b = ڀريو_file(n);
	ASSERT_INT_EQ(sshkey_parse_ذاتي_fileblob(b, "", &ret, عدم), 0);
	sshbuf_free(b);
	أرجع ret;
}

فراغ
sshkey_tests(فراغ)
{
	بنية sshkey *k1 = عدم, *k2 = عدم, *k3 = عدم, *k4 = عدم;
	بنية sshkey *kr = عدم, *kd = عدم, *ke = عدم, *kf = عدم;
	بنية sshbuf *b = عدم;

	TEST_شروعات("new invalid");
	k1 = sshkey_new(-42);
	ASSERT_PTR_EQ(k1, عدم);
	TEST_پورو();

	TEST_شروعات("new/free KEY_UNSPEC");
	k1 = sshkey_new(ڪنجي_UNSPEC);
	ASSERT_PTR_NE(k1, عدم);
	sshkey_free(k1);
	k1 = عدم;
	TEST_پورو();

#جيڪڏهن_وصف_ٿيل WITH_OPENSSL
	TEST_شروعات("new/free KEY_RSA");
	k1 = sshkey_new(ڪنجي_RSA);
	ASSERT_PTR_NE(k1, عدم);
	ASSERT_PTR_NE(k1->pkey, عدم);
	sshkey_free(k1);
	k1 = عدم;
	TEST_پورو();

	TEST_شروعات("new/free KEY_ECDSA");
	k1 = sshkey_new(ڪنجي_ECDSA);
	ASSERT_PTR_NE(k1, عدم);
	ASSERT_PTR_EQ(k1->pkey, عدم);  /* Can't allocate without NID */
	sshkey_free(k1);
	k1 = عدم;
	TEST_پورو();
#جيڪڏهن_پورو /* WITH_OPENSSL */

	TEST_شروعات("new/free KEY_ED25519");
	k1 = sshkey_new(ڪنجي_ED25519);
	ASSERT_PTR_NE(k1, عدم);
	/* These should be blank until key loaded or generated */
	ASSERT_PTR_EQ(k1->ed25519_sk, عدم);
	ASSERT_PTR_EQ(k1->ed25519_pk, عدم);
	sshkey_free(k1);
	k1 = عدم;
	TEST_پورو();

	TEST_شروعات("new/free KEY_MLDSA44_ED25519");
	k1 = sshkey_new(ڪنجي_MLDSA44_ED25519);
	ASSERT_PTR_NE(k1, عدم);
	ASSERT_PTR_EQ(k1->mldsa_ed25519_sk, عدم);
	ASSERT_PTR_EQ(k1->mldsa_ed25519_pk, عدم);
	sshkey_free(k1);
	k1 = عدم;
	TEST_پورو();

#جيڪڏهن_وصف_ٿيل WITH_OPENSSL
	TEST_شروعات("generate KEY_RSA too small modulus");
	ASSERT_INT_EQ(sshkey_generate(ڪنجي_RSA, 128, &k1),
	    SSH_ERR_ڪنجي_ڊيگهائي);
	ASSERT_PTR_EQ(k1, عدم);
	TEST_پورو();

	TEST_شروعات("generate KEY_RSA too large modulus");
	ASSERT_INT_EQ(sshkey_generate(ڪنجي_RSA, 1 << 20, &k1),
	    SSH_ERR_ڪنجي_ڊيگهائي);
	ASSERT_PTR_EQ(k1, عدم);
	TEST_پورو();


	TEST_شروعات("generate KEY_ECDSA wrong bits");
	ASSERT_INT_EQ(sshkey_generate(ڪنجي_ECDSA, 42, &k1),
	    SSH_ERR_ڪنجي_ڊيگهائي);
	ASSERT_PTR_EQ(k1, عدم);
	sshkey_free(k1);
	k1 = عدم;
	TEST_پورو();

	TEST_شروعات("generate KEY_RSA");
	ASSERT_INT_EQ(sshkey_generate(ڪنجي_RSA, 767, &kr),
	    SSH_ERR_ڪنجي_ڊيگهائي);
	ASSERT_INT_EQ(sshkey_generate(ڪنجي_RSA, 1024, &kr), 0);
	ASSERT_PTR_NE(kr, عدم);
	ASSERT_PTR_NE(EVP_PKEY_get0_RSA(kr->pkey), عدم);
	ASSERT_PTR_NE(rsa_n(kr), عدم);
	ASSERT_PTR_NE(rsa_e(kr), عدم);
	ASSERT_PTR_NE(rsa_p(kr), عدم);
	ASSERT_INT_EQ(BN_انگ_بٽ(rsa_n(kr)), 1024);
	TEST_پورو();


	TEST_شروعات("generate KEY_ECDSA");
	ASSERT_INT_EQ(sshkey_generate(ڪنجي_ECDSA, 256, &ke), 0);
	ASSERT_PTR_NE(ke, عدم);
	ASSERT_PTR_NE(EVP_PKEY_get0_EC_ڪنجي(ke->pkey), عدم);
	ASSERT_PTR_NE(EC_ڪنجي_get0_عوامي_ڪنجي(EVP_PKEY_get0_EC_ڪنجي(ke->pkey)),
	    عدم);
	ASSERT_PTR_NE(EC_ڪنجي_get0_ذاتي_ڪنجي(EVP_PKEY_get0_EC_ڪنجي(ke->pkey)),
	    عدم);
	TEST_پورو();
#جيڪڏهن_پورو /* WITH_OPENSSL */

	TEST_شروعات("generate KEY_ED25519");
	ASSERT_INT_EQ(sshkey_generate(ڪنجي_ED25519, 256, &kf), 0);
	ASSERT_PTR_NE(kf, عدم);
	ASSERT_INT_EQ(kf->type, ڪنجي_ED25519);
	ASSERT_PTR_NE(kf->ed25519_pk, عدم);
	ASSERT_PTR_NE(kf->ed25519_sk, عدم);
	TEST_پورو();

	TEST_شروعات("generate KEY_MLDSA44_ED25519");
	ASSERT_INT_EQ(sshkey_generate(ڪنجي_MLDSA44_ED25519, 256, &k1), 0);
	ASSERT_PTR_NE(k1, عدم);
	ASSERT_INT_EQ(k1->type, ڪنجي_MLDSA44_ED25519);
	ASSERT_PTR_NE(k1->mldsa_ed25519_pk, عدم);
	ASSERT_PTR_NE(k1->mldsa_ed25519_sk, عدم);
	sshkey_free(k1);
	k1 = عدم;
	TEST_پورو();

#جيڪڏهن_وصف_ٿيل WITH_OPENSSL
	TEST_شروعات("demote KEY_RSA");
	ASSERT_INT_EQ(sshkey_from_ذاتي(kr, &k1), 0);
	ASSERT_PTR_NE(k1, عدم);
	ASSERT_PTR_NE(kr, k1);
	ASSERT_INT_EQ(k1->type, ڪنجي_RSA);
	ASSERT_PTR_NE(EVP_PKEY_get0_RSA(k1->pkey), عدم);
	ASSERT_PTR_NE(rsa_n(k1), عدم);
	ASSERT_PTR_NE(rsa_e(k1), عدم);
	ASSERT_PTR_EQ(rsa_p(k1), عدم);
	TEST_پورو();

	TEST_شروعات("equal KEY_RSA/demoted KEY_RSA");
	ASSERT_INT_EQ(sshkey_equal(kr, k1), 1);
	sshkey_free(k1);
	k1 = عدم;
	TEST_پورو();


	TEST_شروعات("demote KEY_ECDSA");
	ASSERT_INT_EQ(sshkey_from_ذاتي(ke, &k1), 0);
	ASSERT_PTR_NE(k1, عدم);
	ASSERT_PTR_NE(ke, k1);
	ASSERT_INT_EQ(k1->type, ڪنجي_ECDSA);
	ASSERT_PTR_NE(EVP_PKEY_get0_EC_ڪنجي(k1->pkey), عدم);
	ASSERT_INT_EQ(k1->ecdsa_nid, ke->ecdsa_nid);
	ASSERT_PTR_NE(EC_ڪنجي_get0_عوامي_ڪنجي(EVP_PKEY_get0_EC_ڪنجي(ke->pkey)),
	   عدم);
	ASSERT_PTR_EQ(EC_ڪنجي_get0_ذاتي_ڪنجي(EVP_PKEY_get0_EC_ڪنجي(k1->pkey)),
	   عدم);
	TEST_پورو();

	TEST_شروعات("equal KEY_ECDSA/demoted KEY_ECDSA");
	ASSERT_INT_EQ(sshkey_equal(ke, k1), 1);
	sshkey_free(k1);
	k1 = عدم;
	TEST_پورو();
#جيڪڏهن_پورو /* WITH_OPENSSL */

	TEST_شروعات("demote KEY_ED25519");
	ASSERT_INT_EQ(sshkey_from_ذاتي(kf, &k1), 0);
	ASSERT_PTR_NE(k1, عدم);
	ASSERT_PTR_NE(kf, k1);
	ASSERT_INT_EQ(k1->type, ڪنجي_ED25519);
	ASSERT_PTR_NE(k1->ed25519_pk, عدم);
	ASSERT_PTR_EQ(k1->ed25519_sk, عدم);
	TEST_پورو();

	TEST_شروعات("equal KEY_ED25519/demoted KEY_ED25519");
	ASSERT_INT_EQ(sshkey_equal(kf, k1), 1);
	sshkey_free(k1);
	k1 = عدم;
	TEST_پورو();

	TEST_شروعات("demote KEY_MLDSA44_ED25519");
	ASSERT_INT_EQ(sshkey_generate(ڪنجي_MLDSA44_ED25519, 256, &k2), 0);
	ASSERT_INT_EQ(sshkey_from_ذاتي(k2, &k1), 0);
	ASSERT_PTR_NE(k1, عدم);
	ASSERT_PTR_NE(k2, k1);
	ASSERT_INT_EQ(k1->type, ڪنجي_MLDSA44_ED25519);
	ASSERT_PTR_NE(k1->mldsa_ed25519_pk, عدم);
	ASSERT_PTR_EQ(k1->mldsa_ed25519_sk, عدم);
	TEST_پورو();

	TEST_شروعات("equal KEY_MLDSA44_ED25519/demoted KEY_MLDSA44_ED25519");
	ASSERT_INT_EQ(sshkey_equal(k2, k1), 1);
	sshkey_free(k1);
	sshkey_free(k2);
	k1 = k2 = عدم;
	TEST_پورو();

#جيڪڏهن_وصف_ٿيل WITH_OPENSSL
	TEST_شروعات("equal mismatched key types");
	ASSERT_INT_EQ(sshkey_equal(kd, kr), 0);
	ASSERT_INT_EQ(sshkey_equal(kd, ke), 0);
	ASSERT_INT_EQ(sshkey_equal(kr, ke), 0);
	ASSERT_INT_EQ(sshkey_equal(ke, kf), 0);
	ASSERT_INT_EQ(sshkey_equal(kd, kf), 0);
	TEST_پورو();

	TEST_شروعات("equal different keys");
	ASSERT_INT_EQ(sshkey_generate(ڪنجي_RSA, 1024, &k1), 0);
	ASSERT_INT_EQ(sshkey_equal(kr, k1), 0);
	sshkey_free(k1);
	k1 = عدم;
	ASSERT_INT_EQ(sshkey_generate(ڪنجي_ECDSA, 256, &k1), 0);
	ASSERT_INT_EQ(sshkey_equal(ke, k1), 0);
	sshkey_free(k1);
	k1 = عدم;
	ASSERT_INT_EQ(sshkey_generate(ڪنجي_ED25519, 256, &k1), 0);
	ASSERT_INT_EQ(sshkey_equal(kf, k1), 0);
	sshkey_free(k1);
	k1 = عدم;
	ASSERT_INT_EQ(sshkey_generate(ڪنجي_MLDSA44_ED25519, 256, &k1), 0);
	ASSERT_INT_EQ(sshkey_generate(ڪنجي_MLDSA44_ED25519, 256, &k2), 0);
	ASSERT_INT_EQ(sshkey_equal(k2, k1), 0);
	sshkey_free(k1);
	sshkey_free(k2);
	k1 = k2 = عدم;
	TEST_پورو();
#جيڪڏهن_پورو /* WITH_OPENSSL */

	sshkey_free(kr);
	sshkey_free(kd);
	sshkey_free(ke);
	sshkey_free(kf);
	kr = kd = ke = kf = عدم;

	TEST_شروعات("certify key");
	ASSERT_INT_EQ(sshkey_ڀريو_عوامي(test_معلومات_file("ed25519_1.pub"),
	    &k1, عدم), 0);
	k2 = get_ذاتي("ed25519_2");
	ASSERT_INT_EQ(sshkey_منزل_certified(k1), 0);
	ASSERT_PTR_NE(k1->cert, عدم);
	k1->cert->type = SSH2_CERT_TYPE_USER;
	k1->cert->serial = 1234;
	k1->cert->ڪنجي_id = strdup("estragon");
	ASSERT_PTR_NE(k1->cert->ڪنجي_id, عدم);
	k1->cert->principals = صفر_يادگيري_ڏيو(4, حجم(*k1->cert->principals));
	ASSERT_PTR_NE(k1->cert->principals, عدم);
	k1->cert->principals[0] = strdup("estragon");
	k1->cert->principals[1] = strdup("vladimir");
	k1->cert->principals[2] = strdup("pozzo");
	k1->cert->principals[3] = strdup("lucky");
	ASSERT_PTR_NE(k1->cert->principals[0], عدم);
	ASSERT_PTR_NE(k1->cert->principals[1], عدم);
	ASSERT_PTR_NE(k1->cert->principals[2], عدم);
	ASSERT_PTR_NE(k1->cert->principals[3], عدم);
	k1->cert->nprincipals = 4;
	k1->cert->valid_after = 0;
	k1->cert->valid_before = (uint64_t)-1;
	sshbuf_free(k1->cert->critical);
	k1->cert->critical = sshbuf_new();
	ASSERT_PTR_NE(k1->cert->critical, عدم);
	sshbuf_free(k1->cert->extensions);
	k1->cert->extensions = sshbuf_new();
	ASSERT_PTR_NE(k1->cert->extensions, عدم);
	put_opt(k1->cert->critical, "force-command", "/usr/bin/true");
	put_opt(k1->cert->critical, "source-address", "127.0.0.1");
	put_opt(k1->cert->extensions, "permit-X11-forwarding", عدم);
	put_opt(k1->cert->extensions, "permit-agent-forwarding", عدم);
	ASSERT_INT_EQ(sshkey_from_ذاتي(k2, &k1->cert->signature_ڪنجي), 0);
	ASSERT_INT_EQ(sshkey_certify(k1, k2, عدم, عدم, عدم), 0);
	b = sshbuf_new();
	ASSERT_PTR_NE(b, عدم);
	ASSERT_INT_EQ(sshkey_putb(k1, b), 0);
	ASSERT_INT_EQ(sshkey_from_blob(sshbuf_ptr(b), sshbuf_len(b), &k3), 0);

	sshkey_free(k1);
	sshkey_free(k2);
	sshkey_free(k3);
	k1 = k2 = k3 = عدم;
	sshbuf_reset(b);
	TEST_پورو();

	TEST_شروعات("certify key MLDSA44-ED25519");
	ASSERT_INT_EQ(sshkey_ڀريو_عوامي(
	    test_معلومات_file("mldsa44_ed25519_1.pub"), &k1, عدم), 0);
	k2 = get_ذاتي("mldsa44_ed25519_2");
	ASSERT_INT_EQ(sshkey_منزل_certified(k1), 0);
	ASSERT_PTR_NE(k1->cert, عدم);
	k1->cert->type = SSH2_CERT_TYPE_USER;
	k1->cert->serial = 1234;
	k1->cert->ڪنجي_id = strdup("estragon");
	ASSERT_PTR_NE(k1->cert->ڪنجي_id, عدم);
	k1->cert->principals = صفر_يادگيري_ڏيو(4, حجم(*k1->cert->principals));
	ASSERT_PTR_NE(k1->cert->principals, عدم);
	k1->cert->principals[0] = strdup("estragon");
	k1->cert->principals[1] = strdup("vladimir");
	k1->cert->principals[2] = strdup("pozzo");
	k1->cert->principals[3] = strdup("lucky");
	ASSERT_PTR_NE(k1->cert->principals[0], عدم);
	ASSERT_PTR_NE(k1->cert->principals[1], عدم);
	ASSERT_PTR_NE(k1->cert->principals[2], عدم);
	ASSERT_PTR_NE(k1->cert->principals[3], عدم);
	k1->cert->nprincipals = 4;
	k1->cert->valid_after = 0;
	k1->cert->valid_before = (uint64_t)-1;
	sshbuf_free(k1->cert->critical);
	k1->cert->critical = sshbuf_new();
	ASSERT_PTR_NE(k1->cert->critical, عدم);
	sshbuf_free(k1->cert->extensions);
	k1->cert->extensions = sshbuf_new();
	ASSERT_PTR_NE(k1->cert->extensions, عدم);
	put_opt(k1->cert->critical, "force-command", "/usr/bin/true");
	put_opt(k1->cert->critical, "source-address", "127.0.0.1");
	put_opt(k1->cert->extensions, "permit-X11-forwarding", عدم);
	put_opt(k1->cert->extensions, "permit-agent-forwarding", عدم);
	ASSERT_INT_EQ(sshkey_from_ذاتي(k2, &k1->cert->signature_ڪنجي), 0);
	ASSERT_INT_EQ(sshkey_certify(k1, k2, عدم, عدم, عدم), 0);
	b = sshbuf_new();
	ASSERT_PTR_NE(b, عدم);
	ASSERT_INT_EQ(sshkey_putb(k1, b), 0);
	ASSERT_INT_EQ(sshkey_from_blob(sshbuf_ptr(b), sshbuf_len(b), &k3), 0);
	sshkey_free(k1);
	sshkey_free(k2);
	sshkey_free(k3);
	k1 = k2 = k3 = عدم;
	sshbuf_reset(b);
	TEST_پورو();

#جيڪڏهن_وصف_ٿيل WITH_OPENSSL
	TEST_شروعات("sign and verify RSA");
	k1 = get_ذاتي("rsa_1");
	ASSERT_INT_EQ(sshkey_ڀريو_عوامي(test_معلومات_file("rsa_2.pub"), &k2,
	    عدم), 0);
	signature_tests(k1, k2, "ssh-rsa");
	sshkey_free(k1);
	sshkey_free(k2);
	k1 = k2 = عدم;
	TEST_پورو();

	TEST_شروعات("sign and verify RSA-SHA256");
	k1 = get_ذاتي("rsa_1");
	ASSERT_INT_EQ(sshkey_ڀريو_عوامي(test_معلومات_file("rsa_2.pub"), &k2,
	    عدم), 0);
	signature_tests(k1, k2, "rsa-sha2-256");
	sshkey_free(k1);
	sshkey_free(k2);
	k1 = k2 = عدم;
	TEST_پورو();

	TEST_شروعات("sign and verify RSA-SHA512");
	k1 = get_ذاتي("rsa_1");
	ASSERT_INT_EQ(sshkey_ڀريو_عوامي(test_معلومات_file("rsa_2.pub"), &k2,
	    عدم), 0);
	signature_tests(k1, k2, "rsa-sha2-512");
	sshkey_free(k1);
	sshkey_free(k2);
	k1 = k2 = عدم;
	TEST_پورو();


	TEST_شروعات("sign and verify ECDSA");
	k1 = get_ذاتي("ecdsa_1");
	ASSERT_INT_EQ(sshkey_ڀريو_عوامي(test_معلومات_file("ecdsa_2.pub"), &k2,
	    عدم), 0);
	signature_tests(k1, k2, عدم);
	sshkey_free(k1);
	sshkey_free(k2);
	k1 = k2 = عدم;
	TEST_پورو();
#جيڪڏهن_پورو /* WITH_OPENSSL */

	TEST_شروعات("sign and verify ED25519");
	k1 = get_ذاتي("ed25519_1");
	ASSERT_INT_EQ(sshkey_ڀريو_عوامي(test_معلومات_file("ed25519_2.pub"), &k2,
	    عدم), 0);
	signature_tests(k1, k2, عدم);
	sshkey_free(k1);
	sshkey_free(k2);
	k1 = k2 = عدم;
	TEST_پورو();

	TEST_شروعات("sign and verify MLDSA44-ED25519");
	k1 = get_ذاتي("mldsa44_ed25519_1");
	ASSERT_INT_EQ(sshkey_ڀريو_عوامي(
	    test_معلومات_file("mldsa44_ed25519_2.pub"), &k2, عدم), 0);
	signature_tests(k1, k2, عدم);
	sshkey_free(k1);
	sshkey_free(k2);
	k1 = k2 = عدم;
	TEST_پورو();

#جيڪڏهن_وصف_ٿيل WITH_OPENSSL
	TEST_شروعات("nested certificate");
	ASSERT_INT_EQ(sshkey_ڀريو_cert(test_معلومات_file("rsa_1"), &k1), 0);
	ASSERT_INT_EQ(sshkey_ڀريو_عوامي(test_معلومات_file("rsa_1.pub"), &k2,
	    عدم), 0);
	k3 = get_ذاتي("rsa_1");
	build_cert(b, k2, "ssh-rsa-cert-v01@openssh.com", k3, k1, عدم);
	ASSERT_INT_EQ(sshkey_from_blob(sshbuf_ptr(b), sshbuf_len(b), &k4),
	    SSH_ERR_ڪنجي_CERT_INVALID_SIGN_ڪنجي);
	ASSERT_PTR_EQ(k4, عدم);
	sshkey_free(k1);
	sshkey_free(k2);
	sshkey_free(k3);
	k1 = k2 = k3 = عدم;
	sshbuf_free(b);
	TEST_پورو();
#جيڪڏهن_پورو /* WITH_OPENSSL */
}

فراغ
sshkey_benchmarks(فراغ)
{
	بنية sshkey *k = عدم;

#جيڪڏهن_وصف_ٿيل WITH_OPENSSL
	BENCH_شروعات("generate RSA-1024");
	TEST_شروعات("generate KEY_RSA");
	ASSERT_INT_EQ(sshkey_generate(ڪنجي_RSA, 1024, &k), 0);
	ASSERT_PTR_NE(k, عدم);
	sshkey_free(k);
	k = عدم;
	TEST_پورو();
	BENCH_پڄاڻي("keys");

	BENCH_شروعات("generate RSA-2048");
	TEST_شروعات("generate KEY_RSA");
	ASSERT_INT_EQ(sshkey_generate(ڪنجي_RSA, 2048, &k), 0);
	ASSERT_PTR_NE(k, عدم);
	sshkey_free(k);
	k = عدم;
	TEST_پورو();
	BENCH_پڄاڻي("keys");

	BENCH_شروعات("generate ECDSA-256");
	TEST_شروعات("generate KEY_ECDSA");
	ASSERT_INT_EQ(sshkey_generate(ڪنجي_ECDSA, 256, &k), 0);
	ASSERT_PTR_NE(k, عدم);
	sshkey_free(k);
	k = عدم;
	TEST_پورو();
	BENCH_پڄاڻي("keys");

	BENCH_شروعات("generate ECDSA-384");
	TEST_شروعات("generate KEY_ECDSA");
	ASSERT_INT_EQ(sshkey_generate(ڪنجي_ECDSA, 384, &k), 0);
	ASSERT_PTR_NE(k, عدم);
	sshkey_free(k);
	k = عدم;
	TEST_پورو();
	BENCH_پڄاڻي("keys");

	BENCH_شروعات("generate ECDSA-521");
	TEST_شروعات("generate KEY_ECDSA");
	ASSERT_INT_EQ(sshkey_generate(ڪنجي_ECDSA, 521, &k), 0);
	ASSERT_PTR_NE(k, عدم);
	sshkey_free(k);
	k = عدم;
	TEST_پورو();
	BENCH_پڄاڻي("keys");
#جيڪڏهن_پورو /* WITH_OPENSSL */

	BENCH_شروعات("generate ED25519");
	TEST_شروعات("generate KEY_ED25519");
	ASSERT_INT_EQ(sshkey_generate(ڪنجي_ED25519, 256, &k), 0);
	ASSERT_PTR_NE(k, عدم);
	sshkey_free(k);
	k = عدم;
	TEST_پورو();
	BENCH_پڄاڻي("keys");

	BENCH_شروعات("generate MLDSA44-ED25519");
	TEST_شروعات("generate KEY_MLDSA44_ED25519");
	ASSERT_INT_EQ(sshkey_generate(ڪنجي_MLDSA44_ED25519, 256, &k), 0);
	ASSERT_PTR_NE(k, عدم);
	sshkey_free(k);
	k = عدم;
	TEST_پورو();
	BENCH_پڄاڻي("keys");

#جيڪڏهن_وصف_ٿيل WITH_OPENSSL
	/* sign */
	signature_benchmark("RSA-1024/SHA1", ڪنجي_RSA, 1024, "ssh-rsa", 0);
	signature_benchmark("RSA-1024/SHA256", ڪنجي_RSA, 1024, "rsa-sha2-256", 0);
	signature_benchmark("RSA-1024/SHA512", ڪنجي_RSA, 1024, "rsa-sha2-512", 0);
	signature_benchmark("RSA-2048/SHA1", ڪنجي_RSA, 2048, "ssh-rsa", 0);
	signature_benchmark("RSA-2048/SHA256", ڪنجي_RSA, 2048, "rsa-sha2-256", 0);
	signature_benchmark("RSA-2048/SHA512", ڪنجي_RSA, 2048, "rsa-sha2-512", 0);
	signature_benchmark("ECDSA-256", ڪنجي_ECDSA, 256, عدم, 0);
	signature_benchmark("ECDSA-384", ڪنجي_ECDSA, 384, عدم, 0);
	signature_benchmark("ECDSA-521", ڪنجي_ECDSA, 521, عدم, 0);
	signature_benchmark("ED25519", ڪنجي_ED25519, 0, عدم, 0);
	signature_benchmark("MLDSA44-ED25519", ڪنجي_MLDSA44_ED25519, 0, عدم, 0);

	/* verify */
	signature_benchmark("RSA-1024/SHA1", ڪنجي_RSA, 1024, "ssh-rsa", 1);
	signature_benchmark("RSA-1024/SHA256", ڪنجي_RSA, 1024, "rsa-sha2-256", 1);
	signature_benchmark("RSA-1024/SHA512", ڪنجي_RSA, 1024, "rsa-sha2-512", 1);
	signature_benchmark("RSA-2048/SHA1", ڪنجي_RSA, 2048, "ssh-rsa", 1);
	signature_benchmark("RSA-2048/SHA256", ڪنجي_RSA, 2048, "rsa-sha2-256", 1);
	signature_benchmark("RSA-2048/SHA512", ڪنجي_RSA, 2048, "rsa-sha2-512", 1);
	signature_benchmark("ECDSA-256", ڪنجي_ECDSA, 256, عدم, 1);
	signature_benchmark("ECDSA-384", ڪنجي_ECDSA, 384, عدم, 1);
	signature_benchmark("ECDSA-521", ڪنجي_ECDSA, 521, عدم, 1);
#جيڪڏهن_پورو /* WITH_OPENSSL */
	signature_benchmark("ED25519", ڪنجي_ED25519, 0, عدم, 1);
	signature_benchmark("MLDSA44-ED25519", ڪنجي_MLDSA44_ED25519, 0, عدم, 1);
}
