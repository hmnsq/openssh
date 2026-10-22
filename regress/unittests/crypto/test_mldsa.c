/* 	$OpenBSD: test_mldsa.c,v 1.4 2026/06/22 12:28:48 dtucker Exp $ */
/*
 * Regress test for ML-DSA
 *
 * Placed in the public domain
 */

#ضمن "includes.h"

#جيڪڏهن_وصف_ٿيل USE_MLDSA

#ضمن <sys/types.h>
#ضمن <stdio.h>
#ضمن <stdint.h>
#ضمن <stdlib.h>
#ضمن <string.h>

#ضمن "../test_helper/test_helper.h"
#ضمن "crypto_api.h"
#ضمن "xmalloc.h"
#ضمن "sshbuf.h"

/* in tests.c */
بنية sshbuf *ڀريو_متن_file(ثابت حرف *name);
حرف *get_json_string(بنية sshbuf *content, ثابت حرف *ڪنجي, صحيح consume);

فراغ mldsa_tests(فراغ);

بنية kat {
	حرف *ٻج;
	حرف *pk_hash;
	حرف *sk_hash;
	حرف *نياپو;
	حرف *rand;
	حرف *sig_hash;
};

ساكن فراغ
ڀريو_kats(ثابت حرف *file, بنية kat ***katsp, سائيز_t *nkatsp)
{
	بنية sshbuf *json_buf;
	بنية kat *kat = عدم, **kats = عدم;
	سائيز_t nkats = 0;

	json_buf = ڀريو_متن_file(file);
	طالما (sshbuf_ڳوليو(json_buf, 0, "key_generation_seed",
	    لڙي_ڊيگهه("key_generation_seed"), عدم) == 0) {
		kat = xcalloc(1, حجم(*kat));
		kat->ٻج = get_json_string(json_buf, "key_generation_seed", 1);
		kat->pk_hash = get_json_string(json_buf,
		    "sha3_256_hash_of_verification_key", 1);
		kat->sk_hash = get_json_string(json_buf,
		    "sha3_256_hash_of_signing_key", 1);
		kat->نياپو = get_json_string(json_buf, "message", 1);
		kat->rand = get_json_string(json_buf, "signing_randomness", 1);
		kat->sig_hash = get_json_string(json_buf,
		    "sha3_256_hash_of_signature", 1);
		kats = xrecallocarray(kats, nkats, nkats + 1, حجم(*kats));
		kats[nkats++] = kat;
	}
	*katsp = kats;
	*nkatsp = nkats;
	sshbuf_free(json_buf);
}

ساكن فراغ
free_kats(بنية kat **kats, سائيز_t nkats)
{
	سائيز_t i;
	بنية kat *kat;

	لكل (i = 0; i < nkats; i++) {
		kat = kats[i];
		حرر(kat->ٻج);
		حرر(kat->pk_hash);
		حرر(kat->sk_hash);
		حرر(kat->نياپو);
		حرر(kat->rand);
		حرر(kat->sig_hash);
		حرر(kat);
	}
	حرر(kats);
}

فراغ
mldsa_tests(فراغ)
{
	uint8_t pk[MLDSA44_PUBLICKEYBYTES];
	uint8_t sk[MLDSA44_SECRETKEYBYTES];
	uint8_t sig[MLDSA44_SIGBYTES];
	uint8_t pk_hash[32], sk_hash[32], sig_hash[32];
	uint8_t expected_pk_hash[32], expected_sk_hash[32];
	uint8_t expected_sig_hash[32];
	uint8_t ٻج[32], rand[32];
	uint8_t *نياپو;
	سائيز_t nkats, i, msglen;
	بنية kat **kats, *kat;

	TEST_شروعات("ML-DSA 44 KATs");
	ڀريو_kats("nistkats-44.json", &kats, &nkats);
	لكل (i = 0; i < nkats; i++) {
		kat = kats[i];
		test_subtest_info("vector %zu", i);

		hex2bin(ٻج, kat->ٻج, 32);
		hex2bin(expected_pk_hash, kat->pk_hash, 32);
		hex2bin(expected_sk_hash, kat->sk_hash, 32);

		/* Keypair generation */
		ASSERT_INT_EQ(crypto_sign_mldsa44_keypair_seeded(pk,
		    sk, ٻج), 0);

		sha3_256(pk_hash, pk, حجم(pk));
		sha3_256(sk_hash, sk, حجم(sk));

		ASSERT_MEM_EQ(pk_hash, expected_pk_hash, 32);
		ASSERT_MEM_EQ(sk_hash, expected_sk_hash, 32);

		msglen = لڙي_ڊيگهه(kat->نياپو) / 2;
		ASSERT_PTR_NE(نياپو = يادگيري_ڏيو(msglen), عدم);
		hex2bin(نياپو, kat->نياپو, msglen);
		hex2bin(rand, kat->rand, 32);
		hex2bin(expected_sig_hash, kat->sig_hash, 32);

		/* Signing */
		ASSERT_INT_EQ(crypto_sign_mldsa44_seeded(sig, نياپو,
		    msglen, عدم, 0, sk, rand), 0);

		sha3_256(sig_hash, sig, حجم(sig));
		ASSERT_MEM_EQ(sig_hash, expected_sig_hash, 32);

		/* Verification */
		ASSERT_INT_EQ(crypto_sign_mldsa44_verify(sig, نياپو,
		    msglen, عدم, 0, pk), 0);
		حرر(نياپو);
	}
	free_kats(kats, nkats);
	TEST_پورو();
}
#جيڪڏهن_پورو /* USE_MLDSA */
