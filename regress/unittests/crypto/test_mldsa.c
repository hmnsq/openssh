/* 	$OpenBSD: test_mldsa.c,v 1.4 2026/06/22 12:28:48 dtucker Exp $ */
/*
 * Regress test for ML-DSA
 *
 * Placed in the public domain
 */

#ضمن "includes.h"

#که_تعریف_شوی USE_MLDSA

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
بنية sshbuf *بارول_متن_file(ثابت حرف *name);
حرف *get_json_string(بنية sshbuf *content, ثابت حرف *کلی, صحيح consume);

فراغ mldsa_tests(فراغ);

بنية kat {
	حرف *تخم;
	حرف *pk_hash;
	حرف *sk_hash;
	حرف *پیغام;
	حرف *rand;
	حرف *sig_hash;
};

ساكن فراغ
بارول_kats(ثابت حرف *file, بنية kat ***katsp, اندازه_t *nkatsp)
{
	بنية sshbuf *json_buf;
	بنية kat *kat = عدم, **kats = عدم;
	اندازه_t nkats = 0;

	json_buf = بارول_متن_file(file);
	طالما (sshbuf_پیدا_کړه(json_buf, 0, "key_generation_seed",
	    مزي_اوږدوالی("key_generation_seed"), عدم) == 0) {
		kat = xcalloc(1, حجم(*kat));
		kat->تخم = get_json_string(json_buf, "key_generation_seed", 1);
		kat->pk_hash = get_json_string(json_buf,
		    "sha3_256_hash_of_verification_key", 1);
		kat->sk_hash = get_json_string(json_buf,
		    "sha3_256_hash_of_signing_key", 1);
		kat->پیغام = get_json_string(json_buf, "message", 1);
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
free_kats(بنية kat **kats, اندازه_t nkats)
{
	اندازه_t i;
	بنية kat *kat;

	لكل (i = 0; i < nkats; i++) {
		kat = kats[i];
		حرر(kat->تخم);
		حرر(kat->pk_hash);
		حرر(kat->sk_hash);
		حرر(kat->پیغام);
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
	uint8_t تخم[32], rand[32];
	uint8_t *پیغام;
	اندازه_t nkats, i, msglen;
	بنية kat **kats, *kat;

	TEST_پیل("ML-DSA 44 KATs");
	بارول_kats("nistkats-44.json", &kats, &nkats);
	لكل (i = 0; i < nkats; i++) {
		kat = kats[i];
		test_subtest_info("vector %zu", i);

		hex2bin(تخم, kat->تخم, 32);
		hex2bin(expected_pk_hash, kat->pk_hash, 32);
		hex2bin(expected_sk_hash, kat->sk_hash, 32);

		/* Keypair generation */
		ASSERT_INT_EQ(crypto_sign_mldsa44_keypair_seeded(pk,
		    sk, تخم), 0);

		sha3_256(pk_hash, pk, حجم(pk));
		sha3_256(sk_hash, sk, حجم(sk));

		ASSERT_MEM_EQ(pk_hash, expected_pk_hash, 32);
		ASSERT_MEM_EQ(sk_hash, expected_sk_hash, 32);

		msglen = مزي_اوږدوالی(kat->پیغام) / 2;
		ASSERT_PTR_NE(پیغام = حافظه_ورکړه(msglen), عدم);
		hex2bin(پیغام, kat->پیغام, msglen);
		hex2bin(rand, kat->rand, 32);
		hex2bin(expected_sig_hash, kat->sig_hash, 32);

		/* Signing */
		ASSERT_INT_EQ(crypto_sign_mldsa44_seeded(sig, پیغام,
		    msglen, عدم, 0, sk, rand), 0);

		sha3_256(sig_hash, sig, حجم(sig));
		ASSERT_MEM_EQ(sig_hash, expected_sig_hash, 32);

		/* Verification */
		ASSERT_INT_EQ(crypto_sign_mldsa44_verify(sig, پیغام,
		    msglen, عدم, 0, pk), 0);
		حرر(پیغام);
	}
	free_kats(kats, nkats);
	TEST_بشپړ();
}
#د_که_پای /* USE_MLDSA */
