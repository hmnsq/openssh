/* 	$OpenBSD: test_mldsa.c,v 1.4 2026/06/22 12:28:48 dtucker Exp $ */
/*
 * Regress test for ML-DSA
 *
 * Placed in the public domain
 */

#شامل "includes.h"

#ifdef USE_MLDSA

#شامل <sys/types.h>
#شامل <stdio.h>
#شامل <stdint.h>
#شامل <stdlib.h>
#شامل <string.h>

#شامل "../test_helper/test_helper.h"
#شامل "crypto_api.h"
#شامل "xmalloc.h"
#شامل "sshbuf.h"

/* in tests.c */
ساختار sshbuf *load_text_file(ثابت نویسه *name);
نویسه *get_json_string(ساختار sshbuf *content, ثابت نویسه *کلید, صحیح consume);

تهی mldsa_tests(تهی);

ساختار kat {
	نویسه *seed;
	نویسه *pk_hash;
	نویسه *sk_hash;
	نویسه *پیام;
	نویسه *rand;
	نویسه *sig_hash;
};

ایستا تهی
load_kats(ثابت نویسه *file, ساختار kat ***katsp, size_t *nkatsp)
{
	ساختار sshbuf *json_buf;
	ساختار kat *kat = پوچ, **kats = پوچ;
	size_t nkats = 0;

	json_buf = load_text_file(file);
	وقتی (sshbuf_find(json_buf, 0, "key_generation_seed",
	    strlen("key_generation_seed"), پوچ) == 0) {
		kat = xcalloc(1, اندازه(*kat));
		kat->seed = get_json_string(json_buf, "key_generation_seed", 1);
		kat->pk_hash = get_json_string(json_buf,
		    "sha3_256_hash_of_verification_key", 1);
		kat->sk_hash = get_json_string(json_buf,
		    "sha3_256_hash_of_signing_key", 1);
		kat->پیام = get_json_string(json_buf, "message", 1);
		kat->rand = get_json_string(json_buf, "signing_randomness", 1);
		kat->sig_hash = get_json_string(json_buf,
		    "sha3_256_hash_of_signature", 1);
		kats = xrecallocarray(kats, nkats, nkats + 1, اندازه(*kats));
		kats[nkats++] = kat;
	}
	*katsp = kats;
	*nkatsp = nkats;
	sshbuf_free(json_buf);
}

ایستا تهی
free_kats(ساختار kat **kats, size_t nkats)
{
	size_t i;
	ساختار kat *kat;

	برای (i = 0; i < nkats; i++) {
		kat = kats[i];
		آزاد(kat->seed);
		آزاد(kat->pk_hash);
		آزاد(kat->sk_hash);
		آزاد(kat->پیام);
		آزاد(kat->rand);
		آزاد(kat->sig_hash);
		آزاد(kat);
	}
	آزاد(kats);
}

تهی
mldsa_tests(تهی)
{
	uint8_t pk[MLDSA44_PUBLICKEYBYTES];
	uint8_t sk[MLDSA44_SECRETKEYBYTES];
	uint8_t sig[MLDSA44_SIGBYTES];
	uint8_t pk_hash[32], sk_hash[32], sig_hash[32];
	uint8_t expected_pk_hash[32], expected_sk_hash[32];
	uint8_t expected_sig_hash[32];
	uint8_t seed[32], rand[32];
	uint8_t *پیام;
	size_t nkats, i, msglen;
	ساختار kat **kats, *kat;

	TEST_START("ML-DSA 44 KATs");
	load_kats("nistkats-44.json", &kats, &nkats);
	برای (i = 0; i < nkats; i++) {
		kat = kats[i];
		test_subtest_info("vector %zu", i);

		hex2bin(seed, kat->seed, 32);
		hex2bin(expected_pk_hash, kat->pk_hash, 32);
		hex2bin(expected_sk_hash, kat->sk_hash, 32);

		/* Keypair generation */
		ASSERT_INT_EQ(crypto_sign_mldsa44_keypair_seeded(pk,
		    sk, seed), 0);

		sha3_256(pk_hash, pk, اندازه(pk));
		sha3_256(sk_hash, sk, اندازه(sk));

		ASSERT_MEM_EQ(pk_hash, expected_pk_hash, 32);
		ASSERT_MEM_EQ(sk_hash, expected_sk_hash, 32);

		msglen = strlen(kat->پیام) / 2;
		ASSERT_PTR_NE(پیام = malloc(msglen), پوچ);
		hex2bin(پیام, kat->پیام, msglen);
		hex2bin(rand, kat->rand, 32);
		hex2bin(expected_sig_hash, kat->sig_hash, 32);

		/* Signing */
		ASSERT_INT_EQ(crypto_sign_mldsa44_seeded(sig, پیام,
		    msglen, پوچ, 0, sk, rand), 0);

		sha3_256(sig_hash, sig, اندازه(sig));
		ASSERT_MEM_EQ(sig_hash, expected_sig_hash, 32);

		/* Verification */
		ASSERT_INT_EQ(crypto_sign_mldsa44_verify(sig, پیام,
		    msglen, پوچ, 0, pk), 0);
		آزاد(پیام);
	}
	free_kats(kats, nkats);
	TEST_DONE();
}
#endif /* USE_MLDSA */
