/* 	$OpenBSD: test_mldsa.c,v 1.4 2026/06/22 12:28:48 dtucker Exp $ */
/*
 * Regress test for ML-DSA
 *
 * Placed in the public domain
 */

#অন্তর্ভাব "includes.h"

#ifdef USE_MLDSA

#অন্তর্ভাব <sys/types.h>
#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <stdint.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <string.h>

#অন্তর্ভাব "../test_helper/test_helper.h"
#অন্তর্ভাব "crypto_api.h"
#অন্তর্ভাব "xmalloc.h"
#অন্তর্ভাব "sshbuf.h"

/* in tests.c */
কাঠামো sshbuf *load_text_file(ধ্রুবক অক্ষর *name);
অক্ষর *get_json_string(কাঠামো sshbuf *content, ধ্রুবক অক্ষর *চাবি, পূর্ণসংখ্যা consume);

শূন্য mldsa_tests(শূন্য);

কাঠামো kat {
	অক্ষর *seed;
	অক্ষর *pk_hash;
	অক্ষর *sk_hash;
	অক্ষর *বার্তা;
	অক্ষর *rand;
	অক্ষর *sig_hash;
};

স্থির শূন্য
load_kats(ধ্রুবক অক্ষর *file, কাঠামো kat ***katsp, আকার_t *nkatsp)
{
	কাঠামো sshbuf *json_buf;
	কাঠামো kat *kat = ফাঁকা, **kats = ফাঁকা;
	আকার_t nkats = 0;

	json_buf = load_text_file(file);
	যখন (sshbuf_find(json_buf, 0, "key_generation_seed",
	    strlen("key_generation_seed"), ফাঁকা) == 0) {
		kat = xcalloc(1, আকার(*kat));
		kat->seed = get_json_string(json_buf, "key_generation_seed", 1);
		kat->pk_hash = get_json_string(json_buf,
		    "sha3_256_hash_of_verification_key", 1);
		kat->sk_hash = get_json_string(json_buf,
		    "sha3_256_hash_of_signing_key", 1);
		kat->বার্তা = get_json_string(json_buf, "message", 1);
		kat->rand = get_json_string(json_buf, "signing_randomness", 1);
		kat->sig_hash = get_json_string(json_buf,
		    "sha3_256_hash_of_signature", 1);
		kats = xrecallocarray(kats, nkats, nkats + 1, আকার(*kats));
		kats[nkats++] = kat;
	}
	*katsp = kats;
	*nkatsp = nkats;
	sshbuf_free(json_buf);
}

স্থির শূন্য
free_kats(কাঠামো kat **kats, আকার_t nkats)
{
	আকার_t i;
	কাঠামো kat *kat;

	জন্য (i = 0; i < nkats; i++) {
		kat = kats[i];
		মুক্ত(kat->seed);
		মুক্ত(kat->pk_hash);
		মুক্ত(kat->sk_hash);
		মুক্ত(kat->বার্তা);
		মুক্ত(kat->rand);
		মুক্ত(kat->sig_hash);
		মুক্ত(kat);
	}
	মুক্ত(kats);
}

শূন্য
mldsa_tests(শূন্য)
{
	uint8_t pk[MLDSA44_PUBLICKEYBYTES];
	uint8_t sk[MLDSA44_SECRETKEYBYTES];
	uint8_t sig[MLDSA44_SIGBYTES];
	uint8_t pk_hash[32], sk_hash[32], sig_hash[32];
	uint8_t expected_pk_hash[32], expected_sk_hash[32];
	uint8_t expected_sig_hash[32];
	uint8_t seed[32], rand[32];
	uint8_t *বার্তা;
	আকার_t nkats, i, msglen;
	কাঠামো kat **kats, *kat;

	TEST_START("ML-DSA 44 KATs");
	load_kats("nistkats-44.json", &kats, &nkats);
	জন্য (i = 0; i < nkats; i++) {
		kat = kats[i];
		test_subtest_info("vector %zu", i);

		hex2bin(seed, kat->seed, 32);
		hex2bin(expected_pk_hash, kat->pk_hash, 32);
		hex2bin(expected_sk_hash, kat->sk_hash, 32);

		/* Keypair generation */
		ASSERT_INT_EQ(crypto_sign_mldsa44_keypair_seeded(pk,
		    sk, seed), 0);

		sha3_256(pk_hash, pk, আকার(pk));
		sha3_256(sk_hash, sk, আকার(sk));

		ASSERT_MEM_EQ(pk_hash, expected_pk_hash, 32);
		ASSERT_MEM_EQ(sk_hash, expected_sk_hash, 32);

		msglen = strlen(kat->বার্তা) / 2;
		ASSERT_PTR_NE(বার্তা = malloc(msglen), ফাঁকা);
		hex2bin(বার্তা, kat->বার্তা, msglen);
		hex2bin(rand, kat->rand, 32);
		hex2bin(expected_sig_hash, kat->sig_hash, 32);

		/* Signing */
		ASSERT_INT_EQ(crypto_sign_mldsa44_seeded(sig, বার্তা,
		    msglen, ফাঁকা, 0, sk, rand), 0);

		sha3_256(sig_hash, sig, আকার(sig));
		ASSERT_MEM_EQ(sig_hash, expected_sig_hash, 32);

		/* Verification */
		ASSERT_INT_EQ(crypto_sign_mldsa44_verify(sig, বার্তা,
		    msglen, ফাঁকা, 0, pk), 0);
		মুক্ত(বার্তা);
	}
	free_kats(kats, nkats);
	TEST_DONE();
}
#endif /* USE_MLDSA */
