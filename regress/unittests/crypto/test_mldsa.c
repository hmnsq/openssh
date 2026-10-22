/* 	$OpenBSD: test_mldsa.c,v 1.4 2026/06/22 12:28:48 dtucker Exp $ */
/*
 * Regress test for ML-DSA
 *
 * Placed in the public domain
 */

#অন্তর্ভাৱ "includes.h"

#ifdef USE_MLDSA

#অন্তর্ভাৱ <sys/types.h>
#অন্তর্ভাৱ <stdio.h>
#অন্তর্ভাৱ <stdint.h>
#অন্তর্ভাৱ <stdlib.h>
#অন্তর্ভাৱ <string.h>

#অন্তর্ভাৱ "../test_helper/test_helper.h"
#অন্তর্ভাৱ "crypto_api.h"
#অন্তর্ভাৱ "xmalloc.h"
#অন্তর্ভাৱ "sshbuf.h"

/* in tests.c */
সংরচনা sshbuf *load_text_file(ধ্রুৱ ৱর্ণ *name);
ৱর্ণ *get_json_string(সংরচনা sshbuf *content, ধ্রুৱ ৱর্ণ *চাবি, পূর্ণাঙ্ক consume);

শূন্য mldsa_tests(শূন্য);

সংরচনা kat {
	ৱর্ণ *seed;
	ৱর্ণ *pk_hash;
	ৱর্ণ *sk_hash;
	ৱর্ণ *বাৰ্তা;
	ৱর্ণ *rand;
	ৱর্ণ *sig_hash;
};

স্থির শূন্য
load_kats(ধ্রুৱ ৱর্ণ *file, সংরচনা kat ***katsp, size_t *nkatsp)
{
	সংরচনা sshbuf *json_buf;
	সংরচনা kat *kat = রিক্ত, **kats = রিক্ত;
	size_t nkats = 0;

	json_buf = load_text_file(file);
	যেতিয়ালৈ (sshbuf_find(json_buf, 0, "key_generation_seed",
	    strlen("key_generation_seed"), রিক্ত) == 0) {
		kat = xcalloc(1, পরিমাণ(*kat));
		kat->seed = get_json_string(json_buf, "key_generation_seed", 1);
		kat->pk_hash = get_json_string(json_buf,
		    "sha3_256_hash_of_verification_key", 1);
		kat->sk_hash = get_json_string(json_buf,
		    "sha3_256_hash_of_signing_key", 1);
		kat->বাৰ্তা = get_json_string(json_buf, "message", 1);
		kat->rand = get_json_string(json_buf, "signing_randomness", 1);
		kat->sig_hash = get_json_string(json_buf,
		    "sha3_256_hash_of_signature", 1);
		kats = xrecallocarray(kats, nkats, nkats + 1, পরিমাণ(*kats));
		kats[nkats++] = kat;
	}
	*katsp = kats;
	*nkatsp = nkats;
	sshbuf_free(json_buf);
}

স্থির শূন্য
free_kats(সংরচনা kat **kats, size_t nkats)
{
	size_t i;
	সংরচনা kat *kat;

	বাবে (i = 0; i < nkats; i++) {
		kat = kats[i];
		মুক্ত(kat->seed);
		মুক্ত(kat->pk_hash);
		মুক্ত(kat->sk_hash);
		মুক্ত(kat->বাৰ্তা);
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
	uint8_t *বাৰ্তা;
	size_t nkats, i, msglen;
	সংরচনা kat **kats, *kat;

	TEST_START("ML-DSA 44 KATs");
	load_kats("nistkats-44.json", &kats, &nkats);
	বাবে (i = 0; i < nkats; i++) {
		kat = kats[i];
		test_subtest_info("vector %zu", i);

		hex2bin(seed, kat->seed, 32);
		hex2bin(expected_pk_hash, kat->pk_hash, 32);
		hex2bin(expected_sk_hash, kat->sk_hash, 32);

		/* Keypair generation */
		ASSERT_INT_EQ(crypto_sign_mldsa44_keypair_seeded(pk,
		    sk, seed), 0);

		sha3_256(pk_hash, pk, পরিমাণ(pk));
		sha3_256(sk_hash, sk, পরিমাণ(sk));

		ASSERT_MEM_EQ(pk_hash, expected_pk_hash, 32);
		ASSERT_MEM_EQ(sk_hash, expected_sk_hash, 32);

		msglen = strlen(kat->বাৰ্তা) / 2;
		ASSERT_PTR_NE(বাৰ্তা = malloc(msglen), রিক্ত);
		hex2bin(বাৰ্তা, kat->বাৰ্তা, msglen);
		hex2bin(rand, kat->rand, 32);
		hex2bin(expected_sig_hash, kat->sig_hash, 32);

		/* Signing */
		ASSERT_INT_EQ(crypto_sign_mldsa44_seeded(sig, বাৰ্তা,
		    msglen, রিক্ত, 0, sk, rand), 0);

		sha3_256(sig_hash, sig, পরিমাণ(sig));
		ASSERT_MEM_EQ(sig_hash, expected_sig_hash, 32);

		/* Verification */
		ASSERT_INT_EQ(crypto_sign_mldsa44_verify(sig, বাৰ্তা,
		    msglen, রিক্ত, 0, pk), 0);
		মুক্ত(বাৰ্তা);
	}
	free_kats(kats, nkats);
	TEST_DONE();
}
#endif /* USE_MLDSA */
