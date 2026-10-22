/* 	$OpenBSD: test_mldsa.c,v 1.4 2026/06/22 12:28:48 dtucker Exp $ */
/*
 * Regress test for ML-DSA
 *
 * Placed in the public domain
 */

#ಅನ್ತರ್ಭಾವ "includes.h"

#ifdef USE_MLDSA

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stdint.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>

#ಅನ್ತರ್ಭಾವ "../test_helper/test_helper.h"
#ಅನ್ತರ್ಭಾವ "crypto_api.h"
#ಅನ್ತರ್ಭಾವ "xmalloc.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"

/* in tests.c */
ಸಂರಚನಾ sshbuf *load_text_file(ಧ್ರುವ ವರ್ಣ *name);
ವರ್ಣ *get_json_string(ಸಂರಚನಾ sshbuf *content, ಧ್ರುವ ವರ್ಣ *ಕೀಲಿ, ಪೂರ್ಣಾಙ್ಕ consume);

ಶೂನ್ಯ mldsa_tests(ಶೂನ್ಯ);

ಸಂರಚನಾ kat {
	ವರ್ಣ *seed;
	ವರ್ಣ *pk_hash;
	ವರ್ಣ *sk_hash;
	ವರ್ಣ *ಸಂದೇಶ;
	ವರ್ಣ *rand;
	ವರ್ಣ *sig_hash;
};

ಸ್ಥಿರ ಶೂನ್ಯ
load_kats(ಧ್ರುವ ವರ್ಣ *file, ಸಂರಚನಾ kat ***katsp, size_t *nkatsp)
{
	ಸಂರಚನಾ sshbuf *json_buf;
	ಸಂರಚನಾ kat *kat = ರಿಕ್ತ, **kats = ರಿಕ್ತ;
	size_t nkats = 0;

	json_buf = load_text_file(file);
	ಯಾವತ್ (sshbuf_find(json_buf, 0, "key_generation_seed",
	    strlen("key_generation_seed"), ರಿಕ್ತ) == 0) {
		kat = xcalloc(1, ಪರಿಮಾಣ(*kat));
		kat->seed = get_json_string(json_buf, "key_generation_seed", 1);
		kat->pk_hash = get_json_string(json_buf,
		    "sha3_256_hash_of_verification_key", 1);
		kat->sk_hash = get_json_string(json_buf,
		    "sha3_256_hash_of_signing_key", 1);
		kat->ಸಂದೇಶ = get_json_string(json_buf, "message", 1);
		kat->rand = get_json_string(json_buf, "signing_randomness", 1);
		kat->sig_hash = get_json_string(json_buf,
		    "sha3_256_hash_of_signature", 1);
		kats = xrecallocarray(kats, nkats, nkats + 1, ಪರಿಮಾಣ(*kats));
		kats[nkats++] = kat;
	}
	*katsp = kats;
	*nkatsp = nkats;
	sshbuf_free(json_buf);
}

ಸ್ಥಿರ ಶೂನ್ಯ
free_kats(ಸಂರಚನಾ kat **kats, size_t nkats)
{
	size_t i;
	ಸಂರಚನಾ kat *kat;

	ಪ್ರತಿ (i = 0; i < nkats; i++) {
		kat = kats[i];
		ಮುಕ್ತ(kat->seed);
		ಮುಕ್ತ(kat->pk_hash);
		ಮುಕ್ತ(kat->sk_hash);
		ಮುಕ್ತ(kat->ಸಂದೇಶ);
		ಮುಕ್ತ(kat->rand);
		ಮುಕ್ತ(kat->sig_hash);
		ಮುಕ್ತ(kat);
	}
	ಮುಕ್ತ(kats);
}

ಶೂನ್ಯ
mldsa_tests(ಶೂನ್ಯ)
{
	uint8_t pk[MLDSA44_PUBLICKEYBYTES];
	uint8_t sk[MLDSA44_SECRETKEYBYTES];
	uint8_t sig[MLDSA44_SIGBYTES];
	uint8_t pk_hash[32], sk_hash[32], sig_hash[32];
	uint8_t expected_pk_hash[32], expected_sk_hash[32];
	uint8_t expected_sig_hash[32];
	uint8_t seed[32], rand[32];
	uint8_t *ಸಂದೇಶ;
	size_t nkats, i, msglen;
	ಸಂರಚನಾ kat **kats, *kat;

	TEST_START("ML-DSA 44 KATs");
	load_kats("nistkats-44.json", &kats, &nkats);
	ಪ್ರತಿ (i = 0; i < nkats; i++) {
		kat = kats[i];
		test_subtest_info("vector %zu", i);

		hex2bin(seed, kat->seed, 32);
		hex2bin(expected_pk_hash, kat->pk_hash, 32);
		hex2bin(expected_sk_hash, kat->sk_hash, 32);

		/* Keypair generation */
		ASSERT_INT_EQ(crypto_sign_mldsa44_keypair_seeded(pk,
		    sk, seed), 0);

		sha3_256(pk_hash, pk, ಪರಿಮಾಣ(pk));
		sha3_256(sk_hash, sk, ಪರಿಮಾಣ(sk));

		ASSERT_MEM_EQ(pk_hash, expected_pk_hash, 32);
		ASSERT_MEM_EQ(sk_hash, expected_sk_hash, 32);

		msglen = strlen(kat->ಸಂದೇಶ) / 2;
		ASSERT_PTR_NE(ಸಂದೇಶ = malloc(msglen), ರಿಕ್ತ);
		hex2bin(ಸಂದೇಶ, kat->ಸಂದೇಶ, msglen);
		hex2bin(rand, kat->rand, 32);
		hex2bin(expected_sig_hash, kat->sig_hash, 32);

		/* Signing */
		ASSERT_INT_EQ(crypto_sign_mldsa44_seeded(sig, ಸಂದೇಶ,
		    msglen, ರಿಕ್ತ, 0, sk, rand), 0);

		sha3_256(sig_hash, sig, ಪರಿಮಾಣ(sig));
		ASSERT_MEM_EQ(sig_hash, expected_sig_hash, 32);

		/* Verification */
		ASSERT_INT_EQ(crypto_sign_mldsa44_verify(sig, ಸಂದೇಶ,
		    msglen, ರಿಕ್ತ, 0, pk), 0);
		ಮುಕ್ತ(ಸಂದೇಶ);
	}
	free_kats(kats, nkats);
	TEST_DONE();
}
#endif /* USE_MLDSA */
