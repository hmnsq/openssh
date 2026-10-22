/* 	$OpenBSD: test_mldsa.c,v 1.4 2026/06/22 12:28:48 dtucker Exp $ */
/*
 * Regress test for ML-DSA
 *
 * Placed in the public domain
 */

#ಅನ್ತರ್ಭಾವ "includes.h"

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ USE_MLDSA

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
ರಚನೆ sshbuf *ತುಂಬು_ಪಠ್ಯ_file(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *name);
ಅಕ್ಷರ *get_json_string(ರಚನೆ sshbuf *content, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಕೀಲಿ, ಪೂರ್ಣಾಂಕ consume);

ಶೂನ್ಯ mldsa_tests(ಶೂನ್ಯ);

ರಚನೆ kat {
	ಅಕ್ಷರ *ಬೀಜ;
	ಅಕ್ಷರ *pk_hash;
	ಅಕ್ಷರ *sk_hash;
	ಅಕ್ಷರ *ಸಂದೇಶ;
	ಅಕ್ಷರ *rand;
	ಅಕ್ಷರ *sig_hash;
};

ಸ್ಥಿರ ಶೂನ್ಯ
ತುಂಬು_kats(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *file, ರಚನೆ kat ***katsp, ಗಾತ್ರ_t *nkatsp)
{
	ರಚನೆ sshbuf *json_buf;
	ರಚನೆ kat *kat = ಖಾಲಿ, **kats = ಖಾಲಿ;
	ಗಾತ್ರ_t nkats = 0;

	json_buf = ತುಂಬು_ಪಠ್ಯ_file(file);
	ಆಗ (sshbuf_ಕಂಡುಹಿಡಿ(json_buf, 0, "key_generation_seed",
	    ಅಕ್ಷರಸರಣಿ_ಉದ್ದ("key_generation_seed"), ಖಾಲಿ) == 0) {
		kat = xcalloc(1, ಗಾತ್ರ(*kat));
		kat->ಬೀಜ = get_json_string(json_buf, "key_generation_seed", 1);
		kat->pk_hash = get_json_string(json_buf,
		    "sha3_256_hash_of_verification_key", 1);
		kat->sk_hash = get_json_string(json_buf,
		    "sha3_256_hash_of_signing_key", 1);
		kat->ಸಂದೇಶ = get_json_string(json_buf, "message", 1);
		kat->rand = get_json_string(json_buf, "signing_randomness", 1);
		kat->sig_hash = get_json_string(json_buf,
		    "sha3_256_hash_of_signature", 1);
		kats = xrecallocarray(kats, nkats, nkats + 1, ಗಾತ್ರ(*kats));
		kats[nkats++] = kat;
	}
	*katsp = kats;
	*nkatsp = nkats;
	sshbuf_free(json_buf);
}

ಸ್ಥಿರ ಶೂನ್ಯ
free_kats(ರಚನೆ kat **kats, ಗಾತ್ರ_t nkats)
{
	ಗಾತ್ರ_t i;
	ರಚನೆ kat *kat;

	ಗಾಗಿ (i = 0; i < nkats; i++) {
		kat = kats[i];
		ಬಿಡುಗಡೆ(kat->ಬೀಜ);
		ಬಿಡುಗಡೆ(kat->pk_hash);
		ಬಿಡುಗಡೆ(kat->sk_hash);
		ಬಿಡುಗಡೆ(kat->ಸಂದೇಶ);
		ಬಿಡುಗಡೆ(kat->rand);
		ಬಿಡುಗಡೆ(kat->sig_hash);
		ಬಿಡುಗಡೆ(kat);
	}
	ಬಿಡುಗಡೆ(kats);
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
	uint8_t ಬೀಜ[32], rand[32];
	uint8_t *ಸಂದೇಶ;
	ಗಾತ್ರ_t nkats, i, msglen;
	ರಚನೆ kat **kats, *kat;

	TEST_ಆರಂಭ("ML-DSA 44 KATs");
	ತುಂಬು_kats("nistkats-44.json", &kats, &nkats);
	ಗಾಗಿ (i = 0; i < nkats; i++) {
		kat = kats[i];
		test_subtest_info("vector %zu", i);

		hex2bin(ಬೀಜ, kat->ಬೀಜ, 32);
		hex2bin(expected_pk_hash, kat->pk_hash, 32);
		hex2bin(expected_sk_hash, kat->sk_hash, 32);

		/* Keypair generation */
		ASSERT_INT_EQ(crypto_sign_mldsa44_keypair_seeded(pk,
		    sk, ಬೀಜ), 0);

		sha3_256(pk_hash, pk, ಗಾತ್ರ(pk));
		sha3_256(sk_hash, sk, ಗಾತ್ರ(sk));

		ASSERT_MEM_EQ(pk_hash, expected_pk_hash, 32);
		ASSERT_MEM_EQ(sk_hash, expected_sk_hash, 32);

		msglen = ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(kat->ಸಂದೇಶ) / 2;
		ASSERT_PTR_NE(ಸಂದೇಶ = ಸ್ಮರಣೆ_ಕೊಡು(msglen), ಖಾಲಿ);
		hex2bin(ಸಂದೇಶ, kat->ಸಂದೇಶ, msglen);
		hex2bin(rand, kat->rand, 32);
		hex2bin(expected_sig_hash, kat->sig_hash, 32);

		/* Signing */
		ASSERT_INT_EQ(crypto_sign_mldsa44_seeded(sig, ಸಂದೇಶ,
		    msglen, ಖಾಲಿ, 0, sk, rand), 0);

		sha3_256(sig_hash, sig, ಗಾತ್ರ(sig));
		ASSERT_MEM_EQ(sig_hash, expected_sig_hash, 32);

		/* Verification */
		ASSERT_INT_EQ(crypto_sign_mldsa44_verify(sig, ಸಂದೇಶ,
		    msglen, ಖಾಲಿ, 0, pk), 0);
		ಬಿಡುಗಡೆ(ಸಂದೇಶ);
	}
	free_kats(kats, nkats);
	TEST_ಮುಗಿದ();
}
#ಆದರೆ_ಅಂತ್ಯ /* USE_MLDSA */
