/* 	$OpenBSD: test_mldsa.c,v 1.4 2026/06/22 12:28:48 dtucker Exp $ */
/*
 * Regress test for ML-DSA
 *
 * Placed in the public domain
 */

#അന്തര്ഭാവ "includes.h"

#ifdef USE_MLDSA

#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <stdint.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <string.h>

#അന്തര്ഭാവ "../test_helper/test_helper.h"
#അന്തര്ഭാവ "crypto_api.h"
#അന്തര്ഭാവ "xmalloc.h"
#അന്തര്ഭാവ "sshbuf.h"

/* in tests.c */
ഘടന sshbuf *load_text_file(സ്ഥിരം അക്ഷരം *name);
അക്ഷരം *get_json_string(ഘടന sshbuf *content, സ്ഥിരം അക്ഷരം *താക്കോൽ, പൂർണ്ണസംഖ്യ consume);

ശൂന്യം mldsa_tests(ശൂന്യം);

ഘടന kat {
	അക്ഷരം *seed;
	അക്ഷരം *pk_hash;
	അക്ഷരം *sk_hash;
	അക്ഷരം *സന്ദേശം;
	അക്ഷരം *rand;
	അക്ഷരം *sig_hash;
};

സ്ഥിതം ശൂന്യം
load_kats(സ്ഥിരം അക്ഷരം *file, ഘടന kat ***katsp, size_t *nkatsp)
{
	ഘടന sshbuf *json_buf;
	ഘടന kat *kat = ശൂന്യ, **kats = ശൂന്യ;
	size_t nkats = 0;

	json_buf = load_text_file(file);
	ആകുമ്പോൾ (sshbuf_find(json_buf, 0, "key_generation_seed",
	    strlen("key_generation_seed"), ശൂന്യ) == 0) {
		kat = xcalloc(1, വലുപ്പം(*kat));
		kat->seed = get_json_string(json_buf, "key_generation_seed", 1);
		kat->pk_hash = get_json_string(json_buf,
		    "sha3_256_hash_of_verification_key", 1);
		kat->sk_hash = get_json_string(json_buf,
		    "sha3_256_hash_of_signing_key", 1);
		kat->സന്ദേശം = get_json_string(json_buf, "message", 1);
		kat->rand = get_json_string(json_buf, "signing_randomness", 1);
		kat->sig_hash = get_json_string(json_buf,
		    "sha3_256_hash_of_signature", 1);
		kats = xrecallocarray(kats, nkats, nkats + 1, വലുപ്പം(*kats));
		kats[nkats++] = kat;
	}
	*katsp = kats;
	*nkatsp = nkats;
	sshbuf_free(json_buf);
}

സ്ഥിതം ശൂന്യം
free_kats(ഘടന kat **kats, size_t nkats)
{
	size_t i;
	ഘടന kat *kat;

	വേണ്ടി (i = 0; i < nkats; i++) {
		kat = kats[i];
		സ്വതന്ത്രം(kat->seed);
		സ്വതന്ത്രം(kat->pk_hash);
		സ്വതന്ത്രം(kat->sk_hash);
		സ്വതന്ത്രം(kat->സന്ദേശം);
		സ്വതന്ത്രം(kat->rand);
		സ്വതന്ത്രം(kat->sig_hash);
		സ്വതന്ത്രം(kat);
	}
	സ്വതന്ത്രം(kats);
}

ശൂന്യം
mldsa_tests(ശൂന്യം)
{
	uint8_t pk[MLDSA44_PUBLICKEYBYTES];
	uint8_t sk[MLDSA44_SECRETKEYBYTES];
	uint8_t sig[MLDSA44_SIGBYTES];
	uint8_t pk_hash[32], sk_hash[32], sig_hash[32];
	uint8_t expected_pk_hash[32], expected_sk_hash[32];
	uint8_t expected_sig_hash[32];
	uint8_t seed[32], rand[32];
	uint8_t *സന്ദേശം;
	size_t nkats, i, msglen;
	ഘടന kat **kats, *kat;

	TEST_START("ML-DSA 44 KATs");
	load_kats("nistkats-44.json", &kats, &nkats);
	വേണ്ടി (i = 0; i < nkats; i++) {
		kat = kats[i];
		test_subtest_info("vector %zu", i);

		hex2bin(seed, kat->seed, 32);
		hex2bin(expected_pk_hash, kat->pk_hash, 32);
		hex2bin(expected_sk_hash, kat->sk_hash, 32);

		/* Keypair generation */
		ASSERT_INT_EQ(crypto_sign_mldsa44_keypair_seeded(pk,
		    sk, seed), 0);

		sha3_256(pk_hash, pk, വലുപ്പം(pk));
		sha3_256(sk_hash, sk, വലുപ്പം(sk));

		ASSERT_MEM_EQ(pk_hash, expected_pk_hash, 32);
		ASSERT_MEM_EQ(sk_hash, expected_sk_hash, 32);

		msglen = strlen(kat->സന്ദേശം) / 2;
		ASSERT_PTR_NE(സന്ദേശം = malloc(msglen), ശൂന്യ);
		hex2bin(സന്ദേശം, kat->സന്ദേശം, msglen);
		hex2bin(rand, kat->rand, 32);
		hex2bin(expected_sig_hash, kat->sig_hash, 32);

		/* Signing */
		ASSERT_INT_EQ(crypto_sign_mldsa44_seeded(sig, സന്ദേശം,
		    msglen, ശൂന്യ, 0, sk, rand), 0);

		sha3_256(sig_hash, sig, വലുപ്പം(sig));
		ASSERT_MEM_EQ(sig_hash, expected_sig_hash, 32);

		/* Verification */
		ASSERT_INT_EQ(crypto_sign_mldsa44_verify(sig, സന്ദേശം,
		    msglen, ശൂന്യ, 0, pk), 0);
		സ്വതന്ത്രം(സന്ദേശം);
	}
	free_kats(kats, nkats);
	TEST_DONE();
}
#endif /* USE_MLDSA */
