/* 	$OpenBSD: test_mldsa.c,v 1.4 2026/06/22 12:28:48 dtucker Exp $ */
/*
 * Regress test for ML-DSA
 *
 * Placed in the public domain
 */

#அந்தர்பாவ "includes.h"

#ifdef USE_MLDSA

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <stdint.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <string.h>

#அந்தர்பாவ "../test_helper/test_helper.h"
#அந்தர்பாவ "crypto_api.h"
#அந்தர்பாவ "xmalloc.h"
#அந்தர்பாவ "sshbuf.h"

/* in tests.c */
கட்டமைப்பு sshbuf *load_text_file(மாறிலி எழுத்து *name);
எழுத்து *get_json_string(கட்டமைப்பு sshbuf *content, மாறிலி எழுத்து *சாவி, முழு consume);

வெறுமை mldsa_tests(வெறுமை);

கட்டமைப்பு kat {
	எழுத்து *seed;
	எழுத்து *pk_hash;
	எழுத்து *sk_hash;
	எழுத்து *செய்தி;
	எழுத்து *rand;
	எழுத்து *sig_hash;
};

நிலையான வெறுமை
load_kats(மாறிலி எழுத்து *file, கட்டமைப்பு kat ***katsp, size_t *nkatsp)
{
	கட்டமைப்பு sshbuf *json_buf;
	கட்டமைப்பு kat *kat = வெற்று, **kats = வெற்று;
	size_t nkats = 0;

	json_buf = load_text_file(file);
	போது (sshbuf_find(json_buf, 0, "key_generation_seed",
	    strlen("key_generation_seed"), வெற்று) == 0) {
		kat = xcalloc(1, அளவு(*kat));
		kat->seed = get_json_string(json_buf, "key_generation_seed", 1);
		kat->pk_hash = get_json_string(json_buf,
		    "sha3_256_hash_of_verification_key", 1);
		kat->sk_hash = get_json_string(json_buf,
		    "sha3_256_hash_of_signing_key", 1);
		kat->செய்தி = get_json_string(json_buf, "message", 1);
		kat->rand = get_json_string(json_buf, "signing_randomness", 1);
		kat->sig_hash = get_json_string(json_buf,
		    "sha3_256_hash_of_signature", 1);
		kats = xrecallocarray(kats, nkats, nkats + 1, அளவு(*kats));
		kats[nkats++] = kat;
	}
	*katsp = kats;
	*nkatsp = nkats;
	sshbuf_free(json_buf);
}

நிலையான வெறுமை
free_kats(கட்டமைப்பு kat **kats, size_t nkats)
{
	size_t i;
	கட்டமைப்பு kat *kat;

	க்கு (i = 0; i < nkats; i++) {
		kat = kats[i];
		விடுவி(kat->seed);
		விடுவி(kat->pk_hash);
		விடுவி(kat->sk_hash);
		விடுவி(kat->செய்தி);
		விடுவி(kat->rand);
		விடுவி(kat->sig_hash);
		விடுவி(kat);
	}
	விடுவி(kats);
}

வெறுமை
mldsa_tests(வெறுமை)
{
	uint8_t pk[MLDSA44_PUBLICKEYBYTES];
	uint8_t sk[MLDSA44_SECRETKEYBYTES];
	uint8_t sig[MLDSA44_SIGBYTES];
	uint8_t pk_hash[32], sk_hash[32], sig_hash[32];
	uint8_t expected_pk_hash[32], expected_sk_hash[32];
	uint8_t expected_sig_hash[32];
	uint8_t seed[32], rand[32];
	uint8_t *செய்தி;
	size_t nkats, i, msglen;
	கட்டமைப்பு kat **kats, *kat;

	TEST_START("ML-DSA 44 KATs");
	load_kats("nistkats-44.json", &kats, &nkats);
	க்கு (i = 0; i < nkats; i++) {
		kat = kats[i];
		test_subtest_info("vector %zu", i);

		hex2bin(seed, kat->seed, 32);
		hex2bin(expected_pk_hash, kat->pk_hash, 32);
		hex2bin(expected_sk_hash, kat->sk_hash, 32);

		/* Keypair generation */
		ASSERT_INT_EQ(crypto_sign_mldsa44_keypair_seeded(pk,
		    sk, seed), 0);

		sha3_256(pk_hash, pk, அளவு(pk));
		sha3_256(sk_hash, sk, அளவு(sk));

		ASSERT_MEM_EQ(pk_hash, expected_pk_hash, 32);
		ASSERT_MEM_EQ(sk_hash, expected_sk_hash, 32);

		msglen = strlen(kat->செய்தி) / 2;
		ASSERT_PTR_NE(செய்தி = malloc(msglen), வெற்று);
		hex2bin(செய்தி, kat->செய்தி, msglen);
		hex2bin(rand, kat->rand, 32);
		hex2bin(expected_sig_hash, kat->sig_hash, 32);

		/* Signing */
		ASSERT_INT_EQ(crypto_sign_mldsa44_seeded(sig, செய்தி,
		    msglen, வெற்று, 0, sk, rand), 0);

		sha3_256(sig_hash, sig, அளவு(sig));
		ASSERT_MEM_EQ(sig_hash, expected_sig_hash, 32);

		/* Verification */
		ASSERT_INT_EQ(crypto_sign_mldsa44_verify(sig, செய்தி,
		    msglen, வெற்று, 0, pk), 0);
		விடுவி(செய்தி);
	}
	free_kats(kats, nkats);
	TEST_DONE();
}
#endif /* USE_MLDSA */
