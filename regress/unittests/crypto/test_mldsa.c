/* 	$OpenBSD: test_mldsa.c,v 1.4 2026/06/22 12:28:48 dtucker Exp $ */
/*
 * Regress test for ML-DSA
 *
 * Placed in the public domain
 */

#અન્તર્ભાવ "includes.h"

#ifdef USE_MLDSA

#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <stdint.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <string.h>

#અન્તર્ભાવ "../test_helper/test_helper.h"
#અન્તર્ભાવ "crypto_api.h"
#અન્તર્ભાવ "xmalloc.h"
#અન્તર્ભાવ "sshbuf.h"

/* in tests.c */
સંરચના sshbuf *load_text_file(અચલ અક્ષર *name);
અક્ષર *get_json_string(સંરચના sshbuf *content, અચલ અક્ષર *ચાવી, પૂર્ણાંક consume);

શૂન્ય mldsa_tests(શૂન્ય);

સંરચના kat {
	અક્ષર *seed;
	અક્ષર *pk_hash;
	અક્ષર *sk_hash;
	અક્ષર *સંદેશ;
	અક્ષર *rand;
	અક્ષર *sig_hash;
};

સ્થિર શૂન્ય
load_kats(અચલ અક્ષર *file, સંરચના kat ***katsp, size_t *nkatsp)
{
	સંરચના sshbuf *json_buf;
	સંરચના kat *kat = ખાલી, **kats = ખાલી;
	size_t nkats = 0;

	json_buf = load_text_file(file);
	જ્યારે (sshbuf_find(json_buf, 0, "key_generation_seed",
	    strlen("key_generation_seed"), ખાલી) == 0) {
		kat = xcalloc(1, કદ(*kat));
		kat->seed = get_json_string(json_buf, "key_generation_seed", 1);
		kat->pk_hash = get_json_string(json_buf,
		    "sha3_256_hash_of_verification_key", 1);
		kat->sk_hash = get_json_string(json_buf,
		    "sha3_256_hash_of_signing_key", 1);
		kat->સંદેશ = get_json_string(json_buf, "message", 1);
		kat->rand = get_json_string(json_buf, "signing_randomness", 1);
		kat->sig_hash = get_json_string(json_buf,
		    "sha3_256_hash_of_signature", 1);
		kats = xrecallocarray(kats, nkats, nkats + 1, કદ(*kats));
		kats[nkats++] = kat;
	}
	*katsp = kats;
	*nkatsp = nkats;
	sshbuf_free(json_buf);
}

સ્થિર શૂન્ય
free_kats(સંરચના kat **kats, size_t nkats)
{
	size_t i;
	સંરચના kat *kat;

	માટે (i = 0; i < nkats; i++) {
		kat = kats[i];
		મુક્ત(kat->seed);
		મુક્ત(kat->pk_hash);
		મુક્ત(kat->sk_hash);
		મુક્ત(kat->સંદેશ);
		મુક્ત(kat->rand);
		મુક્ત(kat->sig_hash);
		મુક્ત(kat);
	}
	મુક્ત(kats);
}

શૂન્ય
mldsa_tests(શૂન્ય)
{
	uint8_t pk[MLDSA44_PUBLICKEYBYTES];
	uint8_t sk[MLDSA44_SECRETKEYBYTES];
	uint8_t sig[MLDSA44_SIGBYTES];
	uint8_t pk_hash[32], sk_hash[32], sig_hash[32];
	uint8_t expected_pk_hash[32], expected_sk_hash[32];
	uint8_t expected_sig_hash[32];
	uint8_t seed[32], rand[32];
	uint8_t *સંદેશ;
	size_t nkats, i, msglen;
	સંરચના kat **kats, *kat;

	TEST_START("ML-DSA 44 KATs");
	load_kats("nistkats-44.json", &kats, &nkats);
	માટે (i = 0; i < nkats; i++) {
		kat = kats[i];
		test_subtest_info("vector %zu", i);

		hex2bin(seed, kat->seed, 32);
		hex2bin(expected_pk_hash, kat->pk_hash, 32);
		hex2bin(expected_sk_hash, kat->sk_hash, 32);

		/* Keypair generation */
		ASSERT_INT_EQ(crypto_sign_mldsa44_keypair_seeded(pk,
		    sk, seed), 0);

		sha3_256(pk_hash, pk, કદ(pk));
		sha3_256(sk_hash, sk, કદ(sk));

		ASSERT_MEM_EQ(pk_hash, expected_pk_hash, 32);
		ASSERT_MEM_EQ(sk_hash, expected_sk_hash, 32);

		msglen = strlen(kat->સંદેશ) / 2;
		ASSERT_PTR_NE(સંદેશ = malloc(msglen), ખાલી);
		hex2bin(સંદેશ, kat->સંદેશ, msglen);
		hex2bin(rand, kat->rand, 32);
		hex2bin(expected_sig_hash, kat->sig_hash, 32);

		/* Signing */
		ASSERT_INT_EQ(crypto_sign_mldsa44_seeded(sig, સંદેશ,
		    msglen, ખાલી, 0, sk, rand), 0);

		sha3_256(sig_hash, sig, કદ(sig));
		ASSERT_MEM_EQ(sig_hash, expected_sig_hash, 32);

		/* Verification */
		ASSERT_INT_EQ(crypto_sign_mldsa44_verify(sig, સંદેશ,
		    msglen, ખાલી, 0, pk), 0);
		મુક્ત(સંદેશ);
	}
	free_kats(kats, nkats);
	TEST_DONE();
}
#endif /* USE_MLDSA */
