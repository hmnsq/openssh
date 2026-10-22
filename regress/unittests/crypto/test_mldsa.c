/* 	$OpenBSD: test_mldsa.c,v 1.4 2026/06/22 12:28:48 dtucker Exp $ */
/*
 * Regress test for ML-DSA
 *
 * Placed in the public domain
 */

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ifdef USE_MLDSA

#ଅନ୍ତର୍ଭାଵ <sys/types.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <stdint.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <string.h>

#ଅନ୍ତର୍ଭାଵ "../test_helper/test_helper.h"
#ଅନ୍ତର୍ଭାଵ "crypto_api.h"
#ଅନ୍ତର୍ଭାଵ "xmalloc.h"
#ଅନ୍ତର୍ଭାଵ "sshbuf.h"

/* in tests.c */
ସଂରଚନା sshbuf *load_text_file(ଅଚଳ ଅକ୍ଷର *name);
ଅକ୍ଷର *get_json_string(ସଂରଚନା sshbuf *content, ଅଚଳ ଅକ୍ଷର *ଚାବି, ପୂର୍ଣ୍ଣସଂଖ୍ୟା consume);

ଶୂନ୍ୟ mldsa_tests(ଶୂନ୍ୟ);

ସଂରଚନା kat {
	ଅକ୍ଷର *seed;
	ଅକ୍ଷର *pk_hash;
	ଅକ୍ଷର *sk_hash;
	ଅକ୍ଷର *ସନ୍ଦେଶ;
	ଅକ୍ଷର *rand;
	ଅକ୍ଷର *sig_hash;
};

ସ୍ଥିର ଶୂନ୍ୟ
load_kats(ଅଚଳ ଅକ୍ଷର *file, ସଂରଚନା kat ***katsp, size_t *nkatsp)
{
	ସଂରଚନା sshbuf *json_buf;
	ସଂରଚନା kat *kat = ଖାଲି, **kats = ଖାଲି;
	size_t nkats = 0;

	json_buf = load_text_file(file);
	ଯେତେବେଳେ (sshbuf_find(json_buf, 0, "key_generation_seed",
	    strlen("key_generation_seed"), ଖାଲି) == 0) {
		kat = xcalloc(1, ଆକାର(*kat));
		kat->seed = get_json_string(json_buf, "key_generation_seed", 1);
		kat->pk_hash = get_json_string(json_buf,
		    "sha3_256_hash_of_verification_key", 1);
		kat->sk_hash = get_json_string(json_buf,
		    "sha3_256_hash_of_signing_key", 1);
		kat->ସନ୍ଦେଶ = get_json_string(json_buf, "message", 1);
		kat->rand = get_json_string(json_buf, "signing_randomness", 1);
		kat->sig_hash = get_json_string(json_buf,
		    "sha3_256_hash_of_signature", 1);
		kats = xrecallocarray(kats, nkats, nkats + 1, ଆକାର(*kats));
		kats[nkats++] = kat;
	}
	*katsp = kats;
	*nkatsp = nkats;
	sshbuf_free(json_buf);
}

ସ୍ଥିର ଶୂନ୍ୟ
free_kats(ସଂରଚନା kat **kats, size_t nkats)
{
	size_t i;
	ସଂରଚନା kat *kat;

	ପାଇଁ (i = 0; i < nkats; i++) {
		kat = kats[i];
		ମୁକ୍ତ(kat->seed);
		ମୁକ୍ତ(kat->pk_hash);
		ମୁକ୍ତ(kat->sk_hash);
		ମୁକ୍ତ(kat->ସନ୍ଦେଶ);
		ମୁକ୍ତ(kat->rand);
		ମୁକ୍ତ(kat->sig_hash);
		ମୁକ୍ତ(kat);
	}
	ମୁକ୍ତ(kats);
}

ଶୂନ୍ୟ
mldsa_tests(ଶୂନ୍ୟ)
{
	uint8_t pk[MLDSA44_PUBLICKEYBYTES];
	uint8_t sk[MLDSA44_SECRETKEYBYTES];
	uint8_t sig[MLDSA44_SIGBYTES];
	uint8_t pk_hash[32], sk_hash[32], sig_hash[32];
	uint8_t expected_pk_hash[32], expected_sk_hash[32];
	uint8_t expected_sig_hash[32];
	uint8_t seed[32], rand[32];
	uint8_t *ସନ୍ଦେଶ;
	size_t nkats, i, msglen;
	ସଂରଚନା kat **kats, *kat;

	TEST_START("ML-DSA 44 KATs");
	load_kats("nistkats-44.json", &kats, &nkats);
	ପାଇଁ (i = 0; i < nkats; i++) {
		kat = kats[i];
		test_subtest_info("vector %zu", i);

		hex2bin(seed, kat->seed, 32);
		hex2bin(expected_pk_hash, kat->pk_hash, 32);
		hex2bin(expected_sk_hash, kat->sk_hash, 32);

		/* Keypair generation */
		ASSERT_INT_EQ(crypto_sign_mldsa44_keypair_seeded(pk,
		    sk, seed), 0);

		sha3_256(pk_hash, pk, ଆକାର(pk));
		sha3_256(sk_hash, sk, ଆକାର(sk));

		ASSERT_MEM_EQ(pk_hash, expected_pk_hash, 32);
		ASSERT_MEM_EQ(sk_hash, expected_sk_hash, 32);

		msglen = strlen(kat->ସନ୍ଦେଶ) / 2;
		ASSERT_PTR_NE(ସନ୍ଦେଶ = malloc(msglen), ଖାଲି);
		hex2bin(ସନ୍ଦେଶ, kat->ସନ୍ଦେଶ, msglen);
		hex2bin(rand, kat->rand, 32);
		hex2bin(expected_sig_hash, kat->sig_hash, 32);

		/* Signing */
		ASSERT_INT_EQ(crypto_sign_mldsa44_seeded(sig, ସନ୍ଦେଶ,
		    msglen, ଖାଲି, 0, sk, rand), 0);

		sha3_256(sig_hash, sig, ଆକାର(sig));
		ASSERT_MEM_EQ(sig_hash, expected_sig_hash, 32);

		/* Verification */
		ASSERT_INT_EQ(crypto_sign_mldsa44_verify(sig, ସନ୍ଦେଶ,
		    msglen, ଖାଲି, 0, pk), 0);
		ମୁକ୍ତ(ସନ୍ଦେଶ);
	}
	free_kats(kats, nkats);
	TEST_DONE();
}
#endif /* USE_MLDSA */
