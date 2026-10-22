/* 	$OpenBSD: test_mldsa.c,v 1.4 2026/06/22 12:28:48 dtucker Exp $ */
/*
 * Regress test for ML-DSA
 *
 * Placed in the public domain
 */

#समावेश "includes.h"

#अगर_घोषित USE_MLDSA

#समावेश <sys/types.h>
#समावेश <stdio.h>
#समावेश <stdint.h>
#समावेश <stdlib.h>
#समावेश <string.h>

#समावेश "../test_helper/test_helper.h"
#समावेश "crypto_api.h"
#समावेश "xmalloc.h"
#समावेश "sshbuf.h"

/* in tests.c */
काष्ठा sshbuf *load_text_file(स्थिर अक्षर *name);
अक्षर *get_json_string(काष्ठा sshbuf *content, स्थिर अक्षर *कुंजी, पूर्णांक consume);

व्योम mldsa_tests(व्योम);

काष्ठा kat {
	अक्षर *seed;
	अक्षर *pk_hash;
	अक्षर *sk_hash;
	अक्षर *संदेश;
	अक्षर *अक्रम;
	अक्षर *sig_hash;
};

अटल व्योम
load_kats(स्थिर अक्षर *file, काष्ठा kat ***katsp, माप_प्रकार *nkatsp)
{
	काष्ठा sshbuf *json_buf;
	काष्ठा kat *kat = शून्य, **kats = शून्य;
	माप_प्रकार nkats = 0;

	json_buf = load_text_file(file);
	जबतक (sshbuf_find(json_buf, 0, "key_generation_seed",
	    म_माप("key_generation_seed"), शून्य) == 0) {
		kat = xcalloc(1, माप(*kat));
		kat->seed = get_json_string(json_buf, "key_generation_seed", 1);
		kat->pk_hash = get_json_string(json_buf,
		    "sha3_256_hash_of_verification_key", 1);
		kat->sk_hash = get_json_string(json_buf,
		    "sha3_256_hash_of_signing_key", 1);
		kat->संदेश = get_json_string(json_buf, "message", 1);
		kat->अक्रम = get_json_string(json_buf, "signing_randomness", 1);
		kat->sig_hash = get_json_string(json_buf,
		    "sha3_256_hash_of_signature", 1);
		kats = xrecallocarray(kats, nkats, nkats + 1, माप(*kats));
		kats[nkats++] = kat;
	}
	*katsp = kats;
	*nkatsp = nkats;
	sshbuf_free(json_buf);
}

अटल व्योम
free_kats(काष्ठा kat **kats, माप_प्रकार nkats)
{
	माप_प्रकार i;
	काष्ठा kat *kat;

	क्रम (i = 0; i < nkats; i++) {
		kat = kats[i];
		मुक्त(kat->seed);
		मुक्त(kat->pk_hash);
		मुक्त(kat->sk_hash);
		मुक्त(kat->संदेश);
		मुक्त(kat->अक्रम);
		मुक्त(kat->sig_hash);
		मुक्त(kat);
	}
	मुक्त(kats);
}

व्योम
mldsa_tests(व्योम)
{
	uint8_t pk[MLDSA44_PUBLICKEYBYTES];
	uint8_t sk[MLDSA44_SECRETKEYBYTES];
	uint8_t sig[MLDSA44_SIGBYTES];
	uint8_t pk_hash[32], sk_hash[32], sig_hash[32];
	uint8_t expected_pk_hash[32], expected_sk_hash[32];
	uint8_t expected_sig_hash[32];
	uint8_t seed[32], अक्रम[32];
	uint8_t *संदेश;
	माप_प्रकार nkats, i, msglen;
	काष्ठा kat **kats, *kat;

	TEST_START("ML-DSA 44 KATs");
	load_kats("nistkats-44.json", &kats, &nkats);
	क्रम (i = 0; i < nkats; i++) {
		kat = kats[i];
		test_subtest_info("vector %zu", i);

		hex2bin(seed, kat->seed, 32);
		hex2bin(expected_pk_hash, kat->pk_hash, 32);
		hex2bin(expected_sk_hash, kat->sk_hash, 32);

		/* Keypair generation */
		ASSERT_INT_EQ(crypto_sign_mldsa44_keypair_seeded(pk,
		    sk, seed), 0);

		sha3_256(pk_hash, pk, माप(pk));
		sha3_256(sk_hash, sk, माप(sk));

		ASSERT_MEM_EQ(pk_hash, expected_pk_hash, 32);
		ASSERT_MEM_EQ(sk_hash, expected_sk_hash, 32);

		msglen = म_माप(kat->संदेश) / 2;
		ASSERT_PTR_NE(संदेश = दो_स्मृति(msglen), शून्य);
		hex2bin(संदेश, kat->संदेश, msglen);
		hex2bin(अक्रम, kat->अक्रम, 32);
		hex2bin(expected_sig_hash, kat->sig_hash, 32);

		/* Signing */
		ASSERT_INT_EQ(crypto_sign_mldsa44_seeded(sig, संदेश,
		    msglen, शून्य, 0, sk, अक्रम), 0);

		sha3_256(sig_hash, sig, माप(sig));
		ASSERT_MEM_EQ(sig_hash, expected_sig_hash, 32);

		/* Verification */
		ASSERT_INT_EQ(crypto_sign_mldsa44_verify(sig, संदेश,
		    msglen, शून्य, 0, pk), 0);
		मुक्त(संदेश);
	}
	free_kats(kats, nkats);
	TEST_DONE();
}
#पूर्ण_अगर /* USE_MLDSA */
