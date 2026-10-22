/* 	$OpenBSD: test_mldsa.c,v 1.4 2026/06/22 12:28:48 dtucker Exp $ */
/*
 * Regress test for ML-DSA
 *
 * Placed in the public domain
 */

#अन्तर्भाव "includes.h"

#ifdef USE_MLDSA

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <stdint.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>

#अन्तर्भाव "../test_helper/test_helper.h"
#अन्तर्भाव "crypto_api.h"
#अन्तर्भाव "xmalloc.h"
#अन्तर्भाव "sshbuf.h"

/* in tests.c */
संरचना sshbuf *load_text_file(स्थिरांक अक्षर *name);
अक्षर *get_json_string(संरचना sshbuf *content, स्थिरांक अक्षर *किल्ली, पूर्णांक consume);

शून्य mldsa_tests(शून्य);

संरचना kat {
	अक्षर *seed;
	अक्षर *pk_hash;
	अक्षर *sk_hash;
	अक्षर *संदेश;
	अक्षर *अक्रम;
	अक्षर *sig_hash;
};

स्थिर शून्य
load_kats(स्थिरांक अक्षर *file, संरचना kat ***katsp, माप_प्रकार *nkatsp)
{
	संरचना sshbuf *json_buf;
	संरचना kat *kat = रिक्त, **kats = रिक्त;
	माप_प्रकार nkats = 0;

	json_buf = load_text_file(file);
	पर्यंत (sshbuf_find(json_buf, 0, "key_generation_seed",
	    म_माप("key_generation_seed"), रिक्त) == 0) {
		kat = xcalloc(1, आकार(*kat));
		kat->seed = get_json_string(json_buf, "key_generation_seed", 1);
		kat->pk_hash = get_json_string(json_buf,
		    "sha3_256_hash_of_verification_key", 1);
		kat->sk_hash = get_json_string(json_buf,
		    "sha3_256_hash_of_signing_key", 1);
		kat->संदेश = get_json_string(json_buf, "message", 1);
		kat->अक्रम = get_json_string(json_buf, "signing_randomness", 1);
		kat->sig_hash = get_json_string(json_buf,
		    "sha3_256_hash_of_signature", 1);
		kats = xrecallocarray(kats, nkats, nkats + 1, आकार(*kats));
		kats[nkats++] = kat;
	}
	*katsp = kats;
	*nkatsp = nkats;
	sshbuf_free(json_buf);
}

स्थिर शून्य
free_kats(संरचना kat **kats, माप_प्रकार nkats)
{
	माप_प्रकार i;
	संरचना kat *kat;

	साठी (i = 0; i < nkats; i++) {
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

शून्य
mldsa_tests(शून्य)
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
	संरचना kat **kats, *kat;

	TEST_START("ML-DSA 44 KATs");
	load_kats("nistkats-44.json", &kats, &nkats);
	साठी (i = 0; i < nkats; i++) {
		kat = kats[i];
		test_subtest_info("vector %zu", i);

		hex2bin(seed, kat->seed, 32);
		hex2bin(expected_pk_hash, kat->pk_hash, 32);
		hex2bin(expected_sk_hash, kat->sk_hash, 32);

		/* Keypair generation */
		ASSERT_INT_EQ(crypto_sign_mldsa44_keypair_seeded(pk,
		    sk, seed), 0);

		sha3_256(pk_hash, pk, आकार(pk));
		sha3_256(sk_hash, sk, आकार(sk));

		ASSERT_MEM_EQ(pk_hash, expected_pk_hash, 32);
		ASSERT_MEM_EQ(sk_hash, expected_sk_hash, 32);

		msglen = म_माप(kat->संदेश) / 2;
		ASSERT_PTR_NE(संदेश = दो_स्मृति(msglen), रिक्त);
		hex2bin(संदेश, kat->संदेश, msglen);
		hex2bin(अक्रम, kat->अक्रम, 32);
		hex2bin(expected_sig_hash, kat->sig_hash, 32);

		/* Signing */
		ASSERT_INT_EQ(crypto_sign_mldsa44_seeded(sig, संदेश,
		    msglen, रिक्त, 0, sk, अक्रम), 0);

		sha3_256(sig_hash, sig, आकार(sig));
		ASSERT_MEM_EQ(sig_hash, expected_sig_hash, 32);

		/* Verification */
		ASSERT_INT_EQ(crypto_sign_mldsa44_verify(sig, संदेश,
		    msglen, रिक्त, 0, pk), 0);
		मुक्त(संदेश);
	}
	free_kats(kats, nkats);
	TEST_DONE();
}
#endif /* USE_MLDSA */
