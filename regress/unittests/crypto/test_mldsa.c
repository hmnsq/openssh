/* 	$OpenBSD: test_mldsa.c,v 1.4 2026/06/22 12:28:48 dtucker Exp $ */
/*
 * Regress test for ML-DSA
 *
 * Placed in the public domain
 */

#అన్తర్భావ "includes.h"

#నిర్వచితమైతే USE_MLDSA

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <stdint.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <string.h>

#అన్తర్భావ "../test_helper/test_helper.h"
#అన్తర్భావ "crypto_api.h"
#అన్తర్భావ "xmalloc.h"
#అన్తర్భావ "sshbuf.h"

/* in tests.c */
నిర్మాణం sshbuf *ఎక్కించు_పాఠ్యం_file(స్థిరరాశి అక్షరం *name);
అక్షరం *get_json_string(నిర్మాణం sshbuf *content, స్థిరరాశి అక్షరం *కీలకం, పూర్ణాంకం consume);

శూన్య mldsa_tests(శూన్య);

నిర్మాణం kat {
	అక్షరం *విత్తనం;
	అక్షరం *pk_hash;
	అక్షరం *sk_hash;
	అక్షరం *సందేశం;
	అక్షరం *rand;
	అక్షరం *sig_hash;
};

స్థిర శూన్య
ఎక్కించు_kats(స్థిరరాశి అక్షరం *file, నిర్మాణం kat ***katsp, కొలత_t *nkatsp)
{
	నిర్మాణం sshbuf *json_buf;
	నిర్మాణం kat *kat = ఖాళీ, **kats = ఖాళీ;
	కొలత_t nkats = 0;

	json_buf = ఎక్కించు_పాఠ్యం_file(file);
	అయితే (sshbuf_కనుగొను(json_buf, 0, "key_generation_seed",
	    అక్షరశ్రేణి_పొడవు("key_generation_seed"), ఖాళీ) == 0) {
		kat = xcalloc(1, పరిమాణం(*kat));
		kat->విత్తనం = get_json_string(json_buf, "key_generation_seed", 1);
		kat->pk_hash = get_json_string(json_buf,
		    "sha3_256_hash_of_verification_key", 1);
		kat->sk_hash = get_json_string(json_buf,
		    "sha3_256_hash_of_signing_key", 1);
		kat->సందేశం = get_json_string(json_buf, "message", 1);
		kat->rand = get_json_string(json_buf, "signing_randomness", 1);
		kat->sig_hash = get_json_string(json_buf,
		    "sha3_256_hash_of_signature", 1);
		kats = xrecallocarray(kats, nkats, nkats + 1, పరిమాణం(*kats));
		kats[nkats++] = kat;
	}
	*katsp = kats;
	*nkatsp = nkats;
	sshbuf_free(json_buf);
}

స్థిర శూన్య
free_kats(నిర్మాణం kat **kats, కొలత_t nkats)
{
	కొలత_t i;
	నిర్మాణం kat *kat;

	కొరకు (i = 0; i < nkats; i++) {
		kat = kats[i];
		విడుదల(kat->విత్తనం);
		విడుదల(kat->pk_hash);
		విడుదల(kat->sk_hash);
		విడుదల(kat->సందేశం);
		విడుదల(kat->rand);
		విడుదల(kat->sig_hash);
		విడుదల(kat);
	}
	విడుదల(kats);
}

శూన్య
mldsa_tests(శూన్య)
{
	uint8_t pk[MLDSA44_PUBLICKEYBYTES];
	uint8_t sk[MLDSA44_SECRETKEYBYTES];
	uint8_t sig[MLDSA44_SIGBYTES];
	uint8_t pk_hash[32], sk_hash[32], sig_hash[32];
	uint8_t expected_pk_hash[32], expected_sk_hash[32];
	uint8_t expected_sig_hash[32];
	uint8_t విత్తనం[32], rand[32];
	uint8_t *సందేశం;
	కొలత_t nkats, i, msglen;
	నిర్మాణం kat **kats, *kat;

	TEST_ప్రారంభం("ML-DSA 44 KATs");
	ఎక్కించు_kats("nistkats-44.json", &kats, &nkats);
	కొరకు (i = 0; i < nkats; i++) {
		kat = kats[i];
		test_subtest_info("vector %zu", i);

		hex2bin(విత్తనం, kat->విత్తనం, 32);
		hex2bin(expected_pk_hash, kat->pk_hash, 32);
		hex2bin(expected_sk_hash, kat->sk_hash, 32);

		/* Keypair generation */
		ASSERT_INT_EQ(crypto_sign_mldsa44_keypair_seeded(pk,
		    sk, విత్తనం), 0);

		sha3_256(pk_hash, pk, పరిమాణం(pk));
		sha3_256(sk_hash, sk, పరిమాణం(sk));

		ASSERT_MEM_EQ(pk_hash, expected_pk_hash, 32);
		ASSERT_MEM_EQ(sk_hash, expected_sk_hash, 32);

		msglen = అక్షరశ్రేణి_పొడవు(kat->సందేశం) / 2;
		ASSERT_PTR_NE(సందేశం = జ్ఞాపకం_ఇవ్వు(msglen), ఖాళీ);
		hex2bin(సందేశం, kat->సందేశం, msglen);
		hex2bin(rand, kat->rand, 32);
		hex2bin(expected_sig_hash, kat->sig_hash, 32);

		/* Signing */
		ASSERT_INT_EQ(crypto_sign_mldsa44_seeded(sig, సందేశం,
		    msglen, ఖాళీ, 0, sk, rand), 0);

		sha3_256(sig_hash, sig, పరిమాణం(sig));
		ASSERT_MEM_EQ(sig_hash, expected_sig_hash, 32);

		/* Verification */
		ASSERT_INT_EQ(crypto_sign_mldsa44_verify(sig, సందేశం,
		    msglen, ఖాళీ, 0, pk), 0);
		విడుదల(సందేశం);
	}
	free_kats(kats, nkats);
	TEST_పూర్తి();
}
#అయితే_ముగింపు /* USE_MLDSA */
