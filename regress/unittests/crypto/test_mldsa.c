/* 	$OpenBSD: test_mldsa.c,v 1.4 2026/06/22 12:28:48 dtucker Exp $ */
/*
 * Regress test for ML-DSA
 *
 * Placed in the public domain
 */

#شامل "includes.h"

#اگر_تعریف_شدہ USE_MLDSA

#شامل <sys/types.h>
#شامل <stdio.h>
#شامل <stdint.h>
#شامل <stdlib.h>
#شامل <string.h>

#شامل "../test_helper/test_helper.h"
#شامل "crypto_api.h"
#شامل "xmalloc.h"
#شامل "sshbuf.h"

/* in tests.c */
ساخت sshbuf *بھرو_متن_file(ثابت حرف *name);
حرف *get_json_string(ساخت sshbuf *content, ثابت حرف *کلید, صحیح consume);

خالی mldsa_tests(خالی);

ساخت kat {
	حرف *بیج;
	حرف *pk_hash;
	حرف *sk_hash;
	حرف *پیغام;
	حرف *rand;
	حرف *sig_hash;
};

ساکن خالی
بھرو_kats(ثابت حرف *file, ساخت kat ***katsp, سائز_t *nkatsp)
{
	ساخت sshbuf *json_buf;
	ساخت kat *kat = تہی, **kats = تہی;
	سائز_t nkats = 0;

	json_buf = بھرو_متن_file(file);
	جب (sshbuf_ڈھونڈو(json_buf, 0, "key_generation_seed",
	    لڑی_لمبائی("key_generation_seed"), تہی) == 0) {
		kat = xcalloc(1, حجم(*kat));
		kat->بیج = get_json_string(json_buf, "key_generation_seed", 1);
		kat->pk_hash = get_json_string(json_buf,
		    "sha3_256_hash_of_verification_key", 1);
		kat->sk_hash = get_json_string(json_buf,
		    "sha3_256_hash_of_signing_key", 1);
		kat->پیغام = get_json_string(json_buf, "message", 1);
		kat->rand = get_json_string(json_buf, "signing_randomness", 1);
		kat->sig_hash = get_json_string(json_buf,
		    "sha3_256_hash_of_signature", 1);
		kats = xrecallocarray(kats, nkats, nkats + 1, حجم(*kats));
		kats[nkats++] = kat;
	}
	*katsp = kats;
	*nkatsp = nkats;
	sshbuf_free(json_buf);
}

ساکن خالی
free_kats(ساخت kat **kats, سائز_t nkats)
{
	سائز_t i;
	ساخت kat *kat;

	برائے (i = 0; i < nkats; i++) {
		kat = kats[i];
		آزاد(kat->بیج);
		آزاد(kat->pk_hash);
		آزاد(kat->sk_hash);
		آزاد(kat->پیغام);
		آزاد(kat->rand);
		آزاد(kat->sig_hash);
		آزاد(kat);
	}
	آزاد(kats);
}

خالی
mldsa_tests(خالی)
{
	uint8_t pk[MLDSA44_PUBLICKEYBYTES];
	uint8_t sk[MLDSA44_SECRETKEYBYTES];
	uint8_t sig[MLDSA44_SIGBYTES];
	uint8_t pk_hash[32], sk_hash[32], sig_hash[32];
	uint8_t expected_pk_hash[32], expected_sk_hash[32];
	uint8_t expected_sig_hash[32];
	uint8_t بیج[32], rand[32];
	uint8_t *پیغام;
	سائز_t nkats, i, msglen;
	ساخت kat **kats, *kat;

	TEST_آغاز("ML-DSA 44 KATs");
	بھرو_kats("nistkats-44.json", &kats, &nkats);
	برائے (i = 0; i < nkats; i++) {
		kat = kats[i];
		test_subtest_info("vector %zu", i);

		hex2bin(بیج, kat->بیج, 32);
		hex2bin(expected_pk_hash, kat->pk_hash, 32);
		hex2bin(expected_sk_hash, kat->sk_hash, 32);

		/* Keypair generation */
		ASSERT_INT_EQ(crypto_sign_mldsa44_keypair_seeded(pk,
		    sk, بیج), 0);

		sha3_256(pk_hash, pk, حجم(pk));
		sha3_256(sk_hash, sk, حجم(sk));

		ASSERT_MEM_EQ(pk_hash, expected_pk_hash, 32);
		ASSERT_MEM_EQ(sk_hash, expected_sk_hash, 32);

		msglen = لڑی_لمبائی(kat->پیغام) / 2;
		ASSERT_PTR_NE(پیغام = حافظہ_دو(msglen), تہی);
		hex2bin(پیغام, kat->پیغام, msglen);
		hex2bin(rand, kat->rand, 32);
		hex2bin(expected_sig_hash, kat->sig_hash, 32);

		/* Signing */
		ASSERT_INT_EQ(crypto_sign_mldsa44_seeded(sig, پیغام,
		    msglen, تہی, 0, sk, rand), 0);

		sha3_256(sig_hash, sig, حجم(sig));
		ASSERT_MEM_EQ(sig_hash, expected_sig_hash, 32);

		/* Verification */
		ASSERT_INT_EQ(crypto_sign_mldsa44_verify(sig, پیغام,
		    msglen, تہی, 0, pk), 0);
		آزاد(پیغام);
	}
	free_kats(kats, nkats);
	TEST_مکمل();
}
#اگر_ختم /* USE_MLDSA */
