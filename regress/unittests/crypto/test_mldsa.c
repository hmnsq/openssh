/* 	$OpenBSD: test_mldsa.c,v 1.4 2026/06/22 12:28:48 dtucker Exp $ */
/*
 * Regress test for ML-DSA
 *
 * Placed in the public domain
 */

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ USE_MLDSA

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdint.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "../test_helper/test_helper.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "crypto_api.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "xmalloc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshbuf.h"

/* in tests.c */
ਬਣਤਰ sshbuf *ਲੱਦੋ_ਪਾਠ_file(ਅਚਲ ਅੱਖਰ *name);
ਅੱਖਰ *get_json_string(ਬਣਤਰ sshbuf *content, ਅਚਲ ਅੱਖਰ *ਕੁੰਜੀ, ਪੂਰਨ consume);

ਖਾਲੀ mldsa_tests(ਖਾਲੀ);

ਬਣਤਰ kat {
	ਅੱਖਰ *ਬੀਜ;
	ਅੱਖਰ *pk_hash;
	ਅੱਖਰ *sk_hash;
	ਅੱਖਰ *ਸੁਨੇਹਾ;
	ਅੱਖਰ *rand;
	ਅੱਖਰ *sig_hash;
};

ਸਥਿਰ ਖਾਲੀ
ਲੱਦੋ_kats(ਅਚਲ ਅੱਖਰ *file, ਬਣਤਰ kat ***katsp, ਮਾਪ_t *nkatsp)
{
	ਬਣਤਰ sshbuf *json_buf;
	ਬਣਤਰ kat *kat = ਨਿਰਾ, **kats = ਨਿਰਾ;
	ਮਾਪ_t nkats = 0;

	json_buf = ਲੱਦੋ_ਪਾਠ_file(file);
	ਜਦੋਂ (sshbuf_ਲੱਭੋ(json_buf, 0, "key_generation_seed",
	    ਲੜੀ_ਲੰਬਾਈ("key_generation_seed"), ਨਿਰਾ) == 0) {
		kat = xcalloc(1, ਆਕਾਰ(*kat));
		kat->ਬੀਜ = get_json_string(json_buf, "key_generation_seed", 1);
		kat->pk_hash = get_json_string(json_buf,
		    "sha3_256_hash_of_verification_key", 1);
		kat->sk_hash = get_json_string(json_buf,
		    "sha3_256_hash_of_signing_key", 1);
		kat->ਸੁਨੇਹਾ = get_json_string(json_buf, "message", 1);
		kat->rand = get_json_string(json_buf, "signing_randomness", 1);
		kat->sig_hash = get_json_string(json_buf,
		    "sha3_256_hash_of_signature", 1);
		kats = xrecallocarray(kats, nkats, nkats + 1, ਆਕਾਰ(*kats));
		kats[nkats++] = kat;
	}
	*katsp = kats;
	*nkatsp = nkats;
	sshbuf_free(json_buf);
}

ਸਥਿਰ ਖਾਲੀ
free_kats(ਬਣਤਰ kat **kats, ਮਾਪ_t nkats)
{
	ਮਾਪ_t i;
	ਬਣਤਰ kat *kat;

	ਲਈ (i = 0; i < nkats; i++) {
		kat = kats[i];
		ਮੁਕਤ(kat->ਬੀਜ);
		ਮੁਕਤ(kat->pk_hash);
		ਮੁਕਤ(kat->sk_hash);
		ਮੁਕਤ(kat->ਸੁਨੇਹਾ);
		ਮੁਕਤ(kat->rand);
		ਮੁਕਤ(kat->sig_hash);
		ਮੁਕਤ(kat);
	}
	ਮੁਕਤ(kats);
}

ਖਾਲੀ
mldsa_tests(ਖਾਲੀ)
{
	uint8_t pk[MLDSA44_PUBLICKEYBYTES];
	uint8_t sk[MLDSA44_SECRETKEYBYTES];
	uint8_t sig[MLDSA44_SIGBYTES];
	uint8_t pk_hash[32], sk_hash[32], sig_hash[32];
	uint8_t expected_pk_hash[32], expected_sk_hash[32];
	uint8_t expected_sig_hash[32];
	uint8_t ਬੀਜ[32], rand[32];
	uint8_t *ਸੁਨੇਹਾ;
	ਮਾਪ_t nkats, i, msglen;
	ਬਣਤਰ kat **kats, *kat;

	TEST_ਸ਼ੁਰੂ("ML-DSA 44 KATs");
	ਲੱਦੋ_kats("nistkats-44.json", &kats, &nkats);
	ਲਈ (i = 0; i < nkats; i++) {
		kat = kats[i];
		test_subtest_info("vector %zu", i);

		hex2bin(ਬੀਜ, kat->ਬੀਜ, 32);
		hex2bin(expected_pk_hash, kat->pk_hash, 32);
		hex2bin(expected_sk_hash, kat->sk_hash, 32);

		/* Keypair generation */
		ASSERT_INT_EQ(crypto_sign_mldsa44_keypair_seeded(pk,
		    sk, ਬੀਜ), 0);

		sha3_256(pk_hash, pk, ਆਕਾਰ(pk));
		sha3_256(sk_hash, sk, ਆਕਾਰ(sk));

		ASSERT_MEM_EQ(pk_hash, expected_pk_hash, 32);
		ASSERT_MEM_EQ(sk_hash, expected_sk_hash, 32);

		msglen = ਲੜੀ_ਲੰਬਾਈ(kat->ਸੁਨੇਹਾ) / 2;
		ASSERT_PTR_NE(ਸੁਨੇਹਾ = ਸਮ੍ਰਿਤੀ_ਦਿਓ(msglen), ਨਿਰਾ);
		hex2bin(ਸੁਨੇਹਾ, kat->ਸੁਨੇਹਾ, msglen);
		hex2bin(rand, kat->rand, 32);
		hex2bin(expected_sig_hash, kat->sig_hash, 32);

		/* Signing */
		ASSERT_INT_EQ(crypto_sign_mldsa44_seeded(sig, ਸੁਨੇਹਾ,
		    msglen, ਨਿਰਾ, 0, sk, rand), 0);

		sha3_256(sig_hash, sig, ਆਕਾਰ(sig));
		ASSERT_MEM_EQ(sig_hash, expected_sig_hash, 32);

		/* Verification */
		ASSERT_INT_EQ(crypto_sign_mldsa44_verify(sig, ਸੁਨੇਹਾ,
		    msglen, ਨਿਰਾ, 0, pk), 0);
		ਮੁਕਤ(ਸੁਨੇਹਾ);
	}
	free_kats(kats, nkats);
	TEST_ਪੂਰਾ();
}
#ਜੇ_ਅੰਤ /* USE_MLDSA */
