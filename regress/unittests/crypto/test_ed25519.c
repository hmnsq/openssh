/* 	$OpenBSD: test_ed25519.c,v 1.5 2026/09/16 00:45:04 djm Exp $ */
/*
 * Regress test for Ed25519 keypair from seed
 *
 * Placed in the public domain
 */

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <stdint.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>

#अन्तर्भाव "../test_helper/test_helper.h"
#अन्तर्भाव "crypto_api.h"
#अन्तर्भाव "xmalloc.h"

संरचना ed25519_kat {
	स्थिरांक अक्षर *sk;
	स्थिरांक अक्षर *pk;
	स्थिरांक अक्षर *संदेश;
	स्थिरांक अक्षर *sig;
};

स्थिर स्थिरांक संरचना ed25519_kat ed25519_kats[] = {
	{
		"9d61b19deffd5a60ba844af492ec2cc44449c569"
		"7b326919703bac031cae7f60",
		"d75a980182b10ab7d54bfed3c964073a0ee172f3"
		"daa62325af021a68f707511a",
		"",
		"e5564300c360ac729086e2cc806e828a84877f1e"
		"b8e5d974d873e065224901555fb8821590a33bac"
		"c61e39701cf9b46bd25bf5f0595bbe2465514143"
		"8e7a100b"
	},
	{
		"4ccd089b28ff96da9db6c346ec114e0f5b8a319f"
		"35aba624da8cf6ed4fb8a6fb",
		"3d4017c3e843895a92b70aa74d1b7ebc9c982ccf"
		"2ec4968cc0cd55f12af4660c",
		"72",
		"92a009a9f0d4cab8720e820b5f642540a2b27b54"
		"16503f8fb3762223ebdb69da085ac1e43e15996e"
		"458f3613d0f11d8c387b2eaeb4302aeeb00d2916"
		"12bb0c00"
	},
	{
		"c5aa8df43f9f837bedb7442f31dcb7b166d38535"
		"076f094b85ce3a2e0b4458f7",
		"fc51cd8e6218a1a38da47ed00230f0580816ed13"
		"ba3303ac5deb911548908025",
		"af82",
		"6291d657deec24024827e69c3abe01a30ce548a2"
		"84743a445e3680d7db5ac3ac18ff9b538d16f290"
		"ae67f760984dc6594a7c15e9716ed28dc027bece"
		"ea1ec40a"
	}
};

शून्य ed25519_tests(शून्य);

शून्य
ed25519_tests(शून्य)
{
	uint8_t pk[32], sk[64], seed[32], sig[64];
	uint8_t expected_pk[32], expected_sig[64];
	uint8_t *संदेश;
	माप_प्रकार i, msglen;
	अचिन्हित दीर्घ दीर्घ smlen;

	साठी (i = 0; i < आकार(ed25519_kats)/आकार(ed25519_kats[0]); i++) {
		TEST_START("Ed25519 keypair from seed");
		hex2bin(seed, ed25519_kats[i].sk, 32);
		hex2bin(expected_pk, ed25519_kats[i].pk, 32);
		ASSERT_INT_EQ(crypto_sign_ed25519_seed_keypair(pk, sk, seed), 0);
		ASSERT_MEM_EQ(pk, expected_pk, 32);
		TEST_DONE();

		TEST_START("Ed25519 sign/verify KAT");
		msglen = म_माप(ed25519_kats[i].संदेश) / 2;
		ASSERT_PTR_NE(संदेश = दो_स्मृति(msglen == 0 ? 1 : msglen), रिक्त);
		hex2bin(संदेश, ed25519_kats[i].संदेश, msglen);
		hex2bin(expected_sig, ed25519_kats[i].sig, 64);

		ASSERT_INT_EQ(crypto_sign_ed25519_detached(sig, &smlen,
		    संदेश, msglen, sk), 0);
		ASSERT_INT_EQ(smlen, 64);
		ASSERT_MEM_EQ(sig, expected_sig, 64);

		ASSERT_INT_EQ(crypto_sign_ed25519_verify_detached(sig,
		    संदेश, msglen, pk), 0);
		मुक्त(संदेश);
		TEST_DONE();
	}
}
