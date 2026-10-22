// Basic fuzz test for depcapsulate operation,

#അന്തര്ഭാവ <stddef.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <stdint.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <unistd.h>
#അന്തര്ഭാവ <err.h>

ബാഹ്യ "C" {

#അന്തര്ഭാവ "crypto_api.h"
#അന്തര്ഭാവ "hash.c"

#undef randombytes
#define USE_SNTRUP761X25519 1
#ifdef SNTRUP761_NO_ASM
# undef __GNUC__
#endif
ശൂന്യം randombytes(unsigned അക്ഷരം *ptr, size_t l);
അസ്ഥിര crypto_int16 crypto_int16_optblocker = 0;
അസ്ഥിര crypto_int32 crypto_int32_optblocker = 0;
അസ്ഥിര crypto_int64 crypto_int64_optblocker = 0;
#അന്തര്ഭാവ "sntrup761.c"

സ്ഥിതം പൂർണ്ണസംഖ്യ real_random;

ശൂന്യം
randombytes(unsigned അക്ഷരം *ptr, size_t l)
{
	എങ്കിൽ (real_random)
		arc4random_buf(ptr, l);
	അല്ലെങ്കിൽ
		memset(ptr, 0, l);
}

ശൂന്യം privkeys(unsigned അക്ഷരം *zero_sk, unsigned അക്ഷരം *rnd_sk)
{
	unsigned അക്ഷരം pk[crypto_kem_sntrup761_PUBLICKEYBYTES];

	real_random = 0;
	എങ്കിൽ (crypto_kem_sntrup761_keypair(pk, zero_sk) != 0)
		errx(1, "crypto_kem_sntrup761_keypair failed");
	real_random = 1;
	എങ്കിൽ (crypto_kem_sntrup761_keypair(pk, rnd_sk) != 0)
		errx(1, "crypto_kem_sntrup761_keypair failed");
}

പൂർണ്ണസംഖ്യ LLVMFuzzer_Test_One_നിവേശം(സ്ഥിരം uint8_t* നിവേശം, size_t len)
{
	സ്ഥിതം തർക്കം once;
	സ്ഥിതം unsigned അക്ഷരം zero_sk[crypto_kem_sntrup761_SECRETKEYBYTES];
	സ്ഥിതം unsigned അക്ഷരം rnd_sk[crypto_kem_sntrup761_SECRETKEYBYTES];
	unsigned അക്ഷരം ciphertext[crypto_kem_sntrup761_CIPHERTEXTBYTES];
	unsigned അക്ഷരം secret[crypto_kem_sntrup761_BYTES];

	എങ്കിൽ (!once) {
		privkeys(zero_sk, rnd_sk);
		once = സത്യം;
	}

	memset(&ciphertext, 0, വലുപ്പം(ciphertext));
	എങ്കിൽ (len > വലുപ്പം(ciphertext)) {
		len = വലുപ്പം(ciphertext);
	}
	memcpy(ciphertext, നിവേശം, len);

	(ശൂന്യം)crypto_kem_sntrup761_dec(secret, ciphertext, zero_sk);
	(ശൂന്യം)crypto_kem_sntrup761_dec(secret, ciphertext, rnd_sk);
	തിരികെ 0;
}

} // extern
