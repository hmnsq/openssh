// Basic fuzz test for depcapsulate operation,

#অন্তর্ভাব <stddef.h>
#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <stdint.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <unistd.h>
#অন্তর্ভাব <err.h>

বাহ্যিক "C" {

#অন্তর্ভাব "crypto_api.h"
#অন্তর্ভাব "hash.c"

#undef randombytes
#define USE_SNTRUP761X25519 1
#ifdef SNTRUP761_NO_ASM
# undef __GNUC__
#endif
শূন্য randombytes(unsigned অক্ষর *ptr, আকার_t l);
অস্থির crypto_int16 crypto_int16_optblocker = 0;
অস্থির crypto_int32 crypto_int32_optblocker = 0;
অস্থির crypto_int64 crypto_int64_optblocker = 0;
#অন্তর্ভাব "sntrup761.c"

স্থির পূর্ণসংখ্যা real_random;

শূন্য
randombytes(unsigned অক্ষর *ptr, আকার_t l)
{
	যদি (real_random)
		arc4random_buf(ptr, l);
	অন্যথা
		memset(ptr, 0, l);
}

শূন্য privkeys(unsigned অক্ষর *zero_sk, unsigned অক্ষর *rnd_sk)
{
	unsigned অক্ষর pk[crypto_kem_sntrup761_PUBLICKEYBYTES];

	real_random = 0;
	যদি (crypto_kem_sntrup761_keypair(pk, zero_sk) != 0)
		errx(1, "crypto_kem_sntrup761_keypair failed");
	real_random = 1;
	যদি (crypto_kem_sntrup761_keypair(pk, rnd_sk) != 0)
		errx(1, "crypto_kem_sntrup761_keypair failed");
}

পূর্ণসংখ্যা LLVMFuzzer_Test_One_প্রবেশ(ধ্রুবক uint8_t* প্রবেশ, আকার_t len)
{
	স্থির যৌক্তিক once;
	স্থির unsigned অক্ষর zero_sk[crypto_kem_sntrup761_SECRETKEYBYTES];
	স্থির unsigned অক্ষর rnd_sk[crypto_kem_sntrup761_SECRETKEYBYTES];
	unsigned অক্ষর ciphertext[crypto_kem_sntrup761_CIPHERTEXTBYTES];
	unsigned অক্ষর secret[crypto_kem_sntrup761_BYTES];

	যদি (!once) {
		privkeys(zero_sk, rnd_sk);
		once = সত্য;
	}

	memset(&ciphertext, 0, আকার(ciphertext));
	যদি (len > আকার(ciphertext)) {
		len = আকার(ciphertext);
	}
	memcpy(ciphertext, প্রবেশ, len);

	(শূন্য)crypto_kem_sntrup761_dec(secret, ciphertext, zero_sk);
	(শূন্য)crypto_kem_sntrup761_dec(secret, ciphertext, rnd_sk);
	ফেরত 0;
}

} // extern
