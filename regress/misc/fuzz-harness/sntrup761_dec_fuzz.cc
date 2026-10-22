// Basic fuzz test for depcapsulate operation,

#شامل <stddef.h>
#شامل <stdio.h>
#شامل <stdint.h>
#شامل <stdlib.h>
#شامل <string.h>
#شامل <unistd.h>
#شامل <err.h>

بیرونی "C" {

#شامل "crypto_api.h"
#شامل "hash.c"

#undef randombytes
#define USE_SNTRUP761X25519 1
#ifdef SNTRUP761_NO_ASM
# undef __GNUC__
#endif
تهی randombytes(unsigned نویسه *ptr, size_t l);
فرار crypto_int16 crypto_int16_optblocker = 0;
فرار crypto_int32 crypto_int32_optblocker = 0;
فرار crypto_int64 crypto_int64_optblocker = 0;
#شامل "sntrup761.c"

ایستا صحیح real_random;

تهی
randombytes(unsigned نویسه *ptr, size_t l)
{
	اگر (real_random)
		arc4random_buf(ptr, l);
	وگرنه
		memset(ptr, 0, l);
}

تهی privkeys(unsigned نویسه *zero_sk, unsigned نویسه *rnd_sk)
{
	unsigned نویسه pk[crypto_kem_sntrup761_PUBLICKEYBYTES];

	real_random = 0;
	اگر (crypto_kem_sntrup761_keypair(pk, zero_sk) != 0)
		errx(1, "crypto_kem_sntrup761_keypair failed");
	real_random = 1;
	اگر (crypto_kem_sntrup761_keypair(pk, rnd_sk) != 0)
		errx(1, "crypto_kem_sntrup761_keypair failed");
}

صحیح LLVMFuzzer_Test_One_درون_داد(ثابت uint8_t* درون_داد, size_t len)
{
	ایستا منطقی once;
	ایستا unsigned نویسه zero_sk[crypto_kem_sntrup761_SECRETKEYBYTES];
	ایستا unsigned نویسه rnd_sk[crypto_kem_sntrup761_SECRETKEYBYTES];
	unsigned نویسه ciphertext[crypto_kem_sntrup761_CIPHERTEXTBYTES];
	unsigned نویسه secret[crypto_kem_sntrup761_BYTES];

	اگر (!once) {
		privkeys(zero_sk, rnd_sk);
		once = درست;
	}

	memset(&ciphertext, 0, اندازه(ciphertext));
	اگر (len > اندازه(ciphertext)) {
		len = اندازه(ciphertext);
	}
	memcpy(ciphertext, درون_داد, len);

	(تهی)crypto_kem_sntrup761_dec(secret, ciphertext, zero_sk);
	(تهی)crypto_kem_sntrup761_dec(secret, ciphertext, rnd_sk);
	بازگشت 0;
}

} // extern
