// Basic fuzz test for encapsulate operation.

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

صحیح LLVMFuzzer_Test_One_درون_داد(ثابت uint8_t* درون_داد, size_t len)
{
	unsigned نویسه pk[crypto_kem_sntrup761_PUBLICKEYBYTES];
	unsigned نویسه ciphertext[crypto_kem_sntrup761_CIPHERTEXTBYTES];
	unsigned نویسه secret[crypto_kem_sntrup761_BYTES];

	memset(&pk, 0, اندازه(pk));
	اگر (len > اندازه(pk)) {
		len = اندازه(pk);
	}
	memcpy(pk, درون_داد, len);

	real_random = 0;
	(تهی)crypto_kem_sntrup761_enc(ciphertext, secret, pk);
	real_random = 1;
	(تهی)crypto_kem_sntrup761_enc(ciphertext, secret, pk);
	بازگشت 0;
}

} // extern
