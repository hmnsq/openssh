// Basic fuzz test for encapsulate operation.

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

পূর্ণসংখ্যা LLVMFuzzer_Test_One_প্রবেশ(ধ্রুবক uint8_t* প্রবেশ, আকার_t len)
{
	unsigned অক্ষর pk[crypto_kem_sntrup761_PUBLICKEYBYTES];
	unsigned অক্ষর ciphertext[crypto_kem_sntrup761_CIPHERTEXTBYTES];
	unsigned অক্ষর secret[crypto_kem_sntrup761_BYTES];

	memset(&pk, 0, আকার(pk));
	যদি (len > আকার(pk)) {
		len = আকার(pk);
	}
	memcpy(pk, প্রবেশ, len);

	real_random = 0;
	(শূন্য)crypto_kem_sntrup761_enc(ciphertext, secret, pk);
	real_random = 1;
	(শূন্য)crypto_kem_sntrup761_enc(ciphertext, secret, pk);
	ফেরত 0;
}

} // extern
