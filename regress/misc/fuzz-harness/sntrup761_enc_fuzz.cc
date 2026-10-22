// Basic fuzz test for encapsulate operation.

#ಅನ್ತರ್ಭಾವ <stddef.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stdint.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>
#ಅನ್ತರ್ಭಾವ <err.h>

ಬಾಹ್ಯ "C" {

#ಅನ್ತರ್ಭಾವ "crypto_api.h"
#ಅನ್ತರ್ಭಾವ "hash.c"

#undef randombytes
#define USE_SNTRUP761X25519 1
#ifdef SNTRUP761_NO_ASM
# undef __GNUC__
#endif
ಶೂನ್ಯ randombytes(unsigned ವರ್ಣ *ptr, size_t l);
ಚಞ್ಚಲ crypto_int16 crypto_int16_optblocker = 0;
ಚಞ್ಚಲ crypto_int32 crypto_int32_optblocker = 0;
ಚಞ್ಚಲ crypto_int64 crypto_int64_optblocker = 0;
#ಅನ್ತರ್ಭಾವ "sntrup761.c"

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ real_random;

ಶೂನ್ಯ
randombytes(unsigned ವರ್ಣ *ptr, size_t l)
{
	ಯದಿ (real_random)
		arc4random_buf(ptr, l);
	ಅನ್ಯಥಾ
		memset(ptr, 0, l);
}

ಪೂರ್ಣಾಙ್ಕ LLVMFuzzer_Test_One_ಒಳಹರಿವು(ಧ್ರುವ uint8_t* ಒಳಹರಿವು, size_t len)
{
	unsigned ವರ್ಣ pk[crypto_kem_sntrup761_PUBLICKEYBYTES];
	unsigned ವರ್ಣ ciphertext[crypto_kem_sntrup761_CIPHERTEXTBYTES];
	unsigned ವರ್ಣ secret[crypto_kem_sntrup761_BYTES];

	memset(&pk, 0, ಪರಿಮಾಣ(pk));
	ಯದಿ (len > ಪರಿಮಾಣ(pk)) {
		len = ಪರಿಮಾಣ(pk);
	}
	memcpy(pk, ಒಳಹರಿವು, len);

	real_random = 0;
	(ಶೂನ್ಯ)crypto_kem_sntrup761_enc(ciphertext, secret, pk);
	real_random = 1;
	(ಶೂನ್ಯ)crypto_kem_sntrup761_enc(ciphertext, secret, pk);
	ಪ್ರತ್ಯಾಗಮ 0;
}

} // extern
