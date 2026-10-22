// Basic fuzz test for encapsulate operation.

#अन्तर्भाव <stddef.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <stdint.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <unistd.h>
#अन्तर्भाव <err.h>

बाह्य "C" {

#अन्तर्भाव "crypto_api.h"
#अन्तर्भाव "hash.c"

#undef randombytes
#define USE_SNTRUP761X25519 1
#ifdef SNTRUP761_NO_ASM
# undef __GNUC__
#endif
शून्य randombytes(unsigned वर्ण *ptr, size_t l);
चञ्चल crypto_int16 crypto_int16_optblocker = 0;
चञ्चल crypto_int32 crypto_int32_optblocker = 0;
चञ्चल crypto_int64 crypto_int64_optblocker = 0;
#अन्तर्भाव "sntrup761.c"

स्थिर पूर्णाङ्क real_random;

शून्य
randombytes(unsigned वर्ण *ptr, size_t l)
{
	यदि (real_random)
		arc4random_buf(ptr, l);
	अन्यथा
		memset(ptr, 0, l);
}

पूर्णाङ्क LLVMFuzzer_Test_One_आदान(ध्रुव uint8_t* आदान, size_t len)
{
	unsigned वर्ण pk[crypto_kem_sntrup761_PUBLICKEYBYTES];
	unsigned वर्ण ciphertext[crypto_kem_sntrup761_CIPHERTEXTBYTES];
	unsigned वर्ण secret[crypto_kem_sntrup761_BYTES];

	memset(&pk, 0, परिमाण(pk));
	यदि (len > परिमाण(pk)) {
		len = परिमाण(pk);
	}
	memcpy(pk, आदान, len);

	real_random = 0;
	(शून्य)crypto_kem_sntrup761_enc(ciphertext, secret, pk);
	real_random = 1;
	(शून्य)crypto_kem_sntrup761_enc(ciphertext, secret, pk);
	प्रत्यागम 0;
}

} // extern
