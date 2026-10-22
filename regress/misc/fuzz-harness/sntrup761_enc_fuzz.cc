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
शून्य randombytes(अचिन्हित अक्षर *ptr, माप_प्रकार l);
अस्थिर crypto_int16 crypto_int16_optblocker = 0;
अस्थिर crypto_int32 crypto_int32_optblocker = 0;
अस्थिर crypto_int64 crypto_int64_optblocker = 0;
#अन्तर्भाव "sntrup761.c"

स्थिर पूर्णांक real_random;

शून्य
randombytes(अचिन्हित अक्षर *ptr, माप_प्रकार l)
{
	जर (real_random)
		arc4random_buf(ptr, l);
	अन्यथा
		स_रखो(ptr, 0, l);
}

पूर्णांक LLVMFuzzer_Test_One_आदान(स्थिरांक uint8_t* आदान, माप_प्रकार len)
{
	अचिन्हित अक्षर pk[crypto_kem_sntrup761_PUBLICKEYBYTES];
	अचिन्हित अक्षर ciphertext[crypto_kem_sntrup761_CIPHERTEXTBYTES];
	अचिन्हित अक्षर secret[crypto_kem_sntrup761_BYTES];

	स_रखो(&pk, 0, आकार(pk));
	जर (len > आकार(pk)) {
		len = आकार(pk);
	}
	स_नकल(pk, आदान, len);

	real_random = 0;
	(शून्य)crypto_kem_sntrup761_enc(ciphertext, secret, pk);
	real_random = 1;
	(शून्य)crypto_kem_sntrup761_enc(ciphertext, secret, pk);
	परत 0;
}

} // extern
