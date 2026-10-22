// Basic fuzz test for depcapsulate operation,

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

शून्य privkeys(अचिन्हित अक्षर *zero_sk, अचिन्हित अक्षर *rnd_sk)
{
	अचिन्हित अक्षर pk[crypto_kem_sntrup761_PUBLICKEYBYTES];

	real_random = 0;
	जर (crypto_kem_sntrup761_keypair(pk, zero_sk) != 0)
		errx(1, "crypto_kem_sntrup761_keypair failed");
	real_random = 1;
	जर (crypto_kem_sntrup761_keypair(pk, rnd_sk) != 0)
		errx(1, "crypto_kem_sntrup761_keypair failed");
}

पूर्णांक LLVMFuzzer_Test_One_आदान(स्थिरांक uint8_t* आदान, माप_प्रकार len)
{
	स्थिर तार्किक once;
	स्थिर अचिन्हित अक्षर zero_sk[crypto_kem_sntrup761_SECRETKEYBYTES];
	स्थिर अचिन्हित अक्षर rnd_sk[crypto_kem_sntrup761_SECRETKEYBYTES];
	अचिन्हित अक्षर ciphertext[crypto_kem_sntrup761_CIPHERTEXTBYTES];
	अचिन्हित अक्षर secret[crypto_kem_sntrup761_BYTES];

	जर (!once) {
		privkeys(zero_sk, rnd_sk);
		once = सत्य;
	}

	स_रखो(&ciphertext, 0, आकार(ciphertext));
	जर (len > आकार(ciphertext)) {
		len = आकार(ciphertext);
	}
	स_नकल(ciphertext, आदान, len);

	(शून्य)crypto_kem_sntrup761_dec(secret, ciphertext, zero_sk);
	(शून्य)crypto_kem_sntrup761_dec(secret, ciphertext, rnd_sk);
	परत 0;
}

} // extern
