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
शून्य randombytes(अचिन्हित वर्ण *ptr, माप_प्रकार l);
चञ्चल crypto_int16 crypto_int16_optblocker = 0;
चञ्चल crypto_int32 crypto_int32_optblocker = 0;
चञ्चल crypto_int64 crypto_int64_optblocker = 0;
#अन्तर्भाव "sntrup761.c"

स्थिर पूर्णाङ्क real_random;

शून्य
randombytes(अचिन्हित वर्ण *ptr, माप_प्रकार l)
{
	यदि (real_random)
		arc4random_buf(ptr, l);
	अन्यथा
		स_रखो(ptr, 0, l);
}

शून्य privkeys(अचिन्हित वर्ण *zero_sk, अचिन्हित वर्ण *rnd_sk)
{
	अचिन्हित वर्ण pk[crypto_kem_sntrup761_PUBLICKEYBYTES];

	real_random = 0;
	यदि (crypto_kem_sntrup761_keypair(pk, zero_sk) != 0)
		errx(1, "crypto_kem_sntrup761_keypair failed");
	real_random = 1;
	यदि (crypto_kem_sntrup761_keypair(pk, rnd_sk) != 0)
		errx(1, "crypto_kem_sntrup761_keypair failed");
}

पूर्णाङ्क LLVMFuzzer_Test_One_निवेश(ध्रुव uint8_t* निवेश, माप_प्रकार len)
{
	स्थिर तार्किक once;
	स्थिर अचिन्हित वर्ण zero_sk[crypto_kem_sntrup761_SECRETKEYBYTES];
	स्थिर अचिन्हित वर्ण rnd_sk[crypto_kem_sntrup761_SECRETKEYBYTES];
	अचिन्हित वर्ण ciphertext[crypto_kem_sntrup761_CIPHERTEXTBYTES];
	अचिन्हित वर्ण secret[crypto_kem_sntrup761_BYTES];

	यदि (!once) {
		privkeys(zero_sk, rnd_sk);
		once = सत्य;
	}

	स_रखो(&ciphertext, 0, परिमाण(ciphertext));
	यदि (len > परिमाण(ciphertext)) {
		len = परिमाण(ciphertext);
	}
	स_नकल(ciphertext, निवेश, len);

	(शून्य)crypto_kem_sntrup761_dec(secret, ciphertext, zero_sk);
	(शून्य)crypto_kem_sntrup761_dec(secret, ciphertext, rnd_sk);
	प्रत्यागम 0;
}

} // extern
