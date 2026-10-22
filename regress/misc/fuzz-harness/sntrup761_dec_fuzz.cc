// Basic fuzz test for depcapsulate operation,

#समावेश <stddef.h>
#समावेश <stdio.h>
#समावेश <stdint.h>
#समावेश <stdlib.h>
#समावेश <string.h>
#समावेश <unistd.h>
#समावेश <err.h>

बाह्य "C" {

#समावेश "crypto_api.h"
#समावेश "hash.c"

#अघोषित randombytes
#घोषणा USE_SNTRUP761X25519 1
#अगर_घोषित SNTRUP761_NO_ASM
# undef __GNUC__
#पूर्ण_अगर
व्योम randombytes(अचिन्हित अक्षर *ptr, माप_प्रकार l);
अस्थिर crypto_int16 crypto_int16_optblocker = 0;
अस्थिर crypto_int32 crypto_int32_optblocker = 0;
अस्थिर crypto_int64 crypto_int64_optblocker = 0;
#समावेश "sntrup761.c"

अटल पूर्णांक real_random;

व्योम
randombytes(अचिन्हित अक्षर *ptr, माप_प्रकार l)
{
	अगर (real_random)
		arc4random_buf(ptr, l);
	अन्यथा
		स_रखो(ptr, 0, l);
}

व्योम privkeys(अचिन्हित अक्षर *zero_sk, अचिन्हित अक्षर *rnd_sk)
{
	अचिन्हित अक्षर pk[crypto_kem_sntrup761_PUBLICKEYBYTES];

	real_random = 0;
	अगर (crypto_kem_sntrup761_keypair(pk, zero_sk) != 0)
		errx(1, "crypto_kem_sntrup761_keypair failed");
	real_random = 1;
	अगर (crypto_kem_sntrup761_keypair(pk, rnd_sk) != 0)
		errx(1, "crypto_kem_sntrup761_keypair failed");
}

पूर्णांक LLVMFuzzer_Test_One_निवेश(स्थिर uint8_t* निवेश, माप_प्रकार len)
{
	अटल bool once;
	अटल अचिन्हित अक्षर zero_sk[crypto_kem_sntrup761_SECRETKEYBYTES];
	अटल अचिन्हित अक्षर rnd_sk[crypto_kem_sntrup761_SECRETKEYBYTES];
	अचिन्हित अक्षर ciphertext[crypto_kem_sntrup761_CIPHERTEXTBYTES];
	अचिन्हित अक्षर secret[crypto_kem_sntrup761_BYTES];

	अगर (!once) {
		privkeys(zero_sk, rnd_sk);
		once = true;
	}

	स_रखो(&ciphertext, 0, माप(ciphertext));
	अगर (len > माप(ciphertext)) {
		len = माप(ciphertext);
	}
	स_नकल(ciphertext, निवेश, len);

	(व्योम)crypto_kem_sntrup761_dec(secret, ciphertext, zero_sk);
	(व्योम)crypto_kem_sntrup761_dec(secret, ciphertext, rnd_sk);
	वापस 0;
}

} // extern
