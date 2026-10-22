// Basic fuzz test for encapsulate operation.

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

पूर्णांक LLVMFuzzer_Test_One_निवेश(स्थिर uint8_t* निवेश, माप_प्रकार len)
{
	अचिन्हित अक्षर pk[crypto_kem_sntrup761_PUBLICKEYBYTES];
	अचिन्हित अक्षर ciphertext[crypto_kem_sntrup761_CIPHERTEXTBYTES];
	अचिन्हित अक्षर secret[crypto_kem_sntrup761_BYTES];

	स_रखो(&pk, 0, माप(pk));
	अगर (len > माप(pk)) {
		len = माप(pk);
	}
	स_नकल(pk, निवेश, len);

	real_random = 0;
	(व्योम)crypto_kem_sntrup761_enc(ciphertext, secret, pk);
	real_random = 1;
	(व्योम)crypto_kem_sntrup761_enc(ciphertext, secret, pk);
	वापस 0;
}

} // extern
