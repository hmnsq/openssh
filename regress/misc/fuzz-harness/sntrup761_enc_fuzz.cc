// Basic fuzz test for encapsulate operation.

#અન્તર્ભાવ <stddef.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <stdint.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <unistd.h>
#અન્તર્ભાવ <err.h>

બાહ્ય "C" {

#અન્તર્ભાવ "crypto_api.h"
#અન્તર્ભાવ "hash.c"

#undef randombytes
#define USE_SNTRUP761X25519 1
#ifdef SNTRUP761_NO_ASM
# undef __GNUC__
#endif
શૂન્ય randombytes(unsigned અક્ષર *ptr, size_t l);
અસ્થિર crypto_int16 crypto_int16_optblocker = 0;
અસ્થિર crypto_int32 crypto_int32_optblocker = 0;
અસ્થિર crypto_int64 crypto_int64_optblocker = 0;
#અન્તર્ભાવ "sntrup761.c"

સ્થિર પૂર્ણાંક real_random;

શૂન્ય
randombytes(unsigned અક્ષર *ptr, size_t l)
{
	જો (real_random)
		arc4random_buf(ptr, l);
	નહીંતર
		memset(ptr, 0, l);
}

પૂર્ણાંક LLVMFuzzer_Test_One_આગત(અચલ uint8_t* આગત, size_t len)
{
	unsigned અક્ષર pk[crypto_kem_sntrup761_PUBLICKEYBYTES];
	unsigned અક્ષર ciphertext[crypto_kem_sntrup761_CIPHERTEXTBYTES];
	unsigned અક્ષર secret[crypto_kem_sntrup761_BYTES];

	memset(&pk, 0, કદ(pk));
	જો (len > કદ(pk)) {
		len = કદ(pk);
	}
	memcpy(pk, આગત, len);

	real_random = 0;
	(શૂન્ય)crypto_kem_sntrup761_enc(ciphertext, secret, pk);
	real_random = 1;
	(શૂન્ય)crypto_kem_sntrup761_enc(ciphertext, secret, pk);
	પાછા 0;
}

} // extern
