// Basic fuzz test for depcapsulate operation,

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

શૂન્ય privkeys(unsigned અક્ષર *zero_sk, unsigned અક્ષર *rnd_sk)
{
	unsigned અક્ષર pk[crypto_kem_sntrup761_PUBLICKEYBYTES];

	real_random = 0;
	જો (crypto_kem_sntrup761_keypair(pk, zero_sk) != 0)
		errx(1, "crypto_kem_sntrup761_keypair failed");
	real_random = 1;
	જો (crypto_kem_sntrup761_keypair(pk, rnd_sk) != 0)
		errx(1, "crypto_kem_sntrup761_keypair failed");
}

પૂર્ણાંક LLVMFuzzer_Test_One_આગત(અચલ uint8_t* આગત, size_t len)
{
	સ્થિર તાર્કિક once;
	સ્થિર unsigned અક્ષર zero_sk[crypto_kem_sntrup761_SECRETKEYBYTES];
	સ્થિર unsigned અક્ષર rnd_sk[crypto_kem_sntrup761_SECRETKEYBYTES];
	unsigned અક્ષર ciphertext[crypto_kem_sntrup761_CIPHERTEXTBYTES];
	unsigned અક્ષર secret[crypto_kem_sntrup761_BYTES];

	જો (!once) {
		privkeys(zero_sk, rnd_sk);
		once = સાચું;
	}

	memset(&ciphertext, 0, કદ(ciphertext));
	જો (len > કદ(ciphertext)) {
		len = કદ(ciphertext);
	}
	memcpy(ciphertext, આગત, len);

	(શૂન્ય)crypto_kem_sntrup761_dec(secret, ciphertext, zero_sk);
	(શૂન્ય)crypto_kem_sntrup761_dec(secret, ciphertext, rnd_sk);
	પાછા 0;
}

} // extern
