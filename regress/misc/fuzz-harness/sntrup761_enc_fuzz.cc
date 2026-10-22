// Basic fuzz test for encapsulate operation.

#ଅନ୍ତର୍ଭାଵ <stddef.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <stdint.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <unistd.h>
#ଅନ୍ତର୍ଭାଵ <err.h>

ବାହ୍ୟ "C" {

#ଅନ୍ତର୍ଭାଵ "crypto_api.h"
#ଅନ୍ତର୍ଭାଵ "hash.c"

#undef randombytes
#define USE_SNTRUP761X25519 1
#ifdef SNTRUP761_NO_ASM
# undef __GNUC__
#endif
ଶୂନ୍ୟ randombytes(unsigned ଅକ୍ଷର *ptr, size_t l);
ଅସ୍ଥିର crypto_int16 crypto_int16_optblocker = 0;
ଅସ୍ଥିର crypto_int32 crypto_int32_optblocker = 0;
ଅସ୍ଥିର crypto_int64 crypto_int64_optblocker = 0;
#ଅନ୍ତର୍ଭାଵ "sntrup761.c"

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା real_random;

ଶୂନ୍ୟ
randombytes(unsigned ଅକ୍ଷର *ptr, size_t l)
{
	ଯଦି (real_random)
		arc4random_buf(ptr, l);
	ଅନ୍ୟଥା
		memset(ptr, 0, l);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା LLVMFuzzer_Test_One_ନିବେଶ(ଅଚଳ uint8_t* ନିବେଶ, size_t len)
{
	unsigned ଅକ୍ଷର pk[crypto_kem_sntrup761_PUBLICKEYBYTES];
	unsigned ଅକ୍ଷର ciphertext[crypto_kem_sntrup761_CIPHERTEXTBYTES];
	unsigned ଅକ୍ଷର secret[crypto_kem_sntrup761_BYTES];

	memset(&pk, 0, ଆକାର(pk));
	ଯଦି (len > ଆକାର(pk)) {
		len = ଆକାର(pk);
	}
	memcpy(pk, ନିବେଶ, len);

	real_random = 0;
	(ଶୂନ୍ୟ)crypto_kem_sntrup761_enc(ciphertext, secret, pk);
	real_random = 1;
	(ଶୂନ୍ୟ)crypto_kem_sntrup761_enc(ciphertext, secret, pk);
	ଫେରନ୍ତୁ 0;
}

} // extern
