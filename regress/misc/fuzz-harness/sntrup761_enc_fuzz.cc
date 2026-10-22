// Basic fuzz test for encapsulate operation.

#அந்தர்பாவ <stddef.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <stdint.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <unistd.h>
#அந்தர்பாவ <err.h>

வெளி "C" {

#அந்தர்பாவ "crypto_api.h"
#அந்தர்பாவ "hash.c"

#undef randombytes
#define USE_SNTRUP761X25519 1
#ifdef SNTRUP761_NO_ASM
# undef __GNUC__
#endif
வெறுமை randombytes(unsigned எழுத்து *ptr, size_t l);
நிலையற்ற crypto_int16 crypto_int16_optblocker = 0;
நிலையற்ற crypto_int32 crypto_int32_optblocker = 0;
நிலையற்ற crypto_int64 crypto_int64_optblocker = 0;
#அந்தர்பாவ "sntrup761.c"

நிலையான முழு real_random;

வெறுமை
randombytes(unsigned எழுத்து *ptr, size_t l)
{
	எனில் (real_random)
		arc4random_buf(ptr, l);
	இல்லையெனில்
		memset(ptr, 0, l);
}

முழு LLVMFuzzer_Test_One_உள்ளீடு(மாறிலி uint8_t* உள்ளீடு, size_t len)
{
	unsigned எழுத்து pk[crypto_kem_sntrup761_PUBLICKEYBYTES];
	unsigned எழுத்து ciphertext[crypto_kem_sntrup761_CIPHERTEXTBYTES];
	unsigned எழுத்து secret[crypto_kem_sntrup761_BYTES];

	memset(&pk, 0, அளவு(pk));
	எனில் (len > அளவு(pk)) {
		len = அளவு(pk);
	}
	memcpy(pk, உள்ளீடு, len);

	real_random = 0;
	(வெறுமை)crypto_kem_sntrup761_enc(ciphertext, secret, pk);
	real_random = 1;
	(வெறுமை)crypto_kem_sntrup761_enc(ciphertext, secret, pk);
	திரும்பு 0;
}

} // extern
