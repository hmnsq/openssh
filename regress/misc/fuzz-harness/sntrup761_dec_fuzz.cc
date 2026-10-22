// Basic fuzz test for depcapsulate operation,

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

வெறுமை privkeys(unsigned எழுத்து *zero_sk, unsigned எழுத்து *rnd_sk)
{
	unsigned எழுத்து pk[crypto_kem_sntrup761_PUBLICKEYBYTES];

	real_random = 0;
	எனில் (crypto_kem_sntrup761_keypair(pk, zero_sk) != 0)
		errx(1, "crypto_kem_sntrup761_keypair failed");
	real_random = 1;
	எனில் (crypto_kem_sntrup761_keypair(pk, rnd_sk) != 0)
		errx(1, "crypto_kem_sntrup761_keypair failed");
}

முழு LLVMFuzzer_Test_One_உள்ளீடு(மாறிலி uint8_t* உள்ளீடு, size_t len)
{
	நிலையான தருக்க once;
	நிலையான unsigned எழுத்து zero_sk[crypto_kem_sntrup761_SECRETKEYBYTES];
	நிலையான unsigned எழுத்து rnd_sk[crypto_kem_sntrup761_SECRETKEYBYTES];
	unsigned எழுத்து ciphertext[crypto_kem_sntrup761_CIPHERTEXTBYTES];
	unsigned எழுத்து secret[crypto_kem_sntrup761_BYTES];

	எனில் (!once) {
		privkeys(zero_sk, rnd_sk);
		once = உண்மை;
	}

	memset(&ciphertext, 0, அளவு(ciphertext));
	எனில் (len > அளவு(ciphertext)) {
		len = அளவு(ciphertext);
	}
	memcpy(ciphertext, உள்ளீடு, len);

	(வெறுமை)crypto_kem_sntrup761_dec(secret, ciphertext, zero_sk);
	(வெறுமை)crypto_kem_sntrup761_dec(secret, ciphertext, rnd_sk);
	திரும்பு 0;
}

} // extern
