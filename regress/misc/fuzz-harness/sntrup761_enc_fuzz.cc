// Basic fuzz test for encapsulate operation.

#ਅਨ੍ਤਰ੍ਭਾਵ <stddef.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdint.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <err.h>

ਬਾਹਰੀ "C" {

#ਅਨ੍ਤਰ੍ਭਾਵ "crypto_api.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "hash.c"

#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ randombytes
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ USE_SNTRUP761X25519 1
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ SNTRUP761_NO_ASM
# undef __GNUC__
#ਜੇ_ਅੰਤ
ਖਾਲੀ randombytes(ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *ptr, ਮਾਪ_t l);
ਅਸਥਿਰ crypto_int16 crypto_int16_optblocker = 0;
ਅਸਥਿਰ crypto_int32 crypto_int32_optblocker = 0;
ਅਸਥਿਰ crypto_int64 crypto_int64_optblocker = 0;
#ਅਨ੍ਤਰ੍ਭਾਵ "sntrup761.c"

ਸਥਿਰ ਪੂਰਨ real_random;

ਖਾਲੀ
randombytes(ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *ptr, ਮਾਪ_t l)
{
	ਜੇ (real_random)
		arc4random_buf(ptr, l);
	ਨਹੀਂਤਾਂ
		memset(ptr, 0, l);
}

ਪੂਰਨ LLVMFuzzer_Test_One_ਨਿਵੇਸ਼(ਅਚਲ uint8_t* ਨਿਵੇਸ਼, ਮਾਪ_t len)
{
	ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ pk[crypto_kem_sntrup761_PUBLICKEYBYTES];
	ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ ciphertext[crypto_kem_sntrup761_CIPHERTEXTBYTES];
	ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ secret[crypto_kem_sntrup761_ਬਾਈਟਾਂ];

	memset(&pk, 0, ਆਕਾਰ(pk));
	ਜੇ (len > ਆਕਾਰ(pk)) {
		len = ਆਕਾਰ(pk);
	}
	ਸਮ੍ਰਿਤੀ_ਨਕਲ(pk, ਨਿਵੇਸ਼, len);

	real_random = 0;
	(ਖਾਲੀ)crypto_kem_sntrup761_enc(ciphertext, secret, pk);
	real_random = 1;
	(ਖਾਲੀ)crypto_kem_sntrup761_enc(ciphertext, secret, pk);
	ਵਾਪਸ 0;
}

} // extern
