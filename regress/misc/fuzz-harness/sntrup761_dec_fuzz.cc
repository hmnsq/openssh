// Basic fuzz test for depcapsulate operation,

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

ਖਾਲੀ privkeys(ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *zero_sk, ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *rnd_sk)
{
	ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ pk[crypto_kem_sntrup761_PUBLICKEYBYTES];

	real_random = 0;
	ਜੇ (crypto_kem_sntrup761_keypair(pk, zero_sk) != 0)
		errx(1, "crypto_kem_sntrup761_keypair failed");
	real_random = 1;
	ਜੇ (crypto_kem_sntrup761_keypair(pk, rnd_sk) != 0)
		errx(1, "crypto_kem_sntrup761_keypair failed");
}

ਪੂਰਨ LLVMFuzzer_Test_One_ਨਿਵੇਸ਼(ਅਚਲ uint8_t* ਨਿਵੇਸ਼, ਮਾਪ_t len)
{
	ਸਥਿਰ ਤਾਰਕਿਕ once;
	ਸਥਿਰ ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ zero_sk[crypto_kem_sntrup761_SECRETKEYBYTES];
	ਸਥਿਰ ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ rnd_sk[crypto_kem_sntrup761_SECRETKEYBYTES];
	ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ ciphertext[crypto_kem_sntrup761_CIPHERTEXTBYTES];
	ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ secret[crypto_kem_sntrup761_ਬਾਈਟਾਂ];

	ਜੇ (!once) {
		privkeys(zero_sk, rnd_sk);
		once = ਸੱਚ;
	}

	memset(&ciphertext, 0, ਆਕਾਰ(ciphertext));
	ਜੇ (len > ਆਕਾਰ(ciphertext)) {
		len = ਆਕਾਰ(ciphertext);
	}
	ਸਮ੍ਰਿਤੀ_ਨਕਲ(ciphertext, ਨਿਵੇਸ਼, len);

	(ਖਾਲੀ)crypto_kem_sntrup761_dec(secret, ciphertext, zero_sk);
	(ਖਾਲੀ)crypto_kem_sntrup761_dec(secret, ciphertext, rnd_sk);
	ਵਾਪਸ 0;
}

} // extern
