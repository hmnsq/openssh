// Basic fuzz test for depcapsulate operation,

#অন্তর্ভাৱ <stddef.h>
#অন্তর্ভাৱ <stdio.h>
#অন্তর্ভাৱ <stdint.h>
#অন্তর্ভাৱ <stdlib.h>
#অন্তর্ভাৱ <string.h>
#অন্তর্ভাৱ <unistd.h>
#অন্তর্ভাৱ <err.h>

বাহ্য "C" {

#অন্তর্ভাৱ "crypto_api.h"
#অন্তর্ভাৱ "hash.c"

#undef randombytes
#define USE_SNTRUP761X25519 1
#ifdef SNTRUP761_NO_ASM
# undef __GNUC__
#endif
শূন্য randombytes(unsigned ৱর্ণ *ptr, size_t l);
চঞ্চল crypto_int16 crypto_int16_optblocker = 0;
চঞ্চল crypto_int32 crypto_int32_optblocker = 0;
চঞ্চল crypto_int64 crypto_int64_optblocker = 0;
#অন্তর্ভাৱ "sntrup761.c"

স্থির পূর্ণাঙ্ক real_random;

শূন্য
randombytes(unsigned ৱর্ণ *ptr, size_t l)
{
	যদি (real_random)
		arc4random_buf(ptr, l);
	অন্যথা
		memset(ptr, 0, l);
}

শূন্য privkeys(unsigned ৱর্ণ *zero_sk, unsigned ৱর্ণ *rnd_sk)
{
	unsigned ৱর্ণ pk[crypto_kem_sntrup761_PUBLICKEYBYTES];

	real_random = 0;
	যদি (crypto_kem_sntrup761_keypair(pk, zero_sk) != 0)
		errx(1, "crypto_kem_sntrup761_keypair failed");
	real_random = 1;
	যদি (crypto_kem_sntrup761_keypair(pk, rnd_sk) != 0)
		errx(1, "crypto_kem_sntrup761_keypair failed");
}

পূর্ণাঙ্ক LLVMFuzzer_Test_One_প্ৰবেশ(ধ্রুৱ uint8_t* প্ৰবেশ, size_t len)
{
	স্থির তার্কিক once;
	স্থির unsigned ৱর্ণ zero_sk[crypto_kem_sntrup761_SECRETKEYBYTES];
	স্থির unsigned ৱর্ণ rnd_sk[crypto_kem_sntrup761_SECRETKEYBYTES];
	unsigned ৱর্ণ ciphertext[crypto_kem_sntrup761_CIPHERTEXTBYTES];
	unsigned ৱর্ণ secret[crypto_kem_sntrup761_BYTES];

	যদি (!once) {
		privkeys(zero_sk, rnd_sk);
		once = সঁচা;
	}

	memset(&ciphertext, 0, পরিমাণ(ciphertext));
	যদি (len > পরিমাণ(ciphertext)) {
		len = পরিমাণ(ciphertext);
	}
	memcpy(ciphertext, প্ৰবেশ, len);

	(শূন্য)crypto_kem_sntrup761_dec(secret, ciphertext, zero_sk);
	(শূন্য)crypto_kem_sntrup761_dec(secret, ciphertext, rnd_sk);
	ঘূৰাই 0;
}

} // extern
