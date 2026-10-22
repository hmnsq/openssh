// Basic fuzz test for depcapsulate operation,

#شامل <stddef.h>
#شامل <stdio.h>
#شامل <stdint.h>
#شامل <stdlib.h>
#شامل <string.h>
#شامل <unistd.h>
#شامل <err.h>

خارجی "C" {

#شامل "crypto_api.h"
#شامل "hash.c"

#تعریف_منسوخ randombytes
#تعریف_کرو USE_SNTRUP761X25519 1
#اگر_تعریف_شدہ SNTRUP761_NO_ASM
# undef __GNUC__
#اگر_ختم
خالی randombytes(غیرعلامتی حرف *ptr, سائز_t l);
متلون crypto_int16 crypto_int16_optblocker = 0;
متلون crypto_int32 crypto_int32_optblocker = 0;
متلون crypto_int64 crypto_int64_optblocker = 0;
#شامل "sntrup761.c"

ساکن صحیح real_random;

خالی
randombytes(غیرعلامتی حرف *ptr, سائز_t l)
{
	اگر (real_random)
		arc4random_buf(ptr, l);
	ورنہ
		memset(ptr, 0, l);
}

خالی privkeys(غیرعلامتی حرف *zero_sk, غیرعلامتی حرف *rnd_sk)
{
	غیرعلامتی حرف pk[crypto_kem_sntrup761_PUBLICKEYBYTES];

	real_random = 0;
	اگر (crypto_kem_sntrup761_keypair(pk, zero_sk) != 0)
		errx(1, "crypto_kem_sntrup761_keypair failed");
	real_random = 1;
	اگر (crypto_kem_sntrup761_keypair(pk, rnd_sk) != 0)
		errx(1, "crypto_kem_sntrup761_keypair failed");
}

صحیح LLVMFuzzer_Test_One_داخلہ(ثابت uint8_t* داخلہ, سائز_t len)
{
	ساکن منطقی once;
	ساکن غیرعلامتی حرف zero_sk[crypto_kem_sntrup761_SECRETKEYBYTES];
	ساکن غیرعلامتی حرف rnd_sk[crypto_kem_sntrup761_SECRETKEYBYTES];
	غیرعلامتی حرف ciphertext[crypto_kem_sntrup761_CIPHERTEXTBYTES];
	غیرعلامتی حرف secret[crypto_kem_sntrup761_بائٹیں];

	اگر (!once) {
		privkeys(zero_sk, rnd_sk);
		once = سچ;
	}

	memset(&ciphertext, 0, حجم(ciphertext));
	اگر (len > حجم(ciphertext)) {
		len = حجم(ciphertext);
	}
	حافظہ_نقل(ciphertext, داخلہ, len);

	(خالی)crypto_kem_sntrup761_dec(secret, ciphertext, zero_sk);
	(خالی)crypto_kem_sntrup761_dec(secret, ciphertext, rnd_sk);
	واپس 0;
}

} // extern
