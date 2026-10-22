// Basic fuzz test for encapsulate operation.

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

صحیح LLVMFuzzer_Test_One_داخلہ(ثابت uint8_t* داخلہ, سائز_t len)
{
	غیرعلامتی حرف pk[crypto_kem_sntrup761_PUBLICKEYBYTES];
	غیرعلامتی حرف ciphertext[crypto_kem_sntrup761_CIPHERTEXTBYTES];
	غیرعلامتی حرف secret[crypto_kem_sntrup761_بائٹیں];

	memset(&pk, 0, حجم(pk));
	اگر (len > حجم(pk)) {
		len = حجم(pk);
	}
	حافظہ_نقل(pk, داخلہ, len);

	real_random = 0;
	(خالی)crypto_kem_sntrup761_enc(ciphertext, secret, pk);
	real_random = 1;
	(خالی)crypto_kem_sntrup761_enc(ciphertext, secret, pk);
	واپس 0;
}

} // extern
