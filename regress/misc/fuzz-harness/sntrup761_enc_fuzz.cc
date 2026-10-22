// Basic fuzz test for encapsulate operation.

#ضمن <stddef.h>
#ضمن <stdio.h>
#ضمن <stdint.h>
#ضمن <stdlib.h>
#ضمن <string.h>
#ضمن <unistd.h>
#ضمن <err.h>

خارجي "C" {

#ضمن "crypto_api.h"
#ضمن "hash.c"

#تعریف_رد randombytes
#تعریف_کرو USE_SNTRUP761X25519 1
#جے_تعریف_شدہ SNTRUP761_NO_ASM
# undef __GNUC__
#جے_انت
فراغ randombytes(بنانشانی حرف *ptr, ناپ_t l);
متطاير crypto_int16 crypto_int16_optblocker = 0;
متطاير crypto_int32 crypto_int32_optblocker = 0;
متطاير crypto_int64 crypto_int64_optblocker = 0;
#ضمن "sntrup761.c"

ساكن صحيح real_random;

فراغ
randombytes(بنانشانی حرف *ptr, ناپ_t l)
{
	إذا (real_random)
		arc4random_buf(ptr, l);
	وإلا
		memset(ptr, 0, l);
}

صحيح LLVMFuzzer_Test_One_داخلہ(ثابت uint8_t* داخلہ, ناپ_t len)
{
	بنانشانی حرف pk[crypto_kem_sntrup761_PUBLICKEYBYTES];
	بنانشانی حرف ciphertext[crypto_kem_sntrup761_CIPHERTEXTBYTES];
	بنانشانی حرف secret[crypto_kem_sntrup761_بائٹاں];

	memset(&pk, 0, حجم(pk));
	إذا (len > حجم(pk)) {
		len = حجم(pk);
	}
	حافظہ_نقل(pk, داخلہ, len);

	real_random = 0;
	(فراغ)crypto_kem_sntrup761_enc(ciphertext, secret, pk);
	real_random = 1;
	(فراغ)crypto_kem_sntrup761_enc(ciphertext, secret, pk);
	أرجع 0;
}

} // extern
