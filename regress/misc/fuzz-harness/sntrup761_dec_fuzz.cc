// Basic fuzz test for depcapsulate operation,

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

#تعریف_لغوه randombytes
#تعریف_کړه USE_SNTRUP761X25519 1
#که_تعریف_شوی SNTRUP761_NO_ASM
# undef __GNUC__
#د_که_پای
فراغ randombytes(بینښه حرف *ptr, اندازه_t l);
متطاير crypto_int16 crypto_int16_optblocker = 0;
متطاير crypto_int32 crypto_int32_optblocker = 0;
متطاير crypto_int64 crypto_int64_optblocker = 0;
#ضمن "sntrup761.c"

ساكن صحيح real_random;

فراغ
randombytes(بینښه حرف *ptr, اندازه_t l)
{
	إذا (real_random)
		arc4random_buf(ptr, l);
	وإلا
		memset(ptr, 0, l);
}

فراغ privkeys(بینښه حرف *zero_sk, بینښه حرف *rnd_sk)
{
	بینښه حرف pk[crypto_kem_sntrup761_PUBLICKEYBYTES];

	real_random = 0;
	إذا (crypto_kem_sntrup761_keypair(pk, zero_sk) != 0)
		errx(1, "crypto_kem_sntrup761_keypair failed");
	real_random = 1;
	إذا (crypto_kem_sntrup761_keypair(pk, rnd_sk) != 0)
		errx(1, "crypto_kem_sntrup761_keypair failed");
}

صحيح LLVMFuzzer_Test_One_ننوت(ثابت uint8_t* ننوت, اندازه_t len)
{
	ساكن منطقي once;
	ساكن بینښه حرف zero_sk[crypto_kem_sntrup761_SECRETKEYBYTES];
	ساكن بینښه حرف rnd_sk[crypto_kem_sntrup761_SECRETKEYBYTES];
	بینښه حرف ciphertext[crypto_kem_sntrup761_CIPHERTEXTBYTES];
	بینښه حرف secret[crypto_kem_sntrup761_بایټونه];

	إذا (!once) {
		privkeys(zero_sk, rnd_sk);
		once = ریښتیا;
	}

	memset(&ciphertext, 0, حجم(ciphertext));
	إذا (len > حجم(ciphertext)) {
		len = حجم(ciphertext);
	}
	حافظه_نقل(ciphertext, ننوت, len);

	(فراغ)crypto_kem_sntrup761_dec(secret, ciphertext, zero_sk);
	(فراغ)crypto_kem_sntrup761_dec(secret, ciphertext, rnd_sk);
	أرجع 0;
}

} // extern
