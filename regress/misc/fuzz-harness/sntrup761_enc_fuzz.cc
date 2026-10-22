// Basic fuzz test for encapsulate operation.

#అన్తర్భావ <stddef.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <stdint.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <unistd.h>
#అన్తర్భావ <err.h>

బాహ్య "C" {

#అన్తర్భావ "crypto_api.h"
#అన్తర్భావ "hash.c"

#నిర్వచనం_రద్దు randombytes
#నిర్వచించు USE_SNTRUP761X25519 1
#నిర్వచితమైతే SNTRUP761_NO_ASM
# undef __GNUC__
#అయితే_ముగింపు
శూన్య randombytes(గుర్తులేని అక్షరం *ptr, కొలత_t l);
అస్థిర crypto_int16 crypto_int16_optblocker = 0;
అస్థిర crypto_int32 crypto_int32_optblocker = 0;
అస్థిర crypto_int64 crypto_int64_optblocker = 0;
#అన్తర్భావ "sntrup761.c"

స్థిర పూర్ణాంకం real_random;

శూన్య
randombytes(గుర్తులేని అక్షరం *ptr, కొలత_t l)
{
	ఒకవేళ (real_random)
		arc4random_buf(ptr, l);
	లేకపోతే
		memset(ptr, 0, l);
}

పూర్ణాంకం LLVMFuzzer_Test_One_ఆదానం(స్థిరరాశి uint8_t* ఆదానం, కొలత_t len)
{
	గుర్తులేని అక్షరం pk[crypto_kem_sntrup761_PUBLICKEYBYTES];
	గుర్తులేని అక్షరం ciphertext[crypto_kem_sntrup761_CIPHERTEXTBYTES];
	గుర్తులేని అక్షరం secret[crypto_kem_sntrup761_బైట్లు];

	memset(&pk, 0, పరిమాణం(pk));
	ఒకవేళ (len > పరిమాణం(pk)) {
		len = పరిమాణం(pk);
	}
	జ్ఞాపకం_నకలు(pk, ఆదానం, len);

	real_random = 0;
	(శూన్య)crypto_kem_sntrup761_enc(ciphertext, secret, pk);
	real_random = 1;
	(శూన్య)crypto_kem_sntrup761_enc(ciphertext, secret, pk);
	తిరిగి 0;
}

} // extern
