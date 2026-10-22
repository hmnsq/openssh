// Basic fuzz test for depcapsulate operation,

#ಅನ್ತರ್ಭಾವ <stddef.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stdint.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>
#ಅನ್ತರ್ಭಾವ <err.h>

ಬಾಹ್ಯ "C" {

#ಅನ್ತರ್ಭಾವ "crypto_api.h"
#ಅನ್ತರ್ಭಾವ "hash.c"

#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು randombytes
#ವ್ಯಾಖ್ಯಾನಿಸು USE_SNTRUP761X25519 1
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ SNTRUP761_NO_ASM
# undef __GNUC__
#ಆದರೆ_ಅಂತ್ಯ
ಶೂನ್ಯ randombytes(ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *ptr, ಗಾತ್ರ_t l);
ಅಸ್ಥಿರ crypto_int16 crypto_int16_optblocker = 0;
ಅಸ್ಥಿರ crypto_int32 crypto_int32_optblocker = 0;
ಅಸ್ಥಿರ crypto_int64 crypto_int64_optblocker = 0;
#ಅನ್ತರ್ಭಾವ "sntrup761.c"

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ real_random;

ಶೂನ್ಯ
randombytes(ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *ptr, ಗಾತ್ರ_t l)
{
	ಆದರೆ (real_random)
		arc4random_buf(ptr, l);
	ಇಲ್ಲದಿದ್ದರೆ
		memset(ptr, 0, l);
}

ಶೂನ್ಯ privkeys(ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *zero_sk, ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *rnd_sk)
{
	ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ pk[crypto_kem_sntrup761_PUBLICKEYBYTES];

	real_random = 0;
	ಆದರೆ (crypto_kem_sntrup761_keypair(pk, zero_sk) != 0)
		errx(1, "crypto_kem_sntrup761_keypair failed");
	real_random = 1;
	ಆದರೆ (crypto_kem_sntrup761_keypair(pk, rnd_sk) != 0)
		errx(1, "crypto_kem_sntrup761_keypair failed");
}

ಪೂರ್ಣಾಂಕ LLVMFuzzer_Test_One_ಒಳಹರಿವು(ಸ್ಥಿರಾಂಕ uint8_t* ಒಳಹರಿವು, ಗಾತ್ರ_t len)
{
	ಸ್ಥಿರ ತಾರ್ಕಿಕ once;
	ಸ್ಥಿರ ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ zero_sk[crypto_kem_sntrup761_SECRETKEYBYTES];
	ಸ್ಥಿರ ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ rnd_sk[crypto_kem_sntrup761_SECRETKEYBYTES];
	ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ ciphertext[crypto_kem_sntrup761_CIPHERTEXTBYTES];
	ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ secret[crypto_kem_sntrup761_ಬೈಟುಗಳು];

	ಆದರೆ (!once) {
		privkeys(zero_sk, rnd_sk);
		once = ನಿಜ;
	}

	memset(&ciphertext, 0, ಗಾತ್ರ(ciphertext));
	ಆದರೆ (len > ಗಾತ್ರ(ciphertext)) {
		len = ಗಾತ್ರ(ciphertext);
	}
	ಸ್ಮರಣೆ_ನಕಲು(ciphertext, ಒಳಹರಿವು, len);

	(ಶೂನ್ಯ)crypto_kem_sntrup761_dec(secret, ciphertext, zero_sk);
	(ಶೂನ್ಯ)crypto_kem_sntrup761_dec(secret, ciphertext, rnd_sk);
	ಹಿಂತಿರುಗಿ 0;
}

} // extern
