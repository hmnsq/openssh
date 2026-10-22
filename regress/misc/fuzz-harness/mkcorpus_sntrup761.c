// Makes basic seed corpora for other fuzzers
//
// Will write to ./sntrup761_pubkey_corpus (for sntrup761_enc_fuzz) and
// to ./sntrup761_ciphertext_corpus (for sntrup761_dec_fuzz)

#ಅನ್ತರ್ಭಾವ <sys/stat.h>
#ಅನ್ತರ್ಭಾವ <stddef.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stdint.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>
#ಅನ್ತರ್ಭಾವ <err.h>
#ಅನ್ತರ್ಭಾವ <errno.h>

#ಅನ್ತರ್ಭಾವ "crypto_api.h"
#ಅನ್ತರ್ಭಾವ "hash.c"

#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು randombytes
#ವ್ಯಾಖ್ಯಾನಿಸು USE_SNTRUP761X25519 1
ಶೂನ್ಯ randombytes(ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *ptr, ಗಾತ್ರ_t l);
ಅಸ್ಥಿರ crypto_int16 crypto_int16_optblocker = 0;
ಅಸ್ಥಿರ crypto_int32 crypto_int32_optblocker = 0;
ಅಸ್ಥಿರ crypto_int64 crypto_int64_optblocker = 0;
#ಅನ್ತರ್ಭಾವ "sntrup761.c"

#ವ್ಯಾಖ್ಯಾನಿಸು NSEEDS 1000

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ real_random;

ಶೂನ್ಯ
randombytes(ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *ptr, ಗಾತ್ರ_t l)
{
	ಆದರೆ (real_random)
		arc4random_buf(ptr, l);
	ಇಲ್ಲದಿದ್ದರೆ
		memset(ptr, 0, l);
}

ಶೂನ್ಯ write_blob(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮಾರ್ಗ, ಪೂರ್ಣಾಂಕ n, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *suffix,
    ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *ptr, ಗಾತ್ರ_t l)
{
	ಅಕ್ಷರ name[256];
	FILE *f;

	snprintf(name, ಗಾತ್ರ(name), "%s/%06d.%s", ಮಾರ್ಗ, n, suffix);
	ಆದರೆ ((f = fopen(name, "wb+")) == ಖಾಲಿ)
		err(1, "fopen %s", name);
	ಆದರೆ (fwrite(ptr, l, 1, f) != 1)
		err(1, "write %s", name);
	fclose(f);
}

ಪೂರ್ಣಾಂಕ ಮುಖ್ಯ(ಶೂನ್ಯ)
{
	ಪೂರ್ಣಾಂಕ i;
	ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ pk[crypto_kem_sntrup761_PUBLICKEYBYTES];
	ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ sk[crypto_kem_sntrup761_SECRETKEYBYTES];
	ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ ciphertext[crypto_kem_sntrup761_CIPHERTEXTBYTES];
	ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ secret[crypto_kem_sntrup761_ಬೈಟುಗಳು];

	ಆದರೆ (mkdir("sntrup761_pubkey_corpus", 0777) != 0 && errno != EEXIST)
		err(1, "mkdir sntrup761_pubkey_corpus");
	ಆದರೆ (mkdir("sntrup761_ciphertext_corpus", 0777) != 0 && errno != EEXIST)
		err(1, "mkdir sntrup761_ciphertext_corpus");

	fprintf(stderr, "making: ");
	ಗಾಗಿ (i = 0; i < NSEEDS; i++) {
		real_random = i != 0;
		ಆದರೆ (crypto_kem_sntrup761_keypair(pk, sk) != 0)
			errx(1, "crypto_kem_sntrup761_keypair failed");
		write_blob("sntrup761_pubkey_corpus", i, "pk", pk, ಗಾತ್ರ(pk));
		ಆದರೆ (crypto_kem_sntrup761_enc(ciphertext, secret, pk) != 0)
			errx(1, "crypto_kem_sntrup761_enc failed");
		write_blob("sntrup761_ciphertext_corpus", i, "ct",
		    ciphertext, ಗಾತ್ರ(ciphertext));
		ಆದರೆ (i % 20 == 0)
			fprintf(stderr, ".");
	}
	fprintf(stderr, "\n");
	ಹಿಂತಿರುಗಿ 0;
}
