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

#undef randombytes
#define USE_SNTRUP761X25519 1
ಶೂನ್ಯ randombytes(unsigned ವರ್ಣ *ptr, size_t l);
ಚಞ್ಚಲ crypto_int16 crypto_int16_optblocker = 0;
ಚಞ್ಚಲ crypto_int32 crypto_int32_optblocker = 0;
ಚಞ್ಚಲ crypto_int64 crypto_int64_optblocker = 0;
#ಅನ್ತರ್ಭಾವ "sntrup761.c"

#define NSEEDS 1000

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ real_random;

ಶೂನ್ಯ
randombytes(unsigned ವರ್ಣ *ptr, size_t l)
{
	ಯದಿ (real_random)
		arc4random_buf(ptr, l);
	ಅನ್ಯಥಾ
		memset(ptr, 0, l);
}

ಶೂನ್ಯ write_blob(ಧ್ರುವ ವರ್ಣ *path, ಪೂರ್ಣಾಙ್ಕ n, ಧ್ರುವ ವರ್ಣ *suffix,
    ಧ್ರುವ ಶೂನ್ಯ *ptr, size_t l)
{
	ವರ್ಣ name[256];
	FILE *f;

	snprintf(name, ಪರಿಮಾಣ(name), "%s/%06d.%s", path, n, suffix);
	ಯದಿ ((f = fopen(name, "wb+")) == ರಿಕ್ತ)
		err(1, "fopen %s", name);
	ಯದಿ (fwrite(ptr, l, 1, f) != 1)
		err(1, "write %s", name);
	fclose(f);
}

ಪೂರ್ಣಾಙ್ಕ main(ಶೂನ್ಯ)
{
	ಪೂರ್ಣಾಙ್ಕ i;
	unsigned ವರ್ಣ pk[crypto_kem_sntrup761_PUBLICKEYBYTES];
	unsigned ವರ್ಣ sk[crypto_kem_sntrup761_SECRETKEYBYTES];
	unsigned ವರ್ಣ ciphertext[crypto_kem_sntrup761_CIPHERTEXTBYTES];
	unsigned ವರ್ಣ secret[crypto_kem_sntrup761_BYTES];

	ಯದಿ (mkdir("sntrup761_pubkey_corpus", 0777) != 0 && errno != EEXIST)
		err(1, "mkdir sntrup761_pubkey_corpus");
	ಯದಿ (mkdir("sntrup761_ciphertext_corpus", 0777) != 0 && errno != EEXIST)
		err(1, "mkdir sntrup761_ciphertext_corpus");

	fprintf(stderr, "making: ");
	ಪ್ರತಿ (i = 0; i < NSEEDS; i++) {
		real_random = i != 0;
		ಯದಿ (crypto_kem_sntrup761_keypair(pk, sk) != 0)
			errx(1, "crypto_kem_sntrup761_keypair failed");
		write_blob("sntrup761_pubkey_corpus", i, "pk", pk, ಪರಿಮಾಣ(pk));
		ಯದಿ (crypto_kem_sntrup761_enc(ciphertext, secret, pk) != 0)
			errx(1, "crypto_kem_sntrup761_enc failed");
		write_blob("sntrup761_ciphertext_corpus", i, "ct",
		    ciphertext, ಪರಿಮಾಣ(ciphertext));
		ಯದಿ (i % 20 == 0)
			fprintf(stderr, ".");
	}
	fprintf(stderr, "\n");
	ಪ್ರತ್ಯಾಗಮ 0;
}
