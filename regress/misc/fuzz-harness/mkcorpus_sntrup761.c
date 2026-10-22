// Makes basic seed corpora for other fuzzers
//
// Will write to ./sntrup761_pubkey_corpus (for sntrup761_enc_fuzz) and
// to ./sntrup761_ciphertext_corpus (for sntrup761_dec_fuzz)

#شامل <sys/stat.h>
#شامل <stddef.h>
#شامل <stdio.h>
#شامل <stdint.h>
#شامل <stdlib.h>
#شامل <string.h>
#شامل <unistd.h>
#شامل <err.h>
#شامل <errno.h>

#شامل "crypto_api.h"
#شامل "hash.c"

#undef randombytes
#define USE_SNTRUP761X25519 1
تهی randombytes(unsigned نویسه *ptr, size_t l);
فرار crypto_int16 crypto_int16_optblocker = 0;
فرار crypto_int32 crypto_int32_optblocker = 0;
فرار crypto_int64 crypto_int64_optblocker = 0;
#شامل "sntrup761.c"

#define NSEEDS 1000

ایستا صحیح real_random;

تهی
randombytes(unsigned نویسه *ptr, size_t l)
{
	اگر (real_random)
		arc4random_buf(ptr, l);
	وگرنه
		memset(ptr, 0, l);
}

تهی write_blob(ثابت نویسه *path, صحیح n, ثابت نویسه *suffix,
    ثابت تهی *ptr, size_t l)
{
	نویسه name[256];
	FILE *f;

	snprintf(name, اندازه(name), "%s/%06d.%s", path, n, suffix);
	اگر ((f = fopen(name, "wb+")) == پوچ)
		err(1, "fopen %s", name);
	اگر (fwrite(ptr, l, 1, f) != 1)
		err(1, "write %s", name);
	fclose(f);
}

صحیح اصلی(تهی)
{
	صحیح i;
	unsigned نویسه pk[crypto_kem_sntrup761_PUBLICKEYBYTES];
	unsigned نویسه sk[crypto_kem_sntrup761_SECRETKEYBYTES];
	unsigned نویسه ciphertext[crypto_kem_sntrup761_CIPHERTEXTBYTES];
	unsigned نویسه secret[crypto_kem_sntrup761_BYTES];

	اگر (mkdir("sntrup761_pubkey_corpus", 0777) != 0 && errno != EEXIST)
		err(1, "mkdir sntrup761_pubkey_corpus");
	اگر (mkdir("sntrup761_ciphertext_corpus", 0777) != 0 && errno != EEXIST)
		err(1, "mkdir sntrup761_ciphertext_corpus");

	fprintf(stderr, "making: ");
	برای (i = 0; i < NSEEDS; i++) {
		real_random = i != 0;
		اگر (crypto_kem_sntrup761_keypair(pk, sk) != 0)
			errx(1, "crypto_kem_sntrup761_keypair failed");
		write_blob("sntrup761_pubkey_corpus", i, "pk", pk, اندازه(pk));
		اگر (crypto_kem_sntrup761_enc(ciphertext, secret, pk) != 0)
			errx(1, "crypto_kem_sntrup761_enc failed");
		write_blob("sntrup761_ciphertext_corpus", i, "ct",
		    ciphertext, اندازه(ciphertext));
		اگر (i % 20 == 0)
			fprintf(stderr, ".");
	}
	fprintf(stderr, "\n");
	بازگشت 0;
}
