// Makes basic seed corpora for other fuzzers
//
// Will write to ./sntrup761_pubkey_corpus (for sntrup761_enc_fuzz) and
// to ./sntrup761_ciphertext_corpus (for sntrup761_dec_fuzz)

#অন্তর্ভাব <sys/stat.h>
#অন্তর্ভাব <stddef.h>
#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <stdint.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <unistd.h>
#অন্তর্ভাব <err.h>
#অন্তর্ভাব <errno.h>

#অন্তর্ভাব "crypto_api.h"
#অন্তর্ভাব "hash.c"

#undef randombytes
#define USE_SNTRUP761X25519 1
শূন্য randombytes(unsigned বর্ণ *ptr, size_t l);
চঞ্চল crypto_int16 crypto_int16_optblocker = 0;
চঞ্চল crypto_int32 crypto_int32_optblocker = 0;
চঞ্চল crypto_int64 crypto_int64_optblocker = 0;
#অন্তর্ভাব "sntrup761.c"

#define NSEEDS 1000

স্থির পূর্ণাঙ্ক real_random;

শূন্য
randombytes(unsigned বর্ণ *ptr, size_t l)
{
	যদি (real_random)
		arc4random_buf(ptr, l);
	অন্যথা
		memset(ptr, 0, l);
}

শূন্য write_blob(ধ্রুব বর্ণ *path, পূর্ণাঙ্ক n, ধ্রুব বর্ণ *suffix,
    ধ্রুব শূন্য *ptr, size_t l)
{
	বর্ণ name[256];
	FILE *f;

	snprintf(name, পরিমাণ(name), "%s/%06d.%s", path, n, suffix);
	যদি ((f = fopen(name, "wb+")) == রিক্ত)
		err(1, "fopen %s", name);
	যদি (fwrite(ptr, l, 1, f) != 1)
		err(1, "write %s", name);
	fclose(f);
}

পূর্ণাঙ্ক main(শূন্য)
{
	পূর্ণাঙ্ক i;
	unsigned বর্ণ pk[crypto_kem_sntrup761_PUBLICKEYBYTES];
	unsigned বর্ণ sk[crypto_kem_sntrup761_SECRETKEYBYTES];
	unsigned বর্ণ ciphertext[crypto_kem_sntrup761_CIPHERTEXTBYTES];
	unsigned বর্ণ secret[crypto_kem_sntrup761_BYTES];

	যদি (mkdir("sntrup761_pubkey_corpus", 0777) != 0 && errno != EEXIST)
		err(1, "mkdir sntrup761_pubkey_corpus");
	যদি (mkdir("sntrup761_ciphertext_corpus", 0777) != 0 && errno != EEXIST)
		err(1, "mkdir sntrup761_ciphertext_corpus");

	fprintf(stderr, "making: ");
	প্রতি (i = 0; i < NSEEDS; i++) {
		real_random = i != 0;
		যদি (crypto_kem_sntrup761_keypair(pk, sk) != 0)
			errx(1, "crypto_kem_sntrup761_keypair failed");
		write_blob("sntrup761_pubkey_corpus", i, "pk", pk, পরিমাণ(pk));
		যদি (crypto_kem_sntrup761_enc(ciphertext, secret, pk) != 0)
			errx(1, "crypto_kem_sntrup761_enc failed");
		write_blob("sntrup761_ciphertext_corpus", i, "ct",
		    ciphertext, পরিমাণ(ciphertext));
		যদি (i % 20 == 0)
			fprintf(stderr, ".");
	}
	fprintf(stderr, "\n");
	প্রত্যাগম 0;
}
