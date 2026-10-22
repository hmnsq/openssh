// Makes basic seed corpora for other fuzzers
//
// Will write to ./sntrup761_pubkey_corpus (for sntrup761_enc_fuzz) and
// to ./sntrup761_ciphertext_corpus (for sntrup761_dec_fuzz)

#ଅନ୍ତର୍ଭାଵ <sys/stat.h>
#ଅନ୍ତର୍ଭାଵ <stddef.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <stdint.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <unistd.h>
#ଅନ୍ତର୍ଭାଵ <err.h>
#ଅନ୍ତର୍ଭାଵ <errno.h>

#ଅନ୍ତର୍ଭାଵ "crypto_api.h"
#ଅନ୍ତର୍ଭାଵ "hash.c"

#undef randombytes
#define USE_SNTRUP761X25519 1
ଶୂନ୍ୟ randombytes(unsigned ଅକ୍ଷର *ptr, size_t l);
ଅସ୍ଥିର crypto_int16 crypto_int16_optblocker = 0;
ଅସ୍ଥିର crypto_int32 crypto_int32_optblocker = 0;
ଅସ୍ଥିର crypto_int64 crypto_int64_optblocker = 0;
#ଅନ୍ତର୍ଭାଵ "sntrup761.c"

#define NSEEDS 1000

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା real_random;

ଶୂନ୍ୟ
randombytes(unsigned ଅକ୍ଷର *ptr, size_t l)
{
	ଯଦି (real_random)
		arc4random_buf(ptr, l);
	ଅନ୍ୟଥା
		memset(ptr, 0, l);
}

ଶୂନ୍ୟ write_blob(ଅଚଳ ଅକ୍ଷର *path, ପୂର୍ଣ୍ଣସଂଖ୍ୟା n, ଅଚଳ ଅକ୍ଷର *suffix,
    ଅଚଳ ଶୂନ୍ୟ *ptr, size_t l)
{
	ଅକ୍ଷର name[256];
	FILE *f;

	snprintf(name, ଆକାର(name), "%s/%06d.%s", path, n, suffix);
	ଯଦି ((f = fopen(name, "wb+")) == ଖାଲି)
		err(1, "fopen %s", name);
	ଯଦି (fwrite(ptr, l, 1, f) != 1)
		err(1, "write %s", name);
	fclose(f);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା ମୁଖ୍ୟ(ଶୂନ୍ୟ)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i;
	unsigned ଅକ୍ଷର pk[crypto_kem_sntrup761_PUBLICKEYBYTES];
	unsigned ଅକ୍ଷର sk[crypto_kem_sntrup761_SECRETKEYBYTES];
	unsigned ଅକ୍ଷର ciphertext[crypto_kem_sntrup761_CIPHERTEXTBYTES];
	unsigned ଅକ୍ଷର secret[crypto_kem_sntrup761_BYTES];

	ଯଦି (mkdir("sntrup761_pubkey_corpus", 0777) != 0 && errno != EEXIST)
		err(1, "mkdir sntrup761_pubkey_corpus");
	ଯଦି (mkdir("sntrup761_ciphertext_corpus", 0777) != 0 && errno != EEXIST)
		err(1, "mkdir sntrup761_ciphertext_corpus");

	fprintf(stderr, "making: ");
	ପାଇଁ (i = 0; i < NSEEDS; i++) {
		real_random = i != 0;
		ଯଦି (crypto_kem_sntrup761_keypair(pk, sk) != 0)
			errx(1, "crypto_kem_sntrup761_keypair failed");
		write_blob("sntrup761_pubkey_corpus", i, "pk", pk, ଆକାର(pk));
		ଯଦି (crypto_kem_sntrup761_enc(ciphertext, secret, pk) != 0)
			errx(1, "crypto_kem_sntrup761_enc failed");
		write_blob("sntrup761_ciphertext_corpus", i, "ct",
		    ciphertext, ଆକାର(ciphertext));
		ଯଦି (i % 20 == 0)
			fprintf(stderr, ".");
	}
	fprintf(stderr, "\n");
	ଫେରନ୍ତୁ 0;
}
