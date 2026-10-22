// Makes basic seed corpora for other fuzzers
//
// Will write to ./sntrup761_pubkey_corpus (for sntrup761_enc_fuzz) and
// to ./sntrup761_ciphertext_corpus (for sntrup761_dec_fuzz)

#અન્તર્ભાવ <sys/stat.h>
#અન્તર્ભાવ <stddef.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <stdint.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <unistd.h>
#અન્તર્ભાવ <err.h>
#અન્તર્ભાવ <errno.h>

#અન્તર્ભાવ "crypto_api.h"
#અન્તર્ભાવ "hash.c"

#undef randombytes
#define USE_SNTRUP761X25519 1
શૂન્ય randombytes(unsigned અક્ષર *ptr, size_t l);
અસ્થિર crypto_int16 crypto_int16_optblocker = 0;
અસ્થિર crypto_int32 crypto_int32_optblocker = 0;
અસ્થિર crypto_int64 crypto_int64_optblocker = 0;
#અન્તર્ભાવ "sntrup761.c"

#define NSEEDS 1000

સ્થિર પૂર્ણાંક real_random;

શૂન્ય
randombytes(unsigned અક્ષર *ptr, size_t l)
{
	જો (real_random)
		arc4random_buf(ptr, l);
	નહીંતર
		memset(ptr, 0, l);
}

શૂન્ય write_blob(અચલ અક્ષર *path, પૂર્ણાંક n, અચલ અક્ષર *suffix,
    અચલ શૂન્ય *ptr, size_t l)
{
	અક્ષર name[256];
	FILE *f;

	snprintf(name, કદ(name), "%s/%06d.%s", path, n, suffix);
	જો ((f = fopen(name, "wb+")) == ખાલી)
		err(1, "fopen %s", name);
	જો (fwrite(ptr, l, 1, f) != 1)
		err(1, "write %s", name);
	fclose(f);
}

પૂર્ણાંક મુખ્ય(શૂન્ય)
{
	પૂર્ણાંક i;
	unsigned અક્ષર pk[crypto_kem_sntrup761_PUBLICKEYBYTES];
	unsigned અક્ષર sk[crypto_kem_sntrup761_SECRETKEYBYTES];
	unsigned અક્ષર ciphertext[crypto_kem_sntrup761_CIPHERTEXTBYTES];
	unsigned અક્ષર secret[crypto_kem_sntrup761_BYTES];

	જો (mkdir("sntrup761_pubkey_corpus", 0777) != 0 && errno != EEXIST)
		err(1, "mkdir sntrup761_pubkey_corpus");
	જો (mkdir("sntrup761_ciphertext_corpus", 0777) != 0 && errno != EEXIST)
		err(1, "mkdir sntrup761_ciphertext_corpus");

	fprintf(stderr, "making: ");
	માટે (i = 0; i < NSEEDS; i++) {
		real_random = i != 0;
		જો (crypto_kem_sntrup761_keypair(pk, sk) != 0)
			errx(1, "crypto_kem_sntrup761_keypair failed");
		write_blob("sntrup761_pubkey_corpus", i, "pk", pk, કદ(pk));
		જો (crypto_kem_sntrup761_enc(ciphertext, secret, pk) != 0)
			errx(1, "crypto_kem_sntrup761_enc failed");
		write_blob("sntrup761_ciphertext_corpus", i, "ct",
		    ciphertext, કદ(ciphertext));
		જો (i % 20 == 0)
			fprintf(stderr, ".");
	}
	fprintf(stderr, "\n");
	પાછા 0;
}
