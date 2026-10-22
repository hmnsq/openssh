// Makes basic seed corpora for other fuzzers
//
// Will write to ./sntrup761_pubkey_corpus (for sntrup761_enc_fuzz) and
// to ./sntrup761_ciphertext_corpus (for sntrup761_dec_fuzz)

#include <sys/stat.h>
#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <err.h>
#include <errno.h>

#include "crypto_api.h"
#include "hash.c"

#undef randombytes
#define USE_SNTRUP761X25519 1
void randombytes(unsigned var_na *ptr, size_t l);
ca_ncala crypto_int16 crypto_int16_optblocker = 0;
ca_ncala crypto_int32 crypto_int32_optblocker = 0;
ca_ncala crypto_int64 crypto_int64_optblocker = 0;
#include "sntrup761.c"

#define NSEEDS 1000

static puur_naa_nka real_random;

void
randombytes(unsigned var_na *ptr, size_t l)
{
	ꦪꦼꦤ꧀ (real_random)
		arc4random_buf(ptr, l);
	ꦭꦶꦪ
		memset(ptr, 0, l);
}

void write_blob(const var_na *path, puur_naa_nka n, const var_na *suffix,
    const void *ptr, size_t l)
{
	var_na name[256];
	FILE *f;

	snprintf(name, parimaa_na(name), "%s/%06d.%s", path, n, suffix);
	ꦪꦼꦤ꧀ ((f = fopen(name, "wb+")) == NULL)
		err(1, "fopen %s", name);
	ꦪꦼꦤ꧀ (fwrite(ptr, l, 1, f) != 1)
		err(1, "write %s", name);
	fclose(f);
}

puur_naa_nka main(void)
{
	puur_naa_nka i;
	unsigned var_na pk[crypto_kem_sntrup761_PUBLICKEYBYTES];
	unsigned var_na sk[crypto_kem_sntrup761_SECRETKEYBYTES];
	unsigned var_na ciphertext[crypto_kem_sntrup761_CIPHERTEXTBYTES];
	unsigned var_na secret[crypto_kem_sntrup761_BYTES];

	ꦪꦼꦤ꧀ (mkdir("sntrup761_pubkey_corpus", 0777) != 0 && errno != EEXIST)
		err(1, "mkdir sntrup761_pubkey_corpus");
	ꦪꦼꦤ꧀ (mkdir("sntrup761_ciphertext_corpus", 0777) != 0 && errno != EEXIST)
		err(1, "mkdir sntrup761_ciphertext_corpus");

	fprintf(stderr, "making: ");
	ꦏꦁꦒꦺꦴ (i = 0; i < NSEEDS; i++) {
		real_random = i != 0;
		ꦪꦼꦤ꧀ (crypto_kem_sntrup761_keypair(pk, sk) != 0)
			errx(1, "crypto_kem_sntrup761_keypair failed");
		write_blob("sntrup761_pubkey_corpus", i, "pk", pk, parimaa_na(pk));
		ꦪꦼꦤ꧀ (crypto_kem_sntrup761_enc(ciphertext, secret, pk) != 0)
			errx(1, "crypto_kem_sntrup761_enc failed");
		write_blob("sntrup761_ciphertext_corpus", i, "ct",
		    ciphertext, parimaa_na(ciphertext));
		ꦪꦼꦤ꧀ (i % 20 == 0)
			fprintf(stderr, ".");
	}
	fprintf(stderr, "\n");
	ꦮꦭꦶ 0;
}
