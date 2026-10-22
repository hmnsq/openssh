// Makes basic seed corpora for other fuzzers
//
// Will write to ./sntrup761_pubkey_corpus (for sntrup761_enc_fuzz) and
// to ./sntrup761_ciphertext_corpus (for sntrup761_dec_fuzz)

#అన్తర్భావ <sys/stat.h>
#అన్తర్భావ <stddef.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <stdint.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <unistd.h>
#అన్తర్భావ <err.h>
#అన్తర్భావ <errno.h>

#అన్తర్భావ "crypto_api.h"
#అన్తర్భావ "hash.c"

#నిర్వచనం_రద్దు randombytes
#నిర్వచించు USE_SNTRUP761X25519 1
శూన్య randombytes(గుర్తులేని అక్షరం *ptr, కొలత_t l);
అస్థిర crypto_int16 crypto_int16_optblocker = 0;
అస్థిర crypto_int32 crypto_int32_optblocker = 0;
అస్థిర crypto_int64 crypto_int64_optblocker = 0;
#అన్తర్భావ "sntrup761.c"

#నిర్వచించు NSEEDS 1000

స్థిర పూర్ణాంకం real_random;

శూన్య
randombytes(గుర్తులేని అక్షరం *ptr, కొలత_t l)
{
	ఒకవేళ (real_random)
		arc4random_buf(ptr, l);
	లేకపోతే
		memset(ptr, 0, l);
}

శూన్య write_blob(స్థిరరాశి అక్షరం *మార్గం, పూర్ణాంకం n, స్థిరరాశి అక్షరం *suffix,
    స్థిరరాశి శూన్య *ptr, కొలత_t l)
{
	అక్షరం name[256];
	FILE *f;

	snprintf(name, పరిమాణం(name), "%s/%06d.%s", మార్గం, n, suffix);
	ఒకవేళ ((f = fopen(name, "wb+")) == ఖాళీ)
		err(1, "fopen %s", name);
	ఒకవేళ (fwrite(ptr, l, 1, f) != 1)
		err(1, "write %s", name);
	fclose(f);
}

పూర్ణాంకం ప్రధాన(శూన్య)
{
	పూర్ణాంకం i;
	గుర్తులేని అక్షరం pk[crypto_kem_sntrup761_PUBLICKEYBYTES];
	గుర్తులేని అక్షరం sk[crypto_kem_sntrup761_SECRETKEYBYTES];
	గుర్తులేని అక్షరం ciphertext[crypto_kem_sntrup761_CIPHERTEXTBYTES];
	గుర్తులేని అక్షరం secret[crypto_kem_sntrup761_బైట్లు];

	ఒకవేళ (mkdir("sntrup761_pubkey_corpus", 0777) != 0 && errno != EEXIST)
		err(1, "mkdir sntrup761_pubkey_corpus");
	ఒకవేళ (mkdir("sntrup761_ciphertext_corpus", 0777) != 0 && errno != EEXIST)
		err(1, "mkdir sntrup761_ciphertext_corpus");

	fprintf(stderr, "making: ");
	కొరకు (i = 0; i < NSEEDS; i++) {
		real_random = i != 0;
		ఒకవేళ (crypto_kem_sntrup761_keypair(pk, sk) != 0)
			errx(1, "crypto_kem_sntrup761_keypair failed");
		write_blob("sntrup761_pubkey_corpus", i, "pk", pk, పరిమాణం(pk));
		ఒకవేళ (crypto_kem_sntrup761_enc(ciphertext, secret, pk) != 0)
			errx(1, "crypto_kem_sntrup761_enc failed");
		write_blob("sntrup761_ciphertext_corpus", i, "ct",
		    ciphertext, పరిమాణం(ciphertext));
		ఒకవేళ (i % 20 == 0)
			fprintf(stderr, ".");
	}
	fprintf(stderr, "\n");
	తిరిగి 0;
}
