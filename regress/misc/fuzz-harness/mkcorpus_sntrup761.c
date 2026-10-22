// Makes basic seed corpora for other fuzzers
//
// Will write to ./sntrup761_pubkey_corpus (for sntrup761_enc_fuzz) and
// to ./sntrup761_ciphertext_corpus (for sntrup761_dec_fuzz)

#அந்தர்பாவ <sys/stat.h>
#அந்தர்பாவ <stddef.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <stdint.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <unistd.h>
#அந்தர்பாவ <err.h>
#அந்தர்பாவ <errno.h>

#அந்தர்பாவ "crypto_api.h"
#அந்தர்பாவ "hash.c"

#undef randombytes
#define USE_SNTRUP761X25519 1
வெறுமை randombytes(unsigned எழுத்து *ptr, size_t l);
நிலையற்ற crypto_int16 crypto_int16_optblocker = 0;
நிலையற்ற crypto_int32 crypto_int32_optblocker = 0;
நிலையற்ற crypto_int64 crypto_int64_optblocker = 0;
#அந்தர்பாவ "sntrup761.c"

#define NSEEDS 1000

நிலையான முழு real_random;

வெறுமை
randombytes(unsigned எழுத்து *ptr, size_t l)
{
	எனில் (real_random)
		arc4random_buf(ptr, l);
	இல்லையெனில்
		memset(ptr, 0, l);
}

வெறுமை write_blob(மாறிலி எழுத்து *path, முழு n, மாறிலி எழுத்து *suffix,
    மாறிலி வெறுமை *ptr, size_t l)
{
	எழுத்து name[256];
	FILE *f;

	snprintf(name, அளவு(name), "%s/%06d.%s", path, n, suffix);
	எனில் ((f = fopen(name, "wb+")) == வெற்று)
		err(1, "fopen %s", name);
	எனில் (fwrite(ptr, l, 1, f) != 1)
		err(1, "write %s", name);
	fclose(f);
}

முழு முதன்மை(வெறுமை)
{
	முழு i;
	unsigned எழுத்து pk[crypto_kem_sntrup761_PUBLICKEYBYTES];
	unsigned எழுத்து sk[crypto_kem_sntrup761_SECRETKEYBYTES];
	unsigned எழுத்து ciphertext[crypto_kem_sntrup761_CIPHERTEXTBYTES];
	unsigned எழுத்து secret[crypto_kem_sntrup761_BYTES];

	எனில் (mkdir("sntrup761_pubkey_corpus", 0777) != 0 && errno != EEXIST)
		err(1, "mkdir sntrup761_pubkey_corpus");
	எனில் (mkdir("sntrup761_ciphertext_corpus", 0777) != 0 && errno != EEXIST)
		err(1, "mkdir sntrup761_ciphertext_corpus");

	fprintf(stderr, "making: ");
	க்கு (i = 0; i < NSEEDS; i++) {
		real_random = i != 0;
		எனில் (crypto_kem_sntrup761_keypair(pk, sk) != 0)
			errx(1, "crypto_kem_sntrup761_keypair failed");
		write_blob("sntrup761_pubkey_corpus", i, "pk", pk, அளவு(pk));
		எனில் (crypto_kem_sntrup761_enc(ciphertext, secret, pk) != 0)
			errx(1, "crypto_kem_sntrup761_enc failed");
		write_blob("sntrup761_ciphertext_corpus", i, "ct",
		    ciphertext, அளவு(ciphertext));
		எனில் (i % 20 == 0)
			fprintf(stderr, ".");
	}
	fprintf(stderr, "\n");
	திரும்பு 0;
}
