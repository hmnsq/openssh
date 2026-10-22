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

#تعریف_منسوخ randombytes
#تعریف_کرو USE_SNTRUP761X25519 1
خالی randombytes(غیرعلامتی حرف *ptr, سائز_t l);
متلون crypto_int16 crypto_int16_optblocker = 0;
متلون crypto_int32 crypto_int32_optblocker = 0;
متلون crypto_int64 crypto_int64_optblocker = 0;
#شامل "sntrup761.c"

#تعریف_کرو NSEEDS 1000

ساکن صحیح real_random;

خالی
randombytes(غیرعلامتی حرف *ptr, سائز_t l)
{
	اگر (real_random)
		arc4random_buf(ptr, l);
	ورنہ
		memset(ptr, 0, l);
}

خالی write_blob(ثابت حرف *راستہ, صحیح n, ثابت حرف *suffix,
    ثابت خالی *ptr, سائز_t l)
{
	حرف name[256];
	FILE *f;

	snprintf(name, حجم(name), "%s/%06d.%s", راستہ, n, suffix);
	اگر ((f = fopen(name, "wb+")) == تہی)
		err(1, "fopen %s", name);
	اگر (fwrite(ptr, l, 1, f) != 1)
		err(1, "write %s", name);
	fclose(f);
}

صحیح مین(خالی)
{
	صحیح i;
	غیرعلامتی حرف pk[crypto_kem_sntrup761_PUBLICKEYBYTES];
	غیرعلامتی حرف sk[crypto_kem_sntrup761_SECRETKEYBYTES];
	غیرعلامتی حرف ciphertext[crypto_kem_sntrup761_CIPHERTEXTBYTES];
	غیرعلامتی حرف secret[crypto_kem_sntrup761_بائٹیں];

	اگر (mkdir("sntrup761_pubkey_corpus", 0777) != 0 && errno != EEXIST)
		err(1, "mkdir sntrup761_pubkey_corpus");
	اگر (mkdir("sntrup761_ciphertext_corpus", 0777) != 0 && errno != EEXIST)
		err(1, "mkdir sntrup761_ciphertext_corpus");

	fprintf(stderr, "making: ");
	برائے (i = 0; i < NSEEDS; i++) {
		real_random = i != 0;
		اگر (crypto_kem_sntrup761_keypair(pk, sk) != 0)
			errx(1, "crypto_kem_sntrup761_keypair failed");
		write_blob("sntrup761_pubkey_corpus", i, "pk", pk, حجم(pk));
		اگر (crypto_kem_sntrup761_enc(ciphertext, secret, pk) != 0)
			errx(1, "crypto_kem_sntrup761_enc failed");
		write_blob("sntrup761_ciphertext_corpus", i, "ct",
		    ciphertext, حجم(ciphertext));
		اگر (i % 20 == 0)
			fprintf(stderr, ".");
	}
	fprintf(stderr, "\n");
	واپس 0;
}
