// Makes basic seed corpora for other fuzzers
//
// Will write to ./sntrup761_pubkey_corpus (for sntrup761_enc_fuzz) and
// to ./sntrup761_ciphertext_corpus (for sntrup761_dec_fuzz)

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/stat.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stddef.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdint.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <err.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <errno.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "crypto_api.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "hash.c"

#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ randombytes
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ USE_SNTRUP761X25519 1
ਖਾਲੀ randombytes(ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *ptr, ਮਾਪ_t l);
ਅਸਥਿਰ crypto_int16 crypto_int16_optblocker = 0;
ਅਸਥਿਰ crypto_int32 crypto_int32_optblocker = 0;
ਅਸਥਿਰ crypto_int64 crypto_int64_optblocker = 0;
#ਅਨ੍ਤਰ੍ਭਾਵ "sntrup761.c"

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ NSEEDS 1000

ਸਥਿਰ ਪੂਰਨ real_random;

ਖਾਲੀ
randombytes(ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *ptr, ਮਾਪ_t l)
{
	ਜੇ (real_random)
		arc4random_buf(ptr, l);
	ਨਹੀਂਤਾਂ
		memset(ptr, 0, l);
}

ਖਾਲੀ write_blob(ਅਚਲ ਅੱਖਰ *ਰਸਤਾ, ਪੂਰਨ n, ਅਚਲ ਅੱਖਰ *suffix,
    ਅਚਲ ਖਾਲੀ *ptr, ਮਾਪ_t l)
{
	ਅੱਖਰ name[256];
	FILE *f;

	snprintf(name, ਆਕਾਰ(name), "%s/%06d.%s", ਰਸਤਾ, n, suffix);
	ਜੇ ((f = fopen(name, "wb+")) == ਨਿਰਾ)
		err(1, "fopen %s", name);
	ਜੇ (fwrite(ptr, l, 1, f) != 1)
		err(1, "write %s", name);
	fclose(f);
}

ਪੂਰਨ ਮੁੱਖ(ਖਾਲੀ)
{
	ਪੂਰਨ i;
	ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ pk[crypto_kem_sntrup761_PUBLICKEYBYTES];
	ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ sk[crypto_kem_sntrup761_SECRETKEYBYTES];
	ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ ciphertext[crypto_kem_sntrup761_CIPHERTEXTBYTES];
	ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ secret[crypto_kem_sntrup761_ਬਾਈਟਾਂ];

	ਜੇ (mkdir("sntrup761_pubkey_corpus", 0777) != 0 && errno != EEXIST)
		err(1, "mkdir sntrup761_pubkey_corpus");
	ਜੇ (mkdir("sntrup761_ciphertext_corpus", 0777) != 0 && errno != EEXIST)
		err(1, "mkdir sntrup761_ciphertext_corpus");

	fprintf(stderr, "making: ");
	ਲਈ (i = 0; i < NSEEDS; i++) {
		real_random = i != 0;
		ਜੇ (crypto_kem_sntrup761_keypair(pk, sk) != 0)
			errx(1, "crypto_kem_sntrup761_keypair failed");
		write_blob("sntrup761_pubkey_corpus", i, "pk", pk, ਆਕਾਰ(pk));
		ਜੇ (crypto_kem_sntrup761_enc(ciphertext, secret, pk) != 0)
			errx(1, "crypto_kem_sntrup761_enc failed");
		write_blob("sntrup761_ciphertext_corpus", i, "ct",
		    ciphertext, ਆਕਾਰ(ciphertext));
		ਜੇ (i % 20 == 0)
			fprintf(stderr, ".");
	}
	fprintf(stderr, "\n");
	ਵਾਪਸ 0;
}
