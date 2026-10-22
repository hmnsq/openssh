// Makes basic seed corpora for other fuzzers
//
// Will write to ./sntrup761_pubkey_corpus (for sntrup761_enc_fuzz) and
// to ./sntrup761_ciphertext_corpus (for sntrup761_dec_fuzz)

#അന്തര്ഭാവ <sys/stat.h>
#അന്തര്ഭാവ <stddef.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <stdint.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <unistd.h>
#അന്തര്ഭാവ <err.h>
#അന്തര്ഭാവ <errno.h>

#അന്തര്ഭാവ "crypto_api.h"
#അന്തര്ഭാവ "hash.c"

#undef randombytes
#define USE_SNTRUP761X25519 1
ശൂന്യം randombytes(unsigned അക്ഷരം *ptr, size_t l);
അസ്ഥിര crypto_int16 crypto_int16_optblocker = 0;
അസ്ഥിര crypto_int32 crypto_int32_optblocker = 0;
അസ്ഥിര crypto_int64 crypto_int64_optblocker = 0;
#അന്തര്ഭാവ "sntrup761.c"

#define NSEEDS 1000

സ്ഥിതം പൂർണ്ണസംഖ്യ real_random;

ശൂന്യം
randombytes(unsigned അക്ഷരം *ptr, size_t l)
{
	എങ്കിൽ (real_random)
		arc4random_buf(ptr, l);
	അല്ലെങ്കിൽ
		memset(ptr, 0, l);
}

ശൂന്യം write_blob(സ്ഥിരം അക്ഷരം *path, പൂർണ്ണസംഖ്യ n, സ്ഥിരം അക്ഷരം *suffix,
    സ്ഥിരം ശൂന്യം *ptr, size_t l)
{
	അക്ഷരം name[256];
	FILE *f;

	snprintf(name, വലുപ്പം(name), "%s/%06d.%s", path, n, suffix);
	എങ്കിൽ ((f = fopen(name, "wb+")) == ശൂന്യ)
		err(1, "fopen %s", name);
	എങ്കിൽ (fwrite(ptr, l, 1, f) != 1)
		err(1, "write %s", name);
	fclose(f);
}

പൂർണ്ണസംഖ്യ പ്രധാന(ശൂന്യം)
{
	പൂർണ്ണസംഖ്യ i;
	unsigned അക്ഷരം pk[crypto_kem_sntrup761_PUBLICKEYBYTES];
	unsigned അക്ഷരം sk[crypto_kem_sntrup761_SECRETKEYBYTES];
	unsigned അക്ഷരം ciphertext[crypto_kem_sntrup761_CIPHERTEXTBYTES];
	unsigned അക്ഷരം secret[crypto_kem_sntrup761_BYTES];

	എങ്കിൽ (mkdir("sntrup761_pubkey_corpus", 0777) != 0 && errno != EEXIST)
		err(1, "mkdir sntrup761_pubkey_corpus");
	എങ്കിൽ (mkdir("sntrup761_ciphertext_corpus", 0777) != 0 && errno != EEXIST)
		err(1, "mkdir sntrup761_ciphertext_corpus");

	fprintf(stderr, "making: ");
	വേണ്ടി (i = 0; i < NSEEDS; i++) {
		real_random = i != 0;
		എങ്കിൽ (crypto_kem_sntrup761_keypair(pk, sk) != 0)
			errx(1, "crypto_kem_sntrup761_keypair failed");
		write_blob("sntrup761_pubkey_corpus", i, "pk", pk, വലുപ്പം(pk));
		എങ്കിൽ (crypto_kem_sntrup761_enc(ciphertext, secret, pk) != 0)
			errx(1, "crypto_kem_sntrup761_enc failed");
		write_blob("sntrup761_ciphertext_corpus", i, "ct",
		    ciphertext, വലുപ്പം(ciphertext));
		എങ്കിൽ (i % 20 == 0)
			fprintf(stderr, ".");
	}
	fprintf(stderr, "\n");
	തിരികെ 0;
}
