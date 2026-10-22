// Makes basic seed corpora for other fuzzers
//
// Will write to ./sntrup761_pubkey_corpus (for sntrup761_enc_fuzz) and
// to ./sntrup761_ciphertext_corpus (for sntrup761_dec_fuzz)

#ضمن <sys/stat.h>
#ضمن <stddef.h>
#ضمن <stdio.h>
#ضمن <stdint.h>
#ضمن <stdlib.h>
#ضمن <string.h>
#ضمن <unistd.h>
#ضمن <err.h>
#ضمن <errno.h>

#ضمن "crypto_api.h"
#ضمن "hash.c"

#undef randombytes
#define USE_SNTRUP761X25519 1
فراغ randombytes(unsigned حرف *ptr, size_t l);
متطاير crypto_int16 crypto_int16_optblocker = 0;
متطاير crypto_int32 crypto_int32_optblocker = 0;
متطاير crypto_int64 crypto_int64_optblocker = 0;
#ضمن "sntrup761.c"

#define NSEEDS 1000

ساكن صحيح real_random;

فراغ
randombytes(unsigned حرف *ptr, size_t l)
{
	𐤀𐤌 (real_random)
		arc4random_buf(ptr, l);
	وإلا
		memset(ptr, 0, l);
}

فراغ write_blob(ثابت حرف *path, صحيح n, ثابت حرف *suffix,
    ثابت فراغ *ptr, size_t l)
{
	حرف name[256];
	FILE *f;

	snprintf(name, حجم(name), "%s/%06d.%s", path, n, suffix);
	𐤀𐤌 ((f = fopen(name, "wb+")) == عدم)
		err(1, "fopen %s", name);
	𐤀𐤌 (fwrite(ptr, l, 1, f) != 1)
		err(1, "write %s", name);
	fclose(f);
}

صحيح main(فراغ)
{
	صحيح i;
	unsigned حرف pk[crypto_kem_sntrup761_PUBLICKEYBYTES];
	unsigned حرف sk[crypto_kem_sntrup761_SECRETKEYBYTES];
	unsigned حرف ciphertext[crypto_kem_sntrup761_CIPHERTEXTBYTES];
	unsigned حرف secret[crypto_kem_sntrup761_BYTES];

	𐤀𐤌 (mkdir("sntrup761_pubkey_corpus", 0777) != 0 && errno != EEXIST)
		err(1, "mkdir sntrup761_pubkey_corpus");
	𐤀𐤌 (mkdir("sntrup761_ciphertext_corpus", 0777) != 0 && errno != EEXIST)
		err(1, "mkdir sntrup761_ciphertext_corpus");

	fprintf(stderr, "making: ");
	لكل (i = 0; i < NSEEDS; i++) {
		real_random = i != 0;
		𐤀𐤌 (crypto_kem_sntrup761_keypair(pk, sk) != 0)
			errx(1, "crypto_kem_sntrup761_keypair failed");
		write_blob("sntrup761_pubkey_corpus", i, "pk", pk, حجم(pk));
		𐤀𐤌 (crypto_kem_sntrup761_enc(ciphertext, secret, pk) != 0)
			errx(1, "crypto_kem_sntrup761_enc failed");
		write_blob("sntrup761_ciphertext_corpus", i, "ct",
		    ciphertext, حجم(ciphertext));
		𐤀𐤌 (i % 20 == 0)
			fprintf(stderr, ".");
	}
	fprintf(stderr, "\n");
	أرجع 0;
}
