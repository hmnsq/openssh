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

#وصف_رد randombytes
#وصف_ڪريو USE_SNTRUP761X25519 1
فراغ randombytes(بنانشان حرف *ptr, سائيز_t l);
متطاير crypto_int16 crypto_int16_optblocker = 0;
متطاير crypto_int32 crypto_int32_optblocker = 0;
متطاير crypto_int64 crypto_int64_optblocker = 0;
#ضمن "sntrup761.c"

#وصف_ڪريو NSEEDS 1000

ساكن صحيح real_random;

فراغ
randombytes(بنانشان حرف *ptr, سائيز_t l)
{
	إذا (real_random)
		arc4random_buf(ptr, l);
	وإلا
		memset(ptr, 0, l);
}

فراغ write_blob(ثابت حرف *رستو, صحيح n, ثابت حرف *suffix,
    ثابت فراغ *ptr, سائيز_t l)
{
	حرف name[256];
	FILE *f;

	snprintf(name, حجم(name), "%s/%06d.%s", رستو, n, suffix);
	إذا ((f = fopen(name, "wb+")) == عدم)
		err(1, "fopen %s", name);
	إذا (fwrite(ptr, l, 1, f) != 1)
		err(1, "write %s", name);
	fclose(f);
}

صحيح مکيه(فراغ)
{
	صحيح i;
	بنانشان حرف pk[crypto_kem_sntrup761_PUBLICKEYBYTES];
	بنانشان حرف sk[crypto_kem_sntrup761_SECRETKEYBYTES];
	بنانشان حرف ciphertext[crypto_kem_sntrup761_CIPHERTEXTBYTES];
	بنانشان حرف secret[crypto_kem_sntrup761_بائيٽون];

	إذا (mkdir("sntrup761_pubkey_corpus", 0777) != 0 && errno != EEXIST)
		err(1, "mkdir sntrup761_pubkey_corpus");
	إذا (mkdir("sntrup761_ciphertext_corpus", 0777) != 0 && errno != EEXIST)
		err(1, "mkdir sntrup761_ciphertext_corpus");

	fprintf(stderr, "making: ");
	لكل (i = 0; i < NSEEDS; i++) {
		real_random = i != 0;
		إذا (crypto_kem_sntrup761_keypair(pk, sk) != 0)
			errx(1, "crypto_kem_sntrup761_keypair failed");
		write_blob("sntrup761_pubkey_corpus", i, "pk", pk, حجم(pk));
		إذا (crypto_kem_sntrup761_enc(ciphertext, secret, pk) != 0)
			errx(1, "crypto_kem_sntrup761_enc failed");
		write_blob("sntrup761_ciphertext_corpus", i, "ct",
		    ciphertext, حجم(ciphertext));
		إذا (i % 20 == 0)
			fprintf(stderr, ".");
	}
	fprintf(stderr, "\n");
	أرجع 0;
}
