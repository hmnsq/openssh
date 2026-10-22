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

#لغو_تعریف randombytes
#تعریف_کن USE_SNTRUP761X25519 1
فراغ randombytes(بیعلامت حرف *ptr, اندازه_t l);
متطاير crypto_int16 crypto_int16_optblocker = 0;
متطاير crypto_int32 crypto_int32_optblocker = 0;
متطاير crypto_int64 crypto_int64_optblocker = 0;
#ضمن "sntrup761.c"

#تعریف_کن NSEEDS 1000

ساكن صحيح real_random;

فراغ
randombytes(بیعلامت حرف *ptr, اندازه_t l)
{
	إذا (real_random)
		arc4random_buf(ptr, l);
	وإلا
		memset(ptr, 0, l);
}

فراغ write_blob(ثابت حرف *مسیر, صحيح n, ثابت حرف *suffix,
    ثابت فراغ *ptr, اندازه_t l)
{
	حرف name[256];
	FILE *f;

	snprintf(name, حجم(name), "%s/%06d.%s", مسیر, n, suffix);
	إذا ((f = fopen(name, "wb+")) == عدم)
		err(1, "fopen %s", name);
	إذا (fwrite(ptr, l, 1, f) != 1)
		err(1, "write %s", name);
	fclose(f);
}

صحيح اصلی(فراغ)
{
	صحيح i;
	بیعلامت حرف pk[crypto_kem_sntrup761_PUBLICKEYBYTES];
	بیعلامت حرف sk[crypto_kem_sntrup761_SECRETKEYBYTES];
	بیعلامت حرف ciphertext[crypto_kem_sntrup761_CIPHERTEXTBYTES];
	بیعلامت حرف secret[crypto_kem_sntrup761_بایتها];

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
