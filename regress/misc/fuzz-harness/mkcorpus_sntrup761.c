// Makes basic seed corpora for other fuzzers
//
// Will write to ./sntrup761_pubkey_corpus (for sntrup761_enc_fuzz) and
// to ./sntrup761_ciphertext_corpus (for sntrup761_dec_fuzz)

#अन्तर्भाव <sys/stat.h>
#अन्तर्भाव <stddef.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <stdint.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <unistd.h>
#अन्तर्भाव <err.h>
#अन्तर्भाव <errno.h>

#अन्तर्भाव "crypto_api.h"
#अन्तर्भाव "hash.c"

#undef randombytes
#define USE_SNTRUP761X25519 1
शून्य randombytes(अचिन्हित अक्षर *ptr, माप_प्रकार l);
अस्थिर crypto_int16 crypto_int16_optblocker = 0;
अस्थिर crypto_int32 crypto_int32_optblocker = 0;
अस्थिर crypto_int64 crypto_int64_optblocker = 0;
#अन्तर्भाव "sntrup761.c"

#define NSEEDS 1000

स्थिर पूर्णांक real_random;

शून्य
randombytes(अचिन्हित अक्षर *ptr, माप_प्रकार l)
{
	जर (real_random)
		arc4random_buf(ptr, l);
	अन्यथा
		स_रखो(ptr, 0, l);
}

शून्य write_blob(स्थिरांक अक्षर *path, पूर्णांक n, स्थिरांक अक्षर *suffix,
    स्थिरांक शून्य *ptr, माप_प्रकार l)
{
	अक्षर name[256];
	खाता *f;

	snprintf(name, आकार(name), "%s/%06d.%s", path, n, suffix);
	जर ((f = ख_खोलो(name, "wb+")) == रिक्त)
		err(1, "fopen %s", name);
	जर (ख_डालो(ptr, l, 1, f) != 1)
		err(1, "write %s", name);
	ख_बंद(f);
}

पूर्णांक main(शून्य)
{
	पूर्णांक i;
	अचिन्हित अक्षर pk[crypto_kem_sntrup761_PUBLICKEYBYTES];
	अचिन्हित अक्षर sk[crypto_kem_sntrup761_SECRETKEYBYTES];
	अचिन्हित अक्षर ciphertext[crypto_kem_sntrup761_CIPHERTEXTBYTES];
	अचिन्हित अक्षर secret[crypto_kem_sntrup761_BYTES];

	जर (सूची_गढ़ो("sntrup761_pubkey_corpus", 0777) != 0 && त्रुटि_सं != EEXIST)
		err(1, "mkdir sntrup761_pubkey_corpus");
	जर (सूची_गढ़ो("sntrup761_ciphertext_corpus", 0777) != 0 && त्रुटि_सं != EEXIST)
		err(1, "mkdir sntrup761_ciphertext_corpus");

	ख_लिखो(मानक_त्रुटि, "making: ");
	साठी (i = 0; i < NSEEDS; i++) {
		real_random = i != 0;
		जर (crypto_kem_sntrup761_keypair(pk, sk) != 0)
			errx(1, "crypto_kem_sntrup761_keypair failed");
		write_blob("sntrup761_pubkey_corpus", i, "pk", pk, आकार(pk));
		जर (crypto_kem_sntrup761_enc(ciphertext, secret, pk) != 0)
			errx(1, "crypto_kem_sntrup761_enc failed");
		write_blob("sntrup761_ciphertext_corpus", i, "ct",
		    ciphertext, आकार(ciphertext));
		जर (i % 20 == 0)
			ख_लिखो(मानक_त्रुटि, ".");
	}
	ख_लिखो(मानक_त्रुटि, "\n");
	परत 0;
}
