// Makes basic seed corpora for other fuzzers
//
// Will write to ./sntrup761_pubkey_corpus (for sntrup761_enc_fuzz) and
// to ./sntrup761_ciphertext_corpus (for sntrup761_dec_fuzz)

#समावेश <sys/stat.h>
#समावेश <stddef.h>
#समावेश <stdio.h>
#समावेश <stdint.h>
#समावेश <stdlib.h>
#समावेश <string.h>
#समावेश <unistd.h>
#समावेश <err.h>
#समावेश <errno.h>

#समावेश "crypto_api.h"
#समावेश "hash.c"

#अघोषित randombytes
#घोषणा USE_SNTRUP761X25519 1
व्योम randombytes(अचिन्हित अक्षर *ptr, माप_प्रकार l);
अस्थिर crypto_int16 crypto_int16_optblocker = 0;
अस्थिर crypto_int32 crypto_int32_optblocker = 0;
अस्थिर crypto_int64 crypto_int64_optblocker = 0;
#समावेश "sntrup761.c"

#घोषणा NSEEDS 1000

अटल पूर्णांक real_random;

व्योम
randombytes(अचिन्हित अक्षर *ptr, माप_प्रकार l)
{
	अगर (real_random)
		arc4random_buf(ptr, l);
	अन्यथा
		स_रखो(ptr, 0, l);
}

व्योम write_blob(स्थिर अक्षर *path, पूर्णांक n, स्थिर अक्षर *suffix,
    स्थिर व्योम *ptr, माप_प्रकार l)
{
	अक्षर name[256];
	खाता *f;

	snprintf(name, माप(name), "%s/%06d.%s", path, n, suffix);
	अगर ((f = ख_खोलो(name, "wb+")) == शून्य)
		err(1, "fopen %s", name);
	अगर (ख_डालो(ptr, l, 1, f) != 1)
		err(1, "write %s", name);
	ख_बंद(f);
}

पूर्णांक मुख्य(व्योम)
{
	पूर्णांक i;
	अचिन्हित अक्षर pk[crypto_kem_sntrup761_PUBLICKEYBYTES];
	अचिन्हित अक्षर sk[crypto_kem_sntrup761_SECRETKEYBYTES];
	अचिन्हित अक्षर ciphertext[crypto_kem_sntrup761_CIPHERTEXTBYTES];
	अचिन्हित अक्षर secret[crypto_kem_sntrup761_BYTES];

	अगर (सूची_गढ़ो("sntrup761_pubkey_corpus", 0777) != 0 && त्रुटि_सं != EEXIST)
		err(1, "mkdir sntrup761_pubkey_corpus");
	अगर (सूची_गढ़ो("sntrup761_ciphertext_corpus", 0777) != 0 && त्रुटि_सं != EEXIST)
		err(1, "mkdir sntrup761_ciphertext_corpus");

	ख_लिखो(मानक_त्रुटि, "making: ");
	क्रम (i = 0; i < NSEEDS; i++) {
		real_random = i != 0;
		अगर (crypto_kem_sntrup761_keypair(pk, sk) != 0)
			errx(1, "crypto_kem_sntrup761_keypair failed");
		write_blob("sntrup761_pubkey_corpus", i, "pk", pk, माप(pk));
		अगर (crypto_kem_sntrup761_enc(ciphertext, secret, pk) != 0)
			errx(1, "crypto_kem_sntrup761_enc failed");
		write_blob("sntrup761_ciphertext_corpus", i, "ct",
		    ciphertext, माप(ciphertext));
		अगर (i % 20 == 0)
			ख_लिखो(मानक_त्रुटि, ".");
	}
	ख_लिखो(मानक_त्रुटि, "\n");
	वापस 0;
}
