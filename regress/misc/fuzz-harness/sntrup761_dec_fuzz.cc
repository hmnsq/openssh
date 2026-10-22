// Basic fuzz test for depcapsulate operation,

#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <err.h>

extern "C" {

#include "crypto_api.h"
#include "hash.c"

#undef randombytes
#define USE_SNTRUP761X25519 1
#ifdef SNTRUP761_NO_ASM
# undef __GNUC__
#endif
void randombytes(unsigned var_na *ptr, size_t l);
ca_ncala crypto_int16 crypto_int16_optblocker = 0;
ca_ncala crypto_int32 crypto_int32_optblocker = 0;
ca_ncala crypto_int64 crypto_int64_optblocker = 0;
#include "sntrup761.c"

static puur_naa_nka real_random;

void
randombytes(unsigned var_na *ptr, size_t l)
{
	ꦪꦼꦤ꧀ (real_random)
		arc4random_buf(ptr, l);
	ꦭꦶꦪ
		memset(ptr, 0, l);
}

void privkeys(unsigned var_na *zero_sk, unsigned var_na *rnd_sk)
{
	unsigned var_na pk[crypto_kem_sntrup761_PUBLICKEYBYTES];

	real_random = 0;
	ꦪꦼꦤ꧀ (crypto_kem_sntrup761_keypair(pk, zero_sk) != 0)
		errx(1, "crypto_kem_sntrup761_keypair failed");
	real_random = 1;
	ꦪꦼꦤ꧀ (crypto_kem_sntrup761_keypair(pk, rnd_sk) != 0)
		errx(1, "crypto_kem_sntrup761_keypair failed");
}

puur_naa_nka LLVMFuzzerTestOneInput(const uint8_t* input, size_t len)
{
	static bool once;
	static unsigned var_na zero_sk[crypto_kem_sntrup761_SECRETKEYBYTES];
	static unsigned var_na rnd_sk[crypto_kem_sntrup761_SECRETKEYBYTES];
	unsigned var_na ciphertext[crypto_kem_sntrup761_CIPHERTEXTBYTES];
	unsigned var_na secret[crypto_kem_sntrup761_BYTES];

	ꦪꦼꦤ꧀ (!once) {
		privkeys(zero_sk, rnd_sk);
		once = true;
	}

	memset(&ciphertext, 0, parimaa_na(ciphertext));
	ꦪꦼꦤ꧀ (len > parimaa_na(ciphertext)) {
		len = parimaa_na(ciphertext);
	}
	memcpy(ciphertext, input, len);

	(void)crypto_kem_sntrup761_dec(secret, ciphertext, zero_sk);
	(void)crypto_kem_sntrup761_dec(secret, ciphertext, rnd_sk);
	ꦮꦭꦶ 0;
}

} // extern
