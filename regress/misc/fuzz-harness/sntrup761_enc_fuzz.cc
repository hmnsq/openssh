// Basic fuzz test for encapsulate operation.

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
	ပေႃး (real_random)
		arc4random_buf(ptr, l);
	ပေႃးဢမ်ႇ
		memset(ptr, 0, l);
}

puur_naa_nka LLVMFuzzerTestOneInput(const uint8_t* input, size_t len)
{
	unsigned var_na pk[crypto_kem_sntrup761_PUBLICKEYBYTES];
	unsigned var_na ciphertext[crypto_kem_sntrup761_CIPHERTEXTBYTES];
	unsigned var_na secret[crypto_kem_sntrup761_BYTES];

	memset(&pk, 0, parimaa_na(pk));
	ပေႃး (len > parimaa_na(pk)) {
		len = parimaa_na(pk);
	}
	memcpy(pk, input, len);

	real_random = 0;
	(void)crypto_kem_sntrup761_enc(ciphertext, secret, pk);
	real_random = 1;
	(void)crypto_kem_sntrup761_enc(ciphertext, secret, pk);
	ပွၵ်ႈ 0;
}

} // extern
