#include <stddef.h>
#include <stdio.h>
#include <stdint.h>

extern "C" {

#include "sshkey.h"

целое LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
	struct sshkey *k = NULL;
	целое r = sshkey_from_blob(data, size, &k);
	если (r == 0) sshkey_free(k);
	вернуть 0;
}

} // extern

