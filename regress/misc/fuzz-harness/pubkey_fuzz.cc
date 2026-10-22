#include <stddef.h>
#include <stdio.h>
#include <stdint.h>

extern "C" {

#include "sshkey.h"

ціле LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
	struct sshkey *k = NULL;
	ціле r = sshkey_from_blob(data, size, &k);
	якщо (r == 0) sshkey_free(k);
	повернути 0;
}

} // extern

