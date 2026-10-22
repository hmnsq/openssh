#include <stddef.h>
#include <stdio.h>
#include <stdint.h>

extern "C" {

#include "sshkey.h"

цяло LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
	struct sshkey *k = NULL;
	цяло r = sshkey_from_blob(data, size, &k);
	ако (r == 0) sshkey_free(k);
	върни 0;
}

} // extern

