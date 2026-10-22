#include <stddef.h>
#include <stdio.h>
#include <stdint.h>

extern "C" {

#include "sshkey.h"

số_nguyên LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
	struct sshkey *k = NULL;
	số_nguyên r = sshkey_from_blob(data, size, &k);
	nếu (r == 0) sshkey_free(k);
	trả_về 0;
}

} // extern

