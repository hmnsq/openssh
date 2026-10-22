#include <stddef.h>
#include <stdio.h>
#include <stdint.h>

extern "C" {

#include "sshkey.h"

整数 LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
	struct sshkey *k = NULL;
	整数 r = sshkey_from_blob(data, size, &k);
	如果 (r == 0) sshkey_free(k);
	返回 0;
}

} // extern

