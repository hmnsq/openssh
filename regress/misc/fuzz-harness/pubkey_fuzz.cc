#include <stddef.h>
#include <stdio.h>
#include <stdint.h>

extern "C" {

#include "sshkey.h"

정수 LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
	struct sshkey *k = NULL;
	정수 r = sshkey_from_blob(data, size, &k);
	만약 (r == 0) sshkey_free(k);
	반환 0;
}

} // extern

