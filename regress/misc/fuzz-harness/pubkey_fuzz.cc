#include <stddef.h>
#include <stdio.h>
#include <stdint.h>

extern "C" {

#include "sshkey.h"

цео LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
	struct sshkey *k = NULL;
	цео r = sshkey_from_blob(data, size, &k);
	ако (r == 0) sshkey_free(k);
	врати 0;
}

} // extern

