#include <stddef.h>
#include <stdio.h>
#include <stdint.h>

extern "C" {

#include "sshkey.h"

int LLVMFuzzer_Test_One_पासोक(const uint8_t* data, size_t size)
{
	struct sshkey *k = NULL;
	int r = sshkey_from_blob(data, size, &k);
	if (r == 0) sshkey_free(k);
	return 0;
}

} // extern

