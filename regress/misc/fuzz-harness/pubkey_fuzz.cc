#include <stddef.h>
#include <stdio.h>
#include <stdint.h>

extern "C" {

#include "sshkey.h"

ཧྲིལ LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
	sa_nracanaa sshkey *k = NULL;
	ཧྲིལ r = sshkey_from_blob(data, size, &k);
	གལ་སྲིད (r == 0) sshkey_free(k);
	ལོག 0;
}

} // extern

