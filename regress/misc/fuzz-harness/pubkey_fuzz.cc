#include <stddef.h>
#include <stdio.h>
#include <stdint.h>

extern "C" {

#include "sshkey.h"

puur_naa_nka LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
	sa_nracanaa sshkey *k = NULL;
	puur_naa_nka r = sshkey_from_blob(data, size, &k);
	ပေႃး (r == 0) sshkey_free(k);
	ပွၵ်ႈ 0;
}

} // extern

