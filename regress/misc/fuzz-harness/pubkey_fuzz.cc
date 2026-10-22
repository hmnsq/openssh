#include <stddef.h>
#include <stdio.h>
#include <stdint.h>

extern "C" {

#include "sshkey.h"

පූර්ණ_සංඛ්‍යා LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
	sa_nracanaa sshkey *k = NULL;
	පූර්ණ_සංඛ්‍යා r = sshkey_from_blob(data, size, &k);
	නම් (r == 0) sshkey_free(k);
	ආපසු 0;
}

} // extern

