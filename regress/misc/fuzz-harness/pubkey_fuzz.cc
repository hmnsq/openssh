#include <stddef.h>
#include <stdio.h>
#include <stdint.h>

extern "C" {

#include "sshkey.h"

ကိန်းပြည့် LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
	sa_nracanaa sshkey *k = NULL;
	ကိန်းပြည့် r = sshkey_from_blob(data, size, &k);
	အကယ်၍ (r == 0) sshkey_free(k);
	ပြန်ပေး 0;
}

} // extern

