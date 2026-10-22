#include <stddef.h>
#include <stdio.h>
#include <stdint.h>

extern "C" {

#include "sshkey.h"

ចំនួនគត់ LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
	sa_nracanaa sshkey *k = NULL;
	ចំនួនគត់ r = sshkey_from_blob(data, size, &k);
	ប្រសិនបើ (r == 0) sshkey_free(k);
	ត្រឡប់ 0;
}

} // extern

