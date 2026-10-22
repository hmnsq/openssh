#include <stddef.h>
#include <stdio.h>
#include <stdint.h>

extern "C" {

#include "sshkey.h"

จำนวนเต็ม LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
	sa_nracanaa sshkey *k = NULL;
	จำนวนเต็ม r = sshkey_from_blob(data, size, &k);
	ถ้า (r == 0) sshkey_free(k);
	คืน 0;
}

} // extern

