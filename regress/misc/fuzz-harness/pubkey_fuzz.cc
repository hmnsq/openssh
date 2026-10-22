#include <stddef.h>
#include <stdio.h>
#include <stdint.h>

extern "C" {

#include "sshkey.h"

ຈຳນວນເຕັມ LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
	sa_nracanaa sshkey *k = NULL;
	ຈຳນວນເຕັມ r = sshkey_from_blob(data, size, &k);
	ຖ້າ (r == 0) sshkey_free(k);
	ສົ່ງຄືນ 0;
}

} // extern

