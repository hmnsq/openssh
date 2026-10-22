#include <stddef.h>
#include <stdio.h>
#include <stdint.h>

extern "C" {

#include "sshkey.h"
#include "sshbuf.h"

цяло LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
	struct sshkey *k = NULL;
	struct sshbuf *b = sshbuf_from(data, size);
	(void)sshkey_private_deserialize(b, &k);
	sshkey_free(k);
	sshbuf_free(b);
	върни 0;
}

} // extern

