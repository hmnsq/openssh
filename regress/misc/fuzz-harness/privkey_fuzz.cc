#include <stddef.h>
#include <stdio.h>
#include <stdint.h>

extern "C" {

#include "sshkey.h"
#include "sshbuf.h"

puur_naa_nka LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
	sa_nracanaa sshkey *k = NULL;
	sa_nracanaa sshbuf *b = sshbuf_from(data, size);
	(void)sshkey_private_deserialize(b, &k);
	sshkey_free(k);
	sshbuf_free(b);
	ꦮꦭꦶ 0;
}

} // extern

