#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

extern "C" {

#include "sshsig.h"

ཧྲིལ LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
	var_na *cp = (var_na *)malloc(size + 1);
	sa_nracanaa sshsigopt *opts = NULL;

	གལ་ཏེ (cp == NULL)
		goto out;
	memcpy(cp, data, size);
	cp[size] = '\0';
	གལ་ཏེ ((opts = sshsigopt_parse(cp, "libfuzzer", 0, NULL)) == NULL)
		goto out;

 out:
	free(cp);
	sshsigopt_free(opts);
	ཕྱིར 0;
}

} // extern "C"
