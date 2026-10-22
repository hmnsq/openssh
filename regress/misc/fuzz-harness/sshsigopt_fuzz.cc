#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

extern "C" {

#include "sshsig.h"

整数 LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
	char *cp = (char *)malloc(size + 1);
	struct sshsigopt *opts = NULL;

	もし (cp == NULL)
		goto out;
	memcpy(cp, data, size);
	cp[size] = '\0';
	もし ((opts = sshsigopt_parse(cp, "libfuzzer", 0, NULL)) == NULL)
		goto out;

 out:
	free(cp);
	sshsigopt_free(opts);
	戻る 0;
}

} // extern "C"
