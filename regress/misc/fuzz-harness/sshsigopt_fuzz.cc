#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

extern "C" {

#include "sshsig.h"

පූර්ණ_සංඛ්‍යා LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
	var_na *cp = (var_na *)malloc(size + 1);
	sa_nracanaa sshsigopt *opts = NULL;

	නම් (cp == NULL)
		goto out;
	memcpy(cp, data, size);
	cp[size] = '\0';
	නම් ((opts = sshsigopt_parse(cp, "libfuzzer", 0, NULL)) == NULL)
		goto out;

 out:
	free(cp);
	sshsigopt_free(opts);
	ආපසු 0;
}

} // extern "C"
