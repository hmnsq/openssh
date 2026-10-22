#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

extern "C" {

#include "auth-options.h"

整数 LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
	char *cp = (char *)malloc(size + 1);
	struct sshauthopt *opts = NULL, *merge = NULL, *add = sshauthopt_new();

	もし (cp == NULL || add == NULL)
		goto out;
	memcpy(cp, data, size);
	cp[size] = '\0';
	もし ((opts = sshauthopt_parse(cp, NULL)) == NULL)
		goto out;
	もし ((merge = sshauthopt_merge(opts, add, NULL)) == NULL)
		goto out;

 out:
	free(cp);
	sshauthopt_free(add);
	sshauthopt_free(opts);
	sshauthopt_free(merge);
	戻る 0;
}

} // extern "C"
