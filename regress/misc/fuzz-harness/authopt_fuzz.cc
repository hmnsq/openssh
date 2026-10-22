#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

extern "C" {

#include "auth-options.h"

цео LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
	char *cp = (char *)malloc(size + 1);
	struct sshauthopt *opts = NULL, *merge = NULL, *add = sshauthopt_new();

	ако (cp == NULL || add == NULL)
		goto out;
	memcpy(cp, data, size);
	cp[size] = '\0';
	ако ((opts = sshauthopt_parse(cp, NULL)) == NULL)
		goto out;
	ако ((merge = sshauthopt_merge(opts, add, NULL)) == NULL)
		goto out;

 out:
	free(cp);
	sshauthopt_free(add);
	sshauthopt_free(opts);
	sshauthopt_free(merge);
	врати 0;
}

} // extern "C"
