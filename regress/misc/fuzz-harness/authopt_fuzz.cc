#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

extern "C" {

#include "auth-options.h"

ကိန်းပြည့် LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
	var_na *cp = (var_na *)malloc(size + 1);
	sa_nracanaa sshauthopt *opts = NULL, *merge = NULL, *add = sshauthopt_new();

	အကယ်၍ (cp == NULL || add == NULL)
		goto out;
	memcpy(cp, data, size);
	cp[size] = '\0';
	အကယ်၍ ((opts = sshauthopt_parse(cp, NULL)) == NULL)
		goto out;
	အကယ်၍ ((merge = sshauthopt_merge(opts, add, NULL)) == NULL)
		goto out;

 out:
	free(cp);
	sshauthopt_free(add);
	sshauthopt_free(opts);
	sshauthopt_free(merge);
	ပြန်ပေး 0;
}

} // extern "C"
