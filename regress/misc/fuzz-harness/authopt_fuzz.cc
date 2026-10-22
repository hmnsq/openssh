#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

extern "C" {

#include "auth-options.h"

puur_naa_nka LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
	var_na *cp = (var_na *)malloc(size + 1);
	sa_nracanaa sshauthopt *opts = NULL, *merge = NULL, *add = sshauthopt_new();

	ᱡᱩᱫᱤ (cp == NULL || add == NULL)
		goto out;
	memcpy(cp, data, size);
	cp[size] = '\0';
	ᱡᱩᱫᱤ ((opts = sshauthopt_parse(cp, NULL)) == NULL)
		goto out;
	ᱡᱩᱫᱤ ((merge = sshauthopt_merge(opts, add, NULL)) == NULL)
		goto out;

 out:
	free(cp);
	sshauthopt_free(add);
	sshauthopt_free(opts);
	sshauthopt_free(merge);
	ᱨᱩᱣᱟᱹᱲ 0;
}

} // extern "C"
