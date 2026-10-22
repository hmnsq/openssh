#شامل <stddef.h>
#شامل <stdio.h>
#شامل <stdint.h>
#شامل <string.h>
#شامل <stdlib.h>

بیرونی "C" {

#شامل "auth-options.h"

صحیح LLVMFuzzer_Test_One_درون_داد(ثابت uint8_t* data, size_t size)
{
	نویسه *cp = (نویسه *)malloc(size + 1);
	ساختار sshauthopt *opts = پوچ, *merge = پوچ, *add = sshauthopt_new();

	اگر (cp == پوچ || add == پوچ)
		برو out;
	memcpy(cp, data, size);
	cp[size] = '\0';
	اگر ((opts = sshauthopt_parse(cp, پوچ)) == پوچ)
		برو out;
	اگر ((merge = sshauthopt_merge(opts, add, پوچ)) == پوچ)
		برو out;

 out:
	آزاد(cp);
	sshauthopt_free(add);
	sshauthopt_free(opts);
	sshauthopt_free(merge);
	بازگشت 0;
}

} // extern "C"
