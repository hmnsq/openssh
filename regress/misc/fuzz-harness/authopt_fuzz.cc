#অন্তর্ভাব <stddef.h>
#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <stdint.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <stdlib.h>

বাহ্য "C" {

#অন্তর্ভাব "auth-options.h"

পূর্ণাঙ্ক LLVMFuzzer_Test_One_প্রবেশ(ধ্রুব uint8_t* data, size_t size)
{
	বর্ণ *cp = (বর্ণ *)malloc(size + 1);
	সংরচনা sshauthopt *opts = রিক্ত, *merge = রিক্ত, *add = sshauthopt_new();

	যদি (cp == রিক্ত || add == রিক্ত)
		গচ্ছ out;
	memcpy(cp, data, size);
	cp[size] = '\0';
	যদি ((opts = sshauthopt_parse(cp, রিক্ত)) == রিক্ত)
		গচ্ছ out;
	যদি ((merge = sshauthopt_merge(opts, add, রিক্ত)) == রিক্ত)
		গচ্ছ out;

 out:
	মুক্ত(cp);
	sshauthopt_free(add);
	sshauthopt_free(opts);
	sshauthopt_free(merge);
	প্রত্যাগম 0;
}

} // extern "C"
