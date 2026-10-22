#ଅନ୍ତର୍ଭାଵ <stddef.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <stdint.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>

ବାହ୍ୟ "C" {

#ଅନ୍ତର୍ଭାଵ "auth-options.h"

ପୂର୍ଣ୍ଣସଂଖ୍ୟା LLVMFuzzer_Test_One_ନିବେଶ(ଅଚଳ uint8_t* data, size_t size)
{
	ଅକ୍ଷର *cp = (ଅକ୍ଷର *)malloc(size + 1);
	ସଂରଚନା sshauthopt *opts = ଖାଲି, *merge = ଖାଲି, *add = sshauthopt_new();

	ଯଦି (cp == ଖାଲି || add == ଖାଲି)
		ଯାଅ out;
	memcpy(cp, data, size);
	cp[size] = '\0';
	ଯଦି ((opts = sshauthopt_parse(cp, ଖାଲି)) == ଖାଲି)
		ଯାଅ out;
	ଯଦି ((merge = sshauthopt_merge(opts, add, ଖାଲି)) == ଖାଲି)
		ଯାଅ out;

 out:
	ମୁକ୍ତ(cp);
	sshauthopt_free(add);
	sshauthopt_free(opts);
	sshauthopt_free(merge);
	ଫେରନ୍ତୁ 0;
}

} // extern "C"
