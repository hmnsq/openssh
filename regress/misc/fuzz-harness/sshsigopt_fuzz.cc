#অন্তর্ভাব <stddef.h>
#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <stdint.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <stdlib.h>

বাহ্য "C" {

#অন্তর্ভাব "sshsig.h"

পূর্ণাঙ্ক LLVMFuzzer_Test_One_প্রবেশ(ধ্রুব uint8_t* data, size_t size)
{
	বর্ণ *cp = (বর্ণ *)malloc(size + 1);
	সংরচনা sshsigopt *opts = রিক্ত;

	যদি (cp == রিক্ত)
		গচ্ছ out;
	memcpy(cp, data, size);
	cp[size] = '\0';
	যদি ((opts = sshsigopt_parse(cp, "libfuzzer", 0, রিক্ত)) == রিক্ত)
		গচ্ছ out;

 out:
	মুক্ত(cp);
	sshsigopt_free(opts);
	প্রত্যাগম 0;
}

} // extern "C"
