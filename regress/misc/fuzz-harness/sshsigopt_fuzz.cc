#অন্তর্ভাৱ <stddef.h>
#অন্তর্ভাৱ <stdio.h>
#অন্তর্ভাৱ <stdint.h>
#অন্তর্ভাৱ <string.h>
#অন্তর্ভাৱ <stdlib.h>

বাহ্য "C" {

#অন্তর্ভাৱ "sshsig.h"

পূর্ণাঙ্ক LLVMFuzzer_Test_One_প্ৰবেশ(ধ্রুৱ uint8_t* data, size_t size)
{
	ৱর্ণ *cp = (ৱর্ণ *)malloc(size + 1);
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
	ঘূৰাই 0;
}

} // extern "C"
