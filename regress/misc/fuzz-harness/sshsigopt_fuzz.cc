#অন্তর্ভাব <stddef.h>
#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <stdint.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <stdlib.h>

বাহ্যিক "C" {

#অন্তর্ভাব "sshsig.h"

পূর্ণসংখ্যা LLVMFuzzer_Test_One_প্রবেশ(ধ্রুবক uint8_t* তথ্য, আকার_t আকার_2)
{
	অক্ষর *cp = (অক্ষর *)malloc(আকার_2 + 1);
	কাঠামো sshsigopt *opts = ফাঁকা;

	যদি (cp == ফাঁকা)
		যাও out;
	memcpy(cp, তথ্য, আকার_2);
	cp[আকার_2] = '\0';
	যদি ((opts = sshsigopt_parse(cp, "libfuzzer", 0, ফাঁকা)) == ফাঁকা)
		যাও out;

 out:
	মুক্ত(cp);
	sshsigopt_free(opts);
	ফেরত 0;
}

} // extern "C"
