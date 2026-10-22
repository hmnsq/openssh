#अन्तर्भाव <stddef.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <stdint.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <stdlib.h>

बाह्य "C" {

#अन्तर्भाव "auth-options.h"

पूर्णाङ्क LLVMFuzzer_Test_One_आदान(ध्रुव uint8_t* data, size_t size)
{
	वर्ण *cp = (वर्ण *)malloc(size + 1);
	संरचना sshauthopt *opts = रिक्त, *merge = रिक्त, *add = sshauthopt_new();

	यदि (cp == रिक्त || add == रिक्त)
		गच्छ out;
	memcpy(cp, data, size);
	cp[size] = '\0';
	यदि ((opts = sshauthopt_parse(cp, रिक्त)) == रिक्त)
		गच्छ out;
	यदि ((merge = sshauthopt_merge(opts, add, रिक्त)) == रिक्त)
		गच्छ out;

 out:
	मुक्त(cp);
	sshauthopt_free(add);
	sshauthopt_free(opts);
	sshauthopt_free(merge);
	प्रत्यागम 0;
}

} // extern "C"
