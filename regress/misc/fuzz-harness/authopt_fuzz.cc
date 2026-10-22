#अन्तर्भाव <stddef.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <stdint.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <stdlib.h>

बाह्य "C" {

#अन्तर्भाव "auth-options.h"

पूर्णांक LLVMFuzzer_Test_One_आदान(स्थिरांक uint8_t* data, माप_प्रकार size)
{
	अक्षर *cp = (अक्षर *)दो_स्मृति(size + 1);
	संरचना sshauthopt *opts = रिक्त, *merge = रिक्त, *add = sshauthopt_new();

	जर (cp == रिक्त || add == रिक्त)
		जा out;
	स_नकल(cp, data, size);
	cp[size] = '\0';
	जर ((opts = sshauthopt_parse(cp, रिक्त)) == रिक्त)
		जा out;
	जर ((merge = sshauthopt_merge(opts, add, रिक्त)) == रिक्त)
		जा out;

 out:
	मुक्त(cp);
	sshauthopt_free(add);
	sshauthopt_free(opts);
	sshauthopt_free(merge);
	परत 0;
}

} // extern "C"
