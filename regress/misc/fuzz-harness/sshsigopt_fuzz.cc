#अन्तर्भाव <stddef.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <stdint.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <stdlib.h>

बाह्य "C" {

#अन्तर्भाव "sshsig.h"

पूर्णांक LLVMFuzzer_Test_One_आदान(स्थिरांक uint8_t* data, माप_प्रकार size)
{
	अक्षर *cp = (अक्षर *)दो_स्मृति(size + 1);
	संरचना sshsigopt *opts = रिक्त;

	जर (cp == रिक्त)
		जा out;
	स_नकल(cp, data, size);
	cp[size] = '\0';
	जर ((opts = sshsigopt_parse(cp, "libfuzzer", 0, रिक्त)) == रिक्त)
		जा out;

 out:
	मुक्त(cp);
	sshsigopt_free(opts);
	परत 0;
}

} // extern "C"
