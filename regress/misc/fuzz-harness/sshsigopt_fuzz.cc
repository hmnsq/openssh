#अन्तर्भाव <stddef.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <stdint.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <stdlib.h>

बाह्य "C" {

#अन्तर्भाव "sshsig.h"

पूर्णाङ्क LLVMFuzzer_Test_One_निवेशः(ध्रुव uint8_t* data, size_t size)
{
	वर्ण *cp = (वर्ण *)malloc(size + 1);
	संरचना sshsigopt *opts = रिक्त;

	सचे (cp == रिक्त)
		गच्छ out;
	memcpy(cp, data, size);
	cp[size] = '\0';
	सचे ((opts = sshsigopt_parse(cp, "libfuzzer", 0, रिक्त)) == रिक्त)
		गच्छ out;

 out:
	मुक्त(cp);
	sshsigopt_free(opts);
	पटिनिवत्त 0;
}

} // extern "C"
