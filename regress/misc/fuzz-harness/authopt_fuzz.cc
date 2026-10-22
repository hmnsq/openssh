#अन्तर्भाव <stddef.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <stdint.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <stdlib.h>

बाह्य "C" {

#अन्तर्भाव "auth-options.h"

पूर्णाङ्क LLVMFuzzer_Test_One_निवेशः(ध्रुव uint8_t* दत्त, आकार_t आकार)
{
	वर्ण *cp = (वर्ण *)स्मृतिं_देहि(आकार + 1);
	संरचना sshauthopt *opts = रिक्त, *merge = रिक्त, *सङ्कलय = sshauthopt_new();

	यदि (cp == रिक्त || सङ्कलय == रिक्त)
		गच्छ बहिर्गमनम्;
	स्मृतिं_प्रतिलिख(cp, दत्त, आकार);
	cp[आकार] = '\0';
	यदि ((opts = sshauthopt_parse(cp, रिक्त)) == रिक्त)
		गच्छ बहिर्गमनम्;
	यदि ((merge = sshauthopt_merge(opts, सङ्कलय, रिक्त)) == रिक्त)
		गच्छ बहिर्गमनम्;

 बहिर्गमनम्:
	मुक्त(cp);
	sshauthopt_free(सङ्कलय);
	sshauthopt_free(opts);
	sshauthopt_free(merge);
	प्रत्यागम 0;
}

} // extern "C"
