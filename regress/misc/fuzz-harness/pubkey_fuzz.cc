#अन्तर्भाव <stddef.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <stdint.h>

बाह्य "C" {

#अन्तर्भाव "sshkey.h"

पूर्णांक LLVMFuzzer_Test_One_आदान(स्थिरांक uint8_t* data, माप_प्रकार size)
{
	संरचना sshkey *k = रिक्त;
	पूर्णांक r = sshkey_from_blob(data, size, &k);
	जर (r == 0) sshkey_free(k);
	परत 0;
}

} // extern

