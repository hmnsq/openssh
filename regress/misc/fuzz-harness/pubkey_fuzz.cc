#अन्तर्भाव <stddef.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <stdint.h>

बाह्य "C" {

#अन्तर्भाव "sshkey.h"

पूर्णाङ्क LLVMFuzzer_Test_One_निवेशः(ध्रुव uint8_t* data, size_t size)
{
	संरचना sshkey *k = रिक्त;
	पूर्णाङ्क r = sshkey_from_blob(data, size, &k);
	जइ (r == 0) sshkey_free(k);
	प्रत्यागम 0;
}

} // extern

