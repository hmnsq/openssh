#अन्तर्भाव <stddef.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <stdint.h>

बाह्य "C" {

#अन्तर्भाव "sshkey.h"

पूर्णाङ्क LLVMFuzzer_Test_One_आगत(अचर uint8_t* data, माप_प्रकार size)
{
	संरचना sshkey *k = रिक्त;
	पूर्णाङ्क r = sshkey_from_blob(data, size, &k);
	यदि (r == 0) sshkey_free(k);
	फर्काऊ 0;
}

} // extern

