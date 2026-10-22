#अन्तर्भाव <stddef.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <stdint.h>

बाह्य "C" {

#अन्तर्भाव "sshkey.h"
#अन्तर्भाव "sshbuf.h"

पूर्णाङ्क LLVMFuzzer_Test_One_आगत(अचर uint8_t* data, माप_प्रकार size)
{
	संरचना sshkey *k = रिक्त;
	संरचना sshbuf *b = sshbuf_from(data, size);
	(शून्य)sshkey_private_deserialize(b, &k);
	sshkey_free(k);
	sshbuf_free(b);
	फर्काऊ 0;
}

} // extern

