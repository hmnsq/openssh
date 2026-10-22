#समावेश <stddef.h>
#समावेश <stdio.h>
#समावेश <stdint.h>

बाह्य "C" {

#समावेश "sshkey.h"
#समावेश "sshbuf.h"

पूर्णांक LLVMFuzzer_Test_One_निवेश(स्थिर uint8_t* तथ्य, माप_प्रकार आकार)
{
	काष्ठा sshkey *k = शून्य;
	काष्ठा sshbuf *b = sshbuf_from(तथ्य, आकार);
	(व्योम)sshkey_private_deserialize(b, &k);
	sshkey_free(k);
	sshbuf_free(b);
	वापस 0;
}

} // extern

