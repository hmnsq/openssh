#समावेश <stddef.h>
#समावेश <stdio.h>
#समावेश <stdint.h>

बाह्य "C" {

#समावेश "sshkey.h"

पूर्णांक LLVMFuzzer_Test_One_निवेश(स्थिर uint8_t* तथ्य, माप_प्रकार आकार)
{
	काष्ठा sshkey *k = शून्य;
	पूर्णांक r = sshkey_from_blob(तथ्य, आकार, &k);
	अगर (r == 0) sshkey_free(k);
	वापस 0;
}

} // extern

