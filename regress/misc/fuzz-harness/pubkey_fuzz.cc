#شامل <stddef.h>
#شامل <stdio.h>
#شامل <stdint.h>

بیرونی "C" {

#شامل "sshkey.h"

صحیح LLVMFuzzer_Test_One_درون_داد(ثابت uint8_t* data, size_t size)
{
	ساختار sshkey *k = پوچ;
	صحیح r = sshkey_from_blob(data, size, &k);
	اگر (r == 0) sshkey_free(k);
	بازگشت 0;
}

} // extern

