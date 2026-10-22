#شامل <stddef.h>
#شامل <stdio.h>
#شامل <stdint.h>

بیرونی "C" {

#شامل "sshkey.h"
#شامل "sshbuf.h"

صحیح LLVMFuzzer_Test_One_درون_داد(ثابت uint8_t* data, size_t size)
{
	ساختار sshkey *k = پوچ;
	ساختار sshbuf *b = sshbuf_from(data, size);
	(تهی)sshkey_private_deserialize(b, &k);
	sshkey_free(k);
	sshbuf_free(b);
	بازگشت 0;
}

} // extern

