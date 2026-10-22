#شامل <stddef.h>
#شامل <stdio.h>
#شامل <stdint.h>
#شامل <string.h>
#شامل <stdlib.h>

بیرونی "C" {

#شامل "sshsig.h"

صحیح LLVMFuzzer_Test_One_درون_داد(ثابت uint8_t* data, size_t size)
{
	نویسه *cp = (نویسه *)malloc(size + 1);
	ساختار sshsigopt *opts = پوچ;

	اگر (cp == پوچ)
		برو out;
	memcpy(cp, data, size);
	cp[size] = '\0';
	اگر ((opts = sshsigopt_parse(cp, "libfuzzer", 0, پوچ)) == پوچ)
		برو out;

 out:
	آزاد(cp);
	sshsigopt_free(opts);
	بازگشت 0;
}

} // extern "C"
