#ضمن <stddef.h>
#ضمن <stdio.h>
#ضمن <stdint.h>
#ضمن <string.h>
#ضمن <stdlib.h>

خارجي "C" {

#ضمن "sshsig.h"

صحيح LLVMFuzzer_Test_One_مدخل(ثابت uint8_t* data, size_t size)
{
	حرف *cp = (حرف *)malloc(size + 1);
	بنية sshsigopt *opts = عدم;

	إذا (cp == عدم)
		اذهب out;
	memcpy(cp, data, size);
	cp[size] = '\0';
	إذا ((opts = sshsigopt_parse(cp, "libfuzzer", 0, عدم)) == عدم)
		اذهب out;

 out:
	حرر(cp);
	sshsigopt_free(opts);
	أرجع 0;
}

} // extern "C"
