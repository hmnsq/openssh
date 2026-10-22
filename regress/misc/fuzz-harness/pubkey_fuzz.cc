#ضمن <stddef.h>
#ضمن <stdio.h>
#ضمن <stdint.h>

خارجي "C" {

#ضمن "sshkey.h"

صحيح LLVMFuzzer_Test_One_داخلہ(ثابت uint8_t* data, size_t size)
{
	بنية sshkey *k = عدم;
	صحيح r = sshkey_from_blob(data, size, &k);
	إذا (r == 0) sshkey_free(k);
	أرجع 0;
}

} // extern

