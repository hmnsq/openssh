#ضمن <stddef.h>
#ضمن <stdio.h>
#ضمن <stdint.h>

خارجي "C" {

#ضمن "sshkey.h"

صحيح LLVMFuzzerTestOneInput(ثابت uint8_t* data, size_t size)
{
	بنية sshkey *k = عدم;
	صحيح r = sshkey_from_blob(data, size, &k);
	ܐܢ (r == 0) sshkey_free(k);
	ܦܢܐ 0;
}

} // extern

