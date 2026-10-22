#ضمن <stddef.h>
#ضمن <stdio.h>
#ضمن <stdint.h>

خارجي "C" {

#ضمن "sshkey.h"

صحيح LLVMFuzzer_Test_One_درون_داد(ثابت uint8_t* داده, اندازه_t اندازه)
{
	بنية sshkey *k = عدم;
	صحيح r = sshkey_from_blob(داده, اندازه, &k);
	إذا (r == 0) sshkey_free(k);
	أرجع 0;
}

} // extern

