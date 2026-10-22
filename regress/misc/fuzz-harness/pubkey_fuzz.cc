#ضمن <stddef.h>
#ضمن <stdio.h>
#ضمن <stdint.h>

خارجي "C" {

#ضمن "sshkey.h"

صحيح LLVMFuzzer_Test_One_ننوت(ثابت uint8_t* معلومات, اندازه_t اندازه)
{
	بنية sshkey *k = عدم;
	صحيح r = sshkey_from_blob(معلومات, اندازه, &k);
	إذا (r == 0) sshkey_free(k);
	أرجع 0;
}

} // extern

