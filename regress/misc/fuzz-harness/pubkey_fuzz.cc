#ضمن <stddef.h>
#ضمن <stdio.h>
#ضمن <stdint.h>

خارجي "C" {

#ضمن "sshkey.h"

صحيح LLVMFuzzer_Test_One_داخلا(ثابت uint8_t* معلومات, سائيز_t سائيز)
{
	بنية sshkey *k = عدم;
	صحيح r = sshkey_from_blob(معلومات, سائيز, &k);
	إذا (r == 0) sshkey_free(k);
	أرجع 0;
}

} // extern

