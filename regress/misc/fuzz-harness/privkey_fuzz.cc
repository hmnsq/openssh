#ضمن <stddef.h>
#ضمن <stdio.h>
#ضمن <stdint.h>

خارجي "C" {

#ضمن "sshkey.h"
#ضمن "sshbuf.h"

صحيح LLVMFuzzer_Test_One_داخلا(ثابت uint8_t* معلومات, سائيز_t سائيز)
{
	بنية sshkey *k = عدم;
	بنية sshbuf *b = sshbuf_from(معلومات, سائيز);
	(فراغ)sshkey_ذاتي_deserialize(b, &k);
	sshkey_free(k);
	sshbuf_free(b);
	أرجع 0;
}

} // extern

