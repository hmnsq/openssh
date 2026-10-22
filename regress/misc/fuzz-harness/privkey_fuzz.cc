#ضمن <stddef.h>
#ضمن <stdio.h>
#ضمن <stdint.h>

خارجي "C" {

#ضمن "sshkey.h"
#ضمن "sshbuf.h"

صحيح LLVMFuzzer_Test_One_ننوت(ثابت uint8_t* معلومات, اندازه_t اندازه)
{
	بنية sshkey *k = عدم;
	بنية sshbuf *b = sshbuf_from(معلومات, اندازه);
	(فراغ)sshkey_شخصي_deserialize(b, &k);
	sshkey_free(k);
	sshbuf_free(b);
	أرجع 0;
}

} // extern

