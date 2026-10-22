#ضمن <stddef.h>
#ضمن <stdio.h>
#ضمن <stdint.h>

خارجي "C" {

#ضمن "sshkey.h"
#ضمن "sshbuf.h"

صحيح LLVMFuzzer_Test_One_درون_داد(ثابت uint8_t* داده, اندازه_t اندازه)
{
	بنية sshkey *k = عدم;
	بنية sshbuf *b = sshbuf_from(داده, اندازه);
	(فراغ)sshkey_خصوصی_deserialize(b, &k);
	sshkey_free(k);
	sshbuf_free(b);
	أرجع 0;
}

} // extern

