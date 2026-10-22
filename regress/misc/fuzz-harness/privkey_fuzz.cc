#ضمن <stddef.h>
#ضمن <stdio.h>
#ضمن <stdint.h>

خارجي "C" {

#ضمن "sshkey.h"
#ضمن "sshbuf.h"

صحيح LLVMFuzzerTestOneInput(ثابت uint8_t* data, size_t size)
{
	بنية sshkey *k = عدم;
	بنية sshbuf *b = sshbuf_from(data, size);
	(فراغ)sshkey_private_deserialize(b, &k);
	sshkey_free(k);
	sshbuf_free(b);
	החזר 0;
}

} // extern

