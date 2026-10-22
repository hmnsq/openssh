#ضمن <stddef.h>
#ضمن <stdio.h>
#ضمن <stdint.h>

خارجي "C" {

#ضمن "sshkey.h"
#ضمن "sshbuf.h"

صحيح LLVMFuzzer_Test_One_داخلہ(ثابت uint8_t* انکڑے, ناپ_t ناپ)
{
	بنية sshkey *k = عدم;
	بنية sshbuf *b = sshbuf_from(انکڑے, ناپ);
	(فراغ)sshkey_نجی_deserialize(b, &k);
	sshkey_free(k);
	sshbuf_free(b);
	أرجع 0;
}

} // extern

