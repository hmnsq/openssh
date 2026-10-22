#ضمن <stddef.h>
#ضمن <stdio.h>
#ضمن <stdint.h>

خارجي "C" {

#ضمن "sshkey.h"

صحيح LLVMFuzzer_Test_One_داخلہ(ثابت uint8_t* انکڑے, ناپ_t ناپ)
{
	بنية sshkey *k = عدم;
	صحيح r = sshkey_from_blob(انکڑے, ناپ, &k);
	إذا (r == 0) sshkey_free(k);
	أرجع 0;
}

} // extern

