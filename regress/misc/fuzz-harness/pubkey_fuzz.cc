#شامل <stddef.h>
#شامل <stdio.h>
#شامل <stdint.h>

خارجی "C" {

#شامل "sshkey.h"

صحیح LLVMFuzzer_Test_One_داخلہ(ثابت uint8_t* ڈیٹا, سائز_t سائز)
{
	ساخت sshkey *k = تہی;
	صحیح r = sshkey_from_blob(ڈیٹا, سائز, &k);
	اگر (r == 0) sshkey_free(k);
	واپس 0;
}

} // extern

