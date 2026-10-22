#شامل <stddef.h>
#شامل <stdio.h>
#شامل <stdint.h>

خارجی "C" {

#شامل "sshkey.h"
#شامل "sshbuf.h"

صحیح LLVMFuzzer_Test_One_داخلہ(ثابت uint8_t* ڈیٹا, سائز_t سائز)
{
	ساخت sshkey *k = تہی;
	ساخت sshbuf *b = sshbuf_from(ڈیٹا, سائز);
	(خالی)sshkey_نجی_deserialize(b, &k);
	sshkey_free(k);
	sshbuf_free(b);
	واپس 0;
}

} // extern

