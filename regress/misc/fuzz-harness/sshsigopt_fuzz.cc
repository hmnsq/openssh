#شامل <stddef.h>
#شامل <stdio.h>
#شامل <stdint.h>
#شامل <string.h>
#شامل <stdlib.h>

خارجی "C" {

#شامل "sshsig.h"

صحیح LLVMFuzzer_Test_One_داخلہ(ثابت uint8_t* ڈیٹا, سائز_t سائز)
{
	حرف *cp = (حرف *)حافظہ_دو(سائز + 1);
	ساخت sshsigopt *opts = تہی;

	اگر (cp == تہی)
		جاؤ برآمد;
	حافظہ_نقل(cp, ڈیٹا, سائز);
	cp[سائز] = '\0';
	اگر ((opts = sshsigopt_parse(cp, "libfuzzer", 0, تہی)) == تہی)
		جاؤ برآمد;

 برآمد:
	آزاد(cp);
	sshsigopt_free(opts);
	واپس 0;
}

} // extern "C"
