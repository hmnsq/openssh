#شامل <stddef.h>
#شامل <stdio.h>
#شامل <stdint.h>
#شامل <string.h>
#شامل <stdlib.h>

خارجی "C" {

#شامل "auth-options.h"

صحیح LLVMFuzzer_Test_One_داخلہ(ثابت uint8_t* ڈیٹا, سائز_t سائز)
{
	حرف *cp = (حرف *)حافظہ_دو(سائز + 1);
	ساخت sshauthopt *opts = تہی, *ملاؤ = تہی, *جوڑو = sshauthopt_new();

	اگر (cp == تہی || جوڑو == تہی)
		جاؤ برآمد;
	حافظہ_نقل(cp, ڈیٹا, سائز);
	cp[سائز] = '\0';
	اگر ((opts = sshauthopt_parse(cp, تہی)) == تہی)
		جاؤ برآمد;
	اگر ((ملاؤ = sshauthopt_ملاؤ(opts, جوڑو, تہی)) == تہی)
		جاؤ برآمد;

 برآمد:
	آزاد(cp);
	sshauthopt_free(جوڑو);
	sshauthopt_free(opts);
	sshauthopt_free(ملاؤ);
	واپس 0;
}

} // extern "C"
