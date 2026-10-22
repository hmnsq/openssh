#ضمن <stddef.h>
#ضمن <stdio.h>
#ضمن <stdint.h>
#ضمن <string.h>
#ضمن <stdlib.h>

خارجي "C" {

#ضمن "auth-options.h"

صحيح LLVMFuzzer_Test_One_ننوت(ثابت uint8_t* معلومات, اندازه_t اندازه)
{
	حرف *cp = (حرف *)حافظه_ورکړه(اندازه + 1);
	بنية sshauthopt *opts = عدم, *یوځای = عدم, *جمع_کړه = sshauthopt_new();

	إذا (cp == عدم || جمع_کړه == عدم)
		اذهب بهر;
	حافظه_نقل(cp, معلومات, اندازه);
	cp[اندازه] = '\0';
	إذا ((opts = sshauthopt_parse(cp, عدم)) == عدم)
		اذهب بهر;
	إذا ((یوځای = sshauthopt_یوځای(opts, جمع_کړه, عدم)) == عدم)
		اذهب بهر;

 بهر:
	حرر(cp);
	sshauthopt_free(جمع_کړه);
	sshauthopt_free(opts);
	sshauthopt_free(یوځای);
	أرجع 0;
}

} // extern "C"
