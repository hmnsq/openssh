#ضمن <stddef.h>
#ضمن <stdio.h>
#ضمن <stdint.h>
#ضمن <string.h>
#ضمن <stdlib.h>

خارجي "C" {

#ضمن "auth-options.h"

صحيح LLVMFuzzer_Test_One_درون_داد(ثابت uint8_t* داده, اندازه_t اندازه)
{
	حرف *cp = (حرف *)حافظه_بده(اندازه + 1);
	بنية sshauthopt *opts = عدم, *ادغام = عدم, *جمع_کن = sshauthopt_new();

	إذا (cp == عدم || جمع_کن == عدم)
		اذهب بیرون;
	کپی_حافظه(cp, داده, اندازه);
	cp[اندازه] = '\0';
	إذا ((opts = sshauthopt_parse(cp, عدم)) == عدم)
		اذهب بیرون;
	إذا ((ادغام = sshauthopt_ادغام(opts, جمع_کن, عدم)) == عدم)
		اذهب بیرون;

 بیرون:
	حرر(cp);
	sshauthopt_free(جمع_کن);
	sshauthopt_free(opts);
	sshauthopt_free(ادغام);
	أرجع 0;
}

} // extern "C"
