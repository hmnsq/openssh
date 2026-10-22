#ضمن <stddef.h>
#ضمن <stdio.h>
#ضمن <stdint.h>
#ضمن <string.h>
#ضمن <stdlib.h>

خارجي "C" {

#ضمن "auth-options.h"

صحيح LLVMFuzzer_Test_One_داخلا(ثابت uint8_t* معلومات, سائيز_t سائيز)
{
	حرف *cp = (حرف *)يادگيري_ڏيو(سائيز + 1);
	بنية sshauthopt *opts = عدم, *ملايو = عدم, *جوڙيو = sshauthopt_new();

	إذا (cp == عدم || جوڙيو == عدم)
		اذهب ٻاهريون;
	يادگيري_نقل(cp, معلومات, سائيز);
	cp[سائيز] = '\0';
	إذا ((opts = sshauthopt_parse(cp, عدم)) == عدم)
		اذهب ٻاهريون;
	إذا ((ملايو = sshauthopt_ملايو(opts, جوڙيو, عدم)) == عدم)
		اذهب ٻاهريون;

 ٻاهريون:
	حرر(cp);
	sshauthopt_free(جوڙيو);
	sshauthopt_free(opts);
	sshauthopt_free(ملايو);
	أرجع 0;
}

} // extern "C"
