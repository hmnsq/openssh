#ضمن <stddef.h>
#ضمن <stdio.h>
#ضمن <stdint.h>
#ضمن <string.h>
#ضمن <stdlib.h>

خارجي "C" {

#ضمن "sshsig.h"

صحيح LLVMFuzzer_Test_One_داخلا(ثابت uint8_t* معلومات, سائيز_t سائيز)
{
	حرف *cp = (حرف *)يادگيري_ڏيو(سائيز + 1);
	بنية sshsigopt *opts = عدم;

	إذا (cp == عدم)
		اذهب ٻاهريون;
	يادگيري_نقل(cp, معلومات, سائيز);
	cp[سائيز] = '\0';
	إذا ((opts = sshsigopt_parse(cp, "libfuzzer", 0, عدم)) == عدم)
		اذهب ٻاهريون;

 ٻاهريون:
	حرر(cp);
	sshsigopt_free(opts);
	أرجع 0;
}

} // extern "C"
