#ضمن <stddef.h>
#ضمن <stdio.h>
#ضمن <stdint.h>
#ضمن <string.h>
#ضمن <stdlib.h>

خارجي "C" {

#ضمن "sshsig.h"

صحيح LLVMFuzzer_Test_One_ننوت(ثابت uint8_t* معلومات, اندازه_t اندازه)
{
	حرف *cp = (حرف *)حافظه_ورکړه(اندازه + 1);
	بنية sshsigopt *opts = عدم;

	إذا (cp == عدم)
		اذهب بهر;
	حافظه_نقل(cp, معلومات, اندازه);
	cp[اندازه] = '\0';
	إذا ((opts = sshsigopt_parse(cp, "libfuzzer", 0, عدم)) == عدم)
		اذهب بهر;

 بهر:
	حرر(cp);
	sshsigopt_free(opts);
	أرجع 0;
}

} // extern "C"
