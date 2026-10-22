#ضمن <stddef.h>
#ضمن <stdio.h>
#ضمن <stdint.h>
#ضمن <string.h>
#ضمن <stdlib.h>

خارجي "C" {

#ضمن "sshsig.h"

صحيح LLVMFuzzer_Test_One_درون_داد(ثابت uint8_t* داده, اندازه_t اندازه)
{
	حرف *cp = (حرف *)حافظه_بده(اندازه + 1);
	بنية sshsigopt *opts = عدم;

	إذا (cp == عدم)
		اذهب بیرون;
	کپی_حافظه(cp, داده, اندازه);
	cp[اندازه] = '\0';
	إذا ((opts = sshsigopt_parse(cp, "libfuzzer", 0, عدم)) == عدم)
		اذهب بیرون;

 بیرون:
	حرر(cp);
	sshsigopt_free(opts);
	أرجع 0;
}

} // extern "C"
