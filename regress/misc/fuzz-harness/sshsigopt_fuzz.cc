#ضمن <stddef.h>
#ضمن <stdio.h>
#ضمن <stdint.h>
#ضمن <string.h>
#ضمن <stdlib.h>

خارجي "C" {

#ضمن "sshsig.h"

صحيح LLVMFuzzer_Test_One_داخلہ(ثابت uint8_t* انکڑے, ناپ_t ناپ)
{
	حرف *cp = (حرف *)حافظہ_دیو(ناپ + 1);
	بنية sshsigopt *opts = عدم;

	إذا (cp == عدم)
		اذهب باہرلا;
	حافظہ_نقل(cp, انکڑے, ناپ);
	cp[ناپ] = '\0';
	إذا ((opts = sshsigopt_parse(cp, "libfuzzer", 0, عدم)) == عدم)
		اذهب باہرلا;

 باہرلا:
	حرر(cp);
	sshsigopt_free(opts);
	أرجع 0;
}

} // extern "C"
