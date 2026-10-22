#ضمن <stddef.h>
#ضمن <stdio.h>
#ضمن <stdint.h>
#ضمن <string.h>
#ضمن <stdlib.h>

خارجي "C" {

#ضمن "auth-options.h"

صحيح LLVMFuzzer_Test_One_داخلہ(ثابت uint8_t* انکڑے, ناپ_t ناپ)
{
	حرف *cp = (حرف *)حافظہ_دیو(ناپ + 1);
	بنية sshauthopt *opts = عدم, *ملاؤ = عدم, *جوڑو = sshauthopt_new();

	إذا (cp == عدم || جوڑو == عدم)
		اذهب باہرلا;
	حافظہ_نقل(cp, انکڑے, ناپ);
	cp[ناپ] = '\0';
	إذا ((opts = sshauthopt_parse(cp, عدم)) == عدم)
		اذهب باہرلا;
	إذا ((ملاؤ = sshauthopt_ملاؤ(opts, جوڑو, عدم)) == عدم)
		اذهب باہرلا;

 باہرلا:
	حرر(cp);
	sshauthopt_free(جوڑو);
	sshauthopt_free(opts);
	sshauthopt_free(ملاؤ);
	أرجع 0;
}

} // extern "C"
