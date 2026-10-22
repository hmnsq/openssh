#ضمن <stddef.h>
#ضمن <stdio.h>
#ضمن <stdint.h>
#ضمن <string.h>
#ضمن <stdlib.h>

خارجي "C" {

#ضمن "auth-options.h"

صحيح LLVMFuzzerTestOneInput(ثابت uint8_t* data, size_t size)
{
	حرف *cp = (حرف *)malloc(size + 1);
	بنية sshauthopt *opts = عدم, *merge = عدم, *add = sshauthopt_new();

	אם (cp == عدم || add == عدم)
		اذهب out;
	memcpy(cp, data, size);
	cp[size] = '\0';
	אם ((opts = sshauthopt_parse(cp, عدم)) == عدم)
		اذهب out;
	אם ((merge = sshauthopt_merge(opts, add, عدم)) == عدم)
		اذهب out;

 out:
	حرر(cp);
	sshauthopt_free(add);
	sshauthopt_free(opts);
	sshauthopt_free(merge);
	החזר 0;
}

} // extern "C"
