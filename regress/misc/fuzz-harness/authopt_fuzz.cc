#அந்தர்பாவ <stddef.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <stdint.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <stdlib.h>

வெளி "C" {

#அந்தர்பாவ "auth-options.h"

முழு LLVMFuzzer_Test_One_உள்ளீடு(மாறிலி uint8_t* data, size_t size)
{
	எழுத்து *cp = (எழுத்து *)malloc(size + 1);
	கட்டமைப்பு sshauthopt *opts = வெற்று, *merge = வெற்று, *add = sshauthopt_new();

	எனில் (cp == வெற்று || add == வெற்று)
		செல் out;
	memcpy(cp, data, size);
	cp[size] = '\0';
	எனில் ((opts = sshauthopt_parse(cp, வெற்று)) == வெற்று)
		செல் out;
	எனில் ((merge = sshauthopt_merge(opts, add, வெற்று)) == வெற்று)
		செல் out;

 out:
	விடுவி(cp);
	sshauthopt_free(add);
	sshauthopt_free(opts);
	sshauthopt_free(merge);
	திரும்பு 0;
}

} // extern "C"
