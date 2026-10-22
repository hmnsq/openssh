#அந்தர்பாவ <stddef.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <stdint.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <stdlib.h>

வெளி "C" {

#அந்தர்பாவ "sshsig.h"

முழு LLVMFuzzer_Test_One_உள்ளீடு(மாறிலி uint8_t* data, size_t size)
{
	எழுத்து *cp = (எழுத்து *)malloc(size + 1);
	கட்டமைப்பு sshsigopt *opts = வெற்று;

	எனில் (cp == வெற்று)
		செல் out;
	memcpy(cp, data, size);
	cp[size] = '\0';
	எனில் ((opts = sshsigopt_parse(cp, "libfuzzer", 0, வெற்று)) == வெற்று)
		செல் out;

 out:
	விடுவி(cp);
	sshsigopt_free(opts);
	திரும்பு 0;
}

} // extern "C"
