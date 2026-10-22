#அந்தர்பாவ <stddef.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <stdint.h>

வெளி "C" {

#அந்தர்பாவ "sshkey.h"

முழு LLVMFuzzer_Test_One_உள்ளீடு(மாறிலி uint8_t* data, size_t size)
{
	கட்டமைப்பு sshkey *k = வெற்று;
	முழு r = sshkey_from_blob(data, size, &k);
	எனில் (r == 0) sshkey_free(k);
	திரும்பு 0;
}

} // extern

