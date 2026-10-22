#அந்தர்பாவ <stddef.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <stdint.h>

வெளி "C" {

#அந்தர்பாவ "sshkey.h"
#அந்தர்பாவ "sshbuf.h"

முழு LLVMFuzzer_Test_One_உள்ளீடு(மாறிலி uint8_t* data, size_t size)
{
	கட்டமைப்பு sshkey *k = வெற்று;
	கட்டமைப்பு sshbuf *b = sshbuf_from(data, size);
	(வெறுமை)sshkey_private_deserialize(b, &k);
	sshkey_free(k);
	sshbuf_free(b);
	திரும்பு 0;
}

} // extern

