#অন্তর্ভাৱ <stddef.h>
#অন্তর্ভাৱ <stdio.h>
#অন্তর্ভাৱ <stdint.h>

বাহ্য "C" {

#অন্তর্ভাৱ "sshkey.h"
#অন্তর্ভাৱ "sshbuf.h"

পূর্ণাঙ্ক LLVMFuzzer_Test_One_প্ৰবেশ(ধ্রুৱ uint8_t* data, size_t size)
{
	সংরচনা sshkey *k = রিক্ত;
	সংরচনা sshbuf *b = sshbuf_from(data, size);
	(শূন্য)sshkey_private_deserialize(b, &k);
	sshkey_free(k);
	sshbuf_free(b);
	ঘূৰাই 0;
}

} // extern

