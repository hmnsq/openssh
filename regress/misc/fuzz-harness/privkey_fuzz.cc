#অন্তর্ভাব <stddef.h>
#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <stdint.h>

বাহ্য "C" {

#অন্তর্ভাব "sshkey.h"
#অন্তর্ভাব "sshbuf.h"

পূর্ণাঙ্ক LLVMFuzzer_Test_One_প্রবেশ(ধ্রুব uint8_t* data, size_t size)
{
	সংরচনা sshkey *k = রিক্ত;
	সংরচনা sshbuf *b = sshbuf_from(data, size);
	(শূন্য)sshkey_private_deserialize(b, &k);
	sshkey_free(k);
	sshbuf_free(b);
	প্রত্যাগম 0;
}

} // extern

