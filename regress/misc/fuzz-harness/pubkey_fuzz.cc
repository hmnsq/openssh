#অন্তর্ভাব <stddef.h>
#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <stdint.h>

বাহ্য "C" {

#অন্তর্ভাব "sshkey.h"

পূর্ণাঙ্ক LLVMFuzzer_Test_One_প্রবেশ(ধ্রুব uint8_t* data, size_t size)
{
	সংরচনা sshkey *k = রিক্ত;
	পূর্ণাঙ্ক r = sshkey_from_blob(data, size, &k);
	যদি (r == 0) sshkey_free(k);
	প্রত্যাগম 0;
}

} // extern

