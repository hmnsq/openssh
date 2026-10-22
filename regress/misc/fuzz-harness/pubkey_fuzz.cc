#অন্তর্ভাৱ <stddef.h>
#অন্তর্ভাৱ <stdio.h>
#অন্তর্ভাৱ <stdint.h>

বাহ্য "C" {

#অন্তর্ভাৱ "sshkey.h"

পূর্ণাঙ্ক LLVMFuzzer_Test_One_প্ৰবেশ(ধ্রুৱ uint8_t* data, size_t size)
{
	সংরচনা sshkey *k = রিক্ত;
	পূর্ণাঙ্ক r = sshkey_from_blob(data, size, &k);
	যদি (r == 0) sshkey_free(k);
	ঘূৰাই 0;
}

} // extern

