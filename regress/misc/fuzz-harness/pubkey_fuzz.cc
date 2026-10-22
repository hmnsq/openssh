#অন্তর্ভাব <stddef.h>
#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <stdint.h>

বাহ্যিক "C" {

#অন্তর্ভাব "sshkey.h"

পূর্ণসংখ্যা LLVMFuzzer_Test_One_প্রবেশ(ধ্রুবক uint8_t* তথ্য, আকার_t আকার_2)
{
	কাঠামো sshkey *k = ফাঁকা;
	পূর্ণসংখ্যা r = sshkey_from_blob(তথ্য, আকার_2, &k);
	যদি (r == 0) sshkey_free(k);
	ফেরত 0;
}

} // extern

