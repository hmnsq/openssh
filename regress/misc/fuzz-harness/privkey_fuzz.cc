#অন্তর্ভাব <stddef.h>
#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <stdint.h>

বাহ্যিক "C" {

#অন্তর্ভাব "sshkey.h"
#অন্তর্ভাব "sshbuf.h"

পূর্ণসংখ্যা LLVMFuzzer_Test_One_প্রবেশ(ধ্রুবক uint8_t* তথ্য, আকার_t আকার_2)
{
	কাঠামো sshkey *k = ফাঁকা;
	কাঠামো sshbuf *b = sshbuf_from(তথ্য, আকার_2);
	(শূন্য)sshkey_private_deserialize(b, &k);
	sshkey_free(k);
	sshbuf_free(b);
	ফেরত 0;
}

} // extern

