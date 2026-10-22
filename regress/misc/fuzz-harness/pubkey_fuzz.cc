#ଅନ୍ତର୍ଭାଵ <stddef.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <stdint.h>

ବାହ୍ୟ "C" {

#ଅନ୍ତର୍ଭାଵ "sshkey.h"

ପୂର୍ଣ୍ଣସଂଖ୍ୟା LLVMFuzzer_Test_One_ନିବେଶ(ଅଚଳ uint8_t* data, size_t size)
{
	ସଂରଚନା sshkey *k = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r = sshkey_from_blob(data, size, &k);
	ଯଦି (r == 0) sshkey_free(k);
	ଫେରନ୍ତୁ 0;
}

} // extern

