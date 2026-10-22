#ଅନ୍ତର୍ଭାଵ <stddef.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <stdint.h>

ବାହ୍ୟ "C" {

#ଅନ୍ତର୍ଭାଵ "sshkey.h"
#ଅନ୍ତର୍ଭାଵ "sshbuf.h"

ପୂର୍ଣ୍ଣସଂଖ୍ୟା LLVMFuzzer_Test_One_ନିବେଶ(ଅଚଳ uint8_t* data, size_t size)
{
	ସଂରଚନା sshkey *k = ଖାଲି;
	ସଂରଚନା sshbuf *b = sshbuf_from(data, size);
	(ଶୂନ୍ୟ)sshkey_private_deserialize(b, &k);
	sshkey_free(k);
	sshbuf_free(b);
	ଫେରନ୍ତୁ 0;
}

} // extern

