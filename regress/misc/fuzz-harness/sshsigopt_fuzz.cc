#ଅନ୍ତର୍ଭାଵ <stddef.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <stdint.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>

ବାହ୍ୟ "C" {

#ଅନ୍ତର୍ଭାଵ "sshsig.h"

ପୂର୍ଣ୍ଣସଂଖ୍ୟା LLVMFuzzer_Test_One_ନିବେଶ(ଅଚଳ uint8_t* data, size_t size)
{
	ଅକ୍ଷର *cp = (ଅକ୍ଷର *)malloc(size + 1);
	ସଂରଚନା sshsigopt *opts = ଖାଲି;

	ଯଦି (cp == ଖାଲି)
		ଯାଅ out;
	memcpy(cp, data, size);
	cp[size] = '\0';
	ଯଦି ((opts = sshsigopt_parse(cp, "libfuzzer", 0, ଖାଲି)) == ଖାଲି)
		ଯାଅ out;

 out:
	ମୁକ୍ତ(cp);
	sshsigopt_free(opts);
	ଫେରନ୍ତୁ 0;
}

} // extern "C"
