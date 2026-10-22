#અન્તર્ભાવ <stddef.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <stdint.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <stdlib.h>

બાહ્ય "C" {

#અન્તર્ભાવ "sshsig.h"

પૂર્ણાંક LLVMFuzzer_Test_One_આગત(અચલ uint8_t* data, size_t size)
{
	અક્ષર *cp = (અક્ષર *)malloc(size + 1);
	સંરચના sshsigopt *opts = ખાલી;

	જો (cp == ખાલી)
		જાઓ out;
	memcpy(cp, data, size);
	cp[size] = '\0';
	જો ((opts = sshsigopt_parse(cp, "libfuzzer", 0, ખાલી)) == ખાલી)
		જાઓ out;

 out:
	મુક્ત(cp);
	sshsigopt_free(opts);
	પાછા 0;
}

} // extern "C"
