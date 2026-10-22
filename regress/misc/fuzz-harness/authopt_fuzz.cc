#અન્તર્ભાવ <stddef.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <stdint.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <stdlib.h>

બાહ્ય "C" {

#અન્તર્ભાવ "auth-options.h"

પૂર્ણાંક LLVMFuzzer_Test_One_આગત(અચલ uint8_t* data, size_t size)
{
	અક્ષર *cp = (અક્ષર *)malloc(size + 1);
	સંરચના sshauthopt *opts = ખાલી, *merge = ખાલી, *add = sshauthopt_new();

	જો (cp == ખાલી || add == ખાલી)
		જાઓ out;
	memcpy(cp, data, size);
	cp[size] = '\0';
	જો ((opts = sshauthopt_parse(cp, ખાલી)) == ખાલી)
		જાઓ out;
	જો ((merge = sshauthopt_merge(opts, add, ખાલી)) == ખાલી)
		જાઓ out;

 out:
	મુક્ત(cp);
	sshauthopt_free(add);
	sshauthopt_free(opts);
	sshauthopt_free(merge);
	પાછા 0;
}

} // extern "C"
