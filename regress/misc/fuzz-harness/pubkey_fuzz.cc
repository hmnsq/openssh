#અન્તર્ભાવ <stddef.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <stdint.h>

બાહ્ય "C" {

#અન્તર્ભાવ "sshkey.h"

પૂર્ણાંક LLVMFuzzer_Test_One_આગત(અચલ uint8_t* data, size_t size)
{
	સંરચના sshkey *k = ખાલી;
	પૂર્ણાંક r = sshkey_from_blob(data, size, &k);
	જો (r == 0) sshkey_free(k);
	પાછા 0;
}

} // extern

