#અન્તર્ભાવ <stddef.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <stdint.h>

બાહ્ય "C" {

#અન્તર્ભાવ "sshkey.h"
#અન્તર્ભાવ "sshbuf.h"

પૂર્ણાંક LLVMFuzzer_Test_One_આગત(અચલ uint8_t* data, size_t size)
{
	સંરચના sshkey *k = ખાલી;
	સંરચના sshbuf *b = sshbuf_from(data, size);
	(શૂન્ય)sshkey_private_deserialize(b, &k);
	sshkey_free(k);
	sshbuf_free(b);
	પાછા 0;
}

} // extern

