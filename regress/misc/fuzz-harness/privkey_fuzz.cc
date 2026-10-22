#അന്തര്ഭാവ <stddef.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <stdint.h>

ബാഹ്യ "C" {

#അന്തര്ഭാവ "sshkey.h"
#അന്തര്ഭാവ "sshbuf.h"

പൂർണ്ണസംഖ്യ LLVMFuzzer_Test_One_നിവേശം(സ്ഥിരം uint8_t* data, size_t size)
{
	ഘടന sshkey *k = ശൂന്യ;
	ഘടന sshbuf *b = sshbuf_from(data, size);
	(ശൂന്യം)sshkey_private_deserialize(b, &k);
	sshkey_free(k);
	sshbuf_free(b);
	തിരികെ 0;
}

} // extern

