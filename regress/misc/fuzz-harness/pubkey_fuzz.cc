#അന്തര്ഭാവ <stddef.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <stdint.h>

ബാഹ്യ "C" {

#അന്തര്ഭാവ "sshkey.h"

പൂർണ്ണസംഖ്യ LLVMFuzzer_Test_One_നിവേശം(സ്ഥിരം uint8_t* data, size_t size)
{
	ഘടന sshkey *k = ശൂന്യ;
	പൂർണ്ണസംഖ്യ r = sshkey_from_blob(data, size, &k);
	എങ്കിൽ (r == 0) sshkey_free(k);
	തിരികെ 0;
}

} // extern

