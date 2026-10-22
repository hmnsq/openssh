#അന്തര്ഭാവ <stddef.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <stdint.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <stdlib.h>

ബാഹ്യ "C" {

#അന്തര്ഭാവ "sshsig.h"

പൂർണ്ണസംഖ്യ LLVMFuzzer_Test_One_നിവേശം(സ്ഥിരം uint8_t* data, size_t size)
{
	അക്ഷരം *cp = (അക്ഷരം *)malloc(size + 1);
	ഘടന sshsigopt *opts = ശൂന്യ;

	എങ്കിൽ (cp == ശൂന്യ)
		പോകുക out;
	memcpy(cp, data, size);
	cp[size] = '\0';
	എങ്കിൽ ((opts = sshsigopt_parse(cp, "libfuzzer", 0, ശൂന്യ)) == ശൂന്യ)
		പോകുക out;

 out:
	സ്വതന്ത്രം(cp);
	sshsigopt_free(opts);
	തിരികെ 0;
}

} // extern "C"
