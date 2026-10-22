#അന്തര്ഭാവ <stddef.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <stdint.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <stdlib.h>

ബാഹ്യ "C" {

#അന്തര്ഭാവ "auth-options.h"

പൂർണ്ണസംഖ്യ LLVMFuzzer_Test_One_നിവേശം(സ്ഥിരം uint8_t* data, size_t size)
{
	അക്ഷരം *cp = (അക്ഷരം *)malloc(size + 1);
	ഘടന sshauthopt *opts = ശൂന്യ, *merge = ശൂന്യ, *add = sshauthopt_new();

	എങ്കിൽ (cp == ശൂന്യ || add == ശൂന്യ)
		പോകുക out;
	memcpy(cp, data, size);
	cp[size] = '\0';
	എങ്കിൽ ((opts = sshauthopt_parse(cp, ശൂന്യ)) == ശൂന്യ)
		പോകുക out;
	എങ്കിൽ ((merge = sshauthopt_merge(opts, add, ശൂന്യ)) == ശൂന്യ)
		പോകുക out;

 out:
	സ്വതന്ത്രം(cp);
	sshauthopt_free(add);
	sshauthopt_free(opts);
	sshauthopt_free(merge);
	തിരികെ 0;
}

} // extern "C"
