#ਅਨ੍ਤਰ੍ਭਾਵ <stddef.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdint.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>

ਬਾਹਰੀ "C" {

#ਅਨ੍ਤਰ੍ਭਾਵ "sshsig.h"

ਪੂਰਨ LLVMFuzzer_Test_One_ਨਿਵੇਸ਼(ਅਚਲ uint8_t* ਅੰਕੜੇ, ਮਾਪ_t ਮਾਪ)
{
	ਅੱਖਰ *cp = (ਅੱਖਰ *)ਸਮ੍ਰਿਤੀ_ਦਿਓ(ਮਾਪ + 1);
	ਬਣਤਰ sshsigopt *opts = ਨਿਰਾ;

	ਜੇ (cp == ਨਿਰਾ)
		ਜਾਓ ਬਾਹਰਲਾ;
	ਸਮ੍ਰਿਤੀ_ਨਕਲ(cp, ਅੰਕੜੇ, ਮਾਪ);
	cp[ਮਾਪ] = '\0';
	ਜੇ ((opts = sshsigopt_parse(cp, "libfuzzer", 0, ਨਿਰਾ)) == ਨਿਰਾ)
		ਜਾਓ ਬਾਹਰਲਾ;

 ਬਾਹਰਲਾ:
	ਮੁਕਤ(cp);
	sshsigopt_free(opts);
	ਵਾਪਸ 0;
}

} // extern "C"
