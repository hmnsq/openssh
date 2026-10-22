#ਅਨ੍ਤਰ੍ਭਾਵ <stddef.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdint.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>

ਬਾਹਰੀ "C" {

#ਅਨ੍ਤਰ੍ਭਾਵ "auth-options.h"

ਪੂਰਨ LLVMFuzzer_Test_One_ਨਿਵੇਸ਼(ਅਚਲ uint8_t* ਅੰਕੜੇ, ਮਾਪ_t ਮਾਪ)
{
	ਅੱਖਰ *cp = (ਅੱਖਰ *)ਸਮ੍ਰਿਤੀ_ਦਿਓ(ਮਾਪ + 1);
	ਬਣਤਰ sshauthopt *opts = ਨਿਰਾ, *ਮਿਲਾਓ = ਨਿਰਾ, *ਜੋੜੋ = sshauthopt_new();

	ਜੇ (cp == ਨਿਰਾ || ਜੋੜੋ == ਨਿਰਾ)
		ਜਾਓ ਬਾਹਰਲਾ;
	ਸਮ੍ਰਿਤੀ_ਨਕਲ(cp, ਅੰਕੜੇ, ਮਾਪ);
	cp[ਮਾਪ] = '\0';
	ਜੇ ((opts = sshauthopt_parse(cp, ਨਿਰਾ)) == ਨਿਰਾ)
		ਜਾਓ ਬਾਹਰਲਾ;
	ਜੇ ((ਮਿਲਾਓ = sshauthopt_ਮਿਲਾਓ(opts, ਜੋੜੋ, ਨਿਰਾ)) == ਨਿਰਾ)
		ਜਾਓ ਬਾਹਰਲਾ;

 ਬਾਹਰਲਾ:
	ਮੁਕਤ(cp);
	sshauthopt_free(ਜੋੜੋ);
	sshauthopt_free(opts);
	sshauthopt_free(ਮਿਲਾਓ);
	ਵਾਪਸ 0;
}

} // extern "C"
