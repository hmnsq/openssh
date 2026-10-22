#ಅನ್ತರ್ಭಾವ <stddef.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stdint.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>

ಬಾಹ್ಯ "C" {

#ಅನ್ತರ್ಭಾವ "auth-options.h"

ಪೂರ್ಣಾಙ್ಕ LLVMFuzzer_Test_One_ಒಳಹರಿವು(ಧ್ರುವ uint8_t* data, size_t size)
{
	ವರ್ಣ *cp = (ವರ್ಣ *)malloc(size + 1);
	ಸಂರಚನಾ sshauthopt *opts = ರಿಕ್ತ, *merge = ರಿಕ್ತ, *add = sshauthopt_new();

	ಯದಿ (cp == ರಿಕ್ತ || add == ರಿಕ್ತ)
		ಗಚ್ಛ out;
	memcpy(cp, data, size);
	cp[size] = '\0';
	ಯದಿ ((opts = sshauthopt_parse(cp, ರಿಕ್ತ)) == ರಿಕ್ತ)
		ಗಚ್ಛ out;
	ಯದಿ ((merge = sshauthopt_merge(opts, add, ರಿಕ್ತ)) == ರಿಕ್ತ)
		ಗಚ್ಛ out;

 out:
	ಮುಕ್ತ(cp);
	sshauthopt_free(add);
	sshauthopt_free(opts);
	sshauthopt_free(merge);
	ಪ್ರತ್ಯಾಗಮ 0;
}

} // extern "C"
