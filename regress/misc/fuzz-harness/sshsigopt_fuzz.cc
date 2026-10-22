#ಅನ್ತರ್ಭಾವ <stddef.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stdint.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>

ಬಾಹ್ಯ "C" {

#ಅನ್ತರ್ಭಾವ "sshsig.h"

ಪೂರ್ಣಾಙ್ಕ LLVMFuzzer_Test_One_ಒಳಹರಿವು(ಧ್ರುವ uint8_t* data, size_t size)
{
	ವರ್ಣ *cp = (ವರ್ಣ *)malloc(size + 1);
	ಸಂರಚನಾ sshsigopt *opts = ರಿಕ್ತ;

	ಯದಿ (cp == ರಿಕ್ತ)
		ಗಚ್ಛ out;
	memcpy(cp, data, size);
	cp[size] = '\0';
	ಯದಿ ((opts = sshsigopt_parse(cp, "libfuzzer", 0, ರಿಕ್ತ)) == ರಿಕ್ತ)
		ಗಚ್ಛ out;

 out:
	ಮುಕ್ತ(cp);
	sshsigopt_free(opts);
	ಪ್ರತ್ಯಾಗಮ 0;
}

} // extern "C"
