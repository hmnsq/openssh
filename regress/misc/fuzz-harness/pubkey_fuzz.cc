#ಅನ್ತರ್ಭಾವ <stddef.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stdint.h>

ಬಾಹ್ಯ "C" {

#ಅನ್ತರ್ಭಾವ "sshkey.h"

ಪೂರ್ಣಾಙ್ಕ LLVMFuzzer_Test_One_ಒಳಹರಿವು(ಧ್ರುವ uint8_t* data, size_t size)
{
	ಸಂರಚನಾ sshkey *k = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ r = sshkey_from_blob(data, size, &k);
	ಯದಿ (r == 0) sshkey_free(k);
	ಪ್ರತ್ಯಾಗಮ 0;
}

} // extern

