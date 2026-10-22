#ಅನ್ತರ್ಭಾವ <stddef.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stdint.h>

ಬಾಹ್ಯ "C" {

#ಅನ್ತರ್ಭಾವ "sshkey.h"

ಪೂರ್ಣಾಂಕ LLVMFuzzer_Test_One_ಒಳಹರಿವು(ಸ್ಥಿರಾಂಕ uint8_t* ದತ್ತಾಂಶ, ಗಾತ್ರ_t ಗಾತ್ರ_2)
{
	ರಚನೆ sshkey *k = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ r = sshkey_from_blob(ದತ್ತಾಂಶ, ಗಾತ್ರ_2, &k);
	ಆದರೆ (r == 0) sshkey_free(k);
	ಹಿಂತಿರುಗಿ 0;
}

} // extern

