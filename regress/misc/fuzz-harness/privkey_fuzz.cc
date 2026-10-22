#ಅನ್ತರ್ಭಾವ <stddef.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stdint.h>

ಬಾಹ್ಯ "C" {

#ಅನ್ತರ್ಭಾವ "sshkey.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"

ಪೂರ್ಣಾಂಕ LLVMFuzzer_Test_One_ಒಳಹರಿವು(ಸ್ಥಿರಾಂಕ uint8_t* ದತ್ತಾಂಶ, ಗಾತ್ರ_t ಗಾತ್ರ_2)
{
	ರಚನೆ sshkey *k = ಖಾಲಿ;
	ರಚನೆ sshbuf *b = sshbuf_from(ದತ್ತಾಂಶ, ಗಾತ್ರ_2);
	(ಶೂನ್ಯ)sshkey_ಖಾಸಗಿ_deserialize(b, &k);
	sshkey_free(k);
	sshbuf_free(b);
	ಹಿಂತಿರುಗಿ 0;
}

} // extern

