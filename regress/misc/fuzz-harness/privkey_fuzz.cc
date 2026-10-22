#ಅನ್ತರ್ಭಾವ <stddef.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stdint.h>

ಬಾಹ್ಯ "C" {

#ಅನ್ತರ್ಭಾವ "sshkey.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"

ಪೂರ್ಣಾಙ್ಕ LLVMFuzzer_Test_One_ಒಳಹರಿವು(ಧ್ರುವ uint8_t* data, size_t size)
{
	ಸಂರಚನಾ sshkey *k = ರಿಕ್ತ;
	ಸಂರಚನಾ sshbuf *b = sshbuf_from(data, size);
	(ಶೂನ್ಯ)sshkey_private_deserialize(b, &k);
	sshkey_free(k);
	sshbuf_free(b);
	ಪ್ರತ್ಯಾಗಮ 0;
}

} // extern

