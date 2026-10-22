#ಅನ್ತರ್ಭಾವ <stddef.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stdint.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>

ಬಾಹ್ಯ "C" {

#ಅನ್ತರ್ಭಾವ "auth-options.h"

ಪೂರ್ಣಾಂಕ LLVMFuzzer_Test_One_ಒಳಹರಿವು(ಸ್ಥಿರಾಂಕ uint8_t* ದತ್ತಾಂಶ, ಗಾತ್ರ_t ಗಾತ್ರ_2)
{
	ಅಕ್ಷರ *cp = (ಅಕ್ಷರ *)ಸ್ಮರಣೆ_ಕೊಡು(ಗಾತ್ರ_2 + 1);
	ರಚನೆ sshauthopt *opts = ಖಾಲಿ, *ವಿಲೀನ = ಖಾಲಿ, *ಕೂಡಿಸು = sshauthopt_new();

	ಆದರೆ (cp == ಖಾಲಿ || ಕೂಡಿಸು == ಖಾಲಿ)
		ಹೋಗು ಹೊರಹೋಗು;
	ಸ್ಮರಣೆ_ನಕಲು(cp, ದತ್ತಾಂಶ, ಗಾತ್ರ_2);
	cp[ಗಾತ್ರ_2] = '\0';
	ಆದರೆ ((opts = sshauthopt_parse(cp, ಖಾಲಿ)) == ಖಾಲಿ)
		ಹೋಗು ಹೊರಹೋಗು;
	ಆದರೆ ((ವಿಲೀನ = sshauthopt_ವಿಲೀನ(opts, ಕೂಡಿಸು, ಖಾಲಿ)) == ಖಾಲಿ)
		ಹೋಗು ಹೊರಹೋಗು;

 ಹೊರಹೋಗು:
	ಬಿಡುಗಡೆ(cp);
	sshauthopt_free(ಕೂಡಿಸು);
	sshauthopt_free(opts);
	sshauthopt_free(ವಿಲೀನ);
	ಹಿಂತಿರುಗಿ 0;
}

} // extern "C"
