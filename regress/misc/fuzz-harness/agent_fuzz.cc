// cc_fuzz_target test for ssh-agent.
ಬಾಹ್ಯ "C" {

#ಅನ್ತರ್ಭಾವ <stdint.h>
#ಅನ್ತರ್ಭಾವ <sys/types.h>

ಬಾಹ್ಯ ಶೂನ್ಯ test_one(ಸ್ಥಿರಾಂಕ uint8_t* s, ಗಾತ್ರ_t slen);

ಪೂರ್ಣಾಂಕ LLVMFuzzer_Test_One_ಒಳಹರಿವು(ಸ್ಥಿರಾಂಕ uint8_t* s, ಗಾತ್ರ_t slen)
{
	test_one(s, slen);
	ಹಿಂತಿರುಗಿ 0;
}

} // extern
