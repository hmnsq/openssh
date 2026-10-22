// cc_fuzz_target test for ssh-agent.
ಬಾಹ್ಯ "C" {

#ಅನ್ತರ್ಭಾವ <stdint.h>
#ಅನ್ತರ್ಭಾವ <sys/types.h>

ಬಾಹ್ಯ ಶೂನ್ಯ test_one(ಧ್ರುವ uint8_t* s, size_t slen);

ಪೂರ್ಣಾಙ್ಕ LLVMFuzzer_Test_One_ಒಳಹರಿವು(ಧ್ರುವ uint8_t* s, size_t slen)
{
	test_one(s, slen);
	ಪ್ರತ್ಯಾಗಮ 0;
}

} // extern
