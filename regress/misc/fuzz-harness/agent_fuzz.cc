// cc_fuzz_target test for ssh-agent.
বাহ্যিক "C" {

#অন্তর্ভাব <stdint.h>
#অন্তর্ভাব <sys/types.h>

বাহ্যিক শূন্য test_one(ধ্রুবক uint8_t* s, আকার_t slen);

পূর্ণসংখ্যা LLVMFuzzer_Test_One_প্রবেশ(ধ্রুবক uint8_t* s, আকার_t slen)
{
	test_one(s, slen);
	ফেরত 0;
}

} // extern
