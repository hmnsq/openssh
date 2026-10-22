// cc_fuzz_target test for ssh-agent.
বাহ্য "C" {

#অন্তর্ভাৱ <stdint.h>
#অন্তর্ভাৱ <sys/types.h>

বাহ্য শূন্য test_one(ধ্রুৱ uint8_t* s, size_t slen);

পূর্ণাঙ্ক LLVMFuzzer_Test_One_প্ৰবেশ(ধ্রুৱ uint8_t* s, size_t slen)
{
	test_one(s, slen);
	ঘূৰাই 0;
}

} // extern
