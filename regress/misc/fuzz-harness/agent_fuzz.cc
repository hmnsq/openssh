// cc_fuzz_target test for ssh-agent.
বাহ্য "C" {

#অন্তর্ভাব <stdint.h>
#অন্তর্ভাব <sys/types.h>

বাহ্য শূন্য test_one(ধ্রুব uint8_t* s, size_t slen);

পূর্ণাঙ্ক LLVMFuzzer_Test_One_প্রবেশ(ধ্রুব uint8_t* s, size_t slen)
{
	test_one(s, slen);
	প্রত্যাগম 0;
}

} // extern
