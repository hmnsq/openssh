// cc_fuzz_target test for ssh-agent.
ବାହ୍ୟ "C" {

#ଅନ୍ତର୍ଭାଵ <stdint.h>
#ଅନ୍ତର୍ଭାଵ <sys/types.h>

ବାହ୍ୟ ଶୂନ୍ୟ test_one(ଅଚଳ uint8_t* s, size_t slen);

ପୂର୍ଣ୍ଣସଂଖ୍ୟା LLVMFuzzer_Test_One_ନିବେଶ(ଅଚଳ uint8_t* s, size_t slen)
{
	test_one(s, slen);
	ଫେରନ୍ତୁ 0;
}

} // extern
