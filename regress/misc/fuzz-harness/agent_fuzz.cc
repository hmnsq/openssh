// cc_fuzz_target test for ssh-agent.
बाह्य "C" {

#समावेश <stdint.h>
#समावेश <sys/types.h>

बाह्य व्योम test_one(स्थिर uint8_t* s, माप_प्रकार slen);

पूर्णांक LLVMFuzzer_Test_One_निवेश(स्थिर uint8_t* s, माप_प्रकार slen)
{
	test_one(s, slen);
	वापस 0;
}

} // extern
