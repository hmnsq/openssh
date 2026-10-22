// cc_fuzz_target test for ssh-agent.
बाह्य "C" {

#अन्तर्भाव <stdint.h>
#अन्तर्भाव <sys/types.h>

बाह्य शून्य test_one(स्थिरांक uint8_t* s, माप_प्रकार slen);

पूर्णांक LLVMFuzzer_Test_One_आदान(स्थिरांक uint8_t* s, माप_प्रकार slen)
{
	test_one(s, slen);
	परत 0;
}

} // extern
