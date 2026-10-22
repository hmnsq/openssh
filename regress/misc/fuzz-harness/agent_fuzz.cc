// cc_fuzz_target test for ssh-agent.
बाह्य "C" {

#अन्तर्भाव <stdint.h>
#अन्तर्भाव <sys/types.h>

बाह्य शून्य test_one(ध्रुव uint8_t* s, माप_प्रकार slen);

पूर्णाङ्क LLVMFuzzer_Test_One_निवेश(ध्रुव uint8_t* s, माप_प्रकार slen)
{
	test_one(s, slen);
	प्रत्यागम 0;
}

} // extern
