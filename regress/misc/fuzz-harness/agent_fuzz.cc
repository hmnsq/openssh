// cc_fuzz_target test for ssh-agent.
بیرونی "C" {

#شامل <stdint.h>
#شامل <sys/types.h>

بیرونی تهی test_one(ثابت uint8_t* s, size_t slen);

صحیح LLVMFuzzer_Test_One_درون_داد(ثابت uint8_t* s, size_t slen)
{
	test_one(s, slen);
	بازگشت 0;
}

} // extern
