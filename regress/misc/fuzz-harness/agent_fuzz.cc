// cc_fuzz_target test for ssh-agent.
خارجی "C" {

#شامل <stdint.h>
#شامل <sys/types.h>

خارجی خالی test_one(ثابت uint8_t* s, سائز_t slen);

صحیح LLVMFuzzer_Test_One_داخلہ(ثابت uint8_t* s, سائز_t slen)
{
	test_one(s, slen);
	واپس 0;
}

} // extern
