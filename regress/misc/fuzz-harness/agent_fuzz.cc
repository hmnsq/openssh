// cc_fuzz_target test for ssh-agent.
خارجي "C" {

#ضمن <stdint.h>
#ضمن <sys/types.h>

خارجي فراغ test_one(ثابت uint8_t* s, اندازه_t slen);

صحيح LLVMFuzzer_Test_One_درون_داد(ثابت uint8_t* s, اندازه_t slen)
{
	test_one(s, slen);
	أرجع 0;
}

} // extern
