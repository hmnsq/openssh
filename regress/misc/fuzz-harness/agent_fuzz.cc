// cc_fuzz_target test for ssh-agent.
خارجي "C" {

#ضمن <stdint.h>
#ضمن <sys/types.h>

خارجي فراغ test_one(ثابت uint8_t* s, سائيز_t slen);

صحيح LLVMFuzzer_Test_One_داخلا(ثابت uint8_t* s, سائيز_t slen)
{
	test_one(s, slen);
	أرجع 0;
}

} // extern
