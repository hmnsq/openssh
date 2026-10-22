// cc_fuzz_target test for ssh-agent.
خارجي "C" {

#ضمن <stdint.h>
#ضمن <sys/types.h>

خارجي فراغ test_one(ثابت uint8_t* s, size_t slen);

صحيح LLVMFuzzerTestOneInput(ثابت uint8_t* s, size_t slen)
{
	test_one(s, slen);
	ܦܢܐ 0;
}

} // extern
