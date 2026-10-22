// cc_fuzz_target test for ssh-agent.
ബാഹ്യ "C" {

#അന്തര്ഭാവ <stdint.h>
#അന്തര്ഭാവ <sys/types.h>

ബാഹ്യ ശൂന്യം test_one(സ്ഥിരം uint8_t* s, size_t slen);

പൂർണ്ണസംഖ്യ LLVMFuzzer_Test_One_നിവേശം(സ്ഥിരം uint8_t* s, size_t slen)
{
	test_one(s, slen);
	തിരികെ 0;
}

} // extern
