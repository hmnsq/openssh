// cc_fuzz_target test for ssh-agent.
ਬਾਹਰੀ "C" {

#ਅਨ੍ਤਰ੍ਭਾਵ <stdint.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>

ਬਾਹਰੀ ਖਾਲੀ test_one(ਅਚਲ uint8_t* s, ਮਾਪ_t slen);

ਪੂਰਨ LLVMFuzzer_Test_One_ਨਿਵੇਸ਼(ਅਚਲ uint8_t* s, ਮਾਪ_t slen)
{
	test_one(s, slen);
	ਵਾਪਸ 0;
}

} // extern
