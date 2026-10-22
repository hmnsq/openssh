// cc_fuzz_target test for ssh-agent.
வெளி "C" {

#அந்தர்பாவ <stdint.h>
#அந்தர்பாவ <sys/types.h>

வெளி வெறுமை test_one(மாறிலி uint8_t* s, size_t slen);

முழு LLVMFuzzer_Test_One_உள்ளீடு(மாறிலி uint8_t* s, size_t slen)
{
	test_one(s, slen);
	திரும்பு 0;
}

} // extern
