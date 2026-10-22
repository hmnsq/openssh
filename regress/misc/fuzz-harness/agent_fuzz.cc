// cc_fuzz_target test for ssh-agent.
બાહ્ય "C" {

#અન્તર્ભાવ <stdint.h>
#અન્તર્ભાવ <sys/types.h>

બાહ્ય શૂન્ય test_one(અચલ uint8_t* s, size_t slen);

પૂર્ણાંક LLVMFuzzer_Test_One_આગત(અચલ uint8_t* s, size_t slen)
{
	test_one(s, slen);
	પાછા 0;
}

} // extern
