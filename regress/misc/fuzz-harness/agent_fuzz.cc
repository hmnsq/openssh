// cc_fuzz_target test for ssh-agent.
బాహ్య "C" {

#అన్తర్భావ <stdint.h>
#అన్తర్భావ <sys/types.h>

బాహ్య శూన్య test_one(స్థిరరాశి uint8_t* s, కొలత_t slen);

పూర్ణాంకం LLVMFuzzer_Test_One_ఆదానం(స్థిరరాశి uint8_t* s, కొలత_t slen)
{
	test_one(s, slen);
	తిరిగి 0;
}

} // extern
