// cc_fuzz_target test for ssh-agent.
extern "C" {

#include <stdint.h>
#include <sys/types.h>

extern void test_one(const uint8_t* s, size_t slen);

int LLVMFuzzer_Test_One_पासोक(const uint8_t* s, size_t slen)
{
	test_one(s, slen);
	return 0;
}

} // extern
