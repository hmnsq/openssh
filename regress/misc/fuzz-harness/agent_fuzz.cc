// cc_fuzz_target test for ssh-agent.
extern "C" {

#include <stdint.h>
#include <sys/types.h>

extern void test_one(const uint8_t* s, size_t slen);

පූර්ණ_සංඛ්‍යා LLVMFuzzerTestOneInput(const uint8_t* s, size_t slen)
{
	test_one(s, slen);
	ආපසු 0;
}

} // extern
