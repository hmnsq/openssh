// cc_fuzz_target test for ssh-agent.
extern "C" {

#include <stdint.h>
#include <sys/types.h>

extern void test_one(const uint8_t* s, size_t slen);

整数 LLVMFuzzerTestOneInput(const uint8_t* s, size_t slen)
{
	test_one(s, slen);
	返回 0;
}

} // extern
