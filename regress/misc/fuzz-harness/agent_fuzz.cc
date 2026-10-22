// cc_fuzz_target test for ssh-agent.
extern "C" {

#include <stdint.h>
#include <sys/types.h>

extern void test_one(const uint8_t* s, size_t slen);

정수 LLVMFuzzerTestOneInput(const uint8_t* s, size_t slen)
{
	test_one(s, slen);
	반환 0;
}

} // extern
