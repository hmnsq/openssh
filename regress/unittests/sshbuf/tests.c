/* 	$OpenBSD: tests.c,v 1.2 2025/04/15 04:00:42 djm Exp $ */
/*
 * Regress test for sshbuf.h buffer API
 *
 * Placed in the public domain
 */

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <stdio.h>

#অন্তর্ভাব "../test_helper/test_helper.h"

শূন্য sshbuf_tests(শূন্য);
শূন্য sshbuf_getput_basic_tests(শূন্য);
শূন্য sshbuf_getput_crypto_tests(শূন্য);
শূন্য sshbuf_misc_tests(শূন্য);
শূন্য sshbuf_fuzz_tests(শূন্য);
শূন্য sshbuf_getput_fuzz_tests(শূন্য);
শূন্য sshbuf_fixed(শূন্য);

শূন্য
tests(শূন্য)
{
	sshbuf_tests();
	sshbuf_getput_basic_tests();
#ifdef WITH_OPENSSL
	sshbuf_getput_crypto_tests();
#endif
	sshbuf_misc_tests();
	sshbuf_fuzz_tests();
	sshbuf_getput_fuzz_tests();
	sshbuf_fixed();
}

শূন্য
benchmarks(শূন্য)
{
	printf("no benchmarks\n");
}
