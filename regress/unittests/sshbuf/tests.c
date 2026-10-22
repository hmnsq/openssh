/* 	$OpenBSD: tests.c,v 1.2 2025/04/15 04:00:42 djm Exp $ */
/*
 * Regress test for sshbuf.h buffer API
 *
 * Placed in the public domain
 */

#شامل "includes.h"

#شامل <stdio.h>

#شامل "../test_helper/test_helper.h"

تهی sshbuf_tests(تهی);
تهی sshbuf_getput_basic_tests(تهی);
تهی sshbuf_getput_crypto_tests(تهی);
تهی sshbuf_misc_tests(تهی);
تهی sshbuf_fuzz_tests(تهی);
تهی sshbuf_getput_fuzz_tests(تهی);
تهی sshbuf_fixed(تهی);

تهی
tests(تهی)
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

تهی
benchmarks(تهی)
{
	printf("no benchmarks\n");
}
