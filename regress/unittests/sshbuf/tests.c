/* 	$OpenBSD: tests.c,v 1.2 2025/04/15 04:00:42 djm Exp $ */
/*
 * Regress test for sshbuf.h buffer API
 *
 * Placed in the public domain
 */

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <stdio.h>

#ଅନ୍ତର୍ଭାଵ "../test_helper/test_helper.h"

ଶୂନ୍ୟ sshbuf_tests(ଶୂନ୍ୟ);
ଶୂନ୍ୟ sshbuf_getput_basic_tests(ଶୂନ୍ୟ);
ଶୂନ୍ୟ sshbuf_getput_crypto_tests(ଶୂନ୍ୟ);
ଶୂନ୍ୟ sshbuf_misc_tests(ଶୂନ୍ୟ);
ଶୂନ୍ୟ sshbuf_fuzz_tests(ଶୂନ୍ୟ);
ଶୂନ୍ୟ sshbuf_getput_fuzz_tests(ଶୂନ୍ୟ);
ଶୂନ୍ୟ sshbuf_fixed(ଶୂନ୍ୟ);

ଶୂନ୍ୟ
tests(ଶୂନ୍ୟ)
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

ଶୂନ୍ୟ
benchmarks(ଶୂନ୍ୟ)
{
	printf("no benchmarks\n");
}
