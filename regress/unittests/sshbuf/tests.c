/* 	$OpenBSD: tests.c,v 1.2 2025/04/15 04:00:42 djm Exp $ */
/*
 * Regress test for sshbuf.h buffer API
 *
 * Placed in the public domain
 */

#ضمن "includes.h"

#ضمن <stdio.h>

#ضمن "../test_helper/test_helper.h"

فراغ sshbuf_tests(فراغ);
فراغ sshbuf_getput_basic_tests(فراغ);
فراغ sshbuf_getput_crypto_tests(فراغ);
فراغ sshbuf_misc_tests(فراغ);
فراغ sshbuf_fuzz_tests(فراغ);
فراغ sshbuf_getput_fuzz_tests(فراغ);
فراغ sshbuf_fixed(فراغ);

فراغ
tests(فراغ)
{
	sshbuf_tests();
	sshbuf_getput_basic_tests();
#که_تعریف_شوی WITH_OPENSSL
	sshbuf_getput_crypto_tests();
#د_که_پای
	sshbuf_misc_tests();
	sshbuf_fuzz_tests();
	sshbuf_getput_fuzz_tests();
	sshbuf_fixed();
}

فراغ
benchmarks(فراغ)
{
	چاپ_کړه("no benchmarks\n");
}
