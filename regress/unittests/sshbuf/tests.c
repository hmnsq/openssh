/* 	$OpenBSD: tests.c,v 1.2 2025/04/15 04:00:42 djm Exp $ */
/*
 * Regress test for sshbuf.h buffer API
 *
 * Placed in the public domain
 */

#अन्तर्भाव "includes.h"

#अन्तर्भाव <stdio.h>

#अन्तर्भाव "../test_helper/test_helper.h"

शून्य sshbuf_tests(शून्य);
शून्य sshbuf_getput_basic_tests(शून्य);
शून्य sshbuf_getput_crypto_tests(शून्य);
शून्य sshbuf_misc_tests(शून्य);
शून्य sshbuf_fuzz_tests(शून्य);
शून्य sshbuf_getput_fuzz_tests(शून्य);
शून्य sshbuf_fixed(शून्य);

शून्य
tests(शून्य)
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

शून्य
benchmarks(शून्य)
{
	printf("no benchmarks\n");
}
