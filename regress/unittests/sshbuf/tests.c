/* 	$OpenBSD: tests.c,v 1.2 2025/04/15 04:00:42 djm Exp $ */
/*
 * Regress test for sshbuf.h buffer API
 *
 * Placed in the public domain
 */

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <stdio.h>

#અન્તર્ભાવ "../test_helper/test_helper.h"

શૂન્ય sshbuf_tests(શૂન્ય);
શૂન્ય sshbuf_getput_basic_tests(શૂન્ય);
શૂન્ય sshbuf_getput_crypto_tests(શૂન્ય);
શૂન્ય sshbuf_misc_tests(શૂન્ય);
શૂન્ય sshbuf_fuzz_tests(શૂન્ય);
શૂન્ય sshbuf_getput_fuzz_tests(શૂન્ય);
શૂન્ય sshbuf_fixed(શૂન્ય);

શૂન્ય
tests(શૂન્ય)
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

શૂન્ય
benchmarks(શૂન્ય)
{
	printf("no benchmarks\n");
}
