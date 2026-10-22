/* 	$OpenBSD: tests.c,v 1.2 2025/04/15 04:00:42 djm Exp $ */
/*
 * Regress test for sshbuf.h buffer API
 *
 * Placed in the public domain
 */

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <stdio.h>

#அந்தர்பாவ "../test_helper/test_helper.h"

வெறுமை sshbuf_tests(வெறுமை);
வெறுமை sshbuf_getput_basic_tests(வெறுமை);
வெறுமை sshbuf_getput_crypto_tests(வெறுமை);
வெறுமை sshbuf_misc_tests(வெறுமை);
வெறுமை sshbuf_fuzz_tests(வெறுமை);
வெறுமை sshbuf_getput_fuzz_tests(வெறுமை);
வெறுமை sshbuf_fixed(வெறுமை);

வெறுமை
tests(வெறுமை)
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

வெறுமை
benchmarks(வெறுமை)
{
	printf("no benchmarks\n");
}
