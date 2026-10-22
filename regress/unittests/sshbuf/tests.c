/* 	$OpenBSD: tests.c,v 1.2 2025/04/15 04:00:42 djm Exp $ */
/*
 * Regress test for sshbuf.h buffer API
 *
 * Placed in the public domain
 */

#అన్తర్భావ "includes.h"

#అన్తర్భావ <stdio.h>

#అన్తర్భావ "../test_helper/test_helper.h"

శూన్య sshbuf_tests(శూన్య);
శూన్య sshbuf_getput_basic_tests(శూన్య);
శూన్య sshbuf_getput_crypto_tests(శూన్య);
శూన్య sshbuf_misc_tests(శూన్య);
శూన్య sshbuf_fuzz_tests(శూన్య);
శూన్య sshbuf_getput_fuzz_tests(శూన్య);
శూన్య sshbuf_fixed(శూన్య);

శూన్య
tests(శూన్య)
{
	sshbuf_tests();
	sshbuf_getput_basic_tests();
#నిర్వచితమైతే WITH_OPENSSL
	sshbuf_getput_crypto_tests();
#అయితే_ముగింపు
	sshbuf_misc_tests();
	sshbuf_fuzz_tests();
	sshbuf_getput_fuzz_tests();
	sshbuf_fixed();
}

శూన్య
benchmarks(శూన్య)
{
	రాయి("no benchmarks\n");
}
