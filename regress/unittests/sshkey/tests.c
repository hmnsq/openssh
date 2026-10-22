/* 	$OpenBSD: tests.c,v 1.3 2026/06/29 07:46:22 djm Exp $ */
/*
 * Regress test for sshbuf.h buffer API
 *
 * Placed in the public domain
 */

#అన్తర్భావ "includes.h"

#అన్తర్భావ <stdio.h>

#అన్తర్భావ "../test_helper/test_helper.h"

శూన్య sshkey_tests(శూన్య);
శూన్య sshkey_file_tests(శూన్య);
శూన్య sshkey_fuzz_tests(శూన్య);
శూన్య sshkey_benchmarks(శూన్య);

శూన్య
tests(శూన్య)
{
	sshkey_tests();
	sshkey_file_tests();
	sshkey_fuzz_tests();
}

శూన్య
benchmarks(శూన్య)
{
	రాయి("\n");
	sshkey_benchmarks();
}
