/* 	$OpenBSD: tests.c,v 1.3 2026/06/29 07:46:22 djm Exp $ */
/*
 * Regress test for sshbuf.h buffer API
 *
 * Placed in the public domain
 */

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <stdio.h>

#அந்தர்பாவ "../test_helper/test_helper.h"

வெறுமை sshkey_tests(வெறுமை);
வெறுமை sshkey_file_tests(வெறுமை);
வெறுமை sshkey_fuzz_tests(வெறுமை);
வெறுமை sshkey_benchmarks(வெறுமை);

வெறுமை
tests(வெறுமை)
{
	sshkey_tests();
	sshkey_file_tests();
	sshkey_fuzz_tests();
}

வெறுமை
benchmarks(வெறுமை)
{
	printf("\n");
	sshkey_benchmarks();
}
