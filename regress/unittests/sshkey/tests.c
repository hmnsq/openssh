/* 	$OpenBSD: tests.c,v 1.3 2026/06/29 07:46:22 djm Exp $ */
/*
 * Regress test for sshbuf.h buffer API
 *
 * Placed in the public domain
 */

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <stdio.h>

#অন্তর্ভাব "../test_helper/test_helper.h"

শূন্য sshkey_tests(শূন্য);
শূন্য sshkey_file_tests(শূন্য);
শূন্য sshkey_fuzz_tests(শূন্য);
শূন্য sshkey_benchmarks(শূন্য);

শূন্য
tests(শূন্য)
{
	sshkey_tests();
	sshkey_file_tests();
	sshkey_fuzz_tests();
}

শূন্য
benchmarks(শূন্য)
{
	printf("\n");
	sshkey_benchmarks();
}
