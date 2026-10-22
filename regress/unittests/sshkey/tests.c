/* 	$OpenBSD: tests.c,v 1.3 2026/06/29 07:46:22 djm Exp $ */
/*
 * Regress test for sshbuf.h buffer API
 *
 * Placed in the public domain
 */

#شامل "includes.h"

#شامل <stdio.h>

#شامل "../test_helper/test_helper.h"

تهی sshkey_tests(تهی);
تهی sshkey_file_tests(تهی);
تهی sshkey_fuzz_tests(تهی);
تهی sshkey_benchmarks(تهی);

تهی
tests(تهی)
{
	sshkey_tests();
	sshkey_file_tests();
	sshkey_fuzz_tests();
}

تهی
benchmarks(تهی)
{
	printf("\n");
	sshkey_benchmarks();
}
