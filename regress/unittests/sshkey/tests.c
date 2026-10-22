/* 	$OpenBSD: tests.c,v 1.3 2026/06/29 07:46:22 djm Exp $ */
/*
 * Regress test for sshbuf.h buffer API
 *
 * Placed in the public domain
 */

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <stdio.h>

#ಅನ್ತರ್ಭಾವ "../test_helper/test_helper.h"

ಶೂನ್ಯ sshkey_tests(ಶೂನ್ಯ);
ಶೂನ್ಯ sshkey_file_tests(ಶೂನ್ಯ);
ಶೂನ್ಯ sshkey_fuzz_tests(ಶೂನ್ಯ);
ಶೂನ್ಯ sshkey_benchmarks(ಶೂನ್ಯ);

ಶೂನ್ಯ
tests(ಶೂನ್ಯ)
{
	sshkey_tests();
	sshkey_file_tests();
	sshkey_fuzz_tests();
}

ಶೂನ್ಯ
benchmarks(ಶೂನ್ಯ)
{
	printf("\n");
	sshkey_benchmarks();
}
