/* 	$OpenBSD: tests.c,v 1.3 2026/06/29 07:46:22 djm Exp $ */
/*
 * Regress test for sshbuf.h buffer API
 *
 * Placed in the public domain
 */

#समावेश "includes.h"

#समावेश <stdio.h>

#समावेश "../test_helper/test_helper.h"

व्योम sshkey_tests(व्योम);
व्योम sshkey_file_tests(व्योम);
व्योम sshkey_fuzz_tests(व्योम);
व्योम sshkey_benchmarks(व्योम);

व्योम
tests(व्योम)
{
	sshkey_tests();
	sshkey_file_tests();
	sshkey_fuzz_tests();
}

व्योम
benchmarks(व्योम)
{
	म_लिखो("\n");
	sshkey_benchmarks();
}
