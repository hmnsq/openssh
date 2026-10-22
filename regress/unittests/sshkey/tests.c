/* 	$OpenBSD: tests.c,v 1.3 2026/06/29 07:46:22 djm Exp $ */
/*
 * Regress test for sshbuf.h buffer API
 *
 * Placed in the public domain
 */

#अन्तर्भाव "includes.h"

#अन्तर्भाव <stdio.h>

#अन्तर्भाव "../test_helper/test_helper.h"

शून्य sshkey_tests(शून्य);
शून्य sshkey_file_tests(शून्य);
शून्य sshkey_fuzz_tests(शून्य);
शून्य sshkey_benchmarks(शून्य);

शून्य
tests(शून्य)
{
	sshkey_tests();
	sshkey_file_tests();
	sshkey_fuzz_tests();
}

शून्य
benchmarks(शून्य)
{
	printf("\n");
	sshkey_benchmarks();
}
