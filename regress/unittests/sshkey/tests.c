/* 	$OpenBSD: tests.c,v 1.3 2026/06/29 07:46:22 djm Exp $ */
/*
 * Regress test for sshbuf.h buffer API
 *
 * Placed in the public domain
 */

#ضمن "includes.h"

#ضمن <stdio.h>

#ضمن "../test_helper/test_helper.h"

فراغ sshkey_tests(فراغ);
فراغ sshkey_file_tests(فراغ);
فراغ sshkey_fuzz_tests(فراغ);
فراغ sshkey_benchmarks(فراغ);

فراغ
tests(فراغ)
{
	sshkey_tests();
	sshkey_file_tests();
	sshkey_fuzz_tests();
}

فراغ
benchmarks(فراغ)
{
	چاپ_کن("\n");
	sshkey_benchmarks();
}
