/* 	$OpenBSD: tests.c,v 1.3 2026/06/29 07:46:22 djm Exp $ */
/*
 * Regress test for sshbuf.h buffer API
 *
 * Placed in the public domain
 */

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <stdio.h>

#ଅନ୍ତର୍ଭାଵ "../test_helper/test_helper.h"

ଶୂନ୍ୟ sshkey_tests(ଶୂନ୍ୟ);
ଶୂନ୍ୟ sshkey_file_tests(ଶୂନ୍ୟ);
ଶୂନ୍ୟ sshkey_fuzz_tests(ଶୂନ୍ୟ);
ଶୂନ୍ୟ sshkey_benchmarks(ଶୂନ୍ୟ);

ଶୂନ୍ୟ
tests(ଶୂନ୍ୟ)
{
	sshkey_tests();
	sshkey_file_tests();
	sshkey_fuzz_tests();
}

ଶୂନ୍ୟ
benchmarks(ଶୂନ୍ୟ)
{
	printf("\n");
	sshkey_benchmarks();
}
