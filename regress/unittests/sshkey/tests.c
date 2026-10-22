/* 	$OpenBSD: tests.c,v 1.3 2026/06/29 07:46:22 djm Exp $ */
/*
 * Regress test for sshbuf.h buffer API
 *
 * Placed in the public domain
 */

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <stdio.h>

#અન્તર્ભાવ "../test_helper/test_helper.h"

શૂન્ય sshkey_tests(શૂન્ય);
શૂન્ય sshkey_file_tests(શૂન્ય);
શૂન્ય sshkey_fuzz_tests(શૂન્ય);
શૂન્ય sshkey_benchmarks(શૂન્ય);

શૂન્ય
tests(શૂન્ય)
{
	sshkey_tests();
	sshkey_file_tests();
	sshkey_fuzz_tests();
}

શૂન્ય
benchmarks(શૂન્ય)
{
	printf("\n");
	sshkey_benchmarks();
}
