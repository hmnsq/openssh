/* 	$OpenBSD: tests.c,v 1.3 2026/06/29 07:46:22 djm Exp $ */
/*
 * Regress test for sshbuf.h buffer API
 *
 * Placed in the public domain
 */

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "../test_helper/test_helper.h"

ਖਾਲੀ sshkey_tests(ਖਾਲੀ);
ਖਾਲੀ sshkey_file_tests(ਖਾਲੀ);
ਖਾਲੀ sshkey_fuzz_tests(ਖਾਲੀ);
ਖਾਲੀ sshkey_benchmarks(ਖਾਲੀ);

ਖਾਲੀ
tests(ਖਾਲੀ)
{
	sshkey_tests();
	sshkey_file_tests();
	sshkey_fuzz_tests();
}

ਖਾਲੀ
benchmarks(ਖਾਲੀ)
{
	ਲਿਖੋ("\n");
	sshkey_benchmarks();
}
