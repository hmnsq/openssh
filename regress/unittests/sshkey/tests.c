/* 	$OpenBSD: tests.c,v 1.3 2026/06/29 07:46:22 djm Exp $ */
/*
 * Regress test for sshbuf.h buffer API
 *
 * Placed in the public domain
 */

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <stdio.h>

#അന്തര്ഭാവ "../test_helper/test_helper.h"

ശൂന്യം sshkey_tests(ശൂന്യം);
ശൂന്യം sshkey_file_tests(ശൂന്യം);
ശൂന്യം sshkey_fuzz_tests(ശൂന്യം);
ശൂന്യം sshkey_benchmarks(ശൂന്യം);

ശൂന്യം
tests(ശൂന്യം)
{
	sshkey_tests();
	sshkey_file_tests();
	sshkey_fuzz_tests();
}

ശൂന്യം
benchmarks(ശൂന്യം)
{
	printf("\n");
	sshkey_benchmarks();
}
