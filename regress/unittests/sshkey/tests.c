/* 	$OpenBSD: tests.c,v 1.3 2026/06/29 07:46:22 djm Exp $ */
/*
 * Regress test for sshbuf.h buffer API
 *
 * Placed in the public domain
 */

#شامل "includes.h"

#شامل <stdio.h>

#شامل "../test_helper/test_helper.h"

خالی sshkey_tests(خالی);
خالی sshkey_file_tests(خالی);
خالی sshkey_fuzz_tests(خالی);
خالی sshkey_benchmarks(خالی);

خالی
tests(خالی)
{
	sshkey_tests();
	sshkey_file_tests();
	sshkey_fuzz_tests();
}

خالی
benchmarks(خالی)
{
	لکھو("\n");
	sshkey_benchmarks();
}
