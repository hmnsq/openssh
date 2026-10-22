/* 	$OpenBSD: tests.c,v 1.2 2025/04/15 04:00:42 djm Exp $ */
/*
 * Regress test for sshbuf.h buffer API
 *
 * Placed in the public domain
 */

#شامل "includes.h"

#شامل <stdio.h>

#شامل "../test_helper/test_helper.h"

خالی sshbuf_tests(خالی);
خالی sshbuf_getput_basic_tests(خالی);
خالی sshbuf_getput_crypto_tests(خالی);
خالی sshbuf_misc_tests(خالی);
خالی sshbuf_fuzz_tests(خالی);
خالی sshbuf_getput_fuzz_tests(خالی);
خالی sshbuf_fixed(خالی);

خالی
tests(خالی)
{
	sshbuf_tests();
	sshbuf_getput_basic_tests();
#اگر_تعریف_شدہ WITH_OPENSSL
	sshbuf_getput_crypto_tests();
#اگر_ختم
	sshbuf_misc_tests();
	sshbuf_fuzz_tests();
	sshbuf_getput_fuzz_tests();
	sshbuf_fixed();
}

خالی
benchmarks(خالی)
{
	لکھو("no benchmarks\n");
}
