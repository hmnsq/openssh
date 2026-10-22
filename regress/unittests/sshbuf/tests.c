/* 	$OpenBSD: tests.c,v 1.2 2025/04/15 04:00:42 djm Exp $ */
/*
 * Regress test for sshbuf.h buffer API
 *
 * Placed in the public domain
 */

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <stdio.h>

#ಅನ್ತರ್ಭಾವ "../test_helper/test_helper.h"

ಶೂನ್ಯ sshbuf_tests(ಶೂನ್ಯ);
ಶೂನ್ಯ sshbuf_getput_basic_tests(ಶೂನ್ಯ);
ಶೂನ್ಯ sshbuf_getput_crypto_tests(ಶೂನ್ಯ);
ಶೂನ್ಯ sshbuf_misc_tests(ಶೂನ್ಯ);
ಶೂನ್ಯ sshbuf_fuzz_tests(ಶೂನ್ಯ);
ಶೂನ್ಯ sshbuf_getput_fuzz_tests(ಶೂನ್ಯ);
ಶೂನ್ಯ sshbuf_fixed(ಶೂನ್ಯ);

ಶೂನ್ಯ
tests(ಶೂನ್ಯ)
{
	sshbuf_tests();
	sshbuf_getput_basic_tests();
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
	sshbuf_getput_crypto_tests();
#ಆದರೆ_ಅಂತ್ಯ
	sshbuf_misc_tests();
	sshbuf_fuzz_tests();
	sshbuf_getput_fuzz_tests();
	sshbuf_fixed();
}

ಶೂನ್ಯ
benchmarks(ಶೂನ್ಯ)
{
	ಬರೆ("no benchmarks\n");
}
