/* 	$OpenBSD: tests.c,v 1.2 2025/04/15 04:00:42 djm Exp $ */
/*
 * Regress test for sshbuf.h buffer API
 *
 * Placed in the public domain
 */

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "../test_helper/test_helper.h"

ਖਾਲੀ sshbuf_tests(ਖਾਲੀ);
ਖਾਲੀ sshbuf_getput_basic_tests(ਖਾਲੀ);
ਖਾਲੀ sshbuf_getput_crypto_tests(ਖਾਲੀ);
ਖਾਲੀ sshbuf_misc_tests(ਖਾਲੀ);
ਖਾਲੀ sshbuf_fuzz_tests(ਖਾਲੀ);
ਖਾਲੀ sshbuf_getput_fuzz_tests(ਖਾਲੀ);
ਖਾਲੀ sshbuf_fixed(ਖਾਲੀ);

ਖਾਲੀ
tests(ਖਾਲੀ)
{
	sshbuf_tests();
	sshbuf_getput_basic_tests();
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
	sshbuf_getput_crypto_tests();
#ਜੇ_ਅੰਤ
	sshbuf_misc_tests();
	sshbuf_fuzz_tests();
	sshbuf_getput_fuzz_tests();
	sshbuf_fixed();
}

ਖਾਲੀ
benchmarks(ਖਾਲੀ)
{
	ਲਿਖੋ("no benchmarks\n");
}
