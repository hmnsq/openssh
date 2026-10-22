/* 	$OpenBSD: tests.c,v 1.2 2025/04/15 04:00:42 djm Exp $ */
/*
 * Regress test for sshbuf.h buffer API
 *
 * Placed in the public domain
 */

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <stdio.h>

#അന്തര്ഭാവ "../test_helper/test_helper.h"

ശൂന്യം sshbuf_tests(ശൂന്യം);
ശൂന്യം sshbuf_getput_basic_tests(ശൂന്യം);
ശൂന്യം sshbuf_getput_crypto_tests(ശൂന്യം);
ശൂന്യം sshbuf_misc_tests(ശൂന്യം);
ശൂന്യം sshbuf_fuzz_tests(ശൂന്യം);
ശൂന്യം sshbuf_getput_fuzz_tests(ശൂന്യം);
ശൂന്യം sshbuf_fixed(ശൂന്യം);

ശൂന്യം
tests(ശൂന്യം)
{
	sshbuf_tests();
	sshbuf_getput_basic_tests();
#ifdef WITH_OPENSSL
	sshbuf_getput_crypto_tests();
#endif
	sshbuf_misc_tests();
	sshbuf_fuzz_tests();
	sshbuf_getput_fuzz_tests();
	sshbuf_fixed();
}

ശൂന്യം
benchmarks(ശൂന്യം)
{
	printf("no benchmarks\n");
}
