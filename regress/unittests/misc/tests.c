/* 	$OpenBSD: tests.c,v 1.13 2025/09/04 00:34:17 djm Exp $ */
/*
 * Regress test for misc helper functions.
 *
 * Placed in the public domain.
 */

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <stdint.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <string.h>

#അന്തര്ഭാവ "../test_helper/test_helper.h"

#അന്തര്ഭാവ "log.h"
#അന്തര്ഭാവ "misc.h"

ശൂന്യം test_parse(ശൂന്യം);
ശൂന്യം test_convtime(ശൂന്യം);
ശൂന്യം test_expand(ശൂന്യം);
ശൂന്യം test_argv(ശൂന്യം);
ശൂന്യം test_strdelim(ശൂന്യം);
ശൂന്യം test_hpdelim(ശൂന്യം);
ശൂന്യം test_ptimeout(ശൂന്യം);
ശൂന്യം test_xextendf(ശൂന്യം);
ശൂന്യം test_misc(ശൂന്യം);

ശൂന്യം
tests(ശൂന്യം)
{
	test_parse();
	test_convtime();
	test_expand();
	test_argv();
	test_strdelim();
	test_hpdelim();
	test_ptimeout();
	test_xextendf();
	test_misc();
}

ശൂന്യം
benchmarks(ശൂന്യം)
{
	printf("no benchmarks\n");
}
