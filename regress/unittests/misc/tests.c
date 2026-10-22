/* 	$OpenBSD: tests.c,v 1.13 2025/09/04 00:34:17 djm Exp $ */
/*
 * Regress test for misc helper functions.
 *
 * Placed in the public domain.
 */

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdint.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "../test_helper/test_helper.h"

#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "misc.h"

ਖਾਲੀ test_parse(ਖਾਲੀ);
ਖਾਲੀ test_convtime(ਖਾਲੀ);
ਖਾਲੀ test_expand(ਖਾਲੀ);
ਖਾਲੀ test_argv(ਖਾਲੀ);
ਖਾਲੀ test_strdelim(ਖਾਲੀ);
ਖਾਲੀ test_hpdelim(ਖਾਲੀ);
ਖਾਲੀ test_ptimeout(ਖਾਲੀ);
ਖਾਲੀ test_xextendf(ਖਾਲੀ);
ਖਾਲੀ test_misc(ਖਾਲੀ);

ਖਾਲੀ
tests(ਖਾਲੀ)
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

ਖਾਲੀ
benchmarks(ਖਾਲੀ)
{
	ਲਿਖੋ("no benchmarks\n");
}
