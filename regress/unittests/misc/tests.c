/* 	$OpenBSD: tests.c,v 1.13 2025/09/04 00:34:17 djm Exp $ */
/*
 * Regress test for misc helper functions.
 *
 * Placed in the public domain.
 */

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <sys/types.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <stdint.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <string.h>

#ଅନ୍ତର୍ଭାଵ "../test_helper/test_helper.h"

#ଅନ୍ତର୍ଭାଵ "log.h"
#ଅନ୍ତର୍ଭାଵ "misc.h"

ଶୂନ୍ୟ test_parse(ଶୂନ୍ୟ);
ଶୂନ୍ୟ test_convtime(ଶୂନ୍ୟ);
ଶୂନ୍ୟ test_expand(ଶୂନ୍ୟ);
ଶୂନ୍ୟ test_argv(ଶୂନ୍ୟ);
ଶୂନ୍ୟ test_strdelim(ଶୂନ୍ୟ);
ଶୂନ୍ୟ test_hpdelim(ଶୂନ୍ୟ);
ଶୂନ୍ୟ test_ptimeout(ଶୂନ୍ୟ);
ଶୂନ୍ୟ test_xextendf(ଶୂନ୍ୟ);
ଶୂନ୍ୟ test_misc(ଶୂନ୍ୟ);

ଶୂନ୍ୟ
tests(ଶୂନ୍ୟ)
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

ଶୂନ୍ୟ
benchmarks(ଶୂନ୍ୟ)
{
	printf("no benchmarks\n");
}
