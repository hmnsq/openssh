/* 	$OpenBSD: tests.c,v 1.13 2025/09/04 00:34:17 djm Exp $ */
/*
 * Regress test for misc helper functions.
 *
 * Placed in the public domain.
 */

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <sys/types.h>
#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <stdint.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <string.h>

#অন্তর্ভাব "../test_helper/test_helper.h"

#অন্তর্ভাব "log.h"
#অন্তর্ভাব "misc.h"

শূন্য test_parse(শূন্য);
শূন্য test_convtime(শূন্য);
শূন্য test_expand(শূন্য);
শূন্য test_argv(শূন্য);
শূন্য test_strdelim(শূন্য);
শূন্য test_hpdelim(শূন্য);
শূন্য test_ptimeout(শূন্য);
শূন্য test_xextendf(শূন্য);
শূন্য test_misc(শূন্য);

শূন্য
tests(শূন্য)
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

শূন্য
benchmarks(শূন্য)
{
	printf("no benchmarks\n");
}
