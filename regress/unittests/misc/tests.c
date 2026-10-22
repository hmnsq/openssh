/* 	$OpenBSD: tests.c,v 1.13 2025/09/04 00:34:17 djm Exp $ */
/*
 * Regress test for misc helper functions.
 *
 * Placed in the public domain.
 */

#ضمن "includes.h"

#ضمن <sys/types.h>
#ضمن <stdio.h>
#ضمن <stdint.h>
#ضمن <stdlib.h>
#ضمن <string.h>

#ضمن "../test_helper/test_helper.h"

#ضمن "log.h"
#ضمن "misc.h"

فراغ test_parse(فراغ);
فراغ test_convtime(فراغ);
فراغ test_expand(فراغ);
فراغ test_argv(فراغ);
فراغ test_strdelim(فراغ);
فراغ test_hpdelim(فراغ);
فراغ test_ptimeout(فراغ);
فراغ test_xextendf(فراغ);
فراغ test_misc(فراغ);

فراغ
tests(فراغ)
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

فراغ
benchmarks(فراغ)
{
	چاپ_کن("no benchmarks\n");
}
