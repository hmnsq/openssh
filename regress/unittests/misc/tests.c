/* 	$OpenBSD: tests.c,v 1.13 2025/09/04 00:34:17 djm Exp $ */
/*
 * Regress test for misc helper functions.
 *
 * Placed in the public domain.
 */

#شامل "includes.h"

#شامل <sys/types.h>
#شامل <stdio.h>
#شامل <stdint.h>
#شامل <stdlib.h>
#شامل <string.h>

#شامل "../test_helper/test_helper.h"

#شامل "log.h"
#شامل "misc.h"

تهی test_parse(تهی);
تهی test_convtime(تهی);
تهی test_expand(تهی);
تهی test_argv(تهی);
تهی test_strdelim(تهی);
تهی test_hpdelim(تهی);
تهی test_ptimeout(تهی);
تهی test_xextendf(تهی);
تهی test_misc(تهی);

تهی
tests(تهی)
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

تهی
benchmarks(تهی)
{
	printf("no benchmarks\n");
}
