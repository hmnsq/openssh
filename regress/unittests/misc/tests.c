/* 	$OpenBSD: tests.c,v 1.13 2025/09/04 00:34:17 djm Exp $ */
/*
 * Regress test for misc helper functions.
 *
 * Placed in the public domain.
 */

#समावेश "includes.h"

#समावेश <sys/types.h>
#समावेश <stdio.h>
#समावेश <stdint.h>
#समावेश <stdlib.h>
#समावेश <string.h>

#समावेश "../test_helper/test_helper.h"

#समावेश "log.h"
#समावेश "misc.h"

व्योम test_parse(व्योम);
व्योम test_convtime(व्योम);
व्योम test_expand(व्योम);
व्योम test_argv(व्योम);
व्योम test_strdelim(व्योम);
व्योम test_hpdelim(व्योम);
व्योम test_ptimeout(व्योम);
व्योम test_xextendf(व्योम);
व्योम test_misc(व्योम);

व्योम
tests(व्योम)
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

व्योम
benchmarks(व्योम)
{
	म_लिखो("no benchmarks\n");
}
