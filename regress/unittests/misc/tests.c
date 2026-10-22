/* 	$OpenBSD: tests.c,v 1.13 2025/09/04 00:34:17 djm Exp $ */
/*
 * Regress test for misc helper functions.
 *
 * Placed in the public domain.
 */

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stdint.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>

#ಅನ್ತರ್ಭಾವ "../test_helper/test_helper.h"

#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "misc.h"

ಶೂನ್ಯ test_parse(ಶೂನ್ಯ);
ಶೂನ್ಯ test_convtime(ಶೂನ್ಯ);
ಶೂನ್ಯ test_expand(ಶೂನ್ಯ);
ಶೂನ್ಯ test_argv(ಶೂನ್ಯ);
ಶೂನ್ಯ test_strdelim(ಶೂನ್ಯ);
ಶೂನ್ಯ test_hpdelim(ಶೂನ್ಯ);
ಶೂನ್ಯ test_ptimeout(ಶೂನ್ಯ);
ಶೂನ್ಯ test_xextendf(ಶೂನ್ಯ);
ಶೂನ್ಯ test_misc(ಶೂನ್ಯ);

ಶೂನ್ಯ
tests(ಶೂನ್ಯ)
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

ಶೂನ್ಯ
benchmarks(ಶೂನ್ಯ)
{
	ಬರೆ("no benchmarks\n");
}
