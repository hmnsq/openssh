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

خالی test_parse(خالی);
خالی test_convtime(خالی);
خالی test_expand(خالی);
خالی test_argv(خالی);
خالی test_strdelim(خالی);
خالی test_hpdelim(خالی);
خالی test_ptimeout(خالی);
خالی test_xextendf(خالی);
خالی test_misc(خالی);

خالی
tests(خالی)
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

خالی
benchmarks(خالی)
{
	لکھو("no benchmarks\n");
}
