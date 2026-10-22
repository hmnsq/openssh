/* 	$OpenBSD: tests.c,v 1.4 2025/04/15 04:00:42 djm Exp $ */
/*
 * Placed in the public domain
 */

#شامل "includes.h"

#شامل <stdio.h>

#شامل "../test_helper/test_helper.h"

خالی kex_tests(خالی);
خالی kex_proposal_tests(خالی);
خالی kex_proposal_populate_tests(خالی);

خالی
tests(خالی)
{
	kex_tests();
	kex_proposal_tests();
	kex_proposal_populate_tests();
}

خالی
benchmarks(خالی)
{
	لکھو("\n");
	kex_tests();
}
