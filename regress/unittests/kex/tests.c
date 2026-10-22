/* 	$OpenBSD: tests.c,v 1.4 2025/04/15 04:00:42 djm Exp $ */
/*
 * Placed in the public domain
 */

#شامل "includes.h"

#شامل <stdio.h>

#شامل "../test_helper/test_helper.h"

تهی kex_tests(تهی);
تهی kex_proposal_tests(تهی);
تهی kex_proposal_populate_tests(تهی);

تهی
tests(تهی)
{
	kex_tests();
	kex_proposal_tests();
	kex_proposal_populate_tests();
}

تهی
benchmarks(تهی)
{
	printf("\n");
	kex_tests();
}
