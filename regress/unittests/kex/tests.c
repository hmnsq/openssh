/* 	$OpenBSD: tests.c,v 1.4 2025/04/15 04:00:42 djm Exp $ */
/*
 * Placed in the public domain
 */

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <stdio.h>

#অন্তর্ভাব "../test_helper/test_helper.h"

শূন্য kex_tests(শূন্য);
শূন্য kex_proposal_tests(শূন্য);
শূন্য kex_proposal_populate_tests(শূন্য);

শূন্য
tests(শূন্য)
{
	kex_tests();
	kex_proposal_tests();
	kex_proposal_populate_tests();
}

শূন্য
benchmarks(শূন্য)
{
	printf("\n");
	kex_tests();
}
