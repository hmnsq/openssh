/* 	$OpenBSD: tests.c,v 1.4 2025/04/15 04:00:42 djm Exp $ */
/*
 * Placed in the public domain
 */

#ضمن "includes.h"

#ضمن <stdio.h>

#ضمن "../test_helper/test_helper.h"

فراغ kex_tests(فراغ);
فراغ kex_proposal_tests(فراغ);
فراغ kex_proposal_populate_tests(فراغ);

فراغ
tests(فراغ)
{
	kex_tests();
	kex_proposal_tests();
	kex_proposal_populate_tests();
}

فراغ
benchmarks(فراغ)
{
	چاپ_کن("\n");
	kex_tests();
}
