/* 	$OpenBSD: tests.c,v 1.4 2025/04/15 04:00:42 djm Exp $ */
/*
 * Placed in the public domain
 */

#అన్తర్భావ "includes.h"

#అన్తర్భావ <stdio.h>

#అన్తర్భావ "../test_helper/test_helper.h"

శూన్య kex_tests(శూన్య);
శూన్య kex_proposal_tests(శూన్య);
శూన్య kex_proposal_populate_tests(శూన్య);

శూన్య
tests(శూన్య)
{
	kex_tests();
	kex_proposal_tests();
	kex_proposal_populate_tests();
}

శూన్య
benchmarks(శూన్య)
{
	రాయి("\n");
	kex_tests();
}
