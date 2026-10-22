/* 	$OpenBSD: tests.c,v 1.2 2025/04/15 04:00:42 djm Exp $ */
/*
 * Regress test for known_hosts-related API.
 *
 * Placed in the public domain
 */

#అన్తర్భావ "includes.h"

#అన్తర్భావ <stdio.h>

#అన్తర్భావ "../test_helper/test_helper.h"

శూన్య tests(శూన్య);
శూన్య test_iterate(శూన్య); /* test_iterate.c */

శూన్య
tests(శూన్య)
{
	test_iterate();
}

శూన్య
benchmarks(శూన్య)
{
	రాయి("no benchmarks\n");
}
