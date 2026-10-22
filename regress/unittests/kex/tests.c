/* 	$OpenBSD: tests.c,v 1.4 2025/04/15 04:00:42 djm Exp $ */
/*
 * Placed in the public domain
 */

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <stdio.h>

#அந்தர்பாவ "../test_helper/test_helper.h"

வெறுமை kex_tests(வெறுமை);
வெறுமை kex_proposal_tests(வெறுமை);
வெறுமை kex_proposal_populate_tests(வெறுமை);

வெறுமை
tests(வெறுமை)
{
	kex_tests();
	kex_proposal_tests();
	kex_proposal_populate_tests();
}

வெறுமை
benchmarks(வெறுமை)
{
	printf("\n");
	kex_tests();
}
