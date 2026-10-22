/* 	$OpenBSD: tests.c,v 1.2 2025/04/15 04:00:42 djm Exp $ */
/*
 * Regress test for known_hosts-related API.
 *
 * Placed in the public domain
 */

#অন্তর্ভাৱ "includes.h"

#অন্তর্ভাৱ <stdio.h>

#অন্তর্ভাৱ "../test_helper/test_helper.h"

শূন্য tests(শূন্য);
শূন্য test_iterate(শূন্য); /* test_iterate.c */

শূন্য
tests(শূন্য)
{
	test_iterate();
}

শূন্য
benchmarks(শূন্য)
{
	printf("no benchmarks\n");
}
