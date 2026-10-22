/* 	$OpenBSD: tests.c,v 1.2 2025/04/15 04:00:42 djm Exp $ */
/*
 * Regress test for known_hosts-related API.
 *
 * Placed in the public domain
 */

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <stdio.h>

#அந்தர்பாவ "../test_helper/test_helper.h"

வெறுமை tests(வெறுமை);
வெறுமை test_iterate(வெறுமை); /* test_iterate.c */

வெறுமை
tests(வெறுமை)
{
	test_iterate();
}

வெறுமை
benchmarks(வெறுமை)
{
	printf("no benchmarks\n");
}
