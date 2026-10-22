/* 	$OpenBSD: tests.c,v 1.2 2025/04/15 04:00:42 djm Exp $ */
/*
 * Regress test for known_hosts-related API.
 *
 * Placed in the public domain
 */

#شامل "includes.h"

#شامل <stdio.h>

#شامل "../test_helper/test_helper.h"

تهی tests(تهی);
تهی test_iterate(تهی); /* test_iterate.c */

تهی
tests(تهی)
{
	test_iterate();
}

تهی
benchmarks(تهی)
{
	printf("no benchmarks\n");
}
