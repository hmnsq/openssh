/* 	$OpenBSD: tests.c,v 1.2 2025/04/15 04:00:42 djm Exp $ */
/*
 * Regress test for known_hosts-related API.
 *
 * Placed in the public domain
 */

#ضمن "includes.h"

#ضمن <stdio.h>

#ضمن "../test_helper/test_helper.h"

فراغ tests(فراغ);
فراغ test_iterate(فراغ); /* test_iterate.c */

فراغ
tests(فراغ)
{
	test_iterate();
}

فراغ
benchmarks(فراغ)
{
	printf("no benchmarks\n");
}
