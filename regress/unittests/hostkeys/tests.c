/* 	$OpenBSD: tests.c,v 1.2 2025/04/15 04:00:42 djm Exp $ */
/*
 * Regress test for known_hosts-related API.
 *
 * Placed in the public domain
 */

#समावेश "includes.h"

#समावेश <stdio.h>

#समावेश "../test_helper/test_helper.h"

व्योम tests(व्योम);
व्योम test_iterate(व्योम); /* test_iterate.c */

व्योम
tests(व्योम)
{
	test_iterate();
}

व्योम
benchmarks(व्योम)
{
	म_लिखो("no benchmarks\n");
}
