/* 	$OpenBSD: tests.c,v 1.2 2025/04/15 04:00:42 djm Exp $ */
/*
 * Regress test for known_hosts-related API.
 *
 * Placed in the public domain
 */

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <stdio.h>

#ଅନ୍ତର୍ଭାଵ "../test_helper/test_helper.h"

ଶୂନ୍ୟ tests(ଶୂନ୍ୟ);
ଶୂନ୍ୟ test_iterate(ଶୂନ୍ୟ); /* test_iterate.c */

ଶୂନ୍ୟ
tests(ଶୂନ୍ୟ)
{
	test_iterate();
}

ଶୂନ୍ୟ
benchmarks(ଶୂନ୍ୟ)
{
	printf("no benchmarks\n");
}
