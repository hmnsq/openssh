/* 	$OpenBSD: tests.c,v 1.2 2025/04/15 04:00:42 djm Exp $ */
/*
 * Regress test for known_hosts-related API.
 *
 * Placed in the public domain
 */

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <stdio.h>

#ಅನ್ತರ್ಭಾವ "../test_helper/test_helper.h"

ಶೂನ್ಯ tests(ಶೂನ್ಯ);
ಶೂನ್ಯ test_iterate(ಶೂನ್ಯ); /* test_iterate.c */

ಶೂನ್ಯ
tests(ಶೂನ್ಯ)
{
	test_iterate();
}

ಶೂನ್ಯ
benchmarks(ಶೂನ್ಯ)
{
	ಬರೆ("no benchmarks\n");
}
