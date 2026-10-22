/* 	$OpenBSD: tests.c,v 1.2 2025/04/15 04:00:42 djm Exp $ */
/*
 * Regress test for known_hosts-related API.
 *
 * Placed in the public domain
 */

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "../test_helper/test_helper.h"

ਖਾਲੀ tests(ਖਾਲੀ);
ਖਾਲੀ test_iterate(ਖਾਲੀ); /* test_iterate.c */

ਖਾਲੀ
tests(ਖਾਲੀ)
{
	test_iterate();
}

ਖਾਲੀ
benchmarks(ਖਾਲੀ)
{
	ਲਿਖੋ("no benchmarks\n");
}
