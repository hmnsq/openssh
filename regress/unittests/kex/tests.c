/* 	$OpenBSD: tests.c,v 1.4 2025/04/15 04:00:42 djm Exp $ */
/*
 * Placed in the public domain
 */

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "../test_helper/test_helper.h"

ਖਾਲੀ kex_tests(ਖਾਲੀ);
ਖਾਲੀ kex_proposal_tests(ਖਾਲੀ);
ਖਾਲੀ kex_proposal_populate_tests(ਖਾਲੀ);

ਖਾਲੀ
tests(ਖਾਲੀ)
{
	kex_tests();
	kex_proposal_tests();
	kex_proposal_populate_tests();
}

ਖਾਲੀ
benchmarks(ਖਾਲੀ)
{
	ਲਿਖੋ("\n");
	kex_tests();
}
