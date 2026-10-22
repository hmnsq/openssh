/* 	$OpenBSD: tests.c,v 1.4 2025/04/15 04:00:42 djm Exp $ */
/*
 * Placed in the public domain
 */

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <stdio.h>

#ଅନ୍ତର୍ଭାଵ "../test_helper/test_helper.h"

ଶୂନ୍ୟ kex_tests(ଶୂନ୍ୟ);
ଶୂନ୍ୟ kex_proposal_tests(ଶୂନ୍ୟ);
ଶୂନ୍ୟ kex_proposal_populate_tests(ଶୂନ୍ୟ);

ଶୂନ୍ୟ
tests(ଶୂନ୍ୟ)
{
	kex_tests();
	kex_proposal_tests();
	kex_proposal_populate_tests();
}

ଶୂନ୍ୟ
benchmarks(ଶୂନ୍ୟ)
{
	printf("\n");
	kex_tests();
}
