/* 	$OpenBSD: tests.c,v 1.4 2025/04/15 04:00:42 djm Exp $ */
/*
 * Placed in the public domain
 */

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <stdio.h>

#ಅನ್ತರ್ಭಾವ "../test_helper/test_helper.h"

ಶೂನ್ಯ kex_tests(ಶೂನ್ಯ);
ಶೂನ್ಯ kex_proposal_tests(ಶೂನ್ಯ);
ಶೂನ್ಯ kex_proposal_populate_tests(ಶೂನ್ಯ);

ಶೂನ್ಯ
tests(ಶೂನ್ಯ)
{
	kex_tests();
	kex_proposal_tests();
	kex_proposal_populate_tests();
}

ಶೂನ್ಯ
benchmarks(ಶೂನ್ಯ)
{
	ಬರೆ("\n");
	kex_tests();
}
