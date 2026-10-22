/* 	$OpenBSD: tests.c,v 1.4 2025/04/15 04:00:42 djm Exp $ */
/*
 * Placed in the public domain
 */

#समावेश "includes.h"

#समावेश <stdio.h>

#समावेश "../test_helper/test_helper.h"

व्योम kex_tests(व्योम);
व्योम kex_proposal_tests(व्योम);
व्योम kex_proposal_populate_tests(व्योम);

व्योम
tests(व्योम)
{
	kex_tests();
	kex_proposal_tests();
	kex_proposal_populate_tests();
}

व्योम
benchmarks(व्योम)
{
	म_लिखो("\n");
	kex_tests();
}
