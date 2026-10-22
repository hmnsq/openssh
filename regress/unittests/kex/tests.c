/* 	$OpenBSD: tests.c,v 1.4 2025/04/15 04:00:42 djm Exp $ */
/*
 * Placed in the public domain
 */

#अन्तर्भाव "includes.h"

#अन्तर्भाव <stdio.h>

#अन्तर्भाव "../test_helper/test_helper.h"

शून्य kex_tests(शून्य);
शून्य kex_proposal_tests(शून्य);
शून्य kex_proposal_populate_tests(शून्य);

शून्य
tests(शून्य)
{
	kex_tests();
	kex_proposal_tests();
	kex_proposal_populate_tests();
}

शून्य
benchmarks(शून्य)
{
	printf("\n");
	kex_tests();
}
