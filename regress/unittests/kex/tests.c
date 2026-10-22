/* 	$OpenBSD: tests.c,v 1.4 2025/04/15 04:00:42 djm Exp $ */
/*
 * Placed in the public domain
 */

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <stdio.h>

#અન્તર્ભાવ "../test_helper/test_helper.h"

શૂન્ય kex_tests(શૂન્ય);
શૂન્ય kex_proposal_tests(શૂન્ય);
શૂન્ય kex_proposal_populate_tests(શૂન્ય);

શૂન્ય
tests(શૂન્ય)
{
	kex_tests();
	kex_proposal_tests();
	kex_proposal_populate_tests();
}

શૂન્ય
benchmarks(શૂન્ય)
{
	printf("\n");
	kex_tests();
}
