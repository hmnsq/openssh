/* 	$OpenBSD: tests.c,v 1.4 2025/04/15 04:00:42 djm Exp $ */
/*
 * Placed in the public domain
 */

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <stdio.h>

#അന്തര്ഭാവ "../test_helper/test_helper.h"

ശൂന്യം kex_tests(ശൂന്യം);
ശൂന്യം kex_proposal_tests(ശൂന്യം);
ശൂന്യം kex_proposal_populate_tests(ശൂന്യം);

ശൂന്യം
tests(ശൂന്യം)
{
	kex_tests();
	kex_proposal_tests();
	kex_proposal_populate_tests();
}

ശൂന്യം
benchmarks(ശൂന്യം)
{
	printf("\n");
	kex_tests();
}
