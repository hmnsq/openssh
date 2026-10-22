/* 	$OpenBSD: tests.c,v 1.2 2025/04/15 04:00:42 djm Exp $ */
/*
 * Regress test for known_hosts-related API.
 *
 * Placed in the public domain
 */

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <stdio.h>

#અન્તર્ભાવ "../test_helper/test_helper.h"

શૂન્ય tests(શૂન્ય);
શૂન્ય test_iterate(શૂન્ય); /* test_iterate.c */

શૂન્ય
tests(શૂન્ય)
{
	test_iterate();
}

શૂન્ય
benchmarks(શૂન્ય)
{
	printf("no benchmarks\n");
}
