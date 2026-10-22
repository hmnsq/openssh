/* 	$OpenBSD: tests.c,v 1.13 2025/09/04 00:34:17 djm Exp $ */
/*
 * Regress test for misc helper functions.
 *
 * Placed in the public domain.
 */

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <stdint.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <string.h>

#અન્તર્ભાવ "../test_helper/test_helper.h"

#અન્તર્ભાવ "log.h"
#અન્તર્ભાવ "misc.h"

શૂન્ય test_parse(શૂન્ય);
શૂન્ય test_convtime(શૂન્ય);
શૂન્ય test_expand(શૂન્ય);
શૂન્ય test_argv(શૂન્ય);
શૂન્ય test_strdelim(શૂન્ય);
શૂન્ય test_hpdelim(શૂન્ય);
શૂન્ય test_ptimeout(શૂન્ય);
શૂન્ય test_xextendf(શૂન્ય);
શૂન્ય test_misc(શૂન્ય);

શૂન્ય
tests(શૂન્ય)
{
	test_parse();
	test_convtime();
	test_expand();
	test_argv();
	test_strdelim();
	test_hpdelim();
	test_ptimeout();
	test_xextendf();
	test_misc();
}

શૂન્ય
benchmarks(શૂન્ય)
{
	printf("no benchmarks\n");
}
