/* 	$OpenBSD: tests.c,v 1.13 2025/09/04 00:34:17 djm Exp $ */
/*
 * Regress test for misc helper functions.
 *
 * Placed in the public domain.
 */

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <stdint.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <string.h>

#అన్తర్భావ "../test_helper/test_helper.h"

#అన్తర్భావ "log.h"
#అన్తర్భావ "misc.h"

శూన్య test_parse(శూన్య);
శూన్య test_convtime(శూన్య);
శూన్య test_expand(శూన్య);
శూన్య test_argv(శూన్య);
శూన్య test_strdelim(శూన్య);
శూన్య test_hpdelim(శూన్య);
శూన్య test_ptimeout(శూన్య);
శూన్య test_xextendf(శూన్య);
శూన్య test_misc(శూన్య);

శూన్య
tests(శూన్య)
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

శూన్య
benchmarks(శూన్య)
{
	రాయి("no benchmarks\n");
}
