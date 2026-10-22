/* 	$OpenBSD: tests.c,v 1.5 2025/04/15 04:00:42 djm Exp $ */
/*
 * Regress test for conversions
 *
 * Placed in the public domain
 */

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <stdint.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <limits.h>
#అన్తర్భావ <string.h>

#అన్తర్భావ "../test_helper/test_helper.h"

#అన్తర్భావ "misc.h"

శూన్య
tests(శూన్య)
{
	అక్షరం buf[1024];

	TEST_ప్రారంభం("conversion_convtime");
	ASSERT_INT_EQ(convtime("0"), 0);
	ASSERT_INT_EQ(convtime("1"), 1);
	ASSERT_INT_EQ(convtime("1S"), 1);
	/* from the examples in the comment above the function */
	ASSERT_INT_EQ(convtime("90m"), 5400);
	ASSERT_INT_EQ(convtime("1h30m"), 5400);
	ASSERT_INT_EQ(convtime("2d"), 172800);
	ASSERT_INT_EQ(convtime("1w"), 604800);

	/* negative time is not allowed */
	ASSERT_INT_EQ(convtime("-7"), -1);
	ASSERT_INT_EQ(convtime("-9d"), -1);
	
	/*అధికప్రవాహం*/
	snprintf(buf, పరిమాణం buf, "%llu", (గుర్తులేని దీర్ఘ దీర్ఘ)గరిష్ఠ_పూర్ణాంకం);
	ASSERT_INT_EQ(convtime(buf), గరిష్ఠ_పూర్ణాంకం);
	snprintf(buf, పరిమాణం buf, "%llu", (గుర్తులేని దీర్ఘ దీర్ఘ)గరిష్ఠ_పూర్ణాంకం + 1);
	ASSERT_INT_EQ(convtime(buf), -1);

	/* overflow with multiplier */
	snprintf(buf, పరిమాణం buf, "%lluM", (గుర్తులేని దీర్ఘ దీర్ఘ)గరిష్ఠ_పూర్ణాంకం/60 + 1);
	ASSERT_INT_EQ(convtime(buf), -1);
	ASSERT_INT_EQ(convtime("1000000000000000000000w"), -1);
	TEST_పూర్తి();
}

శూన్య
benchmarks(శూన్య)
{
	రాయి("no benchmarks\n");
}
