/* 	$OpenBSD: tests.c,v 1.5 2025/04/15 04:00:42 djm Exp $ */
/*
 * Regress test for conversions
 *
 * Placed in the public domain
 */

#ضمن "includes.h"

#ضمن <sys/types.h>
#ضمن <stdio.h>
#ضمن <stdint.h>
#ضمن <stdlib.h>
#ضمن <limits.h>
#ضمن <string.h>

#ضمن "../test_helper/test_helper.h"

#ضمن "misc.h"

فراغ
tests(فراغ)
{
	حرف buf[1024];

	TEST_شروع("conversion_convtime");
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
	
	/*سرریز*/
	snprintf(buf, حجم buf, "%llu", (بیعلامت دراز دراز)بیشترین_صحیح);
	ASSERT_INT_EQ(convtime(buf), بیشترین_صحیح);
	snprintf(buf, حجم buf, "%llu", (بیعلامت دراز دراز)بیشترین_صحیح + 1);
	ASSERT_INT_EQ(convtime(buf), -1);

	/* overflow with multiplier */
	snprintf(buf, حجم buf, "%lluM", (بیعلامت دراز دراز)بیشترین_صحیح/60 + 1);
	ASSERT_INT_EQ(convtime(buf), -1);
	ASSERT_INT_EQ(convtime("1000000000000000000000w"), -1);
	TEST_انجامشده();
}

فراغ
benchmarks(فراغ)
{
	چاپ_کن("no benchmarks\n");
}
