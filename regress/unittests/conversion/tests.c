/* 	$OpenBSD: tests.c,v 1.5 2025/04/15 04:00:42 djm Exp $ */
/*
 * Regress test for conversions
 *
 * Placed in the public domain
 */

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <stdint.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <limits.h>
#અન્તર્ભાવ <string.h>

#અન્તર્ભાવ "../test_helper/test_helper.h"

#અન્તર્ભાવ "misc.h"

શૂન્ય
tests(શૂન્ય)
{
	અક્ષર buf[1024];

	TEST_START("conversion_convtime");
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
	
	/* overflow */
	snprintf(buf, કદ buf, "%llu", (unsigned long long)INT_MAX);
	ASSERT_INT_EQ(convtime(buf), INT_MAX);
	snprintf(buf, કદ buf, "%llu", (unsigned long long)INT_MAX + 1);
	ASSERT_INT_EQ(convtime(buf), -1);

	/* overflow with multiplier */
	snprintf(buf, કદ buf, "%lluM", (unsigned long long)INT_MAX/60 + 1);
	ASSERT_INT_EQ(convtime(buf), -1);
	ASSERT_INT_EQ(convtime("1000000000000000000000w"), -1);
	TEST_DONE();
}

શૂન્ય
benchmarks(શૂન્ય)
{
	printf("no benchmarks\n");
}
