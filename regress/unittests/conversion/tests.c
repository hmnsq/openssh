/* 	$OpenBSD: tests.c,v 1.5 2025/04/15 04:00:42 djm Exp $ */
/*
 * Regress test for conversions
 *
 * Placed in the public domain
 */

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <stdint.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <limits.h>
#അന്തര്ഭാവ <string.h>

#അന്തര്ഭാവ "../test_helper/test_helper.h"

#അന്തര്ഭാവ "misc.h"

ശൂന്യം
tests(ശൂന്യം)
{
	അക്ഷരം buf[1024];

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
	snprintf(buf, വലുപ്പം buf, "%llu", (unsigned long long)INT_MAX);
	ASSERT_INT_EQ(convtime(buf), INT_MAX);
	snprintf(buf, വലുപ്പം buf, "%llu", (unsigned long long)INT_MAX + 1);
	ASSERT_INT_EQ(convtime(buf), -1);

	/* overflow with multiplier */
	snprintf(buf, വലുപ്പം buf, "%lluM", (unsigned long long)INT_MAX/60 + 1);
	ASSERT_INT_EQ(convtime(buf), -1);
	ASSERT_INT_EQ(convtime("1000000000000000000000w"), -1);
	TEST_DONE();
}

ശൂന്യം
benchmarks(ശൂന്യം)
{
	printf("no benchmarks\n");
}
