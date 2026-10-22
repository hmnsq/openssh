/* 	$OpenBSD: tests.c,v 1.5 2025/04/15 04:00:42 djm Exp $ */
/*
 * Regress test for conversions
 *
 * Placed in the public domain
 */

#समावेश "includes.h"

#समावेश <sys/types.h>
#समावेश <stdio.h>
#समावेश <stdint.h>
#समावेश <stdlib.h>
#समावेश <limits.h>
#समावेश <string.h>

#समावेश "../test_helper/test_helper.h"

#समावेश "misc.h"

व्योम
tests(व्योम)
{
	अक्षर buf[1024];

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
	snprintf(buf, माप buf, "%llu", (अचिन्हित दीर्घ दीर्घ)पूर्णांक_उच्च);
	ASSERT_INT_EQ(convtime(buf), पूर्णांक_उच्च);
	snprintf(buf, माप buf, "%llu", (अचिन्हित दीर्घ दीर्घ)पूर्णांक_उच्च + 1);
	ASSERT_INT_EQ(convtime(buf), -1);

	/* overflow with multiplier */
	snprintf(buf, माप buf, "%lluM", (अचिन्हित दीर्घ दीर्घ)पूर्णांक_उच्च/60 + 1);
	ASSERT_INT_EQ(convtime(buf), -1);
	ASSERT_INT_EQ(convtime("1000000000000000000000w"), -1);
	TEST_DONE();
}

व्योम
benchmarks(व्योम)
{
	म_लिखो("no benchmarks\n");
}
