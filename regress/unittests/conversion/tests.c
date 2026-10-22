/* 	$OpenBSD: tests.c,v 1.5 2025/04/15 04:00:42 djm Exp $ */
/*
 * Regress test for conversions
 *
 * Placed in the public domain
 */

#شامل "includes.h"

#شامل <sys/types.h>
#شامل <stdio.h>
#شامل <stdint.h>
#شامل <stdlib.h>
#شامل <limits.h>
#شامل <string.h>

#شامل "../test_helper/test_helper.h"

#شامل "misc.h"

خالی
tests(خالی)
{
	حرف buf[1024];

	TEST_آغاز("conversion_convtime");
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
	
	/*حد_سے_تجاوز*/
	snprintf(buf, حجم buf, "%llu", (غیرعلامتی طویل طویل)زیادہ_سے_زیادہ_عدد);
	ASSERT_INT_EQ(convtime(buf), زیادہ_سے_زیادہ_عدد);
	snprintf(buf, حجم buf, "%llu", (غیرعلامتی طویل طویل)زیادہ_سے_زیادہ_عدد + 1);
	ASSERT_INT_EQ(convtime(buf), -1);

	/* overflow with multiplier */
	snprintf(buf, حجم buf, "%lluM", (غیرعلامتی طویل طویل)زیادہ_سے_زیادہ_عدد/60 + 1);
	ASSERT_INT_EQ(convtime(buf), -1);
	ASSERT_INT_EQ(convtime("1000000000000000000000w"), -1);
	TEST_مکمل();
}

خالی
benchmarks(خالی)
{
	لکھو("no benchmarks\n");
}
