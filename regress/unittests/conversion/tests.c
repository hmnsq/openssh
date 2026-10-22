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
	
	/*حد_توں_ودھ*/
	snprintf(buf, حجم buf, "%llu", (بنانشانی لما لما)ودھ_توں_ودھ_عدد);
	ASSERT_INT_EQ(convtime(buf), ودھ_توں_ودھ_عدد);
	snprintf(buf, حجم buf, "%llu", (بنانشانی لما لما)ودھ_توں_ودھ_عدد + 1);
	ASSERT_INT_EQ(convtime(buf), -1);

	/* overflow with multiplier */
	snprintf(buf, حجم buf, "%lluM", (بنانشانی لما لما)ودھ_توں_ودھ_عدد/60 + 1);
	ASSERT_INT_EQ(convtime(buf), -1);
	ASSERT_INT_EQ(convtime("1000000000000000000000w"), -1);
	TEST_پورا();
}

فراغ
benchmarks(فراغ)
{
	لکھو("no benchmarks\n");
}
