/* 	$OpenBSD: test_hpdelim.c,v 1.2 2022/02/06 22:58:33 dtucker Exp $ */
/*
 * Regress test for misc hpdelim() and co
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
#అన్తర్భావ "xmalloc.h"

శూన్య test_hpdelim(శూన్య);

శూన్య
test_hpdelim(శూన్య)
{
	అక్షరం *orig, *str, *cp, *పోర్టు;

#నిర్వచించు ప్రారంభం_STRING(x)	orig = str = xstrdup(x)
#నిర్వచించు పూర్తి_STRING()	విడుదల(orig)

	TEST_ప్రారంభం("hpdelim host only");
	ప్రారంభం_STRING("host");
	cp = hpdelim(&str);
	ASSERT_STRING_EQ(cp, "host");
	ASSERT_PTR_EQ(str, ఖాళీ);
	పూర్తి_STRING();
	TEST_పూర్తి();

	TEST_ప్రారంభం("hpdelim :port");
	ప్రారంభం_STRING(":1234");
	cp = hpdelim(&str);
	ASSERT_STRING_EQ(cp, "");
	ASSERT_PTR_NE(str, ఖాళీ);
	పోర్టు = hpdelim(&str);
	ASSERT_STRING_EQ(పోర్టు, "1234");
	ASSERT_PTR_EQ(str, ఖాళీ);
	పూర్తి_STRING();
	TEST_పూర్తి();

	TEST_ప్రారంభం("hpdelim host:port");
	ప్రారంభం_STRING("host:1234");
	cp = hpdelim(&str);
	ASSERT_STRING_EQ(cp, "host");
	ASSERT_PTR_NE(str, ఖాళీ);
	పోర్టు = hpdelim(&str);
	ASSERT_STRING_EQ(పోర్టు, "1234");
	ASSERT_PTR_EQ(str, ఖాళీ);
	పూర్తి_STRING();
	TEST_పూర్తి();

	TEST_ప్రారంభం("hpdelim [host]:port");
	ప్రారంభం_STRING("[::1]:1234");
	cp = hpdelim(&str);
	ASSERT_STRING_EQ(cp, "[::1]");
	ASSERT_PTR_NE(str, ఖాళీ);
	పోర్టు = hpdelim(&str);
	ASSERT_STRING_EQ(పోర్టు, "1234");
	ASSERT_PTR_EQ(str, ఖాళీ);
	పూర్తి_STRING();
	TEST_పూర్తి();

	TEST_ప్రారంభం("hpdelim missing ] error");
	ప్రారంభం_STRING("[::1:1234");
	cp = hpdelim(&str);
	ASSERT_PTR_EQ(cp, ఖాళీ);
	పూర్తి_STRING();
	TEST_పూర్తి();

}
