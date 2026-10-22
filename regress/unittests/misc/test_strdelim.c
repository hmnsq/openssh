/* 	$OpenBSD: test_strdelim.c,v 1.3 2021/12/14 21:25:27 deraadt Exp $ */
/*
 * Regress test for misc strdelim() and co
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

శూన్య test_strdelim(శూన్య);

శూన్య
test_strdelim(శూన్య)
{
	అక్షరం *orig, *str, *cp;

#నిర్వచించు ప్రారంభం_STRING(x)	orig = str = xstrdup(x)
#నిర్వచించు పూర్తి_STRING()	విడుదల(orig)

	TEST_ప్రారంభం("empty");
	ప్రారంభం_STRING("");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "");	/* XXX arguable */
	cp = strdelim(&str);
	ASSERT_PTR_EQ(cp, ఖాళీ);
	పూర్తి_STRING();
	TEST_పూర్తి();

	TEST_ప్రారంభం("whitespace");
	ప్రారంభం_STRING("	");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "");	/* XXX better as NULL */
	ASSERT_STRING_EQ(str, "");
	పూర్తి_STRING();
	TEST_పూర్తి();

	TEST_ప్రారంభం("trivial");
	ప్రారంభం_STRING("blob");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob");
	cp = strdelim(&str);
	ASSERT_PTR_EQ(cp, ఖాళీ);
	ASSERT_PTR_EQ(str, ఖాళీ);
	పూర్తి_STRING();
	TEST_పూర్తి();

	TEST_ప్రారంభం("trivial whitespace");
	ప్రారంభం_STRING("blob   ");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob");
	ASSERT_STRING_EQ(str, "");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "");	/* XXX better as NULL */
	ASSERT_PTR_EQ(str, ఖాళీ);
	పూర్తి_STRING();
	TEST_పూర్తి();

	TEST_ప్రారంభం("multi");
	ప్రారంభం_STRING("blob1 blob2");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob1");
	ASSERT_STRING_EQ(str, "blob2");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob2");
	ASSERT_PTR_EQ(str, ఖాళీ);
	cp = strdelim(&str);
	ASSERT_PTR_EQ(cp, ఖాళీ);
	పూర్తి_STRING();
	TEST_పూర్తి();

	TEST_ప్రారంభం("multi whitespace");
	ప్రారంభం_STRING("blob1	 	blob2  	 	");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob1");
	ASSERT_STRING_EQ(str, "blob2  	 	");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob2");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "");	/* XXX better as NULL */
	ASSERT_PTR_EQ(str, ఖాళీ);
	పూర్తి_STRING();
	TEST_పూర్తి();

	TEST_ప్రారంభం("multi equals");
	ప్రారంభం_STRING("blob1=blob2");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob1");
	ASSERT_STRING_EQ(str, "blob2");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob2");
	ASSERT_PTR_EQ(str, ఖాళీ);
	cp = strdelim(&str);
	ASSERT_PTR_EQ(cp, ఖాళీ);
	పూర్తి_STRING();
	TEST_పూర్తి();

	TEST_ప్రారంభం("multi too many equals");
	ప్రారంభం_STRING("blob1==blob2");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob1");	/* XXX better returning NULL early */
	ASSERT_STRING_EQ(str, "=blob2");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "");
	ASSERT_STRING_EQ(str, "blob2");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob2");	/* XXX should (but can't) reject */
	ASSERT_PTR_EQ(str, ఖాళీ);
	పూర్తి_STRING();
	TEST_పూర్తి();

	TEST_ప్రారంభం("multi equals strdelimw");
	ప్రారంభం_STRING("blob1=blob2");
	cp = strdelimw(&str);
	ASSERT_STRING_EQ(cp, "blob1=blob2");
	ASSERT_PTR_EQ(str, ఖాళీ);
	cp = strdelimw(&str);
	ASSERT_PTR_EQ(cp, ఖాళీ);
	పూర్తి_STRING();
	TEST_పూర్తి();

	TEST_ప్రారంభం("quoted");
	ప్రారంభం_STRING("\"blob\"");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "");	/* XXX better as NULL */
	ASSERT_PTR_EQ(str, ఖాళీ);
	పూర్తి_STRING();
	TEST_పూర్తి();

	TEST_ప్రారంభం("quoted multi");
	ప్రారంభం_STRING("\"blob1\" blob2");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob1");
	ASSERT_STRING_EQ(str, "blob2");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob2");
	ASSERT_PTR_EQ(str, ఖాళీ);
	cp = strdelim(&str);
	ASSERT_PTR_EQ(cp, ఖాళీ);
	పూర్తి_STRING();
	TEST_పూర్తి();

	TEST_ప్రారంభం("quoted multi reverse");
	ప్రారంభం_STRING("blob1 \"blob2\"");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob1");
	ASSERT_STRING_EQ(str, "\"blob2\"");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob2");
	ASSERT_STRING_EQ(str, "");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "");	/* XXX better as NULL */
	ASSERT_PTR_EQ(str, ఖాళీ);
	పూర్తి_STRING();
	TEST_పూర్తి();

	TEST_ప్రారంభం("quoted multi middle");
	ప్రారంభం_STRING("blob1 \"blob2\" blob3");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob1");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob2");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob3");
	cp = strdelim(&str);
	ASSERT_PTR_EQ(cp, ఖాళీ);
	పూర్తి_STRING();
	TEST_పూర్తి();

	TEST_ప్రారంభం("badquote");
	ప్రారంభం_STRING("\"blob");
	cp = strdelim(&str);
	ASSERT_PTR_EQ(cp, ఖాళీ);
	పూర్తి_STRING();
	TEST_పూర్తి();

	TEST_ప్రారంభం("oops quote");
	ప్రారంభం_STRING("\"blob\\\"");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob\\");	/* XXX wrong */
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "");
	పూర్తి_STRING();
	TEST_పూర్తి();

}
