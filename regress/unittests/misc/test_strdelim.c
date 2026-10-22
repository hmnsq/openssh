/* 	$OpenBSD: test_strdelim.c,v 1.3 2021/12/14 21:25:27 deraadt Exp $ */
/*
 * Regress test for misc strdelim() and co
 *
 * Placed in the public domain.
 */

#ضمن "includes.h"

#ضمن <sys/types.h>
#ضمن <stdio.h>
#ضمن <stdint.h>
#ضمن <stdlib.h>
#ضمن <string.h>

#ضمن "../test_helper/test_helper.h"

#ضمن "log.h"
#ضمن "misc.h"
#ضمن "xmalloc.h"

فراغ test_strdelim(فراغ);

فراغ
test_strdelim(فراغ)
{
	حرف *orig, *str, *cp;

#وصف_ڪريو شروعات_STRING(x)	orig = str = xstrdup(x)
#وصف_ڪريو پورو_STRING()	حرر(orig)

	TEST_شروعات("empty");
	شروعات_STRING("");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "");	/* XXX arguable */
	cp = strdelim(&str);
	ASSERT_PTR_EQ(cp, عدم);
	پورو_STRING();
	TEST_پورو();

	TEST_شروعات("whitespace");
	شروعات_STRING("	");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "");	/* XXX better as NULL */
	ASSERT_STRING_EQ(str, "");
	پورو_STRING();
	TEST_پورو();

	TEST_شروعات("trivial");
	شروعات_STRING("blob");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob");
	cp = strdelim(&str);
	ASSERT_PTR_EQ(cp, عدم);
	ASSERT_PTR_EQ(str, عدم);
	پورو_STRING();
	TEST_پورو();

	TEST_شروعات("trivial whitespace");
	شروعات_STRING("blob   ");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob");
	ASSERT_STRING_EQ(str, "");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "");	/* XXX better as NULL */
	ASSERT_PTR_EQ(str, عدم);
	پورو_STRING();
	TEST_پورو();

	TEST_شروعات("multi");
	شروعات_STRING("blob1 blob2");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob1");
	ASSERT_STRING_EQ(str, "blob2");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob2");
	ASSERT_PTR_EQ(str, عدم);
	cp = strdelim(&str);
	ASSERT_PTR_EQ(cp, عدم);
	پورو_STRING();
	TEST_پورو();

	TEST_شروعات("multi whitespace");
	شروعات_STRING("blob1	 	blob2  	 	");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob1");
	ASSERT_STRING_EQ(str, "blob2  	 	");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob2");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "");	/* XXX better as NULL */
	ASSERT_PTR_EQ(str, عدم);
	پورو_STRING();
	TEST_پورو();

	TEST_شروعات("multi equals");
	شروعات_STRING("blob1=blob2");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob1");
	ASSERT_STRING_EQ(str, "blob2");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob2");
	ASSERT_PTR_EQ(str, عدم);
	cp = strdelim(&str);
	ASSERT_PTR_EQ(cp, عدم);
	پورو_STRING();
	TEST_پورو();

	TEST_شروعات("multi too many equals");
	شروعات_STRING("blob1==blob2");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob1");	/* XXX better returning NULL early */
	ASSERT_STRING_EQ(str, "=blob2");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "");
	ASSERT_STRING_EQ(str, "blob2");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob2");	/* XXX should (but can't) reject */
	ASSERT_PTR_EQ(str, عدم);
	پورو_STRING();
	TEST_پورو();

	TEST_شروعات("multi equals strdelimw");
	شروعات_STRING("blob1=blob2");
	cp = strdelimw(&str);
	ASSERT_STRING_EQ(cp, "blob1=blob2");
	ASSERT_PTR_EQ(str, عدم);
	cp = strdelimw(&str);
	ASSERT_PTR_EQ(cp, عدم);
	پورو_STRING();
	TEST_پورو();

	TEST_شروعات("quoted");
	شروعات_STRING("\"blob\"");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "");	/* XXX better as NULL */
	ASSERT_PTR_EQ(str, عدم);
	پورو_STRING();
	TEST_پورو();

	TEST_شروعات("quoted multi");
	شروعات_STRING("\"blob1\" blob2");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob1");
	ASSERT_STRING_EQ(str, "blob2");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob2");
	ASSERT_PTR_EQ(str, عدم);
	cp = strdelim(&str);
	ASSERT_PTR_EQ(cp, عدم);
	پورو_STRING();
	TEST_پورو();

	TEST_شروعات("quoted multi reverse");
	شروعات_STRING("blob1 \"blob2\"");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob1");
	ASSERT_STRING_EQ(str, "\"blob2\"");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob2");
	ASSERT_STRING_EQ(str, "");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "");	/* XXX better as NULL */
	ASSERT_PTR_EQ(str, عدم);
	پورو_STRING();
	TEST_پورو();

	TEST_شروعات("quoted multi middle");
	شروعات_STRING("blob1 \"blob2\" blob3");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob1");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob2");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob3");
	cp = strdelim(&str);
	ASSERT_PTR_EQ(cp, عدم);
	پورو_STRING();
	TEST_پورو();

	TEST_شروعات("badquote");
	شروعات_STRING("\"blob");
	cp = strdelim(&str);
	ASSERT_PTR_EQ(cp, عدم);
	پورو_STRING();
	TEST_پورو();

	TEST_شروعات("oops quote");
	شروعات_STRING("\"blob\\\"");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob\\");	/* XXX wrong */
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "");
	پورو_STRING();
	TEST_پورو();

}
