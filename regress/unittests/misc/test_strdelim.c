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

#تعریف_کن شروع_STRING(x)	orig = str = xstrdup(x)
#تعریف_کن انجامشده_STRING()	حرر(orig)

	TEST_شروع("empty");
	شروع_STRING("");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "");	/* XXX arguable */
	cp = strdelim(&str);
	ASSERT_PTR_EQ(cp, عدم);
	انجامشده_STRING();
	TEST_انجامشده();

	TEST_شروع("whitespace");
	شروع_STRING("	");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "");	/* XXX better as NULL */
	ASSERT_STRING_EQ(str, "");
	انجامشده_STRING();
	TEST_انجامشده();

	TEST_شروع("trivial");
	شروع_STRING("blob");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob");
	cp = strdelim(&str);
	ASSERT_PTR_EQ(cp, عدم);
	ASSERT_PTR_EQ(str, عدم);
	انجامشده_STRING();
	TEST_انجامشده();

	TEST_شروع("trivial whitespace");
	شروع_STRING("blob   ");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob");
	ASSERT_STRING_EQ(str, "");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "");	/* XXX better as NULL */
	ASSERT_PTR_EQ(str, عدم);
	انجامشده_STRING();
	TEST_انجامشده();

	TEST_شروع("multi");
	شروع_STRING("blob1 blob2");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob1");
	ASSERT_STRING_EQ(str, "blob2");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob2");
	ASSERT_PTR_EQ(str, عدم);
	cp = strdelim(&str);
	ASSERT_PTR_EQ(cp, عدم);
	انجامشده_STRING();
	TEST_انجامشده();

	TEST_شروع("multi whitespace");
	شروع_STRING("blob1	 	blob2  	 	");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob1");
	ASSERT_STRING_EQ(str, "blob2  	 	");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob2");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "");	/* XXX better as NULL */
	ASSERT_PTR_EQ(str, عدم);
	انجامشده_STRING();
	TEST_انجامشده();

	TEST_شروع("multi equals");
	شروع_STRING("blob1=blob2");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob1");
	ASSERT_STRING_EQ(str, "blob2");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob2");
	ASSERT_PTR_EQ(str, عدم);
	cp = strdelim(&str);
	ASSERT_PTR_EQ(cp, عدم);
	انجامشده_STRING();
	TEST_انجامشده();

	TEST_شروع("multi too many equals");
	شروع_STRING("blob1==blob2");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob1");	/* XXX better returning NULL early */
	ASSERT_STRING_EQ(str, "=blob2");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "");
	ASSERT_STRING_EQ(str, "blob2");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob2");	/* XXX should (but can't) reject */
	ASSERT_PTR_EQ(str, عدم);
	انجامشده_STRING();
	TEST_انجامشده();

	TEST_شروع("multi equals strdelimw");
	شروع_STRING("blob1=blob2");
	cp = strdelimw(&str);
	ASSERT_STRING_EQ(cp, "blob1=blob2");
	ASSERT_PTR_EQ(str, عدم);
	cp = strdelimw(&str);
	ASSERT_PTR_EQ(cp, عدم);
	انجامشده_STRING();
	TEST_انجامشده();

	TEST_شروع("quoted");
	شروع_STRING("\"blob\"");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "");	/* XXX better as NULL */
	ASSERT_PTR_EQ(str, عدم);
	انجامشده_STRING();
	TEST_انجامشده();

	TEST_شروع("quoted multi");
	شروع_STRING("\"blob1\" blob2");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob1");
	ASSERT_STRING_EQ(str, "blob2");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob2");
	ASSERT_PTR_EQ(str, عدم);
	cp = strdelim(&str);
	ASSERT_PTR_EQ(cp, عدم);
	انجامشده_STRING();
	TEST_انجامشده();

	TEST_شروع("quoted multi reverse");
	شروع_STRING("blob1 \"blob2\"");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob1");
	ASSERT_STRING_EQ(str, "\"blob2\"");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob2");
	ASSERT_STRING_EQ(str, "");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "");	/* XXX better as NULL */
	ASSERT_PTR_EQ(str, عدم);
	انجامشده_STRING();
	TEST_انجامشده();

	TEST_شروع("quoted multi middle");
	شروع_STRING("blob1 \"blob2\" blob3");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob1");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob2");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob3");
	cp = strdelim(&str);
	ASSERT_PTR_EQ(cp, عدم);
	انجامشده_STRING();
	TEST_انجامشده();

	TEST_شروع("badquote");
	شروع_STRING("\"blob");
	cp = strdelim(&str);
	ASSERT_PTR_EQ(cp, عدم);
	انجامشده_STRING();
	TEST_انجامشده();

	TEST_شروع("oops quote");
	شروع_STRING("\"blob\\\"");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob\\");	/* XXX wrong */
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "");
	انجامشده_STRING();
	TEST_انجامشده();

}
