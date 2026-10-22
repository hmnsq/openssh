/* 	$OpenBSD: test_strdelim.c,v 1.3 2021/12/14 21:25:27 deraadt Exp $ */
/*
 * Regress test for misc strdelim() and co
 *
 * Placed in the public domain.
 */

#شامل "includes.h"

#شامل <sys/types.h>
#شامل <stdio.h>
#شامل <stdint.h>
#شامل <stdlib.h>
#شامل <string.h>

#شامل "../test_helper/test_helper.h"

#شامل "log.h"
#شامل "misc.h"
#شامل "xmalloc.h"

خالی test_strdelim(خالی);

خالی
test_strdelim(خالی)
{
	حرف *orig, *str, *cp;

#تعریف_کرو آغاز_STRING(x)	orig = str = xstrdup(x)
#تعریف_کرو مکمل_STRING()	آزاد(orig)

	TEST_آغاز("empty");
	آغاز_STRING("");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "");	/* XXX arguable */
	cp = strdelim(&str);
	ASSERT_PTR_EQ(cp, تہی);
	مکمل_STRING();
	TEST_مکمل();

	TEST_آغاز("whitespace");
	آغاز_STRING("	");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "");	/* XXX better as NULL */
	ASSERT_STRING_EQ(str, "");
	مکمل_STRING();
	TEST_مکمل();

	TEST_آغاز("trivial");
	آغاز_STRING("blob");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob");
	cp = strdelim(&str);
	ASSERT_PTR_EQ(cp, تہی);
	ASSERT_PTR_EQ(str, تہی);
	مکمل_STRING();
	TEST_مکمل();

	TEST_آغاز("trivial whitespace");
	آغاز_STRING("blob   ");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob");
	ASSERT_STRING_EQ(str, "");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "");	/* XXX better as NULL */
	ASSERT_PTR_EQ(str, تہی);
	مکمل_STRING();
	TEST_مکمل();

	TEST_آغاز("multi");
	آغاز_STRING("blob1 blob2");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob1");
	ASSERT_STRING_EQ(str, "blob2");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob2");
	ASSERT_PTR_EQ(str, تہی);
	cp = strdelim(&str);
	ASSERT_PTR_EQ(cp, تہی);
	مکمل_STRING();
	TEST_مکمل();

	TEST_آغاز("multi whitespace");
	آغاز_STRING("blob1	 	blob2  	 	");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob1");
	ASSERT_STRING_EQ(str, "blob2  	 	");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob2");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "");	/* XXX better as NULL */
	ASSERT_PTR_EQ(str, تہی);
	مکمل_STRING();
	TEST_مکمل();

	TEST_آغاز("multi equals");
	آغاز_STRING("blob1=blob2");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob1");
	ASSERT_STRING_EQ(str, "blob2");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob2");
	ASSERT_PTR_EQ(str, تہی);
	cp = strdelim(&str);
	ASSERT_PTR_EQ(cp, تہی);
	مکمل_STRING();
	TEST_مکمل();

	TEST_آغاز("multi too many equals");
	آغاز_STRING("blob1==blob2");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob1");	/* XXX better returning NULL early */
	ASSERT_STRING_EQ(str, "=blob2");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "");
	ASSERT_STRING_EQ(str, "blob2");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob2");	/* XXX should (but can't) reject */
	ASSERT_PTR_EQ(str, تہی);
	مکمل_STRING();
	TEST_مکمل();

	TEST_آغاز("multi equals strdelimw");
	آغاز_STRING("blob1=blob2");
	cp = strdelimw(&str);
	ASSERT_STRING_EQ(cp, "blob1=blob2");
	ASSERT_PTR_EQ(str, تہی);
	cp = strdelimw(&str);
	ASSERT_PTR_EQ(cp, تہی);
	مکمل_STRING();
	TEST_مکمل();

	TEST_آغاز("quoted");
	آغاز_STRING("\"blob\"");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "");	/* XXX better as NULL */
	ASSERT_PTR_EQ(str, تہی);
	مکمل_STRING();
	TEST_مکمل();

	TEST_آغاز("quoted multi");
	آغاز_STRING("\"blob1\" blob2");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob1");
	ASSERT_STRING_EQ(str, "blob2");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob2");
	ASSERT_PTR_EQ(str, تہی);
	cp = strdelim(&str);
	ASSERT_PTR_EQ(cp, تہی);
	مکمل_STRING();
	TEST_مکمل();

	TEST_آغاز("quoted multi reverse");
	آغاز_STRING("blob1 \"blob2\"");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob1");
	ASSERT_STRING_EQ(str, "\"blob2\"");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob2");
	ASSERT_STRING_EQ(str, "");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "");	/* XXX better as NULL */
	ASSERT_PTR_EQ(str, تہی);
	مکمل_STRING();
	TEST_مکمل();

	TEST_آغاز("quoted multi middle");
	آغاز_STRING("blob1 \"blob2\" blob3");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob1");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob2");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob3");
	cp = strdelim(&str);
	ASSERT_PTR_EQ(cp, تہی);
	مکمل_STRING();
	TEST_مکمل();

	TEST_آغاز("badquote");
	آغاز_STRING("\"blob");
	cp = strdelim(&str);
	ASSERT_PTR_EQ(cp, تہی);
	مکمل_STRING();
	TEST_مکمل();

	TEST_آغاز("oops quote");
	آغاز_STRING("\"blob\\\"");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob\\");	/* XXX wrong */
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "");
	مکمل_STRING();
	TEST_مکمل();

}
