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

#تعریف_کړه پیل_STRING(x)	orig = str = xstrdup(x)
#تعریف_کړه بشپړ_STRING()	حرر(orig)

	TEST_پیل("empty");
	پیل_STRING("");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "");	/* XXX arguable */
	cp = strdelim(&str);
	ASSERT_PTR_EQ(cp, عدم);
	بشپړ_STRING();
	TEST_بشپړ();

	TEST_پیل("whitespace");
	پیل_STRING("	");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "");	/* XXX better as NULL */
	ASSERT_STRING_EQ(str, "");
	بشپړ_STRING();
	TEST_بشپړ();

	TEST_پیل("trivial");
	پیل_STRING("blob");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob");
	cp = strdelim(&str);
	ASSERT_PTR_EQ(cp, عدم);
	ASSERT_PTR_EQ(str, عدم);
	بشپړ_STRING();
	TEST_بشپړ();

	TEST_پیل("trivial whitespace");
	پیل_STRING("blob   ");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob");
	ASSERT_STRING_EQ(str, "");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "");	/* XXX better as NULL */
	ASSERT_PTR_EQ(str, عدم);
	بشپړ_STRING();
	TEST_بشپړ();

	TEST_پیل("multi");
	پیل_STRING("blob1 blob2");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob1");
	ASSERT_STRING_EQ(str, "blob2");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob2");
	ASSERT_PTR_EQ(str, عدم);
	cp = strdelim(&str);
	ASSERT_PTR_EQ(cp, عدم);
	بشپړ_STRING();
	TEST_بشپړ();

	TEST_پیل("multi whitespace");
	پیل_STRING("blob1	 	blob2  	 	");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob1");
	ASSERT_STRING_EQ(str, "blob2  	 	");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob2");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "");	/* XXX better as NULL */
	ASSERT_PTR_EQ(str, عدم);
	بشپړ_STRING();
	TEST_بشپړ();

	TEST_پیل("multi equals");
	پیل_STRING("blob1=blob2");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob1");
	ASSERT_STRING_EQ(str, "blob2");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob2");
	ASSERT_PTR_EQ(str, عدم);
	cp = strdelim(&str);
	ASSERT_PTR_EQ(cp, عدم);
	بشپړ_STRING();
	TEST_بشپړ();

	TEST_پیل("multi too many equals");
	پیل_STRING("blob1==blob2");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob1");	/* XXX better returning NULL early */
	ASSERT_STRING_EQ(str, "=blob2");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "");
	ASSERT_STRING_EQ(str, "blob2");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob2");	/* XXX should (but can't) reject */
	ASSERT_PTR_EQ(str, عدم);
	بشپړ_STRING();
	TEST_بشپړ();

	TEST_پیل("multi equals strdelimw");
	پیل_STRING("blob1=blob2");
	cp = strdelimw(&str);
	ASSERT_STRING_EQ(cp, "blob1=blob2");
	ASSERT_PTR_EQ(str, عدم);
	cp = strdelimw(&str);
	ASSERT_PTR_EQ(cp, عدم);
	بشپړ_STRING();
	TEST_بشپړ();

	TEST_پیل("quoted");
	پیل_STRING("\"blob\"");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "");	/* XXX better as NULL */
	ASSERT_PTR_EQ(str, عدم);
	بشپړ_STRING();
	TEST_بشپړ();

	TEST_پیل("quoted multi");
	پیل_STRING("\"blob1\" blob2");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob1");
	ASSERT_STRING_EQ(str, "blob2");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob2");
	ASSERT_PTR_EQ(str, عدم);
	cp = strdelim(&str);
	ASSERT_PTR_EQ(cp, عدم);
	بشپړ_STRING();
	TEST_بشپړ();

	TEST_پیل("quoted multi reverse");
	پیل_STRING("blob1 \"blob2\"");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob1");
	ASSERT_STRING_EQ(str, "\"blob2\"");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob2");
	ASSERT_STRING_EQ(str, "");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "");	/* XXX better as NULL */
	ASSERT_PTR_EQ(str, عدم);
	بشپړ_STRING();
	TEST_بشپړ();

	TEST_پیل("quoted multi middle");
	پیل_STRING("blob1 \"blob2\" blob3");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob1");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob2");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob3");
	cp = strdelim(&str);
	ASSERT_PTR_EQ(cp, عدم);
	بشپړ_STRING();
	TEST_بشپړ();

	TEST_پیل("badquote");
	پیل_STRING("\"blob");
	cp = strdelim(&str);
	ASSERT_PTR_EQ(cp, عدم);
	بشپړ_STRING();
	TEST_بشپړ();

	TEST_پیل("oops quote");
	پیل_STRING("\"blob\\\"");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob\\");	/* XXX wrong */
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "");
	بشپړ_STRING();
	TEST_بشپړ();

}
