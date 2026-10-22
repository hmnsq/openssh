/* 	$OpenBSD: test_strdelim.c,v 1.3 2021/12/14 21:25:27 deraadt Exp $ */
/*
 * Regress test for misc strdelim() and co
 *
 * Placed in the public domain.
 */

#অন্তর্ভাৱ "includes.h"

#অন্তর্ভাৱ <sys/types.h>
#অন্তর্ভাৱ <stdio.h>
#অন্তর্ভাৱ <stdint.h>
#অন্তর্ভাৱ <stdlib.h>
#অন্তর্ভাৱ <string.h>

#অন্তর্ভাৱ "../test_helper/test_helper.h"

#অন্তর্ভাৱ "log.h"
#অন্তর্ভাৱ "misc.h"
#অন্তর্ভাৱ "xmalloc.h"

শূন্য test_strdelim(শূন্য);

শূন্য
test_strdelim(শূন্য)
{
	ৱর্ণ *orig, *str, *cp;

#define START_STRING(x)	orig = str = xstrdup(x)
#define DONE_STRING()	মুক্ত(orig)

	TEST_START("empty");
	START_STRING("");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "");	/* XXX arguable */
	cp = strdelim(&str);
	ASSERT_PTR_EQ(cp, রিক্ত);
	DONE_STRING();
	TEST_DONE();

	TEST_START("whitespace");
	START_STRING("	");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "");	/* XXX better as NULL */
	ASSERT_STRING_EQ(str, "");
	DONE_STRING();
	TEST_DONE();

	TEST_START("trivial");
	START_STRING("blob");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob");
	cp = strdelim(&str);
	ASSERT_PTR_EQ(cp, রিক্ত);
	ASSERT_PTR_EQ(str, রিক্ত);
	DONE_STRING();
	TEST_DONE();

	TEST_START("trivial whitespace");
	START_STRING("blob   ");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob");
	ASSERT_STRING_EQ(str, "");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "");	/* XXX better as NULL */
	ASSERT_PTR_EQ(str, রিক্ত);
	DONE_STRING();
	TEST_DONE();

	TEST_START("multi");
	START_STRING("blob1 blob2");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob1");
	ASSERT_STRING_EQ(str, "blob2");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob2");
	ASSERT_PTR_EQ(str, রিক্ত);
	cp = strdelim(&str);
	ASSERT_PTR_EQ(cp, রিক্ত);
	DONE_STRING();
	TEST_DONE();

	TEST_START("multi whitespace");
	START_STRING("blob1	 	blob2  	 	");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob1");
	ASSERT_STRING_EQ(str, "blob2  	 	");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob2");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "");	/* XXX better as NULL */
	ASSERT_PTR_EQ(str, রিক্ত);
	DONE_STRING();
	TEST_DONE();

	TEST_START("multi equals");
	START_STRING("blob1=blob2");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob1");
	ASSERT_STRING_EQ(str, "blob2");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob2");
	ASSERT_PTR_EQ(str, রিক্ত);
	cp = strdelim(&str);
	ASSERT_PTR_EQ(cp, রিক্ত);
	DONE_STRING();
	TEST_DONE();

	TEST_START("multi too many equals");
	START_STRING("blob1==blob2");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob1");	/* XXX better returning NULL early */
	ASSERT_STRING_EQ(str, "=blob2");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "");
	ASSERT_STRING_EQ(str, "blob2");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob2");	/* XXX should (but can't) reject */
	ASSERT_PTR_EQ(str, রিক্ত);
	DONE_STRING();
	TEST_DONE();

	TEST_START("multi equals strdelimw");
	START_STRING("blob1=blob2");
	cp = strdelimw(&str);
	ASSERT_STRING_EQ(cp, "blob1=blob2");
	ASSERT_PTR_EQ(str, রিক্ত);
	cp = strdelimw(&str);
	ASSERT_PTR_EQ(cp, রিক্ত);
	DONE_STRING();
	TEST_DONE();

	TEST_START("quoted");
	START_STRING("\"blob\"");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "");	/* XXX better as NULL */
	ASSERT_PTR_EQ(str, রিক্ত);
	DONE_STRING();
	TEST_DONE();

	TEST_START("quoted multi");
	START_STRING("\"blob1\" blob2");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob1");
	ASSERT_STRING_EQ(str, "blob2");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob2");
	ASSERT_PTR_EQ(str, রিক্ত);
	cp = strdelim(&str);
	ASSERT_PTR_EQ(cp, রিক্ত);
	DONE_STRING();
	TEST_DONE();

	TEST_START("quoted multi reverse");
	START_STRING("blob1 \"blob2\"");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob1");
	ASSERT_STRING_EQ(str, "\"blob2\"");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob2");
	ASSERT_STRING_EQ(str, "");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "");	/* XXX better as NULL */
	ASSERT_PTR_EQ(str, রিক্ত);
	DONE_STRING();
	TEST_DONE();

	TEST_START("quoted multi middle");
	START_STRING("blob1 \"blob2\" blob3");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob1");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob2");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob3");
	cp = strdelim(&str);
	ASSERT_PTR_EQ(cp, রিক্ত);
	DONE_STRING();
	TEST_DONE();

	TEST_START("badquote");
	START_STRING("\"blob");
	cp = strdelim(&str);
	ASSERT_PTR_EQ(cp, রিক্ত);
	DONE_STRING();
	TEST_DONE();

	TEST_START("oops quote");
	START_STRING("\"blob\\\"");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob\\");	/* XXX wrong */
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "");
	DONE_STRING();
	TEST_DONE();

}
