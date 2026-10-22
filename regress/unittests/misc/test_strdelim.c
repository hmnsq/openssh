/* 	$OpenBSD: test_strdelim.c,v 1.3 2021/12/14 21:25:27 deraadt Exp $ */
/*
 * Regress test for misc strdelim() and co
 *
 * Placed in the public domain.
 */

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <stdint.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>

#अन्तर्भाव "../test_helper/test_helper.h"

#अन्तर्भाव "log.h"
#अन्तर्भाव "misc.h"
#अन्तर्भाव "xmalloc.h"

शून्य test_strdelim(शून्य);

शून्य
test_strdelim(शून्य)
{
	वर्ण *orig, *str, *cp;

#define START_STRING(x)	orig = str = xstrdup(x)
#define DONE_STRING()	मुक्त(orig)

	TEST_START("empty");
	START_STRING("");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "");	/* XXX arguable */
	cp = strdelim(&str);
	ASSERT_PTR_EQ(cp, रिक्त);
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
	ASSERT_PTR_EQ(cp, रिक्त);
	ASSERT_PTR_EQ(str, रिक्त);
	DONE_STRING();
	TEST_DONE();

	TEST_START("trivial whitespace");
	START_STRING("blob   ");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob");
	ASSERT_STRING_EQ(str, "");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "");	/* XXX better as NULL */
	ASSERT_PTR_EQ(str, रिक्त);
	DONE_STRING();
	TEST_DONE();

	TEST_START("multi");
	START_STRING("blob1 blob2");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob1");
	ASSERT_STRING_EQ(str, "blob2");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob2");
	ASSERT_PTR_EQ(str, रिक्त);
	cp = strdelim(&str);
	ASSERT_PTR_EQ(cp, रिक्त);
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
	ASSERT_PTR_EQ(str, रिक्त);
	DONE_STRING();
	TEST_DONE();

	TEST_START("multi equals");
	START_STRING("blob1=blob2");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob1");
	ASSERT_STRING_EQ(str, "blob2");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob2");
	ASSERT_PTR_EQ(str, रिक्त);
	cp = strdelim(&str);
	ASSERT_PTR_EQ(cp, रिक्त);
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
	ASSERT_PTR_EQ(str, रिक्त);
	DONE_STRING();
	TEST_DONE();

	TEST_START("multi equals strdelimw");
	START_STRING("blob1=blob2");
	cp = strdelimw(&str);
	ASSERT_STRING_EQ(cp, "blob1=blob2");
	ASSERT_PTR_EQ(str, रिक्त);
	cp = strdelimw(&str);
	ASSERT_PTR_EQ(cp, रिक्त);
	DONE_STRING();
	TEST_DONE();

	TEST_START("quoted");
	START_STRING("\"blob\"");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "");	/* XXX better as NULL */
	ASSERT_PTR_EQ(str, रिक्त);
	DONE_STRING();
	TEST_DONE();

	TEST_START("quoted multi");
	START_STRING("\"blob1\" blob2");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob1");
	ASSERT_STRING_EQ(str, "blob2");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob2");
	ASSERT_PTR_EQ(str, रिक्त);
	cp = strdelim(&str);
	ASSERT_PTR_EQ(cp, रिक्त);
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
	ASSERT_PTR_EQ(str, रिक्त);
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
	ASSERT_PTR_EQ(cp, रिक्त);
	DONE_STRING();
	TEST_DONE();

	TEST_START("badquote");
	START_STRING("\"blob");
	cp = strdelim(&str);
	ASSERT_PTR_EQ(cp, रिक्त);
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
