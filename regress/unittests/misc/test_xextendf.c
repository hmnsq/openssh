/* 	$OpenBSD: test_xextendf.c,v 1.1 2025/09/02 11:04:58 djm Exp $ */
/*
 * Regress test for misc xextendf() function.
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

శూన్య test_xextendf(శూన్య);

శూన్య
test_xextendf(శూన్య)
{
	అక్షరం *s = ఖాళీ;

	TEST_ప్రారంభం("xextendf NULL string");
	xextendf(&s, ",", "hello");
	ASSERT_STRING_EQ(s, "hello");
	విడుదల(s);
	s = ఖాళీ;
	TEST_పూర్తి();

	TEST_ప్రారంభం("xextendf empty string");
	s = xstrdup("");
	xextendf(&s, ",", "world");
	ASSERT_STRING_EQ(s, "world");
	విడుదల(s);
	s = ఖాళీ;
	TEST_పూర్తి();

	TEST_ప్రారంభం("xextendf append to string");
	s = xstrdup("foo");
	xextendf(&s, ",", "bar");
	ASSERT_STRING_EQ(s, "foo,bar");
	విడుదల(s);
	s = ఖాళీ;
	TEST_పూర్తి();

	TEST_ప్రారంభం("xextendf append with NULL separator");
	s = xstrdup("foo");
	xextendf(&s, ఖాళీ, "bar");
	ASSERT_STRING_EQ(s, "foobar");
	విడుదల(s);
	s = ఖాళీ;
	TEST_పూర్తి();

	TEST_ప్రారంభం("xextendf append with empty separator");
	s = xstrdup("foo");
	xextendf(&s, "", "bar");
	ASSERT_STRING_EQ(s, "foobar");
	విడుదల(s);
	s = ఖాళీ;
	TEST_పూర్తి();

	TEST_ప్రారంభం("xextendf with format string");
	s = xstrdup("start");
	xextendf(&s, ":", "s=%s,d=%d", "string", 123);
	ASSERT_STRING_EQ(s, "start:s=string,d=123");
	విడుదల(s);
	s = ఖాళీ;
	TEST_పూర్తి();

	TEST_ప్రారంభం("xextendf multiple appends");
	s = ఖాళీ;
	xextendf(&s, ",", "one");
	ASSERT_STRING_EQ(s, "one");
	xextendf(&s, ",", "two");
	ASSERT_STRING_EQ(s, "one,two");
	xextendf(&s, ":", "three=%d", 3);
	ASSERT_STRING_EQ(s, "one,two:three=3");
	xextendf(&s, ఖాళీ, "four");
	ASSERT_STRING_EQ(s, "one,two:three=3four");
	విడుదల(s);
	s = ఖాళీ;
	TEST_పూర్తి();
}
