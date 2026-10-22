/* 	$OpenBSD: test_xextendf.c,v 1.1 2025/09/02 11:04:58 djm Exp $ */
/*
 * Regress test for misc xextendf() function.
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

শূন্য test_xextendf(শূন্য);

শূন্য
test_xextendf(শূন্য)
{
	ৱর্ণ *s = রিক্ত;

	TEST_START("xextendf NULL string");
	xextendf(&s, ",", "hello");
	ASSERT_STRING_EQ(s, "hello");
	মুক্ত(s);
	s = রিক্ত;
	TEST_DONE();

	TEST_START("xextendf empty string");
	s = xstrdup("");
	xextendf(&s, ",", "world");
	ASSERT_STRING_EQ(s, "world");
	মুক্ত(s);
	s = রিক্ত;
	TEST_DONE();

	TEST_START("xextendf append to string");
	s = xstrdup("foo");
	xextendf(&s, ",", "bar");
	ASSERT_STRING_EQ(s, "foo,bar");
	মুক্ত(s);
	s = রিক্ত;
	TEST_DONE();

	TEST_START("xextendf append with NULL separator");
	s = xstrdup("foo");
	xextendf(&s, রিক্ত, "bar");
	ASSERT_STRING_EQ(s, "foobar");
	মুক্ত(s);
	s = রিক্ত;
	TEST_DONE();

	TEST_START("xextendf append with empty separator");
	s = xstrdup("foo");
	xextendf(&s, "", "bar");
	ASSERT_STRING_EQ(s, "foobar");
	মুক্ত(s);
	s = রিক্ত;
	TEST_DONE();

	TEST_START("xextendf with format string");
	s = xstrdup("start");
	xextendf(&s, ":", "s=%s,d=%d", "string", 123);
	ASSERT_STRING_EQ(s, "start:s=string,d=123");
	মুক্ত(s);
	s = রিক্ত;
	TEST_DONE();

	TEST_START("xextendf multiple appends");
	s = রিক্ত;
	xextendf(&s, ",", "one");
	ASSERT_STRING_EQ(s, "one");
	xextendf(&s, ",", "two");
	ASSERT_STRING_EQ(s, "one,two");
	xextendf(&s, ":", "three=%d", 3);
	ASSERT_STRING_EQ(s, "one,two:three=3");
	xextendf(&s, রিক্ত, "four");
	ASSERT_STRING_EQ(s, "one,two:three=3four");
	মুক্ত(s);
	s = রিক্ত;
	TEST_DONE();
}
