/* 	$OpenBSD: test_xextendf.c,v 1.1 2025/09/02 11:04:58 djm Exp $ */
/*
 * Regress test for misc xextendf() function.
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

تهی test_xextendf(تهی);

تهی
test_xextendf(تهی)
{
	نویسه *s = پوچ;

	TEST_START("xextendf NULL string");
	xextendf(&s, ",", "hello");
	ASSERT_STRING_EQ(s, "hello");
	آزاد(s);
	s = پوچ;
	TEST_DONE();

	TEST_START("xextendf empty string");
	s = xstrdup("");
	xextendf(&s, ",", "world");
	ASSERT_STRING_EQ(s, "world");
	آزاد(s);
	s = پوچ;
	TEST_DONE();

	TEST_START("xextendf append to string");
	s = xstrdup("foo");
	xextendf(&s, ",", "bar");
	ASSERT_STRING_EQ(s, "foo,bar");
	آزاد(s);
	s = پوچ;
	TEST_DONE();

	TEST_START("xextendf append with NULL separator");
	s = xstrdup("foo");
	xextendf(&s, پوچ, "bar");
	ASSERT_STRING_EQ(s, "foobar");
	آزاد(s);
	s = پوچ;
	TEST_DONE();

	TEST_START("xextendf append with empty separator");
	s = xstrdup("foo");
	xextendf(&s, "", "bar");
	ASSERT_STRING_EQ(s, "foobar");
	آزاد(s);
	s = پوچ;
	TEST_DONE();

	TEST_START("xextendf with format string");
	s = xstrdup("start");
	xextendf(&s, ":", "s=%s,d=%d", "string", 123);
	ASSERT_STRING_EQ(s, "start:s=string,d=123");
	آزاد(s);
	s = پوچ;
	TEST_DONE();

	TEST_START("xextendf multiple appends");
	s = پوچ;
	xextendf(&s, ",", "one");
	ASSERT_STRING_EQ(s, "one");
	xextendf(&s, ",", "two");
	ASSERT_STRING_EQ(s, "one,two");
	xextendf(&s, ":", "three=%d", 3);
	ASSERT_STRING_EQ(s, "one,two:three=3");
	xextendf(&s, پوچ, "four");
	ASSERT_STRING_EQ(s, "one,two:three=3four");
	آزاد(s);
	s = پوچ;
	TEST_DONE();
}
