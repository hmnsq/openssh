/* 	$OpenBSD: test_xextendf.c,v 1.1 2025/09/02 11:04:58 djm Exp $ */
/*
 * Regress test for misc xextendf() function.
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

فراغ test_xextendf(فراغ);

فراغ
test_xextendf(فراغ)
{
	حرف *s = عدم;

	TEST_START("xextendf NULL string");
	xextendf(&s, ",", "hello");
	ASSERT_STRING_EQ(s, "hello");
	حرر(s);
	s = عدم;
	TEST_DONE();

	TEST_START("xextendf empty string");
	s = xstrdup("");
	xextendf(&s, ",", "world");
	ASSERT_STRING_EQ(s, "world");
	حرر(s);
	s = عدم;
	TEST_DONE();

	TEST_START("xextendf append to string");
	s = xstrdup("foo");
	xextendf(&s, ",", "bar");
	ASSERT_STRING_EQ(s, "foo,bar");
	حرر(s);
	s = عدم;
	TEST_DONE();

	TEST_START("xextendf append with NULL separator");
	s = xstrdup("foo");
	xextendf(&s, عدم, "bar");
	ASSERT_STRING_EQ(s, "foobar");
	حرر(s);
	s = عدم;
	TEST_DONE();

	TEST_START("xextendf append with empty separator");
	s = xstrdup("foo");
	xextendf(&s, "", "bar");
	ASSERT_STRING_EQ(s, "foobar");
	حرر(s);
	s = عدم;
	TEST_DONE();

	TEST_START("xextendf with format string");
	s = xstrdup("start");
	xextendf(&s, ":", "s=%s,d=%d", "string", 123);
	ASSERT_STRING_EQ(s, "start:s=string,d=123");
	حرر(s);
	s = عدم;
	TEST_DONE();

	TEST_START("xextendf multiple appends");
	s = عدم;
	xextendf(&s, ",", "one");
	ASSERT_STRING_EQ(s, "one");
	xextendf(&s, ",", "two");
	ASSERT_STRING_EQ(s, "one,two");
	xextendf(&s, ":", "three=%d", 3);
	ASSERT_STRING_EQ(s, "one,two:three=3");
	xextendf(&s, عدم, "four");
	ASSERT_STRING_EQ(s, "one,two:three=3four");
	حرر(s);
	s = عدم;
	TEST_DONE();
}
