/* 	$OpenBSD: test_xextendf.c,v 1.1 2025/09/02 11:04:58 djm Exp $ */
/*
 * Regress test for misc xextendf() function.
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

शून्य test_xextendf(शून्य);

शून्य
test_xextendf(शून्य)
{
	वर्ण *s = रिक्त;

	TEST_START("xextendf NULL string");
	xextendf(&s, ",", "hello");
	ASSERT_STRING_EQ(s, "hello");
	मुक्त(s);
	s = रिक्त;
	TEST_समाप्तम्();

	TEST_START("xextendf empty string");
	s = xstrdup("");
	xextendf(&s, ",", "world");
	ASSERT_STRING_EQ(s, "world");
	मुक्त(s);
	s = रिक्त;
	TEST_समाप्तम्();

	TEST_START("xextendf append to string");
	s = xstrdup("foo");
	xextendf(&s, ",", "bar");
	ASSERT_STRING_EQ(s, "foo,bar");
	मुक्त(s);
	s = रिक्त;
	TEST_समाप्तम्();

	TEST_START("xextendf append with NULL separator");
	s = xstrdup("foo");
	xextendf(&s, रिक्त, "bar");
	ASSERT_STRING_EQ(s, "foobar");
	मुक्त(s);
	s = रिक्त;
	TEST_समाप्तम्();

	TEST_START("xextendf append with empty separator");
	s = xstrdup("foo");
	xextendf(&s, "", "bar");
	ASSERT_STRING_EQ(s, "foobar");
	मुक्त(s);
	s = रिक्त;
	TEST_समाप्तम्();

	TEST_START("xextendf with format string");
	s = xstrdup("start");
	xextendf(&s, ":", "s=%s,d=%d", "string", 123);
	ASSERT_STRING_EQ(s, "start:s=string,d=123");
	मुक्त(s);
	s = रिक्त;
	TEST_समाप्तम्();

	TEST_START("xextendf multiple appends");
	s = रिक्त;
	xextendf(&s, ",", "one");
	ASSERT_STRING_EQ(s, "one");
	xextendf(&s, ",", "two");
	ASSERT_STRING_EQ(s, "one,two");
	xextendf(&s, ":", "three=%d", 3);
	ASSERT_STRING_EQ(s, "one,two:three=3");
	xextendf(&s, रिक्त, "four");
	ASSERT_STRING_EQ(s, "one,two:three=3four");
	मुक्त(s);
	s = रिक्त;
	TEST_समाप्तम्();
}
