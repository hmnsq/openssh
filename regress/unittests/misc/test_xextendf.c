/* 	$OpenBSD: test_xextendf.c,v 1.1 2025/09/02 11:04:58 djm Exp $ */
/*
 * Regress test for misc xextendf() function.
 *
 * Placed in the public domain.
 */

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <stdint.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <string.h>

#அந்தர்பாவ "../test_helper/test_helper.h"

#அந்தர்பாவ "log.h"
#அந்தர்பாவ "misc.h"
#அந்தர்பாவ "xmalloc.h"

வெறுமை test_xextendf(வெறுமை);

வெறுமை
test_xextendf(வெறுமை)
{
	எழுத்து *s = வெற்று;

	TEST_START("xextendf NULL string");
	xextendf(&s, ",", "hello");
	ASSERT_STRING_EQ(s, "hello");
	விடுவி(s);
	s = வெற்று;
	TEST_DONE();

	TEST_START("xextendf empty string");
	s = xstrdup("");
	xextendf(&s, ",", "world");
	ASSERT_STRING_EQ(s, "world");
	விடுவி(s);
	s = வெற்று;
	TEST_DONE();

	TEST_START("xextendf append to string");
	s = xstrdup("foo");
	xextendf(&s, ",", "bar");
	ASSERT_STRING_EQ(s, "foo,bar");
	விடுவி(s);
	s = வெற்று;
	TEST_DONE();

	TEST_START("xextendf append with NULL separator");
	s = xstrdup("foo");
	xextendf(&s, வெற்று, "bar");
	ASSERT_STRING_EQ(s, "foobar");
	விடுவி(s);
	s = வெற்று;
	TEST_DONE();

	TEST_START("xextendf append with empty separator");
	s = xstrdup("foo");
	xextendf(&s, "", "bar");
	ASSERT_STRING_EQ(s, "foobar");
	விடுவி(s);
	s = வெற்று;
	TEST_DONE();

	TEST_START("xextendf with format string");
	s = xstrdup("start");
	xextendf(&s, ":", "s=%s,d=%d", "string", 123);
	ASSERT_STRING_EQ(s, "start:s=string,d=123");
	விடுவி(s);
	s = வெற்று;
	TEST_DONE();

	TEST_START("xextendf multiple appends");
	s = வெற்று;
	xextendf(&s, ",", "one");
	ASSERT_STRING_EQ(s, "one");
	xextendf(&s, ",", "two");
	ASSERT_STRING_EQ(s, "one,two");
	xextendf(&s, ":", "three=%d", 3);
	ASSERT_STRING_EQ(s, "one,two:three=3");
	xextendf(&s, வெற்று, "four");
	ASSERT_STRING_EQ(s, "one,two:three=3four");
	விடுவி(s);
	s = வெற்று;
	TEST_DONE();
}
