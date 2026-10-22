/* 	$OpenBSD: test_xextendf.c,v 1.1 2025/09/02 11:04:58 djm Exp $ */
/*
 * Regress test for misc xextendf() function.
 *
 * Placed in the public domain.
 */

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <stdint.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <string.h>

#അന്തര്ഭാവ "../test_helper/test_helper.h"

#അന്തര്ഭാവ "log.h"
#അന്തര്ഭാവ "misc.h"
#അന്തര്ഭാവ "xmalloc.h"

ശൂന്യം test_xextendf(ശൂന്യം);

ശൂന്യം
test_xextendf(ശൂന്യം)
{
	അക്ഷരം *s = ശൂന്യ;

	TEST_START("xextendf NULL string");
	xextendf(&s, ",", "hello");
	ASSERT_STRING_EQ(s, "hello");
	സ്വതന്ത്രം(s);
	s = ശൂന്യ;
	TEST_DONE();

	TEST_START("xextendf empty string");
	s = xstrdup("");
	xextendf(&s, ",", "world");
	ASSERT_STRING_EQ(s, "world");
	സ്വതന്ത്രം(s);
	s = ശൂന്യ;
	TEST_DONE();

	TEST_START("xextendf append to string");
	s = xstrdup("foo");
	xextendf(&s, ",", "bar");
	ASSERT_STRING_EQ(s, "foo,bar");
	സ്വതന്ത്രം(s);
	s = ശൂന്യ;
	TEST_DONE();

	TEST_START("xextendf append with NULL separator");
	s = xstrdup("foo");
	xextendf(&s, ശൂന്യ, "bar");
	ASSERT_STRING_EQ(s, "foobar");
	സ്വതന്ത്രം(s);
	s = ശൂന്യ;
	TEST_DONE();

	TEST_START("xextendf append with empty separator");
	s = xstrdup("foo");
	xextendf(&s, "", "bar");
	ASSERT_STRING_EQ(s, "foobar");
	സ്വതന്ത്രം(s);
	s = ശൂന്യ;
	TEST_DONE();

	TEST_START("xextendf with format string");
	s = xstrdup("start");
	xextendf(&s, ":", "s=%s,d=%d", "string", 123);
	ASSERT_STRING_EQ(s, "start:s=string,d=123");
	സ്വതന്ത്രം(s);
	s = ശൂന്യ;
	TEST_DONE();

	TEST_START("xextendf multiple appends");
	s = ശൂന്യ;
	xextendf(&s, ",", "one");
	ASSERT_STRING_EQ(s, "one");
	xextendf(&s, ",", "two");
	ASSERT_STRING_EQ(s, "one,two");
	xextendf(&s, ":", "three=%d", 3);
	ASSERT_STRING_EQ(s, "one,two:three=3");
	xextendf(&s, ശൂന്യ, "four");
	ASSERT_STRING_EQ(s, "one,two:three=3four");
	സ്വതന്ത്രം(s);
	s = ശൂന്യ;
	TEST_DONE();
}
