/* 	$OpenBSD: test_xextendf.c,v 1.1 2025/09/02 11:04:58 djm Exp $ */
/*
 * Regress test for misc xextendf() function.
 *
 * Placed in the public domain.
 */

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdint.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "../test_helper/test_helper.h"

#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "misc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "xmalloc.h"

ਖਾਲੀ test_xextendf(ਖਾਲੀ);

ਖਾਲੀ
test_xextendf(ਖਾਲੀ)
{
	ਅੱਖਰ *s = ਨਿਰਾ;

	TEST_ਸ਼ੁਰੂ("xextendf NULL string");
	xextendf(&s, ",", "hello");
	ASSERT_STRING_EQ(s, "hello");
	ਮੁਕਤ(s);
	s = ਨਿਰਾ;
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("xextendf empty string");
	s = xstrdup("");
	xextendf(&s, ",", "world");
	ASSERT_STRING_EQ(s, "world");
	ਮੁਕਤ(s);
	s = ਨਿਰਾ;
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("xextendf append to string");
	s = xstrdup("foo");
	xextendf(&s, ",", "bar");
	ASSERT_STRING_EQ(s, "foo,bar");
	ਮੁਕਤ(s);
	s = ਨਿਰਾ;
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("xextendf append with NULL separator");
	s = xstrdup("foo");
	xextendf(&s, ਨਿਰਾ, "bar");
	ASSERT_STRING_EQ(s, "foobar");
	ਮੁਕਤ(s);
	s = ਨਿਰਾ;
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("xextendf append with empty separator");
	s = xstrdup("foo");
	xextendf(&s, "", "bar");
	ASSERT_STRING_EQ(s, "foobar");
	ਮੁਕਤ(s);
	s = ਨਿਰਾ;
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("xextendf with format string");
	s = xstrdup("start");
	xextendf(&s, ":", "s=%s,d=%d", "string", 123);
	ASSERT_STRING_EQ(s, "start:s=string,d=123");
	ਮੁਕਤ(s);
	s = ਨਿਰਾ;
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("xextendf multiple appends");
	s = ਨਿਰਾ;
	xextendf(&s, ",", "one");
	ASSERT_STRING_EQ(s, "one");
	xextendf(&s, ",", "two");
	ASSERT_STRING_EQ(s, "one,two");
	xextendf(&s, ":", "three=%d", 3);
	ASSERT_STRING_EQ(s, "one,two:three=3");
	xextendf(&s, ਨਿਰਾ, "four");
	ASSERT_STRING_EQ(s, "one,two:three=3four");
	ਮੁਕਤ(s);
	s = ਨਿਰਾ;
	TEST_ਪੂਰਾ();
}
