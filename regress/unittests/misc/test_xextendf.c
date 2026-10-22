/* 	$OpenBSD: test_xextendf.c,v 1.1 2025/09/02 11:04:58 djm Exp $ */
/*
 * Regress test for misc xextendf() function.
 *
 * Placed in the public domain.
 */

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stdint.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>

#ಅನ್ತರ್ಭಾವ "../test_helper/test_helper.h"

#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "misc.h"
#ಅನ್ತರ್ಭಾವ "xmalloc.h"

ಶೂನ್ಯ test_xextendf(ಶೂನ್ಯ);

ಶೂನ್ಯ
test_xextendf(ಶೂನ್ಯ)
{
	ವರ್ಣ *s = ರಿಕ್ತ;

	TEST_START("xextendf NULL string");
	xextendf(&s, ",", "hello");
	ASSERT_STRING_EQ(s, "hello");
	ಮುಕ್ತ(s);
	s = ರಿಕ್ತ;
	TEST_DONE();

	TEST_START("xextendf empty string");
	s = xstrdup("");
	xextendf(&s, ",", "world");
	ASSERT_STRING_EQ(s, "world");
	ಮುಕ್ತ(s);
	s = ರಿಕ್ತ;
	TEST_DONE();

	TEST_START("xextendf append to string");
	s = xstrdup("foo");
	xextendf(&s, ",", "bar");
	ASSERT_STRING_EQ(s, "foo,bar");
	ಮುಕ್ತ(s);
	s = ರಿಕ್ತ;
	TEST_DONE();

	TEST_START("xextendf append with NULL separator");
	s = xstrdup("foo");
	xextendf(&s, ರಿಕ್ತ, "bar");
	ASSERT_STRING_EQ(s, "foobar");
	ಮುಕ್ತ(s);
	s = ರಿಕ್ತ;
	TEST_DONE();

	TEST_START("xextendf append with empty separator");
	s = xstrdup("foo");
	xextendf(&s, "", "bar");
	ASSERT_STRING_EQ(s, "foobar");
	ಮುಕ್ತ(s);
	s = ರಿಕ್ತ;
	TEST_DONE();

	TEST_START("xextendf with format string");
	s = xstrdup("start");
	xextendf(&s, ":", "s=%s,d=%d", "string", 123);
	ASSERT_STRING_EQ(s, "start:s=string,d=123");
	ಮುಕ್ತ(s);
	s = ರಿಕ್ತ;
	TEST_DONE();

	TEST_START("xextendf multiple appends");
	s = ರಿಕ್ತ;
	xextendf(&s, ",", "one");
	ASSERT_STRING_EQ(s, "one");
	xextendf(&s, ",", "two");
	ASSERT_STRING_EQ(s, "one,two");
	xextendf(&s, ":", "three=%d", 3);
	ASSERT_STRING_EQ(s, "one,two:three=3");
	xextendf(&s, ರಿಕ್ತ, "four");
	ASSERT_STRING_EQ(s, "one,two:three=3four");
	ಮುಕ್ತ(s);
	s = ರಿಕ್ತ;
	TEST_DONE();
}
