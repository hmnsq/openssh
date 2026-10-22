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
	ಅಕ್ಷರ *s = ಖಾಲಿ;

	TEST_ಆರಂಭ("xextendf NULL string");
	xextendf(&s, ",", "hello");
	ASSERT_STRING_EQ(s, "hello");
	ಬಿಡುಗಡೆ(s);
	s = ಖಾಲಿ;
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("xextendf empty string");
	s = xstrdup("");
	xextendf(&s, ",", "world");
	ASSERT_STRING_EQ(s, "world");
	ಬಿಡುಗಡೆ(s);
	s = ಖಾಲಿ;
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("xextendf append to string");
	s = xstrdup("foo");
	xextendf(&s, ",", "bar");
	ASSERT_STRING_EQ(s, "foo,bar");
	ಬಿಡುಗಡೆ(s);
	s = ಖಾಲಿ;
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("xextendf append with NULL separator");
	s = xstrdup("foo");
	xextendf(&s, ಖಾಲಿ, "bar");
	ASSERT_STRING_EQ(s, "foobar");
	ಬಿಡುಗಡೆ(s);
	s = ಖಾಲಿ;
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("xextendf append with empty separator");
	s = xstrdup("foo");
	xextendf(&s, "", "bar");
	ASSERT_STRING_EQ(s, "foobar");
	ಬಿಡುಗಡೆ(s);
	s = ಖಾಲಿ;
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("xextendf with format string");
	s = xstrdup("start");
	xextendf(&s, ":", "s=%s,d=%d", "string", 123);
	ASSERT_STRING_EQ(s, "start:s=string,d=123");
	ಬಿಡುಗಡೆ(s);
	s = ಖಾಲಿ;
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("xextendf multiple appends");
	s = ಖಾಲಿ;
	xextendf(&s, ",", "one");
	ASSERT_STRING_EQ(s, "one");
	xextendf(&s, ",", "two");
	ASSERT_STRING_EQ(s, "one,two");
	xextendf(&s, ":", "three=%d", 3);
	ASSERT_STRING_EQ(s, "one,two:three=3");
	xextendf(&s, ಖಾಲಿ, "four");
	ASSERT_STRING_EQ(s, "one,two:three=3four");
	ಬಿಡುಗಡೆ(s);
	s = ಖಾಲಿ;
	TEST_ಮುಗಿದ();
}
