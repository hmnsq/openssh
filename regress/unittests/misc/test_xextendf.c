/* 	$OpenBSD: test_xextendf.c,v 1.1 2025/09/02 11:04:58 djm Exp $ */
/*
 * Regress test for misc xextendf() function.
 *
 * Placed in the public domain.
 */

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <sys/types.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <stdint.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <string.h>

#ଅନ୍ତର୍ଭାଵ "../test_helper/test_helper.h"

#ଅନ୍ତର୍ଭାଵ "log.h"
#ଅନ୍ତର୍ଭାଵ "misc.h"
#ଅନ୍ତର୍ଭାଵ "xmalloc.h"

ଶୂନ୍ୟ test_xextendf(ଶୂନ୍ୟ);

ଶୂନ୍ୟ
test_xextendf(ଶୂନ୍ୟ)
{
	ଅକ୍ଷର *s = ଖାଲି;

	TEST_START("xextendf NULL string");
	xextendf(&s, ",", "hello");
	ASSERT_STRING_EQ(s, "hello");
	ମୁକ୍ତ(s);
	s = ଖାଲି;
	TEST_DONE();

	TEST_START("xextendf empty string");
	s = xstrdup("");
	xextendf(&s, ",", "world");
	ASSERT_STRING_EQ(s, "world");
	ମୁକ୍ତ(s);
	s = ଖାଲି;
	TEST_DONE();

	TEST_START("xextendf append to string");
	s = xstrdup("foo");
	xextendf(&s, ",", "bar");
	ASSERT_STRING_EQ(s, "foo,bar");
	ମୁକ୍ତ(s);
	s = ଖାଲି;
	TEST_DONE();

	TEST_START("xextendf append with NULL separator");
	s = xstrdup("foo");
	xextendf(&s, ଖାଲି, "bar");
	ASSERT_STRING_EQ(s, "foobar");
	ମୁକ୍ତ(s);
	s = ଖାଲି;
	TEST_DONE();

	TEST_START("xextendf append with empty separator");
	s = xstrdup("foo");
	xextendf(&s, "", "bar");
	ASSERT_STRING_EQ(s, "foobar");
	ମୁକ୍ତ(s);
	s = ଖାଲି;
	TEST_DONE();

	TEST_START("xextendf with format string");
	s = xstrdup("start");
	xextendf(&s, ":", "s=%s,d=%d", "string", 123);
	ASSERT_STRING_EQ(s, "start:s=string,d=123");
	ମୁକ୍ତ(s);
	s = ଖାଲି;
	TEST_DONE();

	TEST_START("xextendf multiple appends");
	s = ଖାଲି;
	xextendf(&s, ",", "one");
	ASSERT_STRING_EQ(s, "one");
	xextendf(&s, ",", "two");
	ASSERT_STRING_EQ(s, "one,two");
	xextendf(&s, ":", "three=%d", 3);
	ASSERT_STRING_EQ(s, "one,two:three=3");
	xextendf(&s, ଖାଲି, "four");
	ASSERT_STRING_EQ(s, "one,two:three=3four");
	ମୁକ୍ତ(s);
	s = ଖାଲି;
	TEST_DONE();
}
