/*
 * Regress test for misc helper functions.
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

ଶୂନ୍ୟ test_misc(ଶୂନ୍ୟ);

ସ୍ଥିର ଶୂନ୍ୟ
test_chop(ଶୂନ୍ୟ)
{
	ଅକ୍ଷର *s;

	TEST_START("chop newline");
	s = xstrdup("hello\n");
	ASSERT_STRING_EQ(chop(s), "hello");
	ମୁକ୍ତ(s);
	TEST_DONE();

	TEST_START("chop carriage return");
	s = xstrdup("hello\r");
	ASSERT_STRING_EQ(chop(s), "hello");
	ମୁକ୍ତ(s);
	TEST_DONE();

	TEST_START("chop CRLF");
	s = xstrdup("hello\r\n");
	ASSERT_STRING_EQ(chop(s), "hello");
	ମୁକ୍ତ(s);
	TEST_DONE();

	TEST_START("chop newline in middle");
	s = xstrdup("he\nllo");
	ASSERT_STRING_EQ(chop(s), "he");
	ମୁକ୍ତ(s);
	TEST_DONE();

	TEST_START("chop no newline");
	s = xstrdup("hello");
	ASSERT_STRING_EQ(chop(s), "hello");
	ମୁକ୍ତ(s);
	TEST_DONE();

	TEST_START("chop empty string");
	s = xstrdup("");
	ASSERT_STRING_EQ(chop(s), "");
	ମୁକ୍ତ(s);
	TEST_DONE();

	TEST_START("chop only newline");
	s = xstrdup("\n");
	ASSERT_STRING_EQ(chop(s), "");
	ମୁକ୍ତ(s);
	TEST_DONE();

	TEST_START("chop only CR");
	s = xstrdup("\r");
	ASSERT_STRING_EQ(chop(s), "");
	ମୁକ୍ତ(s);
	TEST_DONE();

	TEST_START("chop only CRLF");
	s = xstrdup("\r\n");
	ASSERT_STRING_EQ(chop(s), "");
	ମୁକ୍ତ(s);
	TEST_DONE();
}

ସ୍ଥିର ଶୂନ୍ୟ
test_rtrim(ଶୂନ୍ୟ)
{
	ଅକ୍ଷର *s;

	TEST_START("rtrim trailing space");
	s = xstrdup("hello  ");
	rtrim(s);
	ASSERT_STRING_EQ(s, "hello");
	ମୁକ୍ତ(s);
	TEST_DONE();

	TEST_START("rtrim trailing tab");
	s = xstrdup("hello\t\t");
	rtrim(s);
	ASSERT_STRING_EQ(s, "hello");
	ମୁକ୍ତ(s);
	TEST_DONE();

	TEST_START("rtrim trailing mixed whitespace");
	s = xstrdup("hello \t ");
	rtrim(s);
	ASSERT_STRING_EQ(s, "hello");
	ମୁକ୍ତ(s);
	TEST_DONE();

	TEST_START("rtrim no trailing whitespace");
	s = xstrdup("hello");
	rtrim(s);
	ASSERT_STRING_EQ(s, "hello");
	ମୁକ୍ତ(s);
	TEST_DONE();

	TEST_START("rtrim whitespace in middle");
	s = xstrdup("he llo");
	rtrim(s);
	ASSERT_STRING_EQ(s, "he llo");
	ମୁକ୍ତ(s);
	TEST_DONE();

	TEST_START("rtrim empty string");
	s = xstrdup("");
	rtrim(s);
	ASSERT_STRING_EQ(s, "");
	ମୁକ୍ତ(s);
	TEST_DONE();

	TEST_START("rtrim only whitespace");
	s = xstrdup("   \t");
	rtrim(s);
	ASSERT_STRING_EQ(s, "");
	ମୁକ୍ତ(s);
	TEST_DONE();
}

ସ୍ଥିର ଶୂନ୍ୟ
test_strprefix(ଶୂନ୍ୟ)
{
	ଅଚଳ ଅକ୍ଷର *s;

	TEST_START("strprefix basic match");
	s = strprefix("hello world", "hello", 0);
	ASSERT_PTR_NE(s, ଖାଲି);
	ASSERT_STRING_EQ(s, " world");
	TEST_DONE();

	TEST_START("strprefix no match");
	s = strprefix("hello world", "world", 0);
	ASSERT_PTR_EQ(s, ଖାଲି);
	TEST_DONE();

	TEST_START("strprefix full match");
	s = strprefix("hello", "hello", 0);
	ASSERT_PTR_NE(s, ଖାଲି);
	ASSERT_STRING_EQ(s, "");
	TEST_DONE();

	TEST_START("strprefix empty string");
	s = strprefix("", "hello", 0);
	ASSERT_PTR_EQ(s, ଖାଲି);
	TEST_DONE();

	TEST_START("strprefix empty prefix");
	s = strprefix("hello", "", 0);
	ASSERT_PTR_NE(s, ଖାଲି);
	ASSERT_STRING_EQ(s, "hello");
	TEST_DONE();

	TEST_START("strprefix case sensitive no match");
	s = strprefix("Hello world", "hello", 0);
	ASSERT_PTR_EQ(s, ଖାଲି);
	TEST_DONE();

	TEST_START("strprefix case insensitive match");
	s = strprefix("Hello world", "hello", 1);
	ASSERT_PTR_NE(s, ଖାଲି);
	ASSERT_STRING_EQ(s, " world");
	TEST_DONE();

	TEST_START("strprefix case insensitive full match");
	s = strprefix("HELLO", "hello", 1);
	ASSERT_PTR_NE(s, ଖାଲି);
	ASSERT_STRING_EQ(s, "");
	TEST_DONE();
}

ସ୍ଥିର ଶୂନ୍ୟ
test_fmt_timeframe(ଶୂନ୍ୟ)
{
	TEST_START("fmt_timeframe seconds");
	ASSERT_STRING_EQ(fmt_timeframe(0), "00:00:00");
	ASSERT_STRING_EQ(fmt_timeframe(59), "00:00:59");
	ASSERT_STRING_EQ(fmt_timeframe(60), "00:01:00");
	ASSERT_STRING_EQ(fmt_timeframe(3599), "00:59:59");
	ASSERT_STRING_EQ(fmt_timeframe(3600), "01:00:00");
	ASSERT_STRING_EQ(fmt_timeframe(86399), "23:59:59");
	TEST_DONE();

	TEST_START("fmt_timeframe days");
	ASSERT_STRING_EQ(fmt_timeframe(86400), "1d00h00m");
	ASSERT_STRING_EQ(fmt_timeframe(90061), "1d01h01m");
	ASSERT_STRING_EQ(fmt_timeframe(604799), "6d23h59m");
	TEST_DONE();

	TEST_START("fmt_timeframe weeks");
	ASSERT_STRING_EQ(fmt_timeframe(604800), "01w0d00h");
	ASSERT_STRING_EQ(fmt_timeframe(694861), "01w1d01h");
	TEST_DONE();
}

ସ୍ଥିର ଶୂନ୍ୟ
test_arglist(ଶୂନ୍ୟ)
{
	arglist args;
	u_int i;

	memset(&args, 0, ଆକାର(args));

	TEST_START("addargs initial");
	addargs(&args, "one");
	ASSERT_U_INT_EQ(args.ଅଙ୍କ, 1);
	ASSERT_U_INT_EQ(args.nalloc, 32);
	ASSERT_PTR_NE(args.list, ଖାଲି);
	ASSERT_STRING_EQ(args.list[0], "one");
	ASSERT_PTR_EQ(args.list[1], ଖାଲି);
	TEST_DONE();

	TEST_START("addargs second");
	addargs(&args, "two");
	ASSERT_U_INT_EQ(args.ଅଙ୍କ, 2);
	ASSERT_U_INT_EQ(args.nalloc, 32);
	ASSERT_PTR_NE(args.list, ଖାଲି);
	ASSERT_STRING_EQ(args.list[0], "one");
	ASSERT_STRING_EQ(args.list[1], "two");
	ASSERT_PTR_EQ(args.list[2], ଖାଲି);
	TEST_DONE();

	TEST_START("addargs with format");
	addargs(&args, "three=%d", 3);
	ASSERT_U_INT_EQ(args.ଅଙ୍କ, 3);
	ASSERT_U_INT_EQ(args.nalloc, 32);
	ASSERT_PTR_NE(args.list, ଖାଲି);
	ASSERT_STRING_EQ(args.list[0], "one");
	ASSERT_STRING_EQ(args.list[1], "two");
	ASSERT_STRING_EQ(args.list[2], "three=3");
	ASSERT_PTR_EQ(args.list[3], ଖାଲି);
	TEST_DONE();

	TEST_START("replacearg middle");
	replacearg(&args, 1, "TWO!");
	ASSERT_U_INT_EQ(args.ଅଙ୍କ, 3);
	ASSERT_STRING_EQ(args.list[0], "one");
	ASSERT_STRING_EQ(args.list[1], "TWO!");
	ASSERT_STRING_EQ(args.list[2], "three=3");
	ASSERT_PTR_EQ(args.list[3], ଖାଲି);
	TEST_DONE();

	TEST_START("replacearg first");
	replacearg(&args, 0, "ONE!");
	ASSERT_U_INT_EQ(args.ଅଙ୍କ, 3);
	ASSERT_STRING_EQ(args.list[0], "ONE!");
	ASSERT_STRING_EQ(args.list[1], "TWO!");
	ASSERT_STRING_EQ(args.list[2], "three=3");
	ASSERT_PTR_EQ(args.list[3], ଖାଲି);
	TEST_DONE();

	TEST_START("replacearg last");
	replacearg(&args, 2, "THREE=3!");
	ASSERT_U_INT_EQ(args.ଅଙ୍କ, 3);
	ASSERT_STRING_EQ(args.list[0], "ONE!");
	ASSERT_STRING_EQ(args.list[1], "TWO!");
	ASSERT_STRING_EQ(args.list[2], "THREE=3!");
	ASSERT_PTR_EQ(args.list[3], ଖାଲି);
	TEST_DONE();

	TEST_START("replacearg with format");
	replacearg(&args, 1, "two=%d", 2);
	ASSERT_U_INT_EQ(args.ଅଙ୍କ, 3);
	ASSERT_STRING_EQ(args.list[0], "ONE!");
	ASSERT_STRING_EQ(args.list[1], "two=2");
	ASSERT_STRING_EQ(args.list[2], "THREE=3!");
	ASSERT_PTR_EQ(args.list[3], ଖାଲି);
	TEST_DONE();

	TEST_START("addargs reallocation");
	ପାଇଁ (i = args.ଅଙ୍କ; i < 33; i++)
		addargs(&args, "pad-%d", i);
	ASSERT_U_INT_EQ(args.ଅଙ୍କ, 33);
	ASSERT_U_INT_GE(args.nalloc, 33);
	ASSERT_STRING_EQ(args.list[32], "pad-32");
	ASSERT_PTR_EQ(args.list[33], ଖାଲି);
	TEST_DONE();

	TEST_START("freeargs");
	freeargs(&args);
	ASSERT_U_INT_EQ(args.ଅଙ୍କ, 0);
	ASSERT_U_INT_EQ(args.nalloc, 0);
	ASSERT_PTR_EQ(args.list, ଖାଲି);
	TEST_DONE();

	TEST_START("freeargs on NULL");
	freeargs(ଖାଲି);
	TEST_DONE();

	TEST_START("freeargs on empty");
	memset(&args, 0, ଆକାର(args));
	freeargs(&args);
	ASSERT_U_INT_EQ(args.ଅଙ୍କ, 0);
	ASSERT_U_INT_EQ(args.nalloc, 0);
	ASSERT_PTR_EQ(args.list, ଖାଲି);
	TEST_DONE();
}

ସ୍ଥିର ଶୂନ୍ୟ
test_tohex(ଶୂନ୍ୟ)
{
	ଅକ୍ଷର *hex;

	TEST_START("tohex simple");
	hex = tohex("foo", 3);
	ASSERT_STRING_EQ(hex, "666f6f");
	ମୁକ୍ତ(hex);
	TEST_DONE();

	TEST_START("tohex with null");
	hex = tohex("a\0b", 3);
	ASSERT_STRING_EQ(hex, "610062");
	ମୁକ୍ତ(hex);
	TEST_DONE();

	TEST_START("tohex empty");
	hex = tohex("", 0);
	ASSERT_STRING_EQ(hex, "");
	ମୁକ୍ତ(hex);
	TEST_DONE();
}

ସ୍ଥିର ଶୂନ୍ୟ
test_lowercase(ଶୂନ୍ୟ)
{
	ଅକ୍ଷର *s;

	TEST_START("lowercase mixed");
	s = xstrdup("HeLlO WoRlD 123");
	lowercase(s);
	ASSERT_STRING_EQ(s, "hello world 123");
	ମୁକ୍ତ(s);
	TEST_DONE();

	TEST_START("lowercase empty");
	s = xstrdup("");
	lowercase(s);
	ASSERT_STRING_EQ(s, "");
	ମୁକ୍ତ(s);
	TEST_DONE();
}

ସ୍ଥିର ଶୂନ୍ୟ
test_path_absolute(ଶୂନ୍ୟ)
{
	TEST_START("path_absolute absolute");
	ASSERT_INT_EQ(path_absolute("/foo/bar"), 1);
	TEST_DONE();

	TEST_START("path_absolute relative");
	ASSERT_INT_EQ(path_absolute("foo/bar"), 0);
	TEST_DONE();

	TEST_START("path_absolute empty");
	ASSERT_INT_EQ(path_absolute(""), 0);
	TEST_DONE();
}

ସ୍ଥିର ଶୂନ୍ୟ
test_stringlist(ଶୂନ୍ୟ)
{
	ଅକ୍ଷର **list = ଖାଲି;

	TEST_START("stringlist_append initial");
	stringlist_append(&list, "one");
	ASSERT_PTR_NE(list, ଖାଲି);
	ASSERT_STRING_EQ(list[0], "one");
	ASSERT_PTR_EQ(list[1], ଖାଲି);
	TEST_DONE();

	TEST_START("stringlist_append second");
	stringlist_append(&list, "two");
	ASSERT_PTR_NE(list, ଖାଲି);
	ASSERT_STRING_EQ(list[0], "one");
	ASSERT_STRING_EQ(list[1], "two");
	ASSERT_PTR_EQ(list[2], ଖାଲି);
	TEST_DONE();

	TEST_START("stringlist_append third");
	stringlist_append(&list, "three");
	ASSERT_PTR_NE(list, ଖାଲି);
	ASSERT_STRING_EQ(list[0], "one");
	ASSERT_STRING_EQ(list[1], "two");
	ASSERT_STRING_EQ(list[2], "three");
	ASSERT_PTR_EQ(list[3], ଖାଲି);
	TEST_DONE();

	TEST_START("stringlist_free");
	stringlist_free(list);
	TEST_DONE();

	TEST_START("stringlist_free NULL");
	stringlist_free(ଖାଲି);
	TEST_DONE();
}

ସ୍ଥିର ଶୂନ୍ୟ
test_skip_space(ଶୂନ୍ୟ)
{
	ଅକ୍ଷର *s, *p;

	TEST_START("skip_space leading spaces");
	s = p = xstrdup("  hello");
	skip_space(&p);
	ASSERT_STRING_EQ(p, "hello");
	ମୁକ୍ତ(s);
	TEST_DONE();

	TEST_START("skip_space leading tabs");
	s = p = xstrdup("\t\thello");
	skip_space(&p);
	ASSERT_STRING_EQ(p, "hello");
	ମୁକ୍ତ(s);
	TEST_DONE();

	TEST_START("skip_space leading mixed whitespace");
	s = p = xstrdup(" \t hello");
	skip_space(&p);
	ASSERT_STRING_EQ(p, "hello");
	ମୁକ୍ତ(s);
	TEST_DONE();

	TEST_START("skip_space no leading whitespace");
	s = p = xstrdup("hello");
	skip_space(&p);
	ASSERT_STRING_EQ(p, "hello");
	ମୁକ୍ତ(s);
	TEST_DONE();

	TEST_START("skip_space empty string");
	s = p = xstrdup("");
	skip_space(&p);
	ASSERT_STRING_EQ(p, "");
	ମୁକ୍ତ(s);
	TEST_DONE();

	TEST_START("skip_space only whitespace");
	s = p = xstrdup(" \t ");
	skip_space(&p);
	ASSERT_STRING_EQ(p, "");
	ମୁକ୍ତ(s);
	TEST_DONE();
}

ଶୂନ୍ୟ
test_misc(ଶୂନ୍ୟ)
{
	test_chop();
	test_rtrim();
	test_strprefix();
	test_fmt_timeframe();
	test_arglist();
	test_tohex();
	test_lowercase();
	test_path_absolute();
	test_stringlist();
	test_skip_space();
}
