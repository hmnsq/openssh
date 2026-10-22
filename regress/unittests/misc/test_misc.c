/*
 * Regress test for misc helper functions.
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

ಶೂನ್ಯ test_misc(ಶೂನ್ಯ);

ಸ್ಥಿರ ಶೂನ್ಯ
test_chop(ಶೂನ್ಯ)
{
	ವರ್ಣ *s;

	TEST_START("chop newline");
	s = xstrdup("hello\n");
	ASSERT_STRING_EQ(chop(s), "hello");
	ಮುಕ್ತ(s);
	TEST_DONE();

	TEST_START("chop carriage return");
	s = xstrdup("hello\r");
	ASSERT_STRING_EQ(chop(s), "hello");
	ಮುಕ್ತ(s);
	TEST_DONE();

	TEST_START("chop CRLF");
	s = xstrdup("hello\r\n");
	ASSERT_STRING_EQ(chop(s), "hello");
	ಮುಕ್ತ(s);
	TEST_DONE();

	TEST_START("chop newline in middle");
	s = xstrdup("he\nllo");
	ASSERT_STRING_EQ(chop(s), "he");
	ಮುಕ್ತ(s);
	TEST_DONE();

	TEST_START("chop no newline");
	s = xstrdup("hello");
	ASSERT_STRING_EQ(chop(s), "hello");
	ಮುಕ್ತ(s);
	TEST_DONE();

	TEST_START("chop empty string");
	s = xstrdup("");
	ASSERT_STRING_EQ(chop(s), "");
	ಮುಕ್ತ(s);
	TEST_DONE();

	TEST_START("chop only newline");
	s = xstrdup("\n");
	ASSERT_STRING_EQ(chop(s), "");
	ಮುಕ್ತ(s);
	TEST_DONE();

	TEST_START("chop only CR");
	s = xstrdup("\r");
	ASSERT_STRING_EQ(chop(s), "");
	ಮುಕ್ತ(s);
	TEST_DONE();

	TEST_START("chop only CRLF");
	s = xstrdup("\r\n");
	ASSERT_STRING_EQ(chop(s), "");
	ಮುಕ್ತ(s);
	TEST_DONE();
}

ಸ್ಥಿರ ಶೂನ್ಯ
test_rtrim(ಶೂನ್ಯ)
{
	ವರ್ಣ *s;

	TEST_START("rtrim trailing space");
	s = xstrdup("hello  ");
	rtrim(s);
	ASSERT_STRING_EQ(s, "hello");
	ಮುಕ್ತ(s);
	TEST_DONE();

	TEST_START("rtrim trailing tab");
	s = xstrdup("hello\t\t");
	rtrim(s);
	ASSERT_STRING_EQ(s, "hello");
	ಮುಕ್ತ(s);
	TEST_DONE();

	TEST_START("rtrim trailing mixed whitespace");
	s = xstrdup("hello \t ");
	rtrim(s);
	ASSERT_STRING_EQ(s, "hello");
	ಮುಕ್ತ(s);
	TEST_DONE();

	TEST_START("rtrim no trailing whitespace");
	s = xstrdup("hello");
	rtrim(s);
	ASSERT_STRING_EQ(s, "hello");
	ಮುಕ್ತ(s);
	TEST_DONE();

	TEST_START("rtrim whitespace in middle");
	s = xstrdup("he llo");
	rtrim(s);
	ASSERT_STRING_EQ(s, "he llo");
	ಮುಕ್ತ(s);
	TEST_DONE();

	TEST_START("rtrim empty string");
	s = xstrdup("");
	rtrim(s);
	ASSERT_STRING_EQ(s, "");
	ಮುಕ್ತ(s);
	TEST_DONE();

	TEST_START("rtrim only whitespace");
	s = xstrdup("   \t");
	rtrim(s);
	ASSERT_STRING_EQ(s, "");
	ಮುಕ್ತ(s);
	TEST_DONE();
}

ಸ್ಥಿರ ಶೂನ್ಯ
test_strprefix(ಶೂನ್ಯ)
{
	ಧ್ರುವ ವರ್ಣ *s;

	TEST_START("strprefix basic match");
	s = strprefix("hello world", "hello", 0);
	ASSERT_PTR_NE(s, ರಿಕ್ತ);
	ASSERT_STRING_EQ(s, " world");
	TEST_DONE();

	TEST_START("strprefix no match");
	s = strprefix("hello world", "world", 0);
	ASSERT_PTR_EQ(s, ರಿಕ್ತ);
	TEST_DONE();

	TEST_START("strprefix full match");
	s = strprefix("hello", "hello", 0);
	ASSERT_PTR_NE(s, ರಿಕ್ತ);
	ASSERT_STRING_EQ(s, "");
	TEST_DONE();

	TEST_START("strprefix empty string");
	s = strprefix("", "hello", 0);
	ASSERT_PTR_EQ(s, ರಿಕ್ತ);
	TEST_DONE();

	TEST_START("strprefix empty prefix");
	s = strprefix("hello", "", 0);
	ASSERT_PTR_NE(s, ರಿಕ್ತ);
	ASSERT_STRING_EQ(s, "hello");
	TEST_DONE();

	TEST_START("strprefix case sensitive no match");
	s = strprefix("Hello world", "hello", 0);
	ASSERT_PTR_EQ(s, ರಿಕ್ತ);
	TEST_DONE();

	TEST_START("strprefix case insensitive match");
	s = strprefix("Hello world", "hello", 1);
	ASSERT_PTR_NE(s, ರಿಕ್ತ);
	ASSERT_STRING_EQ(s, " world");
	TEST_DONE();

	TEST_START("strprefix case insensitive full match");
	s = strprefix("HELLO", "hello", 1);
	ASSERT_PTR_NE(s, ರಿಕ್ತ);
	ASSERT_STRING_EQ(s, "");
	TEST_DONE();
}

ಸ್ಥಿರ ಶೂನ್ಯ
test_fmt_timeframe(ಶೂನ್ಯ)
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

ಸ್ಥಿರ ಶೂನ್ಯ
test_arglist(ಶೂನ್ಯ)
{
	arglist args;
	u_int i;

	memset(&args, 0, ಪರಿಮಾಣ(args));

	TEST_START("addargs initial");
	addargs(&args, "one");
	ASSERT_U_INT_EQ(args.ಅಂಕೆ, 1);
	ASSERT_U_INT_EQ(args.nalloc, 32);
	ASSERT_PTR_NE(args.list, ರಿಕ್ತ);
	ASSERT_STRING_EQ(args.list[0], "one");
	ASSERT_PTR_EQ(args.list[1], ರಿಕ್ತ);
	TEST_DONE();

	TEST_START("addargs second");
	addargs(&args, "two");
	ASSERT_U_INT_EQ(args.ಅಂಕೆ, 2);
	ASSERT_U_INT_EQ(args.nalloc, 32);
	ASSERT_PTR_NE(args.list, ರಿಕ್ತ);
	ASSERT_STRING_EQ(args.list[0], "one");
	ASSERT_STRING_EQ(args.list[1], "two");
	ASSERT_PTR_EQ(args.list[2], ರಿಕ್ತ);
	TEST_DONE();

	TEST_START("addargs with format");
	addargs(&args, "three=%d", 3);
	ASSERT_U_INT_EQ(args.ಅಂಕೆ, 3);
	ASSERT_U_INT_EQ(args.nalloc, 32);
	ASSERT_PTR_NE(args.list, ರಿಕ್ತ);
	ASSERT_STRING_EQ(args.list[0], "one");
	ASSERT_STRING_EQ(args.list[1], "two");
	ASSERT_STRING_EQ(args.list[2], "three=3");
	ASSERT_PTR_EQ(args.list[3], ರಿಕ್ತ);
	TEST_DONE();

	TEST_START("replacearg middle");
	replacearg(&args, 1, "TWO!");
	ASSERT_U_INT_EQ(args.ಅಂಕೆ, 3);
	ASSERT_STRING_EQ(args.list[0], "one");
	ASSERT_STRING_EQ(args.list[1], "TWO!");
	ASSERT_STRING_EQ(args.list[2], "three=3");
	ASSERT_PTR_EQ(args.list[3], ರಿಕ್ತ);
	TEST_DONE();

	TEST_START("replacearg first");
	replacearg(&args, 0, "ONE!");
	ASSERT_U_INT_EQ(args.ಅಂಕೆ, 3);
	ASSERT_STRING_EQ(args.list[0], "ONE!");
	ASSERT_STRING_EQ(args.list[1], "TWO!");
	ASSERT_STRING_EQ(args.list[2], "three=3");
	ASSERT_PTR_EQ(args.list[3], ರಿಕ್ತ);
	TEST_DONE();

	TEST_START("replacearg last");
	replacearg(&args, 2, "THREE=3!");
	ASSERT_U_INT_EQ(args.ಅಂಕೆ, 3);
	ASSERT_STRING_EQ(args.list[0], "ONE!");
	ASSERT_STRING_EQ(args.list[1], "TWO!");
	ASSERT_STRING_EQ(args.list[2], "THREE=3!");
	ASSERT_PTR_EQ(args.list[3], ರಿಕ್ತ);
	TEST_DONE();

	TEST_START("replacearg with format");
	replacearg(&args, 1, "two=%d", 2);
	ASSERT_U_INT_EQ(args.ಅಂಕೆ, 3);
	ASSERT_STRING_EQ(args.list[0], "ONE!");
	ASSERT_STRING_EQ(args.list[1], "two=2");
	ASSERT_STRING_EQ(args.list[2], "THREE=3!");
	ASSERT_PTR_EQ(args.list[3], ರಿಕ್ತ);
	TEST_DONE();

	TEST_START("addargs reallocation");
	ಪ್ರತಿ (i = args.ಅಂಕೆ; i < 33; i++)
		addargs(&args, "pad-%d", i);
	ASSERT_U_INT_EQ(args.ಅಂಕೆ, 33);
	ASSERT_U_INT_GE(args.nalloc, 33);
	ASSERT_STRING_EQ(args.list[32], "pad-32");
	ASSERT_PTR_EQ(args.list[33], ರಿಕ್ತ);
	TEST_DONE();

	TEST_START("freeargs");
	freeargs(&args);
	ASSERT_U_INT_EQ(args.ಅಂಕೆ, 0);
	ASSERT_U_INT_EQ(args.nalloc, 0);
	ASSERT_PTR_EQ(args.list, ರಿಕ್ತ);
	TEST_DONE();

	TEST_START("freeargs on NULL");
	freeargs(ರಿಕ್ತ);
	TEST_DONE();

	TEST_START("freeargs on empty");
	memset(&args, 0, ಪರಿಮಾಣ(args));
	freeargs(&args);
	ASSERT_U_INT_EQ(args.ಅಂಕೆ, 0);
	ASSERT_U_INT_EQ(args.nalloc, 0);
	ASSERT_PTR_EQ(args.list, ರಿಕ್ತ);
	TEST_DONE();
}

ಸ್ಥಿರ ಶೂನ್ಯ
test_tohex(ಶೂನ್ಯ)
{
	ವರ್ಣ *hex;

	TEST_START("tohex simple");
	hex = tohex("foo", 3);
	ASSERT_STRING_EQ(hex, "666f6f");
	ಮುಕ್ತ(hex);
	TEST_DONE();

	TEST_START("tohex with null");
	hex = tohex("a\0b", 3);
	ASSERT_STRING_EQ(hex, "610062");
	ಮುಕ್ತ(hex);
	TEST_DONE();

	TEST_START("tohex empty");
	hex = tohex("", 0);
	ASSERT_STRING_EQ(hex, "");
	ಮುಕ್ತ(hex);
	TEST_DONE();
}

ಸ್ಥಿರ ಶೂನ್ಯ
test_lowercase(ಶೂನ್ಯ)
{
	ವರ್ಣ *s;

	TEST_START("lowercase mixed");
	s = xstrdup("HeLlO WoRlD 123");
	lowercase(s);
	ASSERT_STRING_EQ(s, "hello world 123");
	ಮುಕ್ತ(s);
	TEST_DONE();

	TEST_START("lowercase empty");
	s = xstrdup("");
	lowercase(s);
	ASSERT_STRING_EQ(s, "");
	ಮುಕ್ತ(s);
	TEST_DONE();
}

ಸ್ಥಿರ ಶೂನ್ಯ
test_path_absolute(ಶೂನ್ಯ)
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

ಸ್ಥಿರ ಶೂನ್ಯ
test_stringlist(ಶೂನ್ಯ)
{
	ವರ್ಣ **list = ರಿಕ್ತ;

	TEST_START("stringlist_append initial");
	stringlist_append(&list, "one");
	ASSERT_PTR_NE(list, ರಿಕ್ತ);
	ASSERT_STRING_EQ(list[0], "one");
	ASSERT_PTR_EQ(list[1], ರಿಕ್ತ);
	TEST_DONE();

	TEST_START("stringlist_append second");
	stringlist_append(&list, "two");
	ASSERT_PTR_NE(list, ರಿಕ್ತ);
	ASSERT_STRING_EQ(list[0], "one");
	ASSERT_STRING_EQ(list[1], "two");
	ASSERT_PTR_EQ(list[2], ರಿಕ್ತ);
	TEST_DONE();

	TEST_START("stringlist_append third");
	stringlist_append(&list, "three");
	ASSERT_PTR_NE(list, ರಿಕ್ತ);
	ASSERT_STRING_EQ(list[0], "one");
	ASSERT_STRING_EQ(list[1], "two");
	ASSERT_STRING_EQ(list[2], "three");
	ASSERT_PTR_EQ(list[3], ರಿಕ್ತ);
	TEST_DONE();

	TEST_START("stringlist_free");
	stringlist_free(list);
	TEST_DONE();

	TEST_START("stringlist_free NULL");
	stringlist_free(ರಿಕ್ತ);
	TEST_DONE();
}

ಸ್ಥಿರ ಶೂನ್ಯ
test_skip_space(ಶೂನ್ಯ)
{
	ವರ್ಣ *s, *p;

	TEST_START("skip_space leading spaces");
	s = p = xstrdup("  hello");
	skip_space(&p);
	ASSERT_STRING_EQ(p, "hello");
	ಮುಕ್ತ(s);
	TEST_DONE();

	TEST_START("skip_space leading tabs");
	s = p = xstrdup("\t\thello");
	skip_space(&p);
	ASSERT_STRING_EQ(p, "hello");
	ಮುಕ್ತ(s);
	TEST_DONE();

	TEST_START("skip_space leading mixed whitespace");
	s = p = xstrdup(" \t hello");
	skip_space(&p);
	ASSERT_STRING_EQ(p, "hello");
	ಮುಕ್ತ(s);
	TEST_DONE();

	TEST_START("skip_space no leading whitespace");
	s = p = xstrdup("hello");
	skip_space(&p);
	ASSERT_STRING_EQ(p, "hello");
	ಮುಕ್ತ(s);
	TEST_DONE();

	TEST_START("skip_space empty string");
	s = p = xstrdup("");
	skip_space(&p);
	ASSERT_STRING_EQ(p, "");
	ಮುಕ್ತ(s);
	TEST_DONE();

	TEST_START("skip_space only whitespace");
	s = p = xstrdup(" \t ");
	skip_space(&p);
	ASSERT_STRING_EQ(p, "");
	ಮುಕ್ತ(s);
	TEST_DONE();
}

ಶೂನ್ಯ
test_misc(ಶೂನ್ಯ)
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
