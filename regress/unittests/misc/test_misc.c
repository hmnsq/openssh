/*
 * Regress test for misc helper functions.
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

فراغ test_misc(فراغ);

ساكن فراغ
test_chop(فراغ)
{
	حرف *s;

	TEST_شروع("chop newline");
	s = xstrdup("hello\n");
	ASSERT_STRING_EQ(chop(s), "hello");
	حرر(s);
	TEST_انجامشده();

	TEST_شروع("chop carriage return");
	s = xstrdup("hello\r");
	ASSERT_STRING_EQ(chop(s), "hello");
	حرر(s);
	TEST_انجامشده();

	TEST_شروع("chop CRLF");
	s = xstrdup("hello\r\n");
	ASSERT_STRING_EQ(chop(s), "hello");
	حرر(s);
	TEST_انجامشده();

	TEST_شروع("chop newline in middle");
	s = xstrdup("he\nllo");
	ASSERT_STRING_EQ(chop(s), "he");
	حرر(s);
	TEST_انجامشده();

	TEST_شروع("chop no newline");
	s = xstrdup("hello");
	ASSERT_STRING_EQ(chop(s), "hello");
	حرر(s);
	TEST_انجامشده();

	TEST_شروع("chop empty string");
	s = xstrdup("");
	ASSERT_STRING_EQ(chop(s), "");
	حرر(s);
	TEST_انجامشده();

	TEST_شروع("chop only newline");
	s = xstrdup("\n");
	ASSERT_STRING_EQ(chop(s), "");
	حرر(s);
	TEST_انجامشده();

	TEST_شروع("chop only CR");
	s = xstrdup("\r");
	ASSERT_STRING_EQ(chop(s), "");
	حرر(s);
	TEST_انجامشده();

	TEST_شروع("chop only CRLF");
	s = xstrdup("\r\n");
	ASSERT_STRING_EQ(chop(s), "");
	حرر(s);
	TEST_انجامشده();
}

ساكن فراغ
test_rtrim(فراغ)
{
	حرف *s;

	TEST_شروع("rtrim trailing space");
	s = xstrdup("hello  ");
	rtrim(s);
	ASSERT_STRING_EQ(s, "hello");
	حرر(s);
	TEST_انجامشده();

	TEST_شروع("rtrim trailing tab");
	s = xstrdup("hello\t\t");
	rtrim(s);
	ASSERT_STRING_EQ(s, "hello");
	حرر(s);
	TEST_انجامشده();

	TEST_شروع("rtrim trailing mixed whitespace");
	s = xstrdup("hello \t ");
	rtrim(s);
	ASSERT_STRING_EQ(s, "hello");
	حرر(s);
	TEST_انجامشده();

	TEST_شروع("rtrim no trailing whitespace");
	s = xstrdup("hello");
	rtrim(s);
	ASSERT_STRING_EQ(s, "hello");
	حرر(s);
	TEST_انجامشده();

	TEST_شروع("rtrim whitespace in middle");
	s = xstrdup("he llo");
	rtrim(s);
	ASSERT_STRING_EQ(s, "he llo");
	حرر(s);
	TEST_انجامشده();

	TEST_شروع("rtrim empty string");
	s = xstrdup("");
	rtrim(s);
	ASSERT_STRING_EQ(s, "");
	حرر(s);
	TEST_انجامشده();

	TEST_شروع("rtrim only whitespace");
	s = xstrdup("   \t");
	rtrim(s);
	ASSERT_STRING_EQ(s, "");
	حرر(s);
	TEST_انجامشده();
}

ساكن فراغ
test_strprefix(فراغ)
{
	ثابت حرف *s;

	TEST_شروع("strprefix basic match");
	s = strprefix("hello world", "hello", 0);
	ASSERT_PTR_NE(s, عدم);
	ASSERT_STRING_EQ(s, " world");
	TEST_انجامشده();

	TEST_شروع("strprefix no match");
	s = strprefix("hello world", "world", 0);
	ASSERT_PTR_EQ(s, عدم);
	TEST_انجامشده();

	TEST_شروع("strprefix full match");
	s = strprefix("hello", "hello", 0);
	ASSERT_PTR_NE(s, عدم);
	ASSERT_STRING_EQ(s, "");
	TEST_انجامشده();

	TEST_شروع("strprefix empty string");
	s = strprefix("", "hello", 0);
	ASSERT_PTR_EQ(s, عدم);
	TEST_انجامشده();

	TEST_شروع("strprefix empty prefix");
	s = strprefix("hello", "", 0);
	ASSERT_PTR_NE(s, عدم);
	ASSERT_STRING_EQ(s, "hello");
	TEST_انجامشده();

	TEST_شروع("strprefix case sensitive no match");
	s = strprefix("Hello world", "hello", 0);
	ASSERT_PTR_EQ(s, عدم);
	TEST_انجامشده();

	TEST_شروع("strprefix case insensitive match");
	s = strprefix("Hello world", "hello", 1);
	ASSERT_PTR_NE(s, عدم);
	ASSERT_STRING_EQ(s, " world");
	TEST_انجامشده();

	TEST_شروع("strprefix case insensitive full match");
	s = strprefix("HELLO", "hello", 1);
	ASSERT_PTR_NE(s, عدم);
	ASSERT_STRING_EQ(s, "");
	TEST_انجامشده();
}

ساكن فراغ
test_fmt_timeframe(فراغ)
{
	TEST_شروع("fmt_timeframe seconds");
	ASSERT_STRING_EQ(fmt_timeframe(0), "00:00:00");
	ASSERT_STRING_EQ(fmt_timeframe(59), "00:00:59");
	ASSERT_STRING_EQ(fmt_timeframe(60), "00:01:00");
	ASSERT_STRING_EQ(fmt_timeframe(3599), "00:59:59");
	ASSERT_STRING_EQ(fmt_timeframe(3600), "01:00:00");
	ASSERT_STRING_EQ(fmt_timeframe(86399), "23:59:59");
	TEST_انجامشده();

	TEST_شروع("fmt_timeframe days");
	ASSERT_STRING_EQ(fmt_timeframe(86400), "1d00h00m");
	ASSERT_STRING_EQ(fmt_timeframe(90061), "1d01h01m");
	ASSERT_STRING_EQ(fmt_timeframe(604799), "6d23h59m");
	TEST_انجامشده();

	TEST_شروع("fmt_timeframe weeks");
	ASSERT_STRING_EQ(fmt_timeframe(604800), "01w0d00h");
	ASSERT_STRING_EQ(fmt_timeframe(694861), "01w1d01h");
	TEST_انجامشده();
}

ساكن فراغ
test_arglist(فراغ)
{
	arglist آرگومانها;
	u_int i;

	memset(&آرگومانها, 0, حجم(آرگومانها));

	TEST_شروع("addargs initial");
	addargs(&آرگومانها, "one");
	ASSERT_U_INT_EQ(آرگومانها.رقم, 1);
	ASSERT_U_INT_EQ(آرگومانها.nalloc, 32);
	ASSERT_PTR_NE(آرگومانها.list, عدم);
	ASSERT_STRING_EQ(آرگومانها.list[0], "one");
	ASSERT_PTR_EQ(آرگومانها.list[1], عدم);
	TEST_انجامشده();

	TEST_شروع("addargs second");
	addargs(&آرگومانها, "two");
	ASSERT_U_INT_EQ(آرگومانها.رقم, 2);
	ASSERT_U_INT_EQ(آرگومانها.nalloc, 32);
	ASSERT_PTR_NE(آرگومانها.list, عدم);
	ASSERT_STRING_EQ(آرگومانها.list[0], "one");
	ASSERT_STRING_EQ(آرگومانها.list[1], "two");
	ASSERT_PTR_EQ(آرگومانها.list[2], عدم);
	TEST_انجامشده();

	TEST_شروع("addargs with format");
	addargs(&آرگومانها, "three=%d", 3);
	ASSERT_U_INT_EQ(آرگومانها.رقم, 3);
	ASSERT_U_INT_EQ(آرگومانها.nalloc, 32);
	ASSERT_PTR_NE(آرگومانها.list, عدم);
	ASSERT_STRING_EQ(آرگومانها.list[0], "one");
	ASSERT_STRING_EQ(آرگومانها.list[1], "two");
	ASSERT_STRING_EQ(آرگومانها.list[2], "three=3");
	ASSERT_PTR_EQ(آرگومانها.list[3], عدم);
	TEST_انجامشده();

	TEST_شروع("replacearg middle");
	replacearg(&آرگومانها, 1, "TWO!");
	ASSERT_U_INT_EQ(آرگومانها.رقم, 3);
	ASSERT_STRING_EQ(آرگومانها.list[0], "one");
	ASSERT_STRING_EQ(آرگومانها.list[1], "TWO!");
	ASSERT_STRING_EQ(آرگومانها.list[2], "three=3");
	ASSERT_PTR_EQ(آرگومانها.list[3], عدم);
	TEST_انجامشده();

	TEST_شروع("replacearg first");
	replacearg(&آرگومانها, 0, "ONE!");
	ASSERT_U_INT_EQ(آرگومانها.رقم, 3);
	ASSERT_STRING_EQ(آرگومانها.list[0], "ONE!");
	ASSERT_STRING_EQ(آرگومانها.list[1], "TWO!");
	ASSERT_STRING_EQ(آرگومانها.list[2], "three=3");
	ASSERT_PTR_EQ(آرگومانها.list[3], عدم);
	TEST_انجامشده();

	TEST_شروع("replacearg last");
	replacearg(&آرگومانها, 2, "THREE=3!");
	ASSERT_U_INT_EQ(آرگومانها.رقم, 3);
	ASSERT_STRING_EQ(آرگومانها.list[0], "ONE!");
	ASSERT_STRING_EQ(آرگومانها.list[1], "TWO!");
	ASSERT_STRING_EQ(آرگومانها.list[2], "THREE=3!");
	ASSERT_PTR_EQ(آرگومانها.list[3], عدم);
	TEST_انجامشده();

	TEST_شروع("replacearg with format");
	replacearg(&آرگومانها, 1, "two=%d", 2);
	ASSERT_U_INT_EQ(آرگومانها.رقم, 3);
	ASSERT_STRING_EQ(آرگومانها.list[0], "ONE!");
	ASSERT_STRING_EQ(آرگومانها.list[1], "two=2");
	ASSERT_STRING_EQ(آرگومانها.list[2], "THREE=3!");
	ASSERT_PTR_EQ(آرگومانها.list[3], عدم);
	TEST_انجامشده();

	TEST_شروع("addargs reallocation");
	لكل (i = آرگومانها.رقم; i < 33; i++)
		addargs(&آرگومانها, "pad-%d", i);
	ASSERT_U_INT_EQ(آرگومانها.رقم, 33);
	ASSERT_U_INT_GE(آرگومانها.nalloc, 33);
	ASSERT_STRING_EQ(آرگومانها.list[32], "pad-32");
	ASSERT_PTR_EQ(آرگومانها.list[33], عدم);
	TEST_انجامشده();

	TEST_شروع("freeargs");
	freeargs(&آرگومانها);
	ASSERT_U_INT_EQ(آرگومانها.رقم, 0);
	ASSERT_U_INT_EQ(آرگومانها.nalloc, 0);
	ASSERT_PTR_EQ(آرگومانها.list, عدم);
	TEST_انجامشده();

	TEST_شروع("freeargs on NULL");
	freeargs(عدم);
	TEST_انجامشده();

	TEST_شروع("freeargs on empty");
	memset(&آرگومانها, 0, حجم(آرگومانها));
	freeargs(&آرگومانها);
	ASSERT_U_INT_EQ(آرگومانها.رقم, 0);
	ASSERT_U_INT_EQ(آرگومانها.nalloc, 0);
	ASSERT_PTR_EQ(آرگومانها.list, عدم);
	TEST_انجامشده();
}

ساكن فراغ
test_tohex(فراغ)
{
	حرف *hex;

	TEST_شروع("tohex simple");
	hex = tohex("foo", 3);
	ASSERT_STRING_EQ(hex, "666f6f");
	حرر(hex);
	TEST_انجامشده();

	TEST_شروع("tohex with null");
	hex = tohex("a\0b", 3);
	ASSERT_STRING_EQ(hex, "610062");
	حرر(hex);
	TEST_انجامشده();

	TEST_شروع("tohex empty");
	hex = tohex("", 0);
	ASSERT_STRING_EQ(hex, "");
	حرر(hex);
	TEST_انجامشده();
}

ساكن فراغ
test_lowercase(فراغ)
{
	حرف *s;

	TEST_شروع("lowercase mixed");
	s = xstrdup("HeLlO WoRlD 123");
	lowercase(s);
	ASSERT_STRING_EQ(s, "hello world 123");
	حرر(s);
	TEST_انجامشده();

	TEST_شروع("lowercase empty");
	s = xstrdup("");
	lowercase(s);
	ASSERT_STRING_EQ(s, "");
	حرر(s);
	TEST_انجامشده();
}

ساكن فراغ
test_مسیر_absolute(فراغ)
{
	TEST_شروع("path_absolute absolute");
	ASSERT_INT_EQ(مسیر_absolute("/foo/bar"), 1);
	TEST_انجامشده();

	TEST_شروع("path_absolute relative");
	ASSERT_INT_EQ(مسیر_absolute("foo/bar"), 0);
	TEST_انجامشده();

	TEST_شروع("path_absolute empty");
	ASSERT_INT_EQ(مسیر_absolute(""), 0);
	TEST_انجامشده();
}

ساكن فراغ
test_stringlist(فراغ)
{
	حرف **list = عدم;

	TEST_شروع("stringlist_append initial");
	stringlist_append(&list, "one");
	ASSERT_PTR_NE(list, عدم);
	ASSERT_STRING_EQ(list[0], "one");
	ASSERT_PTR_EQ(list[1], عدم);
	TEST_انجامشده();

	TEST_شروع("stringlist_append second");
	stringlist_append(&list, "two");
	ASSERT_PTR_NE(list, عدم);
	ASSERT_STRING_EQ(list[0], "one");
	ASSERT_STRING_EQ(list[1], "two");
	ASSERT_PTR_EQ(list[2], عدم);
	TEST_انجامشده();

	TEST_شروع("stringlist_append third");
	stringlist_append(&list, "three");
	ASSERT_PTR_NE(list, عدم);
	ASSERT_STRING_EQ(list[0], "one");
	ASSERT_STRING_EQ(list[1], "two");
	ASSERT_STRING_EQ(list[2], "three");
	ASSERT_PTR_EQ(list[3], عدم);
	TEST_انجامشده();

	TEST_شروع("stringlist_free");
	stringlist_free(list);
	TEST_انجامشده();

	TEST_شروع("stringlist_free NULL");
	stringlist_free(عدم);
	TEST_انجامشده();
}

ساكن فراغ
test_skip_space(فراغ)
{
	حرف *s, *p;

	TEST_شروع("skip_space leading spaces");
	s = p = xstrdup("  hello");
	skip_space(&p);
	ASSERT_STRING_EQ(p, "hello");
	حرر(s);
	TEST_انجامشده();

	TEST_شروع("skip_space leading tabs");
	s = p = xstrdup("\t\thello");
	skip_space(&p);
	ASSERT_STRING_EQ(p, "hello");
	حرر(s);
	TEST_انجامشده();

	TEST_شروع("skip_space leading mixed whitespace");
	s = p = xstrdup(" \t hello");
	skip_space(&p);
	ASSERT_STRING_EQ(p, "hello");
	حرر(s);
	TEST_انجامشده();

	TEST_شروع("skip_space no leading whitespace");
	s = p = xstrdup("hello");
	skip_space(&p);
	ASSERT_STRING_EQ(p, "hello");
	حرر(s);
	TEST_انجامشده();

	TEST_شروع("skip_space empty string");
	s = p = xstrdup("");
	skip_space(&p);
	ASSERT_STRING_EQ(p, "");
	حرر(s);
	TEST_انجامشده();

	TEST_شروع("skip_space only whitespace");
	s = p = xstrdup(" \t ");
	skip_space(&p);
	ASSERT_STRING_EQ(p, "");
	حرر(s);
	TEST_انجامشده();
}

فراغ
test_misc(فراغ)
{
	test_chop();
	test_rtrim();
	test_strprefix();
	test_fmt_timeframe();
	test_arglist();
	test_tohex();
	test_lowercase();
	test_مسیر_absolute();
	test_stringlist();
	test_skip_space();
}
