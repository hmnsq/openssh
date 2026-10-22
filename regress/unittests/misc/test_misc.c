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

	TEST_شروعات("chop newline");
	s = xstrdup("hello\n");
	ASSERT_STRING_EQ(chop(s), "hello");
	حرر(s);
	TEST_پورو();

	TEST_شروعات("chop carriage return");
	s = xstrdup("hello\r");
	ASSERT_STRING_EQ(chop(s), "hello");
	حرر(s);
	TEST_پورو();

	TEST_شروعات("chop CRLF");
	s = xstrdup("hello\r\n");
	ASSERT_STRING_EQ(chop(s), "hello");
	حرر(s);
	TEST_پورو();

	TEST_شروعات("chop newline in middle");
	s = xstrdup("he\nllo");
	ASSERT_STRING_EQ(chop(s), "he");
	حرر(s);
	TEST_پورو();

	TEST_شروعات("chop no newline");
	s = xstrdup("hello");
	ASSERT_STRING_EQ(chop(s), "hello");
	حرر(s);
	TEST_پورو();

	TEST_شروعات("chop empty string");
	s = xstrdup("");
	ASSERT_STRING_EQ(chop(s), "");
	حرر(s);
	TEST_پورو();

	TEST_شروعات("chop only newline");
	s = xstrdup("\n");
	ASSERT_STRING_EQ(chop(s), "");
	حرر(s);
	TEST_پورو();

	TEST_شروعات("chop only CR");
	s = xstrdup("\r");
	ASSERT_STRING_EQ(chop(s), "");
	حرر(s);
	TEST_پورو();

	TEST_شروعات("chop only CRLF");
	s = xstrdup("\r\n");
	ASSERT_STRING_EQ(chop(s), "");
	حرر(s);
	TEST_پورو();
}

ساكن فراغ
test_rtrim(فراغ)
{
	حرف *s;

	TEST_شروعات("rtrim trailing space");
	s = xstrdup("hello  ");
	rtrim(s);
	ASSERT_STRING_EQ(s, "hello");
	حرر(s);
	TEST_پورو();

	TEST_شروعات("rtrim trailing tab");
	s = xstrdup("hello\t\t");
	rtrim(s);
	ASSERT_STRING_EQ(s, "hello");
	حرر(s);
	TEST_پورو();

	TEST_شروعات("rtrim trailing mixed whitespace");
	s = xstrdup("hello \t ");
	rtrim(s);
	ASSERT_STRING_EQ(s, "hello");
	حرر(s);
	TEST_پورو();

	TEST_شروعات("rtrim no trailing whitespace");
	s = xstrdup("hello");
	rtrim(s);
	ASSERT_STRING_EQ(s, "hello");
	حرر(s);
	TEST_پورو();

	TEST_شروعات("rtrim whitespace in middle");
	s = xstrdup("he llo");
	rtrim(s);
	ASSERT_STRING_EQ(s, "he llo");
	حرر(s);
	TEST_پورو();

	TEST_شروعات("rtrim empty string");
	s = xstrdup("");
	rtrim(s);
	ASSERT_STRING_EQ(s, "");
	حرر(s);
	TEST_پورو();

	TEST_شروعات("rtrim only whitespace");
	s = xstrdup("   \t");
	rtrim(s);
	ASSERT_STRING_EQ(s, "");
	حرر(s);
	TEST_پورو();
}

ساكن فراغ
test_strprefix(فراغ)
{
	ثابت حرف *s;

	TEST_شروعات("strprefix basic match");
	s = strprefix("hello world", "hello", 0);
	ASSERT_PTR_NE(s, عدم);
	ASSERT_STRING_EQ(s, " world");
	TEST_پورو();

	TEST_شروعات("strprefix no match");
	s = strprefix("hello world", "world", 0);
	ASSERT_PTR_EQ(s, عدم);
	TEST_پورو();

	TEST_شروعات("strprefix full match");
	s = strprefix("hello", "hello", 0);
	ASSERT_PTR_NE(s, عدم);
	ASSERT_STRING_EQ(s, "");
	TEST_پورو();

	TEST_شروعات("strprefix empty string");
	s = strprefix("", "hello", 0);
	ASSERT_PTR_EQ(s, عدم);
	TEST_پورو();

	TEST_شروعات("strprefix empty prefix");
	s = strprefix("hello", "", 0);
	ASSERT_PTR_NE(s, عدم);
	ASSERT_STRING_EQ(s, "hello");
	TEST_پورو();

	TEST_شروعات("strprefix case sensitive no match");
	s = strprefix("Hello world", "hello", 0);
	ASSERT_PTR_EQ(s, عدم);
	TEST_پورو();

	TEST_شروعات("strprefix case insensitive match");
	s = strprefix("Hello world", "hello", 1);
	ASSERT_PTR_NE(s, عدم);
	ASSERT_STRING_EQ(s, " world");
	TEST_پورو();

	TEST_شروعات("strprefix case insensitive full match");
	s = strprefix("HELLO", "hello", 1);
	ASSERT_PTR_NE(s, عدم);
	ASSERT_STRING_EQ(s, "");
	TEST_پورو();
}

ساكن فراغ
test_fmt_timeframe(فراغ)
{
	TEST_شروعات("fmt_timeframe seconds");
	ASSERT_STRING_EQ(fmt_timeframe(0), "00:00:00");
	ASSERT_STRING_EQ(fmt_timeframe(59), "00:00:59");
	ASSERT_STRING_EQ(fmt_timeframe(60), "00:01:00");
	ASSERT_STRING_EQ(fmt_timeframe(3599), "00:59:59");
	ASSERT_STRING_EQ(fmt_timeframe(3600), "01:00:00");
	ASSERT_STRING_EQ(fmt_timeframe(86399), "23:59:59");
	TEST_پورو();

	TEST_شروعات("fmt_timeframe days");
	ASSERT_STRING_EQ(fmt_timeframe(86400), "1d00h00m");
	ASSERT_STRING_EQ(fmt_timeframe(90061), "1d01h01m");
	ASSERT_STRING_EQ(fmt_timeframe(604799), "6d23h59m");
	TEST_پورو();

	TEST_شروعات("fmt_timeframe weeks");
	ASSERT_STRING_EQ(fmt_timeframe(604800), "01w0d00h");
	ASSERT_STRING_EQ(fmt_timeframe(694861), "01w1d01h");
	TEST_پورو();
}

ساكن فراغ
test_arglist(فراغ)
{
	arglist دليلون;
	u_int i;

	memset(&دليلون, 0, حجم(دليلون));

	TEST_شروعات("addargs initial");
	addargs(&دليلون, "one");
	ASSERT_U_INT_EQ(دليلون.انگ, 1);
	ASSERT_U_INT_EQ(دليلون.nalloc, 32);
	ASSERT_PTR_NE(دليلون.list, عدم);
	ASSERT_STRING_EQ(دليلون.list[0], "one");
	ASSERT_PTR_EQ(دليلون.list[1], عدم);
	TEST_پورو();

	TEST_شروعات("addargs second");
	addargs(&دليلون, "two");
	ASSERT_U_INT_EQ(دليلون.انگ, 2);
	ASSERT_U_INT_EQ(دليلون.nalloc, 32);
	ASSERT_PTR_NE(دليلون.list, عدم);
	ASSERT_STRING_EQ(دليلون.list[0], "one");
	ASSERT_STRING_EQ(دليلون.list[1], "two");
	ASSERT_PTR_EQ(دليلون.list[2], عدم);
	TEST_پورو();

	TEST_شروعات("addargs with format");
	addargs(&دليلون, "three=%d", 3);
	ASSERT_U_INT_EQ(دليلون.انگ, 3);
	ASSERT_U_INT_EQ(دليلون.nalloc, 32);
	ASSERT_PTR_NE(دليلون.list, عدم);
	ASSERT_STRING_EQ(دليلون.list[0], "one");
	ASSERT_STRING_EQ(دليلون.list[1], "two");
	ASSERT_STRING_EQ(دليلون.list[2], "three=3");
	ASSERT_PTR_EQ(دليلون.list[3], عدم);
	TEST_پورو();

	TEST_شروعات("replacearg middle");
	replacearg(&دليلون, 1, "TWO!");
	ASSERT_U_INT_EQ(دليلون.انگ, 3);
	ASSERT_STRING_EQ(دليلون.list[0], "one");
	ASSERT_STRING_EQ(دليلون.list[1], "TWO!");
	ASSERT_STRING_EQ(دليلون.list[2], "three=3");
	ASSERT_PTR_EQ(دليلون.list[3], عدم);
	TEST_پورو();

	TEST_شروعات("replacearg first");
	replacearg(&دليلون, 0, "ONE!");
	ASSERT_U_INT_EQ(دليلون.انگ, 3);
	ASSERT_STRING_EQ(دليلون.list[0], "ONE!");
	ASSERT_STRING_EQ(دليلون.list[1], "TWO!");
	ASSERT_STRING_EQ(دليلون.list[2], "three=3");
	ASSERT_PTR_EQ(دليلون.list[3], عدم);
	TEST_پورو();

	TEST_شروعات("replacearg last");
	replacearg(&دليلون, 2, "THREE=3!");
	ASSERT_U_INT_EQ(دليلون.انگ, 3);
	ASSERT_STRING_EQ(دليلون.list[0], "ONE!");
	ASSERT_STRING_EQ(دليلون.list[1], "TWO!");
	ASSERT_STRING_EQ(دليلون.list[2], "THREE=3!");
	ASSERT_PTR_EQ(دليلون.list[3], عدم);
	TEST_پورو();

	TEST_شروعات("replacearg with format");
	replacearg(&دليلون, 1, "two=%d", 2);
	ASSERT_U_INT_EQ(دليلون.انگ, 3);
	ASSERT_STRING_EQ(دليلون.list[0], "ONE!");
	ASSERT_STRING_EQ(دليلون.list[1], "two=2");
	ASSERT_STRING_EQ(دليلون.list[2], "THREE=3!");
	ASSERT_PTR_EQ(دليلون.list[3], عدم);
	TEST_پورو();

	TEST_شروعات("addargs reallocation");
	لكل (i = دليلون.انگ; i < 33; i++)
		addargs(&دليلون, "pad-%d", i);
	ASSERT_U_INT_EQ(دليلون.انگ, 33);
	ASSERT_U_INT_GE(دليلون.nalloc, 33);
	ASSERT_STRING_EQ(دليلون.list[32], "pad-32");
	ASSERT_PTR_EQ(دليلون.list[33], عدم);
	TEST_پورو();

	TEST_شروعات("freeargs");
	freeargs(&دليلون);
	ASSERT_U_INT_EQ(دليلون.انگ, 0);
	ASSERT_U_INT_EQ(دليلون.nalloc, 0);
	ASSERT_PTR_EQ(دليلون.list, عدم);
	TEST_پورو();

	TEST_شروعات("freeargs on NULL");
	freeargs(عدم);
	TEST_پورو();

	TEST_شروعات("freeargs on empty");
	memset(&دليلون, 0, حجم(دليلون));
	freeargs(&دليلون);
	ASSERT_U_INT_EQ(دليلون.انگ, 0);
	ASSERT_U_INT_EQ(دليلون.nalloc, 0);
	ASSERT_PTR_EQ(دليلون.list, عدم);
	TEST_پورو();
}

ساكن فراغ
test_tohex(فراغ)
{
	حرف *hex;

	TEST_شروعات("tohex simple");
	hex = tohex("foo", 3);
	ASSERT_STRING_EQ(hex, "666f6f");
	حرر(hex);
	TEST_پورو();

	TEST_شروعات("tohex with null");
	hex = tohex("a\0b", 3);
	ASSERT_STRING_EQ(hex, "610062");
	حرر(hex);
	TEST_پورو();

	TEST_شروعات("tohex empty");
	hex = tohex("", 0);
	ASSERT_STRING_EQ(hex, "");
	حرر(hex);
	TEST_پورو();
}

ساكن فراغ
test_lowercase(فراغ)
{
	حرف *s;

	TEST_شروعات("lowercase mixed");
	s = xstrdup("HeLlO WoRlD 123");
	lowercase(s);
	ASSERT_STRING_EQ(s, "hello world 123");
	حرر(s);
	TEST_پورو();

	TEST_شروعات("lowercase empty");
	s = xstrdup("");
	lowercase(s);
	ASSERT_STRING_EQ(s, "");
	حرر(s);
	TEST_پورو();
}

ساكن فراغ
test_رستو_absolute(فراغ)
{
	TEST_شروعات("path_absolute absolute");
	ASSERT_INT_EQ(رستو_absolute("/foo/bar"), 1);
	TEST_پورو();

	TEST_شروعات("path_absolute relative");
	ASSERT_INT_EQ(رستو_absolute("foo/bar"), 0);
	TEST_پورو();

	TEST_شروعات("path_absolute empty");
	ASSERT_INT_EQ(رستو_absolute(""), 0);
	TEST_پورو();
}

ساكن فراغ
test_stringlist(فراغ)
{
	حرف **list = عدم;

	TEST_شروعات("stringlist_append initial");
	stringlist_append(&list, "one");
	ASSERT_PTR_NE(list, عدم);
	ASSERT_STRING_EQ(list[0], "one");
	ASSERT_PTR_EQ(list[1], عدم);
	TEST_پورو();

	TEST_شروعات("stringlist_append second");
	stringlist_append(&list, "two");
	ASSERT_PTR_NE(list, عدم);
	ASSERT_STRING_EQ(list[0], "one");
	ASSERT_STRING_EQ(list[1], "two");
	ASSERT_PTR_EQ(list[2], عدم);
	TEST_پورو();

	TEST_شروعات("stringlist_append third");
	stringlist_append(&list, "three");
	ASSERT_PTR_NE(list, عدم);
	ASSERT_STRING_EQ(list[0], "one");
	ASSERT_STRING_EQ(list[1], "two");
	ASSERT_STRING_EQ(list[2], "three");
	ASSERT_PTR_EQ(list[3], عدم);
	TEST_پورو();

	TEST_شروعات("stringlist_free");
	stringlist_free(list);
	TEST_پورو();

	TEST_شروعات("stringlist_free NULL");
	stringlist_free(عدم);
	TEST_پورو();
}

ساكن فراغ
test_skip_space(فراغ)
{
	حرف *s, *p;

	TEST_شروعات("skip_space leading spaces");
	s = p = xstrdup("  hello");
	skip_space(&p);
	ASSERT_STRING_EQ(p, "hello");
	حرر(s);
	TEST_پورو();

	TEST_شروعات("skip_space leading tabs");
	s = p = xstrdup("\t\thello");
	skip_space(&p);
	ASSERT_STRING_EQ(p, "hello");
	حرر(s);
	TEST_پورو();

	TEST_شروعات("skip_space leading mixed whitespace");
	s = p = xstrdup(" \t hello");
	skip_space(&p);
	ASSERT_STRING_EQ(p, "hello");
	حرر(s);
	TEST_پورو();

	TEST_شروعات("skip_space no leading whitespace");
	s = p = xstrdup("hello");
	skip_space(&p);
	ASSERT_STRING_EQ(p, "hello");
	حرر(s);
	TEST_پورو();

	TEST_شروعات("skip_space empty string");
	s = p = xstrdup("");
	skip_space(&p);
	ASSERT_STRING_EQ(p, "");
	حرر(s);
	TEST_پورو();

	TEST_شروعات("skip_space only whitespace");
	s = p = xstrdup(" \t ");
	skip_space(&p);
	ASSERT_STRING_EQ(p, "");
	حرر(s);
	TEST_پورو();
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
	test_رستو_absolute();
	test_stringlist();
	test_skip_space();
}
