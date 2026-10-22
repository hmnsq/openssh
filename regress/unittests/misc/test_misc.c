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

	TEST_پیل("chop newline");
	s = xstrdup("hello\n");
	ASSERT_STRING_EQ(chop(s), "hello");
	حرر(s);
	TEST_بشپړ();

	TEST_پیل("chop carriage return");
	s = xstrdup("hello\r");
	ASSERT_STRING_EQ(chop(s), "hello");
	حرر(s);
	TEST_بشپړ();

	TEST_پیل("chop CRLF");
	s = xstrdup("hello\r\n");
	ASSERT_STRING_EQ(chop(s), "hello");
	حرر(s);
	TEST_بشپړ();

	TEST_پیل("chop newline in middle");
	s = xstrdup("he\nllo");
	ASSERT_STRING_EQ(chop(s), "he");
	حرر(s);
	TEST_بشپړ();

	TEST_پیل("chop no newline");
	s = xstrdup("hello");
	ASSERT_STRING_EQ(chop(s), "hello");
	حرر(s);
	TEST_بشپړ();

	TEST_پیل("chop empty string");
	s = xstrdup("");
	ASSERT_STRING_EQ(chop(s), "");
	حرر(s);
	TEST_بشپړ();

	TEST_پیل("chop only newline");
	s = xstrdup("\n");
	ASSERT_STRING_EQ(chop(s), "");
	حرر(s);
	TEST_بشپړ();

	TEST_پیل("chop only CR");
	s = xstrdup("\r");
	ASSERT_STRING_EQ(chop(s), "");
	حرر(s);
	TEST_بشپړ();

	TEST_پیل("chop only CRLF");
	s = xstrdup("\r\n");
	ASSERT_STRING_EQ(chop(s), "");
	حرر(s);
	TEST_بشپړ();
}

ساكن فراغ
test_rtrim(فراغ)
{
	حرف *s;

	TEST_پیل("rtrim trailing space");
	s = xstrdup("hello  ");
	rtrim(s);
	ASSERT_STRING_EQ(s, "hello");
	حرر(s);
	TEST_بشپړ();

	TEST_پیل("rtrim trailing tab");
	s = xstrdup("hello\t\t");
	rtrim(s);
	ASSERT_STRING_EQ(s, "hello");
	حرر(s);
	TEST_بشپړ();

	TEST_پیل("rtrim trailing mixed whitespace");
	s = xstrdup("hello \t ");
	rtrim(s);
	ASSERT_STRING_EQ(s, "hello");
	حرر(s);
	TEST_بشپړ();

	TEST_پیل("rtrim no trailing whitespace");
	s = xstrdup("hello");
	rtrim(s);
	ASSERT_STRING_EQ(s, "hello");
	حرر(s);
	TEST_بشپړ();

	TEST_پیل("rtrim whitespace in middle");
	s = xstrdup("he llo");
	rtrim(s);
	ASSERT_STRING_EQ(s, "he llo");
	حرر(s);
	TEST_بشپړ();

	TEST_پیل("rtrim empty string");
	s = xstrdup("");
	rtrim(s);
	ASSERT_STRING_EQ(s, "");
	حرر(s);
	TEST_بشپړ();

	TEST_پیل("rtrim only whitespace");
	s = xstrdup("   \t");
	rtrim(s);
	ASSERT_STRING_EQ(s, "");
	حرر(s);
	TEST_بشپړ();
}

ساكن فراغ
test_strprefix(فراغ)
{
	ثابت حرف *s;

	TEST_پیل("strprefix basic match");
	s = strprefix("hello world", "hello", 0);
	ASSERT_PTR_NE(s, عدم);
	ASSERT_STRING_EQ(s, " world");
	TEST_بشپړ();

	TEST_پیل("strprefix no match");
	s = strprefix("hello world", "world", 0);
	ASSERT_PTR_EQ(s, عدم);
	TEST_بشپړ();

	TEST_پیل("strprefix full match");
	s = strprefix("hello", "hello", 0);
	ASSERT_PTR_NE(s, عدم);
	ASSERT_STRING_EQ(s, "");
	TEST_بشپړ();

	TEST_پیل("strprefix empty string");
	s = strprefix("", "hello", 0);
	ASSERT_PTR_EQ(s, عدم);
	TEST_بشپړ();

	TEST_پیل("strprefix empty prefix");
	s = strprefix("hello", "", 0);
	ASSERT_PTR_NE(s, عدم);
	ASSERT_STRING_EQ(s, "hello");
	TEST_بشپړ();

	TEST_پیل("strprefix case sensitive no match");
	s = strprefix("Hello world", "hello", 0);
	ASSERT_PTR_EQ(s, عدم);
	TEST_بشپړ();

	TEST_پیل("strprefix case insensitive match");
	s = strprefix("Hello world", "hello", 1);
	ASSERT_PTR_NE(s, عدم);
	ASSERT_STRING_EQ(s, " world");
	TEST_بشپړ();

	TEST_پیل("strprefix case insensitive full match");
	s = strprefix("HELLO", "hello", 1);
	ASSERT_PTR_NE(s, عدم);
	ASSERT_STRING_EQ(s, "");
	TEST_بشپړ();
}

ساكن فراغ
test_fmt_timeframe(فراغ)
{
	TEST_پیل("fmt_timeframe seconds");
	ASSERT_STRING_EQ(fmt_timeframe(0), "00:00:00");
	ASSERT_STRING_EQ(fmt_timeframe(59), "00:00:59");
	ASSERT_STRING_EQ(fmt_timeframe(60), "00:01:00");
	ASSERT_STRING_EQ(fmt_timeframe(3599), "00:59:59");
	ASSERT_STRING_EQ(fmt_timeframe(3600), "01:00:00");
	ASSERT_STRING_EQ(fmt_timeframe(86399), "23:59:59");
	TEST_بشپړ();

	TEST_پیل("fmt_timeframe days");
	ASSERT_STRING_EQ(fmt_timeframe(86400), "1d00h00m");
	ASSERT_STRING_EQ(fmt_timeframe(90061), "1d01h01m");
	ASSERT_STRING_EQ(fmt_timeframe(604799), "6d23h59m");
	TEST_بشپړ();

	TEST_پیل("fmt_timeframe weeks");
	ASSERT_STRING_EQ(fmt_timeframe(604800), "01w0d00h");
	ASSERT_STRING_EQ(fmt_timeframe(694861), "01w1d01h");
	TEST_بشپړ();
}

ساكن فراغ
test_arglist(فراغ)
{
	arglist دلیلونه;
	u_int i;

	memset(&دلیلونه, 0, حجم(دلیلونه));

	TEST_پیل("addargs initial");
	addargs(&دلیلونه, "one");
	ASSERT_U_INT_EQ(دلیلونه.عدد, 1);
	ASSERT_U_INT_EQ(دلیلونه.nalloc, 32);
	ASSERT_PTR_NE(دلیلونه.list, عدم);
	ASSERT_STRING_EQ(دلیلونه.list[0], "one");
	ASSERT_PTR_EQ(دلیلونه.list[1], عدم);
	TEST_بشپړ();

	TEST_پیل("addargs second");
	addargs(&دلیلونه, "two");
	ASSERT_U_INT_EQ(دلیلونه.عدد, 2);
	ASSERT_U_INT_EQ(دلیلونه.nalloc, 32);
	ASSERT_PTR_NE(دلیلونه.list, عدم);
	ASSERT_STRING_EQ(دلیلونه.list[0], "one");
	ASSERT_STRING_EQ(دلیلونه.list[1], "two");
	ASSERT_PTR_EQ(دلیلونه.list[2], عدم);
	TEST_بشپړ();

	TEST_پیل("addargs with format");
	addargs(&دلیلونه, "three=%d", 3);
	ASSERT_U_INT_EQ(دلیلونه.عدد, 3);
	ASSERT_U_INT_EQ(دلیلونه.nalloc, 32);
	ASSERT_PTR_NE(دلیلونه.list, عدم);
	ASSERT_STRING_EQ(دلیلونه.list[0], "one");
	ASSERT_STRING_EQ(دلیلونه.list[1], "two");
	ASSERT_STRING_EQ(دلیلونه.list[2], "three=3");
	ASSERT_PTR_EQ(دلیلونه.list[3], عدم);
	TEST_بشپړ();

	TEST_پیل("replacearg middle");
	replacearg(&دلیلونه, 1, "TWO!");
	ASSERT_U_INT_EQ(دلیلونه.عدد, 3);
	ASSERT_STRING_EQ(دلیلونه.list[0], "one");
	ASSERT_STRING_EQ(دلیلونه.list[1], "TWO!");
	ASSERT_STRING_EQ(دلیلونه.list[2], "three=3");
	ASSERT_PTR_EQ(دلیلونه.list[3], عدم);
	TEST_بشپړ();

	TEST_پیل("replacearg first");
	replacearg(&دلیلونه, 0, "ONE!");
	ASSERT_U_INT_EQ(دلیلونه.عدد, 3);
	ASSERT_STRING_EQ(دلیلونه.list[0], "ONE!");
	ASSERT_STRING_EQ(دلیلونه.list[1], "TWO!");
	ASSERT_STRING_EQ(دلیلونه.list[2], "three=3");
	ASSERT_PTR_EQ(دلیلونه.list[3], عدم);
	TEST_بشپړ();

	TEST_پیل("replacearg last");
	replacearg(&دلیلونه, 2, "THREE=3!");
	ASSERT_U_INT_EQ(دلیلونه.عدد, 3);
	ASSERT_STRING_EQ(دلیلونه.list[0], "ONE!");
	ASSERT_STRING_EQ(دلیلونه.list[1], "TWO!");
	ASSERT_STRING_EQ(دلیلونه.list[2], "THREE=3!");
	ASSERT_PTR_EQ(دلیلونه.list[3], عدم);
	TEST_بشپړ();

	TEST_پیل("replacearg with format");
	replacearg(&دلیلونه, 1, "two=%d", 2);
	ASSERT_U_INT_EQ(دلیلونه.عدد, 3);
	ASSERT_STRING_EQ(دلیلونه.list[0], "ONE!");
	ASSERT_STRING_EQ(دلیلونه.list[1], "two=2");
	ASSERT_STRING_EQ(دلیلونه.list[2], "THREE=3!");
	ASSERT_PTR_EQ(دلیلونه.list[3], عدم);
	TEST_بشپړ();

	TEST_پیل("addargs reallocation");
	لكل (i = دلیلونه.عدد; i < 33; i++)
		addargs(&دلیلونه, "pad-%d", i);
	ASSERT_U_INT_EQ(دلیلونه.عدد, 33);
	ASSERT_U_INT_GE(دلیلونه.nalloc, 33);
	ASSERT_STRING_EQ(دلیلونه.list[32], "pad-32");
	ASSERT_PTR_EQ(دلیلونه.list[33], عدم);
	TEST_بشپړ();

	TEST_پیل("freeargs");
	freeargs(&دلیلونه);
	ASSERT_U_INT_EQ(دلیلونه.عدد, 0);
	ASSERT_U_INT_EQ(دلیلونه.nalloc, 0);
	ASSERT_PTR_EQ(دلیلونه.list, عدم);
	TEST_بشپړ();

	TEST_پیل("freeargs on NULL");
	freeargs(عدم);
	TEST_بشپړ();

	TEST_پیل("freeargs on empty");
	memset(&دلیلونه, 0, حجم(دلیلونه));
	freeargs(&دلیلونه);
	ASSERT_U_INT_EQ(دلیلونه.عدد, 0);
	ASSERT_U_INT_EQ(دلیلونه.nalloc, 0);
	ASSERT_PTR_EQ(دلیلونه.list, عدم);
	TEST_بشپړ();
}

ساكن فراغ
test_tohex(فراغ)
{
	حرف *hex;

	TEST_پیل("tohex simple");
	hex = tohex("foo", 3);
	ASSERT_STRING_EQ(hex, "666f6f");
	حرر(hex);
	TEST_بشپړ();

	TEST_پیل("tohex with null");
	hex = tohex("a\0b", 3);
	ASSERT_STRING_EQ(hex, "610062");
	حرر(hex);
	TEST_بشپړ();

	TEST_پیل("tohex empty");
	hex = tohex("", 0);
	ASSERT_STRING_EQ(hex, "");
	حرر(hex);
	TEST_بشپړ();
}

ساكن فراغ
test_lowercase(فراغ)
{
	حرف *s;

	TEST_پیل("lowercase mixed");
	s = xstrdup("HeLlO WoRlD 123");
	lowercase(s);
	ASSERT_STRING_EQ(s, "hello world 123");
	حرر(s);
	TEST_بشپړ();

	TEST_پیل("lowercase empty");
	s = xstrdup("");
	lowercase(s);
	ASSERT_STRING_EQ(s, "");
	حرر(s);
	TEST_بشپړ();
}

ساكن فراغ
test_لار_absolute(فراغ)
{
	TEST_پیل("path_absolute absolute");
	ASSERT_INT_EQ(لار_absolute("/foo/bar"), 1);
	TEST_بشپړ();

	TEST_پیل("path_absolute relative");
	ASSERT_INT_EQ(لار_absolute("foo/bar"), 0);
	TEST_بشپړ();

	TEST_پیل("path_absolute empty");
	ASSERT_INT_EQ(لار_absolute(""), 0);
	TEST_بشپړ();
}

ساكن فراغ
test_stringlist(فراغ)
{
	حرف **list = عدم;

	TEST_پیل("stringlist_append initial");
	stringlist_append(&list, "one");
	ASSERT_PTR_NE(list, عدم);
	ASSERT_STRING_EQ(list[0], "one");
	ASSERT_PTR_EQ(list[1], عدم);
	TEST_بشپړ();

	TEST_پیل("stringlist_append second");
	stringlist_append(&list, "two");
	ASSERT_PTR_NE(list, عدم);
	ASSERT_STRING_EQ(list[0], "one");
	ASSERT_STRING_EQ(list[1], "two");
	ASSERT_PTR_EQ(list[2], عدم);
	TEST_بشپړ();

	TEST_پیل("stringlist_append third");
	stringlist_append(&list, "three");
	ASSERT_PTR_NE(list, عدم);
	ASSERT_STRING_EQ(list[0], "one");
	ASSERT_STRING_EQ(list[1], "two");
	ASSERT_STRING_EQ(list[2], "three");
	ASSERT_PTR_EQ(list[3], عدم);
	TEST_بشپړ();

	TEST_پیل("stringlist_free");
	stringlist_free(list);
	TEST_بشپړ();

	TEST_پیل("stringlist_free NULL");
	stringlist_free(عدم);
	TEST_بشپړ();
}

ساكن فراغ
test_skip_space(فراغ)
{
	حرف *s, *p;

	TEST_پیل("skip_space leading spaces");
	s = p = xstrdup("  hello");
	skip_space(&p);
	ASSERT_STRING_EQ(p, "hello");
	حرر(s);
	TEST_بشپړ();

	TEST_پیل("skip_space leading tabs");
	s = p = xstrdup("\t\thello");
	skip_space(&p);
	ASSERT_STRING_EQ(p, "hello");
	حرر(s);
	TEST_بشپړ();

	TEST_پیل("skip_space leading mixed whitespace");
	s = p = xstrdup(" \t hello");
	skip_space(&p);
	ASSERT_STRING_EQ(p, "hello");
	حرر(s);
	TEST_بشپړ();

	TEST_پیل("skip_space no leading whitespace");
	s = p = xstrdup("hello");
	skip_space(&p);
	ASSERT_STRING_EQ(p, "hello");
	حرر(s);
	TEST_بشپړ();

	TEST_پیل("skip_space empty string");
	s = p = xstrdup("");
	skip_space(&p);
	ASSERT_STRING_EQ(p, "");
	حرر(s);
	TEST_بشپړ();

	TEST_پیل("skip_space only whitespace");
	s = p = xstrdup(" \t ");
	skip_space(&p);
	ASSERT_STRING_EQ(p, "");
	حرر(s);
	TEST_بشپړ();
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
	test_لار_absolute();
	test_stringlist();
	test_skip_space();
}
