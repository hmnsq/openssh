/*
 * Regress test for misc helper functions.
 *
 * Placed in the public domain.
 */

#شامل "includes.h"

#شامل <sys/types.h>
#شامل <stdio.h>
#شامل <stdint.h>
#شامل <stdlib.h>
#شامل <string.h>

#شامل "../test_helper/test_helper.h"

#شامل "log.h"
#شامل "misc.h"
#شامل "xmalloc.h"

خالی test_misc(خالی);

ساکن خالی
test_chop(خالی)
{
	حرف *s;

	TEST_آغاز("chop newline");
	s = xstrdup("hello\n");
	ASSERT_STRING_EQ(chop(s), "hello");
	آزاد(s);
	TEST_مکمل();

	TEST_آغاز("chop carriage return");
	s = xstrdup("hello\r");
	ASSERT_STRING_EQ(chop(s), "hello");
	آزاد(s);
	TEST_مکمل();

	TEST_آغاز("chop CRLF");
	s = xstrdup("hello\r\n");
	ASSERT_STRING_EQ(chop(s), "hello");
	آزاد(s);
	TEST_مکمل();

	TEST_آغاز("chop newline in middle");
	s = xstrdup("he\nllo");
	ASSERT_STRING_EQ(chop(s), "he");
	آزاد(s);
	TEST_مکمل();

	TEST_آغاز("chop no newline");
	s = xstrdup("hello");
	ASSERT_STRING_EQ(chop(s), "hello");
	آزاد(s);
	TEST_مکمل();

	TEST_آغاز("chop empty string");
	s = xstrdup("");
	ASSERT_STRING_EQ(chop(s), "");
	آزاد(s);
	TEST_مکمل();

	TEST_آغاز("chop only newline");
	s = xstrdup("\n");
	ASSERT_STRING_EQ(chop(s), "");
	آزاد(s);
	TEST_مکمل();

	TEST_آغاز("chop only CR");
	s = xstrdup("\r");
	ASSERT_STRING_EQ(chop(s), "");
	آزاد(s);
	TEST_مکمل();

	TEST_آغاز("chop only CRLF");
	s = xstrdup("\r\n");
	ASSERT_STRING_EQ(chop(s), "");
	آزاد(s);
	TEST_مکمل();
}

ساکن خالی
test_rtrim(خالی)
{
	حرف *s;

	TEST_آغاز("rtrim trailing space");
	s = xstrdup("hello  ");
	rtrim(s);
	ASSERT_STRING_EQ(s, "hello");
	آزاد(s);
	TEST_مکمل();

	TEST_آغاز("rtrim trailing tab");
	s = xstrdup("hello\t\t");
	rtrim(s);
	ASSERT_STRING_EQ(s, "hello");
	آزاد(s);
	TEST_مکمل();

	TEST_آغاز("rtrim trailing mixed whitespace");
	s = xstrdup("hello \t ");
	rtrim(s);
	ASSERT_STRING_EQ(s, "hello");
	آزاد(s);
	TEST_مکمل();

	TEST_آغاز("rtrim no trailing whitespace");
	s = xstrdup("hello");
	rtrim(s);
	ASSERT_STRING_EQ(s, "hello");
	آزاد(s);
	TEST_مکمل();

	TEST_آغاز("rtrim whitespace in middle");
	s = xstrdup("he llo");
	rtrim(s);
	ASSERT_STRING_EQ(s, "he llo");
	آزاد(s);
	TEST_مکمل();

	TEST_آغاز("rtrim empty string");
	s = xstrdup("");
	rtrim(s);
	ASSERT_STRING_EQ(s, "");
	آزاد(s);
	TEST_مکمل();

	TEST_آغاز("rtrim only whitespace");
	s = xstrdup("   \t");
	rtrim(s);
	ASSERT_STRING_EQ(s, "");
	آزاد(s);
	TEST_مکمل();
}

ساکن خالی
test_strprefix(خالی)
{
	ثابت حرف *s;

	TEST_آغاز("strprefix basic match");
	s = strprefix("hello world", "hello", 0);
	ASSERT_PTR_NE(s, تہی);
	ASSERT_STRING_EQ(s, " world");
	TEST_مکمل();

	TEST_آغاز("strprefix no match");
	s = strprefix("hello world", "world", 0);
	ASSERT_PTR_EQ(s, تہی);
	TEST_مکمل();

	TEST_آغاز("strprefix full match");
	s = strprefix("hello", "hello", 0);
	ASSERT_PTR_NE(s, تہی);
	ASSERT_STRING_EQ(s, "");
	TEST_مکمل();

	TEST_آغاز("strprefix empty string");
	s = strprefix("", "hello", 0);
	ASSERT_PTR_EQ(s, تہی);
	TEST_مکمل();

	TEST_آغاز("strprefix empty prefix");
	s = strprefix("hello", "", 0);
	ASSERT_PTR_NE(s, تہی);
	ASSERT_STRING_EQ(s, "hello");
	TEST_مکمل();

	TEST_آغاز("strprefix case sensitive no match");
	s = strprefix("Hello world", "hello", 0);
	ASSERT_PTR_EQ(s, تہی);
	TEST_مکمل();

	TEST_آغاز("strprefix case insensitive match");
	s = strprefix("Hello world", "hello", 1);
	ASSERT_PTR_NE(s, تہی);
	ASSERT_STRING_EQ(s, " world");
	TEST_مکمل();

	TEST_آغاز("strprefix case insensitive full match");
	s = strprefix("HELLO", "hello", 1);
	ASSERT_PTR_NE(s, تہی);
	ASSERT_STRING_EQ(s, "");
	TEST_مکمل();
}

ساکن خالی
test_fmt_timeframe(خالی)
{
	TEST_آغاز("fmt_timeframe seconds");
	ASSERT_STRING_EQ(fmt_timeframe(0), "00:00:00");
	ASSERT_STRING_EQ(fmt_timeframe(59), "00:00:59");
	ASSERT_STRING_EQ(fmt_timeframe(60), "00:01:00");
	ASSERT_STRING_EQ(fmt_timeframe(3599), "00:59:59");
	ASSERT_STRING_EQ(fmt_timeframe(3600), "01:00:00");
	ASSERT_STRING_EQ(fmt_timeframe(86399), "23:59:59");
	TEST_مکمل();

	TEST_آغاز("fmt_timeframe days");
	ASSERT_STRING_EQ(fmt_timeframe(86400), "1d00h00m");
	ASSERT_STRING_EQ(fmt_timeframe(90061), "1d01h01m");
	ASSERT_STRING_EQ(fmt_timeframe(604799), "6d23h59m");
	TEST_مکمل();

	TEST_آغاز("fmt_timeframe weeks");
	ASSERT_STRING_EQ(fmt_timeframe(604800), "01w0d00h");
	ASSERT_STRING_EQ(fmt_timeframe(694861), "01w1d01h");
	TEST_مکمل();
}

ساکن خالی
test_arglist(خالی)
{
	arglist دلائل;
	u_int i;

	memset(&دلائل, 0, حجم(دلائل));

	TEST_آغاز("addargs initial");
	addargs(&دلائل, "one");
	ASSERT_U_INT_EQ(دلائل.عدد, 1);
	ASSERT_U_INT_EQ(دلائل.nalloc, 32);
	ASSERT_PTR_NE(دلائل.list, تہی);
	ASSERT_STRING_EQ(دلائل.list[0], "one");
	ASSERT_PTR_EQ(دلائل.list[1], تہی);
	TEST_مکمل();

	TEST_آغاز("addargs second");
	addargs(&دلائل, "two");
	ASSERT_U_INT_EQ(دلائل.عدد, 2);
	ASSERT_U_INT_EQ(دلائل.nalloc, 32);
	ASSERT_PTR_NE(دلائل.list, تہی);
	ASSERT_STRING_EQ(دلائل.list[0], "one");
	ASSERT_STRING_EQ(دلائل.list[1], "two");
	ASSERT_PTR_EQ(دلائل.list[2], تہی);
	TEST_مکمل();

	TEST_آغاز("addargs with format");
	addargs(&دلائل, "three=%d", 3);
	ASSERT_U_INT_EQ(دلائل.عدد, 3);
	ASSERT_U_INT_EQ(دلائل.nalloc, 32);
	ASSERT_PTR_NE(دلائل.list, تہی);
	ASSERT_STRING_EQ(دلائل.list[0], "one");
	ASSERT_STRING_EQ(دلائل.list[1], "two");
	ASSERT_STRING_EQ(دلائل.list[2], "three=3");
	ASSERT_PTR_EQ(دلائل.list[3], تہی);
	TEST_مکمل();

	TEST_آغاز("replacearg middle");
	replacearg(&دلائل, 1, "TWO!");
	ASSERT_U_INT_EQ(دلائل.عدد, 3);
	ASSERT_STRING_EQ(دلائل.list[0], "one");
	ASSERT_STRING_EQ(دلائل.list[1], "TWO!");
	ASSERT_STRING_EQ(دلائل.list[2], "three=3");
	ASSERT_PTR_EQ(دلائل.list[3], تہی);
	TEST_مکمل();

	TEST_آغاز("replacearg first");
	replacearg(&دلائل, 0, "ONE!");
	ASSERT_U_INT_EQ(دلائل.عدد, 3);
	ASSERT_STRING_EQ(دلائل.list[0], "ONE!");
	ASSERT_STRING_EQ(دلائل.list[1], "TWO!");
	ASSERT_STRING_EQ(دلائل.list[2], "three=3");
	ASSERT_PTR_EQ(دلائل.list[3], تہی);
	TEST_مکمل();

	TEST_آغاز("replacearg last");
	replacearg(&دلائل, 2, "THREE=3!");
	ASSERT_U_INT_EQ(دلائل.عدد, 3);
	ASSERT_STRING_EQ(دلائل.list[0], "ONE!");
	ASSERT_STRING_EQ(دلائل.list[1], "TWO!");
	ASSERT_STRING_EQ(دلائل.list[2], "THREE=3!");
	ASSERT_PTR_EQ(دلائل.list[3], تہی);
	TEST_مکمل();

	TEST_آغاز("replacearg with format");
	replacearg(&دلائل, 1, "two=%d", 2);
	ASSERT_U_INT_EQ(دلائل.عدد, 3);
	ASSERT_STRING_EQ(دلائل.list[0], "ONE!");
	ASSERT_STRING_EQ(دلائل.list[1], "two=2");
	ASSERT_STRING_EQ(دلائل.list[2], "THREE=3!");
	ASSERT_PTR_EQ(دلائل.list[3], تہی);
	TEST_مکمل();

	TEST_آغاز("addargs reallocation");
	برائے (i = دلائل.عدد; i < 33; i++)
		addargs(&دلائل, "pad-%d", i);
	ASSERT_U_INT_EQ(دلائل.عدد, 33);
	ASSERT_U_INT_GE(دلائل.nalloc, 33);
	ASSERT_STRING_EQ(دلائل.list[32], "pad-32");
	ASSERT_PTR_EQ(دلائل.list[33], تہی);
	TEST_مکمل();

	TEST_آغاز("freeargs");
	freeargs(&دلائل);
	ASSERT_U_INT_EQ(دلائل.عدد, 0);
	ASSERT_U_INT_EQ(دلائل.nalloc, 0);
	ASSERT_PTR_EQ(دلائل.list, تہی);
	TEST_مکمل();

	TEST_آغاز("freeargs on NULL");
	freeargs(تہی);
	TEST_مکمل();

	TEST_آغاز("freeargs on empty");
	memset(&دلائل, 0, حجم(دلائل));
	freeargs(&دلائل);
	ASSERT_U_INT_EQ(دلائل.عدد, 0);
	ASSERT_U_INT_EQ(دلائل.nalloc, 0);
	ASSERT_PTR_EQ(دلائل.list, تہی);
	TEST_مکمل();
}

ساکن خالی
test_tohex(خالی)
{
	حرف *hex;

	TEST_آغاز("tohex simple");
	hex = tohex("foo", 3);
	ASSERT_STRING_EQ(hex, "666f6f");
	آزاد(hex);
	TEST_مکمل();

	TEST_آغاز("tohex with null");
	hex = tohex("a\0b", 3);
	ASSERT_STRING_EQ(hex, "610062");
	آزاد(hex);
	TEST_مکمل();

	TEST_آغاز("tohex empty");
	hex = tohex("", 0);
	ASSERT_STRING_EQ(hex, "");
	آزاد(hex);
	TEST_مکمل();
}

ساکن خالی
test_lowercase(خالی)
{
	حرف *s;

	TEST_آغاز("lowercase mixed");
	s = xstrdup("HeLlO WoRlD 123");
	lowercase(s);
	ASSERT_STRING_EQ(s, "hello world 123");
	آزاد(s);
	TEST_مکمل();

	TEST_آغاز("lowercase empty");
	s = xstrdup("");
	lowercase(s);
	ASSERT_STRING_EQ(s, "");
	آزاد(s);
	TEST_مکمل();
}

ساکن خالی
test_راستہ_absolute(خالی)
{
	TEST_آغاز("path_absolute absolute");
	ASSERT_INT_EQ(راستہ_absolute("/foo/bar"), 1);
	TEST_مکمل();

	TEST_آغاز("path_absolute relative");
	ASSERT_INT_EQ(راستہ_absolute("foo/bar"), 0);
	TEST_مکمل();

	TEST_آغاز("path_absolute empty");
	ASSERT_INT_EQ(راستہ_absolute(""), 0);
	TEST_مکمل();
}

ساکن خالی
test_stringlist(خالی)
{
	حرف **list = تہی;

	TEST_آغاز("stringlist_append initial");
	stringlist_append(&list, "one");
	ASSERT_PTR_NE(list, تہی);
	ASSERT_STRING_EQ(list[0], "one");
	ASSERT_PTR_EQ(list[1], تہی);
	TEST_مکمل();

	TEST_آغاز("stringlist_append second");
	stringlist_append(&list, "two");
	ASSERT_PTR_NE(list, تہی);
	ASSERT_STRING_EQ(list[0], "one");
	ASSERT_STRING_EQ(list[1], "two");
	ASSERT_PTR_EQ(list[2], تہی);
	TEST_مکمل();

	TEST_آغاز("stringlist_append third");
	stringlist_append(&list, "three");
	ASSERT_PTR_NE(list, تہی);
	ASSERT_STRING_EQ(list[0], "one");
	ASSERT_STRING_EQ(list[1], "two");
	ASSERT_STRING_EQ(list[2], "three");
	ASSERT_PTR_EQ(list[3], تہی);
	TEST_مکمل();

	TEST_آغاز("stringlist_free");
	stringlist_free(list);
	TEST_مکمل();

	TEST_آغاز("stringlist_free NULL");
	stringlist_free(تہی);
	TEST_مکمل();
}

ساکن خالی
test_skip_space(خالی)
{
	حرف *s, *p;

	TEST_آغاز("skip_space leading spaces");
	s = p = xstrdup("  hello");
	skip_space(&p);
	ASSERT_STRING_EQ(p, "hello");
	آزاد(s);
	TEST_مکمل();

	TEST_آغاز("skip_space leading tabs");
	s = p = xstrdup("\t\thello");
	skip_space(&p);
	ASSERT_STRING_EQ(p, "hello");
	آزاد(s);
	TEST_مکمل();

	TEST_آغاز("skip_space leading mixed whitespace");
	s = p = xstrdup(" \t hello");
	skip_space(&p);
	ASSERT_STRING_EQ(p, "hello");
	آزاد(s);
	TEST_مکمل();

	TEST_آغاز("skip_space no leading whitespace");
	s = p = xstrdup("hello");
	skip_space(&p);
	ASSERT_STRING_EQ(p, "hello");
	آزاد(s);
	TEST_مکمل();

	TEST_آغاز("skip_space empty string");
	s = p = xstrdup("");
	skip_space(&p);
	ASSERT_STRING_EQ(p, "");
	آزاد(s);
	TEST_مکمل();

	TEST_آغاز("skip_space only whitespace");
	s = p = xstrdup(" \t ");
	skip_space(&p);
	ASSERT_STRING_EQ(p, "");
	آزاد(s);
	TEST_مکمل();
}

خالی
test_misc(خالی)
{
	test_chop();
	test_rtrim();
	test_strprefix();
	test_fmt_timeframe();
	test_arglist();
	test_tohex();
	test_lowercase();
	test_راستہ_absolute();
	test_stringlist();
	test_skip_space();
}
