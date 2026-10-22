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

تهی test_misc(تهی);

ایستا تهی
test_chop(تهی)
{
	نویسه *s;

	TEST_START("chop newline");
	s = xstrdup("hello\n");
	ASSERT_STRING_EQ(chop(s), "hello");
	آزاد(s);
	TEST_DONE();

	TEST_START("chop carriage return");
	s = xstrdup("hello\r");
	ASSERT_STRING_EQ(chop(s), "hello");
	آزاد(s);
	TEST_DONE();

	TEST_START("chop CRLF");
	s = xstrdup("hello\r\n");
	ASSERT_STRING_EQ(chop(s), "hello");
	آزاد(s);
	TEST_DONE();

	TEST_START("chop newline in middle");
	s = xstrdup("he\nllo");
	ASSERT_STRING_EQ(chop(s), "he");
	آزاد(s);
	TEST_DONE();

	TEST_START("chop no newline");
	s = xstrdup("hello");
	ASSERT_STRING_EQ(chop(s), "hello");
	آزاد(s);
	TEST_DONE();

	TEST_START("chop empty string");
	s = xstrdup("");
	ASSERT_STRING_EQ(chop(s), "");
	آزاد(s);
	TEST_DONE();

	TEST_START("chop only newline");
	s = xstrdup("\n");
	ASSERT_STRING_EQ(chop(s), "");
	آزاد(s);
	TEST_DONE();

	TEST_START("chop only CR");
	s = xstrdup("\r");
	ASSERT_STRING_EQ(chop(s), "");
	آزاد(s);
	TEST_DONE();

	TEST_START("chop only CRLF");
	s = xstrdup("\r\n");
	ASSERT_STRING_EQ(chop(s), "");
	آزاد(s);
	TEST_DONE();
}

ایستا تهی
test_rtrim(تهی)
{
	نویسه *s;

	TEST_START("rtrim trailing space");
	s = xstrdup("hello  ");
	rtrim(s);
	ASSERT_STRING_EQ(s, "hello");
	آزاد(s);
	TEST_DONE();

	TEST_START("rtrim trailing tab");
	s = xstrdup("hello\t\t");
	rtrim(s);
	ASSERT_STRING_EQ(s, "hello");
	آزاد(s);
	TEST_DONE();

	TEST_START("rtrim trailing mixed whitespace");
	s = xstrdup("hello \t ");
	rtrim(s);
	ASSERT_STRING_EQ(s, "hello");
	آزاد(s);
	TEST_DONE();

	TEST_START("rtrim no trailing whitespace");
	s = xstrdup("hello");
	rtrim(s);
	ASSERT_STRING_EQ(s, "hello");
	آزاد(s);
	TEST_DONE();

	TEST_START("rtrim whitespace in middle");
	s = xstrdup("he llo");
	rtrim(s);
	ASSERT_STRING_EQ(s, "he llo");
	آزاد(s);
	TEST_DONE();

	TEST_START("rtrim empty string");
	s = xstrdup("");
	rtrim(s);
	ASSERT_STRING_EQ(s, "");
	آزاد(s);
	TEST_DONE();

	TEST_START("rtrim only whitespace");
	s = xstrdup("   \t");
	rtrim(s);
	ASSERT_STRING_EQ(s, "");
	آزاد(s);
	TEST_DONE();
}

ایستا تهی
test_strprefix(تهی)
{
	ثابت نویسه *s;

	TEST_START("strprefix basic match");
	s = strprefix("hello world", "hello", 0);
	ASSERT_PTR_NE(s, پوچ);
	ASSERT_STRING_EQ(s, " world");
	TEST_DONE();

	TEST_START("strprefix no match");
	s = strprefix("hello world", "world", 0);
	ASSERT_PTR_EQ(s, پوچ);
	TEST_DONE();

	TEST_START("strprefix full match");
	s = strprefix("hello", "hello", 0);
	ASSERT_PTR_NE(s, پوچ);
	ASSERT_STRING_EQ(s, "");
	TEST_DONE();

	TEST_START("strprefix empty string");
	s = strprefix("", "hello", 0);
	ASSERT_PTR_EQ(s, پوچ);
	TEST_DONE();

	TEST_START("strprefix empty prefix");
	s = strprefix("hello", "", 0);
	ASSERT_PTR_NE(s, پوچ);
	ASSERT_STRING_EQ(s, "hello");
	TEST_DONE();

	TEST_START("strprefix case sensitive no match");
	s = strprefix("Hello world", "hello", 0);
	ASSERT_PTR_EQ(s, پوچ);
	TEST_DONE();

	TEST_START("strprefix case insensitive match");
	s = strprefix("Hello world", "hello", 1);
	ASSERT_PTR_NE(s, پوچ);
	ASSERT_STRING_EQ(s, " world");
	TEST_DONE();

	TEST_START("strprefix case insensitive full match");
	s = strprefix("HELLO", "hello", 1);
	ASSERT_PTR_NE(s, پوچ);
	ASSERT_STRING_EQ(s, "");
	TEST_DONE();
}

ایستا تهی
test_fmt_timeframe(تهی)
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

ایستا تهی
test_arglist(تهی)
{
	arglist args;
	u_int i;

	memset(&args, 0, اندازه(args));

	TEST_START("addargs initial");
	addargs(&args, "one");
	ASSERT_U_INT_EQ(args.رقم, 1);
	ASSERT_U_INT_EQ(args.nalloc, 32);
	ASSERT_PTR_NE(args.list, پوچ);
	ASSERT_STRING_EQ(args.list[0], "one");
	ASSERT_PTR_EQ(args.list[1], پوچ);
	TEST_DONE();

	TEST_START("addargs second");
	addargs(&args, "two");
	ASSERT_U_INT_EQ(args.رقم, 2);
	ASSERT_U_INT_EQ(args.nalloc, 32);
	ASSERT_PTR_NE(args.list, پوچ);
	ASSERT_STRING_EQ(args.list[0], "one");
	ASSERT_STRING_EQ(args.list[1], "two");
	ASSERT_PTR_EQ(args.list[2], پوچ);
	TEST_DONE();

	TEST_START("addargs with format");
	addargs(&args, "three=%d", 3);
	ASSERT_U_INT_EQ(args.رقم, 3);
	ASSERT_U_INT_EQ(args.nalloc, 32);
	ASSERT_PTR_NE(args.list, پوچ);
	ASSERT_STRING_EQ(args.list[0], "one");
	ASSERT_STRING_EQ(args.list[1], "two");
	ASSERT_STRING_EQ(args.list[2], "three=3");
	ASSERT_PTR_EQ(args.list[3], پوچ);
	TEST_DONE();

	TEST_START("replacearg middle");
	replacearg(&args, 1, "TWO!");
	ASSERT_U_INT_EQ(args.رقم, 3);
	ASSERT_STRING_EQ(args.list[0], "one");
	ASSERT_STRING_EQ(args.list[1], "TWO!");
	ASSERT_STRING_EQ(args.list[2], "three=3");
	ASSERT_PTR_EQ(args.list[3], پوچ);
	TEST_DONE();

	TEST_START("replacearg first");
	replacearg(&args, 0, "ONE!");
	ASSERT_U_INT_EQ(args.رقم, 3);
	ASSERT_STRING_EQ(args.list[0], "ONE!");
	ASSERT_STRING_EQ(args.list[1], "TWO!");
	ASSERT_STRING_EQ(args.list[2], "three=3");
	ASSERT_PTR_EQ(args.list[3], پوچ);
	TEST_DONE();

	TEST_START("replacearg last");
	replacearg(&args, 2, "THREE=3!");
	ASSERT_U_INT_EQ(args.رقم, 3);
	ASSERT_STRING_EQ(args.list[0], "ONE!");
	ASSERT_STRING_EQ(args.list[1], "TWO!");
	ASSERT_STRING_EQ(args.list[2], "THREE=3!");
	ASSERT_PTR_EQ(args.list[3], پوچ);
	TEST_DONE();

	TEST_START("replacearg with format");
	replacearg(&args, 1, "two=%d", 2);
	ASSERT_U_INT_EQ(args.رقم, 3);
	ASSERT_STRING_EQ(args.list[0], "ONE!");
	ASSERT_STRING_EQ(args.list[1], "two=2");
	ASSERT_STRING_EQ(args.list[2], "THREE=3!");
	ASSERT_PTR_EQ(args.list[3], پوچ);
	TEST_DONE();

	TEST_START("addargs reallocation");
	برای (i = args.رقم; i < 33; i++)
		addargs(&args, "pad-%d", i);
	ASSERT_U_INT_EQ(args.رقم, 33);
	ASSERT_U_INT_GE(args.nalloc, 33);
	ASSERT_STRING_EQ(args.list[32], "pad-32");
	ASSERT_PTR_EQ(args.list[33], پوچ);
	TEST_DONE();

	TEST_START("freeargs");
	freeargs(&args);
	ASSERT_U_INT_EQ(args.رقم, 0);
	ASSERT_U_INT_EQ(args.nalloc, 0);
	ASSERT_PTR_EQ(args.list, پوچ);
	TEST_DONE();

	TEST_START("freeargs on NULL");
	freeargs(پوچ);
	TEST_DONE();

	TEST_START("freeargs on empty");
	memset(&args, 0, اندازه(args));
	freeargs(&args);
	ASSERT_U_INT_EQ(args.رقم, 0);
	ASSERT_U_INT_EQ(args.nalloc, 0);
	ASSERT_PTR_EQ(args.list, پوچ);
	TEST_DONE();
}

ایستا تهی
test_tohex(تهی)
{
	نویسه *hex;

	TEST_START("tohex simple");
	hex = tohex("foo", 3);
	ASSERT_STRING_EQ(hex, "666f6f");
	آزاد(hex);
	TEST_DONE();

	TEST_START("tohex with null");
	hex = tohex("a\0b", 3);
	ASSERT_STRING_EQ(hex, "610062");
	آزاد(hex);
	TEST_DONE();

	TEST_START("tohex empty");
	hex = tohex("", 0);
	ASSERT_STRING_EQ(hex, "");
	آزاد(hex);
	TEST_DONE();
}

ایستا تهی
test_lowercase(تهی)
{
	نویسه *s;

	TEST_START("lowercase mixed");
	s = xstrdup("HeLlO WoRlD 123");
	lowercase(s);
	ASSERT_STRING_EQ(s, "hello world 123");
	آزاد(s);
	TEST_DONE();

	TEST_START("lowercase empty");
	s = xstrdup("");
	lowercase(s);
	ASSERT_STRING_EQ(s, "");
	آزاد(s);
	TEST_DONE();
}

ایستا تهی
test_path_absolute(تهی)
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

ایستا تهی
test_stringlist(تهی)
{
	نویسه **list = پوچ;

	TEST_START("stringlist_append initial");
	stringlist_append(&list, "one");
	ASSERT_PTR_NE(list, پوچ);
	ASSERT_STRING_EQ(list[0], "one");
	ASSERT_PTR_EQ(list[1], پوچ);
	TEST_DONE();

	TEST_START("stringlist_append second");
	stringlist_append(&list, "two");
	ASSERT_PTR_NE(list, پوچ);
	ASSERT_STRING_EQ(list[0], "one");
	ASSERT_STRING_EQ(list[1], "two");
	ASSERT_PTR_EQ(list[2], پوچ);
	TEST_DONE();

	TEST_START("stringlist_append third");
	stringlist_append(&list, "three");
	ASSERT_PTR_NE(list, پوچ);
	ASSERT_STRING_EQ(list[0], "one");
	ASSERT_STRING_EQ(list[1], "two");
	ASSERT_STRING_EQ(list[2], "three");
	ASSERT_PTR_EQ(list[3], پوچ);
	TEST_DONE();

	TEST_START("stringlist_free");
	stringlist_free(list);
	TEST_DONE();

	TEST_START("stringlist_free NULL");
	stringlist_free(پوچ);
	TEST_DONE();
}

ایستا تهی
test_skip_space(تهی)
{
	نویسه *s, *p;

	TEST_START("skip_space leading spaces");
	s = p = xstrdup("  hello");
	skip_space(&p);
	ASSERT_STRING_EQ(p, "hello");
	آزاد(s);
	TEST_DONE();

	TEST_START("skip_space leading tabs");
	s = p = xstrdup("\t\thello");
	skip_space(&p);
	ASSERT_STRING_EQ(p, "hello");
	آزاد(s);
	TEST_DONE();

	TEST_START("skip_space leading mixed whitespace");
	s = p = xstrdup(" \t hello");
	skip_space(&p);
	ASSERT_STRING_EQ(p, "hello");
	آزاد(s);
	TEST_DONE();

	TEST_START("skip_space no leading whitespace");
	s = p = xstrdup("hello");
	skip_space(&p);
	ASSERT_STRING_EQ(p, "hello");
	آزاد(s);
	TEST_DONE();

	TEST_START("skip_space empty string");
	s = p = xstrdup("");
	skip_space(&p);
	ASSERT_STRING_EQ(p, "");
	آزاد(s);
	TEST_DONE();

	TEST_START("skip_space only whitespace");
	s = p = xstrdup(" \t ");
	skip_space(&p);
	ASSERT_STRING_EQ(p, "");
	آزاد(s);
	TEST_DONE();
}

تهی
test_misc(تهی)
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
