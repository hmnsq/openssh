/*
 * Regress test for misc helper functions.
 *
 * Placed in the public domain.
 */

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdint.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "../test_helper/test_helper.h"

#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "misc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "xmalloc.h"

ਖਾਲੀ test_misc(ਖਾਲੀ);

ਸਥਿਰ ਖਾਲੀ
test_chop(ਖਾਲੀ)
{
	ਅੱਖਰ *s;

	TEST_ਸ਼ੁਰੂ("chop newline");
	s = xstrdup("hello\n");
	ASSERT_STRING_EQ(chop(s), "hello");
	ਮੁਕਤ(s);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("chop carriage return");
	s = xstrdup("hello\r");
	ASSERT_STRING_EQ(chop(s), "hello");
	ਮੁਕਤ(s);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("chop CRLF");
	s = xstrdup("hello\r\n");
	ASSERT_STRING_EQ(chop(s), "hello");
	ਮੁਕਤ(s);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("chop newline in middle");
	s = xstrdup("he\nllo");
	ASSERT_STRING_EQ(chop(s), "he");
	ਮੁਕਤ(s);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("chop no newline");
	s = xstrdup("hello");
	ASSERT_STRING_EQ(chop(s), "hello");
	ਮੁਕਤ(s);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("chop empty string");
	s = xstrdup("");
	ASSERT_STRING_EQ(chop(s), "");
	ਮੁਕਤ(s);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("chop only newline");
	s = xstrdup("\n");
	ASSERT_STRING_EQ(chop(s), "");
	ਮੁਕਤ(s);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("chop only CR");
	s = xstrdup("\r");
	ASSERT_STRING_EQ(chop(s), "");
	ਮੁਕਤ(s);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("chop only CRLF");
	s = xstrdup("\r\n");
	ASSERT_STRING_EQ(chop(s), "");
	ਮੁਕਤ(s);
	TEST_ਪੂਰਾ();
}

ਸਥਿਰ ਖਾਲੀ
test_rtrim(ਖਾਲੀ)
{
	ਅੱਖਰ *s;

	TEST_ਸ਼ੁਰੂ("rtrim trailing space");
	s = xstrdup("hello  ");
	rtrim(s);
	ASSERT_STRING_EQ(s, "hello");
	ਮੁਕਤ(s);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("rtrim trailing tab");
	s = xstrdup("hello\t\t");
	rtrim(s);
	ASSERT_STRING_EQ(s, "hello");
	ਮੁਕਤ(s);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("rtrim trailing mixed whitespace");
	s = xstrdup("hello \t ");
	rtrim(s);
	ASSERT_STRING_EQ(s, "hello");
	ਮੁਕਤ(s);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("rtrim no trailing whitespace");
	s = xstrdup("hello");
	rtrim(s);
	ASSERT_STRING_EQ(s, "hello");
	ਮੁਕਤ(s);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("rtrim whitespace in middle");
	s = xstrdup("he llo");
	rtrim(s);
	ASSERT_STRING_EQ(s, "he llo");
	ਮੁਕਤ(s);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("rtrim empty string");
	s = xstrdup("");
	rtrim(s);
	ASSERT_STRING_EQ(s, "");
	ਮੁਕਤ(s);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("rtrim only whitespace");
	s = xstrdup("   \t");
	rtrim(s);
	ASSERT_STRING_EQ(s, "");
	ਮੁਕਤ(s);
	TEST_ਪੂਰਾ();
}

ਸਥਿਰ ਖਾਲੀ
test_strprefix(ਖਾਲੀ)
{
	ਅਚਲ ਅੱਖਰ *s;

	TEST_ਸ਼ੁਰੂ("strprefix basic match");
	s = strprefix("hello world", "hello", 0);
	ASSERT_PTR_NE(s, ਨਿਰਾ);
	ASSERT_STRING_EQ(s, " world");
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("strprefix no match");
	s = strprefix("hello world", "world", 0);
	ASSERT_PTR_EQ(s, ਨਿਰਾ);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("strprefix full match");
	s = strprefix("hello", "hello", 0);
	ASSERT_PTR_NE(s, ਨਿਰਾ);
	ASSERT_STRING_EQ(s, "");
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("strprefix empty string");
	s = strprefix("", "hello", 0);
	ASSERT_PTR_EQ(s, ਨਿਰਾ);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("strprefix empty prefix");
	s = strprefix("hello", "", 0);
	ASSERT_PTR_NE(s, ਨਿਰਾ);
	ASSERT_STRING_EQ(s, "hello");
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("strprefix case sensitive no match");
	s = strprefix("Hello world", "hello", 0);
	ASSERT_PTR_EQ(s, ਨਿਰਾ);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("strprefix case insensitive match");
	s = strprefix("Hello world", "hello", 1);
	ASSERT_PTR_NE(s, ਨਿਰਾ);
	ASSERT_STRING_EQ(s, " world");
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("strprefix case insensitive full match");
	s = strprefix("HELLO", "hello", 1);
	ASSERT_PTR_NE(s, ਨਿਰਾ);
	ASSERT_STRING_EQ(s, "");
	TEST_ਪੂਰਾ();
}

ਸਥਿਰ ਖਾਲੀ
test_fmt_timeframe(ਖਾਲੀ)
{
	TEST_ਸ਼ੁਰੂ("fmt_timeframe seconds");
	ASSERT_STRING_EQ(fmt_timeframe(0), "00:00:00");
	ASSERT_STRING_EQ(fmt_timeframe(59), "00:00:59");
	ASSERT_STRING_EQ(fmt_timeframe(60), "00:01:00");
	ASSERT_STRING_EQ(fmt_timeframe(3599), "00:59:59");
	ASSERT_STRING_EQ(fmt_timeframe(3600), "01:00:00");
	ASSERT_STRING_EQ(fmt_timeframe(86399), "23:59:59");
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("fmt_timeframe days");
	ASSERT_STRING_EQ(fmt_timeframe(86400), "1d00h00m");
	ASSERT_STRING_EQ(fmt_timeframe(90061), "1d01h01m");
	ASSERT_STRING_EQ(fmt_timeframe(604799), "6d23h59m");
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("fmt_timeframe weeks");
	ASSERT_STRING_EQ(fmt_timeframe(604800), "01w0d00h");
	ASSERT_STRING_EQ(fmt_timeframe(694861), "01w1d01h");
	TEST_ਪੂਰਾ();
}

ਸਥਿਰ ਖਾਲੀ
test_arglist(ਖਾਲੀ)
{
	arglist ਦਲੀਲਾਂ;
	u_int i;

	memset(&ਦਲੀਲਾਂ, 0, ਆਕਾਰ(ਦਲੀਲਾਂ));

	TEST_ਸ਼ੁਰੂ("addargs initial");
	addargs(&ਦਲੀਲਾਂ, "one");
	ASSERT_U_INT_EQ(ਦਲੀਲਾਂ.ਅੰਕ, 1);
	ASSERT_U_INT_EQ(ਦਲੀਲਾਂ.nalloc, 32);
	ASSERT_PTR_NE(ਦਲੀਲਾਂ.list, ਨਿਰਾ);
	ASSERT_STRING_EQ(ਦਲੀਲਾਂ.list[0], "one");
	ASSERT_PTR_EQ(ਦਲੀਲਾਂ.list[1], ਨਿਰਾ);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("addargs second");
	addargs(&ਦਲੀਲਾਂ, "two");
	ASSERT_U_INT_EQ(ਦਲੀਲਾਂ.ਅੰਕ, 2);
	ASSERT_U_INT_EQ(ਦਲੀਲਾਂ.nalloc, 32);
	ASSERT_PTR_NE(ਦਲੀਲਾਂ.list, ਨਿਰਾ);
	ASSERT_STRING_EQ(ਦਲੀਲਾਂ.list[0], "one");
	ASSERT_STRING_EQ(ਦਲੀਲਾਂ.list[1], "two");
	ASSERT_PTR_EQ(ਦਲੀਲਾਂ.list[2], ਨਿਰਾ);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("addargs with format");
	addargs(&ਦਲੀਲਾਂ, "three=%d", 3);
	ASSERT_U_INT_EQ(ਦਲੀਲਾਂ.ਅੰਕ, 3);
	ASSERT_U_INT_EQ(ਦਲੀਲਾਂ.nalloc, 32);
	ASSERT_PTR_NE(ਦਲੀਲਾਂ.list, ਨਿਰਾ);
	ASSERT_STRING_EQ(ਦਲੀਲਾਂ.list[0], "one");
	ASSERT_STRING_EQ(ਦਲੀਲਾਂ.list[1], "two");
	ASSERT_STRING_EQ(ਦਲੀਲਾਂ.list[2], "three=3");
	ASSERT_PTR_EQ(ਦਲੀਲਾਂ.list[3], ਨਿਰਾ);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("replacearg middle");
	replacearg(&ਦਲੀਲਾਂ, 1, "TWO!");
	ASSERT_U_INT_EQ(ਦਲੀਲਾਂ.ਅੰਕ, 3);
	ASSERT_STRING_EQ(ਦਲੀਲਾਂ.list[0], "one");
	ASSERT_STRING_EQ(ਦਲੀਲਾਂ.list[1], "TWO!");
	ASSERT_STRING_EQ(ਦਲੀਲਾਂ.list[2], "three=3");
	ASSERT_PTR_EQ(ਦਲੀਲਾਂ.list[3], ਨਿਰਾ);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("replacearg first");
	replacearg(&ਦਲੀਲਾਂ, 0, "ONE!");
	ASSERT_U_INT_EQ(ਦਲੀਲਾਂ.ਅੰਕ, 3);
	ASSERT_STRING_EQ(ਦਲੀਲਾਂ.list[0], "ONE!");
	ASSERT_STRING_EQ(ਦਲੀਲਾਂ.list[1], "TWO!");
	ASSERT_STRING_EQ(ਦਲੀਲਾਂ.list[2], "three=3");
	ASSERT_PTR_EQ(ਦਲੀਲਾਂ.list[3], ਨਿਰਾ);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("replacearg last");
	replacearg(&ਦਲੀਲਾਂ, 2, "THREE=3!");
	ASSERT_U_INT_EQ(ਦਲੀਲਾਂ.ਅੰਕ, 3);
	ASSERT_STRING_EQ(ਦਲੀਲਾਂ.list[0], "ONE!");
	ASSERT_STRING_EQ(ਦਲੀਲਾਂ.list[1], "TWO!");
	ASSERT_STRING_EQ(ਦਲੀਲਾਂ.list[2], "THREE=3!");
	ASSERT_PTR_EQ(ਦਲੀਲਾਂ.list[3], ਨਿਰਾ);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("replacearg with format");
	replacearg(&ਦਲੀਲਾਂ, 1, "two=%d", 2);
	ASSERT_U_INT_EQ(ਦਲੀਲਾਂ.ਅੰਕ, 3);
	ASSERT_STRING_EQ(ਦਲੀਲਾਂ.list[0], "ONE!");
	ASSERT_STRING_EQ(ਦਲੀਲਾਂ.list[1], "two=2");
	ASSERT_STRING_EQ(ਦਲੀਲਾਂ.list[2], "THREE=3!");
	ASSERT_PTR_EQ(ਦਲੀਲਾਂ.list[3], ਨਿਰਾ);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("addargs reallocation");
	ਲਈ (i = ਦਲੀਲਾਂ.ਅੰਕ; i < 33; i++)
		addargs(&ਦਲੀਲਾਂ, "pad-%d", i);
	ASSERT_U_INT_EQ(ਦਲੀਲਾਂ.ਅੰਕ, 33);
	ASSERT_U_INT_GE(ਦਲੀਲਾਂ.nalloc, 33);
	ASSERT_STRING_EQ(ਦਲੀਲਾਂ.list[32], "pad-32");
	ASSERT_PTR_EQ(ਦਲੀਲਾਂ.list[33], ਨਿਰਾ);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("freeargs");
	freeargs(&ਦਲੀਲਾਂ);
	ASSERT_U_INT_EQ(ਦਲੀਲਾਂ.ਅੰਕ, 0);
	ASSERT_U_INT_EQ(ਦਲੀਲਾਂ.nalloc, 0);
	ASSERT_PTR_EQ(ਦਲੀਲਾਂ.list, ਨਿਰਾ);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("freeargs on NULL");
	freeargs(ਨਿਰਾ);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("freeargs on empty");
	memset(&ਦਲੀਲਾਂ, 0, ਆਕਾਰ(ਦਲੀਲਾਂ));
	freeargs(&ਦਲੀਲਾਂ);
	ASSERT_U_INT_EQ(ਦਲੀਲਾਂ.ਅੰਕ, 0);
	ASSERT_U_INT_EQ(ਦਲੀਲਾਂ.nalloc, 0);
	ASSERT_PTR_EQ(ਦਲੀਲਾਂ.list, ਨਿਰਾ);
	TEST_ਪੂਰਾ();
}

ਸਥਿਰ ਖਾਲੀ
test_tohex(ਖਾਲੀ)
{
	ਅੱਖਰ *hex;

	TEST_ਸ਼ੁਰੂ("tohex simple");
	hex = tohex("foo", 3);
	ASSERT_STRING_EQ(hex, "666f6f");
	ਮੁਕਤ(hex);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("tohex with null");
	hex = tohex("a\0b", 3);
	ASSERT_STRING_EQ(hex, "610062");
	ਮੁਕਤ(hex);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("tohex empty");
	hex = tohex("", 0);
	ASSERT_STRING_EQ(hex, "");
	ਮੁਕਤ(hex);
	TEST_ਪੂਰਾ();
}

ਸਥਿਰ ਖਾਲੀ
test_lowercase(ਖਾਲੀ)
{
	ਅੱਖਰ *s;

	TEST_ਸ਼ੁਰੂ("lowercase mixed");
	s = xstrdup("HeLlO WoRlD 123");
	lowercase(s);
	ASSERT_STRING_EQ(s, "hello world 123");
	ਮੁਕਤ(s);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("lowercase empty");
	s = xstrdup("");
	lowercase(s);
	ASSERT_STRING_EQ(s, "");
	ਮੁਕਤ(s);
	TEST_ਪੂਰਾ();
}

ਸਥਿਰ ਖਾਲੀ
test_ਰਸਤਾ_absolute(ਖਾਲੀ)
{
	TEST_ਸ਼ੁਰੂ("path_absolute absolute");
	ASSERT_INT_EQ(ਰਸਤਾ_absolute("/foo/bar"), 1);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("path_absolute relative");
	ASSERT_INT_EQ(ਰਸਤਾ_absolute("foo/bar"), 0);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("path_absolute empty");
	ASSERT_INT_EQ(ਰਸਤਾ_absolute(""), 0);
	TEST_ਪੂਰਾ();
}

ਸਥਿਰ ਖਾਲੀ
test_stringlist(ਖਾਲੀ)
{
	ਅੱਖਰ **list = ਨਿਰਾ;

	TEST_ਸ਼ੁਰੂ("stringlist_append initial");
	stringlist_append(&list, "one");
	ASSERT_PTR_NE(list, ਨਿਰਾ);
	ASSERT_STRING_EQ(list[0], "one");
	ASSERT_PTR_EQ(list[1], ਨਿਰਾ);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("stringlist_append second");
	stringlist_append(&list, "two");
	ASSERT_PTR_NE(list, ਨਿਰਾ);
	ASSERT_STRING_EQ(list[0], "one");
	ASSERT_STRING_EQ(list[1], "two");
	ASSERT_PTR_EQ(list[2], ਨਿਰਾ);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("stringlist_append third");
	stringlist_append(&list, "three");
	ASSERT_PTR_NE(list, ਨਿਰਾ);
	ASSERT_STRING_EQ(list[0], "one");
	ASSERT_STRING_EQ(list[1], "two");
	ASSERT_STRING_EQ(list[2], "three");
	ASSERT_PTR_EQ(list[3], ਨਿਰਾ);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("stringlist_free");
	stringlist_free(list);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("stringlist_free NULL");
	stringlist_free(ਨਿਰਾ);
	TEST_ਪੂਰਾ();
}

ਸਥਿਰ ਖਾਲੀ
test_skip_space(ਖਾਲੀ)
{
	ਅੱਖਰ *s, *p;

	TEST_ਸ਼ੁਰੂ("skip_space leading spaces");
	s = p = xstrdup("  hello");
	skip_space(&p);
	ASSERT_STRING_EQ(p, "hello");
	ਮੁਕਤ(s);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("skip_space leading tabs");
	s = p = xstrdup("\t\thello");
	skip_space(&p);
	ASSERT_STRING_EQ(p, "hello");
	ਮੁਕਤ(s);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("skip_space leading mixed whitespace");
	s = p = xstrdup(" \t hello");
	skip_space(&p);
	ASSERT_STRING_EQ(p, "hello");
	ਮੁਕਤ(s);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("skip_space no leading whitespace");
	s = p = xstrdup("hello");
	skip_space(&p);
	ASSERT_STRING_EQ(p, "hello");
	ਮੁਕਤ(s);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("skip_space empty string");
	s = p = xstrdup("");
	skip_space(&p);
	ASSERT_STRING_EQ(p, "");
	ਮੁਕਤ(s);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("skip_space only whitespace");
	s = p = xstrdup(" \t ");
	skip_space(&p);
	ASSERT_STRING_EQ(p, "");
	ਮੁਕਤ(s);
	TEST_ਪੂਰਾ();
}

ਖਾਲੀ
test_misc(ਖਾਲੀ)
{
	test_chop();
	test_rtrim();
	test_strprefix();
	test_fmt_timeframe();
	test_arglist();
	test_tohex();
	test_lowercase();
	test_ਰਸਤਾ_absolute();
	test_stringlist();
	test_skip_space();
}
