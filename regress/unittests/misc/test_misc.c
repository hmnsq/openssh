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
	ಅಕ್ಷರ *s;

	TEST_ಆರಂಭ("chop newline");
	s = xstrdup("hello\n");
	ASSERT_STRING_EQ(chop(s), "hello");
	ಬಿಡುಗಡೆ(s);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("chop carriage return");
	s = xstrdup("hello\r");
	ASSERT_STRING_EQ(chop(s), "hello");
	ಬಿಡುಗಡೆ(s);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("chop CRLF");
	s = xstrdup("hello\r\n");
	ASSERT_STRING_EQ(chop(s), "hello");
	ಬಿಡುಗಡೆ(s);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("chop newline in middle");
	s = xstrdup("he\nllo");
	ASSERT_STRING_EQ(chop(s), "he");
	ಬಿಡುಗಡೆ(s);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("chop no newline");
	s = xstrdup("hello");
	ASSERT_STRING_EQ(chop(s), "hello");
	ಬಿಡುಗಡೆ(s);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("chop empty string");
	s = xstrdup("");
	ASSERT_STRING_EQ(chop(s), "");
	ಬಿಡುಗಡೆ(s);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("chop only newline");
	s = xstrdup("\n");
	ASSERT_STRING_EQ(chop(s), "");
	ಬಿಡುಗಡೆ(s);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("chop only CR");
	s = xstrdup("\r");
	ASSERT_STRING_EQ(chop(s), "");
	ಬಿಡುಗಡೆ(s);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("chop only CRLF");
	s = xstrdup("\r\n");
	ASSERT_STRING_EQ(chop(s), "");
	ಬಿಡುಗಡೆ(s);
	TEST_ಮುಗಿದ();
}

ಸ್ಥಿರ ಶೂನ್ಯ
test_rtrim(ಶೂನ್ಯ)
{
	ಅಕ್ಷರ *s;

	TEST_ಆರಂಭ("rtrim trailing space");
	s = xstrdup("hello  ");
	rtrim(s);
	ASSERT_STRING_EQ(s, "hello");
	ಬಿಡುಗಡೆ(s);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("rtrim trailing tab");
	s = xstrdup("hello\t\t");
	rtrim(s);
	ASSERT_STRING_EQ(s, "hello");
	ಬಿಡುಗಡೆ(s);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("rtrim trailing mixed whitespace");
	s = xstrdup("hello \t ");
	rtrim(s);
	ASSERT_STRING_EQ(s, "hello");
	ಬಿಡುಗಡೆ(s);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("rtrim no trailing whitespace");
	s = xstrdup("hello");
	rtrim(s);
	ASSERT_STRING_EQ(s, "hello");
	ಬಿಡುಗಡೆ(s);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("rtrim whitespace in middle");
	s = xstrdup("he llo");
	rtrim(s);
	ASSERT_STRING_EQ(s, "he llo");
	ಬಿಡುಗಡೆ(s);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("rtrim empty string");
	s = xstrdup("");
	rtrim(s);
	ASSERT_STRING_EQ(s, "");
	ಬಿಡುಗಡೆ(s);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("rtrim only whitespace");
	s = xstrdup("   \t");
	rtrim(s);
	ASSERT_STRING_EQ(s, "");
	ಬಿಡುಗಡೆ(s);
	TEST_ಮುಗಿದ();
}

ಸ್ಥಿರ ಶೂನ್ಯ
test_strprefix(ಶೂನ್ಯ)
{
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *s;

	TEST_ಆರಂಭ("strprefix basic match");
	s = strprefix("hello world", "hello", 0);
	ASSERT_PTR_NE(s, ಖಾಲಿ);
	ASSERT_STRING_EQ(s, " world");
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("strprefix no match");
	s = strprefix("hello world", "world", 0);
	ASSERT_PTR_EQ(s, ಖಾಲಿ);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("strprefix full match");
	s = strprefix("hello", "hello", 0);
	ASSERT_PTR_NE(s, ಖಾಲಿ);
	ASSERT_STRING_EQ(s, "");
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("strprefix empty string");
	s = strprefix("", "hello", 0);
	ASSERT_PTR_EQ(s, ಖಾಲಿ);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("strprefix empty prefix");
	s = strprefix("hello", "", 0);
	ASSERT_PTR_NE(s, ಖಾಲಿ);
	ASSERT_STRING_EQ(s, "hello");
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("strprefix case sensitive no match");
	s = strprefix("Hello world", "hello", 0);
	ASSERT_PTR_EQ(s, ಖಾಲಿ);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("strprefix case insensitive match");
	s = strprefix("Hello world", "hello", 1);
	ASSERT_PTR_NE(s, ಖಾಲಿ);
	ASSERT_STRING_EQ(s, " world");
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("strprefix case insensitive full match");
	s = strprefix("HELLO", "hello", 1);
	ASSERT_PTR_NE(s, ಖಾಲಿ);
	ASSERT_STRING_EQ(s, "");
	TEST_ಮುಗಿದ();
}

ಸ್ಥಿರ ಶೂನ್ಯ
test_fmt_timeframe(ಶೂನ್ಯ)
{
	TEST_ಆರಂಭ("fmt_timeframe seconds");
	ASSERT_STRING_EQ(fmt_timeframe(0), "00:00:00");
	ASSERT_STRING_EQ(fmt_timeframe(59), "00:00:59");
	ASSERT_STRING_EQ(fmt_timeframe(60), "00:01:00");
	ASSERT_STRING_EQ(fmt_timeframe(3599), "00:59:59");
	ASSERT_STRING_EQ(fmt_timeframe(3600), "01:00:00");
	ASSERT_STRING_EQ(fmt_timeframe(86399), "23:59:59");
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("fmt_timeframe days");
	ASSERT_STRING_EQ(fmt_timeframe(86400), "1d00h00m");
	ASSERT_STRING_EQ(fmt_timeframe(90061), "1d01h01m");
	ASSERT_STRING_EQ(fmt_timeframe(604799), "6d23h59m");
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("fmt_timeframe weeks");
	ASSERT_STRING_EQ(fmt_timeframe(604800), "01w0d00h");
	ASSERT_STRING_EQ(fmt_timeframe(694861), "01w1d01h");
	TEST_ಮುಗಿದ();
}

ಸ್ಥಿರ ಶೂನ್ಯ
test_arglist(ಶೂನ್ಯ)
{
	arglist ವಾದಗಳು;
	u_int i;

	memset(&ವಾದಗಳು, 0, ಗಾತ್ರ(ವಾದಗಳು));

	TEST_ಆರಂಭ("addargs initial");
	addargs(&ವಾದಗಳು, "one");
	ASSERT_U_INT_EQ(ವಾದಗಳು.ಅಂಕೆ, 1);
	ASSERT_U_INT_EQ(ವಾದಗಳು.nalloc, 32);
	ASSERT_PTR_NE(ವಾದಗಳು.list, ಖಾಲಿ);
	ASSERT_STRING_EQ(ವಾದಗಳು.list[0], "one");
	ASSERT_PTR_EQ(ವಾದಗಳು.list[1], ಖಾಲಿ);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("addargs second");
	addargs(&ವಾದಗಳು, "two");
	ASSERT_U_INT_EQ(ವಾದಗಳು.ಅಂಕೆ, 2);
	ASSERT_U_INT_EQ(ವಾದಗಳು.nalloc, 32);
	ASSERT_PTR_NE(ವಾದಗಳು.list, ಖಾಲಿ);
	ASSERT_STRING_EQ(ವಾದಗಳು.list[0], "one");
	ASSERT_STRING_EQ(ವಾದಗಳು.list[1], "two");
	ASSERT_PTR_EQ(ವಾದಗಳು.list[2], ಖಾಲಿ);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("addargs with format");
	addargs(&ವಾದಗಳು, "three=%d", 3);
	ASSERT_U_INT_EQ(ವಾದಗಳು.ಅಂಕೆ, 3);
	ASSERT_U_INT_EQ(ವಾದಗಳು.nalloc, 32);
	ASSERT_PTR_NE(ವಾದಗಳು.list, ಖಾಲಿ);
	ASSERT_STRING_EQ(ವಾದಗಳು.list[0], "one");
	ASSERT_STRING_EQ(ವಾದಗಳು.list[1], "two");
	ASSERT_STRING_EQ(ವಾದಗಳು.list[2], "three=3");
	ASSERT_PTR_EQ(ವಾದಗಳು.list[3], ಖಾಲಿ);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("replacearg middle");
	replacearg(&ವಾದಗಳು, 1, "TWO!");
	ASSERT_U_INT_EQ(ವಾದಗಳು.ಅಂಕೆ, 3);
	ASSERT_STRING_EQ(ವಾದಗಳು.list[0], "one");
	ASSERT_STRING_EQ(ವಾದಗಳು.list[1], "TWO!");
	ASSERT_STRING_EQ(ವಾದಗಳು.list[2], "three=3");
	ASSERT_PTR_EQ(ವಾದಗಳು.list[3], ಖಾಲಿ);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("replacearg first");
	replacearg(&ವಾದಗಳು, 0, "ONE!");
	ASSERT_U_INT_EQ(ವಾದಗಳು.ಅಂಕೆ, 3);
	ASSERT_STRING_EQ(ವಾದಗಳು.list[0], "ONE!");
	ASSERT_STRING_EQ(ವಾದಗಳು.list[1], "TWO!");
	ASSERT_STRING_EQ(ವಾದಗಳು.list[2], "three=3");
	ASSERT_PTR_EQ(ವಾದಗಳು.list[3], ಖಾಲಿ);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("replacearg last");
	replacearg(&ವಾದಗಳು, 2, "THREE=3!");
	ASSERT_U_INT_EQ(ವಾದಗಳು.ಅಂಕೆ, 3);
	ASSERT_STRING_EQ(ವಾದಗಳು.list[0], "ONE!");
	ASSERT_STRING_EQ(ವಾದಗಳು.list[1], "TWO!");
	ASSERT_STRING_EQ(ವಾದಗಳು.list[2], "THREE=3!");
	ASSERT_PTR_EQ(ವಾದಗಳು.list[3], ಖಾಲಿ);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("replacearg with format");
	replacearg(&ವಾದಗಳು, 1, "two=%d", 2);
	ASSERT_U_INT_EQ(ವಾದಗಳು.ಅಂಕೆ, 3);
	ASSERT_STRING_EQ(ವಾದಗಳು.list[0], "ONE!");
	ASSERT_STRING_EQ(ವಾದಗಳು.list[1], "two=2");
	ASSERT_STRING_EQ(ವಾದಗಳು.list[2], "THREE=3!");
	ASSERT_PTR_EQ(ವಾದಗಳು.list[3], ಖಾಲಿ);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("addargs reallocation");
	ಗಾಗಿ (i = ವಾದಗಳು.ಅಂಕೆ; i < 33; i++)
		addargs(&ವಾದಗಳು, "pad-%d", i);
	ASSERT_U_INT_EQ(ವಾದಗಳು.ಅಂಕೆ, 33);
	ASSERT_U_INT_GE(ವಾದಗಳು.nalloc, 33);
	ASSERT_STRING_EQ(ವಾದಗಳು.list[32], "pad-32");
	ASSERT_PTR_EQ(ವಾದಗಳು.list[33], ಖಾಲಿ);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("freeargs");
	freeargs(&ವಾದಗಳು);
	ASSERT_U_INT_EQ(ವಾದಗಳು.ಅಂಕೆ, 0);
	ASSERT_U_INT_EQ(ವಾದಗಳು.nalloc, 0);
	ASSERT_PTR_EQ(ವಾದಗಳು.list, ಖಾಲಿ);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("freeargs on NULL");
	freeargs(ಖಾಲಿ);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("freeargs on empty");
	memset(&ವಾದಗಳು, 0, ಗಾತ್ರ(ವಾದಗಳು));
	freeargs(&ವಾದಗಳು);
	ASSERT_U_INT_EQ(ವಾದಗಳು.ಅಂಕೆ, 0);
	ASSERT_U_INT_EQ(ವಾದಗಳು.nalloc, 0);
	ASSERT_PTR_EQ(ವಾದಗಳು.list, ಖಾಲಿ);
	TEST_ಮುಗಿದ();
}

ಸ್ಥಿರ ಶೂನ್ಯ
test_tohex(ಶೂನ್ಯ)
{
	ಅಕ್ಷರ *hex;

	TEST_ಆರಂಭ("tohex simple");
	hex = tohex("foo", 3);
	ASSERT_STRING_EQ(hex, "666f6f");
	ಬಿಡುಗಡೆ(hex);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("tohex with null");
	hex = tohex("a\0b", 3);
	ASSERT_STRING_EQ(hex, "610062");
	ಬಿಡುಗಡೆ(hex);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("tohex empty");
	hex = tohex("", 0);
	ASSERT_STRING_EQ(hex, "");
	ಬಿಡುಗಡೆ(hex);
	TEST_ಮುಗಿದ();
}

ಸ್ಥಿರ ಶೂನ್ಯ
test_lowercase(ಶೂನ್ಯ)
{
	ಅಕ್ಷರ *s;

	TEST_ಆರಂಭ("lowercase mixed");
	s = xstrdup("HeLlO WoRlD 123");
	lowercase(s);
	ASSERT_STRING_EQ(s, "hello world 123");
	ಬಿಡುಗಡೆ(s);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("lowercase empty");
	s = xstrdup("");
	lowercase(s);
	ASSERT_STRING_EQ(s, "");
	ಬಿಡುಗಡೆ(s);
	TEST_ಮುಗಿದ();
}

ಸ್ಥಿರ ಶೂನ್ಯ
test_ಮಾರ್ಗ_absolute(ಶೂನ್ಯ)
{
	TEST_ಆರಂಭ("path_absolute absolute");
	ASSERT_INT_EQ(ಮಾರ್ಗ_absolute("/foo/bar"), 1);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("path_absolute relative");
	ASSERT_INT_EQ(ಮಾರ್ಗ_absolute("foo/bar"), 0);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("path_absolute empty");
	ASSERT_INT_EQ(ಮಾರ್ಗ_absolute(""), 0);
	TEST_ಮುಗಿದ();
}

ಸ್ಥಿರ ಶೂನ್ಯ
test_stringlist(ಶೂನ್ಯ)
{
	ಅಕ್ಷರ **list = ಖಾಲಿ;

	TEST_ಆರಂಭ("stringlist_append initial");
	stringlist_append(&list, "one");
	ASSERT_PTR_NE(list, ಖಾಲಿ);
	ASSERT_STRING_EQ(list[0], "one");
	ASSERT_PTR_EQ(list[1], ಖಾಲಿ);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("stringlist_append second");
	stringlist_append(&list, "two");
	ASSERT_PTR_NE(list, ಖಾಲಿ);
	ASSERT_STRING_EQ(list[0], "one");
	ASSERT_STRING_EQ(list[1], "two");
	ASSERT_PTR_EQ(list[2], ಖಾಲಿ);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("stringlist_append third");
	stringlist_append(&list, "three");
	ASSERT_PTR_NE(list, ಖಾಲಿ);
	ASSERT_STRING_EQ(list[0], "one");
	ASSERT_STRING_EQ(list[1], "two");
	ASSERT_STRING_EQ(list[2], "three");
	ASSERT_PTR_EQ(list[3], ಖಾಲಿ);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("stringlist_free");
	stringlist_free(list);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("stringlist_free NULL");
	stringlist_free(ಖಾಲಿ);
	TEST_ಮುಗಿದ();
}

ಸ್ಥಿರ ಶೂನ್ಯ
test_skip_space(ಶೂನ್ಯ)
{
	ಅಕ್ಷರ *s, *p;

	TEST_ಆರಂಭ("skip_space leading spaces");
	s = p = xstrdup("  hello");
	skip_space(&p);
	ASSERT_STRING_EQ(p, "hello");
	ಬಿಡುಗಡೆ(s);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("skip_space leading tabs");
	s = p = xstrdup("\t\thello");
	skip_space(&p);
	ASSERT_STRING_EQ(p, "hello");
	ಬಿಡುಗಡೆ(s);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("skip_space leading mixed whitespace");
	s = p = xstrdup(" \t hello");
	skip_space(&p);
	ASSERT_STRING_EQ(p, "hello");
	ಬಿಡುಗಡೆ(s);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("skip_space no leading whitespace");
	s = p = xstrdup("hello");
	skip_space(&p);
	ASSERT_STRING_EQ(p, "hello");
	ಬಿಡುಗಡೆ(s);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("skip_space empty string");
	s = p = xstrdup("");
	skip_space(&p);
	ASSERT_STRING_EQ(p, "");
	ಬಿಡುಗಡೆ(s);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("skip_space only whitespace");
	s = p = xstrdup(" \t ");
	skip_space(&p);
	ASSERT_STRING_EQ(p, "");
	ಬಿಡುಗಡೆ(s);
	TEST_ಮುಗಿದ();
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
	test_ಮಾರ್ಗ_absolute();
	test_stringlist();
	test_skip_space();
}
