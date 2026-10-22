/*
 * Regress test for misc helper functions.
 *
 * Placed in the public domain.
 */

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <stdint.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <string.h>

#అన్తర్భావ "../test_helper/test_helper.h"

#అన్తర్భావ "log.h"
#అన్తర్భావ "misc.h"
#అన్తర్భావ "xmalloc.h"

శూన్య test_misc(శూన్య);

స్థిర శూన్య
test_chop(శూన్య)
{
	అక్షరం *s;

	TEST_ప్రారంభం("chop newline");
	s = xstrdup("hello\n");
	ASSERT_STRING_EQ(chop(s), "hello");
	విడుదల(s);
	TEST_పూర్తి();

	TEST_ప్రారంభం("chop carriage return");
	s = xstrdup("hello\r");
	ASSERT_STRING_EQ(chop(s), "hello");
	విడుదల(s);
	TEST_పూర్తి();

	TEST_ప్రారంభం("chop CRLF");
	s = xstrdup("hello\r\n");
	ASSERT_STRING_EQ(chop(s), "hello");
	విడుదల(s);
	TEST_పూర్తి();

	TEST_ప్రారంభం("chop newline in middle");
	s = xstrdup("he\nllo");
	ASSERT_STRING_EQ(chop(s), "he");
	విడుదల(s);
	TEST_పూర్తి();

	TEST_ప్రారంభం("chop no newline");
	s = xstrdup("hello");
	ASSERT_STRING_EQ(chop(s), "hello");
	విడుదల(s);
	TEST_పూర్తి();

	TEST_ప్రారంభం("chop empty string");
	s = xstrdup("");
	ASSERT_STRING_EQ(chop(s), "");
	విడుదల(s);
	TEST_పూర్తి();

	TEST_ప్రారంభం("chop only newline");
	s = xstrdup("\n");
	ASSERT_STRING_EQ(chop(s), "");
	విడుదల(s);
	TEST_పూర్తి();

	TEST_ప్రారంభం("chop only CR");
	s = xstrdup("\r");
	ASSERT_STRING_EQ(chop(s), "");
	విడుదల(s);
	TEST_పూర్తి();

	TEST_ప్రారంభం("chop only CRLF");
	s = xstrdup("\r\n");
	ASSERT_STRING_EQ(chop(s), "");
	విడుదల(s);
	TEST_పూర్తి();
}

స్థిర శూన్య
test_rtrim(శూన్య)
{
	అక్షరం *s;

	TEST_ప్రారంభం("rtrim trailing space");
	s = xstrdup("hello  ");
	rtrim(s);
	ASSERT_STRING_EQ(s, "hello");
	విడుదల(s);
	TEST_పూర్తి();

	TEST_ప్రారంభం("rtrim trailing tab");
	s = xstrdup("hello\t\t");
	rtrim(s);
	ASSERT_STRING_EQ(s, "hello");
	విడుదల(s);
	TEST_పూర్తి();

	TEST_ప్రారంభం("rtrim trailing mixed whitespace");
	s = xstrdup("hello \t ");
	rtrim(s);
	ASSERT_STRING_EQ(s, "hello");
	విడుదల(s);
	TEST_పూర్తి();

	TEST_ప్రారంభం("rtrim no trailing whitespace");
	s = xstrdup("hello");
	rtrim(s);
	ASSERT_STRING_EQ(s, "hello");
	విడుదల(s);
	TEST_పూర్తి();

	TEST_ప్రారంభం("rtrim whitespace in middle");
	s = xstrdup("he llo");
	rtrim(s);
	ASSERT_STRING_EQ(s, "he llo");
	విడుదల(s);
	TEST_పూర్తి();

	TEST_ప్రారంభం("rtrim empty string");
	s = xstrdup("");
	rtrim(s);
	ASSERT_STRING_EQ(s, "");
	విడుదల(s);
	TEST_పూర్తి();

	TEST_ప్రారంభం("rtrim only whitespace");
	s = xstrdup("   \t");
	rtrim(s);
	ASSERT_STRING_EQ(s, "");
	విడుదల(s);
	TEST_పూర్తి();
}

స్థిర శూన్య
test_strprefix(శూన్య)
{
	స్థిరరాశి అక్షరం *s;

	TEST_ప్రారంభం("strprefix basic match");
	s = strprefix("hello world", "hello", 0);
	ASSERT_PTR_NE(s, ఖాళీ);
	ASSERT_STRING_EQ(s, " world");
	TEST_పూర్తి();

	TEST_ప్రారంభం("strprefix no match");
	s = strprefix("hello world", "world", 0);
	ASSERT_PTR_EQ(s, ఖాళీ);
	TEST_పూర్తి();

	TEST_ప్రారంభం("strprefix full match");
	s = strprefix("hello", "hello", 0);
	ASSERT_PTR_NE(s, ఖాళీ);
	ASSERT_STRING_EQ(s, "");
	TEST_పూర్తి();

	TEST_ప్రారంభం("strprefix empty string");
	s = strprefix("", "hello", 0);
	ASSERT_PTR_EQ(s, ఖాళీ);
	TEST_పూర్తి();

	TEST_ప్రారంభం("strprefix empty prefix");
	s = strprefix("hello", "", 0);
	ASSERT_PTR_NE(s, ఖాళీ);
	ASSERT_STRING_EQ(s, "hello");
	TEST_పూర్తి();

	TEST_ప్రారంభం("strprefix case sensitive no match");
	s = strprefix("Hello world", "hello", 0);
	ASSERT_PTR_EQ(s, ఖాళీ);
	TEST_పూర్తి();

	TEST_ప్రారంభం("strprefix case insensitive match");
	s = strprefix("Hello world", "hello", 1);
	ASSERT_PTR_NE(s, ఖాళీ);
	ASSERT_STRING_EQ(s, " world");
	TEST_పూర్తి();

	TEST_ప్రారంభం("strprefix case insensitive full match");
	s = strprefix("HELLO", "hello", 1);
	ASSERT_PTR_NE(s, ఖాళీ);
	ASSERT_STRING_EQ(s, "");
	TEST_పూర్తి();
}

స్థిర శూన్య
test_fmt_timeframe(శూన్య)
{
	TEST_ప్రారంభం("fmt_timeframe seconds");
	ASSERT_STRING_EQ(fmt_timeframe(0), "00:00:00");
	ASSERT_STRING_EQ(fmt_timeframe(59), "00:00:59");
	ASSERT_STRING_EQ(fmt_timeframe(60), "00:01:00");
	ASSERT_STRING_EQ(fmt_timeframe(3599), "00:59:59");
	ASSERT_STRING_EQ(fmt_timeframe(3600), "01:00:00");
	ASSERT_STRING_EQ(fmt_timeframe(86399), "23:59:59");
	TEST_పూర్తి();

	TEST_ప్రారంభం("fmt_timeframe days");
	ASSERT_STRING_EQ(fmt_timeframe(86400), "1d00h00m");
	ASSERT_STRING_EQ(fmt_timeframe(90061), "1d01h01m");
	ASSERT_STRING_EQ(fmt_timeframe(604799), "6d23h59m");
	TEST_పూర్తి();

	TEST_ప్రారంభం("fmt_timeframe weeks");
	ASSERT_STRING_EQ(fmt_timeframe(604800), "01w0d00h");
	ASSERT_STRING_EQ(fmt_timeframe(694861), "01w1d01h");
	TEST_పూర్తి();
}

స్థిర శూన్య
test_arglist(శూన్య)
{
	arglist వాదనలు;
	u_int i;

	memset(&వాదనలు, 0, పరిమాణం(వాదనలు));

	TEST_ప్రారంభం("addargs initial");
	addargs(&వాదనలు, "one");
	ASSERT_U_INT_EQ(వాదనలు.అంకె, 1);
	ASSERT_U_INT_EQ(వాదనలు.nalloc, 32);
	ASSERT_PTR_NE(వాదనలు.list, ఖాళీ);
	ASSERT_STRING_EQ(వాదనలు.list[0], "one");
	ASSERT_PTR_EQ(వాదనలు.list[1], ఖాళీ);
	TEST_పూర్తి();

	TEST_ప్రారంభం("addargs second");
	addargs(&వాదనలు, "two");
	ASSERT_U_INT_EQ(వాదనలు.అంకె, 2);
	ASSERT_U_INT_EQ(వాదనలు.nalloc, 32);
	ASSERT_PTR_NE(వాదనలు.list, ఖాళీ);
	ASSERT_STRING_EQ(వాదనలు.list[0], "one");
	ASSERT_STRING_EQ(వాదనలు.list[1], "two");
	ASSERT_PTR_EQ(వాదనలు.list[2], ఖాళీ);
	TEST_పూర్తి();

	TEST_ప్రారంభం("addargs with format");
	addargs(&వాదనలు, "three=%d", 3);
	ASSERT_U_INT_EQ(వాదనలు.అంకె, 3);
	ASSERT_U_INT_EQ(వాదనలు.nalloc, 32);
	ASSERT_PTR_NE(వాదనలు.list, ఖాళీ);
	ASSERT_STRING_EQ(వాదనలు.list[0], "one");
	ASSERT_STRING_EQ(వాదనలు.list[1], "two");
	ASSERT_STRING_EQ(వాదనలు.list[2], "three=3");
	ASSERT_PTR_EQ(వాదనలు.list[3], ఖాళీ);
	TEST_పూర్తి();

	TEST_ప్రారంభం("replacearg middle");
	replacearg(&వాదనలు, 1, "TWO!");
	ASSERT_U_INT_EQ(వాదనలు.అంకె, 3);
	ASSERT_STRING_EQ(వాదనలు.list[0], "one");
	ASSERT_STRING_EQ(వాదనలు.list[1], "TWO!");
	ASSERT_STRING_EQ(వాదనలు.list[2], "three=3");
	ASSERT_PTR_EQ(వాదనలు.list[3], ఖాళీ);
	TEST_పూర్తి();

	TEST_ప్రారంభం("replacearg first");
	replacearg(&వాదనలు, 0, "ONE!");
	ASSERT_U_INT_EQ(వాదనలు.అంకె, 3);
	ASSERT_STRING_EQ(వాదనలు.list[0], "ONE!");
	ASSERT_STRING_EQ(వాదనలు.list[1], "TWO!");
	ASSERT_STRING_EQ(వాదనలు.list[2], "three=3");
	ASSERT_PTR_EQ(వాదనలు.list[3], ఖాళీ);
	TEST_పూర్తి();

	TEST_ప్రారంభం("replacearg last");
	replacearg(&వాదనలు, 2, "THREE=3!");
	ASSERT_U_INT_EQ(వాదనలు.అంకె, 3);
	ASSERT_STRING_EQ(వాదనలు.list[0], "ONE!");
	ASSERT_STRING_EQ(వాదనలు.list[1], "TWO!");
	ASSERT_STRING_EQ(వాదనలు.list[2], "THREE=3!");
	ASSERT_PTR_EQ(వాదనలు.list[3], ఖాళీ);
	TEST_పూర్తి();

	TEST_ప్రారంభం("replacearg with format");
	replacearg(&వాదనలు, 1, "two=%d", 2);
	ASSERT_U_INT_EQ(వాదనలు.అంకె, 3);
	ASSERT_STRING_EQ(వాదనలు.list[0], "ONE!");
	ASSERT_STRING_EQ(వాదనలు.list[1], "two=2");
	ASSERT_STRING_EQ(వాదనలు.list[2], "THREE=3!");
	ASSERT_PTR_EQ(వాదనలు.list[3], ఖాళీ);
	TEST_పూర్తి();

	TEST_ప్రారంభం("addargs reallocation");
	కొరకు (i = వాదనలు.అంకె; i < 33; i++)
		addargs(&వాదనలు, "pad-%d", i);
	ASSERT_U_INT_EQ(వాదనలు.అంకె, 33);
	ASSERT_U_INT_GE(వాదనలు.nalloc, 33);
	ASSERT_STRING_EQ(వాదనలు.list[32], "pad-32");
	ASSERT_PTR_EQ(వాదనలు.list[33], ఖాళీ);
	TEST_పూర్తి();

	TEST_ప్రారంభం("freeargs");
	freeargs(&వాదనలు);
	ASSERT_U_INT_EQ(వాదనలు.అంకె, 0);
	ASSERT_U_INT_EQ(వాదనలు.nalloc, 0);
	ASSERT_PTR_EQ(వాదనలు.list, ఖాళీ);
	TEST_పూర్తి();

	TEST_ప్రారంభం("freeargs on NULL");
	freeargs(ఖాళీ);
	TEST_పూర్తి();

	TEST_ప్రారంభం("freeargs on empty");
	memset(&వాదనలు, 0, పరిమాణం(వాదనలు));
	freeargs(&వాదనలు);
	ASSERT_U_INT_EQ(వాదనలు.అంకె, 0);
	ASSERT_U_INT_EQ(వాదనలు.nalloc, 0);
	ASSERT_PTR_EQ(వాదనలు.list, ఖాళీ);
	TEST_పూర్తి();
}

స్థిర శూన్య
test_tohex(శూన్య)
{
	అక్షరం *hex;

	TEST_ప్రారంభం("tohex simple");
	hex = tohex("foo", 3);
	ASSERT_STRING_EQ(hex, "666f6f");
	విడుదల(hex);
	TEST_పూర్తి();

	TEST_ప్రారంభం("tohex with null");
	hex = tohex("a\0b", 3);
	ASSERT_STRING_EQ(hex, "610062");
	విడుదల(hex);
	TEST_పూర్తి();

	TEST_ప్రారంభం("tohex empty");
	hex = tohex("", 0);
	ASSERT_STRING_EQ(hex, "");
	విడుదల(hex);
	TEST_పూర్తి();
}

స్థిర శూన్య
test_lowercase(శూన్య)
{
	అక్షరం *s;

	TEST_ప్రారంభం("lowercase mixed");
	s = xstrdup("HeLlO WoRlD 123");
	lowercase(s);
	ASSERT_STRING_EQ(s, "hello world 123");
	విడుదల(s);
	TEST_పూర్తి();

	TEST_ప్రారంభం("lowercase empty");
	s = xstrdup("");
	lowercase(s);
	ASSERT_STRING_EQ(s, "");
	విడుదల(s);
	TEST_పూర్తి();
}

స్థిర శూన్య
test_మార్గం_absolute(శూన్య)
{
	TEST_ప్రారంభం("path_absolute absolute");
	ASSERT_INT_EQ(మార్గం_absolute("/foo/bar"), 1);
	TEST_పూర్తి();

	TEST_ప్రారంభం("path_absolute relative");
	ASSERT_INT_EQ(మార్గం_absolute("foo/bar"), 0);
	TEST_పూర్తి();

	TEST_ప్రారంభం("path_absolute empty");
	ASSERT_INT_EQ(మార్గం_absolute(""), 0);
	TEST_పూర్తి();
}

స్థిర శూన్య
test_stringlist(శూన్య)
{
	అక్షరం **list = ఖాళీ;

	TEST_ప్రారంభం("stringlist_append initial");
	stringlist_append(&list, "one");
	ASSERT_PTR_NE(list, ఖాళీ);
	ASSERT_STRING_EQ(list[0], "one");
	ASSERT_PTR_EQ(list[1], ఖాళీ);
	TEST_పూర్తి();

	TEST_ప్రారంభం("stringlist_append second");
	stringlist_append(&list, "two");
	ASSERT_PTR_NE(list, ఖాళీ);
	ASSERT_STRING_EQ(list[0], "one");
	ASSERT_STRING_EQ(list[1], "two");
	ASSERT_PTR_EQ(list[2], ఖాళీ);
	TEST_పూర్తి();

	TEST_ప్రారంభం("stringlist_append third");
	stringlist_append(&list, "three");
	ASSERT_PTR_NE(list, ఖాళీ);
	ASSERT_STRING_EQ(list[0], "one");
	ASSERT_STRING_EQ(list[1], "two");
	ASSERT_STRING_EQ(list[2], "three");
	ASSERT_PTR_EQ(list[3], ఖాళీ);
	TEST_పూర్తి();

	TEST_ప్రారంభం("stringlist_free");
	stringlist_free(list);
	TEST_పూర్తి();

	TEST_ప్రారంభం("stringlist_free NULL");
	stringlist_free(ఖాళీ);
	TEST_పూర్తి();
}

స్థిర శూన్య
test_skip_space(శూన్య)
{
	అక్షరం *s, *p;

	TEST_ప్రారంభం("skip_space leading spaces");
	s = p = xstrdup("  hello");
	skip_space(&p);
	ASSERT_STRING_EQ(p, "hello");
	విడుదల(s);
	TEST_పూర్తి();

	TEST_ప్రారంభం("skip_space leading tabs");
	s = p = xstrdup("\t\thello");
	skip_space(&p);
	ASSERT_STRING_EQ(p, "hello");
	విడుదల(s);
	TEST_పూర్తి();

	TEST_ప్రారంభం("skip_space leading mixed whitespace");
	s = p = xstrdup(" \t hello");
	skip_space(&p);
	ASSERT_STRING_EQ(p, "hello");
	విడుదల(s);
	TEST_పూర్తి();

	TEST_ప్రారంభం("skip_space no leading whitespace");
	s = p = xstrdup("hello");
	skip_space(&p);
	ASSERT_STRING_EQ(p, "hello");
	విడుదల(s);
	TEST_పూర్తి();

	TEST_ప్రారంభం("skip_space empty string");
	s = p = xstrdup("");
	skip_space(&p);
	ASSERT_STRING_EQ(p, "");
	విడుదల(s);
	TEST_పూర్తి();

	TEST_ప్రారంభం("skip_space only whitespace");
	s = p = xstrdup(" \t ");
	skip_space(&p);
	ASSERT_STRING_EQ(p, "");
	విడుదల(s);
	TEST_పూర్తి();
}

శూన్య
test_misc(శూన్య)
{
	test_chop();
	test_rtrim();
	test_strprefix();
	test_fmt_timeframe();
	test_arglist();
	test_tohex();
	test_lowercase();
	test_మార్గం_absolute();
	test_stringlist();
	test_skip_space();
}
