/*	$OpenBSD: tests.c,v 1.5 2025/04/15 04:00:42 djm Exp $ */
/*
 * Regress test for the utf8.h *mprintf() API
 *
 * Written by Ingo Schwarze <schwarze@openbsd.org> in 2016
 * and placed in the public domain.
 */

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <locale.h>
#ଅନ୍ତର୍ଭାଵ <stdarg.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>

#ଅନ୍ତର୍ଭାଵ "../test_helper/test_helper.h"

#ଅନ୍ତର୍ଭାଵ "utf8.h"

ସ୍ଥିର ଶୂନ୍ୟ
badarg(ଶୂନ୍ୟ)
{
	ଅକ୍ଷର	 buf[16];
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 len, width;

	width = 1;
	TEST_START("utf8_badarg");
	len = snmprintf(buf, ଆକାର(buf), &width, "\377");
	ASSERT_INT_EQ(len, -1);
	ASSERT_STRING_EQ(buf, "");
	ASSERT_INT_EQ(width, 0);
	TEST_DONE();
}

ସ୍ଥିର ଶୂନ୍ୟ
one(ପୂର୍ଣ୍ଣସଂଖ୍ୟା utf8, ଅଚଳ ଅକ୍ଷର *name, ଅଚଳ ଅକ୍ଷର *mbs, ପୂର୍ଣ୍ଣସଂଖ୍ୟା width,
    ପୂର୍ଣ୍ଣସଂଖ୍ୟା wantwidth, ପୂର୍ଣ୍ଣସଂଖ୍ୟା wantlen, ଅଚଳ ଅକ୍ଷର *wants)
{
	ଅକ୍ଷର	 buf[16];
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା	*wp;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 len;

	ଯଦି (wantlen == -2)
		wantlen = strlen(wants);
	(ଶୂନ୍ୟ)strlcpy(buf, utf8 ? "utf8_" : "c_", ଆକାର(buf));
	(ଶୂନ୍ୟ)strlcat(buf, name, ଆକାର(buf));
	TEST_START(buf);
	wp = wantwidth == -2 ? ଖାଲି : &width;
	len = snmprintf(buf, ଆକାର(buf), wp, "%s", mbs);
	ASSERT_INT_EQ(len, wantlen);
	ASSERT_STRING_EQ(buf, wants);
	ASSERT_INT_EQ(width, wantwidth);
	TEST_DONE();
}

ଶୂନ୍ୟ
tests(ଶୂନ୍ୟ)
{
	ଅକ୍ଷର	*loc;

	TEST_START("utf8_setlocale");
	loc = setlocale(LC_CTYPE, "en_US.UTF-8");
	ASSERT_PTR_NE(loc, ଖାଲି);
	TEST_DONE();

	badarg();
	one(1, "empty", "", 2, 0, 0, "");
	one(1, "ascii", "x", -2, -2, -2, "x");
	one(1, "newline", "a\nb", -2, -2, -2, "a\nb");
	one(1, "cr", "a\rb", -2, -2, -2, "a\rb");
	one(1, "tab", "a\tb", -2, -2, -2, "a\tb");
	one(1, "esc", "\033x", -2, -2, -2, "\\033x");
	one(1, "inv_badbyte", "\377x", -2, -2, -2, "\\377x");
	one(1, "inv_nocont", "\341x", -2, -2, -2, "\\341x");
	one(1, "inv_nolead", "a\200b", -2, -2, -2, "a\\200b");
	one(1, "sz_ascii", "1234567890123456", -2, -2, 16, "123456789012345");
	one(1, "sz_esc", "123456789012\033", -2, -2, 16, "123456789012");
	one(1, "width_ascii", "123", 2, 2, -1, "12");
	one(1, "width_double", "a\343\201\201", 2, 1, -1, "a");
	one(1, "double_fit", "a\343\201\201", 3, 3, 4, "a\343\201\201");
	one(1, "double_spc", "a\343\201\201", 4, 3, 4, "a\343\201\201");

	TEST_START("C_setlocale");
	loc = setlocale(LC_CTYPE, "C");
	ASSERT_PTR_NE(loc, ଖାଲି);
	TEST_DONE();

	badarg();
	one(0, "empty", "", 2, 0, 0, "");
	one(0, "ascii", "x", -2, -2, -2, "x");
	one(0, "newline", "a\nb", -2, -2, -2, "a\nb");
	one(0, "cr", "a\rb", -2, -2, -2, "a\rb");
	one(0, "tab", "a\tb", -2, -2, -2, "a\tb");
	one(0, "esc", "\033x", -2, -2, -2, "\\033x");
	one(0, "inv_badbyte", "\377x", -2, -2, -2, "\\377x");
	one(0, "inv_nocont", "\341x", -2, -2, -2, "\\341x");
	one(0, "inv_nolead", "a\200b", -2, -2, -2, "a\\200b");
	one(0, "sz_ascii", "1234567890123456", -2, -2, 16, "123456789012345");
	one(0, "sz_esc", "123456789012\033", -2, -2, 16, "123456789012");
	one(0, "width_ascii", "123", 2, 2, -1, "12");
	one(0, "width_double", "a\343\201\201", 2, 1, -1, "a");
	one(0, "double_fit", "a\343\201\201", 7, 5, -1, "a\\343");
	one(0, "double_spc", "a\343\201\201", 13, 13, 13, "a\\343\\201\\201");
}

ଶୂନ୍ୟ
benchmarks(ଶୂନ୍ୟ)
{
	printf("no benchmarks\n");
}
