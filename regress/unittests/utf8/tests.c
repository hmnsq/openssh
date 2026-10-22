/*	$OpenBSD: tests.c,v 1.5 2025/04/15 04:00:42 djm Exp $ */
/*
 * Regress test for the utf8.h *mprintf() API
 *
 * Written by Ingo Schwarze <schwarze@openbsd.org> in 2016
 * and placed in the public domain.
 */

#ضمن "includes.h"

#ضمن <locale.h>
#ضمن <stdarg.h>
#ضمن <string.h>
#ضمن <stdio.h>

#ضمن "../test_helper/test_helper.h"

#ضمن "utf8.h"

ساكن فراغ
badarg(فراغ)
{
	حرف	 buf[16];
	صحيح	 len, عرض;

	عرض = 1;
	TEST_شروع("utf8_badarg");
	len = snmprintf(buf, حجم(buf), &عرض, "\377");
	ASSERT_INT_EQ(len, -1);
	ASSERT_STRING_EQ(buf, "");
	ASSERT_INT_EQ(عرض, 0);
	TEST_انجامشده();
}

ساكن فراغ
one(صحيح utf8, ثابت حرف *name, ثابت حرف *mbs, صحيح عرض,
    صحيح wantwidth, صحيح wantlen, ثابت حرف *میخواهد)
{
	حرف	 buf[16];
	صحيح	*wp;
	صحيح	 len;

	إذا (wantlen == -2)
		wantlen = طول_رشته(میخواهد);
	(فراغ)strlcpy(buf, utf8 ? "utf8_" : "c_", حجم(buf));
	(فراغ)strlcat(buf, name, حجم(buf));
	TEST_شروع(buf);
	wp = wantwidth == -2 ? عدم : &عرض;
	len = snmprintf(buf, حجم(buf), wp, "%s", mbs);
	ASSERT_INT_EQ(len, wantlen);
	ASSERT_STRING_EQ(buf, میخواهد);
	ASSERT_INT_EQ(عرض, wantwidth);
	TEST_انجامشده();
}

فراغ
tests(فراغ)
{
	حرف	*loc;

	TEST_شروع("utf8_setlocale");
	loc = setlocale(LC_CTYPE, "en_US.UTF-8");
	ASSERT_PTR_NE(loc, عدم);
	TEST_انجامشده();

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

	TEST_شروع("C_setlocale");
	loc = setlocale(LC_CTYPE, "C");
	ASSERT_PTR_NE(loc, عدم);
	TEST_انجامشده();

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

فراغ
benchmarks(فراغ)
{
	چاپ_کن("no benchmarks\n");
}
