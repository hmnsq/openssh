/*	$OpenBSD: tests.c,v 1.5 2025/04/15 04:00:42 djm Exp $ */
/*
 * Regress test for the utf8.h *mprintf() API
 *
 * Written by Ingo Schwarze <schwarze@openbsd.org> in 2016
 * and placed in the public domain.
 */

#అన్తర్భావ "includes.h"

#అన్తర్భావ <locale.h>
#అన్తర్భావ <stdarg.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <stdio.h>

#అన్తర్భావ "../test_helper/test_helper.h"

#అన్తర్భావ "utf8.h"

స్థిర శూన్య
badarg(శూన్య)
{
	అక్షరం	 buf[16];
	పూర్ణాంకం	 len, వెడల్పు;

	వెడల్పు = 1;
	TEST_ప్రారంభం("utf8_badarg");
	len = snmprintf(buf, పరిమాణం(buf), &వెడల్పు, "\377");
	ASSERT_INT_EQ(len, -1);
	ASSERT_STRING_EQ(buf, "");
	ASSERT_INT_EQ(వెడల్పు, 0);
	TEST_పూర్తి();
}

స్థిర శూన్య
one(పూర్ణాంకం utf8, స్థిరరాశి అక్షరం *name, స్థిరరాశి అక్షరం *mbs, పూర్ణాంకం వెడల్పు,
    పూర్ణాంకం wantwidth, పూర్ణాంకం wantlen, స్థిరరాశి అక్షరం *కోరుతుంది)
{
	అక్షరం	 buf[16];
	పూర్ణాంకం	*wp;
	పూర్ణాంకం	 len;

	ఒకవేళ (wantlen == -2)
		wantlen = అక్షరశ్రేణి_పొడవు(కోరుతుంది);
	(శూన్య)strlcpy(buf, utf8 ? "utf8_" : "c_", పరిమాణం(buf));
	(శూన్య)strlcat(buf, name, పరిమాణం(buf));
	TEST_ప్రారంభం(buf);
	wp = wantwidth == -2 ? ఖాళీ : &వెడల్పు;
	len = snmprintf(buf, పరిమాణం(buf), wp, "%s", mbs);
	ASSERT_INT_EQ(len, wantlen);
	ASSERT_STRING_EQ(buf, కోరుతుంది);
	ASSERT_INT_EQ(వెడల్పు, wantwidth);
	TEST_పూర్తి();
}

శూన్య
tests(శూన్య)
{
	అక్షరం	*loc;

	TEST_ప్రారంభం("utf8_setlocale");
	loc = setlocale(LC_CTYPE, "en_US.UTF-8");
	ASSERT_PTR_NE(loc, ఖాళీ);
	TEST_పూర్తి();

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

	TEST_ప్రారంభం("C_setlocale");
	loc = setlocale(LC_CTYPE, "C");
	ASSERT_PTR_NE(loc, ఖాళీ);
	TEST_పూర్తి();

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

శూన్య
benchmarks(శూన్య)
{
	రాయి("no benchmarks\n");
}
