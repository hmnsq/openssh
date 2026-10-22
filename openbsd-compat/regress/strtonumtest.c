/*	$OpenBSD: strtonumtest.c,v 1.1 2004/08/03 20:38:36 otto Exp $	*/
/*
 * Copyright (c) 2004 Otto Moerbeek <otto@drijf.net>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* OPENBSD ORIGINAL: regress/lib/libc/strtonum/strtonumtest.c */

#అన్తర్భావ "includes.h"

#అన్తర్భావ <limits.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <stdlib.h>

/* LLONG_MAX is known as LONGLONG_MAX on AIX */
#ఒకవేళ defined(LONGLONG_MAX) && !defined(LLONG_MAX)
# define LLONG_MAX LONGLONG_MAX
# define LLONG_MIN LONGLONG_MIN
#అయితే_ముగింపు

/* LLONG_MAX is known as LONG_LONG_MAX on HP-UX */
#ఒకవేళ defined(LONG_LONG_MAX) && !defined(LLONG_MAX)
# define LLONG_MAX LONG_LONG_MAX
# define LLONG_MIN LONG_LONG_MIN
#అయితే_ముగింపు

దీర్ఘ దీర్ఘ strtonum(స్థిరరాశి అక్షరం *, దీర్ఘ దీర్ఘ, దీర్ఘ దీర్ఘ, స్థిరరాశి అక్షరం **);

పూర్ణాంకం fail;

శూన్య
test(స్థిరరాశి అక్షరం *p, దీర్ఘ దీర్ఘ lb, దీర్ఘ దీర్ఘ ub, పూర్ణాంకం ok)
{
	దీర్ఘ దీర్ఘ val;
	స్థిరరాశి అక్షరం *q;

	val = strtonum(p, lb, ub, &q);
	ఒకవేళ (ok && q != ఖాళీ) {
		fprintf(stderr, "%s [%lld-%lld] ", p, lb, ub);
		fprintf(stderr, "NUMBER NOT ACCEPTED %s\n", q);
		fail = 1;
	} లేకపోతే ఒకవేళ (!ok && q == ఖాళీ) {
		fprintf(stderr, "%s [%lld-%lld] %lld ", p, lb, ub, val);
		fprintf(stderr, "NUMBER ACCEPTED\n");
		fail = 1;
	}
}

పూర్ణాంకం ప్రధాన(శూన్య)
{
	test("1", 0, 10, 1);
	test("0", -2, 5, 1);
	test("0", 2, 5, 0);
	test("0", 2, LLONG_MAX, 0);
	test("-2", 0, LLONG_MAX, 0);
	test("0", -5, LLONG_MAX, 1);
	test("-3", -3, LLONG_MAX, 1);
	test("-9223372036854775808", LLONG_MIN, LLONG_MAX, 1);
	test("9223372036854775807", LLONG_MIN, LLONG_MAX, 1);
	test("-9223372036854775809", LLONG_MIN, LLONG_MAX, 0);
	test("9223372036854775808", LLONG_MIN, LLONG_MAX, 0);
	test("1000000000000000000000000", LLONG_MIN, LLONG_MAX, 0);
	test("-1000000000000000000000000", LLONG_MIN, LLONG_MAX, 0);
	test("-2", 10, -1, 0);
	test("-2", -10, -1, 1);
	test("-20", -10, -1, 0);
	test("20", -10, -1, 0);

	తిరిగి (fail);
}

