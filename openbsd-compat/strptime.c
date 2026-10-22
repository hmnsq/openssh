/*	$OpenBSD: strptime.c,v 1.12 2008/06/26 05:42:05 ray Exp $ */
/*	$NetBSD: strptime.c,v 1.12 1998/01/20 21:39:40 mycroft Exp $	*/

/*-
 * Copyright (c) 1997, 1998 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code was contributed to The NetBSD Foundation by Klaus Klein.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/* OPENBSD ORIGINAL: lib/libc/time/strptime.c */

#অন্তর্ভাব "includes.h"

#ifndef HAVE_STRPTIME

#define TM_YEAR_BASE 1900	/* from tzfile.h */

#অন্তর্ভাব <ctype.h>
#অন্তর্ভাব <locale.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <time.h>

/* #define	_ctloc(x)		(_CurrentTimeLocale->x) */

/*
 * We do not implement alternate representations. However, we always
 * check whether a given modifier is allowed for a certain conversion.
 */
#define _ALT_E			0x01
#define _ALT_O			0x02
#define	_LEGAL_ALT(x)		{ যদি (alt_format & ~(x)) প্রত্যাগম (0); }


স্থির	পূর্ণাঙ্ক conv_অঙ্ক(ধ্রুব unsigned বর্ণ **, পূর্ণাঙ্ক *, পূর্ণাঙ্ক, পূর্ণাঙ্ক);
স্থির	বর্ণ *_strptime(ধ্রুব বর্ণ *, ধ্রুব বর্ণ *, সংরচনা tm *, পূর্ণাঙ্ক);


বর্ণ *
strptime(ধ্রুব বর্ণ *buf, ধ্রুব বর্ণ *fmt, সংরচনা tm *tm)
{
	প্রত্যাগম(_strptime(buf, fmt, tm, 1));
}

স্থির বর্ণ *
_strptime(ধ্রুব বর্ণ *buf, ধ্রুব বর্ণ *fmt, সংরচনা tm *tm, পূর্ণাঙ্ক initialize)
{
	unsigned বর্ণ c;
	ধ্রুব unsigned বর্ণ *bp;
	size_t len;
	পূর্ণাঙ্ক alt_format, i;
	স্থির পূর্ণাঙ্ক century, relyear;

	যদি (initialize) {
		century = TM_YEAR_BASE;
		relyear = -1;
	}

	bp = (unsigned বর্ণ *)buf;
	যাবত্ ((c = *fmt) != '\0') {
		/* Clear `alternate' modifier prior to new conversion. */
		alt_format = 0;

		/* Eat up white-space. */
		যদি (isspace(c)) {
			যাবত্ (isspace(*bp))
				bp++;

			fmt++;
			অনুবর্ত;
		}
				
		যদি ((c = *fmt++) != '%')
			গচ্ছ literal;


again:		বিকল্প (c = *fmt++) {
		পক্ষ '%':	/* "%%" is converted to "%". */
literal:
		যদি (c != *bp++)
			প্রত্যাগম (রিক্ত);

		ভঙ্গ;

		/*
		 * "Alternative" modifiers. Just set the appropriate flag
		 * and start over again.
		 */
		পক্ষ 'E':	/* "%E?" alternative conversion modifier. */
			_LEGAL_ALT(0);
			alt_format |= _ALT_E;
			গচ্ছ again;

		পক্ষ 'O':	/* "%O?" alternative conversion modifier. */
			_LEGAL_ALT(0);
			alt_format |= _ALT_O;
			গচ্ছ again;
			
		/*
		 * "Complex" conversion rules, implemented through recursion.
		 */
#যদি 0
		পক্ষ 'c':	/* Date and time, using the locale's format. */
			_LEGAL_ALT(_ALT_E);
			যদি (!(bp = _strptime(bp, _ctloc(d_t_fmt), tm, 0)))
				প্রত্যাগম (রিক্ত);
			ভঙ্গ;
#endif
		পক্ষ 'D':	/* The date as "%m/%d/%y". */
			_LEGAL_ALT(0);
			যদি (!(bp = _strptime(bp, "%m/%d/%y", tm, 0)))
				প্রত্যাগম (রিক্ত);
			ভঙ্গ;
	
		পক্ষ 'R':	/* The time as "%H:%M". */
			_LEGAL_ALT(0);
			যদি (!(bp = _strptime(bp, "%H:%M", tm, 0)))
				প্রত্যাগম (রিক্ত);
			ভঙ্গ;

		পক্ষ 'r':	/* The time as "%I:%M:%S %p". */
			_LEGAL_ALT(0);
			যদি (!(bp = _strptime(bp, "%I:%M:%S %p", tm, 0)))
				প্রত্যাগম (রিক্ত);
			ভঙ্গ;

		পক্ষ 'T':	/* The time as "%H:%M:%S". */
			_LEGAL_ALT(0);
			যদি (!(bp = _strptime(bp, "%H:%M:%S", tm, 0)))
				প্রত্যাগম (রিক্ত);
			ভঙ্গ;
#যদি 0
		পক্ষ 'X':	/* The time, using the locale's format. */
			_LEGAL_ALT(_ALT_E);
			যদি (!(bp = _strptime(bp, _ctloc(t_fmt), tm, 0)))
				প্রত্যাগম (রিক্ত);
			ভঙ্গ;

		পক্ষ 'x':	/* The date, using the locale's format. */
			_LEGAL_ALT(_ALT_E);
			যদি (!(bp = _strptime(bp, _ctloc(d_fmt), tm, 0)))
				প্রত্যাগম (রিক্ত);
			ভঙ্গ;
#endif
		/*
		 * "Elementary" conversion rules.
		 */
#যদি 0
		পক্ষ 'A':	/* The day of week, using the locale's form. */
		পক্ষ 'a':
			_LEGAL_ALT(0);
			প্রতি (i = 0; i < 7; i++) {
				/* Full name. */
				len = strlen(_ctloc(day[i]));
				যদি (strncasecmp(_ctloc(day[i]), bp, len) == 0)
					ভঙ্গ;

				/* Abbreviated name. */
				len = strlen(_ctloc(abday[i]));
				যদি (strncasecmp(_ctloc(abday[i]), bp, len) == 0)
					ভঙ্গ;
			}

			/* Nothing matched. */
			যদি (i == 7)
				প্রত্যাগম (রিক্ত);

			tm->tm_wday = i;
			bp += len;
			ভঙ্গ;

		পক্ষ 'B':	/* The month, using the locale's form. */
		পক্ষ 'b':
		পক্ষ 'h':
			_LEGAL_ALT(0);
			প্রতি (i = 0; i < 12; i++) {
				/* Full name. */
				len = strlen(_ctloc(mon[i]));
				যদি (strncasecmp(_ctloc(mon[i]), bp, len) == 0)
					ভঙ্গ;

				/* Abbreviated name. */
				len = strlen(_ctloc(abmon[i]));
				যদি (strncasecmp(_ctloc(abmon[i]), bp, len) == 0)
					ভঙ্গ;
			}

			/* Nothing matched. */
			যদি (i == 12)
				প্রত্যাগম (রিক্ত);

			tm->tm_mon = i;
			bp += len;
			ভঙ্গ;
#endif

		পক্ষ 'C':	/* The century number. */
			_LEGAL_ALT(_ALT_E);
			যদি (!(conv_অঙ্ক(&bp, &i, 0, 99)))
				প্রত্যাগম (রিক্ত);

			century = i * 100;
			ভঙ্গ;

		পক্ষ 'd':	/* The day of month. */
		পক্ষ 'e':
			_LEGAL_ALT(_ALT_O);
			যদি (!(conv_অঙ্ক(&bp, &tm->tm_mday, 1, 31)))
				প্রত্যাগম (রিক্ত);
			ভঙ্গ;

		পক্ষ 'k':	/* The hour (24-hour clock representation). */
			_LEGAL_ALT(0);
			/* FALLTHROUGH */
		পক্ষ 'H':
			_LEGAL_ALT(_ALT_O);
			যদি (!(conv_অঙ্ক(&bp, &tm->tm_hour, 0, 23)))
				প্রত্যাগম (রিক্ত);
			ভঙ্গ;

		পক্ষ 'l':	/* The hour (12-hour clock representation). */
			_LEGAL_ALT(0);
			/* FALLTHROUGH */
		পক্ষ 'I':
			_LEGAL_ALT(_ALT_O);
			যদি (!(conv_অঙ্ক(&bp, &tm->tm_hour, 1, 12)))
				প্রত্যাগম (রিক্ত);
			ভঙ্গ;

		পক্ষ 'j':	/* The day of year. */
			_LEGAL_ALT(0);
			যদি (!(conv_অঙ্ক(&bp, &tm->tm_yday, 1, 366)))
				প্রত্যাগম (রিক্ত);
			tm->tm_yday--;
			ভঙ্গ;

		পক্ষ 'M':	/* The minute. */
			_LEGAL_ALT(_ALT_O);
			যদি (!(conv_অঙ্ক(&bp, &tm->tm_min, 0, 59)))
				প্রত্যাগম (রিক্ত);
			ভঙ্গ;

		পক্ষ 'm':	/* The month. */
			_LEGAL_ALT(_ALT_O);
			যদি (!(conv_অঙ্ক(&bp, &tm->tm_mon, 1, 12)))
				প্রত্যাগম (রিক্ত);
			tm->tm_mon--;
			ভঙ্গ;

#যদি 0
		পক্ষ 'p':	/* The locale's equivalent of AM/PM. */
			_LEGAL_ALT(0);
			/* AM? */
			len = strlen(_ctloc(am_pm[0]));
			যদি (strncasecmp(_ctloc(am_pm[0]), bp, len) == 0) {
				যদি (tm->tm_hour > 12)	/* i.e., 13:00 AM ?! */
					প্রত্যাগম (রিক্ত);
				অন্যথা যদি (tm->tm_hour == 12)
					tm->tm_hour = 0;

				bp += len;
				ভঙ্গ;
			}
			/* PM? */
			len = strlen(_ctloc(am_pm[1]));
			যদি (strncasecmp(_ctloc(am_pm[1]), bp, len) == 0) {
				যদি (tm->tm_hour > 12)	/* i.e., 13:00 PM ?! */
					প্রত্যাগম (রিক্ত);
				অন্যথা যদি (tm->tm_hour < 12)
					tm->tm_hour += 12;

				bp += len;
				ভঙ্গ;
			}

			/* Nothing matched. */
			প্রত্যাগম (রিক্ত);
#endif
		পক্ষ 'S':	/* The seconds. */
			_LEGAL_ALT(_ALT_O);
			যদি (!(conv_অঙ্ক(&bp, &tm->tm_sec, 0, 61)))
				প্রত্যাগম (রিক্ত);
			ভঙ্গ;

		পক্ষ 'U':	/* The week of year, beginning on sunday. */
		পক্ষ 'W':	/* The week of year, beginning on monday. */
			_LEGAL_ALT(_ALT_O);
			/*
			 * XXX This is bogus, as we can not assume any valid
			 * information present in the tm structure at this
			 * point to calculate a real value, so just check the
			 * range for now.
			 */
			 যদি (!(conv_অঙ্ক(&bp, &i, 0, 53)))
				প্রত্যাগম (রিক্ত);
			 ভঙ্গ;

		পক্ষ 'w':	/* The day of week, beginning on sunday. */
			_LEGAL_ALT(_ALT_O);
			যদি (!(conv_অঙ্ক(&bp, &tm->tm_wday, 0, 6)))
				প্রত্যাগম (রিক্ত);
			ভঙ্গ;

		পক্ষ 'Y':	/* The year. */
			_LEGAL_ALT(_ALT_E);
			যদি (!(conv_অঙ্ক(&bp, &i, 0, 9999)))
				প্রত্যাগম (রিক্ত);

			relyear = -1;
			tm->tm_year = i - TM_YEAR_BASE;
			ভঙ্গ;

		পক্ষ 'y':	/* The year within the century (2 digits). */
			_LEGAL_ALT(_ALT_E | _ALT_O);
			যদি (!(conv_অঙ্ক(&bp, &relyear, 0, 99)))
				প্রত্যাগম (রিক্ত);
			ভঙ্গ;

		/*
		 * Miscellaneous conversions.
		 */
		পক্ষ 'n':	/* Any kind of white-space. */
		পক্ষ 't':
			_LEGAL_ALT(0);
			যাবত্ (isspace(*bp))
				bp++;
			ভঙ্গ;


		স্বভাব:	/* Unknown/unsupported conversion. */
			প্রত্যাগম (রিক্ত);
		}


	}

	/*
	 * We need to evaluate the two digit year spec (%y)
	 * last as we can get a century spec (%C) at any time.
	 */
	যদি (relyear != -1) {
		যদি (century == TM_YEAR_BASE) {
			যদি (relyear <= 68)
				tm->tm_year = relyear + 2000 - TM_YEAR_BASE;
			অন্যথা
				tm->tm_year = relyear + 1900 - TM_YEAR_BASE;
		} অন্যথা {
			tm->tm_year = relyear + century - TM_YEAR_BASE;
		}
	}

	প্রত্যাগম ((বর্ণ *)bp);
}


স্থির পূর্ণাঙ্ক
conv_অঙ্ক(ধ্রুব unsigned বর্ণ **buf, পূর্ণাঙ্ক *dest, পূর্ণাঙ্ক llim, পূর্ণাঙ্ক ulim)
{
	পূর্ণাঙ্ক result = 0;
	পূর্ণাঙ্ক rulim = ulim;

	যদি (**buf < '0' || **buf > '9')
		প্রত্যাগম (0);

	/* we use rulim to break out of the loop when we run out of digits */
	কুরু {
		result *= 10;
		result += *(*buf)++ - '0';
		rulim /= 10;
	} যাবত্ ((result * 10 <= ulim) && rulim && **buf >= '0' && **buf <= '9');

	যদি (result < llim || result > ulim)
		প্রত্যাগম (0);

	*dest = result;
	প্রত্যাগম (1);
}

#endif /* HAVE_STRPTIME */

