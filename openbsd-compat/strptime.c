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
#define	_LEGAL_ALT(x)		{ যদি (alt_format & ~(x)) ফেরত (0); }


স্থির	পূর্ণসংখ্যা conv_অঙ্ক(ধ্রুবক unsigned অক্ষর **, পূর্ণসংখ্যা *, পূর্ণসংখ্যা, পূর্ণসংখ্যা);
স্থির	অক্ষর *_strptime(ধ্রুবক অক্ষর *, ধ্রুবক অক্ষর *, কাঠামো tm *, পূর্ণসংখ্যা);


অক্ষর *
strptime(ধ্রুবক অক্ষর *buf, ধ্রুবক অক্ষর *fmt, কাঠামো tm *tm)
{
	ফেরত(_strptime(buf, fmt, tm, 1));
}

স্থির অক্ষর *
_strptime(ধ্রুবক অক্ষর *buf, ধ্রুবক অক্ষর *fmt, কাঠামো tm *tm, পূর্ণসংখ্যা initialize)
{
	unsigned অক্ষর c;
	ধ্রুবক unsigned অক্ষর *bp;
	আকার_t len;
	পূর্ণসংখ্যা alt_format, i;
	স্থির পূর্ণসংখ্যা century, relyear;

	যদি (initialize) {
		century = TM_YEAR_BASE;
		relyear = -1;
	}

	bp = (unsigned অক্ষর *)buf;
	যখন ((c = *fmt) != '\0') {
		/* Clear `alternate' modifier prior to new conversion. */
		alt_format = 0;

		/* Eat up white-space. */
		যদি (isspace(c)) {
			যখন (isspace(*bp))
				bp++;

			fmt++;
			চালু;
		}
				
		যদি ((c = *fmt++) != '%')
			যাও literal;


again:		নির্বাচন (c = *fmt++) {
		ক্ষেত্র '%':	/* "%%" is converted to "%". */
literal:
		যদি (c != *bp++)
			ফেরত (ফাঁকা);

		বিরতি;

		/*
		 * "Alternative" modifiers. Just set the appropriate flag
		 * and start over again.
		 */
		ক্ষেত্র 'E':	/* "%E?" alternative conversion modifier. */
			_LEGAL_ALT(0);
			alt_format |= _ALT_E;
			যাও again;

		ক্ষেত্র 'O':	/* "%O?" alternative conversion modifier. */
			_LEGAL_ALT(0);
			alt_format |= _ALT_O;
			যাও again;
			
		/*
		 * "Complex" conversion rules, implemented through recursion.
		 */
#যদি 0
		ক্ষেত্র 'c':	/* Date and time, using the locale's format. */
			_LEGAL_ALT(_ALT_E);
			যদি (!(bp = _strptime(bp, _ctloc(d_t_fmt), tm, 0)))
				ফেরত (ফাঁকা);
			বিরতি;
#endif
		ক্ষেত্র 'D':	/* The date as "%m/%d/%y". */
			_LEGAL_ALT(0);
			যদি (!(bp = _strptime(bp, "%m/%d/%y", tm, 0)))
				ফেরত (ফাঁকা);
			বিরতি;
	
		ক্ষেত্র 'R':	/* The time as "%H:%M". */
			_LEGAL_ALT(0);
			যদি (!(bp = _strptime(bp, "%H:%M", tm, 0)))
				ফেরত (ফাঁকা);
			বিরতি;

		ক্ষেত্র 'r':	/* The time as "%I:%M:%S %p". */
			_LEGAL_ALT(0);
			যদি (!(bp = _strptime(bp, "%I:%M:%S %p", tm, 0)))
				ফেরত (ফাঁকা);
			বিরতি;

		ক্ষেত্র 'T':	/* The time as "%H:%M:%S". */
			_LEGAL_ALT(0);
			যদি (!(bp = _strptime(bp, "%H:%M:%S", tm, 0)))
				ফেরত (ফাঁকা);
			বিরতি;
#যদি 0
		ক্ষেত্র 'X':	/* The time, using the locale's format. */
			_LEGAL_ALT(_ALT_E);
			যদি (!(bp = _strptime(bp, _ctloc(t_fmt), tm, 0)))
				ফেরত (ফাঁকা);
			বিরতি;

		ক্ষেত্র 'x':	/* The date, using the locale's format. */
			_LEGAL_ALT(_ALT_E);
			যদি (!(bp = _strptime(bp, _ctloc(d_fmt), tm, 0)))
				ফেরত (ফাঁকা);
			বিরতি;
#endif
		/*
		 * "Elementary" conversion rules.
		 */
#যদি 0
		ক্ষেত্র 'A':	/* The day of week, using the locale's form. */
		ক্ষেত্র 'a':
			_LEGAL_ALT(0);
			জন্য (i = 0; i < 7; i++) {
				/* Full name. */
				len = strlen(_ctloc(day[i]));
				যদি (strncasecmp(_ctloc(day[i]), bp, len) == 0)
					বিরতি;

				/* Abbreviated name. */
				len = strlen(_ctloc(abday[i]));
				যদি (strncasecmp(_ctloc(abday[i]), bp, len) == 0)
					বিরতি;
			}

			/* Nothing matched. */
			যদি (i == 7)
				ফেরত (ফাঁকা);

			tm->tm_wday = i;
			bp += len;
			বিরতি;

		ক্ষেত্র 'B':	/* The month, using the locale's form. */
		ক্ষেত্র 'b':
		ক্ষেত্র 'h':
			_LEGAL_ALT(0);
			জন্য (i = 0; i < 12; i++) {
				/* Full name. */
				len = strlen(_ctloc(mon[i]));
				যদি (strncasecmp(_ctloc(mon[i]), bp, len) == 0)
					বিরতি;

				/* Abbreviated name. */
				len = strlen(_ctloc(abmon[i]));
				যদি (strncasecmp(_ctloc(abmon[i]), bp, len) == 0)
					বিরতি;
			}

			/* Nothing matched. */
			যদি (i == 12)
				ফেরত (ফাঁকা);

			tm->tm_mon = i;
			bp += len;
			বিরতি;
#endif

		ক্ষেত্র 'C':	/* The century number. */
			_LEGAL_ALT(_ALT_E);
			যদি (!(conv_অঙ্ক(&bp, &i, 0, 99)))
				ফেরত (ফাঁকা);

			century = i * 100;
			বিরতি;

		ক্ষেত্র 'd':	/* The day of month. */
		ক্ষেত্র 'e':
			_LEGAL_ALT(_ALT_O);
			যদি (!(conv_অঙ্ক(&bp, &tm->tm_mday, 1, 31)))
				ফেরত (ফাঁকা);
			বিরতি;

		ক্ষেত্র 'k':	/* The hour (24-hour clock representation). */
			_LEGAL_ALT(0);
			/* FALLTHROUGH */
		ক্ষেত্র 'H':
			_LEGAL_ALT(_ALT_O);
			যদি (!(conv_অঙ্ক(&bp, &tm->tm_hour, 0, 23)))
				ফেরত (ফাঁকা);
			বিরতি;

		ক্ষেত্র 'l':	/* The hour (12-hour clock representation). */
			_LEGAL_ALT(0);
			/* FALLTHROUGH */
		ক্ষেত্র 'I':
			_LEGAL_ALT(_ALT_O);
			যদি (!(conv_অঙ্ক(&bp, &tm->tm_hour, 1, 12)))
				ফেরত (ফাঁকা);
			বিরতি;

		ক্ষেত্র 'j':	/* The day of year. */
			_LEGAL_ALT(0);
			যদি (!(conv_অঙ্ক(&bp, &tm->tm_yday, 1, 366)))
				ফেরত (ফাঁকা);
			tm->tm_yday--;
			বিরতি;

		ক্ষেত্র 'M':	/* The minute. */
			_LEGAL_ALT(_ALT_O);
			যদি (!(conv_অঙ্ক(&bp, &tm->tm_min, 0, 59)))
				ফেরত (ফাঁকা);
			বিরতি;

		ক্ষেত্র 'm':	/* The month. */
			_LEGAL_ALT(_ALT_O);
			যদি (!(conv_অঙ্ক(&bp, &tm->tm_mon, 1, 12)))
				ফেরত (ফাঁকা);
			tm->tm_mon--;
			বিরতি;

#যদি 0
		ক্ষেত্র 'p':	/* The locale's equivalent of AM/PM. */
			_LEGAL_ALT(0);
			/* AM? */
			len = strlen(_ctloc(am_pm[0]));
			যদি (strncasecmp(_ctloc(am_pm[0]), bp, len) == 0) {
				যদি (tm->tm_hour > 12)	/* i.e., 13:00 AM ?! */
					ফেরত (ফাঁকা);
				অন্যথা যদি (tm->tm_hour == 12)
					tm->tm_hour = 0;

				bp += len;
				বিরতি;
			}
			/* PM? */
			len = strlen(_ctloc(am_pm[1]));
			যদি (strncasecmp(_ctloc(am_pm[1]), bp, len) == 0) {
				যদি (tm->tm_hour > 12)	/* i.e., 13:00 PM ?! */
					ফেরত (ফাঁকা);
				অন্যথা যদি (tm->tm_hour < 12)
					tm->tm_hour += 12;

				bp += len;
				বিরতি;
			}

			/* Nothing matched. */
			ফেরত (ফাঁকা);
#endif
		ক্ষেত্র 'S':	/* The seconds. */
			_LEGAL_ALT(_ALT_O);
			যদি (!(conv_অঙ্ক(&bp, &tm->tm_sec, 0, 61)))
				ফেরত (ফাঁকা);
			বিরতি;

		ক্ষেত্র 'U':	/* The week of year, beginning on sunday. */
		ক্ষেত্র 'W':	/* The week of year, beginning on monday. */
			_LEGAL_ALT(_ALT_O);
			/*
			 * XXX This is bogus, as we can not assume any valid
			 * information present in the tm structure at this
			 * point to calculate a real value, so just check the
			 * range for now.
			 */
			 যদি (!(conv_অঙ্ক(&bp, &i, 0, 53)))
				ফেরত (ফাঁকা);
			 বিরতি;

		ক্ষেত্র 'w':	/* The day of week, beginning on sunday. */
			_LEGAL_ALT(_ALT_O);
			যদি (!(conv_অঙ্ক(&bp, &tm->tm_wday, 0, 6)))
				ফেরত (ফাঁকা);
			বিরতি;

		ক্ষেত্র 'Y':	/* The year. */
			_LEGAL_ALT(_ALT_E);
			যদি (!(conv_অঙ্ক(&bp, &i, 0, 9999)))
				ফেরত (ফাঁকা);

			relyear = -1;
			tm->tm_year = i - TM_YEAR_BASE;
			বিরতি;

		ক্ষেত্র 'y':	/* The year within the century (2 digits). */
			_LEGAL_ALT(_ALT_E | _ALT_O);
			যদি (!(conv_অঙ্ক(&bp, &relyear, 0, 99)))
				ফেরত (ফাঁকা);
			বিরতি;

		/*
		 * Miscellaneous conversions.
		 */
		ক্ষেত্র 'n':	/* Any kind of white-space. */
		ক্ষেত্র 't':
			_LEGAL_ALT(0);
			যখন (isspace(*bp))
				bp++;
			বিরতি;


		পূর্বনির্ধারিত:	/* Unknown/unsupported conversion. */
			ফেরত (ফাঁকা);
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

	ফেরত ((অক্ষর *)bp);
}


স্থির পূর্ণসংখ্যা
conv_অঙ্ক(ধ্রুবক unsigned অক্ষর **buf, পূর্ণসংখ্যা *dest, পূর্ণসংখ্যা llim, পূর্ণসংখ্যা ulim)
{
	পূর্ণসংখ্যা ফলাফল = 0;
	পূর্ণসংখ্যা rulim = ulim;

	যদি (**buf < '0' || **buf > '9')
		ফেরত (0);

	/* we use rulim to break out of the loop when we run out of digits */
	করো {
		ফলাফল *= 10;
		ফলাফল += *(*buf)++ - '0';
		rulim /= 10;
	} যখন ((ফলাফল * 10 <= ulim) && rulim && **buf >= '0' && **buf <= '9');

	যদি (ফলাফল < llim || ফলাফল > ulim)
		ফেরত (0);

	*dest = ফলাফল;
	ফেরত (1);
}

#endif /* HAVE_STRPTIME */

