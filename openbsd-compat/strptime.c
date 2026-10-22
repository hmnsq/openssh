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

#અન્તર્ભાવ "includes.h"

#ifndef HAVE_STRPTIME

#define TM_YEAR_BASE 1900	/* from tzfile.h */

#અન્તર્ભાવ <ctype.h>
#અન્તર્ભાવ <locale.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <time.h>

/* #define	_ctloc(x)		(_CurrentTimeLocale->x) */

/*
 * We do not implement alternate representations. However, we always
 * check whether a given modifier is allowed for a certain conversion.
 */
#define _ALT_E			0x01
#define _ALT_O			0x02
#define	_LEGAL_ALT(x)		{ જો (alt_format & ~(x)) પાછા (0); }


સ્થિર	પૂર્ણાંક conv_અંક(અચલ unsigned અક્ષર **, પૂર્ણાંક *, પૂર્ણાંક, પૂર્ણાંક);
સ્થિર	અક્ષર *_strptime(અચલ અક્ષર *, અચલ અક્ષર *, સંરચના tm *, પૂર્ણાંક);


અક્ષર *
strptime(અચલ અક્ષર *buf, અચલ અક્ષર *fmt, સંરચના tm *tm)
{
	પાછા(_strptime(buf, fmt, tm, 1));
}

સ્થિર અક્ષર *
_strptime(અચલ અક્ષર *buf, અચલ અક્ષર *fmt, સંરચના tm *tm, પૂર્ણાંક initialize)
{
	unsigned અક્ષર c;
	અચલ unsigned અક્ષર *bp;
	size_t len;
	પૂર્ણાંક alt_format, i;
	સ્થિર પૂર્ણાંક century, relyear;

	જો (initialize) {
		century = TM_YEAR_BASE;
		relyear = -1;
	}

	bp = (unsigned અક્ષર *)buf;
	જ્યારે ((c = *fmt) != '\0') {
		/* Clear `alternate' modifier prior to new conversion. */
		alt_format = 0;

		/* Eat up white-space. */
		જો (isspace(c)) {
			જ્યારે (isspace(*bp))
				bp++;

			fmt++;
			ચાલુ;
		}
				
		જો ((c = *fmt++) != '%')
			જાઓ literal;


again:		પસંદગી (c = *fmt++) {
		સ્થિતિ '%':	/* "%%" is converted to "%". */
literal:
		જો (c != *bp++)
			પાછા (ખાલી);

		તોડો;

		/*
		 * "Alternative" modifiers. Just set the appropriate flag
		 * and start over again.
		 */
		સ્થિતિ 'E':	/* "%E?" alternative conversion modifier. */
			_LEGAL_ALT(0);
			alt_format |= _ALT_E;
			જાઓ again;

		સ્થિતિ 'O':	/* "%O?" alternative conversion modifier. */
			_LEGAL_ALT(0);
			alt_format |= _ALT_O;
			જાઓ again;
			
		/*
		 * "Complex" conversion rules, implemented through recursion.
		 */
#જો 0
		સ્થિતિ 'c':	/* Date and time, using the locale's format. */
			_LEGAL_ALT(_ALT_E);
			જો (!(bp = _strptime(bp, _ctloc(d_t_fmt), tm, 0)))
				પાછા (ખાલી);
			તોડો;
#endif
		સ્થિતિ 'D':	/* The date as "%m/%d/%y". */
			_LEGAL_ALT(0);
			જો (!(bp = _strptime(bp, "%m/%d/%y", tm, 0)))
				પાછા (ખાલી);
			તોડો;
	
		સ્થિતિ 'R':	/* The time as "%H:%M". */
			_LEGAL_ALT(0);
			જો (!(bp = _strptime(bp, "%H:%M", tm, 0)))
				પાછા (ખાલી);
			તોડો;

		સ્થિતિ 'r':	/* The time as "%I:%M:%S %p". */
			_LEGAL_ALT(0);
			જો (!(bp = _strptime(bp, "%I:%M:%S %p", tm, 0)))
				પાછા (ખાલી);
			તોડો;

		સ્થિતિ 'T':	/* The time as "%H:%M:%S". */
			_LEGAL_ALT(0);
			જો (!(bp = _strptime(bp, "%H:%M:%S", tm, 0)))
				પાછા (ખાલી);
			તોડો;
#જો 0
		સ્થિતિ 'X':	/* The time, using the locale's format. */
			_LEGAL_ALT(_ALT_E);
			જો (!(bp = _strptime(bp, _ctloc(t_fmt), tm, 0)))
				પાછા (ખાલી);
			તોડો;

		સ્થિતિ 'x':	/* The date, using the locale's format. */
			_LEGAL_ALT(_ALT_E);
			જો (!(bp = _strptime(bp, _ctloc(d_fmt), tm, 0)))
				પાછા (ખાલી);
			તોડો;
#endif
		/*
		 * "Elementary" conversion rules.
		 */
#જો 0
		સ્થિતિ 'A':	/* The day of week, using the locale's form. */
		સ્થિતિ 'a':
			_LEGAL_ALT(0);
			માટે (i = 0; i < 7; i++) {
				/* Full name. */
				len = strlen(_ctloc(day[i]));
				જો (strncasecmp(_ctloc(day[i]), bp, len) == 0)
					તોડો;

				/* Abbreviated name. */
				len = strlen(_ctloc(abday[i]));
				જો (strncasecmp(_ctloc(abday[i]), bp, len) == 0)
					તોડો;
			}

			/* Nothing matched. */
			જો (i == 7)
				પાછા (ખાલી);

			tm->tm_wday = i;
			bp += len;
			તોડો;

		સ્થિતિ 'B':	/* The month, using the locale's form. */
		સ્થિતિ 'b':
		સ્થિતિ 'h':
			_LEGAL_ALT(0);
			માટે (i = 0; i < 12; i++) {
				/* Full name. */
				len = strlen(_ctloc(mon[i]));
				જો (strncasecmp(_ctloc(mon[i]), bp, len) == 0)
					તોડો;

				/* Abbreviated name. */
				len = strlen(_ctloc(abmon[i]));
				જો (strncasecmp(_ctloc(abmon[i]), bp, len) == 0)
					તોડો;
			}

			/* Nothing matched. */
			જો (i == 12)
				પાછા (ખાલી);

			tm->tm_mon = i;
			bp += len;
			તોડો;
#endif

		સ્થિતિ 'C':	/* The century number. */
			_LEGAL_ALT(_ALT_E);
			જો (!(conv_અંક(&bp, &i, 0, 99)))
				પાછા (ખાલી);

			century = i * 100;
			તોડો;

		સ્થિતિ 'd':	/* The day of month. */
		સ્થિતિ 'e':
			_LEGAL_ALT(_ALT_O);
			જો (!(conv_અંક(&bp, &tm->tm_mday, 1, 31)))
				પાછા (ખાલી);
			તોડો;

		સ્થિતિ 'k':	/* The hour (24-hour clock representation). */
			_LEGAL_ALT(0);
			/* FALLTHROUGH */
		સ્થિતિ 'H':
			_LEGAL_ALT(_ALT_O);
			જો (!(conv_અંક(&bp, &tm->tm_hour, 0, 23)))
				પાછા (ખાલી);
			તોડો;

		સ્થિતિ 'l':	/* The hour (12-hour clock representation). */
			_LEGAL_ALT(0);
			/* FALLTHROUGH */
		સ્થિતિ 'I':
			_LEGAL_ALT(_ALT_O);
			જો (!(conv_અંક(&bp, &tm->tm_hour, 1, 12)))
				પાછા (ખાલી);
			તોડો;

		સ્થિતિ 'j':	/* The day of year. */
			_LEGAL_ALT(0);
			જો (!(conv_અંક(&bp, &tm->tm_yday, 1, 366)))
				પાછા (ખાલી);
			tm->tm_yday--;
			તોડો;

		સ્થિતિ 'M':	/* The minute. */
			_LEGAL_ALT(_ALT_O);
			જો (!(conv_અંક(&bp, &tm->tm_min, 0, 59)))
				પાછા (ખાલી);
			તોડો;

		સ્થિતિ 'm':	/* The month. */
			_LEGAL_ALT(_ALT_O);
			જો (!(conv_અંક(&bp, &tm->tm_mon, 1, 12)))
				પાછા (ખાલી);
			tm->tm_mon--;
			તોડો;

#જો 0
		સ્થિતિ 'p':	/* The locale's equivalent of AM/PM. */
			_LEGAL_ALT(0);
			/* AM? */
			len = strlen(_ctloc(am_pm[0]));
			જો (strncasecmp(_ctloc(am_pm[0]), bp, len) == 0) {
				જો (tm->tm_hour > 12)	/* i.e., 13:00 AM ?! */
					પાછા (ખાલી);
				નહીંતર જો (tm->tm_hour == 12)
					tm->tm_hour = 0;

				bp += len;
				તોડો;
			}
			/* PM? */
			len = strlen(_ctloc(am_pm[1]));
			જો (strncasecmp(_ctloc(am_pm[1]), bp, len) == 0) {
				જો (tm->tm_hour > 12)	/* i.e., 13:00 PM ?! */
					પાછા (ખાલી);
				નહીંતર જો (tm->tm_hour < 12)
					tm->tm_hour += 12;

				bp += len;
				તોડો;
			}

			/* Nothing matched. */
			પાછા (ખાલી);
#endif
		સ્થિતિ 'S':	/* The seconds. */
			_LEGAL_ALT(_ALT_O);
			જો (!(conv_અંક(&bp, &tm->tm_sec, 0, 61)))
				પાછા (ખાલી);
			તોડો;

		સ્થિતિ 'U':	/* The week of year, beginning on sunday. */
		સ્થિતિ 'W':	/* The week of year, beginning on monday. */
			_LEGAL_ALT(_ALT_O);
			/*
			 * XXX This is bogus, as we can not assume any valid
			 * information present in the tm structure at this
			 * point to calculate a real value, so just check the
			 * range for now.
			 */
			 જો (!(conv_અંક(&bp, &i, 0, 53)))
				પાછા (ખાલી);
			 તોડો;

		સ્થિતિ 'w':	/* The day of week, beginning on sunday. */
			_LEGAL_ALT(_ALT_O);
			જો (!(conv_અંક(&bp, &tm->tm_wday, 0, 6)))
				પાછા (ખાલી);
			તોડો;

		સ્થિતિ 'Y':	/* The year. */
			_LEGAL_ALT(_ALT_E);
			જો (!(conv_અંક(&bp, &i, 0, 9999)))
				પાછા (ખાલી);

			relyear = -1;
			tm->tm_year = i - TM_YEAR_BASE;
			તોડો;

		સ્થિતિ 'y':	/* The year within the century (2 digits). */
			_LEGAL_ALT(_ALT_E | _ALT_O);
			જો (!(conv_અંક(&bp, &relyear, 0, 99)))
				પાછા (ખાલી);
			તોડો;

		/*
		 * Miscellaneous conversions.
		 */
		સ્થિતિ 'n':	/* Any kind of white-space. */
		સ્થિતિ 't':
			_LEGAL_ALT(0);
			જ્યારે (isspace(*bp))
				bp++;
			તોડો;


		મૂળભૂત:	/* Unknown/unsupported conversion. */
			પાછા (ખાલી);
		}


	}

	/*
	 * We need to evaluate the two digit year spec (%y)
	 * last as we can get a century spec (%C) at any time.
	 */
	જો (relyear != -1) {
		જો (century == TM_YEAR_BASE) {
			જો (relyear <= 68)
				tm->tm_year = relyear + 2000 - TM_YEAR_BASE;
			નહીંતર
				tm->tm_year = relyear + 1900 - TM_YEAR_BASE;
		} નહીંતર {
			tm->tm_year = relyear + century - TM_YEAR_BASE;
		}
	}

	પાછા ((અક્ષર *)bp);
}


સ્થિર પૂર્ણાંક
conv_અંક(અચલ unsigned અક્ષર **buf, પૂર્ણાંક *dest, પૂર્ણાંક llim, પૂર્ણાંક ulim)
{
	પૂર્ણાંક result = 0;
	પૂર્ણાંક rulim = ulim;

	જો (**buf < '0' || **buf > '9')
		પાછા (0);

	/* we use rulim to break out of the loop when we run out of digits */
	કરો {
		result *= 10;
		result += *(*buf)++ - '0';
		rulim /= 10;
	} જ્યારે ((result * 10 <= ulim) && rulim && **buf >= '0' && **buf <= '9');

	જો (result < llim || result > ulim)
		પાછા (0);

	*dest = result;
	પાછા (1);
}

#endif /* HAVE_STRPTIME */

