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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ifndef HAVE_STRPTIME

#define TM_YEAR_BASE 1900	/* from tzfile.h */

#ಅನ್ತರ್ಭಾವ <ctype.h>
#ಅನ್ತರ್ಭಾವ <locale.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <time.h>

/* #define	_ctloc(x)		(_CurrentTimeLocale->x) */

/*
 * We do not implement alternate representations. However, we always
 * check whether a given modifier is allowed for a certain conversion.
 */
#define _ALT_E			0x01
#define _ALT_O			0x02
#define	_LEGAL_ALT(x)		{ ಯದಿ (alt_format & ~(x)) ಪ್ರತ್ಯಾಗಮ (0); }


ಸ್ಥಿರ	ಪೂರ್ಣಾಙ್ಕ conv_ಅಂಕೆ(ಧ್ರುವ unsigned ವರ್ಣ **, ಪೂರ್ಣಾಙ್ಕ *, ಪೂರ್ಣಾಙ್ಕ, ಪೂರ್ಣಾಙ್ಕ);
ಸ್ಥಿರ	ವರ್ಣ *_strptime(ಧ್ರುವ ವರ್ಣ *, ಧ್ರುವ ವರ್ಣ *, ಸಂರಚನಾ tm *, ಪೂರ್ಣಾಙ್ಕ);


ವರ್ಣ *
strptime(ಧ್ರುವ ವರ್ಣ *buf, ಧ್ರುವ ವರ್ಣ *fmt, ಸಂರಚನಾ tm *tm)
{
	ಪ್ರತ್ಯಾಗಮ(_strptime(buf, fmt, tm, 1));
}

ಸ್ಥಿರ ವರ್ಣ *
_strptime(ಧ್ರುವ ವರ್ಣ *buf, ಧ್ರುವ ವರ್ಣ *fmt, ಸಂರಚನಾ tm *tm, ಪೂರ್ಣಾಙ್ಕ initialize)
{
	unsigned ವರ್ಣ c;
	ಧ್ರುವ unsigned ವರ್ಣ *bp;
	size_t len;
	ಪೂರ್ಣಾಙ್ಕ alt_format, i;
	ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ century, relyear;

	ಯದಿ (initialize) {
		century = TM_YEAR_BASE;
		relyear = -1;
	}

	bp = (unsigned ವರ್ಣ *)buf;
	ಯಾವತ್ ((c = *fmt) != '\0') {
		/* Clear `alternate' modifier prior to new conversion. */
		alt_format = 0;

		/* Eat up white-space. */
		ಯದಿ (isspace(c)) {
			ಯಾವತ್ (isspace(*bp))
				bp++;

			fmt++;
			ಅನುವರ್ತ;
		}
				
		ಯದಿ ((c = *fmt++) != '%')
			ಗಚ್ಛ literal;


again:		ವಿಕಲ್ಪ (c = *fmt++) {
		ಪಕ್ಷ '%':	/* "%%" is converted to "%". */
literal:
		ಯದಿ (c != *bp++)
			ಪ್ರತ್ಯಾಗಮ (ರಿಕ್ತ);

		ಭಙ್ಗ;

		/*
		 * "Alternative" modifiers. Just set the appropriate flag
		 * and start over again.
		 */
		ಪಕ್ಷ 'E':	/* "%E?" alternative conversion modifier. */
			_LEGAL_ALT(0);
			alt_format |= _ALT_E;
			ಗಚ್ಛ again;

		ಪಕ್ಷ 'O':	/* "%O?" alternative conversion modifier. */
			_LEGAL_ALT(0);
			alt_format |= _ALT_O;
			ಗಚ್ಛ again;
			
		/*
		 * "Complex" conversion rules, implemented through recursion.
		 */
#ಯದಿ 0
		ಪಕ್ಷ 'c':	/* Date and time, using the locale's format. */
			_LEGAL_ALT(_ALT_E);
			ಯದಿ (!(bp = _strptime(bp, _ctloc(d_t_fmt), tm, 0)))
				ಪ್ರತ್ಯಾಗಮ (ರಿಕ್ತ);
			ಭಙ್ಗ;
#endif
		ಪಕ್ಷ 'D':	/* The date as "%m/%d/%y". */
			_LEGAL_ALT(0);
			ಯದಿ (!(bp = _strptime(bp, "%m/%d/%y", tm, 0)))
				ಪ್ರತ್ಯಾಗಮ (ರಿಕ್ತ);
			ಭಙ್ಗ;
	
		ಪಕ್ಷ 'R':	/* The time as "%H:%M". */
			_LEGAL_ALT(0);
			ಯದಿ (!(bp = _strptime(bp, "%H:%M", tm, 0)))
				ಪ್ರತ್ಯಾಗಮ (ರಿಕ್ತ);
			ಭಙ್ಗ;

		ಪಕ್ಷ 'r':	/* The time as "%I:%M:%S %p". */
			_LEGAL_ALT(0);
			ಯದಿ (!(bp = _strptime(bp, "%I:%M:%S %p", tm, 0)))
				ಪ್ರತ್ಯಾಗಮ (ರಿಕ್ತ);
			ಭಙ್ಗ;

		ಪಕ್ಷ 'T':	/* The time as "%H:%M:%S". */
			_LEGAL_ALT(0);
			ಯದಿ (!(bp = _strptime(bp, "%H:%M:%S", tm, 0)))
				ಪ್ರತ್ಯಾಗಮ (ರಿಕ್ತ);
			ಭಙ್ಗ;
#ಯದಿ 0
		ಪಕ್ಷ 'X':	/* The time, using the locale's format. */
			_LEGAL_ALT(_ALT_E);
			ಯದಿ (!(bp = _strptime(bp, _ctloc(t_fmt), tm, 0)))
				ಪ್ರತ್ಯಾಗಮ (ರಿಕ್ತ);
			ಭಙ್ಗ;

		ಪಕ್ಷ 'x':	/* The date, using the locale's format. */
			_LEGAL_ALT(_ALT_E);
			ಯದಿ (!(bp = _strptime(bp, _ctloc(d_fmt), tm, 0)))
				ಪ್ರತ್ಯಾಗಮ (ರಿಕ್ತ);
			ಭಙ್ಗ;
#endif
		/*
		 * "Elementary" conversion rules.
		 */
#ಯದಿ 0
		ಪಕ್ಷ 'A':	/* The day of week, using the locale's form. */
		ಪಕ್ಷ 'a':
			_LEGAL_ALT(0);
			ಪ್ರತಿ (i = 0; i < 7; i++) {
				/* Full name. */
				len = strlen(_ctloc(day[i]));
				ಯದಿ (strncasecmp(_ctloc(day[i]), bp, len) == 0)
					ಭಙ್ಗ;

				/* Abbreviated name. */
				len = strlen(_ctloc(abday[i]));
				ಯದಿ (strncasecmp(_ctloc(abday[i]), bp, len) == 0)
					ಭಙ್ಗ;
			}

			/* Nothing matched. */
			ಯದಿ (i == 7)
				ಪ್ರತ್ಯಾಗಮ (ರಿಕ್ತ);

			tm->tm_wday = i;
			bp += len;
			ಭಙ್ಗ;

		ಪಕ್ಷ 'B':	/* The month, using the locale's form. */
		ಪಕ್ಷ 'b':
		ಪಕ್ಷ 'h':
			_LEGAL_ALT(0);
			ಪ್ರತಿ (i = 0; i < 12; i++) {
				/* Full name. */
				len = strlen(_ctloc(mon[i]));
				ಯದಿ (strncasecmp(_ctloc(mon[i]), bp, len) == 0)
					ಭಙ್ಗ;

				/* Abbreviated name. */
				len = strlen(_ctloc(abmon[i]));
				ಯದಿ (strncasecmp(_ctloc(abmon[i]), bp, len) == 0)
					ಭಙ್ಗ;
			}

			/* Nothing matched. */
			ಯದಿ (i == 12)
				ಪ್ರತ್ಯಾಗಮ (ರಿಕ್ತ);

			tm->tm_mon = i;
			bp += len;
			ಭಙ್ಗ;
#endif

		ಪಕ್ಷ 'C':	/* The century number. */
			_LEGAL_ALT(_ALT_E);
			ಯದಿ (!(conv_ಅಂಕೆ(&bp, &i, 0, 99)))
				ಪ್ರತ್ಯಾಗಮ (ರಿಕ್ತ);

			century = i * 100;
			ಭಙ್ಗ;

		ಪಕ್ಷ 'd':	/* The day of month. */
		ಪಕ್ಷ 'e':
			_LEGAL_ALT(_ALT_O);
			ಯದಿ (!(conv_ಅಂಕೆ(&bp, &tm->tm_mday, 1, 31)))
				ಪ್ರತ್ಯಾಗಮ (ರಿಕ್ತ);
			ಭಙ್ಗ;

		ಪಕ್ಷ 'k':	/* The hour (24-hour clock representation). */
			_LEGAL_ALT(0);
			/* FALLTHROUGH */
		ಪಕ್ಷ 'H':
			_LEGAL_ALT(_ALT_O);
			ಯದಿ (!(conv_ಅಂಕೆ(&bp, &tm->tm_hour, 0, 23)))
				ಪ್ರತ್ಯಾಗಮ (ರಿಕ್ತ);
			ಭಙ್ಗ;

		ಪಕ್ಷ 'l':	/* The hour (12-hour clock representation). */
			_LEGAL_ALT(0);
			/* FALLTHROUGH */
		ಪಕ್ಷ 'I':
			_LEGAL_ALT(_ALT_O);
			ಯದಿ (!(conv_ಅಂಕೆ(&bp, &tm->tm_hour, 1, 12)))
				ಪ್ರತ್ಯಾಗಮ (ರಿಕ್ತ);
			ಭಙ್ಗ;

		ಪಕ್ಷ 'j':	/* The day of year. */
			_LEGAL_ALT(0);
			ಯದಿ (!(conv_ಅಂಕೆ(&bp, &tm->tm_yday, 1, 366)))
				ಪ್ರತ್ಯಾಗಮ (ರಿಕ್ತ);
			tm->tm_yday--;
			ಭಙ್ಗ;

		ಪಕ್ಷ 'M':	/* The minute. */
			_LEGAL_ALT(_ALT_O);
			ಯದಿ (!(conv_ಅಂಕೆ(&bp, &tm->tm_min, 0, 59)))
				ಪ್ರತ್ಯಾಗಮ (ರಿಕ್ತ);
			ಭಙ್ಗ;

		ಪಕ್ಷ 'm':	/* The month. */
			_LEGAL_ALT(_ALT_O);
			ಯದಿ (!(conv_ಅಂಕೆ(&bp, &tm->tm_mon, 1, 12)))
				ಪ್ರತ್ಯಾಗಮ (ರಿಕ್ತ);
			tm->tm_mon--;
			ಭಙ್ಗ;

#ಯದಿ 0
		ಪಕ್ಷ 'p':	/* The locale's equivalent of AM/PM. */
			_LEGAL_ALT(0);
			/* AM? */
			len = strlen(_ctloc(am_pm[0]));
			ಯದಿ (strncasecmp(_ctloc(am_pm[0]), bp, len) == 0) {
				ಯದಿ (tm->tm_hour > 12)	/* i.e., 13:00 AM ?! */
					ಪ್ರತ್ಯಾಗಮ (ರಿಕ್ತ);
				ಅನ್ಯಥಾ ಯದಿ (tm->tm_hour == 12)
					tm->tm_hour = 0;

				bp += len;
				ಭಙ್ಗ;
			}
			/* PM? */
			len = strlen(_ctloc(am_pm[1]));
			ಯದಿ (strncasecmp(_ctloc(am_pm[1]), bp, len) == 0) {
				ಯದಿ (tm->tm_hour > 12)	/* i.e., 13:00 PM ?! */
					ಪ್ರತ್ಯಾಗಮ (ರಿಕ್ತ);
				ಅನ್ಯಥಾ ಯದಿ (tm->tm_hour < 12)
					tm->tm_hour += 12;

				bp += len;
				ಭಙ್ಗ;
			}

			/* Nothing matched. */
			ಪ್ರತ್ಯಾಗಮ (ರಿಕ್ತ);
#endif
		ಪಕ್ಷ 'S':	/* The seconds. */
			_LEGAL_ALT(_ALT_O);
			ಯದಿ (!(conv_ಅಂಕೆ(&bp, &tm->tm_sec, 0, 61)))
				ಪ್ರತ್ಯಾಗಮ (ರಿಕ್ತ);
			ಭಙ್ಗ;

		ಪಕ್ಷ 'U':	/* The week of year, beginning on sunday. */
		ಪಕ್ಷ 'W':	/* The week of year, beginning on monday. */
			_LEGAL_ALT(_ALT_O);
			/*
			 * XXX This is bogus, as we can not assume any valid
			 * information present in the tm structure at this
			 * point to calculate a real value, so just check the
			 * range for now.
			 */
			 ಯದಿ (!(conv_ಅಂಕೆ(&bp, &i, 0, 53)))
				ಪ್ರತ್ಯಾಗಮ (ರಿಕ್ತ);
			 ಭಙ್ಗ;

		ಪಕ್ಷ 'w':	/* The day of week, beginning on sunday. */
			_LEGAL_ALT(_ALT_O);
			ಯದಿ (!(conv_ಅಂಕೆ(&bp, &tm->tm_wday, 0, 6)))
				ಪ್ರತ್ಯಾಗಮ (ರಿಕ್ತ);
			ಭಙ್ಗ;

		ಪಕ್ಷ 'Y':	/* The year. */
			_LEGAL_ALT(_ALT_E);
			ಯದಿ (!(conv_ಅಂಕೆ(&bp, &i, 0, 9999)))
				ಪ್ರತ್ಯಾಗಮ (ರಿಕ್ತ);

			relyear = -1;
			tm->tm_year = i - TM_YEAR_BASE;
			ಭಙ್ಗ;

		ಪಕ್ಷ 'y':	/* The year within the century (2 digits). */
			_LEGAL_ALT(_ALT_E | _ALT_O);
			ಯದಿ (!(conv_ಅಂಕೆ(&bp, &relyear, 0, 99)))
				ಪ್ರತ್ಯಾಗಮ (ರಿಕ್ತ);
			ಭಙ್ಗ;

		/*
		 * Miscellaneous conversions.
		 */
		ಪಕ್ಷ 'n':	/* Any kind of white-space. */
		ಪಕ್ಷ 't':
			_LEGAL_ALT(0);
			ಯಾವತ್ (isspace(*bp))
				bp++;
			ಭಙ್ಗ;


		ಸ್ವಭಾವ:	/* Unknown/unsupported conversion. */
			ಪ್ರತ್ಯಾಗಮ (ರಿಕ್ತ);
		}


	}

	/*
	 * We need to evaluate the two digit year spec (%y)
	 * last as we can get a century spec (%C) at any time.
	 */
	ಯದಿ (relyear != -1) {
		ಯದಿ (century == TM_YEAR_BASE) {
			ಯದಿ (relyear <= 68)
				tm->tm_year = relyear + 2000 - TM_YEAR_BASE;
			ಅನ್ಯಥಾ
				tm->tm_year = relyear + 1900 - TM_YEAR_BASE;
		} ಅನ್ಯಥಾ {
			tm->tm_year = relyear + century - TM_YEAR_BASE;
		}
	}

	ಪ್ರತ್ಯಾಗಮ ((ವರ್ಣ *)bp);
}


ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
conv_ಅಂಕೆ(ಧ್ರುವ unsigned ವರ್ಣ **buf, ಪೂರ್ಣಾಙ್ಕ *dest, ಪೂರ್ಣಾಙ್ಕ llim, ಪೂರ್ಣಾಙ್ಕ ulim)
{
	ಪೂರ್ಣಾಙ್ಕ result = 0;
	ಪೂರ್ಣಾಙ್ಕ rulim = ulim;

	ಯದಿ (**buf < '0' || **buf > '9')
		ಪ್ರತ್ಯಾಗಮ (0);

	/* we use rulim to break out of the loop when we run out of digits */
	ಕುರು {
		result *= 10;
		result += *(*buf)++ - '0';
		rulim /= 10;
	} ಯಾವತ್ ((result * 10 <= ulim) && rulim && **buf >= '0' && **buf <= '9');

	ಯದಿ (result < llim || result > ulim)
		ಪ್ರತ್ಯಾಗಮ (0);

	*dest = result;
	ಪ್ರತ್ಯಾಗಮ (1);
}

#endif /* HAVE_STRPTIME */

