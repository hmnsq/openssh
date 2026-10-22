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

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_STRPTIME

#ವ್ಯಾಖ್ಯಾನಿಸು TM_YEAR_ತಳ 1900	/* from tzfile.h */

#ಅನ್ತರ್ಭಾವ <ctype.h>
#ಅನ್ತರ್ಭಾವ <locale.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <time.h>

/* #define	_ctloc(x)		(_CurrentTimeLocale->x) */

/*
 * We do not implement alternate representations. However, we always
 * check whether a given modifier is allowed for a certain conversion.
 */
#ವ್ಯಾಖ್ಯಾನಿಸು _ALT_E			0x01
#ವ್ಯಾಖ್ಯಾನಿಸು _ALT_O			0x02
#ವ್ಯಾಖ್ಯಾನಿಸು	_LEGAL_ALT(x)		{ ಆದರೆ (alt_format & ~(x)) ಹಿಂತಿರುಗಿ (0); }


ಸ್ಥಿರ	ಪೂರ್ಣಾಂಕ conv_ಅಂಕೆ(ಸ್ಥಿರಾಂಕ ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ **, ಪೂರ್ಣಾಂಕ *, ಪೂರ್ಣಾಂಕ, ಪೂರ್ಣಾಂಕ);
ಸ್ಥಿರ	ಅಕ್ಷರ *_strptime(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ರಚನೆ tm *, ಪೂರ್ಣಾಂಕ);


ಅಕ್ಷರ *
strptime(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *buf, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *fmt, ರಚನೆ tm *tm)
{
	ಹಿಂತಿರುಗಿ(_strptime(buf, fmt, tm, 1));
}

ಸ್ಥಿರ ಅಕ್ಷರ *
_strptime(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *buf, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *fmt, ರಚನೆ tm *tm, ಪೂರ್ಣಾಂಕ initialize)
{
	ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ c;
	ಸ್ಥಿರಾಂಕ ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *bp;
	ಗಾತ್ರ_t len;
	ಪೂರ್ಣಾಂಕ alt_format, i;
	ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ century, relyear;

	ಆದರೆ (initialize) {
		century = TM_YEAR_ತಳ;
		relyear = -1;
	}

	bp = (ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *)buf;
	ಆಗ ((c = *fmt) != '\0') {
		/* Clear `alternate' modifier prior to new conversion. */
		alt_format = 0;

		/* Eat up white-space. */
		ಆದರೆ (ಖಾಲಿಯೇ(c)) {
			ಆಗ (ಖಾಲಿಯೇ(*bp))
				bp++;

			fmt++;
			ಮುಂದುವರಿ;
		}
				
		ಆದರೆ ((c = *fmt++) != '%')
			ಹೋಗು literal;


again:		ಆಯ್ಕೆ (c = *fmt++) {
		ಸ್ಥಿತಿ '%':	/* "%%" is converted to "%". */
literal:
		ಆದರೆ (c != *bp++)
			ಹಿಂತಿರುಗಿ (ಖಾಲಿ);

		ನಿಲ್ಲಿಸು;

		/*
		 * "Alternative" modifiers. Just set the appropriate flag
		 * and start over again.
		 */
		ಸ್ಥಿತಿ 'E':	/* "%E?" alternative conversion modifier. */
			_LEGAL_ALT(0);
			alt_format |= _ALT_E;
			ಹೋಗು again;

		ಸ್ಥಿತಿ 'O':	/* "%O?" alternative conversion modifier. */
			_LEGAL_ALT(0);
			alt_format |= _ALT_O;
			ಹೋಗು again;
			
		/*
		 * "Complex" conversion rules, implemented through recursion.
		 */
#ಆದರೆ 0
		ಸ್ಥಿತಿ 'c':	/* Date and time, using the locale's format. */
			_LEGAL_ALT(_ALT_E);
			ಆದರೆ (!(bp = _strptime(bp, _ctloc(d_t_fmt), tm, 0)))
				ಹಿಂತಿರುಗಿ (ಖಾಲಿ);
			ನಿಲ್ಲಿಸು;
#ಆದರೆ_ಅಂತ್ಯ
		ಸ್ಥಿತಿ 'D':	/* The date as "%m/%d/%y". */
			_LEGAL_ALT(0);
			ಆದರೆ (!(bp = _strptime(bp, "%m/%d/%y", tm, 0)))
				ಹಿಂತಿರುಗಿ (ಖಾಲಿ);
			ನಿಲ್ಲಿಸು;
	
		ಸ್ಥಿತಿ 'R':	/* The time as "%H:%M". */
			_LEGAL_ALT(0);
			ಆದರೆ (!(bp = _strptime(bp, "%H:%M", tm, 0)))
				ಹಿಂತಿರುಗಿ (ಖಾಲಿ);
			ನಿಲ್ಲಿಸು;

		ಸ್ಥಿತಿ 'r':	/* The time as "%I:%M:%S %p". */
			_LEGAL_ALT(0);
			ಆದರೆ (!(bp = _strptime(bp, "%I:%M:%S %p", tm, 0)))
				ಹಿಂತಿರುಗಿ (ಖಾಲಿ);
			ನಿಲ್ಲಿಸು;

		ಸ್ಥಿತಿ 'T':	/* The time as "%H:%M:%S". */
			_LEGAL_ALT(0);
			ಆದರೆ (!(bp = _strptime(bp, "%H:%M:%S", tm, 0)))
				ಹಿಂತಿರುಗಿ (ಖಾಲಿ);
			ನಿಲ್ಲಿಸು;
#ಆದರೆ 0
		ಸ್ಥಿತಿ 'X':	/* The time, using the locale's format. */
			_LEGAL_ALT(_ALT_E);
			ಆದರೆ (!(bp = _strptime(bp, _ctloc(t_fmt), tm, 0)))
				ಹಿಂತಿರುಗಿ (ಖಾಲಿ);
			ನಿಲ್ಲಿಸು;

		ಸ್ಥಿತಿ 'x':	/* The date, using the locale's format. */
			_LEGAL_ALT(_ALT_E);
			ಆದರೆ (!(bp = _strptime(bp, _ctloc(d_fmt), tm, 0)))
				ಹಿಂತಿರುಗಿ (ಖಾಲಿ);
			ನಿಲ್ಲಿಸು;
#ಆದರೆ_ಅಂತ್ಯ
		/*
		 * "Elementary" conversion rules.
		 */
#ಆದರೆ 0
		ಸ್ಥಿತಿ 'A':	/* The day of week, using the locale's form. */
		ಸ್ಥಿತಿ 'a':
			_LEGAL_ALT(0);
			ಗಾಗಿ (i = 0; i < 7; i++) {
				/* Full name. */
				len = ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(_ctloc(day[i]));
				ಆದರೆ (strncasecmp(_ctloc(day[i]), bp, len) == 0)
					ನಿಲ್ಲಿಸು;

				/* Abbreviated name. */
				len = ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(_ctloc(abday[i]));
				ಆದರೆ (strncasecmp(_ctloc(abday[i]), bp, len) == 0)
					ನಿಲ್ಲಿಸು;
			}

			/* Nothing matched. */
			ಆದರೆ (i == 7)
				ಹಿಂತಿರುಗಿ (ಖಾಲಿ);

			tm->tm_wday = i;
			bp += len;
			ನಿಲ್ಲಿಸು;

		ಸ್ಥಿತಿ 'B':	/* The month, using the locale's form. */
		ಸ್ಥಿತಿ 'b':
		ಸ್ಥಿತಿ 'h':
			_LEGAL_ALT(0);
			ಗಾಗಿ (i = 0; i < 12; i++) {
				/* Full name. */
				len = ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(_ctloc(mon[i]));
				ಆದರೆ (strncasecmp(_ctloc(mon[i]), bp, len) == 0)
					ನಿಲ್ಲಿಸು;

				/* Abbreviated name. */
				len = ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(_ctloc(abmon[i]));
				ಆದರೆ (strncasecmp(_ctloc(abmon[i]), bp, len) == 0)
					ನಿಲ್ಲಿಸು;
			}

			/* Nothing matched. */
			ಆದರೆ (i == 12)
				ಹಿಂತಿರುಗಿ (ಖಾಲಿ);

			tm->tm_mon = i;
			bp += len;
			ನಿಲ್ಲಿಸು;
#ಆದರೆ_ಅಂತ್ಯ

		ಸ್ಥಿತಿ 'C':	/* The century number. */
			_LEGAL_ALT(_ALT_E);
			ಆದರೆ (!(conv_ಅಂಕೆ(&bp, &i, 0, 99)))
				ಹಿಂತಿರುಗಿ (ಖಾಲಿ);

			century = i * 100;
			ನಿಲ್ಲಿಸು;

		ಸ್ಥಿತಿ 'd':	/* The day of month. */
		ಸ್ಥಿತಿ 'e':
			_LEGAL_ALT(_ALT_O);
			ಆದರೆ (!(conv_ಅಂಕೆ(&bp, &tm->tm_mday, 1, 31)))
				ಹಿಂತಿರುಗಿ (ಖಾಲಿ);
			ನಿಲ್ಲಿಸು;

		ಸ್ಥಿತಿ 'k':	/* The hour (24-hour clock representation). */
			_LEGAL_ALT(0);
			/* FALLTHROUGH */
		ಸ್ಥಿತಿ 'H':
			_LEGAL_ALT(_ALT_O);
			ಆದರೆ (!(conv_ಅಂಕೆ(&bp, &tm->tm_hour, 0, 23)))
				ಹಿಂತಿರುಗಿ (ಖಾಲಿ);
			ನಿಲ್ಲಿಸು;

		ಸ್ಥಿತಿ 'l':	/* The hour (12-hour clock representation). */
			_LEGAL_ALT(0);
			/* FALLTHROUGH */
		ಸ್ಥಿತಿ 'I':
			_LEGAL_ALT(_ALT_O);
			ಆದರೆ (!(conv_ಅಂಕೆ(&bp, &tm->tm_hour, 1, 12)))
				ಹಿಂತಿರುಗಿ (ಖಾಲಿ);
			ನಿಲ್ಲಿಸು;

		ಸ್ಥಿತಿ 'j':	/* The day of year. */
			_LEGAL_ALT(0);
			ಆದರೆ (!(conv_ಅಂಕೆ(&bp, &tm->tm_yday, 1, 366)))
				ಹಿಂತಿರುಗಿ (ಖಾಲಿ);
			tm->tm_yday--;
			ನಿಲ್ಲಿಸು;

		ಸ್ಥಿತಿ 'M':	/* The minute. */
			_LEGAL_ALT(_ALT_O);
			ಆದರೆ (!(conv_ಅಂಕೆ(&bp, &tm->tm_min, 0, 59)))
				ಹಿಂತಿರುಗಿ (ಖಾಲಿ);
			ನಿಲ್ಲಿಸು;

		ಸ್ಥಿತಿ 'm':	/* The month. */
			_LEGAL_ALT(_ALT_O);
			ಆದರೆ (!(conv_ಅಂಕೆ(&bp, &tm->tm_mon, 1, 12)))
				ಹಿಂತಿರುಗಿ (ಖಾಲಿ);
			tm->tm_mon--;
			ನಿಲ್ಲಿಸು;

#ಆದರೆ 0
		ಸ್ಥಿತಿ 'p':	/* The locale's equivalent of AM/PM. */
			_LEGAL_ALT(0);
			/* AM? */
			len = ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(_ctloc(am_pm[0]));
			ಆದರೆ (strncasecmp(_ctloc(am_pm[0]), bp, len) == 0) {
				ಆದರೆ (tm->tm_hour > 12)	/* i.e., 13:00 AM ?! */
					ಹಿಂತಿರುಗಿ (ಖಾಲಿ);
				ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (tm->tm_hour == 12)
					tm->tm_hour = 0;

				bp += len;
				ನಿಲ್ಲಿಸು;
			}
			/* PM? */
			len = ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(_ctloc(am_pm[1]));
			ಆದರೆ (strncasecmp(_ctloc(am_pm[1]), bp, len) == 0) {
				ಆದರೆ (tm->tm_hour > 12)	/* i.e., 13:00 PM ?! */
					ಹಿಂತಿರುಗಿ (ಖಾಲಿ);
				ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (tm->tm_hour < 12)
					tm->tm_hour += 12;

				bp += len;
				ನಿಲ್ಲಿಸು;
			}

			/* Nothing matched. */
			ಹಿಂತಿರುಗಿ (ಖಾಲಿ);
#ಆದರೆ_ಅಂತ್ಯ
		ಸ್ಥಿತಿ 'S':	/* The seconds. */
			_LEGAL_ALT(_ALT_O);
			ಆದರೆ (!(conv_ಅಂಕೆ(&bp, &tm->tm_sec, 0, 61)))
				ಹಿಂತಿರುಗಿ (ಖಾಲಿ);
			ನಿಲ್ಲಿಸು;

		ಸ್ಥಿತಿ 'U':	/* The week of year, beginning on sunday. */
		ಸ್ಥಿತಿ 'W':	/* The week of year, beginning on monday. */
			_LEGAL_ALT(_ALT_O);
			/*
			 * XXX This is bogus, as we can not assume any valid
			 * information present in the tm structure at this
			 * point to calculate a real value, so just check the
			 * range for now.
			 */
			 ಆದರೆ (!(conv_ಅಂಕೆ(&bp, &i, 0, 53)))
				ಹಿಂತಿರುಗಿ (ಖಾಲಿ);
			 ನಿಲ್ಲಿಸು;

		ಸ್ಥಿತಿ 'w':	/* The day of week, beginning on sunday. */
			_LEGAL_ALT(_ALT_O);
			ಆದರೆ (!(conv_ಅಂಕೆ(&bp, &tm->tm_wday, 0, 6)))
				ಹಿಂತಿರುಗಿ (ಖಾಲಿ);
			ನಿಲ್ಲಿಸು;

		ಸ್ಥಿತಿ 'Y':	/* The year. */
			_LEGAL_ALT(_ALT_E);
			ಆದರೆ (!(conv_ಅಂಕೆ(&bp, &i, 0, 9999)))
				ಹಿಂತಿರುಗಿ (ಖಾಲಿ);

			relyear = -1;
			tm->tm_year = i - TM_YEAR_ತಳ;
			ನಿಲ್ಲಿಸು;

		ಸ್ಥಿತಿ 'y':	/* The year within the century (2 digits). */
			_LEGAL_ALT(_ALT_E | _ALT_O);
			ಆದರೆ (!(conv_ಅಂಕೆ(&bp, &relyear, 0, 99)))
				ಹಿಂತಿರುಗಿ (ಖಾಲಿ);
			ನಿಲ್ಲಿಸು;

		/*
		 * Miscellaneous conversions.
		 */
		ಸ್ಥಿತಿ 'n':	/* Any kind of white-space. */
		ಸ್ಥಿತಿ 't':
			_LEGAL_ALT(0);
			ಆಗ (ಖಾಲಿಯೇ(*bp))
				bp++;
			ನಿಲ್ಲಿಸು;


		ಪೂರ್ವನಿಯೋಜಿತ:	/* Unknown/unsupported conversion. */
			ಹಿಂತಿರುಗಿ (ಖಾಲಿ);
		}


	}

	/*
	 * We need to evaluate the two digit year spec (%y)
	 * last as we can get a century spec (%C) at any time.
	 */
	ಆದರೆ (relyear != -1) {
		ಆದರೆ (century == TM_YEAR_ತಳ) {
			ಆದರೆ (relyear <= 68)
				tm->tm_year = relyear + 2000 - TM_YEAR_ತಳ;
			ಇಲ್ಲದಿದ್ದರೆ
				tm->tm_year = relyear + 1900 - TM_YEAR_ತಳ;
		} ಇಲ್ಲದಿದ್ದರೆ {
			tm->tm_year = relyear + century - TM_YEAR_ತಳ;
		}
	}

	ಹಿಂತಿರುಗಿ ((ಅಕ್ಷರ *)bp);
}


ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
conv_ಅಂಕೆ(ಸ್ಥಿರಾಂಕ ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ **buf, ಪೂರ್ಣಾಂಕ *dest, ಪೂರ್ಣಾಂಕ llim, ಪೂರ್ಣಾಂಕ ulim)
{
	ಪೂರ್ಣಾಂಕ ಫಲಿತಾಂಶ = 0;
	ಪೂರ್ಣಾಂಕ rulim = ulim;

	ಆದರೆ (**buf < '0' || **buf > '9')
		ಹಿಂತಿರುಗಿ (0);

	/* we use rulim to break out of the loop when we run out of digits */
	ಮಾಡು {
		ಫಲಿತಾಂಶ *= 10;
		ಫಲಿತಾಂಶ += *(*buf)++ - '0';
		rulim /= 10;
	} ಆಗ ((ಫಲಿತಾಂಶ * 10 <= ulim) && rulim && **buf >= '0' && **buf <= '9');

	ಆದರೆ (ಫಲಿತಾಂಶ < llim || ಫಲಿತಾಂಶ > ulim)
		ಹಿಂತಿರುಗಿ (0);

	*dest = ಫಲಿತಾಂಶ;
	ಹಿಂತಿರುಗಿ (1);
}

#ಆದರೆ_ಅಂತ್ಯ /* HAVE_STRPTIME */

