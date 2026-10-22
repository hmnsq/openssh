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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_STRPTIME

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ TM_YEAR_ਅਧਾਰ 1900	/* from tzfile.h */

#ਅਨ੍ਤਰ੍ਭਾਵ <ctype.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <locale.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <time.h>

/* #define	_ctloc(x)		(_CurrentTimeLocale->x) */

/*
 * We do not implement alternate representations. However, we always
 * check whether a given modifier is allowed for a certain conversion.
 */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ _ALT_E			0x01
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ _ALT_O			0x02
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	_LEGAL_ALT(x)		{ ਜੇ (alt_format & ~(x)) ਵਾਪਸ (0); }


ਸਥਿਰ	ਪੂਰਨ conv_ਅੰਕ(ਅਚਲ ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ **, ਪੂਰਨ *, ਪੂਰਨ, ਪੂਰਨ);
ਸਥਿਰ	ਅੱਖਰ *_strptime(ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *, ਬਣਤਰ tm *, ਪੂਰਨ);


ਅੱਖਰ *
strptime(ਅਚਲ ਅੱਖਰ *buf, ਅਚਲ ਅੱਖਰ *fmt, ਬਣਤਰ tm *tm)
{
	ਵਾਪਸ(_strptime(buf, fmt, tm, 1));
}

ਸਥਿਰ ਅੱਖਰ *
_strptime(ਅਚਲ ਅੱਖਰ *buf, ਅਚਲ ਅੱਖਰ *fmt, ਬਣਤਰ tm *tm, ਪੂਰਨ initialize)
{
	ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ c;
	ਅਚਲ ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *bp;
	ਮਾਪ_t len;
	ਪੂਰਨ alt_format, i;
	ਸਥਿਰ ਪੂਰਨ century, relyear;

	ਜੇ (initialize) {
		century = TM_YEAR_ਅਧਾਰ;
		relyear = -1;
	}

	bp = (ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *)buf;
	ਜਦੋਂ ((c = *fmt) != '\0') {
		/* Clear `alternate' modifier prior to new conversion. */
		alt_format = 0;

		/* Eat up white-space. */
		ਜੇ (ਖਾਲੀ_ਥਾਂ_ਹੈ(c)) {
			ਜਦੋਂ (ਖਾਲੀ_ਥਾਂ_ਹੈ(*bp))
				bp++;

			fmt++;
			ਜਾਰੀ;
		}
				
		ਜੇ ((c = *fmt++) != '%')
			ਜਾਓ literal;


again:		ਚੋਣ (c = *fmt++) {
		ਹਾਲਤ '%':	/* "%%" is converted to "%". */
literal:
		ਜੇ (c != *bp++)
			ਵਾਪਸ (ਨਿਰਾ);

		ਰੋਕੋ;

		/*
		 * "Alternative" modifiers. Just set the appropriate flag
		 * and start over again.
		 */
		ਹਾਲਤ 'E':	/* "%E?" alternative conversion modifier. */
			_LEGAL_ALT(0);
			alt_format |= _ALT_E;
			ਜਾਓ again;

		ਹਾਲਤ 'O':	/* "%O?" alternative conversion modifier. */
			_LEGAL_ALT(0);
			alt_format |= _ALT_O;
			ਜਾਓ again;
			
		/*
		 * "Complex" conversion rules, implemented through recursion.
		 */
#ਜੇ 0
		ਹਾਲਤ 'c':	/* Date and time, using the locale's format. */
			_LEGAL_ALT(_ALT_E);
			ਜੇ (!(bp = _strptime(bp, _ctloc(d_t_fmt), tm, 0)))
				ਵਾਪਸ (ਨਿਰਾ);
			ਰੋਕੋ;
#ਜੇ_ਅੰਤ
		ਹਾਲਤ 'D':	/* The date as "%m/%d/%y". */
			_LEGAL_ALT(0);
			ਜੇ (!(bp = _strptime(bp, "%m/%d/%y", tm, 0)))
				ਵਾਪਸ (ਨਿਰਾ);
			ਰੋਕੋ;
	
		ਹਾਲਤ 'R':	/* The time as "%H:%M". */
			_LEGAL_ALT(0);
			ਜੇ (!(bp = _strptime(bp, "%H:%M", tm, 0)))
				ਵਾਪਸ (ਨਿਰਾ);
			ਰੋਕੋ;

		ਹਾਲਤ 'r':	/* The time as "%I:%M:%S %p". */
			_LEGAL_ALT(0);
			ਜੇ (!(bp = _strptime(bp, "%I:%M:%S %p", tm, 0)))
				ਵਾਪਸ (ਨਿਰਾ);
			ਰੋਕੋ;

		ਹਾਲਤ 'T':	/* The time as "%H:%M:%S". */
			_LEGAL_ALT(0);
			ਜੇ (!(bp = _strptime(bp, "%H:%M:%S", tm, 0)))
				ਵਾਪਸ (ਨਿਰਾ);
			ਰੋਕੋ;
#ਜੇ 0
		ਹਾਲਤ 'X':	/* The time, using the locale's format. */
			_LEGAL_ALT(_ALT_E);
			ਜੇ (!(bp = _strptime(bp, _ctloc(t_fmt), tm, 0)))
				ਵਾਪਸ (ਨਿਰਾ);
			ਰੋਕੋ;

		ਹਾਲਤ 'x':	/* The date, using the locale's format. */
			_LEGAL_ALT(_ALT_E);
			ਜੇ (!(bp = _strptime(bp, _ctloc(d_fmt), tm, 0)))
				ਵਾਪਸ (ਨਿਰਾ);
			ਰੋਕੋ;
#ਜੇ_ਅੰਤ
		/*
		 * "Elementary" conversion rules.
		 */
#ਜੇ 0
		ਹਾਲਤ 'A':	/* The day of week, using the locale's form. */
		ਹਾਲਤ 'a':
			_LEGAL_ALT(0);
			ਲਈ (i = 0; i < 7; i++) {
				/* Full name. */
				len = ਲੜੀ_ਲੰਬਾਈ(_ctloc(day[i]));
				ਜੇ (strncasecmp(_ctloc(day[i]), bp, len) == 0)
					ਰੋਕੋ;

				/* Abbreviated name. */
				len = ਲੜੀ_ਲੰਬਾਈ(_ctloc(abday[i]));
				ਜੇ (strncasecmp(_ctloc(abday[i]), bp, len) == 0)
					ਰੋਕੋ;
			}

			/* Nothing matched. */
			ਜੇ (i == 7)
				ਵਾਪਸ (ਨਿਰਾ);

			tm->tm_wday = i;
			bp += len;
			ਰੋਕੋ;

		ਹਾਲਤ 'B':	/* The month, using the locale's form. */
		ਹਾਲਤ 'b':
		ਹਾਲਤ 'h':
			_LEGAL_ALT(0);
			ਲਈ (i = 0; i < 12; i++) {
				/* Full name. */
				len = ਲੜੀ_ਲੰਬਾਈ(_ctloc(mon[i]));
				ਜੇ (strncasecmp(_ctloc(mon[i]), bp, len) == 0)
					ਰੋਕੋ;

				/* Abbreviated name. */
				len = ਲੜੀ_ਲੰਬਾਈ(_ctloc(abmon[i]));
				ਜੇ (strncasecmp(_ctloc(abmon[i]), bp, len) == 0)
					ਰੋਕੋ;
			}

			/* Nothing matched. */
			ਜੇ (i == 12)
				ਵਾਪਸ (ਨਿਰਾ);

			tm->tm_mon = i;
			bp += len;
			ਰੋਕੋ;
#ਜੇ_ਅੰਤ

		ਹਾਲਤ 'C':	/* The century number. */
			_LEGAL_ALT(_ALT_E);
			ਜੇ (!(conv_ਅੰਕ(&bp, &i, 0, 99)))
				ਵਾਪਸ (ਨਿਰਾ);

			century = i * 100;
			ਰੋਕੋ;

		ਹਾਲਤ 'd':	/* The day of month. */
		ਹਾਲਤ 'e':
			_LEGAL_ALT(_ALT_O);
			ਜੇ (!(conv_ਅੰਕ(&bp, &tm->tm_mday, 1, 31)))
				ਵਾਪਸ (ਨਿਰਾ);
			ਰੋਕੋ;

		ਹਾਲਤ 'k':	/* The hour (24-hour clock representation). */
			_LEGAL_ALT(0);
			/* FALLTHROUGH */
		ਹਾਲਤ 'H':
			_LEGAL_ALT(_ALT_O);
			ਜੇ (!(conv_ਅੰਕ(&bp, &tm->tm_hour, 0, 23)))
				ਵਾਪਸ (ਨਿਰਾ);
			ਰੋਕੋ;

		ਹਾਲਤ 'l':	/* The hour (12-hour clock representation). */
			_LEGAL_ALT(0);
			/* FALLTHROUGH */
		ਹਾਲਤ 'I':
			_LEGAL_ALT(_ALT_O);
			ਜੇ (!(conv_ਅੰਕ(&bp, &tm->tm_hour, 1, 12)))
				ਵਾਪਸ (ਨਿਰਾ);
			ਰੋਕੋ;

		ਹਾਲਤ 'j':	/* The day of year. */
			_LEGAL_ALT(0);
			ਜੇ (!(conv_ਅੰਕ(&bp, &tm->tm_yday, 1, 366)))
				ਵਾਪਸ (ਨਿਰਾ);
			tm->tm_yday--;
			ਰੋਕੋ;

		ਹਾਲਤ 'M':	/* The minute. */
			_LEGAL_ALT(_ALT_O);
			ਜੇ (!(conv_ਅੰਕ(&bp, &tm->tm_min, 0, 59)))
				ਵਾਪਸ (ਨਿਰਾ);
			ਰੋਕੋ;

		ਹਾਲਤ 'm':	/* The month. */
			_LEGAL_ALT(_ALT_O);
			ਜੇ (!(conv_ਅੰਕ(&bp, &tm->tm_mon, 1, 12)))
				ਵਾਪਸ (ਨਿਰਾ);
			tm->tm_mon--;
			ਰੋਕੋ;

#ਜੇ 0
		ਹਾਲਤ 'p':	/* The locale's equivalent of AM/PM. */
			_LEGAL_ALT(0);
			/* AM? */
			len = ਲੜੀ_ਲੰਬਾਈ(_ctloc(am_pm[0]));
			ਜੇ (strncasecmp(_ctloc(am_pm[0]), bp, len) == 0) {
				ਜੇ (tm->tm_hour > 12)	/* i.e., 13:00 AM ?! */
					ਵਾਪਸ (ਨਿਰਾ);
				ਨਹੀਂਤਾਂ ਜੇ (tm->tm_hour == 12)
					tm->tm_hour = 0;

				bp += len;
				ਰੋਕੋ;
			}
			/* PM? */
			len = ਲੜੀ_ਲੰਬਾਈ(_ctloc(am_pm[1]));
			ਜੇ (strncasecmp(_ctloc(am_pm[1]), bp, len) == 0) {
				ਜੇ (tm->tm_hour > 12)	/* i.e., 13:00 PM ?! */
					ਵਾਪਸ (ਨਿਰਾ);
				ਨਹੀਂਤਾਂ ਜੇ (tm->tm_hour < 12)
					tm->tm_hour += 12;

				bp += len;
				ਰੋਕੋ;
			}

			/* Nothing matched. */
			ਵਾਪਸ (ਨਿਰਾ);
#ਜੇ_ਅੰਤ
		ਹਾਲਤ 'S':	/* The seconds. */
			_LEGAL_ALT(_ALT_O);
			ਜੇ (!(conv_ਅੰਕ(&bp, &tm->tm_sec, 0, 61)))
				ਵਾਪਸ (ਨਿਰਾ);
			ਰੋਕੋ;

		ਹਾਲਤ 'U':	/* The week of year, beginning on sunday. */
		ਹਾਲਤ 'W':	/* The week of year, beginning on monday. */
			_LEGAL_ALT(_ALT_O);
			/*
			 * XXX This is bogus, as we can not assume any valid
			 * information present in the tm structure at this
			 * point to calculate a real value, so just check the
			 * range for now.
			 */
			 ਜੇ (!(conv_ਅੰਕ(&bp, &i, 0, 53)))
				ਵਾਪਸ (ਨਿਰਾ);
			 ਰੋਕੋ;

		ਹਾਲਤ 'w':	/* The day of week, beginning on sunday. */
			_LEGAL_ALT(_ALT_O);
			ਜੇ (!(conv_ਅੰਕ(&bp, &tm->tm_wday, 0, 6)))
				ਵਾਪਸ (ਨਿਰਾ);
			ਰੋਕੋ;

		ਹਾਲਤ 'Y':	/* The year. */
			_LEGAL_ALT(_ALT_E);
			ਜੇ (!(conv_ਅੰਕ(&bp, &i, 0, 9999)))
				ਵਾਪਸ (ਨਿਰਾ);

			relyear = -1;
			tm->tm_year = i - TM_YEAR_ਅਧਾਰ;
			ਰੋਕੋ;

		ਹਾਲਤ 'y':	/* The year within the century (2 digits). */
			_LEGAL_ALT(_ALT_E | _ALT_O);
			ਜੇ (!(conv_ਅੰਕ(&bp, &relyear, 0, 99)))
				ਵਾਪਸ (ਨਿਰਾ);
			ਰੋਕੋ;

		/*
		 * Miscellaneous conversions.
		 */
		ਹਾਲਤ 'n':	/* Any kind of white-space. */
		ਹਾਲਤ 't':
			_LEGAL_ALT(0);
			ਜਦੋਂ (ਖਾਲੀ_ਥਾਂ_ਹੈ(*bp))
				bp++;
			ਰੋਕੋ;


		ਮੂਲ:	/* Unknown/unsupported conversion. */
			ਵਾਪਸ (ਨਿਰਾ);
		}


	}

	/*
	 * We need to evaluate the two digit year spec (%y)
	 * last as we can get a century spec (%C) at any time.
	 */
	ਜੇ (relyear != -1) {
		ਜੇ (century == TM_YEAR_ਅਧਾਰ) {
			ਜੇ (relyear <= 68)
				tm->tm_year = relyear + 2000 - TM_YEAR_ਅਧਾਰ;
			ਨਹੀਂਤਾਂ
				tm->tm_year = relyear + 1900 - TM_YEAR_ਅਧਾਰ;
		} ਨਹੀਂਤਾਂ {
			tm->tm_year = relyear + century - TM_YEAR_ਅਧਾਰ;
		}
	}

	ਵਾਪਸ ((ਅੱਖਰ *)bp);
}


ਸਥਿਰ ਪੂਰਨ
conv_ਅੰਕ(ਅਚਲ ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ **buf, ਪੂਰਨ *dest, ਪੂਰਨ llim, ਪੂਰਨ ulim)
{
	ਪੂਰਨ ਨਤੀਜਾ = 0;
	ਪੂਰਨ rulim = ulim;

	ਜੇ (**buf < '0' || **buf > '9')
		ਵਾਪਸ (0);

	/* we use rulim to break out of the loop when we run out of digits */
	ਕਰੋ {
		ਨਤੀਜਾ *= 10;
		ਨਤੀਜਾ += *(*buf)++ - '0';
		rulim /= 10;
	} ਜਦੋਂ ((ਨਤੀਜਾ * 10 <= ulim) && rulim && **buf >= '0' && **buf <= '9');

	ਜੇ (ਨਤੀਜਾ < llim || ਨਤੀਜਾ > ulim)
		ਵਾਪਸ (0);

	*dest = ਨਤੀਜਾ;
	ਵਾਪਸ (1);
}

#ਜੇ_ਅੰਤ /* HAVE_STRPTIME */

