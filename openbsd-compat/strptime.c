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

#அந்தர்பாவ "includes.h"

#ifndef HAVE_STRPTIME

#define TM_YEAR_BASE 1900	/* from tzfile.h */

#அந்தர்பாவ <ctype.h>
#அந்தர்பாவ <locale.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <time.h>

/* #define	_ctloc(x)		(_CurrentTimeLocale->x) */

/*
 * We do not implement alternate representations. However, we always
 * check whether a given modifier is allowed for a certain conversion.
 */
#define _ALT_E			0x01
#define _ALT_O			0x02
#define	_LEGAL_ALT(x)		{ எனில் (alt_format & ~(x)) திரும்பு (0); }


நிலையான	முழு conv_இலக்கம்(மாறிலி unsigned எழுத்து **, முழு *, முழு, முழு);
நிலையான	எழுத்து *_strptime(மாறிலி எழுத்து *, மாறிலி எழுத்து *, கட்டமைப்பு tm *, முழு);


எழுத்து *
strptime(மாறிலி எழுத்து *buf, மாறிலி எழுத்து *fmt, கட்டமைப்பு tm *tm)
{
	திரும்பு(_strptime(buf, fmt, tm, 1));
}

நிலையான எழுத்து *
_strptime(மாறிலி எழுத்து *buf, மாறிலி எழுத்து *fmt, கட்டமைப்பு tm *tm, முழு initialize)
{
	unsigned எழுத்து c;
	மாறிலி unsigned எழுத்து *bp;
	size_t len;
	முழு alt_format, i;
	நிலையான முழு century, relyear;

	எனில் (initialize) {
		century = TM_YEAR_BASE;
		relyear = -1;
	}

	bp = (unsigned எழுத்து *)buf;
	போது ((c = *fmt) != '\0') {
		/* Clear `alternate' modifier prior to new conversion. */
		alt_format = 0;

		/* Eat up white-space. */
		எனில் (isspace(c)) {
			போது (isspace(*bp))
				bp++;

			fmt++;
			தொடர்;
		}
				
		எனில் ((c = *fmt++) != '%')
			செல் literal;


again:		தேர்வு (c = *fmt++) {
		நிலை '%':	/* "%%" is converted to "%". */
literal:
		எனில் (c != *bp++)
			திரும்பு (வெற்று);

		நிறுத்து;

		/*
		 * "Alternative" modifiers. Just set the appropriate flag
		 * and start over again.
		 */
		நிலை 'E':	/* "%E?" alternative conversion modifier. */
			_LEGAL_ALT(0);
			alt_format |= _ALT_E;
			செல் again;

		நிலை 'O':	/* "%O?" alternative conversion modifier. */
			_LEGAL_ALT(0);
			alt_format |= _ALT_O;
			செல் again;
			
		/*
		 * "Complex" conversion rules, implemented through recursion.
		 */
#எனில் 0
		நிலை 'c':	/* Date and time, using the locale's format. */
			_LEGAL_ALT(_ALT_E);
			எனில் (!(bp = _strptime(bp, _ctloc(d_t_fmt), tm, 0)))
				திரும்பு (வெற்று);
			நிறுத்து;
#endif
		நிலை 'D':	/* The date as "%m/%d/%y". */
			_LEGAL_ALT(0);
			எனில் (!(bp = _strptime(bp, "%m/%d/%y", tm, 0)))
				திரும்பு (வெற்று);
			நிறுத்து;
	
		நிலை 'R':	/* The time as "%H:%M". */
			_LEGAL_ALT(0);
			எனில் (!(bp = _strptime(bp, "%H:%M", tm, 0)))
				திரும்பு (வெற்று);
			நிறுத்து;

		நிலை 'r':	/* The time as "%I:%M:%S %p". */
			_LEGAL_ALT(0);
			எனில் (!(bp = _strptime(bp, "%I:%M:%S %p", tm, 0)))
				திரும்பு (வெற்று);
			நிறுத்து;

		நிலை 'T':	/* The time as "%H:%M:%S". */
			_LEGAL_ALT(0);
			எனில் (!(bp = _strptime(bp, "%H:%M:%S", tm, 0)))
				திரும்பு (வெற்று);
			நிறுத்து;
#எனில் 0
		நிலை 'X':	/* The time, using the locale's format. */
			_LEGAL_ALT(_ALT_E);
			எனில் (!(bp = _strptime(bp, _ctloc(t_fmt), tm, 0)))
				திரும்பு (வெற்று);
			நிறுத்து;

		நிலை 'x':	/* The date, using the locale's format. */
			_LEGAL_ALT(_ALT_E);
			எனில் (!(bp = _strptime(bp, _ctloc(d_fmt), tm, 0)))
				திரும்பு (வெற்று);
			நிறுத்து;
#endif
		/*
		 * "Elementary" conversion rules.
		 */
#எனில் 0
		நிலை 'A':	/* The day of week, using the locale's form. */
		நிலை 'a':
			_LEGAL_ALT(0);
			க்கு (i = 0; i < 7; i++) {
				/* Full name. */
				len = strlen(_ctloc(day[i]));
				எனில் (strncasecmp(_ctloc(day[i]), bp, len) == 0)
					நிறுத்து;

				/* Abbreviated name. */
				len = strlen(_ctloc(abday[i]));
				எனில் (strncasecmp(_ctloc(abday[i]), bp, len) == 0)
					நிறுத்து;
			}

			/* Nothing matched. */
			எனில் (i == 7)
				திரும்பு (வெற்று);

			tm->tm_wday = i;
			bp += len;
			நிறுத்து;

		நிலை 'B':	/* The month, using the locale's form. */
		நிலை 'b':
		நிலை 'h':
			_LEGAL_ALT(0);
			க்கு (i = 0; i < 12; i++) {
				/* Full name. */
				len = strlen(_ctloc(mon[i]));
				எனில் (strncasecmp(_ctloc(mon[i]), bp, len) == 0)
					நிறுத்து;

				/* Abbreviated name. */
				len = strlen(_ctloc(abmon[i]));
				எனில் (strncasecmp(_ctloc(abmon[i]), bp, len) == 0)
					நிறுத்து;
			}

			/* Nothing matched. */
			எனில் (i == 12)
				திரும்பு (வெற்று);

			tm->tm_mon = i;
			bp += len;
			நிறுத்து;
#endif

		நிலை 'C':	/* The century number. */
			_LEGAL_ALT(_ALT_E);
			எனில் (!(conv_இலக்கம்(&bp, &i, 0, 99)))
				திரும்பு (வெற்று);

			century = i * 100;
			நிறுத்து;

		நிலை 'd':	/* The day of month. */
		நிலை 'e':
			_LEGAL_ALT(_ALT_O);
			எனில் (!(conv_இலக்கம்(&bp, &tm->tm_mday, 1, 31)))
				திரும்பு (வெற்று);
			நிறுத்து;

		நிலை 'k':	/* The hour (24-hour clock representation). */
			_LEGAL_ALT(0);
			/* FALLTHROUGH */
		நிலை 'H':
			_LEGAL_ALT(_ALT_O);
			எனில் (!(conv_இலக்கம்(&bp, &tm->tm_hour, 0, 23)))
				திரும்பு (வெற்று);
			நிறுத்து;

		நிலை 'l':	/* The hour (12-hour clock representation). */
			_LEGAL_ALT(0);
			/* FALLTHROUGH */
		நிலை 'I':
			_LEGAL_ALT(_ALT_O);
			எனில் (!(conv_இலக்கம்(&bp, &tm->tm_hour, 1, 12)))
				திரும்பு (வெற்று);
			நிறுத்து;

		நிலை 'j':	/* The day of year. */
			_LEGAL_ALT(0);
			எனில் (!(conv_இலக்கம்(&bp, &tm->tm_yday, 1, 366)))
				திரும்பு (வெற்று);
			tm->tm_yday--;
			நிறுத்து;

		நிலை 'M':	/* The minute. */
			_LEGAL_ALT(_ALT_O);
			எனில் (!(conv_இலக்கம்(&bp, &tm->tm_min, 0, 59)))
				திரும்பு (வெற்று);
			நிறுத்து;

		நிலை 'm':	/* The month. */
			_LEGAL_ALT(_ALT_O);
			எனில் (!(conv_இலக்கம்(&bp, &tm->tm_mon, 1, 12)))
				திரும்பு (வெற்று);
			tm->tm_mon--;
			நிறுத்து;

#எனில் 0
		நிலை 'p':	/* The locale's equivalent of AM/PM. */
			_LEGAL_ALT(0);
			/* AM? */
			len = strlen(_ctloc(am_pm[0]));
			எனில் (strncasecmp(_ctloc(am_pm[0]), bp, len) == 0) {
				எனில் (tm->tm_hour > 12)	/* i.e., 13:00 AM ?! */
					திரும்பு (வெற்று);
				இல்லையெனில் எனில் (tm->tm_hour == 12)
					tm->tm_hour = 0;

				bp += len;
				நிறுத்து;
			}
			/* PM? */
			len = strlen(_ctloc(am_pm[1]));
			எனில் (strncasecmp(_ctloc(am_pm[1]), bp, len) == 0) {
				எனில் (tm->tm_hour > 12)	/* i.e., 13:00 PM ?! */
					திரும்பு (வெற்று);
				இல்லையெனில் எனில் (tm->tm_hour < 12)
					tm->tm_hour += 12;

				bp += len;
				நிறுத்து;
			}

			/* Nothing matched. */
			திரும்பு (வெற்று);
#endif
		நிலை 'S':	/* The seconds. */
			_LEGAL_ALT(_ALT_O);
			எனில் (!(conv_இலக்கம்(&bp, &tm->tm_sec, 0, 61)))
				திரும்பு (வெற்று);
			நிறுத்து;

		நிலை 'U':	/* The week of year, beginning on sunday. */
		நிலை 'W':	/* The week of year, beginning on monday. */
			_LEGAL_ALT(_ALT_O);
			/*
			 * XXX This is bogus, as we can not assume any valid
			 * information present in the tm structure at this
			 * point to calculate a real value, so just check the
			 * range for now.
			 */
			 எனில் (!(conv_இலக்கம்(&bp, &i, 0, 53)))
				திரும்பு (வெற்று);
			 நிறுத்து;

		நிலை 'w':	/* The day of week, beginning on sunday. */
			_LEGAL_ALT(_ALT_O);
			எனில் (!(conv_இலக்கம்(&bp, &tm->tm_wday, 0, 6)))
				திரும்பு (வெற்று);
			நிறுத்து;

		நிலை 'Y':	/* The year. */
			_LEGAL_ALT(_ALT_E);
			எனில் (!(conv_இலக்கம்(&bp, &i, 0, 9999)))
				திரும்பு (வெற்று);

			relyear = -1;
			tm->tm_year = i - TM_YEAR_BASE;
			நிறுத்து;

		நிலை 'y':	/* The year within the century (2 digits). */
			_LEGAL_ALT(_ALT_E | _ALT_O);
			எனில் (!(conv_இலக்கம்(&bp, &relyear, 0, 99)))
				திரும்பு (வெற்று);
			நிறுத்து;

		/*
		 * Miscellaneous conversions.
		 */
		நிலை 'n':	/* Any kind of white-space. */
		நிலை 't':
			_LEGAL_ALT(0);
			போது (isspace(*bp))
				bp++;
			நிறுத்து;


		இயல்பு:	/* Unknown/unsupported conversion. */
			திரும்பு (வெற்று);
		}


	}

	/*
	 * We need to evaluate the two digit year spec (%y)
	 * last as we can get a century spec (%C) at any time.
	 */
	எனில் (relyear != -1) {
		எனில் (century == TM_YEAR_BASE) {
			எனில் (relyear <= 68)
				tm->tm_year = relyear + 2000 - TM_YEAR_BASE;
			இல்லையெனில்
				tm->tm_year = relyear + 1900 - TM_YEAR_BASE;
		} இல்லையெனில் {
			tm->tm_year = relyear + century - TM_YEAR_BASE;
		}
	}

	திரும்பு ((எழுத்து *)bp);
}


நிலையான முழு
conv_இலக்கம்(மாறிலி unsigned எழுத்து **buf, முழு *dest, முழு llim, முழு ulim)
{
	முழு result = 0;
	முழு rulim = ulim;

	எனில் (**buf < '0' || **buf > '9')
		திரும்பு (0);

	/* we use rulim to break out of the loop when we run out of digits */
	செய் {
		result *= 10;
		result += *(*buf)++ - '0';
		rulim /= 10;
	} போது ((result * 10 <= ulim) && rulim && **buf >= '0' && **buf <= '9');

	எனில் (result < llim || result > ulim)
		திரும்பு (0);

	*dest = result;
	திரும்பு (1);
}

#endif /* HAVE_STRPTIME */

