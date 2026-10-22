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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ifndef HAVE_STRPTIME

#define TM_YEAR_BASE 1900	/* from tzfile.h */

#ଅନ୍ତର୍ଭାଵ <ctype.h>
#ଅନ୍ତର୍ଭାଵ <locale.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <time.h>

/* #define	_ctloc(x)		(_CurrentTimeLocale->x) */

/*
 * We do not implement alternate representations. However, we always
 * check whether a given modifier is allowed for a certain conversion.
 */
#define _ALT_E			0x01
#define _ALT_O			0x02
#define	_LEGAL_ALT(x)		{ ଯଦି (alt_format & ~(x)) ଫେରନ୍ତୁ (0); }


ସ୍ଥିର	ପୂର୍ଣ୍ଣସଂଖ୍ୟା conv_ଅଙ୍କ(ଅଚଳ unsigned ଅକ୍ଷର **, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
ସ୍ଥିର	ଅକ୍ଷର *_strptime(ଅଚଳ ଅକ୍ଷର *, ଅଚଳ ଅକ୍ଷର *, ସଂରଚନା tm *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା);


ଅକ୍ଷର *
strptime(ଅଚଳ ଅକ୍ଷର *buf, ଅଚଳ ଅକ୍ଷର *fmt, ସଂରଚନା tm *tm)
{
	ଫେରନ୍ତୁ(_strptime(buf, fmt, tm, 1));
}

ସ୍ଥିର ଅକ୍ଷର *
_strptime(ଅଚଳ ଅକ୍ଷର *buf, ଅଚଳ ଅକ୍ଷର *fmt, ସଂରଚନା tm *tm, ପୂର୍ଣ୍ଣସଂଖ୍ୟା initialize)
{
	unsigned ଅକ୍ଷର c;
	ଅଚଳ unsigned ଅକ୍ଷର *bp;
	size_t len;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା alt_format, i;
	ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା century, relyear;

	ଯଦି (initialize) {
		century = TM_YEAR_BASE;
		relyear = -1;
	}

	bp = (unsigned ଅକ୍ଷର *)buf;
	ଯେତେବେଳେ ((c = *fmt) != '\0') {
		/* Clear `alternate' modifier prior to new conversion. */
		alt_format = 0;

		/* Eat up white-space. */
		ଯଦି (isspace(c)) {
			ଯେତେବେଳେ (isspace(*bp))
				bp++;

			fmt++;
			ଜାରି;
		}
				
		ଯଦି ((c = *fmt++) != '%')
			ଯାଅ literal;


again:		ବାଛ (c = *fmt++) {
		ସ୍ଥିତି '%':	/* "%%" is converted to "%". */
literal:
		ଯଦି (c != *bp++)
			ଫେରନ୍ତୁ (ଖାଲି);

		ଭାଙ୍ଗ;

		/*
		 * "Alternative" modifiers. Just set the appropriate flag
		 * and start over again.
		 */
		ସ୍ଥିତି 'E':	/* "%E?" alternative conversion modifier. */
			_LEGAL_ALT(0);
			alt_format |= _ALT_E;
			ଯାଅ again;

		ସ୍ଥିତି 'O':	/* "%O?" alternative conversion modifier. */
			_LEGAL_ALT(0);
			alt_format |= _ALT_O;
			ଯାଅ again;
			
		/*
		 * "Complex" conversion rules, implemented through recursion.
		 */
#ଯଦି 0
		ସ୍ଥିତି 'c':	/* Date and time, using the locale's format. */
			_LEGAL_ALT(_ALT_E);
			ଯଦି (!(bp = _strptime(bp, _ctloc(d_t_fmt), tm, 0)))
				ଫେରନ୍ତୁ (ଖାଲି);
			ଭାଙ୍ଗ;
#endif
		ସ୍ଥିତି 'D':	/* The date as "%m/%d/%y". */
			_LEGAL_ALT(0);
			ଯଦି (!(bp = _strptime(bp, "%m/%d/%y", tm, 0)))
				ଫେରନ୍ତୁ (ଖାଲି);
			ଭାଙ୍ଗ;
	
		ସ୍ଥିତି 'R':	/* The time as "%H:%M". */
			_LEGAL_ALT(0);
			ଯଦି (!(bp = _strptime(bp, "%H:%M", tm, 0)))
				ଫେରନ୍ତୁ (ଖାଲି);
			ଭାଙ୍ଗ;

		ସ୍ଥିତି 'r':	/* The time as "%I:%M:%S %p". */
			_LEGAL_ALT(0);
			ଯଦି (!(bp = _strptime(bp, "%I:%M:%S %p", tm, 0)))
				ଫେରନ୍ତୁ (ଖାଲି);
			ଭାଙ୍ଗ;

		ସ୍ଥିତି 'T':	/* The time as "%H:%M:%S". */
			_LEGAL_ALT(0);
			ଯଦି (!(bp = _strptime(bp, "%H:%M:%S", tm, 0)))
				ଫେରନ୍ତୁ (ଖାଲି);
			ଭାଙ୍ଗ;
#ଯଦି 0
		ସ୍ଥିତି 'X':	/* The time, using the locale's format. */
			_LEGAL_ALT(_ALT_E);
			ଯଦି (!(bp = _strptime(bp, _ctloc(t_fmt), tm, 0)))
				ଫେରନ୍ତୁ (ଖାଲି);
			ଭାଙ୍ଗ;

		ସ୍ଥିତି 'x':	/* The date, using the locale's format. */
			_LEGAL_ALT(_ALT_E);
			ଯଦି (!(bp = _strptime(bp, _ctloc(d_fmt), tm, 0)))
				ଫେରନ୍ତୁ (ଖାଲି);
			ଭାଙ୍ଗ;
#endif
		/*
		 * "Elementary" conversion rules.
		 */
#ଯଦି 0
		ସ୍ଥିତି 'A':	/* The day of week, using the locale's form. */
		ସ୍ଥିତି 'a':
			_LEGAL_ALT(0);
			ପାଇଁ (i = 0; i < 7; i++) {
				/* Full name. */
				len = strlen(_ctloc(day[i]));
				ଯଦି (strncasecmp(_ctloc(day[i]), bp, len) == 0)
					ଭାଙ୍ଗ;

				/* Abbreviated name. */
				len = strlen(_ctloc(abday[i]));
				ଯଦି (strncasecmp(_ctloc(abday[i]), bp, len) == 0)
					ଭାଙ୍ଗ;
			}

			/* Nothing matched. */
			ଯଦି (i == 7)
				ଫେରନ୍ତୁ (ଖାଲି);

			tm->tm_wday = i;
			bp += len;
			ଭାଙ୍ଗ;

		ସ୍ଥିତି 'B':	/* The month, using the locale's form. */
		ସ୍ଥିତି 'b':
		ସ୍ଥିତି 'h':
			_LEGAL_ALT(0);
			ପାଇଁ (i = 0; i < 12; i++) {
				/* Full name. */
				len = strlen(_ctloc(mon[i]));
				ଯଦି (strncasecmp(_ctloc(mon[i]), bp, len) == 0)
					ଭାଙ୍ଗ;

				/* Abbreviated name. */
				len = strlen(_ctloc(abmon[i]));
				ଯଦି (strncasecmp(_ctloc(abmon[i]), bp, len) == 0)
					ଭାଙ୍ଗ;
			}

			/* Nothing matched. */
			ଯଦି (i == 12)
				ଫେରନ୍ତୁ (ଖାଲି);

			tm->tm_mon = i;
			bp += len;
			ଭାଙ୍ଗ;
#endif

		ସ୍ଥିତି 'C':	/* The century number. */
			_LEGAL_ALT(_ALT_E);
			ଯଦି (!(conv_ଅଙ୍କ(&bp, &i, 0, 99)))
				ଫେରନ୍ତୁ (ଖାଲି);

			century = i * 100;
			ଭାଙ୍ଗ;

		ସ୍ଥିତି 'd':	/* The day of month. */
		ସ୍ଥିତି 'e':
			_LEGAL_ALT(_ALT_O);
			ଯଦି (!(conv_ଅଙ୍କ(&bp, &tm->tm_mday, 1, 31)))
				ଫେରନ୍ତୁ (ଖାଲି);
			ଭାଙ୍ଗ;

		ସ୍ଥିତି 'k':	/* The hour (24-hour clock representation). */
			_LEGAL_ALT(0);
			/* FALLTHROUGH */
		ସ୍ଥିତି 'H':
			_LEGAL_ALT(_ALT_O);
			ଯଦି (!(conv_ଅଙ୍କ(&bp, &tm->tm_hour, 0, 23)))
				ଫେରନ୍ତୁ (ଖାଲି);
			ଭାଙ୍ଗ;

		ସ୍ଥିତି 'l':	/* The hour (12-hour clock representation). */
			_LEGAL_ALT(0);
			/* FALLTHROUGH */
		ସ୍ଥିତି 'I':
			_LEGAL_ALT(_ALT_O);
			ଯଦି (!(conv_ଅଙ୍କ(&bp, &tm->tm_hour, 1, 12)))
				ଫେରନ୍ତୁ (ଖାଲି);
			ଭାଙ୍ଗ;

		ସ୍ଥିତି 'j':	/* The day of year. */
			_LEGAL_ALT(0);
			ଯଦି (!(conv_ଅଙ୍କ(&bp, &tm->tm_yday, 1, 366)))
				ଫେରନ୍ତୁ (ଖାଲି);
			tm->tm_yday--;
			ଭାଙ୍ଗ;

		ସ୍ଥିତି 'M':	/* The minute. */
			_LEGAL_ALT(_ALT_O);
			ଯଦି (!(conv_ଅଙ୍କ(&bp, &tm->tm_min, 0, 59)))
				ଫେରନ୍ତୁ (ଖାଲି);
			ଭାଙ୍ଗ;

		ସ୍ଥିତି 'm':	/* The month. */
			_LEGAL_ALT(_ALT_O);
			ଯଦି (!(conv_ଅଙ୍କ(&bp, &tm->tm_mon, 1, 12)))
				ଫେରନ୍ତୁ (ଖାଲି);
			tm->tm_mon--;
			ଭାଙ୍ଗ;

#ଯଦି 0
		ସ୍ଥିତି 'p':	/* The locale's equivalent of AM/PM. */
			_LEGAL_ALT(0);
			/* AM? */
			len = strlen(_ctloc(am_pm[0]));
			ଯଦି (strncasecmp(_ctloc(am_pm[0]), bp, len) == 0) {
				ଯଦି (tm->tm_hour > 12)	/* i.e., 13:00 AM ?! */
					ଫେରନ୍ତୁ (ଖାଲି);
				ଅନ୍ୟଥା ଯଦି (tm->tm_hour == 12)
					tm->tm_hour = 0;

				bp += len;
				ଭାଙ୍ଗ;
			}
			/* PM? */
			len = strlen(_ctloc(am_pm[1]));
			ଯଦି (strncasecmp(_ctloc(am_pm[1]), bp, len) == 0) {
				ଯଦି (tm->tm_hour > 12)	/* i.e., 13:00 PM ?! */
					ଫେରନ୍ତୁ (ଖାଲି);
				ଅନ୍ୟଥା ଯଦି (tm->tm_hour < 12)
					tm->tm_hour += 12;

				bp += len;
				ଭାଙ୍ଗ;
			}

			/* Nothing matched. */
			ଫେରନ୍ତୁ (ଖାଲି);
#endif
		ସ୍ଥିତି 'S':	/* The seconds. */
			_LEGAL_ALT(_ALT_O);
			ଯଦି (!(conv_ଅଙ୍କ(&bp, &tm->tm_sec, 0, 61)))
				ଫେରନ୍ତୁ (ଖାଲି);
			ଭାଙ୍ଗ;

		ସ୍ଥିତି 'U':	/* The week of year, beginning on sunday. */
		ସ୍ଥିତି 'W':	/* The week of year, beginning on monday. */
			_LEGAL_ALT(_ALT_O);
			/*
			 * XXX This is bogus, as we can not assume any valid
			 * information present in the tm structure at this
			 * point to calculate a real value, so just check the
			 * range for now.
			 */
			 ଯଦି (!(conv_ଅଙ୍କ(&bp, &i, 0, 53)))
				ଫେରନ୍ତୁ (ଖାଲି);
			 ଭାଙ୍ଗ;

		ସ୍ଥିତି 'w':	/* The day of week, beginning on sunday. */
			_LEGAL_ALT(_ALT_O);
			ଯଦି (!(conv_ଅଙ୍କ(&bp, &tm->tm_wday, 0, 6)))
				ଫେରନ୍ତୁ (ଖାଲି);
			ଭାଙ୍ଗ;

		ସ୍ଥିତି 'Y':	/* The year. */
			_LEGAL_ALT(_ALT_E);
			ଯଦି (!(conv_ଅଙ୍କ(&bp, &i, 0, 9999)))
				ଫେରନ୍ତୁ (ଖାଲି);

			relyear = -1;
			tm->tm_year = i - TM_YEAR_BASE;
			ଭାଙ୍ଗ;

		ସ୍ଥିତି 'y':	/* The year within the century (2 digits). */
			_LEGAL_ALT(_ALT_E | _ALT_O);
			ଯଦି (!(conv_ଅଙ୍କ(&bp, &relyear, 0, 99)))
				ଫେରନ୍ତୁ (ଖାଲି);
			ଭାଙ୍ଗ;

		/*
		 * Miscellaneous conversions.
		 */
		ସ୍ଥିତି 'n':	/* Any kind of white-space. */
		ସ୍ଥିତି 't':
			_LEGAL_ALT(0);
			ଯେତେବେଳେ (isspace(*bp))
				bp++;
			ଭାଙ୍ଗ;


		ପୂର୍ବନିର୍ଦ୍ଧାରିତ:	/* Unknown/unsupported conversion. */
			ଫେରନ୍ତୁ (ଖାଲି);
		}


	}

	/*
	 * We need to evaluate the two digit year spec (%y)
	 * last as we can get a century spec (%C) at any time.
	 */
	ଯଦି (relyear != -1) {
		ଯଦି (century == TM_YEAR_BASE) {
			ଯଦି (relyear <= 68)
				tm->tm_year = relyear + 2000 - TM_YEAR_BASE;
			ଅନ୍ୟଥା
				tm->tm_year = relyear + 1900 - TM_YEAR_BASE;
		} ଅନ୍ୟଥା {
			tm->tm_year = relyear + century - TM_YEAR_BASE;
		}
	}

	ଫେରନ୍ତୁ ((ଅକ୍ଷର *)bp);
}


ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
conv_ଅଙ୍କ(ଅଚଳ unsigned ଅକ୍ଷର **buf, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *dest, ପୂର୍ଣ୍ଣସଂଖ୍ୟା llim, ପୂର୍ଣ୍ଣସଂଖ୍ୟା ulim)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା result = 0;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା rulim = ulim;

	ଯଦି (**buf < '0' || **buf > '9')
		ଫେରନ୍ତୁ (0);

	/* we use rulim to break out of the loop when we run out of digits */
	କର {
		result *= 10;
		result += *(*buf)++ - '0';
		rulim /= 10;
	} ଯେତେବେଳେ ((result * 10 <= ulim) && rulim && **buf >= '0' && **buf <= '9');

	ଯଦି (result < llim || result > ulim)
		ଫେରନ୍ତୁ (0);

	*dest = result;
	ଫେରନ୍ତୁ (1);
}

#endif /* HAVE_STRPTIME */

