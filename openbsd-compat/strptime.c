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

#అన్తర్భావ "includes.h"

#నిర్వచితం_కాకపోతే HAVE_STRPTIME

#నిర్వచించు TM_YEAR_పునాది 1900	/* from tzfile.h */

#అన్తర్భావ <ctype.h>
#అన్తర్భావ <locale.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <time.h>

/* #define	_ctloc(x)		(_CurrentTimeLocale->x) */

/*
 * We do not implement alternate representations. However, we always
 * check whether a given modifier is allowed for a certain conversion.
 */
#నిర్వచించు _ALT_E			0x01
#నిర్వచించు _ALT_O			0x02
#నిర్వచించు	_LEGAL_ALT(x)		{ ఒకవేళ (alt_format & ~(x)) తిరిగి (0); }


స్థిర	పూర్ణాంకం conv_అంకె(స్థిరరాశి గుర్తులేని అక్షరం **, పూర్ణాంకం *, పూర్ణాంకం, పూర్ణాంకం);
స్థిర	అక్షరం *_strptime(స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *, నిర్మాణం tm *, పూర్ణాంకం);


అక్షరం *
strptime(స్థిరరాశి అక్షరం *buf, స్థిరరాశి అక్షరం *fmt, నిర్మాణం tm *tm)
{
	తిరిగి(_strptime(buf, fmt, tm, 1));
}

స్థిర అక్షరం *
_strptime(స్థిరరాశి అక్షరం *buf, స్థిరరాశి అక్షరం *fmt, నిర్మాణం tm *tm, పూర్ణాంకం initialize)
{
	గుర్తులేని అక్షరం c;
	స్థిరరాశి గుర్తులేని అక్షరం *bp;
	కొలత_t len;
	పూర్ణాంకం alt_format, i;
	స్థిర పూర్ణాంకం century, relyear;

	ఒకవేళ (initialize) {
		century = TM_YEAR_పునాది;
		relyear = -1;
	}

	bp = (గుర్తులేని అక్షరం *)buf;
	అయితే ((c = *fmt) != '\0') {
		/* Clear `alternate' modifier prior to new conversion. */
		alt_format = 0;

		/* Eat up white-space. */
		ఒకవేళ (ఖాళీనా(c)) {
			అయితే (ఖాళీనా(*bp))
				bp++;

			fmt++;
			కొనసాగు;
		}
				
		ఒకవేళ ((c = *fmt++) != '%')
			వెళ్ళు literal;


again:		ఎంపిక (c = *fmt++) {
		స్థితి '%':	/* "%%" is converted to "%". */
literal:
		ఒకవేళ (c != *bp++)
			తిరిగి (ఖాళీ);

		ఆపు;

		/*
		 * "Alternative" modifiers. Just set the appropriate flag
		 * and start over again.
		 */
		స్థితి 'E':	/* "%E?" alternative conversion modifier. */
			_LEGAL_ALT(0);
			alt_format |= _ALT_E;
			వెళ్ళు again;

		స్థితి 'O':	/* "%O?" alternative conversion modifier. */
			_LEGAL_ALT(0);
			alt_format |= _ALT_O;
			వెళ్ళు again;
			
		/*
		 * "Complex" conversion rules, implemented through recursion.
		 */
#ఒకవేళ 0
		స్థితి 'c':	/* Date and time, using the locale's format. */
			_LEGAL_ALT(_ALT_E);
			ఒకవేళ (!(bp = _strptime(bp, _ctloc(d_t_fmt), tm, 0)))
				తిరిగి (ఖాళీ);
			ఆపు;
#అయితే_ముగింపు
		స్థితి 'D':	/* The date as "%m/%d/%y". */
			_LEGAL_ALT(0);
			ఒకవేళ (!(bp = _strptime(bp, "%m/%d/%y", tm, 0)))
				తిరిగి (ఖాళీ);
			ఆపు;
	
		స్థితి 'R':	/* The time as "%H:%M". */
			_LEGAL_ALT(0);
			ఒకవేళ (!(bp = _strptime(bp, "%H:%M", tm, 0)))
				తిరిగి (ఖాళీ);
			ఆపు;

		స్థితి 'r':	/* The time as "%I:%M:%S %p". */
			_LEGAL_ALT(0);
			ఒకవేళ (!(bp = _strptime(bp, "%I:%M:%S %p", tm, 0)))
				తిరిగి (ఖాళీ);
			ఆపు;

		స్థితి 'T':	/* The time as "%H:%M:%S". */
			_LEGAL_ALT(0);
			ఒకవేళ (!(bp = _strptime(bp, "%H:%M:%S", tm, 0)))
				తిరిగి (ఖాళీ);
			ఆపు;
#ఒకవేళ 0
		స్థితి 'X':	/* The time, using the locale's format. */
			_LEGAL_ALT(_ALT_E);
			ఒకవేళ (!(bp = _strptime(bp, _ctloc(t_fmt), tm, 0)))
				తిరిగి (ఖాళీ);
			ఆపు;

		స్థితి 'x':	/* The date, using the locale's format. */
			_LEGAL_ALT(_ALT_E);
			ఒకవేళ (!(bp = _strptime(bp, _ctloc(d_fmt), tm, 0)))
				తిరిగి (ఖాళీ);
			ఆపు;
#అయితే_ముగింపు
		/*
		 * "Elementary" conversion rules.
		 */
#ఒకవేళ 0
		స్థితి 'A':	/* The day of week, using the locale's form. */
		స్థితి 'a':
			_LEGAL_ALT(0);
			కొరకు (i = 0; i < 7; i++) {
				/* Full name. */
				len = అక్షరశ్రేణి_పొడవు(_ctloc(day[i]));
				ఒకవేళ (strncasecmp(_ctloc(day[i]), bp, len) == 0)
					ఆపు;

				/* Abbreviated name. */
				len = అక్షరశ్రేణి_పొడవు(_ctloc(abday[i]));
				ఒకవేళ (strncasecmp(_ctloc(abday[i]), bp, len) == 0)
					ఆపు;
			}

			/* Nothing matched. */
			ఒకవేళ (i == 7)
				తిరిగి (ఖాళీ);

			tm->tm_wday = i;
			bp += len;
			ఆపు;

		స్థితి 'B':	/* The month, using the locale's form. */
		స్థితి 'b':
		స్థితి 'h':
			_LEGAL_ALT(0);
			కొరకు (i = 0; i < 12; i++) {
				/* Full name. */
				len = అక్షరశ్రేణి_పొడవు(_ctloc(mon[i]));
				ఒకవేళ (strncasecmp(_ctloc(mon[i]), bp, len) == 0)
					ఆపు;

				/* Abbreviated name. */
				len = అక్షరశ్రేణి_పొడవు(_ctloc(abmon[i]));
				ఒకవేళ (strncasecmp(_ctloc(abmon[i]), bp, len) == 0)
					ఆపు;
			}

			/* Nothing matched. */
			ఒకవేళ (i == 12)
				తిరిగి (ఖాళీ);

			tm->tm_mon = i;
			bp += len;
			ఆపు;
#అయితే_ముగింపు

		స్థితి 'C':	/* The century number. */
			_LEGAL_ALT(_ALT_E);
			ఒకవేళ (!(conv_అంకె(&bp, &i, 0, 99)))
				తిరిగి (ఖాళీ);

			century = i * 100;
			ఆపు;

		స్థితి 'd':	/* The day of month. */
		స్థితి 'e':
			_LEGAL_ALT(_ALT_O);
			ఒకవేళ (!(conv_అంకె(&bp, &tm->tm_mday, 1, 31)))
				తిరిగి (ఖాళీ);
			ఆపు;

		స్థితి 'k':	/* The hour (24-hour clock representation). */
			_LEGAL_ALT(0);
			/* FALLTHROUGH */
		స్థితి 'H':
			_LEGAL_ALT(_ALT_O);
			ఒకవేళ (!(conv_అంకె(&bp, &tm->tm_hour, 0, 23)))
				తిరిగి (ఖాళీ);
			ఆపు;

		స్థితి 'l':	/* The hour (12-hour clock representation). */
			_LEGAL_ALT(0);
			/* FALLTHROUGH */
		స్థితి 'I':
			_LEGAL_ALT(_ALT_O);
			ఒకవేళ (!(conv_అంకె(&bp, &tm->tm_hour, 1, 12)))
				తిరిగి (ఖాళీ);
			ఆపు;

		స్థితి 'j':	/* The day of year. */
			_LEGAL_ALT(0);
			ఒకవేళ (!(conv_అంకె(&bp, &tm->tm_yday, 1, 366)))
				తిరిగి (ఖాళీ);
			tm->tm_yday--;
			ఆపు;

		స్థితి 'M':	/* The minute. */
			_LEGAL_ALT(_ALT_O);
			ఒకవేళ (!(conv_అంకె(&bp, &tm->tm_min, 0, 59)))
				తిరిగి (ఖాళీ);
			ఆపు;

		స్థితి 'm':	/* The month. */
			_LEGAL_ALT(_ALT_O);
			ఒకవేళ (!(conv_అంకె(&bp, &tm->tm_mon, 1, 12)))
				తిరిగి (ఖాళీ);
			tm->tm_mon--;
			ఆపు;

#ఒకవేళ 0
		స్థితి 'p':	/* The locale's equivalent of AM/PM. */
			_LEGAL_ALT(0);
			/* AM? */
			len = అక్షరశ్రేణి_పొడవు(_ctloc(am_pm[0]));
			ఒకవేళ (strncasecmp(_ctloc(am_pm[0]), bp, len) == 0) {
				ఒకవేళ (tm->tm_hour > 12)	/* i.e., 13:00 AM ?! */
					తిరిగి (ఖాళీ);
				లేకపోతే ఒకవేళ (tm->tm_hour == 12)
					tm->tm_hour = 0;

				bp += len;
				ఆపు;
			}
			/* PM? */
			len = అక్షరశ్రేణి_పొడవు(_ctloc(am_pm[1]));
			ఒకవేళ (strncasecmp(_ctloc(am_pm[1]), bp, len) == 0) {
				ఒకవేళ (tm->tm_hour > 12)	/* i.e., 13:00 PM ?! */
					తిరిగి (ఖాళీ);
				లేకపోతే ఒకవేళ (tm->tm_hour < 12)
					tm->tm_hour += 12;

				bp += len;
				ఆపు;
			}

			/* Nothing matched. */
			తిరిగి (ఖాళీ);
#అయితే_ముగింపు
		స్థితి 'S':	/* The seconds. */
			_LEGAL_ALT(_ALT_O);
			ఒకవేళ (!(conv_అంకె(&bp, &tm->tm_sec, 0, 61)))
				తిరిగి (ఖాళీ);
			ఆపు;

		స్థితి 'U':	/* The week of year, beginning on sunday. */
		స్థితి 'W':	/* The week of year, beginning on monday. */
			_LEGAL_ALT(_ALT_O);
			/*
			 * XXX This is bogus, as we can not assume any valid
			 * information present in the tm structure at this
			 * point to calculate a real value, so just check the
			 * range for now.
			 */
			 ఒకవేళ (!(conv_అంకె(&bp, &i, 0, 53)))
				తిరిగి (ఖాళీ);
			 ఆపు;

		స్థితి 'w':	/* The day of week, beginning on sunday. */
			_LEGAL_ALT(_ALT_O);
			ఒకవేళ (!(conv_అంకె(&bp, &tm->tm_wday, 0, 6)))
				తిరిగి (ఖాళీ);
			ఆపు;

		స్థితి 'Y':	/* The year. */
			_LEGAL_ALT(_ALT_E);
			ఒకవేళ (!(conv_అంకె(&bp, &i, 0, 9999)))
				తిరిగి (ఖాళీ);

			relyear = -1;
			tm->tm_year = i - TM_YEAR_పునాది;
			ఆపు;

		స్థితి 'y':	/* The year within the century (2 digits). */
			_LEGAL_ALT(_ALT_E | _ALT_O);
			ఒకవేళ (!(conv_అంకె(&bp, &relyear, 0, 99)))
				తిరిగి (ఖాళీ);
			ఆపు;

		/*
		 * Miscellaneous conversions.
		 */
		స్థితి 'n':	/* Any kind of white-space. */
		స్థితి 't':
			_LEGAL_ALT(0);
			అయితే (ఖాళీనా(*bp))
				bp++;
			ఆపు;


		అప్రమేయ:	/* Unknown/unsupported conversion. */
			తిరిగి (ఖాళీ);
		}


	}

	/*
	 * We need to evaluate the two digit year spec (%y)
	 * last as we can get a century spec (%C) at any time.
	 */
	ఒకవేళ (relyear != -1) {
		ఒకవేళ (century == TM_YEAR_పునాది) {
			ఒకవేళ (relyear <= 68)
				tm->tm_year = relyear + 2000 - TM_YEAR_పునాది;
			లేకపోతే
				tm->tm_year = relyear + 1900 - TM_YEAR_పునాది;
		} లేకపోతే {
			tm->tm_year = relyear + century - TM_YEAR_పునాది;
		}
	}

	తిరిగి ((అక్షరం *)bp);
}


స్థిర పూర్ణాంకం
conv_అంకె(స్థిరరాశి గుర్తులేని అక్షరం **buf, పూర్ణాంకం *dest, పూర్ణాంకం llim, పూర్ణాంకం ulim)
{
	పూర్ణాంకం ఫలితం = 0;
	పూర్ణాంకం rulim = ulim;

	ఒకవేళ (**buf < '0' || **buf > '9')
		తిరిగి (0);

	/* we use rulim to break out of the loop when we run out of digits */
	చేయి {
		ఫలితం *= 10;
		ఫలితం += *(*buf)++ - '0';
		rulim /= 10;
	} అయితే ((ఫలితం * 10 <= ulim) && rulim && **buf >= '0' && **buf <= '9');

	ఒకవేళ (ఫలితం < llim || ఫలితం > ulim)
		తిరిగి (0);

	*dest = ఫలితం;
	తిరిగి (1);
}

#అయితే_ముగింపు /* HAVE_STRPTIME */

