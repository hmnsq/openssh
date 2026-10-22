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

#include "includes.h"

#ifndef HAVE_STRPTIME

#define TM_YEAR_BASE 1900	/* from tzfile.h */

#include <ctype.h>
#include <locale.h>
#include <string.h>
#include <time.h>

/* #define	_ctloc(x)		(_CurrentTimeLocale->x) */

/*
 * We do not implement alternate representations. However, we always
 * check whether a given modifier is allowed for a certain conversion.
 */
#define _ALT_E			0x01
#define _ALT_O			0x02
#define	_LEGAL_ALT(x)		{ если (alt_format & ~(x)) вернуть (0); }


static	целое _conv_num(const unsigned char **, целое *, целое, целое);
static	char *_strptime(const char *, const char *, struct tm *, целое);


char *
strptime(const char *buf, const char *fmt, struct tm *tm)
{
	вернуть(_strptime(buf, fmt, tm, 1));
}

static char *
_strptime(const char *buf, const char *fmt, struct tm *tm, целое initialize)
{
	unsigned char c;
	const unsigned char *bp;
	size_t len;
	целое alt_format, i;
	static целое century, relyear;

	если (initialize) {
		century = TM_YEAR_BASE;
		relyear = -1;
	}

	bp = (unsigned char *)buf;
	пока ((c = *fmt) != '\0') {
		/* Clear `alternate' modifier prior to new conversion. */
		alt_format = 0;

		/* Eat up white-space. */
		если (isspace(c)) {
			пока (isspace(*bp))
				bp++;

			fmt++;
			continue;
		}
				
		если ((c = *fmt++) != '%')
			goto literal;


again:		switch (c = *fmt++) {
		case '%':	/* "%%" is converted to "%". */
literal:
		если (c != *bp++)
			вернуть (NULL);

		break;

		/*
		 * "Alternative" modifiers. Just set the appropriate flag
		 * and start over again.
		 */
		case 'E':	/* "%E?" alternative conversion modifier. */
			_LEGAL_ALT(0);
			alt_format |= _ALT_E;
			goto again;

		case 'O':	/* "%O?" alternative conversion modifier. */
			_LEGAL_ALT(0);
			alt_format |= _ALT_O;
			goto again;
			
		/*
		 * "Complex" conversion rules, implemented through recursion.
		 */
#если 0
		case 'c':	/* Date and time, using the locale's format. */
			_LEGAL_ALT(_ALT_E);
			если (!(bp = _strptime(bp, _ctloc(d_t_fmt), tm, 0)))
				вернуть (NULL);
			break;
#endif
		case 'D':	/* The date as "%m/%d/%y". */
			_LEGAL_ALT(0);
			если (!(bp = _strptime(bp, "%m/%d/%y", tm, 0)))
				вернуть (NULL);
			break;
	
		case 'R':	/* The time as "%H:%M". */
			_LEGAL_ALT(0);
			если (!(bp = _strptime(bp, "%H:%M", tm, 0)))
				вернуть (NULL);
			break;

		case 'r':	/* The time as "%I:%M:%S %p". */
			_LEGAL_ALT(0);
			если (!(bp = _strptime(bp, "%I:%M:%S %p", tm, 0)))
				вернуть (NULL);
			break;

		case 'T':	/* The time as "%H:%M:%S". */
			_LEGAL_ALT(0);
			если (!(bp = _strptime(bp, "%H:%M:%S", tm, 0)))
				вернуть (NULL);
			break;
#если 0
		case 'X':	/* The time, using the locale's format. */
			_LEGAL_ALT(_ALT_E);
			если (!(bp = _strptime(bp, _ctloc(t_fmt), tm, 0)))
				вернуть (NULL);
			break;

		case 'x':	/* The date, using the locale's format. */
			_LEGAL_ALT(_ALT_E);
			если (!(bp = _strptime(bp, _ctloc(d_fmt), tm, 0)))
				вернуть (NULL);
			break;
#endif
		/*
		 * "Elementary" conversion rules.
		 */
#если 0
		case 'A':	/* The day of week, using the locale's form. */
		case 'a':
			_LEGAL_ALT(0);
			для (i = 0; i < 7; i++) {
				/* Full name. */
				len = strlen(_ctloc(day[i]));
				если (strncasecmp(_ctloc(day[i]), bp, len) == 0)
					break;

				/* Abbreviated name. */
				len = strlen(_ctloc(abday[i]));
				если (strncasecmp(_ctloc(abday[i]), bp, len) == 0)
					break;
			}

			/* Nothing matched. */
			если (i == 7)
				вернуть (NULL);

			tm->tm_wday = i;
			bp += len;
			break;

		case 'B':	/* The month, using the locale's form. */
		case 'b':
		case 'h':
			_LEGAL_ALT(0);
			для (i = 0; i < 12; i++) {
				/* Full name. */
				len = strlen(_ctloc(mon[i]));
				если (strncasecmp(_ctloc(mon[i]), bp, len) == 0)
					break;

				/* Abbreviated name. */
				len = strlen(_ctloc(abmon[i]));
				если (strncasecmp(_ctloc(abmon[i]), bp, len) == 0)
					break;
			}

			/* Nothing matched. */
			если (i == 12)
				вернуть (NULL);

			tm->tm_mon = i;
			bp += len;
			break;
#endif

		case 'C':	/* The century number. */
			_LEGAL_ALT(_ALT_E);
			если (!(_conv_num(&bp, &i, 0, 99)))
				вернуть (NULL);

			century = i * 100;
			break;

		case 'd':	/* The day of month. */
		case 'e':
			_LEGAL_ALT(_ALT_O);
			если (!(_conv_num(&bp, &tm->tm_mday, 1, 31)))
				вернуть (NULL);
			break;

		case 'k':	/* The hour (24-hour clock representation). */
			_LEGAL_ALT(0);
			/* FALLTHROUGH */
		case 'H':
			_LEGAL_ALT(_ALT_O);
			если (!(_conv_num(&bp, &tm->tm_hour, 0, 23)))
				вернуть (NULL);
			break;

		case 'l':	/* The hour (12-hour clock representation). */
			_LEGAL_ALT(0);
			/* FALLTHROUGH */
		case 'I':
			_LEGAL_ALT(_ALT_O);
			если (!(_conv_num(&bp, &tm->tm_hour, 1, 12)))
				вернуть (NULL);
			break;

		case 'j':	/* The day of year. */
			_LEGAL_ALT(0);
			если (!(_conv_num(&bp, &tm->tm_yday, 1, 366)))
				вернуть (NULL);
			tm->tm_yday--;
			break;

		case 'M':	/* The minute. */
			_LEGAL_ALT(_ALT_O);
			если (!(_conv_num(&bp, &tm->tm_min, 0, 59)))
				вернуть (NULL);
			break;

		case 'm':	/* The month. */
			_LEGAL_ALT(_ALT_O);
			если (!(_conv_num(&bp, &tm->tm_mon, 1, 12)))
				вернуть (NULL);
			tm->tm_mon--;
			break;

#если 0
		case 'p':	/* The locale's equivalent of AM/PM. */
			_LEGAL_ALT(0);
			/* AM? */
			len = strlen(_ctloc(am_pm[0]));
			если (strncasecmp(_ctloc(am_pm[0]), bp, len) == 0) {
				если (tm->tm_hour > 12)	/* i.e., 13:00 AM ?! */
					вернуть (NULL);
				иначе если (tm->tm_hour == 12)
					tm->tm_hour = 0;

				bp += len;
				break;
			}
			/* PM? */
			len = strlen(_ctloc(am_pm[1]));
			если (strncasecmp(_ctloc(am_pm[1]), bp, len) == 0) {
				если (tm->tm_hour > 12)	/* i.e., 13:00 PM ?! */
					вернуть (NULL);
				иначе если (tm->tm_hour < 12)
					tm->tm_hour += 12;

				bp += len;
				break;
			}

			/* Nothing matched. */
			вернуть (NULL);
#endif
		case 'S':	/* The seconds. */
			_LEGAL_ALT(_ALT_O);
			если (!(_conv_num(&bp, &tm->tm_sec, 0, 61)))
				вернуть (NULL);
			break;

		case 'U':	/* The week of year, beginning on sunday. */
		case 'W':	/* The week of year, beginning on monday. */
			_LEGAL_ALT(_ALT_O);
			/*
			 * XXX This is bogus, as we can not assume any valid
			 * information present in the tm structure at this
			 * point to calculate a real value, so just check the
			 * range for now.
			 */
			 если (!(_conv_num(&bp, &i, 0, 53)))
				вернуть (NULL);
			 break;

		case 'w':	/* The day of week, beginning on sunday. */
			_LEGAL_ALT(_ALT_O);
			если (!(_conv_num(&bp, &tm->tm_wday, 0, 6)))
				вернуть (NULL);
			break;

		case 'Y':	/* The year. */
			_LEGAL_ALT(_ALT_E);
			если (!(_conv_num(&bp, &i, 0, 9999)))
				вернуть (NULL);

			relyear = -1;
			tm->tm_year = i - TM_YEAR_BASE;
			break;

		case 'y':	/* The year within the century (2 digits). */
			_LEGAL_ALT(_ALT_E | _ALT_O);
			если (!(_conv_num(&bp, &relyear, 0, 99)))
				вернуть (NULL);
			break;

		/*
		 * Miscellaneous conversions.
		 */
		case 'n':	/* Any kind of white-space. */
		case 't':
			_LEGAL_ALT(0);
			пока (isspace(*bp))
				bp++;
			break;


		default:	/* Unknown/unsupported conversion. */
			вернуть (NULL);
		}


	}

	/*
	 * We need to evaluate the two digit year spec (%y)
	 * last as we can get a century spec (%C) at any time.
	 */
	если (relyear != -1) {
		если (century == TM_YEAR_BASE) {
			если (relyear <= 68)
				tm->tm_year = relyear + 2000 - TM_YEAR_BASE;
			иначе
				tm->tm_year = relyear + 1900 - TM_YEAR_BASE;
		} иначе {
			tm->tm_year = relyear + century - TM_YEAR_BASE;
		}
	}

	вернуть ((char *)bp);
}


static целое
_conv_num(const unsigned char **buf, целое *dest, целое llim, целое ulim)
{
	целое result = 0;
	целое rulim = ulim;

	если (**buf < '0' || **buf > '9')
		вернуть (0);

	/* we use rulim to break out of the loop when we run out of digits */
	do {
		result *= 10;
		result += *(*buf)++ - '0';
		rulim /= 10;
	} пока ((result * 10 <= ulim) && rulim && **buf >= '0' && **buf <= '9');

	если (result < llim || result > ulim)
		вернуть (0);

	*dest = result;
	вернуть (1);
}

#endif /* HAVE_STRPTIME */

