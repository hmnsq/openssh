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

#അന്തര്ഭാവ "includes.h"

#ifndef HAVE_STRPTIME

#define TM_YEAR_BASE 1900	/* from tzfile.h */

#അന്തര്ഭാവ <ctype.h>
#അന്തര്ഭാവ <locale.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <time.h>

/* #define	_ctloc(x)		(_CurrentTimeLocale->x) */

/*
 * We do not implement alternate representations. However, we always
 * check whether a given modifier is allowed for a certain conversion.
 */
#define _ALT_E			0x01
#define _ALT_O			0x02
#define	_LEGAL_ALT(x)		{ എങ്കിൽ (alt_format & ~(x)) തിരികെ (0); }


സ്ഥിതം	പൂർണ്ണസംഖ്യ conv_അക്കം(സ്ഥിരം unsigned അക്ഷരം **, പൂർണ്ണസംഖ്യ *, പൂർണ്ണസംഖ്യ, പൂർണ്ണസംഖ്യ);
സ്ഥിതം	അക്ഷരം *_strptime(സ്ഥിരം അക്ഷരം *, സ്ഥിരം അക്ഷരം *, ഘടന tm *, പൂർണ്ണസംഖ്യ);


അക്ഷരം *
strptime(സ്ഥിരം അക്ഷരം *buf, സ്ഥിരം അക്ഷരം *fmt, ഘടന tm *tm)
{
	തിരികെ(_strptime(buf, fmt, tm, 1));
}

സ്ഥിതം അക്ഷരം *
_strptime(സ്ഥിരം അക്ഷരം *buf, സ്ഥിരം അക്ഷരം *fmt, ഘടന tm *tm, പൂർണ്ണസംഖ്യ initialize)
{
	unsigned അക്ഷരം c;
	സ്ഥിരം unsigned അക്ഷരം *bp;
	size_t len;
	പൂർണ്ണസംഖ്യ alt_format, i;
	സ്ഥിതം പൂർണ്ണസംഖ്യ century, relyear;

	എങ്കിൽ (initialize) {
		century = TM_YEAR_BASE;
		relyear = -1;
	}

	bp = (unsigned അക്ഷരം *)buf;
	ആകുമ്പോൾ ((c = *fmt) != '\0') {
		/* Clear `alternate' modifier prior to new conversion. */
		alt_format = 0;

		/* Eat up white-space. */
		എങ്കിൽ (isspace(c)) {
			ആകുമ്പോൾ (isspace(*bp))
				bp++;

			fmt++;
			തുടരുക;
		}
				
		എങ്കിൽ ((c = *fmt++) != '%')
			പോകുക literal;


again:		തിരഞ്ഞെടുപ്പ് (c = *fmt++) {
		അവസ്ഥ '%':	/* "%%" is converted to "%". */
literal:
		എങ്കിൽ (c != *bp++)
			തിരികെ (ശൂന്യ);

		നിർത്തുക;

		/*
		 * "Alternative" modifiers. Just set the appropriate flag
		 * and start over again.
		 */
		അവസ്ഥ 'E':	/* "%E?" alternative conversion modifier. */
			_LEGAL_ALT(0);
			alt_format |= _ALT_E;
			പോകുക again;

		അവസ്ഥ 'O':	/* "%O?" alternative conversion modifier. */
			_LEGAL_ALT(0);
			alt_format |= _ALT_O;
			പോകുക again;
			
		/*
		 * "Complex" conversion rules, implemented through recursion.
		 */
#എങ്കിൽ 0
		അവസ്ഥ 'c':	/* Date and time, using the locale's format. */
			_LEGAL_ALT(_ALT_E);
			എങ്കിൽ (!(bp = _strptime(bp, _ctloc(d_t_fmt), tm, 0)))
				തിരികെ (ശൂന്യ);
			നിർത്തുക;
#endif
		അവസ്ഥ 'D':	/* The date as "%m/%d/%y". */
			_LEGAL_ALT(0);
			എങ്കിൽ (!(bp = _strptime(bp, "%m/%d/%y", tm, 0)))
				തിരികെ (ശൂന്യ);
			നിർത്തുക;
	
		അവസ്ഥ 'R':	/* The time as "%H:%M". */
			_LEGAL_ALT(0);
			എങ്കിൽ (!(bp = _strptime(bp, "%H:%M", tm, 0)))
				തിരികെ (ശൂന്യ);
			നിർത്തുക;

		അവസ്ഥ 'r':	/* The time as "%I:%M:%S %p". */
			_LEGAL_ALT(0);
			എങ്കിൽ (!(bp = _strptime(bp, "%I:%M:%S %p", tm, 0)))
				തിരികെ (ശൂന്യ);
			നിർത്തുക;

		അവസ്ഥ 'T':	/* The time as "%H:%M:%S". */
			_LEGAL_ALT(0);
			എങ്കിൽ (!(bp = _strptime(bp, "%H:%M:%S", tm, 0)))
				തിരികെ (ശൂന്യ);
			നിർത്തുക;
#എങ്കിൽ 0
		അവസ്ഥ 'X':	/* The time, using the locale's format. */
			_LEGAL_ALT(_ALT_E);
			എങ്കിൽ (!(bp = _strptime(bp, _ctloc(t_fmt), tm, 0)))
				തിരികെ (ശൂന്യ);
			നിർത്തുക;

		അവസ്ഥ 'x':	/* The date, using the locale's format. */
			_LEGAL_ALT(_ALT_E);
			എങ്കിൽ (!(bp = _strptime(bp, _ctloc(d_fmt), tm, 0)))
				തിരികെ (ശൂന്യ);
			നിർത്തുക;
#endif
		/*
		 * "Elementary" conversion rules.
		 */
#എങ്കിൽ 0
		അവസ്ഥ 'A':	/* The day of week, using the locale's form. */
		അവസ്ഥ 'a':
			_LEGAL_ALT(0);
			വേണ്ടി (i = 0; i < 7; i++) {
				/* Full name. */
				len = strlen(_ctloc(day[i]));
				എങ്കിൽ (strncasecmp(_ctloc(day[i]), bp, len) == 0)
					നിർത്തുക;

				/* Abbreviated name. */
				len = strlen(_ctloc(abday[i]));
				എങ്കിൽ (strncasecmp(_ctloc(abday[i]), bp, len) == 0)
					നിർത്തുക;
			}

			/* Nothing matched. */
			എങ്കിൽ (i == 7)
				തിരികെ (ശൂന്യ);

			tm->tm_wday = i;
			bp += len;
			നിർത്തുക;

		അവസ്ഥ 'B':	/* The month, using the locale's form. */
		അവസ്ഥ 'b':
		അവസ്ഥ 'h':
			_LEGAL_ALT(0);
			വേണ്ടി (i = 0; i < 12; i++) {
				/* Full name. */
				len = strlen(_ctloc(mon[i]));
				എങ്കിൽ (strncasecmp(_ctloc(mon[i]), bp, len) == 0)
					നിർത്തുക;

				/* Abbreviated name. */
				len = strlen(_ctloc(abmon[i]));
				എങ്കിൽ (strncasecmp(_ctloc(abmon[i]), bp, len) == 0)
					നിർത്തുക;
			}

			/* Nothing matched. */
			എങ്കിൽ (i == 12)
				തിരികെ (ശൂന്യ);

			tm->tm_mon = i;
			bp += len;
			നിർത്തുക;
#endif

		അവസ്ഥ 'C':	/* The century number. */
			_LEGAL_ALT(_ALT_E);
			എങ്കിൽ (!(conv_അക്കം(&bp, &i, 0, 99)))
				തിരികെ (ശൂന്യ);

			century = i * 100;
			നിർത്തുക;

		അവസ്ഥ 'd':	/* The day of month. */
		അവസ്ഥ 'e':
			_LEGAL_ALT(_ALT_O);
			എങ്കിൽ (!(conv_അക്കം(&bp, &tm->tm_mday, 1, 31)))
				തിരികെ (ശൂന്യ);
			നിർത്തുക;

		അവസ്ഥ 'k':	/* The hour (24-hour clock representation). */
			_LEGAL_ALT(0);
			/* FALLTHROUGH */
		അവസ്ഥ 'H':
			_LEGAL_ALT(_ALT_O);
			എങ്കിൽ (!(conv_അക്കം(&bp, &tm->tm_hour, 0, 23)))
				തിരികെ (ശൂന്യ);
			നിർത്തുക;

		അവസ്ഥ 'l':	/* The hour (12-hour clock representation). */
			_LEGAL_ALT(0);
			/* FALLTHROUGH */
		അവസ്ഥ 'I':
			_LEGAL_ALT(_ALT_O);
			എങ്കിൽ (!(conv_അക്കം(&bp, &tm->tm_hour, 1, 12)))
				തിരികെ (ശൂന്യ);
			നിർത്തുക;

		അവസ്ഥ 'j':	/* The day of year. */
			_LEGAL_ALT(0);
			എങ്കിൽ (!(conv_അക്കം(&bp, &tm->tm_yday, 1, 366)))
				തിരികെ (ശൂന്യ);
			tm->tm_yday--;
			നിർത്തുക;

		അവസ്ഥ 'M':	/* The minute. */
			_LEGAL_ALT(_ALT_O);
			എങ്കിൽ (!(conv_അക്കം(&bp, &tm->tm_min, 0, 59)))
				തിരികെ (ശൂന്യ);
			നിർത്തുക;

		അവസ്ഥ 'm':	/* The month. */
			_LEGAL_ALT(_ALT_O);
			എങ്കിൽ (!(conv_അക്കം(&bp, &tm->tm_mon, 1, 12)))
				തിരികെ (ശൂന്യ);
			tm->tm_mon--;
			നിർത്തുക;

#എങ്കിൽ 0
		അവസ്ഥ 'p':	/* The locale's equivalent of AM/PM. */
			_LEGAL_ALT(0);
			/* AM? */
			len = strlen(_ctloc(am_pm[0]));
			എങ്കിൽ (strncasecmp(_ctloc(am_pm[0]), bp, len) == 0) {
				എങ്കിൽ (tm->tm_hour > 12)	/* i.e., 13:00 AM ?! */
					തിരികെ (ശൂന്യ);
				അല്ലെങ്കിൽ എങ്കിൽ (tm->tm_hour == 12)
					tm->tm_hour = 0;

				bp += len;
				നിർത്തുക;
			}
			/* PM? */
			len = strlen(_ctloc(am_pm[1]));
			എങ്കിൽ (strncasecmp(_ctloc(am_pm[1]), bp, len) == 0) {
				എങ്കിൽ (tm->tm_hour > 12)	/* i.e., 13:00 PM ?! */
					തിരികെ (ശൂന്യ);
				അല്ലെങ്കിൽ എങ്കിൽ (tm->tm_hour < 12)
					tm->tm_hour += 12;

				bp += len;
				നിർത്തുക;
			}

			/* Nothing matched. */
			തിരികെ (ശൂന്യ);
#endif
		അവസ്ഥ 'S':	/* The seconds. */
			_LEGAL_ALT(_ALT_O);
			എങ്കിൽ (!(conv_അക്കം(&bp, &tm->tm_sec, 0, 61)))
				തിരികെ (ശൂന്യ);
			നിർത്തുക;

		അവസ്ഥ 'U':	/* The week of year, beginning on sunday. */
		അവസ്ഥ 'W':	/* The week of year, beginning on monday. */
			_LEGAL_ALT(_ALT_O);
			/*
			 * XXX This is bogus, as we can not assume any valid
			 * information present in the tm structure at this
			 * point to calculate a real value, so just check the
			 * range for now.
			 */
			 എങ്കിൽ (!(conv_അക്കം(&bp, &i, 0, 53)))
				തിരികെ (ശൂന്യ);
			 നിർത്തുക;

		അവസ്ഥ 'w':	/* The day of week, beginning on sunday. */
			_LEGAL_ALT(_ALT_O);
			എങ്കിൽ (!(conv_അക്കം(&bp, &tm->tm_wday, 0, 6)))
				തിരികെ (ശൂന്യ);
			നിർത്തുക;

		അവസ്ഥ 'Y':	/* The year. */
			_LEGAL_ALT(_ALT_E);
			എങ്കിൽ (!(conv_അക്കം(&bp, &i, 0, 9999)))
				തിരികെ (ശൂന്യ);

			relyear = -1;
			tm->tm_year = i - TM_YEAR_BASE;
			നിർത്തുക;

		അവസ്ഥ 'y':	/* The year within the century (2 digits). */
			_LEGAL_ALT(_ALT_E | _ALT_O);
			എങ്കിൽ (!(conv_അക്കം(&bp, &relyear, 0, 99)))
				തിരികെ (ശൂന്യ);
			നിർത്തുക;

		/*
		 * Miscellaneous conversions.
		 */
		അവസ്ഥ 'n':	/* Any kind of white-space. */
		അവസ്ഥ 't':
			_LEGAL_ALT(0);
			ആകുമ്പോൾ (isspace(*bp))
				bp++;
			നിർത്തുക;


		സ്ഥിരസ്ഥിതി:	/* Unknown/unsupported conversion. */
			തിരികെ (ശൂന്യ);
		}


	}

	/*
	 * We need to evaluate the two digit year spec (%y)
	 * last as we can get a century spec (%C) at any time.
	 */
	എങ്കിൽ (relyear != -1) {
		എങ്കിൽ (century == TM_YEAR_BASE) {
			എങ്കിൽ (relyear <= 68)
				tm->tm_year = relyear + 2000 - TM_YEAR_BASE;
			അല്ലെങ്കിൽ
				tm->tm_year = relyear + 1900 - TM_YEAR_BASE;
		} അല്ലെങ്കിൽ {
			tm->tm_year = relyear + century - TM_YEAR_BASE;
		}
	}

	തിരികെ ((അക്ഷരം *)bp);
}


സ്ഥിതം പൂർണ്ണസംഖ്യ
conv_അക്കം(സ്ഥിരം unsigned അക്ഷരം **buf, പൂർണ്ണസംഖ്യ *dest, പൂർണ്ണസംഖ്യ llim, പൂർണ്ണസംഖ്യ ulim)
{
	പൂർണ്ണസംഖ്യ result = 0;
	പൂർണ്ണസംഖ്യ rulim = ulim;

	എങ്കിൽ (**buf < '0' || **buf > '9')
		തിരികെ (0);

	/* we use rulim to break out of the loop when we run out of digits */
	ചെയ്യുക {
		result *= 10;
		result += *(*buf)++ - '0';
		rulim /= 10;
	} ആകുമ്പോൾ ((result * 10 <= ulim) && rulim && **buf >= '0' && **buf <= '9');

	എങ്കിൽ (result < llim || result > ulim)
		തിരികെ (0);

	*dest = result;
	തിരികെ (1);
}

#endif /* HAVE_STRPTIME */

