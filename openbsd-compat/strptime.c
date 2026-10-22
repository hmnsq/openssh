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

#شامل "includes.h"

#اگر_غیر_تعریف_شدہ HAVE_STRPTIME

#تعریف_کرو TM_YEAR_بنیاد 1900	/* from tzfile.h */

#شامل <ctype.h>
#شامل <locale.h>
#شامل <string.h>
#شامل <time.h>

/* #define	_ctloc(x)		(_CurrentTimeLocale->x) */

/*
 * We do not implement alternate representations. However, we always
 * check whether a given modifier is allowed for a certain conversion.
 */
#تعریف_کرو _ALT_E			0x01
#تعریف_کرو _ALT_O			0x02
#تعریف_کرو	_LEGAL_ALT(x)		{ اگر (alt_format & ~(x)) واپس (0); }


ساکن	صحیح conv_عدد(ثابت غیرعلامتی حرف **, صحیح *, صحیح, صحیح);
ساکن	حرف *_strptime(ثابت حرف *, ثابت حرف *, ساخت tm *, صحیح);


حرف *
strptime(ثابت حرف *buf, ثابت حرف *fmt, ساخت tm *tm)
{
	واپس(_strptime(buf, fmt, tm, 1));
}

ساکن حرف *
_strptime(ثابت حرف *buf, ثابت حرف *fmt, ساخت tm *tm, صحیح initialize)
{
	غیرعلامتی حرف c;
	ثابت غیرعلامتی حرف *bp;
	سائز_t len;
	صحیح alt_format, i;
	ساکن صحیح century, relyear;

	اگر (initialize) {
		century = TM_YEAR_بنیاد;
		relyear = -1;
	}

	bp = (غیرعلامتی حرف *)buf;
	جب ((c = *fmt) != '\0') {
		/* Clear `alternate' modifier prior to new conversion. */
		alt_format = 0;

		/* Eat up white-space. */
		اگر (خلا_ہے(c)) {
			جب (خلا_ہے(*bp))
				bp++;

			fmt++;
			جاری;
		}
				
		اگر ((c = *fmt++) != '%')
			جاؤ literal;


again:		انتخاب (c = *fmt++) {
		حالت '%':	/* "%%" is converted to "%". */
literal:
		اگر (c != *bp++)
			واپس (تہی);

		توڑو;

		/*
		 * "Alternative" modifiers. Just set the appropriate flag
		 * and start over again.
		 */
		حالت 'E':	/* "%E?" alternative conversion modifier. */
			_LEGAL_ALT(0);
			alt_format |= _ALT_E;
			جاؤ again;

		حالت 'O':	/* "%O?" alternative conversion modifier. */
			_LEGAL_ALT(0);
			alt_format |= _ALT_O;
			جاؤ again;
			
		/*
		 * "Complex" conversion rules, implemented through recursion.
		 */
#اگر 0
		حالت 'c':	/* Date and time, using the locale's format. */
			_LEGAL_ALT(_ALT_E);
			اگر (!(bp = _strptime(bp, _ctloc(d_t_fmt), tm, 0)))
				واپس (تہی);
			توڑو;
#اگر_ختم
		حالت 'D':	/* The date as "%m/%d/%y". */
			_LEGAL_ALT(0);
			اگر (!(bp = _strptime(bp, "%m/%d/%y", tm, 0)))
				واپس (تہی);
			توڑو;
	
		حالت 'R':	/* The time as "%H:%M". */
			_LEGAL_ALT(0);
			اگر (!(bp = _strptime(bp, "%H:%M", tm, 0)))
				واپس (تہی);
			توڑو;

		حالت 'r':	/* The time as "%I:%M:%S %p". */
			_LEGAL_ALT(0);
			اگر (!(bp = _strptime(bp, "%I:%M:%S %p", tm, 0)))
				واپس (تہی);
			توڑو;

		حالت 'T':	/* The time as "%H:%M:%S". */
			_LEGAL_ALT(0);
			اگر (!(bp = _strptime(bp, "%H:%M:%S", tm, 0)))
				واپس (تہی);
			توڑو;
#اگر 0
		حالت 'X':	/* The time, using the locale's format. */
			_LEGAL_ALT(_ALT_E);
			اگر (!(bp = _strptime(bp, _ctloc(t_fmt), tm, 0)))
				واپس (تہی);
			توڑو;

		حالت 'x':	/* The date, using the locale's format. */
			_LEGAL_ALT(_ALT_E);
			اگر (!(bp = _strptime(bp, _ctloc(d_fmt), tm, 0)))
				واپس (تہی);
			توڑو;
#اگر_ختم
		/*
		 * "Elementary" conversion rules.
		 */
#اگر 0
		حالت 'A':	/* The day of week, using the locale's form. */
		حالت 'a':
			_LEGAL_ALT(0);
			برائے (i = 0; i < 7; i++) {
				/* Full name. */
				len = لڑی_لمبائی(_ctloc(day[i]));
				اگر (strncasecmp(_ctloc(day[i]), bp, len) == 0)
					توڑو;

				/* Abbreviated name. */
				len = لڑی_لمبائی(_ctloc(abday[i]));
				اگر (strncasecmp(_ctloc(abday[i]), bp, len) == 0)
					توڑو;
			}

			/* Nothing matched. */
			اگر (i == 7)
				واپس (تہی);

			tm->tm_wday = i;
			bp += len;
			توڑو;

		حالت 'B':	/* The month, using the locale's form. */
		حالت 'b':
		حالت 'h':
			_LEGAL_ALT(0);
			برائے (i = 0; i < 12; i++) {
				/* Full name. */
				len = لڑی_لمبائی(_ctloc(mon[i]));
				اگر (strncasecmp(_ctloc(mon[i]), bp, len) == 0)
					توڑو;

				/* Abbreviated name. */
				len = لڑی_لمبائی(_ctloc(abmon[i]));
				اگر (strncasecmp(_ctloc(abmon[i]), bp, len) == 0)
					توڑو;
			}

			/* Nothing matched. */
			اگر (i == 12)
				واپس (تہی);

			tm->tm_mon = i;
			bp += len;
			توڑو;
#اگر_ختم

		حالت 'C':	/* The century number. */
			_LEGAL_ALT(_ALT_E);
			اگر (!(conv_عدد(&bp, &i, 0, 99)))
				واپس (تہی);

			century = i * 100;
			توڑو;

		حالت 'd':	/* The day of month. */
		حالت 'e':
			_LEGAL_ALT(_ALT_O);
			اگر (!(conv_عدد(&bp, &tm->tm_mday, 1, 31)))
				واپس (تہی);
			توڑو;

		حالت 'k':	/* The hour (24-hour clock representation). */
			_LEGAL_ALT(0);
			/* FALLTHROUGH */
		حالت 'H':
			_LEGAL_ALT(_ALT_O);
			اگر (!(conv_عدد(&bp, &tm->tm_hour, 0, 23)))
				واپس (تہی);
			توڑو;

		حالت 'l':	/* The hour (12-hour clock representation). */
			_LEGAL_ALT(0);
			/* FALLTHROUGH */
		حالت 'I':
			_LEGAL_ALT(_ALT_O);
			اگر (!(conv_عدد(&bp, &tm->tm_hour, 1, 12)))
				واپس (تہی);
			توڑو;

		حالت 'j':	/* The day of year. */
			_LEGAL_ALT(0);
			اگر (!(conv_عدد(&bp, &tm->tm_yday, 1, 366)))
				واپس (تہی);
			tm->tm_yday--;
			توڑو;

		حالت 'M':	/* The minute. */
			_LEGAL_ALT(_ALT_O);
			اگر (!(conv_عدد(&bp, &tm->tm_min, 0, 59)))
				واپس (تہی);
			توڑو;

		حالت 'm':	/* The month. */
			_LEGAL_ALT(_ALT_O);
			اگر (!(conv_عدد(&bp, &tm->tm_mon, 1, 12)))
				واپس (تہی);
			tm->tm_mon--;
			توڑو;

#اگر 0
		حالت 'p':	/* The locale's equivalent of AM/PM. */
			_LEGAL_ALT(0);
			/* AM? */
			len = لڑی_لمبائی(_ctloc(am_pm[0]));
			اگر (strncasecmp(_ctloc(am_pm[0]), bp, len) == 0) {
				اگر (tm->tm_hour > 12)	/* i.e., 13:00 AM ?! */
					واپس (تہی);
				ورنہ اگر (tm->tm_hour == 12)
					tm->tm_hour = 0;

				bp += len;
				توڑو;
			}
			/* PM? */
			len = لڑی_لمبائی(_ctloc(am_pm[1]));
			اگر (strncasecmp(_ctloc(am_pm[1]), bp, len) == 0) {
				اگر (tm->tm_hour > 12)	/* i.e., 13:00 PM ?! */
					واپس (تہی);
				ورنہ اگر (tm->tm_hour < 12)
					tm->tm_hour += 12;

				bp += len;
				توڑو;
			}

			/* Nothing matched. */
			واپس (تہی);
#اگر_ختم
		حالت 'S':	/* The seconds. */
			_LEGAL_ALT(_ALT_O);
			اگر (!(conv_عدد(&bp, &tm->tm_sec, 0, 61)))
				واپس (تہی);
			توڑو;

		حالت 'U':	/* The week of year, beginning on sunday. */
		حالت 'W':	/* The week of year, beginning on monday. */
			_LEGAL_ALT(_ALT_O);
			/*
			 * XXX This is bogus, as we can not assume any valid
			 * information present in the tm structure at this
			 * point to calculate a real value, so just check the
			 * range for now.
			 */
			 اگر (!(conv_عدد(&bp, &i, 0, 53)))
				واپس (تہی);
			 توڑو;

		حالت 'w':	/* The day of week, beginning on sunday. */
			_LEGAL_ALT(_ALT_O);
			اگر (!(conv_عدد(&bp, &tm->tm_wday, 0, 6)))
				واپس (تہی);
			توڑو;

		حالت 'Y':	/* The year. */
			_LEGAL_ALT(_ALT_E);
			اگر (!(conv_عدد(&bp, &i, 0, 9999)))
				واپس (تہی);

			relyear = -1;
			tm->tm_year = i - TM_YEAR_بنیاد;
			توڑو;

		حالت 'y':	/* The year within the century (2 digits). */
			_LEGAL_ALT(_ALT_E | _ALT_O);
			اگر (!(conv_عدد(&bp, &relyear, 0, 99)))
				واپس (تہی);
			توڑو;

		/*
		 * Miscellaneous conversions.
		 */
		حالت 'n':	/* Any kind of white-space. */
		حالت 't':
			_LEGAL_ALT(0);
			جب (خلا_ہے(*bp))
				bp++;
			توڑو;


		طےشدہ:	/* Unknown/unsupported conversion. */
			واپس (تہی);
		}


	}

	/*
	 * We need to evaluate the two digit year spec (%y)
	 * last as we can get a century spec (%C) at any time.
	 */
	اگر (relyear != -1) {
		اگر (century == TM_YEAR_بنیاد) {
			اگر (relyear <= 68)
				tm->tm_year = relyear + 2000 - TM_YEAR_بنیاد;
			ورنہ
				tm->tm_year = relyear + 1900 - TM_YEAR_بنیاد;
		} ورنہ {
			tm->tm_year = relyear + century - TM_YEAR_بنیاد;
		}
	}

	واپس ((حرف *)bp);
}


ساکن صحیح
conv_عدد(ثابت غیرعلامتی حرف **buf, صحیح *dest, صحیح llim, صحیح ulim)
{
	صحیح نتیجہ = 0;
	صحیح rulim = ulim;

	اگر (**buf < '0' || **buf > '9')
		واپس (0);

	/* we use rulim to break out of the loop when we run out of digits */
	کرو {
		نتیجہ *= 10;
		نتیجہ += *(*buf)++ - '0';
		rulim /= 10;
	} جب ((نتیجہ * 10 <= ulim) && rulim && **buf >= '0' && **buf <= '9');

	اگر (نتیجہ < llim || نتیجہ > ulim)
		واپس (0);

	*dest = نتیجہ;
	واپس (1);
}

#اگر_ختم /* HAVE_STRPTIME */

