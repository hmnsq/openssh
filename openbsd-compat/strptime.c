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

#ضمن "includes.h"

#اگر_تعریف_نشده HAVE_STRPTIME

#تعریف_کن TM_YEAR_پایه 1900	/* from tzfile.h */

#ضمن <ctype.h>
#ضمن <locale.h>
#ضمن <string.h>
#ضمن <time.h>

/* #define	_ctloc(x)		(_CurrentTimeLocale->x) */

/*
 * We do not implement alternate representations. However, we always
 * check whether a given modifier is allowed for a certain conversion.
 */
#تعریف_کن _ALT_E			0x01
#تعریف_کن _ALT_O			0x02
#تعریف_کن	_LEGAL_ALT(x)		{ إذا (alt_format & ~(x)) أرجع (0); }


ساكن	صحيح conv_رقم(ثابت بیعلامت حرف **, صحيح *, صحيح, صحيح);
ساكن	حرف *_strptime(ثابت حرف *, ثابت حرف *, بنية tm *, صحيح);


حرف *
strptime(ثابت حرف *buf, ثابت حرف *fmt, بنية tm *tm)
{
	أرجع(_strptime(buf, fmt, tm, 1));
}

ساكن حرف *
_strptime(ثابت حرف *buf, ثابت حرف *fmt, بنية tm *tm, صحيح initialize)
{
	بیعلامت حرف c;
	ثابت بیعلامت حرف *bp;
	اندازه_t len;
	صحيح alt_format, i;
	ساكن صحيح century, relyear;

	إذا (initialize) {
		century = TM_YEAR_پایه;
		relyear = -1;
	}

	bp = (بیعلامت حرف *)buf;
	طالما ((c = *fmt) != '\0') {
		/* Clear `alternate' modifier prior to new conversion. */
		alt_format = 0;

		/* Eat up white-space. */
		إذا (آیا_فاصله(c)) {
			طالما (آیا_فاصله(*bp))
				bp++;

			fmt++;
			استمر;
		}
				
		إذا ((c = *fmt++) != '%')
			اذهب literal;


again:		بدل (c = *fmt++) {
		حالة '%':	/* "%%" is converted to "%". */
literal:
		إذا (c != *bp++)
			أرجع (عدم);

		اكسر;

		/*
		 * "Alternative" modifiers. Just set the appropriate flag
		 * and start over again.
		 */
		حالة 'E':	/* "%E?" alternative conversion modifier. */
			_LEGAL_ALT(0);
			alt_format |= _ALT_E;
			اذهب again;

		حالة 'O':	/* "%O?" alternative conversion modifier. */
			_LEGAL_ALT(0);
			alt_format |= _ALT_O;
			اذهب again;
			
		/*
		 * "Complex" conversion rules, implemented through recursion.
		 */
#إذا 0
		حالة 'c':	/* Date and time, using the locale's format. */
			_LEGAL_ALT(_ALT_E);
			إذا (!(bp = _strptime(bp, _ctloc(d_t_fmt), tm, 0)))
				أرجع (عدم);
			اكسر;
#پایان_اگر
		حالة 'D':	/* The date as "%m/%d/%y". */
			_LEGAL_ALT(0);
			إذا (!(bp = _strptime(bp, "%m/%d/%y", tm, 0)))
				أرجع (عدم);
			اكسر;
	
		حالة 'R':	/* The time as "%H:%M". */
			_LEGAL_ALT(0);
			إذا (!(bp = _strptime(bp, "%H:%M", tm, 0)))
				أرجع (عدم);
			اكسر;

		حالة 'r':	/* The time as "%I:%M:%S %p". */
			_LEGAL_ALT(0);
			إذا (!(bp = _strptime(bp, "%I:%M:%S %p", tm, 0)))
				أرجع (عدم);
			اكسر;

		حالة 'T':	/* The time as "%H:%M:%S". */
			_LEGAL_ALT(0);
			إذا (!(bp = _strptime(bp, "%H:%M:%S", tm, 0)))
				أرجع (عدم);
			اكسر;
#إذا 0
		حالة 'X':	/* The time, using the locale's format. */
			_LEGAL_ALT(_ALT_E);
			إذا (!(bp = _strptime(bp, _ctloc(t_fmt), tm, 0)))
				أرجع (عدم);
			اكسر;

		حالة 'x':	/* The date, using the locale's format. */
			_LEGAL_ALT(_ALT_E);
			إذا (!(bp = _strptime(bp, _ctloc(d_fmt), tm, 0)))
				أرجع (عدم);
			اكسر;
#پایان_اگر
		/*
		 * "Elementary" conversion rules.
		 */
#إذا 0
		حالة 'A':	/* The day of week, using the locale's form. */
		حالة 'a':
			_LEGAL_ALT(0);
			لكل (i = 0; i < 7; i++) {
				/* Full name. */
				len = طول_رشته(_ctloc(day[i]));
				إذا (strncasecmp(_ctloc(day[i]), bp, len) == 0)
					اكسر;

				/* Abbreviated name. */
				len = طول_رشته(_ctloc(abday[i]));
				إذا (strncasecmp(_ctloc(abday[i]), bp, len) == 0)
					اكسر;
			}

			/* Nothing matched. */
			إذا (i == 7)
				أرجع (عدم);

			tm->tm_wday = i;
			bp += len;
			اكسر;

		حالة 'B':	/* The month, using the locale's form. */
		حالة 'b':
		حالة 'h':
			_LEGAL_ALT(0);
			لكل (i = 0; i < 12; i++) {
				/* Full name. */
				len = طول_رشته(_ctloc(mon[i]));
				إذا (strncasecmp(_ctloc(mon[i]), bp, len) == 0)
					اكسر;

				/* Abbreviated name. */
				len = طول_رشته(_ctloc(abmon[i]));
				إذا (strncasecmp(_ctloc(abmon[i]), bp, len) == 0)
					اكسر;
			}

			/* Nothing matched. */
			إذا (i == 12)
				أرجع (عدم);

			tm->tm_mon = i;
			bp += len;
			اكسر;
#پایان_اگر

		حالة 'C':	/* The century number. */
			_LEGAL_ALT(_ALT_E);
			إذا (!(conv_رقم(&bp, &i, 0, 99)))
				أرجع (عدم);

			century = i * 100;
			اكسر;

		حالة 'd':	/* The day of month. */
		حالة 'e':
			_LEGAL_ALT(_ALT_O);
			إذا (!(conv_رقم(&bp, &tm->tm_mday, 1, 31)))
				أرجع (عدم);
			اكسر;

		حالة 'k':	/* The hour (24-hour clock representation). */
			_LEGAL_ALT(0);
			/* FALLTHROUGH */
		حالة 'H':
			_LEGAL_ALT(_ALT_O);
			إذا (!(conv_رقم(&bp, &tm->tm_hour, 0, 23)))
				أرجع (عدم);
			اكسر;

		حالة 'l':	/* The hour (12-hour clock representation). */
			_LEGAL_ALT(0);
			/* FALLTHROUGH */
		حالة 'I':
			_LEGAL_ALT(_ALT_O);
			إذا (!(conv_رقم(&bp, &tm->tm_hour, 1, 12)))
				أرجع (عدم);
			اكسر;

		حالة 'j':	/* The day of year. */
			_LEGAL_ALT(0);
			إذا (!(conv_رقم(&bp, &tm->tm_yday, 1, 366)))
				أرجع (عدم);
			tm->tm_yday--;
			اكسر;

		حالة 'M':	/* The minute. */
			_LEGAL_ALT(_ALT_O);
			إذا (!(conv_رقم(&bp, &tm->tm_min, 0, 59)))
				أرجع (عدم);
			اكسر;

		حالة 'm':	/* The month. */
			_LEGAL_ALT(_ALT_O);
			إذا (!(conv_رقم(&bp, &tm->tm_mon, 1, 12)))
				أرجع (عدم);
			tm->tm_mon--;
			اكسر;

#إذا 0
		حالة 'p':	/* The locale's equivalent of AM/PM. */
			_LEGAL_ALT(0);
			/* AM? */
			len = طول_رشته(_ctloc(am_pm[0]));
			إذا (strncasecmp(_ctloc(am_pm[0]), bp, len) == 0) {
				إذا (tm->tm_hour > 12)	/* i.e., 13:00 AM ?! */
					أرجع (عدم);
				وإلا إذا (tm->tm_hour == 12)
					tm->tm_hour = 0;

				bp += len;
				اكسر;
			}
			/* PM? */
			len = طول_رشته(_ctloc(am_pm[1]));
			إذا (strncasecmp(_ctloc(am_pm[1]), bp, len) == 0) {
				إذا (tm->tm_hour > 12)	/* i.e., 13:00 PM ?! */
					أرجع (عدم);
				وإلا إذا (tm->tm_hour < 12)
					tm->tm_hour += 12;

				bp += len;
				اكسر;
			}

			/* Nothing matched. */
			أرجع (عدم);
#پایان_اگر
		حالة 'S':	/* The seconds. */
			_LEGAL_ALT(_ALT_O);
			إذا (!(conv_رقم(&bp, &tm->tm_sec, 0, 61)))
				أرجع (عدم);
			اكسر;

		حالة 'U':	/* The week of year, beginning on sunday. */
		حالة 'W':	/* The week of year, beginning on monday. */
			_LEGAL_ALT(_ALT_O);
			/*
			 * XXX This is bogus, as we can not assume any valid
			 * information present in the tm structure at this
			 * point to calculate a real value, so just check the
			 * range for now.
			 */
			 إذا (!(conv_رقم(&bp, &i, 0, 53)))
				أرجع (عدم);
			 اكسر;

		حالة 'w':	/* The day of week, beginning on sunday. */
			_LEGAL_ALT(_ALT_O);
			إذا (!(conv_رقم(&bp, &tm->tm_wday, 0, 6)))
				أرجع (عدم);
			اكسر;

		حالة 'Y':	/* The year. */
			_LEGAL_ALT(_ALT_E);
			إذا (!(conv_رقم(&bp, &i, 0, 9999)))
				أرجع (عدم);

			relyear = -1;
			tm->tm_year = i - TM_YEAR_پایه;
			اكسر;

		حالة 'y':	/* The year within the century (2 digits). */
			_LEGAL_ALT(_ALT_E | _ALT_O);
			إذا (!(conv_رقم(&bp, &relyear, 0, 99)))
				أرجع (عدم);
			اكسر;

		/*
		 * Miscellaneous conversions.
		 */
		حالة 'n':	/* Any kind of white-space. */
		حالة 't':
			_LEGAL_ALT(0);
			طالما (آیا_فاصله(*bp))
				bp++;
			اكسر;


		افتراضي:	/* Unknown/unsupported conversion. */
			أرجع (عدم);
		}


	}

	/*
	 * We need to evaluate the two digit year spec (%y)
	 * last as we can get a century spec (%C) at any time.
	 */
	إذا (relyear != -1) {
		إذا (century == TM_YEAR_پایه) {
			إذا (relyear <= 68)
				tm->tm_year = relyear + 2000 - TM_YEAR_پایه;
			وإلا
				tm->tm_year = relyear + 1900 - TM_YEAR_پایه;
		} وإلا {
			tm->tm_year = relyear + century - TM_YEAR_پایه;
		}
	}

	أرجع ((حرف *)bp);
}


ساكن صحيح
conv_رقم(ثابت بیعلامت حرف **buf, صحيح *dest, صحيح llim, صحيح ulim)
{
	صحيح نتیجه = 0;
	صحيح rulim = ulim;

	إذا (**buf < '0' || **buf > '9')
		أرجع (0);

	/* we use rulim to break out of the loop when we run out of digits */
	افعل {
		نتیجه *= 10;
		نتیجه += *(*buf)++ - '0';
		rulim /= 10;
	} طالما ((نتیجه * 10 <= ulim) && rulim && **buf >= '0' && **buf <= '9');

	إذا (نتیجه < llim || نتیجه > ulim)
		أرجع (0);

	*dest = نتیجه;
	أرجع (1);
}

#پایان_اگر /* HAVE_STRPTIME */

