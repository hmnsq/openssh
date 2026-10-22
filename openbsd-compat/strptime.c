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

#अन्तर्भाव "includes.h"

#ifndef HAVE_STRPTIME

#define TM_YEAR_BASE 1900	/* from tzfile.h */

#अन्तर्भाव <ctype.h>
#अन्तर्भाव <locale.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <time.h>

/* #define	_ctloc(x)		(_CurrentTimeLocale->x) */

/*
 * We do not implement alternate representations. However, we always
 * check whether a given modifier is allowed for a certain conversion.
 */
#define _ALT_E			0x01
#define _ALT_O			0x02
#define	_LEGAL_ALT(x)		{ जर (alt_format & ~(x)) परत (0); }


स्थिर	पूर्णांक conv_अंक(स्थिरांक अचिन्हित अक्षर **, पूर्णांक *, पूर्णांक, पूर्णांक);
स्थिर	अक्षर *_strptime(स्थिरांक अक्षर *, स्थिरांक अक्षर *, संरचना पंचांग *, पूर्णांक);


अक्षर *
strptime(स्थिरांक अक्षर *buf, स्थिरांक अक्षर *fmt, संरचना पंचांग *पंचांग)
{
	परत(_strptime(buf, fmt, पंचांग, 1));
}

स्थिर अक्षर *
_strptime(स्थिरांक अक्षर *buf, स्थिरांक अक्षर *fmt, संरचना पंचांग *पंचांग, पूर्णांक initialize)
{
	अचिन्हित अक्षर c;
	स्थिरांक अचिन्हित अक्षर *bp;
	माप_प्रकार len;
	पूर्णांक alt_format, i;
	स्थिर पूर्णांक century, relyear;

	जर (initialize) {
		century = TM_YEAR_BASE;
		relyear = -1;
	}

	bp = (अचिन्हित अक्षर *)buf;
	पर्यंत ((c = *fmt) != '\0') {
		/* Clear `alternate' modifier prior to new conversion. */
		alt_format = 0;

		/* Eat up white-space. */
		जर (है_खाली(c)) {
			पर्यंत (है_खाली(*bp))
				bp++;

			fmt++;
			सुरूठेवा;
		}
				
		जर ((c = *fmt++) != '%')
			जा literal;


again:		निवड (c = *fmt++) {
		स्थिती '%':	/* "%%" is converted to "%". */
literal:
		जर (c != *bp++)
			परत (रिक्त);

		थांबा;

		/*
		 * "Alternative" modifiers. Just set the appropriate flag
		 * and start over again.
		 */
		स्थिती 'E':	/* "%E?" alternative conversion modifier. */
			_LEGAL_ALT(0);
			alt_format |= _ALT_E;
			जा again;

		स्थिती 'O':	/* "%O?" alternative conversion modifier. */
			_LEGAL_ALT(0);
			alt_format |= _ALT_O;
			जा again;
			
		/*
		 * "Complex" conversion rules, implemented through recursion.
		 */
#जर 0
		स्थिती 'c':	/* Date and time, using the locale's format. */
			_LEGAL_ALT(_ALT_E);
			जर (!(bp = _strptime(bp, _ctloc(d_t_fmt), पंचांग, 0)))
				परत (रिक्त);
			थांबा;
#endif
		स्थिती 'D':	/* The date as "%m/%d/%y". */
			_LEGAL_ALT(0);
			जर (!(bp = _strptime(bp, "%m/%d/%y", पंचांग, 0)))
				परत (रिक्त);
			थांबा;
	
		स्थिती 'R':	/* The time as "%H:%M". */
			_LEGAL_ALT(0);
			जर (!(bp = _strptime(bp, "%H:%M", पंचांग, 0)))
				परत (रिक्त);
			थांबा;

		स्थिती 'r':	/* The time as "%I:%M:%S %p". */
			_LEGAL_ALT(0);
			जर (!(bp = _strptime(bp, "%I:%M:%S %p", पंचांग, 0)))
				परत (रिक्त);
			थांबा;

		स्थिती 'T':	/* The time as "%H:%M:%S". */
			_LEGAL_ALT(0);
			जर (!(bp = _strptime(bp, "%H:%M:%S", पंचांग, 0)))
				परत (रिक्त);
			थांबा;
#जर 0
		स्थिती 'X':	/* The time, using the locale's format. */
			_LEGAL_ALT(_ALT_E);
			जर (!(bp = _strptime(bp, _ctloc(t_fmt), पंचांग, 0)))
				परत (रिक्त);
			थांबा;

		स्थिती 'x':	/* The date, using the locale's format. */
			_LEGAL_ALT(_ALT_E);
			जर (!(bp = _strptime(bp, _ctloc(d_fmt), पंचांग, 0)))
				परत (रिक्त);
			थांबा;
#endif
		/*
		 * "Elementary" conversion rules.
		 */
#जर 0
		स्थिती 'A':	/* The day of week, using the locale's form. */
		स्थिती 'a':
			_LEGAL_ALT(0);
			साठी (i = 0; i < 7; i++) {
				/* Full name. */
				len = म_माप(_ctloc(day[i]));
				जर (strncasecmp(_ctloc(day[i]), bp, len) == 0)
					थांबा;

				/* Abbreviated name. */
				len = म_माप(_ctloc(abday[i]));
				जर (strncasecmp(_ctloc(abday[i]), bp, len) == 0)
					थांबा;
			}

			/* Nothing matched. */
			जर (i == 7)
				परत (रिक्त);

			पंचांग->tm_wday = i;
			bp += len;
			थांबा;

		स्थिती 'B':	/* The month, using the locale's form. */
		स्थिती 'b':
		स्थिती 'h':
			_LEGAL_ALT(0);
			साठी (i = 0; i < 12; i++) {
				/* Full name. */
				len = म_माप(_ctloc(mon[i]));
				जर (strncasecmp(_ctloc(mon[i]), bp, len) == 0)
					थांबा;

				/* Abbreviated name. */
				len = म_माप(_ctloc(abmon[i]));
				जर (strncasecmp(_ctloc(abmon[i]), bp, len) == 0)
					थांबा;
			}

			/* Nothing matched. */
			जर (i == 12)
				परत (रिक्त);

			पंचांग->tm_mon = i;
			bp += len;
			थांबा;
#endif

		स्थिती 'C':	/* The century number. */
			_LEGAL_ALT(_ALT_E);
			जर (!(conv_अंक(&bp, &i, 0, 99)))
				परत (रिक्त);

			century = i * 100;
			थांबा;

		स्थिती 'd':	/* The day of month. */
		स्थिती 'e':
			_LEGAL_ALT(_ALT_O);
			जर (!(conv_अंक(&bp, &पंचांग->tm_mday, 1, 31)))
				परत (रिक्त);
			थांबा;

		स्थिती 'k':	/* The hour (24-hour clock representation). */
			_LEGAL_ALT(0);
			/* FALLTHROUGH */
		स्थिती 'H':
			_LEGAL_ALT(_ALT_O);
			जर (!(conv_अंक(&bp, &पंचांग->tm_hour, 0, 23)))
				परत (रिक्त);
			थांबा;

		स्थिती 'l':	/* The hour (12-hour clock representation). */
			_LEGAL_ALT(0);
			/* FALLTHROUGH */
		स्थिती 'I':
			_LEGAL_ALT(_ALT_O);
			जर (!(conv_अंक(&bp, &पंचांग->tm_hour, 1, 12)))
				परत (रिक्त);
			थांबा;

		स्थिती 'j':	/* The day of year. */
			_LEGAL_ALT(0);
			जर (!(conv_अंक(&bp, &पंचांग->tm_yday, 1, 366)))
				परत (रिक्त);
			पंचांग->tm_yday--;
			थांबा;

		स्थिती 'M':	/* The minute. */
			_LEGAL_ALT(_ALT_O);
			जर (!(conv_अंक(&bp, &पंचांग->tm_min, 0, 59)))
				परत (रिक्त);
			थांबा;

		स्थिती 'm':	/* The month. */
			_LEGAL_ALT(_ALT_O);
			जर (!(conv_अंक(&bp, &पंचांग->tm_mon, 1, 12)))
				परत (रिक्त);
			पंचांग->tm_mon--;
			थांबा;

#जर 0
		स्थिती 'p':	/* The locale's equivalent of AM/PM. */
			_LEGAL_ALT(0);
			/* AM? */
			len = म_माप(_ctloc(am_pm[0]));
			जर (strncasecmp(_ctloc(am_pm[0]), bp, len) == 0) {
				जर (पंचांग->tm_hour > 12)	/* i.e., 13:00 AM ?! */
					परत (रिक्त);
				अन्यथा जर (पंचांग->tm_hour == 12)
					पंचांग->tm_hour = 0;

				bp += len;
				थांबा;
			}
			/* PM? */
			len = म_माप(_ctloc(am_pm[1]));
			जर (strncasecmp(_ctloc(am_pm[1]), bp, len) == 0) {
				जर (पंचांग->tm_hour > 12)	/* i.e., 13:00 PM ?! */
					परत (रिक्त);
				अन्यथा जर (पंचांग->tm_hour < 12)
					पंचांग->tm_hour += 12;

				bp += len;
				थांबा;
			}

			/* Nothing matched. */
			परत (रिक्त);
#endif
		स्थिती 'S':	/* The seconds. */
			_LEGAL_ALT(_ALT_O);
			जर (!(conv_अंक(&bp, &पंचांग->tm_sec, 0, 61)))
				परत (रिक्त);
			थांबा;

		स्थिती 'U':	/* The week of year, beginning on sunday. */
		स्थिती 'W':	/* The week of year, beginning on monday. */
			_LEGAL_ALT(_ALT_O);
			/*
			 * XXX This is bogus, as we can not assume any valid
			 * information present in the tm structure at this
			 * point to calculate a real value, so just check the
			 * range for now.
			 */
			 जर (!(conv_अंक(&bp, &i, 0, 53)))
				परत (रिक्त);
			 थांबा;

		स्थिती 'w':	/* The day of week, beginning on sunday. */
			_LEGAL_ALT(_ALT_O);
			जर (!(conv_अंक(&bp, &पंचांग->tm_wday, 0, 6)))
				परत (रिक्त);
			थांबा;

		स्थिती 'Y':	/* The year. */
			_LEGAL_ALT(_ALT_E);
			जर (!(conv_अंक(&bp, &i, 0, 9999)))
				परत (रिक्त);

			relyear = -1;
			पंचांग->tm_year = i - TM_YEAR_BASE;
			थांबा;

		स्थिती 'y':	/* The year within the century (2 digits). */
			_LEGAL_ALT(_ALT_E | _ALT_O);
			जर (!(conv_अंक(&bp, &relyear, 0, 99)))
				परत (रिक्त);
			थांबा;

		/*
		 * Miscellaneous conversions.
		 */
		स्थिती 'n':	/* Any kind of white-space. */
		स्थिती 't':
			_LEGAL_ALT(0);
			पर्यंत (है_खाली(*bp))
				bp++;
			थांबा;


		पूर्वनिर्धारित:	/* Unknown/unsupported conversion. */
			परत (रिक्त);
		}


	}

	/*
	 * We need to evaluate the two digit year spec (%y)
	 * last as we can get a century spec (%C) at any time.
	 */
	जर (relyear != -1) {
		जर (century == TM_YEAR_BASE) {
			जर (relyear <= 68)
				पंचांग->tm_year = relyear + 2000 - TM_YEAR_BASE;
			अन्यथा
				पंचांग->tm_year = relyear + 1900 - TM_YEAR_BASE;
		} अन्यथा {
			पंचांग->tm_year = relyear + century - TM_YEAR_BASE;
		}
	}

	परत ((अक्षर *)bp);
}


स्थिर पूर्णांक
conv_अंक(स्थिरांक अचिन्हित अक्षर **buf, पूर्णांक *dest, पूर्णांक llim, पूर्णांक ulim)
{
	पूर्णांक result = 0;
	पूर्णांक rulim = ulim;

	जर (**buf < '0' || **buf > '9')
		परत (0);

	/* we use rulim to break out of the loop when we run out of digits */
	करा {
		result *= 10;
		result += *(*buf)++ - '0';
		rulim /= 10;
	} पर्यंत ((result * 10 <= ulim) && rulim && **buf >= '0' && **buf <= '9');

	जर (result < llim || result > ulim)
		परत (0);

	*dest = result;
	परत (1);
}

#endif /* HAVE_STRPTIME */

