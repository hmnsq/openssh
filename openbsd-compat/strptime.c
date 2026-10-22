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

#समावेश "includes.h"

#अगर_अघोषित HAVE_STRPTIME

#घोषणा TM_YEAR_BASE 1900	/* from tzfile.h */

#समावेश <ctype.h>
#समावेश <locale.h>
#समावेश <string.h>
#समावेश <time.h>

/* #define	_ctloc(x)		(_CurrentTimeLocale->x) */

/*
 * We do not implement alternate representations. However, we always
 * check whether a given modifier is allowed for a certain conversion.
 */
#घोषणा _ALT_E			0x01
#घोषणा _ALT_O			0x02
#घोषणा	_LEGAL_ALT(x)		{ अगर (alt_format & ~(x)) वापस (0); }


अटल	पूर्णांक conv_अंक(स्थिर अचिन्हित अक्षर **, पूर्णांक *, पूर्णांक, पूर्णांक);
अटल	अक्षर *_strptime(स्थिर अक्षर *, स्थिर अक्षर *, काष्ठा पंचांग *, पूर्णांक);


अक्षर *
strptime(स्थिर अक्षर *buf, स्थिर अक्षर *fmt, काष्ठा पंचांग *पंचांग)
{
	वापस(_strptime(buf, fmt, पंचांग, 1));
}

अटल अक्षर *
_strptime(स्थिर अक्षर *buf, स्थिर अक्षर *fmt, काष्ठा पंचांग *पंचांग, पूर्णांक initialize)
{
	अचिन्हित अक्षर c;
	स्थिर अचिन्हित अक्षर *bp;
	माप_प्रकार len;
	पूर्णांक alt_format, i;
	अटल पूर्णांक century, relyear;

	अगर (initialize) {
		century = TM_YEAR_BASE;
		relyear = -1;
	}

	bp = (अचिन्हित अक्षर *)buf;
	जबतक ((c = *fmt) != '\0') {
		/* Clear `alternate' modifier prior to new conversion. */
		alt_format = 0;

		/* Eat up white-space. */
		अगर (है_खाली(c)) {
			जबतक (है_खाली(*bp))
				bp++;

			fmt++;
			जारी;
		}
				
		अगर ((c = *fmt++) != '%')
			जाओ literal;


again:		चयन (c = *fmt++) {
		हाल '%':	/* "%%" is converted to "%". */
literal:
		अगर (c != *bp++)
			वापस (शून्य);

		अवरोध;

		/*
		 * "Alternative" modifiers. Just set the appropriate flag
		 * and start over again.
		 */
		हाल 'E':	/* "%E?" alternative conversion modifier. */
			_LEGAL_ALT(0);
			alt_format |= _ALT_E;
			जाओ again;

		हाल 'O':	/* "%O?" alternative conversion modifier. */
			_LEGAL_ALT(0);
			alt_format |= _ALT_O;
			जाओ again;
			
		/*
		 * "Complex" conversion rules, implemented through recursion.
		 */
#अगर 0
		हाल 'c':	/* Date and time, using the locale's format. */
			_LEGAL_ALT(_ALT_E);
			अगर (!(bp = _strptime(bp, _ctloc(d_t_fmt), पंचांग, 0)))
				वापस (शून्य);
			अवरोध;
#पूर्ण_अगर
		हाल 'D':	/* The date as "%m/%d/%y". */
			_LEGAL_ALT(0);
			अगर (!(bp = _strptime(bp, "%m/%d/%y", पंचांग, 0)))
				वापस (शून्य);
			अवरोध;
	
		हाल 'R':	/* The time as "%H:%M". */
			_LEGAL_ALT(0);
			अगर (!(bp = _strptime(bp, "%H:%M", पंचांग, 0)))
				वापस (शून्य);
			अवरोध;

		हाल 'r':	/* The time as "%I:%M:%S %p". */
			_LEGAL_ALT(0);
			अगर (!(bp = _strptime(bp, "%I:%M:%S %p", पंचांग, 0)))
				वापस (शून्य);
			अवरोध;

		हाल 'T':	/* The time as "%H:%M:%S". */
			_LEGAL_ALT(0);
			अगर (!(bp = _strptime(bp, "%H:%M:%S", पंचांग, 0)))
				वापस (शून्य);
			अवरोध;
#अगर 0
		हाल 'X':	/* The time, using the locale's format. */
			_LEGAL_ALT(_ALT_E);
			अगर (!(bp = _strptime(bp, _ctloc(t_fmt), पंचांग, 0)))
				वापस (शून्य);
			अवरोध;

		हाल 'x':	/* The date, using the locale's format. */
			_LEGAL_ALT(_ALT_E);
			अगर (!(bp = _strptime(bp, _ctloc(d_fmt), पंचांग, 0)))
				वापस (शून्य);
			अवरोध;
#पूर्ण_अगर
		/*
		 * "Elementary" conversion rules.
		 */
#अगर 0
		हाल 'A':	/* The day of week, using the locale's form. */
		हाल 'a':
			_LEGAL_ALT(0);
			क्रम (i = 0; i < 7; i++) {
				/* Full name. */
				len = म_माप(_ctloc(day[i]));
				अगर (strncasecmp(_ctloc(day[i]), bp, len) == 0)
					अवरोध;

				/* Abbreviated name. */
				len = म_माप(_ctloc(abday[i]));
				अगर (strncasecmp(_ctloc(abday[i]), bp, len) == 0)
					अवरोध;
			}

			/* Nothing matched. */
			अगर (i == 7)
				वापस (शून्य);

			पंचांग->tm_wday = i;
			bp += len;
			अवरोध;

		हाल 'B':	/* The month, using the locale's form. */
		हाल 'b':
		हाल 'h':
			_LEGAL_ALT(0);
			क्रम (i = 0; i < 12; i++) {
				/* Full name. */
				len = म_माप(_ctloc(mon[i]));
				अगर (strncasecmp(_ctloc(mon[i]), bp, len) == 0)
					अवरोध;

				/* Abbreviated name. */
				len = म_माप(_ctloc(abmon[i]));
				अगर (strncasecmp(_ctloc(abmon[i]), bp, len) == 0)
					अवरोध;
			}

			/* Nothing matched. */
			अगर (i == 12)
				वापस (शून्य);

			पंचांग->tm_mon = i;
			bp += len;
			अवरोध;
#पूर्ण_अगर

		हाल 'C':	/* The century number. */
			_LEGAL_ALT(_ALT_E);
			अगर (!(conv_अंक(&bp, &i, 0, 99)))
				वापस (शून्य);

			century = i * 100;
			अवरोध;

		हाल 'd':	/* The day of month. */
		हाल 'e':
			_LEGAL_ALT(_ALT_O);
			अगर (!(conv_अंक(&bp, &पंचांग->tm_mday, 1, 31)))
				वापस (शून्य);
			अवरोध;

		हाल 'k':	/* The hour (24-hour clock representation). */
			_LEGAL_ALT(0);
			/* FALLTHROUGH */
		हाल 'H':
			_LEGAL_ALT(_ALT_O);
			अगर (!(conv_अंक(&bp, &पंचांग->tm_hour, 0, 23)))
				वापस (शून्य);
			अवरोध;

		हाल 'l':	/* The hour (12-hour clock representation). */
			_LEGAL_ALT(0);
			/* FALLTHROUGH */
		हाल 'I':
			_LEGAL_ALT(_ALT_O);
			अगर (!(conv_अंक(&bp, &पंचांग->tm_hour, 1, 12)))
				वापस (शून्य);
			अवरोध;

		हाल 'j':	/* The day of year. */
			_LEGAL_ALT(0);
			अगर (!(conv_अंक(&bp, &पंचांग->tm_yday, 1, 366)))
				वापस (शून्य);
			पंचांग->tm_yday--;
			अवरोध;

		हाल 'M':	/* The minute. */
			_LEGAL_ALT(_ALT_O);
			अगर (!(conv_अंक(&bp, &पंचांग->tm_min, 0, 59)))
				वापस (शून्य);
			अवरोध;

		हाल 'm':	/* The month. */
			_LEGAL_ALT(_ALT_O);
			अगर (!(conv_अंक(&bp, &पंचांग->tm_mon, 1, 12)))
				वापस (शून्य);
			पंचांग->tm_mon--;
			अवरोध;

#अगर 0
		हाल 'p':	/* The locale's equivalent of AM/PM. */
			_LEGAL_ALT(0);
			/* AM? */
			len = म_माप(_ctloc(am_pm[0]));
			अगर (strncasecmp(_ctloc(am_pm[0]), bp, len) == 0) {
				अगर (पंचांग->tm_hour > 12)	/* i.e., 13:00 AM ?! */
					वापस (शून्य);
				अन्यथा अगर (पंचांग->tm_hour == 12)
					पंचांग->tm_hour = 0;

				bp += len;
				अवरोध;
			}
			/* PM? */
			len = म_माप(_ctloc(am_pm[1]));
			अगर (strncasecmp(_ctloc(am_pm[1]), bp, len) == 0) {
				अगर (पंचांग->tm_hour > 12)	/* i.e., 13:00 PM ?! */
					वापस (शून्य);
				अन्यथा अगर (पंचांग->tm_hour < 12)
					पंचांग->tm_hour += 12;

				bp += len;
				अवरोध;
			}

			/* Nothing matched. */
			वापस (शून्य);
#पूर्ण_अगर
		हाल 'S':	/* The seconds. */
			_LEGAL_ALT(_ALT_O);
			अगर (!(conv_अंक(&bp, &पंचांग->tm_sec, 0, 61)))
				वापस (शून्य);
			अवरोध;

		हाल 'U':	/* The week of year, beginning on sunday. */
		हाल 'W':	/* The week of year, beginning on monday. */
			_LEGAL_ALT(_ALT_O);
			/*
			 * XXX This is bogus, as we can not assume any valid
			 * information present in the tm structure at this
			 * point to calculate a real value, so just check the
			 * range for now.
			 */
			 अगर (!(conv_अंक(&bp, &i, 0, 53)))
				वापस (शून्य);
			 अवरोध;

		हाल 'w':	/* The day of week, beginning on sunday. */
			_LEGAL_ALT(_ALT_O);
			अगर (!(conv_अंक(&bp, &पंचांग->tm_wday, 0, 6)))
				वापस (शून्य);
			अवरोध;

		हाल 'Y':	/* The year. */
			_LEGAL_ALT(_ALT_E);
			अगर (!(conv_अंक(&bp, &i, 0, 9999)))
				वापस (शून्य);

			relyear = -1;
			पंचांग->tm_year = i - TM_YEAR_BASE;
			अवरोध;

		हाल 'y':	/* The year within the century (2 digits). */
			_LEGAL_ALT(_ALT_E | _ALT_O);
			अगर (!(conv_अंक(&bp, &relyear, 0, 99)))
				वापस (शून्य);
			अवरोध;

		/*
		 * Miscellaneous conversions.
		 */
		हाल 'n':	/* Any kind of white-space. */
		हाल 't':
			_LEGAL_ALT(0);
			जबतक (है_खाली(*bp))
				bp++;
			अवरोध;


		शेष:	/* Unknown/unsupported conversion. */
			वापस (शून्य);
		}


	}

	/*
	 * We need to evaluate the two digit year spec (%y)
	 * last as we can get a century spec (%C) at any time.
	 */
	अगर (relyear != -1) {
		अगर (century == TM_YEAR_BASE) {
			अगर (relyear <= 68)
				पंचांग->tm_year = relyear + 2000 - TM_YEAR_BASE;
			अन्यथा
				पंचांग->tm_year = relyear + 1900 - TM_YEAR_BASE;
		} अन्यथा {
			पंचांग->tm_year = relyear + century - TM_YEAR_BASE;
		}
	}

	वापस ((अक्षर *)bp);
}


अटल पूर्णांक
conv_अंक(स्थिर अचिन्हित अक्षर **buf, पूर्णांक *dest, पूर्णांक llim, पूर्णांक ulim)
{
	पूर्णांक परिणाम = 0;
	पूर्णांक rulim = ulim;

	अगर (**buf < '0' || **buf > '9')
		वापस (0);

	/* we use rulim to break out of the loop when we run out of digits */
	करो {
		परिणाम *= 10;
		परिणाम += *(*buf)++ - '0';
		rulim /= 10;
	} जबतक ((परिणाम * 10 <= ulim) && rulim && **buf >= '0' && **buf <= '9');

	अगर (परिणाम < llim || परिणाम > ulim)
		वापस (0);

	*dest = परिणाम;
	वापस (1);
}

#पूर्ण_अगर /* HAVE_STRPTIME */

