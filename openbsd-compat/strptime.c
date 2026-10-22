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
#define	_LEGAL_ALT(x)		{ यदि (alt_format & ~(x)) फर्काऊ (0); }


स्थिर	पूर्णाङ्क conv_अङ्क(अचर अचिन्हित वर्ण **, पूर्णाङ्क *, पूर्णाङ्क, पूर्णाङ्क);
स्थिर	वर्ण *_strptime(अचर वर्ण *, अचर वर्ण *, संरचना पंचांग *, पूर्णाङ्क);


वर्ण *
strptime(अचर वर्ण *buf, अचर वर्ण *fmt, संरचना पंचांग *पंचांग)
{
	फर्काऊ(_strptime(buf, fmt, पंचांग, 1));
}

स्थिर वर्ण *
_strptime(अचर वर्ण *buf, अचर वर्ण *fmt, संरचना पंचांग *पंचांग, पूर्णाङ्क initialize)
{
	अचिन्हित वर्ण c;
	अचर अचिन्हित वर्ण *bp;
	माप_प्रकार len;
	पूर्णाङ्क alt_format, i;
	स्थिर पूर्णाङ्क century, relyear;

	यदि (initialize) {
		century = TM_YEAR_BASE;
		relyear = -1;
	}

	bp = (अचिन्हित वर्ण *)buf;
	जबसम्म ((c = *fmt) != '\0') {
		/* Clear `alternate' modifier prior to new conversion. */
		alt_format = 0;

		/* Eat up white-space. */
		यदि (है_खाली(c)) {
			जबसम्म (है_खाली(*bp))
				bp++;

			fmt++;
			जारी;
		}
				
		यदि ((c = *fmt++) != '%')
			गच्छ literal;


again:		विकल्प (c = *fmt++) {
		पक्ष '%':	/* "%%" is converted to "%". */
literal:
		यदि (c != *bp++)
			फर्काऊ (रिक्त);

		रोक;

		/*
		 * "Alternative" modifiers. Just set the appropriate flag
		 * and start over again.
		 */
		पक्ष 'E':	/* "%E?" alternative conversion modifier. */
			_LEGAL_ALT(0);
			alt_format |= _ALT_E;
			गच्छ again;

		पक्ष 'O':	/* "%O?" alternative conversion modifier. */
			_LEGAL_ALT(0);
			alt_format |= _ALT_O;
			गच्छ again;
			
		/*
		 * "Complex" conversion rules, implemented through recursion.
		 */
#यदि 0
		पक्ष 'c':	/* Date and time, using the locale's format. */
			_LEGAL_ALT(_ALT_E);
			यदि (!(bp = _strptime(bp, _ctloc(d_t_fmt), पंचांग, 0)))
				फर्काऊ (रिक्त);
			रोक;
#endif
		पक्ष 'D':	/* The date as "%m/%d/%y". */
			_LEGAL_ALT(0);
			यदि (!(bp = _strptime(bp, "%m/%d/%y", पंचांग, 0)))
				फर्काऊ (रिक्त);
			रोक;
	
		पक्ष 'R':	/* The time as "%H:%M". */
			_LEGAL_ALT(0);
			यदि (!(bp = _strptime(bp, "%H:%M", पंचांग, 0)))
				फर्काऊ (रिक्त);
			रोक;

		पक्ष 'r':	/* The time as "%I:%M:%S %p". */
			_LEGAL_ALT(0);
			यदि (!(bp = _strptime(bp, "%I:%M:%S %p", पंचांग, 0)))
				फर्काऊ (रिक्त);
			रोक;

		पक्ष 'T':	/* The time as "%H:%M:%S". */
			_LEGAL_ALT(0);
			यदि (!(bp = _strptime(bp, "%H:%M:%S", पंचांग, 0)))
				फर्काऊ (रिक्त);
			रोक;
#यदि 0
		पक्ष 'X':	/* The time, using the locale's format. */
			_LEGAL_ALT(_ALT_E);
			यदि (!(bp = _strptime(bp, _ctloc(t_fmt), पंचांग, 0)))
				फर्काऊ (रिक्त);
			रोक;

		पक्ष 'x':	/* The date, using the locale's format. */
			_LEGAL_ALT(_ALT_E);
			यदि (!(bp = _strptime(bp, _ctloc(d_fmt), पंचांग, 0)))
				फर्काऊ (रिक्त);
			रोक;
#endif
		/*
		 * "Elementary" conversion rules.
		 */
#यदि 0
		पक्ष 'A':	/* The day of week, using the locale's form. */
		पक्ष 'a':
			_LEGAL_ALT(0);
			लागि (i = 0; i < 7; i++) {
				/* Full name. */
				len = म_माप(_ctloc(day[i]));
				यदि (strncasecmp(_ctloc(day[i]), bp, len) == 0)
					रोक;

				/* Abbreviated name. */
				len = म_माप(_ctloc(abday[i]));
				यदि (strncasecmp(_ctloc(abday[i]), bp, len) == 0)
					रोक;
			}

			/* Nothing matched. */
			यदि (i == 7)
				फर्काऊ (रिक्त);

			पंचांग->tm_wday = i;
			bp += len;
			रोक;

		पक्ष 'B':	/* The month, using the locale's form. */
		पक्ष 'b':
		पक्ष 'h':
			_LEGAL_ALT(0);
			लागि (i = 0; i < 12; i++) {
				/* Full name. */
				len = म_माप(_ctloc(mon[i]));
				यदि (strncasecmp(_ctloc(mon[i]), bp, len) == 0)
					रोक;

				/* Abbreviated name. */
				len = म_माप(_ctloc(abmon[i]));
				यदि (strncasecmp(_ctloc(abmon[i]), bp, len) == 0)
					रोक;
			}

			/* Nothing matched. */
			यदि (i == 12)
				फर्काऊ (रिक्त);

			पंचांग->tm_mon = i;
			bp += len;
			रोक;
#endif

		पक्ष 'C':	/* The century number. */
			_LEGAL_ALT(_ALT_E);
			यदि (!(conv_अङ्क(&bp, &i, 0, 99)))
				फर्काऊ (रिक्त);

			century = i * 100;
			रोक;

		पक्ष 'd':	/* The day of month. */
		पक्ष 'e':
			_LEGAL_ALT(_ALT_O);
			यदि (!(conv_अङ्क(&bp, &पंचांग->tm_mday, 1, 31)))
				फर्काऊ (रिक्त);
			रोक;

		पक्ष 'k':	/* The hour (24-hour clock representation). */
			_LEGAL_ALT(0);
			/* FALLTHROUGH */
		पक्ष 'H':
			_LEGAL_ALT(_ALT_O);
			यदि (!(conv_अङ्क(&bp, &पंचांग->tm_hour, 0, 23)))
				फर्काऊ (रिक्त);
			रोक;

		पक्ष 'l':	/* The hour (12-hour clock representation). */
			_LEGAL_ALT(0);
			/* FALLTHROUGH */
		पक्ष 'I':
			_LEGAL_ALT(_ALT_O);
			यदि (!(conv_अङ्क(&bp, &पंचांग->tm_hour, 1, 12)))
				फर्काऊ (रिक्त);
			रोक;

		पक्ष 'j':	/* The day of year. */
			_LEGAL_ALT(0);
			यदि (!(conv_अङ्क(&bp, &पंचांग->tm_yday, 1, 366)))
				फर्काऊ (रिक्त);
			पंचांग->tm_yday--;
			रोक;

		पक्ष 'M':	/* The minute. */
			_LEGAL_ALT(_ALT_O);
			यदि (!(conv_अङ्क(&bp, &पंचांग->tm_min, 0, 59)))
				फर्काऊ (रिक्त);
			रोक;

		पक्ष 'm':	/* The month. */
			_LEGAL_ALT(_ALT_O);
			यदि (!(conv_अङ्क(&bp, &पंचांग->tm_mon, 1, 12)))
				फर्काऊ (रिक्त);
			पंचांग->tm_mon--;
			रोक;

#यदि 0
		पक्ष 'p':	/* The locale's equivalent of AM/PM. */
			_LEGAL_ALT(0);
			/* AM? */
			len = म_माप(_ctloc(am_pm[0]));
			यदि (strncasecmp(_ctloc(am_pm[0]), bp, len) == 0) {
				यदि (पंचांग->tm_hour > 12)	/* i.e., 13:00 AM ?! */
					फर्काऊ (रिक्त);
				अन्यथा यदि (पंचांग->tm_hour == 12)
					पंचांग->tm_hour = 0;

				bp += len;
				रोक;
			}
			/* PM? */
			len = म_माप(_ctloc(am_pm[1]));
			यदि (strncasecmp(_ctloc(am_pm[1]), bp, len) == 0) {
				यदि (पंचांग->tm_hour > 12)	/* i.e., 13:00 PM ?! */
					फर्काऊ (रिक्त);
				अन्यथा यदि (पंचांग->tm_hour < 12)
					पंचांग->tm_hour += 12;

				bp += len;
				रोक;
			}

			/* Nothing matched. */
			फर्काऊ (रिक्त);
#endif
		पक्ष 'S':	/* The seconds. */
			_LEGAL_ALT(_ALT_O);
			यदि (!(conv_अङ्क(&bp, &पंचांग->tm_sec, 0, 61)))
				फर्काऊ (रिक्त);
			रोक;

		पक्ष 'U':	/* The week of year, beginning on sunday. */
		पक्ष 'W':	/* The week of year, beginning on monday. */
			_LEGAL_ALT(_ALT_O);
			/*
			 * XXX This is bogus, as we can not assume any valid
			 * information present in the tm structure at this
			 * point to calculate a real value, so just check the
			 * range for now.
			 */
			 यदि (!(conv_अङ्क(&bp, &i, 0, 53)))
				फर्काऊ (रिक्त);
			 रोक;

		पक्ष 'w':	/* The day of week, beginning on sunday. */
			_LEGAL_ALT(_ALT_O);
			यदि (!(conv_अङ्क(&bp, &पंचांग->tm_wday, 0, 6)))
				फर्काऊ (रिक्त);
			रोक;

		पक्ष 'Y':	/* The year. */
			_LEGAL_ALT(_ALT_E);
			यदि (!(conv_अङ्क(&bp, &i, 0, 9999)))
				फर्काऊ (रिक्त);

			relyear = -1;
			पंचांग->tm_year = i - TM_YEAR_BASE;
			रोक;

		पक्ष 'y':	/* The year within the century (2 digits). */
			_LEGAL_ALT(_ALT_E | _ALT_O);
			यदि (!(conv_अङ्क(&bp, &relyear, 0, 99)))
				फर्काऊ (रिक्त);
			रोक;

		/*
		 * Miscellaneous conversions.
		 */
		पक्ष 'n':	/* Any kind of white-space. */
		पक्ष 't':
			_LEGAL_ALT(0);
			जबसम्म (है_खाली(*bp))
				bp++;
			रोक;


		स्वभाव:	/* Unknown/unsupported conversion. */
			फर्काऊ (रिक्त);
		}


	}

	/*
	 * We need to evaluate the two digit year spec (%y)
	 * last as we can get a century spec (%C) at any time.
	 */
	यदि (relyear != -1) {
		यदि (century == TM_YEAR_BASE) {
			यदि (relyear <= 68)
				पंचांग->tm_year = relyear + 2000 - TM_YEAR_BASE;
			अन्यथा
				पंचांग->tm_year = relyear + 1900 - TM_YEAR_BASE;
		} अन्यथा {
			पंचांग->tm_year = relyear + century - TM_YEAR_BASE;
		}
	}

	फर्काऊ ((वर्ण *)bp);
}


स्थिर पूर्णाङ्क
conv_अङ्क(अचर अचिन्हित वर्ण **buf, पूर्णाङ्क *dest, पूर्णाङ्क llim, पूर्णाङ्क ulim)
{
	पूर्णाङ्क result = 0;
	पूर्णाङ्क rulim = ulim;

	यदि (**buf < '0' || **buf > '9')
		फर्काऊ (0);

	/* we use rulim to break out of the loop when we run out of digits */
	गर {
		result *= 10;
		result += *(*buf)++ - '0';
		rulim /= 10;
	} जबसम्म ((result * 10 <= ulim) && rulim && **buf >= '0' && **buf <= '9');

	यदि (result < llim || result > ulim)
		फर्काऊ (0);

	*dest = result;
	फर्काऊ (1);
}

#endif /* HAVE_STRPTIME */

