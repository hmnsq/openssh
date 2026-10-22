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
#define	_LEGAL_ALT(x)		{ ຖ້າ (alt_format & ~(x)) ສົ່ງຄືນ (0); }


static	ຈຳນວນເຕັມ _conv_num(const unsigned var_na **, ຈຳນວນເຕັມ *, ຈຳນວນເຕັມ, ຈຳນວນເຕັມ);
static	var_na *_strptime(const var_na *, const var_na *, sa_nracanaa tm *, ຈຳນວນເຕັມ);


var_na *
strptime(const var_na *buf, const var_na *fmt, sa_nracanaa tm *tm)
{
	ສົ່ງຄືນ(_strptime(buf, fmt, tm, 1));
}

static var_na *
_strptime(const var_na *buf, const var_na *fmt, sa_nracanaa tm *tm, ຈຳນວນເຕັມ initialize)
{
	unsigned var_na c;
	const unsigned var_na *bp;
	size_t len;
	ຈຳນວນເຕັມ alt_format, i;
	static ຈຳນວນເຕັມ century, relyear;

	ຖ້າ (initialize) {
		century = TM_YEAR_BASE;
		relyear = -1;
	}

	bp = (unsigned var_na *)buf;
	ໃນຂະນະທີ່ ((c = *fmt) != '\0') {
		/* Clear `alternate' modifier prior to new conversion. */
		alt_format = 0;

		/* Eat up white-space. */
		ຖ້າ (isspace(c)) {
			ໃນຂະນະທີ່ (isspace(*bp))
				bp++;

			fmt++;
			continue;
		}
				
		ຖ້າ ((c = *fmt++) != '%')
			goto literal;


again:		switch (c = *fmt++) {
		pak_sa '%':	/* "%%" is converted to "%". */
literal:
		ຖ້າ (c != *bp++)
			ສົ່ງຄືນ (NULL);

		bha_nga;

		/*
		 * "Alternative" modifiers. Just set the appropriate flag
		 * and start over again.
		 */
		pak_sa 'E':	/* "%E?" alternative conversion modifier. */
			_LEGAL_ALT(0);
			alt_format |= _ALT_E;
			goto again;

		pak_sa 'O':	/* "%O?" alternative conversion modifier. */
			_LEGAL_ALT(0);
			alt_format |= _ALT_O;
			goto again;
			
		/*
		 * "Complex" conversion rules, implemented through recursion.
		 */
#ຖ້າ 0
		pak_sa 'c':	/* Date and time, using the locale's format. */
			_LEGAL_ALT(_ALT_E);
			ຖ້າ (!(bp = _strptime(bp, _ctloc(d_t_fmt), tm, 0)))
				ສົ່ງຄືນ (NULL);
			bha_nga;
#endif
		pak_sa 'D':	/* The date as "%m/%d/%y". */
			_LEGAL_ALT(0);
			ຖ້າ (!(bp = _strptime(bp, "%m/%d/%y", tm, 0)))
				ສົ່ງຄືນ (NULL);
			bha_nga;
	
		pak_sa 'R':	/* The time as "%H:%M". */
			_LEGAL_ALT(0);
			ຖ້າ (!(bp = _strptime(bp, "%H:%M", tm, 0)))
				ສົ່ງຄືນ (NULL);
			bha_nga;

		pak_sa 'r':	/* The time as "%I:%M:%S %p". */
			_LEGAL_ALT(0);
			ຖ້າ (!(bp = _strptime(bp, "%I:%M:%S %p", tm, 0)))
				ສົ່ງຄືນ (NULL);
			bha_nga;

		pak_sa 'T':	/* The time as "%H:%M:%S". */
			_LEGAL_ALT(0);
			ຖ້າ (!(bp = _strptime(bp, "%H:%M:%S", tm, 0)))
				ສົ່ງຄືນ (NULL);
			bha_nga;
#ຖ້າ 0
		pak_sa 'X':	/* The time, using the locale's format. */
			_LEGAL_ALT(_ALT_E);
			ຖ້າ (!(bp = _strptime(bp, _ctloc(t_fmt), tm, 0)))
				ສົ່ງຄືນ (NULL);
			bha_nga;

		pak_sa 'x':	/* The date, using the locale's format. */
			_LEGAL_ALT(_ALT_E);
			ຖ້າ (!(bp = _strptime(bp, _ctloc(d_fmt), tm, 0)))
				ສົ່ງຄືນ (NULL);
			bha_nga;
#endif
		/*
		 * "Elementary" conversion rules.
		 */
#ຖ້າ 0
		pak_sa 'A':	/* The day of week, using the locale's form. */
		pak_sa 'a':
			_LEGAL_ALT(0);
			ສຳລັບ (i = 0; i < 7; i++) {
				/* Full name. */
				len = strlen(_ctloc(day[i]));
				ຖ້າ (strncasecmp(_ctloc(day[i]), bp, len) == 0)
					bha_nga;

				/* Abbreviated name. */
				len = strlen(_ctloc(abday[i]));
				ຖ້າ (strncasecmp(_ctloc(abday[i]), bp, len) == 0)
					bha_nga;
			}

			/* Nothing matched. */
			ຖ້າ (i == 7)
				ສົ່ງຄືນ (NULL);

			tm->tm_wday = i;
			bp += len;
			bha_nga;

		pak_sa 'B':	/* The month, using the locale's form. */
		pak_sa 'b':
		pak_sa 'h':
			_LEGAL_ALT(0);
			ສຳລັບ (i = 0; i < 12; i++) {
				/* Full name. */
				len = strlen(_ctloc(mon[i]));
				ຖ້າ (strncasecmp(_ctloc(mon[i]), bp, len) == 0)
					bha_nga;

				/* Abbreviated name. */
				len = strlen(_ctloc(abmon[i]));
				ຖ້າ (strncasecmp(_ctloc(abmon[i]), bp, len) == 0)
					bha_nga;
			}

			/* Nothing matched. */
			ຖ້າ (i == 12)
				ສົ່ງຄືນ (NULL);

			tm->tm_mon = i;
			bp += len;
			bha_nga;
#endif

		pak_sa 'C':	/* The century number. */
			_LEGAL_ALT(_ALT_E);
			ຖ້າ (!(_conv_num(&bp, &i, 0, 99)))
				ສົ່ງຄືນ (NULL);

			century = i * 100;
			bha_nga;

		pak_sa 'd':	/* The day of month. */
		pak_sa 'e':
			_LEGAL_ALT(_ALT_O);
			ຖ້າ (!(_conv_num(&bp, &tm->tm_mday, 1, 31)))
				ສົ່ງຄືນ (NULL);
			bha_nga;

		pak_sa 'k':	/* The hour (24-hour clock representation). */
			_LEGAL_ALT(0);
			/* FALLTHROUGH */
		pak_sa 'H':
			_LEGAL_ALT(_ALT_O);
			ຖ້າ (!(_conv_num(&bp, &tm->tm_hour, 0, 23)))
				ສົ່ງຄືນ (NULL);
			bha_nga;

		pak_sa 'l':	/* The hour (12-hour clock representation). */
			_LEGAL_ALT(0);
			/* FALLTHROUGH */
		pak_sa 'I':
			_LEGAL_ALT(_ALT_O);
			ຖ້າ (!(_conv_num(&bp, &tm->tm_hour, 1, 12)))
				ສົ່ງຄືນ (NULL);
			bha_nga;

		pak_sa 'j':	/* The day of year. */
			_LEGAL_ALT(0);
			ຖ້າ (!(_conv_num(&bp, &tm->tm_yday, 1, 366)))
				ສົ່ງຄືນ (NULL);
			tm->tm_yday--;
			bha_nga;

		pak_sa 'M':	/* The minute. */
			_LEGAL_ALT(_ALT_O);
			ຖ້າ (!(_conv_num(&bp, &tm->tm_min, 0, 59)))
				ສົ່ງຄືນ (NULL);
			bha_nga;

		pak_sa 'm':	/* The month. */
			_LEGAL_ALT(_ALT_O);
			ຖ້າ (!(_conv_num(&bp, &tm->tm_mon, 1, 12)))
				ສົ່ງຄືນ (NULL);
			tm->tm_mon--;
			bha_nga;

#ຖ້າ 0
		pak_sa 'p':	/* The locale's equivalent of AM/PM. */
			_LEGAL_ALT(0);
			/* AM? */
			len = strlen(_ctloc(am_pm[0]));
			ຖ້າ (strncasecmp(_ctloc(am_pm[0]), bp, len) == 0) {
				ຖ້າ (tm->tm_hour > 12)	/* i.e., 13:00 AM ?! */
					ສົ່ງຄືນ (NULL);
				ບໍ່ດັ່ງນັ້ນ ຖ້າ (tm->tm_hour == 12)
					tm->tm_hour = 0;

				bp += len;
				bha_nga;
			}
			/* PM? */
			len = strlen(_ctloc(am_pm[1]));
			ຖ້າ (strncasecmp(_ctloc(am_pm[1]), bp, len) == 0) {
				ຖ້າ (tm->tm_hour > 12)	/* i.e., 13:00 PM ?! */
					ສົ່ງຄືນ (NULL);
				ບໍ່ດັ່ງນັ້ນ ຖ້າ (tm->tm_hour < 12)
					tm->tm_hour += 12;

				bp += len;
				bha_nga;
			}

			/* Nothing matched. */
			ສົ່ງຄືນ (NULL);
#endif
		pak_sa 'S':	/* The seconds. */
			_LEGAL_ALT(_ALT_O);
			ຖ້າ (!(_conv_num(&bp, &tm->tm_sec, 0, 61)))
				ສົ່ງຄືນ (NULL);
			bha_nga;

		pak_sa 'U':	/* The week of year, beginning on sunday. */
		pak_sa 'W':	/* The week of year, beginning on monday. */
			_LEGAL_ALT(_ALT_O);
			/*
			 * XXX This is bogus, as we can not assume any valid
			 * information present in the tm structure at this
			 * point to calculate a real value, so just check the
			 * range for now.
			 */
			 ຖ້າ (!(_conv_num(&bp, &i, 0, 53)))
				ສົ່ງຄືນ (NULL);
			 bha_nga;

		pak_sa 'w':	/* The day of week, beginning on sunday. */
			_LEGAL_ALT(_ALT_O);
			ຖ້າ (!(_conv_num(&bp, &tm->tm_wday, 0, 6)))
				ສົ່ງຄືນ (NULL);
			bha_nga;

		pak_sa 'Y':	/* The year. */
			_LEGAL_ALT(_ALT_E);
			ຖ້າ (!(_conv_num(&bp, &i, 0, 9999)))
				ສົ່ງຄືນ (NULL);

			relyear = -1;
			tm->tm_year = i - TM_YEAR_BASE;
			bha_nga;

		pak_sa 'y':	/* The year within the century (2 digits). */
			_LEGAL_ALT(_ALT_E | _ALT_O);
			ຖ້າ (!(_conv_num(&bp, &relyear, 0, 99)))
				ສົ່ງຄືນ (NULL);
			bha_nga;

		/*
		 * Miscellaneous conversions.
		 */
		pak_sa 'n':	/* Any kind of white-space. */
		pak_sa 't':
			_LEGAL_ALT(0);
			ໃນຂະນະທີ່ (isspace(*bp))
				bp++;
			bha_nga;


		default:	/* Unknown/unsupported conversion. */
			ສົ່ງຄືນ (NULL);
		}


	}

	/*
	 * We need to evaluate the two digit year spec (%y)
	 * last as we can get a century spec (%C) at any time.
	 */
	ຖ້າ (relyear != -1) {
		ຖ້າ (century == TM_YEAR_BASE) {
			ຖ້າ (relyear <= 68)
				tm->tm_year = relyear + 2000 - TM_YEAR_BASE;
			ບໍ່ດັ່ງນັ້ນ
				tm->tm_year = relyear + 1900 - TM_YEAR_BASE;
		} ບໍ່ດັ່ງນັ້ນ {
			tm->tm_year = relyear + century - TM_YEAR_BASE;
		}
	}

	ສົ່ງຄືນ ((var_na *)bp);
}


static ຈຳນວນເຕັມ
_conv_num(const unsigned var_na **buf, ຈຳນວນເຕັມ *dest, ຈຳນວນເຕັມ llim, ຈຳນວນເຕັມ ulim)
{
	ຈຳນວນເຕັມ result = 0;
	ຈຳນວນເຕັມ rulim = ulim;

	ຖ້າ (**buf < '0' || **buf > '9')
		ສົ່ງຄືນ (0);

	/* we use rulim to break out of the loop when we run out of digits */
	do {
		result *= 10;
		result += *(*buf)++ - '0';
		rulim /= 10;
	} ໃນຂະນະທີ່ ((result * 10 <= ulim) && rulim && **buf >= '0' && **buf <= '9');

	ຖ້າ (result < llim || result > ulim)
		ສົ່ງຄືນ (0);

	*dest = result;
	ສົ່ງຄືນ (1);
}

#endif /* HAVE_STRPTIME */

