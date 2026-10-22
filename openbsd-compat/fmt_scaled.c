/*	$OpenBSD: fmt_scaled.c,v 1.25 2026/06/06 23:53:59 djm Exp $	*/

/*
 * Copyright (c) 2001, 2002, 2003 Ian F. Darwin.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/* OPENBSD ORIGINAL: lib/libutil/fmt_scaled.c */

/*
 * fmt_scaled: Format numbers scaled for human comprehension
 * scan_scaled: Scan numbers in this format.
 *
 * "Human-readable" output uses 4 digits max, and puts a unit suffix at
 * the end.  Makes output compact and easy-to-read esp. on huge disks.
 * Formatting code was originally in OpenBSD "df", converted to library routine.
 * Scanning code written for OpenBSD libutil.
 */

#ضمن "includes.h"

#که_نه_تعریف_شوی HAVE_FMT_SCALED

#ضمن <stdio.h>
#ضمن <stdlib.h>
#ضمن <errno.h>
#ضمن <string.h>
#ضمن <ctype.h>
#ضمن <limits.h>

تعريفنوع تعداد {
	NONE = 0, KILO = 1, MEGA = 2, GIGA = 3, TERA = 4, PETA = 5, EXA = 6
} unit_type;

/* These three arrays MUST be in sync!  XXX make a struct */
ساكن ثابت unit_type units[] = { NONE, KILO, MEGA, GIGA, TERA, PETA, EXA };
ساكن ثابت حرف scale_chars[] = "BKMGTPE";
ساكن ثابت اوږد اوږد scale_factors[] = {
	1LL,
	1024LL,
	1024LL*1024,
	1024LL*1024*1024,
	1024LL*1024*1024*1024,
	1024LL*1024*1024*1024*1024,
	1024LL*1024*1024*1024*1024*1024,
};
#تعریف_کړه	SCALE_اوږدتیا (حجم(units)/حجم(units[0]))

#تعریف_کړه MAX_DIGITS (SCALE_اوږدتیا * 3)	/* XXX strlen(sprintf("%lld", -1)? */

/* Convert the given input string "scaled" into numeric in "result".
 * Return 0 on success, -1 and errno set on error.
 */
صحيح
لټون_scaled(حرف *scaled, اوږد اوږد *پایله)
{
	حرف *p = scaled;
	صحيح sign = 0;
	بینښه صحيح i, ndigits = 0, fract_digits = 0, muls = 0, divs = 0;
	اوږد اوږد scale_fact = 1, ټولیز = 0, fpart = 0;

	/* Skip leading whitespace */
	طالما (isascii((بینښه حرف)*p) && که_تشه((بینښه حرف)*p))
		++p;

	/* Then at most one leading + or - */
	طالما (*p == '-' || *p == '+') {
		إذا (*p == '-') {
			إذا (sign) {
				errno = EINVAL;
				أرجع -1;
			}
			sign = -1;
			++p;
		} وإلا إذا (*p == '+') {
			إذا (sign) {
				errno = EINVAL;
				أرجع -1;
			}
			sign = +1;
			++p;
		}
	}

	/* Main loop: Scan digits, find decimal point, if present.
	 * We don't allow exponentials, so no scientific notation
	 * (but note that E for Exa might look like e to some!).
	 * Advance 'p' to end, to get scale factor.
	 */
	لكل (; isascii((بینښه حرف)*p) &&
	    (که_عدد((بینښه حرف)*p) || *p=='.'); ++p) {
		إذا (*p == '.') {
			إذا (fract_digits > 0) {	/* oops, more than one '.' */
				errno = EINVAL;
				أرجع -1;
			}
			fract_digits = 1;
			استمر;
		}

		i = (*p) - '0';			/* whew! finally a digit we can use */
		إذا (fract_digits > 0) {
			إذا (fract_digits >= MAX_DIGITS-1)
				/* ignore extra fractional digits */
				استمر;
			fract_digits++;		/* for later scaling */
			إذا (fpart > LLONG_MAX / 10) {
				errno = ERANGE;
				أرجع -1;
			}
			fpart *= 10;
			إذا (i > LLONG_MAX - fpart) {
				errno = ERANGE;
				أرجع -1;
			}
			fpart += i;
		} وإلا {				/* normal digit */
			إذا (++ndigits >= MAX_DIGITS) {
				errno = ERANGE;
				أرجع -1;
			}
			إذا (ټولیز > LLONG_MAX / 10) {
				errno = ERANGE;
				أرجع -1;
			}
			ټولیز *= 10;
			إذا (i > LLONG_MAX - ټولیز) {
				errno = ERANGE;
				أرجع -1;
			}
			ټولیز += i;
		}
	}

	إذا (sign)
		ټولیز *= sign;

	/* If no scale factor given, we're done. fraction is discarded. */
	إذا (!*p) {
		*پایله = ټولیز;
		أرجع 0;
	}

	/* Validate scale factor, and scale whole and fraction by it. */
	لكل (i = 0; i < SCALE_اوږدتیا; i++) {

		/* Are we there yet? */
		إذا (*p == scale_chars[i] ||
			*p == tolower((بینښه حرف)scale_chars[i])) {

			/* If it ends with alphanumerics after the scale char, bad. */
			إذا (که_توری_یا_عدد((بینښه حرف)*(p+1))) {
				errno = EINVAL;
				أرجع -1;
			}
			scale_fact = scale_factors[i];

			/* check for overflow and underflow after scaling */
			إذا (ټولیز > LLONG_MAX / scale_fact ||
			    ټولیز < LLONG_MIN / scale_fact) {
				errno = ERANGE;
				أرجع -1;
			}

			/* scale whole part */
			ټولیز *= scale_fact;

			/*
			 * Scale fractional part: compute
			 *   fpart * scale_fact / 10^(fract_digits-1)
			 * without intermediate overflow. scale_fact is 1024^i,
			 * i.e. a power of 1024 = 2^10. Interleave
			 * multiply-by-1024 with divide-by-10 so the running
			 * value stays within long long range while preserving
			 * precision.
			 */
			muls = i;
			divs = fract_digits > 0 ?  fract_digits - 1 : 0;
			طالما (muls > 0 && divs > 0) {
				إذا (fpart <= LLONG_MAX / 1024) {
					fpart *= 1024;
					muls--;
				} وإلا {
					fpart /= 10;
					divs--;
				}
			}
			طالما (muls > 0) {
				fpart *= 1024;
				muls--;
			}
			طالما (divs > 0) {
				fpart /= 10;
				divs--;
			}
			إذا (sign == -1)
				ټولیز -= fpart;
			وإلا
				ټولیز += fpart;
			*پایله = ټولیز;
			أرجع 0;
		}
	}

	/* Invalid unit or character */
	errno = EINVAL;
	أرجع -1;
}

/* Format the given "number" into human-readable form in "result".
 * Result must point to an allocated buffer of length FMT_SCALED_STRSIZE.
 * Return 0 on success, -1 and errno set if error.
 */
صحيح
fmt_scaled(اوږد اوږد شمېره, حرف *پایله)
{
	اوږد اوږد abval, fract = 0;
	بینښه صحيح i;
	unit_type unit = NONE;

	/* Not every negative long long has a positive representation. */
	إذا (شمېره == LLONG_MIN) {
		errno = ERANGE;
		أرجع -1;
	}

	abval = llabs(شمېره);

	/* Also check for numbers that are just too darned big to format. */
	إذا (abval / 1024 >= scale_factors[SCALE_اوږدتیا-1]) {
		errno = ERANGE;
		أرجع -1;
	}

	/* scale whole part; get unscaled fraction */
	لكل (i = 0; i < SCALE_اوږدتیا; i++) {
		إذا (abval/1024 < scale_factors[i]) {
			unit = units[i];
			fract = (i == 0) ? 0 : abval % scale_factors[i];
			شمېره /= scale_factors[i];
			إذا (i > 0)
				fract /= scale_factors[i - 1];
			اكسر;
		}
	}

	fract = (10 * fract + 512) / 1024;
	/* if the result would be >= 10, round main number */
	إذا (fract >= 10) {
		إذا (شمېره >= 0)
			شمېره++;
		وإلا
			شمېره--;
		fract = 0;
	} وإلا إذا (fract < 0) {
		/* shouldn't happen */
		fract = 0;
	}

	إذا (شمېره == 0)
		strlcpy(پایله, "0B", FMT_SCALED_STRSIZE);
	وإلا إذا (unit == NONE || شمېره >= 100 || شمېره <= -100) {
		إذا (fract >= 5) {
			إذا (شمېره >= 0)
				شمېره++;
			وإلا
				شمېره--;
		}
		(فراغ)snprintf(پایله, FMT_SCALED_STRSIZE, "%lld%c",
			شمېره, scale_chars[unit]);
	} وإلا
		(فراغ)snprintf(پایله, FMT_SCALED_STRSIZE, "%lld.%1lld%c",
			شمېره, fract, scale_chars[unit]);

	أرجع 0;
}

#که_تعریف_شوی	MAIN
/*
 * This is the original version of the program in the man page.
 * Copy-and-paste whatever you need from it.
 */
صحيح
اصلي(صحيح argc, حرف **argv)
{
	حرف *cinput = "1.5K", buf[FMT_SCALED_STRSIZE];
	اوږد اوږد ninput = 10483892, پایله;

	إذا (لټون_scaled(cinput, &پایله) == 0)
		چاپ_کړه("\"%s\" -> %lld\n", cinput, پایله);
	وإلا
		perror(cinput);

	إذا (fmt_scaled(ninput, buf) == 0)
		چاپ_کړه("%lld -> \"%s\"\n", ninput, buf);
	وإلا
		fprintf(stderr, "%lld invalid (%s)\n", ninput, strerror(errno));

	أرجع 0;
}
#د_که_پای

#د_که_پای /* HAVE_FMT_SCALED */
