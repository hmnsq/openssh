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

#شامل "includes.h"

#اگر_غیر_تعریف_شدہ HAVE_FMT_SCALED

#شامل <stdio.h>
#شامل <stdlib.h>
#شامل <errno.h>
#شامل <string.h>
#شامل <ctype.h>
#شامل <limits.h>

قسمتعریف شمار {
	NONE = 0, KILO = 1, MEGA = 2, GIGA = 3, TERA = 4, PETA = 5, EXA = 6
} unit_type;

/* These three arrays MUST be in sync!  XXX make a struct */
ساکن ثابت unit_type units[] = { NONE, KILO, MEGA, GIGA, TERA, PETA, EXA };
ساکن ثابت حرف scale_chars[] = "BKMGTPE";
ساکن ثابت طویل طویل scale_factors[] = {
	1LL,
	1024LL,
	1024LL*1024,
	1024LL*1024*1024,
	1024LL*1024*1024*1024,
	1024LL*1024*1024*1024*1024,
	1024LL*1024*1024*1024*1024*1024,
};
#تعریف_کرو	SCALE_لمبائی (حجم(units)/حجم(units[0]))

#تعریف_کرو MAX_DIGITS (SCALE_لمبائی * 3)	/* XXX strlen(sprintf("%lld", -1)? */

/* Convert the given input string "scaled" into numeric in "result".
 * Return 0 on success, -1 and errno set on error.
 */
صحیح
جائزہ_scaled(حرف *scaled, طویل طویل *نتیجہ)
{
	حرف *p = scaled;
	صحیح sign = 0;
	غیرعلامتی صحیح i, ndigits = 0, fract_digits = 0, muls = 0, divs = 0;
	طویل طویل scale_fact = 1, پورا = 0, fpart = 0;

	/* Skip leading whitespace */
	جب (isascii((غیرعلامتی حرف)*p) && خلا_ہے((غیرعلامتی حرف)*p))
		++p;

	/* Then at most one leading + or - */
	جب (*p == '-' || *p == '+') {
		اگر (*p == '-') {
			اگر (sign) {
				errno = EINVAL;
				واپس -1;
			}
			sign = -1;
			++p;
		} ورنہ اگر (*p == '+') {
			اگر (sign) {
				errno = EINVAL;
				واپس -1;
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
	برائے (; isascii((غیرعلامتی حرف)*p) &&
	    (ہندسہ_ہے((غیرعلامتی حرف)*p) || *p=='.'); ++p) {
		اگر (*p == '.') {
			اگر (fract_digits > 0) {	/* oops, more than one '.' */
				errno = EINVAL;
				واپس -1;
			}
			fract_digits = 1;
			جاری;
		}

		i = (*p) - '0';			/* whew! finally a digit we can use */
		اگر (fract_digits > 0) {
			اگر (fract_digits >= MAX_DIGITS-1)
				/* ignore extra fractional digits */
				جاری;
			fract_digits++;		/* for later scaling */
			اگر (fpart > LLONG_MAX / 10) {
				errno = ERANGE;
				واپس -1;
			}
			fpart *= 10;
			اگر (i > LLONG_MAX - fpart) {
				errno = ERANGE;
				واپس -1;
			}
			fpart += i;
		} ورنہ {				/* normal digit */
			اگر (++ndigits >= MAX_DIGITS) {
				errno = ERANGE;
				واپس -1;
			}
			اگر (پورا > LLONG_MAX / 10) {
				errno = ERANGE;
				واپس -1;
			}
			پورا *= 10;
			اگر (i > LLONG_MAX - پورا) {
				errno = ERANGE;
				واپس -1;
			}
			پورا += i;
		}
	}

	اگر (sign)
		پورا *= sign;

	/* If no scale factor given, we're done. fraction is discarded. */
	اگر (!*p) {
		*نتیجہ = پورا;
		واپس 0;
	}

	/* Validate scale factor, and scale whole and fraction by it. */
	برائے (i = 0; i < SCALE_لمبائی; i++) {

		/* Are we there yet? */
		اگر (*p == scale_chars[i] ||
			*p == tolower((غیرعلامتی حرف)scale_chars[i])) {

			/* If it ends with alphanumerics after the scale char, bad. */
			اگر (حرف_یا_ہندسہ((غیرعلامتی حرف)*(p+1))) {
				errno = EINVAL;
				واپس -1;
			}
			scale_fact = scale_factors[i];

			/* check for overflow and underflow after scaling */
			اگر (پورا > LLONG_MAX / scale_fact ||
			    پورا < LLONG_MIN / scale_fact) {
				errno = ERANGE;
				واپس -1;
			}

			/* scale whole part */
			پورا *= scale_fact;

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
			جب (muls > 0 && divs > 0) {
				اگر (fpart <= LLONG_MAX / 1024) {
					fpart *= 1024;
					muls--;
				} ورنہ {
					fpart /= 10;
					divs--;
				}
			}
			جب (muls > 0) {
				fpart *= 1024;
				muls--;
			}
			جب (divs > 0) {
				fpart /= 10;
				divs--;
			}
			اگر (sign == -1)
				پورا -= fpart;
			ورنہ
				پورا += fpart;
			*نتیجہ = پورا;
			واپس 0;
		}
	}

	/* Invalid unit or character */
	errno = EINVAL;
	واپس -1;
}

/* Format the given "number" into human-readable form in "result".
 * Result must point to an allocated buffer of length FMT_SCALED_STRSIZE.
 * Return 0 on success, -1 and errno set if error.
 */
صحیح
fmt_scaled(طویل طویل نمبر, حرف *نتیجہ)
{
	طویل طویل abval, fract = 0;
	غیرعلامتی صحیح i;
	unit_type unit = NONE;

	/* Not every negative long long has a positive representation. */
	اگر (نمبر == LLONG_MIN) {
		errno = ERANGE;
		واپس -1;
	}

	abval = llabs(نمبر);

	/* Also check for numbers that are just too darned big to format. */
	اگر (abval / 1024 >= scale_factors[SCALE_لمبائی-1]) {
		errno = ERANGE;
		واپس -1;
	}

	/* scale whole part; get unscaled fraction */
	برائے (i = 0; i < SCALE_لمبائی; i++) {
		اگر (abval/1024 < scale_factors[i]) {
			unit = units[i];
			fract = (i == 0) ? 0 : abval % scale_factors[i];
			نمبر /= scale_factors[i];
			اگر (i > 0)
				fract /= scale_factors[i - 1];
			توڑو;
		}
	}

	fract = (10 * fract + 512) / 1024;
	/* if the result would be >= 10, round main number */
	اگر (fract >= 10) {
		اگر (نمبر >= 0)
			نمبر++;
		ورنہ
			نمبر--;
		fract = 0;
	} ورنہ اگر (fract < 0) {
		/* shouldn't happen */
		fract = 0;
	}

	اگر (نمبر == 0)
		strlcpy(نتیجہ, "0B", FMT_SCALED_STRSIZE);
	ورنہ اگر (unit == NONE || نمبر >= 100 || نمبر <= -100) {
		اگر (fract >= 5) {
			اگر (نمبر >= 0)
				نمبر++;
			ورنہ
				نمبر--;
		}
		(خالی)snprintf(نتیجہ, FMT_SCALED_STRSIZE, "%lld%c",
			نمبر, scale_chars[unit]);
	} ورنہ
		(خالی)snprintf(نتیجہ, FMT_SCALED_STRSIZE, "%lld.%1lld%c",
			نمبر, fract, scale_chars[unit]);

	واپس 0;
}

#اگر_تعریف_شدہ	MAIN
/*
 * This is the original version of the program in the man page.
 * Copy-and-paste whatever you need from it.
 */
صحیح
مین(صحیح argc, حرف **argv)
{
	حرف *cinput = "1.5K", buf[FMT_SCALED_STRSIZE];
	طویل طویل ninput = 10483892, نتیجہ;

	اگر (جائزہ_scaled(cinput, &نتیجہ) == 0)
		لکھو("\"%s\" -> %lld\n", cinput, نتیجہ);
	ورنہ
		perror(cinput);

	اگر (fmt_scaled(ninput, buf) == 0)
		لکھو("%lld -> \"%s\"\n", ninput, buf);
	ورنہ
		fprintf(stderr, "%lld invalid (%s)\n", ninput, strerror(errno));

	واپس 0;
}
#اگر_ختم

#اگر_ختم /* HAVE_FMT_SCALED */
