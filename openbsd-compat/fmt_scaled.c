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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ifndef HAVE_FMT_SCALED

#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <ctype.h>
#ಅನ್ತರ್ಭಾವ <limits.h>

ಪ್ರಕಾರನಿರ್ದೇಶ ಗಣನಾ {
	NONE = 0, KILO = 1, MEGA = 2, GIGA = 3, TERA = 4, PETA = 5, EXA = 6
} unit_type;

/* These three arrays MUST be in sync!  XXX make a struct */
ಸ್ಥಿರ ಧ್ರುವ unit_type units[] = { NONE, KILO, MEGA, GIGA, TERA, PETA, EXA };
ಸ್ಥಿರ ಧ್ರುವ ವರ್ಣ scale_chars[] = "BKMGTPE";
ಸ್ಥಿರ ಧ್ರುವ long long scale_factors[] = {
	1LL,
	1024LL,
	1024LL*1024,
	1024LL*1024*1024,
	1024LL*1024*1024*1024,
	1024LL*1024*1024*1024*1024,
	1024LL*1024*1024*1024*1024*1024,
};
#define	SCALE_LENGTH (ಪರಿಮಾಣ(units)/ಪರಿಮಾಣ(units[0]))

#define MAX_DIGITS (SCALE_LENGTH * 3)	/* XXX strlen(sprintf("%lld", -1)? */

/* Convert the given input string "scaled" into numeric in "result".
 * Return 0 on success, -1 and errno set on error.
 */
ಪೂರ್ಣಾಙ್ಕ
scan_scaled(ವರ್ಣ *scaled, long long *result)
{
	ವರ್ಣ *p = scaled;
	ಪೂರ್ಣಾಙ್ಕ sign = 0;
	unsigned ಪೂರ್ಣಾಙ್ಕ i, ndigits = 0, fract_digits = 0, muls = 0, divs = 0;
	long long scale_fact = 1, whole = 0, fpart = 0;

	/* Skip leading whitespace */
	ಯಾವತ್ (isascii((unsigned ವರ್ಣ)*p) && isspace((unsigned ವರ್ಣ)*p))
		++p;

	/* Then at most one leading + or - */
	ಯಾವತ್ (*p == '-' || *p == '+') {
		ಯದಿ (*p == '-') {
			ಯದಿ (sign) {
				errno = EINVAL;
				ಪ್ರತ್ಯಾಗಮ -1;
			}
			sign = -1;
			++p;
		} ಅನ್ಯಥಾ ಯದಿ (*p == '+') {
			ಯದಿ (sign) {
				errno = EINVAL;
				ಪ್ರತ್ಯಾಗಮ -1;
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
	ಪ್ರತಿ (; isascii((unsigned ವರ್ಣ)*p) &&
	    (isdigit((unsigned ವರ್ಣ)*p) || *p=='.'); ++p) {
		ಯದಿ (*p == '.') {
			ಯದಿ (fract_digits > 0) {	/* oops, more than one '.' */
				errno = EINVAL;
				ಪ್ರತ್ಯಾಗಮ -1;
			}
			fract_digits = 1;
			ಅನುವರ್ತ;
		}

		i = (*p) - '0';			/* whew! finally a digit we can use */
		ಯದಿ (fract_digits > 0) {
			ಯದಿ (fract_digits >= MAX_DIGITS-1)
				/* ignore extra fractional digits */
				ಅನುವರ್ತ;
			fract_digits++;		/* for later scaling */
			ಯದಿ (fpart > LLONG_MAX / 10) {
				errno = ERANGE;
				ಪ್ರತ್ಯಾಗಮ -1;
			}
			fpart *= 10;
			ಯದಿ (i > LLONG_MAX - fpart) {
				errno = ERANGE;
				ಪ್ರತ್ಯಾಗಮ -1;
			}
			fpart += i;
		} ಅನ್ಯಥಾ {				/* normal digit */
			ಯದಿ (++ndigits >= MAX_DIGITS) {
				errno = ERANGE;
				ಪ್ರತ್ಯಾಗಮ -1;
			}
			ಯದಿ (whole > LLONG_MAX / 10) {
				errno = ERANGE;
				ಪ್ರತ್ಯಾಗಮ -1;
			}
			whole *= 10;
			ಯದಿ (i > LLONG_MAX - whole) {
				errno = ERANGE;
				ಪ್ರತ್ಯಾಗಮ -1;
			}
			whole += i;
		}
	}

	ಯದಿ (sign)
		whole *= sign;

	/* If no scale factor given, we're done. fraction is discarded. */
	ಯದಿ (!*p) {
		*result = whole;
		ಪ್ರತ್ಯಾಗಮ 0;
	}

	/* Validate scale factor, and scale whole and fraction by it. */
	ಪ್ರತಿ (i = 0; i < SCALE_LENGTH; i++) {

		/* Are we there yet? */
		ಯದಿ (*p == scale_chars[i] ||
			*p == tolower((unsigned ವರ್ಣ)scale_chars[i])) {

			/* If it ends with alphanumerics after the scale char, bad. */
			ಯದಿ (isalnum((unsigned ವರ್ಣ)*(p+1))) {
				errno = EINVAL;
				ಪ್ರತ್ಯಾಗಮ -1;
			}
			scale_fact = scale_factors[i];

			/* check for overflow and underflow after scaling */
			ಯದಿ (whole > LLONG_MAX / scale_fact ||
			    whole < LLONG_MIN / scale_fact) {
				errno = ERANGE;
				ಪ್ರತ್ಯಾಗಮ -1;
			}

			/* scale whole part */
			whole *= scale_fact;

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
			ಯಾವತ್ (muls > 0 && divs > 0) {
				ಯದಿ (fpart <= LLONG_MAX / 1024) {
					fpart *= 1024;
					muls--;
				} ಅನ್ಯಥಾ {
					fpart /= 10;
					divs--;
				}
			}
			ಯಾವತ್ (muls > 0) {
				fpart *= 1024;
				muls--;
			}
			ಯಾವತ್ (divs > 0) {
				fpart /= 10;
				divs--;
			}
			ಯದಿ (sign == -1)
				whole -= fpart;
			ಅನ್ಯಥಾ
				whole += fpart;
			*result = whole;
			ಪ್ರತ್ಯಾಗಮ 0;
		}
	}

	/* Invalid unit or character */
	errno = EINVAL;
	ಪ್ರತ್ಯಾಗಮ -1;
}

/* Format the given "number" into human-readable form in "result".
 * Result must point to an allocated buffer of length FMT_SCALED_STRSIZE.
 * Return 0 on success, -1 and errno set if error.
 */
ಪೂರ್ಣಾಙ್ಕ
fmt_scaled(long long ಸಂಖ್ಯೆ, ವರ್ಣ *result)
{
	long long abval, fract = 0;
	unsigned ಪೂರ್ಣಾಙ್ಕ i;
	unit_type unit = NONE;

	/* Not every negative long long has a positive representation. */
	ಯದಿ (ಸಂಖ್ಯೆ == LLONG_MIN) {
		errno = ERANGE;
		ಪ್ರತ್ಯಾಗಮ -1;
	}

	abval = llabs(ಸಂಖ್ಯೆ);

	/* Also check for numbers that are just too darned big to format. */
	ಯದಿ (abval / 1024 >= scale_factors[SCALE_LENGTH-1]) {
		errno = ERANGE;
		ಪ್ರತ್ಯಾಗಮ -1;
	}

	/* scale whole part; get unscaled fraction */
	ಪ್ರತಿ (i = 0; i < SCALE_LENGTH; i++) {
		ಯದಿ (abval/1024 < scale_factors[i]) {
			unit = units[i];
			fract = (i == 0) ? 0 : abval % scale_factors[i];
			ಸಂಖ್ಯೆ /= scale_factors[i];
			ಯದಿ (i > 0)
				fract /= scale_factors[i - 1];
			ಭಙ್ಗ;
		}
	}

	fract = (10 * fract + 512) / 1024;
	/* if the result would be >= 10, round main number */
	ಯದಿ (fract >= 10) {
		ಯದಿ (ಸಂಖ್ಯೆ >= 0)
			ಸಂಖ್ಯೆ++;
		ಅನ್ಯಥಾ
			ಸಂಖ್ಯೆ--;
		fract = 0;
	} ಅನ್ಯಥಾ ಯದಿ (fract < 0) {
		/* shouldn't happen */
		fract = 0;
	}

	ಯದಿ (ಸಂಖ್ಯೆ == 0)
		strlcpy(result, "0B", FMT_SCALED_STRSIZE);
	ಅನ್ಯಥಾ ಯದಿ (unit == NONE || ಸಂಖ್ಯೆ >= 100 || ಸಂಖ್ಯೆ <= -100) {
		ಯದಿ (fract >= 5) {
			ಯದಿ (ಸಂಖ್ಯೆ >= 0)
				ಸಂಖ್ಯೆ++;
			ಅನ್ಯಥಾ
				ಸಂಖ್ಯೆ--;
		}
		(ಶೂನ್ಯ)snprintf(result, FMT_SCALED_STRSIZE, "%lld%c",
			ಸಂಖ್ಯೆ, scale_chars[unit]);
	} ಅನ್ಯಥಾ
		(ಶೂನ್ಯ)snprintf(result, FMT_SCALED_STRSIZE, "%lld.%1lld%c",
			ಸಂಖ್ಯೆ, fract, scale_chars[unit]);

	ಪ್ರತ್ಯಾಗಮ 0;
}

#ifdef	MAIN
/*
 * This is the original version of the program in the man page.
 * Copy-and-paste whatever you need from it.
 */
ಪೂರ್ಣಾಙ್ಕ
main(ಪೂರ್ಣಾಙ್ಕ argc, ವರ್ಣ **argv)
{
	ವರ್ಣ *cinput = "1.5K", buf[FMT_SCALED_STRSIZE];
	long long ninput = 10483892, result;

	ಯದಿ (scan_scaled(cinput, &result) == 0)
		printf("\"%s\" -> %lld\n", cinput, result);
	ಅನ್ಯಥಾ
		perror(cinput);

	ಯದಿ (fmt_scaled(ninput, buf) == 0)
		printf("%lld -> \"%s\"\n", ninput, buf);
	ಅನ್ಯಥಾ
		fprintf(stderr, "%lld invalid (%s)\n", ninput, strerror(errno));

	ಪ್ರತ್ಯಾಗಮ 0;
}
#endif

#endif /* HAVE_FMT_SCALED */
