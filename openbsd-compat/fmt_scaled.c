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

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_FMT_SCALED

#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <ctype.h>
#ಅನ್ತರ್ಭಾವ <limits.h>

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ಎಣಿಕೆ {
	NONE = 0, KILO = 1, MEGA = 2, GIGA = 3, TERA = 4, PETA = 5, EXA = 6
} unit_type;

/* These three arrays MUST be in sync!  XXX make a struct */
ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ unit_type units[] = { NONE, KILO, MEGA, GIGA, TERA, PETA, EXA };
ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ scale_chars[] = "BKMGTPE";
ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ ದೀರ್ಘ ದೀರ್ಘ scale_factors[] = {
	1LL,
	1024LL,
	1024LL*1024,
	1024LL*1024*1024,
	1024LL*1024*1024*1024,
	1024LL*1024*1024*1024*1024,
	1024LL*1024*1024*1024*1024*1024,
};
#ವ್ಯಾಖ್ಯಾನಿಸು	SCALE_ಉದ್ದಳತೆ (ಗಾತ್ರ(units)/ಗಾತ್ರ(units[0]))

#ವ್ಯಾಖ್ಯಾನಿಸು MAX_DIGITS (SCALE_ಉದ್ದಳತೆ * 3)	/* XXX strlen(sprintf("%lld", -1)? */

/* Convert the given input string "scaled" into numeric in "result".
 * Return 0 on success, -1 and errno set on error.
 */
ಪೂರ್ಣಾಂಕ
ಪರಿಶೀಲನೆ_scaled(ಅಕ್ಷರ *scaled, ದೀರ್ಘ ದೀರ್ಘ *ಫಲಿತಾಂಶ)
{
	ಅಕ್ಷರ *p = scaled;
	ಪೂರ್ಣಾಂಕ sign = 0;
	ಚಿಹ್ನೆರಹಿತ ಪೂರ್ಣಾಂಕ i, ndigits = 0, fract_digits = 0, muls = 0, divs = 0;
	ದೀರ್ಘ ದೀರ್ಘ scale_fact = 1, ಸಂಪೂರ್ಣ = 0, fpart = 0;

	/* Skip leading whitespace */
	ಆಗ (isascii((ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ)*p) && ಖಾಲಿಯೇ((ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ)*p))
		++p;

	/* Then at most one leading + or - */
	ಆಗ (*p == '-' || *p == '+') {
		ಆದರೆ (*p == '-') {
			ಆದರೆ (sign) {
				errno = EINVAL;
				ಹಿಂತಿರುಗಿ -1;
			}
			sign = -1;
			++p;
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (*p == '+') {
			ಆದರೆ (sign) {
				errno = EINVAL;
				ಹಿಂತಿರುಗಿ -1;
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
	ಗಾಗಿ (; isascii((ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ)*p) &&
	    (ಅಂಕಿಯೇ((ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ)*p) || *p=='.'); ++p) {
		ಆದರೆ (*p == '.') {
			ಆದರೆ (fract_digits > 0) {	/* oops, more than one '.' */
				errno = EINVAL;
				ಹಿಂತಿರುಗಿ -1;
			}
			fract_digits = 1;
			ಮುಂದುವರಿ;
		}

		i = (*p) - '0';			/* whew! finally a digit we can use */
		ಆದರೆ (fract_digits > 0) {
			ಆದರೆ (fract_digits >= MAX_DIGITS-1)
				/* ignore extra fractional digits */
				ಮುಂದುವರಿ;
			fract_digits++;		/* for later scaling */
			ಆದರೆ (fpart > LLONG_MAX / 10) {
				errno = ERANGE;
				ಹಿಂತಿರುಗಿ -1;
			}
			fpart *= 10;
			ಆದರೆ (i > LLONG_MAX - fpart) {
				errno = ERANGE;
				ಹಿಂತಿರುಗಿ -1;
			}
			fpart += i;
		} ಇಲ್ಲದಿದ್ದರೆ {				/* normal digit */
			ಆದರೆ (++ndigits >= MAX_DIGITS) {
				errno = ERANGE;
				ಹಿಂತಿರುಗಿ -1;
			}
			ಆದರೆ (ಸಂಪೂರ್ಣ > LLONG_MAX / 10) {
				errno = ERANGE;
				ಹಿಂತಿರುಗಿ -1;
			}
			ಸಂಪೂರ್ಣ *= 10;
			ಆದರೆ (i > LLONG_MAX - ಸಂಪೂರ್ಣ) {
				errno = ERANGE;
				ಹಿಂತಿರುಗಿ -1;
			}
			ಸಂಪೂರ್ಣ += i;
		}
	}

	ಆದರೆ (sign)
		ಸಂಪೂರ್ಣ *= sign;

	/* If no scale factor given, we're done. fraction is discarded. */
	ಆದರೆ (!*p) {
		*ಫಲಿತಾಂಶ = ಸಂಪೂರ್ಣ;
		ಹಿಂತಿರುಗಿ 0;
	}

	/* Validate scale factor, and scale whole and fraction by it. */
	ಗಾಗಿ (i = 0; i < SCALE_ಉದ್ದಳತೆ; i++) {

		/* Are we there yet? */
		ಆದರೆ (*p == scale_chars[i] ||
			*p == tolower((ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ)scale_chars[i])) {

			/* If it ends with alphanumerics after the scale char, bad. */
			ಆದರೆ (ಅಕ್ಷರವೇ_ಅಂಕಿಯೇ((ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ)*(p+1))) {
				errno = EINVAL;
				ಹಿಂತಿರುಗಿ -1;
			}
			scale_fact = scale_factors[i];

			/* check for overflow and underflow after scaling */
			ಆದರೆ (ಸಂಪೂರ್ಣ > LLONG_MAX / scale_fact ||
			    ಸಂಪೂರ್ಣ < LLONG_MIN / scale_fact) {
				errno = ERANGE;
				ಹಿಂತಿರುಗಿ -1;
			}

			/* scale whole part */
			ಸಂಪೂರ್ಣ *= scale_fact;

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
			ಆಗ (muls > 0 && divs > 0) {
				ಆದರೆ (fpart <= LLONG_MAX / 1024) {
					fpart *= 1024;
					muls--;
				} ಇಲ್ಲದಿದ್ದರೆ {
					fpart /= 10;
					divs--;
				}
			}
			ಆಗ (muls > 0) {
				fpart *= 1024;
				muls--;
			}
			ಆಗ (divs > 0) {
				fpart /= 10;
				divs--;
			}
			ಆದರೆ (sign == -1)
				ಸಂಪೂರ್ಣ -= fpart;
			ಇಲ್ಲದಿದ್ದರೆ
				ಸಂಪೂರ್ಣ += fpart;
			*ಫಲಿತಾಂಶ = ಸಂಪೂರ್ಣ;
			ಹಿಂತಿರುಗಿ 0;
		}
	}

	/* Invalid unit or character */
	errno = EINVAL;
	ಹಿಂತಿರುಗಿ -1;
}

/* Format the given "number" into human-readable form in "result".
 * Result must point to an allocated buffer of length FMT_SCALED_STRSIZE.
 * Return 0 on success, -1 and errno set if error.
 */
ಪೂರ್ಣಾಂಕ
fmt_scaled(ದೀರ್ಘ ದೀರ್ಘ ಸಂಖ್ಯೆ, ಅಕ್ಷರ *ಫಲಿತಾಂಶ)
{
	ದೀರ್ಘ ದೀರ್ಘ abval, fract = 0;
	ಚಿಹ್ನೆರಹಿತ ಪೂರ್ಣಾಂಕ i;
	unit_type unit = NONE;

	/* Not every negative long long has a positive representation. */
	ಆದರೆ (ಸಂಖ್ಯೆ == LLONG_MIN) {
		errno = ERANGE;
		ಹಿಂತಿರುಗಿ -1;
	}

	abval = llabs(ಸಂಖ್ಯೆ);

	/* Also check for numbers that are just too darned big to format. */
	ಆದರೆ (abval / 1024 >= scale_factors[SCALE_ಉದ್ದಳತೆ-1]) {
		errno = ERANGE;
		ಹಿಂತಿರುಗಿ -1;
	}

	/* scale whole part; get unscaled fraction */
	ಗಾಗಿ (i = 0; i < SCALE_ಉದ್ದಳತೆ; i++) {
		ಆದರೆ (abval/1024 < scale_factors[i]) {
			unit = units[i];
			fract = (i == 0) ? 0 : abval % scale_factors[i];
			ಸಂಖ್ಯೆ /= scale_factors[i];
			ಆದರೆ (i > 0)
				fract /= scale_factors[i - 1];
			ನಿಲ್ಲಿಸು;
		}
	}

	fract = (10 * fract + 512) / 1024;
	/* if the result would be >= 10, round main number */
	ಆದರೆ (fract >= 10) {
		ಆದರೆ (ಸಂಖ್ಯೆ >= 0)
			ಸಂಖ್ಯೆ++;
		ಇಲ್ಲದಿದ್ದರೆ
			ಸಂಖ್ಯೆ--;
		fract = 0;
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (fract < 0) {
		/* shouldn't happen */
		fract = 0;
	}

	ಆದರೆ (ಸಂಖ್ಯೆ == 0)
		strlcpy(ಫಲಿತಾಂಶ, "0B", FMT_SCALED_STRSIZE);
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (unit == NONE || ಸಂಖ್ಯೆ >= 100 || ಸಂಖ್ಯೆ <= -100) {
		ಆದರೆ (fract >= 5) {
			ಆದರೆ (ಸಂಖ್ಯೆ >= 0)
				ಸಂಖ್ಯೆ++;
			ಇಲ್ಲದಿದ್ದರೆ
				ಸಂಖ್ಯೆ--;
		}
		(ಶೂನ್ಯ)snprintf(ಫಲಿತಾಂಶ, FMT_SCALED_STRSIZE, "%lld%c",
			ಸಂಖ್ಯೆ, scale_chars[unit]);
	} ಇಲ್ಲದಿದ್ದರೆ
		(ಶೂನ್ಯ)snprintf(ಫಲಿತಾಂಶ, FMT_SCALED_STRSIZE, "%lld.%1lld%c",
			ಸಂಖ್ಯೆ, fract, scale_chars[unit]);

	ಹಿಂತಿರುಗಿ 0;
}

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ	MAIN
/*
 * This is the original version of the program in the man page.
 * Copy-and-paste whatever you need from it.
 */
ಪೂರ್ಣಾಂಕ
ಮುಖ್ಯ(ಪೂರ್ಣಾಂಕ argc, ಅಕ್ಷರ **argv)
{
	ಅಕ್ಷರ *cinput = "1.5K", buf[FMT_SCALED_STRSIZE];
	ದೀರ್ಘ ದೀರ್ಘ ninput = 10483892, ಫಲಿತಾಂಶ;

	ಆದರೆ (ಪರಿಶೀಲನೆ_scaled(cinput, &ಫಲಿತಾಂಶ) == 0)
		ಬರೆ("\"%s\" -> %lld\n", cinput, ಫಲಿತಾಂಶ);
	ಇಲ್ಲದಿದ್ದರೆ
		perror(cinput);

	ಆದರೆ (fmt_scaled(ninput, buf) == 0)
		ಬರೆ("%lld -> \"%s\"\n", ninput, buf);
	ಇಲ್ಲದಿದ್ದರೆ
		fprintf(stderr, "%lld invalid (%s)\n", ninput, strerror(errno));

	ಹಿಂತಿರುಗಿ 0;
}
#ಆದರೆ_ಅಂತ್ಯ

#ಆದರೆ_ಅಂತ್ಯ /* HAVE_FMT_SCALED */
