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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_FMT_SCALED

#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <errno.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <ctype.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <limits.h>

ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਗਿਣਤੀ {
	NONE = 0, KILO = 1, MEGA = 2, GIGA = 3, TERA = 4, PETA = 5, EXA = 6
} unit_type;

/* These three arrays MUST be in sync!  XXX make a struct */
ਸਥਿਰ ਅਚਲ unit_type units[] = { NONE, KILO, MEGA, GIGA, TERA, PETA, EXA };
ਸਥਿਰ ਅਚਲ ਅੱਖਰ scale_chars[] = "BKMGTPE";
ਸਥਿਰ ਅਚਲ ਲੰਮਾ ਲੰਮਾ scale_factors[] = {
	1LL,
	1024LL,
	1024LL*1024,
	1024LL*1024*1024,
	1024LL*1024*1024*1024,
	1024LL*1024*1024*1024*1024,
	1024LL*1024*1024*1024*1024*1024,
};
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	SCALE_ਲੰਮਾਈ (ਆਕਾਰ(units)/ਆਕਾਰ(units[0]))

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ MAX_DIGITS (SCALE_ਲੰਮਾਈ * 3)	/* XXX strlen(sprintf("%lld", -1)? */

/* Convert the given input string "scaled" into numeric in "result".
 * Return 0 on success, -1 and errno set on error.
 */
ਪੂਰਨ
ਜਾਂਚ_scaled(ਅੱਖਰ *scaled, ਲੰਮਾ ਲੰਮਾ *ਨਤੀਜਾ)
{
	ਅੱਖਰ *p = scaled;
	ਪੂਰਨ sign = 0;
	ਬਿਨਾਨਿਸ਼ਾਨੀ ਪੂਰਨ i, ndigits = 0, fract_digits = 0, muls = 0, divs = 0;
	ਲੰਮਾ ਲੰਮਾ scale_fact = 1, ਸਾਰਾ = 0, fpart = 0;

	/* Skip leading whitespace */
	ਜਦੋਂ (isascii((ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ)*p) && ਖਾਲੀ_ਥਾਂ_ਹੈ((ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ)*p))
		++p;

	/* Then at most one leading + or - */
	ਜਦੋਂ (*p == '-' || *p == '+') {
		ਜੇ (*p == '-') {
			ਜੇ (sign) {
				errno = EINVAL;
				ਵਾਪਸ -1;
			}
			sign = -1;
			++p;
		} ਨਹੀਂਤਾਂ ਜੇ (*p == '+') {
			ਜੇ (sign) {
				errno = EINVAL;
				ਵਾਪਸ -1;
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
	ਲਈ (; isascii((ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ)*p) &&
	    (ਅੰਕ_ਹੈ((ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ)*p) || *p=='.'); ++p) {
		ਜੇ (*p == '.') {
			ਜੇ (fract_digits > 0) {	/* oops, more than one '.' */
				errno = EINVAL;
				ਵਾਪਸ -1;
			}
			fract_digits = 1;
			ਜਾਰੀ;
		}

		i = (*p) - '0';			/* whew! finally a digit we can use */
		ਜੇ (fract_digits > 0) {
			ਜੇ (fract_digits >= MAX_DIGITS-1)
				/* ignore extra fractional digits */
				ਜਾਰੀ;
			fract_digits++;		/* for later scaling */
			ਜੇ (fpart > LLONG_MAX / 10) {
				errno = ERANGE;
				ਵਾਪਸ -1;
			}
			fpart *= 10;
			ਜੇ (i > LLONG_MAX - fpart) {
				errno = ERANGE;
				ਵਾਪਸ -1;
			}
			fpart += i;
		} ਨਹੀਂਤਾਂ {				/* normal digit */
			ਜੇ (++ndigits >= MAX_DIGITS) {
				errno = ERANGE;
				ਵਾਪਸ -1;
			}
			ਜੇ (ਸਾਰਾ > LLONG_MAX / 10) {
				errno = ERANGE;
				ਵਾਪਸ -1;
			}
			ਸਾਰਾ *= 10;
			ਜੇ (i > LLONG_MAX - ਸਾਰਾ) {
				errno = ERANGE;
				ਵਾਪਸ -1;
			}
			ਸਾਰਾ += i;
		}
	}

	ਜੇ (sign)
		ਸਾਰਾ *= sign;

	/* If no scale factor given, we're done. fraction is discarded. */
	ਜੇ (!*p) {
		*ਨਤੀਜਾ = ਸਾਰਾ;
		ਵਾਪਸ 0;
	}

	/* Validate scale factor, and scale whole and fraction by it. */
	ਲਈ (i = 0; i < SCALE_ਲੰਮਾਈ; i++) {

		/* Are we there yet? */
		ਜੇ (*p == scale_chars[i] ||
			*p == tolower((ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ)scale_chars[i])) {

			/* If it ends with alphanumerics after the scale char, bad. */
			ਜੇ (ਅੱਖਰ_ਜਾਂ_ਅੰਕ((ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ)*(p+1))) {
				errno = EINVAL;
				ਵਾਪਸ -1;
			}
			scale_fact = scale_factors[i];

			/* check for overflow and underflow after scaling */
			ਜੇ (ਸਾਰਾ > LLONG_MAX / scale_fact ||
			    ਸਾਰਾ < LLONG_MIN / scale_fact) {
				errno = ERANGE;
				ਵਾਪਸ -1;
			}

			/* scale whole part */
			ਸਾਰਾ *= scale_fact;

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
			ਜਦੋਂ (muls > 0 && divs > 0) {
				ਜੇ (fpart <= LLONG_MAX / 1024) {
					fpart *= 1024;
					muls--;
				} ਨਹੀਂਤਾਂ {
					fpart /= 10;
					divs--;
				}
			}
			ਜਦੋਂ (muls > 0) {
				fpart *= 1024;
				muls--;
			}
			ਜਦੋਂ (divs > 0) {
				fpart /= 10;
				divs--;
			}
			ਜੇ (sign == -1)
				ਸਾਰਾ -= fpart;
			ਨਹੀਂਤਾਂ
				ਸਾਰਾ += fpart;
			*ਨਤੀਜਾ = ਸਾਰਾ;
			ਵਾਪਸ 0;
		}
	}

	/* Invalid unit or character */
	errno = EINVAL;
	ਵਾਪਸ -1;
}

/* Format the given "number" into human-readable form in "result".
 * Result must point to an allocated buffer of length FMT_SCALED_STRSIZE.
 * Return 0 on success, -1 and errno set if error.
 */
ਪੂਰਨ
fmt_scaled(ਲੰਮਾ ਲੰਮਾ ਸੰਖਿਆ, ਅੱਖਰ *ਨਤੀਜਾ)
{
	ਲੰਮਾ ਲੰਮਾ abval, fract = 0;
	ਬਿਨਾਨਿਸ਼ਾਨੀ ਪੂਰਨ i;
	unit_type unit = NONE;

	/* Not every negative long long has a positive representation. */
	ਜੇ (ਸੰਖਿਆ == LLONG_MIN) {
		errno = ERANGE;
		ਵਾਪਸ -1;
	}

	abval = llabs(ਸੰਖਿਆ);

	/* Also check for numbers that are just too darned big to format. */
	ਜੇ (abval / 1024 >= scale_factors[SCALE_ਲੰਮਾਈ-1]) {
		errno = ERANGE;
		ਵਾਪਸ -1;
	}

	/* scale whole part; get unscaled fraction */
	ਲਈ (i = 0; i < SCALE_ਲੰਮਾਈ; i++) {
		ਜੇ (abval/1024 < scale_factors[i]) {
			unit = units[i];
			fract = (i == 0) ? 0 : abval % scale_factors[i];
			ਸੰਖਿਆ /= scale_factors[i];
			ਜੇ (i > 0)
				fract /= scale_factors[i - 1];
			ਰੋਕੋ;
		}
	}

	fract = (10 * fract + 512) / 1024;
	/* if the result would be >= 10, round main number */
	ਜੇ (fract >= 10) {
		ਜੇ (ਸੰਖਿਆ >= 0)
			ਸੰਖਿਆ++;
		ਨਹੀਂਤਾਂ
			ਸੰਖਿਆ--;
		fract = 0;
	} ਨਹੀਂਤਾਂ ਜੇ (fract < 0) {
		/* shouldn't happen */
		fract = 0;
	}

	ਜੇ (ਸੰਖਿਆ == 0)
		strlcpy(ਨਤੀਜਾ, "0B", FMT_SCALED_STRSIZE);
	ਨਹੀਂਤਾਂ ਜੇ (unit == NONE || ਸੰਖਿਆ >= 100 || ਸੰਖਿਆ <= -100) {
		ਜੇ (fract >= 5) {
			ਜੇ (ਸੰਖਿਆ >= 0)
				ਸੰਖਿਆ++;
			ਨਹੀਂਤਾਂ
				ਸੰਖਿਆ--;
		}
		(ਖਾਲੀ)snprintf(ਨਤੀਜਾ, FMT_SCALED_STRSIZE, "%lld%c",
			ਸੰਖਿਆ, scale_chars[unit]);
	} ਨਹੀਂਤਾਂ
		(ਖਾਲੀ)snprintf(ਨਤੀਜਾ, FMT_SCALED_STRSIZE, "%lld.%1lld%c",
			ਸੰਖਿਆ, fract, scale_chars[unit]);

	ਵਾਪਸ 0;
}

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ	MAIN
/*
 * This is the original version of the program in the man page.
 * Copy-and-paste whatever you need from it.
 */
ਪੂਰਨ
ਮੁੱਖ(ਪੂਰਨ argc, ਅੱਖਰ **argv)
{
	ਅੱਖਰ *cinput = "1.5K", buf[FMT_SCALED_STRSIZE];
	ਲੰਮਾ ਲੰਮਾ ninput = 10483892, ਨਤੀਜਾ;

	ਜੇ (ਜਾਂਚ_scaled(cinput, &ਨਤੀਜਾ) == 0)
		ਲਿਖੋ("\"%s\" -> %lld\n", cinput, ਨਤੀਜਾ);
	ਨਹੀਂਤਾਂ
		perror(cinput);

	ਜੇ (fmt_scaled(ninput, buf) == 0)
		ਲਿਖੋ("%lld -> \"%s\"\n", ninput, buf);
	ਨਹੀਂਤਾਂ
		fprintf(stderr, "%lld invalid (%s)\n", ninput, strerror(errno));

	ਵਾਪਸ 0;
}
#ਜੇ_ਅੰਤ

#ਜੇ_ਅੰਤ /* HAVE_FMT_SCALED */
