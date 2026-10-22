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

#அந்தர்பாவ "includes.h"

#ifndef HAVE_FMT_SCALED

#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <errno.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <ctype.h>
#அந்தர்பாவ <limits.h>

வகைவரை எண்ணிக்கை {
	NONE = 0, KILO = 1, MEGA = 2, GIGA = 3, TERA = 4, PETA = 5, EXA = 6
} unit_type;

/* These three arrays MUST be in sync!  XXX make a struct */
நிலையான மாறிலி unit_type units[] = { NONE, KILO, MEGA, GIGA, TERA, PETA, EXA };
நிலையான மாறிலி எழுத்து scale_chars[] = "BKMGTPE";
நிலையான மாறிலி long long scale_factors[] = {
	1LL,
	1024LL,
	1024LL*1024,
	1024LL*1024*1024,
	1024LL*1024*1024*1024,
	1024LL*1024*1024*1024*1024,
	1024LL*1024*1024*1024*1024*1024,
};
#define	SCALE_LENGTH (அளவு(units)/அளவு(units[0]))

#define MAX_DIGITS (SCALE_LENGTH * 3)	/* XXX strlen(sprintf("%lld", -1)? */

/* Convert the given input string "scaled" into numeric in "result".
 * Return 0 on success, -1 and errno set on error.
 */
முழு
scan_scaled(எழுத்து *scaled, long long *result)
{
	எழுத்து *p = scaled;
	முழு sign = 0;
	unsigned முழு i, ndigits = 0, fract_digits = 0, muls = 0, divs = 0;
	long long scale_fact = 1, whole = 0, fpart = 0;

	/* Skip leading whitespace */
	போது (isascii((unsigned எழுத்து)*p) && isspace((unsigned எழுத்து)*p))
		++p;

	/* Then at most one leading + or - */
	போது (*p == '-' || *p == '+') {
		எனில் (*p == '-') {
			எனில் (sign) {
				errno = EINVAL;
				திரும்பு -1;
			}
			sign = -1;
			++p;
		} இல்லையெனில் எனில் (*p == '+') {
			எனில் (sign) {
				errno = EINVAL;
				திரும்பு -1;
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
	க்கு (; isascii((unsigned எழுத்து)*p) &&
	    (isdigit((unsigned எழுத்து)*p) || *p=='.'); ++p) {
		எனில் (*p == '.') {
			எனில் (fract_digits > 0) {	/* oops, more than one '.' */
				errno = EINVAL;
				திரும்பு -1;
			}
			fract_digits = 1;
			தொடர்;
		}

		i = (*p) - '0';			/* whew! finally a digit we can use */
		எனில் (fract_digits > 0) {
			எனில் (fract_digits >= MAX_DIGITS-1)
				/* ignore extra fractional digits */
				தொடர்;
			fract_digits++;		/* for later scaling */
			எனில் (fpart > LLONG_MAX / 10) {
				errno = ERANGE;
				திரும்பு -1;
			}
			fpart *= 10;
			எனில் (i > LLONG_MAX - fpart) {
				errno = ERANGE;
				திரும்பு -1;
			}
			fpart += i;
		} இல்லையெனில் {				/* normal digit */
			எனில் (++ndigits >= MAX_DIGITS) {
				errno = ERANGE;
				திரும்பு -1;
			}
			எனில் (whole > LLONG_MAX / 10) {
				errno = ERANGE;
				திரும்பு -1;
			}
			whole *= 10;
			எனில் (i > LLONG_MAX - whole) {
				errno = ERANGE;
				திரும்பு -1;
			}
			whole += i;
		}
	}

	எனில் (sign)
		whole *= sign;

	/* If no scale factor given, we're done. fraction is discarded. */
	எனில் (!*p) {
		*result = whole;
		திரும்பு 0;
	}

	/* Validate scale factor, and scale whole and fraction by it. */
	க்கு (i = 0; i < SCALE_LENGTH; i++) {

		/* Are we there yet? */
		எனில் (*p == scale_chars[i] ||
			*p == tolower((unsigned எழுத்து)scale_chars[i])) {

			/* If it ends with alphanumerics after the scale char, bad. */
			எனில் (isalnum((unsigned எழுத்து)*(p+1))) {
				errno = EINVAL;
				திரும்பு -1;
			}
			scale_fact = scale_factors[i];

			/* check for overflow and underflow after scaling */
			எனில் (whole > LLONG_MAX / scale_fact ||
			    whole < LLONG_MIN / scale_fact) {
				errno = ERANGE;
				திரும்பு -1;
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
			போது (muls > 0 && divs > 0) {
				எனில் (fpart <= LLONG_MAX / 1024) {
					fpart *= 1024;
					muls--;
				} இல்லையெனில் {
					fpart /= 10;
					divs--;
				}
			}
			போது (muls > 0) {
				fpart *= 1024;
				muls--;
			}
			போது (divs > 0) {
				fpart /= 10;
				divs--;
			}
			எனில் (sign == -1)
				whole -= fpart;
			இல்லையெனில்
				whole += fpart;
			*result = whole;
			திரும்பு 0;
		}
	}

	/* Invalid unit or character */
	errno = EINVAL;
	திரும்பு -1;
}

/* Format the given "number" into human-readable form in "result".
 * Result must point to an allocated buffer of length FMT_SCALED_STRSIZE.
 * Return 0 on success, -1 and errno set if error.
 */
முழு
fmt_scaled(long long எண், எழுத்து *result)
{
	long long abval, fract = 0;
	unsigned முழு i;
	unit_type unit = NONE;

	/* Not every negative long long has a positive representation. */
	எனில் (எண் == LLONG_MIN) {
		errno = ERANGE;
		திரும்பு -1;
	}

	abval = llabs(எண்);

	/* Also check for numbers that are just too darned big to format. */
	எனில் (abval / 1024 >= scale_factors[SCALE_LENGTH-1]) {
		errno = ERANGE;
		திரும்பு -1;
	}

	/* scale whole part; get unscaled fraction */
	க்கு (i = 0; i < SCALE_LENGTH; i++) {
		எனில் (abval/1024 < scale_factors[i]) {
			unit = units[i];
			fract = (i == 0) ? 0 : abval % scale_factors[i];
			எண் /= scale_factors[i];
			எனில் (i > 0)
				fract /= scale_factors[i - 1];
			நிறுத்து;
		}
	}

	fract = (10 * fract + 512) / 1024;
	/* if the result would be >= 10, round main number */
	எனில் (fract >= 10) {
		எனில் (எண் >= 0)
			எண்++;
		இல்லையெனில்
			எண்--;
		fract = 0;
	} இல்லையெனில் எனில் (fract < 0) {
		/* shouldn't happen */
		fract = 0;
	}

	எனில் (எண் == 0)
		strlcpy(result, "0B", FMT_SCALED_STRSIZE);
	இல்லையெனில் எனில் (unit == NONE || எண் >= 100 || எண் <= -100) {
		எனில் (fract >= 5) {
			எனில் (எண் >= 0)
				எண்++;
			இல்லையெனில்
				எண்--;
		}
		(வெறுமை)snprintf(result, FMT_SCALED_STRSIZE, "%lld%c",
			எண், scale_chars[unit]);
	} இல்லையெனில்
		(வெறுமை)snprintf(result, FMT_SCALED_STRSIZE, "%lld.%1lld%c",
			எண், fract, scale_chars[unit]);

	திரும்பு 0;
}

#ifdef	MAIN
/*
 * This is the original version of the program in the man page.
 * Copy-and-paste whatever you need from it.
 */
முழு
முதன்மை(முழு argc, எழுத்து **argv)
{
	எழுத்து *cinput = "1.5K", buf[FMT_SCALED_STRSIZE];
	long long ninput = 10483892, result;

	எனில் (scan_scaled(cinput, &result) == 0)
		printf("\"%s\" -> %lld\n", cinput, result);
	இல்லையெனில்
		perror(cinput);

	எனில் (fmt_scaled(ninput, buf) == 0)
		printf("%lld -> \"%s\"\n", ninput, buf);
	இல்லையெனில்
		fprintf(stderr, "%lld invalid (%s)\n", ninput, strerror(errno));

	திரும்பு 0;
}
#endif

#endif /* HAVE_FMT_SCALED */
