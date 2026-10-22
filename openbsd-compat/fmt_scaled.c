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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ifndef HAVE_FMT_SCALED

#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <errno.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <ctype.h>
#ଅନ୍ତର୍ଭାଵ <limits.h>

ପ୍ରକାରବ୍ୟାଖ୍ୟା ଗଣନା {
	NONE = 0, KILO = 1, MEGA = 2, GIGA = 3, TERA = 4, PETA = 5, EXA = 6
} unit_type;

/* These three arrays MUST be in sync!  XXX make a struct */
ସ୍ଥିର ଅଚଳ unit_type units[] = { NONE, KILO, MEGA, GIGA, TERA, PETA, EXA };
ସ୍ଥିର ଅଚଳ ଅକ୍ଷର scale_chars[] = "BKMGTPE";
ସ୍ଥିର ଅଚଳ long long scale_factors[] = {
	1LL,
	1024LL,
	1024LL*1024,
	1024LL*1024*1024,
	1024LL*1024*1024*1024,
	1024LL*1024*1024*1024*1024,
	1024LL*1024*1024*1024*1024*1024,
};
#define	SCALE_LENGTH (ଆକାର(units)/ଆକାର(units[0]))

#define MAX_DIGITS (SCALE_LENGTH * 3)	/* XXX strlen(sprintf("%lld", -1)? */

/* Convert the given input string "scaled" into numeric in "result".
 * Return 0 on success, -1 and errno set on error.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
scan_scaled(ଅକ୍ଷର *scaled, long long *result)
{
	ଅକ୍ଷର *p = scaled;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା sign = 0;
	unsigned ପୂର୍ଣ୍ଣସଂଖ୍ୟା i, ndigits = 0, fract_digits = 0, muls = 0, divs = 0;
	long long scale_fact = 1, whole = 0, fpart = 0;

	/* Skip leading whitespace */
	ଯେତେବେଳେ (isascii((unsigned ଅକ୍ଷର)*p) && isspace((unsigned ଅକ୍ଷର)*p))
		++p;

	/* Then at most one leading + or - */
	ଯେତେବେଳେ (*p == '-' || *p == '+') {
		ଯଦି (*p == '-') {
			ଯଦି (sign) {
				errno = EINVAL;
				ଫେରନ୍ତୁ -1;
			}
			sign = -1;
			++p;
		} ଅନ୍ୟଥା ଯଦି (*p == '+') {
			ଯଦି (sign) {
				errno = EINVAL;
				ଫେରନ୍ତୁ -1;
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
	ପାଇଁ (; isascii((unsigned ଅକ୍ଷର)*p) &&
	    (isdigit((unsigned ଅକ୍ଷର)*p) || *p=='.'); ++p) {
		ଯଦି (*p == '.') {
			ଯଦି (fract_digits > 0) {	/* oops, more than one '.' */
				errno = EINVAL;
				ଫେରନ୍ତୁ -1;
			}
			fract_digits = 1;
			ଜାରି;
		}

		i = (*p) - '0';			/* whew! finally a digit we can use */
		ଯଦି (fract_digits > 0) {
			ଯଦି (fract_digits >= MAX_DIGITS-1)
				/* ignore extra fractional digits */
				ଜାରି;
			fract_digits++;		/* for later scaling */
			ଯଦି (fpart > LLONG_MAX / 10) {
				errno = ERANGE;
				ଫେରନ୍ତୁ -1;
			}
			fpart *= 10;
			ଯଦି (i > LLONG_MAX - fpart) {
				errno = ERANGE;
				ଫେରନ୍ତୁ -1;
			}
			fpart += i;
		} ଅନ୍ୟଥା {				/* normal digit */
			ଯଦି (++ndigits >= MAX_DIGITS) {
				errno = ERANGE;
				ଫେରନ୍ତୁ -1;
			}
			ଯଦି (whole > LLONG_MAX / 10) {
				errno = ERANGE;
				ଫେରନ୍ତୁ -1;
			}
			whole *= 10;
			ଯଦି (i > LLONG_MAX - whole) {
				errno = ERANGE;
				ଫେରନ୍ତୁ -1;
			}
			whole += i;
		}
	}

	ଯଦି (sign)
		whole *= sign;

	/* If no scale factor given, we're done. fraction is discarded. */
	ଯଦି (!*p) {
		*result = whole;
		ଫେରନ୍ତୁ 0;
	}

	/* Validate scale factor, and scale whole and fraction by it. */
	ପାଇଁ (i = 0; i < SCALE_LENGTH; i++) {

		/* Are we there yet? */
		ଯଦି (*p == scale_chars[i] ||
			*p == tolower((unsigned ଅକ୍ଷର)scale_chars[i])) {

			/* If it ends with alphanumerics after the scale char, bad. */
			ଯଦି (isalnum((unsigned ଅକ୍ଷର)*(p+1))) {
				errno = EINVAL;
				ଫେରନ୍ତୁ -1;
			}
			scale_fact = scale_factors[i];

			/* check for overflow and underflow after scaling */
			ଯଦି (whole > LLONG_MAX / scale_fact ||
			    whole < LLONG_MIN / scale_fact) {
				errno = ERANGE;
				ଫେରନ୍ତୁ -1;
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
			ଯେତେବେଳେ (muls > 0 && divs > 0) {
				ଯଦି (fpart <= LLONG_MAX / 1024) {
					fpart *= 1024;
					muls--;
				} ଅନ୍ୟଥା {
					fpart /= 10;
					divs--;
				}
			}
			ଯେତେବେଳେ (muls > 0) {
				fpart *= 1024;
				muls--;
			}
			ଯେତେବେଳେ (divs > 0) {
				fpart /= 10;
				divs--;
			}
			ଯଦି (sign == -1)
				whole -= fpart;
			ଅନ୍ୟଥା
				whole += fpart;
			*result = whole;
			ଫେରନ୍ତୁ 0;
		}
	}

	/* Invalid unit or character */
	errno = EINVAL;
	ଫେରନ୍ତୁ -1;
}

/* Format the given "number" into human-readable form in "result".
 * Result must point to an allocated buffer of length FMT_SCALED_STRSIZE.
 * Return 0 on success, -1 and errno set if error.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
fmt_scaled(long long ସଂଖ୍ୟା, ଅକ୍ଷର *result)
{
	long long abval, fract = 0;
	unsigned ପୂର୍ଣ୍ଣସଂଖ୍ୟା i;
	unit_type unit = NONE;

	/* Not every negative long long has a positive representation. */
	ଯଦି (ସଂଖ୍ୟା == LLONG_MIN) {
		errno = ERANGE;
		ଫେରନ୍ତୁ -1;
	}

	abval = llabs(ସଂଖ୍ୟା);

	/* Also check for numbers that are just too darned big to format. */
	ଯଦି (abval / 1024 >= scale_factors[SCALE_LENGTH-1]) {
		errno = ERANGE;
		ଫେରନ୍ତୁ -1;
	}

	/* scale whole part; get unscaled fraction */
	ପାଇଁ (i = 0; i < SCALE_LENGTH; i++) {
		ଯଦି (abval/1024 < scale_factors[i]) {
			unit = units[i];
			fract = (i == 0) ? 0 : abval % scale_factors[i];
			ସଂଖ୍ୟା /= scale_factors[i];
			ଯଦି (i > 0)
				fract /= scale_factors[i - 1];
			ଭାଙ୍ଗ;
		}
	}

	fract = (10 * fract + 512) / 1024;
	/* if the result would be >= 10, round main number */
	ଯଦି (fract >= 10) {
		ଯଦି (ସଂଖ୍ୟା >= 0)
			ସଂଖ୍ୟା++;
		ଅନ୍ୟଥା
			ସଂଖ୍ୟା--;
		fract = 0;
	} ଅନ୍ୟଥା ଯଦି (fract < 0) {
		/* shouldn't happen */
		fract = 0;
	}

	ଯଦି (ସଂଖ୍ୟା == 0)
		strlcpy(result, "0B", FMT_SCALED_STRSIZE);
	ଅନ୍ୟଥା ଯଦି (unit == NONE || ସଂଖ୍ୟା >= 100 || ସଂଖ୍ୟା <= -100) {
		ଯଦି (fract >= 5) {
			ଯଦି (ସଂଖ୍ୟା >= 0)
				ସଂଖ୍ୟା++;
			ଅନ୍ୟଥା
				ସଂଖ୍ୟା--;
		}
		(ଶୂନ୍ୟ)snprintf(result, FMT_SCALED_STRSIZE, "%lld%c",
			ସଂଖ୍ୟା, scale_chars[unit]);
	} ଅନ୍ୟଥା
		(ଶୂନ୍ୟ)snprintf(result, FMT_SCALED_STRSIZE, "%lld.%1lld%c",
			ସଂଖ୍ୟା, fract, scale_chars[unit]);

	ଫେରନ୍ତୁ 0;
}

#ifdef	MAIN
/*
 * This is the original version of the program in the man page.
 * Copy-and-paste whatever you need from it.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ମୁଖ୍ୟ(ପୂର୍ଣ୍ଣସଂଖ୍ୟା argc, ଅକ୍ଷର **argv)
{
	ଅକ୍ଷର *cinput = "1.5K", buf[FMT_SCALED_STRSIZE];
	long long ninput = 10483892, result;

	ଯଦି (scan_scaled(cinput, &result) == 0)
		printf("\"%s\" -> %lld\n", cinput, result);
	ଅନ୍ୟଥା
		perror(cinput);

	ଯଦି (fmt_scaled(ninput, buf) == 0)
		printf("%lld -> \"%s\"\n", ninput, buf);
	ଅନ୍ୟଥା
		fprintf(stderr, "%lld invalid (%s)\n", ninput, strerror(errno));

	ଫେରନ୍ତୁ 0;
}
#endif

#endif /* HAVE_FMT_SCALED */
