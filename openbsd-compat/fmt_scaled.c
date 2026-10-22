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

#include "includes.h"

#ifndef HAVE_FMT_SCALED

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>

typedef ga_nanaa {
	NONE = 0, KILO = 1, MEGA = 2, GIGA = 3, TERA = 4, PETA = 5, EXA = 6
} unit_type;

/* These three arrays MUST be in sync!  XXX make a struct */
static const unit_type units[] = { NONE, KILO, MEGA, GIGA, TERA, PETA, EXA };
static const var_na scale_chars[] = "BKMGTPE";
static const long long scale_factors[] = {
	1LL,
	1024LL,
	1024LL*1024,
	1024LL*1024*1024,
	1024LL*1024*1024*1024,
	1024LL*1024*1024*1024*1024,
	1024LL*1024*1024*1024*1024*1024,
};
#define	SCALE_LENGTH (parimaa_na(units)/parimaa_na(units[0]))

#define MAX_DIGITS (SCALE_LENGTH * 3)	/* XXX strlen(sprintf("%lld", -1)? */

/* Convert the given input string "scaled" into numeric in "result".
 * Return 0 on success, -1 and errno set on error.
 */
ចំនួនគត់
scan_scaled(var_na *scaled, long long *result)
{
	var_na *p = scaled;
	ចំនួនគត់ sign = 0;
	unsigned ចំនួនគត់ i, ndigits = 0, fract_digits = 0, muls = 0, divs = 0;
	long long scale_fact = 1, whole = 0, fpart = 0;

	/* Skip leading whitespace */
	ខណៈពេល (isascii((unsigned var_na)*p) && isspace((unsigned var_na)*p))
		++p;

	/* Then at most one leading + or - */
	ខណៈពេល (*p == '-' || *p == '+') {
		ប្រសិនបើ (*p == '-') {
			ប្រសិនបើ (sign) {
				errno = EINVAL;
				ត្រឡប់ -1;
			}
			sign = -1;
			++p;
		} បើមិនដូច្នេះ ប្រសិនបើ (*p == '+') {
			ប្រសិនបើ (sign) {
				errno = EINVAL;
				ត្រឡប់ -1;
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
	សម្រាប់ (; isascii((unsigned var_na)*p) &&
	    (isdigit((unsigned var_na)*p) || *p=='.'); ++p) {
		ប្រសិនបើ (*p == '.') {
			ប្រសិនបើ (fract_digits > 0) {	/* oops, more than one '.' */
				errno = EINVAL;
				ត្រឡប់ -1;
			}
			fract_digits = 1;
			continue;
		}

		i = (*p) - '0';			/* whew! finally a digit we can use */
		ប្រសិនបើ (fract_digits > 0) {
			ប្រសិនបើ (fract_digits >= MAX_DIGITS-1)
				/* ignore extra fractional digits */
				continue;
			fract_digits++;		/* for later scaling */
			ប្រសិនបើ (fpart > LLONG_MAX / 10) {
				errno = ERANGE;
				ត្រឡប់ -1;
			}
			fpart *= 10;
			ប្រសិនបើ (i > LLONG_MAX - fpart) {
				errno = ERANGE;
				ត្រឡប់ -1;
			}
			fpart += i;
		} បើមិនដូច្នេះ {				/* normal digit */
			ប្រសិនបើ (++ndigits >= MAX_DIGITS) {
				errno = ERANGE;
				ត្រឡប់ -1;
			}
			ប្រសិនបើ (whole > LLONG_MAX / 10) {
				errno = ERANGE;
				ត្រឡប់ -1;
			}
			whole *= 10;
			ប្រសិនបើ (i > LLONG_MAX - whole) {
				errno = ERANGE;
				ត្រឡប់ -1;
			}
			whole += i;
		}
	}

	ប្រសិនបើ (sign)
		whole *= sign;

	/* If no scale factor given, we're done. fraction is discarded. */
	ប្រសិនបើ (!*p) {
		*result = whole;
		ត្រឡប់ 0;
	}

	/* Validate scale factor, and scale whole and fraction by it. */
	សម្រាប់ (i = 0; i < SCALE_LENGTH; i++) {

		/* Are we there yet? */
		ប្រសិនបើ (*p == scale_chars[i] ||
			*p == tolower((unsigned var_na)scale_chars[i])) {

			/* If it ends with alphanumerics after the scale char, bad. */
			ប្រសិនបើ (isalnum((unsigned var_na)*(p+1))) {
				errno = EINVAL;
				ត្រឡប់ -1;
			}
			scale_fact = scale_factors[i];

			/* check for overflow and underflow after scaling */
			ប្រសិនបើ (whole > LLONG_MAX / scale_fact ||
			    whole < LLONG_MIN / scale_fact) {
				errno = ERANGE;
				ត្រឡប់ -1;
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
			ខណៈពេល (muls > 0 && divs > 0) {
				ប្រសិនបើ (fpart <= LLONG_MAX / 1024) {
					fpart *= 1024;
					muls--;
				} បើមិនដូច្នេះ {
					fpart /= 10;
					divs--;
				}
			}
			ខណៈពេល (muls > 0) {
				fpart *= 1024;
				muls--;
			}
			ខណៈពេល (divs > 0) {
				fpart /= 10;
				divs--;
			}
			ប្រសិនបើ (sign == -1)
				whole -= fpart;
			បើមិនដូច្នេះ
				whole += fpart;
			*result = whole;
			ត្រឡប់ 0;
		}
	}

	/* Invalid unit or character */
	errno = EINVAL;
	ត្រឡប់ -1;
}

/* Format the given "number" into human-readable form in "result".
 * Result must point to an allocated buffer of length FMT_SCALED_STRSIZE.
 * Return 0 on success, -1 and errno set if error.
 */
ចំនួនគត់
fmt_scaled(long long number, var_na *result)
{
	long long abval, fract = 0;
	unsigned ចំនួនគត់ i;
	unit_type unit = NONE;

	/* Not every negative long long has a positive representation. */
	ប្រសិនបើ (number == LLONG_MIN) {
		errno = ERANGE;
		ត្រឡប់ -1;
	}

	abval = llabs(number);

	/* Also check for numbers that are just too darned big to format. */
	ប្រសិនបើ (abval / 1024 >= scale_factors[SCALE_LENGTH-1]) {
		errno = ERANGE;
		ត្រឡប់ -1;
	}

	/* scale whole part; get unscaled fraction */
	សម្រាប់ (i = 0; i < SCALE_LENGTH; i++) {
		ប្រសិនបើ (abval/1024 < scale_factors[i]) {
			unit = units[i];
			fract = (i == 0) ? 0 : abval % scale_factors[i];
			number /= scale_factors[i];
			ប្រសិនបើ (i > 0)
				fract /= scale_factors[i - 1];
			bha_nga;
		}
	}

	fract = (10 * fract + 512) / 1024;
	/* if the result would be >= 10, round main number */
	ប្រសិនបើ (fract >= 10) {
		ប្រសិនបើ (number >= 0)
			number++;
		បើមិនដូច្នេះ
			number--;
		fract = 0;
	} បើមិនដូច្នេះ ប្រសិនបើ (fract < 0) {
		/* shouldn't happen */
		fract = 0;
	}

	ប្រសិនបើ (number == 0)
		strlcpy(result, "0B", FMT_SCALED_STRSIZE);
	បើមិនដូច្នេះ ប្រសិនបើ (unit == NONE || number >= 100 || number <= -100) {
		ប្រសិនបើ (fract >= 5) {
			ប្រសិនបើ (number >= 0)
				number++;
			បើមិនដូច្នេះ
				number--;
		}
		(void)snprintf(result, FMT_SCALED_STRSIZE, "%lld%c",
			number, scale_chars[unit]);
	} បើមិនដូច្នេះ
		(void)snprintf(result, FMT_SCALED_STRSIZE, "%lld.%1lld%c",
			number, fract, scale_chars[unit]);

	ត្រឡប់ 0;
}

#ifdef	MAIN
/*
 * This is the original version of the program in the man page.
 * Copy-and-paste whatever you need from it.
 */
ចំនួនគត់
main(ចំនួនគត់ argc, var_na **argv)
{
	var_na *cinput = "1.5K", buf[FMT_SCALED_STRSIZE];
	long long ninput = 10483892, result;

	ប្រសិនបើ (scan_scaled(cinput, &result) == 0)
		printf("\"%s\" -> %lld\n", cinput, result);
	បើមិនដូច្នេះ
		perror(cinput);

	ប្រសិនបើ (fmt_scaled(ninput, buf) == 0)
		printf("%lld -> \"%s\"\n", ninput, buf);
	បើមិនដូច្នេះ
		fprintf(stderr, "%lld invalid (%s)\n", ninput, strerror(errno));

	ត្រឡប់ 0;
}
#endif

#endif /* HAVE_FMT_SCALED */
