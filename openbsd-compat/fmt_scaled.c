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
ຈຳນວນເຕັມ
scan_scaled(var_na *scaled, long long *result)
{
	var_na *p = scaled;
	ຈຳນວນເຕັມ sign = 0;
	unsigned ຈຳນວນເຕັມ i, ndigits = 0, fract_digits = 0, muls = 0, divs = 0;
	long long scale_fact = 1, whole = 0, fpart = 0;

	/* Skip leading whitespace */
	ໃນຂະນະທີ່ (isascii((unsigned var_na)*p) && isspace((unsigned var_na)*p))
		++p;

	/* Then at most one leading + or - */
	ໃນຂະນະທີ່ (*p == '-' || *p == '+') {
		ຖ້າ (*p == '-') {
			ຖ້າ (sign) {
				errno = EINVAL;
				ສົ່ງຄືນ -1;
			}
			sign = -1;
			++p;
		} ບໍ່ດັ່ງນັ້ນ ຖ້າ (*p == '+') {
			ຖ້າ (sign) {
				errno = EINVAL;
				ສົ່ງຄືນ -1;
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
	ສຳລັບ (; isascii((unsigned var_na)*p) &&
	    (isdigit((unsigned var_na)*p) || *p=='.'); ++p) {
		ຖ້າ (*p == '.') {
			ຖ້າ (fract_digits > 0) {	/* oops, more than one '.' */
				errno = EINVAL;
				ສົ່ງຄືນ -1;
			}
			fract_digits = 1;
			continue;
		}

		i = (*p) - '0';			/* whew! finally a digit we can use */
		ຖ້າ (fract_digits > 0) {
			ຖ້າ (fract_digits >= MAX_DIGITS-1)
				/* ignore extra fractional digits */
				continue;
			fract_digits++;		/* for later scaling */
			ຖ້າ (fpart > LLONG_MAX / 10) {
				errno = ERANGE;
				ສົ່ງຄືນ -1;
			}
			fpart *= 10;
			ຖ້າ (i > LLONG_MAX - fpart) {
				errno = ERANGE;
				ສົ່ງຄືນ -1;
			}
			fpart += i;
		} ບໍ່ດັ່ງນັ້ນ {				/* normal digit */
			ຖ້າ (++ndigits >= MAX_DIGITS) {
				errno = ERANGE;
				ສົ່ງຄືນ -1;
			}
			ຖ້າ (whole > LLONG_MAX / 10) {
				errno = ERANGE;
				ສົ່ງຄືນ -1;
			}
			whole *= 10;
			ຖ້າ (i > LLONG_MAX - whole) {
				errno = ERANGE;
				ສົ່ງຄືນ -1;
			}
			whole += i;
		}
	}

	ຖ້າ (sign)
		whole *= sign;

	/* If no scale factor given, we're done. fraction is discarded. */
	ຖ້າ (!*p) {
		*result = whole;
		ສົ່ງຄືນ 0;
	}

	/* Validate scale factor, and scale whole and fraction by it. */
	ສຳລັບ (i = 0; i < SCALE_LENGTH; i++) {

		/* Are we there yet? */
		ຖ້າ (*p == scale_chars[i] ||
			*p == tolower((unsigned var_na)scale_chars[i])) {

			/* If it ends with alphanumerics after the scale char, bad. */
			ຖ້າ (isalnum((unsigned var_na)*(p+1))) {
				errno = EINVAL;
				ສົ່ງຄືນ -1;
			}
			scale_fact = scale_factors[i];

			/* check for overflow and underflow after scaling */
			ຖ້າ (whole > LLONG_MAX / scale_fact ||
			    whole < LLONG_MIN / scale_fact) {
				errno = ERANGE;
				ສົ່ງຄືນ -1;
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
			ໃນຂະນະທີ່ (muls > 0 && divs > 0) {
				ຖ້າ (fpart <= LLONG_MAX / 1024) {
					fpart *= 1024;
					muls--;
				} ບໍ່ດັ່ງນັ້ນ {
					fpart /= 10;
					divs--;
				}
			}
			ໃນຂະນະທີ່ (muls > 0) {
				fpart *= 1024;
				muls--;
			}
			ໃນຂະນະທີ່ (divs > 0) {
				fpart /= 10;
				divs--;
			}
			ຖ້າ (sign == -1)
				whole -= fpart;
			ບໍ່ດັ່ງນັ້ນ
				whole += fpart;
			*result = whole;
			ສົ່ງຄືນ 0;
		}
	}

	/* Invalid unit or character */
	errno = EINVAL;
	ສົ່ງຄືນ -1;
}

/* Format the given "number" into human-readable form in "result".
 * Result must point to an allocated buffer of length FMT_SCALED_STRSIZE.
 * Return 0 on success, -1 and errno set if error.
 */
ຈຳນວນເຕັມ
fmt_scaled(long long number, var_na *result)
{
	long long abval, fract = 0;
	unsigned ຈຳນວນເຕັມ i;
	unit_type unit = NONE;

	/* Not every negative long long has a positive representation. */
	ຖ້າ (number == LLONG_MIN) {
		errno = ERANGE;
		ສົ່ງຄືນ -1;
	}

	abval = llabs(number);

	/* Also check for numbers that are just too darned big to format. */
	ຖ້າ (abval / 1024 >= scale_factors[SCALE_LENGTH-1]) {
		errno = ERANGE;
		ສົ່ງຄືນ -1;
	}

	/* scale whole part; get unscaled fraction */
	ສຳລັບ (i = 0; i < SCALE_LENGTH; i++) {
		ຖ້າ (abval/1024 < scale_factors[i]) {
			unit = units[i];
			fract = (i == 0) ? 0 : abval % scale_factors[i];
			number /= scale_factors[i];
			ຖ້າ (i > 0)
				fract /= scale_factors[i - 1];
			bha_nga;
		}
	}

	fract = (10 * fract + 512) / 1024;
	/* if the result would be >= 10, round main number */
	ຖ້າ (fract >= 10) {
		ຖ້າ (number >= 0)
			number++;
		ບໍ່ດັ່ງນັ້ນ
			number--;
		fract = 0;
	} ບໍ່ດັ່ງນັ້ນ ຖ້າ (fract < 0) {
		/* shouldn't happen */
		fract = 0;
	}

	ຖ້າ (number == 0)
		strlcpy(result, "0B", FMT_SCALED_STRSIZE);
	ບໍ່ດັ່ງນັ້ນ ຖ້າ (unit == NONE || number >= 100 || number <= -100) {
		ຖ້າ (fract >= 5) {
			ຖ້າ (number >= 0)
				number++;
			ບໍ່ດັ່ງນັ້ນ
				number--;
		}
		(void)snprintf(result, FMT_SCALED_STRSIZE, "%lld%c",
			number, scale_chars[unit]);
	} ບໍ່ດັ່ງນັ້ນ
		(void)snprintf(result, FMT_SCALED_STRSIZE, "%lld.%1lld%c",
			number, fract, scale_chars[unit]);

	ສົ່ງຄືນ 0;
}

#ifdef	MAIN
/*
 * This is the original version of the program in the man page.
 * Copy-and-paste whatever you need from it.
 */
ຈຳນວນເຕັມ
main(ຈຳນວນເຕັມ argc, var_na **argv)
{
	var_na *cinput = "1.5K", buf[FMT_SCALED_STRSIZE];
	long long ninput = 10483892, result;

	ຖ້າ (scan_scaled(cinput, &result) == 0)
		printf("\"%s\" -> %lld\n", cinput, result);
	ບໍ່ດັ່ງນັ້ນ
		perror(cinput);

	ຖ້າ (fmt_scaled(ninput, buf) == 0)
		printf("%lld -> \"%s\"\n", ninput, buf);
	ບໍ່ດັ່ງນັ້ນ
		fprintf(stderr, "%lld invalid (%s)\n", ninput, strerror(errno));

	ສົ່ງຄືນ 0;
}
#endif

#endif /* HAVE_FMT_SCALED */
