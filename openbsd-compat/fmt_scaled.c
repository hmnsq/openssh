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

#অন্তর্ভাব "includes.h"

#ifndef HAVE_FMT_SCALED

#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <errno.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <ctype.h>
#অন্তর্ভাব <limits.h>

প্রকারনির্দেশ গণনা {
	NONE = 0, KILO = 1, MEGA = 2, GIGA = 3, TERA = 4, PETA = 5, EXA = 6
} unit_type;

/* These three arrays MUST be in sync!  XXX make a struct */
স্থির ধ্রুব unit_type units[] = { NONE, KILO, MEGA, GIGA, TERA, PETA, EXA };
স্থির ধ্রুব বর্ণ scale_chars[] = "BKMGTPE";
স্থির ধ্রুব long long scale_factors[] = {
	1LL,
	1024LL,
	1024LL*1024,
	1024LL*1024*1024,
	1024LL*1024*1024*1024,
	1024LL*1024*1024*1024*1024,
	1024LL*1024*1024*1024*1024*1024,
};
#define	SCALE_LENGTH (পরিমাণ(units)/পরিমাণ(units[0]))

#define MAX_DIGITS (SCALE_LENGTH * 3)	/* XXX strlen(sprintf("%lld", -1)? */

/* Convert the given input string "scaled" into numeric in "result".
 * Return 0 on success, -1 and errno set on error.
 */
পূর্ণাঙ্ক
scan_scaled(বর্ণ *scaled, long long *result)
{
	বর্ণ *p = scaled;
	পূর্ণাঙ্ক sign = 0;
	unsigned পূর্ণাঙ্ক i, ndigits = 0, fract_digits = 0, muls = 0, divs = 0;
	long long scale_fact = 1, whole = 0, fpart = 0;

	/* Skip leading whitespace */
	যাবত্ (isascii((unsigned বর্ণ)*p) && isspace((unsigned বর্ণ)*p))
		++p;

	/* Then at most one leading + or - */
	যাবত্ (*p == '-' || *p == '+') {
		যদি (*p == '-') {
			যদি (sign) {
				errno = EINVAL;
				প্রত্যাগম -1;
			}
			sign = -1;
			++p;
		} অন্যথা যদি (*p == '+') {
			যদি (sign) {
				errno = EINVAL;
				প্রত্যাগম -1;
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
	প্রতি (; isascii((unsigned বর্ণ)*p) &&
	    (isdigit((unsigned বর্ণ)*p) || *p=='.'); ++p) {
		যদি (*p == '.') {
			যদি (fract_digits > 0) {	/* oops, more than one '.' */
				errno = EINVAL;
				প্রত্যাগম -1;
			}
			fract_digits = 1;
			অনুবর্ত;
		}

		i = (*p) - '0';			/* whew! finally a digit we can use */
		যদি (fract_digits > 0) {
			যদি (fract_digits >= MAX_DIGITS-1)
				/* ignore extra fractional digits */
				অনুবর্ত;
			fract_digits++;		/* for later scaling */
			যদি (fpart > LLONG_MAX / 10) {
				errno = ERANGE;
				প্রত্যাগম -1;
			}
			fpart *= 10;
			যদি (i > LLONG_MAX - fpart) {
				errno = ERANGE;
				প্রত্যাগম -1;
			}
			fpart += i;
		} অন্যথা {				/* normal digit */
			যদি (++ndigits >= MAX_DIGITS) {
				errno = ERANGE;
				প্রত্যাগম -1;
			}
			যদি (whole > LLONG_MAX / 10) {
				errno = ERANGE;
				প্রত্যাগম -1;
			}
			whole *= 10;
			যদি (i > LLONG_MAX - whole) {
				errno = ERANGE;
				প্রত্যাগম -1;
			}
			whole += i;
		}
	}

	যদি (sign)
		whole *= sign;

	/* If no scale factor given, we're done. fraction is discarded. */
	যদি (!*p) {
		*result = whole;
		প্রত্যাগম 0;
	}

	/* Validate scale factor, and scale whole and fraction by it. */
	প্রতি (i = 0; i < SCALE_LENGTH; i++) {

		/* Are we there yet? */
		যদি (*p == scale_chars[i] ||
			*p == tolower((unsigned বর্ণ)scale_chars[i])) {

			/* If it ends with alphanumerics after the scale char, bad. */
			যদি (isalnum((unsigned বর্ণ)*(p+1))) {
				errno = EINVAL;
				প্রত্যাগম -1;
			}
			scale_fact = scale_factors[i];

			/* check for overflow and underflow after scaling */
			যদি (whole > LLONG_MAX / scale_fact ||
			    whole < LLONG_MIN / scale_fact) {
				errno = ERANGE;
				প্রত্যাগম -1;
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
			যাবত্ (muls > 0 && divs > 0) {
				যদি (fpart <= LLONG_MAX / 1024) {
					fpart *= 1024;
					muls--;
				} অন্যথা {
					fpart /= 10;
					divs--;
				}
			}
			যাবত্ (muls > 0) {
				fpart *= 1024;
				muls--;
			}
			যাবত্ (divs > 0) {
				fpart /= 10;
				divs--;
			}
			যদি (sign == -1)
				whole -= fpart;
			অন্যথা
				whole += fpart;
			*result = whole;
			প্রত্যাগম 0;
		}
	}

	/* Invalid unit or character */
	errno = EINVAL;
	প্রত্যাগম -1;
}

/* Format the given "number" into human-readable form in "result".
 * Result must point to an allocated buffer of length FMT_SCALED_STRSIZE.
 * Return 0 on success, -1 and errno set if error.
 */
পূর্ণাঙ্ক
fmt_scaled(long long সংখ্যা, বর্ণ *result)
{
	long long abval, fract = 0;
	unsigned পূর্ণাঙ্ক i;
	unit_type unit = NONE;

	/* Not every negative long long has a positive representation. */
	যদি (সংখ্যা == LLONG_MIN) {
		errno = ERANGE;
		প্রত্যাগম -1;
	}

	abval = llabs(সংখ্যা);

	/* Also check for numbers that are just too darned big to format. */
	যদি (abval / 1024 >= scale_factors[SCALE_LENGTH-1]) {
		errno = ERANGE;
		প্রত্যাগম -1;
	}

	/* scale whole part; get unscaled fraction */
	প্রতি (i = 0; i < SCALE_LENGTH; i++) {
		যদি (abval/1024 < scale_factors[i]) {
			unit = units[i];
			fract = (i == 0) ? 0 : abval % scale_factors[i];
			সংখ্যা /= scale_factors[i];
			যদি (i > 0)
				fract /= scale_factors[i - 1];
			ভঙ্গ;
		}
	}

	fract = (10 * fract + 512) / 1024;
	/* if the result would be >= 10, round main number */
	যদি (fract >= 10) {
		যদি (সংখ্যা >= 0)
			সংখ্যা++;
		অন্যথা
			সংখ্যা--;
		fract = 0;
	} অন্যথা যদি (fract < 0) {
		/* shouldn't happen */
		fract = 0;
	}

	যদি (সংখ্যা == 0)
		strlcpy(result, "0B", FMT_SCALED_STRSIZE);
	অন্যথা যদি (unit == NONE || সংখ্যা >= 100 || সংখ্যা <= -100) {
		যদি (fract >= 5) {
			যদি (সংখ্যা >= 0)
				সংখ্যা++;
			অন্যথা
				সংখ্যা--;
		}
		(শূন্য)snprintf(result, FMT_SCALED_STRSIZE, "%lld%c",
			সংখ্যা, scale_chars[unit]);
	} অন্যথা
		(শূন্য)snprintf(result, FMT_SCALED_STRSIZE, "%lld.%1lld%c",
			সংখ্যা, fract, scale_chars[unit]);

	প্রত্যাগম 0;
}

#ifdef	MAIN
/*
 * This is the original version of the program in the man page.
 * Copy-and-paste whatever you need from it.
 */
পূর্ণাঙ্ক
main(পূর্ণাঙ্ক argc, বর্ণ **argv)
{
	বর্ণ *cinput = "1.5K", buf[FMT_SCALED_STRSIZE];
	long long ninput = 10483892, result;

	যদি (scan_scaled(cinput, &result) == 0)
		printf("\"%s\" -> %lld\n", cinput, result);
	অন্যথা
		perror(cinput);

	যদি (fmt_scaled(ninput, buf) == 0)
		printf("%lld -> \"%s\"\n", ninput, buf);
	অন্যথা
		fprintf(stderr, "%lld invalid (%s)\n", ninput, strerror(errno));

	প্রত্যাগম 0;
}
#endif

#endif /* HAVE_FMT_SCALED */
